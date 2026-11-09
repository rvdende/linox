use super::*;

pub(super) fn linux_execution_instance() -> usize {
    let instance = usize::from(X86_RUNTIME.LINUX_EXECUTION_INSTANCE.load(Ordering::Relaxed));
    if instance < LINUX_RUNTIME_INSTANCE_LIMIT {
        instance
    } else {
        usize::from(LINUX_RUNTIME_HOST_INSTANCE)
    }
}

pub(crate) fn current_linux_execution_instance() -> usize {
    linux_execution_instance()
}

/// Banks of per-process state: a running process's descriptors, threads,
/// signal and address-space state, and that of the fork or exec it is in.
/// A process live on any CPU has one bank, which every CPU running one of
/// its threads uses (`linux_cpu_bank`); state the domain's processes share
/// stays banked per instance only. A CPU with no process uses a bank of its
/// own: the boot CPU has one per execution instance (a suspended domain's
/// init stays in it), an application processor one. The spares are for CPUs
/// whose own bank still holds a process other CPUs run threads of.
const LINUX_BANK_SPARES: usize = CPU_ENTRY_STATE_LIMIT;
pub(super) const LINUX_CPU_BANK_LIMIT: usize =
    LINUX_RUNTIME_INSTANCE_LIMIT + (CPU_ENTRY_STATE_LIMIT - 1) + LINUX_BANK_SPARES;
const LINUX_BANK_NONE: u8 = u8::MAX;

/// The bank CPU `cpu` has for itself in `instance`.
const fn linux_own_bank(cpu: usize, instance: usize) -> usize {
    if cpu == 0 {
        instance
    } else {
        LINUX_RUNTIME_INSTANCE_LIMIT + cpu - 1
    }
}

/// Per CPU and execution instance, the bank it uses: `LINUX_BANK_NONE` for
/// its own (`linux_own_bank`), else a bank index.
static LINUX_CPU_BANK: [[AtomicU8; LINUX_RUNTIME_INSTANCE_LIMIT]; CPU_ENTRY_STATE_LIMIT] =
    [const { [const { AtomicU8::new(LINUX_BANK_NONE) }; LINUX_RUNTIME_INSTANCE_LIMIT] };
        CPU_ENTRY_STATE_LIMIT];
/// Per bank: the process it holds (0: none) and that process's instance.
pub(super) static LINUX_BANK_PID: [AtomicU32; LINUX_CPU_BANK_LIMIT] =
    [const { AtomicU32::new(0) }; LINUX_CPU_BANK_LIMIT];
pub(super) static LINUX_BANK_INSTANCE: [AtomicU8; LINUX_CPU_BANK_LIMIT] =
    [const { AtomicU8::new(0) }; LINUX_CPU_BANK_LIMIT];
/// Per bank, the CPUs using it: those running threads of its process, or
/// one idle CPU keeping a spare for itself.
pub(super) static LINUX_BANK_USERS: [AtomicU8; LINUX_CPU_BANK_LIMIT] =
    [const { AtomicU8::new(0) }; LINUX_CPU_BANK_LIMIT];
/// Per bank, whether a CPU owns its process: runs it as the registry
/// dispatched it, with the process's own kernel activation.
static LINUX_BANK_OWNED: [AtomicBool; LINUX_CPU_BANK_LIMIT] =
    [const { AtomicBool::new(false) }; LINUX_CPU_BANK_LIMIT];
/// Per bank, while no CPU owns its process: the thread slot whose context
/// the registry holds, which only the next owner resumes.
static LINUX_BANK_REGISTRY_THREAD: [AtomicU8; LINUX_CPU_BANK_LIMIT] =
    [const { AtomicU8::new(LINUX_THREAD_SLOT_NONE) }; LINUX_CPU_BANK_LIMIT];
/// Per bank, whether its process is exiting: threads of it on other CPUs
/// leave them.
pub(super) static LINUX_BANK_DYING: [AtomicBool; LINUX_CPU_BANK_LIMIT] =
    [const { AtomicBool::new(false) }; LINUX_CPU_BANK_LIMIT];
/// Per bank, whether its process's saved record is the one a fork
/// transaction staged (`stage_linux_fork_parent_runtime_state`): a save
/// over it keeps what the staging set.
pub(super) static LINUX_BANK_STAGED: [AtomicBool; LINUX_CPU_BANK_LIMIT] =
    [const { AtomicBool::new(false) }; LINUX_CPU_BANK_LIMIT];
/// Saves of a process from a bank that held none or another: a bookkeeping
/// error, counted for SysRq `u`.
pub(super) static LINUX_BANK_FOREIGN_SAVES: AtomicU32 = AtomicU32::new(0);
/// Waits that could not park their process (reported for the first few).
pub(super) static LINUX_PARK_REFUSALS: AtomicU32 = AtomicU32::new(0);

/// The fork transaction's state passes from the parent's bank to the child's
/// and back, as it did while a CPU had one bank: what the parent set up for
/// the child (which pid it tracks, whether its exec releases the parent) and
/// what the child reports (exited, exec'd, yielded). Copied into a bank a
/// process is restored into from the bank the CPU used before.
fn copy_linux_bank_transients(from: usize, to: usize) {
    macro_rules! copy {
        ($($field:ident),* $(,)?) => {$(
            X86_RUNTIME.$field.at_bank(to).store(
                X86_RUNTIME.$field.at_bank(from).load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
        )*};
    }
    copy!(
        LINUX_PROCESS_CHILD_EXITED,
        LINUX_PROCESS_CHILD_EXECUTED,
        LINUX_PROCESS_CHILD_YIELDED,
        LINUX_PROCESS_CHILD_EXIT_PID,
        LINUX_PROCESS_CHILD_EXEC_PID,
        LINUX_PROCESS_CHILD_YIELD_PID,
        LINUX_PROCESS_CHILD_STATUS,
        LINUX_PROCESS_RELEASE_PARENT_ON_EXEC,
        LINUX_FORK_REQUESTED,
        LINUX_PARENT_RESUMED,
        LINUX_FORK_CHILD_STACK,
        LINUX_FORK_SHARE_VM,
        LINUX_FORK_NEW_MOUNT_NAMESPACE,
        LINUX_FORK_NEW_USER_NAMESPACE,
        LINUX_FORK_CGROUP_GENERATION,
        LINUX_FORK_CHILD_TID_ADDRESS,
        LINUX_FORK_PARENT_TID_ADDRESS,
        LINUX_FORK_PIDFD_ADDRESS,
        LINUX_FORK_CLEAR_SIGHAND,
        LINUX_FORK_OWN_PAGES,
        LINUX_FORK_CLONE_FLAGS,
        LINUX_FORK_TLS,
        LINUX_FORK_CLEAR_TID_ADDRESS,
    );
}

pub(super) fn linux_bank_cpu() -> usize {
    current_cpu_index_checked()
        .filter(|cpu| *cpu < CPU_ENTRY_STATE_LIMIT)
        .unwrap_or(0)
}

/// The bank this CPU uses in the current execution instance.
pub(super) fn linux_cpu_bank() -> usize {
    let cpu = linux_bank_cpu();
    let instance = linux_execution_instance();
    let bank = LINUX_CPU_BANK[cpu][instance].load(Ordering::Relaxed);
    if bank == LINUX_BANK_NONE {
        linux_own_bank(cpu, instance)
    } else {
        usize::from(bank)
    }
}

/// This CPU's own bank, for the thread it runs (its current thread slot and
/// preemption state), whichever process's bank it uses.
pub(super) fn linux_thread_cpu_bank() -> usize {
    linux_own_bank(linux_bank_cpu(), linux_execution_instance())
}

pub(super) fn linux_bank_holds(bank: usize, pid: u32, instance: usize) -> bool {
    LINUX_BANK_PID[bank].load(Ordering::Acquire) == pid
        && usize::from(LINUX_BANK_INSTANCE[bank].load(Ordering::Acquire)) == instance
}

/// The bank process `pid` of `instance` is live in: some CPU uses it.
pub(super) fn linux_live_process_bank(pid: u32, instance: usize) -> Option<usize> {
    (0..LINUX_CPU_BANK_LIMIT).find(|bank| {
        LINUX_BANK_USERS[*bank].load(Ordering::Acquire) != 0
            && linux_bank_holds(*bank, pid, instance)
    })
}

fn linux_bank_is_free(bank: usize) -> bool {
    LINUX_BANK_PID[bank].load(Ordering::Acquire) == 0
        && LINUX_BANK_USERS[bank].load(Ordering::Acquire) == 0
}

/// The spare banks.
fn linux_spare_banks() -> core::ops::Range<usize> {
    LINUX_RUNTIME_INSTANCE_LIMIT + CPU_ENTRY_STATE_LIMIT - 1..LINUX_CPU_BANK_LIMIT
}

fn linux_point_cpu_at_bank(cpu: usize, instance: usize, bank: usize) {
    let value = if bank == linux_own_bank(cpu, instance) {
        LINUX_BANK_NONE
    } else {
        bank as u8
    };
    LINUX_CPU_BANK[cpu][instance].store(value, Ordering::Release);
}

/// How a CPU came to use a process's bank.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum BankAttach {
    /// Other CPUs run its threads: the bank is the process's current state.
    Live,
    /// The caller fills it from the process's saved state.
    Fresh,
}

/// Makes the bank of process `pid` (of this instance) this CPU's: the bank
/// it is live in, or a free one. The bank this CPU used before is let go: a
/// process the caller saved, or an idle reservation. `owner` for the CPU
/// that runs the process as the registry dispatched it. None when no bank
/// is free, or another CPU owns the process.
pub(super) fn attach_linux_process_bank(pid: u32, owner: bool) -> Option<BankAttach> {
    let cpu = linux_bank_cpu();
    let instance = linux_execution_instance();
    let current = linux_cpu_bank();
    // The same process again (a fork transaction restoring what it staged,
    // a suspended runtime its init): it keeps its bank and is filled from
    // its saved state unless other CPUs are in it.
    if LINUX_BANK_USERS[current].load(Ordering::Acquire) != 0
        && linux_bank_holds(current, pid, instance)
    {
        if owner {
            LINUX_BANK_OWNED[current].store(true, Ordering::Release);
            LINUX_BANK_REGISTRY_THREAD[current].store(LINUX_THREAD_SLOT_NONE, Ordering::Release);
            LINUX_BANK_STAGED[current].store(false, Ordering::Release);
        }
        return Some(if LINUX_BANK_USERS[current].load(Ordering::Acquire) == 1 {
            BankAttach::Fresh
        } else {
            BankAttach::Live
        });
    }
    linux_release_current_bank(cpu, instance, true);
    if let Some(bank) = linux_live_process_bank(pid, instance) {
        if owner && LINUX_BANK_OWNED[bank].swap(true, Ordering::AcqRel) {
            serial_write("linox: process owned by two CPUs pid/cpu: ");
            serial_write_u64(u64::from(pid));
            serial_write(" ");
            serial_write_u64(cpu as u64);
            serial_write("\r\n");
            linux_take_idle_bank(cpu, instance);
            return None;
        }
        LINUX_BANK_USERS[bank].fetch_add(1, Ordering::AcqRel);
        if owner {
            LINUX_BANK_REGISTRY_THREAD[bank].store(LINUX_THREAD_SLOT_NONE, Ordering::Release);
            LINUX_BANK_STAGED[bank].store(false, Ordering::Release);
        }
        linux_point_cpu_at_bank(cpu, instance, bank);
        X86_RUNTIME
            .LINUX_CURRENT_PROCESS_PID
            .store(pid, Ordering::SeqCst);
        return Some(BankAttach::Live);
    }
    let own = linux_own_bank(cpu, instance);
    let Some(bank) = core::iter::once(own)
        .chain(linux_spare_banks())
        .find(|bank| linux_bank_is_free(*bank))
    else {
        serial_write("linox: no free process bank pid/cpu: ");
        serial_write_u64(u64::from(pid));
        serial_write(" ");
        serial_write_u64(cpu as u64);
        serial_write("\r\n");
        linux_take_idle_bank(cpu, instance);
        return None;
    };
    LINUX_BANK_PID[bank].store(pid, Ordering::Release);
    LINUX_BANK_INSTANCE[bank].store(instance as u8, Ordering::Release);
    LINUX_BANK_USERS[bank].store(1, Ordering::Release);
    LINUX_BANK_OWNED[bank].store(owner, Ordering::Release);
    LINUX_BANK_DYING[bank].store(false, Ordering::Release);
    LINUX_BANK_STAGED[bank].store(false, Ordering::Release);
    LINUX_BANK_REGISTRY_THREAD[bank].store(LINUX_THREAD_SLOT_NONE, Ordering::Release);
    if bank != current {
        copy_linux_bank_transients(current, bank);
    }
    linux_point_cpu_at_bank(cpu, instance, bank);
    // The bank may be another than the one the caller named the process
    // current in.
    X86_RUNTIME
        .LINUX_CURRENT_PROCESS_PID
        .store(pid, Ordering::SeqCst);
    Some(BankAttach::Fresh)
}

/// Lets go of the bank this CPU uses: a process it leaves (saved before by
/// the caller, or exiting) or a spare it kept while idle. The CPU is left
/// pointing at its own bank, which may still hold a live process.
fn linux_release_current_bank(cpu: usize, instance: usize, owner: bool) {
    let bank = linux_cpu_bank();
    let own = linux_own_bank(cpu, instance);
    let pid = LINUX_BANK_PID[bank].load(Ordering::Acquire);
    if pid != 0 && LINUX_BANK_USERS[bank].load(Ordering::Acquire) != 0 {
        if owner && LINUX_BANK_OWNED[bank].swap(false, Ordering::AcqRel) {
            LINUX_BANK_REGISTRY_THREAD[bank].store(
                X86_RUNTIME.LINUX_CURRENT_THREAD_SLOT.load(Ordering::SeqCst),
                Ordering::Release,
            );
        }
        if LINUX_BANK_USERS[bank].fetch_sub(1, Ordering::AcqRel) == 1 {
            LINUX_BANK_PID[bank].store(0, Ordering::Release);
            LINUX_BANK_INSTANCE[bank].store(0, Ordering::Release);
            LINUX_BANK_OWNED[bank].store(false, Ordering::Release);
            LINUX_BANK_DYING[bank].store(false, Ordering::Release);
        } else {
            // A fork transaction names the child current before it
            // restores it: the process's threads elsewhere keep seeing
            // their own pid.
            X86_RUNTIME
                .LINUX_CURRENT_PROCESS_PID
                .store(pid, Ordering::SeqCst);
        }
    } else if bank != own && pid == 0 && LINUX_BANK_USERS[bank].load(Ordering::Acquire) != 0 {
        LINUX_BANK_USERS[bank].store(0, Ordering::Release);
    }
    LINUX_CPU_BANK[cpu][instance].store(LINUX_BANK_NONE, Ordering::Release);
}

/// Points an idle CPU at a bank holding no process: its own when free, else
/// a spare it keeps until it attaches to a process.
fn linux_take_idle_bank(cpu: usize, instance: usize) {
    if linux_bank_is_free(linux_own_bank(cpu, instance)) {
        LINUX_CPU_BANK[cpu][instance].store(LINUX_BANK_NONE, Ordering::Release);
        return;
    }
    for bank in linux_spare_banks() {
        if LINUX_BANK_PID[bank].load(Ordering::Acquire) == 0
            && LINUX_BANK_USERS[bank]
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            LINUX_CPU_BANK[cpu][instance].store(bank as u8, Ordering::Release);
            return;
        }
    }
    serial_write("linox: no free idle bank cpu: ");
    serial_write_u64(cpu as u64);
    serial_write("\r\n");
    LINUX_CPU_BANK[cpu][instance].store(LINUX_BANK_NONE, Ordering::Release);
}

/// A CPU with no process to run leaves the bank of the one it ran (saved
/// before, or settled after its exit; `owner` when it ran the process as
/// the registry dispatched it) and takes an idle one.
fn leave_linux_process_bank(owner: bool) {
    let cpu = linux_bank_cpu();
    let instance = linux_execution_instance();
    linux_release_current_bank(cpu, instance, owner);
    linux_take_idle_bank(cpu, instance);
}

/// Records that the bank this CPU uses holds process `pid`, when the
/// process was set up in it directly (a domain's init) rather than
/// restored into it.
pub(super) fn adopt_linux_process_bank(pid: u32) {
    let bank = linux_cpu_bank();
    if LINUX_BANK_PID[bank].load(Ordering::Acquire) == 0 {
        LINUX_BANK_PID[bank].store(pid, Ordering::Release);
        LINUX_BANK_INSTANCE[bank].store(linux_execution_instance() as u8, Ordering::Release);
        LINUX_BANK_USERS[bank].store(1, Ordering::Release);
        LINUX_BANK_OWNED[bank].store(true, Ordering::Release);
        LINUX_BANK_DYING[bank].store(false, Ordering::Release);
        LINUX_BANK_REGISTRY_THREAD[bank].store(LINUX_THREAD_SLOT_NONE, Ordering::Release);
    }
}

/// Per CPU: threads run on the light path, calls put back for the owner,
/// and the last such call's number (SysRq `u`).
static LINUX_LIGHT_RUNS: [AtomicU32; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU32::new(0) }; CPU_ENTRY_STATE_LIMIT];
static LINUX_LIGHT_MIGRATIONS: [AtomicU32; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU32::new(0) }; CPU_ENTRY_STATE_LIMIT];
static LINUX_LIGHT_LAST_MIGRATION: [AtomicU32; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU32::new(0) }; CPU_ENTRY_STATE_LIMIT];

/// SysRq `u`: the process banks in use and each CPU's light-path counts.
pub(super) fn linux_report_process_banks() {
    serial_write("linox: sysrq: banks bank/pid/instance/users/owned/registry-thread/dying:\r\n");
    for bank in 0..LINUX_CPU_BANK_LIMIT {
        if LINUX_BANK_USERS[bank].load(Ordering::Acquire) == 0
            && LINUX_BANK_PID[bank].load(Ordering::Acquire) == 0
        {
            continue;
        }
        serial_write("linox: bank ");
        for value in [
            bank as u64,
            u64::from(LINUX_BANK_PID[bank].load(Ordering::Acquire)),
            u64::from(LINUX_BANK_INSTANCE[bank].load(Ordering::Acquire)),
            u64::from(LINUX_BANK_USERS[bank].load(Ordering::Acquire)),
            u64::from(LINUX_BANK_OWNED[bank].load(Ordering::Acquire)),
            u64::from(LINUX_BANK_REGISTRY_THREAD[bank].load(Ordering::Acquire)),
            u64::from(LINUX_BANK_DYING[bank].load(Ordering::Acquire)),
        ] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
    }
    serial_write(
        "linox: sysrq: light-path runs cpu/bank/slot/runs/migrations/last-migrated-call/syscalls:\r\n",
    );
    for cpu in 0..CPU_ENTRY_STATE_LIMIT {
        serial_write("linox: cpu ");
        for value in [
            cpu as u64,
            u64::from(LINUX_LIGHT_THREAD_BANK[cpu].load(Ordering::Acquire)),
            u64::from(LINUX_LIGHT_THREAD_SLOT[cpu].load(Ordering::Acquire)),
            u64::from(LINUX_LIGHT_RUNS[cpu].load(Ordering::Relaxed)),
            u64::from(LINUX_LIGHT_MIGRATIONS[cpu].load(Ordering::Relaxed)),
            u64::from(LINUX_LIGHT_LAST_MIGRATION[cpu].load(Ordering::Relaxed)),
            linux_syscall::LINUX_SYSCALL_ENTRIES[cpu].load(Ordering::Relaxed),
        ] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
    }
    serial_write("linox: sysrq: foreign saves ");
    serial_write_u64(u64::from(LINUX_BANK_FOREIGN_SAVES.load(Ordering::Relaxed)));
    serial_write("\r\n");
}

/// SysRq `u` and the sixty-second snapshot: the threads of every process
/// live in a bank as the bank holds them (the saved record of a process
/// whose threads run on other CPUs is stale), with the process's activation
/// state, and whether each CPU's light thread yielded.
pub(super) fn linux_report_live_bank_threads() {
    serial_write("linox: sysrq: live banks bank/pid/parked-threads/running-activation:\r\n");
    for bank in 0..LINUX_CPU_BANK_LIMIT {
        let pid = LINUX_BANK_PID[bank].load(Ordering::Acquire);
        if LINUX_BANK_USERS[bank].load(Ordering::Acquire) == 0 || pid == 0 {
            continue;
        }
        serial_write("linox: bank ");
        for value in [
            bank as u64,
            u64::from(pid),
            linux_parked_threads(pid).len() as u64,
            u64::from(linux_process_activation_running(pid)),
        ] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
        for slot in 0..LINUX_THREAD_LIMIT {
            let state = X86_RUNTIME.LINUX_THREAD_STATES[slot]
                .at_bank(bank)
                .load(Ordering::Acquire);
            if state == LINUX_THREAD_FREE {
                continue;
            }
            serial_write("linox:   thread slot/tid/state/wait/key/deadline/owner-only: ");
            for value in [
                slot as u64,
                u64::from(
                    X86_RUNTIME.LINUX_THREAD_TIDS[slot]
                        .at_bank(bank)
                        .load(Ordering::Acquire),
                ),
                u64::from(state),
                u64::from(
                    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot]
                        .at_bank(bank)
                        .load(Ordering::Acquire),
                ),
                X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot]
                    .at_bank(bank)
                    .load(Ordering::Acquire),
                X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot]
                    .at_bank(bank)
                    .load(Ordering::Acquire),
                u64::from(
                    X86_RUNTIME.LINUX_THREAD_OWNER_ONLY.at_bank(bank)[slot].load(Ordering::Acquire),
                ),
            ] {
                serial_write_u64(value);
                serial_write(" ");
            }
            serial_write("\r\n");
        }
    }
    serial_write("linox: sysrq: light cpus cpu/yielded/slice-ticks:\r\n");
    for cpu in 0..CPU_ENTRY_STATE_LIMIT {
        serial_write("linox: cpu ");
        for value in [
            cpu as u64,
            u64::from(LINUX_LIGHT_THREAD_YIELDED[cpu].load(Ordering::Acquire)),
            u64::from(LINUX_PROCESS_SLICE[cpu].load(Ordering::Relaxed)),
        ] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
    }
}

/// Makes the threads of the current process that run on other CPUs leave
/// them, as `wait_for_linux_process_threads_to_leave` does for an exiting
/// process, for an exec that ends them: they are told by `LINUX_BANK_DYING`
/// and drop their contexts, and the flag is cleared once they are out so
/// the new image's threads can run.
pub(super) fn evict_linux_light_threads() {
    let bank = linux_cpu_bank();
    if !linux_bank_shared() {
        return;
    }
    LINUX_BANK_DYING[bank].store(true, Ordering::Release);
    let started = timer::timestamp_counter();
    while LINUX_BANK_USERS[bank].load(Ordering::Acquire) > 1 {
        crate::sync::kernel_entry_leave_to_user();
        core::hint::spin_loop();
        crate::sync::kernel_entry_return_from_user();
        if timer::timestamp_counter().wrapping_sub(started) > 20_000_000_000 {
            serial_write("linox: threads of an exec'ing process did not leave pid/users: ");
            serial_write_u64(u64::from(current_linux_process_pid()));
            serial_write(" ");
            serial_write_u64(u64::from(LINUX_BANK_USERS[bank].load(Ordering::Acquire)));
            serial_write("\r\n");
            break;
        }
    }
    LINUX_BANK_DYING[bank].store(false, Ordering::Release);
}

/// Whether CPUs other than this one use the bank this CPU uses.
pub(super) fn linux_bank_shared() -> bool {
    LINUX_BANK_USERS[linux_cpu_bank()].load(Ordering::Acquire) > 1
}

/// Before the state of exiting process `pid` goes: its threads running on
/// other CPUs leave them, told to by `LINUX_BANK_DYING` (their next system
/// call or timer tick), while this CPU waits with the kernel-entry lock let
/// go. The bank is the process's live one, whether or not this CPU uses it
/// (init ending a killed process from its own bank): a CPU left running one
/// of the threads would go on in the freed memory, and its root, once
/// freed, maps no kernel either (a triple fault at its next interrupt).
pub(super) fn wait_for_linux_process_threads_to_leave(pid: u32) {
    let instance = linux_execution_instance();
    let Some(bank) = linux_live_process_bank(pid, instance) else {
        return;
    };
    // This CPU's own use of the bank stays until it leaves it.
    let here = u8::from(linux_cpu_bank() == bank);
    if LINUX_BANK_USERS[bank].load(Ordering::Acquire) <= here {
        return;
    }
    LINUX_BANK_DYING[bank].store(true, Ordering::Release);
    let started = timer::timestamp_counter();
    // The last thread out frees a bank this CPU is not in.
    while LINUX_BANK_USERS[bank].load(Ordering::Acquire) > here
        && linux_bank_holds(bank, pid, instance)
    {
        crate::sync::kernel_entry_leave_to_user();
        core::hint::spin_loop();
        crate::sync::kernel_entry_return_from_user();
        if timer::timestamp_counter().wrapping_sub(started) > 20_000_000_000 {
            serial_write("linox: threads of exiting process did not leave pid/users: ");
            serial_write_u64(u64::from(pid));
            serial_write(" ");
            serial_write_u64(u64::from(LINUX_BANK_USERS[bank].load(Ordering::Acquire)));
            serial_write("\r\n");
            break;
        }
    }
}

/// The CPU as the runtime's thread model sees it: 0 on every CPU that runs
/// processes whole (the boot CPU, and an application processor in a domain
/// runtime's loop, see `run_application_processor_runtime`), the CPU's own
/// index on an application processor running one thread of the process the
/// boot CPU runs.
pub(super) fn current_linux_runtime_cpu_index() -> usize {
    let cpu = current_cpu_index_checked().unwrap_or(0);
    if cpu < CPU_ENTRY_STATE_LIMIT
        && LINUX_SMP_LOOP_ACTIVE[cpu].load(Ordering::Acquire)
        && LINUX_LIGHT_THREAD_BANK[cpu].load(Ordering::Acquire) == LINUX_BANK_NONE
    {
        0
    } else {
        cpu
    }
}

/// Per CPU of a domain runtime's loop: the bank and thread slot of the
/// thread it runs on the light path (`run_linux_light_thread`): a thread
/// of a process another CPU owns, or none owns. `LINUX_BANK_NONE` while the
/// CPU runs a process as the registry dispatched it, or nothing.
static LINUX_LIGHT_THREAD_BANK: [AtomicU8; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU8::new(LINUX_BANK_NONE) }; CPU_ENTRY_STATE_LIMIT];
static LINUX_LIGHT_THREAD_SLOT: [AtomicU8; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU8::new(LINUX_THREAD_SLOT_NONE) }; CPU_ENTRY_STATE_LIMIT];
/// Per CPU: its light thread left the CPU on purpose (preempted, kept for
/// the owner, or blocked), so the loop looks for other work before it.
static LINUX_LIGHT_THREAD_YIELDED: [AtomicBool; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicBool::new(false) }; CPU_ENTRY_STATE_LIMIT];

/// The bank and thread slot of the light thread this CPU runs, if any.
pub(super) fn linux_light_thread_here() -> Option<(usize, usize)> {
    let cpu = current_cpu_index_checked().filter(|cpu| *cpu < CPU_ENTRY_STATE_LIMIT)?;
    let bank = LINUX_LIGHT_THREAD_BANK[cpu].load(Ordering::Acquire);
    (bank != LINUX_BANK_NONE).then(|| {
        (
            usize::from(bank),
            usize::from(LINUX_LIGHT_THREAD_SLOT[cpu].load(Ordering::Acquire)),
        )
    })
}

/// Whether another CPU runs thread `slot` of this CPU's process.
pub(super) fn linux_thread_runs_elsewhere(slot: usize) -> bool {
    let here = linux_bank_cpu();
    let bank = linux_cpu_bank();
    (0..CPU_ENTRY_STATE_LIMIT).any(|cpu| {
        cpu != here
            && usize::from(LINUX_LIGHT_THREAD_BANK[cpu].load(Ordering::Acquire)) == bank
            && usize::from(LINUX_LIGHT_THREAD_SLOT[cpu].load(Ordering::Acquire)) == slot
    })
}

/// The next thread an idle CPU of the loop can run on the light path, after
/// `cursor` (a bank and slot index, for a round robin): in a live bank of
/// this instance whose process is not exiting, ready, not kept for the
/// owner, and not the thread whose context the registry holds.
fn pick_linux_light_thread(cursor: &mut usize) -> Option<(usize, usize)> {
    let instance = linux_execution_instance();
    let cpu = current_linux_runtime_cpu_index();
    let total = LINUX_CPU_BANK_LIMIT * LINUX_THREAD_LIMIT;
    for step in 1..=total {
        let index = (*cursor + step) % total;
        let (bank, slot) = (index / LINUX_THREAD_LIMIT, index % LINUX_THREAD_LIMIT);
        if LINUX_BANK_USERS[bank].load(Ordering::Acquire) == 0
            || LINUX_BANK_PID[bank].load(Ordering::Acquire) == 0
            || usize::from(LINUX_BANK_INSTANCE[bank].load(Ordering::Acquire)) != instance
            || LINUX_BANK_DYING[bank].load(Ordering::Acquire)
            || usize::from(LINUX_BANK_REGISTRY_THREAD[bank].load(Ordering::Acquire)) == slot
            || X86_RUNTIME.LINUX_THREAD_STATES[slot]
                .at_bank(bank)
                .load(Ordering::Acquire)
                != LINUX_THREAD_READY
            || X86_RUNTIME.LINUX_THREAD_OWNER_ONLY.at_bank(bank)[slot].load(Ordering::Acquire) != 0
        {
            continue;
        }
        // A process sched_setaffinity pinned to other CPUs is not run here.
        let pid = LINUX_BANK_PID[bank].load(Ordering::Acquire);
        if linux_process::live_process_cpu_affinity(pid)
            .is_some_and(|mask| mask & (1_u64 << cpu) == 0)
        {
            continue;
        }
        *cursor = index;
        return Some((bank, slot));
    }
    None
}

/// Runs thread `slot` of the process live in `bank` on this CPU of the
/// runtime's loop, which runs nothing, until it blocks, is preempted, is
/// kept for the owner, or exits. Its process's bank is this CPU's
/// meanwhile; the thread's state goes to the saved record when it leaves,
/// and the whole process's when this was the last CPU in the bank.
fn run_linux_light_thread(cpu: usize, bank: usize, slot: usize) -> bool {
    let instance = linux_execution_instance();
    let pid = LINUX_BANK_PID[bank].load(Ordering::Acquire);
    if pid == 0 {
        return false;
    }
    LINUX_BANK_USERS[bank].fetch_add(1, Ordering::AcqRel);
    linux_release_current_bank(cpu, instance, false);
    linux_point_cpu_at_bank(cpu, instance, bank);
    LINUX_LIGHT_RUNS[cpu].fetch_add(1, Ordering::Relaxed);
    LINUX_LIGHT_THREAD_SLOT[cpu].store(slot as u8, Ordering::Release);
    LINUX_LIGHT_THREAD_BANK[cpu].store(bank as u8, Ordering::Release);
    LINUX_LIGHT_THREAD_YIELDED[cpu].store(false, Ordering::Release);
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
    LINUX_PROCESS_SLICE[cpu].store(0, Ordering::SeqCst);
    linux_process::start_live_process_cpu(pid, timer::timestamp_counter());
    linux_mark_thread_cpu();
    let ran = run_linux_light_thread_here(cpu, bank, pid, slot);
    linux_charge_thread_cpu(slot);
    if !ran {
        // Not run: left to the owner rather than tried again at once.
        X86_RUNTIME.LINUX_THREAD_OWNER_ONLY[slot].store(1, Ordering::SeqCst);
    }
    linux_process::charge_live_process_cpu(timer::timestamp_counter());
    LINUX_LIGHT_THREAD_BANK[cpu].store(LINUX_BANK_NONE, Ordering::Release);
    LINUX_LIGHT_THREAD_SLOT[cpu].store(LINUX_THREAD_SLOT_NONE, Ordering::Release);
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
    let live = linux_process::live_process_status(pid)
        .is_some_and(|status| status.state != linux_process::LiveProcessState::Zombie);
    if live && !LINUX_BANK_DYING[bank].load(Ordering::Acquire) {
        if LINUX_BANK_USERS[bank].load(Ordering::Acquire) == 1 {
            // The last CPU in the bank: the saved state becomes the
            // process's state, as the owner's save makes it. A record a
            // fork transaction staged keeps what the staging set, and its
            // descriptors stay retained.
            let registry_thread = LINUX_BANK_REGISTRY_THREAD[bank].load(Ordering::Acquire);
            let staged = LINUX_BANK_STAGED[bank].load(Ordering::Acquire);
            if let (Some(mut state), Some(destination)) = (
                capture_linux_process_runtime_state_for(registry_thread),
                linux_process_runtime_state(pid),
            ) {
                if staged {
                    state.active = true;
                    state.completed = false;
                    state.exit_status = 0;
                    state.termination_signal = 0;
                    if retain_linux_descriptor_runtime_state(&mut state.descriptors) {
                        release_linux_descriptor_runtime_state(&destination.descriptors);
                    }
                }
                *destination = state;
            }
        } else if let Some(threads) = linux_process_thread_runtime_state(pid) {
            threads[slot] = capture_linux_thread_runtime_state(slot);
        }
    }
    leave_linux_process_bank(false);
    ran
}

/// `run_linux_light_thread` with the bank attached.
fn run_linux_light_thread_here(cpu: usize, bank: usize, pid: u32, slot: usize) -> bool {
    let Some(root) = linux_process::live_process_root(pid) else {
        return false;
    };
    loop {
        let kernel_entry = crate::sync::kernel_entry_lock();
        if LINUX_BANK_DYING[bank].load(Ordering::Acquire) {
            return true;
        }
        let Some(handle) = linux_thread_handle(slot) else {
            return true;
        };
        if X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_READY {
            return true;
        }
        let Some(context) = linux_thread_return_context(handle) else {
            return false;
        };
        if !switch_linux_thread(handle) {
            return false;
        }
        let Some(general) = linux_thread_resume_general(handle, context) else {
            return false;
        };
        X86_RUNTIME.LINUX_THREAD_OWNER_ONLY[slot].store(0, Ordering::SeqCst);
        LINUX_LIGHT_THREAD_YIELDED[cpu].store(false, Ordering::Release);
        let entered = address_space::resume_live_linux_process(
            root,
            context.rip,
            context.rsp,
            context.fs_base,
            general,
            context.rflags,
        );
        if !entered {
            // Not entered: the thread is as it was, ready.
            X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
            X86_RUNTIME
                .LINUX_CURRENT_THREAD_SLOT
                .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
            serial_write("linox: light thread entry failed pid/slot/cpu: ");
            serial_write_u64(u64::from(pid));
            serial_write(" ");
            serial_write_u64(slot as u64);
            serial_write(" ");
            serial_write_u64(cpu as u64);
            serial_write("\r\n");
            return false;
        }
        // The thread left the CPU: blocked, exited, preempted, kept for
        // the owner, or woken again already.
        let state = X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst);
        if state == LINUX_THREAD_RUNNING {
            // Returned to the kernel without leaving the thread: its
            // process is ending (nothing of its context is needed) or a
            // kernel error dropped it.
            X86_RUNTIME
                .LINUX_CURRENT_THREAD_SLOT
                .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
            if LINUX_BANK_DYING[bank].load(Ordering::Acquire)
                || !X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst)
            {
                return true;
            }
            serial_write("linox: light thread dropped pid/slot/cpu: ");
            serial_write_u64(u64::from(pid));
            serial_write(" ");
            serial_write_u64(slot as u64);
            serial_write(" ");
            serial_write_u64(cpu as u64);
            serial_write("\r\n");
            return false;
        }
        drop(kernel_entry);
        if state == LINUX_THREAD_READY && !LINUX_LIGHT_THREAD_YIELDED[cpu].load(Ordering::Acquire) {
            continue;
        }
        return true;
    }
}

/// The light thread on this CPU leaves it, with `context` to go on from
/// later: kept for the process's owner (`owner_only`: a system call only
/// the owner's path runs), else for any CPU of the loop.
pub(super) fn park_linux_light_thread(
    handle: LinuxThreadHandle,
    context: LinuxUserContext,
    owner_only: bool,
) -> u64 {
    let Some(cpu) = current_cpu_index_checked().filter(|cpu| *cpu < CPU_ENTRY_STATE_LIMIT) else {
        return LINUX_EINVAL;
    };
    let slot = usize::from(handle.slot);
    if !save_linux_thread_return_context(handle, context) {
        serial_write("linox: light thread context rejected pid/slot/rip/rsp: ");
        for value in [
            u64::from(current_linux_process_pid()),
            slot as u64,
            context.rip,
            context.rsp,
        ] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
        return LINUX_EINVAL;
    }
    let _ = save_linux_thread_extended_state(current_linux_process_pid(), slot);
    X86_RUNTIME.LINUX_THREAD_OWNER_ONLY[slot].store(u8::from(owner_only), Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
    LINUX_LIGHT_THREAD_YIELDED[cpu].store(true, Ordering::Release);
    LINUX_RETURN_TO_KERNEL
}

/// `park_linux_light_thread` with the exact registers the timer or a fault
/// interrupted the thread at (rcx and r11 live, not a system call's).
fn park_linux_light_thread_exact(
    handle: LinuxThreadHandle,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    owner_only: bool,
) -> u64 {
    let context = LinuxUserContext {
        registers: LinuxSyscallFrame {
            r15: general[14],
            r14: general[13],
            r13: general[12],
            r12: general[11],
            rbp: general[6],
            rbx: general[1],
            r10: general[9],
            r9: general[8],
            r8: general[7],
            rdx: general[3],
            rsi: general[4],
            rdi: general[5],
        },
        rip,
        rsp,
        rflags,
        rax: general[0],
        fs_base: active_fs_base(),
    };
    let result = park_linux_light_thread(handle, context, owner_only);
    if result == LINUX_RETURN_TO_KERNEL {
        let slot = usize::from(handle.slot);
        X86_RUNTIME.LINUX_THREAD_RCXS[slot].store(general[2], Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_R11S[slot].store(general[10], Ordering::SeqCst);
    }
    result
}

/// A system call the light path does not run: the thread's call is put back
/// for the process's owner, which runs it as the registry dispatched the
/// process (process creation, exec, exit of the process, waits for children
/// and the descriptor waits that run other processes meanwhile, signals).
pub(super) fn migrate_current_linux_thread_to_owner(caller: LinuxUserContext, number: u64) -> u64 {
    let Some((_, slot)) = linux_light_thread_here() else {
        return LINUX_EINVAL;
    };
    if let Some(cpu) = current_cpu_index_checked().filter(|cpu| *cpu < CPU_ENTRY_STATE_LIMIT) {
        LINUX_LIGHT_MIGRATIONS[cpu].fetch_add(1, Ordering::Relaxed);
        LINUX_LIGHT_LAST_MIGRATION[cpu].store(number as u32, Ordering::Relaxed);
    }
    let Some(handle) = linux_thread_handle(slot) else {
        return LINUX_RETURN_TO_KERNEL;
    };
    let mut restart = caller;
    restart.rip = caller.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
    restart.rax = number;
    park_linux_light_thread(handle, restart, true)
}

/// Whether the light path runs system call `number` itself. The rest go to
/// the owner (`migrate_current_linux_thread_to_owner`): calls that create
/// or replace the process, end it, wait for its children, deliver or wait
/// for signals, change its identity or namespaces, or wait for descriptors
/// by running other processes meanwhile.
pub(super) fn linux_light_syscall_allowed(number: u64, registers: LinuxSyscallFrame) -> bool {
    if matches!(
        number,
        LINUX_FORK_SYSCALL
            | LINUX_VFORK_SYSCALL
            | LINUX_EXECVE_SYSCALL
            | LINUX_EXECVEAT_SYSCALL
            | LINUX_EXIT_GROUP_SYSCALL
            | LINUX_WAIT4_SYSCALL
            | LINUX_WAITID_SYSCALL
            | LINUX_KILL_SYSCALL
            | LINUX_TKILL_SYSCALL
            | LINUX_TGKILL_SYSCALL
            | LINUX_RT_SIGQUEUEINFO_SYSCALL
            | LINUX_RT_TGSIGQUEUEINFO_SYSCALL
            | LINUX_PIDFD_SEND_SIGNAL_SYSCALL
            | LINUX_RT_SIGRETURN_SYSCALL
            | LINUX_RT_SIGSUSPEND_SYSCALL
            | LINUX_RT_SIGTIMEDWAIT_SYSCALL
            | LINUX_PAUSE_SYSCALL
            | LINUX_SIGNALFD_SYSCALL
            | LINUX_SIGNALFD4_SYSCALL
            | LINUX_POLL_SYSCALL
            | LINUX_PPOLL_SYSCALL
            | LINUX_SELECT_SYSCALL
            | LINUX_PSELECT6_SYSCALL
            | LINUX_EPOLL_WAIT_SYSCALL
            | LINUX_EPOLL_PWAIT_SYSCALL
            | LINUX_EPOLL_PWAIT2_SYSCALL
            | LINUX_NANOSLEEP_SYSCALL
            | LINUX_CLOCK_NANOSLEEP_SYSCALL
            | LINUX_SETSID_SYSCALL
            | LINUX_SETPGID_SYSCALL
            | LINUX_SETUID_SYSCALL
            | LINUX_SETGID_SYSCALL
            | LINUX_SETREUID_SYSCALL
            | LINUX_SETREGID_SYSCALL
            | LINUX_SETRESUID_SYSCALL
            | LINUX_SETRESGID_SYSCALL
            | LINUX_SETFSUID_SYSCALL
            | LINUX_SETFSGID_SYSCALL
            | LINUX_SETGROUPS_SYSCALL
            | LINUX_CAPSET_SYSCALL
            | LINUX_UNSHARE_SYSCALL
            | LINUX_SETNS_SYSCALL
            | LINUX_MOUNT_SYSCALL
            | LINUX_UMOUNT2_SYSCALL
            | LINUX_CHROOT_SYSCALL
            | LINUX_PIVOT_ROOT_SYSCALL
            | LINUX_PTRACE_SYSCALL
            | LINUX_REBOOT_SYSCALL
            | LINUX_SECCOMP_SYSCALL
            | LINUX_PERSONALITY_SYSCALL
            | LINUX_VHANGUP_SYSCALL
            | LINUX_PROCESS_VM_READV_SYSCALL
            | LINUX_PROCESS_VM_WRITEV_SYSCALL
            | LINUX_PIDFD_OPEN_SYSCALL
            | LINUX_PIDFD_GETFD_SYSCALL
    ) {
        return false;
    }
    !linux_syscall_creates_process(number, registers.rdi, registers.rdi)
}

/// A light thread's fatal fault: the thread is kept for the owner at the
/// faulting instruction. A fault signal is the faulting thread's alone, as
/// Linux forces it on the current task: the owner runs the instruction
/// again and the fault it raises there is delivered to that thread, with
/// its own code and address. Queued for the process, the owner delivered it
/// to whichever thread it ran (userfaultfd06's SIGBUS went to the thread
/// that poisoned the page, whose handler then longjmp'd onto the faulting
/// thread's stack). A trap is past its instruction, so it is queued for
/// the thread; running out of memory (SIGKILL) ends the whole process.
pub(super) fn fault_linux_light_thread(
    frame: &UserFaultFrame,
    fault: domain::FaultMetadata,
    signal: u64,
) -> u64 {
    let Some((_, slot)) = linux_light_thread_here() else {
        return u64::MAX;
    };
    let pid = current_linux_process_pid();
    if signal == LINUX_SIGKILL {
        let _ = linux_queue_process_signal(pid, signal, LINUX_SI_KERNEL, Some(fault.address));
    } else if matches!(fault.vector, 1 | 3) {
        let Some(process_slot) = linux_process::live_process_slot(pid) else {
            return u64::MAX;
        };
        let _ = linux_queue_saved_thread_signal(
            pid,
            process_slot,
            slot,
            signal,
            LINUX_SI_KERNEL,
            Some(fault.address),
        );
    }
    let Some(handle) = linux_thread_handle(slot) else {
        return u64::MAX;
    };
    let context = frame.context();
    let _ = park_linux_light_thread_exact(
        handle,
        [
            context.rax,
            context.rbx,
            context.rcx,
            context.rdx,
            context.rsi,
            context.rdi,
            context.rbp,
            context.r8,
            context.r9,
            context.r10,
            context.r11,
            context.r12,
            context.r13,
            context.r14,
            context.r15,
        ],
        context.rip,
        context.rsp,
        context.rflags,
        true,
    );
    u64::MAX
}

/// On a light thread's CPU the timer ends its slice (or the process is
/// exiting): the thread goes to the vDSO's preemption entry, whose system
/// call saves its exact context and lets the CPU look for other work.
fn linux_preempt_light_thread_from_timer(cpu: usize, bank: usize, frame: &mut UserInterruptFrame) {
    let Some(context) = frame.user_context(USER_CODE_SELECTOR, USER_DATA_SELECTOR) else {
        return;
    };
    let ticks = LINUX_PROCESS_SLICE[cpu].fetch_add(1, Ordering::SeqCst) + 1;
    let dying = LINUX_BANK_DYING[bank].load(Ordering::Acquire);
    if ticks < linux_thread_slice_ticks() && !dying {
        return;
    }
    let Some(entry) = crate::linux_elf::vdso_preempt_entry() else {
        return;
    };
    if (entry..entry + 9).contains(&context.rip) {
        return;
    }
    let preempted = LinuxPreemptedContext {
        pid: current_linux_process_pid(),
        general: [
            context.rax,
            context.rbx,
            context.rcx,
            context.rdx,
            context.rsi,
            context.rdi,
            context.rbp,
            context.r8,
            context.r9,
            context.r10,
            context.r11,
            context.r12,
            context.r13,
            context.r14,
            context.r15,
        ],
        rip: context.rip,
        rsp: context.rsp,
        rflags: context.rflags,
        signal: false,
    };
    let mut redirected = context;
    redirected.rip = entry;
    if frame.restore_user_context(redirected, USER_CODE_SELECTOR, USER_DATA_SELECTOR) {
        *LINUX_PREEMPTED_CONTEXT[cpu].lock() = Some(preempted);
        LINUX_PROCESS_SLICE[cpu].store(0, Ordering::SeqCst);
    }
}

/// Timed futex and sleep waits of threads in live banks this CPU is not
/// in: their deadlines pass while no CPU of their process makes a system
/// call (a process whose owner is away and whose other threads block).
fn expire_linux_light_waits() -> u32 {
    let instance = linux_execution_instance();
    let mut expired = 0;
    let Some(now) = linux_elapsed_nanoseconds() else {
        return 0;
    };
    for bank in 0..LINUX_CPU_BANK_LIMIT {
        if LINUX_BANK_USERS[bank].load(Ordering::Acquire) == 0
            || LINUX_BANK_PID[bank].load(Ordering::Acquire) == 0
            || usize::from(LINUX_BANK_INSTANCE[bank].load(Ordering::Acquire)) != instance
            || LINUX_BANK_DYING[bank].load(Ordering::Acquire)
            || !X86_RUNTIME
                .LINUX_TIMED_WAITS_ACTIVE
                .at_bank(bank)
                .load(Ordering::Acquire)
        {
            continue;
        }
        for slot in 0..LINUX_THREAD_LIMIT {
            let deadline = X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot]
                .at_bank(bank)
                .load(Ordering::SeqCst);
            if deadline == 0
                || now < deadline
                || X86_RUNTIME.LINUX_THREAD_STATES[slot]
                    .at_bank(bank)
                    .load(Ordering::SeqCst)
                    != LINUX_THREAD_BLOCKED
            {
                continue;
            }
            let result = match X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot]
                .at_bank(bank)
                .load(Ordering::SeqCst)
            {
                LINUX_THREAD_WAIT_FUTEX => LINUX_ETIMEDOUT,
                LINUX_THREAD_WAIT_SLEEP => 0,
                LINUX_THREAD_WAIT_RETRY => X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot]
                    .at_bank(bank)
                    .load(Ordering::SeqCst),
                _ => continue,
            };
            X86_RUNTIME.LINUX_THREAD_RAXS[slot]
                .at_bank(bank)
                .store(result, Ordering::SeqCst);
            X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot]
                .at_bank(bank)
                .store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
            X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot]
                .at_bank(bank)
                .store(0, Ordering::SeqCst);
            X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot]
                .at_bank(bank)
                .store(0, Ordering::SeqCst);
            X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot]
                .at_bank(bank)
                .store(0, Ordering::SeqCst);
            X86_RUNTIME.LINUX_THREAD_STATES[slot]
                .at_bank(bank)
                .store(LINUX_THREAD_READY, Ordering::SeqCst);
            expired += 1;
        }
    }
    expired
}

/// The domain instance, plus one, whose runtime lets the other CPUs it was
/// given run its processes; 0 while none does.
static LINUX_SMP_RUNTIME_INSTANCE: AtomicU8 = AtomicU8::new(0);
/// Application processors in a domain runtime's loop.
static LINUX_SMP_LOOP_ACTIVE: [AtomicBool; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicBool::new(false) }; CPU_ENTRY_STATE_LIMIT];

/// Whether a domain runtime is running its processes on more than one CPU.
pub(super) fn linux_smp_runtime_active() -> bool {
    LINUX_SMP_RUNTIME_INSTANCE.load(Ordering::Acquire) != 0
}

/// Lets the domain's other CPUs (its `cpu=N` setting) run its processes
/// while the boot CPU's runtime loop runs.
pub(super) fn start_linux_smp_runtime() {
    let cpus = linux_available_cpu_count().min(CPU_ENTRY_STATE_LIMIT);
    if cpus < 2 || cfg!(feature = "verification-boot") {
        return;
    }
    LINUX_SMP_RUNTIME_INSTANCE.store(linux_execution_instance() as u8 + 1, Ordering::Release);
    for cpu in 1..cpus {
        crate::arch::x86_64::smp::wake_application_processor(cpu);
    }
}

/// Ends `start_linux_smp_runtime`: the other CPUs finish the process they
/// run and leave the runtime, before the boot CPU suspends or tears it down.
/// The kernel-entry lock is let go while they do. Whether it had started.
pub(super) fn stop_linux_smp_runtime() -> bool {
    if LINUX_SMP_RUNTIME_INSTANCE.swap(0, Ordering::AcqRel) == 0 {
        return false;
    }
    while LINUX_SMP_LOOP_ACTIVE
        .iter()
        .any(|active| active.load(Ordering::Acquire))
    {
        crate::sync::kernel_entry_leave_to_user();
        core::hint::spin_loop();
        crate::sync::kernel_entry_return_from_user();
    }
    true
}

/// Whether an idle application processor `cpu` should join a domain
/// runtime's loop.
pub(crate) fn linux_runtime_wants_cpu(cpu: usize) -> bool {
    cpu != 0
        && cpu < CPU_ENTRY_STATE_LIMIT
        && LINUX_SMP_RUNTIME_INSTANCE.load(Ordering::Acquire) != 0
}

/// An application processor's runtime loop: while the domain's runtime lets
/// it, takes ready processes no other CPU runs and runs each until it waits,
/// yields or exits, as the boot CPU's loop runs the others. Processes that
/// sleep in a wait are left to the boot CPU's loop, which looks at their
/// waits again; this one takes the runnable ones.
pub(crate) fn run_application_processor_runtime(cpu: usize) {
    let instance = LINUX_SMP_RUNTIME_INSTANCE.load(Ordering::Acquire);
    if instance == 0 || cpu == 0 || cpu >= CPU_ENTRY_STATE_LIMIT {
        return;
    }
    let guard = crate::sync::kernel_entry_lock();
    if LINUX_SMP_RUNTIME_INSTANCE.load(Ordering::Acquire) != instance {
        return;
    }
    let Some(saved_msrs) = configure_linux_syscall() else {
        return;
    };
    let previous_instance = X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .swap(instance - 1, Ordering::AcqRel);
    LINUX_SMP_LOOP_ACTIVE[cpu].store(true, Ordering::Release);
    let ticking = timer::arm_linux_cpu_tick();
    drop(guard);
    let mut after = 0;
    let mut thread_cursor = 0;
    let mut idle_ticks = LINUX_SMP_IDLE_SPIN_TICKS;
    let mut process_first = false;
    loop {
        // Looking for work takes the kernel-entry lock only when it is free:
        // a CPU with nothing to run must not queue for it behind the owner
        // CPU's system calls (a fork storm retiring hundreds of children was
        // slowed to a crawl by three idle CPUs taking turns on the lock).
        let Some(guard) = crate::sync::kernel_entry_try_lock() else {
            let started = timer::timestamp_counter();
            let until = started.wrapping_add(LINUX_SMP_IDLE_SPIN_TICKS);
            while timer::timestamp_counter() < until {
                core::hint::spin_loop();
            }
            crate::cpu_time::add_lock_wait(timer::timestamp_counter().saturating_sub(started));
            continue;
        };
        if LINUX_SMP_RUNTIME_INSTANCE.load(Ordering::Acquire) != instance
            || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire)
            || X86_RUNTIME.LINUX_RUNTIME_SUSPENDED.load(Ordering::Acquire)
        {
            break;
        }
        let _ = expire_linux_light_waits();
        deliver_linux_wakeups();
        // Light threads and dispatchable processes take turns: a process
        // pinned with its threads to this CPU alone (nice05 pins its main
        // thread and two busy threads to one CPU) would otherwise never
        // see its main thread run while the threads keep this CPU busy.
        process_first = !process_first;
        if !process_first {
            if let Some((bank, slot)) = pick_linux_light_thread(&mut thread_cursor) {
                idle_ticks = LINUX_SMP_IDLE_SPIN_TICKS;
                run_linux_light_thread_reporting(cpu, bank, slot);
                drop(guard);
                continue;
            }
        }
        let now = linux_elapsed_nanoseconds().unwrap_or(0);
        // A process parked in a wait (Sleeping) is the boot CPU's to resume,
        // unless its affinity keeps it from the boot CPU: then nobody else
        // would, and pinned to another CPU it slept for good (a usleep after
        // sched_setaffinity, which not even its alarm ended). One asleep
        // until a deadline that has passed is taken here too: the boot CPU
        // may be held for milliseconds by the process it runs (24 ms past a
        // sleeper's deadline), and an idle CPU resumes it on time.
        let picked = linux_process::ready_live_process_after(after, now, |pid| {
            pid != 1
                && linux_process::live_process_status(pid).is_some_and(|status| {
                    status.state == linux_process::LiveProcessState::Running
                        || status.state == linux_process::LiveProcessState::Sleeping
                            && (linux_process::live_process_cpu_affinity(pid)
                                .is_some_and(|mask| mask & 1 == 0)
                                || linux_process::live_process_sleep_due(pid, now))
                })
                && !linux_process_activation_running(pid)
        });
        if let Some(pid) = picked {
            after = pid;
            idle_ticks = LINUX_SMP_IDLE_SPIN_TICKS;
            crate::cpu_time::add_run();
            if !run_linux_process_on_this_cpu(pid) {
                serial_write("linox: application processor run failed cpu/pid: ");
                serial_write_u64(cpu as u64);
                serial_write(" ");
                serial_write_u64(u64::from(pid));
                serial_write("\r\n");
            }
            drop(guard);
            continue;
        }
        if process_first {
            if let Some((bank, slot)) = pick_linux_light_thread(&mut thread_cursor) {
                idle_ticks = LINUX_SMP_IDLE_SPIN_TICKS;
                run_linux_light_thread_reporting(cpu, bank, slot);
                drop(guard);
                continue;
            }
        }
        drop(guard);
        // Nothing to run: leave the kernel to the other CPUs for a while,
        // longer each time nothing turns up (up to about a millisecond), so
        // idle CPUs do not hold up busy ones' system calls. Once the wait
        // is that long, a CPU with its own tick halts until the tick (a
        // millisecond) instead: spinning, every idle CPU of every domain
        // kept a host CPU busy, which starved the CPUs that had work on a
        // loaded host (futex_cmp_requeue01's thousand forks then took
        // seconds).
        let started = timer::timestamp_counter();
        // A sleeper due before the tick is resumed by a CPU that looks
        // again by then, not one halted past it (futex_wait05's 1 ms waits);
        // with the lock busy, another CPU is at work and this one looks
        // again soon.
        let sleeper_due = || {
            let Some(_guard) = crate::sync::kernel_entry_try_lock() else {
                return true;
            };
            let now = linux_elapsed_nanoseconds().unwrap_or(0);
            linux_process::next_live_block_deadline().is_some_and(|deadline| {
                deadline.saturating_sub(now) < 1_000_000_000 / timer::LINUX_WAIT_TICKS_PER_SECOND
            })
        };
        // With a sleeper due this CPU looks again soon, not after a wait
        // that has backed off to about a millisecond: it may be the one
        // to resume it.
        let due_soon = sleeper_due();
        if ticking && idle_ticks >= LINUX_SMP_IDLE_SPIN_TICKS * 64 && !due_soon {
            // SAFETY: interrupts are enabled only around the halt, with no
            // lock held; this CPU's tick handler returns at once from a
            // kernel-mode frame, and `cli` ends the window.
            unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
        } else {
            let wait = if due_soon {
                LINUX_SMP_IDLE_SPIN_TICKS
            } else {
                idle_ticks
            };
            let until = started.wrapping_add(wait);
            while timer::timestamp_counter() < until {
                core::hint::spin_loop();
            }
        }
        crate::cpu_time::add_idle(timer::timestamp_counter().saturating_sub(started));
        if !due_soon {
            idle_ticks = (idle_ticks * 2).min(LINUX_SMP_IDLE_SPIN_TICKS * 64);
        }
    }
    if ticking {
        timer::disarm_linux_cpu_tick();
    }
    let _ = restore_linux_syscall(saved_msrs);
    X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .store(previous_instance, Ordering::Release);
    LINUX_SMP_LOOP_ACTIVE[cpu].store(false, Ordering::Release);
}

/// `run_linux_light_thread` from the loop, reporting a failure to run.
fn run_linux_light_thread_reporting(cpu: usize, bank: usize, slot: usize) {
    crate::cpu_time::add_run();
    if !run_linux_light_thread(cpu, bank, slot) {
        serial_write("linox: application processor thread run failed cpu/bank/slot: ");
        serial_write_u64(cpu as u64);
        serial_write(" ");
        serial_write_u64(bank as u64);
        serial_write(" ");
        serial_write_u64(slot as u64);
        serial_write("\r\n");
    }
}

/// Keeps process `pid` on this CPU while it lives: the CPU made the process
/// ready but switches back to it (the parent of a fork it runs, or the
/// process a scheduling frame runs others from), so no other CPU of a
/// multi-CPU runtime may take it meanwhile.
pub(super) struct LinuxProcessPin(Option<u32>);

impl LinuxProcessPin {
    pub(super) fn new(pid: u32) -> Self {
        let pinned = linux_smp_runtime_active()
            && linux_process::pin_live_process(pid, current_cpu_index_checked());
        Self(pinned.then_some(pid))
    }
}

impl Drop for LinuxProcessPin {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = linux_process::pin_live_process(pid, None);
        }
    }
}

/// Timestamp-counter ticks an idle application processor first waits
/// before it looks for a process again; the wait doubles while it stays
/// idle, up to 64 times this, after which it halts until its tick.
pub(super) const LINUX_SMP_IDLE_SPIN_TICKS: u64 = 50_000;

/// Runs process `pid`, ready and run by no other CPU, on this CPU, which
/// runs no process, until it waits, yields, is preempted or exits; then
/// settles it and leaves the CPU with no process: an exit ends it
/// (`settle_linux_process_exit`), anything else puts it back among the
/// ready ones. A fork it asks for is made on the way and the process goes
/// on, as Linux runs a fork's parent first: the child waits in the run
/// queue for a scheduler loop to take it. Every scheduler loop, the boot
/// CPU's and the application processors', runs processes here.
fn run_linux_process_on_this_cpu(pid: u32) -> bool {
    run_linux_process_here(pid) != LinuxRunOutcome::Failed
}

/// How a process run by a scheduler loop came back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxRunOutcome {
    /// It waits, yielded, was preempted or exited, and was settled.
    Settled,
    /// It is the domain's init and it ended: its state stays current on
    /// this CPU for the runtime's teardown.
    InitEnded,
    /// It could not be run or settled.
    Failed,
}

/// `run_linux_process_on_this_cpu`, saying whether the process was init and
/// ended (exited, or ended by a signal or a fault it could not handle):
/// that ends the runtime, which tears down from init's state, so it is left
/// current instead of being saved (its threads are gone, so a save would
/// keep nothing).
pub(super) fn run_linux_process_here(pid: u32) -> LinuxRunOutcome {
    let Some(mut selected) = linux_process::claim_live_process(pid) else {
        return LinuxRunOutcome::Failed;
    };
    if !restore_saved_linux_process_runtime_state(pid) || !restore_linux_process_extended_state(pid)
    {
        let _ = linux_process::release_live_process(pid);
        return LinuxRunOutcome::Failed;
    }
    X86_RUNTIME
        .LINUX_CURRENT_PROCESS_PID
        .store(pid, Ordering::SeqCst);
    let resumed = loop {
        let resumed = match linux_thread_turn(pid, &selected) {
            LinuxThreadTurn::Resume(tid) => {
                sync_live_linux_process_address_space(pid) && run_parked_linux_thread(pid, tid)
            }
            LinuxThreadTurn::Enter(dispatch) => {
                // With no thread parked in a call to end the process from
                // its wait, SIGKILL ends it here.
                let pending_sigkill = linux_peek_dynamic_signal(1 << (LINUX_SIGKILL - 1))
                    .is_some_and(|(_, pending)| u64::from(pending.signal) == LINUX_SIGKILL);
                if pending_sigkill {
                    linux_terminate_by_default_signal(LINUX_SIGKILL) == LINUX_RETURN_TO_KERNEL
                } else {
                    sync_live_linux_process_address_space(pid)
                        && run_dispatched_linux_process(&dispatch)
                }
            }
            LinuxThreadTurn::Blocked => {
                block_linux_process_threads(pid);
                break true;
            }
            LinuxThreadTurn::Failed => false,
        };
        if !resumed {
            break resumed;
        }
        if X86_RUNTIME.LINUX_FORK_REQUESTED.load(Ordering::SeqCst) {
            // The parent of a fork goes on with the child's pid as its
            // result.
            if !execute_deferred_live_fork() {
                break false;
            }
        } else if !linux_process_continues_in_place(pid) {
            break resumed;
        }
        match linux_process::dispatch_live_process(pid) {
            Some(again) => selected = again,
            None => break false,
        }
    };
    if pid == 1
        && (X86_RUNTIME.ELF_PROBE_COMPLETED.load(Ordering::SeqCst)
            || !X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst))
    {
        return if resumed && linux_process::release_live_process(pid) {
            LinuxRunOutcome::InitEnded
        } else {
            LinuxRunOutcome::Failed
        };
    }
    // An exit (exit_group, a fatal signal) ends the threads still parked in
    // calls: each unwinds out of its call, and its activation ends.
    if linux_child_exited(pid) {
        unwind_parked_linux_threads(pid);
    }
    save_current_linux_process_runtime_state(pid);
    let saved = save_linux_process_extended_state(pid);
    let settled = match take_linux_child_exit(pid) {
        Some(status) => settle_linux_process_exit(pid, status),
        None => linux_process::release_live_process(pid),
    };
    leave_linux_process_bank(true);
    X86_RUNTIME
        .LINUX_CURRENT_PROCESS_PID
        .store(0, Ordering::SeqCst);
    if resumed && saved && settled {
        LinuxRunOutcome::Settled
    } else {
        LinuxRunOutcome::Failed
    }
}

/// What of process `pid`, current on this CPU, runs next.
enum LinuxThreadTurn {
    /// Thread `tid`'s system call, parked on its activation, goes on: its
    /// wait is over (woken, its deadline passed) or SIGKILL ends it there.
    Resume(u32),
    /// The process is entered at its registry context: its current thread,
    /// or a ready one made current.
    Enter(linux_process::LiveProcessDispatch),
    /// None of its threads can run here: they all wait.
    Blocked,
    Failed,
}

/// Picks what of process `pid`, current on this CPU, dispatched with
/// `selected` (its registry context, its current thread's), runs next: a
/// thread parked in a call whose wait is over first (the longest blocked;
/// the current thread, if any, is ready for later), then the current
/// thread, then a ready one in turn (docs/SCHEDULER.md, "Activations per
/// thread").
fn linux_thread_turn(pid: u32, selected: &linux_process::LiveProcessDispatch) -> LinuxThreadTurn {
    // Threads that waited the old way (on an application processor) are
    // looked at in their process's own bank.
    let _ = wake_linux_descriptor_waits();
    let _ = expire_linux_waits();
    let parked = linux_parked_threads(pid);
    if !parked.is_empty() {
        let now = linux_elapsed_nanoseconds().unwrap_or(0);
        let due = linux_process::due_live_thread(pid, now)
            .filter(|tid| parked.contains(tid))
            .or_else(|| linux_process_killed(pid).then(|| parked[0]));
        if let Some(tid) = due {
            let Some(handle) = linux_thread_handle_by_tid(u64::from(tid)) else {
                return LinuxThreadTurn::Failed;
            };
            if !ready_current_linux_thread(
                selected.general,
                selected.rip,
                selected.rsp,
                selected.rflags,
            ) || !unpark_linux_thread(handle)
            {
                return LinuxThreadTurn::Failed;
            }
            let _ = linux_process::take_live_thread_block(pid, tid);
            return LinuxThreadTurn::Resume(tid);
        }
    }
    if current_linux_thread_slot().is_some() {
        return LinuxThreadTurn::Enter(*selected);
    }
    let Some((ready, (general, rip, rsp, rflags, fs_base))) = ready_linux_thread_handle()
        .and_then(|ready| Some((ready, linux_thread_entry_context(ready)?)))
    else {
        // A process with no thread table yet is entered as dispatched; one
        // whose threads all wait, or run on other CPUs, has nothing to run
        // here (entering its registry's context with no thread current
        // would run a thread that is not this CPU's).
        let threads = (0..LINUX_THREAD_LIMIT).any(|slot| {
            X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_FREE
        });
        return if threads {
            LinuxThreadTurn::Blocked
        } else {
            LinuxThreadTurn::Enter(*selected)
        };
    };
    if !linux_process::set_live_process_thread_context(pid, general, rip, rsp, rflags, fs_base)
        || !switch_linux_thread(ready)
    {
        return LinuxThreadTurn::Failed;
    }
    linux_process::dispatch_live_process(pid)
        .map_or(LinuxThreadTurn::Failed, LinuxThreadTurn::Enter)
}

/// Process `pid`, current on this CPU, none of whose threads can run here,
/// waits as a whole: on what its parked threads and those that waited the
/// old way wait for. With a thread running on another CPU it has work,
/// and is passed over by no one.
fn block_linux_process_threads(pid: u32) {
    match linux_other_threads_wait() {
        Some(others) => {
            let now = linux_elapsed_nanoseconds().unwrap_or(0);
            linux_process::block_live_process_threads(pid, others, now);
        }
        None => linux_process::set_live_process_waiting(pid, true),
    }
}

/// Whether process `pid`, which came back to the kernel from this CPU (a
/// yield, a preemption, a thread that parked or ended) and is ready, goes
/// on in place: nothing else is ready to take the CPU, so its kernel state
/// stays in this CPU's bank rather than being saved and restored again at
/// once (docs/SCHEDULER.md, step 5), and its next thread runs. It does not
/// when it exited, waits, stopped, ends the runtime (init), or the runtime
/// is to suspend.
fn linux_process_continues_in_place(pid: u32) -> bool {
    if X86_RUNTIME.LINUX_RUNTIME_SUSPENDED.load(Ordering::Acquire)
        || X86_RUNTIME
            .LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED
            .load(Ordering::Acquire)
        || linux_child_exited(pid)
        || pid == 1
            && (X86_RUNTIME.ELF_PROBE_COMPLETED.load(Ordering::SeqCst)
                || !X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst))
        || linux_process::live_process_status(pid)
            .is_none_or(|status| status.state != linux_process::LiveProcessState::Running)
        // sched_setaffinity excluded this CPU: the process moves to one it
        // allows at once, as Linux migrates it, rather than going on here
        // (getcpu01).
        || linux_process::live_process_cpu_affinity(pid)
            .is_some_and(|mask| mask & (1_u64 << linux_cpu_slot()) == 0)
    {
        return false;
    }
    // Other CPUs' system calls go first, as between the loop's rounds; what
    // they woke is ready before this one decides.
    crate::sync::kernel_entry_yield();
    deliver_linux_wakeups();
    let now = linux_elapsed_nanoseconds().unwrap_or(0);
    !linux_process::other_live_process_ready(pid, now)
}

/// Ends process `pid`, current on this CPU, which exited with `status`: its
/// parent gets SIGCHLD and a zombie to reap, and everything it held goes.
/// The CPU is left with no process.
pub(super) fn settle_linux_process_exit(pid: u32, status: u8) -> bool {
    // The save before made them leave; nothing of the process may still
    // run anywhere once its memory goes.
    wait_for_linux_process_threads_to_leave(pid);
    linux_end_pid_namespace(pid);
    // The process leaves its mount namespace before its record may go
    // with its runtime slot.
    let mount_namespace =
        linux_process_runtime_state(pid).and_then(|state| state.mount_namespace.take());
    let process_slot = linux_process::live_process_slot(pid);
    let parent = linux_process::live_process_parent_pid(pid);
    let signals_cleared = process_slot
        .is_some_and(|slot| clear_linux_signal_queues_for_process(linux_signal_instance(), slot));
    let child_signal_queued =
        parent.is_some_and(|parent| linux_signal_child_exit(parent, pid, status));
    let exited = signals_cleared
        && child_signal_queued
        && linux_process::complete_live_process_exit_detached(pid, status);

    linux_release_process_cgroup(pid);
    release_linux_process_shared_mappings(pid);
    release_linux_process_keys(pid);
    linux_fanotify_exit(pid);
    if let Some(state) = linux_process_runtime_state(pid) {
        release_linux_process_descriptors(pid, state);
        *state = LinuxProcessRuntimeState::EMPTY;
    }
    if let Some(namespace) = mount_namespace {
        linux_release_mount_namespace(namespace);
    }
    if let Some(threads) = linux_process_thread_runtime_state(pid) {
        threads.fill(LinuxThreadRuntimeState::EMPTY);
    }
    discard_linux_process_extended_state(pid);
    wake_linux_descriptor_waits();
    // What it held (descriptors, locks, memory) went: waits on those look
    // again.
    crate::linux_wait_queue::note_state_change();
    // A domain exec's command that ends gives the console back, and the
    // domain goes back to the background: the loop suspends it at its next
    // scheduling point (`suspend_linux_runtime_from_loop`), with every other
    // process where it was. What the domain does with the console meanwhile
    // (a shell polling its standard input, which only a read would suspend
    // on) must not keep the controller from its prompt.
    if let Some(slot) = active_container_slot() {
        if X86_RUNTIME.CONTAINER_EXEC_CHILD[slot]
            .compare_exchange(pid, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].store(false, Ordering::Release);
            X86_RUNTIME
                .LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED
                .store(true, Ordering::Release);
        }
    }
    exited && release_linux_process_runtime_slot(pid)
}

pub(crate) fn execute_cross_cpu_runtime_operation(operation: u64) -> bool {
    let slot = (operation >> 8) as crate::linux_socket::SlotId;
    match operation & 0xff {
        CROSS_CPU_RUNTIME_SIGNAL => crate::linux_signal::enqueue(
            linux_process::current_ipc_instance(),
            crate::linux_signal::Scope::Process,
            linux_process::PROCESS_LIMIT - 1,
            crate::linux_signal::Pending {
                signal: 10,
                code: -1,
                value: CROSS_CPU_RUNTIME_KEY,
                sender_pid: 2,
                sender_uid: 0,
            },
            false,
        )
        .is_ok_and(|queued| queued),
        // The waiter is a thread of the process the boot CPU runs: this
        // CPU wakes it from that process's bank (the operation's argument),
        // as a light thread of the process would.
        CROSS_CPU_RUNTIME_FUTEX_WAKE => {
            let bank = &LINUX_CPU_BANK[linux_bank_cpu()][linux_execution_instance()];
            let previous = bank.swap((operation >> 8) as u8, Ordering::AcqRel);
            let woken = wake_linux_futex(CROSS_CPU_RUNTIME_KEY, 1) == 1;
            bank.store(previous, Ordering::Release);
            woken
        }
        CROSS_CPU_RUNTIME_SOCKET_SEND => {
            crate::linux_socket::send(slot, b"socket-smp", None) == Ok(10)
        }
        CROSS_CPU_RUNTIME_PIPE_SEND => crate::linux_socket::send(slot, b"pipe-smp", None) == Ok(8),
        CROSS_CPU_RUNTIME_SCHEDULE => scheduler::schedule_process_on_current_cpu_for_test(),
        _ => false,
    }
}

pub(super) fn switch_linux_thread(handle: LinuxThreadHandle) -> bool {
    let slot = usize::from(handle.slot);
    let Some(context) = linux_thread_context(handle) else {
        return false;
    };
    if X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_READY {
        return false;
    }
    let prior = X86_RUNTIME.LINUX_CURRENT_THREAD_SLOT.load(Ordering::SeqCst);
    if prior != LINUX_THREAD_SLOT_NONE {
        let prior = usize::from(prior);
        if prior >= LINUX_THREAD_LIMIT
            || X86_RUNTIME.LINUX_THREAD_STATES[prior].load(Ordering::SeqCst) != LINUX_THREAD_RUNNING
            || X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
                && !switch_linux_thread_extended_state(prior, slot)
        {
            return false;
        }
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[prior].store(
            X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
        X86_RUNTIME.LINUX_THREAD_STATES[prior].store(LINUX_THREAD_READY, Ordering::SeqCst);
        linux_charge_thread_cpu(prior);
    } else if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        // A thread that blocked saved its extended state, and a timer may
        // have preempted it with live vector registers; it resumes on that
        // state rather than on whatever the last thread left.
        if !restore_linux_thread_extended_state(current_linux_process_pid(), slot) {
            return false;
        }
    } else if !reset_extended_user_state() {
        return false;
    }
    if !install_linux_tls_context(context) {
        return false;
    }
    if linux_light_thread_here().is_none() {
        X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.store(
            X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
    // Whatever call kept the thread for the owner runs now.
    X86_RUNTIME.LINUX_THREAD_OWNER_ONLY[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_RUNNING, Ordering::SeqCst);
    linux_mark_thread_cpu();
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(handle.slot, Ordering::SeqCst);
    true
}

/// A thread takes this CPU: its CPU time runs from now.
pub(super) fn linux_mark_thread_cpu() {
    LINUX_THREAD_CPU_MARK[linux_cpu_slot()].store(timer::timestamp_counter(), Ordering::Relaxed);
}

/// Thread `slot` leaves this CPU: the cycles since it took the CPU are
/// its, as Linux charges a task at the switch. That is a context switch,
/// and a migration when the thread ran elsewhere the time before.
pub(super) fn linux_charge_thread_cpu(slot: usize) {
    let mark = LINUX_THREAD_CPU_MARK[linux_cpu_slot()].swap(0, Ordering::Relaxed);
    let now = timer::timestamp_counter();
    if mark == 0 || now <= mark || slot >= LINUX_THREAD_LIMIT {
        return;
    }
    crate::cpu_time::note(crate::cpu_time::TaskEvent::ContextSwitch);
    let cpu = linux_cpu_slot() as u64 + 1;
    let last = X86_RUNTIME.LINUX_THREAD_LAST_CPUS[slot].swap(cpu, Ordering::Relaxed);
    if last != 0 && last != cpu {
        crate::cpu_time::note(crate::cpu_time::TaskEvent::Migration);
    }
    X86_RUNTIME.LINUX_THREAD_CPU_CYCLES[slot].fetch_add(now - mark, Ordering::SeqCst);
}

/// The CPU time thread `slot` of the current process has used, in
/// timestamp-counter cycles, the running interval of the current thread
/// included.
pub(super) fn linux_thread_cpu_cycles(slot: usize) -> u64 {
    let cycles = X86_RUNTIME.LINUX_THREAD_CPU_CYCLES[slot].load(Ordering::SeqCst);
    if current_linux_thread_slot() != Some(slot) {
        return cycles;
    }
    let mark = LINUX_THREAD_CPU_MARK[linux_cpu_slot()].load(Ordering::Relaxed);
    let now = timer::timestamp_counter();
    if mark == 0 || now <= mark {
        return cycles;
    }
    cycles.saturating_add(now - mark)
}

/// The current thread's nice value plus 20: its slot's, or the process's
/// for a process with no thread table yet.
pub(super) fn current_linux_thread_nice() -> u8 {
    current_linux_thread_slot().map_or_else(
        || X86_RUNTIME.ELF_PROBE_NICE.load(Ordering::SeqCst),
        |slot| X86_RUNTIME.LINUX_THREAD_NICES[slot].load(Ordering::SeqCst),
    )
}

/// The timer ticks the current thread runs before it is preempted: the nice
/// 0 slice scaled by its nice's weight, between a tick and ten times the
/// slice (nice05: the lower nice thread of two pinned to one CPU runs more).
fn linux_thread_slice_ticks() -> u32 {
    let weight = LINUX_NICE_WEIGHTS[usize::from(current_linux_thread_nice().min(39))];
    (LINUX_PROCESS_SLICE_TICKS.saturating_mul(weight) / LINUX_NICE_WEIGHTS[20])
        .clamp(1, LINUX_PROCESS_SLICE_TICKS * 10)
}

/// A process the timer preempted: its exact registers at the interrupted
/// instruction (rax..r15 in `process_general` order), kept until it reaches
/// the preemption entry and reports in.
#[derive(Clone, Copy)]
pub(super) struct LinuxPreemptedContext {
    pub(super) pid: u32,
    pub(super) general: [u64; 15],
    pub(super) rip: u64,
    pub(super) rsp: u64,
    pub(super) rflags: u64,
    /// Interrupted to take a signal rather than to give up the CPU.
    pub(super) signal: bool,
}

/// Ticks between looks at the signal queues of a process running user code;
/// the pending set and the real timer are checked on every tick.
const LINUX_SIGNAL_QUEUE_CHECK_TICKS: u32 = 10;

/// Whether the process running user code has a signal to take: its real
/// timer has expired, or a signal it does not block is pending. Linux
/// delivers it on return from the interrupt; the process may never make
/// another system call (a busy loop waiting for SIGALRM, or one to stop with
/// SIGINT).
fn linux_signal_due_from_timer(check_queues: bool) -> bool {
    // The interval timer's deadline and the earliest POSIX timer's: either
    // passing means a signal to queue and deliver.
    let timer_due = |deadline: u64| {
        deadline != 0 && linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline)
    };
    let requested = !X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst);
    timer_due(
        X86_RUNTIME
            .ELF_PROBE_REAL_TIMER_DEADLINE
            .load(Ordering::SeqCst),
    ) || timer_due(
        X86_RUNTIME
            .ELF_PROBE_POSIX_TIMER_DEADLINE
            .load(Ordering::SeqCst),
    ) || X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst) & requested != 0
        || check_queues && linux_peek_dynamic_signal(requested).is_some()
}

/// Per CPU, the context of the process its timer just sent to the vDSO's
/// preemption entry, which that process's next system call there (on the
/// same CPU) takes.
pub(super) static LINUX_PREEMPTED_CONTEXT: [crate::sync::IrqSpinLock<
    Option<LinuxPreemptedContext>,
>; CPU_ENTRY_STATE_LIMIT] =
    [const { crate::sync::IrqSpinLock::new(crate::sync::LockRank::SCHEDULER, None) };
        CPU_ENTRY_STATE_LIMIT];
/// Per CPU, the timer ticks its current process has run since it was last
/// entered.
pub(super) static LINUX_PROCESS_SLICE: [AtomicU32; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU32::new(0) }; CPU_ENTRY_STATE_LIMIT];
/// Per CPU, the deadline of the due sleeper its tick last ended a slice
/// early for (`linux_sleeper_due_from_timer`).
static LINUX_WAKEUP_PREEMPTED_DEADLINE: [AtomicU64; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU64::new(0) }; CPU_ENTRY_STATE_LIMIT];

/// Whether a process marked asleep has reached its deadline, and this CPU's
/// tick has not yet ended a slice for that deadline: wakeup preemption.
/// A marked sleeper runs again at a scheduling point, and a process this
/// CPU runs for a whole slice would otherwise hold that off for up to its
/// slice, 50 ms (sleeps woke up to
/// 24 ms late). Once per deadline: if the yield's scheduler runs another
/// process first, the sleeper waits for the next scheduling point, not a
/// slice ended on every tick.
fn linux_sleeper_due_from_timer() -> bool {
    // User code never holds the lock; held or wanted by another CPU, that
    // CPU is in the kernel and the next tick looks again.
    let Some(_guard) = crate::sync::kernel_entry_try_lock() else {
        return false;
    };
    let Some(now) = linux_elapsed_nanoseconds() else {
        return false;
    };
    let Some(deadline) =
        linux_process::next_live_block_deadline().filter(|deadline| *deadline <= now)
    else {
        return false;
    };
    LINUX_WAKEUP_PREEMPTED_DEADLINE[linux_cpu_slot()].swap(deadline, Ordering::SeqCst) != deadline
}

/// Ticks between looks, from the timer, for a thread of the running
/// process that a waker made due while it ran (a futex wake of a sibling).
const LINUX_THREAD_WAKE_CHECK_TICKS: u32 = 4;

/// Whether a thread of the process this CPU runs, parked in a call, was
/// woken (or its deadline passed) while another thread of it runs: the
/// slice ends early so the scheduler resumes it, as Linux preempts for a
/// woken task, instead of after a whole slice. Looked at every few ticks.
fn linux_thread_woken_from_timer(ticks: u32) -> bool {
    if !ticks.is_multiple_of(LINUX_THREAD_WAKE_CHECK_TICKS) {
        return false;
    }
    let Some(_guard) = crate::sync::kernel_entry_try_lock() else {
        return false;
    };
    let pid = current_linux_process_pid();
    pid != 0
        && linux_process::due_live_thread(pid, linux_elapsed_nanoseconds().unwrap_or(0)).is_some()
}

/// This CPU's entry in a per-CPU table.
pub(super) fn linux_cpu_slot() -> usize {
    current_cpu_index_checked()
        .filter(|cpu| *cpu < CPU_ENTRY_STATE_LIMIT)
        .unwrap_or(0)
}

/// An application processor's timer tick (its own local APIC, armed while it
/// runs a domain runtime's processes): the boot CPU's tick does the
/// domain's timekeeping; this one only preempts the process this CPU runs
/// once its slice is used, so a CPU-bound process here gives the CPU up
/// as it would on the boot CPU (a forked child running inside its parent's
/// fork lets the parent go on).
pub(crate) fn linux_application_processor_tick(frame: &mut UserInterruptFrame) {
    if frame
        .user_context(USER_CODE_SELECTOR, USER_DATA_SELECTOR)
        .is_none()
    {
        return;
    }
    let _kernel_entry = crate::sync::kernel_entry_lock();
    if !linux_smp_runtime_active() {
        return;
    }
    match current_cpu_index_checked()
        .filter(|cpu| *cpu < CPU_ENTRY_STATE_LIMIT)
        .and_then(|cpu| linux_light_thread_here().map(|(bank, _)| (cpu, bank)))
    {
        Some((cpu, bank)) => linux_preempt_light_thread_from_timer(cpu, bank, frame),
        None => {
            // The process this CPU owns has its blocked threads' waits
            // checked here, as the boot CPU's tick checks its own: a pipe
            // read whose writer went away while every thread kept a CPU busy
            // was never woken (dirtyc0w_shmem's popen of zcat).
            let _ = wake_linux_descriptor_waits() + expire_linux_waits();
            linux_preempt_process_from_timer(frame)
        }
    }
}

/// Called on a timer tick that interrupted user mode: when a process has
/// used its slice (every process, init too, is entered by a scheduler
/// loop, which takes the yield), saves the exact interrupted registers and
/// sends the process to the vDSO's preemption entry, whose system call
/// yields it (`linux_complete_timer_preemption`). Linux preempts at the
/// tick itself; doing it through a system call reuses the normal
/// return-to-kernel path.
pub(super) fn linux_preempt_process_from_timer(frame: &mut UserInterruptFrame) {
    // On an application processor too: a process it runs as the owner
    // (run_linux_process_on_this_cpu) is yielded to its loop, and one
    // pinned there with a busy thread current otherwise keeps the CPU from
    // its other threads for good (nice05's two busy threads and main thread
    // on one CPU).
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return;
    }
    let Some(mut context) = frame.user_context(USER_CODE_SELECTOR, USER_DATA_SELECTOR) else {
        return;
    };
    let ticks = LINUX_PROCESS_SLICE[linux_cpu_slot()].fetch_add(1, Ordering::SeqCst) + 1;
    let signal_due = !X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst)
        && linux_signal_due_from_timer(ticks.is_multiple_of(LINUX_SIGNAL_QUEUE_CHECK_TICKS));
    if ticks < linux_thread_slice_ticks()
        && !signal_due
        && !linux_sleeper_due_from_timer()
        && !linux_thread_woken_from_timer(ticks)
    {
        return;
    }
    let pid = current_linux_process_pid();
    let Some(entry) = crate::linux_elf::vdso_preempt_entry() else {
        return;
    };
    let signal = X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst);
    // A process nobody can take the yield of still lets a ready sibling
    // thread have the CPU: the switch stays inside the process (a busy
    // thread on the owner's path otherwise kept the thread the registry
    // holds, which only the owner runs, from ever running: dirtyc0w_shmem's
    // eight busy threads).
    let preemptible = linux_preemption_yield_taken(pid) || ready_linux_thread_handle().is_some();
    if (entry..entry + 9).contains(&context.rip) || !signal_due && (!preemptible || signal) {
        return;
    }
    let preempted = LinuxPreemptedContext {
        pid,
        general: [
            context.rax,
            context.rbx,
            context.rcx,
            context.rdx,
            context.rsi,
            context.rdi,
            context.rbp,
            context.r8,
            context.r9,
            context.r10,
            context.r11,
            context.r12,
            context.r13,
            context.r14,
            context.r15,
        ],
        rip: context.rip,
        rsp: context.rsp,
        rflags: context.rflags,
        signal: signal_due,
    };
    context.rip = entry;
    if frame.restore_user_context(context, USER_CODE_SELECTOR, USER_DATA_SELECTOR) {
        *LINUX_PREEMPTED_CONTEXT[linux_cpu_slot()].lock() = Some(preempted);
        if !signal_due {
            LINUX_PROCESS_SLICE[linux_cpu_slot()].store(0, Ordering::SeqCst);
        }
    }
}

/// Whether a timer preemption of process `pid` can yield it: a runtime's
/// processes are all entered by a scheduler loop, which takes the yield,
/// except a child still in its parent's memory (a vfork child, until it
/// executes or exits).
pub(super) fn linux_preemption_yield_taken(pid: u32) -> bool {
    X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && linux_light_thread_here().is_none()
        && !linux_process::live_process_shares_parent_vm(pid)
}

/// The preemption entry's system call (`user_rip` just after it): records
/// the context the timer saved as the process's own and yields it, so the
/// scheduler resumes it later at the interrupted instruction. None if no
/// preemption is pending for this process there.
pub(super) fn linux_complete_timer_preemption(
    output: *mut LinuxSyscallFrame,
    user_rip: u64,
) -> Option<u64> {
    let entry = crate::linux_elf::vdso_preempt_entry()?;
    if user_rip != entry + 7 {
        return None;
    }
    let pid = current_linux_process_pid();
    let preempted = {
        let mut pending = LINUX_PREEMPTED_CONTEXT[linux_cpu_slot()].lock();
        pending.filter(|preempted| preempted.pid == pid)?;
        pending.take()?
    };
    if let Some((bank, slot)) = linux_light_thread_here() {
        if LINUX_BANK_DYING[bank].load(Ordering::Acquire) {
            X86_RUNTIME
                .LINUX_CURRENT_THREAD_SLOT
                .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
            return Some(LINUX_RETURN_TO_KERNEL);
        }
        let handle = linux_thread_handle(slot)?;
        return Some(park_linux_light_thread_exact(
            handle,
            preempted.general,
            preempted.rip,
            preempted.rsp,
            preempted.rflags,
            false,
        ));
    }
    if preempted.signal {
        return Some(linux_deliver_signal_to_interrupted(output, &preempted));
    }
    // A sibling thread kept for the owner (its call is not for the light
    // path) takes the CPU from the preempted thread, as a thread switch on
    // one CPU would: dispatching the process again resumes the thread the
    // timer interrupted, so with a busy thread current a thread waiting for
    // the owner never ran (nice05's main thread sleeping while its two busy
    // threads, pinned with it to one CPU, kept that CPU's owner path).
    if let Some(result) = linux_preempted_owner_switches_to_kept_thread(output, &preempted) {
        return Some(result);
    }
    // With nobody to take a yield, or nothing else ready to take the CPU,
    // the process carries on where the tick interrupted it.
    let recorded = linux_preemption_yield_taken(pid)
        && {
            deliver_linux_wakeups();
            let now = linux_elapsed_nanoseconds().unwrap_or(0);
            // Another process to run, or a thread of this one parked in a
            // call whose wait is over.
            linux_process::other_live_process_ready(pid, now)
                || linux_process::due_live_thread(pid, now).is_some()
                || linux_process::live_process_cpu_affinity(pid)
                    .is_some_and(|mask| mask & (1_u64 << linux_cpu_slot()) == 0)
        }
        && linux_process::set_live_process_thread_context(
            pid,
            preempted.general,
            preempted.rip,
            preempted.rsp,
            preempted.rflags,
            active_fs_base(),
        );
    if !recorded {
        // Carry on where the tick interrupted the process instead.
        return Some(
            if write_linux_exact_live_return(
                output,
                preempted.general,
                preempted.rip,
                preempted.rsp,
                preempted.rflags,
            ) {
                LINUX_RETURN_FROM_IRET
            } else {
                LINUX_EINVAL
            },
        );
    }
    Some(LINUX_RETURN_TO_KERNEL)
}

/// Per CPU, whether the last owner-path preemption there switched to a
/// sibling thread rather than yielding the process: the next yields.
pub(super) static LINUX_PREEMPTION_SWITCHED: [AtomicBool; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicBool::new(false) }; CPU_ENTRY_STATE_LIMIT];

/// A ready thread of the current process kept for the owner, after the
/// current slot in a round robin, with a saved context to resume.
pub(super) fn kept_ready_linux_thread_handle() -> Option<LinuxThreadHandle> {
    let after = current_linux_thread_slot().unwrap_or(0);
    (1..=LINUX_THREAD_LIMIT).find_map(|offset| {
        let slot = after.wrapping_add(offset) % LINUX_THREAD_LIMIT;
        (X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_READY
            && X86_RUNTIME.LINUX_THREAD_OWNER_ONLY[slot].load(Ordering::SeqCst) != 0)
            .then(|| linux_thread_handle(slot))
            .flatten()
            .filter(|handle| linux_thread_return_context(*handle).is_some())
    })
}
