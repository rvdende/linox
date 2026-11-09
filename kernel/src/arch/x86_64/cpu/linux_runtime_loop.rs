#![forbid(unsafe_code)]
use super::*;

pub(crate) fn execute_linux_process_child(
    entry: usize,
    stack: usize,
    fs_base: u64,
    general: [u64; 15],
) -> Option<u8> {
    let cpu = current_cpu_index();
    let entry_valid = entry != 0 && entry < 1 << 47;
    let stack_valid = stack != 0 && stack < 1 << 47;
    let fs_valid = fs_base < 1 << 47;
    let fork_return_valid = general[0] == 0;
    let scheduler_idle = scheduler::current_domain().is_none();
    // The gate is installed before APs enter userspace. Avoid rewriting every
    // CPU's IDT while another CPU may already be executing the same path.
    let gate_installed = user_interrupt_surface_is_minimal()
        || install_user_interrupt_gate(SYSCALL_VECTOR, EntryStub::native_system_call());
    let interrupt_surface_valid = user_interrupt_surface_is_minimal();
    let preconditions = u8::from(entry_valid)
        | (u8::from(stack_valid) << 1)
        | (u8::from(fs_valid) << 2)
        | (u8::from(fork_return_valid) << 3)
        | (u8::from(scheduler_idle) << 4)
        | (u8::from(gate_installed) << 5)
        | (u8::from(interrupt_surface_valid) << 6);
    X86_RUNTIME
        .PROCESS_CHILD_EXECUTION_DIAGNOSTIC
        .get(cpu)?
        .store(preconditions, Ordering::SeqCst);
    if preconditions != 0x7f {
        return None;
    }
    let saved_fs = active_fs_base();
    let _ = msr::set_fs_base(fs_base);
    if active_fs_base() != fs_base {
        let _ = msr::set_fs_base(saved_fs);
        return None;
    }
    for (expected, value) in X86_RUNTIME
        .PROCESS_CHILD_EXPECTED_REGISTERS
        .get(cpu)?
        .iter()
        .zip(general)
    {
        expected.store(value, Ordering::SeqCst);
    }
    X86_RUNTIME
        .PROCESS_CHILD_EXPECTED_FS_BASE
        .get(cpu)?
        .store(fs_base, Ordering::SeqCst);
    X86_RUNTIME
        .PROCESS_CHILD_CONTEXT_VALID
        .get(cpu)?
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .PROCESS_CHILD_EXIT_STATUS
        .get(cpu)?
        .store(0, Ordering::SeqCst);
    if X86_RUNTIME
        .PROCESS_CHILD_PROBE_STATE
        .get(cpu)?
        .compare_exchange(
            PROCESS_CHILD_PROBE_IDLE,
            PROCESS_CHILD_PROBE_EXPECT_CONTEXT,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_err()
    {
        let _ = msr::set_fs_base(saved_fs);
        return None;
    }
    // SAFETY: The caller has activated a root containing the validated RX
    // entry, writable stack, supervisor kernel mappings, and TSS stack. The
    // process entry stub installs the complete saved general-register array,
    // including the validated Linux fork-child RAX value. The first INT 0x80
    // validates that frame and returns to ring 3. A subsequent Linux exit(2)
    // trap captures its status and returns to the saved kernel stack because no
    // global native scheduler runtime is active.
    enter_linux_runtime_process(entry, stack, &general, 0x202);
    let child_fs_preserved = active_fs_base() == fs_base;
    let probe_state = X86_RUNTIME
        .PROCESS_CHILD_PROBE_STATE
        .get(cpu)?
        .swap(PROCESS_CHILD_PROBE_IDLE, Ordering::SeqCst);
    let context_valid = X86_RUNTIME
        .PROCESS_CHILD_CONTEXT_VALID
        .get(cpu)?
        .swap(false, Ordering::SeqCst);
    let exit_status = X86_RUNTIME
        .PROCESS_CHILD_EXIT_STATUS
        .get(cpu)?
        .swap(0, Ordering::SeqCst);
    let _ = msr::set_fs_base(saved_fs);
    let fs_restored = active_fs_base() == saved_fs;
    X86_RUNTIME.PROCESS_CHILD_EXECUTION_DIAGNOSTIC[cpu].store(
        0x80 | u8::from(child_fs_preserved)
            | (u8::from(context_valid) << 1)
            | (u8::from(probe_state == PROCESS_CHILD_PROBE_COMPLETE) << 2)
            | (u8::from(fs_restored) << 3)
            | (u8::from(exit_status == 42) << 4),
        Ordering::SeqCst,
    );
    (child_fs_preserved
        && context_valid
        && probe_state == PROCESS_CHILD_PROBE_COMPLETE
        && fs_restored)
        .then_some(exit_status)
}

pub(crate) fn resume_live_linux_process(
    entry: usize,
    stack: usize,
    fs_base: u64,
    general: [u64; 15],
    rflags: u64,
) -> bool {
    if entry == 0 || entry >= 1 << 47 || stack == 0 || stack >= 1 << 47 || fs_base >= 1 << 47 {
        return false;
    }
    if general[0] == LINUX_RETURN_TO_KERNEL {
        serial_write("linox: resuming pid ");
        serial_write_u64(u64::from(current_linux_process_pid()));
        serial_write(" at rip ");
        serial_write_u64(entry as u64);
        serial_write(" with the kernel's return-to-kernel marker as its result\r\n");
        write_linux_runtime_syscall_trace();
    }
    let saved_fs = active_fs_base();
    let _ = msr::set_fs_base(fs_base);
    if active_fs_base() != fs_base {
        let _ = msr::set_fs_base(saved_fs);
        return false;
    }
    // SAFETY: The caller activated the generation-checked process root and
    // validated this complete return context against its private mappings.
    // A terminating or deferred Linux syscall returns through the saved kernel
    // stack installed by this entry stub.
    enter_linux_runtime_process(entry, stack, &general, rflags);
    let returned_fs = active_fs_base();
    // A runtime process that came back to the kernel (an exit, an exec, a
    // fork, a yield or a preemption) may have left another thread current,
    // or set its own thread pointer: any user address will do, and its next
    // entry loads the one its context names.
    let preserved = returned_fs == fs_base
        || X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && returned_fs < 1 << 47;
    let _ = msr::set_fs_base(saved_fs);
    let restored = active_fs_base() == saved_fs;
    if !preserved
        && (X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
            || cfg!(feature = "verification-boot"))
    {
        serial_write("linox: Linux resume FS mismatch expected/returned/saved/restored: ");
        for value in [fs_base, returned_fs, saved_fs, u64::from(restored)] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
    }
    preserved && restored
}

#[allow(dead_code)]
pub(crate) fn reset_process_child_execution_diagnostic() {
    let cpu = current_cpu_index();
    X86_RUNTIME
        .PROCESS_CHILD_EXECUTION_DIAGNOSTIC
        .get(cpu)
        .expect("current processor index is bounded")
        .store(0, Ordering::SeqCst);
}

pub(super) fn ready_linux_thread_handle() -> Option<LinuxThreadHandle> {
    if linux_light_thread_here().is_some() {
        return None;
    }
    let after = current_linux_thread_slot().unwrap_or_else(|| {
        usize::from(
            X86_RUNTIME
                .LINUX_LAST_PREEMPTED_THREAD_SLOT
                .load(Ordering::Acquire),
        )
    });
    (1..=LINUX_THREAD_LIMIT).find_map(|offset| {
        let slot = after.wrapping_add(offset) % LINUX_THREAD_LIMIT;
        (X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_READY)
            .then(|| linux_thread_handle(slot))
            .flatten()
            .filter(|handle| linux_thread_return_context(*handle).is_some())
    })
}

/// Whether a thread that must wait in a system call here parks on its own
/// activation (docs/SCHEDULER.md, "Activations per thread"): on the boot
/// CPU of a runtime. Its siblings run meanwhile, each entered on an
/// activation of its own. Elsewhere (an application processor, the boot
/// probe) it waits as a thread wait, handing the CPU to a ready sibling.
pub(super) fn linux_threads_park_here() -> bool {
    X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && current_linux_runtime_cpu_index() == 0
        && linux_light_thread_here().is_none()
}

/// The ready sibling a thread that must wait hands the CPU to, waiting as
/// a thread wait: none where threads park instead
/// (`linux_threads_park_here`).
pub(super) fn linux_thread_wait_handoff() -> Option<LinuxThreadHandle> {
    if linux_threads_park_here() {
        return None;
    }
    ready_linux_thread_handle()
}

pub(super) fn yield_ready_linux_thread_handle() -> Option<LinuxThreadHandle> {
    if linux_light_thread_here().is_some() {
        return None;
    }
    // A timer-preempted thread has already consumed its current quantum.
    // Do not let a sibling's voluntary yield immediately hand the CPU back;
    // the next timer quantum will make it eligible through preemption. The
    // search starts after the yielding thread, so every ready thread gets a
    // turn; always taking the lowest slot let two threads alternate while
    // later ones starved.
    let last_preempted = X86_RUNTIME
        .LINUX_LAST_PREEMPTED_THREAD_SLOT
        .load(Ordering::Acquire);
    let after = current_linux_thread_slot().unwrap_or(usize::from(last_preempted));
    (1..=LINUX_THREAD_LIMIT).find_map(|offset| {
        let slot = after.wrapping_add(offset) % LINUX_THREAD_LIMIT;
        (slot != usize::from(last_preempted)
            && X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::Acquire) == LINUX_THREAD_READY)
            .then(|| linux_thread_handle(slot))
            .flatten()
            .filter(|handle| linux_thread_return_context(*handle).is_some())
    })
}

pub(super) fn block_current_linux_thread(kind: u8, key: u64, output: u64, deadline: u64) -> bool {
    let Some(slot) = current_linux_thread_slot() else {
        return false;
    };
    if !matches!(
        kind,
        LINUX_THREAD_WAIT_FUTEX
            | LINUX_THREAD_WAIT_SIGNAL
            | LINUX_THREAD_WAIT_SLEEP
            | LINUX_THREAD_WAIT_POLL
            | LINUX_THREAD_WAIT_EPOLL
            | LINUX_THREAD_WAIT_EVENTFD_READ
            | LINUX_THREAD_WAIT_PPOLL
            | LINUX_THREAD_WAIT_EPOLL_PWAIT
            | LINUX_THREAD_WAIT_PIPE_READ
            | LINUX_THREAD_WAIT_TIMERFD_READ
            | LINUX_THREAD_WAIT_PIPE_WRITE
            | LINUX_THREAD_WAIT_EVENTFD_WRITE
            | LINUX_THREAD_WAIT_PAUSE
            | LINUX_THREAD_WAIT_SIGSUSPEND
            | LINUX_THREAD_WAIT_SELECT
            | LINUX_THREAD_WAIT_PSELECT
            | LINUX_THREAD_WAIT_RETRY
    ) || key == 0
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_RUNNING
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_NONE
        || X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst) != 0
        || X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst) != 0
        || X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::SeqCst) != 0
    {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(key, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(output, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(deadline, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(kind, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_BLOCKED, Ordering::SeqCst);
    if deadline != 0 {
        // Publish the scan hint only after the blocked state and deadline are
        // both visible. Otherwise a timer interrupt can scan the partially
        // published wait, clear the hint, and leave this thread unwakeable.
        X86_RUNTIME
            .LINUX_TIMED_WAITS_ACTIVE
            .store(true, Ordering::Release);
        if let Some(now) = linux_elapsed_nanoseconds() {
            timer::request_linux_tick_within(deadline.saturating_sub(now));
        }
    }
    if matches!(
        kind,
        LINUX_THREAD_WAIT_POLL
            | LINUX_THREAD_WAIT_PPOLL
            | LINUX_THREAD_WAIT_EPOLL
            | LINUX_THREAD_WAIT_EPOLL_PWAIT
            | LINUX_THREAD_WAIT_SELECT
            | LINUX_THREAD_WAIT_PSELECT
            | LINUX_THREAD_WAIT_EVENTFD_READ
            | LINUX_THREAD_WAIT_EVENTFD_WRITE
            | LINUX_THREAD_WAIT_PIPE_READ
            | LINUX_THREAD_WAIT_PIPE_WRITE
            | LINUX_THREAD_WAIT_TIMERFD_READ
    ) {
        X86_RUNTIME
            .LINUX_DESCRIPTOR_WAITS_ACTIVE
            .store(true, Ordering::Release);
    }
    // The next thread to run may use the vector registers, so keep this
    // thread's until it resumes.
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let _ = save_linux_thread_extended_state(current_linux_process_pid(), slot);
    }
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
    true
}

/// A ring of recent futex events for the sixty-second snapshot: who waited
/// and who woke whom, with the CPU, to find a lost wakeup.
pub(super) const LINUX_FUTEX_TRACE_LIMIT: usize = 512;
pub(super) static LINUX_FUTEX_TRACE: [[AtomicU64; 4]; LINUX_FUTEX_TRACE_LIMIT] =
    [const { [const { AtomicU64::new(0) }; 4] }; LINUX_FUTEX_TRACE_LIMIT];
pub(super) static LINUX_FUTEX_TRACE_NEXT: AtomicU64 = AtomicU64::new(0);

/// Whether a thread of the current process runs on an application processor
/// outside a blocking wait (threads run there only in domains configured with
/// more than one CPU). Such a thread uses the domain's live thread table,
/// which holds whichever process is current, so the boot CPU must not switch
/// to another process (or another domain) until the thread blocks or exits.
/// A remote thread that is blocked keeps spinning on its slot, and gives the
/// slot up if it sees another process's thread there.
/// Whether system call `number` (fork, vfork, clone or clone3, with clone
/// flags `flags` or clone3 arguments at `arguments`) creates a process,
/// which runs at once in place of its parent.
pub(super) fn linux_syscall_creates_process(number: u64, flags: u64, arguments: u64) -> bool {
    match number {
        LINUX_FORK_SYSCALL | LINUX_VFORK_SYSCALL => true,
        LINUX_CLONE_SYSCALL => flags & LINUX_CLONE_THREAD == 0,
        LINUX_CLONE3_SYSCALL => {
            let mut bytes = [0_u8; size_of::<u64>()];
            copy_from_linux_user(arguments, &mut bytes)
                && u64::from_ne_bytes(bytes) & LINUX_CLONE_THREAD == 0
        }
        _ => false,
    }
}

/// What a blocking syscall does after letting other processes run.
pub(super) enum LinuxBlockedWait {
    /// Check the wait condition again in this call.
    Recheck,
    /// Return this result; it may resume another context.
    Return(u64),
}

/// Blocks the current thread in syscall `number` until `wait` ends: the
/// thread, of init too, parks in the call on its own activation and stays
/// parked until a waker for what it waits on, a signal or its deadline
/// ends its block (docs/SCHEDULER.md, step 5), and then looks at its wait
/// once more (`Recheck`). Its process runs on meanwhile while another of
/// its threads can, and leaves the run queue when none can. Where it
/// cannot park it yields with the call set to restart. Returns `None` when
/// it cannot wait here (an application processor's caller restarts or
/// waits as a thread wait).
pub(super) fn run_other_linux_processes(
    output: LinuxSyscallFrameHandle,
    caller: LinuxUserContext,
    number: u64,
    wait: WaitOn,
) -> Option<LinuxBlockedWait> {
    run_other_linux_processes_deferring(output, caller, number, wait, true)
}

/// `run_other_linux_processes`; with `defer_to_siblings` false, on an
/// application processor, the other processes run even while a sibling
/// thread is ready, which may itself be only waiting to retry its call.
/// On the boot CPU a thread always parks: its siblings run meanwhile.
pub(super) fn run_other_linux_processes_deferring(
    output: LinuxSyscallFrameHandle,
    caller: LinuxUserContext,
    number: u64,
    wait: WaitOn,
    defer_to_siblings: bool,
) -> Option<LinuxBlockedWait> {
    let _ = defer_to_siblings;
    // The boot verification probe has no scheduler loop to wait in.
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return None;
    }
    // A thread on the light path waits as the owner's thread: the call
    // goes to the owner.
    if linux_light_thread_here().is_some() {
        return Some(LinuxBlockedWait::Return(
            migrate_current_linux_thread_to_owner(caller, number),
        ));
    }
    // Only the boot CPU enters processes on activation stacks that can park;
    // an application processor's caller restarts or yields the call.
    if current_linux_runtime_cpu_index() != 0 {
        return None;
    }
    // Descriptor waits of threads that waited the old way (on an
    // application processor) made ready while another process ran complete
    // here, in this process's address space.
    let _ = wake_linux_descriptor_waits();
    let pid = current_linux_process_pid();
    // A signal that arrived while this call waited interrupts it (EINTR,
    // or a restart after an SA_RESTART handler), as in Linux, instead of
    // the call waiting again.
    let signal_was_active = X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst);
    let mut interrupted = caller;
    interrupted.rax = LINUX_EINTR;
    let delivered = linux_deliver_pending_signal_restarting(
        output,
        interrupted,
        (caller.rip, caller.rflags),
        Some(number),
    );
    if delivered != 0 {
        return Some(LinuxBlockedWait::Return(delivered));
    }
    if !signal_was_active && X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        return Some(LinuxBlockedWait::Return(0));
    }
    // Record the call set to restart, then park in it: the call keeps its
    // place and checks its wait again when the loop resumes it. Where it
    // cannot park, the call restarts from user mode instead.
    let mut restart = caller;
    restart.rip = caller.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
    if !yield_current_linux_process(restart, number) {
        return None;
    }
    // Waiting in the call, on the thread's own activation: blocked until
    // what it waits for comes. Its process waits as a whole (and /proc
    // shows it sleeping) only when none of its threads can run.
    match block_and_park_linux_thread(pid, restart, wait) {
        Some(activation::Wake::Continue) => {}
        // Its thread is ending: the call unwinds, back to the kernel.
        Some(activation::Wake::Unwind) => {
            return Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL));
        }
        None => {
            if LINUX_PARK_REFUSALS.fetch_add(1, Ordering::Relaxed) < 8 {
                serial_write("linox: thread cannot park pid/tid/cpu/call/activation: ");
                for value in [
                    u64::from(pid),
                    u64::from(current_linux_tid().unwrap_or(0)),
                    current_cpu_index_checked().unwrap_or(99) as u64,
                    number,
                    u64::from(linux_process_activation_running(pid)),
                ] {
                    serial_write_u64(value);
                    serial_write(" ");
                }
                serial_write("\r\n");
            }
            return Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL));
        }
    }
    // Resumed to be killed: SIGKILL ends the process from inside its
    // wait, as Linux's fatal signals wake a sleeping task to exit.
    if linux_peek_dynamic_signal(1 << (LINUX_SIGKILL - 1))
        .is_some_and(|(_, pending)| u64::from(pending.signal) == LINUX_SIGKILL)
    {
        return Some(LinuxBlockedWait::Return(linux_terminate_by_default_signal(
            LINUX_SIGKILL,
        )));
    }
    // A wait for children looks for them before a signal interrupts it,
    // as Linux's does: the exit signal of the child it waits for must not
    // end it with EINTR (clone301). A signal still pending when nothing
    // turns up interrupts the next round.
    if matches!(number, LINUX_WAIT4_SYSCALL | LINUX_WAITID_SYSCALL) {
        return Some(LinuxBlockedWait::Recheck);
    }
    // A sleep writes the time it has left before a signal interrupts
    // it (the next round delivers the signal first thing): asleep since
    // its last round, the time it wrote then was stale (nanosleep02).
    if matches!(
        number,
        LINUX_NANOSLEEP_SYSCALL | LINUX_CLOCK_NANOSLEEP_SYSCALL
    ) {
        return Some(LinuxBlockedWait::Recheck);
    }
    let mut interrupted = caller;
    interrupted.rax = LINUX_EINTR;
    let delivered = linux_deliver_pending_signal_restarting(
        output,
        interrupted,
        (caller.rip, caller.rflags),
        Some(number),
    );
    Some(if delivered != 0 {
        LinuxBlockedWait::Return(delivered)
    } else if X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        LinuxBlockedWait::Return(0)
    } else {
        LinuxBlockedWait::Recheck
    })
}

/// Blocks the current thread of process `pid` in its call for `wait`
/// (until its process's real or POSIX timer is due if sooner: only its
/// call notices those) and parks it on its activation; `restart` is the
/// call set to be issued again. The process blocks as a whole when none
/// of its other threads can run, on what all its threads wait for. None
/// when it could not park: the thread is current again, unblocked.
fn block_and_park_linux_thread(
    pid: u32,
    restart: LinuxUserContext,
    wait: WaitOn,
) -> Option<activation::Wake> {
    // A call never waits holding a spin lock: whoever runs meanwhile would
    // deadlock on it, and the call may continue on another CPU.
    if crate::sync::spin_lock_held() {
        serial_write("linox: a system call tried to park holding a spin lock; pid ");
        serial_write_u64(u64::from(pid));
        serial_write(" rank ");
        serial_write_u64(u64::from(crate::sync::held_rank()));
        serial_write("\r\n");
        return None;
    }
    let tid = current_linux_tid()?;
    let slot = current_linux_thread_slot()?;
    let block = wait
        .until(
            X86_RUNTIME
                .ELF_PROBE_REAL_TIMER_DEADLINE
                .load(Ordering::SeqCst),
        )
        .until(
            X86_RUNTIME
                .ELF_PROBE_POSIX_TIMER_DEADLINE
                .load(Ordering::SeqCst),
        );
    if !linux_process::block_live_thread(pid, tid, slot as u8, block) {
        return None;
    }
    if let Some(others) = linux_other_threads_wait() {
        let now = linux_elapsed_nanoseconds().unwrap_or(0);
        linux_process::block_live_process_threads(pid, others, now);
    }
    let Some(handle) = park_current_linux_thread(restart) else {
        let _ = linux_process::take_live_thread_block(pid, tid);
        linux_process::set_live_process_waiting(pid, false);
        return None;
    };
    let wake = park_linux_thread(pid, tid);
    if wake.is_none() {
        // It goes on as the current thread, with the call set to restart.
        let _ = linux_process::take_live_thread_block(pid, tid);
        linux_process::set_live_process_waiting(pid, false);
        let _ = unpark_linux_thread(handle);
    }
    wake
}

/// What the current process's threads other than the current one wait
/// for that only this process looks at (threads blocked the old way, on an
/// application processor: anything but a futex word only this process's
/// threads wake, a sleep and a signal wait is looked at again whenever
/// anything may have changed), with their deadlines. Threads parked in
/// calls of their own wait in the registry. None when another thread is
/// ready or runs on another CPU: the process has work, and is passed over
/// by no one.
pub(super) fn linux_other_threads_wait() -> Option<WaitOn> {
    let current = current_linux_thread_slot();
    let mut block = WaitOn::NOTHING;
    for slot in (0..LINUX_THREAD_LIMIT).filter(|slot| Some(*slot) != current) {
        match X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) {
            LINUX_THREAD_FREE | LINUX_THREAD_PARKED => {}
            LINUX_THREAD_BLOCKED if !linux_thread_runs_elsewhere(slot) => {
                block = block
                    .until(X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::SeqCst));
                // A futex word only this process's threads wake, a sleep and
                // a signal wait end with the deadline or a signal; anything
                // else a thread waits on is looked at again whenever
                // anything may have changed.
                if !matches!(
                    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst),
                    LINUX_THREAD_WAIT_FUTEX
                        | LINUX_THREAD_WAIT_SLEEP
                        | LINUX_THREAD_WAIT_SIGNAL
                        | LINUX_THREAD_WAIT_PAUSE
                        | LINUX_THREAD_WAIT_SIGSUSPEND
                ) {
                    block = block.and(WaitOn::ANYTHING);
                }
            }
            _ => return None,
        }
    }
    Some(block)
}

/// What a call waiting for descriptor `descriptor` to be ready waits on: a
/// local socket's or pipe's wakeups, a timerfd's expiry, the system calls
/// that change an eventfd, signalfd or pidfd; anything else (a terminal, a
/// network socket, whose device is polled, a device file) any change or
/// tick.
pub(super) fn linux_descriptor_wait(descriptor: u64) -> WaitOn {
    if let Some(slot) = linux_socket_slot(descriptor) {
        return if crate::linux_socket::event_counts(slot).is_some() {
            WaitOn::keyed(wait_events::SOCKET, u64::from(slot))
        } else {
            WaitOn::ANYTHING
        };
    }
    if let Some(timer) = linux_timerfd_state(descriptor) {
        return WaitOn::of(wait_events::STATE).until(timer.deadline.load(Ordering::SeqCst));
    }
    if linux_eventfd_descriptor(descriptor)
        || linux_signalfd_descriptor(descriptor)
        || linux_pidfd_descriptor(descriptor)
    {
        return WaitOn::of(wait_events::STATE);
    }
    WaitOn::ANYTHING
}

/// What the boot CPU's scheduler takes from the wait queues
/// (`linux_wait_queue`) before it picks a process: the processes blocked on
/// what came since make the run queue again. Every scheduler calls this
/// before it looks for work.
pub(in crate::arch::x86_64) fn deliver_linux_wakeups() {
    let wakeups = crate::linux_wait_queue::take();
    if wakeups.is_empty() {
        return;
    }
    if wakeups.all != 0 {
        linux_process::wake_live_processes(wakeups.all, None);
    }
    for (event, key) in wakeups.keyed() {
        if wakeups.all & event == 0 {
            linux_process::wake_live_processes(*event, Some(*key));
        }
    }
}

/// The key of thread `tid` of process `pid` of the running domain for its
/// activation.
pub(super) fn linux_thread_activation_owner(pid: u32, tid: u32) -> activation::Owner {
    activation::Owner {
        instance: linux_execution_instance() as u32,
        pid,
        tid,
    }
}

/// Whether an activation of process `pid` of the running domain (any
/// thread's) runs on some CPU.
pub(super) fn linux_process_activation_running(pid: u32) -> bool {
    activation::is_running(linux_execution_instance() as u32, pid)
}

/// The threads of process `pid` of the running domain parked in calls on
/// their activations.
pub(super) fn linux_parked_threads(pid: u32) -> Vec<u32> {
    activation::parked_threads(linux_execution_instance() as u32, pid)
}

/// Parks thread `tid` of the current process `pid` inside its system call
/// (see `activation::park`; the thread already left the CPU,
/// `park_current_linux_thread`) and, once resumed, makes its thread
/// pointer and address space current again, which whatever ran meanwhile
/// replaced. None when it cannot park; an unwinding call goes back to the
/// kernel as it is.
fn park_linux_thread(pid: u32, tid: u32) -> Option<activation::Wake> {
    let fs_base = active_fs_base();
    let root = address_space::current_root_address();
    // Others sharing its state run while it waits, and it sees what they
    // changed when it wakes.
    push_linux_shared_runtime_state();
    let wake = activation::park(linux_thread_activation_owner(pid, tid))?;
    if wake == activation::Wake::Unwind {
        return Some(wake);
    }
    pull_linux_shared_runtime_state();
    // Both are this process's, saved on its own stack before it parked;
    // the process is current again.
    let _ = install_user_fs_base(fs_base);
    let _ = address_space::restore_root_after_resume(root);
    // What a system call entry checks, the parked call checks on waking:
    // expired waits, and an expired real timer raising SIGALRM, which then
    // interrupts the wait.
    expire_linux_waits();
    let _ = refresh_linux_real_timer();
    let _ = refresh_linux_posix_timers();
    Some(wake)
}

/// Resumes thread `tid` of process `pid`, parked in a system call and
/// made current again (`unpark_linux_thread`), until it parks again or its
/// activation finishes; false when it has none. The parked call restores
/// its own thread pointer and address space.
pub(super) fn resume_parked_linux_thread(pid: u32, tid: u32) -> bool {
    X86_RUNTIME
        .LINUX_CURRENT_PROCESS_PID
        .store(pid, Ordering::SeqCst);
    LINUX_PROCESS_SLICE[linux_cpu_slot()].store(0, Ordering::SeqCst);
    // `pid` is current again: the scheduler loop restored its kernel state
    // before resuming it; the resumed call installs its own entry state
    // while it runs, and the runtime's is put back after.
    activation::resume(linux_thread_activation_owner(pid, tid), false).is_some()
}

/// Ends thread `tid` of the current process `pid`, parked in a system
/// call, because its process exits or executes: its call unwinds back to
/// the kernel, and its activation finishes and its stack goes back. With
/// a spin lock held (none may be held while another call runs) the
/// activation is dropped as it is instead. Its block and futex record go.
pub(super) fn unwind_parked_linux_thread(pid: u32, tid: u32) {
    linux_process::drop_live_thread_blocks(pid, Some(tid));
    drop_linux_thread_futex_waits(pid, tid);
    let owner = linux_thread_activation_owner(pid, tid);
    let root = address_space::current_root_address();
    let unwound = !crate::sync::spin_lock_held() && activation::unwind(owner);
    if !unwound {
        activation::discard(owner);
    }
    let _ = address_space::restore_root_after_resume(root);
}

/// Ends every thread of the current process `pid` still parked in a
/// system call (`unwind_parked_linux_thread`): the process exited.
pub(super) fn unwind_parked_linux_threads(pid: u32) {
    for tid in linux_parked_threads(pid) {
        unwind_parked_linux_thread(pid, tid);
    }
    linux_process::drop_live_thread_blocks(pid, None);
}

/// How often, at most, sched_yield lets other processes run.
const LINUX_YIELD_ROTATION_MICROSECONDS: u64 = 250;
/// When sched_yield last let other processes run (timestamp counter).
static LINUX_YIELD_ROTATED_AT: AtomicU64 = AtomicU64::new(0);

pub(super) fn linux_sched_yield_live_return(
    output: LinuxSyscallFrameHandle,
    registers: LinuxSyscallFrame,
    user_stack: u64,
    user_rip: u64,
    user_rflags: u64,
) -> u64 {
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let target = yield_ready_linux_thread_handle().unwrap_or(current);
    let caller = linux_thread_context(current).map(|tls| LinuxUserContext {
        registers,
        rip: user_rip,
        rsp: user_stack,
        rflags: user_rflags,
        rax: 0,
        fs_base: tls.thread_pointer as u64,
    });
    if target == current {
        // With no other thread of this process ready, other processes get
        // the CPU, as in Linux: a process spinning on sched_yield while it
        // waits for another one would otherwise never let that one run. The
        // call returns 0 when this process is next scheduled. Init, which
        // runs the others from its own waits, just returns. The others are
        // mostly parked waits that only recheck, so a yield goes round them
        // at most every LINUX_YIELD_ROTATION_MICROSECONDS and otherwise
        // returns at once: a GPU driver polling for its device's reply
        // yields thousands of times a second.
        let now = timer::timestamp_counter();
        let interval = timer::monotonic_frequency()
            .map_or(0, |hz| hz / 1_000_000 * LINUX_YIELD_ROTATION_MICROSECONDS);
        let due = now.wrapping_sub(LINUX_YIELD_ROTATED_AT.load(Ordering::Relaxed)) >= interval;
        if due
            && current_linux_runtime_cpu_index() == 0
            && linux_process::other_live_process_ready(
                current_linux_process_pid(),
                linux_elapsed_nanoseconds().unwrap_or(0),
            )
            && caller.is_some_and(|caller| {
                LINUX_YIELD_ROTATED_AT.store(now, Ordering::Relaxed);
                yield_current_linux_process(caller, 0)
            })
        {
            return LINUX_RETURN_TO_KERNEL;
        }
        X86_RUNTIME
            .LINUX_LIVE_RETURN_VALIDATED
            .store(true, Ordering::Relaxed);
        return 0;
    }
    let Some(caller) = caller else {
        return LINUX_ESRCH;
    };
    if !save_linux_thread_return_context(current, caller) {
        return LINUX_EINVAL;
    }
    let mut target_registers = LinuxSyscallFrame::ZERO;
    let mut target_rip = 0;
    let mut target_rsp = 0;
    let mut target_rflags = 0;
    let mut target_rax = 0;
    if !install_linux_thread_return(
        target,
        &mut target_registers,
        &mut target_rip,
        &mut target_rsp,
        &mut target_rflags,
        &mut target_rax,
    ) {
        return LINUX_EINVAL;
    } else {
        X86_RUNTIME
            .LINUX_YIELD_SWITCH_COUNT
            .fetch_add(1, Ordering::SeqCst);
    }
    let selected = LinuxUserContext {
        registers: target_registers,
        rip: target_rip,
        rsp: target_rsp,
        rflags: target_rflags,
        rax: target_rax,
        fs_base: active_fs_base(),
    };
    if !write_linux_thread_live_return(output, target, selected) {
        return LINUX_EINVAL;
    }
    X86_RUNTIME
        .LINUX_LIVE_RETURN_VALIDATED
        .store(true, Ordering::SeqCst);
    LINUX_RETURN_FROM_IRET
}

pub(super) fn write_linux_live_return(
    output: LinuxSyscallFrameHandle,
    context: LinuxUserContext,
) -> bool {
    if output.is_null() || !context.is_valid() {
        return false;
    }
    // The frame is the running call's (a handle writes only the live one),
    // and the stub returns through it to the context set here.
    output.write(context.registers)
        && cpu_tables::set_user_return(context.rip, context.rsp, Some(context.rflags))
        && output.read() == Some(context.registers)
        && cpu_tables::entry_state().is_some_and(|entry_state| {
            entry_state.user_rsp == context.rsp
                && entry_state.user_rip == context.rip
                && entry_state.user_rflags == context.rflags
        })
}

/// The Linox-internal system call the vDSO's preemption entry makes; above
/// every Linux system call number.
pub(super) const LINUX_PREEMPT_SYSCALL: u64 = 0x4750;
/// The Linox-internal system call a vfork parent is resumed into while its
/// child runs, in place of its vfork's return: it waits there for the
/// child to execute or exit, then returns the child's pid as the vfork.
pub(super) const LINUX_VFORK_WAIT_SYSCALL: u64 = 0x4751;

/// A vfork parent's wait for its child (`LINUX_VFORK_WAIT_SYSCALL`). Only
/// SIGKILL and stop signals reach it meanwhile, as Linux's vfork wait is
/// killable only; the others wait until the vfork returns.
#[inline(never)]
pub(super) fn linux_vfork_wait_live(
    output: LinuxSyscallFrameHandle,
    caller: LinuxUserContext,
) -> u64 {
    const SIGSTOP: u64 = 19;
    const UNBLOCKABLE: u64 = (1 << (LINUX_SIGKILL - 1)) | (1 << (SIGSTOP - 1));
    let pid = current_linux_process_pid();
    let mask = X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst);
    store_current_linux_signal_mask(!UNBLOCKABLE);
    let result = loop {
        let Some((child, pending)) = linux_process::live_process_vfork_child(pid) else {
            break LINUX_ENOSYS;
        };
        if !pending {
            break u64::from(linux_pid_seen_by(pid, child));
        }
        let wait = WaitOn::of(wait_events::CHILD);
        match run_other_linux_processes(output, caller, LINUX_VFORK_WAIT_SYSCALL, wait) {
            Some(LinuxBlockedWait::Recheck) => {}
            Some(LinuxBlockedWait::Return(result)) => break result,
            // It cannot wait in the call here (an application processor,
            // or a sibling thread is ready): it leaves the CPU with the wait
            // set to restart, since the child may still be using its memory.
            None => {
                let mut restart = caller;
                restart.rip = caller.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
                if yield_current_linux_process(restart, LINUX_VFORK_WAIT_SYSCALL) {
                    break LINUX_RETURN_TO_KERNEL;
                }
                break u64::from(linux_pid_seen_by(pid, child));
            }
        }
    };
    store_current_linux_signal_mask(mask);
    if result != LINUX_RETURN_TO_KERNEL {
        let _ = linux_process::set_live_process_vfork_child(pid, 0);
    }
    result
}
/// Timer ticks a thread of nice 0 runs before it is preempted so that
/// others get the CPU; a thread's own slice scales with its nice as Linux's
/// load weights do (`linux_thread_slice_ticks`).
pub(super) const LINUX_PROCESS_SLICE_TICKS: u32 = 50;
/// A nice value of 0, as the thread table keeps it (nice plus 20).
pub(super) const LINUX_NICE_DEFAULT: u8 = 20;
/// Linux's load weight per nice value, -20 first: each step is about 10%
/// of CPU time more or less than the next.
pub(super) const LINUX_NICE_WEIGHTS: [u32; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

/// Per CPU, the timestamp counter when the thread it runs took the CPU.
pub(super) static LINUX_THREAD_CPU_MARK: [AtomicU64; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU64::new(0) }; CPU_ENTRY_STATE_LIMIT];

/// On the owner's path, a timer preemption of the current thread switches
/// to a sibling kept for the owner: the preempted thread's exact context
/// goes to its slot (ready for any CPU) and the kept thread's call returns
/// through the frame. None when there is no such thread or the switch
/// cannot be made, and the preemption yields the process as before.
pub(super) fn linux_preempted_owner_switches_to_kept_thread(
    output: LinuxSyscallFrameHandle,
    preempted: &LinuxPreemptedContext,
) -> Option<u64> {
    let current = current_linux_thread_handle()?;
    // A thread kept for the owner, else any ready sibling, every other
    // preemption: the process's threads share this CPU with the other
    // processes (a process pinned to one CPU has no other CPU to run its
    // ready threads on: its bank is live only while the owner runs). A
    // kept thread does not take every slice either when the process can
    // yield: a busy child whose sibling always waited for the owner kept
    // the CPU from the parent it ran inside, which never left its fork
    // (bind06's LTP parent, with its heartbeat signal held blocked there).
    let cpu = linux_cpu_slot();
    let switched_last = LINUX_PREEMPTION_SWITCHED[cpu].swap(false, Ordering::Relaxed);
    let target = match kept_ready_linux_thread_handle() {
        Some(_) if switched_last && linux_preemption_yield_taken(preempted.pid) => return None,
        Some(target) => target,
        None if switched_last => return None,
        None => ready_linux_thread_handle()?,
    };
    LINUX_PREEMPTION_SWITCHED[cpu].store(true, Ordering::Relaxed);
    let general = preempted.general;
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
        rip: preempted.rip,
        rsp: preempted.rsp,
        rflags: preempted.rflags,
        rax: general[0],
        fs_base: active_fs_base(),
    };
    if !save_linux_thread_return_context(current, context) {
        return None;
    }
    let slot = usize::from(current.slot);
    X86_RUNTIME.LINUX_THREAD_RCXS[slot].store(general[2], Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_R11S[slot].store(general[10], Ordering::SeqCst);
    let mut registers = LinuxSyscallFrame::ZERO;
    let (mut rip, mut rsp, mut rflags, mut rax) = (0, 0, 0, 0);
    if !install_linux_thread_return(
        target,
        &mut registers,
        &mut rip,
        &mut rsp,
        &mut rflags,
        &mut rax,
    ) {
        return None;
    }
    X86_RUNTIME
        .LINUX_LAST_PREEMPTED_THREAD_SLOT
        .store(current.slot, Ordering::SeqCst);
    let selected = LinuxUserContext {
        registers,
        rip,
        rsp,
        rflags,
        rax,
        fs_base: active_fs_base(),
    };
    if !write_linux_thread_live_return(output, target, selected) {
        return Some(LINUX_EINVAL);
    }
    X86_RUNTIME
        .LINUX_LIVE_RETURN_VALIDATED
        .store(true, Ordering::SeqCst);
    Some(LINUX_RETURN_FROM_IRET)
}

/// Delivers the pending signal to a process the timer interrupted in user
/// code, with exactly the interrupted registers in its signal frame (rcx and
/// r11 are live there, not clobbered as by a system call); with nothing to
/// deliver after all, the process carries on where it was.
pub(super) fn linux_deliver_signal_to_interrupted(
    output: LinuxSyscallFrameHandle,
    preempted: &LinuxPreemptedContext,
) -> u64 {
    let general = preempted.general;
    let _ = refresh_linux_real_timer();
    let _ = refresh_linux_posix_timers();
    let interrupted = LinuxUserContext {
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
        rip: preempted.rip,
        rsp: preempted.rsp,
        rflags: preempted.rflags,
        rax: general[0],
        fs_base: active_fs_base(),
    };
    let delivered = linux_deliver_pending_signal(output, interrupted, (general[2], general[10]));
    // A handler is entered through the frame the call returns with (and the
    // signal is then active); other results end or stop the process.
    if delivered != 0 || X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        return delivered;
    }
    if write_linux_exact_live_return(
        output,
        general,
        preempted.rip,
        preempted.rsp,
        preempted.rflags,
    ) {
        LINUX_RETURN_FROM_IRET
    } else {
        LINUX_EINVAL
    }
}

/// Returns from the current system call to `rip` with exactly the registers
/// in `general` (`process_general` order), through the IRETQ epilogue.
pub(super) fn write_linux_exact_live_return(
    output: LinuxSyscallFrameHandle,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
) -> bool {
    let registers = LinuxSyscallFrame {
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
    };
    let context = LinuxUserContext {
        registers,
        rip,
        rsp,
        rflags,
        rax: general[0],
        fs_base: active_fs_base(),
    };
    if !write_linux_live_return(output, context) {
        return false;
    }
    cpu_tables::set_iret_registers(general[0], general[2], general[10])
}

pub(super) fn write_linux_thread_live_return(
    output: LinuxSyscallFrameHandle,
    handle: LinuxThreadHandle,
    context: LinuxUserContext,
) -> bool {
    let Some(general) = linux_thread_resume_general(handle, context) else {
        return false;
    };
    if !write_linux_live_return(output, context) {
        return false;
    }
    // A target thread may have been interrupted between arbitrary userspace
    // instructions. Unlike a normal SYSCALL return, RCX and R11 are then live
    // application registers rather than the return RIP and RFLAGS. Publish the
    // exact saved values for the IRETQ epilogue used by cross-thread returns.
    cpu_tables::set_iret_registers(general[0], general[2], general[10])
}

/// Resumes thread `tid` of process `pid`, parked in a system call and made
/// current again, until it parks again or returns to the kernel; the
/// caller's root is put back after.
pub(super) fn run_parked_linux_thread(pid: u32, tid: u32) -> bool {
    let previous_root = address_space::current_root_address();
    let resumed = resume_parked_linux_thread(pid, tid);
    let restored = address_space::restore_root_after_resume(previous_root);
    if !(resumed && restored) {
        serial_write("linox: parked thread resume failed pid/tid/cpu/resumed/restored: ");
        for value in [
            u64::from(pid),
            u64::from(tid),
            current_cpu_index_checked().unwrap_or(99) as u64,
            u64::from(resumed),
            u64::from(restored),
        ] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
    }
    restored && resumed
}

/// Enters `process` in user mode, as the registry dispatched it (its
/// current thread at the registry's context), until it returns to the
/// kernel or parks: by a system call that leaves it (an exit, a yield, a
/// fork that runs the child) or waits, a fault or a preemption. Every
/// process the kernel runs is entered here; a thread parked in a call is
/// resumed by `run_parked_linux_thread`.
pub(super) fn run_dispatched_linux_process(process: &linux_process::LiveProcessDispatch) -> bool {
    if linux_process_activation_running(process.pid) {
        serial_write("linox: entering a process whose activation runs pid/cpu: ");
        serial_write_u64(u64::from(process.pid));
        serial_write(" ");
        serial_write_u64(current_cpu_index_checked().unwrap_or(99) as u64);
        serial_write("\r\n");
    }
    let entered = address_space::resume_live_linux_process(
        process.root,
        process.rip,
        process.rsp,
        process.fs_base,
        process.general,
        process.rflags,
    );
    if !entered {
        serial_write("linox: process entry failed pid/cpu/root/rip/rsp/current-root: ");
        for value in [
            u64::from(process.pid),
            current_cpu_index_checked().unwrap_or(99) as u64,
            process.root.address(),
            process.rip,
            process.rsp,
            address_space::current_root_address(),
        ] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
    }
    entered
}

pub(super) fn save_suspended_linux_runtime(
    context: LinuxUserContext,
    address: u64,
    count: u64,
    background: bool,
) -> bool {
    if !context.is_valid()
        || !background && (address == 0 || count == 0)
        || !refresh_live_linux_process_registry(context)
        || X86_RUNTIME
            .LINUX_RUNTIME_SUSPENDED
            .swap(true, Ordering::AcqRel)
    {
        return false;
    }
    for (stored, value) in X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_REGISTERS
        .iter()
        .zip(context.registers.into_array())
    {
        stored.store(value, Ordering::Release);
    }
    X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_ADDRESS
        .store(address, Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_COUNT
        .store(count, Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_RIP
        .store(context.rip, Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_RSP
        .store(context.rsp, Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_RFLAGS
        .store(context.rflags, Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_FS_BASE
        .store(context.fs_base, Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_RESULT
        .store(context.rax, Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_PID
        .store(current_linux_process_pid(), Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_BACKGROUND_SUSPENDED
        .store(background, Ordering::Release);
    if let Some(slot) = active_container_slot() {
        X86_RUNTIME.CONTAINER_BACKGROUND_SUSPENDED[slot].store(background, Ordering::Release);
    }
    true
}

pub(crate) fn resume_suspended_linux_runtime(mmap: u64) -> LinuxElfResult {
    let _kernel_entry = crate::sync::kernel_entry_lock();
    if !X86_RUNTIME.LINUX_RUNTIME_SUSPENDED.load(Ordering::Acquire) {
        return LinuxElfResult::FAILED;
    }
    let Some(slot) = active_container_slot() else {
        return LinuxElfResult::FAILED;
    };
    let stopping = X86_RUNTIME.CONTAINER_STOP_REQUESTED[slot].swap(false, Ordering::AcqRel);
    let domain_exec = X86_RUNTIME.CONTAINER_EXEC_REQUESTED[slot].swap(false, Ordering::AcqRel);
    let background = X86_RUNTIME
        .LINUX_RUNTIME_BACKGROUND_SUSPENDED
        .load(Ordering::Acquire);
    if !stopping
        && !domain_exec
        && !background
        && !X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire)
    {
        return LinuxElfResult::FAILED;
    }
    let address = X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_ADDRESS
        .load(Ordering::Acquire);
    let count = X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_COUNT
        .load(Ordering::Acquire);
    if !background && (address == 0 || count == 0) {
        return LinuxElfResult::FAILED;
    }
    let registers = LinuxSyscallFrame::from_array(core::array::from_fn(|index| {
        X86_RUNTIME.LINUX_RUNTIME_SUSPEND_REGISTERS[index].load(Ordering::Acquire)
    }));
    let context = LinuxUserContext {
        registers,
        rip: X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_RIP
            .load(Ordering::Acquire),
        rsp: X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_RSP
            .load(Ordering::Acquire),
        rflags: X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_RFLAGS
            .load(Ordering::Acquire),
        rax: if stopping {
            0
        } else if background {
            X86_RUNTIME
                .LINUX_RUNTIME_SUSPEND_RESULT
                .load(Ordering::Acquire)
        } else {
            1
        },
        fs_base: X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_FS_BASE
            .load(Ordering::Acquire),
    };
    // A background domain the loop suspended between processes has no
    // process of its own to resume (`suspend_linux_runtime_from_loop`): a
    // domain exec's command is then a child of init.
    let suspended_pid = X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_PID
        .load(Ordering::Acquire);
    let loop_suspended = background && suspended_pid == 0;
    if !loop_suspended && !context.is_valid() {
        return LinuxElfResult::FAILED;
    }
    if !linux_mount::activate_initial() {
        serial_write("linox: suspended Linux resume could not activate mounts\r\n");
        return LinuxElfResult::FAILED;
    }
    if !linux_process::resume_runtime_process_registry() {
        serial_write("linox: suspended Linux resume could not restore process registry\r\n");
        let _ = linux_mount::deactivate_initial();
        return LinuxElfResult::FAILED;
    }
    // Wakeups queued while the domain was suspended went to other domains'
    // schedulers: every blocked process looks at its wait once more.
    let _ = linux_process::wake_all_live_processes();
    let Some(saved_msrs) = configure_linux_syscall() else {
        serial_write("linox: suspended Linux resume could not configure syscall state\r\n");
        let _ = linux_process::suspend_runtime_process_registry();
        let _ = linux_mount::deactivate_initial();
        return LinuxElfResult::FAILED;
    };
    if !restore_container_extended_state() {
        serial_write("linox: suspended Linux resume could not restore extended state\r\n");
        let _ = linux_process::finish_runtime_process_registry();
        let _ = linux_mount::deactivate_initial();
        let _ = restore_linux_syscall(saved_msrs);
        return LinuxElfResult::FAILED;
    }
    if stopping {
        X86_RUNTIME
            .LINUX_RUNTIME_SUSPENDED
            .store(false, Ordering::Release);
        X86_RUNTIME
            .LINUX_RUNTIME_BACKGROUND_SUSPENDED
            .store(false, Ordering::Release);
        X86_RUNTIME.CONTAINER_BACKGROUND_SUSPENDED[slot].store(false, Ordering::Release);
        X86_RUNTIME
            .LINUX_RUNTIME_MODE
            .store(true, Ordering::Release);
        if !timer::arm_linux_wait_timer() {
            let _ = linux_process::finish_runtime_process_registry();
            let _ = linux_mount::deactivate_initial();
            let _ = restore_linux_syscall(saved_msrs);
            X86_RUNTIME
                .LINUX_RUNTIME_MODE
                .store(false, Ordering::Release);
            return LinuxElfResult::FAILED;
        }
        retire_all_linux_threads();
        if !linux_process::force_stop_runtime_process_registry() {
            let _ = linux_mount::deactivate_initial();
            let _ = timer::finish_linux_wait_timer();
            let _ = restore_linux_syscall(saved_msrs);
            X86_RUNTIME
                .LINUX_RUNTIME_MODE
                .store(false, Ordering::Release);
            return LinuxElfResult::FAILED;
        }
        X86_RUNTIME
            .ELF_PROBE_COMPLETED
            .store(true, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::Release);
        X86_RUNTIME
            .LINUX_RUNTIME_EXIT_STATUS
            .store(0, Ordering::Release);
        return finish_linux_runtime(mmap, saved_msrs, true);
    }
    let Some(process) = linux_process::dispatch_live_process(suspended_pid.max(1)) else {
        serial_write("linox: suspended Linux resume process is unavailable\r\n");
        let _ = linux_process::finish_runtime_process_registry();
        let _ = linux_mount::deactivate_initial();
        let _ = restore_linux_syscall(saved_msrs);
        return LinuxElfResult::FAILED;
    };
    if !sync_live_linux_process_address_space(process.pid) {
        serial_write("linox: suspended Linux resume address space is unavailable\r\n");
        let _ = linux_process::finish_runtime_process_registry();
        let _ = linux_mount::deactivate_initial();
        let _ = restore_linux_syscall(saved_msrs);
        return LinuxElfResult::FAILED;
    }
    X86_RUNTIME
        .LINUX_CURRENT_PROCESS_PID
        .store(process.pid, Ordering::Release);
    if (!background || domain_exec)
        && (!restore_saved_linux_process_runtime_state(process.pid)
            || !restore_linux_process_extended_state(process.pid))
    {
        serial_write("linox: suspended Linux resume process state is unavailable\r\n");
        let _ = linux_process::finish_runtime_process_registry();
        let _ = linux_mount::deactivate_initial();
        let _ = restore_linux_syscall(saved_msrs);
        return LinuxElfResult::FAILED;
    }
    if !background && !domain_exec {
        let byte = crate::serial_read_byte_blocking();
        if !address_space::copy_to_linux_process(process.pid, process.root, address, &[byte]) {
            serial_write("linox: suspended Linux resume could not deliver console input\r\n");
            serial_write("linox: console input pid/root/address/count: ");
            for value in [
                u64::from(process.pid),
                process.root.address(),
                address,
                count,
            ] {
                serial_write_u64(value);
                serial_write(" ");
            }
            serial_write("\r\n");
            let _ = linux_process::finish_runtime_process_registry();
            let _ = linux_mount::deactivate_initial();
            let _ = restore_linux_syscall(saved_msrs);
            return LinuxElfResult::FAILED;
        }
    }
    X86_RUNTIME
        .LINUX_RUNTIME_SUSPENDED
        .store(false, Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_BACKGROUND_SUSPENDED
        .store(false, Ordering::Release);
    X86_RUNTIME.CONTAINER_BACKGROUND_SUSPENDED[slot].store(false, Ordering::Release);
    // A request to give the CPU back made before this suspension (a domain
    // exec's command that ended, the timer) was answered by it.
    X86_RUNTIME
        .LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED
        .store(false, Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_MODE
        .store(true, Ordering::Release);
    if domain_exec {
        X86_RUNTIME
            .LINUX_DOMAIN_EXEC_INJECT
            .store(true, Ordering::Release);
        X86_RUNTIME
            .LINUX_FORK_REQUESTED
            .store(true, Ordering::Release);
        X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].store(true, Ordering::Release);
    }
    if !timer::arm_linux_wait_timer() {
        serial_write("linox: suspended Linux resume could not arm timer\r\n");
        let _ = linux_process::finish_runtime_process_registry();
        let _ = linux_mount::deactivate_initial();
        let _ = restore_linux_syscall(saved_msrs);
        X86_RUNTIME
            .LINUX_RUNTIME_MODE
            .store(false, Ordering::Release);
        return LinuxElfResult::FAILED;
    }
    // The suspended process goes on from the context its suspension saved
    // in the registry, run by the loop as every process is: with its call's
    // result (a background suspension) or the console byte just delivered.
    // A domain exec's command is a child of it, ready in the run queue and
    // run first; the suspended process goes on as it would have, a console
    // read waiting again (the console is the command's meanwhile), so its
    // registry context keeps its own result rather than the fork's.
    let resumed = if domain_exec {
        let result = linux_process::live_process_return_value(process.pid);
        let forked = execute_deferred_live_fork();
        let restored = if background {
            result.is_some_and(|result| {
                linux_process::set_live_process_return_value(process.pid, result)
            })
        } else {
            // A console suspension records the read it was made in.
            linux_process::restart_live_process_call(
                process.pid,
                X86_RUNTIME
                    .LINUX_RUNTIME_SUSPEND_RESULT
                    .load(Ordering::Acquire),
            )
        };
        save_current_linux_process_runtime_state(process.pid);
        forked && restored && save_linux_process_extended_state(process.pid)
    } else {
        background || linux_process::set_live_process_return_value(process.pid, 1)
    };
    if !resumed {
        serial_write("linox: suspended Linux process resume rejected pid/root/rip: ");
        serial_write_u64(u64::from(process.pid));
        serial_write(" ");
        serial_write_u64(process.root.address());
        serial_write(" ");
        serial_write_u64(context.rip);
        serial_write("\r\n");
        let _ = linux_process::finish_runtime_process_registry();
        let _ = linux_mount::deactivate_initial();
        let _ = timer::finish_linux_wait_timer();
        let _ = restore_linux_syscall(saved_msrs);
        X86_RUNTIME
            .LINUX_RUNTIME_MODE
            .store(false, Ordering::Release);
        return LinuxElfResult::FAILED;
    }
    let first = if domain_exec {
        Some(X86_RUNTIME.CONTAINER_EXEC_CHILD[slot].load(Ordering::Acquire))
    } else {
        (!loop_suspended).then_some(process.pid)
    };
    run_linux_runtime(mmap, saved_msrs, first)
}

/// Suspends a background domain's runtime from the boot CPU's loop, between
/// processes, when the timer asked it to give the CPU back
/// (`LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED`) and no system call ending
/// took the request (every process waiting, say): the loop itself is what
/// resumes, with no process's call to complete (suspended pid 0).
fn suspend_linux_runtime_from_loop() -> bool {
    let Some(slot) = active_container_slot() else {
        return false;
    };
    if X86_RUNTIME
        .LINUX_RUNTIME_SUSPENDED
        .swap(true, Ordering::AcqRel)
    {
        return false;
    }
    X86_RUNTIME
        .LINUX_RUNTIME_SUSPEND_PID
        .store(0, Ordering::Release);
    X86_RUNTIME
        .LINUX_RUNTIME_BACKGROUND_SUSPENDED
        .store(true, Ordering::Release);
    X86_RUNTIME.CONTAINER_BACKGROUND_SUSPENDED[slot].store(true, Ordering::Release);
    true
}

/// The boot CPU's scheduler loop for a Linux runtime (docs/SCHEDULER.md,
/// step 4). It owns the domain's run queue: it takes the ready processes in
/// turn, init among them, and runs each on this CPU until it waits, yields,
/// is preempted or exits (`run_linux_process_on_this_cpu`). Every process
/// waits by parking in its call or returning to the kernel; none runs
/// nested inside another's system call, and a fork leaves its child ready
/// in the queue while the parent goes on. A process with SIGKILL pending
/// goes first, as Linux wakes a killed task, and `first` (a process being
/// resumed after a suspension, or a domain exec's command) before any.
/// Blocked processes are not ready: the wakeups queued since the last
/// round make theirs ready first (`deliver_linux_wakeups`). With nothing
/// ready the CPU halts until an interrupt (a tick at the earliest
/// deadline at the latest). Returns when init has ended (its state left
/// current) or the runtime is suspending; false if a process could not be
/// run.
fn run_linux_runtime_loop(mut first: Option<u32>) -> bool {
    let mut ran = true;
    loop {
        if X86_RUNTIME.LINUX_RUNTIME_SUSPENDED.load(Ordering::Acquire)
            || X86_RUNTIME
                .LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED
                .swap(false, Ordering::AcqRel)
                && suspend_linux_runtime_from_loop()
        {
            return ran;
        }
        linux_stall_diagnostic_from_loop();
        deliver_linux_wakeups();
        let now = linux_elapsed_nanoseconds().unwrap_or(0);
        let picked = first
            .take()
            .or_else(|| {
                linux_process::ready_live_process_after(0, now, |pid| {
                    linux_process_killed(pid) && linux_runtime_loop_may_run(pid)
                })
            })
            .or_else(|| linux_process::next_ready_live_process(now, linux_runtime_loop_may_run));
        match picked.map(run_linux_process_here) {
            Some(LinuxRunOutcome::Settled) => {}
            Some(LinuxRunOutcome::InitEnded) => return ran,
            Some(LinuxRunOutcome::Failed) => {
                serial_write("linox: runtime loop could not run pid ");
                serial_write_u64(u64::from(picked.unwrap_or(0)));
                serial_write("\r\n");
                ran = false;
            }
            // SAFETY: interrupts wake the CPU for the timer and devices; the
            // kernel-entry lock serializes the work they start.
            None => linux_wait_for_interrupt(),
        }
        // Other CPUs' system calls go first.
        crate::sync::kernel_entry_yield();
    }
}

/// Whether the boot CPU's loop may run process `pid`, ready in the run
/// queue: one whose kernel activation another CPU runs is that CPU's.
fn linux_runtime_loop_may_run(pid: u32) -> bool {
    !linux_process_activation_running(pid)
}

/// Whether the domain's console belongs to a `domain exec` command that is
/// not the current process or one of its ancestors: the command and what
/// it starts read the console meanwhile.
pub(super) fn linux_console_held_by_domain_exec() -> bool {
    let Some(slot) = active_container_slot() else {
        return false;
    };
    let holder = X86_RUNTIME.CONTAINER_EXEC_CHILD[slot].load(Ordering::Acquire);
    if holder == 0 {
        return false;
    }
    let mut pid = current_linux_process_pid();
    for _ in 0..linux_process::PROCESS_LIMIT {
        if pid == holder {
            return false;
        }
        match linux_process::live_process_parent_pid(pid) {
            Some(parent) if parent != 0 => pid = parent,
            _ => break,
        }
    }
    true
}

/// Whether process `pid` has SIGKILL pending.
pub(super) fn linux_process_killed(pid: u32) -> bool {
    linux_process::live_process_slot(pid)
        .and_then(|slot| {
            crate::linux_signal::pending_mask(
                linux_signal_instance(),
                crate::linux_signal::Scope::Process,
                slot,
            )
            .ok()
        })
        .is_some_and(|mask| mask & (1_u64 << (LINUX_SIGKILL - 1)) != 0)
}

/// Makes process `pid`'s saved kernel state current on this CPU again, for
/// the runtime's suspension or teardown, which read and keep what the
/// running process holds.
fn make_linux_process_current(pid: u32) -> bool {
    X86_RUNTIME
        .LINUX_CURRENT_PROCESS_PID
        .store(pid, Ordering::SeqCst);
    restore_saved_linux_process_runtime_state(pid) && restore_linux_process_extended_state(pid)
}

/// Runs the domain's processes from the boot CPU's loop, with the other
/// CPUs of the domain, until init ends or the runtime suspends, then
/// finishes or suspends the runtime. `first` runs before any other.
pub(super) fn run_linux_runtime(
    mmap: u64,
    saved_msrs: SyscallMsrs,
    first: Option<u32>,
) -> LinuxElfResult {
    start_linux_smp_runtime();
    let ran = run_linux_runtime_loop(first);
    stop_linux_smp_runtime();
    // Init's state is the runtime's while it is suspended (a stop tears it
    // down from there); an init that ended left its own current.
    let init_current = !X86_RUNTIME.LINUX_RUNTIME_SUSPENDED.load(Ordering::Acquire)
        || make_linux_process_current(1);
    finish_linux_runtime(mmap, saved_msrs, ran && init_current)
}

/// Suspends the runtime, or tears it down once init has ended (or the
/// domain is being stopped); `forks_completed` says whether its processes
/// ran without a failure.
fn finish_linux_runtime(
    mmap: u64,
    saved_msrs: SyscallMsrs,
    mut forks_completed: bool,
) -> LinuxElfResult {
    if !X86_RUNTIME.LINUX_RUNTIME_SUSPENDED.load(Ordering::Acquire) {
        // Init, alone now, leaves the run queue with it.
        forks_completed &= linux_process::retire_lone_live_process(1);
    }
    if forks_completed && X86_RUNTIME.LINUX_RUNTIME_SUSPENDED.load(Ordering::Acquire) {
        let state_saved = save_container_extended_state();
        let registry_suspended = state_saved && linux_process::suspend_runtime_process_registry();
        let mount_deactivated = registry_suspended && linux_mount::deactivate_initial();
        let timer_finished = timer::finish_linux_wait_timer();
        let msrs_restored = restore_linux_syscall(saved_msrs);
        X86_RUNTIME
            .LINUX_RUNTIME_MODE
            .store(false, Ordering::Release);
        return LinuxElfResult {
            valid: mount_deactivated && timer_finished && msrs_restored,
            suspended: mount_deactivated && timer_finished && msrs_restored,
            ..LinuxElfResult::FAILED
        };
    }
    // The runtime is over: calls still parked never continue.
    activation::discard_parked(linux_execution_instance() as u32);
    let completed = X86_RUNTIME
        .ELF_PROBE_COMPLETED
        .swap(false, Ordering::SeqCst);
    let extended_state_discarded = discard_container_extended_state();
    let mmap_released = release_linux_runtime_mmaps(mmap);
    let descriptors_closed = linux_close_all_descriptors();
    let sockets_stopped = descriptors_closed && crate::linux_socket::shutdown();
    let tmpfs_released = linux_tmpfs::teardown();
    let overlay_released = crate::linux_overlay::teardown();
    let registry_finished = linux_process::finish_runtime_process_registry();
    let aio_released = registry_finished && crate::linux_aio::teardown();
    let sysv_ipc_released = aio_released && crate::linux_sysv_ipc::teardown();
    if sysv_ipc_released {
        X86_RUNTIME
            .ELF_PROBE_POSIX_MQ_BYTES
            .store(0, Ordering::SeqCst);
    }
    let keyrings_released = sysv_ipc_released && crate::linux_keyring::teardown();
    let mount_deactivated = linux_mount::deactivate_initial();
    let timer_finished = timer::finish_linux_wait_timer();
    let msrs_restored = restore_linux_syscall(saved_msrs);
    let threads_released = finish_linux_thread_table();
    let inactive = !X86_RUNTIME.ELF_PROBE_ACTIVE.swap(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_RUNTIME_MODE
        .store(false, Ordering::SeqCst);
    let valid = forks_completed
        && extended_state_discarded
        && completed
        && mmap_released
        && descriptors_closed
        && sockets_stopped
        && tmpfs_released
        && overlay_released
        && registry_finished
        && sysv_ipc_released
        && keyrings_released
        && mount_deactivated
        && timer_finished
        && msrs_restored
        && threads_released
        && inactive;
    if !valid {
        serial_write("linox: Linux runtime cleanup failed\r\n");
        write_linux_runtime_syscall_trace();
    }
    LinuxElfResult {
        valid,
        ..LinuxElfResult::FAILED
    }
}
