use super::*;

/// A copy of this CPU's running process's signal context.
pub(super) fn current_linux_signal_context() -> LinuxSignalContext {
    let words = &X86_MUTABLE_RUNTIME.signal_context[linux_cpu_bank()];
    LinuxSignalContext::from_words(core::array::from_fn(|index| {
        words[index].load(Ordering::Acquire)
    }))
}

/// Replaces this CPU's running process's signal context.
pub(super) fn set_current_linux_signal_context(context: LinuxSignalContext) {
    let words = &X86_MUTABLE_RUNTIME.signal_context[linux_cpu_bank()];
    for (word, value) in words.iter().zip(context.into_words()) {
        word.store(value, Ordering::Release);
    }
}

/// The signal context as `cpu/linux_mmap.rs` (another change's file) reads
/// it, in an `unsafe` block: `linux_signal_context().get().cast_const()
/// .read()`. It goes when that file calls `current_linux_signal_context`.
pub(super) fn linux_signal_context() -> LinuxSignalContextView {
    LinuxSignalContextView
}

/// See `linux_signal_context`.
pub(super) struct LinuxSignalContextView;

impl LinuxSignalContextView {
    pub(super) fn get(&self) -> Self {
        Self
    }

    pub(super) fn cast_const(self) -> Self {
        self
    }

    /// The context (`current_linux_signal_context`).
    ///
    /// # Safety
    ///
    /// None: it is `unsafe` only so the caller's `unsafe` block stays valid
    /// until that file moves to `current_linux_signal_context`.
    pub(super) unsafe fn read(self) -> LinuxSignalContext {
        current_linux_signal_context()
    }
}

/// The record for process slot `slot` of domain instance `instance`,
/// allocated on first use.
pub(super) fn linux_process_record(
    instance: usize,
    slot: usize,
) -> Option<&'static mut LinuxProcessRecord> {
    if instance >= LINUX_PROCESS_RUNTIME_INSTANCE_LIMIT
        || slot >= linux_process::PROCESS_RUNTIME_LIMIT
    {
        return None;
    }
    // SAFETY: the table is only reached through these accessors, which the
    // recursive kernel-entry boundary serializes.
    let table = unsafe { &mut (*X86_MUTABLE_RUNTIME.process_records.get())[instance] };
    if table.len() <= slot {
        table.try_reserve(slot + 1 - table.len()).ok()?;
        table.resize(slot + 1, LinuxProcessRecordSlot::EMPTY);
    }
    let entry = &mut table[slot];
    if entry.record.is_null() {
        let length = size_of::<LinuxProcessRecord>();
        let (first, _) = memory::allocate_contiguous_extent(
            memory::FrameOwner::KERNEL,
            length.div_ceil(PAGE_SIZE),
        )?;
        let record =
            paging::direct_map_range_address(first.address(), length)? as *mut LinuxProcessRecord;
        // SAFETY: the extent is a fresh, zeroed, kernel-owned allocation sized
        // for one record, and nothing else refers to it yet. The extended
        // states and their valid flags are correct as zeros; the runtime and
        // thread states are written field by field so no record-sized
        // temporary is built on the kernel stack.
        unsafe {
            core::ptr::addr_of_mut!((*record).runtime).write(LinuxProcessRuntimeState::EMPTY);
            let threads =
                core::ptr::addr_of_mut!((*record).threads).cast::<LinuxThreadRuntimeState>();
            for thread in 0..LINUX_THREAD_LIMIT {
                threads.add(thread).write(LinuxThreadRuntimeState::EMPTY);
            }
        }
        *entry = LinuxProcessRecordSlot { record, first };
    }
    // SAFETY: the pointer addresses a live, kernel-owned record, and callers
    // do not hold two references to one slot.
    Some(unsafe { &mut *entry.record })
}

/// Releases process `pid`'s runtime slot once it has ended (see
/// `linux_process::release_live_process_runtime_slot`), and the slot's
/// record with it when the slot is above those kept.
pub(super) fn release_linux_process_runtime_slot(pid: u32) -> bool {
    let slot = linux_process::live_process_runtime_slot(pid);
    if !linux_process::release_live_process_runtime_slot(pid) {
        return false;
    }
    let instance = current_container_slot().unwrap_or(control_abi::DOMAIN_LIMIT);
    let Some(slot) = slot.filter(|slot| *slot >= LINUX_PROCESS_RECORDS_KEPT) else {
        return true;
    };
    // SAFETY: as in linux_process_record; the process that used the slot
    // has ended and its record was emptied, so nothing refers to it.
    let tables = unsafe { &mut *X86_MUTABLE_RUNTIME.process_records.get() };
    let Some(entry) = tables
        .get_mut(instance)
        .and_then(|table| table.get_mut(slot))
        .filter(|entry| !entry.record.is_null())
    else {
        return true;
    };
    let pages = size_of::<LinuxProcessRecord>().div_ceil(PAGE_SIZE);
    let released =
        memory::scrub_and_release_contiguous_extent(memory::FrameOwner::KERNEL, entry.first, pages);
    if released {
        *entry = LinuxProcessRecordSlot::EMPTY;
    }
    released
}

/// The frames held by the process records allocated so far, every domain
/// instance's: those of the kept slots stay for the next process.
pub(crate) fn linux_process_record_frames() -> usize {
    // SAFETY: as in linux_process_record; only the entries are read.
    let tables = unsafe { &*X86_MUTABLE_RUNTIME.process_records.get() };
    let pages = size_of::<LinuxProcessRecord>().div_ceil(PAGE_SIZE);
    tables
        .iter()
        .flatten()
        .filter(|entry| !entry.record.is_null())
        .count()
        * pages
}

/// The records already allocated for the current domain instance.
pub(super) fn allocated_linux_process_records(
) -> impl Iterator<Item = &'static mut LinuxProcessRecord> {
    let instance = current_container_slot().unwrap_or(control_abi::DOMAIN_LIMIT);
    // SAFETY: as in linux_process_record; every non-null entry is a live
    // record.
    let tables = unsafe { &*X86_MUTABLE_RUNTIME.process_records.get() };
    tables
        .get(instance)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|entry| !entry.record.is_null())
        .map(|entry| unsafe { &mut *entry.record })
}

fn linux_current_process_record(pid: u32) -> Option<&'static mut LinuxProcessRecord> {
    let instance = current_container_slot().unwrap_or(control_abi::DOMAIN_LIMIT);
    linux_process_record(instance, linux_process::live_process_runtime_slot(pid)?)
}

pub(super) fn linux_process_runtime_state(
    pid: u32,
) -> Option<&'static mut LinuxProcessRuntimeState> {
    linux_current_process_record(pid).map(|record| &mut record.runtime)
}

/// How many threads process `pid`, which is not the current process, has:
/// those its saved thread table holds, or one without a table.
pub(super) fn linux_process_thread_count(pid: u32) -> usize {
    let saved = linux_process_runtime_state(pid).is_some_and(|state| state.valid);
    linux_process_thread_runtime_state(pid)
        .filter(|_| saved)
        .map_or(1, |threads| {
            threads
                .iter()
                .filter(|thread| thread.state != LINUX_THREAD_FREE)
                .count()
                .max(1)
        })
}

/// Whether `pid`'s main thread is blocked in a wait. Linux's
/// `/proc/PID/stat` shows the thread-group leader's state, so a process
/// whose other threads run still reads as sleeping there.
pub(super) fn linux_leader_thread_blocked(pid: u32) -> bool {
    if pid == current_linux_process_pid() {
        return linux_thread_handle_by_tid(u64::from(pid)).is_some_and(|leader| {
            matches!(
                X86_RUNTIME.LINUX_THREAD_STATES[usize::from(leader.slot)].load(Ordering::SeqCst),
                LINUX_THREAD_BLOCKED | LINUX_THREAD_PARKED
            )
        });
    }
    linux_process_runtime_state(pid).is_some_and(|state| state.valid)
        && linux_process_thread_runtime_state(pid).is_some_and(|threads| {
            threads.iter().any(|thread| {
                thread.tid == pid
                    && matches!(thread.state, LINUX_THREAD_BLOCKED | LINUX_THREAD_PARKED)
            })
        })
}

pub(super) fn linux_process_thread_runtime_state(
    pid: u32,
) -> Option<&'static mut [LinuxThreadRuntimeState; LINUX_THREAD_LIMIT]> {
    linux_current_process_record(pid).map(|record| &mut record.threads)
}

pub(super) struct LinuxForkParentRuntime {
    pub(super) stack: Option<(usize, u64, u64)>,
    pub(super) nice: u8,
}

/// The outer fork transaction's exec policy and the process whose exit,
/// exec and yield it waits for. A child that forks starts a nested
/// transaction, which points these at the grandchild; when the child
/// resumes inside that transaction (after the grandchild exits, execs or
/// yields), it is the outer transaction's child again: its own exec (a
/// subshell that runs a pipeline, then execs its last command) must reach
/// the outer transaction, and so must a yield. The timer yields a process
/// only when its yield is taken (`linux_preemption_yield_taken`): a
/// multithreaded child that had forked once was otherwise never preempted
/// back to the parent waiting in the outer transaction, which then never
/// ran (dirtyc0w_shmem).
pub(super) struct LinuxForkExecFlagGuard {
    previous: bool,
    exit_pid: u32,
    exec_pid: u32,
    yield_pid: u32,
    /// Whether `resume_parent` already gave the pids back: a report the
    /// parent makes after that must not be overwritten.
    pids_restored: core::cell::Cell<bool>,
}

impl LinuxForkExecFlagGuard {
    pub(super) fn capture() -> Self {
        Self {
            previous: X86_RUNTIME
                .LINUX_PROCESS_RELEASE_PARENT_ON_EXEC
                .load(Ordering::SeqCst),
            exit_pid: X86_RUNTIME
                .LINUX_PROCESS_CHILD_EXIT_PID
                .load(Ordering::SeqCst),
            exec_pid: X86_RUNTIME
                .LINUX_PROCESS_CHILD_EXEC_PID
                .load(Ordering::SeqCst),
            yield_pid: X86_RUNTIME
                .LINUX_PROCESS_CHILD_YIELD_PID
                .load(Ordering::SeqCst),
            pids_restored: core::cell::Cell::new(false),
        }
    }
}

impl Drop for LinuxForkExecFlagGuard {
    fn drop(&mut self) {
        X86_RUNTIME
            .LINUX_PROCESS_RELEASE_PARENT_ON_EXEC
            .store(self.previous, Ordering::SeqCst);
        self.resume_parent();
    }
}

impl LinuxForkExecFlagGuard {
    /// Points the exit, exec and yield pids back at the outer transaction's
    /// child before the parent resumes inside this transaction; once only.
    /// The flags stay as they are (this transaction took its child's
    /// report), and an exit or yield reported meanwhile keeps its pid.
    pub(super) fn resume_parent(&self) {
        if self.pids_restored.replace(true) {
            return;
        }
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXEC_PID
            .store(self.exec_pid, Ordering::SeqCst);
        if !X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXITED
            .load(Ordering::SeqCst)
        {
            X86_RUNTIME
                .LINUX_PROCESS_CHILD_EXIT_PID
                .store(self.exit_pid, Ordering::SeqCst);
        }
        if !X86_RUNTIME
            .LINUX_PROCESS_CHILD_YIELDED
            .load(Ordering::SeqCst)
        {
            X86_RUNTIME
                .LINUX_PROCESS_CHILD_YIELD_PID
                .store(self.yield_pid, Ordering::SeqCst);
        }
    }
}

// Keep the large process-state snapshot in this bounded frame. Inlining this
// function into the recursive fork executor retains roughly 50 KiB for every
// live child and can exhaust the kernel stack during a systemd boot.
#[inline(never)]
pub(super) fn stage_linux_fork_parent_runtime_state(
    parent_pid: u32,
    share_descriptors: bool,
) -> Option<LinuxForkParentRuntime> {
    assign_linux_open_file_ids();
    current_linux_thread_slot()?;
    let mut state = capture_linux_process_runtime_state()?;
    state.active = true;
    state.completed = false;
    state.exit_status = 0;
    state.termination_signal = 0;
    // The child's copy holds the open files again, unless the two share
    // the one table (CLONE_FILES), whose files the group holds once.
    if !share_descriptors && !retain_linux_descriptor_runtime_state(&mut state.descriptors) {
        return None;
    }
    let parent_stack = current_linux_thread_slot().map(|slot| {
        (
            slot,
            X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].load(Ordering::SeqCst),
            X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].load(Ordering::SeqCst),
        )
    });
    let nice = state.nice;
    *linux_process_runtime_state(parent_pid)? = state;
    LINUX_BANK_STAGED[linux_cpu_bank()].store(true, Ordering::Release);
    Some(LinuxForkParentRuntime {
        stack: parent_stack,
        nice,
    })
}

pub(super) fn release_staged_linux_fork_descriptors(parent_pid: u32, shared: bool) {
    if shared {
        return;
    }
    if let Some(state) = linux_process_runtime_state(parent_pid).filter(|state| state.valid) {
        release_linux_descriptor_runtime_state(&state.descriptors);
    }
}

pub(super) fn stage_linux_fork_child_runtime_state(
    parent_pid: u32,
    child_pid: u32,
    new_mount_namespace: bool,
) -> Option<linux_mount::MountNamespaceHandle> {
    let parent: &LinuxProcessRuntimeState =
        linux_process_runtime_state(parent_pid).filter(|state| state.valid)?;
    let child = linux_process_runtime_state(child_pid)?;
    let parent_threads: &[LinuxThreadRuntimeState; LINUX_THREAD_LIMIT] =
        linux_process_thread_runtime_state(parent_pid)?;
    let child_threads = linux_process_thread_runtime_state(child_pid)?;
    if parent_pid == child_pid {
        return None;
    }
    let mount_namespace = if new_mount_namespace {
        linux_clone_mount_namespace()?
    } else {
        parent.mount_namespace?
    };
    // Parent and child are different processes, so different records; the
    // slices copy in place, with no record-sized temporary on the stack.
    core::slice::from_mut(&mut *child).copy_from_slice(core::slice::from_ref(parent));
    child_threads.copy_from_slice(parent_threads);
    {
        let current = usize::from(child.current_thread_slot);
        for (slot, thread) in child_threads.iter_mut().enumerate() {
            if slot != current {
                *thread = LinuxThreadRuntimeState::EMPTY;
            }
        }
        if current < LINUX_THREAD_LIMIT {
            child_threads[current].tid = child_pid;
            child_threads[current].state = LINUX_THREAD_RUNNING;
            // A new task's CPU time starts at zero: inherited, the parent's
            // (a test runner's minutes) counted against the child's
            // RLIMIT_CPU and CPU-clock timers (setrlimit06).
            child_threads[current].cpu_cycles = 0;
        }
        child.last_preempted_thread_slot = LINUX_THREAD_SLOT_NONE;
        child.next_tid = child_pid.saturating_add(1);
        child.active = true;
        child.completed = false;
        child.exit_status = 0;
        child.termination_signal = 0;
        child.real_timer_interval = 0;
        child.real_timer_deadline = 0;
        child.posix_timer_deadline = 0;
        child.pending_signals = 0;
        child.pending_signal_codes.fill(0);
        child.pending_signal_values.fill(0);
        child.signal_active = false;
        child.signal_context = LinuxSignalContext::ZERO;
        child.parent_death_signal = 0;
        child.mount_namespace = Some(mount_namespace);
    }
    Some(mount_namespace)
}

pub(super) fn save_current_linux_process_runtime_state(pid: u32) {
    crate::linux_profile::span(crate::linux_profile::Span::SaveProcess, || {
        save_current_linux_process_runtime_state_now(pid)
    })
}

fn save_current_linux_process_runtime_state_now(pid: u32) {
    let started = cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
    // The thread leaves first, so its switch is in the interval charged.
    if let Some(slot) = current_linux_thread_slot() {
        linux_charge_thread_cpu(slot);
    }
    linux_process::charge_live_process_cpu(timer::timestamp_counter());
    adopt_linux_process_bank(pid);
    if !linux_bank_holds(linux_cpu_bank(), pid, linux_execution_instance()) {
        // The bank holds another process: its state is not this one's.
        LINUX_BANK_FOREIGN_SAVES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if linux_child_exited(pid) {
        wait_for_linux_process_threads_to_leave(pid);
    }
    if let (Some(state), Some(destination)) = (
        capture_linux_process_runtime_state(),
        linux_process_runtime_state(pid),
    ) {
        *destination = state;
    }
    if let Some(started) = started {
        X86_RUNTIME
            .LINUX_BOOT_PROFILE_SAVE_COUNT
            .fetch_add(1, Ordering::Relaxed);
        X86_RUNTIME.LINUX_BOOT_PROFILE_SAVE_TICKS.fetch_add(
            timer::timestamp_counter().saturating_sub(started),
            Ordering::Relaxed,
        );
    }
}

pub(super) fn restore_saved_linux_process_runtime_state(pid: u32) -> bool {
    crate::linux_profile::span(crate::linux_profile::Span::RestoreProcess, || {
        restore_saved_linux_process_runtime_state_now(pid)
    })
}

fn restore_saved_linux_process_runtime_state_now(pid: u32) -> bool {
    let started = cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
    let Some(state) = linux_process_runtime_state(pid).filter(|state| state.valid) else {
        return false;
    };
    let Some(attached) = attach_linux_process_bank(pid, true) else {
        return false;
    };
    linux_process::start_live_process_cpu(pid, timer::timestamp_counter());
    linux_mark_thread_cpu();
    if attached == BankAttach::Live {
        // Threads of the process run on other CPUs: the bank is its state,
        // newer than what was saved. This CPU takes up the saved thread.
        X86_RUNTIME
            .LINUX_CURRENT_THREAD_SLOT
            .store(state.current_thread_slot, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_LAST_PREEMPTED_THREAD_SLOT
            .store(state.last_preempted_thread_slot, Ordering::SeqCst);
        let thread_signal_mask = X86_RUNTIME
            .LINUX_THREAD_SIGNAL_MASKS
            .get(usize::from(state.current_thread_slot))
            .map_or(0, |mask| mask.load(Ordering::SeqCst));
        X86_RUNTIME
            .ELF_PROBE_SIGNAL_MASK
            .store(thread_signal_mask, Ordering::SeqCst);
        return true;
    }
    restore_linux_process_runtime_state(state);
    let Some(threads) = linux_process_thread_runtime_state(pid) else {
        return false;
    };
    restore_linux_thread_runtime_state(
        threads,
        state.current_thread_slot,
        state.last_preempted_thread_slot,
    );
    let thread_signal_mask = threads
        .get(usize::from(state.current_thread_slot))
        .map_or(0, |thread| thread.signal_mask);
    X86_RUNTIME
        .ELF_PROBE_SIGNAL_MASK
        .store(thread_signal_mask, Ordering::SeqCst);
    if let Some(started) = started {
        X86_RUNTIME
            .LINUX_BOOT_PROFILE_RESTORE_COUNT
            .fetch_add(1, Ordering::Relaxed);
        X86_RUNTIME.LINUX_BOOT_PROFILE_RESTORE_TICKS.fetch_add(
            timer::timestamp_counter().saturating_sub(started),
            Ordering::Relaxed,
        );
    }
    true
}

// Isolate the large descriptor snapshot from callers that remain on the
// kernel stack while a child process runs.
#[inline(never)]
pub(super) fn capture_linux_descriptors_for_process(pid: u32) -> bool {
    let Some(state) = linux_process_runtime_state(pid) else {
        return false;
    };
    assign_linux_open_file_ids();
    state.descriptors = capture_linux_descriptor_runtime_state();
    true
}

pub(super) fn capture_linux_thread_runtime_state(slot: usize) -> LinuxThreadRuntimeState {
    LinuxThreadRuntimeState {
        state: X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst),
        generation: X86_RUNTIME.LINUX_THREAD_GENERATIONS[slot].load(Ordering::SeqCst),
        tid: X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst),
        pointer: X86_RUNTIME.LINUX_THREAD_POINTERS[slot].load(Ordering::SeqCst),
        tls_extent: X86_RUNTIME.LINUX_THREAD_TLS_EXTENTS[slot].load(Ordering::SeqCst),
        tls_size: X86_RUNTIME.LINUX_THREAD_TLS_SIZES[slot].load(Ordering::SeqCst),
        stack_base: X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].load(Ordering::SeqCst),
        stack_size: X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].load(Ordering::SeqCst),
        registers: core::array::from_fn(|index| {
            X86_RUNTIME.LINUX_THREAD_REGISTERS[slot][index].load(Ordering::SeqCst)
        }),
        rip: X86_RUNTIME.LINUX_THREAD_RIPS[slot].load(Ordering::SeqCst),
        rsp: X86_RUNTIME.LINUX_THREAD_RSPS[slot].load(Ordering::SeqCst),
        rflags: X86_RUNTIME.LINUX_THREAD_RFLAGS[slot].load(Ordering::SeqCst),
        rax: X86_RUNTIME.LINUX_THREAD_RAXS[slot].load(Ordering::SeqCst),
        rcx: X86_RUNTIME.LINUX_THREAD_RCXS[slot].load(Ordering::SeqCst),
        r11: X86_RUNTIME.LINUX_THREAD_R11S[slot].load(Ordering::SeqCst),
        clear_child_tid: X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[slot].load(Ordering::SeqCst),
        robust_list: X86_RUNTIME.LINUX_THREAD_ROBUST_LISTS[slot].load(Ordering::SeqCst),
        rseq_pointer: X86_RUNTIME.LINUX_THREAD_RSEQ_POINTERS[slot].load(Ordering::SeqCst),
        rseq_length: X86_RUNTIME.LINUX_THREAD_RSEQ_LENGTHS[slot].load(Ordering::SeqCst),
        rseq_signature: X86_RUNTIME.LINUX_THREAD_RSEQ_SIGNATURES[slot].load(Ordering::SeqCst),
        signal_mask: X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].load(Ordering::SeqCst),
        wait_kind: X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst),
        wait_key: X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst),
        wait_output: X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst),
        wait_deadline: X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::SeqCst),
        wait_prior_signal_mask: X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot]
            .load(Ordering::SeqCst),
        poll_descriptors: core::array::from_fn(|index| {
            X86_RUNTIME.LINUX_THREAD_POLL_DESCRIPTORS[slot][index].load(Ordering::SeqCst)
        }),
        poll_events: core::array::from_fn(|index| {
            X86_RUNTIME.LINUX_THREAD_POLL_EVENTS[slot][index].load(Ordering::SeqCst)
        }),
        select_read_address: X86_RUNTIME.LINUX_THREAD_SELECT_READ_ADDRESSES[slot]
            .load(Ordering::SeqCst),
        select_write_address: X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_ADDRESSES[slot]
            .load(Ordering::SeqCst),
        select_exception_address: X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES[slot]
            .load(Ordering::SeqCst),
        select_timeout_address: X86_RUNTIME.LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES[slot]
            .load(Ordering::SeqCst),
        select_read_set: core::array::from_fn(|index| {
            X86_RUNTIME.LINUX_THREAD_SELECT_READ_SETS[slot][index].load(Ordering::SeqCst)
        }),
        select_write_set: core::array::from_fn(|index| {
            X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_SETS[slot][index].load(Ordering::SeqCst)
        }),
        select_exception_set: core::array::from_fn(|index| {
            X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_SETS[slot][index].load(Ordering::SeqCst)
        }),
        iov_addresses: core::array::from_fn(|index| {
            X86_RUNTIME.LINUX_THREAD_IOV_ADDRESSES[slot][index].load(Ordering::SeqCst)
        }),
        iov_lengths: core::array::from_fn(|index| {
            X86_RUNTIME.LINUX_THREAD_IOV_LENGTHS[slot][index].load(Ordering::SeqCst)
        }),
        owner_only: X86_RUNTIME.LINUX_THREAD_OWNER_ONLY[slot].load(Ordering::SeqCst),
        nice: X86_RUNTIME.LINUX_THREAD_NICES[slot].load(Ordering::SeqCst),
        cpu_cycles: X86_RUNTIME.LINUX_THREAD_CPU_CYCLES[slot].load(Ordering::SeqCst),
        last_cpu: X86_RUNTIME.LINUX_THREAD_LAST_CPUS[slot].load(Ordering::SeqCst),
    }
}

fn restore_linux_thread_runtime_state(
    threads: &[LinuxThreadRuntimeState; LINUX_THREAD_LIMIT],
    current: u8,
    last_preempted: u8,
) {
    for (slot, state) in threads.iter().enumerate() {
        // A slot free in both tables is already clear but for its generation.
        if state.state == LINUX_THREAD_FREE
            && X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_FREE
        {
            X86_RUNTIME.LINUX_THREAD_GENERATIONS[slot].store(state.generation, Ordering::SeqCst);
            continue;
        }
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(state.state, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_GENERATIONS[slot].store(state.generation, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_TIDS[slot].store(state.tid, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_NICES[slot].store(state.nice, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_CPU_CYCLES[slot].store(state.cpu_cycles, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_LAST_CPUS[slot].store(state.last_cpu, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_POINTERS[slot].store(state.pointer, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_TLS_EXTENTS[slot].store(state.tls_extent, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_TLS_SIZES[slot].store(state.tls_size, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].store(state.stack_base, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].store(state.stack_size, Ordering::SeqCst);
        for (destination, value) in X86_RUNTIME.LINUX_THREAD_REGISTERS[slot]
            .iter()
            .zip(state.registers)
        {
            destination.store(value, Ordering::SeqCst);
        }
        X86_RUNTIME.LINUX_THREAD_RIPS[slot].store(state.rip, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RSPS[slot].store(state.rsp, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RFLAGS[slot].store(state.rflags, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(state.rax, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RCXS[slot].store(state.rcx, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_R11S[slot].store(state.r11, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[slot]
            .store(state.clear_child_tid, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_ROBUST_LISTS[slot].store(state.robust_list, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RSEQ_POINTERS[slot].store(state.rseq_pointer, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RSEQ_LENGTHS[slot].store(state.rseq_length, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RSEQ_SIGNATURES[slot]
            .store(state.rseq_signature, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(state.signal_mask, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_OWNER_ONLY[slot].store(state.owner_only, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(state.wait_kind, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(state.wait_key, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(state.wait_output, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(state.wait_deadline, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot]
            .store(state.wait_prior_signal_mask, Ordering::SeqCst);
        for (destination, value) in X86_RUNTIME.LINUX_THREAD_POLL_DESCRIPTORS[slot]
            .iter()
            .zip(state.poll_descriptors)
        {
            destination.store(value, Ordering::SeqCst);
        }
        for (destination, value) in X86_RUNTIME.LINUX_THREAD_POLL_EVENTS[slot]
            .iter()
            .zip(state.poll_events)
        {
            destination.store(value, Ordering::SeqCst);
        }
        X86_RUNTIME.LINUX_THREAD_SELECT_READ_ADDRESSES[slot]
            .store(state.select_read_address, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_ADDRESSES[slot]
            .store(state.select_write_address, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES[slot]
            .store(state.select_exception_address, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES[slot]
            .store(state.select_timeout_address, Ordering::SeqCst);
        for (destination, value) in X86_RUNTIME.LINUX_THREAD_SELECT_READ_SETS[slot]
            .iter()
            .zip(state.select_read_set)
        {
            destination.store(value, Ordering::SeqCst);
        }
        for (destination, value) in X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_SETS[slot]
            .iter()
            .zip(state.select_write_set)
        {
            destination.store(value, Ordering::SeqCst);
        }
        for (destination, value) in X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_SETS[slot]
            .iter()
            .zip(state.select_exception_set)
        {
            destination.store(value, Ordering::SeqCst);
        }
        for (destination, value) in X86_RUNTIME.LINUX_THREAD_IOV_ADDRESSES[slot]
            .iter()
            .zip(state.iov_addresses)
        {
            destination.store(value, Ordering::SeqCst);
        }
        for (destination, value) in X86_RUNTIME.LINUX_THREAD_IOV_LENGTHS[slot]
            .iter()
            .zip(state.iov_lengths)
        {
            destination.store(value, Ordering::SeqCst);
        }
    }
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(current, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_LAST_PREEMPTED_THREAD_SLOT
        .store(last_preempted, Ordering::SeqCst);
    // The timed- and descriptor-wait scan hints describe the current
    // process's threads, and a process that ran in between clears them when
    // its own scan finds nothing. A blocked thread here needs the next scans
    // to look again, or its select, poll or timeout is never completed.
    if threads
        .iter()
        .any(|thread| thread.state == LINUX_THREAD_BLOCKED)
    {
        X86_RUNTIME
            .LINUX_TIMED_WAITS_ACTIVE
            .store(true, Ordering::Release);
        X86_RUNTIME
            .LINUX_DESCRIPTOR_WAITS_ACTIVE
            .store(true, Ordering::Release);
    }
}

/// The current process's runtime state; no thread may be current (all of
/// them parked in calls, ready, or the current one just ended).
fn capture_linux_process_runtime_state() -> Option<LinuxProcessRuntimeState> {
    capture_linux_process_runtime_state_for(
        current_linux_thread_slot().map_or(LINUX_THREAD_SLOT_NONE, |slot| slot as u8),
    )
}

/// `capture_linux_process_runtime_state` with `thread_slot` as the thread
/// the process resumes with: the current one, or, from a CPU running none
/// of the process's threads, the one whose context the registry holds.
pub(super) fn capture_linux_process_runtime_state_for(
    thread_slot: u8,
) -> Option<LinuxProcessRuntimeState> {
    let pid = current_linux_process_pid();
    let threads = linux_process_thread_runtime_state(pid)?;
    for (slot, state) in threads.iter_mut().enumerate() {
        // A free slot is clear but for its generation (see
        // clear_linux_thread_slot): copying its ~17 KiB of zeros on every
        // process switch was most of a switch's cost.
        *state =
            if X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_FREE {
                LinuxThreadRuntimeState {
                    generation: X86_RUNTIME.LINUX_THREAD_GENERATIONS[slot].load(Ordering::SeqCst),
                    ..LinuxThreadRuntimeState::EMPTY
                }
            } else {
                capture_linux_thread_runtime_state(slot)
            };
    }
    Some(LinuxProcessRuntimeState {
        valid: true,
        active: X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst),
        completed: X86_RUNTIME.ELF_PROBE_COMPLETED.load(Ordering::SeqCst),
        exit_status: X86_RUNTIME.ELF_PROBE_EXIT_STATUS.load(Ordering::SeqCst),
        termination_signal: X86_RUNTIME
            .ELF_PROBE_TERMINATION_SIGNAL
            .load(Ordering::SeqCst),
        parent_death_signal: X86_RUNTIME
            .ELF_PROBE_PARENT_DEATH_SIGNAL
            .load(Ordering::SeqCst),
        mount_namespace: linux_mount::current_handle(),
        mmap: capture_linux_mmap_runtime_state(),
        descriptors: capture_linux_descriptor_runtime_state(),
        image_extents: [
            X86_RUNTIME.ELF_PROBE_CODE_BASE.load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_CODE_SIZE.load(Ordering::SeqCst),
            X86_RUNTIME
                .ELF_PROBE_LOADER_CODE_BASE
                .load(Ordering::SeqCst),
            X86_RUNTIME
                .ELF_PROBE_LOADER_CODE_SIZE
                .load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_DATA.load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_DATA_SIZE.load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_RELRO.load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_RELRO_SIZE.load(Ordering::SeqCst),
        ],
        brk: X86_RUNTIME.ELF_PROBE_BRK.load(Ordering::SeqCst),
        stack: X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst),
        stack_low: X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst),
        cwd: X86_RUNTIME.ELF_PROBE_CWD.load(Ordering::SeqCst),
        rootfs_cwd: X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.load(Ordering::SeqCst),
        overlay_cwd: X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.load(Ordering::SeqCst),
        umask: X86_RUNTIME.ELF_PROBE_UMASK.load(Ordering::SeqCst),
        rlimits: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_RLIMITS[index].load(Ordering::SeqCst)
        }),
        process_name: [
            X86_RUNTIME
                .ELF_PROBE_PROCESS_NAME_LOW
                .load(Ordering::SeqCst),
            X86_RUNTIME
                .ELF_PROBE_PROCESS_NAME_HIGH
                .load(Ordering::SeqCst),
        ],
        dumpable: X86_RUNTIME.ELF_PROBE_DUMPABLE.load(Ordering::SeqCst),
        tsc_sigsegv: X86_RUNTIME.ELF_PROBE_TSC_SIGSEGV.load(Ordering::SeqCst),
        securebits: X86_RUNTIME.ELF_PROBE_SECUREBITS.load(Ordering::SeqCst),
        personality: X86_RUNTIME.ELF_PROBE_PERSONALITY.load(Ordering::SeqCst),
        nice: X86_RUNTIME.ELF_PROBE_NICE.load(Ordering::SeqCst),
        ioprio: X86_RUNTIME.ELF_PROBE_IOPRIO.load(Ordering::SeqCst),
        no_new_privileges: X86_RUNTIME.ELF_PROBE_NO_NEW_PRIVS.load(Ordering::SeqCst),
        seccomp_strict: X86_RUNTIME.ELF_PROBE_SECCOMP_STRICT.load(Ordering::SeqCst),
        seccomp_filtered: X86_RUNTIME
            .ELF_PROBE_SECCOMP_FILTERED
            .load(Ordering::SeqCst),
        membarrier_registrations: X86_RUNTIME
            .ELF_PROBE_MEMBARRIER_REGISTRATIONS
            .load(Ordering::SeqCst),
        real_timer_interval: X86_RUNTIME
            .ELF_PROBE_REAL_TIMER_INTERVAL
            .load(Ordering::SeqCst),
        real_timer_deadline: X86_RUNTIME
            .ELF_PROBE_REAL_TIMER_DEADLINE
            .load(Ordering::SeqCst),
        posix_timer_deadline: X86_RUNTIME
            .ELF_PROBE_POSIX_TIMER_DEADLINE
            .load(Ordering::SeqCst),
        pending_signals: X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst),
        pending_signal_codes: core::array::from_fn(|signal| {
            X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[signal].load(Ordering::SeqCst)
        }),
        pending_signal_values: core::array::from_fn(|signal| {
            X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[signal].load(Ordering::SeqCst)
        }),
        signal_active: X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst),
        signal_context: current_linux_signal_context(),
        exec_ignored_signals: X86_RUNTIME
            .ELF_PROBE_EXEC_IGNORED_SIGNALS
            .load(Ordering::SeqCst),
        signal_handlers: core::array::from_fn(|signal| {
            X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal].load(Ordering::SeqCst)
        }),
        signal_flags: core::array::from_fn(|signal| {
            X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[signal].load(Ordering::SeqCst)
        }),
        signal_restorers: core::array::from_fn(|signal| {
            X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[signal].load(Ordering::SeqCst)
        }),
        signal_action_masks: core::array::from_fn(|signal| {
            X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[signal].load(Ordering::SeqCst)
        }),
        alternate_signal_stack: [
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_POINTER
                .load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_ALT_STACK_SIZE.load(Ordering::SeqCst),
        ],
        alternate_signal_stack_flags: X86_RUNTIME.ELF_PROBE_ALT_STACK_FLAGS.load(Ordering::SeqCst),
        current_thread_slot: thread_slot,
        last_preempted_thread_slot: X86_RUNTIME
            .LINUX_LAST_PREEMPTED_THREAD_SLOT
            .load(Ordering::SeqCst),
        next_tid: X86_RUNTIME.LINUX_NEXT_TID.load(Ordering::SeqCst),
    })
}

fn restore_linux_process_runtime_state(state: &LinuxProcessRuntimeState) {
    if let Some(namespace) = state.mount_namespace {
        let _ = linux_mount::switch_to(namespace);
    }
    X86_RUNTIME
        .ELF_PROBE_ACTIVE
        .store(state.active, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_COMPLETED
        .store(state.completed, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EXIT_STATUS
        .store(state.exit_status, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_TERMINATION_SIGNAL
        .store(state.termination_signal, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PARENT_DEATH_SIGNAL
        .store(state.parent_death_signal, Ordering::SeqCst);
    restore_linux_mmap_runtime_state(state.mmap);
    restore_linux_descriptor_runtime_state(&state.descriptors);
    for (destination, value) in [
        &X86_RUNTIME.ELF_PROBE_CODE_BASE,
        &X86_RUNTIME.ELF_PROBE_CODE_SIZE,
        &X86_RUNTIME.ELF_PROBE_LOADER_CODE_BASE,
        &X86_RUNTIME.ELF_PROBE_LOADER_CODE_SIZE,
        &X86_RUNTIME.ELF_PROBE_DATA,
        &X86_RUNTIME.ELF_PROBE_DATA_SIZE,
        &X86_RUNTIME.ELF_PROBE_RELRO,
        &X86_RUNTIME.ELF_PROBE_RELRO_SIZE,
    ]
    .into_iter()
    .zip(state.image_extents)
    {
        destination.store(value, Ordering::SeqCst);
    }
    X86_RUNTIME.ELF_PROBE_BRK.store(state.brk, Ordering::SeqCst);
    if state.stack != 0 {
        X86_RUNTIME
            .ELF_PROBE_STACK
            .store(state.stack, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_STACK_LOW
        .store(state.stack_low, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_CWD.store(state.cwd, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ROOTFS_CWD
        .store(state.rootfs_cwd, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_OVERLAY_CWD
        .store(state.overlay_cwd, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_UMASK
        .store(state.umask, Ordering::SeqCst);
    for (limit, value) in X86_RUNTIME
        .ELF_PROBE_RLIMITS
        .iter()
        .zip(state.rlimits.iter().copied())
    {
        limit.store(value, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_LOW
        .store(state.process_name[0], Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_HIGH
        .store(state.process_name[1], Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_DUMPABLE
        .store(state.dumpable, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_TSC_SIGSEGV
        .store(state.tsc_sigsegv, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SECUREBITS
        .store(state.securebits, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PERSONALITY
        .store(state.personality, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_NICE
        .store(state.nice, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_IOPRIO
        .store(state.ioprio, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_NO_NEW_PRIVS
        .store(state.no_new_privileges, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SECCOMP_STRICT
        .store(state.seccomp_strict, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SECCOMP_FILTERED
        .store(state.seccomp_filtered, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_MEMBARRIER_REGISTRATIONS
        .store(state.membarrier_registrations, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_INTERVAL
        .store(state.real_timer_interval, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_DEADLINE
        .store(state.real_timer_deadline, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_POSIX_TIMER_DEADLINE
        .store(state.posix_timer_deadline, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PENDING_SIGNALS
        .store(state.pending_signals, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_ACTIVE
        .store(state.signal_active, Ordering::SeqCst);
    set_current_linux_signal_context(state.signal_context);
    X86_RUNTIME
        .ELF_PROBE_EXEC_IGNORED_SIGNALS
        .store(state.exec_ignored_signals, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_POINTER
        .store(state.alternate_signal_stack[0], Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_SIZE
        .store(state.alternate_signal_stack[1], Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_FLAGS
        .store(state.alternate_signal_stack_flags, Ordering::SeqCst);
    for signal in 0..LINUX_SIGNAL_COUNT {
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[signal]
            .store(state.pending_signal_codes[signal], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[signal]
            .store(state.pending_signal_values[signal], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal]
            .store(state.signal_handlers[signal], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[signal]
            .store(state.signal_flags[signal], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[signal]
            .store(state.signal_restorers[signal], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[signal]
            .store(state.signal_action_masks[signal], Ordering::SeqCst);
    }
    X86_RUNTIME
        .LINUX_NEXT_TID
        .store(state.next_tid, Ordering::SeqCst);
}

/// The parts of a process's runtime state clone can share with other
/// processes: the descriptor table (CLONE_FILES), the filesystem context,
/// cwd and umask (CLONE_FS), and the signal handlers (CLONE_SIGHAND).
#[derive(Clone, Copy)]
struct LinuxSharedRuntimeParts {
    descriptors: bool,
    filesystem: bool,
    signal_handlers: bool,
}

impl LinuxSharedRuntimeParts {
    /// What process `pid` shares with another live process now.
    fn of(pid: u32) -> Self {
        use linux_process::SharedResource;
        let shared = |resource| linux_process::live_process_resource_shared(pid, resource);
        Self {
            descriptors: shared(SharedResource::Descriptors),
            filesystem: shared(SharedResource::Filesystem),
            signal_handlers: shared(SharedResource::SignalHandlers),
        }
    }

    fn any(self) -> bool {
        self.descriptors || self.filesystem || self.signal_handlers
    }
}

/// Processes that share runtime state each keep a copy of it, in their
/// bank while they run and in their record otherwise: the record is the
/// state, and a running process's bank is brought up to date from it as a
/// system call starts (or a parked one resumes), then written back to the
/// records of everyone sharing it when the call ends (or parks). System
/// calls run one at a time under the kernel-entry lock, so each one sees
/// what the last one left. One table's open files are held once, by the
/// group: only the last process to end releases them.
#[inline(never)]
pub(super) fn pull_linux_shared_runtime_state() {
    if !linux_processes_may_share_state() {
        return;
    }
    let pid = current_linux_process_pid();
    let parts = LinuxSharedRuntimeParts::of(pid);
    if !parts.any() || !linux_bank_holds(linux_cpu_bank(), pid, linux_execution_instance()) {
        return;
    }
    let Some(state) = linux_process_runtime_state(pid).filter(|state| state.valid) else {
        return;
    };
    if parts.descriptors {
        install_linux_descriptor_runtime_state(&state.descriptors);
    }
    if parts.filesystem {
        X86_RUNTIME.ELF_PROBE_CWD.store(state.cwd, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_ROOTFS_CWD
            .store(state.rootfs_cwd, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_OVERLAY_CWD
            .store(state.overlay_cwd, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_UMASK
            .store(state.umask, Ordering::SeqCst);
    }
    if parts.signal_handlers {
        for signal in 0..LINUX_SIGNAL_COUNT {
            X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal]
                .store(state.signal_handlers[signal], Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[signal]
                .store(state.signal_flags[signal], Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[signal]
                .store(state.signal_restorers[signal], Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[signal]
                .store(state.signal_action_masks[signal], Ordering::SeqCst);
        }
    }
}

/// Writes what the current process shares with others from its bank to
/// its record and theirs (see `pull_linux_shared_runtime_state`).
#[inline(never)]
pub(super) fn push_linux_shared_runtime_state() {
    use linux_process::SharedResource;
    if !linux_processes_may_share_state() {
        return;
    }
    let pid = current_linux_process_pid();
    let parts = LinuxSharedRuntimeParts::of(pid);
    if !parts.any() || !linux_bank_holds(linux_cpu_bank(), pid, linux_execution_instance()) {
        return;
    }
    let Some(state) = linux_process_runtime_state(pid).filter(|state| state.valid) else {
        return;
    };
    if parts.descriptors {
        assign_linux_open_file_ids();
        state.descriptors = capture_linux_descriptor_runtime_state();
    }
    if parts.filesystem {
        state.cwd = X86_RUNTIME.ELF_PROBE_CWD.load(Ordering::SeqCst);
        state.rootfs_cwd = X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.load(Ordering::SeqCst);
        state.overlay_cwd = X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.load(Ordering::SeqCst);
        state.umask = X86_RUNTIME.ELF_PROBE_UMASK.load(Ordering::SeqCst);
    }
    if parts.signal_handlers {
        for signal in 0..LINUX_SIGNAL_COUNT {
            state.signal_handlers[signal] =
                X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal].load(Ordering::SeqCst);
            state.signal_flags[signal] =
                X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[signal].load(Ordering::SeqCst);
            state.signal_restorers[signal] =
                X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[signal].load(Ordering::SeqCst);
            state.signal_action_masks[signal] =
                X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[signal].load(Ordering::SeqCst);
        }
    }
    let source: &LinuxProcessRuntimeState = state;
    let copy_to_sharers = |resource, copy: &dyn Fn(&mut LinuxProcessRuntimeState)| {
        for peer in linux_process::live_processes_sharing(pid, resource) {
            if let Some(destination) = linux_process_runtime_state(peer).filter(|state| state.valid)
            {
                copy(destination);
            }
        }
    };
    // `source` is this process's record, which no copy below writes: each
    // destination is another process's.
    if parts.descriptors {
        copy_to_sharers(SharedResource::Descriptors, &|destination| {
            destination.descriptors = source.descriptors;
        });
    }
    if parts.filesystem {
        copy_to_sharers(SharedResource::Filesystem, &|destination| {
            destination.cwd = source.cwd;
            destination.rootfs_cwd = source.rootfs_cwd;
            destination.overlay_cwd = source.overlay_cwd;
            destination.umask = source.umask;
        });
    }
    if parts.signal_handlers {
        copy_to_sharers(SharedResource::SignalHandlers, &|destination| {
            destination.signal_handlers = source.signal_handlers;
            destination.signal_flags = source.signal_flags;
            destination.signal_restorers = source.signal_restorers;
            destination.signal_action_masks = source.signal_action_masks;
        });
    }
}

/// Whether any process of the running domain may share runtime state
/// with another: only then does a system call look for sharers.
fn linux_processes_may_share_state() -> bool {
    X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Relaxed)
        && linux_process::live_processes_share_state()
}

/// Keeps the current process's shared runtime state in step around one
/// system call: brought up to date as it is made, written back as it
/// leaves (see `pull_linux_shared_runtime_state`).
pub(super) struct LinuxSharedStateCall;

impl LinuxSharedStateCall {
    pub(super) fn enter() -> Self {
        pull_linux_shared_runtime_state();
        Self
    }
}

impl Drop for LinuxSharedStateCall {
    fn drop(&mut self) {
        push_linux_shared_runtime_state();
    }
}

/// Releases the open files of process `pid`'s saved descriptor table,
/// which it no longer uses, unless another live process still shares that
/// table (CLONE_FILES): the last one to go releases them.
#[inline(never)]
pub(super) fn release_linux_process_descriptors(pid: u32, state: &LinuxProcessRuntimeState) {
    if !linux_process::live_process_resource_shared(pid, linux_process::SharedResource::Descriptors)
    {
        release_linux_descriptor_runtime_state(&state.descriptors);
    }
}

/// Gives process `pid`, the current one, a descriptor table of its own when
/// it shares one (unshare's CLONE_FILES, CLOSE_RANGE_UNSHARE, exec): a copy
/// of the shared table, whose open files it holds now as well. False when
/// they cannot be held.
#[inline(never)]
pub(super) fn unshare_linux_descriptors(pid: u32) -> bool {
    use linux_process::SharedResource;
    if !linux_process::live_process_resource_shared(pid, SharedResource::Descriptors) {
        return true;
    }
    // The bank is the group's table as this call found it; the part above
    // the fixed table becomes a copy of the process's own.
    assign_linux_open_file_ids();
    let mut table = capture_linux_descriptor_runtime_state();
    if !retain_linux_descriptor_runtime_state(&mut table) {
        return false;
    }
    X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OVERFLOW
        .store(table.overflow, Ordering::SeqCst);
    linux_process::share_live_process_resource(pid, SharedResource::Descriptors, None)
}

/// An exec leaves what the process shared with others behind, as Linux's
/// does (unshare_files, unshare_sighand): a descriptor table of its own,
/// whose open files it holds now as well, and signal handlers of its own,
/// which the new program resets. The filesystem context stays shared.
#[inline(never)]
pub(super) fn unshare_linux_state_for_exec(pid: u32) {
    use linux_process::SharedResource;
    if !linux_processes_may_share_state() {
        return;
    }
    let _ = unshare_linux_descriptors(pid);
    if linux_process::live_process_resource_shared(pid, SharedResource::SignalHandlers) {
        let _ =
            linux_process::share_live_process_resource(pid, SharedResource::SignalHandlers, None);
    }
}

/// Gives every open descriptor its open-file id before the table is copied
/// to a child: ids are otherwise assigned on first use, and a parent and
/// child that each assigned one later would disagree about sharing a file.
fn assign_linux_open_file_ids() {
    for descriptor in 0..LINUX_DESCRIPTOR_TABLE_LIMIT {
        if linux_descriptor_open(descriptor) {
            let _ = linux_descriptor_open_file_id(descriptor);
        }
    }
    let table = X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OVERFLOW
        .load(Ordering::SeqCst);
    for (descriptor, entry) in crate::linux_fd_table::entries(table) {
        if entry.open_file_id == 0 {
            let _ = linux_descriptor_open_file_id(descriptor);
        }
    }
}

// A process switch saves and installs the whole table, and none of it is
// shared with another CPU then (a process's remote threads are blocked
// before it is switched out), so the copies use relaxed accesses and one
// fence instead of a sequentially consistent store per element.
fn capture_linux_descriptor_runtime_state() -> LinuxDescriptorRuntimeState {
    core::sync::atomic::fence(Ordering::SeqCst);
    let mut state = LinuxDescriptorRuntimeState {
        console: X86_RUNTIME
            .ELF_PROBE_CONSOLE_DESCRIPTORS
            .load(Ordering::Relaxed),
        stderr_open: X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::Relaxed),
        close_on_exec: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_CONSOLE_CLOEXEC[index].load(Ordering::Relaxed)
        }),
        created: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_DESCRIPTOR_CREATED[index].load(Ordering::Relaxed)
        }),
        read_leases: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_DESCRIPTOR_READ_LEASES[index].load(Ordering::Relaxed)
        }),
        write_leases: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_DESCRIPTOR_WRITE_LEASES[index].load(Ordering::Relaxed)
        }),
        devices: X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS.snapshot(),
        rootfs: X86_RUNTIME.ELF_PROBE_ROOTFS_DESCRIPTORS.snapshot(),
        sockets: X86_RUNTIME.ELF_PROBE_SOCKET_SLOTS.snapshot(),
        socket_flags: X86_RUNTIME.ELF_PROBE_SOCKET_FLAGS.snapshot(),
        stdio_sockets: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS[index].load(Ordering::Relaxed)
        }),
        stdio_socket_flags: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[index].load(Ordering::Relaxed)
        }),
        tmp_generations: X86_RUNTIME.ELF_PROBE_TMP_FILE_GENERATIONS.snapshot(),
        offsets: X86_RUNTIME.ELF_PROBE_DESCRIPTOR_OFFSETS.snapshot(),
        stdio_devices: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index].load(Ordering::Relaxed)
        }),
        stdio_rootfs: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS[index].load(Ordering::Relaxed)
        }),
        stdio_tmp_generations: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index].load(Ordering::Relaxed)
        }),
        stdio_offsets: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS[index].load(Ordering::Relaxed)
        }),
        open_file_ids: X86_RUNTIME.ELF_PROBE_OPEN_FILE_IDS.snapshot(),
        stdio_open_file_ids: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_STDIO_OPEN_FILE_IDS[index].load(Ordering::Relaxed)
        }),
        epoll_descriptor: X86_RUNTIME
            .ELF_PROBE_EPOLL_DESCRIPTOR
            .load(Ordering::Relaxed),
        epoll_events: X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS.snapshot(),
        epoll_data: X86_RUNTIME.ELF_PROBE_EPOLL_DATA.snapshot(),
        runtime_epoll_active: X86_RUNTIME.LINUX_RUNTIME_EPOLL_ACTIVE.snapshot(),
        runtime_epoll_aliases: X86_RUNTIME.LINUX_RUNTIME_EPOLL_ALIASES.snapshot(),
        runtime_epoll_watch_epoll: X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL.snapshot(),
        runtime_epoll_watch_seen: X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_SEEN.snapshot(),
        runtime_epoll_watch_target: X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET.snapshot(),
        runtime_eventfd_active: linux_descriptor_bitmap(
            &X86_RUNTIME.LINUX_RUNTIME_EVENTFD_ACTIVE.snapshot(),
        ),
        runtime_timerfd_active: linux_descriptor_bitmap(
            &X86_RUNTIME.LINUX_RUNTIME_TIMERFD_ACTIVE.snapshot(),
        ),
        max_open_file_id: 0,
        overflow: X86_RUNTIME
            .ELF_PROBE_DESCRIPTOR_OVERFLOW
            .load(Ordering::Relaxed),
    };
    state.max_open_file_id = state
        .open_file_ids
        .iter()
        .chain(&state.stdio_open_file_ids)
        .copied()
        .max()
        .unwrap_or(0);
    state
}

/// One bit per descriptor, set where `flags` is non-zero.
fn linux_descriptor_bitmap(
    flags: &[u8; LINUX_DEVICE_DESCRIPTOR_COUNT],
) -> [u64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT] {
    let mut bitmap = [0_u64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT];
    for (index, flag) in flags.iter().enumerate() {
        bitmap[index / 64] |= u64::from(*flag != 0) << (index % 64);
    }
    bitmap
}

/// The flags `bitmap` (from `linux_descriptor_bitmap`) records.
fn linux_descriptor_bitmap_flags(
    bitmap: &[u64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
) -> [u8; LINUX_DEVICE_DESCRIPTOR_COUNT] {
    core::array::from_fn(|index| ((bitmap[index / 64] >> (index % 64)) & 1) as u8)
}

/// The eventfd and timerfd open files saved descriptor table `state` refers
/// to: kind and id, one per descriptor.
fn linux_saved_event_files(
    state: &LinuxDescriptorRuntimeState,
) -> impl Iterator<Item = (crate::linux_event_files::Kind, u64)> + '_ {
    (0..LINUX_DEVICE_DESCRIPTOR_COUNT).filter_map(|index| {
        let (word, bit) = (index / 64, index % 64);
        let kind = if (state.runtime_eventfd_active[word] >> bit) & 1 != 0 {
            crate::linux_event_files::Kind::EventFd
        } else if (state.runtime_timerfd_active[word] >> bit) & 1 != 0 {
            crate::linux_event_files::Kind::TimerFd
        } else {
            return None;
        };
        Some((kind, state.offsets[index]))
    })
}

pub(super) fn retain_linux_descriptor_runtime_state(
    state: &mut LinuxDescriptorRuntimeState,
) -> bool {
    if !retain_linux_fixed_descriptors(state) {
        return false;
    }
    // The descriptors above the fixed table: a reference to their table,
    // which the first change through either copy copies
    // (`linux_own_overflow_table`).
    if state.overflow != 0 && !crate::linux_fd_table::retain(state.overflow) {
        release_linux_descriptor_runtime_state(&LinuxDescriptorRuntimeState {
            overflow: 0,
            ..*state
        });
        return false;
    }
    true
}

/// The current process's table above the fixed one, made its own first
/// when another copy of its descriptors refers to it too (copy on write):
/// the copy holds again what its descriptors refer to. None without
/// memory, or without a table.
pub(super) fn linux_own_overflow_table() -> Option<u32> {
    let table = X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OVERFLOW
        .load(Ordering::SeqCst);
    if table == 0 || !crate::linux_fd_table::shared(table) {
        return (table != 0).then_some(table);
    }
    let copy = crate::linux_fd_table::copy(table)?;
    if !retain_linux_overflow_descriptors(copy) {
        let _ = crate::linux_fd_table::free(copy);
        return None;
    }
    // Other references remain, so this frees nothing.
    let _ = crate::linux_fd_table::release(table);
    X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OVERFLOW
        .store(copy, Ordering::SeqCst);
    Some(copy)
}

/// The eventfd or timerfd open file a descriptor above the fixed table
/// refers to.
fn linux_overflow_event_file(
    entry: &crate::linux_fd_table::Entry,
) -> Option<(crate::linux_event_files::Kind, u64)> {
    match entry.event {
        1 => Some((crate::linux_event_files::Kind::EventFd, entry.offset)),
        2 => Some((crate::linux_event_files::Kind::TimerFd, entry.offset)),
        _ => None,
    }
}

/// Holds again what table `id`'s descriptors above the fixed table refer
/// to (sockets and pipes, POSIX message queues, eventfd and timerfd
/// files), for a copy of them.
fn retain_linux_overflow_descriptors(id: u32) -> bool {
    let entries = crate::linux_fd_table::entries(id);
    for (retained, (_, entry)) in entries.iter().enumerate() {
        let held = if entry.socket != 0 {
            crate::linux_socket::duplicate(entry.socket - 1)
        } else if let Some((kind, file)) = linux_overflow_event_file(entry) {
            crate::linux_event_files::retain(kind, file)
        } else if entry.state & !3 == LINUX_DEVICE_POSIX_MQ {
            u32::try_from(entry.offset)
                .is_ok_and(|queue| crate::linux_sysv_ipc::posix_queue_duplicate(queue).is_ok())
        } else {
            true
        };
        if !held {
            release_linux_overflow_entries(entries.iter().take(retained).map(|(_, entry)| *entry));
            return false;
        }
    }
    true
}

/// Lets go of what the descriptors `entries` (above the fixed table)
/// refer to.
fn release_linux_overflow_entries(entries: impl Iterator<Item = crate::linux_fd_table::Entry>) {
    for entry in entries {
        if entry.socket != 0 {
            let _ = crate::linux_socket::close(entry.socket - 1);
        } else if let Some((kind, file)) = linux_overflow_event_file(&entry) {
            crate::linux_event_files::release(kind, file);
        } else if entry.state & !3 == LINUX_DEVICE_POSIX_MQ {
            if let Ok(destroyed) = crate::linux_sysv_ipc::posix_queue_close(entry.offset as u32) {
                let _ = linux_release_posix_queue_charge(destroyed);
            }
        }
    }
}

fn retain_linux_fixed_descriptors(state: &LinuxDescriptorRuntimeState) -> bool {
    for (retained, (kind, id)) in linux_saved_event_files(state).enumerate() {
        if !crate::linux_event_files::retain(kind, id) {
            for (kind, id) in linux_saved_event_files(state).take(retained) {
                crate::linux_event_files::release(kind, id);
            }
            return false;
        }
    }
    if !retain_linux_descriptor_sockets_and_queues(state) {
        for (kind, id) in linux_saved_event_files(state) {
            crate::linux_event_files::release(kind, id);
        }
        return false;
    }
    true
}

fn retain_linux_descriptor_sockets_and_queues(state: &LinuxDescriptorRuntimeState) -> bool {
    let mut retained = 0_usize;
    for socket in state.stdio_sockets.iter().chain(&state.sockets).copied() {
        if socket == 0 {
            continue;
        }
        if !crate::linux_socket::duplicate(socket - 1) {
            for prior in state
                .stdio_sockets
                .iter()
                .chain(&state.sockets)
                .copied()
                .filter(|slot| *slot != 0)
                .take(retained)
            {
                let _ = crate::linux_socket::close(prior - 1);
            }
            return false;
        }
        retained += 1;
    }
    let devices = state.stdio_devices.iter().chain(&state.devices);
    let offsets = state.stdio_offsets.iter().chain(&state.offsets).copied();
    let mut mq_retained = 0;
    for (device, id) in devices.zip(offsets) {
        if device & !3 != LINUX_DEVICE_POSIX_MQ {
            continue;
        }
        if u32::try_from(id).is_err()
            || crate::linux_sysv_ipc::posix_queue_duplicate(id as u32).is_err()
        {
            for prior_id in state
                .stdio_devices
                .iter()
                .chain(&state.devices)
                .zip(state.stdio_offsets.iter().chain(&state.offsets).copied())
                .filter(|(device, _)| *device & !3 == LINUX_DEVICE_POSIX_MQ)
                .map(|(_, id)| id)
                .take(mq_retained)
            {
                if let Ok(destroyed) = crate::linux_sysv_ipc::posix_queue_close(prior_id as u32) {
                    let _ = linux_release_posix_queue_charge(destroyed);
                }
            }
            return false;
        }
        mq_retained += 1;
    }
    true
}

pub(super) fn release_linux_descriptor_runtime_state(state: &LinuxDescriptorRuntimeState) {
    if state.overflow != 0 {
        release_linux_overflow_entries(
            crate::linux_fd_table::release(state.overflow)
                .into_iter()
                .map(|(_, entry)| entry),
        );
    }
    for (kind, id) in linux_saved_event_files(state) {
        crate::linux_event_files::release(kind, id);
    }
    for socket in state
        .stdio_sockets
        .iter()
        .chain(&state.sockets)
        .copied()
        .filter(|slot| *slot != 0)
    {
        let _ = crate::linux_socket::close(socket - 1);
    }
    // The objects whose last descriptor that was (an open loop device, a
    // pseudo-terminal, ...) go now, as they do at close(2); a process that
    // exits without closing its descriptors left them waiting until some
    // other close, so a loop device it had open stayed open (busy).
    linux_release_objects();
    for (device, id) in state
        .stdio_devices
        .iter()
        .chain(&state.devices)
        .zip(state.stdio_offsets.iter().chain(&state.offsets).copied())
    {
        if device & !3 == LINUX_DEVICE_POSIX_MQ {
            if let Ok(destroyed) = crate::linux_sysv_ipc::posix_queue_close(id as u32) {
                let _ = linux_release_posix_queue_charge(destroyed);
            }
        }
    }
}

fn restore_linux_descriptor_runtime_state(state: &LinuxDescriptorRuntimeState) {
    // A context switch transfers the active descriptor-table view back to the
    // process snapshot saved immediately before this restore. Socket reference
    // counts remain owned by the per-process tables across switches; only
    // close(2) and process teardown may release them.
    install_linux_descriptor_runtime_state(state);
}

fn install_linux_descriptor_runtime_state(state: &LinuxDescriptorRuntimeState) {
    X86_RUNTIME
        .ELF_PROBE_CONSOLE_DESCRIPTORS
        .store(state.console, Ordering::Relaxed);
    X86_RUNTIME
        .ELF_PROBE_STDERR_OPEN
        .store(state.stderr_open, Ordering::Relaxed);
    for (word, value) in X86_RUNTIME
        .ELF_PROBE_CONSOLE_CLOEXEC
        .iter()
        .zip(state.close_on_exec.iter().copied())
    {
        word.store(value, Ordering::Relaxed);
    }
    for (table, values) in [
        (&X86_RUNTIME.ELF_PROBE_DESCRIPTOR_CREATED, &state.created),
        (
            &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_READ_LEASES,
            &state.read_leases,
        ),
        (
            &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_WRITE_LEASES,
            &state.write_leases,
        ),
    ] {
        for (word, value) in table.iter().zip(values.iter().copied()) {
            word.store(value, Ordering::Relaxed);
        }
    }
    for index in 0..state.stdio_sockets.len() {
        X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS[index]
            .store(state.stdio_sockets[index], Ordering::Relaxed);
        X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[index]
            .store(state.stdio_socket_flags[index], Ordering::Relaxed);
    }
    X86_RUNTIME
        .ELF_PROBE_DEVICE_DESCRIPTORS
        .install(&state.devices);
    X86_RUNTIME
        .ELF_PROBE_ROOTFS_DESCRIPTORS
        .install(&state.rootfs);
    X86_RUNTIME.ELF_PROBE_SOCKET_SLOTS.install(&state.sockets);
    X86_RUNTIME
        .ELF_PROBE_SOCKET_FLAGS
        .install(&state.socket_flags);
    X86_RUNTIME
        .ELF_PROBE_TMP_FILE_GENERATIONS
        .install(&state.tmp_generations);
    X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OFFSETS
        .install(&state.offsets);
    X86_RUNTIME
        .ELF_PROBE_OPEN_FILE_IDS
        .install(&state.open_file_ids);
    for index in 0..state.stdio_devices.len() {
        X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index]
            .store(state.stdio_devices[index], Ordering::Relaxed);
        X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS[index]
            .store(state.stdio_rootfs[index], Ordering::Relaxed);
        X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index]
            .store(state.stdio_tmp_generations[index], Ordering::Relaxed);
        X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS[index]
            .store(state.stdio_offsets[index], Ordering::Relaxed);
        X86_RUNTIME.ELF_PROBE_STDIO_OPEN_FILE_IDS[index]
            .store(state.stdio_open_file_ids[index], Ordering::Relaxed);
    }
    X86_RUNTIME
        .ELF_PROBE_EPOLL_DESCRIPTOR
        .store(state.epoll_descriptor, Ordering::Relaxed);
    X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OVERFLOW
        .store(state.overflow, Ordering::Relaxed);
    X86_RUNTIME
        .ELF_PROBE_EPOLL_EVENTS
        .install(&state.epoll_events);
    X86_RUNTIME.ELF_PROBE_EPOLL_DATA.install(&state.epoll_data);
    X86_RUNTIME
        .LINUX_RUNTIME_EPOLL_WATCH_EPOLL
        .install(&state.runtime_epoll_watch_epoll);
    X86_RUNTIME
        .LINUX_RUNTIME_EPOLL_WATCH_SEEN
        .install(&state.runtime_epoll_watch_seen);
    X86_RUNTIME
        .LINUX_RUNTIME_EPOLL_WATCH_TARGET
        .install(&state.runtime_epoll_watch_target);
    X86_RUNTIME
        .LINUX_RUNTIME_EPOLL_ACTIVE
        .install(&state.runtime_epoll_active);
    X86_RUNTIME
        .LINUX_RUNTIME_EPOLL_ALIASES
        .install(&state.runtime_epoll_aliases);
    X86_RUNTIME
        .LINUX_RUNTIME_EVENTFD_ACTIVE
        .install(&linux_descriptor_bitmap_flags(
            &state.runtime_eventfd_active,
        ));
    X86_RUNTIME
        .LINUX_RUNTIME_TIMERFD_ACTIVE
        .install(&linux_descriptor_bitmap_flags(
            &state.runtime_timerfd_active,
        ));
    core::sync::atomic::fence(Ordering::SeqCst);
}
