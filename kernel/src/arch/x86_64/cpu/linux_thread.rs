#![forbid(unsafe_code)]
use super::*;

pub(super) fn reserve_linux_thread(
    context: LinuxTlsContext,
    stack_base: usize,
    stack_size: usize,
) -> Option<LinuxThreadHandle> {
    if !context.is_valid()
        || stack_base == 0
        || !stack_base.is_multiple_of(PAGE_SIZE)
        || stack_size == 0
        || !stack_size.is_multiple_of(PAGE_SIZE)
        || stack_base
            .checked_add(stack_size)
            .is_none_or(|end| end > 1 << 47)
    {
        return None;
    }
    let slot = X86_RUNTIME
        .LINUX_THREAD_STATES
        .iter()
        .position(|state| state.load(Ordering::SeqCst) == LINUX_THREAD_FREE)?;
    let generation = X86_RUNTIME.LINUX_THREAD_GENERATIONS[slot]
        .load(Ordering::SeqCst)
        .checked_add(1)?;
    // Runtime thread IDs come from the process ID counter, so a thread ID
    // never equals another process's ID (a jobserver's tkill would reach it).
    let tid = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        linux_process::allocate_live_thread_id()?
    } else {
        X86_RUNTIME.LINUX_NEXT_TID.load(Ordering::SeqCst)
    };
    let next_tid = tid.checked_add(1)?;
    let inherited_signal_mask = current_linux_thread_slot().map_or_else(
        || X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst),
        |current| X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[current].load(Ordering::SeqCst),
    );
    X86_RUNTIME.LINUX_THREAD_GENERATIONS[slot].store(generation, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_TIDS[slot].store(tid, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_POINTERS[slot].store(context.thread_pointer as u64, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_TLS_EXTENTS[slot].store(context.extent as u64, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_TLS_SIZES[slot].store(context.extent_size as u64, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].store(stack_base as u64, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].store(stack_size as u64, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_ROBUST_LISTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_NICES[slot].store(current_linux_thread_nice(), Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_CPU_CYCLES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_LAST_CPUS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSEQ_POINTERS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSEQ_LENGTHS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSEQ_SIGNATURES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(inherited_signal_mask, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_NEXT_TID.store(next_tid, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    Some(LinuxThreadHandle {
        slot: slot as u8,
        generation,
        tid,
    })
}

pub(super) fn linux_thread_context(handle: LinuxThreadHandle) -> Option<LinuxTlsContext> {
    let slot = usize::from(handle.slot);
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_FREE
        || X86_RUNTIME.LINUX_THREAD_GENERATIONS[slot].load(Ordering::SeqCst) != handle.generation
        || X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst) != handle.tid
    {
        return None;
    }
    Some(LinuxTlsContext {
        thread_pointer: usize::try_from(
            X86_RUNTIME.LINUX_THREAD_POINTERS[slot].load(Ordering::SeqCst),
        )
        .ok()?,
        extent: usize::try_from(X86_RUNTIME.LINUX_THREAD_TLS_EXTENTS[slot].load(Ordering::SeqCst))
            .ok()?,
        extent_size: usize::try_from(
            X86_RUNTIME.LINUX_THREAD_TLS_SIZES[slot].load(Ordering::SeqCst),
        )
        .ok()?,
    })
}

pub(super) fn construct_linux_clone_context(
    handle: LinuxThreadHandle,
    request: LinuxCloneRequest,
    parent_registers: LinuxSyscallFrame,
    return_rip: u64,
    return_rflags: u64,
    _parent_writable_base: u64,
    _parent_writable_size: usize,
) -> Option<LinuxCloneResult> {
    let slot = usize::from(handle.slot);
    let context = linux_thread_context(handle)?;
    if !linux_thread_clone_flags_supported(request.flags)
        || slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_READY
        || current_linux_thread_slot() == Some(slot)
        || request.tls != context.thread_pointer as u64
        || request.child_stack & 7 != 0
        || request.child_stack < X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].load(Ordering::SeqCst)
        || X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot]
            .load(Ordering::SeqCst)
            .checked_add(X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].load(Ordering::SeqCst))
            .is_none_or(|end| request.child_stack > end)
        || request.parent_tid & 3 != 0
        || request.child_tid & 3 != 0
    {
        return None;
    }
    let child = LinuxUserContext {
        registers: parent_registers,
        rip: return_rip,
        rsp: request.child_stack,
        rflags: return_rflags,
        rax: 0,
        fs_base: request.tls,
    };
    if !child.is_valid() {
        return None;
    }
    for (saved, value) in X86_RUNTIME.LINUX_THREAD_REGISTERS[slot]
        .iter()
        .zip(child.registers.into_array())
    {
        saved.store(value, Ordering::SeqCst);
    }
    X86_RUNTIME.LINUX_THREAD_RIPS[slot].store(child.rip, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSPS[slot].store(child.rsp, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RFLAGS[slot].store(child.rflags, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(child.rax, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RCXS[slot].store(child.rip, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_R11S[slot].store(child.rflags, Ordering::SeqCst);
    let clear_child_tid = if request.flags & LINUX_CLONE_CHILD_CLEARTID != 0 {
        request.child_tid
    } else {
        0
    };
    X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[slot].store(clear_child_tid, Ordering::SeqCst);
    Some(LinuxCloneResult {
        parent_rax: u64::from(handle.tid),
        child,
    })
}

pub(super) fn publish_linux_clone(
    handle: LinuxThreadHandle,
    request: LinuxCloneRequest,
    parent_registers: LinuxSyscallFrame,
    return_rip: u64,
    return_rflags: u64,
    parent_writable_base: u64,
    parent_writable_size: usize,
) -> Result<LinuxCloneResult, LinuxClonePublishError> {
    let result = construct_linux_clone_context(
        handle,
        request,
        parent_registers,
        return_rip,
        return_rflags,
        parent_writable_base,
        parent_writable_size,
    )
    .ok_or(LinuxClonePublishError::InvalidRequest)?;
    let parent_tid_requested = request.flags & LINUX_CLONE_PARENT_SETTID != 0;
    let child_tid_requested = request.flags & LINUX_CLONE_CHILD_SETTID != 0;
    if parent_tid_requested
        && !linux_writable_user_range_contains(request.parent_tid, size_of::<u32>())
        || child_tid_requested
            && !linux_writable_user_range_contains(request.child_tid, size_of::<u32>())
    {
        clear_linux_thread_execution(usize::from(handle.slot));
        return Err(LinuxClonePublishError::TidFault);
    }
    let tid = handle.tid.to_ne_bytes();
    if parent_tid_requested && !copy_to_linux_user(request.parent_tid, &tid)
        || child_tid_requested && !copy_to_linux_user(request.child_tid, &tid)
    {
        clear_linux_thread_execution(usize::from(handle.slot));
        return Err(LinuxClonePublishError::TidFault);
    }
    Ok(result)
}

pub(super) fn linux_thread_return_context(handle: LinuxThreadHandle) -> Option<LinuxUserContext> {
    let slot = usize::from(handle.slot);
    let tls = linux_thread_context(handle)?;
    let mut registers = [0_u64; LINUX_SYSCALL_FRAME_REGISTERS];
    for (value, saved) in registers
        .iter_mut()
        .zip(&X86_RUNTIME.LINUX_THREAD_REGISTERS[slot])
    {
        *value = saved.load(Ordering::SeqCst);
    }
    let context = LinuxUserContext {
        registers: LinuxSyscallFrame::from_array(registers),
        rip: X86_RUNTIME.LINUX_THREAD_RIPS[slot].load(Ordering::SeqCst),
        rsp: X86_RUNTIME.LINUX_THREAD_RSPS[slot].load(Ordering::SeqCst),
        rflags: X86_RUNTIME.LINUX_THREAD_RFLAGS[slot].load(Ordering::SeqCst),
        rax: X86_RUNTIME.LINUX_THREAD_RAXS[slot].load(Ordering::SeqCst),
        fs_base: tls.thread_pointer as u64,
    };
    context.is_valid().then_some(context)
}

pub(super) fn linux_thread_resume_general(
    handle: LinuxThreadHandle,
    context: LinuxUserContext,
) -> Option<[u64; 15]> {
    let slot = usize::from(handle.slot);
    (linux_thread_context(handle).is_some() && linux_thread_return_context(handle) == Some(context))
        .then(|| {
            context.registers.process_general(
                context.rax,
                X86_RUNTIME.LINUX_THREAD_RCXS[slot].load(Ordering::SeqCst),
                X86_RUNTIME.LINUX_THREAD_R11S[slot].load(Ordering::SeqCst),
            )
        })
}

pub(super) fn save_linux_thread_return_context(
    handle: LinuxThreadHandle,
    context: LinuxUserContext,
) -> bool {
    let slot = usize::from(handle.slot);
    let Some(tls) = linux_thread_context(handle) else {
        return false;
    };
    let stack_base = X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].load(Ordering::SeqCst);
    let Some(stack_end) =
        stack_base.checked_add(X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].load(Ordering::SeqCst))
    else {
        return false;
    };
    if !context.is_valid()
        || context.fs_base != tls.thread_pointer as u64
        || context.rsp < stack_base
        || context.rsp > stack_end
    {
        return false;
    }
    for (saved, value) in X86_RUNTIME.LINUX_THREAD_REGISTERS[slot]
        .iter()
        .zip(context.registers.into_array())
    {
        saved.store(value, Ordering::SeqCst);
    }
    X86_RUNTIME.LINUX_THREAD_RIPS[slot].store(context.rip, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSPS[slot].store(context.rsp, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RFLAGS[slot].store(context.rflags, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(context.rax, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RCXS[slot].store(context.rip, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_R11S[slot].store(context.rflags, Ordering::SeqCst);
    true
}

pub(super) fn restore_linux_thread_return_context(
    handle: LinuxThreadHandle,
    snapshot: Option<LinuxUserContext>,
) {
    if let Some(context) = snapshot {
        let _ = save_linux_thread_return_context(handle, context);
    } else {
        clear_linux_thread_execution(usize::from(handle.slot));
    }
}

pub(super) fn install_linux_thread_return(
    handle: LinuxThreadHandle,
    registers: &mut LinuxSyscallFrame,
    rip: &mut u64,
    rsp: &mut u64,
    rflags: &mut u64,
    rax: &mut u64,
) -> bool {
    let Some(context) = linux_thread_return_context(handle) else {
        return false;
    };
    if !switch_linux_thread(handle) {
        return false;
    }
    *registers = context.registers;
    *rip = context.rip;
    *rsp = context.rsp;
    *rflags = context.rflags;
    *rax = context.rax;
    true
}

/// The current thread leaves the CPU to wait in its system call, parked on
/// its own activation (docs/SCHEDULER.md, "Activations per thread"): its
/// signal mask and vector state are kept in its slot, with `restart`, the
/// call set to be issued again, as its saved user context, and no thread
/// is current until the scheduler makes one so. None when no thread is
/// current here.
pub(super) fn park_current_linux_thread(restart: LinuxUserContext) -> Option<LinuxThreadHandle> {
    let handle = current_linux_thread_handle()?;
    let slot = usize::from(handle.slot);
    X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(
        X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst),
        Ordering::SeqCst,
    );
    // Its call goes on in its activation; the slot holds where it would
    // go on from user mode, for the process's registry when it is the
    // thread the process is next entered at.
    if restart.is_valid() {
        store_linux_thread_context(slot, restart, restart.rip, restart.rflags);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let _ = save_linux_thread_extended_state(current_linux_process_pid(), slot);
    }
    linux_charge_thread_cpu(slot);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_PARKED, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
    Some(handle)
}

/// Makes parked thread `handle` current again, for its call to go on (or
/// unwind) when its activation is resumed: its vector state, thread
/// pointer and signal mask come back. No other thread may be current.
pub(super) fn unpark_linux_thread(handle: LinuxThreadHandle) -> bool {
    let slot = usize::from(handle.slot);
    let Some(context) = linux_thread_context(handle) else {
        return false;
    };
    if X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_PARKED
        || current_linux_thread_slot().is_some()
        || X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
            && !restore_linux_thread_extended_state(current_linux_process_pid(), slot)
        || !install_linux_tls_context(context)
    {
        return false;
    }
    if linux_light_thread_here().is_none() {
        X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.store(
            X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
    X86_RUNTIME.LINUX_THREAD_OWNER_ONLY[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_RUNNING, Ordering::SeqCst);
    linux_mark_thread_cpu();
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(handle.slot, Ordering::SeqCst);
    true
}

/// The current thread, which the process's registry context (`general`,
/// `rip`, `rsp`, `rflags`: where it was preempted or yielded) holds, gives
/// the CPU to another thread of its process: that context goes to its slot
/// with its exact rcx and r11, it is ready for any CPU, and no thread is
/// current. True too when no thread is current.
pub(super) fn ready_current_linux_thread(
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
) -> bool {
    let Some(handle) = current_linux_thread_handle() else {
        return true;
    };
    let slot = usize::from(handle.slot);
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
        fs_base: X86_RUNTIME.LINUX_THREAD_POINTERS[slot].load(Ordering::SeqCst),
    };
    if !context.is_valid() {
        return false;
    }
    store_linux_thread_context(slot, context, general[2], general[10]);
    X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(
        X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst),
        Ordering::SeqCst,
    );
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let _ = save_linux_thread_extended_state(current_linux_process_pid(), slot);
    }
    linux_charge_thread_cpu(slot);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
    true
}

/// Saves `context` as thread slot `slot`'s user context, with the exact
/// rcx and r11 it resumes with.
fn store_linux_thread_context(slot: usize, context: LinuxUserContext, rcx: u64, r11: u64) {
    for (saved, value) in X86_RUNTIME.LINUX_THREAD_REGISTERS[slot]
        .iter()
        .zip(context.registers.into_array())
    {
        saved.store(value, Ordering::SeqCst);
    }
    X86_RUNTIME.LINUX_THREAD_RIPS[slot].store(context.rip, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSPS[slot].store(context.rsp, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RFLAGS[slot].store(context.rflags, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(context.rax, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RCXS[slot].store(rcx, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_R11S[slot].store(r11, Ordering::SeqCst);
}

/// Thread `handle`'s saved user context as the registers a process entry
/// takes (`process_general` order, with its exact rcx and r11), with its
/// rip, rsp, rflags and thread pointer.
pub(super) fn linux_thread_entry_context(
    handle: LinuxThreadHandle,
) -> Option<([u64; 15], u64, u64, u64, u64)> {
    let slot = usize::from(handle.slot);
    let context = linux_thread_return_context(handle)?;
    let general = context.registers.process_general(
        context.rax,
        X86_RUNTIME.LINUX_THREAD_RCXS[slot].load(Ordering::SeqCst),
        X86_RUNTIME.LINUX_THREAD_R11S[slot].load(Ordering::SeqCst),
    );
    Some((
        general,
        context.rip,
        context.rsp,
        context.rflags,
        context.fs_base,
    ))
}

pub(super) fn retire_linux_thread(handle: LinuxThreadHandle) -> bool {
    let slot = usize::from(handle.slot);
    if linux_thread_context(handle).is_none()
        || X86_RUNTIME.LINUX_CURRENT_THREAD_SLOT.load(Ordering::SeqCst) == handle.slot
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_READY
    {
        return false;
    }
    clear_linux_thread_slot(slot);
    true
}

/// An exec's point of no return: the process's other threads end (Linux's
/// de_thread), leaving the calling one. linux_execve_at let the exec start
/// only when none of them runs on another CPU.
pub(super) fn end_other_linux_threads_for_exec() {
    let Some(current) = current_linux_thread_slot() else {
        return;
    };
    // Threads on other CPUs leave them first: their slots are cleared
    // below, and the image they run in is about to go. Threads parked in
    // calls unwind out of them first, and their activations end.
    evict_linux_light_threads();
    let pid = current_linux_process_pid();
    for slot in (0..LINUX_THREAD_LIMIT).filter(|slot| *slot != current) {
        let state = X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst);
        if state == LINUX_THREAD_PARKED {
            unwind_parked_linux_thread(
                pid,
                X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst),
            );
        }
        if state != LINUX_THREAD_FREE {
            clear_linux_thread_slot(slot);
        }
    }
}

pub(super) fn retire_current_linux_thread() -> bool {
    let slot = X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .swap(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
    let slot = usize::from(slot);
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_RUNNING
    {
        return false;
    }
    clear_linux_thread_slot(slot);
    true
}

pub(super) fn retire_all_linux_threads() {
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
    for slot in 0..LINUX_THREAD_LIMIT {
        clear_linux_thread_slot(slot);
    }
}

fn clear_linux_thread_slot(slot: usize) {
    discard_linux_thread_extended_state(slot);
    let _ = X86_RUNTIME
        .LINUX_LAST_PREEMPTED_THREAD_SLOT
        .compare_exchange(
            slot as u8,
            LINUX_THREAD_SLOT_NONE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    if let Some(process) = linux_process::live_process_slot(current_linux_process_pid()) {
        let _ = crate::linux_signal::clear(
            linux_signal_instance(),
            linux_thread_signal_queue(process, slot),
        );
    }
    let stack_base = X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].load(Ordering::SeqCst);
    let stack_size = X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].load(Ordering::SeqCst);
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && stack_base != 0
        && stack_size == PAGE_SIZE as u64
    {
        // The boot proof owns its fixed sibling stack and verifies scrubbing.
        // Runtime stacks belong to libc and remain mapped after thread exit so
        // userspace can inspect or recycle its thread-control allocation.
        let zeroes = [0_u8; 128];
        for offset in (0..PAGE_SIZE).step_by(zeroes.len()) {
            if crate::trusted::user_copy::copy_to_user(stack_base + offset as u64, &zeroes)
                != zeroes.len()
            {
                break;
            }
        }
    }
    // The thread's keyrings go with it (the process's go at its exit).
    let tid = X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst);
    if tid != 0
        && X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_FREE
        && crate::sync::rank_available(crate::sync::LockRank::KEYRINGS)
    {
        let _ = crate::linux_keyring::with(|keys| {
            keys.exit_thread(tid);
            Ok(())
        });
    }
    X86_RUNTIME.LINUX_THREAD_TIDS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_POINTERS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_TLS_EXTENTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_TLS_SIZES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].store(0, Ordering::SeqCst);
    clear_linux_thread_execution(slot);
    X86_RUNTIME.LINUX_THREAD_ROBUST_LISTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSEQ_POINTERS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSEQ_LENGTHS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSEQ_SIGNATURES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_OWNER_ONLY[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].store(0, Ordering::SeqCst);
    clear_linux_poll_snapshot(slot);
    clear_linux_select_snapshot(slot);
    clear_linux_iov_snapshot(slot);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_FREE, Ordering::SeqCst);
}

fn clear_linux_thread_execution(slot: usize) {
    for register in &X86_RUNTIME.LINUX_THREAD_REGISTERS[slot] {
        register.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME.LINUX_THREAD_RIPS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSPS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RFLAGS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RCXS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_R11S[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[slot].store(0, Ordering::SeqCst);
}

pub(super) fn current_linux_thread_slot() -> Option<usize> {
    let slot = usize::from(X86_RUNTIME.LINUX_CURRENT_THREAD_SLOT.load(Ordering::SeqCst));
    (slot < LINUX_THREAD_LIMIT
        && X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_RUNNING)
        .then_some(slot)
}

pub(super) fn store_current_linux_signal_mask(mask: u64) {
    // The process-wide copy is the owner's thread's; a thread on the
    // light path has only its slot's.
    if linux_light_thread_here().is_none() {
        X86_RUNTIME
            .ELF_PROBE_SIGNAL_MASK
            .store(mask, Ordering::SeqCst);
    }
    if let Some(slot) = current_linux_thread_slot() {
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(mask, Ordering::SeqCst);
    }
}

/// Begins a lone thread's masked wait of `kind` (sigtimedwait, sigsuspend)
/// in the owner's path: `mask` is the thread's mask while it waits; the
/// one before is kept for a handler's frame to restore
/// (`linux_lone_wait_prior_mask`) and for `end_linux_lone_masked_wait`.
/// The thread stays running; its wait kind marks the wait.
pub(super) fn begin_linux_lone_masked_wait(slot: usize, kind: u8, mask: u64) -> u64 {
    let prior = current_linux_signal_mask();
    X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].store(prior, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(kind, Ordering::SeqCst);
    store_current_linux_signal_mask(mask);
    prior
}

/// Ends the wait `begin_linux_lone_masked_wait` began: the mask goes back
/// to `prior`, unless a handler is active, whose frame restores it.
pub(super) fn end_linux_lone_masked_wait(slot: usize, prior: u64) {
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].store(0, Ordering::SeqCst);
    if !X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        store_current_linux_signal_mask(prior);
    }
}

/// The mask a handler's frame restores for a lone thread in a masked wait
/// (`begin_linux_lone_masked_wait`), else None.
pub(super) fn linux_lone_wait_prior_mask() -> Option<u64> {
    let slot = current_linux_thread_slot()?;
    matches!(
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst),
        LINUX_THREAD_WAIT_SIGNAL | LINUX_THREAD_WAIT_SIGSUSPEND | LINUX_THREAD_WAIT_STOPPED
    )
    .then(|| X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].load(Ordering::SeqCst))
}

/// The current thread's signal mask: its slot's on the light path, else
/// the process-wide copy the owner keeps for its thread.
pub(super) fn current_linux_signal_mask() -> u64 {
    match (linux_light_thread_here(), current_linux_thread_slot()) {
        (Some(_), Some(slot)) => X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].load(Ordering::SeqCst),
        _ => X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst),
    }
}

pub(super) fn linux_thread_handle(slot: usize) -> Option<LinuxThreadHandle> {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_FREE
    {
        return None;
    }
    let generation = X86_RUNTIME.LINUX_THREAD_GENERATIONS[slot].load(Ordering::SeqCst);
    let tid = X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst);
    (generation != 0 && tid != 0).then_some(LinuxThreadHandle {
        slot: slot as u8,
        generation,
        tid,
    })
}

pub(super) fn current_linux_thread_handle() -> Option<LinuxThreadHandle> {
    linux_thread_handle(current_linux_thread_slot()?)
}

pub(super) fn linux_thread_handle_by_tid(tid: u64) -> Option<LinuxThreadHandle> {
    let tid = u32::try_from(tid).ok()?;
    (0..LINUX_THREAD_LIMIT).find_map(|slot| {
        (X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst) == tid)
            .then(|| linux_thread_handle(slot))
            .flatten()
    })
}

pub(super) fn current_linux_tid() -> Option<u32> {
    current_linux_thread_slot()
        .map(|slot| X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst))
        .filter(|tid| *tid != 0)
}

pub(super) fn set_current_linux_clear_child_tid(address: u64) -> bool {
    current_linux_thread_slot().is_some_and(|slot| {
        X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[slot].store(address, Ordering::SeqCst);
        true
    })
}

pub(super) fn current_linux_clear_child_tid() -> Option<u64> {
    current_linux_thread_slot()
        .map(|slot| X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[slot].load(Ordering::SeqCst))
}

pub(super) fn set_current_linux_robust_list(address: u64) -> bool {
    current_linux_thread_slot().is_some_and(|slot| {
        X86_RUNTIME.LINUX_THREAD_ROBUST_LISTS[slot].store(address, Ordering::SeqCst);
        true
    })
}

pub(super) fn current_linux_robust_list() -> Option<u64> {
    current_linux_thread_slot()
        .map(|slot| X86_RUNTIME.LINUX_THREAD_ROBUST_LISTS[slot].load(Ordering::SeqCst))
}

pub(super) fn linux_rseq(address: u64, length: u64, flags: u64, signature: u64) -> u64 {
    const RSEQ_SIZE: u32 = 32;
    const RSEQ_FLAG_UNREGISTER: u32 = 1;
    let length = length as u32;
    let flags = flags as u32;
    let signature = signature as u32;
    let Some(slot) = current_linux_thread_slot() else {
        return LINUX_ESRCH;
    };
    let registered = X86_RUNTIME.LINUX_THREAD_RSEQ_POINTERS[slot].load(Ordering::SeqCst);
    let registered_length = X86_RUNTIME.LINUX_THREAD_RSEQ_LENGTHS[slot].load(Ordering::SeqCst);
    let registered_signature =
        X86_RUNTIME.LINUX_THREAD_RSEQ_SIGNATURES[slot].load(Ordering::SeqCst);
    if flags & RSEQ_FLAG_UNREGISTER != 0 {
        if flags & !RSEQ_FLAG_UNREGISTER != 0
            || registered == 0
            || registered != address
            || registered_length != length
        {
            return LINUX_EINVAL;
        }
        if registered_signature != signature {
            return LINUX_EPERM;
        }
        if !copy_to_linux_user(address, &0_u32.to_ne_bytes())
            || !copy_to_linux_user(address + 4, &u32::MAX.to_ne_bytes())
            || !copy_to_linux_user(address + 20, &0_u32.to_ne_bytes())
            || !copy_to_linux_user(address + 24, &0_u32.to_ne_bytes())
        {
            return LINUX_EFAULT;
        }
        X86_RUNTIME.LINUX_THREAD_RSEQ_POINTERS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RSEQ_LENGTHS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RSEQ_SIGNATURES[slot].store(0, Ordering::SeqCst);
        return 0;
    }
    if flags != 0 {
        return LINUX_EINVAL;
    }
    if registered != 0 {
        if registered != address || registered_length != length {
            return LINUX_EINVAL;
        }
        if registered_signature != signature {
            return LINUX_EPERM;
        }
        return LINUX_EBUSY;
    }
    if length < RSEQ_SIZE
        || length == RSEQ_SIZE && !address.is_multiple_of(RSEQ_SIZE as u64)
        || length != RSEQ_SIZE && !address.is_multiple_of(size_of::<u32>() as u64)
    {
        return LINUX_EINVAL;
    }
    if !linux_writable_user_range_contains(address, length as usize)
        || !copy_to_linux_user(address, &0_u32.to_ne_bytes())
        || !copy_to_linux_user(address + 4, &0_u32.to_ne_bytes())
        || !copy_to_linux_user(address + 20, &0_u32.to_ne_bytes())
        || !copy_to_linux_user(address + 24, &0_u32.to_ne_bytes())
    {
        return LINUX_EFAULT;
    }
    X86_RUNTIME.LINUX_THREAD_RSEQ_POINTERS[slot].store(address, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSEQ_LENGTHS[slot].store(length, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_RSEQ_SIGNATURES[slot].store(signature, Ordering::SeqCst);
    0
}

pub(super) fn finish_linux_thread_table() -> bool {
    let clean = X86_RUNTIME.LINUX_CURRENT_THREAD_SLOT.load(Ordering::SeqCst)
        == LINUX_THREAD_SLOT_NONE
        && X86_RUNTIME
            .LINUX_THREAD_STATES
            .iter()
            .all(|state| state.load(Ordering::SeqCst) == LINUX_THREAD_FREE)
        && X86_RUNTIME
            .LINUX_THREAD_TIDS
            .iter()
            .all(|tid| tid.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_POINTERS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_TLS_EXTENTS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_TLS_SIZES
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_STACK_BASES
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_STACK_SIZES
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_RIPS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_RSPS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_RFLAGS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_RAXS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_RCXS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_R11S
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME.LINUX_THREAD_REGISTERS.iter().all(|registers| {
            registers
                .iter()
                .all(|value| value.load(Ordering::SeqCst) == 0)
        })
        && X86_RUNTIME
            .LINUX_THREAD_CLEAR_CHILD_TIDS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_ROBUST_LISTS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_RSEQ_POINTERS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_RSEQ_LENGTHS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_RSEQ_SIGNATURES
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_SIGNAL_MASKS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_WAIT_KINDS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == LINUX_THREAD_WAIT_NONE)
        && X86_RUNTIME
            .LINUX_THREAD_WAIT_KEYS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_WAIT_OUTPUTS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_WAIT_DEADLINES
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_POLL_DESCRIPTORS
            .iter()
            .all(|descriptors| {
                descriptors
                    .iter()
                    .all(|value| value.load(Ordering::SeqCst) == 0)
            })
        && X86_RUNTIME
            .LINUX_THREAD_POLL_EVENTS
            .iter()
            .all(|events| events.iter().all(|value| value.load(Ordering::SeqCst) == 0))
        && X86_RUNTIME
            .LINUX_THREAD_SELECT_READ_ADDRESSES
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_SELECT_WRITE_ADDRESSES
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES
            .iter()
            .all(|value| value.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .LINUX_THREAD_SELECT_READ_SETS
            .iter()
            .all(|set| set.iter().all(|value| value.load(Ordering::SeqCst) == 0))
        && X86_RUNTIME
            .LINUX_THREAD_SELECT_WRITE_SETS
            .iter()
            .all(|set| set.iter().all(|value| value.load(Ordering::SeqCst) == 0))
        && X86_RUNTIME
            .LINUX_THREAD_SELECT_EXCEPTION_SETS
            .iter()
            .all(|set| set.iter().all(|value| value.load(Ordering::SeqCst) == 0))
        && X86_RUNTIME
            .LINUX_THREAD_IOV_ADDRESSES
            .iter()
            .all(|addresses| {
                addresses
                    .iter()
                    .all(|value| value.load(Ordering::SeqCst) == 0)
            })
        && X86_RUNTIME.LINUX_THREAD_IOV_LENGTHS.iter().all(|lengths| {
            lengths
                .iter()
                .all(|value| value.load(Ordering::SeqCst) == 0)
        });
    for slot in 0..LINUX_THREAD_LIMIT {
        clear_linux_thread_slot(slot);
    }
    X86_RUNTIME
        .LINUX_CURRENT_THREAD_SLOT
        .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_NEXT_TID.store(1, Ordering::SeqCst);
    clean
}

pub(super) fn install_linux_tls_context(context: LinuxTlsContext) -> bool {
    if !context.is_valid() {
        return false;
    }
    if !install_user_fs_base(context.thread_pointer as u64) {
        return false;
    }
    if context.extent_size == 0 {
        X86_RUNTIME.ELF_PROBE_TLS.store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_TLS_SIZE.store(0, Ordering::SeqCst);
        return true;
    }
    X86_RUNTIME
        .ELF_PROBE_TLS
        .store(context.extent as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_TLS_SIZE
        .store(context.extent_size as u64, Ordering::SeqCst);
    true
}

pub(super) fn update_current_linux_tls(thread_pointer: u64) -> bool {
    let Some(slot) = current_linux_thread_slot() else {
        return false;
    };
    let context = if thread_pointer == 0 {
        LinuxTlsContext {
            thread_pointer: 0,
            extent: 0,
            extent_size: 0,
        }
    } else {
        let Ok(thread_pointer) = usize::try_from(thread_pointer) else {
            return false;
        };
        let extent = thread_pointer & !(PAGE_SIZE - 1);
        let extent_size = if thread_pointer
            .checked_add(16)
            .is_some_and(|end| end <= extent + PAGE_SIZE)
        {
            PAGE_SIZE
        } else {
            PAGE_SIZE * 2
        };
        LinuxTlsContext {
            thread_pointer,
            extent,
            extent_size,
        }
    };
    if !context.is_valid() || !install_linux_tls_context(context) {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_POINTERS[slot].store(context.thread_pointer as u64, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_TLS_EXTENTS[slot].store(context.extent as u64, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_TLS_SIZES[slot].store(context.extent_size as u64, Ordering::SeqCst);
    true
}

pub(super) fn update_current_linux_fs_base(thread_pointer: u64) -> bool {
    if thread_pointer >= 1 << 47 {
        return false;
    }
    let Some(slot) = current_linux_thread_slot() else {
        return false;
    };
    if !install_user_fs_base(thread_pointer) {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_POINTERS[slot].store(thread_pointer, Ordering::SeqCst);
    true
}
