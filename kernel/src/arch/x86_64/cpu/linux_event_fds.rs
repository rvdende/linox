use super::*;

pub(super) fn linux_eventfd(initial: u64, flags: u64) -> u64 {
    let flags = u64::from(flags as u32);
    if flags & !(LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_O_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && X86_RUNTIME
            .ELF_PROBE_EVENTFD_DESCRIPTOR
            .load(Ordering::SeqCst)
            != 0
    {
        return LINUX_EMFILE;
    }
    let descriptor_start = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        LINUX_AUX_DESCRIPTOR_FIRST
    } else {
        2
    };
    let descriptor = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        match linux_allocate_descriptor(descriptor_start) {
            Ok(descriptor) => descriptor,
            Err(error) => return error,
        }
    } else {
        let Some(descriptor) = (descriptor_start..LINUX_AUX_DESCRIPTOR_LIMIT)
            .find(|descriptor| linux_aux_descriptor_free(*descriptor))
        else {
            return LINUX_EMFILE;
        };
        descriptor
    };
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let Some(id) =
            crate::linux_event_files::create_eventfd(u64::from(initial as u32), flags as u32)
        else {
            return LINUX_ENFILE;
        };
        linux_legacy_descriptor_offset(descriptor).store(id, Ordering::SeqCst);
        linux_fd_cell::<u8>(descriptor, LinuxFdField::EventFd).store(1, Ordering::SeqCst);
    } else {
        X86_RUNTIME
            .ELF_PROBE_EVENTFD_COUNTER
            .store(u64::from(initial as u32), Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_EVENTFD_FLAGS
            .store(flags as u32, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_EVENTFD_DESCRIPTOR
            .store(descriptor as u16, Ordering::SeqCst);
    }
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    descriptor
}

/// An eventfd descriptor's counter and flags: its open file's, or the boot
/// probe's own.
pub(super) fn linux_eventfd_state(
    descriptor: u64,
) -> Option<(
    &'static dyn LinuxFileCell<u64>,
    &'static dyn LinuxFileCell<u32>,
)> {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let id = linux_eventfd_file(descriptor)?;
        let file = crate::linux_event_files::eventfd(id)?;
        Some((&file.counter, &file.flags))
    } else {
        let stored = X86_RUNTIME
            .ELF_PROBE_EVENTFD_DESCRIPTOR
            .load(Ordering::SeqCst);
        (stored != 0 && u64::from(stored) == descriptor).then_some((
            &X86_RUNTIME.ELF_PROBE_EVENTFD_COUNTER,
            &X86_RUNTIME.ELF_PROBE_EVENTFD_FLAGS,
        ))
    }
}

/// The open file id of eventfd `descriptor` (in its offset cell).
pub(super) fn linux_eventfd_file(descriptor: u64) -> Option<u64> {
    let descriptor = u64::from(descriptor as u32);
    (descriptor >= LINUX_AUX_DESCRIPTOR_FIRST
        && linux_fd_cell::<u8>(descriptor, LinuxFdField::EventFd).load(Ordering::SeqCst) != 0)
        .then(|| linux_legacy_descriptor_offset(descriptor).load(Ordering::SeqCst))
}

/// The open file id of timerfd `descriptor`.
pub(super) fn linux_timerfd_file(descriptor: u64) -> Option<u64> {
    let descriptor = u64::from(descriptor as u32);
    (descriptor >= LINUX_AUX_DESCRIPTOR_FIRST
        && linux_fd_cell::<u8>(descriptor, LinuxFdField::TimerFd).load(Ordering::SeqCst) != 0)
        .then(|| linux_legacy_descriptor_offset(descriptor).load(Ordering::SeqCst))
}

/// Puts a new descriptor `target` on the eventfd or timerfd open file of
/// `source`, as dup2 does, closing what `target` held.
pub(super) fn linux_event_file_dup(source: u64, target: u64) -> u64 {
    let (kind, id) = match (linux_eventfd_file(source), linux_timerfd_file(source)) {
        (Some(id), _) => (crate::linux_event_files::Kind::EventFd, id),
        (_, Some(id)) => (crate::linux_event_files::Kind::TimerFd, id),
        _ => return LINUX_EBADF,
    };
    if source == target {
        return target;
    }
    // The descriptor kinds below 3 have no eventfd or timerfd slot.
    if target < LINUX_AUX_DESCRIPTOR_FIRST || target >= linux_nofile_soft_limit() {
        return LINUX_EBADF;
    }
    if linux_descriptor_open(target) && linux_descriptor_close(target) != 0 {
        return LINUX_EBADF;
    }
    if !crate::linux_event_files::retain(kind, id) {
        return LINUX_EBADF;
    }
    linux_legacy_descriptor_offset(target).store(id, Ordering::SeqCst);
    match kind {
        crate::linux_event_files::Kind::EventFd => {
            linux_fd_cell::<u8>(target, LinuxFdField::EventFd).store(1, Ordering::SeqCst)
        }
        crate::linux_event_files::Kind::TimerFd => {
            linux_fd_cell::<u8>(target, LinuxFdField::TimerFd).store(1, Ordering::SeqCst)
        }
    }
    set_linux_descriptor_close_on_exec(target, false);
    target
}

pub(super) fn linux_eventfd_read(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    if !linux_eventfd_descriptor(descriptor) {
        return None;
    }
    if count != 8 {
        return Some(LINUX_EINVAL);
    }
    let (counter, state_flags) = linux_eventfd_state(descriptor)?;
    let current = counter.load(Ordering::SeqCst);
    if current == 0 {
        return Some(
            if state_flags.load(Ordering::SeqCst) & LINUX_EFD_NONBLOCK as u32 != 0 {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    }
    let semaphore = state_flags.load(Ordering::SeqCst) & LINUX_EFD_SEMAPHORE as u32 != 0;
    let result = if semaphore { 1 } else { current };
    if !copy_to_linux_user(address, &result.to_ne_bytes()) {
        return Some(LINUX_EFAULT);
    }
    counter.store(if semaphore { current - 1 } else { 0 }, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    Some(8)
}

fn complete_linux_eventfd_read_wait(slot: usize) -> bool {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_EVENTFD_READ
    {
        return false;
    }
    let descriptor = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = linux_eventfd_read(descriptor, address, 8).unwrap_or(LINUX_EBADF);
    if result == LINUX_ENOSYS {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EVENTFD_READ_WAKE_COUNT
        .fetch_add(1, Ordering::SeqCst);
    true
}

pub(super) fn wake_linux_eventfd_read_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_eventfd_read_wait(slot));
    }
    woken
}

fn complete_linux_eventfd_write_wait(slot: usize) -> bool {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_EVENTFD_WRITE
    {
        return false;
    }
    let increment = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let descriptor = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let result = linux_eventfd_write_value(descriptor, increment, false).unwrap_or(LINUX_EBADF);
    if result == LINUX_ENOSYS {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EVENTFD_WRITE_WAKE_COUNT
        .fetch_add(1, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    true
}

pub(super) fn wake_linux_eventfd_write_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_eventfd_write_wait(slot));
    }
    woken
}

pub(super) fn linux_eventfd_write(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    if !linux_eventfd_descriptor(descriptor) {
        return None;
    }
    if count != 8 {
        return Some(LINUX_EINVAL);
    }
    let mut bytes = [0_u8; 8];
    if !copy_from_linux_user(address, &mut bytes) {
        return Some(LINUX_EFAULT);
    }
    linux_eventfd_write_value(descriptor, u64::from_ne_bytes(bytes), true)
}

/// The kernel's own signal on an eventfd (an AIO completion): adds one,
/// stopping at ULLONG_MAX, the overflow state a read returns and poll
/// reports as POLLERR, as Linux's eventfd_signal does.
pub(super) fn linux_eventfd_signal(descriptor: u64) {
    if !linux_eventfd_descriptor(descriptor) {
        return;
    }
    let Some((counter, _)) = linux_eventfd_state(descriptor) else {
        return;
    };
    counter.store(
        counter.load(Ordering::SeqCst).saturating_add(1),
        Ordering::SeqCst,
    );
    wake_linux_descriptor_waits();
}

fn linux_eventfd_write_value(descriptor: u64, increment: u64, wake: bool) -> Option<u64> {
    if !linux_eventfd_descriptor(descriptor) {
        return None;
    }
    if increment == u64::MAX {
        return Some(LINUX_EINVAL);
    }
    let (counter, state_flags) = linux_eventfd_state(descriptor)?;
    let current = counter.load(Ordering::SeqCst);
    let Some(next) = current.checked_add(increment) else {
        return Some(
            if state_flags.load(Ordering::SeqCst) & LINUX_EFD_NONBLOCK as u32 != 0 {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    };
    if next == u64::MAX {
        return Some(
            if state_flags.load(Ordering::SeqCst) & LINUX_EFD_NONBLOCK as u32 != 0 {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    }
    counter.store(next, Ordering::SeqCst);
    if wake {
        wake_linux_descriptor_waits();
    }
    Some(8)
}

pub(super) fn linux_eventfd_descriptor(descriptor: u64) -> bool {
    linux_eventfd_state(descriptor).is_some()
}

pub(super) fn linux_pidfd_descriptor(descriptor: u64) -> bool {
    linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_PIDFD
}

pub(super) fn linux_pidfd_process(descriptor: u64) -> Option<u32> {
    if !linux_pidfd_descriptor(descriptor) {
        return None;
    }
    let identity = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
    let pid = identity as u32;
    let generation = (identity >> 32) as u32;
    (pid != 0 && linux_process::live_process_generation(pid) == Some(generation)).then_some(pid)
}

/// Process `pid`'s slot generation and PID namespace, read before a wait
/// reaps it, for `linux_pidfd_record_exit`.
pub(super) fn linux_pidfd_identity(pid: u32) -> Option<(u32, u32)> {
    let generation = linux_process::live_process_generation(pid)?;
    let namespace = linux_process::live_process_namespaces(pid).map_or(0, |set| set.pid);
    Some((generation, namespace))
}

/// Keeps reaped process `pid`'s wait status for its pidfds
/// (PIDFD_INFO_EXIT); `identity` is from `linux_pidfd_identity`.
pub(super) fn linux_pidfd_record_exit(pid: u32, identity: Option<(u32, u32)>, status: u32) {
    if let Some((generation, namespace)) = identity {
        crate::linux_pidfs::reaped(
            linux_execution_instance(),
            pid,
            generation,
            namespace,
            status,
        );
    }
}

/// ioctl on a pidfd: PIDFD_GET_INFO (Linux 6.15's: the process's ids and
/// credentials while it is unreaped, its wait status once reaped when
/// PIDFD_INFO_EXIT asks); other requests are ENOTTY.
pub(super) fn linux_pidfd_ioctl(descriptor: u64, request: u64, argument: u64) -> u64 {
    const PIDFS_IOCTL_MAGIC: u64 = 0xff;
    const PIDFD_GET_INFO_NUMBER: u64 = 11;
    const PIDFD_INFO_PID: u64 = 1 << 0;
    const PIDFD_INFO_CREDS: u64 = 1 << 1;
    const PIDFD_INFO_EXIT: u64 = 1 << 3;
    /// struct pidfd_info's first version (up to the spare fields), the
    /// least a caller may pass, and its size now.
    const PIDFD_INFO_SIZE_VER0: usize = 64;
    const PIDFD_INFO_SIZE: usize = 72;
    let request = u64::from(request as u32);
    if (request >> 8) & 0xff != PIDFS_IOCTL_MAGIC || request & 0xff != PIDFD_GET_INFO_NUMBER {
        return LINUX_ENOTTY;
    }
    let size = ((request >> 16) & 0x3fff) as usize;
    if argument == 0 || size < PIDFD_INFO_SIZE_VER0 {
        return LINUX_EINVAL;
    }
    let mut mask = [0_u8; 8];
    if !copy_from_linux_user(argument, &mut mask) {
        return LINUX_EFAULT;
    }
    let mask = u64::from_ne_bytes(mask);
    let identity = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
    let (pid, generation) = (identity as u32, (identity >> 32) as u32);
    let caller = current_linux_process_pid();
    let observer = current_linux_namespaces().pid;
    let instance = linux_execution_instance();
    let live = linux_process::live_process_generation(pid) == Some(generation);
    let exit = (!live)
        .then(|| crate::linux_pidfs::exit(instance, pid, generation))
        .flatten();
    // Only processes in the caller's PID namespace or below it.
    let namespace = if live {
        linux_process::live_process_namespaces(pid).map_or(0, |set| set.pid)
    } else {
        exit.map_or(0, |exit| exit.namespace)
    };
    if !linux_namespace::pid_within(instance, observer, namespace) {
        return LINUX_ESRCH;
    }
    let mut info = [0_u8; PIDFD_INFO_SIZE];
    let mut reported = 0;
    if !live {
        // A reaped process tells only how it ended, and only when asked.
        let Some(exit) = exit.filter(|_| mask & PIDFD_INFO_EXIT != 0) else {
            return LINUX_ESRCH;
        };
        reported |= PIDFD_INFO_EXIT;
        info[60..64].copy_from_slice(&exit.status.to_ne_bytes());
    } else {
        let Some(credentials) = linux_process::live_process_credentials(pid) else {
            return LINUX_ESRCH;
        };
        let parent = linux_process::live_process_parent_pid(pid).unwrap_or(0);
        let seen = linux_pid_seen_by(caller, pid);
        if seen == 0 {
            return LINUX_ESRCH;
        }
        let parent = if parent == 0 {
            0
        } else {
            linux_pid_seen_by(caller, parent)
        };
        let words = [
            seen,
            seen,
            parent,
            credentials.user.real,
            credentials.group.real,
            credentials.user.effective,
            credentials.group.effective,
            credentials.user.saved,
            credentials.group.saved,
            credentials.user.filesystem,
            credentials.group.filesystem,
        ];
        for (index, word) in words.iter().enumerate() {
            info[16 + index * 4..20 + index * 4].copy_from_slice(&word.to_ne_bytes());
        }
        reported |= PIDFD_INFO_PID | PIDFD_INFO_CREDS;
    }
    info[..8].copy_from_slice(&reported.to_ne_bytes());
    // As copy_struct_to_user: a shorter struct gets its part, a longer
    // one zeros past ours.
    if !copy_to_linux_user(argument, &info[..size.min(PIDFD_INFO_SIZE)]) {
        return LINUX_EFAULT;
    }
    let zeros = [0_u8; 256];
    let mut offset = PIDFD_INFO_SIZE;
    while offset < size {
        let length = (size - offset).min(zeros.len());
        if !copy_to_linux_user(argument + offset as u64, &zeros[..length]) {
            return LINUX_EFAULT;
        }
        offset += length;
    }
    0
}

pub(super) fn linux_signalfd_descriptor(descriptor: u64) -> bool {
    linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_SIGNALFD
}

pub(super) fn linux_signalfd(
    descriptor: u64,
    mask_address: u64,
    mask_size: u64,
    flags: u64,
) -> u64 {
    const SFD_NONBLOCK: u64 = 0x800;
    const SFD_CLOEXEC: u64 = 0x8_0000;
    let descriptor = u64::from(descriptor as u32);
    let flags = u64::from(flags as u32);
    if mask_size != LINUX_SIGNAL_SET_SIZE || flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    let mut bytes = [0_u8; LINUX_SIGNAL_SET_SIZE as usize];
    if !copy_from_linux_user(mask_address, &mut bytes) {
        return LINUX_EFAULT;
    }
    let mask = u64::from_ne_bytes(bytes) & !LINUX_UNBLOCKABLE_SIGNALS;
    let descriptor = if descriptor == u64::from(u32::MAX) {
        match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
            Ok(descriptor) => descriptor,
            Err(error) => return error,
        }
    } else if linux_signalfd_descriptor(descriptor) {
        // An existing signalfd takes the new mask only; its flags stay.
        linux_legacy_descriptor_offset(descriptor).store(mask, Ordering::SeqCst);
        return descriptor;
    } else {
        // An open descriptor that is no signalfd is EINVAL, as in Linux.
        return if linux_descriptor_open(descriptor) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device)
        .store(LINUX_DEVICE_SIGNALFD, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(flags as u32, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(mask, Ordering::SeqCst);
    set_linux_descriptor_close_on_exec(descriptor, flags & SFD_CLOEXEC != 0);
    descriptor
}

pub(super) fn linux_signalfd_read(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    if !linux_signalfd_descriptor(descriptor) {
        return None;
    }
    if count < 128 {
        return Some(LINUX_EINVAL);
    }
    let mask = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
    let pending = X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst) & mask;
    let dynamic = linux_peek_dynamic_signal(mask);
    if pending == 0 && dynamic.is_none() {
        return Some(LINUX_EAGAIN);
    }
    let legacy_signal = (pending != 0).then(|| u64::from(pending.trailing_zeros()) + 1);
    let use_dynamic = dynamic.is_some_and(|(scope, queued)| {
        scope == crate::linux_signal::Scope::Thread
            || legacy_signal.is_none_or(|legacy| u64::from(queued.signal) <= legacy)
    });
    let dynamic = use_dynamic.then_some(dynamic).flatten();
    let signal = dynamic.map_or_else(
        || legacy_signal.unwrap_or(0),
        |(_, queued)| u64::from(queued.signal),
    );
    let index = signal as usize - 1;
    let code = dynamic.map_or_else(
        || X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].load(Ordering::SeqCst) as i32,
        |(_, queued)| queued.code,
    );
    let value = dynamic.map_or_else(
        || X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].load(Ordering::SeqCst),
        |(_, queued)| queued.value,
    );
    let (sender_pid, sender_uid) = dynamic.map_or_else(linux_signal_sender, |(_, queued)| {
        (queued.sender_pid, queued.sender_uid)
    });
    let mut information = [0_u8; 128];
    information[..4].copy_from_slice(&(signal as u32).to_ne_bytes());
    information[8..12].copy_from_slice(&code.to_ne_bytes());
    information[12..16].copy_from_slice(&sender_pid.to_ne_bytes());
    information[16..20].copy_from_slice(&sender_uid.to_ne_bytes());
    if signal == LINUX_SIGCHLD {
        information[40..44].copy_from_slice(&(value as u32).to_ne_bytes());
    } else {
        information[44..48].copy_from_slice(&(value as u32).to_ne_bytes());
        information[48..56].copy_from_slice(&value.to_ne_bytes());
    }
    if !copy_to_linux_user(address, &information) {
        return Some(LINUX_EFAULT);
    }
    let signal_bit = 1_u64 << (signal - 1);
    if let Some((scope, _)) = dynamic {
        let _ = linux_dequeue_dynamic_signal(scope, signal_bit);
    } else {
        X86_RUNTIME
            .ELF_PROBE_PENDING_SIGNALS
            .fetch_and(!signal_bit, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].store(0, Ordering::SeqCst);
    }
    Some(128)
}

pub(super) fn linux_pidfd_open(process: u64, flags: u64) -> u64 {
    const PIDFD_NONBLOCK: u64 = 0x800;
    let process = process as i32;
    let flags = u64::from(flags as u32);
    if flags & !PIDFD_NONBLOCK != 0 {
        return LINUX_EINVAL;
    }
    if process <= 0 {
        return LINUX_EINVAL;
    }
    let process = process as u32;
    let Some(generation) = linux_process::live_process_generation(process) else {
        return LINUX_ESRCH;
    };
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device)
        .store(LINUX_DEVICE_PIDFD, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(flags as u32, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(
        u64::from(process) | (u64::from(generation) << 32),
        Ordering::SeqCst,
    );
    set_linux_descriptor_close_on_exec(descriptor, true);
    descriptor
}

pub(super) fn linux_pidfd_getfd(pid_descriptor: u64, target: u64, flags: u64) -> u64 {
    let target = u64::from(target as u32);
    let flags = u64::from(flags as u32);
    if flags != 0 {
        return LINUX_EINVAL;
    }
    if !linux_pidfd_descriptor(pid_descriptor) {
        return LINUX_EBADF;
    }
    let Some(process) = linux_pidfd_process(pid_descriptor) else {
        return LINUX_ESRCH;
    };
    if process == current_linux_process_pid() {
        return linux_console_dup(target);
    }
    if linux_process::live_process_status(process).is_none_or(|status| !status.state.is_running()) {
        return LINUX_ESRCH;
    }
    if !linux_ptrace_access_permitted(process) {
        return LINUX_EPERM;
    }
    let saved = with_valid_linux_process_runtime_state(process, |state| {
        if target >= LINUX_DESCRIPTOR_TABLE_LIMIT {
            Err(state.descriptors.overflow)
        } else {
            Ok(linux_saved_descriptor(&state.descriptors, target))
        }
    });
    let Some((device, oci, socket, socket_flags, tmp_generation, offset, open_file_id)) =
        (match saved {
            None => None,
            Some(Ok(found)) => found,
            // Above the fixed table: its own table, looked at with the
            // record lock released.
            Some(Err(overflow)) => linux_saved_overflow_descriptor(overflow, target),
        })
    else {
        return LINUX_EBADF;
    };
    if socket != 0 || device & (LINUX_FILE_MASK | LINUX_DEVICE_CONSOLE) == 0 {
        return LINUX_EOPNOTSUPP;
    }
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(device, Ordering::SeqCst);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Rootfs).store(oci, Ordering::SeqCst);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Socket).store(0, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(socket_flags, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Generation)
        .store(tmp_generation, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(offset, Ordering::SeqCst);
    if let Some(cell) = linux_descriptor_open_file_id_cell(descriptor) {
        cell.store(open_file_id, Ordering::SeqCst);
    }
    set_linux_descriptor_close_on_exec(descriptor, true);
    descriptor
}

/// Descriptor `descriptor` (above the fixed table) of a saved table whose
/// table above the fixed one is `overflow`.
fn linux_saved_overflow_descriptor(
    overflow: u32,
    descriptor: u64,
) -> Option<(u16, u16, crate::linux_socket::SlotId, u32, u32, u64, u64)> {
    let entry = crate::linux_fd_table::get(overflow, descriptor)
        .filter(|entry| !entry.vacant() && entry.open_file_id != 0)?;
    Some((
        entry.state,
        entry.rootfs,
        entry.socket,
        entry.socket_flags,
        entry.generation,
        entry.offset,
        entry.open_file_id,
    ))
}

/// Descriptor `descriptor` of the fixed part of saved table `state`.
fn linux_saved_descriptor(
    state: &LinuxDescriptorRuntimeState,
    descriptor: u64,
) -> Option<(u16, u16, crate::linux_socket::SlotId, u32, u32, u64, u64)> {
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
        let index = descriptor as usize;
        let id = state.stdio_open_file_ids[index];
        let explicit_device = state.stdio_devices[index];
        let console_access = if descriptor < 2 {
            u16::from((state.console >> (descriptor * 2)) & 0b11)
        } else if state.stderr_open {
            LINUX_DESCRIPTOR_OUTPUT
        } else {
            0
        };
        let device = if explicit_device != 0 {
            explicit_device
        } else if console_access != 0 {
            LINUX_DEVICE_CONSOLE | console_access
        } else {
            0
        };
        return (id != 0).then_some((
            device,
            state.stdio_rootfs[index],
            state.stdio_sockets[index],
            state.stdio_socket_flags[index],
            state.stdio_tmp_generations[index],
            state.stdio_offsets[index],
            id,
        ));
    }
    let index = (descriptor - LINUX_AUX_DESCRIPTOR_FIRST) as usize;
    let id = state.open_file_ids[index];
    (id != 0).then_some((
        state.devices[index],
        state.rootfs[index],
        state.sockets[index],
        state.socket_flags[index],
        state.tmp_generations[index],
        state.offsets[index],
        id,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn linux_pidfd_send_signal(
    descriptor: u64,
    signal: u64,
    information: u64,
    flags: u64,
    output: LinuxSyscallFrameHandle,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> u64 {
    const SI_TKILL: i32 = -6;
    let signal = u64::from(signal as u32);
    let flags = u64::from(flags as u32);
    if flags != 0 {
        return LINUX_EINVAL;
    }
    // A pidfd, or a process's /proc directory.
    let process = if linux_pidfd_descriptor(descriptor) {
        linux_pidfd_process(descriptor)
    } else if matches!(
        linux_device_descriptor(descriptor) & !3,
        LINUX_PROC_PID1_DIRECTORY | LINUX_PROC_PID2_DIRECTORY
    ) {
        linux_proc_directory_descriptor_process(descriptor)
    } else {
        return LINUX_EBADF;
    };
    let Some(process) = process else {
        return LINUX_ESRCH;
    };
    let generated = if information == 0 {
        (signal, LINUX_SI_USER, None)
    } else {
        let mut bytes = [0_u8; size_of::<LinuxSignalInformation>()];
        if !copy_from_linux_user(information, &mut bytes) {
            return LINUX_EFAULT;
        }
        // The information names the signal sent (EINVAL otherwise); only
        // a process signalling itself may pass a code the kernel's own
        // signals use (si_code >= 0, or SI_TKILL).
        if u64::from(u32::from_ne_bytes(bytes[..4].try_into().unwrap())) != signal {
            return LINUX_EINVAL;
        }
        let code = i32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        if process != current_linux_process_pid() && (code >= 0 || code == SI_TKILL) {
            return LINUX_EPERM;
        }
        (
            signal,
            code,
            Some(u64::from_ne_bytes(bytes[24..32].try_into().unwrap())),
        )
    };
    linux_kill(
        u64::from(process),
        generated,
        output,
        interrupted,
        return_registers,
    )
}
