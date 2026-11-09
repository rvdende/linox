use super::*;

/// F_SETLEASE on a regular file: a read lease needs the file open for
/// reading only (EAGAIN), as a writer anywhere forbids one in Linux. Leases
/// are kept per descriptor and never broken: no other opener is told.
fn linux_fcntl_set_lease(descriptor: u64, kind: u64) -> u64 {
    use crate::linux_lease::Kind;
    const F_RDLCK: u64 = 0;
    const F_WRLCK: u64 = 1;
    const F_UNLCK: u64 = 2;
    let kind = match u64::from(kind as u32) {
        F_RDLCK => Some(Kind::Read),
        F_WRLCK => Some(Kind::Write),
        F_UNLCK => None,
        _ => return LINUX_EINVAL,
    };
    // Leases are on regular files: an overlay node's or a volume's.
    let Some(handle) = linux_overlay_descriptor_handle(descriptor) else {
        return LINUX_EINVAL;
    };
    let Some(metadata) = crate::linux_overlay::metadata(handle)
        .filter(|metadata| metadata.kind == crate::linux_overlay::NodeKind::File)
    else {
        return LINUX_EINVAL;
    };
    // Only the file's owner may take one, or a holder of CAP_LEASE.
    if kind.is_some()
        && current_linux_credentials().is_none_or(|credentials| {
            credentials.user.filesystem != metadata.owner
                && !credentials.has(linox_credentials::capability::LEASE)
        })
    {
        return LINUX_EACCES;
    }
    let file = crate::linux_overlay::generation(handle);
    let pid = current_linux_process_pid();
    let opens = linux_lease_opens(file, descriptor);
    match crate::linux_lease::set(
        linux_execution_instance(),
        (pid, descriptor as u32, file),
        kind,
        opens,
        |holder, held| linux_lease_holder_valid(holder, held, file),
    ) {
        Ok(()) => 0,
        Err(crate::linux_lease::Error::Conflict) => LINUX_EAGAIN,
        Err(crate::linux_lease::Error::NoMemory) => LINUX_ENOMEM,
    }
}

/// The descriptors of the domain's processes that have overlay node
/// `file` open (the calling process's from its live table, the others'
/// from their saved ones): each with its process, number and whether it
/// writes.
fn linux_file_descriptors(file: u32, mut visit: impl FnMut(u32, u64, bool)) {
    let open = |state: u16, generation: u32| {
        (state & !3 == LINUX_FILE_TMP_SCRATCH && state & 3 != 0 && generation == file)
            .then_some(state & 2 != 0)
    };
    let me = current_linux_process_pid();
    for index in 0..X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS.len() {
        if let Some(writes) = open(
            X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index].load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index].load(Ordering::SeqCst),
        ) {
            visit(me, index as u64, writes);
        }
    }
    for index in 0..LINUX_DEVICE_DESCRIPTOR_COUNT {
        if let Some(writes) = X86_RUNTIME
            .ELF_PROBE_DEVICE_DESCRIPTORS
            .get(index)
            .zip(X86_RUNTIME.ELF_PROBE_TMP_FILE_GENERATIONS.get(index))
            .and_then(|(state, generation)| {
                open(
                    state.load(Ordering::SeqCst),
                    generation.load(Ordering::SeqCst),
                )
            })
        {
            visit(me, LINUX_AUX_DESCRIPTOR_FIRST + index as u64, writes);
        }
    }
    for (descriptor, entry) in linux_overflow_descriptors() {
        if let Some(writes) = open(entry.state, entry.generation) {
            visit(me, descriptor, writes);
        }
    }
    for pid in (0..linux_process::live_process_slots())
        .filter_map(linux_process::live_process_pid_at)
        .filter(|pid| *pid != me)
    {
        let Some(state) = linux_process_runtime_state(pid).filter(|state| state.valid) else {
            continue;
        };
        let descriptors = &state.descriptors;
        for (index, (state, generation)) in descriptors
            .stdio_devices
            .iter()
            .zip(&descriptors.stdio_tmp_generations)
            .enumerate()
        {
            if let Some(writes) = open(*state, *generation) {
                visit(pid, index as u64, writes);
            }
        }
        for (index, (state, generation)) in descriptors
            .devices
            .iter()
            .zip(&descriptors.tmp_generations)
            .enumerate()
        {
            if let Some(writes) = open(*state, *generation) {
                visit(pid, LINUX_AUX_DESCRIPTOR_FIRST + index as u64, writes);
            }
        }
        for (descriptor, entry) in linux_saved_overflow_entries(descriptors) {
            if let Some(writes) = open(entry.state, entry.generation) {
                visit(pid, descriptor, writes);
            }
        }
    }
}

/// How the opens of overlay node `file` other than the caller's
/// `descriptor` stand, for a lease on it.
fn linux_lease_opens(file: u32, descriptor: u64) -> crate::linux_lease::Opens {
    let me = current_linux_process_pid();
    let mut opens = crate::linux_lease::Opens::default();
    linux_file_descriptors(file, |pid, held, writes| {
        opens.writers |= writes;
        opens.others |= pid != me || held != descriptor;
    });
    opens
}

/// Whether descriptor `descriptor` of `pid` still has overlay node `file`
/// open: a lease it holds lasts as long.
fn linux_lease_holder_valid(pid: u32, descriptor: u32, file: u32) -> bool {
    let mut held = false;
    linux_file_descriptors(file, |holder, number, _| {
        held |= holder == pid && number == u64::from(descriptor);
    });
    held
}

/// What an open of `path` (from `directory`) with `flags`, or a truncate
/// (`truncating`), does about leases on the file: None when none is in
/// the way, else the call's result for now (EWOULDBLOCK for O_NONBLOCK,
/// or LINUX_LEASE_PENDING to wait and try again). The holders hear SIGIO
/// as their leases start to break.
fn linux_lease_break_at(
    directory: u64,
    path_address: u64,
    flags: u64,
    truncating: bool,
) -> Option<u64> {
    const SIGIO: u64 = 29;
    if !crate::linux_lease::active() {
        return None;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = copy_linux_c_string(path_address, &mut path).ok()?;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length =
        linux_canonical_path_at(u64::from(directory as u32), &path[..length], &mut canonical)
            .ok()?;
    let follow = flags & LINUX_O_NOFOLLOW == 0;
    let (_, _, metadata) = linux_overlay_lookup_following(&mut canonical, length, follow).ok()?;
    let file = crate::linux_overlay::generation(metadata?.handle);
    let write = truncating || flags & 3 != 0 || flags & LINUX_O_TRUNC != 0;
    let seconds = linux_proc_sysctl_value(b"sys/fs/lease-break-time")
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(45);
    let now = linux_elapsed_nanoseconds()?;
    let mut holders = Vec::new();
    let breaking = crate::linux_lease::break_for(
        linux_execution_instance(),
        (file, current_linux_process_pid(), write),
        (now, seconds.saturating_mul(NANOSECONDS_PER_SECOND)),
        |holder, held| linux_lease_holder_valid(holder, held, file),
        |holder, _| holders.push(holder),
    );
    for holder in holders {
        let _ = linux_queue_process_signal(holder, SIGIO, LINUX_SI_KERNEL, None);
    }
    match breaking {
        crate::linux_lease::Breaking::Clear => None,
        crate::linux_lease::Breaking::Wait if flags & LINUX_O_NONBLOCK != 0 && !truncating => {
            Some(LINUX_EAGAIN)
        }
        crate::linux_lease::Breaking::Wait => Some(LINUX_LEASE_PENDING),
    }
}

/// An open or truncate that may meet a lease: `call` runs once no lease is
/// in the way; until then the caller waits as F_SETLKW does, a signal
/// interrupting it, while the lease holder gives the lease up (or its
/// break time runs out).
pub(super) fn linux_lease_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    (number, directory, path_address, flags): (u64, u64, u64, u64),
    call: impl FnOnce() -> u64,
) -> u64 {
    let truncating = number == LINUX_TRUNCATE_SYSCALL;
    loop {
        match linux_lease_break_at(directory, path_address, flags, truncating) {
            None => return call(),
            Some(LINUX_LEASE_PENDING) => {}
            Some(result) => return result,
        }
        if linux_light_thread_here().is_some() {
            if let (Some(current), Some(deadline)) = (
                current_linux_thread_handle(),
                linux_elapsed_nanoseconds().map(|now| now.saturating_add(1_000_000)),
            ) {
                let mut restart = caller;
                restart.rip = caller.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
                restart.rax = number;
                if save_linux_thread_return_context(current, restart)
                    && block_current_linux_thread(LINUX_THREAD_WAIT_RETRY, number, 0, deadline)
                {
                    return LINUX_RETURN_TO_KERNEL;
                }
            }
        }
        // A lease is broken by its holder's fcntl, or by force once the
        // lease break time has passed: every tick looks again.
        match run_other_linux_processes(output, caller, number, WaitOn::ANYTHING) {
            Some(LinuxBlockedWait::Recheck) => {}
            Some(LinuxBlockedWait::Return(result)) => return result,
            None => match ready_linux_thread_handle() {
                Some(target) => {
                    return linux_retry_after_thread_live_return(output, caller, number, target)
                }
                None => linux_wait_for_interrupt(),
            },
        }
    }
}

/// F_NOTIFY (dnotify) on a directory descriptor: the process is signalled
/// (F_SETSIG's signal, else SIGIO) when the directory or its entries
/// change as `events` (DN_*) asks; `linux_inotify` matches the events.
fn linux_fcntl_notify(descriptor: u64, events: u64) -> u64 {
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_walk_start(descriptor, &mut path) {
        Ok(length) => length,
        Err(_) => return LINUX_ENOTDIR,
    };
    if !linux_inotify_is_directory(&path[..length]) {
        return LINUX_ENOTDIR;
    }
    match crate::linux_inotify::dnotify_register(
        linux_execution_instance(),
        current_linux_process_pid(),
        descriptor as u32,
        &path[..length],
        events as u32,
    ) {
        Ok(()) => 0,
        Err(_) => LINUX_ENOMEM,
    }
}

/// Sends the dnotify notices the last system call caused: F_SETSIG's
/// signal with si_code POLL_MSG, si_band and si_fd (kept where a queued
/// signal's information keeps the sender and the value), or SIGIO.
pub(in crate::arch::x86_64) fn linux_send_dnotify_notices() {
    const POLL_MSG: i32 = 3;
    // POLLIN | POLLRDNORM | POLLMSG, Linux's band for POLL_MSG.
    const BAND: u32 = 0x441;
    const SIGIO: u64 = 29;
    let mut notices = Vec::new();
    crate::linux_inotify::take_dnotify_notices(linux_execution_instance(), &mut notices);
    for (pid, descriptor, signal) in notices {
        if signal == 0 {
            let _ = linux_queue_process_signal(pid, SIGIO, LINUX_SI_KERNEL, None);
        } else {
            let _ = linux_queue_process_signal_from(
                pid,
                u64::from(signal),
                POLL_MSG,
                Some(u64::from(descriptor)),
                (BAND, 0),
            );
        }
    }
}

/// F_GETLEASE: F_RDLCK, F_WRLCK or F_UNLCK (what a lease being broken
/// becomes).
fn linux_fcntl_get_lease(descriptor: u64) -> u64 {
    let lease = linux_overlay_descriptor_handle(descriptor).and_then(|handle| {
        crate::linux_lease::get(
            linux_execution_instance(),
            current_linux_process_pid(),
            descriptor as u32,
            crate::linux_overlay::generation(handle),
        )
    });
    match lease {
        Some(crate::linux_lease::Kind::Read) => 0,
        Some(crate::linux_lease::Kind::Write) => 1,
        None => 2,
    }
}

fn linux_console_fcntl(descriptor: u64, command: u64, argument: u64) -> u64 {
    let state = linux_console_descriptor(descriptor);
    if state == 0 {
        return LINUX_EBADF;
    }
    match command {
        LINUX_F_DUPFD => linux_console_dup_at_least(descriptor, argument, false),
        LINUX_F_DUPFD_CLOEXEC => linux_console_dup_at_least(descriptor, argument, true),
        LINUX_F_GETFD => u64::from(linux_descriptor_close_on_exec(descriptor)),
        LINUX_F_SETFD => {
            set_linux_descriptor_close_on_exec(
                descriptor,
                argument & u64::from(LINUX_FD_CLOEXEC) != 0,
            );
            0
        }
        LINUX_F_GETFL if u16::from(state) == LINUX_DESCRIPTOR_INPUT => linux_console_status(0),
        LINUX_F_GETFL if u16::from(state) == LINUX_DESCRIPTOR_OUTPUT => linux_console_status(1),
        // apt sets O_NONBLOCK on its terminal to drain typed-ahead input
        // before dpkg runs, and exits if the terminal refuses.
        LINUX_F_SETFL => {
            crate::set_console_nonblocking(argument & LINUX_O_NONBLOCK != 0);
            0
        }
        _ => LINUX_EINVAL,
    }
}

/// F_GETFL of a console descriptor: its access mode and O_NONBLOCK.
fn linux_console_status(access: u64) -> u64 {
    access
        | if crate::console_nonblocking() {
            LINUX_O_NONBLOCK
        } else {
            0
        }
}

fn linux_fcntl_descriptor_flags(descriptor: u64, command: u64, argument: u64) -> u64 {
    match command {
        LINUX_F_GETFD => u64::from(linux_descriptor_close_on_exec(descriptor)),
        LINUX_F_SETFD => {
            set_linux_descriptor_close_on_exec(
                descriptor,
                argument & u64::from(LINUX_FD_CLOEXEC) != 0,
            );
            0
        }
        _ => LINUX_EINVAL,
    }
}

fn linux_memfd_fcntl(descriptor: u64, command: u64, argument: u64) -> u64 {
    let Some(handle) = linux_overlay_descriptor_handle(descriptor) else {
        return LINUX_EINVAL;
    };
    let Some(current) = crate::linux_overlay::file_seals(handle) else {
        return LINUX_EINVAL;
    };
    if command == LINUX_F_GET_SEALS {
        return u64::from(current);
    }
    let Ok(requested) = u32::try_from(argument) else {
        return LINUX_EINVAL;
    };
    if requested & !LINUX_F_SEAL_MASK != 0 {
        return LINUX_EINVAL;
    }
    // Sealing takes a descriptor open for writing (EPERM).
    if linux_device_descriptor(descriptor) & LINUX_DESCRIPTOR_OUTPUT == 0 {
        return LINUX_EPERM;
    }
    // F_SEAL_WRITE waits for no shared mapping that may write (EBUSY).
    if requested & LINUX_F_SEAL_WRITE != 0
        && current & LINUX_F_SEAL_SEAL == 0
        && linux_descriptor_stat(descriptor).is_some_and(|stat| {
            crate::linux_areas::file_writably_mapped(
                linux_execution_instance(),
                u64::from_ne_bytes(stat[..8].try_into().unwrap_or([0; 8])),
                u64::from_ne_bytes(stat[8..16].try_into().unwrap_or([0; 8])),
            )
        })
    {
        return LINUX_EBUSY;
    }
    match crate::linux_overlay::add_file_seals(handle, requested) {
        Some(true) => 0,
        Some(false) => LINUX_EPERM,
        None => LINUX_EINVAL,
    }
}

/// fcntl's F_SETOWN (8), F_GETOWN (9), F_SETOWN_EX (15), F_GETOWN_EX (16),
/// and F_SETSIG and F_GETSIG for pipes and sockets (`linux_async_io`).
fn linux_fcntl_owner(descriptor: u64, command: u64, argument: u64) -> u64 {
    use crate::linux_async_io::Owner;
    const F_OWNER_TID: i32 = 0;
    const F_OWNER_PID: i32 = 1;
    const F_OWNER_PGRP: i32 = 2;
    let (domain, pid) = (linux_execution_instance(), current_linux_process_pid());
    let slot = linux_socket_slot(descriptor).unwrap_or(crate::linux_socket::SlotId::MAX);
    let fd = descriptor as u32;
    match command {
        8 => {
            let id = argument as i32;
            let owner = match id {
                0 => None,
                id if id > 0 => Some(Owner::Process(id as u32)),
                id => Some(Owner::Group(id.unsigned_abs())),
            };
            crate::linux_async_io::set_owner(domain, pid, fd, slot, owner);
            0
        }
        9 => match crate::linux_async_io::owner(domain, pid, fd) {
            Some(Owner::Process(id) | Owner::Thread(id)) => u64::from(id),
            Some(Owner::Group(group)) => (-i64::from(group)) as u64,
            None => 0,
        },
        15 => {
            let mut request = [0_u8; 8];
            if !copy_from_linux_user(argument, &mut request) {
                return LINUX_EFAULT;
            }
            let kind = i32::from_ne_bytes(request[..4].try_into().unwrap());
            let id = i32::from_ne_bytes(request[4..].try_into().unwrap());
            if id < 0 {
                return LINUX_EINVAL;
            }
            let owner = match (kind, id as u32) {
                (F_OWNER_TID | F_OWNER_PID | F_OWNER_PGRP, 0) => None,
                (F_OWNER_TID, id) => Some(Owner::Thread(id)),
                (F_OWNER_PID, id) => Some(Owner::Process(id)),
                (F_OWNER_PGRP, id) => Some(Owner::Group(id)),
                _ => return LINUX_EINVAL,
            };
            crate::linux_async_io::set_owner(domain, pid, fd, slot, owner);
            0
        }
        16 => {
            let (kind, id) = match crate::linux_async_io::owner(domain, pid, fd) {
                Some(Owner::Thread(id)) => (F_OWNER_TID, id),
                Some(Owner::Process(id)) => (F_OWNER_PID, id),
                Some(Owner::Group(id)) => (F_OWNER_PGRP, id),
                None => (F_OWNER_PID, 0),
            };
            let mut reply = [0_u8; 8];
            reply[..4].copy_from_slice(&kind.to_ne_bytes());
            reply[4..].copy_from_slice(&id.to_ne_bytes());
            if copy_to_linux_user(argument, &reply) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_F_SETSIG => {
            if argument > LINUX_SIGNAL_COUNT as u64 {
                LINUX_EINVAL
            } else if crate::linux_inotify::set_notice_signal(domain, pid, fd, argument as u8) {
                0
            } else {
                LINUX_ENOMEM
            }
        }
        LINUX_F_GETSIG => u64::from(crate::linux_inotify::notice_signal(domain, pid, fd)),
        _ => LINUX_EINVAL,
    }
}

/// Signals the owners of O_ASYNC descriptors reading socket `slot`'s peer
/// (data written to `slot` arrived there): F_SETSIG's signal or SIGIO, to
/// a process, its group, or a thread's process.
pub(super) fn linux_notify_async_io(slot: crate::linux_socket::SlotId) {
    const SIGIO: u64 = 29;
    const POLL_IN: i32 = 1;
    let Some(peer) = crate::linux_socket::local_peer_slot(slot) else {
        return;
    };
    let domain = linux_execution_instance();
    for (pid, fd, owner) in crate::linux_async_io::listeners(domain, peer) {
        let signal = match crate::linux_inotify::notice_signal(domain, pid, fd) {
            0 => SIGIO,
            signal => u64::from(signal),
        };
        let selector = match owner {
            crate::linux_async_io::Owner::Process(id)
            | crate::linux_async_io::Owner::Thread(id) => id as i32,
            crate::linux_async_io::Owner::Group(group) => -(group as i32),
        };
        if let Ok((targets, count)) = linux_signal_targets(selector) {
            for target in &targets[..count] {
                let _ = linux_queue_process_signal(*target, signal, POLL_IN, None);
            }
        }
    }
}

pub(super) fn linux_descriptor_fcntl(descriptor: u64, command: u64, argument: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let command = u64::from(command as u32);
    let state = linux_device_descriptor(descriptor);
    // A lock command reads and checks its flock first, whatever the
    // descriptor (EFAULT, then EINVAL, before EBADF: fcntl13).
    if matches!(
        command,
        LINUX_F_GETLK
            | LINUX_F_OFD_GETLK
            | LINUX_F_SETLK
            | LINUX_F_SETLKW
            | LINUX_F_OFD_SETLK
            | LINUX_F_OFD_SETLKW
    ) {
        return linux_fcntl_lock(descriptor, command, argument);
    }
    // Signal-driven I/O's owner (any descriptor), and F_SETSIG on pipes
    // and sockets, whose own commands come below.
    if matches!(command, 8 | 9 | 15 | 16)
        || matches!(command, LINUX_F_SETSIG | LINUX_F_GETSIG)
            && linux_socket_slot(descriptor).is_some()
    {
        if !linux_descriptor_open(descriptor) {
            return LINUX_EBADF;
        }
        return linux_fcntl_owner(descriptor, command, argument);
    }
    if descriptor == 2 && X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::SeqCst) {
        return match command {
            LINUX_F_DUPFD => linux_console_dup_at_least(descriptor, argument, false),
            LINUX_F_DUPFD_CLOEXEC => linux_console_dup_at_least(descriptor, argument, true),
            LINUX_F_GETFD | LINUX_F_SETFD => {
                linux_fcntl_descriptor_flags(descriptor, command, argument)
            }
            LINUX_F_GETFL => 1,
            LINUX_F_SETFL => linux_descriptor_set_status_flags(
                &X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[descriptor as usize],
                argument,
                LINUX_O_APPEND | LINUX_O_NONBLOCK,
            ),
            _ => LINUX_EINVAL,
        };
    }
    if linux_socket_slot(descriptor).is_some() {
        let pipe_access = if state & LINUX_DEVICE_PIPE != 0 {
            u64::from(state & 3) - 1
        } else {
            2
        };
        let flags_cell = linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags);
        let flags: &dyn LinuxFileCell<u32> = &flags_cell;
        return match command {
            LINUX_F_DUPFD => linux_device_dup_at_least(descriptor, argument, false),
            LINUX_F_DUPFD_CLOEXEC => linux_device_dup_at_least(descriptor, argument, true),
            LINUX_F_GETFD | LINUX_F_SETFD => {
                linux_fcntl_descriptor_flags(descriptor, command, argument)
            }
            LINUX_F_GETFL => pipe_access | u64::from(flags.load(Ordering::SeqCst)),
            // O_ASYNC: data arriving signals the descriptor's owner.
            LINUX_F_SETFL => {
                const O_ASYNC: u64 = 0o20000;
                if let Some(slot) = linux_socket_slot(descriptor) {
                    crate::linux_async_io::set_async(
                        linux_execution_instance(),
                        current_linux_process_pid(),
                        descriptor as u32,
                        slot,
                        argument & O_ASYNC != 0,
                    );
                }
                linux_descriptor_set_status_flags(flags, argument, LINUX_O_NONBLOCK | O_ASYNC)
            }
            LINUX_F_GETPIPE_SZ if state & LINUX_DEVICE_PIPE != 0 => linux_socket_slot(descriptor)
                .map_or(LINUX_EBADF, |slot| {
                    crate::linux_socket::local_capacity(slot)
                        .map_or_else(linux_socket_error, |capacity| capacity as u64)
                }),
            LINUX_F_SETPIPE_SZ if state & LINUX_DEVICE_PIPE != 0 => {
                let requested = u64::from(argument as u32);
                // A size past 1 << 31 is not a size (fcntl37).
                if requested > 1 << 31 {
                    return LINUX_EINVAL;
                }
                if requested > linux_pipe_max_size()
                    && !current_linux_credentials()
                        .is_some_and(|value| value.has(linox_credentials::capability::SYS_RESOURCE))
                {
                    return LINUX_EPERM;
                }
                linux_socket_slot(descriptor).map_or(LINUX_EBADF, |slot| {
                    match crate::linux_socket::set_local_capacity(slot, requested as usize) {
                        Ok(capacity) => capacity as u64,
                        Err(crate::linux_socket::Error::Exhausted) => LINUX_EBUSY,
                        Err(error) => linux_socket_error(error),
                    }
                })
            }
            _ => LINUX_EINVAL,
        };
    }
    if state == 0 {
        if linux_epoll_descriptor(descriptor) {
            return match command {
                LINUX_F_DUPFD => linux_console_dup_at_least(descriptor, argument, false),
                LINUX_F_DUPFD_CLOEXEC => linux_console_dup_at_least(descriptor, argument, true),
                LINUX_F_GETFD | LINUX_F_SETFD => {
                    linux_fcntl_descriptor_flags(descriptor, command, argument)
                }
                LINUX_F_GETFL => 2,
                _ => LINUX_EINVAL,
            };
        }
        if linux_eventfd_descriptor(descriptor) {
            let Some((_, eventfd_flags)) = linux_eventfd_state(descriptor) else {
                return LINUX_EBADF;
            };
            return match command {
                LINUX_F_DUPFD => linux_console_dup_at_least(descriptor, argument, false),
                LINUX_F_DUPFD_CLOEXEC => linux_console_dup_at_least(descriptor, argument, true),
                LINUX_F_GETFD | LINUX_F_SETFD => {
                    linux_fcntl_descriptor_flags(descriptor, command, argument)
                }
                LINUX_F_GETFL => {
                    2 | u64::from(eventfd_flags.load(Ordering::SeqCst) & LINUX_EFD_NONBLOCK as u32)
                }
                LINUX_F_SETFL => linux_descriptor_set_nonblocking(eventfd_flags, argument),
                _ => LINUX_EINVAL,
            };
        }
        if let Some(state) = linux_timerfd_state(descriptor) {
            return match command {
                LINUX_F_DUPFD => linux_console_dup_at_least(descriptor, argument, false),
                LINUX_F_DUPFD_CLOEXEC => linux_console_dup_at_least(descriptor, argument, true),
                LINUX_F_GETFD | LINUX_F_SETFD => {
                    linux_fcntl_descriptor_flags(descriptor, command, argument)
                }
                LINUX_F_GETFL => {
                    2 | u64::from(state.flags.load(Ordering::SeqCst) & LINUX_TFD_NONBLOCK as u32)
                }
                LINUX_F_SETFL => linux_descriptor_set_nonblocking(state.flags, argument),
                _ => LINUX_EINVAL,
            };
        }
        if linux_pipe_descriptor(descriptor) {
            return match command {
                LINUX_F_GETFD | LINUX_F_SETFD => {
                    linux_fcntl_descriptor_flags(descriptor, command, argument)
                }
                LINUX_F_GETFL => {
                    let access = u64::from(linux_pipe_write_descriptor(descriptor));
                    let flags = if access == 0 {
                        &X86_RUNTIME.ELF_PROBE_PIPE_READ_FLAGS
                    } else {
                        &X86_RUNTIME.ELF_PROBE_PIPE_WRITE_FLAGS
                    };
                    access | u64::from(flags.load(Ordering::SeqCst) & LINUX_O_NONBLOCK as u32)
                }
                LINUX_F_SETFL => {
                    let flags = if linux_pipe_read_descriptor(descriptor) {
                        &X86_RUNTIME.ELF_PROBE_PIPE_READ_FLAGS
                    } else {
                        &X86_RUNTIME.ELF_PROBE_PIPE_WRITE_FLAGS
                    };
                    linux_descriptor_set_nonblocking(flags, argument)
                }
                _ => LINUX_EINVAL,
            };
        }
        return linux_console_fcntl(descriptor, command, argument);
    }
    match command {
        LINUX_F_DUPFD if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) => {
            linux_device_dup_at_least(descriptor, argument, false)
        }
        LINUX_F_DUPFD_CLOEXEC if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) => {
            linux_device_dup_at_least(descriptor, argument, true)
        }
        LINUX_F_GETFD | LINUX_F_SETFD => {
            linux_fcntl_descriptor_flags(descriptor, command, argument)
        }
        LINUX_F_GETLK | LINUX_F_OFD_GETLK | LINUX_F_SETLK | LINUX_F_SETLKW | LINUX_F_OFD_SETLK
        | LINUX_F_OFD_SETLKW => linux_fcntl_lock(descriptor, command, argument),
        LINUX_F_ADD_SEALS | LINUX_F_GET_SEALS => linux_memfd_fcntl(descriptor, command, argument),
        // Whether this descriptor's open created the file (fcntl40).
        LINUX_F_CREATED_QUERY => u64::from(linux_descriptor_flag(
            &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_CREATED,
            descriptor,
        )),
        LINUX_F_SETLEASE => linux_fcntl_set_lease(descriptor, argument),
        LINUX_F_GETLEASE => linux_fcntl_get_lease(descriptor),
        LINUX_F_SETSIG => {
            if argument > LINUX_SIGNAL_COUNT as u64 {
                LINUX_EINVAL
            } else if crate::linux_inotify::set_notice_signal(
                linux_execution_instance(),
                current_linux_process_pid(),
                descriptor as u32,
                argument as u8,
            ) {
                0
            } else {
                LINUX_ENOMEM
            }
        }
        LINUX_F_GETSIG => u64::from(crate::linux_inotify::notice_signal(
            linux_execution_instance(),
            current_linux_process_pid(),
            descriptor as u32,
        )),
        LINUX_F_NOTIFY => linux_fcntl_notify(descriptor, argument),
        LINUX_F_GETFL => {
            // A descriptor without access bits (a signalfd, other anonymous
            // files) is O_RDWR; `(0 - 1)` wrapped to every flag, O_NONBLOCK
            // among them (signalfd4_02).
            let access = match state & 3 {
                0 => 2,
                bits => bits - 1,
            };
            u64::from(access)
                | u64::from(
                    linux_socket_flags(descriptor).unwrap_or(0)
                        & !(LINUX_PRIVATE_SECRET_DESCRIPTOR
                            | LINUX_PRIVATE_IO_URING_DESCRIPTOR
                            | LINUX_PRIVATE_PROC_LINK_DESCRIPTOR
                            | LINUX_PRIVATE_NONOTIFY_DESCRIPTOR
                            | LINUX_PRIVATE_LANDLOCK_DESCRIPTOR),
                )
        }
        LINUX_F_SETFL => {
            if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
                return LINUX_EBADF;
            }
            linux_descriptor_set_status_flags(
                &linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags),
                argument,
                LINUX_O_APPEND | LINUX_O_NONBLOCK,
            )
        }
        _ => LINUX_EINVAL,
    }
}

pub(super) fn linux_flock(descriptor: u64, operation: u64) -> u64 {
    const LOCK_SHARED: u64 = 1;
    const LOCK_EXCLUSIVE: u64 = 2;
    const LOCK_NONBLOCKING: u64 = 4;
    const LOCK_UNLOCK: u64 = 8;
    let descriptor = u64::from(descriptor as u32);
    let operation = u64::from(operation as u32);
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    let kind = operation & !LOCK_NONBLOCKING;
    if !matches!(kind, LOCK_SHARED | LOCK_EXCLUSIVE | LOCK_UNLOCK) {
        return LINUX_EINVAL;
    }
    // The open file description holds the lock; a descriptor without an
    // open-file id stands for its own.
    let description = linux_descriptor_open_file_id(descriptor).unwrap_or(1 << 63 | descriptor);
    let holder = (current_linux_process_pid(), description);
    if kind == LOCK_UNLOCK {
        crate::linux_record_lock::flock_release(description);
        return 0;
    }
    // A pipe or socket has no device and inode: the descriptor stands in.
    let file = linux_record_lock_file(descriptor).unwrap_or((u64::MAX, descriptor));
    match crate::linux_record_lock::flock_set(file, holder, kind == LOCK_EXCLUSIVE, |pid| {
        linux_process::live_process_status(pid).is_some()
    }) {
        Ok(()) => 0,
        // EWOULDBLOCK, for the caller to wait on unless LOCK_NB.
        Err(crate::linux_record_lock::FlockError::Conflict) => LINUX_EAGAIN,
        Err(crate::linux_record_lock::FlockError::NoMemory) => LINUX_ENOMEM,
    }
}

/// flock(2): one attempt, and without LOCK_NB a wait for the holder to let
/// go, as F_SETLKW waits: a signal interrupts it (EINTR, flock07).
pub(super) fn linux_flock_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    descriptor: u64,
    operation: u64,
) -> u64 {
    const LOCK_NONBLOCKING: u64 = 4;
    loop {
        let result = linux_flock(descriptor, operation);
        if result != LINUX_EAGAIN || u64::from(operation as u32) & LOCK_NONBLOCKING != 0 {
            return result;
        }
        if linux_light_thread_here().is_some() {
            if let (Some(current), Some(deadline)) = (
                current_linux_thread_handle(),
                linux_elapsed_nanoseconds().map(|now| now.saturating_add(1_000_000)),
            ) {
                let mut restart = caller;
                restart.rip = caller.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
                restart.rax = LINUX_FLOCK_SYSCALL;
                if save_linux_thread_return_context(current, restart)
                    && block_current_linux_thread(
                        LINUX_THREAD_WAIT_RETRY,
                        LINUX_FLOCK_SYSCALL,
                        0,
                        deadline,
                    )
                {
                    return LINUX_RETURN_TO_KERNEL;
                }
            }
        }
        match run_other_linux_processes(
            output,
            caller,
            LINUX_FLOCK_SYSCALL,
            WaitOn::of(wait_events::STATE),
        ) {
            Some(LinuxBlockedWait::Recheck) => {}
            Some(LinuxBlockedWait::Return(result)) => return result,
            None => match ready_linux_thread_handle() {
                Some(target) => {
                    return linux_retry_after_thread_live_return(
                        output,
                        caller,
                        LINUX_FLOCK_SYSCALL,
                        target,
                    )
                }
                None => linux_wait_for_interrupt(),
            },
        }
    }
}

/// The file a descriptor's record locks apply to: its device and inode.
pub(super) fn linux_record_lock_file(descriptor: u64) -> Option<crate::linux_record_lock::File> {
    let stat = linux_descriptor_stat(descriptor)?;
    Some((
        u64::from_ne_bytes(stat[..8].try_into().ok()?),
        u64::from_ne_bytes(stat[8..16].try_into().ok()?),
    ))
}

/// Record locks with `struct flock` at `address` (fcntl F_GETLK, F_SETLK,
/// F_SETLKW and the F_OFD_ forms). One attempt: F_SETLKW's wait is
/// `linux_fcntl_setlkw_live_return`.
fn linux_fcntl_lock(descriptor: u64, command: u64, address: u64) -> u64 {
    use crate::linux_record_lock::{Kind, Owner};
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;
    let mut flock = [0_u8; 32];
    if address == 0 || !copy_from_linux_user(address, &mut flock) {
        return LINUX_EFAULT;
    }
    let lock_type = i16::from_ne_bytes([flock[0], flock[1]]);
    let whence = i16::from_ne_bytes([flock[2], flock[3]]);
    let offset = i64::from_ne_bytes(flock[8..16].try_into().unwrap());
    let length = i64::from_ne_bytes(flock[16..24].try_into().unwrap());
    let description = matches!(
        command,
        LINUX_F_OFD_GETLK | LINUX_F_OFD_SETLK | LINUX_F_OFD_SETLKW
    );
    // OFD locks have no process: l_pid must be 0.
    if description && flock[24..28] != [0; 4] {
        return LINUX_EINVAL;
    }
    let Some(stat) = linux_descriptor_stat(descriptor) else {
        return LINUX_EBADF;
    };
    let file = (
        u64::from_ne_bytes(stat[..8].try_into().unwrap()),
        u64::from_ne_bytes(stat[8..16].try_into().unwrap()),
    );
    let base = match whence {
        0 => 0,
        1 => linux_descriptor_offset(descriptor).load(Ordering::SeqCst) as i64,
        2 => i64::from_ne_bytes(stat[48..56].try_into().unwrap()),
        _ => return LINUX_EINVAL,
    };
    // A negative length locks the bytes before the start.
    let Some((start, end)) = base.checked_add(offset).and_then(|start| match length {
        0 => Some((start, None)),
        length if length > 0 => start.checked_add(length).map(|end| (start, Some(end))),
        length => start.checked_add(length).map(|first| (first, Some(start))),
    }) else {
        return LINUX_EINVAL;
    };
    if start < 0 {
        return LINUX_EINVAL;
    }
    let (start, end) = (start as u64, end.map_or(u64::MAX, |end| end as u64));
    let pid = current_linux_process_pid();
    let owner = if description {
        match linux_descriptor_open_file_id(descriptor) {
            Some(id) => Owner::Description(id),
            None => return LINUX_EBADF,
        }
    } else {
        Owner::Process(pid)
    };
    let alive = |pid: u32| {
        linux_process::live_process_status(pid).is_some_and(|status| status.state.is_running())
    };
    let kind = match lock_type {
        F_RDLCK => Some(Kind::Read),
        F_WRLCK => Some(Kind::Write),
        F_UNLCK => None,
        _ => return LINUX_EINVAL,
    };
    if matches!(command, LINUX_F_GETLK | LINUX_F_OFD_GETLK) {
        let Some(kind) = kind else {
            return LINUX_EINVAL;
        };
        match crate::linux_record_lock::conflict(file, owner, (kind, start, end), alive) {
            Some(blocking) => {
                let blocking_type = match blocking.kind {
                    Kind::Read => F_RDLCK,
                    Kind::Write => F_WRLCK,
                };
                let blocking_length = if blocking.end == u64::MAX {
                    0
                } else {
                    blocking.end - blocking.start
                };
                let blocking_pid = match blocking.owner {
                    Owner::Process(pid) => pid as i32,
                    Owner::Description(_) => -1,
                };
                flock[..2].copy_from_slice(&blocking_type.to_ne_bytes());
                flock[2..4].copy_from_slice(&0_i16.to_ne_bytes());
                flock[8..16].copy_from_slice(&blocking.start.to_ne_bytes());
                flock[16..24].copy_from_slice(&blocking_length.to_ne_bytes());
                flock[24..28].copy_from_slice(&blocking_pid.to_ne_bytes());
            }
            None => flock[..2].copy_from_slice(&F_UNLCK.to_ne_bytes()),
        }
        return if copy_to_linux_user(address, &flock) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    // A read lock needs the descriptor open for reading, a write lock for
    // writing.
    let access = linux_device_descriptor(descriptor) & 3;
    if kind == Some(Kind::Read) && !matches!(access, LINUX_DESCRIPTOR_INPUT | 3)
        || kind == Some(Kind::Write) && !matches!(access, LINUX_DESCRIPTOR_OUTPUT | 3)
    {
        return LINUX_EBADF;
    }
    match crate::linux_record_lock::set(file, owner, pid, (kind, start, end), alive) {
        Ok(()) => {
            crate::linux_record_lock::stop_waiting(pid);
            0
        }
        // A process lock F_SETLKW would wait for, held by a process that
        // (through others) waits for this one, is EDEADLK.
        Err(crate::linux_record_lock::Error::Conflict(blocking))
            if command == LINUX_F_SETLKW
                && matches!(owner, Owner::Process(_))
                && match blocking.owner {
                    Owner::Process(holder) => {
                        crate::linux_record_lock::wait_would_deadlock(pid, holder, alive)
                    }
                    _ => false,
                } =>
        {
            LINUX_EDEADLK
        }
        Err(crate::linux_record_lock::Error::Conflict(_)) => LINUX_EAGAIN,
        Err(crate::linux_record_lock::Error::NoMemory) => LINUX_ENOLCK,
    }
}

/// fcntl F_SETLKW and F_OFD_SETLKW: waits while another owner's lock is in
/// the way, letting other processes run, until it is released or a signal
/// arrives.
pub(super) fn linux_fcntl_setlkw_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    (descriptor, command, address): (u64, u64, u64),
) -> u64 {
    loop {
        let result = linux_descriptor_fcntl(descriptor, command, address);
        if result != LINUX_EAGAIN {
            return result;
        }
        // On the light path the thread waits its millisecond parked right
        // here and tries again on whichever CPU picks it up, rather than
        // moving to the owner for every conflict: fcntl36's 36 threads
        // contending one lock sent the owner thousands of migrations.
        if linux_light_thread_here().is_some() {
            if let (Some(current), Some(deadline)) = (
                current_linux_thread_handle(),
                linux_elapsed_nanoseconds().map(|now| now.saturating_add(1_000_000)),
            ) {
                let mut restart = caller;
                restart.rip = caller.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
                restart.rax = LINUX_FCNTL_SYSCALL;
                // As a futex wait leaves the light path: the context saved,
                // the wait recorded with its deadline, and the loop moves on;
                // the expiry makes the thread ready with the call to issue.
                if save_linux_thread_return_context(current, restart)
                    && block_current_linux_thread(
                        LINUX_THREAD_WAIT_RETRY,
                        LINUX_FCNTL_SYSCALL,
                        0,
                        deadline,
                    )
                {
                    return LINUX_RETURN_TO_KERNEL;
                }
            }
        }
        match run_other_linux_processes(
            output,
            caller,
            LINUX_FCNTL_SYSCALL,
            WaitOn::of(wait_events::STATE),
        ) {
            Some(LinuxBlockedWait::Recheck) => {}
            Some(LinuxBlockedWait::Return(result)) => return result,
            // A sibling thread, which may hold the lock, is ready: it runs
            // while this one waits a tick and takes the lock again. With
            // nothing else to run, the holder is on another CPU.
            None => match ready_linux_thread_handle() {
                Some(target) => {
                    return linux_retry_after_thread_live_return(
                        output,
                        caller,
                        LINUX_FCNTL_SYSCALL,
                        target,
                    )
                }
                None => linux_wait_for_interrupt(),
            },
        }
    }
}

/// Blocks the calling thread for a millisecond, set to issue system call
/// `number` again when it wakes (`LINUX_THREAD_WAIT_RETRY`), and switches
/// to the ready sibling thread `target`.
fn linux_retry_after_thread_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    target: LinuxThreadHandle,
) -> u64 {
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let Some(tls) = linux_thread_context(current) else {
        return LINUX_ESRCH;
    };
    let Some(deadline) = linux_elapsed_nanoseconds().map(|now| now.saturating_add(1_000_000))
    else {
        return LINUX_EINVAL;
    };
    let mut restart = caller;
    restart.rip = caller.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
    restart.rax = number;
    if !save_linux_thread_return_context(current, restart)
        || !block_current_linux_thread(LINUX_THREAD_WAIT_RETRY, number, 0, deadline)
    {
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
        let slot = usize::from(current.slot);
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_RUNNING, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_CURRENT_THREAD_SLOT
            .store(current.slot, Ordering::SeqCst);
        let _ = install_linux_tls_context(tls);
        return LINUX_EINVAL;
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
