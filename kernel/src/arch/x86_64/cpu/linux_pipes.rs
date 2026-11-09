use super::*;

fn complete_linux_pipe_read_wait(slot: usize) -> bool {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_PIPE_READ
    {
        return false;
    }
    let packed = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let descriptor = packed & 0xff;
    let count = (packed & !LINUX_PIPE_READV_WAIT_FLAG) >> 8;
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = if packed & LINUX_PIPE_READV_WAIT_FLAG != 0 {
        let Ok(vector_count) = usize::try_from(count) else {
            return false;
        };
        if !(1..=LINUX_IOV_LIMIT).contains(&vector_count) {
            return false;
        }
        let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
        for (index, range) in ranges[..vector_count].iter_mut().enumerate() {
            let Ok(length) = usize::try_from(
                X86_RUNTIME.LINUX_THREAD_IOV_LENGTHS[slot][index].load(Ordering::SeqCst),
            ) else {
                return false;
            };
            *range = (
                X86_RUNTIME.LINUX_THREAD_IOV_ADDRESSES[slot][index].load(Ordering::SeqCst),
                length,
            );
        }
        linux_pipe_readv_ranges(descriptor, &ranges[..vector_count])
    } else if let Some(slot) = linux_socket_slot(descriptor)
        .filter(|_| linux_socket_pipe_descriptor(descriptor, LINUX_DESCRIPTOR_INPUT))
    {
        linux_socket_pipe_read_wait_result(slot, address, count)
    } else {
        linux_pipe_read(descriptor, address, count).unwrap_or(LINUX_EBADF)
    };
    if result == LINUX_ENOSYS {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    clear_linux_iov_snapshot(slot);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PIPE_READ_WAKE_COUNT
        .fetch_add(1, Ordering::SeqCst);
    true
}

/// A blocked read of up to `count` bytes (at most a page) from the pipe in
/// socket table `slot` into `address`: its result once the pipe has data or
/// no writer, and ENOSYS while the read must still wait.
fn linux_socket_pipe_read_wait_result(
    slot: crate::linux_socket::SlotId,
    address: u64,
    count: u64,
) -> u64 {
    let mut bytes = [0_u8; PAGE_SIZE];
    let length = usize::try_from(count).unwrap_or(PAGE_SIZE).min(PAGE_SIZE);
    match crate::linux_socket::recv(slot, &mut bytes[..length]) {
        Ok((received, _)) => {
            if copy_to_linux_user(address, &bytes[..received]) {
                received as u64
            } else {
                LINUX_EFAULT
            }
        }
        Err(crate::linux_socket::Error::WouldBlock | crate::linux_socket::Error::InProgress) => {
            LINUX_ENOSYS
        }
        Err(error) => linux_socket_error(error),
    }
}

pub(super) fn wake_linux_pipe_read_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_pipe_read_wait(slot));
    }
    woken
}

fn complete_linux_pipe_write_wait(slot: usize) -> bool {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_PIPE_WRITE
    {
        return false;
    }
    let packed = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let descriptor = packed & 0xff;
    let count = (packed & !LINUX_PIPE_WRITEV_WAIT_FLAG) >> 8;
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = if packed & LINUX_PIPE_WRITEV_WAIT_FLAG != 0 {
        let Ok(vector_count) = usize::try_from(count) else {
            return false;
        };
        if !(1..=LINUX_IOV_LIMIT).contains(&vector_count) {
            return false;
        }
        let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
        for (index, range) in ranges[..vector_count].iter_mut().enumerate() {
            let Ok(length) = usize::try_from(
                X86_RUNTIME.LINUX_THREAD_IOV_LENGTHS[slot][index].load(Ordering::SeqCst),
            ) else {
                return false;
            };
            *range = (
                X86_RUNTIME.LINUX_THREAD_IOV_ADDRESSES[slot][index].load(Ordering::SeqCst),
                length,
            );
        }
        linux_pipe_writev_ranges(descriptor, &ranges[..vector_count])
    } else {
        linux_pipe_write(descriptor, address, count).unwrap_or(LINUX_EBADF)
    };
    if result == LINUX_ENOSYS {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    clear_linux_iov_snapshot(slot);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PIPE_WRITE_WAKE_COUNT
        .fetch_add(1, Ordering::SeqCst);
    true
}

pub(super) fn wake_linux_pipe_write_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_pipe_write_wait(slot));
    }
    woken
}

pub(super) fn blocked_linux_pipe_writer() -> Option<LinuxThreadHandle> {
    (0..LINUX_THREAD_LIMIT).find_map(|slot| {
        (X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_BLOCKED
            && X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
                == LINUX_THREAD_WAIT_PIPE_WRITE)
            .then(|| linux_thread_handle(slot))
            .flatten()
    })
}

pub(super) fn linux_pipe(address: u64, flags: u64) -> u64 {
    let flags = u64::from(flags as u32);
    // Packet-mode (O_DIRECT) pipes are the runtime's (linux_socket_pipe).
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return linux_runtime_pipe(address, flags);
    }
    if flags & !(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    if X86_RUNTIME
        .ELF_PROBE_PIPE_READ_DESCRIPTOR
        .load(Ordering::SeqCst)
        != 0
        || X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
            .load(Ordering::SeqCst)
            != 0
    {
        return LINUX_EMFILE;
    }
    let mut descriptors = [0_u64; 2];
    let mut found = 0;
    for descriptor in 2..LINUX_AUX_DESCRIPTOR_LIMIT {
        if linux_aux_descriptor_free(descriptor) {
            descriptors[found] = descriptor;
            found += 1;
            if found == descriptors.len() {
                break;
            }
        }
    }
    if found != descriptors.len() {
        return LINUX_EMFILE;
    }
    let mut output = [0_u8; 8];
    output[..4].copy_from_slice(&(descriptors[0] as u32).to_ne_bytes());
    output[4..].copy_from_slice(&(descriptors[1] as u32).to_ne_bytes());
    if !copy_to_linux_user(address, &output) {
        return LINUX_EFAULT;
    }
    for byte in &X86_RUNTIME.ELF_PROBE_PIPE_BUFFER {
        byte.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_READ_FLAGS
        .store(flags as u32, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_WRITE_FLAGS
        .store(flags as u32, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_READ_DESCRIPTOR
        .store(descriptors[0] as u16, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
        .store(descriptors[1] as u16, Ordering::SeqCst);
    for descriptor in descriptors {
        set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    }
    0
}

pub(super) fn linux_open_named_fifo(flags: u64, handle: crate::linux_overlay::Handle) -> u64 {
    let access = flags & 3;
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    // A nonblocking open for writing finds no reader on a FIFO nobody has
    // open (ENXIO), as Linux answers (open06).
    if access == 1
        && flags & LINUX_O_NONBLOCK != 0
        && crate::linux_overlay::fifo_socket(handle)
            .is_none_or(|slot| crate::linux_socket::kind(slot).is_none())
    {
        return LINUX_ENXIO;
    }
    let slot = match crate::linux_overlay::fifo_socket(handle) {
        Some(slot) if crate::linux_socket::duplicate(slot) => slot,
        _ => match crate::linux_socket::open_loopback(1) {
            Ok(slot) if crate::linux_overlay::set_fifo_socket(handle, slot) => slot,
            Ok(slot) => {
                let _ = crate::linux_socket::close(slot);
                return LINUX_EIO;
            }
            Err(error) => return linux_socket_error(error),
        },
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Socket).store(slot + 1, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags)
        .store((flags & LINUX_O_NONBLOCK) as u32, Ordering::SeqCst);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(
        LINUX_DEVICE_SOCKET | LINUX_DEVICE_PIPE | (access + 1) as u16,
        Ordering::SeqCst,
    );
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    descriptor
}

/// vmsplice(2): writes the vectors into a pipe opened for writing, or reads
/// a pipe opened only for reading into them; SPLICE_F_NONBLOCK makes one
/// attempt (EAGAIN), and otherwise the call waits as writev or readv does.
pub(super) fn linux_vmsplice_live_return(
    output: LinuxSyscallFrameHandle,
    caller: LinuxUserContext,
    descriptor: u64,
    vectors: u64,
    count: u64,
    flags: u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let flags = u64::from(flags as u32);
    if flags & !LINUX_SPLICE_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    let writes = linux_pipe_write_descriptor(descriptor);
    if !writes && !linux_pipe_read_descriptor(descriptor) {
        return LINUX_EBADF;
    }
    if flags & LINUX_SPLICE_F_NONBLOCK == 0 {
        return if writes {
            linux_descriptor_writev_live_return(output, caller, descriptor, vectors, count)
        } else {
            linux_descriptor_readv_live_return(output, caller, descriptor, vectors, count)
        };
    }
    X86_RUNTIME
        .LINUX_SOCKET_SINGLE_ATTEMPT
        .store(true, Ordering::SeqCst);
    let result = if writes {
        linux_descriptor_writev(descriptor, vectors, count)
    } else {
        linux_descriptor_readv(descriptor, vectors, count)
    };
    X86_RUNTIME
        .LINUX_SOCKET_SINGLE_ATTEMPT
        .store(false, Ordering::SeqCst);
    if result == LINUX_EPIPE && writes {
        linux_broken_pipe_live_return(output, caller)
    } else {
        result
    }
}

const LINUX_SPLICE_F_MOVE: u64 = 1;
pub(super) const LINUX_SPLICE_F_NONBLOCK: u64 = 2;
const LINUX_SPLICE_F_MORE: u64 = 4;
const LINUX_SPLICE_F_GIFT: u64 = 8;
const LINUX_SPLICE_FLAGS: u64 =
    LINUX_SPLICE_F_MOVE | LINUX_SPLICE_F_NONBLOCK | LINUX_SPLICE_F_MORE | LINUX_SPLICE_F_GIFT;

/// What one side of splice(2) or tee(2) is; only these move data.
#[derive(Clone, Copy)]
enum LinuxSpliceEnd {
    Pipe(crate::linux_socket::SlotId),
    Socket(crate::linux_socket::SlotId),
    File,
    Other,
}

impl LinuxSpliceEnd {
    fn of(descriptor: u64) -> Self {
        let state = linux_device_descriptor(descriptor);
        // An io_uring is kept as a scratch file but is none to splice.
        if linux_io_uring_descriptor(descriptor) {
            return Self::Other;
        }
        match linux_socket_slot(descriptor) {
            Some(slot) if state & LINUX_DEVICE_PIPE != 0 => Self::Pipe(slot),
            // A kernel object shared like a socket (an io_uring, a DRM
            // file) is no socket: splice refuses it at once rather than
            // waiting on the pipe (splice07 hung on pipe -> io_uring).
            Some(slot)
                if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Object) =>
            {
                Self::Other
            }
            Some(slot) => Self::Socket(slot),
            // /dev/zero, /dev/full and /dev/urandom read as files do, so
            // they can be spliced into a pipe (splice08).
            None if linux_overlay_descriptor_handle(descriptor).is_some()
                || linux_rootfs_descriptor(descriptor) != 0
                || linux_tmp_descriptor_handle(descriptor, state).is_some()
                || linux_proc_sysctl_index(state).is_some()
                || state & LINUX_DEVICE_ZERO != 0 && state & LINUX_DEVICE_DIRECTORY == 0 =>
            {
                Self::File
            }
            None => Self::Other,
        }
    }
}

/// How a splice(2) or tee(2) step ended: with the call's result, or unable
/// to start because the pipe or socket it reads is empty, or the one it
/// fills is full.
enum LinuxSpliceStep {
    Done(u64),
    Blocked,
}

/// A step that cannot go on: blocked if nothing moved yet, and otherwise
/// done with what moved.
fn linux_splice_blocked(moved: usize) -> LinuxSpliceStep {
    if moved == 0 {
        LinuxSpliceStep::Blocked
    } else {
        LinuxSpliceStep::Done(moved as u64)
    }
}

/// A step that ended after `moved` bytes, with `failure` if it stopped on an
/// error: the bytes already moved are the result, as with a short write.
fn linux_splice_moved(moved: usize, failure: Option<u64>) -> LinuxSpliceStep {
    LinuxSpliceStep::Done(match failure {
        Some(error) if moved == 0 => error,
        _ => moved as u64,
    })
}

/// The system call's result for `step`. A blocked call fails with EAGAIN
/// when nonblocking; otherwise the rest of the domain runs and the call
/// starts again, as a blocking pipe read does. Filling a pipe or socket with
/// no reader raises SIGPIPE.
fn linux_splice_live_return(
    output: LinuxSyscallFrameHandle,
    caller: LinuxUserContext,
    number: u64,
    nonblocking: bool,
    step: LinuxSpliceStep,
) -> u64 {
    match step {
        LinuxSpliceStep::Done(LINUX_EPIPE) => linux_broken_pipe_live_return(output, caller),
        LinuxSpliceStep::Done(result) => result,
        LinuxSpliceStep::Blocked
            if nonblocking || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire) =>
        {
            LINUX_EAGAIN
        }
        LinuxSpliceStep::Blocked => {
            linux_retry_later_live_return(output, caller, number, WaitOn::ANYTHING)
        }
    }
}

/// splice(2) and tee(2) need `source` open for reading and `sink` for
/// writing (EBADF), checked before what kind of files they are.
fn linux_splice_access(source: u64, sink: u64) -> Result<(), u64> {
    if !linux_descriptor_open(source)
        || !linux_descriptor_open(sink)
        || !matches!(
            linux_device_descriptor(source) & 3,
            LINUX_DESCRIPTOR_INPUT | 3
        )
        || !matches!(
            linux_device_descriptor(sink) & 3,
            LINUX_DESCRIPTOR_OUTPUT | 3
        )
    {
        return Err(LINUX_EBADF);
    }
    Ok(())
}

/// Whether a splice(2) or tee(2) between `ends` waits: not with
/// SPLICE_F_NONBLOCK or a pipe or socket end opened O_NONBLOCK.
fn linux_splice_nonblocking(flags: u64, ends: [(u64, LinuxSpliceEnd); 2]) -> bool {
    flags & LINUX_SPLICE_F_NONBLOCK != 0
        || ends.iter().any(|(descriptor, end)| {
            matches!(end, LinuxSpliceEnd::Pipe(_) | LinuxSpliceEnd::Socket(_))
                && linux_socket_nonblocking(*descriptor)
        })
}

/// splice(2): moves up to `length` bytes between `source` and `sink`, one
/// of which is a pipe; the other may be a pipe, a socket or a regular file,
/// whose offset is the pointed-to value if given (left as it was in the
/// file) or else the file position.
pub(super) fn linux_splice(
    output: LinuxSyscallFrameHandle,
    caller: LinuxUserContext,
    (source, source_offset): (u64, u64),
    (sink, sink_offset): (u64, u64),
    length: u64,
    flags: u64,
) -> u64 {
    let source = u64::from(source as u32);
    let sink = u64::from(sink as u32);
    let flags = u64::from(flags as u32);
    if length == 0 {
        return 0;
    }
    if flags & !LINUX_SPLICE_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    if let Err(error) = linux_splice_access(source, sink) {
        return error;
    }
    let (from, to) = (LinuxSpliceEnd::of(source), LinuxSpliceEnd::of(sink));
    let nonblocking = linux_splice_nonblocking(flags, [(source, from), (sink, to)]);
    let step = match (from, to) {
        (LinuxSpliceEnd::Pipe(from), LinuxSpliceEnd::Pipe(to)) => {
            if source_offset != 0 || sink_offset != 0 {
                return LINUX_ESPIPE;
            }
            if crate::linux_socket::same_pipe(from, to) {
                return LINUX_EINVAL;
            }
            linux_splice_between_pipes(from, to, length, true)
        }
        (LinuxSpliceEnd::Pipe(from), to) => {
            if source_offset != 0 {
                return LINUX_ESPIPE;
            }
            linux_splice_from_pipe(from, (sink, sink_offset), to, length)
        }
        (from, LinuxSpliceEnd::Pipe(to)) => {
            if sink_offset != 0 {
                return LINUX_ESPIPE;
            }
            linux_splice_to_pipe((source, source_offset), from, to, length)
        }
        _ => return LINUX_EINVAL,
    };
    linux_splice_live_return(output, caller, LINUX_SPLICE_SYSCALL, nonblocking, step)
}

/// tee(2): copies up to `length` bytes from one pipe to another without
/// consuming them.
pub(super) fn linux_tee(
    output: LinuxSyscallFrameHandle,
    caller: LinuxUserContext,
    source: u64,
    sink: u64,
    length: u64,
    flags: u64,
) -> u64 {
    let source = u64::from(source as u32);
    let sink = u64::from(sink as u32);
    let flags = u64::from(flags as u32);
    if flags & !LINUX_SPLICE_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    if length == 0 {
        return 0;
    }
    if let Err(error) = linux_splice_access(source, sink) {
        return error;
    }
    let (from, to) = (LinuxSpliceEnd::of(source), LinuxSpliceEnd::of(sink));
    let (LinuxSpliceEnd::Pipe(from_slot), LinuxSpliceEnd::Pipe(to_slot)) = (from, to) else {
        return LINUX_EINVAL;
    };
    if crate::linux_socket::same_pipe(from_slot, to_slot) {
        return LINUX_EINVAL;
    }
    let nonblocking = linux_splice_nonblocking(flags, [(source, from), (sink, to)]);
    let step = linux_splice_between_pipes(from_slot, to_slot, length, false);
    linux_splice_live_return(output, caller, LINUX_TEE_SYSCALL, nonblocking, step)
}

/// Moves (or, for tee, copies: `consume` false) bytes from one pipe to
/// another, as many as are queued and fit, up to `length`.
fn linux_splice_between_pipes(
    from: crate::linux_socket::SlotId,
    to: crate::linux_socket::SlotId,
    length: u64,
    consume: bool,
) -> LinuxSpliceStep {
    let requested = usize::try_from(length).unwrap_or(usize::MAX);
    let mut buffer = [0_u8; PAGE_SIZE];
    let mut moved = 0_usize;
    while moved < requested {
        let Some(room) = crate::linux_socket::pipe_room(to) else {
            return linux_splice_moved(moved, Some(LINUX_EPIPE));
        };
        let chunk = (requested - moved).min(buffer.len()).min(room);
        if chunk == 0 {
            return linux_splice_blocked(moved);
        }
        let available = match crate::linux_socket::peek_local(from, &mut buffer[..chunk]) {
            Ok(0) => break,
            Ok(available) => available,
            Err(crate::linux_socket::Error::WouldBlock) => return linux_splice_blocked(moved),
            Err(error) => return linux_splice_moved(moved, Some(linux_socket_error(error))),
        };
        let sent = match crate::linux_socket::send(to, &buffer[..available], None) {
            Ok(sent) => sent,
            Err(crate::linux_socket::Error::WouldBlock) => return linux_splice_blocked(moved),
            Err(error) => return linux_splice_moved(moved, Some(linux_socket_error(error))),
        };
        if consume
            && !matches!(
                crate::linux_socket::recv(from, &mut buffer[..sent]),
                Ok((received, _)) if received == sent
            )
        {
            return linux_splice_moved(moved, Some(LINUX_EIO));
        }
        moved += sent;
        // tee copies what the pipe holds once: another pass would see the
        // same bytes again.
        if !consume || sent < available {
            break;
        }
    }
    LinuxSpliceStep::Done(moved as u64)
}

/// Moves bytes from pipe `from` into a socket or regular file `sink`.
/// Whether `descriptor` is /dev/null or /dev/zero (`Some(false)`), which
/// take and drop what is written, or /dev/full (`Some(true)`), which takes
/// nothing (ENOSPC).
fn linux_discard_sink(descriptor: u64) -> Option<bool> {
    let state = linux_device_descriptor(descriptor);
    if !linux_descriptor_open(descriptor)
        || linux_console_descriptor(descriptor) != 0
        || linux_socket_slot(descriptor).is_some()
        || linux_overlay_descriptor_handle(descriptor).is_some()
        || linux_rootfs_descriptor(descriptor) != 0
        || linux_tmp_descriptor_handle(descriptor, state).is_some()
        || linux_io_uring_descriptor(descriptor)
        || linux_graphics_device(state).is_some()
        || state & (LINUX_FILE_MASK | LINUX_DEVICE_DIRECTORY | LINUX_DEVICE_CONSOLE) != 0
    {
        return None;
    }
    match state & !3 {
        0 | LINUX_DEVICE_ZERO => Some(false),
        LINUX_DEVICE_FULL => Some(true),
        _ => None,
    }
}

fn linux_splice_from_pipe(
    from: crate::linux_socket::SlotId,
    (sink, sink_offset): (u64, u64),
    to: LinuxSpliceEnd,
    length: u64,
) -> LinuxSpliceStep {
    // Into /dev/null or /dev/zero the bytes are taken from the pipe and
    // dropped, as writing them would; /dev/full takes none (splice09).
    if let Some(full) = linux_discard_sink(sink) {
        if full {
            return LinuxSpliceStep::Done(LINUX_ENOSPC);
        }
        let requested = usize::try_from(length).unwrap_or(usize::MAX);
        let mut buffer = [0_u8; PAGE_SIZE];
        let mut moved = 0_usize;
        while moved < requested {
            let chunk = (requested - moved).min(buffer.len());
            match crate::linux_socket::recv(from, &mut buffer[..chunk]) {
                Ok((0, _)) => break,
                Ok((received, _)) => moved += received,
                Err(crate::linux_socket::Error::WouldBlock) if moved == 0 => {
                    return LinuxSpliceStep::Blocked;
                }
                Err(crate::linux_socket::Error::WouldBlock) => break,
                Err(error) => return linux_splice_moved(moved, Some(linux_socket_error(error))),
            }
        }
        return linux_splice_moved(moved, None);
    }
    let (mut offset, explicit) = match to {
        LinuxSpliceEnd::File => {
            if linux_socket_flags(sink).is_some_and(|flags| flags & LINUX_O_APPEND as u32 != 0) {
                return LinuxSpliceStep::Done(LINUX_EINVAL);
            }
            match linux_file_range_offset(sink_offset, sink) {
                Ok(offset) => offset,
                Err(error) => return LinuxSpliceStep::Done(error),
            }
        }
        LinuxSpliceEnd::Socket(_) if sink_offset == 0 => (0, false),
        _ => return LinuxSpliceStep::Done(LINUX_EINVAL),
    };
    let requested = usize::try_from(length).unwrap_or(usize::MAX);
    let mut buffer = [0_u8; PAGE_SIZE];
    let mut moved = 0_usize;
    let mut failure = None;
    while moved < requested {
        let chunk = (requested - moved).min(buffer.len());
        let available = match crate::linux_socket::peek_local(from, &mut buffer[..chunk]) {
            Ok(0) => break,
            Ok(available) => available,
            Err(crate::linux_socket::Error::WouldBlock) if moved == 0 => {
                return LinuxSpliceStep::Blocked;
            }
            Err(crate::linux_socket::Error::WouldBlock) => break,
            Err(error) => {
                failure = Some(linux_socket_error(error));
                break;
            }
        };
        let written = match to {
            LinuxSpliceEnd::Socket(slot) => {
                match crate::linux_socket::send(slot, &buffer[..available], None) {
                    Ok(written) => written,
                    Err(crate::linux_socket::Error::WouldBlock) if moved == 0 => {
                        return LinuxSpliceStep::Blocked;
                    }
                    Err(crate::linux_socket::Error::WouldBlock) => break,
                    Err(error) => {
                        failure = Some(linux_socket_error(error));
                        break;
                    }
                }
            }
            _ => match linux_regular_file_write_kernel(sink, offset, &buffer[..available]) {
                Ok(written) => written,
                Err(error) => {
                    failure = Some(if error == LINUX_EISDIR {
                        LINUX_EINVAL
                    } else {
                        error
                    });
                    break;
                }
            },
        };
        if written == 0 {
            break;
        }
        if !matches!(
            crate::linux_socket::recv(from, &mut buffer[..written]),
            Ok((received, _)) if received == written
        ) {
            failure = Some(LINUX_EIO);
            break;
        }
        offset = offset.saturating_add(written);
        moved += written;
        if written < available {
            break;
        }
    }
    if matches!(to, LinuxSpliceEnd::File)
        && linux_commit_file_range_offset(sink_offset, sink, explicit, offset).is_err()
    {
        failure = Some(LINUX_EFAULT);
    }
    linux_splice_moved(moved, failure)
}

/// Moves bytes from a socket or regular file `source` into pipe `to`, no
/// more than fit, so nothing read is lost.
fn linux_splice_to_pipe(
    (source, source_offset): (u64, u64),
    from: LinuxSpliceEnd,
    to: crate::linux_socket::SlotId,
    length: u64,
) -> LinuxSpliceStep {
    let (mut offset, explicit) = match from {
        LinuxSpliceEnd::File => match linux_file_range_offset(source_offset, source) {
            Ok(offset) => offset,
            Err(error) => return LinuxSpliceStep::Done(error),
        },
        LinuxSpliceEnd::Socket(slot)
            if source_offset == 0 && !crate::linux_socket::unix_stream_unconnected(slot) =>
        {
            (0, false)
        }
        _ => return LinuxSpliceStep::Done(LINUX_EINVAL),
    };
    let requested = usize::try_from(length).unwrap_or(usize::MAX);
    let mut buffer = [0_u8; PAGE_SIZE];
    let mut moved = 0_usize;
    let mut failure = None;
    while moved < requested {
        let Some(room) = crate::linux_socket::pipe_room(to) else {
            failure = Some(LINUX_EPIPE);
            break;
        };
        let chunk = (requested - moved).min(buffer.len()).min(room);
        if chunk == 0 {
            if moved == 0 {
                return LinuxSpliceStep::Blocked;
            }
            break;
        }
        let read = match from {
            LinuxSpliceEnd::Socket(slot) => {
                match crate::linux_socket::recv(slot, &mut buffer[..chunk]) {
                    Ok((read, _)) => read,
                    Err(crate::linux_socket::Error::WouldBlock) if moved == 0 => {
                        return LinuxSpliceStep::Blocked;
                    }
                    Err(crate::linux_socket::Error::WouldBlock) => break,
                    Err(error) => {
                        failure = Some(linux_socket_error(error));
                        break;
                    }
                }
            }
            // A directory has nothing to splice (EINVAL), as in Linux.
            _ => match linux_regular_file_read_kernel(source, offset, &mut buffer[..chunk]) {
                Ok(read) => read,
                Err(error) => {
                    failure = Some(if error == LINUX_EISDIR {
                        LINUX_EINVAL
                    } else {
                        error
                    });
                    break;
                }
            },
        };
        if read == 0 {
            break;
        }
        let sent = match crate::linux_socket::send(to, &buffer[..read], None) {
            Ok(sent) => sent,
            Err(error) => {
                failure = Some(linux_socket_error(error));
                break;
            }
        };
        offset = offset.saturating_add(sent);
        moved += sent;
        if sent < read {
            break;
        }
    }
    if matches!(from, LinuxSpliceEnd::File)
        && linux_commit_file_range_offset(source_offset, source, explicit, offset).is_err()
    {
        failure = Some(LINUX_EFAULT);
    }
    linux_splice_moved(moved, failure)
}

fn linux_runtime_pipe(address: u64, flags: u64) -> u64 {
    linux_socket_pipe(
        address,
        flags,
        LINUX_AUX_DESCRIPTOR_FIRST,
        copy_to_linux_user,
    )
}

pub(super) fn linux_socket_pipe(
    address: u64,
    flags: u64,
    first_descriptor: u64,
    copy: impl FnOnce(u64, &[u8]) -> bool,
) -> u64 {
    if flags & !(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC | LINUX_O_DIRECT) != 0 {
        return LINUX_EINVAL;
    }
    let Some(descriptors) = linux_free_descriptors::<2>(first_descriptor) else {
        return LINUX_EMFILE;
    };
    // A packet-mode (O_DIRECT) pipe keeps each write as one packet, which a
    // read returns on its own: a sequenced-packet pair, where a plain pipe
    // is a byte stream.
    let socket_type = if flags & LINUX_O_DIRECT != 0 { 5 } else { 1 };
    let (reader, writer) = match crate::linux_socket::open_pair(socket_type) {
        Ok(pair) => pair,
        Err(error) => return linux_socket_error(error),
    };
    // An unprivileged process gets no pipe larger than pipe-max-size: Linux
    // caps the default capacity, not only F_SETPIPE_SZ requests.
    if !current_linux_credentials().is_some_and(|value| value.user.effective == 0) {
        let limit = linux_pipe_max_size() as usize;
        if crate::linux_socket::local_capacity(reader).is_ok_and(|capacity| capacity > limit) {
            let _ = crate::linux_socket::set_local_capacity(reader, limit);
        }
    }
    let mut output = [0_u8; 8];
    output[..4].copy_from_slice(&(descriptors[0] as u32).to_ne_bytes());
    output[4..].copy_from_slice(&(descriptors[1] as u32).to_ne_bytes());
    if !copy(address, &output) {
        let _ = crate::linux_socket::close(reader);
        let _ = crate::linux_socket::close(writer);
        return LINUX_EFAULT;
    }
    let ends = [
        (descriptors[0], reader, LINUX_DESCRIPTOR_INPUT),
        (descriptors[1], writer, LINUX_DESCRIPTOR_OUTPUT),
    ];
    let installed = ends.map(|(descriptor, slot, access)| {
        install_linux_socket_descriptor(
            descriptor,
            slot,
            LINUX_DEVICE_SOCKET | LINUX_DEVICE_PIPE | access,
            (flags & (LINUX_O_NONBLOCK | LINUX_O_DIRECT)) as u32,
            flags & LINUX_O_CLOEXEC != 0,
        )
    });
    if installed.contains(&false) {
        // Out of memory for the table above the fixed one: neither end
        // stays open (closing an installed end closes its socket).
        for ((descriptor, slot, _), installed) in ends.into_iter().zip(installed) {
            if installed {
                let _ = linux_descriptor_close(descriptor);
            } else {
                let _ = crate::linux_socket::close(slot);
            }
        }
        return LINUX_ENOMEM;
    }
    0
}

pub(super) fn linux_pipe_read(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    if !linux_pipe_read_descriptor(descriptor) {
        return None;
    }
    if count == 0 {
        return Some(0);
    }
    let length = X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst) as usize;
    if length == 0 {
        if X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
            .load(Ordering::SeqCst)
            == 0
        {
            return Some(0);
        }
        return Some(
            if X86_RUNTIME.ELF_PROBE_PIPE_READ_FLAGS.load(Ordering::SeqCst)
                & LINUX_O_NONBLOCK as u32
                != 0
            {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    }
    let requested = usize::try_from(count).unwrap_or(usize::MAX);
    let returned = length.min(requested);
    let mut output = [0_u8; LINUX_PIPE_CAPACITY];
    for (target, source) in output[..returned]
        .iter_mut()
        .zip(&X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[..returned])
    {
        *target = source.load(Ordering::SeqCst);
    }
    if !copy_to_linux_user(address, &output[..returned]) {
        return Some(LINUX_EFAULT);
    }
    for index in 0..length - returned {
        let value = X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[index + returned].load(Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[index].store(value, Ordering::SeqCst);
    }
    for byte in &X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[length - returned..length] {
        byte.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_PIPE_LENGTH
        .store((length - returned) as u32, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    Some(returned as u64)
}

pub(super) fn linux_pipe_write(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    if !linux_pipe_write_descriptor(descriptor) {
        return None;
    }
    if count == 0 {
        return Some(0);
    }
    if X86_RUNTIME
        .ELF_PROBE_PIPE_READ_DESCRIPTOR
        .load(Ordering::SeqCst)
        == 0
    {
        return Some(LINUX_EPIPE);
    }
    let Ok(requested) = usize::try_from(count) else {
        return Some(LINUX_EINVAL);
    };
    if requested > LINUX_PIPE_CAPACITY {
        return Some(LINUX_EINVAL);
    }
    let length = X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst) as usize;
    if requested > LINUX_PIPE_CAPACITY - length {
        return Some(
            if X86_RUNTIME
                .ELF_PROBE_PIPE_WRITE_FLAGS
                .load(Ordering::SeqCst)
                & LINUX_O_NONBLOCK as u32
                != 0
            {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    }
    let mut input = [0_u8; LINUX_PIPE_CAPACITY];
    if !copy_from_linux_user(address, &mut input[..requested]) {
        return Some(LINUX_EFAULT);
    }
    for (target, source) in X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[length..length + requested]
        .iter()
        .zip(&input[..requested])
    {
        target.store(*source, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_PIPE_LENGTH
        .store((length + requested) as u32, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    Some(count)
}

pub(super) fn linux_pipe_writev(descriptor: u64, vectors: u64, count: u64) -> Option<u64> {
    if !linux_pipe_write_descriptor(descriptor) {
        return None;
    }
    let (ranges, vector_count) = match linux_writev_ranges(vectors, count) {
        Ok(snapshot) => snapshot,
        Err(error) => return Some(error),
    };
    Some(linux_pipe_writev_ranges(
        descriptor,
        &ranges[..vector_count],
    ))
}

pub(super) fn linux_writev_ranges(
    vectors: u64,
    count: u64,
) -> Result<([(u64, usize); LINUX_IOV_LIMIT], usize), u64> {
    let Ok(vector_count) = usize::try_from(count) else {
        return Err(LINUX_EINVAL);
    };
    if vector_count > LINUX_IOV_LIMIT {
        return Err(LINUX_EINVAL);
    }
    let mut table = [0_u8; LINUX_IOV_LIMIT * 16];
    if !copy_from_linux_user(vectors, &mut table[..vector_count * 16]) {
        return Err(LINUX_EFAULT);
    }
    let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
    let mut total = 0_usize;
    for (index, vector) in table[..vector_count * 16]
        .as_chunks::<16>()
        .0
        .iter()
        .enumerate()
    {
        let address = u64::from_ne_bytes(vector[..8].try_into().unwrap());
        let length = u64::from_ne_bytes(vector[8..].try_into().unwrap());
        let Ok(length) = usize::try_from(length) else {
            return Err(LINUX_EINVAL);
        };
        let Some(end) = total.checked_add(length) else {
            return Err(LINUX_EINVAL);
        };
        if end > LINUX_PIPE_CAPACITY {
            return Err(LINUX_EINVAL);
        }
        if length != 0 && !linux_readable_user_range_contains(address, length) {
            return Err(LINUX_EFAULT);
        }
        ranges[index] = (address, length);
        total = end;
    }
    Ok((ranges, vector_count))
}

fn linux_pipe_writev_ranges(descriptor: u64, ranges: &[(u64, usize)]) -> u64 {
    if !linux_pipe_write_descriptor(descriptor) {
        return LINUX_EBADF;
    }
    if X86_RUNTIME
        .ELF_PROBE_PIPE_READ_DESCRIPTOR
        .load(Ordering::SeqCst)
        == 0
    {
        return LINUX_EPIPE;
    }
    let mut total = 0_usize;
    for (_, length) in ranges.iter().copied() {
        let Some(end) = total.checked_add(length) else {
            return LINUX_EINVAL;
        };
        if length == 0 || end > LINUX_PIPE_CAPACITY {
            return LINUX_EINVAL;
        }
        total = end;
    }
    let current = X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst) as usize;
    if total > LINUX_PIPE_CAPACITY - current {
        return if X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_FLAGS
            .load(Ordering::SeqCst)
            & LINUX_O_NONBLOCK as u32
            != 0
        {
            LINUX_EAGAIN
        } else {
            LINUX_ENOSYS
        };
    }
    let mut input = [0_u8; LINUX_PIPE_CAPACITY];
    let mut copied = 0;
    for (address, length) in ranges.iter().copied() {
        if !copy_from_linux_user(address, &mut input[copied..copied + length]) {
            return LINUX_EFAULT;
        }
        copied += length;
    }
    for (target, source) in X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[current..current + total]
        .iter()
        .zip(&input[..total])
    {
        target.store(*source, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_PIPE_LENGTH
        .store((current + total) as u32, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    total as u64
}

pub(super) fn linux_pipe_readv(descriptor: u64, vectors: u64, count: u64) -> Option<u64> {
    if !linux_pipe_read_descriptor(descriptor) {
        return None;
    }
    let (ranges, vector_count) = match linux_readv_ranges(vectors, count) {
        Ok(snapshot) => snapshot,
        Err(error) => return Some(error),
    };
    Some(linux_pipe_readv_ranges(descriptor, &ranges[..vector_count]))
}

pub(super) fn linux_readv_ranges(
    vectors: u64,
    count: u64,
) -> Result<([(u64, usize); LINUX_IOV_LIMIT], usize), u64> {
    let Ok(vector_count) = usize::try_from(count) else {
        return Err(LINUX_EINVAL);
    };
    if vector_count > LINUX_IOV_LIMIT {
        return Err(LINUX_EINVAL);
    }
    let mut table = [0_u8; LINUX_IOV_LIMIT * 16];
    if !copy_from_linux_user(vectors, &mut table[..vector_count * 16]) {
        return Err(LINUX_EFAULT);
    }
    let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
    let mut capacity = 0_usize;
    for (index, vector) in table[..vector_count * 16]
        .as_chunks::<16>()
        .0
        .iter()
        .enumerate()
    {
        let address = u64::from_ne_bytes(vector[..8].try_into().unwrap());
        let length = u64::from_ne_bytes(vector[8..].try_into().unwrap());
        let Ok(length) = usize::try_from(length) else {
            return Err(LINUX_EINVAL);
        };
        let Some(end) = capacity.checked_add(length) else {
            return Err(LINUX_EINVAL);
        };
        if length == 0 || end > LINUX_PIPE_CAPACITY {
            return Err(LINUX_EINVAL);
        }
        if !linux_writable_user_range_contains(address, length) {
            return Err(LINUX_EFAULT);
        }
        ranges[index] = (address, length);
        capacity = end;
    }
    Ok((ranges, vector_count))
}

fn linux_pipe_readv_ranges(descriptor: u64, ranges: &[(u64, usize)]) -> u64 {
    if !linux_pipe_read_descriptor(descriptor) || ranges.is_empty() {
        return LINUX_EBADF;
    }
    let mut capacity = 0_usize;
    for (address, range_length) in ranges.iter().copied() {
        let Some(end) = capacity.checked_add(range_length) else {
            return LINUX_EINVAL;
        };
        if range_length == 0
            || end > LINUX_PIPE_CAPACITY
            || !linux_writable_user_range_contains(address, range_length)
        {
            return if range_length == 0 || end > LINUX_PIPE_CAPACITY {
                LINUX_EINVAL
            } else {
                LINUX_EFAULT
            };
        }
        capacity = end;
    }
    let length = X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst) as usize;
    if length == 0 {
        if X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
            .load(Ordering::SeqCst)
            == 0
        {
            return 0;
        }
        return if X86_RUNTIME.ELF_PROBE_PIPE_READ_FLAGS.load(Ordering::SeqCst)
            & LINUX_O_NONBLOCK as u32
            != 0
        {
            LINUX_EAGAIN
        } else {
            LINUX_ENOSYS
        };
    }
    let returned = length.min(capacity);
    let mut output = [0_u8; LINUX_PIPE_CAPACITY];
    for (target, source) in output[..returned]
        .iter_mut()
        .zip(&X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[..returned])
    {
        *target = source.load(Ordering::SeqCst);
    }
    let mut copied = 0;
    for (address, range_length) in ranges.iter().copied() {
        let amount = range_length.min(returned - copied);
        if amount == 0 {
            break;
        }
        if !copy_to_linux_user(address, &output[copied..copied + amount]) {
            return LINUX_EFAULT;
        }
        copied += amount;
    }
    for index in 0..length - returned {
        let value = X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[index + returned].load(Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[index].store(value, Ordering::SeqCst);
    }
    for byte in &X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[length - returned..length] {
        byte.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_PIPE_LENGTH
        .store((length - returned) as u32, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    returned as u64
}

pub(super) fn linux_pipe_read_descriptor(descriptor: u64) -> bool {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return linux_socket_pipe_descriptor(descriptor, LINUX_DESCRIPTOR_INPUT);
    }
    descriptor >= 2
        && u64::from(
            X86_RUNTIME
                .ELF_PROBE_PIPE_READ_DESCRIPTOR
                .load(Ordering::SeqCst),
        ) == descriptor
}

pub(super) fn linux_pipe_write_descriptor(descriptor: u64) -> bool {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return linux_socket_pipe_descriptor(descriptor, LINUX_DESCRIPTOR_OUTPUT);
    }
    descriptor >= 2
        && u64::from(
            X86_RUNTIME
                .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
                .load(Ordering::SeqCst),
        ) == descriptor
}

pub(super) fn linux_pipe_descriptor(descriptor: u64) -> bool {
    linux_pipe_read_descriptor(descriptor) || linux_pipe_write_descriptor(descriptor)
}
