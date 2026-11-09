use super::*;

fn linux_aio_error(error: crate::linux_aio::Error) -> u64 {
    match error {
        crate::linux_aio::Error::Invalid => LINUX_EINVAL,
        crate::linux_aio::Error::NoMemory => LINUX_ENOMEM,
        crate::linux_aio::Error::Full => LINUX_EAGAIN,
    }
}

pub(super) fn linux_io_setup(events: u64, output: u64) -> u64 {
    // nr_events is a 32-bit unsigned count: zero and counts whose event ring
    // would pass 256 MiB are invalid, and more than aio-max-nr is EAGAIN.
    const LINUX_AIO_EVENTS_LIMIT: u64 = 0x1000_0000 / 32;
    let events = u64::from(events as u32);
    if events == 0
        || events > LINUX_AIO_EVENTS_LIMIT
        || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
    {
        return LINUX_EINVAL;
    }
    if events > LINUX_AIO_MAX_NR {
        return LINUX_EAGAIN;
    }
    let mut old = [0_u8; 8];
    if !copy_from_linux_user(output, &mut old) {
        return LINUX_EFAULT;
    }
    if u64::from_ne_bytes(old) != 0 {
        return LINUX_EINVAL;
    }
    let Some(bytes) = events
        .checked_mul(32)
        .and_then(|bytes| bytes.checked_add(32))
    else {
        return LINUX_EINVAL;
    };
    let pages = bytes.div_ceil(PAGE_SIZE as u64);
    let mapping = linux_runtime_mmap(
        0,
        pages * PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if mapping >= LINUX_RETURN_TO_KERNEL {
        return mapping;
    }
    if let Err(error) =
        crate::linux_aio::create(current_linux_process_pid(), mapping, events, pages)
    {
        let _ = linux_runtime_munmap(mapping, pages * PAGE_SIZE as u64);
        return linux_aio_error(error);
    }
    let mut header = [0_u8; 32];
    header[..4].copy_from_slice(&(mapping as u32).to_ne_bytes());
    header[4..8].copy_from_slice(&(events as u32).to_ne_bytes());
    header[16..20].copy_from_slice(&0xa10a_10a1_u32.to_ne_bytes());
    header[28..32].copy_from_slice(&32_u32.to_ne_bytes());
    if !copy_to_linux_user(mapping, &header) || !copy_to_linux_user(output, &mapping.to_ne_bytes())
    {
        let _ = crate::linux_aio::destroy(current_linux_process_pid(), mapping);
        let _ = linux_runtime_munmap(mapping, pages * PAGE_SIZE as u64);
        return LINUX_EFAULT;
    }
    0
}

pub(super) fn linux_io_destroy(context: u64) -> u64 {
    let pages = match crate::linux_aio::destroy(current_linux_process_pid(), context) {
        Ok(pages) => pages,
        Err(error) => return linux_aio_error(error),
    };
    linux_runtime_munmap(context, pages * PAGE_SIZE as u64)
}

pub(super) fn linux_io_submit(context: u64, count: u64, pointers: u64) -> u64 {
    // As Linux: an unknown context, then a negative count, are EINVAL; a
    // count past the context's size submits what fits.
    if crate::linux_aio::info(current_linux_process_pid(), context).is_err() {
        return LINUX_EINVAL;
    }
    if (count as i64) < 0 {
        return LINUX_EINVAL;
    }
    let count = count.min(1024);
    let mut submitted = 0_u64;
    for index in 0..count {
        match crate::linux_aio::can_submit(current_linux_process_pid(), context) {
            Ok(true) => {}
            Ok(false) => {
                return if submitted == 0 {
                    LINUX_EAGAIN
                } else {
                    submitted
                }
            }
            Err(error) => {
                return if submitted == 0 {
                    linux_aio_error(error)
                } else {
                    submitted
                }
            }
        }
        let Some(pointer_address) = pointers.checked_add(index * 8) else {
            return if submitted == 0 {
                LINUX_EFAULT
            } else {
                submitted
            };
        };
        let mut pointer = [0_u8; 8];
        if !copy_from_linux_user(pointer_address, &mut pointer) {
            return if submitted == 0 {
                LINUX_EFAULT
            } else {
                submitted
            };
        }
        let object = u64::from_ne_bytes(pointer);
        let mut control = [0_u8; 64];
        if !copy_from_linux_user(object, &mut control) {
            return if submitted == 0 {
                LINUX_EFAULT
            } else {
                submitted
            };
        }
        let data = u64::from_ne_bytes(control[..8].try_into().unwrap());
        let opcode = u16::from_ne_bytes(control[16..18].try_into().unwrap());
        let descriptor = u32::from_ne_bytes(control[20..24].try_into().unwrap()) as u64;
        let buffer = u64::from_ne_bytes(control[24..32].try_into().unwrap());
        let length = u64::from_ne_bytes(control[32..40].try_into().unwrap());
        let offset = i64::from_ne_bytes(control[40..48].try_into().unwrap());
        let reserved = u64::from_ne_bytes(control[48..56].try_into().unwrap());
        // A request is checked as it is submitted, as Linux's io_submit_one:
        // its reserved field, its descriptor (EBADF), and that the
        // descriptor was opened for the transfer's direction (EBADF).
        let state = linux_device_descriptor(descriptor);
        let refusal = if reserved != 0 || offset < 0 {
            Some(LINUX_EINVAL)
        } else if !linux_descriptor_open(descriptor)
            || opcode == 0 && state & LINUX_DESCRIPTOR_INPUT == 0 && state & 3 != 0
            || opcode == 1 && state & LINUX_DESCRIPTOR_OUTPUT == 0 && state & 3 != 0
        {
            Some(LINUX_EBADF)
        } else {
            None
        };
        if let Some(error) = refusal {
            return if submitted == 0 { error } else { submitted };
        }
        let stream = linux_pipe_descriptor(descriptor) || linux_socket_slot(descriptor).is_some();
        let result = match opcode {
            // A pipe or socket has no offset to read at: the read takes what
            // is there now, EAGAIN when nothing is (io_submit04).
            0 if stream => linux_aio_stream_read(descriptor, buffer, length),
            0 => linux_regular_file_read_at(descriptor, buffer, length, offset as u64),
            1 => linux_regular_file_write_at(descriptor, buffer, length, offset as u64),
            2 | 3 => {
                if linux_descriptor_open(descriptor) {
                    0
                } else {
                    LINUX_EBADF
                }
            }
            _ => {
                return if submitted == 0 {
                    LINUX_EINVAL
                } else {
                    submitted
                }
            }
        };
        let event = crate::linux_aio::Event {
            data,
            object,
            result: result as i64,
            result2: 0,
        };
        if let Err(error) = crate::linux_aio::push(current_linux_process_pid(), context, event) {
            return if submitted == 0 {
                linux_aio_error(error)
            } else {
                submitted
            };
        }
        // IOCB_FLAG_RESFD: the completion also signals the eventfd named.
        const IOCB_FLAG_RESFD: u32 = 1;
        if u32::from_ne_bytes(control[56..60].try_into().unwrap()) & IOCB_FLAG_RESFD != 0 {
            linux_eventfd_signal(u64::from(u32::from_ne_bytes(
                control[60..64].try_into().unwrap(),
            )));
        }
        submitted += 1;
    }
    submitted
}

pub(super) fn linux_io_getevents(
    context: u64,
    minimum: u64,
    maximum: u64,
    output: u64,
    timeout: u64,
    signal: u64,
) -> u64 {
    if minimum > maximum
        || maximum > 1024
        || crate::linux_aio::info(current_linux_process_pid(), context).is_err()
    {
        return LINUX_EINVAL;
    }
    let mut zero_timeout = false;
    if timeout != 0 {
        let mut value = [0_u8; 16];
        if !copy_from_linux_user(timeout, &mut value) {
            return LINUX_EFAULT;
        }
        let Some(duration) = linux_timespec_nanoseconds(&value) else {
            return LINUX_EINVAL;
        };
        zero_timeout = duration == 0;
    }
    if signal != 0 {
        let mut descriptor = [0_u8; 16];
        if !copy_from_linux_user(signal, &mut descriptor) {
            return LINUX_EFAULT;
        }
        let set = u64::from_ne_bytes(descriptor[..8].try_into().unwrap());
        let size = u64::from_ne_bytes(descriptor[8..].try_into().unwrap());
        // struct __aio_sigset: a null set means no mask, whatever the size.
        let mut mask = [0_u8; 8];
        if set != 0 && (size != 8 || !copy_from_linux_user(set, &mut mask)) {
            return if size != 8 {
                LINUX_EINVAL
            } else {
                LINUX_EFAULT
            };
        }
    }
    let mut received = 0_u64;
    while received < maximum {
        let event = match crate::linux_aio::pop(current_linux_process_pid(), context) {
            Ok(Some(event)) => event,
            Ok(None) => break,
            Err(error) => {
                return if received == 0 {
                    linux_aio_error(error)
                } else {
                    received
                }
            }
        };
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&event.data.to_ne_bytes());
        bytes[8..16].copy_from_slice(&event.object.to_ne_bytes());
        bytes[16..24].copy_from_slice(&event.result.to_ne_bytes());
        bytes[24..].copy_from_slice(&event.result2.to_ne_bytes());
        let Some(destination) = received
            .checked_mul(32)
            .and_then(|offset| output.checked_add(offset))
        else {
            return if received == 0 {
                LINUX_EFAULT
            } else {
                received
            };
        };
        if !copy_to_linux_user(destination, &bytes) {
            return if received == 0 {
                LINUX_EFAULT
            } else {
                received
            };
        }
        received += 1;
    }
    if received < minimum && !zero_timeout {
        return LINUX_EAGAIN;
    }
    received
}

/// io_cancel: the request's key is read first (EFAULT), must be 0
/// (KIOCB_KEY, else EINVAL), and the context must exist (EINVAL). Requests
/// complete as they are submitted here, so none is left to cancel
/// (EINVAL, as Linux answers for a completed one).
pub(super) fn linux_io_cancel(context: u64, control: u64, _result: u64) -> u64 {
    let mut key = [0_u8; 4];
    if control
        .checked_add(8)
        .is_none_or(|address| !copy_from_linux_user(address, &mut key))
    {
        return LINUX_EFAULT;
    }
    let _ = crate::linux_aio::info(current_linux_process_pid(), context);
    LINUX_EINVAL
}

/// An AIO read from a pipe or socket: what is queued now, without waiting.
fn linux_aio_stream_read(descriptor: u64, buffer: u64, length: u64) -> u64 {
    let Some(slot) = linux_socket_slot(descriptor) else {
        return LINUX_EBADF;
    };
    let mut bytes = [0_u8; PAGE_SIZE];
    let length = usize::try_from(length).unwrap_or(PAGE_SIZE).min(PAGE_SIZE);
    match crate::linux_socket::recv(slot, &mut bytes[..length]) {
        Ok((received, _)) => {
            if received != 0 && !copy_to_linux_user(buffer, &bytes[..received]) {
                LINUX_EFAULT
            } else {
                received as u64
            }
        }
        Err(error) => linux_socket_error(error),
    }
}

pub(super) fn linux_io_uring_descriptor(descriptor: u64) -> bool {
    linux_socket_flags(descriptor)
        .is_some_and(|flags| flags & LINUX_PRIVATE_IO_URING_DESCRIPTOR != 0)
}

/// The ring a descriptor stands for: its domain and its open file
/// description's id.
fn linux_io_uring_key(descriptor: u64) -> Option<(usize, u64)> {
    if !linux_io_uring_descriptor(descriptor) {
        return None;
    }
    linux_descriptor_open_file_id(descriptor).map(|id| (linux_execution_instance(), id))
}

/// Whether the current process may make a ring, as
/// /proc/sys/kernel/io_uring_disabled decides: 0 lets everyone, 1 only
/// those with CAP_SYS_ADMIN, 2 nobody.
fn linux_io_uring_allowed() -> bool {
    match linux_proc_sysctl_value(b"sys/kernel/io_uring_disabled").unwrap_or(0) {
        0 => true,
        1 => linux_has_capability(linox_credentials::capability::SYS_ADMIN),
        _ => false,
    }
}

pub(super) fn linux_io_uring_setup(entries: u64, parameters: u64) -> u64 {
    use crate::linux_io_uring::{
        CQ_CQES, CQ_FLAGS, CQ_HEAD, CQ_OVERFLOW, CQ_RING_ENTRIES, CQ_RING_MASK, CQ_TAIL, SQ_ARRAY,
        SQ_DROPPED, SQ_FLAGS, SQ_HEAD, SQ_RING_ENTRIES, SQ_RING_MASK, SQ_TAIL,
    };
    const SETUP_CQSIZE: u32 = 1 << 3;
    const SETUP_CLAMP: u32 = 1 << 4;
    const FEAT_NODROP: u32 = 1 << 1;
    const FEAT_SUBMIT_STABLE: u32 = 1 << 2;
    const FEAT_RW_CUR_POS: u32 = 1 << 3;
    let entries = entries as u32;
    if !linux_io_uring_allowed() {
        return LINUX_EPERM;
    }
    let mut params = [0_u8; 120];
    if !copy_from_linux_user(parameters, &mut params) {
        return LINUX_EFAULT;
    }
    let field = |params: &[u8; 120], offset: usize| {
        u32::from_ne_bytes(params[offset..offset + 4].try_into().unwrap())
    };
    let flags = field(&params, 8);
    // Polling threads, other ring layouts and the rest are not offered.
    if flags & !(SETUP_CQSIZE | SETUP_CLAMP) != 0 || params[28..40].iter().any(|byte| *byte != 0) {
        return LINUX_EINVAL;
    }
    let cq_entries = (flags & SETUP_CQSIZE != 0).then(|| field(&params, 4));
    let Some((sq_entries, cq_entries)) =
        crate::linux_io_uring::sizes(entries, cq_entries, flags & SETUP_CLAMP != 0)
    else {
        return LINUX_EINVAL;
    };
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    params[..4].copy_from_slice(&sq_entries.to_ne_bytes());
    params[4..8].copy_from_slice(&cq_entries.to_ne_bytes());
    params[20..24]
        .copy_from_slice(&(FEAT_NODROP | FEAT_SUBMIT_STABLE | FEAT_RW_CUR_POS).to_ne_bytes());
    let sq_offsets = [
        SQ_HEAD,
        SQ_TAIL,
        SQ_RING_MASK,
        SQ_RING_ENTRIES,
        SQ_FLAGS,
        SQ_DROPPED,
        SQ_ARRAY,
    ];
    let cq_offsets = [
        CQ_HEAD,
        CQ_TAIL,
        CQ_RING_MASK,
        CQ_RING_ENTRIES,
        CQ_OVERFLOW,
        CQ_CQES,
        CQ_FLAGS,
    ];
    for (base, offsets) in [(40, &sq_offsets), (80, &cq_offsets)] {
        params[base..base + 40].fill(0);
        for (index, offset) in offsets.iter().enumerate() {
            let at = base + index * 4;
            params[at..at + 4].copy_from_slice(&(*offset as u32).to_ne_bytes());
        }
    }
    if !copy_to_linux_user(parameters, &params) {
        return LINUX_EFAULT;
    }
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device)
        .store(LINUX_DEVICE_ZERO | 3, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags)
        .store(LINUX_PRIVATE_IO_URING_DESCRIPTOR, Ordering::SeqCst);
    let created = linux_descriptor_open_file_id(descriptor).is_some_and(|id| {
        crate::linux_io_uring::create(
            linux_execution_instance(),
            id,
            current_linux_process_pid(),
            sq_entries,
            cq_entries,
        )
    });
    if !created {
        linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(0, Ordering::SeqCst);
        linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(0, Ordering::SeqCst);
        return LINUX_ENOMEM;
    }
    // A ring's descriptor is always close-on-exec, as in Linux.
    set_linux_descriptor_close_on_exec(descriptor, true);
    descriptor
}

/// mmap of a ring's descriptor: a shared area for the submission ring,
/// the completion ring or the submission entries, by `offset`.
pub(super) fn linux_io_uring_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    descriptor: u64,
    offset: u64,
) -> u64 {
    use crate::linux_io_uring::{
        Region, CQ_RING_ENTRIES, CQ_RING_MASK, SQ_RING_ENTRIES, SQ_RING_MASK,
    };
    const MAP_TYPE: u64 = 0xf;
    let Some((domain, id)) = linux_io_uring_key(descriptor) else {
        return LINUX_EBADF;
    };
    let Some(region) = Region::from_offset(offset) else {
        return LINUX_EINVAL;
    };
    let Some(rings) = crate::linux_io_uring::rings(domain, id) else {
        return LINUX_EBADF;
    };
    if length == 0
        || length > region.size(&rings).next_multiple_of(PAGE_SIZE as u64)
        || !matches!(
            flags & MAP_TYPE,
            LINUX_MAP_SHARED | LINUX_MAP_SHARED_VALIDATE
        )
    {
        return LINUX_EINVAL;
    }
    let mapping = linux_runtime_mmap(
        address,
        length,
        protection,
        flags & !MAP_TYPE | LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if mapping >= LINUX_RETURN_TO_KERNEL {
        return mapping;
    }
    let (entries, mask, count) = match region {
        Region::SubmissionRing => (rings.sq_entries, SQ_RING_MASK, SQ_RING_ENTRIES),
        Region::CompletionRing => (rings.cq_entries, CQ_RING_MASK, CQ_RING_ENTRIES),
        Region::SubmissionEntries => (0, 0, 0),
    };
    let initialized = entries == 0
        || copy_to_linux_user(mapping + mask, &(entries - 1).to_ne_bytes())
            && copy_to_linux_user(mapping + count, &entries.to_ne_bytes());
    if initialized && crate::linux_io_uring::mapped(domain, id, region, mapping) {
        mapping
    } else {
        let _ = linux_runtime_munmap(mapping, length);
        LINUX_EFAULT
    }
}

/// One submission entry (struct io_uring_sqe), as io_uring_enter reads it.
struct LinuxIoUringEntry {
    opcode: u8,
    flags: u8,
    descriptor: u64,
    offset: u64,
    address: u64,
    length: u64,
    operation_flags: u64,
    user_data: [u8; 8],
    buffer_index: u16,
}

impl LinuxIoUringEntry {
    fn parse(sqe: &[u8; 64]) -> Self {
        let word = |offset: usize| u32::from_ne_bytes(sqe[offset..offset + 4].try_into().unwrap());
        let double =
            |offset: usize| u64::from_ne_bytes(sqe[offset..offset + 8].try_into().unwrap());
        Self {
            opcode: sqe[0],
            flags: sqe[1],
            descriptor: u64::from(word(4)),
            offset: double(8),
            address: double(16),
            length: u64::from(word(24)),
            operation_flags: u64::from(word(28)),
            user_data: sqe[32..40].try_into().unwrap(),
            buffer_index: u16::from_ne_bytes(sqe[40..42].try_into().unwrap()),
        }
    }
}

const LINUX_IORING_OP_NOP: u8 = 0;
const LINUX_IORING_OP_READV: u8 = 1;
const LINUX_IORING_OP_WRITEV: u8 = 2;
const LINUX_IORING_OP_FSYNC: u8 = 3;
const LINUX_IORING_OP_READ_FIXED: u8 = 4;
const LINUX_IORING_OP_WRITE_FIXED: u8 = 5;
const LINUX_IORING_OP_SENDMSG: u8 = 9;
const LINUX_IORING_OP_READ: u8 = 22;
const LINUX_IORING_OP_WRITE: u8 = 23;
/// The operations a ring runs, as IORING_REGISTER_PROBE reports them.
const LINUX_IORING_SUPPORTED_OPS: [u8; 9] = [
    LINUX_IORING_OP_NOP,
    LINUX_IORING_OP_READV,
    LINUX_IORING_OP_WRITEV,
    LINUX_IORING_OP_FSYNC,
    LINUX_IORING_OP_READ_FIXED,
    LINUX_IORING_OP_WRITE_FIXED,
    LINUX_IORING_OP_SENDMSG,
    LINUX_IORING_OP_READ,
    LINUX_IORING_OP_WRITE,
];
/// The highest operation Linux 6.12 knows (IORING_OP_LAST - 1).
pub(super) const LINUX_IORING_OP_LAST: u8 = 57;

/// Runs one submission entry of ring `ring` and returns its result.
fn linux_io_uring_run(ring: (usize, u64), entry: &LinuxIoUringEntry) -> u64 {
    const FIXED_FILE: u8 = 1 << 0;
    const BUFFER_SELECT: u8 = 1 << 5;
    const VALID_FLAGS: u8 = 0x7f;
    if entry.flags & !VALID_FLAGS != 0 || entry.flags & BUFFER_SELECT != 0 {
        return LINUX_EINVAL;
    }
    // No files are registered, so no fixed file index names one.
    if entry.flags & FIXED_FILE != 0 {
        return LINUX_EBADF;
    }
    let descriptor = entry.descriptor;
    // A file without a position (a pipe or socket) reads and writes at its
    // stream whatever the offset; -1 uses and moves the file position.
    let positioned = |result: u64, streamed: &dyn Fn() -> u64| {
        if result == LINUX_ESPIPE {
            streamed()
        } else {
            result
        }
    };
    match entry.opcode {
        LINUX_IORING_OP_NOP => 0,
        LINUX_IORING_OP_READV | LINUX_IORING_OP_WRITEV => {
            let write = entry.opcode == LINUX_IORING_OP_WRITEV;
            let streamed = || {
                if write {
                    linux_descriptor_writev(descriptor, entry.address, entry.length)
                } else {
                    linux_descriptor_readv(descriptor, entry.address, entry.length)
                }
            };
            if entry.offset == u64::MAX {
                streamed()
            } else {
                positioned(
                    linux_positioned_iov(
                        descriptor,
                        entry.address,
                        entry.length,
                        entry.offset,
                        entry.operation_flags,
                        write,
                    ),
                    &streamed,
                )
            }
        }
        LINUX_IORING_OP_FSYNC => {
            const FSYNC_DATASYNC: u64 = 1;
            if entry.operation_flags & !FSYNC_DATASYNC != 0 {
                LINUX_EINVAL
            } else {
                linux_fsync(descriptor)
            }
        }
        LINUX_IORING_OP_READ_FIXED
        | LINUX_IORING_OP_WRITE_FIXED
        | LINUX_IORING_OP_READ
        | LINUX_IORING_OP_WRITE => {
            let fixed = matches!(
                entry.opcode,
                LINUX_IORING_OP_READ_FIXED | LINUX_IORING_OP_WRITE_FIXED
            );
            if fixed
                && !crate::linux_io_uring::buffer(ring.0, ring.1, usize::from(entry.buffer_index))
                    .is_some_and(|buffer| buffer.holds(entry.address, entry.length))
            {
                return LINUX_EFAULT;
            }
            let write = matches!(
                entry.opcode,
                LINUX_IORING_OP_WRITE_FIXED | LINUX_IORING_OP_WRITE
            );
            let streamed = || {
                if write {
                    linux_descriptor_write(descriptor, entry.address, entry.length)
                } else {
                    linux_descriptor_read(descriptor, entry.address, entry.length)
                }
            };
            if entry.offset == u64::MAX {
                streamed()
            } else if write {
                positioned(
                    linux_regular_file_write_at(
                        descriptor,
                        entry.address,
                        entry.length,
                        linux_pwrite_offset(descriptor, entry.offset),
                    ),
                    &streamed,
                )
            } else {
                positioned(
                    linux_regular_file_read_at(
                        descriptor,
                        entry.address,
                        entry.length,
                        entry.offset,
                    ),
                    &streamed,
                )
            }
        }
        LINUX_IORING_OP_SENDMSG => {
            linux_socket_sendmsg(descriptor, entry.address, entry.operation_flags)
        }
        _ => LINUX_EINVAL,
    }
}

pub(super) fn linux_io_uring_enter(
    descriptor: u64,
    to_submit: u64,
    minimum_complete: u64,
    flags: u64,
    argument: u64,
    argument_size: u64,
) -> u64 {
    use crate::linux_io_uring::{
        CQE_SIZE, CQ_CQES, CQ_HEAD, CQ_TAIL, SQE_SIZE, SQ_ARRAY, SQ_DROPPED, SQ_HEAD, SQ_TAIL,
    };
    const GETEVENTS: u64 = 1 << 0;
    const SQ_WAKEUP: u64 = 1 << 1;
    const SQ_WAIT: u64 = 1 << 2;
    const EXT_ARG: u64 = 1 << 3;
    const REGISTERED_RING: u64 = 1 << 4;
    const IO_LINK: u8 = 1 << 2;
    const IO_HARDLINK: u8 = 1 << 3;
    const CQE_SKIP_SUCCESS: u8 = 1 << 6;
    let descriptor = u64::from(descriptor as u32);
    let to_submit = to_submit as u32;
    let minimum_complete = minimum_complete as u32;
    let flags = u64::from(flags as u32);
    if flags & !(GETEVENTS | SQ_WAKEUP | SQ_WAIT | EXT_ARG | REGISTERED_RING) != 0 {
        return LINUX_EINVAL;
    }
    // No ring descriptors are registered (IORING_REGISTER_RING_FDS).
    if flags & REGISTERED_RING != 0 {
        return if descriptor >= 16 {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    }
    let Some(ring) = linux_io_uring_key(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EOPNOTSUPP
        } else {
            LINUX_EBADF
        };
    };
    // Extended arguments (IORING_FEAT_EXT_ARG) are not offered.
    if flags & EXT_ARG != 0 {
        return LINUX_EINVAL;
    }
    let Some(rings) = crate::linux_io_uring::rings(ring.0, ring.1) else {
        return LINUX_EBADF;
    };
    let read_u32 = |address| {
        let mut value = [0_u8; 4];
        copy_from_linux_user(address, &mut value).then(|| u32::from_ne_bytes(value))
    };
    let mut submitted = 0_u32;
    if to_submit != 0 {
        if rings.sq == 0 || rings.cq == 0 || rings.sqes == 0 {
            return LINUX_EFAULT;
        }
        let (Some(mut sq_head), Some(sq_tail), Some(mut cq_tail)) = (
            read_u32(rings.sq + SQ_HEAD),
            read_u32(rings.sq + SQ_TAIL),
            read_u32(rings.cq + CQ_TAIL),
        ) else {
            return LINUX_EFAULT;
        };
        let available = sq_tail.wrapping_sub(sq_head).min(rings.sq_entries);
        // A link chain whose earlier entry failed ends its later entries
        // with ECANCELED.
        let mut chain_failed = false;
        for _ in 0..available.min(to_submit) {
            // The completion ring holds what is not yet reaped; a full one
            // stops the submissions (EBUSY when none went in).
            let Some(cq_head) = read_u32(rings.cq + CQ_HEAD) else {
                return LINUX_EFAULT;
            };
            if cq_tail.wrapping_sub(cq_head) >= rings.cq_entries {
                if submitted == 0 {
                    return LINUX_EBUSY;
                }
                break;
            }
            let slot = u64::from(sq_head & (rings.sq_entries - 1));
            let Some(index) = read_u32(rings.sq + SQ_ARRAY + slot * 4) else {
                return LINUX_EFAULT;
            };
            sq_head = sq_head.wrapping_add(1);
            if index >= rings.sq_entries {
                // An index past the entries is dropped and counted.
                let dropped = read_u32(rings.sq + SQ_DROPPED).unwrap_or(0);
                let _ = copy_to_linux_user(
                    rings.sq + SQ_DROPPED,
                    &dropped.wrapping_add(1).to_ne_bytes(),
                );
                continue;
            }
            let mut sqe = [0_u8; SQE_SIZE as usize];
            if !copy_from_linux_user(rings.sqes + u64::from(index) * SQE_SIZE, &mut sqe) {
                return LINUX_EFAULT;
            }
            let entry = LinuxIoUringEntry::parse(&sqe);
            let result = if chain_failed {
                LINUX_ECANCELED
            } else {
                linux_io_uring_run(ring, &entry)
            };
            let failed = result >= LINUX_RETURN_TO_KERNEL;
            if entry.flags & (IO_LINK | IO_HARDLINK) == 0 {
                chain_failed = false;
            } else if failed && entry.flags & IO_HARDLINK == 0 {
                chain_failed = true;
            }
            submitted += 1;
            if !failed && entry.flags & CQE_SKIP_SUCCESS != 0 {
                continue;
            }
            let mut cqe = [0_u8; CQE_SIZE as usize];
            cqe[..8].copy_from_slice(&entry.user_data);
            cqe[8..12].copy_from_slice(&(result as i32).to_ne_bytes());
            let slot = u64::from(cq_tail & (rings.cq_entries - 1));
            if !copy_to_linux_user(rings.cq + CQ_CQES + slot * CQE_SIZE, &cqe) {
                return LINUX_EFAULT;
            }
            cq_tail = cq_tail.wrapping_add(1);
            if !copy_to_linux_user(rings.cq + CQ_TAIL, &cq_tail.to_ne_bytes()) {
                return LINUX_EFAULT;
            }
        }
        if !copy_to_linux_user(rings.sq + SQ_HEAD, &sq_head.to_ne_bytes()) {
            return LINUX_EFAULT;
        }
    }
    // Every entry completes as it is submitted, so there is nothing to wait
    // for; a signal mask for the wait must still be a sigset_t's size.
    if flags & GETEVENTS != 0 && minimum_complete != 0 && rings.cq != 0 {
        let ready = match (read_u32(rings.cq + CQ_HEAD), read_u32(rings.cq + CQ_TAIL)) {
            (Some(head), Some(tail)) => tail.wrapping_sub(head),
            _ => return LINUX_EFAULT,
        };
        if ready < minimum_complete.min(rings.cq_entries) && argument != 0 && argument_size != 8 {
            return LINUX_EINVAL;
        }
    }
    u64::from(submitted)
}

pub(super) fn linux_io_uring_register(
    descriptor: u64,
    opcode: u64,
    argument: u64,
    count: u64,
) -> u64 {
    const REGISTER_BUFFERS: u32 = 0;
    const UNREGISTER_BUFFERS: u32 = 1;
    const REGISTER_PROBE: u32 = 8;
    const REGISTER_CLONE_BUFFERS: u32 = 30;
    const REGISTER_USE_REGISTERED_RING: u32 = 1 << 31;
    let descriptor = u64::from(descriptor as u32);
    let opcode = opcode as u32;
    let count = count as u32;
    if opcode & REGISTER_USE_REGISTERED_RING != 0 {
        return if descriptor >= 16 {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    }
    let Some((domain, id)) = linux_io_uring_key(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EOPNOTSUPP
        } else {
            LINUX_EBADF
        };
    };
    match opcode {
        REGISTER_BUFFERS => {
            if argument == 0 || count == 0 || count > crate::linux_io_uring::MAX_BUFFERS {
                return LINUX_EINVAL;
            }
            let mut buffers = Vec::new();
            if buffers.try_reserve_exact(count as usize).is_err() {
                return LINUX_ENOMEM;
            }
            for index in 0..u64::from(count) {
                let mut iovec = [0_u8; 16];
                if !copy_from_linux_user(argument + index * 16, &mut iovec) {
                    return LINUX_EFAULT;
                }
                let address = u64::from_ne_bytes(iovec[..8].try_into().unwrap());
                let length = u64::from_ne_bytes(iovec[8..].try_into().unwrap());
                // A null buffer of no length is a sparse slot; any other
                // must be mapped user memory of at most 1 GiB.
                let valid = address == 0 && length == 0
                    || address != 0
                        && length != 0
                        && length <= crate::linux_io_uring::MAX_BUFFER_LENGTH
                        && linux_writable_user_range_contains(address, length as usize);
                if !valid {
                    return LINUX_EFAULT;
                }
                buffers.push(crate::linux_io_uring::Buffer { address, length });
            }
            match crate::linux_io_uring::register_buffers(domain, id, buffers) {
                Ok(()) => 0,
                Err(crate::linux_io_uring::Error::Busy) => LINUX_EBUSY,
                Err(_) => LINUX_EBADF,
            }
        }
        UNREGISTER_BUFFERS => {
            if argument != 0 || count != 0 {
                return LINUX_EINVAL;
            }
            match crate::linux_io_uring::unregister_buffers(domain, id) {
                Ok(()) => 0,
                Err(crate::linux_io_uring::Error::NoBuffers) => LINUX_ENXIO,
                Err(_) => LINUX_EBADF,
            }
        }
        REGISTER_PROBE => linux_io_uring_probe(argument, count),
        REGISTER_CLONE_BUFFERS => {
            const SOURCE_REGISTERED: u32 = 1 << 0;
            const DESTINATION_REPLACE: u32 = 1 << 1;
            if count != 1 {
                return LINUX_EINVAL;
            }
            let mut clone = [0_u8; 32];
            if !copy_from_linux_user(argument, &mut clone) {
                return LINUX_EFAULT;
            }
            let field = |index: usize| {
                u32::from_ne_bytes(clone[index * 4..index * 4 + 4].try_into().unwrap())
            };
            let flags = field(1);
            if flags & !(SOURCE_REGISTERED | DESTINATION_REPLACE) != 0
                || clone[20..].iter().any(|byte| *byte != 0)
            {
                return LINUX_EINVAL;
            }
            let source = u64::from(field(0));
            if flags & SOURCE_REGISTERED != 0 {
                return if source >= 16 {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                };
            }
            let Some((_, source_id)) = linux_io_uring_key(source) else {
                return if linux_descriptor_open(source) {
                    LINUX_EOPNOTSUPP
                } else {
                    LINUX_EBADF
                };
            };
            match crate::linux_io_uring::clone_buffers(
                domain,
                id,
                source_id,
                (field(2), field(3), field(4)),
                flags & DESTINATION_REPLACE != 0,
            ) {
                Ok(()) => 0,
                Err(crate::linux_io_uring::Error::Busy) => LINUX_EBUSY,
                Err(crate::linux_io_uring::Error::NoBuffers) => LINUX_ENXIO,
                Err(crate::linux_io_uring::Error::NoMemory) => LINUX_ENOMEM,
                Err(crate::linux_io_uring::Error::NotFound) => LINUX_EBADF,
                Err(crate::linux_io_uring::Error::Invalid) => LINUX_EINVAL,
            }
        }
        _ => LINUX_EINVAL,
    }
}

/// IORING_REGISTER_PROBE: which of the operations Linux knows the ring
/// runs (struct io_uring_probe with `count` entries at most).
fn linux_io_uring_probe(argument: u64, count: u32) -> u64 {
    const PROBE_HEADER: usize = 16;
    const PROBE_ENTRY: usize = 8;
    const OP_SUPPORTED: u16 = 1;
    const OPERATIONS: usize = LINUX_IORING_OP_LAST as usize + 1;
    // Entries past the operations Linux knows are left alone.
    let entries = (count as usize).min(OPERATIONS);
    let mut probe = [0_u8; PROBE_HEADER + OPERATIONS * PROBE_ENTRY];
    let size = PROBE_HEADER + entries * PROBE_ENTRY;
    if !copy_from_linux_user(argument, &mut probe[..size]) {
        return LINUX_EFAULT;
    }
    // The structure must come zeroed.
    if probe[..size].iter().any(|byte| *byte != 0) {
        return LINUX_EINVAL;
    }
    probe[0] = LINUX_IORING_OP_LAST;
    probe[1] = entries as u8;
    for operation in 0..entries {
        let offset = PROBE_HEADER + operation * PROBE_ENTRY;
        probe[offset] = operation as u8;
        if LINUX_IORING_SUPPORTED_OPS.contains(&(operation as u8)) {
            probe[offset + 2..offset + 4].copy_from_slice(&OP_SUPPORTED.to_ne_bytes());
        }
    }
    if copy_to_linux_user(argument, &probe[..size]) {
        0
    } else {
        LINUX_EFAULT
    }
}

/// Closing a ring's descriptor: the ring goes when its creator closes its
/// last descriptor of it.
pub(super) fn linux_io_uring_release(descriptor: u64) {
    let Some((domain, id)) = linux_io_uring_key(descriptor) else {
        return;
    };
    if linux_descriptor_numbers().any(|candidate| {
        candidate != descriptor
            && linux_io_uring_descriptor(candidate)
            && linux_descriptor_open_file_id(candidate) == Some(id)
    }) {
        return;
    }
    crate::linux_io_uring::release(domain, Some(id), current_linux_process_pid());
}
