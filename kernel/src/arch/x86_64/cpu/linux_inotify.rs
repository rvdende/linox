use super::*;

pub(super) fn linux_inotify_descriptor(descriptor: u64) -> bool {
    linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_INOTIFY
}

/// The kernel's own directories under /sys that are there without the
/// overlay holding them (mount points for their filesystems).
pub(super) fn linux_api_directory(path: &[u8]) -> bool {
    matches!(
        path,
        b"sys"
            | b"sys/fs/cgroup"
            | b"sys/fs/bpf"
            | b"sys/kernel/debug"
            | b"sys/kernel/tracing"
            | b"sys/kernel/security"
            | b"sys/fs/pstore"
    )
}

fn linux_inotify_instance(descriptor: u64) -> Option<usize> {
    if !linux_inotify_descriptor(descriptor) {
        return None;
    }
    // The instance is the descriptor's open file description id, which
    // only grows: a long-running domain's go past 16 bits.
    let instance = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
    instance
        .checked_sub(1)
        .and_then(|index| usize::try_from(index).ok())
}

/// The inotify instance a descriptor stands for: its domain and id.
pub(super) fn linux_inotify_key(descriptor: u64) -> Option<(usize, u64)> {
    linux_inotify_instance(descriptor).map(|instance| (linux_execution_instance(), instance as u64))
}

pub(super) fn linux_inotify_init(flags: u64) -> u64 {
    const IN_NONBLOCK: u64 = 0x800;
    const IN_CLOEXEC: u64 = 0x8_0000;
    let flags = u64::from(flags as u32);
    if flags & !(IN_NONBLOCK | IN_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(
        LINUX_DEVICE_INOTIFY | LINUX_DESCRIPTOR_INPUT,
        Ordering::SeqCst,
    );
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(flags as u32, Ordering::SeqCst);
    let Some(instance) = linux_descriptor_open_file_id(descriptor) else {
        linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(0, Ordering::SeqCst);
        linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(0, Ordering::SeqCst);
        return LINUX_EMFILE;
    };
    linux_legacy_descriptor_offset(descriptor).store(instance + 1, Ordering::SeqCst);
    // The queue holds max_queued_events as /proc/sys/fs/inotify sets it.
    let limit = linux_proc_sysctl_value(b"sys/fs/inotify/max_queued_events")
        .and_then(|limit| usize::try_from(limit).ok())
        .unwrap_or(crate::linux_inotify::DEFAULT_QUEUE_LIMIT);
    if !crate::linux_inotify::create(
        linux_execution_instance(),
        instance,
        current_linux_process_pid(),
        limit,
    ) {
        linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(0, Ordering::SeqCst);
        linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(0, Ordering::SeqCst);
        linux_legacy_descriptor_offset(descriptor).store(0, Ordering::SeqCst);
        return LINUX_ENOMEM;
    }
    set_linux_descriptor_close_on_exec(descriptor, flags & IN_CLOEXEC != 0);
    descriptor
}

pub(super) fn linux_inotify_add_watch(descriptor: u64, path_address: u64, mask: u64) -> u64 {
    use crate::linux_inotify::{IN_ALL_EVENTS, IN_ONLYDIR};
    let descriptor = u64::from(descriptor as u32);
    let mask = mask as u32;
    let Some((domain, instance)) = linux_inotify_key(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    };
    if mask & IN_ALL_EVENTS == 0 {
        return LINUX_EINVAL;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = if &path[..path_length] == b"/" {
        0
    } else {
        match linux_canonical_path_at(
            u64::from(LINUX_AT_FDCWD),
            &path[..path_length],
            &mut canonical,
        ) {
            Ok(length) => length,
            Err(error) => return error,
        }
    };
    let overlay = crate::linux_overlay::lookup(&canonical[..length]);
    let oci = crate::published_rootfs::lookup_metadata_at(
        crate::published_rootfs::ROOT_HANDLE,
        &crate::linux_overlay::image_location(&canonical[..length]),
    );
    let virtual_device = LinuxCharacterDevice::from_canonical(&canonical[..length]).is_some()
        || LinuxCharacterDevice::from_path(&path[..path_length]).is_some();
    if overlay.is_none() && oci.is_none() && !virtual_device {
        return LINUX_ENOENT;
    }
    let directory = overlay
        .is_some_and(|metadata| metadata.kind == crate::linux_overlay::NodeKind::Directory)
        || oci.is_some_and(|(_, entry)| {
            entry.is_none_or(|entry| entry.kind == crate::published_rootfs::EntryKind::Directory)
        });
    if mask & IN_ONLYDIR != 0 && !directory {
        return LINUX_ENOTDIR;
    }
    if mask & IN_ONLYDIR != 0 && !directory {
        return LINUX_ENOTDIR;
    }
    match crate::linux_inotify::add_watch(domain, instance, &canonical[..length], mask) {
        Ok(wd) => wd as u64,
        Err(crate::linux_inotify::Error::Exists) => LINUX_EEXIST,
        Err(crate::linux_inotify::Error::NoMemory) => LINUX_ENOSPC,
        Err(crate::linux_inotify::Error::Invalid) => LINUX_EINVAL,
    }
}

pub(super) fn linux_inotify_rm_watch(descriptor: u64, watch_descriptor: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let Some((domain, instance)) = linux_inotify_key(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    };
    match crate::linux_inotify::rm_watch(domain, instance, watch_descriptor as i32) {
        Ok(()) => {
            wake_linux_descriptor_waits();
            0
        }
        Err(_) => LINUX_EINVAL,
    }
}

pub(super) fn linux_inotify_read(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    let (domain, instance) = linux_inotify_key(descriptor)?;
    let capacity = usize::try_from(count).unwrap_or(usize::MAX);
    let result = crate::linux_inotify::read(domain, instance, capacity, |offset, bytes| {
        copy_to_linux_user(address + offset as u64, bytes)
    });
    Some(match result {
        Ok(0) => LINUX_EAGAIN,
        Ok(written) => written as u64,
        Err(crate::linux_inotify::Error::NoMemory) => LINUX_EFAULT,
        Err(_) => LINUX_EINVAL,
    })
}

/// A canonical path, as watches name paths. It is kept on the heap at its
/// own length: a call carries two from before it runs to after.
pub(super) type LinuxInotifyPath = Vec<u8>;

/// `path` copied to the kernel heap; None when the heap is out of memory.
pub(super) fn linux_heap_path(path: &[u8]) -> Option<LinuxInotifyPath> {
    let mut stored = Vec::new();
    stored.try_reserve_exact(path.len()).ok()?;
    stored.extend_from_slice(path);
    Some(stored)
}

/// The canonical path a path argument names, from `directory`.
pub(super) fn linux_inotify_path_at(directory: u64, address: u64) -> Option<LinuxInotifyPath> {
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = copy_linux_c_string(address, &mut path).ok()?;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let canonical_length = if &path[..length] == b"/" {
        0
    } else {
        linux_canonical_path_at(u64::from(directory as u32), &path[..length], &mut canonical)
            .ok()?
    };
    linux_heap_path(&canonical[..canonical_length])
}

/// The canonical path of an open descriptor's file, for the events done
/// through it: none for a descriptor fanotify opened for a listener, whose
/// use raises no events (FMODE_NONOTIFY).
pub(super) fn linux_inotify_descriptor_path(descriptor: u64) -> Option<LinuxInotifyPath> {
    if linux_socket_flags(u64::from(descriptor as u32))
        .is_some_and(|flags| flags & LINUX_PRIVATE_NONOTIFY_DESCRIPTOR != 0)
    {
        return None;
    }
    linux_descriptor_canonical_path(descriptor)
}

/// The canonical path of an open descriptor's file, if it has one.
pub(super) fn linux_descriptor_canonical_path(descriptor: u64) -> Option<LinuxInotifyPath> {
    let descriptor = u64::from(descriptor as u32);
    if linux_overlay_descriptor_handle(descriptor).is_none()
        && linux_rootfs_descriptor(descriptor) == 0
    {
        return None;
    }
    let mut absolute = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = linux_descriptor_path(descriptor, &mut absolute)?;
    let relative = absolute[..length]
        .strip_prefix(b"/")
        .unwrap_or(&absolute[..length]);
    linux_heap_path(relative)
}

/// Whether canonical `path` still names a file (an open one may have been
/// unlinked).
pub(super) fn linux_inotify_exists(path: &[u8]) -> bool {
    path.is_empty()
        || crate::linux_overlay::lookup(path).is_some()
        || crate::linux_overlay::image_path(path).is_some_and(|image| {
            crate::published_rootfs::lookup_metadata_at(
                crate::published_rootfs::ROOT_HANDLE,
                &image,
            )
            .is_some_and(|(_, entry)| entry.is_some())
        })
}

/// Whether canonical `path` names a directory.
pub(super) fn linux_inotify_is_directory(path: &[u8]) -> bool {
    if path.is_empty() {
        return true;
    }
    if let Some(metadata) = crate::linux_overlay::lookup(path) {
        return metadata.kind == crate::linux_overlay::NodeKind::Directory;
    }
    crate::published_rootfs::lookup_metadata_at(
        crate::published_rootfs::ROOT_HANDLE,
        &crate::linux_overlay::image_location(path),
    )
    .is_some_and(|(_, entry)| {
        entry.is_none_or(|entry| entry.kind == crate::published_rootfs::EntryKind::Directory)
    })
}

/// An event on an overlay node, by its path (the cgroup events files).
pub(super) fn linux_inotify_overlay_event(handle: crate::linux_overlay::Handle, mask: u32) {
    if !crate::linux_inotify::active() {
        return;
    }
    let mut absolute = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    if let Some(length) = crate::linux_overlay::copy_path(handle, &mut absolute) {
        crate::linux_inotify::notify(
            linux_execution_instance(),
            &absolute[..length],
            mask,
            false,
            false,
        );
    }
}

/// What a system call inotify reports needs from before it runs: the
/// path it removes or renames (from and to), or the descriptor it closes.
pub(in crate::arch::x86_64) struct LinuxInotifyCall {
    number: u64,
    arguments: [u64; 6],
    first: Option<LinuxInotifyPath>,
    second: Option<LinuxInotifyPath>,
    directory: bool,
    writer: bool,
    /// The objects at `first` and `second` as fanotify names them, before
    /// the call removes or renames them.
    nodes: [Option<LinuxFanotifyNode>; 2],
}

/// Before system call `number` with `arguments`, when inotify has watches.
pub(in crate::arch::x86_64) fn linux_inotify_before(
    number: u64,
    arguments: [u64; 6],
) -> Option<LinuxInotifyCall> {
    if !(crate::linux_inotify::active() || crate::linux_fanotify::active())
        || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Relaxed)
    {
        return None;
    }
    const AT_REMOVEDIR: u64 = 0x200;
    let at = u64::from(LINUX_AT_FDCWD);
    let (first, second, directory) = match number {
        LINUX_UNLINK_SYSCALL => (linux_inotify_path_at(at, arguments[0]), None, false),
        LINUX_RMDIR_SYSCALL => (linux_inotify_path_at(at, arguments[0]), None, true),
        LINUX_UNLINKAT_SYSCALL => (
            linux_inotify_path_at(arguments[0], arguments[1]),
            None,
            arguments[2] & AT_REMOVEDIR != 0,
        ),
        LINUX_RENAME_SYSCALL => {
            let from = linux_inotify_path_at(at, arguments[0]);
            let directory = from.as_deref().is_some_and(linux_inotify_is_directory);
            (from, linux_inotify_path_at(at, arguments[1]), directory)
        }
        LINUX_RENAMEAT_SYSCALL | LINUX_RENAMEAT2_SYSCALL => {
            let from = linux_inotify_path_at(arguments[0], arguments[1]);
            let directory = from.as_deref().is_some_and(linux_inotify_is_directory);
            (
                from,
                linux_inotify_path_at(arguments[2], arguments[3]),
                directory,
            )
        }
        LINUX_CLOSE_SYSCALL => {
            let path = linux_inotify_descriptor_path(arguments[0]);
            let directory = crate::linux_inotify::active()
                && path.as_deref().is_some_and(linux_inotify_is_directory);
            let writer = linux_device_descriptor(u64::from(arguments[0] as u32))
                & LINUX_DESCRIPTOR_OUTPUT
                != 0;
            // What fanotify reports of the close, from the descriptor
            // while it is still open.
            let node = path
                .as_deref()
                .filter(|_| crate::linux_fanotify::active())
                .and_then(|path| {
                    linux_fanotify_descriptor_node(u64::from(arguments[0] as u32), path)
                });
            return Some(LinuxInotifyCall {
                number,
                arguments,
                first: path,
                second: None,
                directory,
                writer,
                nodes: [node, None],
            });
        }
        _ => (None, None, false),
    };
    let nodes = [
        linux_fanotify_before(first.as_deref()),
        linux_fanotify_before(second.as_deref()),
    ];
    Some(LinuxInotifyCall {
        number,
        arguments,
        first,
        second,
        directory,
        writer: false,
        nodes,
    })
}

/// Counts a finished read or write call into the caller's /proc/self/io,
/// as Linux's vfs_read and vfs_write do: the call (syscr, syscw) unless
/// it failed its checks (a bad descriptor, buffer or argument), and the
/// bytes it passed (rchar, wchar); sendfile, splice and copy_file_range
/// read and write both.
pub(super) fn linux_account_call_io(number: u64, result: u64) {
    let (read, write) = match number {
        LINUX_READ_SYSCALL
        | LINUX_PREAD64_SYSCALL
        | LINUX_READV_SYSCALL
        | LINUX_PREADV_SYSCALL
        | LINUX_PREADV2_SYSCALL => (true, false),
        LINUX_WRITE_SYSCALL
        | LINUX_PWRITE64_SYSCALL
        | LINUX_WRITEV_SYSCALL
        | LINUX_PWRITEV_SYSCALL
        | LINUX_PWRITEV2_SYSCALL => (false, true),
        LINUX_SENDFILE_SYSCALL | LINUX_SPLICE_SYSCALL | LINUX_COPY_FILE_RANGE_SYSCALL => {
            (true, true)
        }
        _ => return,
    };
    if matches!(
        result,
        LINUX_RETURN_TO_KERNEL | LINUX_RETURN_FROM_IRET | LINUX_EBADF | LINUX_EFAULT | LINUX_EINVAL
    ) {
        return;
    }
    let bytes = if result < LINUX_RETURN_TO_KERNEL {
        result
    } else {
        0
    };
    linux_process::account_live_process_io(current_linux_process_pid(), |io| {
        if read {
            io.syscr += 1;
            io.rchar = io.rchar.wrapping_add(bytes);
        }
        if write {
            io.syscw += 1;
            io.wchar = io.wchar.wrapping_add(bytes);
        }
    });
}

/// Storage I/O the current process caused: `bytes` read from (or written
/// to, `write`) a volume's device, /proc/self/io's read_bytes and
/// write_bytes.
pub(crate) fn linux_account_storage_io(write: bool, bytes: usize) {
    linux_process::account_live_process_io(current_linux_process_pid(), |io| {
        if write {
            io.write_bytes = io.write_bytes.wrapping_add(bytes as u64);
        } else {
            io.read_bytes = io.read_bytes.wrapping_add(bytes as u64);
        }
    });
}

/// After the call: the inotify and fanotify events its result stands for.
pub(in crate::arch::x86_64) fn linux_inotify_after(call: LinuxInotifyCall, result: u64) {
    use crate::linux_fanotify::{
        FAN_ACCESS, FAN_ATTRIB, FAN_CLOSE_NOWRITE, FAN_CLOSE_WRITE, FAN_MODIFY, FAN_OPEN,
    };
    use crate::linux_inotify::{
        IN_ACCESS, IN_ATTRIB, IN_CLOSE_NOWRITE, IN_CLOSE_WRITE, IN_MODIFY, IN_OPEN,
    };
    if result >= LINUX_RETURN_TO_KERNEL {
        return;
    }
    let domain = linux_execution_instance();
    let arguments = call.arguments;
    let at = u64::from(LINUX_AT_FDCWD);
    // Looking a path up costs a directory walk: inotify's part only when
    // it has watches.
    let inotify = crate::linux_inotify::active();
    let object = |path: Option<LinuxInotifyPath>, mask: u32| {
        if let Some(path) = path.filter(|_| inotify) {
            let path = &path[..];
            let directory = linux_inotify_is_directory(path);
            crate::linux_inotify::notify(
                domain,
                path,
                mask,
                directory,
                !linux_inotify_exists(path),
            );
        }
    };
    let created = |path: &Option<LinuxInotifyPath>, directory: bool| {
        if let Some(path) = path {
            crate::linux_inotify::created(domain, path, directory);
            linux_fanotify_created(path, false);
        }
    };
    // A new name of a file: its link count changes, then its directory
    // gains the entry.
    let linked = |path: &Option<LinuxInotifyPath>| {
        if let Some(path) = path {
            crate::linux_inotify::created(domain, path, false);
            linux_fanotify_created(path, true);
        }
    };
    // An attribute change, which fanotify hears by name (no open file).
    let changed = |path: Option<LinuxInotifyPath>, mask: u32| {
        if let Some(path) = &path {
            linux_fanotify_change(path, mask);
        }
        path
    };
    // Events through an open file: fanotify describes it by its
    // descriptor.
    let fanotify = |descriptor: u64, path: &Option<LinuxInotifyPath>, mask: u32| {
        if let Some(path) = path {
            linux_fanotify_descriptor_event(u64::from(descriptor as u32), path, None, mask);
        }
    };
    match call.number {
        LINUX_OPEN_SYSCALL | LINUX_OPENAT_SYSCALL | LINUX_CREAT_SYSCALL | LINUX_OPENAT2_SYSCALL => {
            let path = linux_inotify_descriptor_path(result);
            if linux_descriptor_flag(&X86_RUNTIME.ELF_PROBE_DESCRIPTOR_CREATED, result) {
                created(&path, false);
            }
            // The descriptor's path is the file's on its filesystem; the
            // name opened tells the mount (a bind mount's).
            if let Some(path) = &path {
                let opened = (crate::linux_fanotify::active()
                    && crate::linux_fanotify::mount_marks())
                .then(|| {
                    let (directory, name) = match call.number {
                        LINUX_OPEN_SYSCALL | LINUX_CREAT_SYSCALL => (at, arguments[0]),
                        _ => (arguments[0], arguments[1]),
                    };
                    linux_inotify_path_at(directory, name)
                })
                .flatten();
                linux_fanotify_descriptor_event(
                    u64::from(result as u32),
                    path,
                    opened.as_deref(),
                    FAN_OPEN,
                );
            }
            object(path, IN_OPEN);
        }
        LINUX_READ_SYSCALL
        | LINUX_PREAD64_SYSCALL
        | LINUX_READV_SYSCALL
        | LINUX_PREADV_SYSCALL
        | LINUX_PREADV2_SYSCALL
            if result != 0 =>
        {
            let path = linux_inotify_descriptor_path(arguments[0]);
            fanotify(arguments[0], &path, FAN_ACCESS);
            object(path, IN_ACCESS);
        }
        LINUX_WRITE_SYSCALL
        | LINUX_PWRITE64_SYSCALL
        | LINUX_WRITEV_SYSCALL
        | LINUX_PWRITEV_SYSCALL
        | LINUX_PWRITEV2_SYSCALL
            if result != 0 =>
        {
            let path = linux_inotify_descriptor_path(arguments[0]);
            fanotify(arguments[0], &path, FAN_MODIFY);
            object(path, IN_MODIFY);
        }
        LINUX_FALLOCATE_SYSCALL => {
            let path = linux_inotify_descriptor_path(arguments[0]);
            fanotify(arguments[0], &path, FAN_MODIFY);
            object(path, IN_MODIFY);
        }
        // A truncate changes the file's size by name, as Linux's
        // notify_change reports it: not through the open file.
        LINUX_FTRUNCATE_SYSCALL => {
            let path = linux_inotify_descriptor_path(arguments[0]);
            object(changed(path, FAN_MODIFY), IN_MODIFY);
        }
        LINUX_TRUNCATE_SYSCALL => {
            let path = linux_inotify_path_at(at, arguments[0]);
            object(changed(path, FAN_MODIFY), IN_MODIFY);
        }
        LINUX_CHMOD_SYSCALL
        | LINUX_CHOWN_SYSCALL
        | LINUX_LCHOWN_SYSCALL
        | LINUX_UTIME_SYSCALL
        | LINUX_UTIMES_SYSCALL
        | LINUX_SETXATTR_SYSCALL
        | LINUX_LSETXATTR_SYSCALL
        | LINUX_REMOVEXATTR_SYSCALL => {
            let path = linux_inotify_path_at(at, arguments[0]);
            object(changed(path, FAN_ATTRIB), IN_ATTRIB);
        }
        LINUX_FCHMODAT_SYSCALL
        | LINUX_FCHMODAT2_SYSCALL
        | LINUX_FCHOWNAT_SYSCALL
        | LINUX_FUTIMESAT_SYSCALL => {
            let path = linux_inotify_path_at(arguments[0], arguments[1]);
            object(changed(path, FAN_ATTRIB), IN_ATTRIB);
        }
        LINUX_UTIMENSAT_SYSCALL => {
            let path = if arguments[1] == 0 {
                linux_inotify_descriptor_path(arguments[0])
            } else {
                linux_inotify_path_at(arguments[0], arguments[1])
            };
            object(changed(path, FAN_ATTRIB), IN_ATTRIB);
        }
        LINUX_FCHMOD_SYSCALL | LINUX_FCHOWN_SYSCALL | LINUX_FSETXATTR_SYSCALL => {
            let path = linux_inotify_descriptor_path(arguments[0]);
            object(changed(path, FAN_ATTRIB), IN_ATTRIB);
        }
        LINUX_MKDIR_SYSCALL => created(&linux_inotify_path_at(at, arguments[0]), true),
        LINUX_MKDIRAT_SYSCALL => created(&linux_inotify_path_at(arguments[0], arguments[1]), true),
        LINUX_MKNOD_SYSCALL => created(&linux_inotify_path_at(at, arguments[0]), false),
        LINUX_MKNODAT_SYSCALL => created(&linux_inotify_path_at(arguments[0], arguments[1]), false),
        LINUX_SYMLINK_SYSCALL => created(&linux_inotify_path_at(at, arguments[1]), false),
        LINUX_LINK_SYSCALL => linked(&linux_inotify_path_at(at, arguments[1])),
        LINUX_SYMLINKAT_SYSCALL => {
            created(&linux_inotify_path_at(arguments[1], arguments[2]), false);
        }
        LINUX_LINKAT_SYSCALL => linked(&linux_inotify_path_at(arguments[2], arguments[3])),
        LINUX_UNLINK_SYSCALL | LINUX_UNLINKAT_SYSCALL | LINUX_RMDIR_SYSCALL => {
            if let Some(victim) = &call.nodes[0] {
                linux_fanotify_removed(victim);
            }
            // Marks on what is gone go with it.
            if let Some(path) = call
                .first
                .as_deref()
                .filter(|path| !linux_inotify_exists(path))
            {
                crate::linux_fanotify::removed(domain, path);
            }
            if let Some(path) = call.first {
                crate::linux_inotify::deleted(domain, &path, call.directory);
            }
        }
        LINUX_RENAME_SYSCALL | LINUX_RENAMEAT_SYSCALL | LINUX_RENAMEAT2_SYSCALL => {
            const RENAME_EXCHANGE: u64 = 2;
            let exchange =
                call.number == LINUX_RENAMEAT2_SYSCALL && arguments[4] & RENAME_EXCHANGE != 0;
            // Marks follow what moved, before it hears it moved.
            if let (Some(from), Some(to)) = (&call.first, &call.second) {
                crate::linux_fanotify::renamed(domain, from, to, exchange);
            }
            if let (Some(source), Some(to)) = (&call.nodes[0], &call.second) {
                linux_fanotify_renamed(source, to, call.nodes[1].as_ref(), exchange);
            }
            if let (Some(from), Some(to)) = (call.first, call.second) {
                crate::linux_inotify::renamed(domain, &from, &to, call.directory);
            }
        }
        LINUX_CLOSE_SYSCALL => {
            let closed = if call.writer {
                FAN_CLOSE_WRITE
            } else {
                FAN_CLOSE_NOWRITE
            };
            let [node, _] = call.nodes;
            if let Some(node) = node {
                linux_fanotify_node_event(node, closed);
            }
            if let Some(path) = call.first.filter(|_| inotify) {
                let mask = if call.writer {
                    IN_CLOSE_WRITE
                } else {
                    IN_CLOSE_NOWRITE
                };
                let path = &path[..];
                let unlinked = !linux_inotify_exists(path);
                crate::linux_inotify::notify(domain, path, mask, call.directory, unlinked);
            }
        }
        _ => return,
    }
    wake_linux_descriptor_waits();
}

pub(super) fn linux_inotify_ready(descriptor: u64) -> bool {
    linux_inotify_key(descriptor)
        .is_some_and(|(domain, instance)| crate::linux_inotify::ready(domain, instance))
}

pub(super) fn linux_inotify_release(descriptor: u64) {
    let Some(instance) = linux_inotify_instance(descriptor) else {
        return;
    };
    let identity = instance as u64 + 1;
    if linux_descriptor_numbers().any(|candidate| {
        candidate != descriptor
            && linux_inotify_descriptor(candidate)
            && linux_descriptor_offset(candidate).load(Ordering::SeqCst) == identity
    }) {
        return;
    }
    crate::linux_inotify::release(
        linux_execution_instance(),
        Some(instance as u64),
        current_linux_process_pid(),
    );
}
