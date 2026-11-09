use super::*;

/// `linux_openat_path`'s open, without what Landlock marks on the
/// descriptor; `truncating` is truncate(2)'s, which Landlock lets through
/// with LANDLOCK_ACCESS_FS_TRUNCATE in place of WRITE_FILE.
pub(super) fn linux_open_file_at(
    directory: u64,
    mut path: [u8; LINUX_PATH_MAX],
    mut path_length: usize,
    flags: u64,
    mode: u64,
    truncating: bool,
) -> u64 {
    /// __O_TMPFILE: an unnamed file in the directory opened.
    const LINUX_O_TMPFILE_BIT: u64 = 0x40_0000;
    let directory = u64::from(directory as u32);
    let mut flags = u64::from(flags as u32);
    let mode = u64::from(mode as u32);
    let access = flags & 3;
    // O_EXCL without O_CREAT means something only for a block device
    // (an exclusive open); elsewhere Linux ignores it.
    if access == 3 {
        return LINUX_EINVAL;
    }
    // A trailing slash names a directory: creating through one is EISDIR,
    // and otherwise it opens as O_DIRECTORY would, so a file is ENOTDIR.
    let named = &path[..path_length];
    if named.len() > 1 && named.ends_with(b"/") && named.iter().any(|byte| *byte != b'/') {
        if flags & LINUX_O_CREAT != 0 {
            return LINUX_EISDIR;
        }
        flags |= LINUX_O_DIRECTORY;
    }
    // O_TMPFILE is __O_TMPFILE with O_DIRECTORY, without O_CREAT, and
    // needs write access (all EINVAL otherwise, as in Linux).
    let temporary = flags & LINUX_O_TMPFILE_BIT != 0;
    if temporary
        && (flags & (LINUX_O_DIRECTORY | LINUX_O_CREAT) != LINUX_O_DIRECTORY || access == 0)
    {
        return LINUX_EINVAL;
    }
    // Like Linux's open and openat (only openat2 is strict), ignore the
    // flags that change nothing here: O_SYNC, O_DSYNC, O_DIRECT, O_ASYNC
    // and any unknown bit. GNU tar opens what it extracts with some.
    let flags = flags
        & (3 | LINUX_O_CLOEXEC
            | LINUX_O_NOCTTY
            | LINUX_O_DIRECTORY
            | LINUX_O_CREAT
            | LINUX_O_EXCL
            | LINUX_O_TRUNC
            | LINUX_O_APPEND
            | LINUX_O_NONBLOCK
            | LINUX_O_LARGEFILE
            | LINUX_O_NOFOLLOW
            | LINUX_O_NOATIME
            | LINUX_O_PATH);
    // /proc/self/exe opens the file the process runs (rustup's installer
    // reads its ELF header to learn the bitness).
    if flags & LINUX_O_NOFOLLOW == 0 {
        if let Some(executable) = linux_proc_self_exe_target(directory, &path[..path_length]) {
            let Some(target) = path.get_mut(..executable.len()) else {
                return LINUX_ENAMETOOLONG;
            };
            target.copy_from_slice(&executable);
            path_length = executable.len();
        }
    }
    if let Some(descriptor) = linux_descriptor_link_at(directory, &path[..path_length], true) {
        if !linux_descriptor_open(descriptor) {
            return LINUX_ENOENT;
        }
        // O_PATH | O_NOFOLLOW names the /proc fd entry itself, a link no
        // file system mounts on: the descriptor opens the file it leads
        // to, marked as that entry's (mount08).
        let link_flags = LINUX_O_PATH | LINUX_O_NOFOLLOW;
        if flags & link_flags == link_flags {
            let opened = linux_openat_path(
                directory,
                path,
                path_length,
                flags & !LINUX_O_NOFOLLOW,
                mode,
            );
            if opened < LINUX_RETURN_TO_KERNEL {
                linux_fd_cell::<u32>(opened, LinuxFdField::Flags)
                    .fetch_or(LINUX_PRIVATE_PROC_LINK_DESCRIPTOR, Ordering::SeqCst);
            }
            return opened;
        }
        // A pipe end opens again as itself, with this open's flags. Linux
        // would also open the other end; opening a socket is ENXIO.
        if linux_pipe_descriptor(descriptor) {
            let end = linux_device_descriptor(descriptor) & 3;
            if (access + 1) as u16 & !end != 0 {
                return LINUX_ENXIO;
            }
            let reopened = linux_device_dup_at_least(descriptor, 0, flags & LINUX_O_CLOEXEC != 0);
            if let Some(status) = (reopened < LINUX_RETURN_TO_KERNEL)
                .then(|| linux_socket_flags_cell(reopened))
                .flatten()
            {
                linux_descriptor_set_status_flags(&status, flags, LINUX_O_NONBLOCK);
            }
            return reopened;
        }
        if linux_socket_slot(descriptor).is_some() {
            return LINUX_ENXIO;
        }
        if linux_overlay_descriptor_handle(descriptor).is_some() {
            let reopened = linux_device_dup_at_least(descriptor, 0, flags & LINUX_O_CLOEXEC != 0);
            if reopened >= LINUX_RETURN_TO_KERNEL {
                return reopened;
            }
            let state = linux_device_descriptor(reopened);
            let reopened_access = (access + 1) as u16;
            if reopened < LINUX_AUX_DESCRIPTOR_FIRST {
                X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[reopened as usize]
                    .store((state & !3) | reopened_access, Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[reopened as usize].store(
                    (flags & (LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_PATH | LINUX_O_NOATIME))
                        as u32,
                    Ordering::SeqCst,
                );
            } else {
                linux_fd_cell::<u16>(reopened, LinuxFdField::Device)
                    .store((state & !3) | reopened_access, Ordering::SeqCst);
                linux_fd_cell::<u32>(reopened, LinuxFdField::Flags).store(
                    (flags & (LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_PATH | LINUX_O_NOATIME))
                        as u32,
                    Ordering::SeqCst,
                );
            }
            if let Some(id) = linux_descriptor_open_file_id_cell(reopened) {
                id.store(0, Ordering::SeqCst);
            }
            linux_legacy_descriptor_offset(reopened).store(0, Ordering::SeqCst);
            if linux_descriptor_open_file_id(reopened).is_none() {
                let _ = linux_descriptor_close(reopened);
                return LINUX_EMFILE;
            }
            // O_TRUNC empties the file as an open by name would, within its
            // seals (a shrink-sealed memfd refuses: memfd_create01).
            if flags & LINUX_O_TRUNC != 0 && access != 0 {
                let truncated = linux_ftruncate(reopened, 0);
                if truncated != 0 {
                    let _ = linux_descriptor_close(reopened);
                    return truncated;
                }
            }
            return reopened;
        }
        // Anything else opens again by its path (the console as
        // /dev/console); one with no path (an eventfd) cannot be opened.
        let mut resolved = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let Some(resolved_length) = linux_descriptor_link_target(descriptor, &mut resolved)
            .filter(|length| resolved[..*length].starts_with(b"/"))
        else {
            return LINUX_ENXIO;
        };
        path[..resolved_length].copy_from_slice(&resolved[..resolved_length]);
        path_length = resolved_length;
    }
    let path = &path[..path_length];
    if temporary {
        return linux_open_temporary(directory, path, flags, mode);
    }
    // A program a process of the domain is executing cannot be opened for
    // writing (creat07).
    if access != 0 && linux_path_executing(directory, path) {
        return LINUX_ETXTBSY;
    }
    // /proc/PID/ns/NAME opens the namespace (nsfs), read-only.
    if let Some(reference) = linux_proc_namespace_at(path) {
        return match reference {
            Ok(_) if access != 0 || flags & LINUX_O_CREAT != 0 => LINUX_EACCES,
            Ok(reference) => linux_open_namespace(reference, flags & LINUX_O_CLOEXEC != 0),
            Err(error) => error,
        };
    }
    let tmp_path = path == b"/tmp/linox-ready";
    let proc_fdinfo_target = linux_proc_fdinfo_target(path);
    let proc_dynamic_pid = linux_proc_process_file(path)
        .filter(|(_, name)| {
            matches!(
                *name,
                b"status"
                    | b"stat"
                    | b"statm"
                    | b"io"
                    | b"maps"
                    | b"smaps"
                    | b"pagemap"
                    | b"mem"
                    | b"oom_score_adj"
                    | b"timens_offsets"
                    | b"comm"
                    | b"task"
                    | b"task/"
            ) || name.starts_with(b"task/")
        })
        .map(|(pid, name)| {
            // /proc/PID/task/TID/stat is the thread's: its descriptor keeps
            // the thread id instead.
            name.strip_prefix(b"task/")
                .filter(|rest| rest.ends_with(b"/stat"))
                .and_then(linux_leading_decimal)
                .unwrap_or(pid)
        })
        // A process's own directory keeps its pid too: Linux takes the
        // descriptor as a pidfd (pidfd_send_signal01).
        .or_else(|| match path {
            b"/proc/self" | b"/proc/self/" => Some(current_linux_process_pid()),
            _ => linux_proc_pid_directory(path, true),
        });
    let virtual_device =
        LinuxCharacterDevice::from_path(path).is_some() || linux_graphics_path_kind(path).is_some();
    let writable_proc_path = linux_runtime_file_kind(path).is_some_and(linux_writable_proc_file);
    if tmp_path && flags & LINUX_O_DIRECTORY != 0 {
        return LINUX_ENOTDIR;
    }
    let mut tmp_handle = None;
    let mut tmp_created = false;
    let mut overlay_handle = None;
    // Whether this open makes the file (F_CREATED_QUERY): a copy-up of an
    // image file is not a creation.
    let mut created = false;
    let mut rootfs_handle = 0;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let mut normalized = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    let mut canonical_length = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        match linux_canonical_path_at(directory, path, &mut canonical) {
            Ok(length) => Some(length),
            Err(error)
                if flags & LINUX_O_CREAT != 0
                    || matches!(
                        error,
                        LINUX_EACCES | LINUX_ENOTDIR | LINUX_ELOOP | LINUX_ENAMETOOLONG
                    ) =>
            {
                return error
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let mut overlay_metadata =
        canonical_length.and_then(|length| crate::linux_overlay::lookup(&canonical[..length]));
    let mut rootfs_at_path = linux_rootfs_path_at(directory, path);
    let mut followed = 0;
    while let Some(link) =
        overlay_metadata.filter(|metadata| metadata.kind == crate::linux_overlay::NodeKind::Symlink)
    {
        const LINK_LIMIT: usize = 40;
        followed += 1;
        // O_PATH with O_NOFOLLOW opens the symlink itself (readlinkat01).
        if flags & (LINUX_O_PATH | LINUX_O_NOFOLLOW) == LINUX_O_PATH | LINUX_O_NOFOLLOW {
            break;
        }
        if flags & LINUX_O_NOFOLLOW != 0 || followed > LINK_LIMIT {
            return LINUX_ELOOP;
        }
        if let Err(error) =
            linux_check_follow_link(&canonical[..canonical_length.unwrap_or(0)], link.owner)
        {
            return error;
        }
        let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let Some(target_length) = crate::linux_overlay::read(link.handle, 0, &mut target) else {
            return LINUX_EIO;
        };
        let mut resolved = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let resolved_length = match linux_resolve_link_target(
            &canonical[..canonical_length.unwrap_or(0)],
            &target[..target_length],
            &mut resolved,
        ) {
            Ok(length) => length,
            Err(error) => return error,
        };
        let mut absolute = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
        absolute[0] = b'/';
        absolute[1..1 + resolved_length].copy_from_slice(&resolved[..resolved_length]);
        overlay_metadata = crate::linux_overlay::lookup(&resolved[..resolved_length]);
        rootfs_at_path =
            linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), &absolute[..1 + resolved_length]);
        canonical[..resolved_length].copy_from_slice(&resolved[..resolved_length]);
        canonical_length = Some(resolved_length);
    }
    if rootfs_at_path.as_ref().is_some_and(|(_, entry)| {
        entry
            .as_ref()
            .is_some_and(|entry| entry.kind == crate::published_rootfs::EntryKind::Symlink)
    }) {
        let Some((_, Some(entry))) = rootfs_at_path.clone() else {
            unreachable!()
        };
        if flags & LINUX_O_NOFOLLOW != 0 {
            return LINUX_ELOOP;
        }
        let Some(link_path_length) = canonical_length else {
            return LINUX_ENOENT;
        };
        if let Err(error) = linux_check_follow_link(&canonical[..link_path_length], entry.owner) {
            return error;
        }
        let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let target_length = if entry.link().starts_with(b"/") {
            if entry.link().len() >= target.len() {
                return LINUX_ENAMETOOLONG;
            }
            target[..entry.link().len()].copy_from_slice(entry.link());
            entry.link().len()
        } else {
            let parent_length = canonical[..link_path_length]
                .iter()
                .rposition(|byte| *byte == b'/')
                .unwrap_or(0);
            let Some(end) = parent_length
                .checked_add(2)
                .and_then(|value| value.checked_add(entry.link().len()))
                .filter(|end| *end < target.len())
            else {
                return LINUX_ENAMETOOLONG;
            };
            target[0] = b'/';
            target[1..1 + parent_length].copy_from_slice(&canonical[..parent_length]);
            target[1 + parent_length] = b'/';
            target[2 + parent_length..end].copy_from_slice(entry.link());
            end
        };
        let mut resolved = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let resolved_length = match linux_canonical_path_at(
            u64::from(LINUX_AT_FDCWD),
            &target[..target_length],
            &mut resolved,
        ) {
            Ok(length) => length,
            Err(error) => return error,
        };
        let mut absolute = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        absolute[0] = b'/';
        absolute[1..1 + resolved_length].copy_from_slice(&resolved[..resolved_length]);
        overlay_metadata = crate::linux_overlay::lookup(&resolved[..resolved_length]);
        rootfs_at_path =
            linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), &absolute[..1 + resolved_length]);
        canonical[..resolved_length].copy_from_slice(&resolved[..resolved_length]);
        canonical_length = Some(resolved_length);
    }
    if flags & (LINUX_O_CREAT | LINUX_O_EXCL) == (LINUX_O_CREAT | LINUX_O_EXCL)
        && (overlay_metadata.is_some() || rootfs_at_path.is_some())
    {
        return LINUX_EEXIST;
    }
    if let Some(attributes) = overlay_metadata
        .filter(|_| flags & LINUX_O_PATH == 0)
        .map(|metadata| metadata.attributes)
    {
        let truncate = flags & LINUX_O_TRUNC != 0;
        if attributes & LINUX_FS_IMMUTABLE_FL != 0 && (access != 0 || truncate)
            || attributes & LINUX_FS_APPEND_FL != 0
                && (access != 0 && flags & LINUX_O_APPEND == 0 || truncate)
        {
            return LINUX_EPERM;
        }
    }
    if let Some(length) = canonical_length.filter(|_| flags & LINUX_O_PATH == 0) {
        let path = &canonical[..length];
        let check = if overlay_metadata.is_some() || rootfs_at_path.is_some() {
            use linox_credentials::access::{READ, WRITE};
            let wanted = match access {
                0 => READ,
                1 => WRITE,
                _ => READ | WRITE,
            } | if flags & LINUX_O_TRUNC != 0 { WRITE } else { 0 };
            if wanted & WRITE != 0 && linux_read_only_path(path) {
                return LINUX_EROFS;
            }
            // Only a file's owner or root may read it without updating its
            // access time.
            let noatime_denied = flags & LINUX_O_NOATIME != 0
                && current_linux_credentials()
                    .zip(linux_path_access(path))
                    .is_some_and(|(credentials, file)| !credentials.owns(file));
            linux_check_path_access(path, wanted).and(if noatime_denied {
                Err(LINUX_EPERM)
            } else {
                Ok(())
            })
        } else if flags & LINUX_O_CREAT != 0 && !tmp_path && !virtual_device && !writable_proc_path
        {
            linux_check_entry_change(path, false)
        } else {
            Ok(())
        };
        if let Err(error) = check.and_then(|()| {
            linux_landlock_check_open(
                path,
                flags,
                overlay_metadata.is_some() || rootfs_at_path.is_some() || virtual_device,
                truncating,
            )
        }) {
            return error;
        }
    }
    if let Some(metadata) = overlay_metadata {
        overlay_handle = Some(metadata.handle);
        // O_TRUNC truncates regular files only; Linux ignores it for
        // devices and FIFOs (`2>/dev/null` opens O_CREAT|O_TRUNC).
        let regular = metadata.kind == crate::linux_overlay::NodeKind::File;
        // A directory is not truncated, nor created over (O_CREAT: EISDIR).
        if flags & (LINUX_O_TRUNC | LINUX_O_CREAT) != 0
            && metadata.kind == crate::linux_overlay::NodeKind::Directory
        {
            return LINUX_EISDIR;
        }
        if flags & LINUX_O_TRUNC != 0 && regular && access == 0 {
            return LINUX_EACCES;
        }
        if flags & LINUX_O_TRUNC != 0 && regular && !linux_truncate_overlay_file(metadata.handle, 0)
        {
            return LINUX_EIO;
        }
    } else if canonical_length.is_some()
        && access != 0
        && !tmp_path
        && !virtual_device
        && !writable_proc_path
    {
        let length = canonical_length.unwrap_or(0);
        // A file the image has is copied up with its mode and owner, as a
        // write to it on Linux keeps them (useradd rewrites /etc/passwd from
        // what fstat says); only a new file takes the creation mode.
        let image_file = rootfs_at_path
            .as_ref()
            .and_then(|(_, entry)| entry.as_ref())
            .filter(|entry| {
                matches!(
                    entry.kind,
                    crate::published_rootfs::EntryKind::File
                        | crate::published_rootfs::EntryKind::Hardlink
                )
            });
        let initial = image_file.map_or(&[][..], |entry| entry.data());
        if rootfs_at_path
            .as_ref()
            .and_then(|(_, entry)| entry.as_ref())
            .is_some_and(|entry| entry.kind == crate::published_rootfs::EntryKind::Directory)
        {
            return LINUX_EISDIR;
        }
        if rootfs_at_path.is_none() && flags & LINUX_O_CREAT == 0 {
            return linux_missing_path_error(&canonical[..length]);
        }
        if !linux_overlay_parent_exists(&canonical[..length]) {
            return linux_missing_path_error(&canonical[..length]);
        }
        let permissions = image_file.map_or_else(
            || linux_file_creation_mode(&canonical[..length], mode as u32),
            |entry| linux_rootfs_mode(entry) & 0o7777,
        );
        let Some(handle) = crate::linux_overlay::create_file(
            &canonical[..length],
            permissions,
            if flags & LINUX_O_TRUNC != 0 {
                &[]
            } else {
                initial
            },
        ) else {
            return LINUX_ENOSPC;
        };
        if let Some(entry) = image_file {
            crate::linux_overlay::set_owner(handle, entry.owner, entry.group);
        }
        overlay_handle = Some(handle);
        created = rootfs_at_path.is_none();
    } else if canonical_length.is_some()
        && flags & LINUX_O_CREAT != 0
        && !tmp_path
        && !virtual_device
        && !writable_proc_path
    {
        let length = canonical_length.unwrap_or(0);
        if !linux_overlay_parent_exists(&canonical[..length]) {
            return linux_missing_path_error(&canonical[..length]);
        }
        let Some(handle) = crate::linux_overlay::create_file(
            &canonical[..length],
            linux_file_creation_mode(&canonical[..length], mode as u32),
            &[],
        ) else {
            return LINUX_ENOSPC;
        };
        overlay_handle = Some(handle);
        created = true;
    }
    // O_DIRECTORY opens only a directory: a FIFO, socket or device file is
    // ENOTDIR before anything opens it (LTP's cleanup tells files from
    // directories this way).
    if flags & LINUX_O_DIRECTORY != 0
        && overlay_handle
            .and_then(crate::linux_overlay::metadata)
            .is_some_and(|metadata| {
                !matches!(
                    metadata.kind,
                    crate::linux_overlay::NodeKind::Directory
                        | crate::linux_overlay::NodeKind::Symlink
                )
            })
    {
        return LINUX_ENOTDIR;
    }
    let kind = if let Some(handle) = overlay_handle {
        match crate::linux_overlay::metadata(handle).map(|metadata| metadata.kind) {
            Some(crate::linux_overlay::NodeKind::File) => LINUX_FILE_TMP_SCRATCH,
            Some(crate::linux_overlay::NodeKind::Directory) => LINUX_ROOT_MEASURED_DIRECTORY,
            // O_PATH | O_NOFOLLOW names the symlink itself.
            Some(crate::linux_overlay::NodeKind::Symlink) if flags & LINUX_O_PATH != 0 => {
                LINUX_FILE_TMP_SCRATCH
            }
            Some(crate::linux_overlay::NodeKind::Symlink) => return LINUX_EINVAL,
            Some(crate::linux_overlay::NodeKind::Fifo) if flags & LINUX_O_PATH != 0 => {
                LINUX_FILE_TMP_SCRATCH
            }
            Some(crate::linux_overlay::NodeKind::Fifo) => {
                return linux_open_named_fifo(flags, handle);
            }
            Some(crate::linux_overlay::NodeKind::Socket) if flags & LINUX_O_PATH != 0 => {
                LINUX_FILE_TMP_SCRATCH
            }
            // A socket file is not opened (Linux's ENXIO); connect(2) names it.
            Some(crate::linux_overlay::NodeKind::Socket) => return LINUX_ENXIO,
            Some(
                crate::linux_overlay::NodeKind::CharacterDevice
                | crate::linux_overlay::NodeKind::BlockDevice,
            ) if flags & LINUX_O_PATH != 0 => LINUX_FILE_TMP_SCRATCH,
            Some(crate::linux_overlay::NodeKind::CharacterDevice)
                if crate::linux_drm::available()
                    && crate::linux_overlay::metadata(handle).is_some_and(|metadata| {
                        metadata.device == crate::linux_drm::NODE_DEVICE
                    }) =>
            {
                return linux_open_render_node(flags);
            }
            // A device file opens the kernel's device itself: the
            // descriptor keeps no tie to the file, so reads and writes go
            // to the device and fstat shows it.
            Some(
                kind @ (crate::linux_overlay::NodeKind::CharacterDevice
                | crate::linux_overlay::NodeKind::BlockDevice),
            ) => match linux_device_node_kind(handle, kind) {
                Ok(LinuxDeviceNode::Character(kind)) => {
                    overlay_handle = None;
                    kind
                }
                Ok(LinuxDeviceNode::Block(major, minor)) => {
                    return linux_open_block_device(major, minor, flags)
                }
                Ok(LinuxDeviceNode::LoopControl) => {
                    return linux_open_object(crate::linux_loop::CLASS_CONTROL, 0, flags)
                }
                Ok(LinuxDeviceNode::KernelLog) => return linux_open_kernel_log(flags),
                Ok(LinuxDeviceNode::PtyMaster) => return linux_open_pty_master(flags),
                Ok(LinuxDeviceNode::PtySlave(index)) => return linux_open_pty_slave(index, flags),
                Ok(LinuxDeviceNode::Userfaultfd) => return linux_open_userfaultfd_device(flags),
                Ok(LinuxDeviceNode::Tun) => return linux_open_tun(flags),
                Err(error) => return error,
            },
            None => return LINUX_ENOENT,
        }
    } else if path == b"/etc/resolv.conf" {
        LINUX_FILE_RESOLV_CONF
    } else if tmp_path {
        let existing = linux_tmpfs::open(b"linox-ready");
        if existing.is_some()
            && flags & (LINUX_O_CREAT | LINUX_O_EXCL) == (LINUX_O_CREAT | LINUX_O_EXCL)
        {
            return LINUX_EEXIST;
        }
        tmp_handle = existing.or_else(|| {
            let created = (flags & LINUX_O_CREAT != 0)
                .then(|| linux_tmpfs::create(b"linox-ready"))
                .flatten();
            tmp_created = created.is_some();
            created
        });
        if tmp_handle.is_none() {
            return LINUX_ENOENT;
        }
        LINUX_FILE_TMP_SCRATCH
    } else if let Some(kind) = linux_virtual_mount_path_at(directory, path) {
        kind
    } else if let Some((handle, entry)) = rootfs_at_path {
        rootfs_handle = handle;
        match entry.map(|entry| entry.kind) {
            None | Some(crate::published_rootfs::EntryKind::Directory) => {
                LINUX_ROOT_MEASURED_DIRECTORY
            }
            Some(crate::published_rootfs::EntryKind::File) => LINUX_FILE_ROOT_GENERIC,
            Some(crate::published_rootfs::EntryKind::Hardlink) => LINUX_FILE_ROOT_GENERIC,
            Some(crate::published_rootfs::EntryKind::Symlink) => return LINUX_EINVAL,
        }
    } else {
        // The kernel's devices come before the image: its /dev is only a
        // directory, and /dev/null would open as that.
        match path {
            path if LinuxCharacterDevice::from_path(path).is_some() => {
                LinuxCharacterDevice::from_path(path).map_or(0, LinuxCharacterDevice::kind)
            }
            path => match linux_relative_path_kind(directory, path) {
                Ok(Some(kind)) => kind,
                // A /proc directory named with "." or "..", or relative
                // to a /proc directory, is looked up from the root.
                _ if canonical_length
                    .and_then(|length| {
                        linux_proc_normalized_path(path, &canonical[..length], &mut normalized)
                    })
                    .is_some_and(|length| {
                        linux_root_directory_kind(&normalized[..length]).is_some()
                    }) =>
                {
                    let length = canonical_length.map_or(0, |length| length + 1);
                    linux_root_directory_kind(&normalized[..length]).unwrap_or(0)
                }
                Ok(None) => match linux_root_directory_kind(path)
                    .or_else(|| linux_runtime_file_kind(path))
                {
                    Some(kind) => kind,
                    None => {
                        return canonical_length.map_or(LINUX_ENOENT, |length| {
                            linux_missing_path_error(&canonical[..length])
                        })
                    }
                },
                Err(error) => return error,
            },
        }
    };
    // A directory opens only for reading, and never with O_CREAT (open11).
    if kind & LINUX_DEVICE_DIRECTORY != 0 && (access != 0 || flags & LINUX_O_CREAT != 0) {
        return LINUX_EISDIR;
    }
    if kind & LINUX_DEVICE_DIRECTORY == 0 && flags & LINUX_O_DIRECTORY != 0 {
        return LINUX_ENOTDIR;
    }
    if kind & LINUX_FILE_MASK != 0
        && access != 0
        && !linux_tmp_file(kind)
        && !linux_writable_proc_file(kind)
        && linux_graphics_device(kind).is_none()
    {
        return LINUX_EACCES;
    }
    // /proc/PID/mem opens only for a process the caller may trace.
    if kind & !3 == LINUX_FILE_PROC_DYNAMIC_MEM
        && proc_dynamic_pid.is_some_and(|pid| !linux_ptrace_access_permitted(pid))
    {
        return LINUX_EACCES;
    }
    let state = kind | (access + 1) as u16;
    let Some(descriptor) = (0..LINUX_AUX_DESCRIPTOR_LIMIT)
        .find(|descriptor| !linux_descriptor_open(*descriptor))
        .or_else(|| linux_free_overflow_descriptor(LINUX_DESCRIPTOR_TABLE_LIMIT))
    else {
        if tmp_created {
            let _ = tmp_handle.is_some_and(|handle| linux_tmpfs::unlink(b"linox-ready", handle));
        }
        return LINUX_EMFILE;
    };
    // /proc/mounts remembers the mount table it was opened on: a later
    // change is POLLPRI until it is read again (epoll_wait10).
    let mounts_seen = (kind & !3 == LINUX_FILE_PROC_MOUNTS)
        .then(|| u64::from(crate::linux_mounts::changes(linux_execution_instance())));
    let tmp_generation = proc_fdinfo_target
        .or(proc_dynamic_pid.map(u64::from))
        .or(mounts_seen)
        .map_or_else(
            || {
                overlay_handle.map_or_else(
                    || tmp_handle.map_or(0, linux_tmpfs::generation),
                    crate::linux_overlay::generation,
                )
            },
            |target| u32::try_from(target.saturating_add(1)).unwrap_or(0),
        );
    let descriptor_flags =
        (flags & (LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_PATH | LINUX_O_NOATIME)) as u32;
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        let installed = install_linux_overflow_descriptor(
            descriptor,
            crate::linux_fd_table::Entry {
                state,
                rootfs: rootfs_handle,
                generation: tmp_generation,
                socket_flags: descriptor_flags,
                close_on_exec: flags & LINUX_O_CLOEXEC != 0,
                created,
                ..Default::default()
            },
        );
        return if installed { descriptor } else { LINUX_ENOMEM };
    }
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
        let index = descriptor as usize;
        X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index].store(state, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS[index]
            .store(rootfs_handle, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index]
            .store(tmp_generation, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[index].store(descriptor_flags, Ordering::SeqCst);
    } else {
        linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(state, Ordering::SeqCst);
        linux_fd_cell::<u16>(descriptor, LinuxFdField::Rootfs)
            .store(rootfs_handle, Ordering::SeqCst);
        linux_fd_cell::<u32>(descriptor, LinuxFdField::Generation)
            .store(tmp_generation, Ordering::SeqCst);
        linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags)
            .store(descriptor_flags, Ordering::SeqCst);
    }
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    reset_linux_descriptor_flags(descriptor, created);
    // A new open starts at offset 0, O_APPEND or not: each write of an
    // O_APPEND file moves to its end first (open12).
    linux_descriptor_offset(descriptor).store(0, Ordering::SeqCst);
    descriptor
}

/// openat2(2)'s RESOLVE_* restrictions on the path walk.
const LINUX_RESOLVE_NO_XDEV: u64 = 0x01;
const LINUX_RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const LINUX_RESOLVE_NO_SYMLINKS: u64 = 0x04;
const LINUX_RESOLVE_BENEATH: u64 = 0x08;
const LINUX_RESOLVE_IN_ROOT: u64 = 0x10;
const LINUX_RESOLVE_CACHED: u64 = 0x20;

pub(super) fn linux_openat2(directory: u64, path_address: u64, how_address: u64, size: u64) -> u64 {
    /// The open flags openat2(2) accepts (it rejects the rest, unlike open).
    const VALID_FLAGS: u64 = 3
        | LINUX_O_CREAT
        | LINUX_O_EXCL
        | LINUX_O_NOCTTY
        | LINUX_O_TRUNC
        | LINUX_O_APPEND
        | LINUX_O_NONBLOCK
        | 0o10_000 // O_DSYNC
        | 0o20_000 // O_ASYNC
        | 0o40_000 // O_DIRECT
        | LINUX_O_LARGEFILE
        | LINUX_O_DIRECTORY
        | LINUX_O_NOFOLLOW
        | LINUX_O_NOATIME
        | LINUX_O_CLOEXEC
        | 0o4_000_000 // __O_SYNC
        | LINUX_O_PATH
        | 0o20_000_000; // __O_TMPFILE
    const RESOLVE_FLAGS: u64 = LINUX_RESOLVE_NO_XDEV
        | LINUX_RESOLVE_NO_MAGICLINKS
        | LINUX_RESOLVE_NO_SYMLINKS
        | LINUX_RESOLVE_BENEATH
        | LINUX_RESOLVE_IN_ROOT
        | LINUX_RESOLVE_CACHED;
    let directory = u64::from(directory as u32);
    const OPEN_HOW_SIZE_VER0: usize = 24;
    let Ok(size) = usize::try_from(size) else {
        return LINUX_E2BIG;
    };
    if size < OPEN_HOW_SIZE_VER0 {
        return LINUX_EINVAL;
    }
    if size > PAGE_SIZE {
        return LINUX_E2BIG;
    }
    let mut how = [0_u8; OPEN_HOW_SIZE_VER0];
    if !copy_from_linux_user(how_address, &mut how) {
        return LINUX_EFAULT;
    }
    let mut extension_offset = OPEN_HOW_SIZE_VER0;
    let mut extension = [0_u8; 64];
    while extension_offset < size {
        let length = (size - extension_offset).min(extension.len());
        let Some(address) = how_address.checked_add(extension_offset as u64) else {
            return LINUX_EFAULT;
        };
        if !copy_from_linux_user(address, &mut extension[..length]) {
            return LINUX_EFAULT;
        }
        if extension[..length].iter().any(|byte| *byte != 0) {
            return LINUX_E2BIG;
        }
        extension_offset += length;
    }
    let flags = u64::from_ne_bytes(how[..8].try_into().unwrap());
    let mode = u64::from_ne_bytes(how[8..16].try_into().unwrap());
    let resolve = u64::from_ne_bytes(how[16..24].try_into().unwrap());
    let creates = flags & (LINUX_O_CREAT | 0o20_000_000) != 0;
    if flags & !VALID_FLAGS != 0
        || resolve & !RESOLVE_FLAGS != 0
        || resolve & (LINUX_RESOLVE_BENEATH | LINUX_RESOLVE_IN_ROOT)
            == (LINUX_RESOLVE_BENEATH | LINUX_RESOLVE_IN_ROOT)
        || mode & !0o7777 != 0
        || mode != 0 && !creates
    {
        return LINUX_EINVAL;
    }
    // A lookup that could not be done from the cache alone (one that may
    // create or truncate) is EAGAIN; every other lookup here is cached.
    if resolve & LINUX_RESOLVE_CACHED != 0
        && flags & (LINUX_O_CREAT | LINUX_O_TRUNC | 0o20_000_000) != 0
    {
        return LINUX_EAGAIN;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let restricted = resolve & !LINUX_RESOLVE_CACHED;
    if restricted == 0 || path_length == 0 {
        return linux_openat_path(directory, path, path_length, flags, mode);
    }
    // Resolve under the restrictions, then open the canonical path found.
    let follow_final = flags & (LINUX_O_NOFOLLOW | LINUX_O_PATH) != LINUX_O_NOFOLLOW;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_resolve_restricted(
        directory,
        &path[..path_length],
        restricted,
        follow_final,
        &mut canonical,
    ) {
        Ok(length) => length,
        Err(error) => return error,
    };
    // A trailing slash still asks for a directory.
    let mut absolute = [0_u8; LINUX_PATH_MAX];
    absolute[0] = b'/';
    absolute[1..1 + length].copy_from_slice(&canonical[..length]);
    let mut absolute_length = length + 1;
    if length != 0 && path[..path_length].ends_with(b"/") {
        absolute[absolute_length] = b'/';
        absolute_length += 1;
    }
    linux_openat_path(
        u64::from(LINUX_AT_FDCWD),
        absolute,
        absolute_length,
        flags,
        mode,
    )
}

/// Whether canonical `path` is a magic link: /proc/PID/fd/N, exe, cwd,
/// root and the like, which jump instead of naming a path.
fn linux_magic_link(path: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(b"proc/") else {
        return false;
    };
    let Some(separator) = rest.iter().position(|byte| *byte == b'/') else {
        return false;
    };
    let (process, name) = (&rest[..separator], &rest[separator + 1..]);
    (process == b"self" || process == b"thread-self" || process.iter().all(u8::is_ascii_digit))
        && (matches!(name, b"exe" | b"cwd" | b"root")
            || name.starts_with(b"fd/")
            || name.starts_with(b"map_files/")
            || name.starts_with(b"ns/"))
}

/// The target of the symlink at exactly canonical `path`, the overlay's
/// before the image's, into `target`; `None` if `path` is not a symlink.
pub(super) fn linux_exact_symlink(
    path: &[u8],
    target: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Option<usize> {
    if let Some(metadata) = crate::linux_overlay::lookup(path) {
        if metadata.kind != crate::linux_overlay::NodeKind::Symlink {
            return None;
        }
        return crate::linux_overlay::read(metadata.handle, 0, target);
    }
    let image = crate::linux_overlay::image_path(path)?;
    let entry = crate::published_rootfs::exact_entry(&image)
        .filter(|entry| entry.kind == crate::published_rootfs::EntryKind::Symlink)?;
    let length = entry.link().len();
    target.get_mut(..length)?.copy_from_slice(entry.link());
    Some(length)
}

/// Resolves `path` relative to `directory` as openat2(2) does under the
/// RESOLVE_* `restrictions`, into its canonical path in `output` (no
/// leading slash):
///
/// - RESOLVE_BENEATH: the walk may not leave `directory`, by an absolute
///   path, `..` or a symlink (EXDEV).
/// - RESOLVE_IN_ROOT: `directory` is the walk's root: absolute paths and
///   `..` at the top stay in it.
/// - RESOLVE_NO_SYMLINKS: any symlink on the way is ELOOP, the last
///   component's too unless it is not followed.
/// - RESOLVE_NO_MAGICLINKS: likewise for /proc's magic links.
/// - RESOLVE_NO_XDEV: crossing a mount point is EXDEV.
fn linux_resolve_restricted(
    directory: u64,
    path: &[u8],
    restrictions: u64,
    follow_final: bool,
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Result<usize, u64> {
    const LINK_LIMIT: usize = 40;
    let mut base = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let base_length = if path.starts_with(b"/")
        && restrictions & (LINUX_RESOLVE_BENEATH | LINUX_RESOLVE_IN_ROOT) == 0
    {
        0
    } else {
        linux_walk_start(directory, &mut base)?
    };
    let confined = restrictions & (LINUX_RESOLVE_BENEATH | LINUX_RESOLVE_IN_ROOT) != 0;
    let top = if confined { base_length } else { 0 };
    let mount_space = linux_mount_space();
    let mut rest: Vec<u8> = Vec::new();
    rest.try_reserve_exact(path.len())
        .map_err(|_| LINUX_ENOMEM)?;
    rest.extend_from_slice(path);
    output[..base_length].copy_from_slice(&base[..base_length]);
    let mut length = base_length;
    if rest.starts_with(b"/") {
        if restrictions & LINUX_RESOLVE_BENEATH != 0 {
            return Err(LINUX_EXDEV);
        }
        length = top;
    }
    let mut followed = 0;
    let mut position = 0;
    while position < rest.len() {
        let end = rest[position..]
            .iter()
            .position(|byte| *byte == b'/')
            .map_or(rest.len(), |offset| position + offset);
        let component = &rest[position..end];
        position = end + 1;
        let is_last = rest[position.min(rest.len())..]
            .iter()
            .all(|byte| *byte == b'/');
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            if length <= top {
                if restrictions & LINUX_RESOLVE_BENEATH != 0 {
                    return Err(LINUX_EXDEV);
                }
                continue;
            }
            if restrictions & LINUX_RESOLVE_NO_XDEV != 0
                && (crate::linux_mounts::is_mount_point(mount_space, &output[..length])
                    || linux_kernel_mount_point(&output[..length]))
            {
                return Err(LINUX_EXDEV);
            }
            length = linux_parent_path(&output[..length]).len();
            continue;
        }
        if component.len() > 255 {
            return Err(LINUX_ENAMETOOLONG);
        }
        let parent_length = length;
        if length != 0 {
            *output.get_mut(length).ok_or(LINUX_ENAMETOOLONG)? = b'/';
            length += 1;
        }
        let end = length
            .checked_add(component.len())
            .filter(|end| *end < output.len())
            .ok_or(LINUX_ENAMETOOLONG)?;
        output[length..end].copy_from_slice(component);
        length = end;
        // The kernel's own mounts (/proc, cgroup) are crossed too
        // (openat202 opens /proc/version).
        if restrictions & LINUX_RESOLVE_NO_XDEV != 0
            && (crate::linux_mounts::is_mount_point(mount_space, &output[..length])
                || linux_kernel_mount_point(&output[..length]))
        {
            return Err(LINUX_EXDEV);
        }
        if is_last && !follow_final {
            continue;
        }
        if linux_magic_link(&output[..length]) {
            if restrictions & (LINUX_RESOLVE_NO_MAGICLINKS | LINUX_RESOLVE_NO_SYMLINKS) != 0 {
                return Err(LINUX_ELOOP);
            }
            continue;
        }
        let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let Some(target_length) = linux_exact_symlink(&output[..length], &mut target) else {
            continue;
        };
        if restrictions & LINUX_RESOLVE_NO_SYMLINKS != 0 {
            return Err(LINUX_ELOOP);
        }
        followed += 1;
        if followed > LINK_LIMIT {
            return Err(LINUX_ELOOP);
        }
        // Walk the target from the link's directory, then what remains.
        let target = &target[..target_length];
        length = parent_length;
        if target.starts_with(b"/") {
            if restrictions & LINUX_RESOLVE_BENEATH != 0 {
                return Err(LINUX_EXDEV);
            }
            length = top;
        }
        let mut next: Vec<u8> = Vec::new();
        next.try_reserve_exact(target.len() + 1 + rest.len().saturating_sub(position))
            .map_err(|_| LINUX_ENOMEM)?;
        next.extend_from_slice(target);
        if position < rest.len() {
            next.push(b'/');
            next.extend_from_slice(&rest[position..]);
        }
        rest = next;
        position = 0;
    }
    Ok(length)
}

pub(super) fn linux_memfd_create(name_address: u64, flags: u64) -> u64 {
    const MFD_CLOEXEC: u64 = 1;
    const MFD_ALLOW_SEALING: u64 = 2;
    let flags = u64::from(flags as u32);
    let huge = match linux_memfd_huge_flags(flags, MFD_CLOEXEC | MFD_ALLOW_SEALING) {
        Ok(huge) => huge,
        Err(error) => return error,
    };
    // A name past 249 bytes (NAME_MAX less "memfd:") is EINVAL.
    let mut name = [0_u8; 250];
    if let Err(error) = copy_linux_c_string(name_address, &mut name) {
        return if error == LINUX_ENAMETOOLONG {
            LINUX_EINVAL
        } else {
            error
        };
    }
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    let Some(handle) = crate::linux_overlay::create_file(b"tmp/.linox-memfd", 0o777, &[]) else {
        return LINUX_ENOSPC;
    };
    if !crate::linux_overlay::configure_memfd(handle, flags & MFD_ALLOW_SEALING != 0)
        || huge && !crate::linux_overlay::set_huge(handle)
        || !crate::linux_overlay::unlink(handle)
    {
        return LINUX_EIO;
    }
    linux_install_unnamed_descriptor(descriptor, handle, 3, 0, flags & MFD_CLOEXEC != 0)
}

/// Makes free descriptor `descriptor` refer to `handle`, an overlay file
/// with no name (a memfd, secret memory or an O_TMPFILE file), with
/// `access` (`LINUX_DESCRIPTOR_INPUT`/`OUTPUT` bits) and descriptor status
/// flags `status`, at offset 0.
fn linux_install_unnamed_descriptor(
    descriptor: u64,
    handle: crate::linux_overlay::Handle,
    access: u16,
    status: u32,
    close_on_exec: bool,
) -> u64 {
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device)
        .store(LINUX_FILE_TMP_SCRATCH | access, Ordering::SeqCst);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Rootfs).store(0, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Generation)
        .store(crate::linux_overlay::generation(handle), Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(status, Ordering::SeqCst);
    linux_descriptor_offset(descriptor).store(0, Ordering::SeqCst);
    set_linux_descriptor_close_on_exec(descriptor, close_on_exec);
    descriptor
}

/// O_TMPFILE: opens a regular file with no name, made in the directory at
/// `path` with `mode` less the umask, which linkat(2) can name later unless
/// `flags` has O_EXCL. The directory must exist (ENOENT, ENOTDIR), be
/// writable (EROFS) and grant write and search permission (EACCES).
fn linux_open_temporary(directory: u64, path: &[u8], flags: u64, mode: u64) -> u64 {
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_canonical_path_at(directory, path, &mut canonical) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let length = match linux_overlay_lookup_following(&mut canonical, length, true) {
        Ok((length, _, _)) => length,
        Err(error) => return error,
    };
    let parent = &canonical[..length];
    let Some(access) = linux_path_access(parent) else {
        return linux_missing_path_error(parent);
    };
    if !access.directory {
        return LINUX_ENOTDIR;
    }
    if linux_read_only_path(parent) {
        return LINUX_EROFS;
    }
    if let Err(error) = linux_check_access(
        Some(access),
        linox_credentials::access::WRITE | linox_credentials::access::EXECUTE,
        false,
    ) {
        return error;
    }
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    let mut probe = Vec::new();
    if probe.try_reserve_exact(parent.len() + 2).is_err() {
        return LINUX_ENOMEM;
    }
    probe.extend_from_slice(parent);
    probe.extend_from_slice(b"/x");
    let Some(handle) = crate::linux_overlay::create_temporary(
        parent,
        linux_file_creation_mode(&probe, mode as u32 & 0o7777),
        flags & LINUX_O_EXCL == 0,
    ) else {
        return LINUX_ENOSPC;
    };
    linux_install_unnamed_descriptor(
        descriptor,
        handle,
        (flags & 3) as u16 + 1,
        (flags & (LINUX_O_APPEND | LINUX_O_NONBLOCK)) as u32,
        flags & LINUX_O_CLOEXEC != 0,
    )
}

pub(super) fn linux_memfd_secret(flags: u64) -> u64 {
    const FD_CLOEXEC: u64 = 1;
    if flags & !FD_CLOEXEC != 0 {
        return LINUX_EINVAL;
    }
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    let Some(handle) = crate::linux_overlay::create_file(b"tmp/.linox-secret", 0o600, &[]) else {
        return LINUX_ENOSPC;
    };
    if !crate::linux_overlay::unlink(handle) || !crate::linux_overlay::mark_pseudo(handle) {
        return LINUX_EIO;
    }
    linux_install_unnamed_descriptor(
        descriptor,
        handle,
        3,
        LINUX_PRIVATE_SECRET_DESCRIPTOR,
        flags & FD_CLOEXEC != 0,
    )
}

pub(super) fn linux_secret_descriptor(descriptor: u64) -> bool {
    linux_socket_flags(descriptor).is_some_and(|flags| flags & LINUX_PRIVATE_SECRET_DESCRIPTOR != 0)
}

pub(super) fn linux_path_descriptor(descriptor: u64) -> bool {
    linux_socket_flags(descriptor).is_some_and(|flags| flags & LINUX_O_PATH as u32 != 0)
}

/// The file handle (and fanotify file identifier) of overlay node
/// `handle`: a volume's file by its volume's tag and inode, which stay its
/// own across remounts as ext4's handles do (kind 3); any other node by
/// its generation (kind 1).
pub(in crate::arch::x86_64) fn linux_handle_identity(handle: crate::linux_overlay::Handle) -> u64 {
    if let Some((tag, inode)) = crate::linux_blockfs::stable_identity(handle) {
        return (u64::from(tag) << 8 | 3) << 32 | u64::from(inode);
    }
    u64::from(1_u32) << 32 | u64::from(crate::linux_overlay::generation(handle))
}

/// [`linux_handle_identity`] of the overlay node with `generation`.
fn linux_generation_identity(generation: u32) -> u64 {
    crate::linux_overlay::from_generation(generation).map_or(
        u64::from(1_u32) << 32 | u64::from(generation),
        linux_handle_identity,
    )
}

pub(super) fn linux_name_to_handle_at(
    directory: u64,
    path_address: u64,
    handle_address: u64,
    mount_id_address: u64,
    flags: u64,
) -> u64 {
    const AT_HANDLE_MNT_ID_UNIQUE: u64 = 1;
    const AT_HANDLE_FID: u64 = 0x200;
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    const HANDLE_SIZE: u32 = 8;
    const HANDLE_TYPE: i32 = 0x474e;
    if flags & !(AT_HANDLE_MNT_ID_UNIQUE | AT_HANDLE_FID | AT_SYMLINK_FOLLOW | LINUX_AT_EMPTY_PATH)
        != 0
    {
        return LINUX_EINVAL;
    }
    let mut header = [0_u8; 8];
    if !copy_from_linux_user(handle_address, &mut header) {
        return LINUX_EFAULT;
    }
    let supplied = u32::from_ne_bytes(header[..4].try_into().unwrap());
    if supplied > 128 {
        return LINUX_EINVAL;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let identity = if length == 0 {
        if flags & LINUX_AT_EMPTY_PATH == 0 {
            return LINUX_ENOENT;
        }
        let rootfs = |handle: u16| u64::from(2_u32) << 32 | u64::from(handle);
        if directory as u32 == LINUX_AT_FDCWD {
            let overlay = X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.load(Ordering::SeqCst);
            if overlay != 0 {
                Some(linux_generation_identity(overlay))
            } else {
                Some(rootfs(
                    X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.load(Ordering::SeqCst),
                ))
            }
        } else if let Some(handle) = linux_overlay_descriptor_handle(directory) {
            Some(linux_handle_identity(handle))
        } else {
            let handle = linux_rootfs_descriptor(directory);
            (handle != 0).then(|| rootfs(handle))
        }
    } else {
        let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        // AT_SYMLINK_FOLLOW names what a final symlink points to.
        let resolved = if flags & AT_SYMLINK_FOLLOW != 0 {
            linux_resolve_restricted(directory, &path[..length], 0, true, &mut canonical)
        } else {
            linux_canonical_path_at(directory, &path[..length], &mut canonical)
        };
        match resolved {
            Ok(canonical_length) => crate::linux_overlay::lookup(&canonical[..canonical_length])
                .map(|metadata| linux_handle_identity(metadata.handle))
                .or_else(|| {
                    linux_rootfs_path_at(directory, &path[..length])
                        .map(|(handle, _)| u64::from(2_u32) << 32 | u64::from(handle))
                }),
            Err(error) => return error,
        }
    };
    let Some(identity) = identity else {
        return if length == 0 {
            LINUX_EBADF
        } else {
            LINUX_EOPNOTSUPP
        };
    };
    let mount_written = if flags & AT_HANDLE_MNT_ID_UNIQUE != 0 {
        let Some(id) = linux_mount::current_unique_mount_id(1) else {
            return LINUX_EINVAL;
        };
        copy_to_linux_user(mount_id_address, &id.to_ne_bytes())
    } else {
        copy_to_linux_user(mount_id_address, &1_i32.to_ne_bytes())
    };
    if !mount_written {
        return LINUX_EFAULT;
    }
    header[..4].copy_from_slice(&HANDLE_SIZE.to_ne_bytes());
    header[4..].copy_from_slice(&HANDLE_TYPE.to_ne_bytes());
    if supplied < HANDLE_SIZE {
        return if copy_to_linux_user(handle_address, &header) {
            LINUX_EOVERFLOW
        } else {
            LINUX_EFAULT
        };
    }
    let mut output = [0_u8; 16];
    output[..8].copy_from_slice(&header);
    output[8..16].copy_from_slice(&identity.to_ne_bytes());
    if copy_to_linux_user(handle_address, &output) {
        0
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_open_by_handle_at(
    mount_descriptor: u64,
    handle_address: u64,
    flags: u64,
) -> u64 {
    let mount_descriptor = u64::from(mount_descriptor as u32);
    let flags = u64::from(flags as u32);
    const HANDLE_TYPE: i32 = 0x474e;
    let access = flags & 3;
    let valid = 3
        | LINUX_O_CLOEXEC
        | LINUX_O_DIRECTORY
        | LINUX_O_APPEND
        | LINUX_O_NONBLOCK
        | LINUX_O_LARGEFILE
        | LINUX_O_NOFOLLOW
        | LINUX_O_NOATIME
        | LINUX_O_PATH;
    if access == 3
        || flags & !valid != 0
        || flags & LINUX_O_PATH != 0
            && flags & !(LINUX_O_PATH | LINUX_O_CLOEXEC | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW) != 0
    {
        return LINUX_EINVAL;
    }
    if mount_descriptor as u32 != LINUX_AT_FDCWD
        && (!linux_descriptor_open(mount_descriptor)
            || linux_proc_file(linux_device_descriptor(mount_descriptor)))
    {
        return LINUX_EBADF;
    }
    // Decoding a handle needs CAP_DAC_READ_SEARCH, checked before the
    // handle is read, as Linux does (open_by_handle_at02).
    if !linux_has_capability(linox_credentials::capability::DAC_READ_SEARCH) {
        return LINUX_EPERM;
    }
    // The handles name files of the root's filesystems: a descriptor on
    // anything else (a pipe, a socket, the console) names another
    // filesystem, where they are stale.
    let stale_mount = mount_descriptor as u32 != LINUX_AT_FDCWD
        && linux_overlay_descriptor_handle(mount_descriptor).is_none()
        && linux_rootfs_descriptor(mount_descriptor) == 0;
    let mut handle = [0_u8; 16];
    if !copy_from_linux_user(handle_address, &mut handle[..8]) {
        return LINUX_EFAULT;
    }
    let size = u32::from_ne_bytes(handle[..4].try_into().unwrap());
    let handle_type = i32::from_ne_bytes(handle[4..8].try_into().unwrap());
    if size == 0 || size > 128 {
        return LINUX_EINVAL;
    }
    if size != 8 || handle_type != HANDLE_TYPE || stale_mount {
        return LINUX_ESTALE;
    }
    if !copy_from_linux_user(handle_address + 8, &mut handle[8..]) {
        return LINUX_EFAULT;
    }
    let identity = u64::from_ne_bytes(handle[8..16].try_into().unwrap());
    let kind = (identity >> 32) as u32;
    let identifier = identity as u32;
    let mut overlay = None;
    let mut oci = 0_u16;
    let node_kind = match kind {
        _ if kind == 1 || kind & 0xff == 3 => {
            let handle = if kind == 1 {
                crate::linux_overlay::from_generation(identifier)
            } else {
                crate::linux_blockfs::from_stable_identity(kind >> 8, identifier)
            };
            let Some(handle) = handle else {
                return LINUX_ESTALE;
            };
            let Some(metadata) = crate::linux_overlay::metadata(handle) else {
                return LINUX_ESTALE;
            };
            overlay = Some(handle);
            metadata.kind
        }
        2 => {
            let Ok(handle) = u16::try_from(identifier) else {
                return LINUX_ESTALE;
            };
            let entry = if handle == crate::published_rootfs::ROOT_HANDLE {
                None
            } else {
                let Some(entry) = crate::published_rootfs::entry(handle) else {
                    return LINUX_ESTALE;
                };
                Some(entry)
            };
            oci = handle;
            match entry.map(|entry| entry.kind) {
                None | Some(crate::published_rootfs::EntryKind::Directory) => {
                    crate::linux_overlay::NodeKind::Directory
                }
                Some(
                    crate::published_rootfs::EntryKind::File
                    | crate::published_rootfs::EntryKind::Hardlink,
                ) => crate::linux_overlay::NodeKind::File,
                Some(crate::published_rootfs::EntryKind::Symlink) => {
                    crate::linux_overlay::NodeKind::Symlink
                }
            }
        }
        _ => return LINUX_ESTALE,
    };
    if node_kind == crate::linux_overlay::NodeKind::Symlink && flags & LINUX_O_PATH == 0 {
        return LINUX_ELOOP;
    }
    if node_kind == crate::linux_overlay::NodeKind::Directory && access != 0 {
        return LINUX_EISDIR;
    }
    if node_kind != crate::linux_overlay::NodeKind::Directory && flags & LINUX_O_DIRECTORY != 0 {
        return LINUX_ENOTDIR;
    }
    if kind == 2 && access != 0 && flags & LINUX_O_PATH == 0 {
        return LINUX_EROFS;
    }
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    let state_kind = match node_kind {
        crate::linux_overlay::NodeKind::Directory => LINUX_ROOT_MEASURED_DIRECTORY,
        crate::linux_overlay::NodeKind::File | crate::linux_overlay::NodeKind::Symlink => {
            LINUX_FILE_TMP_SCRATCH
        }
        crate::linux_overlay::NodeKind::Fifo
        | crate::linux_overlay::NodeKind::Socket
        | crate::linux_overlay::NodeKind::CharacterDevice
        | crate::linux_overlay::NodeKind::BlockDevice => return LINUX_EOPNOTSUPP,
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device)
        .store(state_kind | (access + 1) as u16, Ordering::SeqCst);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Rootfs).store(oci, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Generation).store(
        overlay.map_or(0, crate::linux_overlay::generation),
        Ordering::SeqCst,
    );
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(
        (flags & (LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_PATH | LINUX_O_NOATIME)) as u32,
        Ordering::SeqCst,
    );
    linux_descriptor_offset(descriptor).store(0, Ordering::SeqCst);
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    descriptor
}

pub(super) fn linux_newfstatat(
    directory: u64,
    path_address: u64,
    stat_address: u64,
    flags: u64,
) -> u64 {
    let directory = u64::from(directory as u32);
    let flags = u64::from(flags as u32);
    if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
        return LINUX_EINVAL;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let path = &path[..path_length];
    if linux_path_component_too_long(path) {
        return LINUX_ENAMETOOLONG;
    }
    // An empty pathname names nothing without AT_EMPTY_PATH, as in statx:
    // std::filesystem::exists("") must be false (mold canonicalizes what
    // exists).
    if path.is_empty() && flags & LINUX_AT_EMPTY_PATH == 0 {
        return LINUX_ENOENT;
    }
    if let Some(stat) =
        linux_proc_self_exe_stat(directory, path, flags & LINUX_AT_SYMLINK_NOFOLLOW == 0)
    {
        return if copy_to_linux_user(stat_address, &stat) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(stat) = linux_proc_namespace_stat(path, flags & LINUX_AT_SYMLINK_NOFOLLOW == 0) {
        return match stat {
            Ok(stat) if copy_to_linux_user(stat_address, &stat) => 0,
            Ok(_) => LINUX_EFAULT,
            Err(error) => error,
        };
    }
    if path.is_empty() {
        let Some(stat) = linux_descriptor_stat(directory) else {
            return LINUX_EBADF;
        };
        return if copy_to_linux_user(stat_address, &stat) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(stat) =
        linux_descriptor_link_path_stat(directory, path, flags & LINUX_AT_SYMLINK_NOFOLLOW == 0)
    {
        let Some(stat) = stat else {
            return LINUX_ENOENT;
        };
        return if copy_to_linux_user(stat_address, &stat) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(kind) = linux_virtual_mount_path_at(directory, path) {
        let stat = if kind & LINUX_DEVICE_DIRECTORY != 0 {
            linux_stat(
                LINUX_STAT_DIRECTORY_MODE,
                linux_virtual_mount_directory_inode(path, kind),
            )
        } else {
            linux_regular_file_stat(kind)
        };
        return if copy_to_linux_user(stat_address, &stat) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(device) = linux_graphics_path_kind(path).and_then(linux_graphics_device) {
        return if copy_to_linux_user(stat_address, &linux_graphics_stat(device)) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let canonical_length = match linux_canonical_path_at(directory, path, &mut canonical) {
        Ok(length) => Some(length),
        Err(error @ (LINUX_EACCES | LINUX_ENOTDIR | LINUX_ELOOP)) => return error,
        Err(_) => None,
    };
    let mut followed_to_image = None;
    if let Some(length) = canonical_length {
        let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
        match linux_overlay_lookup_following(&mut canonical, length, follow) {
            Ok((_, _, Some(metadata))) => {
                let stat = linux_overlay_stat(metadata);
                return if copy_to_linux_user(stat_address, &stat) {
                    0
                } else {
                    LINUX_EFAULT
                };
            }
            // An overlay link to a file only the image has.
            Ok((resolved, true, None)) => followed_to_image = Some(resolved),
            Ok(_) => {}
            Err(error) => return error,
        }
    }
    {
        let mut absolute = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
        let image_path = match followed_to_image {
            Some(length) => {
                absolute[0] = b'/';
                absolute[1..1 + length].copy_from_slice(&canonical[..length]);
                &absolute[..1 + length]
            }
            None => path,
        };
        let image_directory = if followed_to_image.is_some() {
            u64::from(LINUX_AT_FDCWD)
        } else {
            directory
        };
        let oci = if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
            linux_rootfs_metadata_path_at(image_directory, image_path)
        } else {
            linux_rootfs_path_at(image_directory, image_path)
        };
        if let Some((handle, entry)) = oci {
            let stat = linux_rootfs_stat(handle, entry);
            return if copy_to_linux_user(stat_address, &stat) {
                0
            } else {
                LINUX_EFAULT
            };
        }
    }
    // A /proc name spelled with "." or "..", or relative to a /proc
    // directory, is looked up from the root.
    let mut normalized = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    let path = match canonical_length
        .and_then(|length| linux_proc_normalized_path(path, &canonical[..length], &mut normalized))
    {
        Some(length) => &normalized[..length],
        None => path,
    };
    let relative_kind = match linux_relative_path_kind(directory, path) {
        Ok(kind) => kind,
        Err(LINUX_ENOENT) => {
            return canonical_length.map_or(LINUX_ENOENT, |length| {
                linux_missing_path_error(&canonical[..length])
            })
        }
        Err(error) => return error,
    };
    let stat = match (relative_kind, path) {
        (Some(kind), _) if kind & LINUX_DEVICE_DIRECTORY != 0 => linux_stat(
            LINUX_STAT_DIRECTORY_MODE,
            linux_root_directory_inode(kind).unwrap_or(0),
        ),
        (Some(kind), _) => linux_regular_file_stat(kind),
        (None, path) if LinuxCharacterDevice::from_path(path).is_some() => {
            LinuxCharacterDevice::from_path(path)
                .map_or([0; LINUX_STAT_SIZE], |device| device.stat())
        }
        (None, path) if linux_root_directory_kind(path).is_some() => linux_stat(
            LINUX_STAT_DIRECTORY_MODE,
            linux_virtual_directory_inode(path, linux_root_directory_kind(path).unwrap_or(0)),
        ),
        (None, path) => match linux_runtime_file_kind(path) {
            // A kernel directory below a process's (/proc/self/fd).
            Some(kind) if kind & LINUX_DEVICE_DIRECTORY != 0 => linux_stat(
                LINUX_STAT_DIRECTORY_MODE,
                linux_virtual_directory_inode(path, kind),
            ),
            Some(kind) => linux_regular_file_stat(kind),
            None => {
                return canonical_length.map_or(LINUX_ENOENT, |length| {
                    linux_missing_path_error(&canonical[..length])
                })
            }
        },
    };
    if !copy_to_linux_user(stat_address, &stat) {
        return LINUX_EFAULT;
    }
    0
}
