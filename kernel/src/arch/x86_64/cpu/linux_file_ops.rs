use super::*;

pub(super) fn linux_mkdirat(directory: u64, path_address: u64, mode: u64) -> u64 {
    let directory = u64::from(directory as u32);
    let mode = u64::from(mode as u32);
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let requested_path = &path[..path_length];
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_canonical_path_at(directory, requested_path, &mut canonical) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let path = &canonical[..length];
    if crate::linux_overlay::lookup(path).is_some()
        || linux_rootfs_metadata_path_at(directory, requested_path).is_some()
    {
        return LINUX_EEXIST;
    }
    if !linux_overlay_parent_exists(path) {
        return linux_missing_path_error(path);
    }
    if let Err(error) = linux_landlock_check_make(path, 0o040_000)
        .and_then(|()| linux_check_entry_change(path, false))
    {
        return error;
    }
    let Some(directory_handle) = crate::linux_overlay::create_directory(
        path,
        (mode as u32) & !(X86_RUNTIME.ELF_PROBE_UMASK.load(Ordering::SeqCst) as u32),
    ) else {
        return LINUX_ENOSPC;
    };
    if path.starts_with(b"sys/fs/cgroup/") && !linux_cgroup_mkdir(path, directory_handle) {
        let _ = crate::linux_overlay::unlink(directory_handle);
        return LINUX_ENOSPC;
    }
    0
}

/// Set while `linux_ensure_dev_nodes` makes the nodes: making one walks its
/// parent, `/dev`, which comes back here.
pub(super) static LINUX_MAKING_DEV_NODES: AtomicBool = AtomicBool::new(false);

pub(super) fn linux_mknodat(directory: u64, path_address: u64, mode: u64, device: u64) -> u64 {
    let directory = u64::from(directory as u32);
    let mode = u64::from(mode as u32);
    let device = u64::from(device as u32);
    const S_IFMT: u64 = 0o170000;
    const S_IFIFO: u64 = 0o010000;
    const S_IFCHR: u64 = 0o020000;
    const S_IFBLK: u64 = 0o060000;
    const S_IFREG: u64 = 0o100000;
    const S_IFSOCK: u64 = 0o140000;

    let kind = mode & S_IFMT;
    // Device files are inert names here (opening one reaches only the
    // kernel's null, zero and console devices), but creating one still
    // takes CAP_MKNOD, as in Linux.
    if matches!(kind, S_IFCHR | S_IFBLK)
        && current_linux_credentials().is_none_or(|credentials| !credentials.privileged())
    {
        return LINUX_EPERM;
    }
    if !matches!(kind, 0 | S_IFREG | S_IFIFO | S_IFCHR | S_IFBLK | S_IFSOCK) {
        return LINUX_EINVAL;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let requested_path = &path[..path_length];
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_canonical_path_at(directory, requested_path, &mut canonical) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let path = &canonical[..length];
    if crate::linux_overlay::lookup(path).is_some()
        || linux_rootfs_metadata_path_at(directory, requested_path).is_some()
    {
        return LINUX_EEXIST;
    }
    if !linux_overlay_parent_exists(path) {
        return linux_missing_path_error(path);
    }
    if let Err(error) = linux_landlock_check_make(path, kind as u32)
        .and_then(|()| linux_check_entry_change(path, false))
    {
        return error;
    }
    let permissions = linux_file_creation_mode(path, mode as u32 & 0o7777);
    let created = match kind {
        S_IFIFO => crate::linux_overlay::create_fifo(path, permissions),
        S_IFSOCK => crate::linux_overlay::create_socket(path, permissions),
        S_IFCHR => crate::linux_overlay::create_device(
            path,
            crate::linux_overlay::NodeKind::CharacterDevice,
            permissions,
            device as u32,
        ),
        S_IFBLK => crate::linux_overlay::create_device(
            path,
            crate::linux_overlay::NodeKind::BlockDevice,
            permissions,
            device as u32,
        ),
        _ => crate::linux_overlay::create_file(path, permissions, &[]),
    };
    created.map_or(LINUX_ENOSPC, |_| 0)
}

pub(super) fn linux_symlinkat(target_address: u64, directory: u64, path_address: u64) -> u64 {
    let directory = u64::from(directory as u32);
    let mut target = [0_u8; LINUX_PATH_MAX];
    let target_length = match copy_linux_c_string(target_address, &mut target) {
        Ok(0) => return LINUX_ENOENT,
        Ok(length) => length,
        Err(error) => return error,
    };
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let requested_path = &path[..path_length];
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_canonical_path_at(directory, requested_path, &mut canonical) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let path = &canonical[..length];
    if crate::linux_overlay::lookup(path).is_some()
        || linux_rootfs_metadata_path_at(directory, requested_path).is_some()
    {
        return LINUX_EEXIST;
    }
    if !linux_overlay_parent_exists(path) {
        return linux_missing_path_error(path);
    }
    if let Err(error) = linux_landlock_check_make(path, 0o120_000)
        .and_then(|()| linux_check_entry_change(path, false))
    {
        return error;
    }
    crate::linux_overlay::create_symlink(path, &target[..target_length]).map_or(LINUX_ENOSPC, |_| 0)
}

/// Names `handle`, a file with no name that a descriptor holds, at `path`
/// relative to `directory`: an O_TMPFILE file not opened with O_EXCL. A
/// deleted file cannot be named again (ENOENT), nor a memfd (EXDEV).
fn linux_link_unnamed(handle: crate::linux_overlay::Handle, directory: u64, path: &[u8]) -> u64 {
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_canonical_path_at(directory, path, &mut canonical) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let destination = &canonical[..length];
    if crate::linux_overlay::lookup(destination).is_some()
        || linux_rootfs_metadata_path_at(directory, path).is_some()
    {
        return LINUX_EEXIST;
    }
    if !linux_overlay_parent_exists(destination) {
        return linux_missing_path_error(destination);
    }
    if let Err(error) = linux_check_entry_change(destination, false) {
        return error;
    }
    match crate::linux_overlay::link_unnamed(destination, handle) {
        Ok(()) => 0,
        Err(crate::linux_overlay::LinkError::Gone) => LINUX_ENOENT,
        Err(crate::linux_overlay::LinkError::CrossDevice) => LINUX_EXDEV,
        Err(crate::linux_overlay::LinkError::Exists) => LINUX_EEXIST,
        Err(crate::linux_overlay::LinkError::Failed) => LINUX_ENOSPC,
    }
}

pub(super) fn linux_linkat(
    old_directory: u64,
    old_path_address: u64,
    new_directory: u64,
    new_path_address: u64,
    flags: u64,
) -> u64 {
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    const AT_EMPTY_PATH: u64 = 0x1000;
    let old_directory = u64::from(old_directory as u32);
    let new_directory = u64::from(new_directory as u32);
    let flags = u64::from(flags as u32);
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return LINUX_EINVAL;
    }
    let mut old_path = [0_u8; LINUX_PATH_MAX];
    let mut old_path_length = match copy_linux_c_string(old_path_address, &mut old_path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let mut new_path = [0_u8; LINUX_PATH_MAX];
    let new_path_length = match copy_linux_c_string(new_path_address, &mut new_path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    // The file may be named by a descriptor: `old_directory` itself with
    // AT_EMPTY_PATH and an empty path, or the descriptor a /proc/self/fd/N
    // path names when AT_SYMLINK_FOLLOW follows it. That is how an
    // O_TMPFILE file gets its name.
    let by_descriptor = if old_path_length == 0 && flags & AT_EMPTY_PATH != 0 {
        Some(old_directory)
    } else if flags & AT_SYMLINK_FOLLOW != 0 {
        linux_descriptor_link_at(old_directory, &old_path[..old_path_length], true)
    } else {
        None
    };
    if let Some(descriptor) = by_descriptor {
        if let Some(handle) = linux_overlay_descriptor_handle(descriptor)
            .filter(|handle| !crate::linux_overlay::linked(*handle))
        {
            return linux_link_unnamed(handle, new_directory, &new_path[..new_path_length]);
        }
        // A named file: link it by its path.
        let mut resolved = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let Some(length) = linux_descriptor_path(descriptor, &mut resolved) else {
            return if linux_descriptor_open(descriptor) {
                LINUX_ENOENT
            } else {
                LINUX_EBADF
            };
        };
        old_path[..length].copy_from_slice(&resolved[..length]);
        old_path_length = length;
    } else if old_path_length == 0 {
        return LINUX_ENOENT;
    }
    let mut old_canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let mut old_length = match linux_canonical_path_at(
        old_directory,
        &old_path[..old_path_length],
        &mut old_canonical,
    ) {
        Ok(length) => length,
        Err(error) => return error,
    };
    if flags & AT_SYMLINK_FOLLOW != 0 && by_descriptor.is_none() {
        old_length = match linux_overlay_lookup_following(&mut old_canonical, old_length, true) {
            Ok((length, _, _)) => length,
            Err(error) => return error,
        };
    }
    let mut new_canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let new_length = match linux_canonical_path_at(
        new_directory,
        &new_path[..new_path_length],
        &mut new_canonical,
    ) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let destination = &new_canonical[..new_length];
    if crate::linux_overlay::lookup(destination).is_some()
        || linux_rootfs_metadata_path_at(new_directory, &new_path[..new_path_length]).is_some()
    {
        return LINUX_EEXIST;
    }
    if !linux_overlay_parent_exists(destination) {
        return linux_missing_path_error(destination);
    }
    if let Err(error) = linux_check_entry_change(destination, false) {
        return error;
    }
    // The kernel's own filesystems are other devices than the overlay.
    let old = &old_canonical[..old_length];
    if ["proc", "sys", "dev"].iter().any(|mount| {
        old == mount.as_bytes()
            || old.starts_with(mount.as_bytes()) && old.get(mount.len()) == Some(&b'/')
    }) || crate::linux_mounts::mount_id_at(linux_mount_space(), old)
        != crate::linux_mounts::mount_id_at(linux_mount_space(), destination)
    {
        return LINUX_EXDEV;
    }
    if let Err(error) = linux_landlock_check_link(old, destination) {
        return error;
    }
    // A file only the image has is copied up first, so both names share the
    // overlay's copy.
    let source = match linux_copy_up_path(&old_canonical[..old_length]) {
        Ok(handle) => crate::linux_overlay::metadata(handle),
        Err(_) => crate::linux_overlay::lookup(&old_canonical[..old_length]),
    };
    if let Some(source) = source {
        if source.kind == crate::linux_overlay::NodeKind::Directory {
            return LINUX_EPERM;
        }
        if let Err(error) = linux_check_hardlink_source(source) {
            return error;
        }
        if crate::linux_overlay::create_link(destination, source.handle) {
            return 0;
        }
        let created = match source.kind {
            crate::linux_overlay::NodeKind::File => {
                crate::linux_overlay::create_file(destination, source.mode, &[])
            }
            crate::linux_overlay::NodeKind::Symlink => {
                let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
                let Some(length) = crate::linux_overlay::read(source.handle, 0, &mut target) else {
                    return LINUX_EIO;
                };
                crate::linux_overlay::create_symlink(destination, &target[..length])
            }
            crate::linux_overlay::NodeKind::Fifo => {
                crate::linux_overlay::create_fifo(destination, source.mode)
            }
            crate::linux_overlay::NodeKind::Socket => {
                crate::linux_overlay::create_socket(destination, source.mode)
            }
            kind @ (crate::linux_overlay::NodeKind::CharacterDevice
            | crate::linux_overlay::NodeKind::BlockDevice) => {
                crate::linux_overlay::create_device(destination, kind, source.mode, source.device)
            }
            crate::linux_overlay::NodeKind::Directory => None,
        };
        let Some(created) = created else {
            return LINUX_ENOSPC;
        };
        if source.kind == crate::linux_overlay::NodeKind::File {
            let mut offset = 0;
            let mut chunk = [0_u8; 4096];
            while offset < source.size {
                let length = (source.size - offset).min(chunk.len());
                if crate::linux_overlay::read(source.handle, offset, &mut chunk[..length])
                    != Some(length)
                    || crate::linux_overlay::write(created, offset, &chunk[..length])
                        != Some(length)
                {
                    return LINUX_EIO;
                }
                offset += length;
            }
        }
        return 0;
    }
    let Some((_, Some(entry))) =
        linux_rootfs_metadata_path_at(old_directory, &old_path[..old_path_length])
    else {
        return linux_missing_path_error(&old_canonical[..old_length]);
    };
    match entry.kind {
        crate::published_rootfs::EntryKind::File | crate::published_rootfs::EntryKind::Hardlink => {
            crate::linux_overlay::create_file(
                destination,
                linux_rootfs_mode(entry) & 0o7777,
                entry.data,
            )
        }
        crate::published_rootfs::EntryKind::Symlink => {
            crate::linux_overlay::create_symlink(destination, entry.link)
        }
        crate::published_rootfs::EntryKind::Directory => return LINUX_EPERM,
    }
    .map_or(LINUX_ENOSPC, |_| 0)
}

pub(super) fn linux_unlinkat(directory: u64, path_address: u64, flags: u64) -> u64 {
    let directory = u64::from(directory as u32);
    let flags = u64::from(flags as u32);
    if flags & !LINUX_AT_REMOVEDIR != 0 {
        return LINUX_EINVAL;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let path = &path[..path_length];
    // rmdir of a path ending in "." is EINVAL, in ".." ENOTEMPTY, as
    // Linux answers before looking the directory up (rmdir02).
    if flags & LINUX_AT_REMOVEDIR != 0 {
        let last = path
            .rsplit(|byte| *byte == b'/')
            .find(|component| !component.is_empty());
        match last {
            Some(b".") => return LINUX_EINVAL,
            Some(b"..") => return LINUX_ENOTEMPTY,
            _ => {}
        }
    }
    if directory as u32 == LINUX_AT_FDCWD && path == b"/tmp/linox-ready" {
        if flags != 0 {
            return LINUX_ENOTDIR;
        }
        let Some(handle) = linux_tmpfs::open(b"linox-ready") else {
            return LINUX_ENOENT;
        };
        let generation = linux_tmpfs::generation(handle);
        if linux_descriptor_numbers().any(|descriptor| {
            descriptor >= LINUX_AUX_DESCRIPTOR_FIRST
                && linux_tmp_file(linux_device_descriptor(descriptor))
                && linux_descriptor_tmp_generation(descriptor) == Some(generation)
        }) {
            return LINUX_EBUSY;
        }
        return if linux_tmpfs::unlink(b"linox-ready", handle) {
            0
        } else {
            LINUX_ENOENT
        };
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_canonical_path_at(directory, path, &mut canonical) {
        Ok(length) => length,
        Err(error) => return error,
    };
    if linux_path_access(&canonical[..length]).is_some() {
        if let Err(error) =
            linux_landlock_check_remove(&canonical[..length], flags == LINUX_AT_REMOVEDIR)
                .and_then(|()| linux_check_entry_change(&canonical[..length], true))
        {
            return error;
        }
    }
    let Some(metadata) = crate::linux_overlay::lookup(&canonical[..length]) else {
        // A name only the image has: removing it whites it out, after the
        // checks the overlay's own names get below.
        let image = crate::linux_overlay::image_path(&canonical[..length]);
        let image_directory = image
            .as_deref()
            .and_then(crate::published_rootfs::exact_entry)
            .map(|entry| entry.kind == crate::published_rootfs::EntryKind::Directory);
        if image.is_some() {
            match (image_directory, flags == LINUX_AT_REMOVEDIR) {
                (Some(false), true) => return LINUX_ENOTDIR,
                (Some(true), false) => return LINUX_EISDIR,
                (Some(true), true)
                    if crate::linux_mounts::is_mount_point(
                        linux_mount_space(),
                        &canonical[..length],
                    ) =>
                {
                    return LINUX_EBUSY
                }
                (Some(true), true) if !linux_merged_directory_empty(&canonical[..length]) => {
                    return LINUX_ENOTEMPTY
                }
                _ => {}
            }
        }
        return if let Some(image) = image {
            if crate::published_rootfs::lookup_at(crate::published_rootfs::ROOT_HANDLE, &image)
                .is_none()
            {
                linux_missing_path_error(&canonical[..length])
            } else if crate::linux_overlay::whiteout(&canonical[..length]) {
                0
            } else {
                LINUX_ENOSPC
            }
        } else {
            LINUX_ENOENT
        };
    };
    if metadata.attributes & (LINUX_FS_IMMUTABLE_FL | LINUX_FS_APPEND_FL) != 0 {
        return LINUX_EPERM;
    }
    if flags == LINUX_AT_REMOVEDIR && metadata.kind != crate::linux_overlay::NodeKind::Directory {
        return LINUX_ENOTDIR;
    }
    if flags == LINUX_AT_REMOVEDIR
        && crate::linux_mounts::is_mount_point(linux_mount_space(), &canonical[..length])
    {
        return LINUX_EBUSY;
    }
    if flags == 0 && metadata.kind == crate::linux_overlay::NodeKind::Directory {
        return LINUX_EISDIR;
    }
    if flags == LINUX_AT_REMOVEDIR && canonical[..length].starts_with(b"sys/fs/cgroup/") {
        if let Err(error) = linux_cgroup_rmdir(metadata.handle) {
            return error;
        }
    }
    let lower_exists = crate::published_rootfs::lookup_at(
        crate::published_rootfs::ROOT_HANDLE,
        &crate::linux_overlay::image_location(&canonical[..length]),
    )
    .is_some();
    // The image's entries below a directory the overlay also has are its
    // entries too (linux_getdents lists them).
    if metadata.kind == crate::linux_overlay::NodeKind::Directory
        && !linux_merged_directory_empty(&canonical[..length])
    {
        return LINUX_ENOTEMPTY;
    }
    let removed = if metadata.kind == crate::linux_overlay::NodeKind::Directory {
        crate::linux_overlay::unlink(metadata.handle)
    } else {
        crate::linux_overlay::unlink_path(&canonical[..length])
    };
    if removed {
        if !lower_exists || crate::linux_overlay::whiteout(&canonical[..length]) {
            0
        } else {
            LINUX_ENOSPC
        }
    } else if metadata.kind == crate::linux_overlay::NodeKind::Directory {
        LINUX_ENOTEMPTY
    } else {
        LINUX_EIO
    }
}

pub(super) fn linux_ftruncate(descriptor: u64, length: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let state = linux_device_descriptor(descriptor);
    // Linux's order: a negative length, then a closed descriptor (EBADF),
    // then one not open for writing or not a regular file (EINVAL:
    // ftruncate03's read-only file and socket).
    if length > i64::MAX as u64 {
        return LINUX_EINVAL;
    }
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    if state & 3 != LINUX_DESCRIPTOR_OUTPUT && state & 3 != 3
        || linux_socket_slot(descriptor).is_some()
    {
        return LINUX_EINVAL;
    }
    if let Err(error) = linux_landlock_check_ftruncate(descriptor) {
        return error;
    }
    let handle = match linux_copy_up_descriptor(descriptor) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    if let Err(error) = linux_check_writable_handle(handle) {
        return error;
    }
    let length = length as usize;
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return LINUX_EIO;
    };
    if metadata.attributes & (LINUX_FS_IMMUTABLE_FL | LINUX_FS_APPEND_FL) != 0 {
        return LINUX_EPERM;
    }
    // Only the size seals stop a truncate; a write-sealed memfd may still
    // shrink and grow, as in Linux (memfd_create01).
    if let Some(seals) = crate::linux_overlay::file_seals(handle) {
        if length < metadata.size && seals & LINUX_F_SEAL_SHRINK != 0
            || length > metadata.size && seals & LINUX_F_SEAL_GROW != 0
        {
            return LINUX_EPERM;
        }
    }
    if length > metadata.size && linux_file_extension_limit(length).is_err() {
        return LINUX_EFBIG;
    }
    if linux_truncate_overlay_file(handle, length) {
        0
    } else {
        LINUX_ENOSPC
    }
}

pub(super) fn linux_fallocate(descriptor: u64, mode: u64, offset: u64, length: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let mode = u64::from(mode as u32);
    let state = linux_device_descriptor(descriptor);
    if state & 3 != LINUX_DESCRIPTOR_OUTPUT && state & 3 != 3 {
        return LINUX_EBADF;
    }
    // tmpfs: allocation, with or without FALLOC_FL_KEEP_SIZE, and
    // FALLOC_FL_PUNCH_HOLE with KEEP_SIZE, which zeroes the range; ext4
    // volumes zero, collapse and insert ranges too.
    const KEEP_SIZE: u64 = 1;
    const PUNCH_HOLE: u64 = 2;
    const COLLAPSE_RANGE: u64 = 8;
    const ZERO_RANGE: u64 = 0x10;
    const INSERT_RANGE: u64 = 0x20;
    const UNSHARE_RANGE: u64 = 0x40;
    if offset > i64::MAX as u64 || length == 0 || length > i64::MAX as u64 {
        return LINUX_EINVAL;
    }
    // The flag combinations vfs_fallocate refuses for every filesystem.
    if mode & !(KEEP_SIZE | PUNCH_HOLE | COLLAPSE_RANGE | ZERO_RANGE | INSERT_RANGE | UNSHARE_RANGE)
        != 0
        || mode & PUNCH_HOLE != 0 && mode & KEEP_SIZE == 0
    {
        return LINUX_EOPNOTSUPP;
    }
    if mode & PUNCH_HOLE != 0 && mode & ZERO_RANGE != 0
        || mode & COLLAPSE_RANGE != 0 && mode != COLLAPSE_RANGE
        || mode & INSERT_RANGE != 0 && mode != INSERT_RANGE
    {
        return LINUX_EINVAL;
    }
    let Some(end) = offset
        .checked_add(length)
        .filter(|end| *end <= i64::MAX as u64)
    else {
        return LINUX_EFBIG;
    };
    let handle = match linux_copy_up_descriptor(descriptor) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return LINUX_EIO;
    };
    if metadata.kind != crate::linux_overlay::NodeKind::File {
        return LINUX_EISDIR;
    }
    if crate::linux_blockfs::owns(handle) {
        use crate::linux_blockfs::Allocation;
        let keep_size = mode & KEEP_SIZE != 0;
        let allocation = match mode & !KEEP_SIZE {
            0 => Allocation::Allocate { keep_size },
            PUNCH_HOLE => Allocation::PunchHole,
            ZERO_RANGE => Allocation::ZeroRange { keep_size },
            COLLAPSE_RANGE => Allocation::CollapseRange,
            INSERT_RANGE => Allocation::InsertRange,
            _ => return LINUX_EOPNOTSUPP,
        };
        // Block maps (ext2's, and ext4 files without extents) hold no
        // unwritten blocks: linox_ext2 answers EOPNOTSUPP for them.
        return match crate::linux_blockfs::fallocate(handle, allocation, offset, length) {
            Some(Ok(())) => 0,
            Some(Err(error)) => error.wrapping_neg(),
            None => LINUX_EIO,
        };
    }
    if !matches!(mode, 0 | KEEP_SIZE | 3) {
        return LINUX_EOPNOTSUPP;
    }
    // Allocating changes no data, so only F_SEAL_GROW stops it (and only
    // when the size grows); the write seals stop a hole punch.
    if let Some(seals) = crate::linux_overlay::file_seals(handle) {
        if mode & PUNCH_HOLE != 0 && seals & (LINUX_F_SEAL_WRITE | LINUX_F_SEAL_FUTURE_WRITE) != 0
            || mode == 0 && end as usize > metadata.size && seals & LINUX_F_SEAL_GROW != 0
        {
            return LINUX_EPERM;
        }
    }
    if mode & PUNCH_HOLE != 0 {
        // The whole pages go (and their tmpfs blocks), the rest reads back
        // as zeros; past the end there is nothing to punch.
        return if crate::linux_overlay::punch_hole(handle, offset as usize, end as usize) {
            let _ = crate::linux_overlay::touch_modified(handle, linux_realtime_now());
            0
        } else {
            LINUX_EIO
        };
    }
    if metadata.size < end as usize && linux_file_extension_limit(end as usize).is_err() {
        return LINUX_EFBIG;
    }
    // The allocated range counts against a tmpfs's size, with or without
    // FALLOC_FL_KEEP_SIZE.
    if !crate::linux_overlay::reserve(handle, end as usize) {
        return LINUX_ENOSPC;
    }
    if mode & KEEP_SIZE != 0 {
        return 0;
    }
    if metadata.size >= end as usize || crate::linux_overlay::truncate(handle, end as usize) {
        0
    } else {
        LINUX_ENOSPC
    }
}

pub(super) fn linux_fchmod(descriptor: u64, mode: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let mode = u64::from(mode as u32);
    let handle = match linux_copy_up_descriptor(descriptor) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    if crate::linux_overlay::file_seals(handle).is_some_and(|seals| {
        seals & LINUX_F_SEAL_EXEC != 0
            && crate::linux_overlay::metadata(handle)
                .is_some_and(|metadata| (metadata.mode ^ mode as u32) & 0o111 != 0)
    }) {
        return LINUX_EPERM;
    }
    linux_overlay_chmod(handle, mode as u32)
}

pub(super) fn linux_overlay_file_access(
    metadata: crate::linux_overlay::Metadata,
) -> linox_credentials::FileAccess {
    linox_credentials::FileAccess {
        owner: metadata.owner,
        group: metadata.group,
        mode: metadata.mode & 0o7777,
        directory: metadata.kind == crate::linux_overlay::NodeKind::Directory,
    }
}

/// chmod(2) on an overlay file: only its owner or root may change its mode,
/// and a caller outside the file's group, unless root, cannot set its
/// set-group-ID bit.
fn linux_overlay_chmod(handle: crate::linux_overlay::Handle, mut mode: u32) -> u64 {
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return LINUX_EIO;
    };
    if let Err(error) = linux_check_writable_handle(handle) {
        return error;
    }
    if metadata.attributes & (LINUX_FS_IMMUTABLE_FL | LINUX_FS_APPEND_FL) != 0 {
        return LINUX_EPERM;
    }
    let file = linux_overlay_file_access(metadata);
    if let Some(credentials) = current_linux_credentials() {
        if !credentials.owns(file) {
            return LINUX_EPERM;
        }
        let in_group =
            linux_process::with_live_process_groups(current_linux_process_pid(), |groups| {
                credentials.in_group(groups, file.group)
            })
            .unwrap_or(true);
        if !credentials.filesystem_privileged() && !in_group {
            mode &= !0o2000;
        }
    }
    if crate::linux_overlay::set_mode(handle, mode) {
        0
    } else {
        LINUX_EIO
    }
}

/// chown(2) on an overlay file: root may give it any owner and group that
/// exists, its owner only one of its own groups. Changing the owner of
/// anything but a directory clears its set-user-ID bit, and its
/// set-group-ID bit when group-executable.
fn linux_overlay_chown(handle: crate::linux_overlay::Handle, owner: u32, group: u32) -> u64 {
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return LINUX_EIO;
    };
    if let Err(error) = linux_check_writable_handle(handle) {
        return error;
    }
    if metadata.attributes & (LINUX_FS_IMMUTABLE_FL | LINUX_FS_APPEND_FL) != 0 {
        return LINUX_EPERM;
    }
    let file = linux_overlay_file_access(metadata);
    let (Some(namespace), Some(credentials)) =
        (current_linux_user_namespace(), current_linux_credentials())
    else {
        return LINUX_ESRCH;
    };
    let id_count = linux_user::identity_authority(namespace, &credentials).id_count;
    let unchanged = linox_credentials::UNCHANGED;
    if [owner, group]
        .into_iter()
        .any(|id| id != unchanged && id >= id_count)
    {
        return LINUX_EINVAL;
    }
    let permitted =
        linux_process::with_live_process_groups(current_linux_process_pid(), |groups| {
            credentials.may_chown(groups, file, owner, group)
        })
        .unwrap_or(false);
    if !permitted {
        return LINUX_EPERM;
    }
    let owner = if owner == unchanged {
        file.owner
    } else {
        owner
    };
    let group = if group == unchanged {
        file.group
    } else {
        group
    };
    let mut mode = file.mode;
    if !file.directory {
        mode &= !0o4000;
        if mode & 0o010 != 0 {
            mode &= !0o2000;
        }
    }
    if crate::linux_overlay::set_owner(handle, owner, group)
        && crate::linux_overlay::set_mode(handle, mode)
    {
        0
    } else {
        LINUX_EIO
    }
}

/// The overlay file at canonical `path`, copied up from the image first if
/// only the image has it.
fn linux_copy_up_path(path: &[u8]) -> Result<crate::linux_overlay::Handle, u64> {
    if let Some(metadata) = crate::linux_overlay::lookup(path) {
        return Ok(metadata.handle);
    }
    // A missing file is ENOENT, or ENOTDIR when a directory on the way is
    // a file (chmod06).
    let Some(image) = crate::linux_overlay::image_path(path) else {
        return Err(linux_missing_path_error(path));
    };
    let (_, entry) =
        crate::published_rootfs::lookup_at(crate::published_rootfs::ROOT_HANDLE, &image)
            .ok_or_else(|| linux_missing_path_error(path))?;
    let entry = entry.ok_or(LINUX_EROFS)?;
    linux_copy_up_entry(path, entry)
}

/// Copies the image's `entry` at canonical `path` into the overlay, keeping
/// its mode and owner.
pub(super) fn linux_copy_up_entry(
    path: &[u8],
    entry: crate::published_rootfs::Entry<'_>,
) -> Result<crate::linux_overlay::Handle, u64> {
    let mode = linux_rootfs_mode(entry) & 0o7777;
    let handle = match entry.kind {
        crate::published_rootfs::EntryKind::File | crate::published_rootfs::EntryKind::Hardlink => {
            crate::linux_overlay::create_file(path, mode, entry.data)
        }
        crate::published_rootfs::EntryKind::Directory => {
            crate::linux_overlay::create_directory(path, mode)
        }
        crate::published_rootfs::EntryKind::Symlink => return Err(LINUX_EROFS),
    }
    .ok_or(LINUX_ENOSPC)?;
    // The copy keeps the image file's owner, not its copier's.
    crate::linux_overlay::set_owner(handle, entry.owner, entry.group);
    Ok(handle)
}

/// fchmodat(2) and fchmodat2(2), whose `flags` may be AT_SYMLINK_NOFOLLOW
/// (a symlink's own mode cannot change: EOPNOTSUPP) and AT_EMPTY_PATH (an
/// empty path names `directory` itself).
pub(super) fn linux_fchmodat(directory: u64, path_address: u64, mode: u64, flags: u64) -> u64 {
    let directory = u64::from(directory as u32);
    let mode = u64::from(mode as u32);
    let flags = u64::from(flags as u32);
    if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
        return LINUX_EINVAL;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    if path_length == 0 && flags & LINUX_AT_EMPTY_PATH != 0 {
        return linux_fchmod(directory, mode);
    }
    // A /proc/self/fd/N link names what its descriptor has open: a
    // symlink itself for an O_PATH | O_NOFOLLOW descriptor of one, whose
    // mode cannot change (EOPNOTSUPP since Linux 6.6, chmod09).
    if let Some(descriptor) = linux_descriptor_link_at(directory, &path[..path_length], true) {
        let mut resolved = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        if let Some(length) = linux_descriptor_path(descriptor, &mut resolved) {
            if linux_exact_symlink(&resolved[1..length], &mut target).is_some() {
                return LINUX_EOPNOTSUPP;
            }
        }
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_canonical_path_at(directory, &path[..path_length], &mut canonical) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
    if !follow {
        let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        if linux_exact_symlink(&canonical[..length], &mut target).is_some() {
            return LINUX_EOPNOTSUPP;
        }
    }
    let length = match linux_overlay_lookup_following(&mut canonical, length, follow) {
        Ok((length, _, _)) => length,
        Err(error) => return error,
    };
    match linux_copy_up_path(&canonical[..length]) {
        Ok(handle) => linux_overlay_chmod(handle, mode as u32),
        Err(error) => error,
    }
}

pub(super) fn linux_fchown(descriptor: u64, uid: u64, gid: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    match linux_copy_up_descriptor(descriptor) {
        Ok(handle) => linux_overlay_chown(handle, uid as u32, gid as u32),
        Err(error) => error,
    }
}

pub(super) fn linux_fchownat(
    directory: u64,
    path_address: u64,
    uid: u64,
    gid: u64,
    flags: u64,
) -> u64 {
    let directory = u64::from(directory as u32);
    let uid = u64::from(uid as u32);
    let gid = u64::from(gid as u32);
    let flags = u64::from(flags as u32);
    if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
        return LINUX_EINVAL;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    if path_length == 0 && flags & LINUX_AT_EMPTY_PATH != 0 {
        return linux_fchown(directory, uid, gid);
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_canonical_path_at(directory, &path[..path_length], &mut canonical) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
    let length = match linux_overlay_lookup_following(&mut canonical, length, follow) {
        Ok((length, _, _)) => length,
        Err(error) => return error,
    };
    match linux_copy_up_path(&canonical[..length]) {
        Ok(handle) => linux_overlay_chown(handle, uid as u32, gid as u32),
        Err(error) => error,
    }
}

fn linux_xattr_name(address: u64, output: &mut [u8; 256]) -> Result<usize, u64> {
    // A name longer than XATTR_NAME_MAX is out of range, not too long.
    let length = match copy_linux_c_string(address, output) {
        Err(LINUX_ENAMETOOLONG) => return Err(LINUX_ERANGE),
        result => result?,
    };
    if length == 0 || length > 255 {
        Err(LINUX_ERANGE)
    } else {
        Ok(length)
    }
}

/// The overlay file an xattr call's path names: the symlink itself for
/// the l* calls, what it leads to for the others (`follow`).
/// FS_IOC_GETFLAGS attributes: a file that may not change at all, or only
/// grow.
pub(super) const LINUX_FS_IMMUTABLE_FL: u32 = 0x10;
pub(super) const LINUX_FS_APPEND_FL: u32 = 0x20;
/// The attributes a file keeps, as tmpfs does: immutable, append-only,
/// no-dump and no-atime.
const LINUX_FS_MODIFIABLE_FLAGS: u32 = LINUX_FS_IMMUTABLE_FL | LINUX_FS_APPEND_FL | 0x40 | 0x80;
/// The attributes an ext2 file keeps: those, and secure deletion,
/// undeletion, compression, synchronous updates, no-tail-merging,
/// directory sync and top of a directory hierarchy.
const LINUX_EXT2_MODIFIABLE_FLAGS: u32 = 0x0003_80ff;

/// An overlay file's FS_*_FL attributes.
fn linux_overlay_attributes(handle: crate::linux_overlay::Handle) -> u32 {
    crate::linux_overlay::metadata(handle).map_or(0, |metadata| metadata.attributes)
}

/// FS_IOC_GETFLAGS and FS_IOC_SETFLAGS (chattr and lsattr) on a file or
/// directory of the domain's filesystem; None for other requests and
/// descriptors.
pub(super) fn linux_file_attributes_ioctl(
    descriptor: u64,
    request: u64,
    argument: u64,
) -> Option<u64> {
    const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
    const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
    const FS_IOC32_GETFLAGS: u32 = 0x8004_6601;
    const FS_IOC32_SETFLAGS: u32 = 0x4004_6602;
    let request = request as u32;
    let get = matches!(request, FS_IOC_GETFLAGS | FS_IOC32_GETFLAGS);
    if !get && !matches!(request, FS_IOC_SETFLAGS | FS_IOC32_SETFLAGS) {
        return None;
    }
    let handle = linux_overlay_descriptor_handle(descriptor);
    let image_file = handle.is_none() && linux_rootfs_entry(descriptor).is_some();
    if handle.is_none() && !image_file {
        return None;
    }
    if get {
        let attributes = handle.map_or(0, linux_overlay_attributes);
        return Some(if copy_to_linux_user(argument, &attributes.to_ne_bytes()) {
            0
        } else {
            LINUX_EFAULT
        });
    }
    let mut value = [0_u8; 4];
    if !copy_from_linux_user(argument, &mut value) {
        return Some(LINUX_EFAULT);
    }
    let attributes = u32::from_ne_bytes(value);
    let handle = match handle.map_or_else(|| linux_copy_up_descriptor(descriptor), Ok) {
        Ok(handle) => handle,
        Err(error) => return Some(error),
    };
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return Some(LINUX_EBADF);
    };
    let credentials = current_linux_credentials();
    if !credentials.is_some_and(|credentials| credentials.owns(linux_overlay_file_access(metadata)))
    {
        return Some(LINUX_EPERM);
    }
    if (metadata.attributes ^ attributes) & (LINUX_FS_IMMUTABLE_FL | LINUX_FS_APPEND_FL) != 0
        && !credentials.is_some_and(|credentials| {
            credentials.has(linox_credentials::capability::LINUX_IMMUTABLE)
        })
    {
        return Some(LINUX_EPERM);
    }
    // ext2 keeps the flags its inodes have room for (EXT2_FL_USER_MODIFIABLE),
    // tmpfs only a few.
    let modifiable = if crate::linux_blockfs::owns(handle) {
        LINUX_EXT2_MODIFIABLE_FLAGS
    } else {
        LINUX_FS_MODIFIABLE_FLAGS
    };
    if attributes & !modifiable != 0 {
        return Some(LINUX_EOPNOTSUPP);
    }
    if let Err(error) = linux_check_writable_handle(handle) {
        return Some(error);
    }
    let _ = crate::linux_overlay::set_attributes(handle, attributes);
    Some(0)
}

/// FS_IOC_FIEMAP on a file of a mounted volume: where its data lies on the
/// disk; the overlay's files have no disk (EOPNOTSUPP, as tmpfs). FICLONE,
/// FICLONERANGE and FIDEDUPERANGE need shared extents, which neither has
/// (EOPNOTSUPP). None for other requests and descriptors.
pub(super) fn linux_fiemap_ioctl(descriptor: u64, request: u64, argument: u64) -> Option<u64> {
    const FS_IOC_FIEMAP: u32 = 0xc020_660b;
    const FICLONE: u32 = 0x4004_9409;
    const FICLONERANGE: u32 = 0x4020_940d;
    const FIDEDUPERANGE: u32 = 0xc018_9436;
    const FIEMAP_FLAG_SYNC: u32 = 1;
    const FIEMAP_FLAG_XATTR: u32 = 2;
    const FIEMAP_EXTENT_LAST: u32 = 0x1;
    const FIEMAP_EXTENT_MERGED: u32 = 0x1000;
    const HEADER: usize = 32;
    const EXTENT: usize = 56;
    const LINUX_EBADR: u64 = u64::MAX - 52;
    let request = request as u32;
    if !matches!(
        request,
        FS_IOC_FIEMAP | FICLONE | FICLONERANGE | FIDEDUPERANGE
    ) {
        return None;
    }
    let handle = linux_overlay_descriptor_handle(descriptor);
    if handle.is_none() && linux_rootfs_entry(descriptor).is_none() {
        return None;
    }
    let Some(handle) =
        handle.filter(|handle| request == FS_IOC_FIEMAP && crate::linux_blockfs::owns(*handle))
    else {
        return Some(LINUX_EOPNOTSUPP);
    };
    let mut header = [0_u8; HEADER];
    if !copy_from_linux_user(argument, &mut header) {
        return Some(LINUX_EFAULT);
    }
    let word = |at: usize| u64::from_ne_bytes(header[at..at + 8].try_into().unwrap_or_default());
    let half = |at: usize| u32::from_ne_bytes(header[at..at + 4].try_into().unwrap_or_default());
    let (start, length, flags, capacity) = (word(0), word(8), half(16), half(24));
    let unsupported = flags & !(FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR);
    if unsupported != 0 {
        // The flags the filesystem lacks go back in fm_flags.
        return Some(
            if copy_to_linux_user(argument + 16, &unsupported.to_ne_bytes()) {
                LINUX_EBADR
            } else {
                LINUX_EFAULT
            },
        );
    }
    if length == 0 {
        return Some(LINUX_EINVAL);
    }
    let Some(extents) = crate::linux_blockfs::extents(handle, start, length) else {
        return Some(LINUX_EBADF);
    };
    let mapped = if capacity == 0 {
        // A count of zero asks only how many there are.
        extents.len()
    } else {
        extents.len().min(capacity as usize)
    };
    for (index, extent) in extents.iter().take(capacity as usize).enumerate() {
        let mut record = [0_u8; EXTENT];
        record[0..8].copy_from_slice(&extent.logical.to_ne_bytes());
        record[8..16].copy_from_slice(&extent.physical.to_ne_bytes());
        record[16..24].copy_from_slice(&extent.length.to_ne_bytes());
        let last = if index + 1 == extents.len() {
            FIEMAP_EXTENT_LAST
        } else {
            0
        };
        record[40..44].copy_from_slice(&(FIEMAP_EXTENT_MERGED | last).to_ne_bytes());
        let at = argument + (HEADER + index * EXTENT) as u64;
        if !copy_to_linux_user(at, &record) {
            return Some(LINUX_EFAULT);
        }
    }
    Some(
        if copy_to_linux_user(argument + 20, &(mapped as u32).to_ne_bytes()) {
            0
        } else {
            LINUX_EFAULT
        },
    )
}

fn linux_xattr_path_handle(
    path_address: u64,
    follow: bool,
) -> Result<crate::linux_overlay::Handle, u64> {
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = copy_linux_c_string(path_address, &mut path)?;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = linux_canonical_path_at(
        u64::from(LINUX_AT_FDCWD),
        &path[..path_length],
        &mut canonical,
    )?;
    let (length, _, _) = linux_overlay_lookup_following(&mut canonical, length, follow)?;
    if let Some(metadata) = crate::linux_overlay::lookup(&canonical[..length]) {
        return Ok(metadata.handle);
    }
    if crate::published_rootfs::lookup_at(
        crate::published_rootfs::ROOT_HANDLE,
        &crate::linux_overlay::image_location(&canonical[..length]),
    )
    .is_some()
    {
        Err(LINUX_EROFS)
    } else {
        Err(LINUX_ENOENT)
    }
}

pub(super) fn linux_fsetxattr(
    descriptor: u64,
    name_address: u64,
    value_address: u64,
    value_size: u64,
    flags: u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let flags = u64::from(flags as u32);
    if flags & !(LINUX_XATTR_CREATE | LINUX_XATTR_REPLACE) != 0
        || flags == LINUX_XATTR_CREATE | LINUX_XATTR_REPLACE
    {
        return LINUX_EINVAL;
    }
    let Ok(value_size) = usize::try_from(value_size) else {
        return LINUX_E2BIG;
    };
    if value_size > LINUX_XATTR_SIZE_MAX {
        return LINUX_E2BIG;
    }
    if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
        return linux_fsetxattr_handle(
            handle,
            name_address,
            value_address,
            value_size as u64,
            flags,
        );
    }
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    let mut name = [0_u8; 256];
    let name_length = match linux_xattr_name(name_address, &mut name) {
        Ok(length) => length,
        Err(error) => return error,
    };
    // A device, pipe or socket takes no user.* attributes (EPERM); the
    // kernel's other files take none at all.
    let special = linux_descriptor_stat(descriptor).is_some_and(|stat| {
        let kind = u32::from_ne_bytes(stat[24..28].try_into().unwrap_or_default()) & 0o170_000;
        !matches!(kind, 0o100_000 | 0o040_000)
    });
    if special && name[..name_length].starts_with(b"user.") {
        LINUX_EPERM
    } else {
        LINUX_EROFS
    }
}

pub(super) fn linux_setxattr_path(
    path_address: u64,
    name_address: u64,
    value_address: u64,
    value_size: u64,
    flags: u64,
    follow: bool,
) -> u64 {
    let flags = u64::from(flags as u32);
    let handle = match linux_xattr_path_handle(path_address, follow) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    linux_fsetxattr_handle(handle, name_address, value_address, value_size, flags)
}

fn linux_fsetxattr_handle(
    handle: crate::linux_overlay::Handle,
    name_address: u64,
    value_address: u64,
    value_size: u64,
    flags: u64,
) -> u64 {
    let flags = u64::from(flags as u32);
    // Reuse the descriptor implementation's exact semantics without exposing
    // a synthetic descriptor by performing the same bounded validation here.
    if flags & !(LINUX_XATTR_CREATE | LINUX_XATTR_REPLACE) != 0
        || flags == LINUX_XATTR_CREATE | LINUX_XATTR_REPLACE
    {
        return LINUX_EINVAL;
    }
    let Ok(value_size) = usize::try_from(value_size) else {
        return LINUX_E2BIG;
    };
    if value_size > LINUX_XATTR_SIZE_MAX {
        return LINUX_E2BIG;
    }
    let mut name = [0_u8; 256];
    let name_length = match linux_xattr_name(name_address, &mut name) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let name = &name[..name_length];
    if linux_overlay_attributes(handle) & (LINUX_FS_IMMUTABLE_FL | LINUX_FS_APPEND_FL) != 0 {
        return LINUX_EPERM;
    }
    // user.* attributes belong to regular files and directories only
    // (Linux's xattr_permission: EPERM elsewhere).
    if name.starts_with(b"user.")
        && crate::linux_overlay::metadata(handle).is_some_and(|metadata| {
            !matches!(
                metadata.kind,
                crate::linux_overlay::NodeKind::File | crate::linux_overlay::NodeKind::Directory
            )
        })
    {
        return LINUX_EPERM;
    }
    let exists = crate::linux_overlay::get_xattr_chunk(handle, name, 0, &mut []).is_some();
    if flags == LINUX_XATTR_CREATE && exists {
        return LINUX_EEXIST;
    }
    if flags == LINUX_XATTR_REPLACE && !exists {
        return LINUX_ENODATA;
    }
    let mut faulted = false;
    let stored = crate::linux_overlay::set_xattr_from(
        handle,
        name,
        value_size,
        false,
        false,
        |offset, output| {
            let Some(address) = value_address.checked_add(offset as u64) else {
                faulted = true;
                return false;
            };
            if !copy_from_linux_user(address, output) {
                faulted = true;
                return false;
            }
            true
        },
    );
    if stored {
        0
    } else if faulted {
        LINUX_EFAULT
    } else {
        LINUX_ENOSPC
    }
}

pub(super) fn linux_fgetxattr(
    descriptor: u64,
    name_address: u64,
    value_address: u64,
    value_size: u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let Some(handle) = linux_overlay_descriptor_handle(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_ENODATA
        } else {
            LINUX_EBADF
        };
    };
    linux_fgetxattr_handle(handle, name_address, value_address, value_size)
}

pub(super) fn linux_getxattr_path(
    path_address: u64,
    name_address: u64,
    value_address: u64,
    value_size: u64,
    follow: bool,
) -> u64 {
    let handle = match linux_xattr_path_handle(path_address, follow) {
        Ok(handle) => handle,
        Err(LINUX_EROFS) => return LINUX_ENODATA,
        Err(error) => return error,
    };
    linux_fgetxattr_handle(handle, name_address, value_address, value_size)
}

fn linux_fgetxattr_handle(
    handle: crate::linux_overlay::Handle,
    name_address: u64,
    value_address: u64,
    value_size: u64,
) -> u64 {
    let mut name = [0_u8; 256];
    let name_length = match linux_xattr_name(name_address, &mut name) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let name = &name[..name_length];
    let Some((required, _)) = crate::linux_overlay::get_xattr_chunk(handle, name, 0, &mut [])
    else {
        return LINUX_ENODATA;
    };
    if value_size == 0 {
        return required as u64;
    }
    let Ok(value_size) = usize::try_from(value_size) else {
        return LINUX_ERANGE;
    };
    if value_size < required {
        return LINUX_ERANGE;
    }
    let mut offset = 0;
    let mut chunk = [0_u8; 4096];
    while offset < required {
        let length = (required - offset).min(chunk.len());
        let Some((_, copied)) =
            crate::linux_overlay::get_xattr_chunk(handle, name, offset, &mut chunk[..length])
        else {
            return LINUX_EIO;
        };
        if copied != length
            || !copy_to_linux_user(
                value_address.saturating_add(offset as u64),
                &chunk[..length],
            )
        {
            return LINUX_EFAULT;
        }
        offset += length;
    }
    required as u64
}

pub(super) fn linux_flistxattr(descriptor: u64, list_address: u64, list_size: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let Some(handle) = linux_overlay_descriptor_handle(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            0
        } else {
            LINUX_EBADF
        };
    };
    linux_flistxattr_handle(handle, list_address, list_size)
}

pub(super) fn linux_listxattr_path(
    path_address: u64,
    list_address: u64,
    list_size: u64,
    follow: bool,
) -> u64 {
    let handle = match linux_xattr_path_handle(path_address, follow) {
        Ok(handle) => handle,
        Err(LINUX_EROFS) => return 0,
        Err(error) => return error,
    };
    linux_flistxattr_handle(handle, list_address, list_size)
}

fn linux_flistxattr_handle(
    handle: crate::linux_overlay::Handle,
    list_address: u64,
    list_size: u64,
) -> u64 {
    let Some((required, _)) = crate::linux_overlay::list_xattrs_chunk(handle, 0, &mut []) else {
        return LINUX_EIO;
    };
    if list_size == 0 {
        return required as u64;
    }
    let Ok(list_size) = usize::try_from(list_size) else {
        return LINUX_ERANGE;
    };
    if list_size < required {
        return LINUX_ERANGE;
    }
    let mut offset = 0;
    let mut chunk = [0_u8; 4096];
    while offset < required {
        let length = (required - offset).min(chunk.len());
        let Some((_, copied)) =
            crate::linux_overlay::list_xattrs_chunk(handle, offset, &mut chunk[..length])
        else {
            return LINUX_EIO;
        };
        if copied != length
            || !copy_to_linux_user(list_address.saturating_add(offset as u64), &chunk[..length])
        {
            return LINUX_EFAULT;
        }
        offset += length;
    }
    required as u64
}

pub(super) fn linux_fremovexattr(descriptor: u64, name_address: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let Some(handle) = linux_overlay_descriptor_handle(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_ENODATA
        } else {
            LINUX_EBADF
        };
    };
    linux_fremovexattr_handle(handle, name_address)
}

pub(super) fn linux_removexattr_path(path_address: u64, name_address: u64, follow: bool) -> u64 {
    let handle = match linux_xattr_path_handle(path_address, follow) {
        Ok(handle) => handle,
        Err(LINUX_EROFS) => return LINUX_ENODATA,
        Err(error) => return error,
    };
    linux_fremovexattr_handle(handle, name_address)
}

fn linux_fremovexattr_handle(handle: crate::linux_overlay::Handle, name_address: u64) -> u64 {
    let mut name = [0_u8; 256];
    let name_length = match linux_xattr_name(name_address, &mut name) {
        Ok(length) => length,
        Err(error) => return error,
    };
    if linux_overlay_attributes(handle) & (LINUX_FS_IMMUTABLE_FL | LINUX_FS_APPEND_FL) != 0 {
        return LINUX_EPERM;
    }
    if crate::linux_overlay::remove_xattr(handle, &name[..name_length]) {
        0
    } else {
        LINUX_ENODATA
    }
}

fn linux_timestamp_handle(
    directory: u64,
    path_address: u64,
    flags: u64,
) -> Result<crate::linux_overlay::Handle, u64> {
    if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
        return Err(LINUX_EINVAL);
    }
    let handle = if path_address == 0 {
        if flags != 0 {
            return Err(LINUX_EINVAL);
        }
        linux_copy_up_descriptor(directory)?
    } else {
        let mut path = [0_u8; LINUX_PATH_MAX];
        let path_length = copy_linux_c_string(path_address, &mut path)?;
        if path_length == 0 && flags & LINUX_AT_EMPTY_PATH != 0 {
            linux_copy_up_descriptor(directory)?
        } else if flags & LINUX_AT_SYMLINK_NOFOLLOW == 0 {
            // Resolve the final component through the normal open path before
            // copy-up. RPM commonly timestamps paths such as /etc/os-release
            // whose image entry is a symlink; treating the link as an
            // immutable lower-layer object incorrectly surfaced EROFS/ENOENT.
            let descriptor = linux_openat(directory, path_address, LINUX_O_PATH, 0);
            if descriptor >= LINUX_RETURN_TO_KERNEL {
                return Err(descriptor);
            }
            let copied = linux_copy_up_descriptor(descriptor);
            let _ = linux_descriptor_close(descriptor);
            copied?
        } else {
            let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            let length = linux_canonical_path_at(directory, &path[..path_length], &mut canonical)?;
            if let Some(metadata) = crate::linux_overlay::lookup(&canonical[..length]) {
                metadata.handle
            } else {
                let Some((_, Some(entry))) =
                    linux_rootfs_metadata_path_at(directory, &path[..path_length])
                else {
                    return Err(LINUX_ENOENT);
                };
                let mode = linux_rootfs_mode(entry) & 0o7777;
                let created = match entry.kind {
                    crate::published_rootfs::EntryKind::File
                    | crate::published_rootfs::EntryKind::Hardlink => {
                        crate::linux_overlay::create_file(&canonical[..length], mode, entry.data)
                    }
                    crate::published_rootfs::EntryKind::Directory => {
                        crate::linux_overlay::create_directory(&canonical[..length], mode)
                    }
                    crate::published_rootfs::EntryKind::Symlink => {
                        crate::linux_overlay::create_symlink(&canonical[..length], entry.link)
                    }
                };
                let Some(handle) = created else {
                    return Err(LINUX_ENOSPC);
                };
                handle
            }
        }
    };
    crate::linux_overlay::metadata(handle)
        .map(|_| handle)
        .ok_or(LINUX_ENOENT)
}

fn linux_set_times(handle: crate::linux_overlay::Handle, times: [(i64, i64); 2]) -> u64 {
    if crate::linux_overlay::set_times(handle, times[0], times[1]) {
        0
    } else {
        LINUX_EIO
    }
}

pub(super) fn linux_utimensat(
    directory: u64,
    path_address: u64,
    times_address: u64,
    flags: u64,
) -> u64 {
    let directory = u64::from(directory as u32);
    let flags = u64::from(flags as u32);
    // No path means the descriptor itself, but AT_FDCWD names none: the
    // missing path is then EFAULT, as in Linux (musl's utimes comes here).
    if path_address == 0 && directory == u64::from(LINUX_AT_FDCWD) {
        return LINUX_EFAULT;
    }
    let handle = match linux_timestamp_handle(directory, path_address, flags) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return LINUX_ENOENT;
    };
    let now = linux_realtime_time()
        .map(|(seconds, nanoseconds)| (seconds as i64, nanoseconds as i64))
        .unwrap_or((0, 0));
    let mut times = [now, now];
    let mut only_now = true;
    let mut omitted = 0;
    if times_address != 0 {
        let mut input = [0_u8; 32];
        if !copy_from_linux_user(times_address, &mut input) {
            return LINUX_EFAULT;
        }
        for (index, time) in times.iter_mut().enumerate() {
            let offset = index * 16;
            let seconds = i64::from_ne_bytes(input[offset..offset + 8].try_into().unwrap());
            let nanoseconds =
                i64::from_ne_bytes(input[offset + 8..offset + 16].try_into().unwrap());
            only_now &= nanoseconds == LINUX_UTIME_NOW;
            omitted += usize::from(nanoseconds == LINUX_UTIME_OMIT);
            *time = match nanoseconds {
                LINUX_UTIME_NOW => now,
                LINUX_UTIME_OMIT if index == 0 => metadata.atime,
                LINUX_UTIME_OMIT => metadata.mtime,
                0..=999_999_999 => (seconds, nanoseconds),
                _ => return LINUX_EINVAL,
            };
        }
    }
    // Leaving both times as they are changes nothing and checks nothing.
    if omitted == 2 {
        return 0;
    }
    // An immutable file's times do not change, nor an append-only file's
    // to anything but now.
    if metadata.attributes & LINUX_FS_IMMUTABLE_FL != 0
        || metadata.attributes & LINUX_FS_APPEND_FL != 0 && !only_now
    {
        return LINUX_EPERM;
    }
    if let Err(error) = linux_check_set_times(metadata, only_now) {
        return error;
    }
    linux_set_times(handle, times)
}

/// Who may set a file's times: its owner or root may set any; anyone who
/// may write it may set them to now (EACCES); others none (EPERM).
fn linux_check_set_times(
    metadata: crate::linux_overlay::Metadata,
    only_now: bool,
) -> Result<(), u64> {
    linux_check_writable_handle(metadata.handle)?;
    let file = linux_overlay_file_access(metadata);
    if current_linux_credentials().is_none_or(|credentials| credentials.owns(file)) {
        return Ok(());
    }
    if !only_now {
        return Err(LINUX_EPERM);
    }
    linux_check_access(Some(file), linox_credentials::access::WRITE, false)
}

pub(super) fn linux_utime(path_address: u64, times_address: u64) -> u64 {
    if path_address == 0 {
        return LINUX_EFAULT;
    }
    let handle = match linux_timestamp_handle(u64::from(LINUX_AT_FDCWD), path_address, 0) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return LINUX_ENOENT;
    };
    if let Err(error) = linux_check_set_times(metadata, times_address == 0) {
        return error;
    }
    let now = linux_realtime_time()
        .map(|(seconds, nanoseconds)| (seconds as i64, nanoseconds as i64))
        .unwrap_or((0, 0));
    if times_address == 0 {
        return linux_set_times(handle, [now, now]);
    }
    let mut input = [0_u8; 16];
    if !copy_from_linux_user(times_address, &mut input) {
        return LINUX_EFAULT;
    }
    linux_set_times(
        handle,
        [
            (i64::from_ne_bytes(input[..8].try_into().unwrap()), 0),
            (i64::from_ne_bytes(input[8..].try_into().unwrap()), 0),
        ],
    )
}

pub(super) fn linux_utimes(directory: u64, path_address: u64, times_address: u64) -> u64 {
    // A missing path means the descriptor (futimesat), but there is none
    // for AT_FDCWD (utimes).
    if path_address == 0 && directory as u32 == LINUX_AT_FDCWD {
        return LINUX_EFAULT;
    }
    let handle = match linux_timestamp_handle(directory, path_address, 0) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return LINUX_ENOENT;
    };
    if let Err(error) = linux_check_set_times(metadata, times_address == 0) {
        return error;
    }
    let now = linux_realtime_time()
        .map(|(seconds, nanoseconds)| (seconds as i64, nanoseconds as i64))
        .unwrap_or((0, 0));
    if times_address == 0 {
        return linux_set_times(handle, [now, now]);
    }
    let mut input = [0_u8; 32];
    if !copy_from_linux_user(times_address, &mut input) {
        return LINUX_EFAULT;
    }
    let mut times = [(0_i64, 0_i64); 2];
    for (index, time) in times.iter_mut().enumerate() {
        let offset = index * 16;
        let seconds = i64::from_ne_bytes(input[offset..offset + 8].try_into().unwrap());
        let microseconds = i64::from_ne_bytes(input[offset + 8..offset + 16].try_into().unwrap());
        if !(0..1_000_000).contains(&microseconds) {
            return LINUX_EINVAL;
        }
        *time = (seconds, microseconds * 1_000);
    }
    linux_set_times(handle, times)
}

pub(super) fn linux_truncate(path_address: u64, length: u64) -> u64 {
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let flags = LINUX_O_LARGEFILE | 1;
    let descriptor = linux_landlock_opened(
        linux_open_file_at(u64::from(LINUX_AT_FDCWD), path, path_length, flags, 0, true),
        flags,
    );
    if descriptor >= LINUX_RETURN_TO_KERNEL {
        return descriptor;
    }
    let result = linux_ftruncate(descriptor, length);
    let close = linux_descriptor_close(descriptor);
    if result == 0 {
        close
    } else {
        result
    }
}

pub(super) fn linux_renameat(
    old_directory: u64,
    old_path_address: u64,
    new_directory: u64,
    new_path_address: u64,
    flags: u64,
) -> u64 {
    let old_directory = u64::from(old_directory as u32);
    let new_directory = u64::from(new_directory as u32);
    let flags = u64::from(flags as u32);
    const RENAME_NOREPLACE: u64 = 1;
    const RENAME_EXCHANGE: u64 = 2;
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0
        || flags == RENAME_NOREPLACE | RENAME_EXCHANGE
    {
        return LINUX_EINVAL;
    }
    let mut old_path = [0_u8; LINUX_PATH_MAX];
    let old_length = match copy_linux_c_string(old_path_address, &mut old_path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let mut new_path = [0_u8; LINUX_PATH_MAX];
    let new_length = match copy_linux_c_string(new_path_address, &mut new_path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let mut old_canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let old_length =
        match linux_canonical_path_at(old_directory, &old_path[..old_length], &mut old_canonical) {
            Ok(length) => length,
            Err(error) => return error,
        };
    let mut new_canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let new_length =
        match linux_canonical_path_at(new_directory, &new_path[..new_length], &mut new_canonical) {
            Ok(length) => length,
            Err(error) => return error,
        };
    let Some(source) = crate::linux_overlay::lookup(&old_canonical[..old_length]) else {
        return LINUX_ENOENT;
    };
    if let Err(error) = linux_check_entry_change(&old_canonical[..old_length], true)
        .and_then(|()| linux_check_entry_change(&new_canonical[..new_length], true))
    {
        return error;
    }
    let target = crate::linux_overlay::lookup(&new_canonical[..new_length]);
    let (old, new) = (&old_canonical[..old_length], &new_canonical[..new_length]);
    let space = linux_mount_space();
    if crate::linux_mounts::mount_id_at(space, old) != crate::linux_mounts::mount_id_at(space, new)
    {
        return LINUX_EXDEV;
    }
    // A directory cannot move below itself, nor a name onto a directory
    // above it (which holds it, so is not empty).
    let below = |above: &[u8], path: &[u8]| {
        path.strip_prefix(above)
            .is_some_and(|rest| rest.starts_with(b"/"))
    };
    if below(old, new) {
        return LINUX_EINVAL;
    }
    if below(new, old) {
        return LINUX_ENOTEMPTY;
    }
    if let Err(error) = linux_landlock_check_rename(old, new, flags == RENAME_EXCHANGE) {
        return error;
    }
    if flags != RENAME_EXCHANGE {
        if let Some(target) = target.filter(|target| target.handle != source.handle) {
            let directory = crate::linux_overlay::NodeKind::Directory;
            match (source.kind == directory, target.kind == directory) {
                (true, false) => return LINUX_ENOTDIR,
                (false, true) => return LINUX_EISDIR,
                _ => {}
            }
        }
    }
    // An overlay renames in its upper layer.
    if crate::linux_overlayfs::owns(source.handle) {
        let mode = match flags {
            RENAME_EXCHANGE => crate::linux_overlayfs::RenameMode::Exchange,
            RENAME_NOREPLACE => crate::linux_overlayfs::RenameMode::NoReplace,
            _ => crate::linux_overlayfs::RenameMode::Replace,
        };
        let result = crate::linux_overlayfs::rename(
            &crate::linux_mount_paths::storage(old),
            &crate::linux_mount_paths::storage(new),
            mode,
        );
        linux_reclaim_unlinked_files();
        return match result {
            Some(Ok(())) => 0,
            Some(Err(errno)) => errno.wrapping_neg(),
            None => LINUX_EXDEV,
        };
    }
    // A volume renames in one step, replacing the target as it goes.
    if crate::linux_blockfs::owns(source.handle) {
        let mode = match flags {
            RENAME_EXCHANGE => linox_ext2::RenameMode::Exchange,
            RENAME_NOREPLACE => linox_ext2::RenameMode::NoReplace,
            _ => linox_ext2::RenameMode::Replace,
        };
        let result = crate::linux_blockfs::rename_with(
            &crate::linux_mount_paths::storage(old),
            &crate::linux_mount_paths::storage(new),
            mode,
        );
        linux_reclaim_unlinked_files();
        return match result {
            Some(Ok(())) => 0,
            Some(Err(errno)) => errno.wrapping_neg(),
            None => LINUX_EXDEV,
        };
    }
    if flags == RENAME_EXCHANGE {
        return linux_rename_exchange(&old_canonical[..old_length], &new_canonical[..new_length]);
    }
    if flags == RENAME_NOREPLACE
        && (target.is_some()
            || crate::linux_overlay::image_path(&new_canonical[..new_length]).is_some_and(
                |image| {
                    crate::published_rootfs::lookup_at(crate::published_rootfs::ROOT_HANDLE, &image)
                        .is_some()
                },
            ))
    {
        return LINUX_EEXIST;
    }
    if !linux_overlay_parent_exists(&new_canonical[..new_length]) {
        return linux_missing_path_error(&new_canonical[..new_length]);
    }
    // Renaming a name onto another name of the same file does nothing.
    if target.is_some_and(|target| target.handle == source.handle) {
        return 0;
    }
    if target.is_some_and(|target| {
        !if target.kind == crate::linux_overlay::NodeKind::Directory {
            crate::linux_overlay::unlink(target.handle)
        } else {
            crate::linux_overlay::unlink_path(&new_canonical[..new_length])
        }
    }) {
        return LINUX_ENOTEMPTY;
    }
    if crate::linux_overlay::rename_path(&old_canonical[..old_length], &new_canonical[..new_length])
    {
        0
    } else {
        LINUX_EIO
    }
}

/// renameat2(RENAME_EXCHANGE): swaps the names `old` and `new`, both of
/// which must exist, through a temporary name beside `old`.
fn linux_rename_exchange(old: &[u8], new: &[u8]) -> u64 {
    if old == new {
        return 0;
    }
    if crate::linux_overlay::lookup(new).is_none() {
        if linux_path_access(new).is_none() {
            return LINUX_ENOENT;
        }
        if let Err(error) = linux_copy_up_path(new) {
            return error;
        }
    }
    const SUFFIX: &[u8] = b".linox-exchange";
    let mut temporary = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let Some(end) = old
        .len()
        .checked_add(SUFFIX.len())
        .filter(|end| *end < temporary.len())
    else {
        return LINUX_ENAMETOOLONG;
    };
    temporary[..old.len()].copy_from_slice(old);
    temporary[old.len()..end].copy_from_slice(SUFFIX);
    let temporary = &temporary[..end];
    if crate::linux_overlay::rename_path(old, temporary)
        && crate::linux_overlay::rename_path(new, old)
        && crate::linux_overlay::rename_path(temporary, new)
    {
        0
    } else {
        LINUX_EIO
    }
}

pub(super) fn linux_faccessat(directory: u64, path_address: u64, mode: u64, flags: u64) -> u64 {
    let directory = u64::from(directory as u32);
    let mode = u64::from(mode as u32);
    let flags = u64::from(flags as u32);
    if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EACCESS | LINUX_AT_EMPTY_PATH) != 0
        || mode & !7 != 0
    {
        return LINUX_EINVAL;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let path = &path[..path_length];
    if path.is_empty() {
        if flags & LINUX_AT_EMPTY_PATH == 0 {
            return LINUX_ENOENT;
        }
        let Some(stat) = linux_descriptor_stat(directory) else {
            return LINUX_EBADF;
        };
        let permissions = u32::from_ne_bytes(stat[24..28].try_into().unwrap()) & 0o777;
        let denied = mode & 4 != 0 && permissions & 0o444 == 0
            || mode & 2 != 0 && permissions & 0o222 == 0
            || mode & 1 != 0 && permissions & 0o111 == 0;
        return if denied { LINUX_EACCES } else { 0 };
    }
    // Namespace files are read-only (0444), which root may still write.
    if let Some(reference) = linux_proc_namespace_at(path) {
        return match reference {
            Ok(_) if mode & 1 != 0 => LINUX_EACCES,
            Ok(_) => 0,
            Err(error) => error,
        };
    }
    if let Some(kind) = linux_virtual_mount_path_at(directory, path) {
        // A /proc file the domain may write (sysctls and the like) is
        // writable by root, as its 0644 mode says (shmget02's save of
        // /proc/sys/kernel/shmmax).
        let root = current_linux_credentials().is_some_and(|credentials| credentials.privileged());
        let denied = if kind & LINUX_DEVICE_DIRECTORY != 0 {
            mode & 2 != 0
        } else {
            mode & 1 != 0 || mode & 2 != 0 && !(root && linux_writable_proc_file(kind))
        };
        return if denied { LINUX_EACCES } else { 0 };
    }
    // access(2) judges by the real ids, faccessat(AT_EACCESS) the effective.
    let real_ids = flags & LINUX_AT_EACCESS == 0;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let canonical_result = linux_canonical_path_at(directory, path, &mut canonical);
    if let Err(error @ (LINUX_EACCES | LINUX_ENOTDIR | LINUX_ELOOP)) = canonical_result {
        return error;
    }
    if let Ok(length) = canonical_result {
        // access(2) follows a symlink at the end of the path (a loop is
        // ELOOP: access04) unless AT_SYMLINK_NOFOLLOW.
        let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
        let mut target = canonical;
        let (target_length, metadata) =
            match linux_overlay_lookup_following(&mut target, length, follow) {
                Ok((length, _, metadata)) => (length, metadata),
                Err(error) => return error,
            };
        if let Some(metadata) = metadata {
            if mode & 2 != 0 && linux_read_only_path(&target[..target_length]) {
                return LINUX_EROFS;
            }
            let file = linux_overlay_file_access(metadata);
            return linux_check_access(Some(file), mode as u32, real_ids)
                .map_or_else(|error| error, |()| 0);
        }
    }
    if let Some((_, entry)) = linux_rootfs_path_at(directory, path) {
        // The image's root directory has no entry: r-x for everyone.
        let file = entry.map_or(
            linox_credentials::FileAccess {
                owner: 0,
                group: 0,
                mode: 0o755,
                directory: true,
            },
            |entry| linox_credentials::FileAccess {
                owner: entry.owner,
                group: entry.group,
                mode: entry.mode & 0o7777,
                directory: entry.kind == crate::published_rootfs::EntryKind::Directory,
            },
        );
        return linux_check_access(Some(file), mode as u32, real_ids)
            .map_or_else(|error| error, |()| 0);
    }
    let relative_kind = match linux_relative_path_kind(directory, path) {
        Ok(kind) => kind,
        Err(LINUX_ENOENT) => {
            return canonical_result.map_or(LINUX_ENOENT, |length| {
                linux_missing_path_error(&canonical[..length])
            })
        }
        Err(error) => return error,
    };
    if let Some(kind) = relative_kind {
        let denied = if linux_tmp_file(kind) {
            mode & 1 != 0
        } else if linux_proc_file(kind) {
            mode & 1 != 0 || mode & 2 != 0 && !linux_writable_proc_file(kind)
        } else {
            mode & 2 != 0
        };
        return if denied { LINUX_EACCES } else { 0 };
    }
    let directory = match path {
        path if LinuxCharacterDevice::from_path(path).is_some() => false,
        path if linux_root_directory_kind(path).is_some() => true,
        path if linux_runtime_file_kind(path).is_some() => {
            let kind = linux_runtime_file_kind(path).unwrap_or(0);
            let denied = if linux_tmp_file(kind) {
                mode & 1 != 0
            } else if linux_proc_file(kind) {
                mode & 1 != 0 || mode & 2 != 0 && !linux_writable_proc_file(kind)
            } else {
                mode & 2 != 0
            };
            if denied {
                return LINUX_EACCES;
            }
            return 0;
        }
        _ => {
            return canonical_result.map_or(LINUX_ENOENT, |length| {
                linux_missing_path_error(&canonical[..length])
            })
        }
    };
    if !directory && mode & 1 != 0 || directory && mode & 2 != 0 {
        LINUX_EACCES
    } else {
        0
    }
}

pub(super) fn linux_statx(
    directory: u64,
    path_address: u64,
    flags: u64,
    mask: u64,
    stat_address: u64,
) -> u64 {
    let directory = u64::from(directory as u32);
    let flags = u64::from(flags as u32);
    let mask = u64::from(mask as u32);
    if flags
        & !(LINUX_AT_SYMLINK_NOFOLLOW
            | LINUX_AT_NO_AUTOMOUNT
            | LINUX_AT_EMPTY_PATH
            | LINUX_AT_STATX_SYNC_TYPE)
        != 0
        || mask & u64::from(LINUX_STATX_RESERVED) != 0
    {
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
    if path.is_empty() {
        if flags & LINUX_AT_EMPTY_PATH == 0 {
            return LINUX_ENOENT;
        }
        let Some(stat) = linux_descriptor_stat(directory) else {
            return LINUX_EBADF;
        };
        let statx = linux_statx_from_stat(&stat);
        return if copy_to_linux_user(stat_address, &statx) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(stat) =
        linux_proc_self_exe_stat(directory, path, flags & LINUX_AT_SYMLINK_NOFOLLOW == 0)
    {
        return if copy_to_linux_user(stat_address, &linux_statx_from_stat(&stat)) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(stat) = linux_proc_namespace_stat(path, flags & LINUX_AT_SYMLINK_NOFOLLOW == 0) {
        return match stat {
            Ok(stat) if copy_to_linux_user(stat_address, &linux_statx_from_stat(&stat)) => 0,
            Ok(_) => LINUX_EFAULT,
            Err(error) => error,
        };
    }
    if let Some(stat) =
        linux_descriptor_link_path_stat(directory, path, flags & LINUX_AT_SYMLINK_NOFOLLOW == 0)
    {
        let Some(stat) = stat else {
            return LINUX_ENOENT;
        };
        return if copy_to_linux_user(stat_address, &linux_statx_from_stat(&stat)) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(kind) = linux_virtual_mount_path_at(directory, path) {
        let (inode, mode, size) = if kind & LINUX_DEVICE_DIRECTORY != 0 {
            (
                linux_virtual_mount_directory_inode(path, kind),
                LINUX_STAT_DIRECTORY_MODE,
                0,
            )
        } else {
            (
                linux_regular_file_inode(kind).unwrap_or(0),
                linux_regular_file_mode(kind),
                linux_file_size(kind),
            )
        };
        let mut stat = [0_u8; 256];
        let relative = path.strip_prefix(b"/").unwrap_or(path);
        linux_statx_set_mount(
            &mut stat,
            if relative == b"sys/fs/cgroup" || relative.starts_with(b"sys/fs/cgroup/") {
                LinuxFilesystemKind::Cgroup2
            } else {
                LinuxFilesystemKind::Proc
            },
        );
        stat[4..8].copy_from_slice(&(PAGE_SIZE as u32).to_ne_bytes());
        stat[16..20].copy_from_slice(&1_u32.to_ne_bytes());
        stat[28..30].copy_from_slice(&(mode as u16).to_ne_bytes());
        stat[32..40].copy_from_slice(&inode.to_ne_bytes());
        stat[40..48].copy_from_slice(&size.to_ne_bytes());
        stat[48..56].copy_from_slice(&size.div_ceil(512).to_ne_bytes());
        return if copy_to_linux_user(stat_address, &stat) {
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
    if let Some(length) = canonical_length {
        let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
        let found = match linux_overlay_lookup_following(&mut canonical, length, follow) {
            Ok((_, _, metadata)) => metadata,
            Err(error) => return error,
        };
        if let Some(metadata) = found {
            let stat = linux_statx_from_metadata(metadata);
            return if copy_to_linux_user(stat_address, &stat) {
                0
            } else {
                LINUX_EFAULT
            };
        }
    }
    {
        let oci = if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
            linux_rootfs_metadata_path_at(directory, path)
        } else {
            linux_rootfs_path_at(directory, path)
        };
        if let Some((handle, entry)) = oci {
            let mode = entry.map_or(LINUX_STAT_DIRECTORY_MODE, linux_rootfs_mode);
            let size = entry.map_or(0, |entry| entry.data.len() as u64);
            let mut stat = [0_u8; 256];
            linux_statx_set_mount(&mut stat, LinuxFilesystemKind::Root);
            stat[4..8].copy_from_slice(&(PAGE_SIZE as u32).to_ne_bytes());
            stat[16..20].copy_from_slice(&1_u32.to_ne_bytes());
            let (owner, group) = entry.map_or((0, 0), |entry| (entry.owner, entry.group));
            stat[20..24].copy_from_slice(&owner.to_ne_bytes());
            stat[24..28].copy_from_slice(&group.to_ne_bytes());
            stat[28..30].copy_from_slice(&(mode as u16).to_ne_bytes());
            stat[32..40].copy_from_slice(&linux_rootfs_inode(handle).to_ne_bytes());
            stat[40..48].copy_from_slice(&size.to_ne_bytes());
            stat[48..56].copy_from_slice(&size.div_ceil(512).to_ne_bytes());
            return if copy_to_linux_user(stat_address, &stat) {
                0
            } else {
                LINUX_EFAULT
            };
        }
    }
    // As in newfstatat: /proc names with "." or "..", or relative to a /proc
    // directory, are looked up from the root.
    let mut normalized = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    let path = match canonical_length
        .and_then(|length| linux_proc_normalized_path(path, &canonical[..length], &mut normalized))
    {
        Some(length) => &normalized[..length],
        None => path,
    };
    let relative_kind = match linux_relative_path_kind(directory, path) {
        Ok(kind) => kind,
        Err(error) => return error,
    };
    let (inode, device, mode, size) = match (relative_kind, path) {
        (Some(kind), _) if kind & LINUX_DEVICE_DIRECTORY != 0 => (
            linux_root_directory_inode(kind).unwrap_or(0),
            None,
            LINUX_STAT_DIRECTORY_MODE,
            0,
        ),
        (Some(kind), _) => (
            linux_regular_file_inode(kind).unwrap_or(0),
            None,
            linux_regular_file_mode(kind),
            linux_file_size(kind),
        ),
        (None, path) if LinuxCharacterDevice::from_path(path).is_some() => {
            let (inode, major, minor, permissions) = LinuxCharacterDevice::from_path(path)
                .map_or((0, 0, 0, 0), LinuxCharacterDevice::identity);
            (inode, Some((major, minor)), 0o020_000 | permissions, 0)
        }
        (None, path) if linux_root_directory_kind(path).is_some() => (
            linux_virtual_directory_inode(path, linux_root_directory_kind(path).unwrap_or(0)),
            None,
            LINUX_STAT_DIRECTORY_MODE,
            0,
        ),
        (None, path) => match linux_runtime_file_kind(path) {
            Some(kind) if kind & LINUX_DEVICE_DIRECTORY != 0 => (
                linux_virtual_directory_inode(path, kind),
                None,
                LINUX_STAT_DIRECTORY_MODE,
                0,
            ),
            Some(kind) => (
                linux_regular_file_inode(kind).unwrap_or(0),
                None,
                linux_regular_file_mode(kind),
                linux_file_size(kind),
            ),
            None => return LINUX_ENOENT,
        },
    };
    let mut stat = [0_u8; 256];
    let filesystem = if path == b"/proc" || path.starts_with(b"/proc/") {
        LinuxFilesystemKind::Proc
    } else if path == b"/sys/fs/cgroup" || path.starts_with(b"/sys/fs/cgroup/") {
        LinuxFilesystemKind::Cgroup2
    } else {
        LinuxFilesystemKind::Root
    };
    linux_statx_set_mount(&mut stat, filesystem);
    stat[4..8].copy_from_slice(&(PAGE_SIZE as u32).to_ne_bytes());
    stat[16..20].copy_from_slice(&1_u32.to_ne_bytes());
    stat[28..30].copy_from_slice(&(mode as u16).to_ne_bytes());
    stat[32..40].copy_from_slice(&inode.to_ne_bytes());
    stat[40..48].copy_from_slice(&size.to_ne_bytes());
    stat[48..56].copy_from_slice(&size.div_ceil(512).to_ne_bytes());
    if let Some((major, minor)) = device {
        stat[128..132].copy_from_slice(&major.to_ne_bytes());
        stat[132..136].copy_from_slice(&minor.to_ne_bytes());
    }
    if !copy_to_linux_user(stat_address, &stat) {
        return LINUX_EFAULT;
    }
    0
}

/// A `struct statx` with the fields a `struct stat` has.
fn linux_statx_from_stat(stat: &[u8; LINUX_STAT_SIZE]) -> [u8; 256] {
    let word = |offset: usize| u64::from_ne_bytes(stat[offset..offset + 8].try_into().unwrap());
    let half = |offset: usize| u32::from_ne_bytes(stat[offset..offset + 4].try_into().unwrap());
    let mut statx = [0_u8; 256];
    linux_statx_set_mount(&mut statx, LinuxFilesystemKind::Root);
    statx[4..8].copy_from_slice(&(word(56) as u32).to_ne_bytes());
    statx[16..20].copy_from_slice(&(word(16) as u32).to_ne_bytes());
    statx[20..24].copy_from_slice(&half(28).to_ne_bytes());
    statx[24..28].copy_from_slice(&half(32).to_ne_bytes());
    statx[28..30].copy_from_slice(&(half(24) as u16).to_ne_bytes());
    statx[32..40].copy_from_slice(&word(8).to_ne_bytes());
    statx[40..48].copy_from_slice(&word(48).to_ne_bytes());
    statx[48..56].copy_from_slice(&word(64).to_ne_bytes());
    // Access, change and modification times: seconds then nanoseconds.
    for (from, to) in [(72, 64), (104, 96), (88, 112)] {
        statx[to..to + 8].copy_from_slice(&word(from).to_ne_bytes());
        statx[to + 8..to + 12].copy_from_slice(&(word(from + 8) as u32).to_ne_bytes());
    }
    let (major, minor) = linux_device_numbers(word(40) as u32);
    statx[128..132].copy_from_slice(&major.to_ne_bytes());
    statx[132..136].copy_from_slice(&minor.to_ne_bytes());
    // A file on a block device's filesystem names that device.
    let filesystem = word(0) as u32;
    if filesystem != 0 {
        let (major, minor) = linux_device_numbers(filesystem);
        statx[136..140].copy_from_slice(&major.to_ne_bytes());
        statx[140..144].copy_from_slice(&minor.to_ne_bytes());
    }
    statx
}

/// statx(2) of an overlay or volume file: its stat, and the inode flags
/// statx shows as attributes (those tmpfs shows, and on ext2 also
/// compression).
fn linux_statx_from_metadata(metadata: crate::linux_overlay::Metadata) -> [u8; 256] {
    const STATX_ATTR_COMPRESSED: u64 = 0x4;
    const STATX_ATTR_IMMUTABLE: u64 = 0x10;
    const STATX_ATTR_APPEND: u64 = 0x20;
    const STATX_ATTR_NODUMP: u64 = 0x40;
    let mut statx = linux_statx_from_stat(&linux_overlay_stat(metadata));
    let mut supported = STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND | STATX_ATTR_NODUMP;
    if crate::linux_blockfs::owns(metadata.handle) {
        supported |= STATX_ATTR_COMPRESSED;
    }
    // The FS_*_FL bits of these attributes have the same values.
    let attributes = u64::from(metadata.attributes) & supported;
    statx[8..16].copy_from_slice(&attributes.to_ne_bytes());
    statx[56..64].copy_from_slice(&supported.to_ne_bytes());
    // The creation time, where the filesystem keeps one (ext4's inodes).
    if let Some((seconds, nanoseconds)) = metadata.btime {
        const STATX_BTIME: u32 = 0x800;
        let mask = u32::from_ne_bytes(statx[..4].try_into().unwrap_or_default()) | STATX_BTIME;
        statx[..4].copy_from_slice(&mask.to_ne_bytes());
        statx[80..88].copy_from_slice(&seconds.to_ne_bytes());
        statx[88..92].copy_from_slice(&(nanoseconds as u32).to_ne_bytes());
    }
    statx
}

/// statx(2) with the id of the domain mount a file of the root's lies on,
/// reporting the mount's unique id (listmount's and statmount's) instead
/// of the old one when STATX_MNT_ID_UNIQUE is asked.
pub(super) fn linux_statx_unique_mount(
    directory: u64,
    path_address: u64,
    flags: u64,
    mask: u64,
    stat_address: u64,
) -> u64 {
    const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
    let result = linux_statx(directory, path_address, flags, mask, stat_address);
    if result != 0 {
        return result;
    }
    let mut stat = [0_u8; 256];
    if !copy_from_linux_user(stat_address, &mut stat) {
        return result;
    }
    linux_statx_extras(directory, path_address, flags, mask, &mut stat);
    let reported = u32::from_ne_bytes(stat[..4].try_into().unwrap_or([0; 4]));
    let mut mount = u64::from_ne_bytes(stat[144..152].try_into().unwrap_or([0; 8]));
    let domain_mount = (reported & LINUX_STATX_MNT_ID != 0
        && mount == u64::from(crate::linux_mounts::ROOT_ID))
    .then(|| linux_statx_domain_mount(directory, path_address, flags))
    .flatten();
    if let Some(id) = domain_mount {
        mount = u64::from(id);
    }
    stat[144..152].copy_from_slice(&mount.to_ne_bytes());
    if mask as u32 & STATX_MNT_ID_UNIQUE != 0 && reported & LINUX_STATX_MNT_ID != 0 {
        if let Some(unique) = linux_mount::current_unique_mount_id(mount) {
            stat[..4].copy_from_slice(
                &(reported & !LINUX_STATX_MNT_ID | STATX_MNT_ID_UNIQUE).to_ne_bytes(),
            );
            stat[144..152].copy_from_slice(&unique.to_ne_bytes());
        }
    }
    if copy_to_linux_user(stat_address, &stat) {
        0
    } else {
        LINUX_EFAULT
    }
}

/// The canonical path of what statx found (`path_address` from
/// `directory`, or the descriptor with AT_EMPTY_PATH), and, when `lookup`,
/// its file's metadata with a final symlink followed unless
/// AT_SYMLINK_NOFOLLOW. Without `lookup` a final symlink stays: a mount
/// point is never one, so the path tells a mount root all the same unless
/// a symlink leads to one.
fn linux_statx_target(
    directory: u64,
    path_address: u64,
    flags: u64,
    lookup: bool,
) -> Option<(LinuxInotifyPath, Option<crate::linux_overlay::Metadata>)> {
    let directory = u64::from(directory as u32);
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = copy_linux_c_string(path_address, &mut path).ok()?;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    if length == 0 {
        if flags & LINUX_AT_EMPTY_PATH == 0 {
            return None;
        }
        let length = linux_descriptor_path(directory, &mut canonical)?;
        let relative = canonical[..length]
            .strip_prefix(b"/")
            .unwrap_or(&canonical[..length]);
        let metadata = linux_overlay_descriptor_handle(directory)
            .filter(|_| lookup)
            .and_then(crate::linux_overlay::metadata);
        return Some((linux_heap_path(relative)?, metadata));
    }
    let length = match linux_canonical_path_at(directory, &path[..length], &mut canonical) {
        Ok(length) => length,
        Err(LINUX_EISDIR) => 0,
        Err(_) => return None,
    };
    if !lookup {
        return Some((linux_heap_path(&canonical[..length])?, None));
    }
    let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
    let (length, _, metadata) =
        linux_overlay_lookup_following(&mut canonical, length, follow).ok()?;
    Some((linux_heap_path(&canonical[..length])?, metadata))
}

/// Whether canonical `path` is the root of a mount: the root's, /proc's,
/// cgroup2's or a domain mount's.
fn linux_mount_root(path: &[u8]) -> bool {
    if matches!(path, b"" | b"proc" | b"sys/fs/cgroup") {
        return true;
    }
    let space = linux_mount_space();
    let id = crate::linux_mounts::mount_id_at(space, path);
    crate::linux_mounts::with_mount(space, id, |mount| mount.path == path).unwrap_or(false)
}

/// What statx adds to the stat it found, as Linux's VFS and filesystems
/// do: STATX_ATTR_MOUNT_ROOT (every filesystem knows it), and with
/// STATX_DIOALIGN the direct I/O alignment of a volume's regular file (its
/// device's 512-byte sectors, as ext4 gives it) or of a loop device (its
/// queue's DMA alignment and logical block size).
fn linux_statx_extras(
    directory: u64,
    path_address: u64,
    flags: u64,
    mask: u64,
    stat: &mut [u8; 256],
) {
    use crate::linux_overlay::NodeKind;
    const STATX_ATTR_MOUNT_ROOT: u64 = 0x2000;
    const STATX_DIOALIGN: u32 = 0x2000;
    const SECTOR_SIZE: u32 = 512;
    let word =
        |stat: &[u8; 256], at: usize| u64::from_ne_bytes(stat[at..at + 8].try_into().unwrap());
    let attributes_mask = word(stat, 56) | STATX_ATTR_MOUNT_ROOT;
    stat[56..64].copy_from_slice(&attributes_mask.to_ne_bytes());
    let dio = mask as u32 & STATX_DIOALIGN != 0;
    let Some((path, metadata)) = linux_statx_target(directory, path_address, flags, dio) else {
        return;
    };
    if linux_mount_root(&path) {
        let attributes = word(stat, 8) | STATX_ATTR_MOUNT_ROOT;
        stat[8..16].copy_from_slice(&attributes.to_ne_bytes());
    }
    if !dio {
        return;
    }
    let alignment = metadata.and_then(|metadata| match metadata.kind {
        NodeKind::File if crate::linux_blockfs::owns(metadata.handle) => {
            Some((SECTOR_SIZE, SECTOR_SIZE))
        }
        NodeKind::BlockDevice => {
            let (major, minor) = linux_device_numbers(metadata.device);
            (major == crate::linux_loop::MAJOR)
                .then(|| crate::linux_loop::block_size_of(minor))
                .flatten()
                .map(|block_size| (crate::linux_loop::DMA_ALIGNMENT + 1, block_size))
        }
        _ => None,
    });
    if let Some((memory, offset)) = alignment {
        let reported = u32::from_ne_bytes(stat[..4].try_into().unwrap()) | STATX_DIOALIGN;
        stat[..4].copy_from_slice(&reported.to_ne_bytes());
        stat[152..156].copy_from_slice(&memory.to_ne_bytes());
        stat[156..160].copy_from_slice(&offset.to_ne_bytes());
    }
}

/// The domain mount the file statx found lies on, if any: the deepest one
/// at or above its path.
fn linux_statx_domain_mount(directory: u64, path_address: u64, flags: u64) -> Option<u32> {
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = copy_linux_c_string(path_address, &mut path).ok()?;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = if length == 0 {
        if flags & LINUX_AT_EMPTY_PATH == 0 {
            return None;
        }
        linux_descriptor_path(u64::from(directory as u32), &mut canonical)?
    } else {
        match linux_canonical_path_at(u64::from(directory as u32), &path[..length], &mut canonical)
        {
            Ok(length) => length,
            Err(LINUX_EISDIR) => 0,
            Err(_) => return None,
        }
    };
    let id = crate::linux_mounts::mount_id_at(linux_mount_space(), &canonical[..length]);
    (id != crate::linux_mounts::ROOT_ID).then_some(id)
}

/// Whether the caller may see the domain's mounts (its root and /proc):
/// from a chroot below them neither is reachable, and seeing them then
/// needs CAP_SYS_ADMIN, as Linux's listmount and statmount require.
pub(super) fn linux_mounts_visible() -> bool {
    !linux_chrooted() || linux_has_capability(linox_credentials::capability::SYS_ADMIN)
}

fn linux_statx_set_mount(stat: &mut [u8; 256], filesystem: LinuxFilesystemKind) {
    let (device_minor, mount_id) = match filesystem {
        LinuxFilesystemKind::Root => (1_u32, 1_u64),
        LinuxFilesystemKind::Proc => (2, 2),
        LinuxFilesystemKind::Cgroup2 => (3, 3),
        LinuxFilesystemKind::Pipe
        | LinuxFilesystemKind::Socket
        | LinuxFilesystemKind::Anonymous => (0, 0),
    };
    stat[..4].copy_from_slice(&(LINUX_STATX_BASIC_STATS | LINUX_STATX_MNT_ID).to_ne_bytes());
    stat[140..144].copy_from_slice(&device_minor.to_ne_bytes());
    stat[144..152].copy_from_slice(&mount_id.to_ne_bytes());
}

pub(super) fn linux_syncfs(descriptor: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    if linux_descriptor_open(descriptor) {
        crate::linux_blockfs::sync_all();
        0
    } else {
        LINUX_EBADF
    }
}

pub(super) fn linux_readahead(descriptor: u64, offset: u64, count: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    if (offset as i64) < 0 {
        return LINUX_EINVAL;
    }
    let state = linux_device_descriptor(descriptor);
    if !matches!(state & 3, LINUX_DESCRIPTOR_INPUT | 3) || linux_path_descriptor(descriptor) {
        return LINUX_EBADF;
    }
    // A directory or another kind of file has no pages to read ahead.
    if state & LINUX_DEVICE_DIRECTORY != 0 || linux_inotify_descriptor(descriptor) {
        return LINUX_EINVAL;
    }
    if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
        // A volume's file comes into the page cache; the image's and the
        // in-memory overlay's contents are resident already.
        let _ = crate::linux_blockfs::read_ahead(handle, offset, count);
        0
    } else if linux_rootfs_entry(descriptor).is_some() || linux_regular_file(state).is_some() {
        0
    } else {
        LINUX_EINVAL
    }
}

pub(super) fn linux_fadvise64(descriptor: u64, offset: u64, length: u64, advice: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let advice = advice as u32;
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    if linux_pipe_descriptor(descriptor) {
        return LINUX_ESPIPE;
    }
    if (offset as i64) < 0 || (length as i64) < 0 || advice > 5 {
        return LINUX_EINVAL;
    }
    // POSIX_FADV_WILLNEED reads a volume's file into the page cache, as
    // readahead does (a length of 0: to the end). The image's and the
    // in-memory filesystems' data is resident, so their hints are met.
    const POSIX_FADV_WILLNEED: u32 = 3;
    if advice == POSIX_FADV_WILLNEED {
        if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
            let length = if length == 0 { u64::MAX } else { length };
            let _ = crate::linux_blockfs::read_ahead(handle, offset, length);
        }
    }
    0
}

pub(super) fn linux_descriptor_stat(descriptor: u64) -> Option<[u8; LINUX_STAT_SIZE]> {
    if linux_console_descriptor_open(descriptor)
        || descriptor == 2 && X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::SeqCst)
    {
        return Some(linux_console_stat());
    }
    // Pipes and sockets are numbered by their socket slot, as Linux's
    // pipefs and sockfs inodes tell them apart.
    let socket_inode = || 0x1000 + linux_socket_slot(descriptor).map_or(0, u64::from);
    if linux_pipe_descriptor(descriptor) {
        return Some(linux_stat(LINUX_STAT_FIFO_MODE, socket_inode()));
    }
    if let Some((end, index)) = linux_pty_descriptor(descriptor) {
        return Some(linux_pty_stat(end, index));
    }
    if let Some((class, id)) = linux_object_descriptor(descriptor) {
        if class == crate::linux_drm::CLASS_FILE {
            // A character device, 226:128.
            let mut stat = linux_stat(0o020_666, 50);
            stat[40..48].copy_from_slice(&u64::from(crate::linux_drm::NODE_DEVICE).to_ne_bytes());
            return Some(stat);
        }
        if class == LINUX_USERFAULTFD_DEVICE_CLASS {
            let mut stat = linux_stat(0o020_600, 0x2000 + u64::from(LINUX_USERFAULTFD_DEVICE));
            stat[40..48].copy_from_slice(&u64::from(LINUX_USERFAULTFD_DEVICE).to_ne_bytes());
            return Some(stat);
        }
        if class == LINUX_TUN_CLASS {
            let mut stat = linux_stat(0o020_666, 0x2000 + u64::from(LINUX_TUN_DEVICE));
            stat[40..48].copy_from_slice(&u64::from(LINUX_TUN_DEVICE).to_ne_bytes());
            return Some(stat);
        }
        if class == crate::linux_kmsg::CLASS_READER {
            // A character device, 1:11, owned by root.
            let device = linux_device_number(crate::linux_kmsg::MAJOR, crate::linux_kmsg::MINOR);
            let mut stat = linux_stat(0o020_644, 0x2000 + u64::from(device));
            stat[40..48].copy_from_slice(&u64::from(device).to_ne_bytes());
            return Some(stat);
        }
        if let Some((device, block)) = linux_block_descriptor_device(class, id) {
            // A block device (7:N, 1:N) or /dev/loop-control (10:237),
            // owned by root and the disk group.
            let kind = if block { 0o060_000 } else { 0o020_000 };
            let mut stat = linux_stat(kind | 0o660, 0x2000 + u64::from(device));
            stat[32..36].copy_from_slice(&6_u32.to_ne_bytes());
            stat[40..48].copy_from_slice(&u64::from(device).to_ne_bytes());
            return Some(stat);
        }
        return Some(linux_stat(LINUX_STAT_ANONYMOUS_MODE, 4));
    }
    if linux_socket_slot(descriptor).is_some() {
        return Some(linux_stat(LINUX_STAT_SOCKET_MODE, socket_inode()));
    }
    if let Some(reference) = linux_namespace_reference(descriptor) {
        return Some(linux_namespace_stat(reference, true));
    }
    if linux_epoll_descriptor(descriptor)
        || linux_eventfd_descriptor(descriptor)
        || linux_timerfd_descriptor(descriptor)
        || linux_userfaultfd_descriptor(descriptor)
        || linux_fanotify_descriptor(descriptor)
        || linux_io_uring_descriptor(descriptor)
    {
        return Some(linux_stat(LINUX_STAT_ANONYMOUS_MODE, 4));
    }
    if let Some(metadata) =
        linux_overlay_descriptor_handle(descriptor).and_then(crate::linux_overlay::metadata)
    {
        return Some(linux_overlay_stat(metadata));
    }
    let rootfs_handle = linux_rootfs_descriptor(descriptor);
    if rootfs_handle != 0 {
        let entry = (rootfs_handle != crate::published_rootfs::ROOT_HANDLE)
            .then(|| crate::published_rootfs::entry(rootfs_handle))
            .flatten();
        return Some(linux_rootfs_stat(rootfs_handle, entry));
    }
    let device = linux_device_descriptor(descriptor);
    if let Some(graphics) = linux_graphics_device(device) {
        return Some(linux_graphics_stat(graphics));
    }
    (device != 0).then(|| {
        if device & LINUX_DEVICE_DIRECTORY != 0 {
            let inode = linux_proc_directory_descriptor_pid(descriptor).map_or_else(
                || linux_root_directory_inode(device).unwrap_or(0),
                linux_proc_pid_directory_inode,
            );
            linux_stat(LINUX_STAT_DIRECTORY_MODE, inode)
        } else if device & LINUX_FILE_MASK != 0 {
            linux_regular_file_stat(device)
        } else {
            LinuxCharacterDevice::from_kind(device).stat()
        }
    })
}

pub(super) fn linux_stat(mode: u32, inode: u64) -> [u8; LINUX_STAT_SIZE] {
    let mut stat = [0_u8; LINUX_STAT_SIZE];
    stat[8..16].copy_from_slice(&inode.to_ne_bytes());
    stat[16..24].copy_from_slice(&1_u64.to_ne_bytes());
    stat[24..28].copy_from_slice(&mode.to_ne_bytes());
    stat[56..64].copy_from_slice(&(PAGE_SIZE as u64).to_ne_bytes());
    stat
}

/// The descriptor a `/proc/self/fd/N` magic link in `path` names, with
/// `path` taken relative to `directory` as a path argument is: also
/// `/proc/thread-self/fd/N`, the caller's own `/proc/PID/fd/N`, `/dev/fd/N`
/// (`/dev/fd` links to `/proc/self/fd`) and, through a directory descriptor
/// of `/proc/self/fd`, plain `N`. With `follow`, also `/dev/stdin`,
/// `/dev/stdout` and `/dev/stderr`, links to the first three.
pub(super) fn linux_descriptor_link_at(directory: u64, path: &[u8], follow: bool) -> Option<u64> {
    let mut absolute = [0_u8; 96];
    let path = if path.starts_with(b"/") {
        path
    } else {
        if directory as u32 == LINUX_AT_FDCWD {
            return None;
        }
        let parent = linux_measured_directory_path(linux_device_descriptor(directory))?;
        let length = 1 + parent.len() + 1 + path.len();
        let output = absolute.get_mut(..length)?;
        output[0] = b'/';
        output[1..1 + parent.len()].copy_from_slice(parent);
        output[1 + parent.len()] = b'/';
        output[2 + parent.len()..].copy_from_slice(path);
        output
    };
    let digits = if let Some(rest) = path.strip_prefix(b"/proc/") {
        let separator = rest.iter().position(|byte| *byte == b'/')?;
        let owner = &rest[..separator];
        let own = |id: u32| {
            let mut number = [0_u8; 10];
            let mut length = 0;
            let mut value = id;
            loop {
                number[length] = b'0' + (value % 10) as u8;
                length += 1;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            number[..length].reverse();
            owner == &number[..length]
        };
        if !(owner == b"self"
            || owner == b"thread-self"
            || own(current_linux_process_pid())
            || current_linux_tid().is_some_and(own))
        {
            return None;
        }
        rest[separator + 1..].strip_prefix(b"fd/")?
    } else if let Some(digits) = path.strip_prefix(b"/dev/fd/") {
        digits
    } else {
        return match (follow, path) {
            (true, b"/dev/stdin") => Some(0),
            (true, b"/dev/stdout") => Some(1),
            (true, b"/dev/stderr") => Some(2),
            _ => None,
        };
    };
    if digits.is_empty() || digits.len() > 10 {
        return None;
    }
    digits.iter().try_fold(0_u64, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u64::from(byte - b'0'))
    })
}

/// What `readlink` shows for `descriptor`'s `/proc/self/fd` entry: the
/// path of its file, or Linux's name for one that has none.
pub(super) fn linux_descriptor_link_target(
    descriptor: u64,
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Option<usize> {
    if let Some(length) = linux_descriptor_path(descriptor, output) {
        return Some(length);
    }
    if !linux_descriptor_open(descriptor) {
        return None;
    }
    if let Some((end, index)) = linux_pty_descriptor(descriptor) {
        return linux_pty_link_target(end, index, output);
    }
    let state = linux_device_descriptor(descriptor);
    let inode = linux_descriptor_stat(descriptor).map_or(0, |stat| {
        u64::from_ne_bytes(stat[8..16].try_into().unwrap_or([0; 8]))
    });
    let block = linux_block_descriptor(descriptor);
    let block_minor = block.and_then(|(class, id)| match class {
        crate::linux_loop::CLASS_DEVICE => crate::linux_loop::minor(id),
        crate::linux_ramdisk::CLASS_DISK => crate::linux_ramdisk::minor(id),
        _ => None,
    });
    let (prefix, numbered): (&[u8], bool) = if linux_userfaultfd_descriptor(descriptor) {
        (b"anon_inode:[userfaultfd]", false)
    } else if linux_perf_descriptor(descriptor) {
        (b"anon_inode:[perf_event]", false)
    } else if linux_pipe_descriptor(descriptor) {
        (b"pipe:[", true)
    } else if let Some((class, _)) = block {
        match class {
            crate::linux_loop::CLASS_DEVICE => (b"/dev/loop", true),
            crate::linux_ramdisk::CLASS_DISK => (b"/dev/ram", true),
            crate::linux_kmsg::CLASS_READER => (b"/dev/kmsg", false),
            _ => (b"/dev/loop-control", false),
        }
    } else if linux_socket_slot(descriptor).is_some() {
        (b"socket:[", true)
    } else if linux_epoll_descriptor(descriptor) {
        (b"anon_inode:[eventpoll]", false)
    } else if linux_eventfd_descriptor(descriptor) {
        (b"anon_inode:[eventfd]", false)
    } else if linux_timerfd_descriptor(descriptor) {
        (b"anon_inode:[timerfd]", false)
    } else if linux_signalfd_descriptor(descriptor) {
        (b"anon_inode:[signalfd]", false)
    } else if linux_inotify_descriptor(descriptor) {
        (b"anon_inode:inotify", false)
    } else if linux_pidfd_descriptor(descriptor) {
        (b"anon_inode:[pidfd]", false)
    } else if linux_fanotify_descriptor(descriptor) {
        (b"anon_inode:[fanotify]", false)
    } else if linux_io_uring_descriptor(descriptor) {
        (b"anon_inode:[io_uring]", false)
    } else if linux_landlock_ruleset_descriptor(descriptor) {
        (b"anon_inode:[landlock-ruleset]", false)
    } else if linux_object_descriptor(descriptor)
        .is_some_and(|(class, _)| class == crate::linux_drm::CLASS_FILE)
    {
        (b"/dev/dri/renderD128", false)
    } else if linux_object_descriptor(descriptor)
        .is_some_and(|(class, _)| class == LINUX_USERFAULTFD_DEVICE_CLASS)
    {
        (b"/dev/userfaultfd", false)
    } else if let Some(device) = linux_graphics_device(state) {
        match device {
            LinuxGraphicsDevice::Framebuffer => (b"/dev/fb0", false),
            LinuxGraphicsDevice::Input(_) => (b"/dev/input/event", true),
        }
    } else {
        match LinuxCharacterDevice::from_kind(state) {
            // The console of the standard descriptors has no kind bits.
            LinuxCharacterDevice::Null if state == 0 => (b"/dev/console", false),
            LinuxCharacterDevice::Null => (b"/dev/null", false),
            LinuxCharacterDevice::Zero => (b"/dev/zero", false),
            LinuxCharacterDevice::Full => (b"/dev/full", false),
            LinuxCharacterDevice::Random | LinuxCharacterDevice::Urandom => {
                (b"/dev/urandom", false)
            }
            LinuxCharacterDevice::Console | LinuxCharacterDevice::Tty => (b"/dev/console", false),
        }
    };
    output.get_mut(..prefix.len())?.copy_from_slice(prefix);
    let mut length = prefix.len();
    if numbered {
        let number = match (linux_graphics_device(state), block_minor) {
            (_, Some(minor)) => u64::from(minor),
            (Some(LinuxGraphicsDevice::Input(device)), _) => device as u64,
            _ => inode,
        };
        let mut digits = [0_u8; 20];
        let mut count = 0;
        let mut value = number;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for digit in digits[..count].iter().rev() {
            *output.get_mut(length)? = *digit;
            length += 1;
        }
        if prefix.ends_with(b"[") {
            *output.get_mut(length)? = b']';
            length += 1;
        }
    }
    Some(length)
}

/// lstat of `descriptor`'s `/proc/self/fd` entry: a symbolic link, as
/// listed by getdents (inode 1000 + N), its size the target's length.
fn linux_descriptor_link_stat(descriptor: u64) -> Option<[u8; LINUX_STAT_SIZE]> {
    let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = linux_descriptor_link_target(descriptor, &mut target)?;
    let mut stat = linux_stat(0o120_777, 1_000 + descriptor);
    stat[48..56].copy_from_slice(&(length as u64).to_ne_bytes());
    Some(stat)
}

/// stat of what the magic link `path` names (`linux_descriptor_link_at`)
/// when following it, else of the link; `Some(None)` when its descriptor is
/// not open, `None` when `path` is no such link.
pub(super) fn linux_descriptor_link_path_stat(
    directory: u64,
    path: &[u8],
    follow: bool,
) -> Option<Option<[u8; LINUX_STAT_SIZE]>> {
    let descriptor = linux_descriptor_link_at(directory, path, follow)?;
    Some(if follow {
        linux_descriptor_stat(descriptor)
    } else {
        linux_descriptor_link_stat(descriptor)
    })
}

pub(super) fn linux_descriptor_path(
    descriptor: u64,
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Option<usize> {
    if !linux_descriptor_open(descriptor) {
        return None;
    }
    output[0] = b'/';
    if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
        return linux_shown_overlay_path(handle, &mut output[1..]).map(|length| length + 1);
    }
    let rootfs = linux_rootfs_descriptor(descriptor);
    if rootfs != 0 {
        return linux_shown_rootfs_path(rootfs, &mut output[1..]).map(|length| length + 1);
    }
    let state = linux_device_descriptor(descriptor);
    linux_measured_directory_path(state).and_then(|path| {
        output.get_mut(1..1 + path.len())?.copy_from_slice(path);
        Some(path.len() + 1)
    })
}

pub(super) fn linux_fstatfs(descriptor: u64, stat_address: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
        let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        if let Some(data) = crate::linux_overlay::copy_path(handle, &mut path)
            .and_then(|length| linux_tmpfs_statfs_data(&path[..length]))
        {
            return if copy_to_linux_user(stat_address, &data) {
                0
            } else {
                LINUX_EFAULT
            };
        }
        if let Some(statfs) = crate::linux_blockfs::statfs_of(handle) {
            let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            let length = crate::linux_overlay::copy_path(handle, &mut path).unwrap_or(0);
            return if copy_to_linux_user(
                stat_address,
                &linux_volume_statfs_data(statfs, &path[..length]),
            ) {
                0
            } else {
                LINUX_EFAULT
            };
        }
    }
    if copy_to_linux_user(
        stat_address,
        &linux_statfs_data(linux_statfs_descriptor_kind(descriptor)),
    ) {
        0
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_regular_file_stat(state: u16) -> [u8; LINUX_STAT_SIZE] {
    let mut stat = linux_stat(
        linux_regular_file_mode(state),
        linux_regular_file_inode(state).unwrap_or(0),
    );
    let size = linux_file_size(state);
    stat[48..56].copy_from_slice(&size.to_ne_bytes());
    stat[64..72].copy_from_slice(&size.div_ceil(512).to_ne_bytes());
    stat
}

fn linux_regular_file_mode(state: u16) -> u32 {
    if linux_tmp_file(state) {
        0o100600
    } else if linux_writable_proc_file(state) {
        0o100644
    } else if linux_proc_file(state) {
        0o100444
    } else {
        LINUX_STAT_REGULAR_MODE
    }
}

pub(super) fn linux_file_size(state: u16) -> u64 {
    if state & !3 == LINUX_FILE_RESOLV_CONF {
        linux_resolv_conf().1 as u64
    } else if linux_proc_sysvipc_file(state) {
        let mut file = [0_u8; LINUX_PROC_SYSVIPC_CAPACITY];
        linux_proc_sysvipc_contents(state, &mut file).unwrap_or(0) as u64
    } else if linux_proc_keys_file(state) {
        linux_proc_keys_contents(state).map_or(0, |text| text.len() as u64)
    } else if state & !3 == LINUX_FILE_PROC_SWAPS {
        crate::linux_swap::proc_swaps(linux_execution_instance())
            .map_or(0, |text| text.len() as u64)
    } else if state & !3 == LINUX_FILE_PROC_CPUINFO {
        let count = linux_available_cpu_count();
        let mut record = [0_u8; 768];
        let mut size = 0_u64;
        for cpu in 0..count {
            size = size
                .saturating_add(linux_cpuinfo_record(cpu, count, &mut record).unwrap_or(0) as u64);
        }
        size
    } else if state & !3 == LINUX_FILE_PROC_STAT {
        let mut file = [0_u8; 2048];
        linux_proc_stat_file(&mut file).unwrap_or(0) as u64
    } else if state & !3 == LINUX_FILE_PROC_FDINFO {
        64
    } else if linux_tmp_file(state) {
        linux_tmpfs::open(b"linox-ready")
            .and_then(linux_tmpfs::size)
            .map_or(0, |size| size as u64)
    } else {
        linux_regular_file(state).map_or(0, |file| file.len() as u64)
    }
}
