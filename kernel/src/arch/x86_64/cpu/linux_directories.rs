use super::*;

/// The working directory's path as getcwd(2) and /proc/self/cwd show
/// it, into `shown`; returns its length.
pub(super) fn linux_cwd_path(
    shown: &mut [u8; crate::linux_overlay::PATH_CAPACITY + 16],
) -> Result<usize, u64> {
    let state = X86_RUNTIME.ELF_PROBE_CWD.load(Ordering::SeqCst);
    let mut output = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    output[0] = b'/';
    let rootfs_cwd = X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.load(Ordering::SeqCst);
    let overlay_cwd = X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.load(Ordering::SeqCst);
    let length = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && overlay_cwd != 0 {
        let Some(handle) = crate::linux_overlay::from_generation(overlay_cwd) else {
            return Err(LINUX_ENOENT);
        };
        let Some(path_length) = linux_shown_overlay_path(handle, &mut output[1..]) else {
            return Err(LINUX_ENOENT);
        };
        1 + path_length
    } else if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && rootfs_cwd != 0 {
        let Some(path_length) = linux_shown_rootfs_path(rootfs_cwd, &mut output[1..]) else {
            return Err(LINUX_ENOENT);
        };
        1 + path_length
    } else if state == LINUX_ROOT_DIRECTORY {
        1
    } else if state == LINUX_DEVICE_DIRECTORY {
        output[1..4].copy_from_slice(b"dev");
        4
    } else {
        let Some(path) = linux_measured_directory_path(state) else {
            return Err(LINUX_ENOENT);
        };
        let Some(destination) = output.get_mut(1..1 + path.len()) else {
            return Err(LINUX_ERANGE);
        };
        destination.copy_from_slice(path);
        1 + path.len()
    };
    // In a chroot the path is shown from the root; a directory outside
    // it is "(unreachable)" followed by its path, as Linux reports it.
    let mut root = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let root_length = linux_root_prefix(&mut root);
    let length = if root_length == 0 {
        shown[..length].copy_from_slice(&output[..length]);
        length
    } else if linux_root_floor(&output[1..length]) != 0 {
        // What follows the root is "" (the root itself) or "/...".
        let rest = &output[1 + root_length..length];
        if rest.is_empty() {
            shown[0] = b'/';
            1
        } else {
            shown[..rest.len()].copy_from_slice(rest);
            rest.len()
        }
    } else {
        const UNREACHABLE: &[u8] = b"(unreachable)";
        shown[..UNREACHABLE.len()].copy_from_slice(UNREACHABLE);
        shown[UNREACHABLE.len()..UNREACHABLE.len() + length].copy_from_slice(&output[..length]);
        UNREACHABLE.len() + length
    };
    Ok(length)
}

pub(super) fn linux_getcwd(address: u64, capacity: u64) -> u64 {
    let mut shown = [0_u8; crate::linux_overlay::PATH_CAPACITY + 16];
    let length = match linux_cwd_path(&mut shown) {
        Ok(length) => length,
        Err(error) => return error,
    };
    shown[length] = 0;
    let required = length + 1;
    // Linux builds the path in a PATH_MAX buffer: one that does not fit is
    // ENAMETOOLONG, whatever the caller's buffer.
    if required > LINUX_PATH_MAX {
        return LINUX_ENAMETOOLONG;
    }
    if capacity < required as u64 {
        return LINUX_ERANGE;
    }
    if !copy_to_linux_user(address, &shown[..required]) {
        return LINUX_EFAULT;
    }
    required as u64
}

/// chroot(2), in a domain set `privileged=true`: makes a directory the
/// process's root (`linux_process::set_live_process_root`), which its
/// children inherit. Linux's order: the lookup's errors, then search
/// permission on the directory (EACCES), then CAP_SYS_CHROOT (EPERM).
pub(super) fn linux_chroot(path_address: u64) -> u64 {
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ChangeRoot) {
        return LINUX_EPERM;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let path = &path[..length];
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let root = match linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), path, &mut canonical) {
        // The domain's root itself.
        Err(LINUX_EISDIR) => Vec::new(),
        Err(error) => return error,
        Ok(canonical_length) => {
            let (length, _, found) =
                match linux_overlay_lookup_following(&mut canonical, canonical_length, true) {
                    Ok(found) => found,
                    Err(error) => return error,
                };
            let access = if let Some(metadata) = found {
                if metadata.kind != crate::linux_overlay::NodeKind::Directory {
                    return LINUX_ENOTDIR;
                }
                linux_overlay_file_access(metadata)
            } else {
                let Some((handle, entry)) = linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), path)
                else {
                    return linux_missing_path_error(&canonical[..length]);
                };
                if entry.is_some_and(|entry| {
                    entry.kind != crate::published_rootfs::EntryKind::Directory
                }) {
                    return LINUX_ENOTDIR;
                }
                let Some(image_length) = crate::published_rootfs::copy_path(handle, &mut canonical)
                else {
                    return LINUX_ENOENT;
                };
                // Directories of the image are searchable by everyone.
                let mut root = Vec::new();
                if root.try_reserve_exact(image_length).is_err() {
                    return LINUX_ENOMEM;
                }
                root.extend_from_slice(&canonical[..image_length]);
                return linux_finish_chroot(root);
            };
            if let Err(error) =
                linux_check_access(Some(access), linox_credentials::access::EXECUTE, false)
            {
                return error;
            }
            let mut root = Vec::new();
            if root.try_reserve_exact(length).is_err() {
                return LINUX_ENOMEM;
            }
            root.extend_from_slice(&canonical[..length]);
            root
        }
    };
    linux_finish_chroot(root)
}

/// The canonical directory at the path at `address`, as pivot_root looks
/// its arguments up: following a final symlink, a directory (ENOTDIR).
fn linux_lookup_directory(address: u64) -> Result<Vec<u8>, u64> {
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = copy_linux_c_string(address, &mut path)?;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length =
        match linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), &path[..length], &mut canonical) {
            Ok(length) => length,
            // The domain's root itself.
            Err(LINUX_EISDIR) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
    let (length, _, found) = linux_overlay_lookup_following(&mut canonical, length, true)?;
    let directory = match found {
        Some(metadata) => metadata.kind == crate::linux_overlay::NodeKind::Directory,
        None => {
            let Some((_, entry)) = linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), &path[..])
            else {
                return Err(linux_missing_path_error(&canonical[..length]));
            };
            entry.is_none_or(|entry| entry.kind == crate::published_rootfs::EntryKind::Directory)
        }
    };
    if !directory {
        return Err(LINUX_ENOTDIR);
    }
    let mut directory = Vec::new();
    directory
        .try_reserve_exact(length)
        .map_err(|_| LINUX_ENOMEM)?;
    directory.extend_from_slice(&canonical[..length]);
    Ok(directory)
}

/// pivot_root(2): makes the mount at `new_root` the root of the processes
/// of the mount namespace whose root was the caller's (their working
/// directory too when it was that root), as Linux's checks allow: no
/// shared mount involved, neither directory on the current root's mount
/// (EBUSY), the root and `new_root` mount roots with a parent, and
/// `put_old` at or under `new_root`, which lies under the root (EINVAL).
/// The old root's mount is not shown at `put_old`: paths are not
/// redirected between mounts here.
pub(super) fn linux_pivot_root(new_root_address: u64, put_old_address: u64) -> u64 {
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ChangeRoot)
        || !linux_has_capability(linox_credentials::capability::SYS_ADMIN)
    {
        return LINUX_EPERM;
    }
    let new_root = match linux_lookup_directory(new_root_address) {
        Ok(path) => path,
        Err(error) => return error,
    };
    let put_old = match linux_lookup_directory(put_old_address) {
        Ok(path) => path,
        Err(error) => return error,
    };
    let mut root = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let root_length = linux_root_prefix(&mut root);
    let root = &root[..root_length];
    let space = linux_mount_space();
    let mount_at = |path: &[u8]| crate::linux_mounts::mount_id_at(space, path);
    let shared = |id: u32| {
        crate::linux_mounts::with_mount(space, id, |mount| mount.sharing.peer_group != 0)
            .unwrap_or(false)
    };
    let parent = |id: u32| {
        crate::linux_mounts::with_mount(space, id, |mount| mount.parent)
            .unwrap_or(crate::linux_mounts::ROOT_ID)
    };
    let (root_mount, new_mount, old_mount) =
        (mount_at(root), mount_at(&new_root), mount_at(&put_old));
    let below = |point: &[u8], path: &[u8]| {
        point.is_empty()
            || path
                .strip_prefix(point)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
    };
    if shared(old_mount) || shared(parent(new_mount)) || shared(parent(root_mount)) {
        return LINUX_EINVAL;
    }
    if new_mount == root_mount || old_mount == root_mount {
        return LINUX_EBUSY;
    }
    if root_mount == crate::linux_mounts::ROOT_ID
        || !crate::linux_mounts::is_mount_point(space, root)
        || !crate::linux_mounts::is_mount_point(space, &new_root)
        || !below(&new_root, &put_old)
        || !below(root, &new_root)
    {
        return LINUX_EINVAL;
    }
    // Every process of this mount namespace rooted where the caller is
    // moves to the new root.
    let namespace = linux_mount::current_handle();
    let caller = current_linux_process_pid();
    for slot in 0..linux_process::live_process_slots() {
        let Some(pid) = linux_process::live_process_pid_at(slot) else {
            continue;
        };
        let in_namespace = pid == caller
            || with_linux_process_runtime_state(pid, |state| state.mount_namespace)
                .is_some_and(|own| own == namespace);
        let rooted_here =
            linux_process::with_live_process_root(pid, |own| own == root).unwrap_or(false);
        if !in_namespace || !rooted_here {
            continue;
        }
        let mut moved = Vec::new();
        if moved.try_reserve_exact(new_root.len()).is_err() {
            return LINUX_ENOMEM;
        }
        moved.extend_from_slice(&new_root);
        if !linux_process::set_live_process_root(pid, moved) {
            return LINUX_ESRCH;
        }
    }
    let mut cwd = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let at_root = linux_walk_start(u64::from(LINUX_AT_FDCWD), &mut cwd)
        .is_ok_and(|length| &cwd[..length] == root);
    if at_root {
        if let Some(metadata) = crate::linux_overlay::lookup(&new_root) {
            X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.store(
                crate::linux_overlay::generation(metadata.handle),
                Ordering::SeqCst,
            );
            X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_CWD
                .store(LINUX_ROOT_MEASURED_DIRECTORY, Ordering::SeqCst);
        }
    }
    0
}

fn linux_finish_chroot(root: Vec<u8>) -> u64 {
    if !linux_has_capability(linox_credentials::capability::SYS_CHROOT) {
        return LINUX_EPERM;
    }
    if linux_process::set_live_process_root(current_linux_process_pid(), root) {
        0
    } else {
        LINUX_ESRCH
    }
}

pub(super) fn linux_chdir(path_address: u64) -> u64 {
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let path = &path[..length];
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let canonical_length =
            match linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), path, &mut canonical) {
                Ok(length) => Some(length),
                Err(error @ (LINUX_EACCES | LINUX_ENOTDIR | LINUX_ELOOP | LINUX_ENAMETOOLONG)) => {
                    return error
                }
                Err(_) => None,
            };
        if let Some(length) = canonical_length {
            let (followed, found) =
                match linux_overlay_lookup_following(&mut canonical, length, true) {
                    Ok((followed, _, found)) => (followed, found),
                    Err(error) => return error,
                };
            if let Some(metadata) = found {
                if metadata.kind != crate::linux_overlay::NodeKind::Directory {
                    return LINUX_ENOTDIR;
                }
                linux_note_path_view(
                    &canonical[..followed],
                    crate::linux_path_views::Key::Overlay(crate::linux_overlay::generation(
                        metadata.handle,
                    )),
                );
                // Changing into a directory needs search permission on it.
                if let Err(error) = linux_check_access(
                    Some(linux_overlay_file_access(metadata)),
                    linox_credentials::access::EXECUTE,
                    false,
                ) {
                    return error;
                }
                X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.store(
                    crate::linux_overlay::generation(metadata.handle),
                    Ordering::SeqCst,
                );
                X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.store(0, Ordering::SeqCst);
                X86_RUNTIME
                    .ELF_PROBE_CWD
                    .store(LINUX_ROOT_MEASURED_DIRECTORY, Ordering::SeqCst);
                return 0;
            }
        }
        if let Some(kind) = linux_virtual_mount_path_at(u64::from(LINUX_AT_FDCWD), path) {
            if kind & LINUX_DEVICE_DIRECTORY == 0 {
                return LINUX_ENOTDIR;
            }
            X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_CWD.store(kind & !3, Ordering::SeqCst);
            return 0;
        }
        let Some((handle, entry)) = linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), path) else {
            return canonical_length.map_or(LINUX_ENOENT, |length| {
                linux_missing_path_error(&canonical[..length])
            });
        };
        if entry.is_some_and(|entry| entry.kind != crate::published_rootfs::EntryKind::Directory) {
            return LINUX_ENOTDIR;
        }
        if let Some(length) = canonical_length {
            linux_note_path_view(
                &canonical[..length],
                crate::linux_path_views::Key::Image(handle),
            );
        }
        X86_RUNTIME
            .ELF_PROBE_ROOTFS_CWD
            .store(handle, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.store(0, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_CWD
            .store(LINUX_ROOT_DIRECTORY, Ordering::SeqCst);
        return 0;
    }
    let kind = if path.starts_with(b"/") {
        linux_root_directory_kind(path)
    } else {
        match linux_relative_path_kind(u64::from(LINUX_AT_FDCWD), path) {
            Ok(kind) => kind,
            Err(error) => return error,
        }
    };
    let Some(kind) = kind else {
        return LINUX_ENOENT;
    };
    if kind & LINUX_DEVICE_DIRECTORY == 0 {
        return LINUX_ENOTDIR;
    }
    X86_RUNTIME.ELF_PROBE_CWD.store(kind & !3, Ordering::SeqCst);
    0
}

pub(super) fn linux_fchdir(descriptor: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let state = linux_device_descriptor(descriptor);
    if state == 0 {
        return LINUX_EBADF;
    }
    if state & LINUX_DEVICE_DIRECTORY == 0 {
        return LINUX_ENOTDIR;
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
            let Some(metadata) = crate::linux_overlay::metadata(handle) else {
                return LINUX_EBADF;
            };
            if metadata.kind != crate::linux_overlay::NodeKind::Directory {
                return LINUX_ENOTDIR;
            }
            // Changing into a directory needs search permission on it.
            if let Err(error) = linux_check_access(
                Some(linux_overlay_file_access(metadata)),
                linox_credentials::access::EXECUTE,
                false,
            ) {
                return error;
            }
            X86_RUNTIME
                .ELF_PROBE_OVERLAY_CWD
                .store(crate::linux_overlay::generation(handle), Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_CWD
                .store(state & !3, Ordering::SeqCst);
            return 0;
        }
        let handle = linux_rootfs_descriptor(descriptor);
        if handle == 0 {
            return LINUX_ENOENT;
        }
        X86_RUNTIME
            .ELF_PROBE_ROOTFS_CWD
            .store(handle, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_CWD
        .store(state & !3, Ordering::SeqCst);
    0
}

/// The image's directory at canonical `path`, unless the overlay hides it:
/// the lower half of a directory the overlay also has.
fn linux_image_directory(path: &[u8]) -> Option<u16> {
    let image = crate::linux_overlay::image_path(path)?;
    if !image.is_empty()
        && crate::published_rootfs::exact_entry(&image)?.kind
            != crate::published_rootfs::EntryKind::Directory
    {
        return None;
    }
    crate::published_rootfs::lookup_at(crate::published_rootfs::ROOT_HANDLE, &image)
        .map(|(handle, _)| handle)
}

/// Whether the directory at canonical `path` lists nothing but `.` and `..`
/// (linux_getdents): no overlay entry below it and no image entry the
/// overlay leaves visible.
pub(super) fn linux_merged_directory_empty(path: &[u8]) -> bool {
    if matches!(crate::linux_overlay::next_child_at(path, 0), Some(Some(_))) {
        return false;
    }
    let Some(lower) = linux_image_directory(path) else {
        return true;
    };
    let mut cursor = 0;
    while let Some(Some(child)) = crate::published_rootfs::next_child(lower, cursor) {
        let mut child_path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        if linux_child_path(path, child.name(), &mut child_path).is_some_and(|child_path| {
            crate::linux_overlay::lookup(child_path).is_none()
                && crate::linux_overlay::image_path(child_path).is_some()
        }) {
            return false;
        }
        cursor = child.next_cursor;
    }
    true
}

/// `name` below the canonical directory `parent`, in `output`.
fn linux_child_path<'a>(parent: &[u8], name: &[u8], output: &'a mut [u8]) -> Option<&'a [u8]> {
    let separator = usize::from(!parent.is_empty());
    let output = output.get_mut(..parent.len() + separator + name.len())?;
    output[..parent.len()].copy_from_slice(parent);
    if separator != 0 {
        output[parent.len()] = b'/';
    }
    output[parent.len() + separator..].copy_from_slice(name);
    Some(output)
}

pub(super) fn linux_getdents64(descriptor: u64, address: u64, count: u64) -> u64 {
    linux_getdents(descriptor, address, count, false)
}

/// getdents(2): reading a directory updates its access time, as the mount
/// it is on says (linux_note_accessed).
pub(super) fn linux_getdents(descriptor: u64, address: u64, count: u64, legacy: bool) -> u64 {
    let result = linux_getdents_entries(descriptor, address, count, legacy);
    if result < LINUX_RETURN_TO_KERNEL {
        if let Some(handle) = linux_overlay_descriptor_handle(u64::from(descriptor as u32)) {
            if !linux_descriptor_noatime(u64::from(descriptor as u32)) {
                linux_note_accessed(handle, true);
            }
        }
    }
    result
}

fn linux_getdents_entries(descriptor: u64, address: u64, count: u64, legacy: bool) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    let state = linux_device_descriptor(descriptor);
    if state & LINUX_DEVICE_DIRECTORY == 0 {
        return LINUX_ENOTDIR;
    }
    // A removed directory lists nothing more (Linux's dead directory).
    if linux_overlay_descriptor_handle(descriptor)
        .is_some_and(|handle| !crate::linux_overlay::linked(handle))
    {
        return LINUX_ENOENT;
    }
    let offset = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
    let Ok(capacity) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    let mut entries = [0_u8; PAGE_SIZE];
    let output_capacity = capacity.min(entries.len());
    let mut used = 0_usize;
    let next_offset;
    let rootfs_directory = linux_rootfs_descriptor(descriptor);
    let overlay_directory = linux_overlay_descriptor_handle(descriptor);
    if overlay_directory.is_some() || rootfs_directory != 0 {
        // The directory as path lookup sees it (linux_path_access): the
        // image's entries the overlay neither hides nor replaces, then the
        // overlay's own. Cookies from LINUX_DIRENT_OVERLAY_PHASE on walk the
        // overlay, those below it the image.
        let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let (directory_inode, parent_inode, path_length, lower) = match overlay_directory {
            Some(directory) => {
                let Some(length) = crate::linux_overlay::copy_path(directory, &mut path) else {
                    return LINUX_EBADF;
                };
                (
                    directory.inode(),
                    directory.inode(),
                    length,
                    linux_image_directory(&path[..length]),
                )
            }
            None => {
                let Some(length) = crate::published_rootfs::copy_path(rootfs_directory, &mut path)
                else {
                    return LINUX_EBADF;
                };
                (
                    linux_rootfs_inode(rootfs_directory),
                    linux_rootfs_inode(crate::published_rootfs::ROOT_HANDLE),
                    length,
                    Some(rootfs_directory),
                )
            }
        };
        let directory_path = &path[..path_length];
        let initial = offset == 0;
        let Some(mut cookie) = (if initial {
            Some(0)
        } else {
            offset.checked_sub(2)
        }) else {
            return LINUX_EINVAL;
        };
        if initial {
            for (inode, next, name) in [
                (directory_inode, 1_i64, &b"."[..]),
                (parent_inode, 2, &b".."[..]),
            ] {
                if !append_linux_dirent(
                    &mut entries[..output_capacity],
                    &mut used,
                    legacy,
                    inode,
                    next,
                    4,
                    name,
                ) {
                    return LINUX_EINVAL;
                }
            }
        }
        let mut full = false;
        if cookie < LINUX_DIRENT_OVERLAY_PHASE {
            if let Some(lower) = lower {
                let Ok(mut cursor) = usize::try_from(cookie) else {
                    return LINUX_EINVAL;
                };
                loop {
                    let Some(child) = crate::published_rootfs::next_child(lower, cursor) else {
                        return LINUX_EINVAL;
                    };
                    let Some(child) = child else {
                        break;
                    };
                    let mut child_path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
                    let shown = linux_child_path(directory_path, child.name(), &mut child_path)
                        .is_some_and(|child_path| {
                            crate::linux_overlay::lookup(child_path).is_none()
                                && crate::linux_overlay::image_path(child_path).is_some()
                        });
                    let kind = match child.entry.kind {
                        crate::published_rootfs::EntryKind::Directory => 4,
                        crate::published_rootfs::EntryKind::File => 8,
                        crate::published_rootfs::EntryKind::Hardlink => 8,
                        crate::published_rootfs::EntryKind::Symlink => 10,
                    };
                    let Ok(next) = i64::try_from(child.next_cursor + 2) else {
                        return LINUX_EINVAL;
                    };
                    if shown
                        && !append_linux_dirent(
                            &mut entries[..output_capacity],
                            &mut used,
                            legacy,
                            linux_rootfs_inode(child.handle),
                            next,
                            kind,
                            child.name(),
                        )
                    {
                        full = true;
                        break;
                    }
                    cursor = child.next_cursor;
                    cookie = cursor as u64;
                }
            }
            if !full {
                cookie = LINUX_DIRENT_OVERLAY_PHASE;
            }
        }
        if !full {
            let Ok(mut cursor) = usize::try_from(cookie - LINUX_DIRENT_OVERLAY_PHASE) else {
                return LINUX_EINVAL;
            };
            // No overlay (a domain without a writable layer) lists nothing.
            while let Some(Some(child)) =
                crate::linux_overlay::next_child_at(directory_path, cursor)
            {
                let kind = match child.metadata.kind {
                    crate::linux_overlay::NodeKind::File => 8,
                    crate::linux_overlay::NodeKind::Directory => 4,
                    crate::linux_overlay::NodeKind::Symlink => 10,
                    crate::linux_overlay::NodeKind::Fifo => 1,
                    crate::linux_overlay::NodeKind::Socket => 12,
                    crate::linux_overlay::NodeKind::CharacterDevice => 2,
                    crate::linux_overlay::NodeKind::BlockDevice => 6,
                };
                let Some(next) = (child.next_cursor as u64)
                    .checked_add(LINUX_DIRENT_OVERLAY_PHASE + 2)
                    .and_then(|next| i64::try_from(next).ok())
                else {
                    return LINUX_EINVAL;
                };
                if !append_linux_dirent(
                    &mut entries[..output_capacity],
                    &mut used,
                    legacy,
                    child.metadata.handle.inode(),
                    next,
                    kind,
                    child.name(),
                ) {
                    full = true;
                    break;
                }
                cursor = child.next_cursor;
                cookie = LINUX_DIRENT_OVERLAY_PHASE + cursor as u64;
            }
        }
        if used == 0 {
            return if full { LINUX_EINVAL } else { 0 };
        }
        next_offset = cookie + 2;
    } else if let Some(directory) = linux_measured_directory_path(state) {
        let directory_inode = linux_proc_directory_descriptor_pid(descriptor).map_or_else(
            || linux_root_directory_inode(state).unwrap_or(0),
            linux_proc_pid_directory_inode,
        );
        let parent_inode = if directory.is_empty() {
            directory_inode
        } else if directory == b"proc/1" || directory == b"proc/2" || directory == b"proc/sys" {
            initramfs::published_directory_node(b"proc")
                .map(|node| 64 + u64::from(node))
                .unwrap_or(11)
        } else if linux_proc_sys_directory_index(directory).is_some() {
            linux_proc_sys_directory_index(linux_parent_path(directory))
                .map_or(11, |index| LINUX_PROC_SYS_DIRECTORY_INODES + index as u64)
        } else {
            11
        };
        let initial = offset == 0;
        let mut cursor = if initial {
            0
        } else {
            let Some(cursor) = offset
                .checked_sub(2)
                .and_then(|cursor| usize::try_from(cursor).ok())
            else {
                return LINUX_EINVAL;
            };
            cursor
        };
        if initial {
            for (inode, next, name) in [
                (directory_inode, 1_i64, &b"."[..]),
                (parent_inode, 2, &b".."[..]),
            ] {
                if !append_linux_dirent(
                    &mut entries[..output_capacity],
                    &mut used,
                    legacy,
                    inode,
                    next,
                    4,
                    name,
                ) {
                    return LINUX_EINVAL;
                }
            }
        }
        if directory == b"proc/self/fd" {
            // The fixed table's descriptors, then those above it (the
            // cursor is the next descriptor to look at).
            let overflow = crate::linux_fd_table::entries(
                X86_RUNTIME
                    .ELF_PROBE_DESCRIPTOR_OVERFLOW
                    .load(Ordering::SeqCst),
            );
            loop {
                let descriptor = if cursor < LINUX_AUX_DESCRIPTOR_LIMIT as usize {
                    cursor as u64
                } else {
                    match overflow
                        .iter()
                        .map(|(descriptor, _)| *descriptor)
                        .find(|descriptor| *descriptor >= cursor as u64)
                    {
                        Some(descriptor) => descriptor,
                        None => break,
                    }
                };
                cursor = descriptor as usize + 1;
                if !linux_descriptor_open(descriptor) {
                    continue;
                }
                let mut name = [0_u8; 20];
                let mut value = descriptor;
                let mut digits = 1_usize;
                while value >= 10 {
                    value /= 10;
                    digits += 1;
                }
                value = descriptor;
                for index in (0..digits).rev() {
                    name[index] = b'0' + (value % 10) as u8;
                    value /= 10;
                }
                if !append_linux_dirent(
                    &mut entries[..output_capacity],
                    &mut used,
                    legacy,
                    1_000 + descriptor,
                    (cursor + 2) as i64,
                    10,
                    &name[..digits],
                ) {
                    if used == 0 {
                        return LINUX_EINVAL;
                    }
                    cursor -= 1;
                    break;
                }
            }
        } else if directory == b"proc/self/task" {
            // The threads of the process the directory was opened for, by id.
            let pid = linux_proc_dynamic_descriptor_pid(descriptor)
                .unwrap_or_else(current_linux_process_pid);
            let mut tids = [0_u32; LINUX_THREAD_LIMIT];
            let count = linux_process_thread_ids(pid, &mut tids);
            if cursor > count {
                return LINUX_EINVAL;
            }
            for (index, tid) in tids[..count].iter().enumerate() {
                if cursor == index {
                    let mut name = [0_u8; 10];
                    let mut length = 0;
                    if !append_linux_decimal(&mut name, &mut length, u64::from(*tid))
                        || !append_linux_dirent(
                            &mut entries[..output_capacity],
                            &mut used,
                            legacy,
                            linux_proc_task_directory_inode(*tid),
                            (index + 3) as i64,
                            4,
                            &name[..length],
                        )
                    {
                        if used == 0 {
                            return LINUX_EINVAL;
                        }
                        break;
                    }
                    cursor += 1;
                }
            }
        } else if directory == b"proc/1" {
            let runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
            let entry_count = if runtime { 15 } else { 8 };
            if cursor > entry_count {
                return LINUX_EINVAL;
            }
            let file = |kind| linux_regular_file_inode(kind).unwrap_or(0);
            for (index, (inode, kind, name)) in [
                (17_u64, 8_u8, &b"status"[..]),
                (19, 8, b"mountinfo"),
                (20, 8, b"uid_map"),
                (21, 8, b"gid_map"),
                (22, 8, b"setgroups"),
                (32, 8, b"stat"),
                (33, 8, b"statm"),
                (37, 8, b"cgroup"),
                (40, 8, b"cmdline"),
                (41, 8, b"environ"),
                (file(LINUX_FILE_PROC_DYNAMIC_MAPS), 8, b"maps"),
                (file(LINUX_FILE_PROC_DYNAMIC_SMAPS), 8, b"smaps"),
                (file(LINUX_FILE_PROC_DYNAMIC_PAGEMAP), 8, b"pagemap"),
                (file(LINUX_FILE_PROC_MOUNTS), 8, b"mounts"),
                (file(LINUX_FILE_PROC_OOM_SCORE_ADJ), 8, b"oom_score_adj"),
                (file(LINUX_FILE_PROC_TIMENS_OFFSETS), 8, b"timens_offsets"),
                (
                    linux_root_directory_inode(LINUX_PROC_FD_DIRECTORY).unwrap_or(0),
                    4,
                    b"fd",
                ),
                (47, 10, b"exe"),
            ]
            .into_iter()
            .enumerate()
            .take(entry_count)
            {
                // Only init's command line and environment are served
                // (linux_proc_pid_file_kind); other processes' directories
                // do not list them.
                let listed_pid = linux_proc_directory_descriptor_pid(descriptor).unwrap_or(1);
                if listed_pid != 1 && matches!(name, b"cmdline" | b"environ") {
                    if cursor == index {
                        cursor += 1;
                    }
                    continue;
                }
                if cursor == index {
                    if !append_linux_dirent(
                        &mut entries[..output_capacity],
                        &mut used,
                        legacy,
                        inode,
                        (index + 3) as i64,
                        kind,
                        name,
                    ) {
                        if used == 0 {
                            return LINUX_EINVAL;
                        }
                        break;
                    }
                    cursor += 1;
                }
            }
        } else if directory == b"proc/2" {
            if cursor > 4 {
                return LINUX_EINVAL;
            }
            if linux_process::live_process_status(2).is_none() {
                return LINUX_ENOENT;
            }
            for (index, inode, name) in [
                (0_usize, 24_u64, &b"status"[..]),
                (1_usize, 34_u64, &b"stat"[..]),
                (2_usize, 35_u64, &b"statm"[..]),
                (3_usize, 38_u64, &b"cgroup"[..]),
            ] {
                if cursor == index {
                    if !append_linux_dirent(
                        &mut entries[..output_capacity],
                        &mut used,
                        legacy,
                        inode,
                        (index + 3) as i64,
                        8,
                        name,
                    ) {
                        if used == 0 {
                            return LINUX_EINVAL;
                        }
                        break;
                    }
                    cursor += 1;
                }
            }
        } else if linux_proc_sys_directory_index(directory).is_some() {
            for (index, (inode, kind, name)) in linux_proc_sys_children(directory).enumerate() {
                if cursor == index {
                    if !append_linux_dirent(
                        &mut entries[..output_capacity],
                        &mut used,
                        legacy,
                        inode,
                        (index + 3) as i64,
                        kind,
                        name,
                    ) {
                        if used == 0 {
                            return LINUX_EINVAL;
                        }
                        break;
                    }
                    cursor += 1;
                }
            }
        } else if directory == b"proc" {
            // The fixed files, then `self`, then a directory per process.
            // Cursors from PROC_PID_CURSOR on name the next pid to list, so
            // processes that come and go between calls shift no others.
            const PROC_PID_CURSOR: usize = 64;
            let file = |kind| linux_regular_file_inode(kind).unwrap_or(0);
            let fixed = [
                (25_u64, 8_u8, &b"cpuinfo"[..]),
                (26, 8, &b"meminfo"[..]),
                (27, 8, &b"stat"[..]),
                (28, 8, &b"uptime"[..]),
                (29, 8, &b"loadavg"[..]),
                (30, 8, &b"filesystems"[..]),
                (31, 8, &b"cmdline"[..]),
                (12, 10, &b"self"[..]),
                (LINUX_PROC_SYS_DIRECTORY_INODES, 4, &b"sys"[..]),
                (file(LINUX_FILE_PROC_MOUNTS), 8, &b"mounts"[..]),
                (file(LINUX_FILE_PROC_MODULES), 8, &b"modules"[..]),
                (file(LINUX_FILE_PROC_KEYS), 8, &b"keys"[..]),
                (file(LINUX_FILE_PROC_KEY_USERS), 8, &b"key-users"[..]),
                (file(LINUX_FILE_PROC_SWAPS), 8, &b"swaps"[..]),
                (file(LINUX_FILE_PROC_CONFIG), 8, &b"config.gz"[..]),
                (
                    file(LINUX_FILE_PROC_SYSRQ_TRIGGER),
                    8,
                    &b"sysrq-trigger"[..],
                ),
            ];
            let mut full = false;
            while let Some((inode, kind, name)) = fixed.get(cursor).copied() {
                if !append_linux_dirent(
                    &mut entries[..output_capacity],
                    &mut used,
                    legacy,
                    inode,
                    (cursor + 3) as i64,
                    kind,
                    name,
                ) {
                    if used == 0 {
                        return LINUX_EINVAL;
                    }
                    full = true;
                    break;
                }
                cursor += 1;
            }
            if !full {
                cursor = cursor.max(PROC_PID_CURSOR);
                while let Some(pid) = u32::try_from(cursor - PROC_PID_CURSOR)
                    .ok()
                    .and_then(linux_process::next_live_pid)
                {
                    let mut name = [0_u8; 20];
                    let length = write_linux_decimal(u64::from(pid), &mut name);
                    let next = PROC_PID_CURSOR + pid as usize + 1;
                    if !append_linux_dirent(
                        &mut entries[..output_capacity],
                        &mut used,
                        legacy,
                        linux_proc_pid_directory_inode(pid),
                        (next + 2) as i64,
                        4,
                        &name[..length],
                    ) {
                        if used == 0 {
                            return LINUX_EINVAL;
                        }
                        break;
                    }
                    cursor = next;
                }
            }
        } else if directory == b"tmp" {
            if cursor > 1 {
                return LINUX_EINVAL;
            }
            if cursor == 0 {
                let entry = linux_tmpfs::entry()
                    .map(|(handle, name)| (linux_tmpfs::inode(handle), 8, name));
                if let Some((inode, kind, name)) = entry {
                    if !append_linux_dirent(
                        &mut entries[..output_capacity],
                        &mut used,
                        legacy,
                        inode,
                        3,
                        kind,
                        name,
                    ) {
                        return LINUX_EINVAL;
                    }
                    cursor = 1;
                }
            }
        } else {
            loop {
                let Some(child) = initramfs::published_next_child(directory, cursor) else {
                    return LINUX_EINVAL;
                };
                let Some(child) = child else {
                    break;
                };
                let kind = match child.mode & 0o170000 {
                    0o040000 => 4,
                    0o100000 => 8,
                    0o120000 => 10,
                    _ => return LINUX_EINVAL,
                };
                let child_inode = match (directory, child.name) {
                    (b"", b"dev") => 4,
                    (b"", b"etc") => 10,
                    (b"", b"proc") => 12,
                    (b"", b"sys") => 13,
                    (b"", b"tmp") => 14,
                    (b"", b"init") => 5,
                    (b"etc", b"hostname") => 9,
                    _ => {
                        let Ok(node) = u64::try_from(child.next_cursor) else {
                            return LINUX_EINVAL;
                        };
                        let Some(inode) = 32_u64.checked_add(node) else {
                            return LINUX_EINVAL;
                        };
                        inode
                    }
                };
                let Some(cookie) = child.next_cursor.checked_add(2) else {
                    return LINUX_EINVAL;
                };
                let Ok(next) = i64::try_from(cookie) else {
                    return LINUX_EINVAL;
                };
                if !append_linux_dirent(
                    &mut entries[..output_capacity],
                    &mut used,
                    legacy,
                    child_inode,
                    next,
                    kind,
                    child.name,
                ) {
                    if used == 0 {
                        return LINUX_EINVAL;
                    }
                    break;
                }
                cursor = child.next_cursor;
            }
        }
        if used == 0 {
            return 0;
        }
        let Some(cookie) = cursor.checked_add(2) else {
            return LINUX_EINVAL;
        };
        let Ok(cookie) = u64::try_from(cookie) else {
            return LINUX_EINVAL;
        };
        next_offset = cookie;
    } else {
        if offset != 0 {
            return 0;
        }
        for (inode, next, kind, name) in [
            (4_u64, 1_i64, 4_u8, &b"."[..]),
            (4, 2, 4, &b".."[..]),
            (1, 3, 2, &b"null"[..]),
            (2, 4, 2, &b"zero"[..]),
            (3, 5, 2, &b"console"[..]),
            (3, 6, 2, &b"tty"[..]),
        ] {
            if !append_linux_dirent(
                &mut entries[..output_capacity],
                &mut used,
                legacy,
                inode,
                next,
                kind,
                name,
            ) {
                return LINUX_EINVAL;
            }
        }
        next_offset = 1;
    }
    if capacity < used {
        return LINUX_EINVAL;
    }
    if !copy_to_linux_user(address, &entries[..used]) {
        return LINUX_EFAULT;
    }
    linux_descriptor_offset(descriptor).store(next_offset, Ordering::SeqCst);
    used as u64
}

fn append_linux_dirent(
    output: &mut [u8],
    used: &mut usize,
    legacy: bool,
    inode: u64,
    next: i64,
    kind: u8,
    name: &[u8],
) -> bool {
    let header_size = if legacy { 18 } else { 19 };
    let record_size = (header_size + name.len() + 1 + usize::from(legacy) + 7) & !7;
    let Some(end) = used.checked_add(record_size) else {
        return false;
    };
    let Some(record) = output.get_mut(*used..end) else {
        return false;
    };
    record[..8].copy_from_slice(&inode.to_ne_bytes());
    record[8..16].copy_from_slice(&next.to_ne_bytes());
    record[16..18].copy_from_slice(&(record_size as u16).to_ne_bytes());
    if legacy {
        record[18..18 + name.len()].copy_from_slice(name);
        record[record_size - 1] = kind;
    } else {
        record[18] = kind;
        record[19..19 + name.len()].copy_from_slice(name);
    }
    *used = end;
    true
}
