use super::*;

pub(super) fn linux_readlink_at(
    directory: u64,
    path_address: u64,
    output_address: u64,
    output_size: u64,
) -> u64 {
    if output_size == 0 {
        return LINUX_EINVAL;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let path = &path[..path_length];
    // An empty path reads the symlink an O_PATH descriptor names.
    if path.is_empty() {
        let Some(link) = linux_overlay_descriptor_handle(directory)
            .and_then(crate::linux_overlay::metadata)
            .filter(|metadata| metadata.kind == crate::linux_overlay::NodeKind::Symlink)
        else {
            return LINUX_ENOENT;
        };
        let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let Some(target_length) = crate::linux_overlay::read(link.handle, 0, &mut target) else {
            return LINUX_EIO;
        };
        let output_length = usize::try_from(output_size)
            .unwrap_or(usize::MAX)
            .min(target_length);
        return if copy_to_linux_user(output_address, &target[..output_length]) {
            output_length as u64
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(reference) = linux_proc_namespace_at(path) {
        let reference = match reference {
            Ok(reference) => reference,
            Err(error) => return error,
        };
        let mut link = [0_u8; 32];
        let length = linux_namespace_link(reference, &mut link)
            .min(usize::try_from(output_size).unwrap_or(usize::MAX));
        return if copy_to_linux_user(output_address, &link[..length]) {
            length as u64
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(descriptor) = linux_descriptor_link_at(directory, path, false) {
        let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let Some(target_length) = linux_descriptor_link_target(descriptor, &mut target) else {
            return LINUX_ENOENT;
        };
        let output_length = usize::try_from(output_size)
            .unwrap_or(usize::MAX)
            .min(target_length);
        return if copy_to_linux_user(output_address, &target[..output_length]) {
            output_length as u64
        } else {
            LINUX_EFAULT
        };
    }
    // The process's own /proc/self/cwd: its working directory as getcwd
    // shows it.
    if matches!(path, b"/proc/self/cwd" | b"/proc/thread-self/cwd")
        || path
            .strip_prefix(b"/proc/")
            .and_then(|rest| rest.strip_suffix(b"/cwd"))
            .is_some_and(|digits| {
                core::str::from_utf8(digits)
                    .ok()
                    .and_then(|digits| digits.parse::<u32>().ok())
                    == Some(current_linux_process_pid())
            })
    {
        let mut shown = [0_u8; crate::linux_overlay::PATH_CAPACITY + 16];
        let length = match linux_cwd_path(&mut shown) {
            Ok(length) => length,
            Err(error) => return error,
        };
        let output_length = usize::try_from(output_size)
            .unwrap_or(usize::MAX)
            .min(length);
        return if copy_to_linux_user(output_address, &shown[..output_length]) {
            output_length as u64
        } else {
            LINUX_EFAULT
        };
    }
    if directory as u32 != LINUX_AT_FDCWD
        && linux_rootfs_descriptor(directory) == 0
        && linux_overlay_descriptor_handle(directory).is_none()
    {
        return LINUX_EBADF;
    }
    if directory as u32 != LINUX_AT_FDCWD || path != b"/proc/self/exe" {
        let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let canonical_length = match linux_canonical_path_at(directory, path, &mut canonical) {
            Ok(length) => Some(length),
            Err(error @ (LINUX_EACCES | LINUX_ENOTDIR | LINUX_ELOOP)) => return error,
            Err(_) => None,
        };
        if let Some(metadata) =
            canonical_length.and_then(|length| crate::linux_overlay::lookup(&canonical[..length]))
        {
            if metadata.kind != crate::linux_overlay::NodeKind::Symlink {
                return LINUX_EINVAL;
            }
            let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            let Some(target_length) = crate::linux_overlay::read(metadata.handle, 0, &mut target)
            else {
                return LINUX_EIO;
            };
            let output_length = usize::try_from(output_size)
                .unwrap_or(usize::MAX)
                .min(target_length);
            return if copy_to_linux_user(output_address, &target[..output_length]) {
                output_length as u64
            } else {
                LINUX_EFAULT
            };
        }
        if let Some((_, entry)) = linux_rootfs_metadata_path_at(directory, path) {
            let Some(entry) = entry else {
                return LINUX_EINVAL;
            };
            if entry.kind != crate::published_rootfs::EntryKind::Symlink {
                return LINUX_EINVAL;
            }
            let output_length = usize::try_from(output_size)
                .unwrap_or(usize::MAX)
                .min(entry.link().len());
            return if copy_to_linux_user(output_address, &entry.link()[..output_length]) {
                output_length as u64
            } else {
                LINUX_EFAULT
            };
        }
        if linux_virtual_mount_path_at(directory, path).is_some()
            || (directory as u32 == LINUX_AT_FDCWD && linux_root_directory_kind(path).is_some())
        {
            return LINUX_EINVAL;
        }
        // A path through a regular file is ENOTDIR (readlinkat02).
        return canonical_length.map_or(LINUX_ENOENT, |length| {
            linux_missing_path_error(&canonical[..length])
        });
    }
    let exec_node = X86_RUNTIME.ELF_PROBE_EXEC_NODE.load(Ordering::SeqCst);
    let mut measured_path = [0_u8; 64];
    let recorded = crate::linux_exe::lookup(
        X86_RUNTIME.LINUX_EXECUTION_INSTANCE.load(Ordering::SeqCst),
        current_linux_process_pid(),
    );
    let executable = if let Some(path) = recorded.as_deref() {
        path
    } else if exec_node == 0 {
        b"/init" as &[u8]
    } else {
        let Some(name) = initramfs::published_file_name_by_node(exec_node) else {
            return LINUX_ESRCH;
        };
        if name == b"linux/init" {
            b"/init" as &[u8]
        } else {
            measured_path[0] = b'/';
            let Some(destination) = measured_path.get_mut(1..1 + name.len()) else {
                return LINUX_ENAMETOOLONG;
            };
            destination.copy_from_slice(name);
            &measured_path[..1 + name.len()]
        }
    };
    let output_length = usize::try_from(output_size)
        .unwrap_or(usize::MAX)
        .min(executable.len());
    if !copy_to_linux_user(output_address, &executable[..output_length]) {
        return LINUX_EFAULT;
    }
    output_length as u64
}

pub(super) fn linux_runtime_file_kind(path: &[u8]) -> Option<u16> {
    if let Some(kind) = linux_graphics_path_kind(path) {
        return Some(kind);
    }
    if !linux_mount::current_root_is_read_only() {
        return None;
    }
    if path == b"/etc/resolv.conf" {
        return Some(LINUX_FILE_RESOLV_CONF);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && path == b"/proc/sys/fs/file-max" {
        return Some(LINUX_FILE_PROC_FILE_MAX);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && path == b"/proc/sys/fs/nr_open" {
        return Some(LINUX_FILE_PROC_NR_OPEN);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && path == b"/proc/sys/kernel/hostname"
    {
        return Some(LINUX_FILE_PROC_HOSTNAME);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && path == b"/proc/sys/kernel/random/boot_id"
    {
        return Some(LINUX_FILE_PROC_BOOT_ID);
    }
    if let Some(name) = path.strip_prefix(b"/proc/") {
        if let Some(kind) = linux_proc_root_file_kind(name) {
            return Some(kind);
        }
    }
    // The caller's fdinfo by /proc/self or by its own pid (inotify12).
    if linux_proc_fdinfo_target(path).is_some() {
        return Some(LINUX_FILE_PROC_FDINFO);
    }
    if let Some(name) = path.strip_prefix(b"/proc/self/") {
        return linux_proc_pid_file_kind(current_linux_process_pid(), name);
    }
    if let Some((pid, name)) = linux_proc_numeric_file(path, true) {
        return linux_proc_pid_file_kind(pid, name);
    }
    if path == b"/proc/1/status" {
        return Some(LINUX_FILE_PROC_STATUS);
    }
    if path == b"/proc/2/status" && linux_process::live_process_status(2).is_some() {
        return Some(LINUX_FILE_PROC_PID2_STATUS);
    }
    if let Some(name) = path.strip_prefix(b"/proc/1/") {
        return linux_proc_pid_file_kind(1, name);
    }
    if let Some(name) = path.strip_prefix(b"/proc/2/") {
        return linux_proc_pid_file_kind(2, name);
    }
    if path == b"/proc/1/mountinfo" {
        return Some(LINUX_FILE_PROC_MOUNTINFO);
    }
    if path == b"/proc/1/uid_map" {
        return Some(LINUX_FILE_PROC_UID_MAP);
    }
    if path == b"/proc/1/gid_map" {
        return Some(LINUX_FILE_PROC_GID_MAP);
    }
    if path == b"/proc/1/setgroups" {
        return Some(LINUX_FILE_PROC_SETGROUPS);
    }
    if path == b"/tmp/linox-ready" && linux_tmpfs::open(b"linox-ready").is_some() {
        return Some(LINUX_FILE_TMP_SCRATCH);
    }
    let (kind, root_name) = match path {
        b"/init" => (LINUX_FILE_INIT, b"linux/init" as &[u8]),
        b"/lib64/ld-linox.so" => (LINUX_FILE_INTERPRETER, b"linux/ld-linox.so" as &[u8]),
        b"/lib64/liblinox.so" => (LINUX_FILE_DEPENDENCY, b"linux/liblinox.so" as &[u8]),
        b"/lib64/liblinox-aux.so" => (
            LINUX_FILE_AUXILIARY_DEPENDENCY,
            b"linux/liblinox-aux.so" as &[u8],
        ),
        _ => {
            let root_name = path.strip_prefix(b"/")?;
            if root_name.starts_with(b"linux/") {
                return None;
            }
            let kind = if root_name == b"etc/hostname" {
                LINUX_FILE_ROOT_HOSTNAME
            } else {
                LINUX_FILE_ROOT_GENERIC
            };
            (kind, root_name)
        }
    };
    let node = initramfs::published_regular_file_node(root_name)?;
    Some(kind | (u16::from(node) << LINUX_ROOT_NODE_SHIFT))
}

pub(super) fn linux_root_directory_kind(path: &[u8]) -> Option<u16> {
    if !linux_mount::current_root_is_read_only() {
        return None;
    }
    match path {
        b"/" => Some(LINUX_ROOT_DIRECTORY),
        b"/dev" => Some(LINUX_DEVICE_DIRECTORY),
        b"/proc/self" | b"/proc/self/" => {
            Some(linux_proc_pid_directory_kind(current_linux_process_pid()))
        }
        b"/proc/1" => Some(LINUX_PROC_PID1_DIRECTORY),
        b"/proc/2" if linux_process::live_process_status(2).is_some() => {
            Some(LINUX_PROC_PID2_DIRECTORY)
        }
        _ if linux_proc_pid_directory(path, true).is_some() => Some(LINUX_PROC_PID1_DIRECTORY),
        b"/sys/fs/cgroup" => Some(LINUX_CGROUP_DIRECTORY),
        _ => {
            let name = path.strip_prefix(b"/")?;
            if let Some(index) = linux_proc_sys_directory_index(name) {
                return Some(linux_proc_sys_directory_kind(index));
            }
            let node = initramfs::published_directory_node(name)?;
            Some(LINUX_ROOT_MEASURED_DIRECTORY | (u16::from(node) << LINUX_ROOT_NODE_SHIFT))
        }
    }
}

fn linux_measured_path_kind(path: &[u8]) -> Option<u16> {
    if !linux_mount::current_root_is_read_only() {
        return None;
    }
    if path == b"dev" {
        return Some(LINUX_DEVICE_DIRECTORY);
    }
    if path == b"sys/fs/cgroup" {
        return Some(LINUX_CGROUP_DIRECTORY);
    }
    if let Some(index) = linux_proc_sys_directory_index(path) {
        return Some(linux_proc_sys_directory_kind(index));
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && path == b"proc/sys/fs/file-max" {
        return Some(LINUX_FILE_PROC_FILE_MAX);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && path == b"proc/sys/fs/nr_open" {
        return Some(LINUX_FILE_PROC_NR_OPEN);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && path == b"proc/sys/kernel/hostname"
    {
        return Some(LINUX_FILE_PROC_HOSTNAME);
    }
    if let Some(name) = path.strip_prefix(b"proc/") {
        if let Some(kind) = linux_proc_root_file_kind(name) {
            return Some(kind);
        }
    }
    if let Some(name) = path
        .strip_prefix(b"proc/self/")
        .filter(|name| !name.is_empty())
    {
        return linux_proc_pid_file_kind(current_linux_process_pid(), name);
    }
    if let Some((pid, name)) = linux_proc_numeric_file(path, false) {
        return linux_proc_pid_file_kind(pid, name);
    }
    if path == b"proc/self" || path == b"proc/self/" {
        return Some(linux_proc_pid_directory_kind(current_linux_process_pid()));
    }
    if path == b"proc/self/fd" {
        return Some(LINUX_PROC_FD_DIRECTORY);
    }
    if path == b"proc/1" {
        return Some(LINUX_PROC_PID1_DIRECTORY);
    }
    if path == b"proc/2" && linux_process::live_process_status(2).is_some() {
        return Some(LINUX_PROC_PID2_DIRECTORY);
    }
    if linux_proc_pid_directory(path, false).is_some() {
        return Some(LINUX_PROC_PID1_DIRECTORY);
    }
    if path == b"proc/1/status" {
        return Some(LINUX_FILE_PROC_STATUS);
    }
    if path == b"proc/2/status" && linux_process::live_process_status(2).is_some() {
        return Some(LINUX_FILE_PROC_PID2_STATUS);
    }
    if let Some(name) = path.strip_prefix(b"proc/1/") {
        return linux_proc_pid_file_kind(1, name);
    }
    if let Some(name) = path.strip_prefix(b"proc/2/") {
        return linux_proc_pid_file_kind(2, name);
    }
    if path == b"proc/1/mountinfo" {
        return Some(LINUX_FILE_PROC_MOUNTINFO);
    }
    if path == b"proc/1/uid_map" {
        return Some(LINUX_FILE_PROC_UID_MAP);
    }
    if path == b"proc/1/gid_map" {
        return Some(LINUX_FILE_PROC_GID_MAP);
    }
    if path == b"proc/1/setgroups" {
        return Some(LINUX_FILE_PROC_SETGROUPS);
    }
    if path == b"tmp/linox-ready" && linux_tmpfs::open(b"linox-ready").is_some() {
        return Some(LINUX_FILE_TMP_SCRATCH);
    }
    if let Some(node) = initramfs::published_directory_node(path) {
        return Some(LINUX_ROOT_MEASURED_DIRECTORY | (u16::from(node) << LINUX_ROOT_NODE_SHIFT));
    }
    let mut absolute = [0_u8; 64];
    absolute[0] = b'/';
    absolute.get_mut(1..1 + path.len())?.copy_from_slice(path);
    linux_runtime_file_kind(&absolute[..1 + path.len()])
}

pub(super) fn linux_virtual_mount_path_at(directory: u64, path: &[u8]) -> Option<u16> {
    // /proc and /sys/fs/cgroup are mounted at the domain's root, which a
    // process in a chroot does not see.
    if linux_chrooted() {
        return None;
    }
    let relative = path.strip_prefix(b"/").unwrap_or(path);
    let relative = if relative == b"proc/" {
        b"proc"
    } else {
        relative
    };
    if relative != b"proc" && !relative.starts_with(b"proc/") && relative != b"sys/fs/cgroup" {
        return None;
    }
    let from_root = path.starts_with(b"/")
        || if directory as u32 == LINUX_AT_FDCWD {
            X86_RUNTIME.ELF_PROBE_CWD.load(Ordering::SeqCst) == LINUX_ROOT_DIRECTORY
                && matches!(
                    X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.load(Ordering::SeqCst),
                    0 | crate::published_rootfs::ROOT_HANDLE
                )
        } else {
            linux_device_descriptor(directory) & !3 == LINUX_ROOT_DIRECTORY
                && matches!(
                    linux_rootfs_descriptor(directory),
                    0 | crate::published_rootfs::ROOT_HANDLE
                )
        };
    from_root
        .then(|| linux_measured_path_kind(relative))
        .flatten()
}

pub(super) fn linux_normalized_relative_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

/// The inode of the kernel's directory `kind` at absolute `path`: a
/// process's or thread's /proc directory has its own, by its id.
pub(super) fn linux_virtual_directory_inode(path: &[u8], kind: u16) -> u64 {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    if path == b"/proc/self" {
        return linux_proc_pid_directory_inode(current_linux_process_pid());
    }
    if let Some(pid) = linux_proc_pid_directory(path, true) {
        return linux_proc_pid_directory_inode(pid);
    }
    let thread = linux_proc_process_file(path)
        .and_then(|(_, name)| name.strip_prefix(b"task/"))
        .filter(|tid| !tid.is_empty() && tid.iter().all(u8::is_ascii_digit))
        .and_then(linux_leading_decimal);
    thread.map_or_else(
        || linux_root_directory_inode(kind).unwrap_or(0),
        linux_proc_task_directory_inode,
    )
}

/// `linux_virtual_directory_inode` for a /proc path from the root
/// (`linux_virtual_mount_path_at`), with or without its leading slash.
pub(super) fn linux_virtual_mount_directory_inode(path: &[u8], kind: u16) -> u64 {
    let mut absolute = [0_u8; LINUX_PATH_MAX + 1];
    let relative = path.strip_prefix(b"/").unwrap_or(path);
    absolute[0] = b'/';
    absolute[1..1 + relative.len()].copy_from_slice(relative);
    let absolute = &absolute[..1 + relative.len()];
    // /proc itself is the image's directory, which lookups through the
    // image (/proc/., /proc/1/..) report.
    if kind & (LINUX_DEVICE_DIRECTORY | LINUX_FILE_MASK) == LINUX_ROOT_MEASURED_DIRECTORY {
        if let Some((handle, _)) = linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), absolute) {
            return linux_rootfs_inode(handle);
        }
    }
    linux_virtual_directory_inode(absolute, kind)
}

/// `canonical`, a canonical path under /proc, as an absolute path in
/// `output`, for the kernel's own lookups, which know /proc names only as
/// spelled from the root: a path with "." or ".." in it, or one relative
/// to a /proc directory (`ls` in /proc/sys/kernel stats "."). None for
/// anything else, which is looked up as given.
pub(super) fn linux_proc_normalized_path(
    path: &[u8],
    canonical: &[u8],
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY + 1],
) -> Option<usize> {
    let under_proc = canonical == b"proc" || canonical.starts_with(b"proc/");
    let irregular = !path.starts_with(b"/")
        || path
            .split(|byte| *byte == b'/')
            .any(|component| component == b"." || component == b"..");
    if !under_proc || !irregular || linux_chrooted() {
        return None;
    }
    output[0] = b'/';
    output
        .get_mut(1..1 + canonical.len())?
        .copy_from_slice(canonical);
    Some(1 + canonical.len())
}

/// The inode of a /proc file whose node is its own: from
/// `LINUX_PROC_NODE_INODES` on, one per node, so none is another's.
pub(super) fn linux_proc_node_inode(kind: u16) -> u64 {
    LINUX_PROC_NODE_INODES + u64::from(kind >> 8)
}

pub(super) fn linux_root_directory_inode(kind: u16) -> Option<u64> {
    let role = kind & (LINUX_DEVICE_DIRECTORY | LINUX_FILE_MASK);
    if role == LINUX_DEVICE_DIRECTORY {
        return Some(4);
    }
    if role == LINUX_ROOT_DIRECTORY {
        return Some(11);
    }
    if role == LINUX_PROC_PID1_DIRECTORY {
        return match kind & LINUX_ROOT_NODE_MASK {
            0 => Some(16),
            LINUX_PROC_PID2_DIRECTORY_NODE => Some(23),
            LINUX_PROC_FD_DIRECTORY_NODE => Some(36),
            LINUX_PROC_TASK_DIRECTORY_NODE => Some(linux_proc_node_inode(kind)),
            LINUX_CGROUP_DIRECTORY_NODE => Some(39),
            _ => linux_proc_sys_directory_of(kind)
                .map(|index| LINUX_PROC_SYS_DIRECTORY_INODES + index as u64),
        };
    }
    let node = (kind & LINUX_ROOT_NODE_MASK) >> LINUX_ROOT_NODE_SHIFT;
    (role == LINUX_ROOT_MEASURED_DIRECTORY && node != 0).then_some(64 + u64::from(node))
}

pub(super) fn linux_measured_directory_path(kind: u16) -> Option<&'static [u8]> {
    if !linux_mount::current_root_is_read_only() {
        return None;
    }
    let role = kind & (LINUX_DEVICE_DIRECTORY | LINUX_FILE_MASK);
    if role == LINUX_ROOT_DIRECTORY {
        return Some(b"");
    }
    if role == LINUX_PROC_PID1_DIRECTORY {
        return match kind & LINUX_ROOT_NODE_MASK {
            0 => Some(b"proc/1"),
            LINUX_PROC_PID2_DIRECTORY_NODE => Some(b"proc/2"),
            LINUX_PROC_FD_DIRECTORY_NODE => Some(b"proc/self/fd"),
            LINUX_PROC_TASK_DIRECTORY_NODE => Some(b"proc/self/task"),
            LINUX_CGROUP_DIRECTORY_NODE => Some(b"sys/fs/cgroup"),
            _ => linux_proc_sys_directory_of(kind).map(|index| LINUX_PROC_SYS_DIRECTORIES[index]),
        };
    }
    let node = ((kind & LINUX_ROOT_NODE_MASK) >> LINUX_ROOT_NODE_SHIFT) as u8;
    (role == LINUX_ROOT_MEASURED_DIRECTORY)
        .then(|| initramfs::published_directory_by_node(node))
        .flatten()
}

pub(super) fn linux_relative_path_kind(directory: u64, path: &[u8]) -> Result<Option<u16>, u64> {
    if path.starts_with(b"/") {
        return Ok(None);
    }
    if !linux_normalized_relative_path(path) {
        return Err(LINUX_ENOENT);
    }
    let state = if directory as u32 == LINUX_AT_FDCWD {
        X86_RUNTIME.ELF_PROBE_CWD.load(Ordering::SeqCst)
    } else {
        let state = linux_device_descriptor(directory);
        if state == 0 {
            return Err(LINUX_EBADF);
        }
        state
    };
    if state & LINUX_DEVICE_DIRECTORY == 0 {
        return Err(LINUX_ENOTDIR);
    }
    let Some(parent) = linux_measured_directory_path(state) else {
        return Err(LINUX_ENOENT);
    };
    let mut measured_path = [0_u8; 64];
    let Some(output) = measured_path.get_mut(..parent.len()) else {
        return Err(LINUX_ENOENT);
    };
    output.copy_from_slice(parent);
    let mut length = parent.len();
    if !parent.is_empty() {
        measured_path[length] = b'/';
        length += 1;
    }
    let Some(output) = measured_path.get_mut(length..length + path.len()) else {
        return Err(LINUX_ENOENT);
    };
    output.copy_from_slice(path);
    length += path.len();
    linux_measured_path_kind(&measured_path[..length])
        .map(Some)
        .ok_or(LINUX_ENOENT)
}

pub(super) fn linux_rootfs_path_at(
    directory: u64,
    path: &[u8],
) -> Option<(u16, Option<crate::published_rootfs::Entry>)> {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return None;
    }
    let (at, requested) = (directory, path);
    let mut rooted = [0_u8; LINUX_PATH_MAX + crate::linux_overlay::PATH_CAPACITY];
    let path = linux_rooted_path(path, &mut rooted)?;
    let directory = if path.starts_with(b"/") {
        crate::published_rootfs::ROOT_HANDLE
    } else if directory as u32 == LINUX_AT_FDCWD {
        X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.load(Ordering::SeqCst)
    } else {
        linux_rootfs_descriptor(directory)
    };
    let found = (directory != 0)
        .then(|| crate::published_rootfs::lookup_at(directory, path))
        .flatten()
        .filter(|(handle, _)| !linux_rootfs_handle_hidden(*handle));
    found.or_else(|| linux_rootfs_bound_lookup(at, requested, false))
}

/// The image's file at the root filesystem path a bind mount leads
/// `path` (from `directory`, a rootfs handle as `linux_rootfs_path_at`
/// takes it) to, when it leads it elsewhere: /mnt/x where /usr is bound
/// on /mnt is the image's /usr/x. The final symlink is followed unless
/// `metadata`. None for a path no bind of a root filesystem directory
/// leads, which the lookup by the path itself answered.
fn linux_rootfs_bound_lookup(
    directory: u64,
    path: &[u8],
    metadata: bool,
) -> Option<(u16, Option<crate::published_rootfs::Entry>)> {
    if !crate::linux_mount_paths::root_bound() || path.is_empty() {
        return None;
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = if path.starts_with(b"/") {
        linux_root_prefix(&mut canonical)
    } else {
        linux_walk_start(directory, &mut canonical).ok()?
    };
    let length = linux_walk_path_components(&mut canonical, length, path, &mut 0, true).ok()?;
    let alloc::borrow::Cow::Owned(image) = crate::linux_overlay::image_path(&canonical[..length])?
    else {
        return None;
    };
    let found = if metadata {
        crate::published_rootfs::lookup_metadata_at(crate::published_rootfs::ROOT_HANDLE, &image)
    } else {
        crate::published_rootfs::lookup_at(crate::published_rootfs::ROOT_HANDLE, &image)
    };
    found.filter(|(handle, _)| !linux_rootfs_handle_hidden(*handle))
}

pub(super) fn linux_rootfs_handle_hidden(handle: u16) -> bool {
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    crate::published_rootfs::copy_path(handle, &mut path)
        .is_some_and(|length| crate::linux_overlay::hidden(&path[..length]))
}

/// Whether `path` (from `directory`) names the program a live process of
/// the domain is executing.
pub(super) fn linux_path_executing(directory: u64, path: &[u8]) -> bool {
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    let Ok(length) = linux_canonical_path_at(
        directory,
        path,
        (&mut canonical[1..]).try_into().expect("path capacity"),
    ) else {
        return false;
    };
    canonical[0] = b'/';
    crate::linux_exe::executing(
        X86_RUNTIME.LINUX_EXECUTION_INSTANCE.load(Ordering::SeqCst),
        &canonical[..length + 1],
    )
}

/// Whether a process of the domain has the overlay file of `generation`
/// open for writing: the current process from its descriptor tables, the
/// others from their saved records.
pub(super) fn linux_overlay_file_open_for_write(generation: u32) -> bool {
    let writer = |state: u16, file: u32| {
        state & !3 == LINUX_FILE_TMP_SCRATCH && state & 2 != 0 && file == generation
    };
    let current = (0..3).any(|index| {
        writer(
            X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index].load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index].load(Ordering::SeqCst),
        )
    }) || (0..LINUX_DEVICE_DESCRIPTOR_COUNT).any(|index| {
        X86_RUNTIME
            .ELF_PROBE_DEVICE_DESCRIPTORS
            .get(index)
            .zip(X86_RUNTIME.ELF_PROBE_TMP_FILE_GENERATIONS.get(index))
            .is_some_and(|(state, file)| {
                writer(state.load(Ordering::SeqCst), file.load(Ordering::SeqCst))
            })
    }) || linux_overflow_descriptors()
        .iter()
        .any(|(_, entry)| writer(entry.state, entry.generation));
    if current {
        return true;
    }
    let me = current_linux_process_pid();
    (0..linux_process::live_process_slots())
        .filter_map(linux_process::live_process_pid_at)
        .filter(|pid| *pid != me)
        .any(|pid| {
            // The fixed table is looked at under the record lock, the
            // table above it (its own lock) after.
            with_valid_linux_process_runtime_state(pid, |state| {
                let descriptors = &state.descriptors;
                let fixed = descriptors
                    .stdio_devices
                    .iter()
                    .zip(&descriptors.stdio_tmp_generations)
                    .any(|(state, file)| writer(*state, *file))
                    || descriptors
                        .devices
                        .iter()
                        .zip(&descriptors.tmp_generations)
                        .any(|(state, file)| writer(*state, *file));
                (fixed, descriptors.overflow)
            })
            .is_some_and(|(fixed, overflow)| {
                fixed
                    || linux_saved_overflow_entries(overflow)
                        .iter()
                        .any(|(_, entry)| writer(entry.state, entry.generation))
            })
        })
}

/// The descriptors above the fixed table of a saved descriptor table
/// (another process's), whose table above it is `overflow`, in order.
pub(super) fn linux_saved_overflow_entries(
    overflow: u32,
) -> Vec<(u64, crate::linux_fd_table::Entry)> {
    if overflow == 0 || !crate::linux_fd_table::active() {
        return Vec::new();
    }
    crate::linux_fd_table::entries(overflow)
}

pub(super) fn linux_overlay_descriptor_handle(
    descriptor: u64,
) -> Option<crate::linux_overlay::Handle> {
    // A /proc file's generation slot holds its own value (a pid, a
    // descriptor, a mount-table change count), never an overlay node's.
    if linux_proc_generation_kind(linux_device_descriptor(descriptor)) {
        return None;
    }
    let generation = if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        linux_overflow_entry(descriptor)?.generation
    } else if let Some(generation) = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS.get(index))
    {
        generation.load(Ordering::SeqCst)
    } else {
        descriptor
            .checked_sub(LINUX_AUX_DESCRIPTOR_FIRST)
            .and_then(|index| {
                X86_RUNTIME
                    .ELF_PROBE_TMP_FILE_GENERATIONS
                    .get(index as usize)
            })
            .map(|generation| generation.load(Ordering::SeqCst))?
    };
    crate::linux_overlay::from_generation(generation)
}

pub(super) fn linux_copy_up_descriptor(
    descriptor: u64,
) -> Result<crate::linux_overlay::Handle, u64> {
    if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
        return Ok(handle);
    }
    if !linux_descriptor_open(descriptor) {
        return Err(LINUX_EBADF);
    }
    let rootfs_handle = linux_rootfs_descriptor(descriptor);
    let entry = crate::published_rootfs::entry(rootfs_handle).ok_or(LINUX_EROFS)?;
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = crate::published_rootfs::copy_path(rootfs_handle, &mut path).ok_or(LINUX_EROFS)?;
    let handle = if let Some(metadata) = crate::linux_overlay::lookup(&path[..length]) {
        metadata.handle
    } else {
        linux_copy_up_entry(&path[..length], entry).map_err(|error| {
            if error == LINUX_EROFS {
                LINUX_ENOSPC
            } else {
                error
            }
        })?
    };
    let generation = crate::linux_overlay::generation(handle);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Generation).store(generation, Ordering::SeqCst);
    Ok(handle)
}

/// Writes the current process's root directory (its chroot, a canonical
/// path without a leading slash) at the start of `output`; its length, 0
/// for the domain's root. Absolute paths and symlink targets start here.
pub(super) fn linux_root_prefix(output: &mut [u8]) -> usize {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Relaxed) {
        return 0;
    }
    linux_process::with_live_process_root(current_linux_process_pid(), |root| {
        match output.get_mut(..root.len()) {
            Some(start) => {
                start.copy_from_slice(root);
                root.len()
            }
            None => 0,
        }
    })
    .unwrap_or(0)
}

/// The length of the current root directory when canonical `path` is at
/// or under it, else 0: where ".." stops.
pub(super) fn linux_root_floor(path: &[u8]) -> usize {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Relaxed) {
        return 0;
    }
    linux_process::with_live_process_root(current_linux_process_pid(), |root| {
        let inside = !root.is_empty()
            && path.starts_with(root)
            && (path.len() == root.len() || path[root.len()] == b'/');
        if inside {
            root.len()
        } else {
            0
        }
    })
    .unwrap_or(0)
}

/// An absolute `path` as the domain sees it from the current process's
/// root directory ("/" + root + path), in `buffer`; other paths as given.
/// None when it does not fit.
fn linux_rooted_path<'a>(path: &'a [u8], buffer: &'a mut [u8]) -> Option<&'a [u8]> {
    if !path.starts_with(b"/") {
        return Some(path);
    }
    let Some(root_length) = buffer.get_mut(1..).map(linux_root_prefix) else {
        return Some(path);
    };
    if root_length == 0 {
        return Some(path);
    }
    let length = 1 + root_length + path.len();
    let destination = buffer.get_mut(1 + root_length..length)?;
    destination.copy_from_slice(path);
    buffer[0] = b'/';
    Some(&buffer[..length])
}

/// Whether the current process has a root directory of its own (chroot).
pub(super) fn linux_chrooted() -> bool {
    X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Relaxed)
        && linux_process::with_live_process_root(current_linux_process_pid(), |root| {
            !root.is_empty()
        })
        .unwrap_or(false)
}

pub(super) fn linux_canonical_path_at(
    directory: u64,
    path: &[u8],
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Result<usize, u64> {
    // An empty pathname names nothing; calls that accept AT_EMPTY_PATH use
    // the descriptor before getting here.
    if path.is_empty() {
        return Err(LINUX_ENOENT);
    }
    let length = if path.starts_with(b"/") {
        linux_root_prefix(output)
    } else {
        linux_walk_start(directory, output)?
    };
    let length = linux_walk_path_components(output, length, path, &mut 0, true)?;
    crate::linux_mounts::note_walk(linux_mount_space(), &output[..length]);
    if length == 0 {
        return Err(LINUX_EISDIR);
    }
    if output[..length].starts_with(b"sys/fs/cgroup/") {
        linux_cgroup_ensure_root();
    }
    if output[..length].starts_with(b"sys/kernel/mm") {
        linux_refresh_hugepages_sysfs();
    }
    if output[..length].starts_with(b"sys/devices/system/node") {
        linux_refresh_numa_sysfs();
    }
    if output[..length].starts_with(b"dev/dri") || output[..length].starts_with(b"sys/dev") {
        crate::linux_drm::ensure_nodes();
    }
    if &output[..length] == b"dev" || output[..length].starts_with(b"dev/") {
        linux_ensure_dev_nodes();
        crate::linux_loop::ensure_nodes();
    } else if &output[..length] == b"sys"
        || output[..length].starts_with(b"sys/block")
        || output[..length].starts_with(b"sys/dev")
    {
        crate::linux_loop::ensure_nodes();
    }
    // Root may search every directory; anyone else needs search permission
    // on each directory the walk passes through.
    if current_linux_credentials().is_some_and(|credentials| !credentials.filesystem_privileged()) {
        linux_check_path_walk(&output[..length])?;
    }
    Ok(length)
}

/// Where a relative path walk from `directory` starts: the canonical path
/// of the current directory (AT_FDCWD) or of the directory `directory`
/// refers to, in `output`; 0 for the root.
pub(super) fn linux_walk_start(
    directory: u64,
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Result<usize, u64> {
    Ok(if directory as u32 == LINUX_AT_FDCWD {
        let overlay = X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.load(Ordering::SeqCst);
        let rootfs = X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.load(Ordering::SeqCst);
        let kernel_directory = (overlay == 0 && rootfs == 0)
            .then(|| {
                linux_measured_directory_path(X86_RUNTIME.ELF_PROBE_CWD.load(Ordering::SeqCst))
            })
            .flatten();
        if overlay != 0 {
            let handle = crate::linux_overlay::from_generation(overlay).ok_or(LINUX_ENOENT)?;
            linux_shown_overlay_path(handle, output).ok_or(LINUX_ENOENT)?
        } else if let Some(path) = kernel_directory {
            // A kernel directory (/proc/sys/kernel) is the working
            // directory: the walk starts from its path.
            let destination = output.get_mut(..path.len()).ok_or(LINUX_ENAMETOOLONG)?;
            destination.copy_from_slice(path);
            path.len()
        } else {
            linux_shown_rootfs_path(
                X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.load(Ordering::SeqCst),
                output,
            )
            .ok_or(LINUX_ENOENT)?
        }
    } else if let Some(handle) = linux_overlay_descriptor_handle(directory) {
        let metadata = crate::linux_overlay::metadata(handle).ok_or(LINUX_EBADF)?;
        if metadata.kind != crate::linux_overlay::NodeKind::Directory {
            return Err(LINUX_ENOTDIR);
        }
        linux_shown_overlay_path(handle, output).ok_or(LINUX_EBADF)?
    } else {
        let handle = linux_rootfs_descriptor(directory);
        if handle == 0 {
            if !linux_descriptor_open(directory) {
                return Err(LINUX_EBADF);
            }
            // A kernel directory (/proc, /sys/fs/cgroup, ...) walks from its
            // path; one without a path here (a /proc/PID directory) is left
            // to the caller's own lookup (ENOENT, which callers fall back
            // from); any other open descriptor cannot start a relative walk.
            let state = linux_device_descriptor(directory);
            let path = linux_measured_directory_path(state).ok_or(
                if state & LINUX_DEVICE_DIRECTORY != 0 {
                    LINUX_ENOENT
                } else {
                    LINUX_ENOTDIR
                },
            )?;
            let destination = output.get_mut(..path.len()).ok_or(LINUX_ENAMETOOLONG)?;
            destination.copy_from_slice(path);
            path.len()
        } else {
            linux_shown_rootfs_path(handle, output).ok_or(LINUX_ENOTDIR)?
        }
    })
}

/// The path the current process is shown for overlay file `handle`:
/// through the bind mount it reached it by (`crate::linux_path_views`),
/// else its own.
pub(super) fn linux_shown_overlay_path(
    handle: crate::linux_overlay::Handle,
    output: &mut [u8],
) -> Option<usize> {
    if crate::linux_path_views::any() {
        let mut stored = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        if let Some(shown) =
            crate::linux_overlay::copy_path_stored(handle, &mut stored).and_then(|length| {
                crate::linux_path_views::shown(
                    linux_execution_instance(),
                    current_linux_process_pid(),
                    crate::linux_path_views::Key::Overlay(crate::linux_overlay::generation(handle)),
                    &stored[..length],
                )
            })
        {
            output.get_mut(..shown.len())?.copy_from_slice(&shown);
            return Some(shown.len());
        }
    }
    crate::linux_overlay::copy_path(handle, output)
}

/// The path the current process is shown for image file `handle`, as
/// `linux_shown_overlay_path` gives an overlay file's.
pub(super) fn linux_shown_rootfs_path(handle: u16, output: &mut [u8]) -> Option<usize> {
    let length = crate::published_rootfs::copy_path(handle, output)?;
    if let Some(shown) = crate::linux_path_views::shown(
        linux_execution_instance(),
        current_linux_process_pid(),
        crate::linux_path_views::Key::Image(handle),
        &output[..length],
    ) {
        output.get_mut(..shown.len())?.copy_from_slice(&shown);
        return Some(shown.len());
    }
    Some(length)
}

/// Notes the bind mount the current process reached `key`'s file through
/// at canonical `path`, or that it reached it through none.
pub(super) fn linux_note_path_view(path: &[u8], key: crate::linux_path_views::Key) {
    let mount = crate::linux_mount_paths::bind_of(path);
    crate::linux_path_views::record(
        linux_execution_instance(),
        current_linux_process_pid(),
        key,
        mount
            .as_ref()
            .map(|(point, target)| (point.as_slice(), target.as_slice())),
    );
}

/// Notes the bind mount, if any, through which `path` (from `directory`)
/// reached the file just opened as `descriptor`.
fn linux_note_descriptor_view(directory: u64, path: &[u8], descriptor: u64) {
    if !crate::linux_mount_paths::bound() && !crate::linux_path_views::any() {
        return;
    }
    let key = if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
        crate::linux_path_views::Key::Overlay(crate::linux_overlay::generation(handle))
    } else {
        match linux_rootfs_descriptor(descriptor) {
            0 => return,
            handle => crate::linux_path_views::Key::Image(handle),
        }
    };
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    if let Ok(length) = linux_canonical_path_at(directory, path, &mut canonical) {
        linux_note_path_view(&canonical[..length], key);
    }
}

/// Walks `path`'s components onto the canonical path `output[..length]`,
/// as Linux's path walk does: `.` and `..` by name, and each component that
/// names one of the overlay's symlinks, except the last when `last_is_final`
/// (the caller decides whether to follow it), is replaced by the link's
/// target, relative to the link's directory unless absolute. `followed`
/// counts links across the whole walk; more than 40 is ELOOP. The image's
/// own links are followed by its lookups.
/// Whether a component of `path` is longer than NAME_MAX (ENAMETOOLONG),
/// which Linux finds before it looks anything up.
pub(super) fn linux_path_component_too_long(path: &[u8]) -> bool {
    path.split(|byte| *byte == b'/')
        .any(|component| component.len() > 255)
}

fn linux_walk_path_components(
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
    mut length: usize,
    path: &[u8],
    followed: &mut usize,
    last_is_final: bool,
) -> Result<usize, u64> {
    const LINK_LIMIT: usize = 40;
    let follow_links = crate::linux_overlay::has_symlinks();
    let mut components = path
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty() && *component != b".")
        .peekable();
    while let Some(component) = components.next() {
        if component == b".." {
            // ".." at the process's root directory stays there (chroot).
            let floor = linux_root_floor(&output[..length]);
            if length > floor {
                length = output[..length]
                    .iter()
                    .rposition(|byte| *byte == b'/')
                    .unwrap_or(0)
                    .max(floor);
            }
            continue;
        }
        if component.contains(&0) {
            return Err(LINUX_ENOENT);
        }
        // NAME_MAX: no name in a directory is longer.
        if component.len() > 255 {
            return Err(LINUX_ENAMETOOLONG);
        }
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
        let is_final = last_is_final && components.peek().is_none();
        if !follow_links || is_final {
            continue;
        }
        let Some(link) = crate::linux_overlay::lookup(&output[..length])
            .filter(|metadata| metadata.kind == crate::linux_overlay::NodeKind::Symlink)
        else {
            continue;
        };
        *followed += 1;
        if *followed > LINK_LIMIT {
            return Err(LINUX_ELOOP);
        }
        linux_check_follow_link(&output[..length], link.owner)?;
        // The target is kept on the heap, at its own length: the walk
        // recurses into it, as deep as links lead to links.
        let mut target = Vec::new();
        target
            .try_reserve_exact(link.size)
            .map_err(|_| LINUX_ENOMEM)?;
        target.resize(link.size, 0);
        let target_length =
            crate::linux_overlay::read(link.handle, 0, &mut target).ok_or(LINUX_EIO)?;
        let base = if target[..target_length].starts_with(b"/") {
            linux_root_prefix(output)
        } else {
            linux_parent_path(&output[..length]).len()
        };
        length =
            linux_walk_path_components(output, base, &target[..target_length], followed, false)?;
    }
    Ok(length)
}

/// Looks up canonical `canonical[..length]` in the overlay, following the
/// overlay's symlinks at the last component when `follow` (up to 40, then
/// ELOOP). Returns the final canonical length, whether a link was
/// followed, and, if the overlay has the file there, its metadata;
/// otherwise the caller looks in the image.
pub(super) fn linux_overlay_lookup_following(
    canonical: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
    mut length: usize,
    follow: bool,
) -> Result<(usize, bool, Option<crate::linux_overlay::Metadata>), u64> {
    const LINK_LIMIT: usize = 40;
    for followed in 0..=LINK_LIMIT {
        let metadata = crate::linux_overlay::lookup(&canonical[..length]);
        let Some(link) = metadata
            .filter(|metadata| follow && metadata.kind == crate::linux_overlay::NodeKind::Symlink)
        else {
            return Ok((length, followed != 0, metadata));
        };
        linux_check_follow_link(&canonical[..length], link.owner)?;
        let mut target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let target_length =
            crate::linux_overlay::read(link.handle, 0, &mut target).ok_or(LINUX_EIO)?;
        let mut resolved = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        length = linux_resolve_link_target(
            &canonical[..length],
            &target[..target_length],
            &mut resolved,
        )?;
        canonical[..length].copy_from_slice(&resolved[..length]);
    }
    Err(LINUX_ELOOP)
}

/// fs.protected_symlinks (Linux's may_follow_link): while it is on, a
/// symlink in a sticky, world-writable directory is followed only by its
/// owner, or when the directory's owner owns it too; anyone else gets
/// EACCES. Root is held to it like everyone.
pub(super) fn linux_check_follow_link(path: &[u8], link_owner: u32) -> Result<(), u64> {
    // A nosymfollow mount's symlinks are not followed (readlink still
    // reads them).
    if linux_mount_flags(path) & crate::linux_mounts::NO_SYMFOLLOW != 0 {
        return Err(LINUX_ELOOP);
    }
    if linux_proc_sysctl_value(b"sys/fs/protected_symlinks").unwrap_or(0) == 0 {
        return Ok(());
    }
    let Some(credentials) = current_linux_credentials() else {
        return Ok(());
    };
    if credentials.user.filesystem == link_owner {
        return Ok(());
    }
    let Some(directory) = linux_path_access(linux_parent_path(path)) else {
        return Ok(());
    };
    const STICKY_WORLD_WRITABLE: u32 = 0o1002;
    if directory.mode & STICKY_WORLD_WRITABLE != STICKY_WORLD_WRITABLE
        || directory.owner == link_owner
    {
        return Ok(());
    }
    Err(LINUX_EACCES)
}

/// fs.protected_hardlinks (Linux's may_linkat): while it is on, only the
/// file's owner, root, or a caller who may read and write the file (a
/// regular file neither set-user-ID nor executable set-group-ID) may give
/// it another name; others get EPERM.
pub(super) fn linux_check_hardlink_source(
    source: crate::linux_overlay::Metadata,
) -> Result<(), u64> {
    const SET_USER_ID: u32 = 0o4000;
    const SET_GROUP_ID: u32 = 0o2000;
    const GROUP_EXECUTE: u32 = 0o010;
    if linux_proc_sysctl_value(b"sys/fs/protected_hardlinks").unwrap_or(0) == 0 {
        return Ok(());
    }
    let Some(credentials) = current_linux_credentials() else {
        return Ok(());
    };
    if credentials.user.filesystem == source.owner || credentials.filesystem_privileged() {
        return Ok(());
    }
    let safe = source.kind == crate::linux_overlay::NodeKind::File
        && source.mode & SET_USER_ID == 0
        && source.mode & (SET_GROUP_ID | GROUP_EXECUTE) != SET_GROUP_ID | GROUP_EXECUTE;
    let readable_writable = safe
        && linux_check_access(
            Some(linux_overlay_file_access(source)),
            linox_credentials::access::READ | linox_credentials::access::WRITE,
            false,
        )
        .is_ok();
    if readable_writable {
        Ok(())
    } else {
        Err(LINUX_EPERM)
    }
}

/// The canonical path a symlink at canonical `link` leads to: its `target`,
/// relative to the link's directory unless absolute, with symlinks among
/// the target's directories followed.
pub(super) fn linux_resolve_link_target(
    link: &[u8],
    target: &[u8],
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Result<usize, u64> {
    let base = if target.starts_with(b"/") {
        linux_root_prefix(output)
    } else {
        let parent = linux_parent_path(link);
        output[..parent.len()].copy_from_slice(parent);
        parent.len()
    };
    let length = linux_walk_path_components(output, base, target, &mut 0, true)?;
    if length == 0 {
        return Err(LINUX_EISDIR);
    }
    Ok(length)
}

/// What the path walk finds at a directory prefix of a canonical path.
enum LinuxWalkStep {
    Directory(linox_credentials::FileAccess),
    NotDirectory,
    /// A symlink, a kernel directory (/proc, /dev) or nothing: the walk
    /// cannot judge it, and the lookup that follows reports what it finds.
    Unknown,
}

fn linux_walk_step(prefix: &[u8]) -> LinuxWalkStep {
    if let Some(metadata) = crate::linux_overlay::lookup(prefix) {
        return match metadata.kind {
            crate::linux_overlay::NodeKind::Directory => {
                LinuxWalkStep::Directory(linux_overlay_file_access(metadata))
            }
            crate::linux_overlay::NodeKind::Symlink => LinuxWalkStep::Unknown,
            _ => LinuxWalkStep::NotDirectory,
        };
    }
    let Some(image) = crate::linux_overlay::image_path(prefix) else {
        return LinuxWalkStep::Unknown;
    };
    match crate::published_rootfs::lookup_at(crate::published_rootfs::ROOT_HANDLE, &image) {
        Some((_, Some(entry))) => match entry.kind {
            crate::published_rootfs::EntryKind::Directory => {
                LinuxWalkStep::Directory(linox_credentials::FileAccess {
                    owner: entry.owner,
                    group: entry.group,
                    mode: entry.mode & 0o7777,
                    directory: true,
                })
            }
            crate::published_rootfs::EntryKind::Symlink => LinuxWalkStep::Unknown,
            _ => LinuxWalkStep::NotDirectory,
        },
        _ => LinuxWalkStep::Unknown,
    }
}

/// The directories above the last component of canonical `path`, outermost
/// first.
fn linux_walk_prefixes(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .map(|(index, _)| &path[..index])
}

/// Linux's path walk checks on the directories above the last component of
/// canonical `path`: each must be a directory (ENOTDIR) the caller may
/// search (EACCES).
fn linux_check_path_walk(path: &[u8]) -> Result<(), u64> {
    for prefix in linux_walk_prefixes(path) {
        match linux_walk_step(prefix) {
            LinuxWalkStep::Directory(directory) => {
                linux_check_access(Some(directory), linox_credentials::access::EXECUTE, false)?
            }
            LinuxWalkStep::NotDirectory => return Err(LINUX_ENOTDIR),
            LinuxWalkStep::Unknown => return Ok(()),
        }
    }
    Ok(())
}

/// The error for canonical `path` that does not exist: ENOTDIR when the
/// walk passes through something that is not a directory, else ENOENT.
/// Computed only on failure, so lookups that succeed pay nothing.
pub(super) fn linux_missing_path_error(path: &[u8]) -> u64 {
    for prefix in linux_walk_prefixes(path) {
        match linux_walk_step(prefix) {
            LinuxWalkStep::Directory(_) => {}
            LinuxWalkStep::NotDirectory => return LINUX_ENOTDIR,
            LinuxWalkStep::Unknown => break,
        }
    }
    LINUX_ENOENT
}

/// The owner, group and mode of the file at canonical `path`: the
/// overlay's copy if there is one, else the image's. The kernel's own files
/// (devices, /proc) and the root directory have none, and permission checks
/// leave them alone.
pub(super) fn linux_path_access(path: &[u8]) -> Option<linox_credentials::FileAccess> {
    if let Some(metadata) = crate::linux_overlay::lookup(path) {
        return Some(linox_credentials::FileAccess {
            owner: metadata.owner,
            group: metadata.group,
            mode: metadata.mode & 0o7777,
            directory: metadata.kind == crate::linux_overlay::NodeKind::Directory,
        });
    }
    let image = crate::linux_overlay::image_path(path)?;
    let (_, entry) =
        crate::published_rootfs::lookup_at(crate::published_rootfs::ROOT_HANDLE, &image)?;
    let entry = entry?;
    Some(linox_credentials::FileAccess {
        owner: entry.owner,
        group: entry.group,
        mode: entry.mode & 0o7777,
        directory: entry.kind == crate::published_rootfs::EntryKind::Directory,
    })
}

/// Checks that the current process may have `wanted` (bits of
/// `linox_credentials::access`) on `file`, judged by its filesystem ids, or
/// by its real ids for access(2): EACCES if not.
pub(super) fn linux_check_access(
    file: Option<linox_credentials::FileAccess>,
    wanted: u32,
    real_ids: bool,
) -> Result<(), u64> {
    let (Some(file), Some(mut credentials)) = (file, current_linux_credentials()) else {
        return Ok(());
    };
    if real_ids {
        credentials.user.filesystem = credentials.user.real;
        credentials.group.filesystem = credentials.group.real;
    }
    if credentials.filesystem_privileged() && wanted & linox_credentials::access::EXECUTE == 0 {
        return Ok(());
    }
    let allowed = linux_process::with_live_process_groups(current_linux_process_pid(), |groups| {
        credentials.may_access(groups, file, wanted)
    })
    .unwrap_or(true);
    if allowed {
        Ok(())
    } else {
        Err(LINUX_EACCES)
    }
}

/// Checks that the current process may have `wanted` on the file at
/// canonical `path`.
pub(super) fn linux_check_path_access(path: &[u8], wanted: u32) -> Result<(), u64> {
    linux_check_access(linux_path_access(path), wanted, false)
}

/// The directory holding canonical `path` (the root directory is empty).
pub(super) fn linux_parent_path(path: &[u8]) -> &[u8] {
    path.iter()
        .rposition(|byte| *byte == b'/')
        .map_or(&[][..], |separator| &path[..separator])
}

/// Checks that the current process may add or remove the entry at
/// canonical `path`: write and search permission on its directory, and in
/// a sticky directory (removal only) ownership of the entry or directory,
/// which fails with EPERM.
pub(super) fn linux_check_entry_change(path: &[u8], removal: bool) -> Result<(), u64> {
    if linux_read_only_path(linux_parent_path(path)) {
        return Err(LINUX_EROFS);
    }
    // A parent that is not a directory fails the path walk itself (ENOTDIR,
    // ELOOP), which the caller reports.
    let parent = linux_path_access(linux_parent_path(path)).filter(|parent| parent.directory);
    linux_check_access(
        parent,
        linox_credentials::access::WRITE | linox_credentials::access::EXECUTE,
        false,
    )?;
    let (Some(parent), Some(credentials)) = (parent, current_linux_credentials()) else {
        return Ok(());
    };
    const STICKY: u32 = 0o1000;
    if removal
        && parent.mode & STICKY != 0
        && !credentials.owns(parent)
        && linux_path_access(path).is_some_and(|entry| !credentials.owns(entry))
    {
        return Err(LINUX_EPERM);
    }
    Ok(())
}

pub(super) fn linux_overlay_parent_exists(path: &[u8]) -> bool {
    let Some(separator) = path.iter().rposition(|byte| *byte == b'/') else {
        return true;
    };
    let parent = &path[..separator];
    matches!(
        parent,
        b"dev/shm"
            | b"dev/pts"
            | b"proc"
            | b"run"
            | b"sys"
            | b"sys/fs/cgroup"
            | b"sys/fs/bpf"
            | b"sys/kernel/debug"
            | b"sys/kernel/tracing"
            | b"sys/kernel/security"
            | b"sys/fs/pstore"
    ) || crate::linux_overlay::lookup(parent)
        .is_some_and(|metadata| metadata.kind == crate::linux_overlay::NodeKind::Directory)
        || crate::published_rootfs::lookup_at(
            crate::published_rootfs::ROOT_HANDLE,
            &crate::linux_overlay::image_location(parent),
        )
        .is_some_and(|(_, entry)| {
            entry.is_none_or(|entry| entry.kind == crate::published_rootfs::EntryKind::Directory)
        })
}

pub(super) fn linux_rootfs_metadata_path_at(
    directory: u64,
    path: &[u8],
) -> Option<(u16, Option<crate::published_rootfs::Entry>)> {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return None;
    }
    let (at, requested) = (directory, path);
    let mut rooted = [0_u8; LINUX_PATH_MAX + crate::linux_overlay::PATH_CAPACITY];
    let path = linux_rooted_path(path, &mut rooted)?;
    let directory = if path.starts_with(b"/") {
        crate::published_rootfs::ROOT_HANDLE
    } else if directory as u32 == LINUX_AT_FDCWD {
        X86_RUNTIME.ELF_PROBE_ROOTFS_CWD.load(Ordering::SeqCst)
    } else {
        linux_rootfs_descriptor(directory)
    };
    let found = (directory != 0)
        .then(|| crate::published_rootfs::lookup_metadata_at(directory, path))
        .flatten()
        .filter(|(handle, _)| !linux_rootfs_handle_hidden(*handle));
    found.or_else(|| linux_rootfs_bound_lookup(at, requested, true))
}

pub(super) fn linux_rootfs_descriptor(descriptor: u64) -> u16 {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_overflow_entry(descriptor).map_or(0, |entry| entry.rootfs);
    }
    if let Some(handle) = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS.get(index))
    {
        return handle.load(Ordering::SeqCst);
    }
    descriptor
        .checked_sub(LINUX_AUX_DESCRIPTOR_FIRST)
        .and_then(|index| X86_RUNTIME.ELF_PROBE_ROOTFS_DESCRIPTORS.get(index as usize))
        .map(|handle| handle.load(Ordering::SeqCst))
        .unwrap_or(0)
}

pub(super) fn linux_rootfs_entry(descriptor: u64) -> Option<crate::published_rootfs::Entry> {
    crate::published_rootfs::entry(linux_rootfs_descriptor(descriptor))
}

pub(super) fn linux_rootfs_inode(handle: u16) -> u64 {
    1024 + u64::from(handle)
}

pub(super) fn linux_rootfs_mode(entry: &crate::published_rootfs::Entry) -> u32 {
    let kind = match entry.kind {
        crate::published_rootfs::EntryKind::File => 0o100000,
        crate::published_rootfs::EntryKind::Hardlink => 0o100000,
        crate::published_rootfs::EntryKind::Directory => 0o040000,
        crate::published_rootfs::EntryKind::Symlink => 0o120000,
    };
    kind | entry.mode & 0o7777
}

/// The root filesystem's device, 0:1, as /proc/self/mountinfo and
/// statmount name the root mount's (`linux_kernel_filesystem`): stat's
/// st_dev for the image's files, as for the overlay's
/// (`linux_mount_paths::device_of`).
pub(super) const LINUX_ROOT_FILESYSTEM_DEVICE: u32 = crate::linux_mount_paths::ROOT_DEVICE;

pub(super) fn linux_rootfs_stat(
    handle: u16,
    entry: Option<crate::published_rootfs::Entry>,
) -> [u8; LINUX_STAT_SIZE] {
    let entry = entry.as_ref();
    let mode = entry.map_or(LINUX_STAT_DIRECTORY_MODE, linux_rootfs_mode);
    let mut stat = linux_stat(mode, linux_rootfs_inode(handle));
    stat[0..8].copy_from_slice(&u64::from(LINUX_ROOT_FILESYSTEM_DEVICE).to_ne_bytes());
    let (owner, group) = entry.map_or((0, 0), |entry| (entry.owner, entry.group));
    stat[28..32].copy_from_slice(&owner.to_ne_bytes());
    stat[32..36].copy_from_slice(&group.to_ne_bytes());
    let size = entry.map_or(0, |entry| entry.data().len() as u64);
    stat[48..56].copy_from_slice(&size.to_ne_bytes());
    stat[64..72].copy_from_slice(&size.div_ceil(512).to_ne_bytes());
    stat
}

pub(super) fn linux_overlay_stat(
    metadata: crate::linux_overlay::Metadata,
) -> [u8; LINUX_STAT_SIZE] {
    let kind = match metadata.kind {
        crate::linux_overlay::NodeKind::File => 0o100000,
        crate::linux_overlay::NodeKind::Directory => 0o040000,
        crate::linux_overlay::NodeKind::Symlink => 0o120000,
        crate::linux_overlay::NodeKind::Fifo => 0o010000,
        crate::linux_overlay::NodeKind::Socket => 0o140000,
        crate::linux_overlay::NodeKind::CharacterDevice => 0o020000,
        crate::linux_overlay::NodeKind::BlockDevice => 0o060000,
    };
    let mut stat = linux_stat(kind | metadata.mode, metadata.handle.inode());
    stat[0..8].copy_from_slice(&u64::from(metadata.filesystem).to_ne_bytes());
    stat[56..64].copy_from_slice(&u64::from(metadata.block_size).to_ne_bytes());
    stat[40..48].copy_from_slice(&u64::from(metadata.device).to_ne_bytes());
    stat[16..24].copy_from_slice(&u64::from(metadata.links).to_ne_bytes());
    stat[28..32].copy_from_slice(&metadata.owner.to_ne_bytes());
    stat[32..36].copy_from_slice(&metadata.group.to_ne_bytes());
    stat[48..56].copy_from_slice(&(metadata.size as u64).to_ne_bytes());
    stat[64..72].copy_from_slice(&metadata.sectors.to_ne_bytes());
    stat[72..80].copy_from_slice(&metadata.atime.0.to_ne_bytes());
    stat[80..88].copy_from_slice(&metadata.atime.1.to_ne_bytes());
    stat[88..96].copy_from_slice(&metadata.mtime.0.to_ne_bytes());
    stat[96..104].copy_from_slice(&metadata.mtime.1.to_ne_bytes());
    stat[104..112].copy_from_slice(&metadata.ctime.0.to_ne_bytes());
    stat[112..120].copy_from_slice(&metadata.ctime.1.to_ne_bytes());
    stat
}

pub(super) fn linux_openat(directory: u64, path_address: u64, flags: u64, mode: u64) -> u64 {
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    linux_openat_path(directory, path, path_length, flags, mode)
}

/// openat(2) of `path[..path_length]`, a path already in kernel memory.
pub(super) fn linux_openat_path(
    directory: u64,
    path: [u8; LINUX_PATH_MAX],
    path_length: usize,
    flags: u64,
    mode: u64,
) -> u64 {
    let opened = linux_landlock_opened(
        linux_open_file_at(directory, path, path_length, flags, mode, false),
        flags,
    );
    if opened < LINUX_RETURN_TO_KERNEL {
        linux_note_descriptor_view(directory, &path[..path_length], opened);
    }
    if opened == LINUX_ENOENT {
        linux_volume_damage(directory, &path[..path_length]);
    }
    opened
}

/// Looks for the damage a lookup of `path` (from `directory`) that found
/// nothing met on a volume: a directory entry naming no valid inode, or an
/// inode with no links or file type. The volume records it as ext4 does,
/// and the call fails with EFSCORRUPTED ([`linux_volume_failures`]).
fn linux_volume_damage(directory: u64, path: &[u8]) {
    if !crate::linux_blockfs::any_mounted() {
        return;
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let Ok(length) = linux_canonical_path_at(u64::from(directory as u32), path, &mut canonical)
    else {
        return;
    };
    let storage = crate::linux_mount_paths::storage(&canonical[..length]);
    crate::linux_blockfs::note_damage_at(&storage);
}

/// Reports the damage this domain's volumes found during the system call
/// that returns `result`, as ext4 reports each error (fanotify's
/// FAN_FS_ERROR, on the inode at fault, or on none for a bitmap). A call
/// that failed fails with the first damage's errno (EBADMSG for a
/// checksum that does not match, EFSCORRUPTED for other damage) in place
/// of what the volume's lookup or read made of it (ENOENT, EIO), as the
/// ext4 operation that met the damage fails with it.
pub(in crate::arch::x86_64) fn linux_volume_failures(result: u64) -> u64 {
    let failures = crate::linux_blockfs::take_failures();
    let Some(first) = failures.first() else {
        return result;
    };
    for failure in failures.iter().filter(|failure| failure.notify) {
        linux_fanotify_fs_error(
            failure.fsid,
            failure.handle.map(linux_handle_identity),
            failure.errno as i32,
        );
    }
    // A Linux errno, not a value or one of the kernel's own markers.
    let failed = (1..=133).contains(&result.wrapping_neg());
    if failed {
        first.errno.wrapping_neg()
    } else {
        result
    }
}

/// Whether mount(2)'s option string at `data_address` holds `option`
/// among its comma-separated options.
pub(super) fn linux_mount_data_has(data_address: u64, option: &[u8]) -> bool {
    let mut data = [0_u8; 512];
    data_address != 0
        && copy_linux_c_string(data_address, &mut data).is_ok_and(|length| {
            data[..length]
                .split(|byte| *byte == b',')
                .any(|given| given == option)
        })
}
