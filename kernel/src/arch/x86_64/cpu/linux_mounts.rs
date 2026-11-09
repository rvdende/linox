use super::*;

fn linux_mount_id_request(address: u64) -> Result<(u64, u64), u64> {
    const VERSION_ZERO_SIZE: usize = 24;
    const VERSION_ONE_SIZE: usize = 32;
    let mut request = [0_u8; VERSION_ONE_SIZE];
    if !copy_from_linux_user(address, &mut request[..4]) {
        return Err(LINUX_EFAULT);
    }
    let size = u32::from_ne_bytes(request[..4].try_into().unwrap()) as usize;
    if !(VERSION_ZERO_SIZE..=PAGE_SIZE).contains(&size) {
        return Err(LINUX_EINVAL);
    }
    let copied = size.min(VERSION_ONE_SIZE);
    if !copy_from_linux_user(address, &mut request[..copied]) {
        return Err(LINUX_EFAULT);
    }
    if request[4..8].iter().any(|byte| *byte != 0) {
        return Err(LINUX_EINVAL);
    }
    if size > VERSION_ONE_SIZE {
        let mut extension = [0_u8; 64];
        let mut offset = VERSION_ONE_SIZE;
        while offset < size {
            let length = (size - offset).min(extension.len());
            if !copy_from_linux_user(address + offset as u64, &mut extension[..length]) {
                return Err(LINUX_EFAULT);
            }
            if extension[..length].iter().any(|byte| *byte != 0) {
                return Err(LINUX_E2BIG);
            }
            offset += length;
        }
    }
    let namespace = if size >= VERSION_ONE_SIZE {
        u64::from_ne_bytes(request[24..32].try_into().unwrap())
    } else {
        0
    };
    let current_namespace = linux_mount::current_namespace_id().ok_or(LINUX_EINVAL)?;
    // The first unique mount id is above 2^31 (MNT_UNIQUE_ID_OFFSET);
    // LSMT_ROOT is all ones.
    if u64::from_ne_bytes(request[8..16].try_into().unwrap()) <= 1 << 31 {
        return Err(LINUX_EINVAL);
    }
    if namespace != 0 && namespace != current_namespace {
        return Err(LINUX_ENOENT);
    }
    Ok((
        u64::from_ne_bytes(request[8..16].try_into().unwrap()),
        u64::from_ne_bytes(request[16..24].try_into().unwrap()),
    ))
}

/// The domain mount of the current namespace with unique id `unique`.
fn linux_domain_mount_by_unique_id(unique: u64) -> Option<u32> {
    let local = u32::try_from(unique & u64::from(u32::MAX)).ok()?;
    if local <= 3 || linux_mount::current_unique_mount_id(u64::from(local)) != Some(unique) {
        return None;
    }
    crate::linux_mounts::with_mount(linux_mount_space(), local, |_| local)
}

/// The superblock magic statfs and statmount report for `filesystem`.
fn linux_filesystem_magic(filesystem: &[u8]) -> u64 {
    match filesystem {
        b"ext2" | b"ext3" | b"ext4" => u64::from(linox_ext2::MAGIC),
        b"tmpfs" | b"devtmpfs" => 0x0102_1994,
        b"ramfs" => 0x8584_58f6,
        b"proc" => 0x9fa0,
        b"sysfs" => 0x6265_6572,
        b"cgroup2" => 0x6367_7270,
        b"devpts" => 0x1cd1,
        b"mqueue" => 0x1980_0202,
        b"debugfs" => 0x6462_6720,
        b"tracefs" => 0x7472_6163,
        b"securityfs" => 0x7363_6673,
        b"pstore" => 0x6165_676c,
        b"bpf" => 0xcafe_4a11,
        b"hugetlbfs" => 0x9584_58f6,
        _ => 0x8584_58f6,
    }
}

/// A domain mount's options as mountinfo's sixth field shows them, in
/// Linux's order.
pub(super) fn linux_mount_options(flags: u32, output: &mut [u8], used: &mut usize) -> bool {
    use crate::linux_mounts::{
        NO_ATIME, NO_DEVICES, NO_DIRATIME, NO_EXEC, NO_SUID, NO_SYMFOLLOW, READ_ONLY, STRICT_ATIME,
    };
    append_linux_bytes(
        output,
        used,
        if flags & READ_ONLY != 0 { b"ro" } else { b"rw" },
    ) && (flags & NO_SUID == 0 || append_linux_bytes(output, used, b",nosuid"))
        && (flags & NO_DEVICES == 0 || append_linux_bytes(output, used, b",nodev"))
        && (flags & NO_EXEC == 0 || append_linux_bytes(output, used, b",noexec"))
        && (flags & NO_ATIME == 0 || append_linux_bytes(output, used, b",noatime"))
        && (flags & NO_DIRATIME == 0 || append_linux_bytes(output, used, b",nodiratime"))
        && (flags & (NO_ATIME | STRICT_ATIME) != 0
            || append_linux_bytes(output, used, b",relatime"))
        && (flags & NO_SYMFOLLOW == 0 || append_linux_bytes(output, used, b",nosymfollow"))
}

/// Canonical mount point `path` as the current process sees it from its
/// root ("/" + the rest), into `output`; None when it lies outside the
/// root.
pub(super) fn linux_shown_mount_point(
    path: &[u8],
    output: &mut [u8],
    used: &mut usize,
) -> Option<()> {
    let mut root = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let root_length = linux_root_prefix(&mut root);
    let rest = if root_length == 0 {
        path
    } else {
        let rest = path.strip_prefix(&root[..root_length])?;
        if !rest.is_empty() && !rest.starts_with(b"/") {
            return None;
        }
        rest.strip_prefix(b"/").unwrap_or(rest)
    };
    (append_linux_bytes(output, used, b"/") && append_linux_bytes(output, used, rest)).then_some(())
}

pub(super) fn linux_statmount(
    request_address: u64,
    output_address: u64,
    capacity: u64,
    flags: u64,
) -> u64 {
    const FIXED_SIZE: usize = 512;
    const SB_BASIC: u64 = 1;
    const MNT_BASIC: u64 = 2;
    const PROPAGATE_FROM: u64 = 4;
    const MNT_ROOT: u64 = 8;
    const MNT_POINT: u64 = 0x10;
    const FS_TYPE: u64 = 0x20;
    const MNT_NS_ID: u64 = 0x40;
    const MNT_OPTS: u64 = 0x80;
    const SUPPORTED: u64 = SB_BASIC
        | MNT_BASIC
        | PROPAGATE_FROM
        | MNT_ROOT
        | MNT_POINT
        | FS_TYPE
        | MNT_NS_ID
        | MNT_OPTS;
    if flags != 0 {
        return LINUX_EINVAL;
    }
    let (mount_id, requested) = match linux_mount_id_request(request_address) {
        Ok(request) => request,
        Err(error) => return error,
    };
    // Bits Linux does not know are left out of the answer; a string asked
    // for needs room past the structure (Linux's prepare_kstatmount).
    if requested & (MNT_ROOT | MNT_POINT | FS_TYPE | MNT_OPTS) != 0 && capacity == FIXED_SIZE as u64
    {
        return LINUX_EOVERFLOW;
    }
    let requested = requested & SUPPORTED;
    let Some(root_id) = linux_mount::current_unique_mount_id(1) else {
        return LINUX_EINVAL;
    };
    let Some(proc_id) = linux_mount::current_unique_mount_id(2) else {
        return LINUX_EINVAL;
    };
    let domain_mount = linux_domain_mount_by_unique_id(mount_id);
    let proc_mount = if mount_id == root_id || domain_mount.is_some() {
        false
    } else if mount_id == proc_id {
        true
    } else {
        return LINUX_ENOENT;
    };
    if !linux_mounts_visible() {
        return LINUX_EPERM;
    }
    let mut output = [0_u8; FIXED_SIZE + 2 * crate::linux_overlay::PATH_CAPACITY + 128];
    output[8..16].copy_from_slice(&requested.to_ne_bytes());
    if let Some(local) = domain_mount {
        let space = linux_mount_space();
        let filled = crate::linux_mounts::with_mount(space, local, |mount| {
            linux_statmount_domain(mount, requested, &mut output)
        });
        let used = match filled {
            Some(Ok(used)) => used,
            Some(Err(error)) => return error,
            None => return LINUX_ENOENT,
        };
        return linux_statmount_copy(&mut output, used, capacity, output_address);
    }
    if requested & SB_BASIC != 0 {
        output[16..20].copy_from_slice(&0_u32.to_ne_bytes());
        output[20..24].copy_from_slice(&(if proc_mount { 2_u32 } else { 1 }).to_ne_bytes());
        output[24..32]
            .copy_from_slice(&(if proc_mount { 0x9fa0_u64 } else { 0x8584_58f6 }).to_ne_bytes());
        output[32..36].copy_from_slice(&(if proc_mount { 0_u32 } else { 1 }).to_ne_bytes());
    }
    if requested & MNT_BASIC != 0 {
        output[40..48].copy_from_slice(&mount_id.to_ne_bytes());
        output[48..56]
            .copy_from_slice(&(if proc_mount { root_id } else { mount_id }).to_ne_bytes());
        output[56..60].copy_from_slice(&(if proc_mount { 2_u32 } else { 1 }).to_ne_bytes());
        output[60..64].copy_from_slice(&1_u32.to_ne_bytes());
        output[64..72].copy_from_slice(&(if proc_mount { 0x0e_u64 } else { 0x07 }).to_ne_bytes());
        output[72..80].copy_from_slice(&(1_u64 << 18).to_ne_bytes());
    }
    if requested & PROPAGATE_FROM != 0 {
        output[96..104].copy_from_slice(&0_u64.to_ne_bytes());
    }
    if requested & MNT_NS_ID != 0 {
        output[112..120].copy_from_slice(
            &linux_mount::current_namespace_id()
                .unwrap_or(0)
                .to_ne_bytes(),
        );
    }
    let mut used = FIXED_SIZE;
    let mut append = |field: usize, value: &[u8]| -> bool {
        let offset = used - FIXED_SIZE;
        let Some(end) = used.checked_add(value.len() + 1) else {
            return false;
        };
        let Some(destination) = output.get_mut(used..end) else {
            return false;
        };
        destination[..value.len()].copy_from_slice(value);
        destination[value.len()] = 0;
        output[field..field + 4].copy_from_slice(&(offset as u32).to_ne_bytes());
        used = end;
        true
    };
    if requested & MNT_OPTS != 0
        && !append(
            4,
            if proc_mount {
                b"rw,nosuid,nodev,noexec,relatime"
            } else {
                b"ro,nosuid,nodev"
            },
        )
        || requested & FS_TYPE != 0 && !append(36, if proc_mount { b"proc" } else { b"linox-root" })
        || requested & MNT_ROOT != 0 && !append(104, b"/")
        || requested & MNT_POINT != 0 && !append(108, if proc_mount { b"/proc" } else { b"/" })
    {
        return LINUX_EOVERFLOW;
    }
    linux_statmount_copy(&mut output, used, capacity, output_address)
}

/// Copies statmount's answer, `output[..used]` (the structure, then its
/// strings), to the caller's `capacity` bytes at `address` as Linux does:
/// the strings must fit with room to spare (EOVERFLOW), the structure is
/// cut to a smaller buffer, and `size` says how much was copied.
fn linux_statmount_copy(output: &mut [u8], used: usize, capacity: u64, address: u64) -> u64 {
    const FIXED_SIZE: usize = 512;
    let strings = used - FIXED_SIZE;
    if strings != 0 && used as u64 >= capacity {
        return LINUX_EOVERFLOW;
    }
    let header = (capacity as usize).min(FIXED_SIZE);
    output[..4].copy_from_slice(&((header + strings) as u32).to_ne_bytes());
    if strings != 0 && !copy_to_linux_user(address + FIXED_SIZE as u64, &output[FIXED_SIZE..used]) {
        return LINUX_EFAULT;
    }
    if copy_to_linux_user(address, &output[..header]) {
        0
    } else {
        LINUX_EFAULT
    }
}

/// Fills statmount's `output` with what `requested` asks of domain mount
/// `mount`; returns the size used.
fn linux_statmount_domain(
    mount: &crate::linux_mounts::Mount,
    requested: u64,
    output: &mut [u8],
) -> Result<usize, u64> {
    const FIXED_SIZE: usize = 512;
    const SB_BASIC: u64 = 1;
    const MNT_BASIC: u64 = 2;
    const PROPAGATE_FROM: u64 = 4;
    const MNT_ROOT: u64 = 8;
    const MNT_POINT: u64 = 0x10;
    const FS_TYPE: u64 = 0x20;
    const MNT_NS_ID: u64 = 0x40;
    const MNT_OPTS: u64 = 0x80;
    const MS_UNBINDABLE: u64 = 1 << 17;
    const MS_PRIVATE: u64 = 1 << 18;
    const MS_SLAVE: u64 = 1 << 19;
    const MS_SHARED: u64 = 1 << 20;
    use crate::linux_mounts::{NO_ATIME, NO_DEVICES, NO_EXEC, NO_SUID, READ_ONLY};
    let unique = |local: u32| linux_mount::current_unique_mount_id(u64::from(local)).unwrap_or(0);
    if requested & SB_BASIC != 0 {
        let (major, minor) = linux_device_numbers(mount.device);
        output[16..20].copy_from_slice(&major.to_ne_bytes());
        output[20..24].copy_from_slice(&minor.to_ne_bytes());
        output[24..32].copy_from_slice(&linux_filesystem_magic(&mount.filesystem).to_ne_bytes());
        // The superblock's SB_RDONLY, which a read-only mount sets.
        let superblock_flags = u32::from(mount.flags & READ_ONLY != 0);
        output[32..36].copy_from_slice(&superblock_flags.to_ne_bytes());
    }
    let sharing = mount.sharing;
    if requested & MNT_BASIC != 0 {
        output[40..48].copy_from_slice(&unique(mount.id).to_ne_bytes());
        output[48..56].copy_from_slice(&unique(mount.parent).to_ne_bytes());
        output[56..60].copy_from_slice(&mount.id.to_ne_bytes());
        output[60..64].copy_from_slice(&mount.parent.to_ne_bytes());
        let attributes = [
            (READ_ONLY, 1_u64),
            (NO_SUID, 2),
            (NO_DEVICES, 4),
            (NO_EXEC, 8),
            (NO_ATIME, 0x10),
        ]
        .into_iter()
        .filter(|(flag, _)| mount.flags & flag != 0)
        .fold(0, |attributes, (_, attribute)| attributes | attribute);
        output[64..72].copy_from_slice(&attributes.to_ne_bytes());
        let mut propagation = 0;
        if sharing.peer_group != 0 {
            propagation |= MS_SHARED;
        }
        if sharing.master != 0 {
            propagation |= MS_SLAVE;
        }
        if sharing.unbindable {
            propagation |= MS_UNBINDABLE;
        }
        if propagation == 0 {
            propagation = MS_PRIVATE;
        }
        output[72..80].copy_from_slice(&propagation.to_ne_bytes());
        output[80..88].copy_from_slice(&u64::from(sharing.peer_group).to_ne_bytes());
        output[88..96].copy_from_slice(&u64::from(sharing.master).to_ne_bytes());
    }
    if requested & PROPAGATE_FROM != 0 {
        output[96..104].copy_from_slice(&u64::from(sharing.master).to_ne_bytes());
    }
    if requested & MNT_NS_ID != 0 {
        output[112..120].copy_from_slice(
            &linux_mount::current_namespace_id()
                .unwrap_or(0)
                .to_ne_bytes(),
        );
    }
    let mut used = FIXED_SIZE;
    let mut append = |output: &mut [u8], field: usize, value: &[u8]| -> bool {
        let offset = used - FIXED_SIZE;
        let Some(end) = used.checked_add(value.len() + 1) else {
            return false;
        };
        let Some(destination) = output.get_mut(used..end) else {
            return false;
        };
        destination[..value.len()].copy_from_slice(value);
        destination[value.len()] = 0;
        output[field..field + 4].copy_from_slice(&(offset as u32).to_ne_bytes());
        used = end;
        true
    };
    let mut text = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    if requested & MNT_OPTS != 0 {
        let mut length = 0;
        if !linux_mount_options(mount.flags, &mut text, &mut length)
            || !append(output, 4, &text[..length])
        {
            return Err(LINUX_EOVERFLOW);
        }
    }
    if requested & FS_TYPE != 0 && !append(output, 36, &mount.filesystem) {
        return Err(LINUX_EOVERFLOW);
    }
    if requested & MNT_ROOT != 0 {
        let mut length = 0;
        if !append_linux_bytes(&mut text, &mut length, b"/")
            || !append_linux_bytes(&mut text, &mut length, &mount.root)
            || !append(output, 104, &text[..length])
        {
            return Err(LINUX_EOVERFLOW);
        }
    }
    if requested & MNT_POINT != 0 {
        let mut length = 0;
        if linux_shown_mount_point(&mount.path, &mut text, &mut length).is_none() {
            length = 0;
            if !append_linux_bytes(&mut text, &mut length, b"/")
                || !append_linux_bytes(&mut text, &mut length, &mount.path)
            {
                return Err(LINUX_EOVERFLOW);
            }
        }
        if !append(output, 108, &text[..length]) {
            return Err(LINUX_EOVERFLOW);
        }
    }
    Ok(used)
}

/// listmount(2): the unique ids of the mounts below a mount (all of them,
/// not just its children, the mount itself left out), or below the
/// caller's root with LSMT_ROOT (its root mount included), in id order or
/// reversed, after `last` when continuing a listing.
pub(super) fn linux_listmount(
    request_address: u64,
    output_address: u64,
    count: u64,
    flags: u64,
) -> u64 {
    const LSMT_ROOT: u64 = u64::MAX;
    const LISTMOUNT_REVERSE: u64 = 1;
    const MAXIMUM: u64 = 1_000_000;
    if flags & !LISTMOUNT_REVERSE != 0 {
        return LINUX_EINVAL;
    }
    if count > MAXIMUM {
        return LINUX_EOVERFLOW;
    }
    let (parent, last) = match linux_mount_id_request(request_address) {
        Ok(request) => request,
        Err(error) => return error,
    };
    // The first unique mount id is above 2^31 (MNT_UNIQUE_ID_OFFSET).
    if last != 0 && last <= 1 << 31 {
        return LINUX_EINVAL;
    }
    let Some(root) = linux_mount::current_unique_mount_id(1) else {
        return LINUX_EINVAL;
    };
    let Some(proc_mount) = linux_mount::current_unique_mount_id(2) else {
        return LINUX_EINVAL;
    };
    let space = linux_mount_space();
    let unique = |local: u32| linux_mount::current_unique_mount_id(u64::from(local)).unwrap_or(0);
    // Where the listing starts: a mount's root, or the caller's root.
    let mut root_path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let root_length = linux_root_prefix(&mut root_path);
    let (origin, directory): (u32, alloc::vec::Vec<u8>) = if parent == LSMT_ROOT {
        let path = &root_path[..root_length];
        let mut directory = alloc::vec::Vec::new();
        if directory.try_reserve_exact(path.len()).is_err() {
            return LINUX_ENOMEM;
        }
        directory.extend_from_slice(path);
        (crate::linux_mounts::root_mount_at(space, path), directory)
    } else if parent == root {
        (crate::linux_mounts::ROOT_ID, alloc::vec::Vec::new())
    } else if parent == proc_mount {
        (2, b"proc".to_vec())
    } else {
        let Some(local) = linux_domain_mount_by_unique_id(parent) else {
            return LINUX_ENOENT;
        };
        let Some(Some(directory)) = crate::linux_mounts::with_mount(space, local, |mount| {
            let mut path = alloc::vec::Vec::new();
            path.try_reserve_exact(mount.path.len()).ok()?;
            path.extend_from_slice(&mount.path);
            Some(path)
        }) else {
            return LINUX_ENOENT;
        };
        (local, directory)
    };
    if parent != LSMT_ROOT && !linux_mounts_visible() {
        return LINUX_EPERM;
    }
    let under = |path: &[u8]| {
        directory.is_empty()
            || path
                .strip_prefix(directory.as_slice())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
    };
    let mut candidates: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    // The kernel's own root and /proc mounts.
    if origin == crate::linux_mounts::ROOT_ID && under(b"") && parent != root {
        candidates.push(root);
    }
    if origin == crate::linux_mounts::ROOT_ID && under(b"proc") {
        candidates.push(proc_mount);
    }
    crate::linux_mounts::for_each_below(space, origin, &directory, |local| {
        if candidates.try_reserve(1).is_ok() {
            candidates.push(unique(local));
        }
    });
    candidates.retain(|mount| *mount != 0 && *mount != parent);
    candidates.sort_unstable();
    if flags & LISTMOUNT_REVERSE != 0 {
        candidates.reverse();
    }
    let mut returned = 0_u64;
    for &mount in &candidates {
        if returned >= count {
            break;
        }
        let after_cursor = if flags & LISTMOUNT_REVERSE != 0 {
            last == 0 || mount < last
        } else {
            mount > last
        };
        if !after_cursor {
            continue;
        }
        if !copy_to_linux_user(output_address + returned * 8, &mount.to_ne_bytes()) {
            return LINUX_EFAULT;
        }
        returned += 1;
    }
    returned
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxFilesystemKind {
    Root,
    Proc,
    Cgroup2,
    Pipe,
    Socket,
    Anonymous,
}

pub(super) fn linux_statfs_data(kind: LinuxFilesystemKind) -> [u8; 120] {
    const RAMFS_MAGIC: u64 = 0x8584_58f6;
    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
    const PIPEFS_MAGIC: u64 = 0x5049_5045;
    const SOCKFS_MAGIC: u64 = 0x534f_434b;
    const ANON_INODE_FS_MAGIC: u64 = 0x0904_1934;
    const ST_NOSUID: u64 = 2;
    const ST_NODEV: u64 = 4;
    const ST_NOEXEC: u64 = 8;
    const ST_VALID: u64 = 32;
    const ST_RELATIME: u64 = 4096;

    let (magic, filesystem_id, flags): (u64, u64, u64) = match kind {
        LinuxFilesystemKind::Root => (RAMFS_MAGIC, 1, ST_VALID | ST_NOSUID | ST_NODEV),
        LinuxFilesystemKind::Proc => (
            PROC_SUPER_MAGIC,
            2,
            ST_VALID | ST_NOSUID | ST_NODEV | ST_NOEXEC | ST_RELATIME,
        ),
        LinuxFilesystemKind::Cgroup2 => (
            CGROUP2_SUPER_MAGIC,
            3,
            ST_VALID | ST_NOSUID | ST_NODEV | ST_NOEXEC | ST_RELATIME,
        ),
        LinuxFilesystemKind::Pipe => (PIPEFS_MAGIC, 0, ST_VALID),
        LinuxFilesystemKind::Socket => (SOCKFS_MAGIC, 0, ST_VALID),
        LinuxFilesystemKind::Anonymous => (ANON_INODE_FS_MAGIC, 0, ST_VALID),
    };
    let mut stat = [0_u8; 120];
    stat[0..8].copy_from_slice(&magic.to_ne_bytes());
    stat[8..16].copy_from_slice(&(PAGE_SIZE as u64).to_ne_bytes());
    if kind == LinuxFilesystemKind::Root {
        let (total_frames, free_frames) = linux_domain_frame_counts();
        stat[16..24].copy_from_slice(&total_frames.to_ne_bytes());
        stat[24..32].copy_from_slice(&free_frames.to_ne_bytes());
        stat[32..40].copy_from_slice(&free_frames.to_ne_bytes());
    }
    stat[56..64].copy_from_slice(&filesystem_id.to_ne_bytes());
    stat[64..72].copy_from_slice(&(crate::linux_overlay::NAME_MAX as u64).to_ne_bytes());
    stat[72..80].copy_from_slice(&(PAGE_SIZE as u64).to_ne_bytes());
    stat[80..88].copy_from_slice(&flags.to_ne_bytes());
    stat
}

pub(super) fn linux_statfs_descriptor_kind(descriptor: u64) -> LinuxFilesystemKind {
    let state = linux_device_descriptor(descriptor);
    if linux_proc_file(state)
        || linux_measured_directory_path(state)
            .is_some_and(|path| path == b"proc" || path.starts_with(b"proc/"))
    {
        return LinuxFilesystemKind::Proc;
    }
    if state & LINUX_DEVICE_PIPE != 0 || linux_pipe_descriptor(descriptor) {
        return LinuxFilesystemKind::Pipe;
    }
    if linux_userfaultfd_descriptor(descriptor) {
        return LinuxFilesystemKind::Anonymous;
    }
    if state & LINUX_DEVICE_SOCKET != 0 {
        return LinuxFilesystemKind::Socket;
    }
    if linux_epoll_descriptor(descriptor)
        || linux_eventfd_descriptor(descriptor)
        || linux_timerfd_descriptor(descriptor)
        || state
            & (LINUX_DEVICE_FANOTIFY
                | LINUX_DEVICE_POSIX_MQ
                | LINUX_DEVICE_INOTIFY
                | LINUX_DEVICE_PIDFD
                | LINUX_DEVICE_SIGNALFD)
            != 0
    {
        return LinuxFilesystemKind::Anonymous;
    }
    LinuxFilesystemKind::Root
}

pub(super) fn linux_ustat(device: u64, output_address: u64) -> u64 {
    // The initial Linux mount namespace publishes rootfs as device 0:1;
    // stat reports the root's device as 0.
    if !matches!(u64::from(device as u32), 0 | 1) {
        return LINUX_EINVAL;
    }
    // Linux simple_statfs leaves capacity and inode counts undefined (zero)
    // for ramfs. Keep the deprecated ustat view consistent with it.
    let output = [0_u8; 32];
    if copy_to_linux_user(output_address, &output) {
        0
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_statfs(path_address: u64, stat_address: u64) -> u64 {
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let path = &path[..length];
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let canonical_length =
        match linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), path, &mut canonical) {
            Ok(length) => Some(length),
            Err(error)
                if matches!(
                    error,
                    LINUX_EACCES | LINUX_ENOTDIR | LINUX_ELOOP | LINUX_ENAMETOOLONG
                ) =>
            {
                return error;
            }
            Err(_) => None,
        };
    let canonical_is_proc = canonical_length.is_some_and(|length| {
        &canonical[..length] == b"proc" || canonical[..length].starts_with(b"proc/")
    });
    let canonical_is_cgroup = canonical_length.is_some_and(|length| {
        &canonical[..length] == b"sys/fs/cgroup"
            || canonical[..length].starts_with(b"sys/fs/cgroup/")
    });
    // statfs follows a symlink at the last component (ELOOP for a loop).
    let overlay = match canonical_length
        .map(|length| linux_overlay_lookup_following(&mut canonical, length, true))
    {
        Some(Ok((_, _, metadata))) => metadata,
        Some(Err(error)) => return error,
        None => None,
    };
    let virtual_path = linux_virtual_mount_path_at(u64::from(LINUX_AT_FDCWD), path);
    // The kernel's mount points under /sys are there even when the image
    // has no directory for them.
    let api_directory =
        canonical_length.is_some_and(|length| linux_api_directory(&canonical[..length]));
    if overlay.is_none()
        && linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), path).is_none()
        && virtual_path.is_none()
        && linux_root_directory_kind(path).is_none()
        && !canonical_is_proc
        && !canonical_is_cgroup
        && !api_directory
    {
        return canonical_length.map_or(LINUX_ENOENT, |length| {
            linux_missing_path_error(&canonical[..length])
        });
    }
    if let Some(data) =
        canonical_length.and_then(|length| linux_tmpfs_statfs_data(&canonical[..length]))
    {
        return if copy_to_linux_user(stat_address, &data) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(statfs) = overlay
        .map(|metadata| metadata.handle)
        .and_then(crate::linux_blockfs::statfs_of)
    {
        let length = canonical_length.unwrap_or(0);
        return if copy_to_linux_user(
            stat_address,
            &linux_volume_statfs_data(statfs, &canonical[..length]),
        ) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    let kind = if virtual_path.is_some() || canonical_is_proc {
        LinuxFilesystemKind::Proc
    } else if canonical_is_cgroup {
        LinuxFilesystemKind::Cgroup2
    } else {
        LinuxFilesystemKind::Root
    };
    let mut data = linux_statfs_data(kind);
    // A file below a domain mount (a tmpfs, a bind mount) has its options.
    if kind == LinuxFilesystemKind::Root {
        if let Some(length) = canonical_length {
            let space = linux_mount_space();
            let path = &canonical[..length];
            if crate::linux_mounts::mount_id_at(space, path) != crate::linux_mounts::ROOT_ID {
                let flags = linux_mount_statfs_flags(crate::linux_mounts::flags_at(space, path));
                data[80..88].copy_from_slice(&flags.to_ne_bytes());
            }
        }
    }
    if copy_to_linux_user(stat_address, &data) {
        0
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_mount_filesystem(
    source_address: u64,
    target_address: u64,
    filesystem_address: u64,
    flags: u64,
    data_address: u64,
) -> u64 {
    const MS_RDONLY: u64 = 1;
    const MS_NOSUID: u64 = 2;
    const MS_NODEV: u64 = 4;
    const MS_NOEXEC: u64 = 8;
    const MS_SYNCHRONOUS: u64 = 16;
    const MS_REMOUNT: u64 = 32;
    const MS_MANDLOCK: u64 = 64;
    const MS_DIRSYNC: u64 = 128;
    const MS_NOSYMFOLLOW: u64 = 256;
    const MS_NOATIME: u64 = 1024;
    const MS_NODIRATIME: u64 = 2048;
    const MS_BIND: u64 = 4096;
    const MS_MOVE: u64 = 8192;
    const MS_REC: u64 = 16384;
    const MS_SILENT: u64 = 32768;
    const MS_POSIXACL: u64 = 1 << 16;
    const MS_UNBINDABLE: u64 = 1 << 17;
    const MS_PRIVATE: u64 = 1 << 18;
    const MS_SLAVE: u64 = 1 << 19;
    const MS_SHARED: u64 = 1 << 20;
    const MS_RELATIME: u64 = 1 << 21;
    const MS_KERNMOUNT: u64 = 1 << 22;
    const MS_I_VERSION: u64 = 1 << 23;
    const MS_STRICTATIME: u64 = 1 << 24;
    const MS_LAZYTIME: u64 = 1 << 25;
    const VALID_FLAGS: u64 = MS_RDONLY
        | MS_NOSUID
        | MS_NODEV
        | MS_NOEXEC
        | MS_SYNCHRONOUS
        | MS_REMOUNT
        | MS_MANDLOCK
        | MS_DIRSYNC
        | MS_NOSYMFOLLOW
        | MS_NOATIME
        | MS_NODIRATIME
        | MS_BIND
        | MS_MOVE
        | MS_REC
        | MS_SILENT
        | MS_POSIXACL
        | MS_UNBINDABLE
        | MS_PRIVATE
        | MS_SLAVE
        | MS_SHARED
        | MS_RELATIME
        | MS_KERNMOUNT
        | MS_I_VERSION
        | MS_STRICTATIME
        | MS_LAZYTIME;

    let Some(namespace) = current_linux_user_namespace() else {
        return LINUX_ESRCH;
    };
    if current_container_slot().is_none()
        || linux_user::privileged_operation_denied(
            namespace,
            linux_user::PrivilegedOperation::ManageMounts,
        )
        || current_linux_credentials().is_none_or(|credentials| credentials.user.effective != 0)
    {
        return LINUX_EPERM;
    }
    // The old magic number in the flags' top half is dropped (MS_MGC_VAL,
    // which quotacheck still passes).
    const MS_MGC_MASK: u64 = 0xffff_0000;
    const MS_MGC_VAL: u64 = 0xc0ed_0000;
    let flags = if flags & MS_MGC_MASK == MS_MGC_VAL {
        flags & !MS_MGC_MASK
    } else {
        flags
    };
    if flags & !VALID_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    // Mandatory locking is not built in (Linux without
    // CONFIG_MANDATORY_FILE_LOCKING refuses the option).
    if flags & MS_MANDLOCK != 0 {
        return LINUX_EPERM;
    }

    let mut target = [0_u8; LINUX_PATH_MAX];
    let mut target_length = match copy_linux_c_string(target_address, &mut target) {
        Ok(length) => length,
        Err(error) => return error,
    };
    while target_length > 1 && target[target_length - 1] == b'/' {
        target_length -= 1;
    }
    let mut resolved_target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let target = if let Some(descriptor) =
        linux_descriptor_link_at(LINUX_AT_FDCWD.into(), &target[..target_length], true)
    {
        // A descriptor of a /proc fd entry itself leads to that entry,
        // which is no mount point (Linux's ENOENT).
        if linux_socket_flags(descriptor)
            .is_some_and(|flags| flags & LINUX_PRIVATE_PROC_LINK_DESCRIPTOR != 0)
        {
            return LINUX_ENOENT;
        }
        let Some(length) = linux_descriptor_path(descriptor, &mut resolved_target) else {
            return LINUX_ENOENT;
        };
        &resolved_target[..length]
    } else {
        &target[..target_length]
    };
    let target_is_api_directory = matches!(
        target,
        b"/dev/shm"
            | b"/dev/pts"
            | b"/proc"
            | b"/run"
            | b"/sys"
            | b"/sys/fs/cgroup"
            | b"/sys/fs/bpf"
            | b"/sys/kernel/debug"
            | b"/sys/kernel/tracing"
            | b"/sys/kernel/security"
            | b"/sys/fs/pstore"
    );
    let target_is_directory = target_is_api_directory
        || linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), target).is_some_and(|(_, entry)| {
            entry.is_none_or(|entry| entry.kind == crate::published_rootfs::EntryKind::Directory)
        })
        || linux_virtual_mount_path_at(u64::from(LINUX_AT_FDCWD), target)
            .is_some_and(|kind| kind & LINUX_DEVICE_DIRECTORY != 0)
        || {
            let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), target, &mut canonical)
                .ok()
                .and_then(|length| crate::linux_overlay::lookup(&canonical[..length]))
                .is_some_and(|metadata| metadata.kind == crate::linux_overlay::NodeKind::Directory)
        };
    let target_exists = target_is_directory
        || linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), target).is_some()
        || {
            let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), target, &mut canonical)
                .ok()
                .is_some_and(|length| crate::linux_overlay::lookup(&canonical[..length]).is_some())
        };
    if !target_exists {
        return LINUX_ENOENT;
    }

    let mount_flags = [
        (MS_RDONLY, crate::linux_mounts::READ_ONLY),
        (MS_NOSUID, crate::linux_mounts::NO_SUID),
        (MS_NODEV, crate::linux_mounts::NO_DEVICES),
        (MS_NOEXEC, crate::linux_mounts::NO_EXEC),
        (MS_NOATIME, crate::linux_mounts::NO_ATIME),
        (MS_NODIRATIME, crate::linux_mounts::NO_DIRATIME),
        (MS_NOSYMFOLLOW, crate::linux_mounts::NO_SYMFOLLOW),
        (MS_STRICTATIME, crate::linux_mounts::STRICT_ATIME),
    ]
    .into_iter()
    .filter(|(flag, _)| flags & flag != 0)
    .fold(0, |options, (_, option)| options | option);
    let mut canonical_target = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let canonical_length =
        linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), target, &mut canonical_target)
            .unwrap_or(0);
    let canonical_target = &canonical_target[..canonical_length];
    let space = linux_mount_space();
    let propagation = flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE);
    if flags & MS_REMOUNT != 0 && propagation == 0 {
        // Remounting changes a domain mount's options; the root and the
        // kernel's own mounts keep theirs. With MS_BIND it changes only
        // the mount's own (a read-only bind mount), not its filesystem's.
        let storage = crate::linux_mounts::superblock_at(space, canonical_target)
            .filter(|_| flags & MS_BIND == 0)
            .map(|(_, storage)| storage);
        let storage = storage.as_deref().unwrap_or(b"\0");
        // A volume with a file open for writing cannot become read-only.
        if flags & MS_RDONLY != 0
            && crate::linux_blockfs::generations_at(storage).is_some_and(|generations| {
                generations
                    .into_iter()
                    .any(linux_overlay_file_open_for_write)
            })
        {
            return LINUX_EBUSY;
        }
        // A volume's errors= changes on a remount too.
        if crate::linux_blockfs::generations_at(storage).is_some() {
            let mut data = [0_u8; 512];
            let data_length = if data_address == 0 {
                0
            } else {
                copy_linux_c_string(data_address, &mut data).unwrap_or(0)
            };
            match linux_volume_error_option(&data[..data_length]) {
                Ok(Some(policy)) => {
                    crate::linux_blockfs::set_error_policy(storage, policy);
                }
                Ok(None) => {}
                Err(error) => return error,
            }
        }
        match crate::linux_blockfs::remount(storage, flags & MS_RDONLY != 0) {
            Some(Err(error)) => return error.wrapping_neg(),
            // ext4's "abort" (a debugging option): the filesystem stops as
            // if it met an error, ESHUTDOWN on no inode in particular,
            // which fanotify reports as FAN_FS_ERROR.
            Some(Ok(())) if linux_mount_data_has(data_address, b"abort") => {
                const ESHUTDOWN: i32 = 108;
                if let Some(statfs) = crate::linux_blockfs::statfs_at(storage) {
                    linux_fanotify_fs_error(statfs.id, None, ESHUTDOWN);
                }
            }
            _ => {}
        }
        // A tmpfs remount may change its size (EINVAL below what it uses).
        match linux_tmpfs_mount_options(data_address) {
            Ok(Some(options))
                if options != crate::linux_tmpfs_quota::Options::default()
                    && !crate::linux_tmpfs_quota::remounted(
                        linux_execution_instance(),
                        storage,
                        options,
                    ) =>
            {
                return LINUX_EINVAL;
            }
            Err(error) => return error,
            _ => {}
        }
        return match crate::linux_mounts::remount(space, canonical_target, mount_flags) {
            Ok(()) => 0,
            Err(_) if flags & MS_BIND != 0 || linux_kernel_mount_point(canonical_target) => 0,
            Err(_) => LINUX_EINVAL,
        };
    }
    // Linux's order: a bind mount, a change of propagation, a move, then
    // a new mount.
    if flags & MS_BIND != 0 {
        return linux_bind_mount(source_address, canonical_target, flags & MS_REC != 0);
    }
    if propagation != 0 {
        let kernel_point = linux_kernel_mount_point(canonical_target);
        if !kernel_point && !crate::linux_mounts::is_mount_point(space, canonical_target) {
            return LINUX_EINVAL;
        }
        // Exactly one propagation type, with nothing but MS_REC and
        // MS_SILENT beside it.
        use crate::linux_mounts::Propagation;
        let kind = match flags & !(MS_REC | MS_SILENT) {
            MS_SHARED => Propagation::Shared,
            MS_PRIVATE => Propagation::Private,
            MS_SLAVE => Propagation::Slave,
            MS_UNBINDABLE => Propagation::Unbindable,
            _ => return LINUX_EINVAL,
        };
        return match crate::linux_mounts::set_propagation(
            space,
            canonical_target,
            kind,
            flags & MS_REC != 0,
            kernel_point,
        ) {
            Ok(()) => 0,
            Err(_) => LINUX_EINVAL,
        };
    }
    if flags & MS_MOVE != 0 {
        if source_address == 0 {
            return LINUX_EFAULT;
        }
        let mut source = [0_u8; LINUX_PATH_MAX];
        let length = match copy_linux_c_string(source_address, &mut source) {
            Ok(length) => length,
            Err(error) => return error,
        };
        let mut from = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let from_length = match linux_canonical_path_at(
            u64::from(LINUX_AT_FDCWD),
            &source[..length],
            &mut from,
        ) {
            Ok(length) => length,
            Err(LINUX_EISDIR) => return LINUX_EINVAL,
            Err(error) => return error,
        };
        if !target_is_directory {
            return LINUX_ENOTDIR;
        }
        return linux_move_mounted_tree(&from[..from_length], canonical_target);
    }
    if !target_is_directory {
        return LINUX_ENOTDIR;
    }
    if filesystem_address == 0 {
        return LINUX_EINVAL;
    }
    let mut filesystem = [0_u8; 32];
    let filesystem_length = match copy_linux_c_string(filesystem_address, &mut filesystem) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let filesystem = &filesystem[..filesystem_length];
    if !linux_mountable_filesystem(filesystem) {
        return LINUX_ENODEV;
    }
    let mut source = [0_u8; LINUX_PATH_MAX];
    let source = if source_address != 0 {
        match copy_linux_c_string(source_address, &mut source) {
            Ok(length) => Some(&source[..length]),
            Err(error) => return error,
        }
    } else {
        None
    };
    // The option string: overlayfs's layers, a tmpfs's size. Data that is
    // no short string carries no options for a tmpfs, and is no business
    // of the filesystems that take none.
    let mut data = alloc::vec::Vec::new();
    if data_address != 0
        && (matches!(filesystem, b"overlay" | b"tmpfs") || linux_volume_type(filesystem).is_some())
    {
        let mut page = [0_u8; PAGE_SIZE];
        match copy_linux_c_string(data_address, &mut page) {
            Ok(length) => {
                if data.try_reserve_exact(length).is_err() {
                    return LINUX_ENOMEM;
                }
                data.extend_from_slice(&page[..length]);
            }
            Err(LINUX_ENAMETOOLONG) if filesystem == b"tmpfs" => {}
            Err(LINUX_ENAMETOOLONG) => return LINUX_EINVAL,
            Err(error) => return error,
        }
    }
    linux_mount_new(canonical_target, source, filesystem, mount_flags, &data)
}

/// The filesystems mount(2) and fsopen(2) know.
pub(super) fn linux_mountable_filesystem(filesystem: &[u8]) -> bool {
    matches!(
        filesystem,
        b"ext2"
            | b"ext3"
            | b"ext4"
            | b"tmpfs"
            | b"ramfs"
            | b"proc"
            | b"sysfs"
            | b"devtmpfs"
            | b"devpts"
            | b"cgroup2"
            | b"securityfs"
            | b"pstore"
            | b"bpf"
            | b"tracefs"
            | b"debugfs"
            | b"hugetlbfs"
            | b"mqueue"
            | b"overlay"
    )
}

/// Mounts a new `filesystem` from `source` on canonical directory `target`
/// with the domain mount options `options` and the option string `data`:
/// the part of mount(2) after its checks, which a mount fsmount(2) made
/// goes through when move_mount(2) attaches it.
pub(super) fn linux_mount_new(
    target: &[u8],
    source: Option<&[u8]>,
    filesystem: &[u8],
    options: u32,
    data: &[u8],
) -> u64 {
    if let Some(fs_type) = linux_volume_type(filesystem) {
        let Some(source) = source else {
            return LINUX_EINVAL;
        };
        return linux_mount_volume(source, target, options, fs_type, data);
    }
    if filesystem == b"overlay" {
        return linux_mount_overlayfs(target, source.unwrap_or(b"none"), options, data);
    }
    if filesystem == b"cgroup2" && !linux_cgroup_ensure_root() {
        return LINUX_ENOSPC;
    }
    let source = source.unwrap_or(b"none");
    // The kernel's own /proc and cgroup mounts are always there.
    if linux_kernel_mount_point(target) {
        return 0;
    }
    let tmpfs_options = match linux_tmpfs_options(data) {
        Ok(options) => options,
        Err(error) if filesystem == b"tmpfs" => return error,
        Err(_) => None,
    };
    // A tmpfs, ramfs or hugetlbfs is a filesystem of its own, empty, stored
    // below its storage root; its root is the mounter's, mode 1777, as in
    // Linux. The kernel's own filesystems (devtmpfs's device files among
    // them) are found by their paths.
    let superblock = if matches!(filesystem, b"tmpfs" | b"ramfs" | b"hugetlbfs") {
        let superblock = crate::linux_mounts::new_superblock();
        let storage = crate::linux_mount_paths::storage_root(superblock);
        let Some(root) = crate::linux_overlay::create_directory_stored(&storage, 0o1777) else {
            return LINUX_ENOMEM;
        };
        let (owner, group) = current_linux_credentials().map_or((0, 0), |credentials| {
            (credentials.user.filesystem, credentials.group.filesystem)
        });
        let _ = crate::linux_overlay::set_mode(root, 0o1777)
            && crate::linux_overlay::set_owner(root, owner, group);
        if let Some(options) = tmpfs_options.filter(|_| filesystem == b"tmpfs") {
            let _ =
                crate::linux_tmpfs_quota::mounted(linux_execution_instance(), &storage, options);
        }
        superblock
    } else {
        0
    };
    match crate::linux_mounts::mount(
        linux_mount_space(),
        target,
        source,
        filesystem,
        options,
        superblock,
    ) {
        Ok(_) => 0,
        Err(_) => {
            if superblock != 0 {
                linux_filesystem_gone(crate::linux_mounts::Gone {
                    superblock,
                    filesystem: alloc::vec::Vec::new(),
                });
            }
            LINUX_ENOMEM
        }
    }
}

/// A tmpfs's size options in mount(2)'s `data` (`size=`, `nr_blocks=`,
/// `nr_inodes=`): None without data; EINVAL for a malformed size.
fn linux_tmpfs_mount_options(
    data_address: u64,
) -> Result<Option<crate::linux_tmpfs_quota::Options>, u64> {
    if data_address == 0 {
        return Ok(None);
    }
    let mut data = [0_u8; 512];
    let length = match copy_linux_c_string(data_address, &mut data) {
        Ok(length) => length,
        // Data that is not a short string carries no size options.
        Err(LINUX_ENAMETOOLONG) => return Ok(None),
        Err(error) => return Err(error),
    };
    linux_tmpfs_options(&data[..length])
}

/// A tmpfs's size options in the option string `data`: None for none.
fn linux_tmpfs_options(data: &[u8]) -> Result<Option<crate::linux_tmpfs_quota::Options>, u64> {
    if data.is_empty() {
        return Ok(None);
    }
    let (total_frames, _) = linux_domain_frame_counts();
    crate::linux_tmpfs_quota::parse(data, total_frames * PAGE_SIZE as u64)
        .map(Some)
        .ok_or(LINUX_EINVAL)
}

/// The block device an ext2 volume would be mounted from: the device file
/// at `source`, as its number, with its canonical path (a leading slash
/// first, as /proc/mounts names it) in `name`, returning that length too.
/// A file that is no block device is ENOTBLK, which is how LTP tells a
/// filesystem the kernel has from one it lacks.
pub(super) fn linux_volume_device(
    source: &[u8],
    name: &mut [u8; crate::linux_overlay::PATH_CAPACITY + 1],
) -> Result<(u32, usize), u64> {
    if source.is_empty() {
        return Err(LINUX_ENOENT);
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), source, &mut canonical)?;
    name[0] = b'/';
    name[1..=length].copy_from_slice(&canonical[..length]);
    match linux_overlay_lookup_following(&mut canonical, length, true)? {
        (_, _, Some(metadata)) if metadata.kind == crate::linux_overlay::NodeKind::BlockDevice => {
            Ok((metadata.device, length + 1))
        }
        (_, _, Some(_)) => Err(LINUX_ENOTBLK),
        (length, _, None) => Err(
            if linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), source).is_some()
                || LinuxCharacterDevice::from_path(source).is_some()
            {
                LINUX_ENOTBLK
            } else {
                linux_missing_path_error(&canonical[..length])
            },
        ),
    }
}

/// The ext filesystem type a mount type names (all are served by
/// linox_ext2, which takes the features each type's Linux driver does).
pub(super) fn linux_volume_type(filesystem: &[u8]) -> Option<linox_ext2::FsType> {
    match filesystem {
        b"ext2" => Some(linox_ext2::FsType::Ext2),
        b"ext3" => Some(linox_ext2::FsType::Ext3),
        b"ext4" => Some(linox_ext2::FsType::Ext4),
        _ => None,
    }
}

/// The quota options of an ext filesystem's mount option string
/// (usrquota or quota, grpquota, prjquota; noquota clears them). Other
/// options are taken and have no effect here.
fn linux_volume_quota_options(data: &[u8]) -> linox_ext2::QuotaOptions {
    let mut quota = linox_ext2::QuotaOptions::default();
    for option in data.split(|byte| *byte == b',') {
        match option {
            b"usrquota" | b"quota" => quota.user = true,
            b"grpquota" => quota.group = true,
            b"prjquota" => quota.project = true,
            b"noquota" => quota = linox_ext2::QuotaOptions::default(),
            _ => {}
        }
    }
    quota
}

/// The errors= option of an ext filesystem's mount option string
/// (continue, remount-ro, panic; EINVAL for another value), the last one
/// given if several are.
fn linux_volume_error_option(data: &[u8]) -> Result<Option<linox_ext2::ErrorPolicy>, u64> {
    let mut policy = None;
    for option in data.split(|byte| *byte == b',') {
        let Some(value) = option.strip_prefix(b"errors=") else {
            continue;
        };
        policy = Some(match value {
            b"continue" => linox_ext2::ErrorPolicy::Continue,
            b"remount-ro" => linox_ext2::ErrorPolicy::ReadOnly,
            b"panic" => linox_ext2::ErrorPolicy::Panic,
            _ => return Err(LINUX_EINVAL),
        });
    }
    Ok(policy)
}

/// Whether the caller may go past quota limits (CAP_SYS_RESOURCE).
pub(crate) fn linux_quota_exempt() -> bool {
    linux_has_capability(linox_credentials::capability::SYS_RESOURCE)
}

/// mount(2) of the ext2, ext3 or ext4 filesystem (`fs_type`) on the block
/// device at `source` on canonical `target`, a directory, with the domain
/// mount options `options` (`linux_mounts`) and the option string `data`.
fn linux_mount_volume(
    source: &[u8],
    target: &[u8],
    options: u32,
    fs_type: linox_ext2::FsType,
    data: &[u8],
) -> u64 {
    let mut source_name = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    let (device, source_name_length) = match linux_volume_device(source, &mut source_name) {
        Ok(found) => found,
        Err(error) => return error,
    };
    if crate::linux_blockfs::device_mounted(device) {
        return LINUX_EBUSY;
    }
    let read_only = options & crate::linux_mounts::READ_ONLY != 0;
    let (major, minor) = linux_device_numbers(device);
    let source = match major {
        crate::linux_loop::MAJOR => {
            let open = match crate::linux_loop::open(minor, true, !read_only) {
                Ok(open) => open,
                Err(error) => return linux_loop_errno(error),
            };
            match crate::linux_loop::backing(open) {
                // A volume's or an overlay's own file cannot carry another
                // volume here.
                Ok((backing, _, _, _))
                    if crate::linux_blockfs::owns(backing)
                        || crate::linux_overlayfs::owns(backing) =>
                {
                    crate::linux_loop::release(crate::linux_loop::CLASS_DEVICE, open);
                    return LINUX_EINVAL;
                }
                Ok((_, _, _, true)) if !read_only => {
                    crate::linux_loop::release(crate::linux_loop::CLASS_DEVICE, open);
                    return LINUX_EACCES;
                }
                Ok((backing, offset, size, _)) => {
                    // A volume reads its disk all over: index the backing
                    // file's pages rather than chaining them.
                    let _ = crate::linux_overlay::make_paged(backing);
                    crate::linux_blockfs::Source::Loop {
                        minor,
                        open,
                        backing,
                        offset,
                        size,
                    }
                }
                Err(_) => {
                    crate::linux_loop::release(crate::linux_loop::CLASS_DEVICE, open);
                    return LINUX_EINVAL;
                }
            }
        }
        crate::linux_ramdisk::MAJOR => match crate::linux_ramdisk::open(minor, true, !read_only) {
            Ok(open) => crate::linux_blockfs::Source::Ram {
                minor,
                open,
                size: crate::linux_ramdisk::DISK_SIZE,
            },
            Err(error) => return linux_loop_errno(error),
        },
        _ => return LINUX_ENXIO,
    };
    let io = match source {
        crate::linux_blockfs::Source::Loop { open, .. } => crate::linux_loop::io_counters(open),
        crate::linux_blockfs::Source::Ram { .. } => None,
    };
    // The volume is stored below a storage root of its own.
    let superblock = crate::linux_mounts::new_superblock();
    let storage = crate::linux_mount_paths::storage_root(superblock);
    let quota = linux_volume_quota_options(data);
    let errors = match linux_volume_error_option(data) {
        Ok(errors) => errors,
        Err(error) => {
            linux_release_volume_device(source);
            return error;
        }
    };
    if let Err(error) =
        crate::linux_blockfs::mount(&storage, source, io, read_only, fs_type, quota, errors)
    {
        linux_release_volume_device(source);
        return error.wrapping_neg();
    }
    let named = &source_name[..source_name_length];
    let space = linux_mount_space();
    let type_name: &[u8] = match fs_type {
        linox_ext2::FsType::Ext2 => b"ext2",
        linox_ext2::FsType::Ext3 => b"ext3",
        linox_ext2::FsType::Ext4 => b"ext4",
    };
    let Ok(id) = crate::linux_mounts::mount(space, target, named, type_name, options, superblock)
    else {
        if let Some(Ok(source)) = crate::linux_blockfs::unmount(&storage) {
            linux_release_volume_device(source);
        }
        return LINUX_ENOMEM;
    };
    // The mount shows the disk it is on, not an anonymous device.
    crate::linux_mounts::set_device(space, id, device);
    0
}

/// Closes the device a volume was mounted from.
fn linux_release_volume_device(source: crate::linux_blockfs::Source) {
    match source {
        crate::linux_blockfs::Source::Loop { open, .. } => {
            crate::linux_loop::release(crate::linux_loop::CLASS_DEVICE, open)
        }
        crate::linux_blockfs::Source::Ram { open, .. } => {
            crate::linux_ramdisk::release(crate::linux_ramdisk::CLASS_DISK, open)
        }
    }
}

/// Whether a file of generation `generation` is in use by any process of
/// the domain: open as a descriptor, or a working directory. A process
/// live on some CPU is read from its bank, any other from its saved record.
pub(crate) fn linux_generation_in_use(generation: u32) -> bool {
    // An active swap file keeps its volume busy.
    if crate::linux_swap::uses_generation(generation) {
        return true;
    }
    let in_bank = |bank: usize| {
        let stdio = X86_RUNTIME
            .ELF_PROBE_STDIO_TMP_FILE_GENERATIONS
            .at_bank(bank);
        (0..3).any(|index| {
            stdio[index].load(Ordering::SeqCst) == generation
                && X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index]
                    .at_bank(bank)
                    .load(Ordering::SeqCst)
                    != 0
        }) || X86_RUNTIME
            .ELF_PROBE_DEVICE_DESCRIPTORS
            .at_bank(bank)
            .iter()
            .zip(X86_RUNTIME.ELF_PROBE_TMP_FILE_GENERATIONS.at_bank(bank))
            .any(|(state, file)| {
                state.load(Ordering::SeqCst) != 0 && file.load(Ordering::SeqCst) == generation
            })
            || crate::linux_fd_table::active()
                && crate::linux_fd_table::entries(
                    X86_RUNTIME
                        .ELF_PROBE_DESCRIPTOR_OVERFLOW
                        .at_bank(bank)
                        .load(Ordering::SeqCst),
                )
                .iter()
                .any(|(_, entry)| entry.generation == generation)
            || X86_RUNTIME
                .ELF_PROBE_OVERLAY_CWD
                .at_bank(bank)
                .load(Ordering::SeqCst)
                == generation
    };
    if in_bank(linux_cpu_bank()) {
        return true;
    }
    let me = current_linux_process_pid();
    let instance = linux_execution_instance();
    (0..linux_process::live_process_slots())
        .filter_map(linux_process::live_process_pid_at)
        .filter(|pid| *pid != me)
        .any(|pid| {
            if let Some(bank) = linux_live_process_bank(pid, instance) {
                return in_bank(bank);
            }
            // The fixed table under the record lock, the table above it
            // (its own lock) after.
            with_valid_linux_process_runtime_state(pid, |state| {
                let descriptors = &state.descriptors;
                let fixed = state.overlay_cwd == generation
                    || descriptors
                        .stdio_devices
                        .iter()
                        .zip(&descriptors.stdio_tmp_generations)
                        .any(|(state, file)| *state != 0 && *file == generation)
                    || descriptors
                        .devices
                        .iter()
                        .zip(&descriptors.tmp_generations)
                        .any(|(state, file)| *state != 0 && *file == generation);
                (fixed, descriptors.overflow)
            })
            .is_some_and(|(fixed, overflow)| {
                fixed
                    || linux_saved_overflow_entries(overflow)
                        .iter()
                        .any(|(_, entry)| entry.generation == generation)
            })
        })
}

/// Frees the files, on the overlay or a volume, that lost their last name
/// once nothing has them open (after a close or an unlink).
pub(crate) fn linux_reclaim_unlinked_files() {
    // An overlay file whose name went holds its layer's file while open.
    let in_use = |generation: u32| {
        linux_generation_in_use(generation)
            || crate::linux_overlayfs::pinned(generation, linux_generation_in_use)
    };
    crate::linux_overlayfs::reclaim(linux_generation_in_use);
    crate::linux_overlay::reclaim_unlinked(|handle| {
        in_use(crate::linux_overlay::generation(handle))
            || crate::linux_loop::backs(handle)
            || linux_lent_file_mapped(handle)
    });
    if crate::linux_blockfs::has_orphans() {
        for source in crate::linux_blockfs::reclaim(in_use) {
            linux_release_volume_device(source);
        }
    }
}

/// Whether a page table may still map a frame of overlay file `handle`
/// that was handed out to be mapped (a shared mapping's): a memory area
/// mapping it shared says so cheaply, and failing that every page table
/// of the domain is searched, as an area can be missing where the page
/// tables still map it.
fn linux_lent_file_mapped(handle: crate::linux_overlay::Handle) -> bool {
    let Some(frames) = crate::linux_overlay::lent_frames(handle) else {
        return false;
    };
    if frames.is_empty() {
        return false;
    }
    crate::linux_areas::inode_shared_mapped(linux_execution_instance(), handle.inode())
        || linux_frames_mapped(&frames)
}

/// Whether a page table of the domain may map one of `frames` (physical
/// page addresses, sorted): every process's, retiring ones included.
pub(crate) fn linux_frames_mapped(frames: &[u64]) -> bool {
    let maps = |root: u64| address_space::linux_root_maps_any(root, frames);
    scheduler::current_address_space_root().is_some_and(maps)
        || linux_process::any_live_process_root(maps)
}

/// Frees the unlinked files whose frames a mapping just let go of, once
/// no memory area maps them shared any more (the page tables are checked
/// then too).
pub(super) fn linux_reclaim_unmapped_files() {
    let instance = linux_execution_instance();
    if crate::linux_overlay::unlinked_lent()
        .into_iter()
        .any(|handle| !crate::linux_areas::inode_shared_mapped(instance, handle.inode()))
    {
        linux_reclaim_unlinked_files();
    }
}

/// The filesystems a mount makes of its own that are not volumes, each
/// stored below a storage root of its own (crate::linux_mount_paths): the
/// in-memory ones and overlayfs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxMountedFilesystem {
    Tmpfs,
    Ramfs,
    Hugetlbfs,
    Overlay,
}

/// The filesystem of its own the mount holding canonical `path` has, and
/// its device; None for a path on any other filesystem.
fn linux_mounted_filesystem_at(path: &[u8]) -> Option<(LinuxMountedFilesystem, u32)> {
    let space = linux_mount_space();
    let id = crate::linux_mounts::mount_id_at(space, path);
    crate::linux_mounts::with_mount(space, id, |mount| {
        let filesystem = match &mount.filesystem[..] {
            b"tmpfs" => LinuxMountedFilesystem::Tmpfs,
            b"ramfs" => LinuxMountedFilesystem::Ramfs,
            b"hugetlbfs" => LinuxMountedFilesystem::Hugetlbfs,
            b"overlay" => LinuxMountedFilesystem::Overlay,
            _ => return None,
        };
        Some((filesystem, mount.device))
    })?
}

/// statfs's f_fsid of the filesystem of its own holding canonical `path`
/// (a bind mount of one too), the same for every mount of it: from its
/// device, as Linux's simple_statfs and hugetlbfs give it, with the magic
/// as well for a tmpfs and an overlay (whose own fsid Linux makes from
/// the UUID it gives each overlay). fanotify's filesystem marks and
/// identifiers report it too. None off such a filesystem.
pub(super) fn linux_tmpfs_fsid(path: &[u8]) -> Option<[u8; 8]> {
    const TMPFS_MAGIC: u32 = 0x0102_1994;
    const OVERLAYFS_SUPER_MAGIC: u32 = 0x794c_7630;
    let (filesystem, device) = linux_mounted_filesystem_at(path)?;
    let mut fsid = [0_u8; 8];
    fsid[..4].copy_from_slice(&device.to_ne_bytes());
    match filesystem {
        LinuxMountedFilesystem::Tmpfs => fsid[4..].copy_from_slice(&TMPFS_MAGIC.to_ne_bytes()),
        LinuxMountedFilesystem::Overlay => {
            fsid[4..].copy_from_slice(&OVERLAYFS_SUPER_MAGIC.to_ne_bytes());
        }
        LinuxMountedFilesystem::Ramfs | LinuxMountedFilesystem::Hugetlbfs => {}
    }
    Some(fsid)
}

/// statfs(2)'s answer for canonical `path` when a ramfs, hugetlbfs or
/// overlay mount holds it, as Linux's simple_statfs, hugetlbfs_statfs and
/// ovl_statfs give it: the magic, the page size (the huge page size for
/// hugetlbfs), the fsid, and no counts for the in-memory ones (hugetlbfs
/// has no size limit here; its inodes are unlimited, -1); an overlay
/// reports the domain's memory, where its upper layer's files are.
fn linux_memory_statfs_data(
    filesystem: LinuxMountedFilesystem,
    path: &[u8],
    fsid: [u8; 8],
) -> [u8; 120] {
    const RAMFS_MAGIC: u64 = 0x8584_58f6;
    const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
    const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;
    let (magic, block_size) = match filesystem {
        LinuxMountedFilesystem::Hugetlbfs => (HUGETLBFS_MAGIC, LINUX_HUGE_PAGE_SIZE),
        LinuxMountedFilesystem::Overlay => (OVERLAYFS_SUPER_MAGIC, PAGE_SIZE as u64),
        LinuxMountedFilesystem::Ramfs | LinuxMountedFilesystem::Tmpfs => {
            (RAMFS_MAGIC, PAGE_SIZE as u64)
        }
    };
    let flags = linux_mount_statfs_flags(crate::linux_mounts::flags_at(linux_mount_space(), path));
    let mut stat = [0_u8; 120];
    stat[0..8].copy_from_slice(&magic.to_ne_bytes());
    stat[8..16].copy_from_slice(&block_size.to_ne_bytes());
    if filesystem == LinuxMountedFilesystem::Overlay {
        let (total_frames, free_frames) = linux_domain_frame_counts();
        stat[16..24].copy_from_slice(&total_frames.to_ne_bytes());
        stat[24..32].copy_from_slice(&free_frames.to_ne_bytes());
        stat[32..40].copy_from_slice(&free_frames.to_ne_bytes());
    }
    stat[56..64].copy_from_slice(&fsid);
    stat[64..72].copy_from_slice(&(crate::linux_overlay::NAME_MAX as u64).to_ne_bytes());
    stat[72..80].copy_from_slice(&block_size.to_ne_bytes());
    stat[80..88].copy_from_slice(&flags.to_ne_bytes());
    stat
}

/// statfs(2)'s answer for canonical `path` when a tmpfs mount holds it:
/// tmpfs's magic, and its size limits and use where it has them, else the
/// domain's memory, as an unlimited tmpfs shows; a ramfs's, hugetlbfs's
/// or overlay's (`linux_memory_statfs_data`). None off those.
pub(super) fn linux_tmpfs_statfs_data(path: &[u8]) -> Option<[u8; 120]> {
    const TMPFS_MAGIC: u64 = 0x0102_1994;
    let fsid = linux_tmpfs_fsid(path)?;
    let (filesystem, _) = linux_mounted_filesystem_at(path)?;
    if filesystem != LinuxMountedFilesystem::Tmpfs {
        return Some(linux_memory_statfs_data(filesystem, path, fsid));
    }
    let space = linux_mount_space();
    let (total_frames, free_frames) = linux_domain_frame_counts();
    let (blocks, free, files, free_files) = match crate::linux_tmpfs_quota::usage(
        linux_execution_instance(),
        &crate::linux_mount_paths::storage(path),
    ) {
        Some((limit, used, inodes, used_inodes)) => {
            let blocks = limit.unwrap_or(total_frames);
            let files = inodes.unwrap_or(total_frames);
            (
                blocks,
                blocks.saturating_sub(used),
                files,
                files.saturating_sub(used_inodes),
            )
        }
        None => (total_frames, free_frames, total_frames, free_frames),
    };
    let flags = linux_mount_statfs_flags(crate::linux_mounts::flags_at(space, path));
    let mut stat = [0_u8; 120];
    let block_size = crate::linux_tmpfs_quota::BLOCK_SIZE;
    stat[0..8].copy_from_slice(&TMPFS_MAGIC.to_ne_bytes());
    stat[8..16].copy_from_slice(&block_size.to_ne_bytes());
    stat[16..24].copy_from_slice(&blocks.to_ne_bytes());
    stat[24..32].copy_from_slice(&free.to_ne_bytes());
    stat[32..40].copy_from_slice(&free.to_ne_bytes());
    stat[40..48].copy_from_slice(&files.to_ne_bytes());
    stat[48..56].copy_from_slice(&free_files.to_ne_bytes());
    stat[56..64].copy_from_slice(&fsid);
    stat[64..72].copy_from_slice(&(crate::linux_overlay::NAME_MAX as u64).to_ne_bytes());
    stat[72..80].copy_from_slice(&block_size.to_ne_bytes());
    stat[80..88].copy_from_slice(&flags.to_ne_bytes());
    Some(stat)
}

/// statfs(2)'s answer for a volume: ext2's counts, and the options of the
/// mount at canonical `path`.
pub(super) fn linux_volume_statfs_data(statfs: linox_ext2::Statfs, path: &[u8]) -> [u8; 120] {
    let flags = linux_mount_statfs_flags(crate::linux_mounts::flags_at(linux_mount_space(), path));
    let mut stat = [0_u8; 120];
    let block_size = u64::from(statfs.block_size);
    stat[0..8].copy_from_slice(&u64::from(linox_ext2::MAGIC).to_ne_bytes());
    stat[8..16].copy_from_slice(&block_size.to_ne_bytes());
    stat[16..24].copy_from_slice(&statfs.blocks.to_ne_bytes());
    stat[24..32].copy_from_slice(&statfs.free_blocks.to_ne_bytes());
    stat[32..40].copy_from_slice(&statfs.available_blocks.to_ne_bytes());
    stat[40..48].copy_from_slice(&statfs.inodes.to_ne_bytes());
    stat[48..56].copy_from_slice(&statfs.free_inodes.to_ne_bytes());
    stat[56..60].copy_from_slice(&statfs.id[0].to_ne_bytes());
    stat[60..64].copy_from_slice(&statfs.id[1].to_ne_bytes());
    stat[64..72].copy_from_slice(&u64::from(statfs.name_max).to_ne_bytes());
    stat[72..80].copy_from_slice(&block_size.to_ne_bytes());
    stat[80..88].copy_from_slice(&flags.to_ne_bytes());
    stat
}

/// statfs(2)'s f_flags for a domain mount with options `options`.
fn linux_mount_statfs_flags(options: u32) -> u64 {
    const ST_RDONLY: u64 = 1;
    const ST_NOSUID: u64 = 2;
    const ST_NODEV: u64 = 4;
    const ST_NOEXEC: u64 = 8;
    const ST_VALID: u64 = 32;
    const ST_NOATIME: u64 = 1024;
    const ST_NODIRATIME: u64 = 2048;
    const ST_RELATIME: u64 = 4096;
    const ST_NOSYMFOLLOW: u64 = 0x2000;
    let relatime =
        options & (crate::linux_mounts::NO_ATIME | crate::linux_mounts::STRICT_ATIME) == 0;
    [
        (crate::linux_mounts::READ_ONLY, ST_RDONLY),
        (crate::linux_mounts::NO_SUID, ST_NOSUID),
        (crate::linux_mounts::NO_DEVICES, ST_NODEV),
        (crate::linux_mounts::NO_EXEC, ST_NOEXEC),
        (crate::linux_mounts::NO_ATIME, ST_NOATIME),
        (crate::linux_mounts::NO_DIRATIME, ST_NODIRATIME),
        (crate::linux_mounts::NO_SYMFOLLOW, ST_NOSYMFOLLOW),
    ]
    .into_iter()
    .filter(|(option, _)| options & option != 0)
    .fold(
        if relatime {
            ST_VALID | ST_RELATIME
        } else {
            ST_VALID
        },
        |flags, (_, flag)| flags | flag,
    )
}

/// The options of the mount canonical `path` is on.
pub(super) fn linux_mount_flags(path: &[u8]) -> u32 {
    crate::linux_mounts::flags_at(linux_mount_space(), path)
}

/// The options of the mount the file `handle` is reached through.
pub(super) fn linux_handle_mount_flags(handle: crate::linux_overlay::Handle) -> u32 {
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    crate::linux_overlay::copy_path(handle, &mut path)
        .map_or(0, |length| linux_mount_flags(&path[..length]))
}

/// Whether `descriptor` was opened with O_NOATIME.
pub(super) fn linux_descriptor_noatime(descriptor: u64) -> bool {
    linux_socket_flags(descriptor).is_some_and(|flags| flags & LINUX_O_NOATIME as u32 != 0)
}

/// A read of `descriptor`, open on the file `handle`, updates its access
/// time unless it was opened with O_NOATIME, even when it read nothing,
/// as Linux's file_accessed.
pub(super) fn linux_note_read(descriptor: u64, handle: crate::linux_overlay::Handle) {
    if !linux_descriptor_noatime(descriptor) {
        linux_note_accessed(handle, false);
    }
}

/// Updates the access time of the file `handle` that a read (or, with
/// `directory`, a listing) just read, as Linux's atime rules and the
/// file's mount say: never on a noatime or read-only mount (nor a
/// directory on a nodiratime one) or for an FS_NOATIME_FL file; always on
/// a strictatime mount; else (relatime) when the access time is no later
/// than the change or modification time, or a day old.
pub(super) fn linux_note_accessed(handle: crate::linux_overlay::Handle, directory: bool) {
    const FS_NOATIME_FL: u32 = 0x80;
    const DAY: i64 = 24 * 60 * 60;
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return;
    };
    if metadata.attributes & FS_NOATIME_FL != 0 {
        return;
    }
    let now = linux_realtime_now();
    let stale = metadata.atime <= metadata.mtime
        || metadata.atime <= metadata.ctime
        || now.0.saturating_sub(metadata.atime.0) >= DAY;
    if !stale && !crate::linux_mounts::any_strict_atime() {
        return;
    }
    let flags = linux_handle_mount_flags(handle);
    use crate::linux_mounts::{NO_ATIME, NO_DIRATIME, READ_ONLY, STRICT_ATIME};
    if flags & (NO_ATIME | READ_ONLY) != 0
        || directory && flags & NO_DIRATIME != 0
        || !stale && flags & STRICT_ATIME == 0
    {
        return;
    }
    let _ = crate::linux_overlay::touch_accessed(handle, now);
}

/// The root and the mounts the kernel makes itself (/proc, cgroup2).
pub(super) fn linux_kernel_mount_point(canonical: &[u8]) -> bool {
    matches!(canonical, b"" | b"proc" | b"sys/fs/cgroup")
}

/// The current process's mount table: its domain's, in its mount
/// namespace.
pub(super) fn linux_mount_space() -> crate::linux_mounts::Space {
    crate::linux_mounts::Space {
        instance: linux_execution_instance(),
        namespace: linux_mount::current_handle().map_or(0, linux_mount::MountNamespaceHandle::id),
    }
}

/// The kernel filesystem canonical `path` is on when no domain mount
/// covers it: /proc, cgroup2 or the root.
pub(super) fn linux_kernel_filesystem(
    path: &[u8],
) -> crate::linux_mounts::KernelFilesystem<'static> {
    let below = |point: &[u8]| {
        path.strip_prefix(point)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
    };
    let (filesystem, source, device): (&'static [u8], &'static [u8], u32) = if below(b"proc") {
        (b"proc", b"proc", 2)
    } else if below(b"sys/fs/cgroup") {
        (b"cgroup2", b"cgroup2", 3)
    } else {
        (b"linox-root", b"rootfs", LINUX_ROOT_FILESYSTEM_DEVICE)
    };
    crate::linux_mounts::KernelFilesystem {
        filesystem,
        source,
        device,
    }
}

/// mount(2) with MS_BIND: shows the filesystem under the path at
/// `source_address` at canonical `target` too, with the mounts below it
/// when `recursive` (MS_REC). An unbindable source is EINVAL.
fn linux_bind_mount(source_address: u64, target: &[u8], recursive: bool) -> u64 {
    if source_address == 0 {
        return LINUX_EFAULT;
    }
    let mut source = [0_u8; LINUX_PATH_MAX];
    let length = match copy_linux_c_string(source_address, &mut source) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length =
        match linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), &source[..length], &mut canonical)
        {
            Ok(length) => length,
            // The domain's root itself.
            Err(LINUX_EISDIR) => 0,
            Err(error) => return error,
        };
    let canonical = &canonical[..length];
    if linux_path_access(canonical).is_none() && !linux_kernel_mount_point(canonical) {
        return linux_missing_path_error(canonical);
    }
    match crate::linux_mounts::bind(
        linux_mount_space(),
        canonical,
        target,
        recursive,
        &linux_kernel_filesystem(canonical),
    ) {
        Ok(_) => 0,
        Err(crate::linux_mounts::Error::NotMounted) => LINUX_EINVAL,
        Err(crate::linux_mounts::Error::NoMemory) => LINUX_ENOMEM,
    }
}

/// umount2(2): removes a domain mount; a tmpfs takes what was created on
/// it along.
pub(super) fn linux_umount(target_address: u64, flags: u64) -> u64 {
    const MNT_FORCE: u64 = 1;
    const MNT_DETACH: u64 = 2;
    const MNT_EXPIRE: u64 = 4;
    const UMOUNT_NOFOLLOW: u64 = 8;
    let flags = u64::from(flags as u32);
    if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0
        || flags & MNT_EXPIRE != 0 && flags & (MNT_FORCE | MNT_DETACH) != 0
    {
        return LINUX_EINVAL;
    }
    if current_container_slot().is_none()
        || current_linux_credentials().is_none_or(|credentials| !credentials.privileged())
    {
        return LINUX_EPERM;
    }
    let mut target = [0_u8; LINUX_PATH_MAX];
    let target_length = match copy_linux_c_string(target_address, &mut target) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let mut length = match linux_canonical_path_at(
        u64::from(LINUX_AT_FDCWD),
        &target[..target_length],
        &mut canonical,
    ) {
        Ok(length) => length,
        Err(LINUX_EISDIR) => return LINUX_EBUSY,
        Err(error) => return error,
    };
    // The last symlink is followed, unless UMOUNT_NOFOLLOW.
    if flags & UMOUNT_NOFOLLOW == 0 {
        length = match linux_overlay_lookup_following(&mut canonical, length, true) {
            Ok((length, ..)) => length,
            Err(error) => return error,
        };
    }
    let canonical = &canonical[..length];
    if linux_path_access(canonical).is_none()
        && !linux_kernel_mount_point(canonical)
        && !linux_api_directory(canonical)
    {
        return linux_missing_path_error(canonical);
    }
    let space = linux_mount_space();
    // MNT_EXPIRE unmounts only a mount it marked before and nothing used
    // since (EAGAIN while it marks it).
    if flags & MNT_EXPIRE != 0 {
        match crate::linux_mounts::expire(space, canonical) {
            Ok(true) => {}
            Ok(false) => return LINUX_EAGAIN,
            Err(_) if linux_kernel_mount_point(canonical) => return LINUX_EINVAL,
            Err(_) => return LINUX_EINVAL,
        }
    }
    // When this is the filesystem's last mount, a file of it still open, or
    // a working directory on it, keeps it mounted (EBUSY), unless the
    // unmount is lazy (MNT_DETACH): then it leaves the namespace and goes
    // with its last close.
    if let Some((_, storage)) = crate::linux_mounts::last_mount_of(space, canonical) {
        let generations = crate::linux_overlayfs::generations_at(&storage)
            .or_else(|| crate::linux_blockfs::generations_at(&storage));
        if flags & MNT_DETACH == 0
            && generations
                .is_some_and(|generations| generations.into_iter().any(linux_generation_in_use))
        {
            return LINUX_EBUSY;
        }
    }
    match crate::linux_mounts::unmount(space, canonical) {
        Ok(gone) => {
            // A filesystem that goes with its last mount (not a bind mount
            // of one that stays): the watches on its files end.
            let filesystem_gone = gone.is_some();
            if let Some(gone) = gone {
                linux_filesystem_gone(gone);
            }
            if filesystem_gone {
                let domain = linux_execution_instance();
                crate::linux_inotify::unmounted(domain, canonical);
                crate::linux_fanotify::removed(domain, canonical);
                wake_linux_descriptor_waits();
            }
            0
        }
        Err(_) if linux_kernel_mount_point(canonical) => LINUX_EBUSY,
        Err(_) => LINUX_EINVAL,
    }
}

/// A filesystem went with its last mount: a tmpfs's files go, a volume is
/// unmounted (once its files in use are closed, when some are), an
/// overlay's files are forgotten.
pub(super) fn linux_filesystem_gone(gone: crate::linux_mounts::Gone) {
    let storage = crate::linux_mount_paths::storage_root(gone.superblock);
    if crate::linux_overlayfs::unmount(&storage) {
        return;
    }
    if let Some(generations) = crate::linux_blockfs::generations_at(&storage) {
        if generations.into_iter().any(linux_generation_in_use) {
            crate::linux_blockfs::detach(&storage);
        } else if let Some(Ok(source)) = crate::linux_blockfs::unmount(&storage) {
            linux_release_volume_device(source);
        }
        return;
    }
    crate::linux_tmpfs_quota::unmounted(linux_execution_instance(), &storage);
    crate::linux_overlay::unlink_below_stored(&storage);
    if let Some(root) = crate::linux_overlay::lookup_stored(&storage) {
        let _ = crate::linux_overlay::unlink(root.handle);
    }
}

/// Canonical `path` lies on a read-only mount: changing it is EROFS.
pub(super) fn linux_read_only_path(path: &[u8]) -> bool {
    crate::linux_mounts::flags_at(linux_mount_space(), path) & crate::linux_mounts::READ_ONLY != 0
}

/// EROFS for a change to the overlay file `handle` on a read-only mount.
pub(super) fn linux_check_writable_handle(handle: crate::linux_overlay::Handle) -> Result<(), u64> {
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    match crate::linux_overlay::copy_path(handle, &mut path) {
        Some(length) if linux_read_only_path(&path[..length]) => Err(LINUX_EROFS),
        _ => Ok(()),
    }
}

/// mount_setattr(2): changes the options (MOUNT_ATTR_*) and propagation of
/// the mount at a path and, with AT_RECURSIVE, of the mounts below it, in
/// Linux's order of checks: the flags, the size, privilege, the
/// attributes (nothing to change succeeds at once), then the path, which
/// must be a mount's root.
pub(super) fn linux_mount_setattr(
    directory: u64,
    path_address: u64,
    flags: u64,
    attributes_address: u64,
    size: u64,
) -> u64 {
    linux_mount_setattr_at(
        directory,
        Some(path_address),
        flags,
        attributes_address,
        size,
    )
}

/// mount_setattr(2) of the path at `path_address`, or (None) of the
/// descriptor `directory` itself, as open_tree_attr(2) applies it to the
/// tree it opened.
pub(in crate::arch::x86_64) fn linux_mount_setattr_at(
    directory: u64,
    path_address: Option<u64>,
    flags: u64,
    attributes_address: u64,
    size: u64,
) -> u64 {
    const MOUNT_ATTR_SIZE: usize = 32;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_RECURSIVE: u64 = 0x8000;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_NO_AUTOMOUNT: u64 = 0x800;
    const VALID_FLAGS: u64 = AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;
    const MOUNT_ATTR_RDONLY: u64 = 1;
    const MOUNT_ATTR_NOSUID: u64 = 2;
    const MOUNT_ATTR_NODEV: u64 = 4;
    const MOUNT_ATTR_NOEXEC: u64 = 8;
    const MOUNT_ATTR_ATIME: u64 = 0x70;
    const MOUNT_ATTR_NOATIME: u64 = 0x10;
    const MOUNT_ATTR_STRICTATIME: u64 = 0x20;
    const MOUNT_ATTR_NODIRATIME: u64 = 0x80;
    const MOUNT_ATTR_IDMAP: u64 = 0x10_0000;
    const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x20_0000;
    const VALID_ATTRIBUTES: u64 = MOUNT_ATTR_RDONLY
        | MOUNT_ATTR_NOSUID
        | MOUNT_ATTR_NODEV
        | MOUNT_ATTR_NOEXEC
        | MOUNT_ATTR_ATIME
        | MOUNT_ATTR_NODIRATIME
        | MOUNT_ATTR_IDMAP
        | MOUNT_ATTR_NOSYMFOLLOW;
    const MS_UNBINDABLE: u64 = 1 << 17;
    const MS_PRIVATE: u64 = 1 << 18;
    const MS_SLAVE: u64 = 1 << 19;
    const MS_SHARED: u64 = 1 << 20;
    let flags = u64::from(flags as u32);
    if flags & !VALID_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    if size > PAGE_SIZE as u64 {
        return LINUX_E2BIG;
    }
    if size < MOUNT_ATTR_SIZE as u64 {
        return LINUX_EINVAL;
    }
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ManageMounts)
        || !linux_has_capability(linox_credentials::capability::SYS_ADMIN)
    {
        return LINUX_EPERM;
    }
    let mut attributes = [0_u8; MOUNT_ATTR_SIZE];
    if !copy_from_linux_user(attributes_address, &mut attributes) {
        return LINUX_EFAULT;
    }
    // A larger structure's tail must be zero (copy_struct_from_user).
    let mut tail = [0_u8; 64];
    let mut offset = MOUNT_ATTR_SIZE as u64;
    while offset < size {
        let length = (size - offset).min(tail.len() as u64) as usize;
        if !copy_from_linux_user(attributes_address + offset, &mut tail[..length]) {
            return LINUX_EFAULT;
        }
        if tail[..length].iter().any(|byte| *byte != 0) {
            return LINUX_E2BIG;
        }
        offset += length as u64;
    }
    let word = |at: usize| u64::from_ne_bytes(attributes[at..at + 8].try_into().unwrap());
    let (set, clear, propagation, user_namespace) = (word(0), word(8), word(16), word(24));
    if set == 0 && clear == 0 && propagation == 0 {
        return 0;
    }
    use crate::linux_mounts::Propagation;
    let propagation = match propagation {
        0 => None,
        MS_SHARED => Some(Propagation::Shared),
        MS_PRIVATE => Some(Propagation::Private),
        MS_SLAVE => Some(Propagation::Slave),
        MS_UNBINDABLE => Some(Propagation::Unbindable),
        _ => return LINUX_EINVAL,
    };
    if (set | clear) & !VALID_ATTRIBUTES != 0
        || clear & MOUNT_ATTR_ATIME != 0 && clear & MOUNT_ATTR_ATIME != MOUNT_ATTR_ATIME
        || clear & MOUNT_ATTR_ATIME == 0 && set & MOUNT_ATTR_ATIME != 0
        || user_namespace != 0 && set & MOUNT_ATTR_IDMAP == 0
    {
        return LINUX_EINVAL;
    }
    let options = |attributes: u64| {
        [
            (MOUNT_ATTR_RDONLY, crate::linux_mounts::READ_ONLY),
            (MOUNT_ATTR_NOSUID, crate::linux_mounts::NO_SUID),
            (MOUNT_ATTR_NODEV, crate::linux_mounts::NO_DEVICES),
            (MOUNT_ATTR_NOEXEC, crate::linux_mounts::NO_EXEC),
            (MOUNT_ATTR_NODIRATIME, crate::linux_mounts::NO_DIRATIME),
            (MOUNT_ATTR_NOSYMFOLLOW, crate::linux_mounts::NO_SYMFOLLOW),
        ]
        .into_iter()
        .filter(|(attribute, _)| attributes & attribute != 0)
        .fold(0, |options, (_, option)| options | option)
    };
    let mut set_options = options(set);
    let mut clear_options = options(clear);
    if clear & MOUNT_ATTR_ATIME != 0 {
        clear_options |= crate::linux_mounts::NO_ATIME | crate::linux_mounts::STRICT_ATIME;
        match set & MOUNT_ATTR_ATIME {
            MOUNT_ATTR_NOATIME => set_options |= crate::linux_mounts::NO_ATIME,
            MOUNT_ATTR_STRICTATIME => set_options |= crate::linux_mounts::STRICT_ATIME,
            _ => {}
        }
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = match path_address {
        Some(address) => match copy_linux_c_string(address, &mut path) {
            Ok(length) => length,
            Err(error) => return error,
        },
        None => 0,
    };
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = if length == 0 {
        if flags & AT_EMPTY_PATH == 0 && path_address.is_some() {
            return LINUX_ENOENT;
        }
        if !linux_descriptor_open(directory) {
            return LINUX_EBADF;
        }
        // A detached mount (fsmount, open_tree) takes the options with it
        // to where it is attached.
        if let Some(id) = linux_detached_mount_descriptor(directory) {
            crate::linux_fscontext::change_mount_flags(id, set_options, clear_options);
            return 0;
        }
        match linux_descriptor_canonical(directory, &mut canonical) {
            Some(length) => length,
            None => return 0,
        }
    } else {
        match linux_canonical_path_at(directory, &path[..length], &mut canonical) {
            Ok(length) => length,
            Err(LINUX_EISDIR) => 0,
            Err(error) => return error,
        }
    };
    let canonical = &canonical[..length];
    if linux_path_access(canonical).is_none() && !linux_kernel_mount_point(canonical) {
        return linux_missing_path_error(canonical);
    }
    let space = linux_mount_space();
    let kernel_point = linux_kernel_mount_point(canonical);
    if !kernel_point && !crate::linux_mounts::is_mount_point(space, canonical) {
        return LINUX_EINVAL;
    }
    let recursive = flags & AT_RECURSIVE != 0;
    let changed = crate::linux_mounts::change_options(
        space,
        canonical,
        (set_options, clear_options),
        recursive,
        kernel_point,
    )
    .and_then(|()| {
        propagation.map_or(Ok(()), |kind| {
            crate::linux_mounts::set_propagation(space, canonical, kind, recursive, kernel_point)
        })
    });
    match changed {
        Ok(()) => 0,
        Err(crate::linux_mounts::Error::NotMounted) => LINUX_EINVAL,
        Err(crate::linux_mounts::Error::NoMemory) => LINUX_ENOMEM,
    }
}
