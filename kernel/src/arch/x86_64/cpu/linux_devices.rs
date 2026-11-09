use super::*;

pub(super) fn linux_generic_ioctl(descriptor: u64, request: u64, argument: u64) -> Option<u64> {
    if let Some(result) = linux_socket_ioctl(descriptor, request, argument) {
        return Some(result);
    }
    // PROCMAP_QUERY (_IOWR('f', 17, struct procmap_query)) on /proc/PID/maps.
    const PROCMAP_QUERY: u64 = 0xc068_6611;
    if u64::from(request as u32) == PROCMAP_QUERY
        && linux_device_descriptor(descriptor) & !3 == LINUX_FILE_PROC_DYNAMIC_MAPS
    {
        return Some(linux_procmap_query(descriptor, argument));
    }
    // RNDGETENTCNT on /dev/random and /dev/urandom: the pool is always
    // full (Linux reports 256 since 5.18), as entropy_avail says.
    const RNDGETENTCNT: u64 = 0x8004_5200;
    if u64::from(request as u32) == RNDGETENTCNT
        && linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_RANDOM
    {
        return Some(if copy_to_linux_user(argument, &256_i32.to_ne_bytes()) {
            0
        } else {
            LINUX_EFAULT
        });
    }
    match u64::from(request as u32) {
        LINUX_FIOCLEX => Some(linux_descriptor_fcntl(
            descriptor,
            LINUX_F_SETFD,
            u64::from(LINUX_FD_CLOEXEC),
        )),
        LINUX_FIONCLEX => Some(linux_descriptor_fcntl(descriptor, LINUX_F_SETFD, 0)),
        LINUX_FIONBIO => {
            let mut value = [0_u8; size_of::<i32>()];
            if !copy_from_linux_user(argument, &mut value) {
                return Some(LINUX_EFAULT);
            }
            let flags = linux_descriptor_fcntl(descriptor, LINUX_F_GETFL, 0);
            if flags >= u64::MAX - 4095 {
                return Some(flags);
            }
            let flags = if i32::from_ne_bytes(value) != 0 {
                flags | LINUX_O_NONBLOCK
            } else {
                flags & !LINUX_O_NONBLOCK
            };
            Some(linux_descriptor_fcntl(
                descriptor,
                LINUX_F_SETFL,
                flags & !LINUX_O_ACCMODE,
            ))
        }
        // FIOASYNC sets or clears O_ASYNC, as F_SETFL would (a file with
        // no signal-driven I/O keeps the flag and nothing comes of it).
        LINUX_FIOASYNC => {
            const O_ASYNC: u64 = 0o20_000;
            let mut value = [0_u8; size_of::<i32>()];
            if !copy_from_linux_user(argument, &mut value) {
                return Some(LINUX_EFAULT);
            }
            let flags = linux_descriptor_fcntl(descriptor, LINUX_F_GETFL, 0);
            if flags >= u64::MAX - 4095 {
                return Some(flags);
            }
            let flags = if i32::from_ne_bytes(value) != 0 {
                flags | O_ASYNC
            } else {
                flags & !O_ASYNC
            };
            let result =
                linux_descriptor_fcntl(descriptor, LINUX_F_SETFL, flags & !LINUX_O_ACCMODE);
            Some(if result < LINUX_RETURN_TO_KERNEL {
                0
            } else {
                result
            })
        }
        // FIONREAD on a regular file: the bytes from the file position to
        // its end (other files answer it themselves).
        LINUX_FIONREAD => {
            let stat = linux_descriptor_stat(descriptor)?;
            let mode = u32::from_ne_bytes(stat[24..28].try_into().unwrap());
            if mode & 0o170_000 != 0o100_000 || linux_socket_slot(descriptor).is_some() {
                return None;
            }
            let size = i64::from_ne_bytes(stat[48..56].try_into().unwrap());
            let position = linux_descriptor_offset(descriptor).load(Ordering::SeqCst) as i64;
            let remaining = size.saturating_sub(position) as i32;
            Some(if copy_to_linux_user(argument, &remaining.to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            })
        }
        _ => None,
    }
}

/// Makes the kernel's devices and Linux's standard links in the domain's
/// `/dev` (in its overlay) the first time a path under `/dev` is walked, so
/// listing it and lstat find what open and stat already do: `null`,
/// `zero`, `console` and `tty` (`LinuxCharacterDevice`), `fd`, `stdin`,
/// `stdout` and `stderr` linking into `/proc/self/fd`, and `shm` for POSIX
/// shared memory.
pub(super) fn linux_ensure_dev_nodes() {
    const LINKS: [(&[u8], &[u8]); 4] = [
        (b"dev/fd", b"/proc/self/fd"),
        (b"dev/stdin", b"/proc/self/fd/0"),
        (b"dev/stdout", b"/proc/self/fd/1"),
        (b"dev/stderr", b"/proc/self/fd/2"),
    ];
    // dev/stderr is made last: once it exists, everything does (or the
    // domain removed some on purpose).
    if crate::linux_overlay::lookup(b"dev/stderr").is_some()
        || crate::linux_overlay::hidden(b"dev/stderr")
        || LINUX_MAKING_DEV_NODES.swap(true, Ordering::Acquire)
    {
        return;
    }
    let root_owned = |handle: Option<crate::linux_overlay::Handle>| {
        if let Some(handle) = handle {
            let _ = crate::linux_overlay::set_owner(handle, 0, 0);
        }
    };
    let image_has = |path: &[u8]| crate::published_rootfs::exact_entry(path).is_some();
    if !image_has(b"dev") && crate::linux_overlay::lookup(b"dev").is_none() {
        root_owned(crate::linux_overlay::create_directory(b"dev", 0o755));
    }
    if !image_has(b"dev/shm") && crate::linux_overlay::lookup(b"dev/shm").is_none() {
        root_owned(crate::linux_overlay::create_directory(b"dev/shm", 0o1777));
    }
    if !image_has(b"dev/net") && crate::linux_overlay::lookup(b"dev/net").is_none() {
        root_owned(crate::linux_overlay::create_directory(b"dev/net", 0o755));
    }
    for device in LinuxCharacterDevice::ALL {
        let mut path = [0_u8; 16];
        let name = device.name();
        path[..4].copy_from_slice(b"dev/");
        path[4..4 + name.len()].copy_from_slice(name);
        let name = &path[..4 + name.len()];
        if crate::linux_overlay::lookup(name).is_none() {
            let (_, major, minor, permissions) = device.identity();
            root_owned(crate::linux_overlay::create_device(
                name,
                crate::linux_overlay::NodeKind::CharacterDevice,
                permissions,
                major << 8 | minor,
            ));
        }
    }
    if crate::linux_overlay::lookup(b"dev/kmsg").is_none() {
        root_owned(crate::linux_overlay::create_device(
            b"dev/kmsg",
            crate::linux_overlay::NodeKind::CharacterDevice,
            0o644,
            linux_device_number(crate::linux_kmsg::MAJOR, crate::linux_kmsg::MINOR),
        ));
    }
    // /dev/pts lists the pty slaves; /dev/ptmx makes them.
    if !image_has(b"dev/pts") && crate::linux_overlay::lookup(b"dev/pts").is_none() {
        root_owned(crate::linux_overlay::create_directory(b"dev/pts", 0o755));
    }
    for (name, device, permissions) in [
        (&b"dev/ptmx"[..], crate::linux_pty::MASTER_DEVICE, 0o666),
        (b"dev/userfaultfd", LINUX_USERFAULTFD_DEVICE, 0o600),
        (b"dev/net/tun", LINUX_TUN_DEVICE, 0o666),
    ] {
        if crate::linux_overlay::lookup(name).is_none() {
            root_owned(crate::linux_overlay::create_device(
                name,
                crate::linux_overlay::NodeKind::CharacterDevice,
                permissions,
                device,
            ));
        }
    }
    for (name, target) in LINKS {
        if crate::linux_overlay::lookup(name).is_none() {
            root_owned(crate::linux_overlay::create_symlink(name, target));
        }
    }
    LINUX_MAKING_DEV_NODES.store(false, Ordering::Release);
}

/// The major and minor numbers of a device number as mknod(2) and stat(2)
/// encode it (Linux's new_decode_dev).
pub(super) fn linux_device_numbers(device: u32) -> (u32, u32) {
    (
        (device & 0xf_ff00) >> 8,
        (device & 0xff) | ((device >> 12) & 0xf_ff00),
    )
}

/// The device number of `major`:`minor` as stat(2) encodes it (Linux's
/// new_encode_dev).
pub(crate) fn linux_device_number(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

/// A device a device file opens.
pub(super) enum LinuxDeviceNode {
    /// One of the kernel's character devices, by descriptor kind.
    Character(u16),
    /// Block device `major`:`minor`: a loop device (7) or RAM disk (1).
    Block(u32, u32),
    /// /dev/loop-control (10:237).
    LoopControl,
    /// /dev/kmsg (1:11).
    KernelLog,
    /// /dev/ptmx (5:2): a new pseudo-terminal pair.
    PtyMaster,
    /// /dev/pts/N (136:N and up): pair N's slave.
    PtySlave(u64),
    /// /dev/userfaultfd (10:126).
    Userfaultfd,
    /// /dev/net/tun (10:200).
    Tun,
}

/// What opening the device file `handle` opens: the kernel's null, zero and
/// console devices, loop devices, RAM disks, /dev/ptmx and pty slaves, and
/// /dev/userfaultfd for their numbers; no other device is reachable through
/// a device file (ENXIO), and none on a nodev mount (EACCES).
pub(super) fn linux_device_node_kind(
    handle: crate::linux_overlay::Handle,
    kind: crate::linux_overlay::NodeKind,
) -> Result<LinuxDeviceNode, u64> {
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = crate::linux_overlay::copy_path(handle, &mut path).ok_or(LINUX_ENOENT)?;
    if crate::linux_mounts::flags_at(linux_mount_space(), &path[..length])
        & crate::linux_mounts::NO_DEVICES
        != 0
    {
        return Err(LINUX_EACCES);
    }
    let device = crate::linux_overlay::metadata(handle)
        .ok_or(LINUX_ENOENT)?
        .device;
    let character = kind == crate::linux_overlay::NodeKind::CharacterDevice;
    if character && device == crate::linux_pty::MASTER_DEVICE {
        return Ok(LinuxDeviceNode::PtyMaster);
    }
    if character && device == LINUX_USERFAULTFD_DEVICE {
        return Ok(LinuxDeviceNode::Userfaultfd);
    }
    if character && device == LINUX_TUN_DEVICE {
        return Ok(LinuxDeviceNode::Tun);
    }
    if let Some(index) = crate::linux_pty::slave_index(device).filter(|_| character) {
        return Ok(LinuxDeviceNode::PtySlave(index));
    }
    match (kind, linux_device_numbers(device)) {
        (
            crate::linux_overlay::NodeKind::BlockDevice,
            (major @ (crate::linux_loop::MAJOR | crate::linux_ramdisk::MAJOR), minor),
        ) => Ok(LinuxDeviceNode::Block(major, minor)),
        (
            crate::linux_overlay::NodeKind::CharacterDevice,
            (crate::linux_loop::CONTROL_MAJOR, crate::linux_loop::CONTROL_MINOR),
        ) => Ok(LinuxDeviceNode::LoopControl),
        (
            crate::linux_overlay::NodeKind::CharacterDevice,
            (crate::linux_kmsg::MAJOR, crate::linux_kmsg::MINOR),
        ) => Ok(LinuxDeviceNode::KernelLog),
        (crate::linux_overlay::NodeKind::CharacterDevice, numbers) => LinuxCharacterDevice::ALL
            .into_iter()
            .find(|device| {
                let (_, major, minor, _) = device.identity();
                (major, minor) == numbers
            })
            .map(|device| LinuxDeviceNode::Character(device.kind()))
            .ok_or(LINUX_ENXIO),
        _ => Err(LINUX_ENXIO),
    }
}

/// Releases the kernel objects whose last descriptor has closed: DRM
/// render node files and dma-bufs, open loop devices, RAM disks,
/// /dev/kmsg, pseudo-terminals, userfaultfds and Landlock rulesets.
pub(crate) fn linux_release_objects() {
    for (class, id) in crate::linux_socket::take_released_objects() {
        crate::linux_drm::release(class, id);
        crate::linux_loop::release(class, id);
        crate::linux_ramdisk::release(class, id);
        crate::linux_kmsg::release(class, id);
        crate::linux_pty::release(class, id);
        crate::linux_fscontext::release(class, id);
        linux_userfaultfd_release(class, id);
        crate::linux_landlock::release(class, id);
        linux_tun_release(class, id);
        linux_perf_release(class, id);
    }
}

/// The kernel object (class and id) an object descriptor refers to: a
/// DRM render node file, a GPU fence or a dma-buf, an open loop device or
/// /dev/loop-control.
pub(super) fn linux_object_descriptor(descriptor: u64) -> Option<(u8, u64)> {
    linux_socket_slot(descriptor).and_then(crate::linux_socket::object)
}

/// Makes a descriptor for object `slot`, the lowest free one.
pub(super) fn linux_install_object_descriptor(
    slot: crate::linux_socket::SlotId,
    flags: u64,
) -> u64 {
    linux_install_object_descriptor_with_access(slot, flags, 3)
}

/// `linux_install_object_descriptor` open for `access` (input, output or
/// both).
pub(super) fn linux_install_object_descriptor_with_access(
    slot: crate::linux_socket::SlotId,
    flags: u64,
    access: u16,
) -> u64 {
    let Some(descriptor) = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        let _ = crate::linux_socket::close(slot);
        linux_release_objects();
        return LINUX_EMFILE;
    };
    let installed = linux_socket_descriptor_installed(
        descriptor,
        slot,
        LINUX_DEVICE_SOCKET | access,
        (flags & LINUX_O_NONBLOCK) as u32,
        flags & LINUX_O_CLOEXEC != 0,
    );
    if installed >= LINUX_RETURN_TO_KERNEL {
        linux_release_objects();
    }
    installed
}

/// /dev/userfaultfd (10:126), whose USERFAULTFD_IOC_NEW makes userfaultfds:
/// an object slot of a class that keeps no state to release. Classes 1 to
/// 9 belong to DRM, loop devices, RAM disks, /dev/kmsg and ptys.
pub(super) const LINUX_USERFAULTFD_DEVICE: u32 = (10 << 8) | 126;
pub(super) const LINUX_USERFAULTFD_DEVICE_CLASS: u8 = 10;

pub(super) fn linux_open_userfaultfd_device(flags: u64) -> u64 {
    linux_open_object(LINUX_USERFAULTFD_DEVICE_CLASS, 0, flags)
}

/// Opens /dev/dri/renderD128.
pub(super) fn linux_open_render_node(flags: u64) -> u64 {
    match crate::linux_drm::open() {
        Some(slot) => linux_install_object_descriptor(slot, flags),
        None => LINUX_ENOMEM,
    }
}

/// Opens /dev/kmsg: the machine's kernel log, which only a domain set
/// `privileged=true` reads or writes (EPERM, as Linux refuses a reader that
/// syslog would).
pub(super) fn linux_open_kernel_log(flags: u64) -> u64 {
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ObserveKernelLog) {
        return LINUX_EPERM;
    }
    let access = flags & 3;
    let id = crate::linux_kmsg::open(access != 1, access != 0);
    match crate::linux_socket::open_object(crate::linux_kmsg::CLASS_READER, id) {
        Ok(slot) => linux_install_object_descriptor(slot, flags),
        Err(_) => {
            crate::linux_kmsg::release(crate::linux_kmsg::CLASS_READER, id);
            LINUX_ENOMEM
        }
    }
}

/// Opens block device `major`:`minor`: a loop device (/dev/loopN) or a RAM
/// disk (/dev/ramN).
pub(super) fn linux_open_block_device(major: u32, minor: u32, flags: u64) -> u64 {
    // An exclusive open of a disk a filesystem is mounted from is EBUSY
    // (mkfs refuses a mounted device this way).
    if flags & (LINUX_O_EXCL | LINUX_O_CREAT) == LINUX_O_EXCL
        && crate::linux_blockfs::device_mounted(linux_device_number(major, minor))
    {
        return LINUX_EBUSY;
    }
    let access = flags & 3;
    let (readable, writable) = (access != 1, access != 0);
    let (class, opened) = if major == crate::linux_ramdisk::MAJOR {
        (
            crate::linux_ramdisk::CLASS_DISK,
            crate::linux_ramdisk::open(minor, readable, writable),
        )
    } else {
        (
            crate::linux_loop::CLASS_DEVICE,
            crate::linux_loop::open(minor, readable, writable),
        )
    };
    let id = match opened {
        Ok(id) => id,
        Err(error) => return linux_loop_errno(error),
    };
    match crate::linux_socket::open_object(class, id) {
        Ok(slot) => linux_install_object_descriptor(slot, flags),
        Err(_) => {
            crate::linux_loop::release(class, id);
            crate::linux_ramdisk::release(class, id);
            LINUX_ENOMEM
        }
    }
}

pub(super) fn linux_loop_errno(error: crate::linux_loop::Error) -> u64 {
    error.number().wrapping_neg()
}

/// The class and id of a block device (loop device or RAM disk),
/// /dev/loop-control or /dev/kmsg descriptor.
pub(super) fn linux_block_descriptor(descriptor: u64) -> Option<(u8, u64)> {
    linux_object_descriptor(descriptor).filter(|(class, _)| {
        matches!(
            *class,
            crate::linux_loop::CLASS_DEVICE
                | crate::linux_loop::CLASS_CONTROL
                | crate::linux_ramdisk::CLASS_DISK
                | crate::linux_kmsg::CLASS_READER
        )
    })
}

/// read, write and lseek on /dev/kmsg open `id`: a record at a time.
fn linux_kernel_log_syscall(number: u64, id: u64, buffer: u64, count: u64) -> u64 {
    let result = match number {
        LINUX_READ_SYSCALL => match crate::linux_kmsg::read(id, count as usize) {
            Ok(record) if !copy_to_linux_user(buffer, &record) => return LINUX_EFAULT,
            Ok(record) => Ok(record.len() as u64),
            Err(error) => Err(error),
        },
        // Linux refuses a write longer than a record before reading it.
        LINUX_WRITE_SYSCALL if count > crate::linux_kmsg::RECORD_MAX as u64 => {
            Err(crate::linux_kmsg::Error::Invalid)
        }
        LINUX_WRITE_SYSCALL => {
            let mut input = alloc::vec![0_u8; count as usize];
            if !copy_from_linux_user(buffer, &mut input) {
                return LINUX_EFAULT;
            }
            crate::linux_kmsg::write(id, &input).map(|written| written as u64)
        }
        LINUX_LSEEK_SYSCALL => crate::linux_kmsg::seek(id, buffer as i64, count as u32),
        LINUX_PREAD64_SYSCALL | LINUX_PWRITE64_SYSCALL => return LINUX_ESPIPE,
        LINUX_IOCTL_SYSCALL => return LINUX_ENOTTY,
        _ => Ok(0),
    };
    result.unwrap_or_else(|error| error.number().wrapping_neg())
}

/// Whether a read of /dev/kmsg descriptor `descriptor` that found no new
/// record waits for one (no O_NONBLOCK).
pub(super) fn linux_kernel_log_read_waits(number: u64, descriptor: u64) -> bool {
    number == LINUX_READ_SYSCALL
        && linux_block_descriptor(descriptor)
            .is_some_and(|(class, _)| class == crate::linux_kmsg::CLASS_READER)
        && linux_socket_flags(descriptor).is_some_and(|flags| flags & LINUX_O_NONBLOCK as u32 == 0)
}

/// The device number (as stat(2) shows it) and whether it is a block
/// device, of block device or /dev/loop-control descriptor `class`/`id`.
pub(super) fn linux_block_descriptor_device(class: u8, id: u64) -> Option<(u32, bool)> {
    match class {
        crate::linux_loop::CLASS_DEVICE => crate::linux_loop::minor(id)
            .map(|minor| (linux_device_number(crate::linux_loop::MAJOR, minor), true)),
        crate::linux_ramdisk::CLASS_DISK => crate::linux_ramdisk::minor(id).map(|minor| {
            (
                linux_device_number(crate::linux_ramdisk::MAJOR, minor),
                true,
            )
        }),
        crate::linux_loop::CLASS_CONTROL => Some((
            linux_device_number(
                crate::linux_loop::CONTROL_MAJOR,
                crate::linux_loop::CONTROL_MINOR,
            ),
            false,
        )),
        _ => None,
    }
}

/// The calling process, for a block device ioctl.
struct LinuxLoopCaller;

impl crate::linux_loop::Caller for LinuxLoopCaller {
    fn copy_in(&self, address: u64, output: &mut [u8]) -> bool {
        copy_from_linux_user(address, output)
    }

    fn copy_out(&mut self, address: u64, input: &[u8]) -> bool {
        copy_to_linux_user(address, input)
    }

    fn backing(
        &mut self,
        descriptor: u32,
    ) -> Result<crate::linux_loop::Backing, crate::linux_loop::Error> {
        use crate::linux_loop::{Backing, Error};
        let descriptor = u64::from(descriptor);
        if !linux_descriptor_open(descriptor) || linux_path_descriptor(descriptor) {
            return Err(Error::BadDescriptor);
        }
        if let Some((crate::linux_loop::CLASS_DEVICE, id)) = linux_object_descriptor(descriptor) {
            return Ok(Backing::Loop(id));
        }
        let writable = linux_device_descriptor(descriptor) & LINUX_DESCRIPTOR_OUTPUT != 0;
        let regular_image_file = linux_rootfs_entry(descriptor).is_some_and(|entry| {
            matches!(
                entry.kind,
                crate::published_rootfs::EntryKind::File
                    | crate::published_rootfs::EntryKind::Hardlink
            )
        });
        let handle = match linux_overlay_descriptor_handle(descriptor) {
            Some(handle) => handle,
            // An image file is copied up to have a handle to keep.
            None if regular_image_file => {
                linux_copy_up_descriptor(descriptor).map_err(|_| Error::Io)?
            }
            None => return Ok(Backing::Other),
        };
        Ok(
            match crate::linux_overlay::metadata(handle).map(|metadata| metadata.kind) {
                Some(crate::linux_overlay::NodeKind::File) => Backing::File { handle, writable },
                _ => Backing::Other,
            },
        )
    }

    fn administrator(&self) -> bool {
        current_linux_credentials()
            .is_some_and(|credentials| credentials.has(linox_credentials::capability::SYS_ADMIN))
    }
}

/// read, write, lseek, pread64, pwrite64, fsync, fdatasync and ioctl on a
/// block device or /dev/loop-control descriptor; `offset` is pread64's and
/// pwrite64's.
pub(super) fn linux_block_syscall(
    number: u64,
    descriptor: u64,
    buffer: u64,
    count: u64,
    offset: u64,
) -> u64 {
    let Some((class, id)) = linux_block_descriptor(descriptor) else {
        return LINUX_EBADF;
    };
    if number == LINUX_IOCTL_SYSCALL {
        if let Some(result) = linux_generic_ioctl(descriptor, buffer, count) {
            return result;
        }
    }
    if class == crate::linux_kmsg::CLASS_READER {
        return linux_kernel_log_syscall(number, id, buffer, count);
    }
    let disk = class == crate::linux_ramdisk::CLASS_DISK;
    let result = if class == crate::linux_loop::CLASS_CONTROL {
        match number {
            LINUX_IOCTL_SYSCALL => crate::linux_loop::control(buffer as u32, count),
            // The control device has no data, and seeking it does nothing.
            LINUX_LSEEK_SYSCALL => Ok(0),
            _ => Err(crate::linux_loop::Error::Invalid),
        }
    } else {
        match number {
            LINUX_IOCTL_SYSCALL if disk => {
                crate::linux_ramdisk::ioctl(id, buffer as u32, count, &mut LinuxLoopCaller)
            }
            LINUX_IOCTL_SYSCALL => {
                crate::linux_loop::ioctl(id, buffer as u32, count, &mut LinuxLoopCaller)
            }
            LINUX_LSEEK_SYSCALL if disk => {
                crate::linux_ramdisk::seek(id, buffer as i64, count as u32)
            }
            LINUX_LSEEK_SYSCALL => crate::linux_loop::seek(id, buffer as i64, count as u32),
            LINUX_READ_SYSCALL => {
                return linux_block_transfer(class, id, buffer, count, None, false)
            }
            LINUX_WRITE_SYSCALL => {
                return linux_block_transfer(class, id, buffer, count, None, true)
            }
            LINUX_PREAD64_SYSCALL | LINUX_PWRITE64_SYSCALL if (offset as i64) < 0 => {
                Err(crate::linux_loop::Error::Invalid)
            }
            LINUX_PREAD64_SYSCALL => {
                return linux_block_transfer(class, id, buffer, count, Some(offset), false)
            }
            LINUX_PWRITE64_SYSCALL => {
                return linux_block_transfer(class, id, buffer, count, Some(offset), true)
            }
            // Writes reach the backing file or memory at once.
            _ => Ok(0),
        }
    };
    result.unwrap_or_else(linux_loop_errno)
}

/// Reads or writes `count` bytes at `address` from or to the block device
/// of open `class`/`id`, at `offset` or else at (and advancing) the file
/// position.
fn linux_block_transfer(
    class: u8,
    id: u64,
    address: u64,
    count: u64,
    offset: Option<u64>,
    write: bool,
) -> u64 {
    let disk = class == crate::linux_ramdisk::CLASS_DISK;
    let position = || {
        if disk {
            crate::linux_ramdisk::position(id)
        } else {
            crate::linux_loop::position(id)
        }
    };
    let start = match offset.map_or_else(position, Ok) {
        Ok(start) => start,
        Err(error) => return linux_loop_errno(error),
    };
    let requested = count.min(i64::MAX as u64 & !(PAGE_SIZE as u64 - 1));
    let mut buffer = [0_u8; PAGE_SIZE];
    let mut total = 0_u64;
    // A zero-length transfer still checks the descriptor and the device.
    loop {
        let chunk = (requested - total).min(PAGE_SIZE as u64) as usize;
        let at = start + total;
        let result = if write {
            if !copy_from_linux_user(address.wrapping_add(total), &mut buffer[..chunk]) {
                Err(crate::linux_loop::Error::Fault)
            } else if disk {
                crate::linux_ramdisk::write_at(id, at, &buffer[..chunk])
            } else {
                crate::linux_loop::write_at(id, at, &buffer[..chunk])
            }
        } else {
            let read = if disk {
                crate::linux_ramdisk::read_at(id, at, &mut buffer[..chunk])
            } else {
                crate::linux_loop::read_at(id, at, &mut buffer[..chunk])
            };
            read.and_then(|length| {
                // Nothing read (the end of the device) copies nothing.
                if length == 0 || copy_to_linux_user(address.wrapping_add(total), &buffer[..length])
                {
                    Ok(length)
                } else {
                    Err(crate::linux_loop::Error::Fault)
                }
            })
        };
        match result {
            Ok(length) => {
                total += length as u64;
                if length < chunk || total == requested {
                    break;
                }
            }
            Err(error) if total == 0 => return linux_loop_errno(error),
            Err(_) => break,
        }
    }
    if offset.is_none() {
        if disk {
            crate::linux_ramdisk::set_position(id, start + total);
        } else {
            crate::linux_loop::set_position(id, start + total);
        }
    }
    total
}

/// A new descriptor for object `class`/`id`, given its first reference.
pub(super) fn linux_open_object(class: u8, id: u64, flags: u64) -> u64 {
    match crate::linux_socket::open_object(class, id) {
        Ok(slot) => linux_install_object_descriptor(slot, flags),
        Err(_) => LINUX_ENOMEM,
    }
}

/// The calling process's memory for `linox_drm`.
struct LinuxUserMemory;

impl linox_drm::UserMemory for LinuxUserMemory {
    fn read(&self, address: u64, output: &mut [u8]) -> bool {
        copy_from_linux_user(address, output)
    }

    fn write(&mut self, address: u64, input: &[u8]) -> bool {
        copy_to_linux_user(address, input)
    }
}

fn linux_drm_errno(error: linox_drm::Errno) -> u64 {
    (-i64::from(error.number())) as u64
}

/// read, write and ioctl on an object descriptor.
pub(super) fn linux_object_syscall(number: u64, descriptor: u64, buffer: u64, count: u64) -> u64 {
    const DMA_BUF_IOCTL_SYNC: u64 = 0x4008_6200;
    let Some((class, id)) = linux_object_descriptor(descriptor) else {
        return LINUX_EBADF;
    };
    match (number, class) {
        (LINUX_IOCTL_SYSCALL, crate::linux_drm::CLASS_FILE) => {
            linux_drm_ioctl(id, buffer as u32, count)
        }
        // USERFAULTFD_IOC_NEW: a userfaultfd, as userfaultfd(2) makes one;
        // opening the device was the permission check.
        (LINUX_IOCTL_SYSCALL, LINUX_USERFAULTFD_DEVICE_CLASS) if buffer & 0xffff_ffff == 0xaa00 => {
            linux_userfaultfd_create(count, true)
        }
        (LINUX_IOCTL_SYSCALL, crate::linux_userfaultfd::CLASS_CONTEXT) => {
            linux_userfaultfd_ioctl(descriptor, buffer, count)
        }
        (LINUX_READ_SYSCALL, crate::linux_userfaultfd::CLASS_CONTEXT) => {
            linux_userfaultfd_read(descriptor, buffer, count)
        }
        (LINUX_IOCTL_SYSCALL, LINUX_TUN_CLASS) => linux_tun_ioctl(id, buffer as u32, count),
        (LINUX_READ_SYSCALL, LINUX_TUN_CLASS) => linux_tun_read(id, buffer, count),
        (LINUX_WRITE_SYSCALL, LINUX_TUN_CLASS) => linux_tun_write(id, buffer, count),
        (LINUX_READ_SYSCALL, LINUX_PERF_CLASS) => linux_perf_read(descriptor, buffer, count),
        (LINUX_IOCTL_SYSCALL, LINUX_PERF_CLASS) => linux_perf_ioctl(descriptor, buffer, count),
        // Host memory is coherent: there is nothing to flush.
        (LINUX_IOCTL_SYSCALL, crate::linux_drm::CLASS_DMABUF)
            if buffer & 0xffff_ffff == DMA_BUF_IOCTL_SYNC =>
        {
            0
        }
        (LINUX_IOCTL_SYSCALL, _) => LINUX_ENOTTY,
        _ => LINUX_EINVAL,
    }
}

/// A DRM ioctl on render node file `file`: copies the argument in (Linux
/// takes the caller's size, zero-extending a shorter structure), runs it,
/// makes the descriptors it asks for, and copies the argument back.
/// A DRM ioctl's result: what the call returns, or EAGAIN when it waits for
/// the GPU (an input fence, a busy buffer, a full queue), which the system
/// call layer turns into running other work and issuing the call again.
fn linux_drm_ioctl(file: u64, command: u32, address: u64) -> u64 {
    let started = timer::timestamp_counter();
    let result = linux_drm_ioctl_inner(file, command, address);
    crate::linux_drm::record_ioctl(
        command,
        result == LINUX_EAGAIN,
        timer::timestamp_counter().wrapping_sub(started),
    );
    if result >= LINUX_RETURN_TO_KERNEL && result != LINUX_EAGAIN {
        crate::linux_drm::log_failure(command, result.wrapping_neg());
    }
    result
}

fn linux_drm_ioctl_inner(file: u64, command: u32, address: u64) -> u64 {
    let (request, user_size) = match linox_drm::Request::decode(command) {
        Ok(decoded) => decoded,
        Err(error) => return linux_drm_errno(error),
    };
    let size = request.size();
    let copied = user_size.min(size);
    let mut argument = [0_u8; 64];
    if copied != 0 && !copy_from_linux_user(address, &mut argument[..copied]) {
        return LINUX_EFAULT;
    }
    // An execbuffer waits for its input fence first.
    if request == linox_drm::Request::Execbuffer {
        if let Some(fence) = linox_drm::execbuffer_in_fence(&argument[..size]) {
            let Some((crate::linux_drm::CLASS_FENCE, fence)) =
                linux_object_descriptor(u64::from(fence as u32))
            else {
                return LINUX_EINVAL;
            };
            if !crate::drivers::virtio_gpu::fence_signaled(fence) {
                return LINUX_EAGAIN;
            }
        }
    }
    let mut gpu = crate::drivers::virtio_gpu::VirtioGpu;
    let outcome = crate::linux_profile::span(crate::linux_profile::Span::DrmFileIoctl, || {
        crate::linux_drm::with_file(file, |open| {
            open.ioctl(
                &mut gpu,
                &mut LinuxUserMemory,
                request,
                &mut argument[..size],
            )
        })
    });
    let outcome = match outcome {
        None => return LINUX_EBADF,
        Some(Err(error)) => return linux_drm_errno(error),
        Some(Ok(outcome)) => outcome,
    };
    match outcome {
        linox_drm::Outcome::Done => {}
        linox_drm::Outcome::FenceDescriptor { fence, offset } => {
            let descriptor =
                crate::linux_profile::span(crate::linux_profile::Span::DrmFenceDescriptor, || {
                    linux_open_object(crate::linux_drm::CLASS_FENCE, fence, LINUX_O_CLOEXEC)
                });
            if descriptor >= LINUX_RETURN_TO_KERNEL {
                return descriptor;
            }
            argument[offset..offset + 4].copy_from_slice(&(descriptor as u32).to_le_bytes());
        }
        linox_drm::Outcome::Export {
            resource,
            size: length,
            flags,
            offset,
        } => {
            let Some(id) = crate::linux_drm::export(crate::linux_drm::DmaBuf {
                resource,
                size: length,
                memory: 2,
            }) else {
                return LINUX_ENOMEM;
            };
            linox_drm::Gpu::retain(&mut gpu, resource);
            let descriptor = linux_open_object(
                crate::linux_drm::CLASS_DMABUF,
                id,
                u64::from(flags) & LINUX_O_CLOEXEC,
            );
            if descriptor >= LINUX_RETURN_TO_KERNEL {
                return descriptor;
            }
            argument[offset..offset + 4].copy_from_slice(&(descriptor as u32).to_le_bytes());
        }
        linox_drm::Outcome::Import { descriptor } => {
            let Some((crate::linux_drm::CLASS_DMABUF, id)) =
                linux_object_descriptor(u64::from(descriptor as u32))
            else {
                return LINUX_EBADF;
            };
            let Some(dmabuf) = crate::linux_drm::dmabuf(id) else {
                return LINUX_EBADF;
            };
            let imported = crate::linux_drm::with_file(file, |open| {
                open.import(
                    &mut gpu,
                    dmabuf.resource,
                    dmabuf.size,
                    dmabuf.memory,
                    &mut argument[..size],
                )
            });
            match imported {
                None => return LINUX_EBADF,
                Some(Err(error)) => return linux_drm_errno(error),
                Some(Ok(())) => {}
            }
        }
    }
    // _IOC_READ: the caller wants the structure back.
    if command >> 31 != 0 && copied != 0 && !copy_to_linux_user(address, &argument[..copied]) {
        return LINUX_EFAULT;
    }
    0
}

/// mmap of an object descriptor: a render node maps a blob at the fake
/// offset DRM_IOCTL_VIRTGPU_MAP gave, and a dma-buf its blob, if mapped.
pub(super) fn linux_object_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    descriptor: u64,
    offset: u64,
) -> u64 {
    let Some((class, id)) = linux_object_descriptor(descriptor) else {
        return LINUX_EBADF;
    };
    // Counted with the ioctls, as number 0xff, for a SysRq `l` profile.
    crate::linux_drm::record_ioctl(0xff, false, 0);
    if flags & LINUX_MAP_SHARED == 0 || length == 0 || !offset.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let (physical, cache) = match class {
        crate::linux_drm::CLASS_FILE => {
            match crate::linux_drm::with_file(id, |open| open.mmap(offset, length)) {
                Some(Ok(mapping)) => (mapping.physical, mapping.cache),
                Some(Err(error)) => return linux_drm_errno(error),
                None => return LINUX_EBADF,
            }
        }
        crate::linux_drm::CLASS_DMABUF => {
            let Some(dmabuf) = crate::linux_drm::dmabuf(id) else {
                return LINUX_EBADF;
            };
            if offset
                .checked_add(length)
                .is_none_or(|end| end > dmabuf.size.next_multiple_of(PAGE_SIZE as u64))
            {
                return LINUX_EINVAL;
            }
            match crate::drivers::virtio_gpu::mapped_physical(dmabuf.resource) {
                Some((physical, cache)) => (physical + offset, cache),
                None => return LINUX_ENODEV,
            }
        }
        _ => return LINUX_ENODEV,
    };
    let pages = length.div_ceil(PAGE_SIZE as u64) as usize;
    let fixed = flags & LINUX_MAP_FIXED != 0;
    let Some(mapping) = linux_runtime_select_mapping(address, pages, fixed, false) else {
        return LINUX_ENOMEM;
    };
    if !linux_runtime_range_available(mapping, pages)
        && (!fixed || linux_runtime_munmap(mapping, (pages * PAGE_SIZE) as u64) != 0)
    {
        return LINUX_ENOMEM;
    }
    for page in 0..pages {
        let installed = address_space::install_current_linux_device_page(
            mapping + (page * PAGE_SIZE) as u64,
            physical + (page * PAGE_SIZE) as u64,
            protection & LINUX_PROT_WRITE != 0,
            match cache {
                linox_drm::Cache::Cached => address_space::DeviceCaching::WriteBack,
                linox_drm::Cache::WriteCombined => address_space::DeviceCaching::WriteCombining,
                linox_drm::Cache::Uncached => address_space::DeviceCaching::Uncached,
            },
        );
        if !installed {
            let _ = rollback_linux_runtime_mapping(mapping, page);
            return LINUX_ENOMEM;
        }
    }
    mapping
}

pub(super) fn linux_console_descriptor_open(descriptor: u64) -> bool {
    linux_console_descriptor(descriptor) != 0
}

fn linux_tty_get_termios(address: u64) -> u64 {
    let mut termios = [0_u8; 36];
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        for (index, flag) in X86_RUNTIME.LINUX_TTY_TERMIOS_FLAGS.iter().enumerate() {
            termios[index * 4..index * 4 + 4]
                .copy_from_slice(&flag.load(Ordering::SeqCst).to_ne_bytes());
        }
        termios[16] = X86_RUNTIME.LINUX_TTY_LINE.load(Ordering::SeqCst);
        for (index, character) in X86_RUNTIME.LINUX_TTY_CONTROL_CHARACTERS.iter().enumerate() {
            termios[17 + index] = character.load(Ordering::SeqCst);
        }
    }
    if copy_to_linux_user(address, &termios) {
        0
    } else {
        LINUX_EFAULT
    }
}

fn linux_tty_set_termios(address: u64) -> u64 {
    let mut termios = [0_u8; 36];
    if !copy_from_linux_user(address, &mut termios) {
        return LINUX_EFAULT;
    }
    for (index, flag) in X86_RUNTIME.LINUX_TTY_TERMIOS_FLAGS.iter().enumerate() {
        flag.store(
            u32::from_ne_bytes(termios[index * 4..index * 4 + 4].try_into().unwrap()),
            Ordering::SeqCst,
        );
    }
    X86_RUNTIME
        .LINUX_TTY_LINE
        .store(termios[16], Ordering::SeqCst);
    for (index, character) in X86_RUNTIME.LINUX_TTY_CONTROL_CHARACTERS.iter().enumerate() {
        character.store(termios[17 + index], Ordering::SeqCst);
    }
    0
}

pub(super) fn linux_tty_ioctl(request: u64, argument: u64) -> u64 {
    let pid = current_linux_process_pid();
    match request {
        LINUX_TCGETS => linux_tty_get_termios(argument),
        LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF => {
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                linux_tty_set_termios(argument)
            } else {
                LINUX_ENOTTY
            }
        }
        // termios2: the same settings followed by the input and output
        // speeds, which the console reports as 38400 baud and ignores.
        LINUX_TCGETS2 => {
            let result = linux_tty_get_termios(argument);
            let speeds = [38_400_u32.to_ne_bytes(), 38_400_u32.to_ne_bytes()].concat();
            if result != 0 {
                result
            } else if argument
                .checked_add(36)
                .is_some_and(|address| copy_to_linux_user(address, &speeds))
            {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_TCSETS2 | LINUX_TCSETSW2 | LINUX_TCSETSF2 => {
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                linux_tty_set_termios(argument)
            } else {
                LINUX_ENOTTY
            }
        }
        LINUX_TIOCSCTTY => {
            let Some(session) = linux_process::live_process_session(pid) else {
                return LINUX_ESRCH;
            };
            if session != pid {
                return LINUX_EPERM;
            }
            let owner = X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst);
            let privileged_force = argument == 1
                && current_linux_credentials()
                    .is_some_and(|credentials| credentials.user.effective == 0);
            if owner != 0 && owner != session && !privileged_force {
                return LINUX_EPERM;
            }
            X86_RUNTIME
                .LINUX_TTY_SESSION
                .store(session, Ordering::SeqCst);
            X86_RUNTIME.LINUX_TTY_FOREGROUND_GROUP.store(
                linux_process::live_process_group(pid).unwrap_or(pid),
                Ordering::SeqCst,
            );
            0
        }
        LINUX_TIOCGPGRP => {
            let Some(session) = linux_process::live_process_session(pid) else {
                return LINUX_ESRCH;
            };
            if X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst) != session {
                return LINUX_ENOTTY;
            }
            let group = X86_RUNTIME
                .LINUX_TTY_FOREGROUND_GROUP
                .load(Ordering::SeqCst);
            if copy_to_linux_user(argument, &(group as i32).to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_TIOCSPGRP => {
            let Some(session) = linux_process::live_process_session(pid) else {
                return LINUX_ESRCH;
            };
            if X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst) != session {
                return LINUX_ENOTTY;
            }
            let mut bytes = [0_u8; 4];
            if !copy_from_linux_user(argument, &mut bytes) {
                return LINUX_EFAULT;
            }
            let group = i32::from_ne_bytes(bytes);
            if group <= 0
                || !(0..linux_process::live_process_slots()).any(|slot| {
                    linux_process::live_process_pid_at(slot).is_some_and(|candidate| {
                        linux_process::live_process_group(candidate) == Some(group as u32)
                            && linux_process::live_process_session(candidate) == Some(session)
                    })
                })
            {
                return LINUX_EPERM;
            }
            X86_RUNTIME
                .LINUX_TTY_FOREGROUND_GROUP
                .store(group as u32, Ordering::SeqCst);
            0
        }
        LINUX_TIOCNOTTY => {
            let Some(session) = linux_process::live_process_session(pid) else {
                return LINUX_ESRCH;
            };
            if X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst) != session {
                return LINUX_ENOTTY;
            }
            if session == pid {
                X86_RUNTIME.LINUX_TTY_SESSION.store(0, Ordering::SeqCst);
                X86_RUNTIME
                    .LINUX_TTY_FOREGROUND_GROUP
                    .store(0, Ordering::SeqCst);
            }
            0
        }
        LINUX_TIOCGSID => {
            let Some(session) = linux_process::live_process_session(pid) else {
                return LINUX_ESRCH;
            };
            if X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst) != session {
                return LINUX_ENOTTY;
            }
            if copy_to_linux_user(argument, &(session as i32).to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_TIOCGWINSZ => {
            let mut window = [0_u8; 8];
            window[..2].copy_from_slice(&24_u16.to_ne_bytes());
            window[2..4].copy_from_slice(&80_u16.to_ne_bytes());
            if copy_to_linux_user(argument, &window) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_TIOCVHANGUP => {
            if current_linux_credentials()
                .is_some_and(|credentials| credentials.user.effective == 0)
            {
                X86_RUNTIME.LINUX_TTY_SESSION.store(0, Ordering::SeqCst);
                X86_RUNTIME
                    .LINUX_TTY_FOREGROUND_GROUP
                    .store(0, Ordering::SeqCst);
                0
            } else {
                LINUX_EPERM
            }
        }
        _ => LINUX_ENOTTY,
    }
}

/// The character devices the kernel provides itself. Each has its own
/// inode and Linux's device number: programs compare them (GNU grep takes
/// output whose identity is /dev/null's as discarded and prints nothing).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxCharacterDevice {
    Null,
    Zero,
    Full,
    Random,
    Urandom,
    Console,
    Tty,
}

impl LinuxCharacterDevice {
    const ALL: [Self; 7] = [
        Self::Null,
        Self::Zero,
        Self::Full,
        Self::Random,
        Self::Urandom,
        Self::Console,
        Self::Tty,
    ];

    /// The device's name in /dev.
    fn name(self) -> &'static [u8] {
        match self {
            Self::Null => b"null",
            Self::Zero => b"zero",
            Self::Full => b"full",
            Self::Random => b"random",
            Self::Urandom => b"urandom",
            Self::Console => b"console",
            Self::Tty => b"tty",
        }
    }

    /// The device at `path`, `/dev/NAME`.
    pub(super) fn from_path(path: &[u8]) -> Option<Self> {
        Self::from_name(path.strip_prefix(b"/dev/")?)
    }

    /// The device at canonical `path` (`dev/NAME`).
    pub(super) fn from_canonical(path: &[u8]) -> Option<Self> {
        Self::from_name(path.strip_prefix(b"dev/")?)
    }

    fn from_name(name: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|device| device.name() == name)
    }

    /// The device an open descriptor's kind (`linux_device_descriptor`)
    /// names: /dev/null opens with no kind bits, only its access mode.
    pub(super) fn from_kind(kind: u16) -> Self {
        match kind & !3 {
            LINUX_DEVICE_FULL => Self::Full,
            LINUX_DEVICE_RANDOM => Self::Urandom,
            _ if kind & LINUX_DEVICE_ZERO != 0 => Self::Zero,
            0 => Self::Null,
            _ => Self::Console,
        }
    }

    /// The kind bits a descriptor opened on the device carries.
    pub(super) fn kind(self) -> u16 {
        match self {
            Self::Null => 0,
            Self::Zero => LINUX_DEVICE_ZERO,
            Self::Full => LINUX_DEVICE_FULL,
            Self::Random | Self::Urandom => LINUX_DEVICE_RANDOM,
            Self::Console | Self::Tty => LINUX_DEVICE_CONSOLE,
        }
    }

    /// Inode, major and minor number and permissions, as on Linux.
    pub(super) fn identity(self) -> (u64, u32, u32, u32) {
        match self {
            Self::Null => (1, 1, 3, 0o666),
            Self::Zero => (2, 1, 5, 0o666),
            Self::Full => (6, 1, 7, 0o666),
            Self::Random => (7, 1, 8, 0o666),
            Self::Urandom => (8, 1, 9, 0o666),
            Self::Console => (3, 5, 1, 0o600),
            Self::Tty => (5, 5, 0, 0o666),
        }
    }

    pub(super) fn stat(self) -> [u8; LINUX_STAT_SIZE] {
        let (inode, major, minor, permissions) = self.identity();
        let mut stat = linux_stat(0o020_000 | permissions, inode);
        let (major, minor) = (u64::from(major), u64::from(minor));
        let rdev = (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12);
        stat[40..48].copy_from_slice(&rdev.to_ne_bytes());
        stat
    }
}

pub(super) fn linux_console_stat() -> [u8; LINUX_STAT_SIZE] {
    LinuxCharacterDevice::Console.stat()
}

/// Character devices for graphical sessions: the firmware framebuffer as
/// Linux fbdev (/dev/fb0) and evdev input devices (/dev/input/eventN).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxGraphicsDevice {
    Framebuffer,
    Input(usize),
}

pub(super) fn linux_graphics_device(state: u16) -> Option<LinuxGraphicsDevice> {
    match state & !3 {
        LINUX_FILE_FRAMEBUFFER => Some(LinuxGraphicsDevice::Framebuffer),
        kind if kind & !LINUX_ROOT_NODE_MASK == LINUX_FILE_MASK => {
            let device = usize::from((kind >> 8).wrapping_sub(LINUX_INPUT_NODE_FIRST >> 8));
            (device < crate::linux_input::DEVICE_LIMIT)
                .then_some(LinuxGraphicsDevice::Input(device))
        }
        _ => None,
    }
}

pub(super) fn linux_graphics_descriptor(descriptor: u64) -> Option<LinuxGraphicsDevice> {
    if linux_socket_slot(descriptor).is_some() {
        return None;
    }
    linux_graphics_device(linux_device_descriptor(descriptor))
}

pub(super) fn linux_graphics_path_kind(path: &[u8]) -> Option<u16> {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return None;
    }
    if path == b"/dev/fb0" {
        return crate::framebuffer::display().map(|_| LINUX_FILE_FRAMEBUFFER);
    }
    let [digit] = path.strip_prefix(b"/dev/input/event")? else {
        return None;
    };
    let device = digit.checked_sub(b'0')?;
    crate::linux_input::device_kind(usize::from(device))?;
    Some(LINUX_FILE_MASK | (LINUX_INPUT_NODE_FIRST + (u16::from(device) << 8)))
}

pub(super) fn linux_graphics_stat(device: LinuxGraphicsDevice) -> [u8; LINUX_STAT_SIZE] {
    // Linux numbers: fb0 is character device 29:0, eventN is 13:(64 + N).
    let (inode, major, minor) = match device {
        LinuxGraphicsDevice::Framebuffer => (60, 29_u64, 0_u64),
        LinuxGraphicsDevice::Input(device) => (61 + device as u64, 13, 64 + device as u64),
    };
    let mut stat = linux_stat(LINUX_STAT_CHARACTER_DEVICE_MODE | 0o060, inode);
    let rdev = (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12);
    stat[40..48].copy_from_slice(&rdev.to_ne_bytes());
    stat
}

pub(super) fn linux_graphics_syscall(number: u64, descriptor: u64, buffer: u64, count: u64) -> u64 {
    let Some(device) = linux_graphics_descriptor(descriptor) else {
        return LINUX_EBADF;
    };
    let state = linux_device_descriptor(descriptor);
    match number {
        LINUX_IOCTL_SYSCALL => {
            if let Some(result) = linux_generic_ioctl(descriptor, buffer, count) {
                return result;
            }
            match device {
                LinuxGraphicsDevice::Framebuffer => linux_framebuffer_ioctl(buffer, count),
                LinuxGraphicsDevice::Input(device) => linux_evdev_ioctl(device, buffer, count),
            }
        }
        LINUX_READ_SYSCALL if state & LINUX_DESCRIPTOR_INPUT == 0 => LINUX_EBADF,
        LINUX_WRITE_SYSCALL if state & LINUX_DESCRIPTOR_OUTPUT == 0 => LINUX_EBADF,
        LINUX_READ_SYSCALL | LINUX_WRITE_SYSCALL => match device {
            LinuxGraphicsDevice::Input(device) if number == LINUX_READ_SYSCALL => {
                let mut events = [0_u8; crate::linux_input::EVENT_SIZE * 64];
                let wanted = usize::try_from(count)
                    .unwrap_or(usize::MAX)
                    .min(events.len());
                let wanted = wanted - wanted % crate::linux_input::EVENT_SIZE;
                if wanted == 0 {
                    return LINUX_EINVAL;
                }
                // Readers poll first; a read with nothing queued reports
                // EAGAIN rather than blocking.
                let length = crate::linux_input::read(device, &mut events[..wanted]);
                if length == 0 {
                    return LINUX_EAGAIN;
                }
                if !copy_to_linux_user(buffer, &events[..length]) {
                    return LINUX_EFAULT;
                }
                length as u64
            }
            // Injected events are accepted and dropped.
            LinuxGraphicsDevice::Input(_) => count,
            LinuxGraphicsDevice::Framebuffer => {
                linux_framebuffer_transfer(descriptor, buffer, count, number == LINUX_WRITE_SYSCALL)
            }
        },
        _ => LINUX_EINVAL,
    }
}

fn linux_framebuffer_transfer(descriptor: u64, buffer: u64, count: u64, write: bool) -> u64 {
    let offset = linux_descriptor_offset(descriptor);
    let mut position = usize::try_from(offset.load(Ordering::SeqCst)).unwrap_or(usize::MAX);
    let mut remaining = usize::try_from(count).unwrap_or(usize::MAX);
    let mut moved = 0_usize;
    let mut chunk = [0_u8; PAGE_SIZE];
    while remaining != 0 {
        let length = remaining.min(PAGE_SIZE);
        let user = buffer + moved as u64;
        if write && !copy_from_linux_user(user, &mut chunk[..length]) {
            return if moved == 0 {
                LINUX_EFAULT
            } else {
                moved as u64
            };
        }
        let done = crate::framebuffer::transfer(position, &mut chunk[..length], write);
        if !write && !copy_to_linux_user(user, &chunk[..done]) {
            return if moved == 0 {
                LINUX_EFAULT
            } else {
                moved as u64
            };
        }
        moved += done;
        position += done;
        remaining -= length;
        if done < length {
            break;
        }
    }
    offset.store(position as u64, Ordering::SeqCst);
    if write && moved == 0 && count != 0 {
        return LINUX_ENOSPC;
    }
    moved as u64
}

fn linux_framebuffer_ioctl(request: u64, argument: u64) -> u64 {
    const FBIOGET_VSCREENINFO: u64 = 0x4600;
    const FBIOPUT_VSCREENINFO: u64 = 0x4601;
    const FBIOGET_FSCREENINFO: u64 = 0x4602;
    const FBIOPAN_DISPLAY: u64 = 0x4606;
    const FBIOBLANK: u64 = 0x4611;
    const FBIO_WAITFORVSYNC: u64 = 0x4004_4620;
    let Some(display) = crate::framebuffer::display() else {
        return LINUX_ENODEV;
    };
    match request & 0xffff_ffff {
        // The mode is fixed by the firmware, so setting it reports it back.
        FBIOGET_VSCREENINFO | FBIOPUT_VSCREENINFO => {
            let mut info = [0_u32; 40];
            info[0] = display.width;
            info[1] = display.height;
            info[2] = display.width;
            info[3] = display.height;
            info[6] = 32;
            // red, green, blue and transparency bitfields: offset, length.
            let (red, blue) = if display.bgrx { (16, 0) } else { (0, 16) };
            info[8] = red;
            info[9] = 8;
            info[11] = 8;
            info[12] = 8;
            info[14] = blue;
            info[15] = 8;
            info[17] = 24;
            // height and width in millimetres are unknown.
            info[22] = u32::MAX;
            info[23] = u32::MAX;
            let mut bytes = [0_u8; 160];
            for (chunk, value) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(info) {
                chunk.copy_from_slice(&value.to_ne_bytes());
            }
            if copy_to_linux_user(argument, &bytes) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        FBIOGET_FSCREENINFO => {
            let mut info = [0_u8; 80];
            info[..7].copy_from_slice(b"linoxfb");
            info[16..24].copy_from_slice(&display.physical.to_ne_bytes());
            info[24..28].copy_from_slice(&(display.length as u32).to_ne_bytes());
            // FB_TYPE_PACKED_PIXELS, then FB_VISUAL_TRUECOLOR.
            info[36..40].copy_from_slice(&2_u32.to_ne_bytes());
            info[48..52].copy_from_slice(&display.line_length.to_ne_bytes());
            if copy_to_linux_user(argument, &info) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        FBIOPAN_DISPLAY | FBIOBLANK | FBIO_WAITFORVSYNC => 0,
        _ => LINUX_ENOTTY,
    }
}

/// Maps the framebuffer into the caller, after which the kernel console
/// stops drawing until the domain's descriptors are torn down.
pub(super) fn linux_framebuffer_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    offset: u64,
) -> u64 {
    let Some(display) = crate::framebuffer::display() else {
        return LINUX_ENODEV;
    };
    let mapped = display.length.next_multiple_of(PAGE_SIZE) as u64;
    if flags & LINUX_MAP_SHARED == 0
        || protection & LINUX_PROT_READ == 0
        || length == 0
        || !offset.is_multiple_of(PAGE_SIZE as u64)
        || offset.checked_add(length).is_none_or(|end| end > mapped)
        || !display.physical.is_multiple_of(PAGE_SIZE as u64)
    {
        return LINUX_EINVAL;
    }
    let pages = length.div_ceil(PAGE_SIZE as u64) as usize;
    let fixed = flags & LINUX_MAP_FIXED != 0;
    let Some(mapping) = linux_runtime_select_mapping(address, pages, fixed, false) else {
        return LINUX_ENOMEM;
    };
    if !linux_runtime_range_available(mapping, pages)
        && (!fixed || linux_runtime_munmap(mapping, (pages * PAGE_SIZE) as u64) != 0)
    {
        return LINUX_ENOMEM;
    }
    for page in 0..pages {
        let installed = address_space::install_current_linux_device_page(
            mapping + (page * PAGE_SIZE) as u64,
            display.physical + offset + (page * PAGE_SIZE) as u64,
            protection & LINUX_PROT_WRITE != 0,
            address_space::DeviceCaching::WriteBack,
        );
        if !installed {
            let _ = rollback_linux_runtime_mapping(mapping, page);
            return LINUX_ENOMEM;
        }
    }
    crate::framebuffer::set_owned(true);
    mapping
}

fn linux_evdev_ioctl(device: usize, request: u64, argument: u64) -> u64 {
    const EVIOCGRAB: u64 = 0x4004_4590;
    const EVIOCSCLOCKID: u64 = 0x4004_45a0;
    let request = request & 0xffff_ffff;
    if matches!(request, EVIOCGRAB | EVIOCSCLOCKID) {
        return 0;
    }
    let Some(kind) = crate::linux_input::device_kind(device) else {
        return LINUX_ENODEV;
    };
    // _IOC(direction, 'E', number, size)
    let (direction, size, number) = (request >> 30, (request >> 16) & 0x3fff, request & 0xff);
    if (request >> 8) & 0xff != u64::from(b'E') || direction != 2 {
        return LINUX_ENOTTY;
    }
    let mut reply = [0_u8; 256];
    let length = match number {
        // EVIOCGVERSION
        0x01 => {
            reply[..4].copy_from_slice(&0x0001_0001_u32.to_ne_bytes());
            4
        }
        // EVIOCGID: bus type (USB), vendor, product, version
        0x02 => {
            reply[..2].copy_from_slice(&3_u16.to_ne_bytes());
            8
        }
        // EVIOCGNAME
        0x06 => {
            let name = crate::linux_input::device_name(device);
            let length = name.len().min(size as usize).min(reply.len() - 1);
            reply[..length].copy_from_slice(&name[..length]);
            length + 1
        }
        // EVIOCGPHYS, EVIOCGUNIQ: empty strings
        0x07 | 0x08 => 1,
        // EVIOCGPROP, and the key, LED, sound and switch states: all clear
        0x09 | 0x18..=0x1b => size as usize,
        // EVIOCGBIT(type): supported event types and codes
        0x20..=0x3f => {
            let mut set = |bit: u16| {
                if let Some(byte) = reply.get_mut(usize::from(bit / 8)) {
                    *byte |= 1 << (bit % 8);
                }
            };
            let pointer = !matches!(kind, crate::linux_input::DeviceKind::Keyboard);
            match (number - 0x20) as u16 {
                0 => {
                    set(crate::linux_input::EV_SYN);
                    set(crate::linux_input::EV_KEY);
                    match kind {
                        crate::linux_input::DeviceKind::Keyboard => {}
                        crate::linux_input::DeviceKind::Mouse => set(crate::linux_input::EV_REL),
                        crate::linux_input::DeviceKind::Tablet { .. } => {
                            set(crate::linux_input::EV_ABS);
                            set(crate::linux_input::EV_REL);
                        }
                    }
                }
                crate::linux_input::EV_KEY if pointer => {
                    set(crate::linux_input::BTN_LEFT);
                    set(crate::linux_input::BTN_RIGHT);
                    set(crate::linux_input::BTN_MIDDLE);
                }
                crate::linux_input::EV_KEY => (1..=248).for_each(&mut set),
                crate::linux_input::EV_REL if pointer => {
                    if matches!(kind, crate::linux_input::DeviceKind::Mouse) {
                        set(crate::linux_input::REL_X);
                        set(crate::linux_input::REL_Y);
                    }
                    set(crate::linux_input::REL_WHEEL);
                }
                crate::linux_input::EV_ABS
                    if matches!(kind, crate::linux_input::DeviceKind::Tablet { .. }) =>
                {
                    set(crate::linux_input::ABS_X);
                    set(crate::linux_input::ABS_Y);
                }
                _ => {}
            }
            size as usize
        }
        // EVIOCGABS(axis): value, minimum, maximum, fuzz, flat, resolution
        0x40..=0x7f => {
            let crate::linux_input::DeviceKind::Tablet { maximum } = kind else {
                return LINUX_EINVAL;
            };
            if !matches!(
                (number - 0x40) as u16,
                crate::linux_input::ABS_X | crate::linux_input::ABS_Y
            ) {
                return LINUX_EINVAL;
            }
            reply[8..12].copy_from_slice(&maximum.to_ne_bytes());
            24
        }
        _ => return LINUX_ENOTTY,
    };
    let length = length.min(size as usize).min(reply.len());
    if !copy_to_linux_user(argument, &reply[..length]) {
        return LINUX_EFAULT;
    }
    if matches!(number, 0x06..=0x08) {
        length as u64
    } else {
        0
    }
}
