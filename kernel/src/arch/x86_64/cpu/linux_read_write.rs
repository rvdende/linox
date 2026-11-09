use super::*;

pub(super) fn linux_descriptor_read(descriptor: u64, address: u64, count: u64) -> u64 {
    if linux_io_uring_descriptor(descriptor) {
        return LINUX_EINVAL;
    }
    if let Some(result) = linux_signalfd_read(descriptor, address, count) {
        return result;
    }
    if let Some(result) = linux_inotify_read(descriptor, address, count) {
        return result;
    }
    if let Some(result) = linux_fanotify_read(descriptor, address, count) {
        return result;
    }
    if linux_socket_slot(descriptor).is_some() {
        let device = linux_device_descriptor(descriptor);
        if device & LINUX_DEVICE_PIPE != 0 && device & 3 & LINUX_DESCRIPTOR_INPUT == 0 {
            return LINUX_EBADF;
        }
        let first = linux_socket_recvfrom(None, descriptor, address, count, 0, 0, 0);
        let packets = linux_socket_flags(descriptor)
            .is_some_and(|flags| u64::from(flags) & LINUX_O_DIRECT != 0);
        if device & LINUX_DEVICE_PIPE == 0 || packets {
            return first;
        }
        // A pipe read returns everything queued up to `count`, as Linux's
        // does; only the first part may wait.
        const MSG_DONTWAIT: u64 = 0x40;
        let mut total = first;
        while total >= PAGE_SIZE as u64 && total < count && total.is_multiple_of(PAGE_SIZE as u64) {
            let more = linux_socket_recvfrom(
                None,
                descriptor,
                address + total,
                count - total,
                MSG_DONTWAIT,
                0,
                0,
            );
            if more == 0 || more >= LINUX_RETURN_TO_KERNEL {
                break;
            }
            total += more;
        }
        return total;
    }
    if let Some(result) = linux_eventfd_read(descriptor, address, count) {
        return result;
    }
    if let Some(result) = linux_timerfd_read(descriptor, address, count) {
        return result;
    }
    if let Some(result) = linux_pipe_read(descriptor, address, count) {
        return result;
    }
    let device = linux_device_descriptor(descriptor);
    if linux_userfaultfd_descriptor(descriptor) {
        return LINUX_EAGAIN;
    }
    if linux_path_descriptor(descriptor) {
        return LINUX_EBADF;
    }
    if linux_secret_descriptor(descriptor) {
        return LINUX_EINVAL;
    }
    if u16::from(linux_console_descriptor(descriptor)) & LINUX_DESCRIPTOR_INPUT != 0
        || device & LINUX_DEVICE_CONSOLE != 0 && matches!(device & 3, LINUX_DESCRIPTOR_INPUT | 3)
    {
        if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) || count == 0 {
            return 0;
        }
        let Some(byte) = container_console_read_byte() else {
            return 0;
        };
        if !copy_to_linux_user(address, &[byte]) {
            return LINUX_EFAULT;
        }
        return 1;
    }
    if let Some(entry) = linux_rootfs_entry(descriptor) {
        if entry.kind == crate::published_rootfs::EntryKind::Directory {
            return LINUX_EISDIR;
        }
        let state = linux_device_descriptor(descriptor);
        if !matches!(state & 3, LINUX_DESCRIPTOR_INPUT | 3) {
            return LINUX_EBADF;
        }
        let offset = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        if start >= entry.data.len() || count == 0 {
            return 0;
        }
        let end = start
            .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
            .min(entry.data.len());
        if !copy_to_linux_user(address, &entry.data[start..end]) {
            return LINUX_EFAULT;
        }
        linux_descriptor_offset(descriptor).store(end as u64, Ordering::SeqCst);
        return (end - start) as u64;
    }
    if let Some(result) = linux_overlay_read(descriptor, device, address, count) {
        return result;
    }
    if linux_tmp_file(device) {
        return linux_tmp_read(descriptor, device, address, count);
    }
    if device & !3 == LINUX_FILE_RESOLV_CONF {
        let (contents, size) = linux_resolv_conf();
        let start = linux_descriptor_offset(descriptor).load(Ordering::SeqCst) as usize;
        if start >= size || count == 0 {
            return 0;
        }
        let end = start
            .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
            .min(size);
        if !copy_to_linux_user(address, &contents[start..end]) {
            return LINUX_EFAULT;
        }
        linux_descriptor_offset(descriptor).store(end as u64, Ordering::SeqCst);
        return (end - start) as u64;
    }
    if matches!(
        device & !3,
        LINUX_FILE_PROC_FDINFO
            | LINUX_FILE_PROC_CPUINFO
            | LINUX_FILE_PROC_SYSVIPC_MSG
            | LINUX_FILE_PROC_SYSVIPC_SHM
            | LINUX_FILE_PROC_SYSVIPC_SEM
            | LINUX_FILE_PROC_KEYS
            | LINUX_FILE_PROC_KEY_USERS
            | LINUX_FILE_PROC_SWAPS
            | LINUX_FILE_PROC_STAT
            | LINUX_FILE_PROC_DYNAMIC_STAT
            | LINUX_FILE_PROC_DYNAMIC_STATUS
            | LINUX_FILE_PROC_DYNAMIC_STATM
            | LINUX_FILE_PROC_DYNAMIC_IO
            | LINUX_FILE_PROC_DYNAMIC_MAPS
            | LINUX_FILE_PROC_DYNAMIC_SMAPS
            | LINUX_FILE_PROC_DYNAMIC_PAGEMAP
            | LINUX_FILE_PROC_DYNAMIC_MEM
            | LINUX_FILE_PROC_OOM_SCORE_ADJ
            | LINUX_FILE_PROC_TIMENS_OFFSETS
            | LINUX_FILE_PROC_TASK_COMM
            | LINUX_FILE_PROC_TASK_STAT
            | LINUX_FILE_PROC_MOUNTS
            | LINUX_FILE_PROC_MOUNTINFO
    ) || linux_proc_sysctl_index(device).is_some()
    {
        let offset = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
        let result = linux_regular_file_read_at(descriptor, address, count, offset);
        if result < LINUX_RETURN_TO_KERNEL {
            linux_descriptor_offset(descriptor)
                .store(offset.saturating_add(result), Ordering::SeqCst);
        }
        return result;
    }
    if let Some(file) = linux_regular_file(device) {
        if !matches!(device & 3, LINUX_DESCRIPTOR_INPUT | 3) {
            return LINUX_EBADF;
        }
        let offset = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        if start >= file.len() || count == 0 {
            return 0;
        }
        let requested = usize::try_from(count).unwrap_or(usize::MAX);
        let end = start.saturating_add(requested).min(file.len());
        if !copy_to_linux_user(address, &file[start..end]) {
            return LINUX_EFAULT;
        }
        linux_descriptor_offset(descriptor).store(end as u64, Ordering::SeqCst);
        return (end - start) as u64;
    }
    if device & LINUX_DEVICE_DIRECTORY != 0 {
        return LINUX_EISDIR;
    }
    let access = device & 3;
    if access == LINUX_DESCRIPTOR_INPUT || access == 3 {
        if device & LINUX_DEVICE_ZERO == 0 || count == 0 {
            return 0;
        }
        if device & !3 == LINUX_DEVICE_RANDOM {
            return linux_getrandom(address, count, 0);
        }
        let Ok(length) = usize::try_from(count) else {
            return LINUX_EINVAL;
        };
        // /dev/zero (and /dev/full) fill the whole buffer, a chunk at a time.
        let zeros = [0_u8; LINUX_WRITE_LIMIT];
        for offset in (0..length).step_by(LINUX_WRITE_LIMIT) {
            let chunk = (length - offset).min(LINUX_WRITE_LIMIT);
            if !copy_to_linux_user(address + offset as u64, &zeros[..chunk]) {
                return if offset == 0 {
                    LINUX_EFAULT
                } else {
                    offset as u64
                };
            }
        }
        count
    } else {
        LINUX_EBADF
    }
}

pub(super) fn linux_resolv_conf() -> ([u8; 32], usize) {
    fn decimal(value: u8, output: &mut [u8]) -> usize {
        if value >= 100 {
            output[0] = b'0' + value / 100;
            output[1] = b'0' + value / 10 % 10;
            output[2] = b'0' + value % 10;
            3
        } else if value >= 10 {
            output[0] = b'0' + value / 10;
            output[1] = b'0' + value % 10;
            2
        } else {
            output[0] = b'0' + value;
            1
        }
    }

    let mut output = [0_u8; 32];
    output[..11].copy_from_slice(b"nameserver ");
    let mut used = 11;
    for (index, octet) in (crate::network::dns() as u32)
        .to_be_bytes()
        .into_iter()
        .enumerate()
    {
        used += decimal(octet, &mut output[used..]);
        output[used] = if index == 3 { b'\n' } else { b'.' };
        used += 1;
    }
    (output, used)
}

pub(super) fn linux_regular_file_read_at(
    descriptor: u64,
    address: u64,
    count: u64,
    offset: u64,
) -> u64 {
    let state = linux_device_descriptor(descriptor);
    if state & !3 == LINUX_FILE_PROC_MOUNTS {
        linux_set_descriptor_tmp_generation(
            descriptor,
            crate::linux_mounts::changes(linux_execution_instance()).wrapping_add(1),
        );
    }
    if linux_path_descriptor(descriptor) {
        return LINUX_EBADF;
    }
    if (offset as i64) < 0 {
        return LINUX_EINVAL;
    }
    if linux_pipe_descriptor(descriptor) || linux_socket_slot(descriptor).is_some() {
        // No position to read at (pread on a pipe or socket).
        return LINUX_ESPIPE;
    }
    if state & LINUX_DEVICE_DIRECTORY != 0 {
        return LINUX_EISDIR;
    }
    if linux_secret_descriptor(descriptor) {
        return LINUX_EINVAL;
    }
    // /proc/sys/kernel/domainname reads the domain's name (splice06).
    if linux_proc_sysctl_index(state)
        .is_some_and(|index| LINUX_PROC_SYSCTLS[index].1 == b"sys/kernel/domainname")
    {
        let mut name = [0_u8; LINUX_UTS_NAME_CAPACITY];
        let length = linux_uts_name(LINUX_UTS_DOMAIN, &mut name);
        let mut file = [0_u8; LINUX_UTS_NAME_CAPACITY + 1];
        file[..length].copy_from_slice(&name[..length]);
        file[length] = b'\n';
        let file = &file[..=length];
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        if start >= file.len() || count == 0 {
            return 0;
        }
        let end = start
            .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
            .min(file.len());
        return if copy_to_linux_user(address, &file[start..end]) {
            (end - start) as u64
        } else {
            LINUX_EFAULT
        };
    }
    // A /proc/sys value the domain wrote reads back as what it wrote (a
    // number, or ping_group_range's pair).
    if linux_proc_sysctl_index(state)
        .and_then(linux_proc_sysctl_override)
        .is_some()
    {
        let Some((file, used)) = linux_proc_sysctl_text(state) else {
            return LINUX_EIO;
        };
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        if start >= used || count == 0 {
            return 0;
        }
        let end = start
            .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
            .min(used);
        return if copy_to_linux_user(address, &file[start..end]) {
            (end - start) as u64
        } else {
            LINUX_EFAULT
        };
    }
    if state & !3 == LINUX_FILE_PROC_CPUINFO {
        return linux_proc_cpuinfo_read(address, count, offset);
    }
    if matches!(
        state & !3,
        LINUX_FILE_PROC_MOUNTS | LINUX_FILE_PROC_MOUNTINFO
    ) {
        let Some(file) = linux_proc_mount_table(state & !3 == LINUX_FILE_PROC_MOUNTINFO) else {
            return LINUX_EIO;
        };
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        if start >= file.len() || count == 0 {
            return 0;
        }
        let end = start
            .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
            .min(file.len());
        return if copy_to_linux_user(address, &file[start..end]) {
            (end - start) as u64
        } else {
            LINUX_EFAULT
        };
    }
    if linux_proc_sysvipc_file(state) {
        return linux_proc_sysvipc_read(state, address, count, offset);
    }
    if linux_proc_keys_file(state) {
        return linux_proc_keys_read(state, address, count, offset);
    }
    if state & !3 == LINUX_FILE_PROC_SWAPS {
        return linux_proc_swaps_read(address, count, offset);
    }
    if state & !3 == LINUX_FILE_PROC_TASK_STAT {
        return linux_proc_task_stat_read(descriptor, address, count, offset);
    }
    if state & !3 == LINUX_FILE_PROC_STAT {
        return linux_proc_stat_read(address, count, offset);
    }
    if state & !3 == LINUX_FILE_PROC_FDINFO {
        let Some(target) = linux_proc_fdinfo_descriptor_target(descriptor) else {
            return LINUX_EBADF;
        };
        // An inotify descriptor lists its watches, one line each, with the
        // mask and flags they were added with (inotify12).
        if let Some((domain, instance)) = linux_inotify_key(target) {
            let mut file = [0_u8; 1024];
            let prefix = b"pos:\t0\nflags:\t02000000\nmnt_id:\t1\nino:\t1\n";
            file[..prefix.len()].copy_from_slice(prefix);
            let mut used = prefix.len();
            crate::linux_inotify::watches(domain, instance, |wd, mask| {
                let mut line = [0_u8; 96];
                let mut length = 0;
                let written = append_linux_bytes(&mut line, &mut length, b"inotify wd:")
                    && append_linux_hex(&mut line, &mut length, wd as u32 as u64)
                    && append_linux_bytes(&mut line, &mut length, b" ino:1 sdev:0 mask:")
                    && append_linux_hex(&mut line, &mut length, u64::from(mask))
                    && append_linux_bytes(&mut line, &mut length, b" ignored_mask:0\n");
                if written && used + length <= file.len() {
                    file[used..used + length].copy_from_slice(&line[..length]);
                    used += length;
                }
            });
            let Ok(start) = usize::try_from(offset) else {
                return 0;
            };
            if start >= used || count == 0 {
                return 0;
            }
            let end = start
                .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
                .min(used);
            return if copy_to_linux_user(address, &file[start..end]) {
                (end - start) as u64
            } else {
                LINUX_EFAULT
            };
        }
        if let Some(file) = linux_fanotify_fdinfo(target) {
            let Ok(start) = usize::try_from(offset) else {
                return 0;
            };
            if start >= file.len() || count == 0 {
                return 0;
            }
            let end = start
                .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
                .min(file.len());
            return if copy_to_linux_user(address, &file[start..end]) {
                (end - start) as u64
            } else {
                LINUX_EFAULT
            };
        }
        if !linux_pidfd_descriptor(target) {
            let Some((file, used)) = linux_generic_fdinfo(target) else {
                return LINUX_ENOENT;
            };
            let Ok(start) = usize::try_from(offset) else {
                return 0;
            };
            if start >= used || count == 0 {
                return 0;
            }
            let end = start
                .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
                .min(used);
            return if copy_to_linux_user(address, &file[start..end]) {
                (end - start) as u64
            } else {
                LINUX_EFAULT
            };
        }
        let Some(pid) = linux_pidfd_process(target) else {
            return LINUX_ENOENT;
        };
        let mut file = [0_u8; 96];
        let prefix = b"pos:\t0\nflags:\t02000002\nmnt_id:\t1\nino:\t46\nPid:\t";
        file[..prefix.len()].copy_from_slice(prefix);
        let mut used = prefix.len();
        used += write_linux_decimal(u64::from(pid), &mut file[used..]);
        let namespace_prefix = b"\nNSpid:\t";
        file[used..used + namespace_prefix.len()].copy_from_slice(namespace_prefix);
        used += namespace_prefix.len();
        used += write_linux_decimal(u64::from(pid), &mut file[used..]);
        file[used] = b'\n';
        used += 1;
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        if start >= used || count == 0 {
            return 0;
        }
        let end = start
            .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
            .min(used);
        return if copy_to_linux_user(address, &file[start..end]) {
            (end - start) as u64
        } else {
            LINUX_EFAULT
        };
    }
    if state & !3 == LINUX_FILE_PROC_DYNAMIC_MEM {
        let Some(pid) = linux_proc_dynamic_descriptor_pid(descriptor) else {
            return LINUX_EBADF;
        };
        return linux_proc_mem_transfer(pid, address, count, offset, false);
    }
    // /proc/PID/pagemap: an entry of eight bytes for each virtual page,
    // made for the range read: bit 63 when the page is present (another
    // process's pages read as absent), the frame number withheld (0), as
    // Linux withholds it without CAP_SYS_ADMIN.
    if state & !3 == LINUX_FILE_PROC_DYNAMIC_PAGEMAP {
        let Some(pid) = linux_proc_dynamic_descriptor_pid(descriptor) else {
            return LINUX_EBADF;
        };
        let own = pid == current_linux_process_pid();
        let count = usize::try_from(count).unwrap_or(usize::MAX).min(PAGE_SIZE);
        let first = offset / 8;
        let skip = (offset % 8) as usize;
        let mut entries = [0_u8; PAGE_SIZE + 8];
        let mut used = 0;
        let mut page = first;
        while used < skip + count && used + 8 <= entries.len() {
            let address = page.saturating_mul(PAGE_SIZE as u64);
            if address >= 1 << 47 {
                break;
            }
            let present = own
                && address_space::current_linux_runtime_page(address)
                    .frame
                    .is_some();
            let entry: u64 = if present { 1 << 63 | 1 << 56 } else { 0 };
            entries[used..used + 8].copy_from_slice(&entry.to_ne_bytes());
            used += 8;
            page += 1;
        }
        let end = used.min(skip + count);
        if skip >= end {
            return 0;
        }
        return if copy_to_linux_user(address, &entries[skip..end]) {
            (end - skip) as u64
        } else {
            LINUX_EFAULT
        };
    }
    if matches!(
        state & !3,
        LINUX_FILE_PROC_DYNAMIC_MAPS | LINUX_FILE_PROC_DYNAMIC_SMAPS
    ) {
        let Some(pid) = linux_proc_dynamic_descriptor_pid(descriptor) else {
            return LINUX_EBADF;
        };
        let Some(maps) = linux_proc_maps(pid, state & !3 == LINUX_FILE_PROC_DYNAMIC_SMAPS) else {
            return LINUX_ENOENT;
        };
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(maps.len());
        let end = start
            .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
            .min(maps.len());
        return if start == end || copy_to_linux_user(address, &maps[start..end]) {
            (end - start) as u64
        } else {
            LINUX_EFAULT
        };
    }
    if matches!(
        state & !3,
        LINUX_FILE_PROC_DYNAMIC_STAT
            | LINUX_FILE_PROC_DYNAMIC_STATUS
            | LINUX_FILE_PROC_DYNAMIC_STATM
            | LINUX_FILE_PROC_DYNAMIC_IO
            | LINUX_FILE_PROC_OOM_SCORE_ADJ
            | LINUX_FILE_PROC_TIMENS_OFFSETS
            | LINUX_FILE_PROC_TASK_COMM
    ) {
        let Some(pid) = linux_proc_dynamic_descriptor_pid(descriptor) else {
            return LINUX_EBADF;
        };
        let Some(status) = linux_process::live_process_status(pid) else {
            return LINUX_ENOENT;
        };
        let state_letter = match status.state {
            linux_process::LiveProcessState::Running if linux_leader_thread_blocked(pid) => b'S',
            linux_process::LiveProcessState::Running => b'R',
            linux_process::LiveProcessState::Sleeping => b'S',
            linux_process::LiveProcessState::Stopped => b'T',
            linux_process::LiveProcessState::Zombie => b'Z',
        };
        let mut file = [0_u8; 768];
        let mut used = 0_usize;
        let mut name = [0_u8; 16];
        let generated = match state & !3 {
            LINUX_FILE_PROC_DYNAMIC_STATUS => {
                append_linux_bytes(&mut file, &mut used, b"Name:\t")
                    && append_linux_bytes(&mut file, &mut used, linux_process_name(pid, &mut name))
                    && append_linux_bytes(&mut file, &mut used, b"\nState:\t")
                    && append_linux_bytes(&mut file, &mut used, &[state_letter])
                    && append_linux_bytes(
                        &mut file,
                        &mut used,
                        match status.state {
                            linux_process::LiveProcessState::Running => b" (running)\n",
                            linux_process::LiveProcessState::Sleeping => b" (sleeping)\n",
                            linux_process::LiveProcessState::Stopped => b" (stopped)\n",
                            linux_process::LiveProcessState::Zombie => b" (zombie)\n",
                        },
                    )
                    && append_linux_bytes(&mut file, &mut used, b"Tgid:\t")
                    && append_linux_decimal(&mut file, &mut used, u64::from(status.pid))
                    && append_linux_bytes(&mut file, &mut used, b"\nPid:\t")
                    && append_linux_decimal(&mut file, &mut used, u64::from(status.pid))
                    && append_linux_bytes(&mut file, &mut used, b"\nPPid:\t")
                    && append_linux_decimal(&mut file, &mut used, u64::from(status.parent_pid))
                    && append_linux_bytes(&mut file, &mut used, b"\n")
                    && append_linux_credentials_status(&mut file, &mut used)
                    && append_linux_bytes(&mut file, &mut used, b"VmLck:\t")
                    && append_linux_decimal(
                        &mut file,
                        &mut used,
                        crate::linux_areas::locked_bytes(linux_execution_instance(), status.pid)
                            / 1024,
                    )
                    && append_linux_bytes(&mut file, &mut used, b" kB\nVmSwap:\t")
                    && append_linux_decimal(
                        &mut file,
                        &mut used,
                        linux_process_swap_pages(status.pid) * (PAGE_SIZE as u64 / 1024),
                    )
                    && append_linux_bytes(&mut file, &mut used, b" kB\n")
                    && append_linux_bytes(&mut file, &mut used, &linux_capability_status(pid))
                    && append_linux_bytes(
                        &mut file,
                        &mut used,
                        &linux_allowed_status(
                            linux_process::live_process_cpu_affinity(pid)
                                .map_or(0, |mask| mask & linux_available_cpu_mask()),
                        ),
                    )
            }
            LINUX_FILE_PROC_DYNAMIC_STAT => {
                append_linux_decimal(&mut file, &mut used, u64::from(status.pid))
                    && append_linux_bytes(&mut file, &mut used, b" (")
                    && append_linux_bytes(&mut file, &mut used, linux_process_name(pid, &mut name))
                    && append_linux_bytes(&mut file, &mut used, b") ")
                    && append_linux_bytes(&mut file, &mut used, &[state_letter])
                    && append_linux_bytes(&mut file, &mut used, b" ")
                    && append_linux_decimal(&mut file, &mut used, u64::from(status.parent_pid))
                    && append_linux_bytes(&mut file, &mut used, b" 1 1 0 -1 4194560 0 0 0 0 ")
                    && append_linux_decimal(&mut file, &mut used, linux_process_cpu_ticks(pid))
                    && append_linux_bytes(&mut file, &mut used, b" 0 0 0 20 0 1 0 1 1048576 256 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
            }
            LINUX_FILE_PROC_DYNAMIC_STATM => {
                append_linux_bytes(&mut file, &mut used, b"256 64 32 16 0 32 0\n")
            }
            LINUX_FILE_PROC_DYNAMIC_IO => linux_process::live_process_io(pid).is_some_and(|io| {
                [
                    (&b"rchar: "[..], io.rchar),
                    (b"wchar: ", io.wchar),
                    (b"syscr: ", io.syscr),
                    (b"syscw: ", io.syscw),
                    (b"read_bytes: ", io.read_bytes),
                    (b"write_bytes: ", io.write_bytes),
                    (b"cancelled_write_bytes: ", io.cancelled_write_bytes),
                ]
                .into_iter()
                .all(|(name, value)| {
                    append_linux_bytes(&mut file, &mut used, name)
                        && append_linux_decimal(&mut file, &mut used, value)
                        && append_linux_bytes(&mut file, &mut used, b"\n")
                })
            }),
            // A thread's name is its process's (prctl PR_SET_NAME names the
            // process here).
            LINUX_FILE_PROC_TASK_COMM => {
                append_linux_bytes(&mut file, &mut used, linux_process_name(pid, &mut name))
                    && append_linux_bytes(&mut file, &mut used, b"\n")
            }
            LINUX_FILE_PROC_TIMENS_OFFSETS => {
                linux_proc_timens_offsets(pid, &mut file, &mut used)
            }
            LINUX_FILE_PROC_OOM_SCORE_ADJ => {
                linux_process::live_process_oom_score_adj(pid).is_some_and(|value| {
                    (value >= 0 || append_linux_bytes(&mut file, &mut used, b"-"))
                        && append_linux_decimal(
                            &mut file,
                            &mut used,
                            u64::from(value.unsigned_abs()),
                        )
                        && append_linux_bytes(&mut file, &mut used, b"\n")
                })
            }
            _ => false,
        };
        if !generated {
            return LINUX_EIO;
        }
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        if start >= used || count == 0 {
            return 0;
        }
        let end = start
            .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
            .min(used);
        return if copy_to_linux_user(address, &file[start..end]) {
            (end - start) as u64
        } else {
            LINUX_EFAULT
        };
    }
    if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
        if !matches!(state & 3, LINUX_DESCRIPTOR_INPUT | 3) {
            return LINUX_EBADF;
        }
        let Ok(start) = usize::try_from(offset) else {
            return LINUX_EINVAL;
        };
        let result = linux_overlay_copy_to_user(handle, start, address, count);
        if result < LINUX_RETURN_TO_KERNEL {
            linux_note_read(descriptor, handle);
        }
        return result;
    }
    if let Some(entry) = linux_rootfs_entry(descriptor) {
        if !matches!(state & 3, LINUX_DESCRIPTOR_INPUT | 3) {
            return LINUX_EBADF;
        }
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        if start >= entry.data.len() || count == 0 {
            return 0;
        }
        let end = start
            .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
            .min(entry.data.len());
        if !copy_to_linux_user(address, &entry.data[start..end]) {
            return LINUX_EFAULT;
        }
        return (end - start) as u64;
    }
    let Some(file) = linux_regular_file(state) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_ESPIPE
        } else {
            LINUX_EBADF
        };
    };
    if !matches!(state & 3, LINUX_DESCRIPTOR_INPUT | 3) {
        return LINUX_EBADF;
    }
    if (offset as i64) < 0 {
        return LINUX_EINVAL;
    }
    let Ok(start) = usize::try_from(offset) else {
        return 0;
    };
    if start >= file.len() || count == 0 {
        return 0;
    }
    let requested = usize::try_from(count).unwrap_or(usize::MAX);
    let end = start.saturating_add(requested).min(file.len());
    if !copy_to_linux_user(address, &file[start..end]) {
        return LINUX_EFAULT;
    }
    (end - start) as u64
}

/// The offset pwrite to `descriptor` writes at: the end of the file for
/// one opened with O_APPEND, as Linux's pwrite does (pwrite04), else
/// `offset`.
pub(super) fn linux_pwrite_offset(descriptor: u64, offset: u64) -> u64 {
    if !linux_socket_flags(descriptor).is_some_and(|flags| flags & LINUX_O_APPEND as u32 != 0) {
        return offset;
    }
    linux_descriptor_stat(descriptor).map_or(offset, |stat| {
        u64::from_ne_bytes(stat[48..56].try_into().unwrap())
    })
}

pub(super) fn linux_regular_file_write_at(
    descriptor: u64,
    address: u64,
    count: u64,
    offset: u64,
) -> u64 {
    let state = linux_device_descriptor(descriptor);
    if linux_path_descriptor(descriptor) {
        return LINUX_EBADF;
    }
    if (offset as i64) < 0 {
        return LINUX_EINVAL;
    }
    if linux_pipe_descriptor(descriptor) || linux_socket_slot(descriptor).is_some() {
        // No position to write at (pwrite02, pwritev02, pwritev202).
        return LINUX_ESPIPE;
    }
    if linux_secret_descriptor(descriptor) {
        return LINUX_EINVAL;
    }
    if !matches!(state & 3, LINUX_DESCRIPTOR_OUTPUT | 3) {
        return LINUX_EBADF;
    }
    if state & !3 == LINUX_FILE_PROC_DYNAMIC_MEM {
        let Some(pid) = linux_proc_dynamic_descriptor_pid(descriptor) else {
            return LINUX_EBADF;
        };
        return linux_proc_mem_transfer(pid, address, count, offset, true);
    }
    let Some(handle) = linux_overlay_descriptor_handle(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    };
    let Ok(start) = usize::try_from(offset) else {
        return LINUX_EINVAL;
    };
    linux_overlay_copy_from_user(handle, start, address, count)
}

pub(super) fn linux_regular_file_read_kernel(
    descriptor: u64,
    offset: usize,
    output: &mut [u8],
) -> Result<usize, u64> {
    let state = linux_device_descriptor(descriptor);
    if linux_path_descriptor(descriptor) {
        return Err(LINUX_EBADF);
    }
    if linux_secret_descriptor(descriptor) {
        return Err(LINUX_EINVAL);
    }
    if !matches!(state & 3, LINUX_DESCRIPTOR_INPUT | 3) {
        return Err(LINUX_EBADF);
    }
    // A /proc/sys value spliced into a pipe (splice06).
    if let Some((text, length)) = linux_proc_sysctl_text(state) {
        let text = text.get(offset..length).unwrap_or_default();
        let copied = text.len().min(output.len());
        output[..copied].copy_from_slice(&text[..copied]);
        return Ok(copied);
    }
    if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
        let metadata = crate::linux_overlay::metadata(handle).ok_or(LINUX_EBADF)?;
        if metadata.kind != crate::linux_overlay::NodeKind::File {
            return Err(LINUX_EISDIR);
        }
        let read = crate::linux_overlay::read(handle, offset, output).ok_or(LINUX_EIO)?;
        linux_note_read(descriptor, handle);
        return Ok(read);
    }
    if let Some(entry) = linux_rootfs_entry(descriptor) {
        if entry.kind == crate::published_rootfs::EntryKind::Directory {
            return Err(LINUX_EISDIR);
        }
        if offset >= entry.data.len() {
            return Ok(0);
        }
        let length = output.len().min(entry.data.len() - offset);
        output[..length].copy_from_slice(&entry.data[offset..offset + length]);
        return Ok(length);
    }
    if linux_tmp_file(state) {
        let handle = linux_tmp_descriptor_handle(descriptor, state).ok_or(LINUX_EBADF)?;
        return linux_tmpfs::read(handle, offset, output).ok_or(LINUX_EBADF);
    }
    // /dev/zero and /dev/full read as zeros and /dev/urandom as random
    // bytes from the kernel's side too, so they can be spliced into a pipe
    // (splice08).
    if state & LINUX_DEVICE_ZERO != 0 && state & LINUX_DEVICE_DIRECTORY == 0 {
        if state & !3 == LINUX_DEVICE_RANDOM {
            for chunk in output.chunks_mut(16) {
                let random = linux_startup_random().ok_or(LINUX_EIO)?;
                chunk.copy_from_slice(&random[..chunk.len()]);
            }
        } else {
            output.fill(0);
        }
        return Ok(output.len());
    }
    Err(if linux_descriptor_open(descriptor) {
        LINUX_ESPIPE
    } else {
        LINUX_EBADF
    })
}

pub(super) fn linux_regular_file_write_kernel(
    descriptor: u64,
    offset: usize,
    input: &[u8],
) -> Result<usize, u64> {
    let state = linux_device_descriptor(descriptor);
    if linux_path_descriptor(descriptor) {
        return Err(LINUX_EBADF);
    }
    if linux_secret_descriptor(descriptor) {
        return Err(LINUX_EINVAL);
    }
    if !matches!(state & 3, LINUX_DESCRIPTOR_OUTPUT | 3) {
        return Err(LINUX_EBADF);
    }
    // A /proc/sys value written from a pipe (splice06).
    if let Some(index) = linux_proc_sysctl_index(state) {
        return if LINUX_PROC_SYSCTLS[index].1 == b"sys/kernel/domainname" {
            linux_proc_domainname_write_bytes(state, input)
        } else {
            linux_proc_sysctl_write_bytes(state, index, input)
        };
    }
    let length = linux_file_write_limit(offset, input.len())?;
    let input = &input[..length];
    if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
        let metadata = crate::linux_overlay::metadata(handle).ok_or(LINUX_EBADF)?;
        if metadata.kind != crate::linux_overlay::NodeKind::File {
            return Err(LINUX_EISDIR);
        }
        if linux_overlay_huge(handle) {
            return Err(LINUX_EINVAL);
        }
        return crate::linux_overlay::write(handle, offset, input).ok_or(LINUX_ENOSPC);
    }
    if linux_tmp_file(state) {
        let handle = linux_tmp_descriptor_handle(descriptor, state).ok_or(LINUX_EBADF)?;
        return linux_tmpfs::write(handle, offset, input).ok_or(LINUX_ENOSPC);
    }
    let handle = linux_copy_up_descriptor(descriptor)?;
    let metadata = crate::linux_overlay::metadata(handle).ok_or(LINUX_EBADF)?;
    if metadata.kind != crate::linux_overlay::NodeKind::File {
        return Err(LINUX_EISDIR);
    }
    crate::linux_overlay::write(handle, offset, input).ok_or(LINUX_ENOSPC)
}

pub(super) fn linux_file_range_offset(pointer: u64, descriptor: u64) -> Result<(usize, bool), u64> {
    let offset = if pointer == 0 {
        linux_descriptor_offset(descriptor).load(Ordering::SeqCst)
    } else {
        if !linux_writable_user_range_contains(pointer, core::mem::size_of::<i64>()) {
            return Err(LINUX_EFAULT);
        }
        let mut bytes = [0_u8; 8];
        if !copy_from_linux_user(pointer, &mut bytes) {
            return Err(LINUX_EFAULT);
        }
        let value = i64::from_ne_bytes(bytes);
        if value < 0 {
            return Err(LINUX_EINVAL);
        }
        value as u64
    };
    usize::try_from(offset)
        .map(|offset| (offset, pointer != 0))
        .map_err(|_| LINUX_EFBIG)
}

pub(super) fn linux_commit_file_range_offset(
    pointer: u64,
    descriptor: u64,
    explicit: bool,
    offset: usize,
) -> Result<(), u64> {
    if explicit {
        copy_to_linux_user(pointer, &(offset as i64).to_ne_bytes())
            .then_some(())
            .ok_or(LINUX_EFAULT)
    } else {
        linux_descriptor_offset(descriptor).store(offset as u64, Ordering::SeqCst);
        Ok(())
    }
}

fn linux_descriptors_same_file(
    first: u64,
    second: u64,
    first_state: u16,
    second_state: u16,
) -> bool {
    first == second
        || linux_overlay_descriptor_handle(first)
            .zip(linux_overlay_descriptor_handle(second))
            .is_some_and(|(first, second)| first == second)
        || (linux_rootfs_descriptor(first) != 0
            && linux_rootfs_descriptor(first) == linux_rootfs_descriptor(second))
        || linux_tmp_descriptor_handle(first, first_state)
            .zip(linux_tmp_descriptor_handle(second, second_state))
            .is_some_and(|(first, second)| first == second)
}

/// One end of a copy_file_range(2): its overlay handle, whether it is a
/// directory, whether a regular file, and its size.
struct LinuxCopyEnd {
    handle: Option<crate::linux_overlay::Handle>,
    directory: bool,
    regular: bool,
    size: u64,
}

fn linux_copy_end(descriptor: u64, state: u16) -> LinuxCopyEnd {
    let handle = linux_overlay_descriptor_handle(descriptor);
    if let Some(metadata) = handle.and_then(crate::linux_overlay::metadata) {
        return LinuxCopyEnd {
            handle,
            directory: metadata.kind == crate::linux_overlay::NodeKind::Directory,
            regular: metadata.kind == crate::linux_overlay::NodeKind::File,
            size: metadata.size as u64,
        };
    }
    if let Some(file) = linux_tmp_descriptor_handle(descriptor, state) {
        return LinuxCopyEnd {
            handle: None,
            directory: false,
            regular: true,
            size: linux_tmpfs::size(file).unwrap_or(0) as u64,
        };
    }
    let entry = linux_rootfs_entry(descriptor);
    let directory =
        entry.is_some_and(|entry| entry.kind == crate::published_rootfs::EntryKind::Directory);
    LinuxCopyEnd {
        handle: None,
        directory,
        regular: entry.is_some() && !directory,
        size: entry.map_or(0, |entry| entry.data.len() as u64),
    }
}

pub(super) fn linux_copy_file_range(
    input: u64,
    input_offset_pointer: u64,
    output: u64,
    output_offset_pointer: u64,
    length: u64,
    flags: u64,
) -> u64 {
    let input = u64::from(input as u32);
    let output = u64::from(output as u32);
    let flags = u64::from(flags as u32);
    if flags != 0 {
        return LINUX_EINVAL;
    }
    if !linux_descriptor_open(input) || !linux_descriptor_open(output) {
        return LINUX_EBADF;
    }
    let input_state = linux_device_descriptor(input);
    let output_state = linux_device_descriptor(output);
    // generic_file_rw_checks: directories, then whatever is no regular
    // file, then the open modes.
    let source = linux_copy_end(input, input_state);
    let target = linux_copy_end(output, output_state);
    if source.directory || target.directory {
        return LINUX_EISDIR;
    }
    if !source.regular || !target.regular {
        return LINUX_EINVAL;
    }
    if !matches!(input_state & 3, LINUX_DESCRIPTOR_INPUT | 3)
        || !matches!(output_state & 3, LINUX_DESCRIPTOR_OUTPUT | 3)
    {
        return LINUX_EBADF;
    }
    if linux_socket_flags(output).is_some_and(|flags| flags & LINUX_O_APPEND as u32 != 0) {
        return LINUX_EBADF;
    }
    if input_offset_pointer != 0 && input_offset_pointer == output_offset_pointer {
        return LINUX_EINVAL;
    }
    // generic_copy_file_checks: one filesystem (neither ext4 nor tmpfs
    // copies across superblocks), an output that may change, offsets
    // that do not wrap, the input's end and the output's size limits, and
    // no overlap within one file.
    let volume = |handle: Option<crate::linux_overlay::Handle>| {
        handle.and_then(crate::linux_blockfs::volume_of)
    };
    let (source_volume, target_volume) = (volume(source.handle), volume(target.handle));
    if source_volume.map(|(id, _)| id) != target_volume.map(|(id, _)| id) {
        return LINUX_EXDEV;
    }
    if target
        .handle
        .and_then(crate::linux_overlay::metadata)
        .is_some_and(|metadata| metadata.attributes & LINUX_FS_IMMUTABLE_FL != 0)
    {
        return LINUX_EPERM;
    }
    let (mut input_offset, explicit_input) =
        match linux_file_range_offset(input_offset_pointer, input) {
            Ok(offset) => offset,
            Err(error) => return error,
        };
    let (mut output_offset, explicit_output) =
        match linux_file_range_offset(output_offset_pointer, output) {
            Ok(offset) => offset,
            Err(error) => return error,
        };
    if (input_offset as u64).checked_add(length).is_none()
        || (output_offset as u64).checked_add(length).is_none()
    {
        return LINUX_EOVERFLOW;
    }
    let mut count = length.min(source.size.saturating_sub(input_offset as u64));
    count = match linux_file_write_limit(output_offset, count as usize) {
        Ok(allowed) => allowed as u64,
        Err(error) => return error,
    };
    let largest = target_volume.map_or(i64::MAX as u64, |(_, largest)| largest);
    if output_offset as u64 >= largest {
        return LINUX_EFBIG;
    }
    count = count.min(largest - output_offset as u64);
    if linux_descriptors_same_file(input, output, input_state, output_state)
        && (output_offset as u64) + count > input_offset as u64
        && (output_offset as u64) < input_offset as u64 + count
    {
        return LINUX_EINVAL;
    }
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EFBIG;
    };
    let mut buffer = [0_u8; PAGE_SIZE];
    let mut copied = 0_usize;
    let mut terminal_error = 0;
    while copied < requested {
        let chunk = (requested - copied).min(buffer.len());
        let read = match linux_regular_file_read_kernel(input, input_offset, &mut buffer[..chunk]) {
            Ok(read) => read,
            Err(error) => {
                terminal_error = error;
                break;
            }
        };
        if read == 0 {
            break;
        }
        let written = match linux_regular_file_write_kernel(output, output_offset, &buffer[..read])
        {
            Ok(written) => written,
            Err(error) => {
                terminal_error = error;
                break;
            }
        };
        input_offset = input_offset.saturating_add(written);
        output_offset = output_offset.saturating_add(written);
        copied += written;
        if written < read || output_offset as u64 >= linux_file_size_limit() {
            break;
        }
    }
    if linux_commit_file_range_offset(input_offset_pointer, input, explicit_input, input_offset)
        .is_err()
        || linux_commit_file_range_offset(
            output_offset_pointer,
            output,
            explicit_output,
            output_offset,
        )
        .is_err()
    {
        return if copied == 0 {
            LINUX_EFAULT
        } else {
            copied as u64
        };
    }
    if copied == 0 && terminal_error != 0 {
        terminal_error
    } else {
        copied as u64
    }
}

pub(super) fn linux_sendfile(output: u64, input: u64, offset_pointer: u64, count: u64) -> u64 {
    if !linux_descriptor_open(input) || !linux_descriptor_open(output) {
        return LINUX_EBADF;
    }
    let input_state = linux_device_descriptor(input);
    if !matches!(input_state & 3, LINUX_DESCRIPTOR_INPUT | 3) {
        return LINUX_EBADF;
    }
    let input_is_regular = linux_overlay_descriptor_handle(input).is_some()
        || linux_rootfs_descriptor(input) != 0
        || linux_tmp_descriptor_handle(input, input_state).is_some();
    if !input_is_regular {
        return LINUX_EINVAL;
    }
    let output_state = linux_device_descriptor(output);
    let output_socket = linux_socket_slot(output);
    let output_is_regular = linux_overlay_descriptor_handle(output).is_some()
        || linux_rootfs_descriptor(output) != 0
        || linux_tmp_descriptor_handle(output, output_state).is_some();
    if output_socket.is_none() && !output_is_regular {
        return LINUX_EINVAL;
    }
    // Linux checks that the output is open for writing before anything else
    // about it.
    if output_is_regular && !matches!(output_state & 3, LINUX_DESCRIPTOR_OUTPUT | 3) {
        return LINUX_EBADF;
    }
    if output_is_regular && linux_descriptors_same_file(input, output, input_state, output_state) {
        return LINUX_EINVAL;
    }
    if output_is_regular
        && linux_socket_flags(output).is_some_and(|flags| flags & LINUX_O_APPEND as u32 != 0)
    {
        return LINUX_EINVAL;
    }
    let (mut input_offset, explicit_offset) = match linux_file_range_offset(offset_pointer, input) {
        Ok(offset) => offset,
        Err(error) => return error,
    };
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if requested > isize::MAX as usize {
        return LINUX_EINVAL;
    }
    let mut output_offset = if output_is_regular {
        linux_descriptor_offset(output).load(Ordering::SeqCst) as usize
    } else {
        0
    };
    let mut buffer = [0_u8; PAGE_SIZE];
    let mut copied = 0_usize;
    let mut terminal_error = 0;
    while copied < requested {
        let chunk = (requested - copied).min(buffer.len());
        let read = match linux_regular_file_read_kernel(input, input_offset, &mut buffer[..chunk]) {
            Ok(read) => read,
            Err(error) => {
                terminal_error = error;
                break;
            }
        };
        if read == 0 {
            break;
        }
        let written = if let Some(slot) = output_socket {
            let result = if linux_socket_nonblocking(output) {
                crate::linux_socket::send(slot, &buffer[..read], None)
            } else {
                crate::linux_socket::send_blocking(slot, &buffer[..read], None)
            };
            match result {
                Ok(written) => written,
                Err(error) => {
                    terminal_error = linux_socket_error(error);
                    break;
                }
            }
        } else {
            match linux_regular_file_write_kernel(output, output_offset, &buffer[..read]) {
                Ok(written) => written,
                Err(error) => {
                    terminal_error = error;
                    break;
                }
            }
        };
        if written == 0 {
            break;
        }
        input_offset = input_offset.saturating_add(written);
        output_offset = output_offset.saturating_add(written);
        copied += written;
        if written < read || output_is_regular && output_offset as u64 >= linux_file_size_limit() {
            break;
        }
    }
    if linux_commit_file_range_offset(offset_pointer, input, explicit_offset, input_offset).is_err()
    {
        return if copied == 0 {
            LINUX_EFAULT
        } else {
            copied as u64
        };
    }
    if output_is_regular {
        linux_descriptor_offset(output).store(output_offset as u64, Ordering::SeqCst);
    }
    if copied == 0 && terminal_error != 0 {
        terminal_error
    } else {
        copied as u64
    }
}

fn linux_console_input_descriptor(descriptor: u64) -> bool {
    let device = linux_device_descriptor(descriptor);
    u16::from(linux_console_descriptor(descriptor)) & LINUX_DESCRIPTOR_INPUT != 0
        || device & LINUX_DEVICE_CONSOLE != 0 && matches!(device & 3, LINUX_DESCRIPTOR_INPUT | 3)
}

pub(super) fn linux_descriptor_read_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    descriptor: u64,
    address: u64,
    count: u64,
) -> u64 {
    // A read of nothing from a pipe or socket is done at once, as Linux's
    // pipe_read and sock_read_iter return 0 before looking for data
    // (splice08 reads 0 bytes from an empty pipe).
    if count == 0
        && (linux_socket_slot(descriptor).is_some()
            || linux_socket_pipe_descriptor(descriptor, LINUX_DESCRIPTOR_INPUT))
    {
        return 0;
    }
    if linux_blocking_socket_yields(descriptor) {
        // A thread of a process with another ready thread blocks on an
        // empty pipe until a writer fills it, as in Linux: retrying in a
        // loop, two such threads (git's reader and its sideband thread)
        // would hand the CPU to each other and starve the writer.
        if descriptor <= 0xff
            && linux_socket_pipe_descriptor(descriptor, LINUX_DESCRIPTOR_INPUT)
            && ready_linux_thread_handle().is_some()
        {
            X86_RUNTIME
                .LINUX_SOCKET_SINGLE_ATTEMPT
                .store(true, Ordering::SeqCst);
            let immediate = linux_descriptor_read(descriptor, address, count);
            X86_RUNTIME
                .LINUX_SOCKET_SINGLE_ATTEMPT
                .store(false, Ordering::SeqCst);
            if immediate != LINUX_EAGAIN || count == 0 {
                return immediate;
            }
            let wait_count = count.min(PAGE_SIZE as u64);
            if !linux_writable_user_range_contains(address, wait_count as usize) {
                return LINUX_EFAULT;
            }
            return linux_blocking_descriptor_io_live_return(
                output,
                caller,
                LINUX_READ_SYSCALL,
                LINUX_THREAD_WAIT_PIPE_READ,
                address,
                wait_count << 8 | descriptor,
                0,
                None,
            );
        }
        return linux_local_socket_io_live_return(
            output,
            caller,
            LINUX_READ_SYSCALL,
            descriptor,
            || linux_descriptor_read(descriptor, address, count),
        );
    }
    // A read of the attached console with nothing typed yet waits like any
    // other blocking read instead of spinning on the device, which would
    // stop the whole domain until someone types: a ready sibling thread runs
    // (brush reads input on its own thread, so its main thread must be able
    // to finish `exit`), or other processes do, and the read checks again.
    // While a `domain exec` command has the console, only it and what it
    // started read it; the rest of the domain waits for the console as a
    // background process group waits for its terminal, and a console the
    // command gave back on exiting is read (and the domain suspended) as
    // a detached one.
    let console_attached = || {
        active_container_slot().is_some_and(|slot| {
            X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire)
        })
    };
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire)
        && linux_console_input_descriptor(descriptor)
        && console_attached()
    {
        if crate::console_nonblocking()
            && (!crate::serial_input_ready() || linux_console_held_by_domain_exec())
        {
            return LINUX_EAGAIN;
        }
        while console_attached()
            && (!crate::serial_input_ready() || linux_console_held_by_domain_exec())
        {
            if ready_linux_thread_handle().is_some() || current_linux_runtime_cpu_index() != 0 {
                return linux_retry_later_live_return(
                    output,
                    caller,
                    LINUX_READ_SYSCALL,
                    WaitOn::ANYTHING,
                );
            }
            // The serial console is polled: every tick looks again.
            if let Some(LinuxBlockedWait::Return(result)) =
                run_other_linux_processes(output, caller, LINUX_READ_SYSCALL, WaitOn::ANYTHING)
            {
                return result;
            }
            core::hint::spin_loop();
        }
    }
    let immediate =
        if linux_socket_slot(descriptor).is_some() && !linux_socket_nonblocking(descriptor) {
            linux_socket_recvfrom(
                Some((output, caller, LINUX_READ_SYSCALL)),
                descriptor,
                address,
                count,
                0,
                0,
                0,
            )
        } else {
            linux_descriptor_read(descriptor, address, count)
        };
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire)
        && (u16::from(linux_console_descriptor(descriptor)) & LINUX_DESCRIPTOR_INPUT != 0
            || linux_device_descriptor(descriptor) & LINUX_DEVICE_CONSOLE != 0
                && matches!(
                    linux_device_descriptor(descriptor) & 3,
                    LINUX_DESCRIPTOR_INPUT | 3
                ))
        && X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_REQUESTED
            .swap(false, Ordering::AcqRel)
    {
        // The read is recorded with the suspension: a domain exec run while
        // the domain is suspended has it issued again.
        let suspended = LinuxUserContext {
            rax: LINUX_READ_SYSCALL,
            ..caller
        };
        if count == 0 || !save_suspended_linux_runtime(suspended, address, count, false) {
            return LINUX_EINVAL;
        }
        return LINUX_RETURN_TO_KERNEL;
    }
    // An inotify or fanotify descriptor opened without IN_NONBLOCK or
    // FAN_NONBLOCK waits for an event as other blocking reads wait: the
    // rest of the domain runs and the read starts again (inotify11).
    if immediate == LINUX_EAGAIN
        && (linux_inotify_descriptor(descriptor) || linux_fanotify_descriptor(descriptor))
        && !linux_socket_flags(descriptor).is_some_and(|flags| flags & LINUX_O_NONBLOCK as u32 != 0)
    {
        return linux_retry_later_live_return(output, caller, LINUX_READ_SYSCALL, WaitOn::ANYTHING);
    }
    if immediate != LINUX_ENOSYS
        || !linux_eventfd_descriptor(descriptor)
            && !linux_pipe_read_descriptor(descriptor)
            && !linux_timerfd_descriptor(descriptor)
    {
        return immediate;
    }
    let (kind, wait_count) = if linux_eventfd_descriptor(descriptor) {
        if count != 8 {
            return LINUX_EINVAL;
        }
        (LINUX_THREAD_WAIT_EVENTFD_READ, 8)
    } else if linux_timerfd_descriptor(descriptor) {
        if count != 8 {
            return LINUX_EINVAL;
        }
        (LINUX_THREAD_WAIT_TIMERFD_READ, 8)
    } else {
        (
            LINUX_THREAD_WAIT_PIPE_READ,
            count.min(LINUX_PIPE_CAPACITY as u64),
        )
    };
    if wait_count == 0 || !linux_writable_user_range_contains(address, wait_count as usize) {
        return LINUX_EFAULT;
    }
    let wait_output = if kind == LINUX_THREAD_WAIT_PIPE_READ {
        wait_count << 8 | descriptor
    } else {
        descriptor
    };
    linux_blocking_descriptor_io_live_return(
        output,
        caller,
        LINUX_READ_SYSCALL,
        kind,
        address,
        wait_output,
        if kind == LINUX_THREAD_WAIT_TIMERFD_READ {
            linux_timerfd_state(descriptor)
                .map(|state| state.deadline.load(Ordering::SeqCst))
                .unwrap_or(0)
        } else {
            0
        },
        None,
    )
}

pub(super) fn linux_descriptor_readv_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    descriptor: u64,
    vectors: u64,
    count: u64,
) -> u64 {
    if linux_blocking_socket_yields(descriptor) {
        return linux_local_socket_io_live_return(
            output,
            caller,
            LINUX_READV_SYSCALL,
            descriptor,
            || linux_descriptor_readv(descriptor, vectors, count),
        );
    }
    let immediate = linux_descriptor_readv(descriptor, vectors, count);
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire)
        && (u16::from(linux_console_descriptor(descriptor)) & LINUX_DESCRIPTOR_INPUT != 0
            || linux_device_descriptor(descriptor) & LINUX_DEVICE_CONSOLE != 0
                && matches!(
                    linux_device_descriptor(descriptor) & 3,
                    LINUX_DESCRIPTOR_INPUT | 3
                ))
        && X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_REQUESTED
            .swap(false, Ordering::AcqRel)
    {
        let (ranges, vector_count) = match linux_readv_ranges(vectors, count) {
            Ok(snapshot) => snapshot,
            Err(error) => return error,
        };
        let suspended = LinuxUserContext {
            rax: LINUX_READV_SYSCALL,
            ..caller
        };
        if vector_count == 0 || !save_suspended_linux_runtime(suspended, ranges[0].0, 1, false) {
            return LINUX_EINVAL;
        }
        return LINUX_RETURN_TO_KERNEL;
    }
    if immediate != LINUX_ENOSYS || !linux_pipe_read_descriptor(descriptor) {
        return immediate;
    }
    let (ranges, vector_count) = match linux_readv_ranges(vectors, count) {
        Ok(snapshot) => snapshot,
        Err(error) => return error,
    };
    linux_blocking_descriptor_io_live_return(
        output,
        caller,
        LINUX_READV_SYSCALL,
        LINUX_THREAD_WAIT_PIPE_READ,
        vectors,
        LINUX_PIPE_READV_WAIT_FLAG | (vector_count as u64) << 8 | descriptor,
        0,
        Some(&ranges[..vector_count]),
    )
}

pub(super) fn linux_descriptor_write_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    descriptor: u64,
    address: u64,
    count: u64,
) -> u64 {
    if linux_blocking_socket_yields(descriptor) {
        return linux_local_socket_io_live_return(
            output,
            caller,
            LINUX_WRITE_SYSCALL,
            descriptor,
            || linux_descriptor_write(descriptor, address, count),
        );
    }
    let immediate = linux_descriptor_write(descriptor, address, count);
    if immediate == LINUX_EPIPE && linux_pipe_write_descriptor(descriptor) {
        return linux_broken_pipe_live_return(output, caller);
    }
    if immediate != LINUX_ENOSYS
        || !linux_pipe_write_descriptor(descriptor) && !linux_eventfd_descriptor(descriptor)
    {
        return immediate;
    }
    if linux_eventfd_descriptor(descriptor) {
        if count != 8 {
            return LINUX_EINVAL;
        }
        let mut bytes = [0_u8; 8];
        if !copy_from_linux_user(address, &mut bytes) {
            return LINUX_EFAULT;
        }
        let increment = u64::from_ne_bytes(bytes);
        if increment == 0 || increment == u64::MAX {
            return LINUX_EINVAL;
        }
        return linux_blocking_descriptor_io_live_return(
            output,
            caller,
            LINUX_WRITE_SYSCALL,
            LINUX_THREAD_WAIT_EVENTFD_WRITE,
            increment,
            descriptor,
            0,
            None,
        );
    }
    let Ok(write_count) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if write_count == 0
        || write_count > LINUX_PIPE_CAPACITY
        || !linux_readable_user_range_contains(address, write_count)
    {
        return if write_count == 0 || write_count > LINUX_PIPE_CAPACITY {
            LINUX_EINVAL
        } else {
            LINUX_EFAULT
        };
    }
    linux_blocking_descriptor_io_live_return(
        output,
        caller,
        LINUX_WRITE_SYSCALL,
        LINUX_THREAD_WAIT_PIPE_WRITE,
        address,
        count << 8 | descriptor,
        0,
        None,
    )
}

pub(super) fn linux_descriptor_writev_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    descriptor: u64,
    vectors: u64,
    count: u64,
) -> u64 {
    if linux_blocking_socket_yields(descriptor) {
        return linux_local_socket_io_live_return(
            output,
            caller,
            LINUX_WRITEV_SYSCALL,
            descriptor,
            || linux_descriptor_writev(descriptor, vectors, count),
        );
    }
    let immediate = linux_descriptor_writev(descriptor, vectors, count);
    if immediate == LINUX_EPIPE && linux_pipe_write_descriptor(descriptor) {
        return linux_broken_pipe_live_return(output, caller);
    }
    if immediate != LINUX_ENOSYS || !linux_pipe_write_descriptor(descriptor) {
        return immediate;
    }
    let (ranges, vector_count) = match linux_writev_ranges(vectors, count) {
        Ok(snapshot) => snapshot,
        Err(error) => return error,
    };
    linux_blocking_descriptor_io_live_return(
        output,
        caller,
        LINUX_WRITEV_SYSCALL,
        LINUX_THREAD_WAIT_PIPE_WRITE,
        vectors,
        LINUX_PIPE_WRITEV_WAIT_FLAG | (vector_count as u64) << 8 | descriptor,
        0,
        Some(&ranges[..vector_count]),
    )
}

pub(super) fn linux_broken_pipe_live_return(
    output: *mut LinuxSyscallFrame,
    mut interrupted: LinuxUserContext,
) -> u64 {
    interrupted.rax = LINUX_EPIPE;
    let result = linux_kill(
        u64::from(current_linux_process_pid()),
        (LINUX_SIGPIPE, LINUX_SI_KERNEL, None),
        output,
        interrupted,
        (interrupted.rip, interrupted.rflags),
    );
    if result == LINUX_RETURN_TO_KERNEL || result != 0 {
        result
    } else if X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        0
    } else {
        LINUX_EPIPE
    }
}

pub(super) fn linux_file_size_limit_signal(
    output: *mut LinuxSyscallFrame,
    mut interrupted: LinuxUserContext,
    return_registers: (u64, u64),
    result: u64,
) -> u64 {
    debug_assert_eq!(result, LINUX_EFBIG);
    interrupted.rax = result;
    let delivered = linux_kill(
        u64::from(current_linux_process_pid()),
        (LINUX_SIGXFSZ, LINUX_SI_KERNEL, None),
        output,
        interrupted,
        return_registers,
    );
    if delivered == LINUX_RETURN_TO_KERNEL || delivered != 0 {
        delivered
    } else if X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        0
    } else {
        result
    }
}

pub(super) fn linux_real_timer_signal(
    output: *mut LinuxSyscallFrame,
    mut interrupted: LinuxUserContext,
    return_registers: (u64, u64),
    result: u64,
) -> u64 {
    interrupted.rax = result;
    let delivered = linux_deliver_pending_signal(output, interrupted, return_registers);
    if delivered == LINUX_RETURN_TO_KERNEL || delivered != 0 {
        delivered
    } else if X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        0
    } else {
        result
    }
}

/// Blocks the calling thread on a descriptor and runs a ready sibling. With
/// none, other processes run instead, such as the other end of a pipe, and
/// the call (system call `number`) starts again.
#[allow(clippy::too_many_arguments)]
fn linux_blocking_descriptor_io_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    kind: u8,
    wait_key: u64,
    wait_output: u64,
    deadline: u64,
    iov_snapshot: Option<&[(u64, usize)]>,
) -> u64 {
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let Some(target) = ready_linux_thread_handle() else {
        let wait = WaitOn::ANYTHING.until(deadline);
        return match run_other_linux_processes(output, caller, number, wait) {
            Some(LinuxBlockedWait::Return(result)) => result,
            _ => linux_restart_syscall_live_return(output, caller, number),
        };
    };
    let Some(tls) = linux_thread_context(current) else {
        return LINUX_ESRCH;
    };
    let slot = usize::from(current.slot);
    if let Some(ranges) = iov_snapshot {
        for (index, (address, length)) in ranges.iter().copied().enumerate() {
            X86_RUNTIME.LINUX_THREAD_IOV_ADDRESSES[slot][index].store(address, Ordering::SeqCst);
            X86_RUNTIME.LINUX_THREAD_IOV_LENGTHS[slot][index]
                .store(length as u64, Ordering::SeqCst);
        }
    }
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(kind, wait_key, wait_output, deadline)
    {
        clear_linux_iov_snapshot(slot);
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
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
        clear_linux_iov_snapshot(slot);
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
    if kind == LINUX_THREAD_WAIT_PIPE_READ {
        X86_RUNTIME
            .LINUX_PIPE_READ_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if kind == LINUX_THREAD_WAIT_PIPE_WRITE {
        X86_RUNTIME
            .LINUX_PIPE_WRITE_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if kind == LINUX_THREAD_WAIT_EVENTFD_WRITE {
        X86_RUNTIME
            .LINUX_EVENTFD_WRITE_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if kind == LINUX_THREAD_WAIT_TIMERFD_READ {
        X86_RUNTIME
            .LINUX_TIMERFD_READ_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else {
        X86_RUNTIME
            .LINUX_EVENTFD_READ_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
    }
    LINUX_RETURN_FROM_IRET
}

/// Whether a blocking call on the socket `descriptor` waits by yielding: a
/// socket in blocking mode, such as a pipe between processes or a TCP
/// connection. Its peer may be another process, which cannot run while the
/// call spins in the kernel, and a spin bounded only by an iteration count
/// gave up on slow servers with EAGAIN, which Linux never returns from a
/// blocking call. A socket with a timeout (SO_RCVTIMEO, SO_SNDTIMEO) yields
/// too: spinning out its timeout held the domain's only CPU from the peer
/// (cadrs's geometry kernel could not send the hello its app waited 10 s
/// for). Threads on application processors keep the in-kernel waits.
/// Whether a blocking call on socket `descriptor` lets the rest of the
/// domain run instead of polling inside the kernel: on every CPU. A thread
/// on the light path goes to the owner for it, and a process an
/// application processor owns starts the call again; the bounded poll with
/// the entry lock held kept the writer, on another CPU, out of the kernel
/// until the poll gave up (bind04's peer thread read EAGAIN).
pub(super) fn linux_blocking_socket_yields(descriptor: u64) -> bool {
    X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire)
        && linux_socket_slot(descriptor).is_some()
        && !linux_socket_nonblocking(descriptor)
}

/// When a blocking call on the socket `descriptor`, at user address `rip`,
/// gives up: the deadline an earlier attempt of the same call left, or its
/// timeout for this direction (`write`) from now; None without a timeout.
fn linux_socket_wait_deadline(descriptor: u64, write: bool, rip: u64) -> Option<u64> {
    let option = if write {
        crate::linux_socket::TimeoutOption::Send
    } else {
        crate::linux_socket::TimeoutOption::Receive
    };
    let saved = take_linux_restart_deadline(rip);
    let microseconds = linux_socket_slot(descriptor)
        .and_then(|slot| crate::linux_socket::timeout_option(slot, option).ok())
        .filter(|microseconds| *microseconds != 0)?;
    saved.or_else(|| linux_elapsed_nanoseconds()?.checked_add(microseconds.saturating_mul(1_000)))
}

/// Runs `operation`, system call `number` on the blocking socket
/// `descriptor`, once without waiting. If it would block, the rest of the
/// domain runs and the call starts again, until the socket's timeout passes
/// (EAGAIN, as Linux). A write to a pipe whose reader is gone raises SIGPIPE.
pub(super) fn linux_local_socket_io_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    descriptor: u64,
    operation: impl FnOnce() -> u64,
) -> u64 {
    let write = matches!(number, LINUX_WRITE_SYSCALL | LINUX_WRITEV_SYSCALL);
    let deadline = linux_socket_wait_deadline(descriptor, write, caller.rip);
    X86_RUNTIME
        .LINUX_SOCKET_SINGLE_ATTEMPT
        .store(true, Ordering::SeqCst);
    let result = operation();
    X86_RUNTIME
        .LINUX_SOCKET_SINGLE_ATTEMPT
        .store(false, Ordering::SeqCst);
    match result {
        LINUX_EAGAIN => {
            let wait = linux_descriptor_wait(descriptor);
            let Some(deadline) = deadline else {
                return linux_retry_later_live_return(output, caller, number, wait);
            };
            if linux_elapsed_nanoseconds().is_none_or(|now| now >= deadline) {
                return LINUX_EAGAIN;
            }
            // The restarted call takes the deadline back; a call that ends
            // here instead (a signal) drops it.
            save_linux_restart_deadline(caller.rip, deadline);
            let result =
                linux_retry_later_live_return(output, caller, number, wait.until(deadline));
            if !matches!(result, LINUX_RETURN_FROM_IRET | LINUX_RETURN_TO_KERNEL)
                && result != number
            {
                let _ = take_linux_restart_deadline(caller.rip);
            }
            result
        }
        LINUX_EPIPE | LINUX_ENOTCONN
            if write && linux_device_descriptor(descriptor) & LINUX_DEVICE_PIPE != 0 =>
        {
            linux_broken_pipe_live_return(output, caller)
        }
        result => result,
    }
}

/// Lets the rest of the domain run before system call `number` starts again:
/// a ready sibling thread first, and otherwise other processes.
/// Consecutive times a waiting thread handed the CPU to a ready sibling
/// thread instead of letting other processes run.
static LINUX_RETRY_SIBLING_HANDOFFS: AtomicU32 = AtomicU32::new(0);
const LINUX_RETRY_SIBLING_HANDOFF_LIMIT: u32 = 1;

pub(super) fn linux_retry_later_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    wait: WaitOn,
) -> u64 {
    if linux_light_thread_here().is_some() {
        return migrate_current_linux_thread_to_owner(caller, number);
    }
    let mut restart = caller;
    restart.rip = caller.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
    restart.rax = number;
    // Waiting threads of one process that hand the CPU to each other would
    // never let the process they wait for run (git's two threads reading
    // pipes that its index-pack child fills): after a few handoffs in a
    // row, the other processes get their turn.
    let handoffs = LINUX_RETRY_SIBLING_HANDOFFS.fetch_add(1, Ordering::Relaxed);
    let others_first = handoffs >= LINUX_RETRY_SIBLING_HANDOFF_LIMIT;
    let sibling = if others_first {
        None
    } else {
        yield_ready_linux_thread_handle()
    };
    if sibling.is_none() {
        LINUX_RETRY_SIBLING_HANDOFFS.store(0, Ordering::Relaxed);
    }
    if let (Some(current), Some(target)) = (current_linux_thread_handle(), sibling) {
        let mut registers = LinuxSyscallFrame::ZERO;
        let (mut rip, mut rsp, mut rflags, mut rax) = (0, 0, 0, 0);
        if save_linux_thread_return_context(current, restart)
            && install_linux_thread_return(
                target,
                &mut registers,
                &mut rip,
                &mut rsp,
                &mut rflags,
                &mut rax,
            )
        {
            let selected = LinuxUserContext {
                registers,
                rip,
                rsp,
                rflags,
                rax,
                fs_base: active_fs_base(),
            };
            if !write_linux_thread_live_return(output, target, selected) {
                return LINUX_EINVAL;
            }
            X86_RUNTIME
                .LINUX_LIVE_RETURN_VALIDATED
                .store(true, Ordering::SeqCst);
            return LINUX_RETURN_FROM_IRET;
        }
    }
    match run_other_linux_processes_deferring(output, caller, number, wait, !others_first) {
        Some(LinuxBlockedWait::Return(result)) => result,
        _ => linux_restart_syscall_live_return(output, caller, number),
    }
}

/// Returns to the caller's system call instruction, so system call `number`
/// runs again with the same arguments.
pub(super) fn linux_restart_syscall_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
) -> u64 {
    let mut restart = caller;
    restart.rip = caller.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
    restart.rax = number;
    if !write_linux_live_return(output, restart) {
        return LINUX_EINVAL;
    }
    X86_RUNTIME
        .LINUX_LIVE_RETURN_VALIDATED
        .store(true, Ordering::SeqCst);
    number
}

pub(super) fn linux_descriptor_write(descriptor: u64, address: u64, count: u64) -> u64 {
    if linux_io_uring_descriptor(descriptor) {
        return LINUX_EINVAL;
    }
    if let Some(result) = linux_fanotify_write(descriptor, address, count) {
        return result;
    }
    if linux_userfaultfd_descriptor(descriptor) {
        return LINUX_EINVAL;
    }
    if linux_socket_slot(descriptor).is_some() {
        let device = linux_device_descriptor(descriptor);
        if device & LINUX_DEVICE_PIPE != 0 && device & 3 & LINUX_DESCRIPTOR_OUTPUT == 0 {
            return LINUX_EBADF;
        }
        return linux_socket_sendto(descriptor, address, count, 0, 0, 0);
    }
    if descriptor == 2
        && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::SeqCst)
    {
        return linux_bounded_console_write(address, count);
    }
    if let Some(result) = linux_eventfd_write(descriptor, address, count) {
        return result;
    }
    if linux_timerfd_descriptor(descriptor) {
        return LINUX_EINVAL;
    }
    if let Some(result) = linux_pipe_write(descriptor, address, count) {
        return result;
    }
    let device = linux_device_descriptor(descriptor);
    if linux_path_descriptor(descriptor) {
        return LINUX_EBADF;
    }
    if linux_secret_descriptor(descriptor) {
        return LINUX_EINVAL;
    }
    if device & !3 == LINUX_FILE_PROC_OOM_SCORE_ADJ {
        return linux_proc_oom_score_adj_write(descriptor, device, address, count);
    }
    if device & !3 == LINUX_FILE_PROC_DYNAMIC_MEM {
        let offset = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
        let result = linux_regular_file_write_at(descriptor, address, count, offset);
        if result < LINUX_RETURN_TO_KERNEL {
            linux_descriptor_offset(descriptor)
                .store(offset.saturating_add(result), Ordering::SeqCst);
        }
        return result;
    }
    if device & !3 == LINUX_FILE_PROC_TIMENS_OFFSETS {
        return linux_proc_timens_offsets_write(descriptor, device, address, count);
    }
    if let Some(index) = linux_proc_sysctl_index(device) {
        if LINUX_PROC_SYSCTLS[index].1 == b"sys/kernel/domainname" {
            return linux_proc_domainname_write(device, address, count);
        }
        return linux_proc_sysctl_write(device, index, address, count);
    }
    if device & !3 == LINUX_FILE_PROC_SYSRQ_TRIGGER {
        return linux_sysrq_trigger_write(address, count);
    }
    if let Some(result) = linux_overlay_write(descriptor, device, address, count) {
        return result;
    }
    if linux_tmp_file(device) {
        return linux_tmp_write(descriptor, device, address, count);
    }
    let access = device & 3;
    if access == LINUX_DESCRIPTOR_OUTPUT || access == 3 {
        if device & LINUX_DEVICE_CONSOLE != 0 {
            linux_bounded_console_write(address, count)
        } else if device & !3 == LINUX_DEVICE_FULL && count != 0 {
            LINUX_ENOSPC
        } else {
            count
        }
    } else {
        linux_console_write(descriptor, address, count)
    }
}

pub(super) fn linux_descriptor_readv(descriptor: u64, vectors: u64, count: u64) -> u64 {
    if let Some(result) = linux_socket_readv(descriptor, vectors, count) {
        return result;
    }
    if let Some(result) = linux_pipe_readv(descriptor, vectors, count) {
        return result;
    }
    let device = linux_device_descriptor(descriptor);
    if linux_overlay_descriptor_handle(descriptor).is_some()
        || linux_rootfs_entry(descriptor).is_some()
        || linux_tmp_file(device)
        || matches!(device & !3, LINUX_FILE_PROC_CPUINFO | LINUX_FILE_PROC_STAT)
    {
        let (ranges, vector_count) = match linux_socket_iov_ranges(vectors, count, true) {
            Ok(ranges) => ranges,
            Err(error) => return error,
        };
        let mut total = 0_u64;
        for (address, length) in ranges[..vector_count].iter().copied() {
            let result = linux_descriptor_read(descriptor, address, length as u64);
            if result >= u64::MAX - 4095 {
                return if total == 0 { result } else { total };
            }
            total = total.saturating_add(result);
            if result != length as u64 {
                break;
            }
        }
        return total;
    }
    let access = device & 3;
    if access != LINUX_DESCRIPTOR_INPUT
        && access != 3
        && u16::from(linux_console_descriptor(descriptor)) & LINUX_DESCRIPTOR_INPUT == 0
    {
        return LINUX_EBADF;
    }
    let Ok(vector_count) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if !(1..=LINUX_IOV_LIMIT).contains(&vector_count) {
        return LINUX_EINVAL;
    }
    let mut table = [0_u8; LINUX_IOV_LIMIT * 16];
    if !copy_from_linux_user(vectors, &mut table[..vector_count * 16]) {
        return LINUX_EFAULT;
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
            return LINUX_EINVAL;
        };
        // Linux accepts empty vectors, and musl's stdio relies on them.
        let Some(next_total) = total
            .checked_add(length)
            .filter(|total| *total <= isize::MAX as usize)
        else {
            return LINUX_EINVAL;
        };
        if length != 0 && !linux_writable_user_range_contains(address, length) {
            return LINUX_EFAULT;
        }
        ranges[index] = (address, length);
        total = next_total;
    }
    if u16::from(linux_console_descriptor(descriptor)) & LINUX_DESCRIPTOR_INPUT != 0
        || device & LINUX_DEVICE_CONSOLE != 0 && matches!(device & 3, LINUX_DESCRIPTOR_INPUT | 3)
    {
        if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            return 0;
        }
        let Some(byte) = container_console_read_byte() else {
            return 0;
        };
        if !copy_to_linux_user(ranges[0].0, &[byte]) {
            return LINUX_EFAULT;
        }
        return 1;
    }
    if let Some(file) = linux_regular_file(device) {
        let offset = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        let returned = file.len().saturating_sub(start).min(total);
        let mut copied = 0;
        for (address, length) in ranges[..vector_count].iter().copied() {
            if copied == returned {
                break;
            }
            let length = length.min(returned - copied);
            if length != 0
                && !copy_to_linux_user(address, &file[start + copied..start + copied + length])
            {
                return LINUX_EFAULT;
            }
            copied += length;
        }
        linux_descriptor_offset(descriptor).store((start + returned) as u64, Ordering::SeqCst);
        return returned as u64;
    }
    if device & LINUX_DEVICE_ZERO == 0 {
        return 0;
    }
    if device & !3 == LINUX_DEVICE_RANDOM {
        for (address, length) in ranges[..vector_count].iter().copied() {
            let result = linux_getrandom(address, length as u64, 0);
            if result >= u64::MAX - 4095 {
                return result;
            }
        }
        return total as u64;
    }
    let zeros = [0_u8; LINUX_WRITE_LIMIT];
    for (address, length) in ranges[..vector_count].iter().copied() {
        for offset in (0..length).step_by(LINUX_WRITE_LIMIT) {
            let chunk = (length - offset).min(LINUX_WRITE_LIMIT);
            if !copy_to_linux_user(address + offset as u64, &zeros[..chunk]) {
                return LINUX_EFAULT;
            }
        }
    }
    total as u64
}

/// preadv/pwritev and their v2 forms. x86-64 passes the whole offset in the
/// low word and Linux ignores the high one. Regular files never block and are
/// written through, so the priority and sync flags change nothing.
/// A positioned write to a file opened with O_APPEND goes to its end, as
/// Linux's does, unless RWF_NOAPPEND (which Rust's `write_at` passes) asks
/// for the position.
pub(super) fn linux_positioned_iov(
    descriptor: u64,
    vectors: u64,
    count: u64,
    offset: u64,
    flags: u64,
    write: bool,
) -> u64 {
    if flags
        & !(LINUX_RWF_HIPRI
            | LINUX_RWF_DSYNC
            | LINUX_RWF_SYNC
            | LINUX_RWF_NOWAIT
            | LINUX_RWF_APPEND
            | LINUX_RWF_NOAPPEND)
        != 0
    {
        return LINUX_EOPNOTSUPP;
    }
    let (ranges, vector_count) = match linux_socket_iov_ranges(vectors, count, !write) {
        Ok(ranges) => ranges,
        Err(error) => return error,
    };
    if !linux_path_descriptor(descriptor) && (offset as i64) < 0 {
        return LINUX_EINVAL;
    }
    if !write
        && !linux_path_descriptor(descriptor)
        && linux_device_descriptor(descriptor) & LINUX_DEVICE_DIRECTORY != 0
    {
        return LINUX_EISDIR;
    }
    let mut offset = if write && flags & LINUX_RWF_APPEND != 0 {
        match linux_descriptor_stat(descriptor) {
            Some(stat) => u64::from_ne_bytes(stat[48..56].try_into().unwrap()),
            None => return LINUX_EBADF,
        }
    } else if write && flags & LINUX_RWF_NOAPPEND == 0 {
        linux_pwrite_offset(descriptor, offset)
    } else {
        offset
    };
    // RWF_NOWAIT reads only what a volume's page cache holds: none of it is
    // EAGAIN, part of it a short read.
    let mut cached = usize::MAX;
    // Only a disk's files take RWF_NOWAIT (Linux's FMODE_NOWAIT): tmpfs and
    // ramfs files, the overlay's, refuse it.
    if flags & LINUX_RWF_NOWAIT != 0
        && (linux_overlay_descriptor_handle(descriptor)
            .is_some_and(|handle| !crate::linux_blockfs::owns(handle))
            || linux_rootfs_entry(descriptor).is_some())
    {
        return LINUX_EOPNOTSUPP;
    }
    if !write && flags & LINUX_RWF_NOWAIT != 0 {
        if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
            let wanted = ranges[..vector_count]
                .iter()
                .map(|(_, length)| *length)
                .sum::<usize>();
            if let Some(bytes) = crate::linux_blockfs::cached_bytes(handle, offset as usize, wanted)
            {
                if bytes == 0 && wanted != 0 {
                    let size = crate::linux_overlay::metadata(handle).map_or(0, |m| m.size);
                    if (offset as usize) < size {
                        return LINUX_EAGAIN;
                    }
                }
                cached = bytes;
            }
        }
    }
    let mut total = 0_u64;
    for (address, length) in ranges[..vector_count].iter().copied() {
        let length = length.min(cached.saturating_sub(total as usize));
        if length == 0 && cached != usize::MAX {
            break;
        }
        let result = if write {
            linux_regular_file_write_at(descriptor, address, length as u64, offset)
        } else {
            linux_regular_file_read_at(descriptor, address, length as u64, offset)
        };
        if result >= u64::MAX - 4095 {
            return if total == 0 { result } else { total };
        }
        total = total.saturating_add(result);
        let Some(next) = offset.checked_add(result) else {
            return if total == result {
                LINUX_EINVAL
            } else {
                total - result
            };
        };
        offset = next;
        if result != length as u64 || write && offset >= linux_file_size_limit() {
            break;
        }
    }
    total
}

fn linux_console_write(descriptor: u64, address: u64, count: u64) -> u64 {
    if u16::from(linux_console_descriptor(descriptor)) & LINUX_DESCRIPTOR_OUTPUT == 0 {
        return LINUX_EBADF;
    }
    linux_bounded_console_write(address, count)
}

fn linux_bounded_console_write(address: u64, count: u64) -> u64 {
    let Ok(length) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if length == 0 {
        return 0;
    }
    if !linux_readable_user_range_contains(address, length) {
        return LINUX_EFAULT;
    }
    let mut bytes = [0_u8; LINUX_WRITE_LIMIT];
    let mut written = 0_usize;
    while written < length {
        let chunk = (length - written).min(bytes.len());
        if !copy_from_linux_user(address + written as u64, &mut bytes[..chunk]) {
            return LINUX_EFAULT;
        }
        container_console_write(&bytes[..chunk]);
        written += chunk;
    }
    count
}

pub(super) fn linux_descriptor_writev(descriptor: u64, vectors: u64, count: u64) -> u64 {
    if let Some(result) = linux_socket_writev(descriptor, vectors, count) {
        return result;
    }
    if let Some(result) = linux_pipe_writev(descriptor, vectors, count) {
        return result;
    }
    let device = linux_device_descriptor(descriptor);
    // stdio flushes with writev, so a /proc value written with fprintf
    // arrives here: these go through the descriptor's write handler.
    if linux_overlay_descriptor_handle(descriptor).is_some()
        || linux_tmp_file(device)
        || device & !3 == LINUX_FILE_PROC_OOM_SCORE_ADJ
        || device & !3 == LINUX_FILE_PROC_DYNAMIC_MEM
        || device & !3 == LINUX_FILE_PROC_TIMENS_OFFSETS
        || device & !3 == LINUX_FILE_PROC_SYSRQ_TRIGGER
        || linux_proc_sysctl_index(device).is_some()
    {
        let (ranges, vector_count) = match linux_socket_iov_ranges(vectors, count, false) {
            Ok(ranges) => ranges,
            Err(error) => return error,
        };
        let mut total = 0_u64;
        for (address, length) in ranges[..vector_count].iter().copied() {
            let result = linux_descriptor_write(descriptor, address, length as u64);
            if result >= u64::MAX - 4095 {
                return if total == 0 { result } else { total };
            }
            total = total.saturating_add(result);
            if result != length as u64
                || linux_descriptor_offset(descriptor).load(Ordering::SeqCst)
                    >= linux_file_size_limit()
            {
                break;
            }
        }
        return total;
    }
    let access = device & 3;
    let writable_device = device != 0 && (access == LINUX_DESCRIPTOR_OUTPUT || access == 3);
    let serial = descriptor == 2 && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || u16::from(linux_console_descriptor(descriptor)) & LINUX_DESCRIPTOR_OUTPUT != 0
        || writable_device && device & LINUX_DEVICE_CONSOLE != 0;
    let discard = writable_device && device & LINUX_DEVICE_CONSOLE == 0;
    if !serial && !discard {
        return LINUX_EBADF;
    }
    let Ok(vector_count) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if !(1..=LINUX_IOV_LIMIT).contains(&vector_count) {
        return LINUX_EINVAL;
    }
    let mut table = [0_u8; LINUX_IOV_LIMIT * 16];
    if !copy_from_linux_user(vectors, &mut table[..vector_count * 16]) {
        return LINUX_EFAULT;
    }
    let mut output = [0_u8; LINUX_WRITE_LIMIT];
    let mut total = 0_usize;
    for vector in table[..vector_count * 16].as_chunks::<16>().0 {
        let mut address_bytes = [0_u8; 8];
        address_bytes.copy_from_slice(&vector[..8]);
        let address = u64::from_ne_bytes(address_bytes);
        let mut length_bytes = [0_u8; 8];
        length_bytes.copy_from_slice(&vector[8..]);
        let length = u64::from_ne_bytes(length_bytes);
        let Ok(length) = usize::try_from(length) else {
            return LINUX_EINVAL;
        };
        let Some(end) = total.checked_add(length) else {
            return LINUX_EINVAL;
        };
        if end > LINUX_WRITE_LIMIT {
            return LINUX_EINVAL;
        }
        if serial && length != 0 && !copy_from_linux_user(address, &mut output[total..end]) {
            return LINUX_EFAULT;
        }
        total = end;
    }
    if serial {
        container_console_write(&output[..total]);
    }
    total as u64
}
