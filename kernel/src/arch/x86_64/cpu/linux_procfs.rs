#![forbid(unsafe_code)]

use super::*;

/// The text of the /proc/sys value a descriptor state names, as a read
/// shows it: the domain's name for kernel/domainname, its core pattern for
/// kernel/core_pattern, a number the domain wrote, else the built-in
/// value; with its length.
pub(super) fn linux_proc_sysctl_text(
    state: u16,
) -> Option<([u8; LINUX_SYSCTL_TEXT_CAPACITY], usize)> {
    let index = linux_proc_sysctl_index(state)?;
    let mut text = [0_u8; LINUX_SYSCTL_TEXT_CAPACITY];
    if LINUX_PROC_SYSCTLS[index].1 == b"sys/kernel/core_pattern" {
        let pattern = crate::linux_core::pattern(linux_execution_instance());
        let length = pattern.len().min(LINUX_SYSCTL_TEXT_CAPACITY - 1);
        text[..length].copy_from_slice(&pattern[..length]);
        text[length] = b'\n';
        return Some((text, length + 1));
    }
    if LINUX_PROC_SYSCTLS[index].1 == b"sys/kernel/domainname" {
        let mut name = [0_u8; LINUX_UTS_NAME_CAPACITY];
        let length = linux_uts_name(LINUX_UTS_DOMAIN, &mut name);
        text[..length].copy_from_slice(&name[..length]);
        text[length] = b'\n';
        return Some((text, length + 1));
    }
    let value = linux_fanotify_limit_value(LINUX_PROC_SYSCTLS[index].1)
        .or_else(|| linux_proc_sysctl_override(index));
    if let Some((low, high)) = value
        .filter(|_| LINUX_PROC_SYSCTLS[index].1 == LINUX_PING_GROUP_RANGE)
        .map(linux_sysctl_unpack_pair)
    {
        let mut used = 0;
        let generated = append_linux_decimal(&mut text, &mut used, low)
            && append_linux_bytes(&mut text, &mut used, b"\t")
            && append_linux_decimal(&mut text, &mut used, high)
            && append_linux_bytes(&mut text, &mut used, b"\n");
        return generated.then_some((text, used));
    }
    if let Some(value) = value {
        let mut used = 0;
        let generated = (value >= 0 || append_linux_bytes(&mut text, &mut used, b"-"))
            && append_linux_decimal(&mut text, &mut used, value.unsigned_abs())
            && append_linux_bytes(&mut text, &mut used, b"\n");
        return generated.then_some((text, used));
    }
    let built_in = LINUX_PROC_SYSCTLS[index].2;
    let length = built_in.len().min(text.len());
    text[..length].copy_from_slice(&built_in[..length]);
    Some((text, length))
}

pub(super) fn linux_proc_root_file_kind(name: &[u8]) -> Option<u16> {
    if let Some((node, ..)) = LINUX_PROC_SYSCTLS.iter().find(|(_, path, _)| *path == name) {
        return Some(LINUX_FILE_MASK | node);
    }
    match name {
        b"mounts" => Some(LINUX_FILE_PROC_MOUNTS),
        b"cpuinfo" => Some(LINUX_FILE_PROC_CPUINFO),
        b"meminfo" => Some(LINUX_FILE_PROC_MEMINFO),
        b"stat" => Some(LINUX_FILE_PROC_STAT),
        b"uptime" => Some(LINUX_FILE_PROC_UPTIME),
        b"loadavg" => Some(LINUX_FILE_PROC_LOADAVG),
        b"filesystems" => Some(LINUX_FILE_PROC_FILESYSTEMS),
        b"modules" => Some(LINUX_FILE_PROC_MODULES),
        b"keys" => Some(LINUX_FILE_PROC_KEYS),
        b"swaps" => Some(LINUX_FILE_PROC_SWAPS),
        b"key-users" => Some(LINUX_FILE_PROC_KEY_USERS),
        b"config.gz" => Some(LINUX_FILE_PROC_CONFIG),
        b"cmdline" => Some(LINUX_FILE_PROC_CMDLINE),
        b"sysrq-trigger" => Some(LINUX_FILE_PROC_SYSRQ_TRIGGER),
        b"sysvipc/msg" => Some(LINUX_FILE_PROC_SYSVIPC_MSG),
        b"sysvipc/shm" => Some(LINUX_FILE_PROC_SYSVIPC_SHM),
        b"sysvipc/sem" => Some(LINUX_FILE_PROC_SYSVIPC_SEM),
        _ => None,
    }
}

/// Whether a descriptor state names one of the `/proc/sysvipc` listings.
pub(super) fn linux_proc_sysvipc_file(state: u16) -> bool {
    matches!(
        state & !3,
        LINUX_FILE_PROC_SYSVIPC_MSG | LINUX_FILE_PROC_SYSVIPC_SHM | LINUX_FILE_PROC_SYSVIPC_SEM
    )
}

/// Linux's header lines, which the listings start with.
pub(super) const LINUX_PROC_SYSVIPC_MSG_HEADER: &[u8] = b"       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n";
pub(super) const LINUX_PROC_SYSVIPC_SHM_HEADER: &[u8] = b"       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n";
pub(super) const LINUX_PROC_SYSVIPC_SEM_HEADER: &[u8] =
    b"       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n";
/// Room for the listing: about sixty objects; a longer one is cut short.
pub(super) const LINUX_PROC_SYSVIPC_CAPACITY: usize = 4096;

/// Appends `value` in octal, as `/proc/sysvipc` shows permissions.
fn append_linux_octal(output: &mut [u8], used: &mut usize, value: u64) -> bool {
    let mut digits = [0_u8; 22];
    let mut length = 0;
    let mut remaining = value;
    loop {
        digits[length] = b'0' + (remaining & 7) as u8;
        length += 1;
        remaining >>= 3;
        if remaining == 0 {
            break;
        }
    }
    digits[..length].reverse();
    append_linux_bytes(output, used, &digits[..length])
}

/// Appends a row of `/proc/sysvipc` fields: the signed key, then the
/// octal permissions at `perms_index`, the rest in decimal, each after a
/// space, and a newline.
fn append_linux_sysvipc_row(
    output: &mut [u8],
    used: &mut usize,
    key: i32,
    fields: &[u64],
    perms_index: usize,
) -> bool {
    let mut ok = (key >= 0 || append_linux_bytes(output, used, b"-"))
        && append_linux_decimal(output, used, u64::from(key.unsigned_abs()));
    for (index, value) in fields.iter().enumerate() {
        ok = ok
            && append_linux_bytes(output, used, b" ")
            && if index == perms_index {
                append_linux_octal(output, used, *value)
            } else {
                append_linux_decimal(output, used, *value)
            };
    }
    ok && append_linux_bytes(output, used, b"\n")
}

/// Generates a `/proc/sysvipc` listing into `file`: the header, then one
/// line per object of the domain, as far as `file` holds them.
pub(super) fn linux_proc_sysvipc_contents(state: u16, file: &mut [u8]) -> Option<usize> {
    let mut used = 0;
    let generated = match state & !3 {
        LINUX_FILE_PROC_SYSVIPC_MSG => {
            append_linux_bytes(file, &mut used, LINUX_PROC_SYSVIPC_MSG_HEADER)
                && crate::linux_sysv_ipc::message_queues()
                    .iter()
                    .all(|(id, queue)| {
                        append_linux_sysvipc_row(
                            file,
                            &mut used,
                            queue.key,
                            &[
                                u64::from(*id),
                                u64::from(queue.mode & 0o777),
                                queue.bytes,
                                queue.messages,
                                u64::from(queue.last_sender),
                                u64::from(queue.last_receiver),
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                            ],
                            1,
                        )
                    })
        }
        LINUX_FILE_PROC_SYSVIPC_SHM => {
            append_linux_bytes(file, &mut used, LINUX_PROC_SYSVIPC_SHM_HEADER)
                && crate::linux_sysv_ipc::segments()
                    .iter()
                    .all(|(id, segment)| {
                        append_linux_sysvipc_row(
                            file,
                            &mut used,
                            segment.key,
                            &[
                                u64::from(*id),
                                u64::from(segment.mode & 0o777),
                                segment.size,
                                u64::from(segment.creator_pid),
                                u64::from(segment.last_pid),
                                segment.attachments,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                segment.size,
                                0,
                            ],
                            1,
                        )
                    })
        }
        LINUX_FILE_PROC_SYSVIPC_SEM => {
            append_linux_bytes(file, &mut used, LINUX_PROC_SYSVIPC_SEM_HEADER)
                && crate::linux_sysv_ipc::semaphore_sets()
                    .iter()
                    .all(|(id, set)| {
                        append_linux_sysvipc_row(
                            file,
                            &mut used,
                            set.key,
                            &[
                                u64::from(*id),
                                u64::from(set.mode & 0o777),
                                set.count,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                            ],
                            1,
                        )
                    })
        }
        _ => return None,
    };
    // A listing the buffer could not hold ends at its last whole line.
    let _ = generated;
    Some(used)
}

/// Reads a `/proc/sysvipc` listing from `offset`.
pub(super) fn linux_proc_sysvipc_read(state: u16, address: u64, count: u64, offset: u64) -> u64 {
    let mut file = [0_u8; LINUX_PROC_SYSVIPC_CAPACITY];
    let Some(used) = linux_proc_sysvipc_contents(state, &mut file) else {
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
    if copy_to_linux_user(address, &file[start..end]) {
        (end - start) as u64
    } else {
        LINUX_EFAULT
    }
}

/// Whether a descriptor state names /proc/keys or /proc/key-users.
pub(super) fn linux_proc_keys_file(state: u16) -> bool {
    matches!(state & !3, LINUX_FILE_PROC_KEYS | LINUX_FILE_PROC_KEY_USERS)
}

/// Reads /proc/swaps from `offset`.
pub(super) fn linux_proc_swaps_read(address: u64, count: u64, offset: u64) -> u64 {
    let Some(text) = crate::linux_swap::proc_swaps(linux_execution_instance()) else {
        return LINUX_ENOMEM;
    };
    let Ok(start) = usize::try_from(offset) else {
        return 0;
    };
    if start >= text.len() || count == 0 {
        return 0;
    }
    let end = start
        .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
        .min(text.len());
    if copy_to_linux_user(address, &text[start..end]) {
        (end - start) as u64
    } else {
        LINUX_EFAULT
    }
}

/// The text of /proc/keys (the domain's keys the caller may view) or
/// /proc/key-users (each user's key count and quota usage).
pub(super) fn linux_proc_keys_contents(state: u16) -> Result<Vec<u8>, u64> {
    let now = linux_key_clock();
    linux_with_keys(|keys, caller| {
        if state & !3 == LINUX_FILE_PROC_KEYS {
            keys.proc_keys(caller, now)
        } else {
            keys.proc_key_users()
        }
    })
}

/// Reads /proc/keys or /proc/key-users from `offset`.
pub(super) fn linux_proc_keys_read(state: u16, address: u64, count: u64, offset: u64) -> u64 {
    let text = match linux_proc_keys_contents(state) {
        Ok(text) => text,
        Err(error) => return error,
    };
    let Ok(start) = usize::try_from(offset) else {
        return 0;
    };
    if start >= text.len() || count == 0 {
        return 0;
    }
    let end = start
        .saturating_add(usize::try_from(count).unwrap_or(usize::MAX))
        .min(text.len());
    if copy_to_linux_user(address, &text[start..end]) {
        (end - start) as u64
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_proc_numeric_file(path: &[u8], absolute: bool) -> Option<(u32, &[u8])> {
    let rest = if absolute {
        path.strip_prefix(b"/proc/")?
    } else {
        path.strip_prefix(b"proc/")?
    };
    let slash = rest.iter().position(|byte| *byte == b'/')?;
    let (pid, name) = (&rest[..slash], &rest[slash + 1..]);
    if pid.is_empty() || name.is_empty() {
        return None;
    }
    let pid = pid.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value.checked_mul(10)?.checked_add(u32::from(byte - b'0')))
            .flatten()
    })?;
    (pid != 0).then_some((pid, name))
}

/// The process and file name of a `/proc/PID/NAME` or `/proc/self/NAME` path.
pub(super) fn linux_proc_process_file(path: &[u8]) -> Option<(u32, &[u8])> {
    match path.strip_prefix(b"/proc/self/") {
        Some([]) => None,
        Some(name) => Some((current_linux_process_pid(), name)),
        None => linux_proc_numeric_file(path, true),
    }
}

pub(super) fn linux_proc_fdinfo_target(path: &[u8]) -> Option<u64> {
    // /proc/self/fdinfo/N, or the calling process's own /proc/PID/fdinfo/N.
    let descriptor = path.strip_prefix(b"/proc/self/fdinfo/").or_else(|| {
        let rest = path.strip_prefix(b"/proc/")?;
        let slash = rest.iter().position(|byte| *byte == b'/')?;
        let pid = core::str::from_utf8(&rest[..slash])
            .ok()?
            .parse::<u32>()
            .ok()?;
        (pid == current_linux_process_pid())
            .then(|| rest[slash..].strip_prefix(b"/fdinfo/"))
            .flatten()
    })?;
    let descriptor = descriptor.iter().try_fold(0_u64, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value.checked_mul(10)?.checked_add(u64::from(byte - b'0')))
            .flatten()
    })?;
    // Every open descriptor has one: its position, flags, mount and inode,
    // and what its kind adds (a pidfd's process, an inotify descriptor's
    // watches, a fanotify group's marks, an eventfd's count).
    linux_descriptor_open(descriptor).then_some(descriptor)
}

/// /proc/self/fdinfo/N for descriptor `target` of a kind with no lines of
/// its own: Linux's position, flags (octal, with O_CLOEXEC), mount and
/// inode, and an eventfd's count.
pub(super) fn linux_generic_fdinfo(target: u64) -> Option<([u8; 256], usize)> {
    let stat = linux_descriptor_stat(target)?;
    let inode = u64::from_ne_bytes(stat[8..16].try_into().unwrap());
    let mode = u32::from_ne_bytes(stat[24..28].try_into().unwrap());
    let state = linux_device_descriptor(target);
    let access = match state & 3 {
        1 => 0,
        2 => 1,
        _ => 2,
    };
    let status = linux_socket_flags(target).unwrap_or(0) as u64
        & (LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_PATH | LINUX_O_NOATIME);
    let regular = mode & 0o170000 == 0o100000;
    let flags = access
        | status
        | if regular { LINUX_O_LARGEFILE } else { 0 }
        | if linux_descriptor_close_on_exec(target) {
            LINUX_O_CLOEXEC
        } else {
            0
        };
    let position = if regular {
        linux_descriptor_offset(target).load(Ordering::SeqCst)
    } else {
        0
    };
    let mut file = [0_u8; 256];
    let mut used = 0;
    let mut written = append_linux_bytes(&mut file, &mut used, b"pos:\t")
        && append_linux_decimal(&mut file, &mut used, position)
        && append_linux_bytes(&mut file, &mut used, b"\nflags:\t0")
        && append_linux_octal(&mut file, &mut used, flags)
        && append_linux_bytes(&mut file, &mut used, b"\nmnt_id:\t1\nino:\t")
        && append_linux_decimal(&mut file, &mut used, inode)
        && append_linux_bytes(&mut file, &mut used, b"\n");
    if let Some((counter, eventfd_flags)) = linux_eventfd_state(target) {
        // As Linux prints it: "%16llx", the count right-aligned.
        let count = counter.load(Ordering::SeqCst);
        let mut hex = [0_u8; 16];
        let mut hex_length = 0;
        append_linux_hex(&mut hex, &mut hex_length, count);
        let mut padded = [b' '; 16];
        padded[16 - hex_length..].copy_from_slice(&hex[..hex_length]);
        written = written
            && append_linux_bytes(&mut file, &mut used, b"eventfd-count: ")
            && append_linux_bytes(&mut file, &mut used, &padded)
            && append_linux_bytes(&mut file, &mut used, b"\neventfd-id: ")
            && append_linux_decimal(
                &mut file,
                &mut used,
                linux_eventfd_file(target).unwrap_or(0),
            )
            && append_linux_bytes(&mut file, &mut used, b"\neventfd-semaphore: ")
            && append_linux_decimal(
                &mut file,
                &mut used,
                u64::from(eventfd_flags.load(Ordering::SeqCst) as u64 & LINUX_EFD_SEMAPHORE != 0),
            )
            && append_linux_bytes(&mut file, &mut used, b"\n");
    }
    written.then_some((file, used))
}

/// The command name (comm) of process `pid`, in `name`: the running
/// process's own, or the one saved with another's state.
pub(super) fn linux_process_name(pid: u32, name: &mut [u8; 16]) -> &[u8] {
    let words = if pid == current_linux_process_pid() {
        [
            X86_RUNTIME
                .ELF_PROBE_PROCESS_NAME_LOW
                .load(Ordering::SeqCst),
            X86_RUNTIME
                .ELF_PROBE_PROCESS_NAME_HIGH
                .load(Ordering::SeqCst),
        ]
    } else {
        linux_process_runtime_state(pid)
            .filter(|state| state.valid)
            .map_or([0; 2], |state| state.process_name)
    };
    name[..8].copy_from_slice(&words[0].to_ne_bytes());
    name[8..].copy_from_slice(&words[1].to_ne_bytes());
    let length = name.iter().position(|byte| *byte == 0).unwrap_or(15);
    if length == 0 {
        return b"process";
    }
    &name[..length]
}

/// The live process a `/proc/PID` path names (`proc/PID` when not
/// `absolute`), with or without a trailing slash.
pub(super) fn linux_proc_pid_directory(path: &[u8], absolute: bool) -> Option<u32> {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    let digits = if absolute {
        path.strip_prefix(b"/proc/")?
    } else {
        path.strip_prefix(b"proc/")?
    };
    if digits.is_empty() || digits[0] == b'0' {
        return None;
    }
    let pid = digits.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value.checked_mul(10)?.checked_add(u32::from(byte - b'0')))
            .flatten()
    })?;
    linux_process::live_process_status(pid).map(|_| pid)
}

/// The directory kind of process `pid`'s /proc directory. Pids 1 and 2 have
/// their own; every other process's directory lists the same names as pid
/// 1's, and its files resolve by the pid in their path.
pub(super) fn linux_proc_pid_directory_kind(pid: u32) -> u16 {
    if pid == 2 && linux_process::live_process_status(2).is_some() {
        LINUX_PROC_PID2_DIRECTORY
    } else {
        LINUX_PROC_PID1_DIRECTORY
    }
}

pub(super) fn linux_proc_pid_file_kind(pid: u32, name: &[u8]) -> Option<u16> {
    linux_process::live_process_status(pid)?;
    match (pid, name) {
        (pid, b"fd") if pid == current_linux_process_pid() => Some(LINUX_PROC_FD_DIRECTORY),
        (_, b"cgroup") => Some(LINUX_FILE_PROC_CGROUP),
        (_, b"coredump_filter") => Some(LINUX_FILE_PROC_COREDUMP_FILTER),
        (_, b"oom_score_adj") => Some(LINUX_FILE_PROC_OOM_SCORE_ADJ),
        (_, b"timens_offsets") => Some(LINUX_FILE_PROC_TIMENS_OFFSETS),
        (_, b"mounts") => Some(LINUX_FILE_PROC_MOUNTS),
        (1, b"cmdline") if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) => {
            Some(LINUX_FILE_PROC_PROCESS_CMDLINE)
        }
        (1, b"environ") if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) => {
            Some(LINUX_FILE_PROC_PROCESS_ENVIRON)
        }
        (1, b"status") => Some(LINUX_FILE_PROC_STATUS),
        (1, b"stat") => Some(LINUX_FILE_PROC_PID1_STAT),
        (1, b"statm") => Some(LINUX_FILE_PROC_PID1_STATM),
        (_, b"mountinfo") => Some(LINUX_FILE_PROC_MOUNTINFO),
        (_, b"uid_map") => Some(LINUX_FILE_PROC_UID_MAP),
        (_, b"gid_map") => Some(LINUX_FILE_PROC_GID_MAP),
        (_, b"setgroups") => Some(LINUX_FILE_PROC_SETGROUPS),
        (_, b"ns/user") => Some(LINUX_FILE_PROC_USER_NAMESPACE),
        (2, b"status") => Some(LINUX_FILE_PROC_PID2_STATUS),
        (2, b"stat") => Some(LINUX_FILE_PROC_PID2_STAT),
        (2, b"statm") => Some(LINUX_FILE_PROC_PID2_STATM),
        (_, b"status") => Some(LINUX_FILE_PROC_DYNAMIC_STATUS),
        (_, b"stat") => Some(LINUX_FILE_PROC_DYNAMIC_STAT),
        (_, b"statm") => Some(LINUX_FILE_PROC_DYNAMIC_STATM),
        (_, b"io") => Some(LINUX_FILE_PROC_DYNAMIC_IO),
        (_, b"maps") => Some(LINUX_FILE_PROC_DYNAMIC_MAPS),
        (_, b"smaps") => Some(LINUX_FILE_PROC_DYNAMIC_SMAPS),
        (_, b"pagemap") => Some(LINUX_FILE_PROC_DYNAMIC_PAGEMAP),
        (_, b"mem") => Some(LINUX_FILE_PROC_DYNAMIC_MEM),
        (_, b"comm") => Some(LINUX_FILE_PROC_TASK_COMM),
        (_, b"task" | b"task/") => Some(LINUX_PROC_TASK_DIRECTORY),
        (_, name) if name.starts_with(b"task/") => linux_proc_task_file_kind(pid, &name[5..]),
        _ => None,
    }
}

/// `/proc/PID/task/TID` and the files under it, for a thread `pid` has.
fn linux_proc_task_file_kind(pid: u32, name: &[u8]) -> Option<u16> {
    let (digits, file) = match name.iter().position(|byte| *byte == b'/') {
        Some(at) => (&name[..at], &name[at + 1..]),
        None => (name, &b""[..]),
    };
    if digits.is_empty() || digits[0] == b'0' {
        return None;
    }
    let tid = digits.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value.checked_mul(10)?.checked_add(u32::from(byte - b'0')))
            .flatten()
    })?;
    let mut tids = [0_u32; LINUX_THREAD_LIMIT];
    let count = linux_process_thread_ids(pid, &mut tids);
    if !tids[..count].contains(&tid) {
        return None;
    }
    match file {
        // A thread's directory lists its process's files.
        b"" => Some(LINUX_PROC_PID1_DIRECTORY),
        b"comm" => Some(LINUX_FILE_PROC_TASK_COMM),
        b"stat" => Some(LINUX_FILE_PROC_TASK_STAT),
        b"status" => Some(LINUX_FILE_PROC_DYNAMIC_STATUS),
        b"statm" => Some(LINUX_FILE_PROC_DYNAMIC_STATM),
        b"io" => Some(LINUX_FILE_PROC_DYNAMIC_IO),
        _ => None,
    }
}

/// The leading decimal of `digits` up to a `/` or its end (a thread id in
/// a `/proc/PID/task/TID/...` name).
pub(super) fn linux_leading_decimal(digits: &[u8]) -> Option<u32> {
    let digits = digits
        .iter()
        .position(|byte| *byte == b'/')
        .map_or(digits, |at| &digits[..at]);
    if digits.is_empty() || digits[0] == b'0' {
        return None;
    }
    digits.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value.checked_mul(10)?.checked_add(u32::from(byte - b'0')))
            .flatten()
    })
}

/// The process thread `tid` belongs to, and the thread's state as /proc
/// shows it: R running or ready, S blocked. The current process's live
/// table first, then processes live in banks on other CPUs, then saved
/// records; a process with no thread slot in use is its own single thread.
pub(super) fn linux_thread_state_by_tid(tid: u32) -> Option<(u32, u8)> {
    let letter = |state: u8| {
        if matches!(state, LINUX_THREAD_RUNNING | LINUX_THREAD_READY) {
            b'R'
        } else {
            b'S'
        }
    };
    let current = current_linux_process_pid();
    for slot in 0..LINUX_THREAD_LIMIT {
        let state = X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst);
        if state != LINUX_THREAD_FREE
            && X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst) == tid
        {
            return Some((current, letter(state)));
        }
    }
    let instance = linux_execution_instance();
    for bank in 0..LINUX_CPU_BANK_LIMIT {
        let pid = LINUX_BANK_PID[bank].load(Ordering::Acquire);
        if pid == 0
            || LINUX_BANK_USERS[bank].load(Ordering::Acquire) == 0
            || usize::from(LINUX_BANK_INSTANCE[bank].load(Ordering::Acquire)) != instance
        {
            continue;
        }
        for slot in 0..LINUX_THREAD_LIMIT {
            let state = X86_RUNTIME.LINUX_THREAD_STATES[slot]
                .at_bank(bank)
                .load(Ordering::Acquire);
            if state != LINUX_THREAD_FREE
                && X86_RUNTIME.LINUX_THREAD_TIDS[slot]
                    .at_bank(bank)
                    .load(Ordering::Acquire)
                    == tid
            {
                return Some((pid, letter(state)));
            }
        }
    }
    let mut pid = 0;
    while let Some(next) = linux_process::next_live_pid(pid) {
        pid = next;
        if let Some(thread) = linux_process_thread_runtime_state(pid).and_then(|threads| {
            threads
                .iter()
                .find(|thread| thread.state != LINUX_THREAD_FREE && thread.tid == tid)
        }) {
            return Some((pid, letter(thread.state)));
        }
    }
    let status = linux_process::live_process_status(tid)?;
    let letter = match status.state {
        linux_process::LiveProcessState::Running if linux_leader_thread_blocked(tid) => b'S',
        linux_process::LiveProcessState::Running => b'R',
        linux_process::LiveProcessState::Sleeping => b'S',
        linux_process::LiveProcessState::Stopped => b'T',
        linux_process::LiveProcessState::Zombie => b'Z',
    };
    Some((tid, letter))
}

/// Reads `/proc/PID/task/TID/stat`: the process's stat line with the
/// thread's id and state.
pub(super) fn linux_proc_task_stat_read(
    descriptor: u64,
    address: u64,
    count: u64,
    offset: u64,
) -> u64 {
    let Some(tid) = linux_proc_dynamic_descriptor_pid(descriptor) else {
        return LINUX_EBADF;
    };
    let Some((pid, state_letter)) = linux_thread_state_by_tid(tid) else {
        return LINUX_ESRCH;
    };
    let Some(status) = linux_process::live_process_status(pid) else {
        return LINUX_ESRCH;
    };
    let mut name = [0_u8; 16];
    let mut file = [0_u8; 256];
    let mut used = 0;
    let generated = append_linux_decimal(&mut file, &mut used, u64::from(tid))
        && append_linux_bytes(&mut file, &mut used, b" (")
        && append_linux_bytes(&mut file, &mut used, linux_process_name(pid, &mut name))
        && append_linux_bytes(&mut file, &mut used, b") ")
        && append_linux_bytes(&mut file, &mut used, &[state_letter])
        && append_linux_bytes(&mut file, &mut used, b" ")
        && append_linux_decimal(&mut file, &mut used, u64::from(status.parent_pid))
        && append_linux_bytes(&mut file, &mut used, b" 1 1 0 -1 4194560 0 0 0 0 ")
        && append_linux_decimal(&mut file, &mut used, linux_process_cpu_ticks(pid))
        && append_linux_bytes(&mut file, &mut used, b" 0 0 0 20 0 1 0 1 1048576 256 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
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
    if copy_to_linux_user(address, &file[start..end]) {
        (end - start) as u64
    } else {
        LINUX_EFAULT
    }
}

/// The thread ids of process `pid`: from the live table for the current
/// process, else from the process's saved record; a process with no thread
/// slots in use has its own id alone.
pub(super) fn linux_process_thread_ids(pid: u32, tids: &mut [u32; LINUX_THREAD_LIMIT]) -> usize {
    let mut count = 0;
    if pid == current_linux_process_pid() {
        for slot in 0..LINUX_THREAD_LIMIT {
            if X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_FREE {
                tids[count] = X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst);
                count += 1;
            }
        }
    } else if let Some(bank) = (0..LINUX_CPU_BANK_LIMIT).find(|bank| {
        LINUX_BANK_USERS[*bank].load(Ordering::Acquire) != 0
            && LINUX_BANK_PID[*bank].load(Ordering::Acquire) == pid
            && usize::from(LINUX_BANK_INSTANCE[*bank].load(Ordering::Acquire))
                == linux_execution_instance()
    }) {
        // A process live in a bank: its threads as they are now, which its
        // saved record is behind while they run on other CPUs.
        for slot in 0..LINUX_THREAD_LIMIT {
            if X86_RUNTIME.LINUX_THREAD_STATES[slot]
                .at_bank(bank)
                .load(Ordering::Acquire)
                != LINUX_THREAD_FREE
            {
                tids[count] = X86_RUNTIME.LINUX_THREAD_TIDS[slot]
                    .at_bank(bank)
                    .load(Ordering::Acquire);
                count += 1;
            }
        }
    } else if let Some(threads) = linux_process_thread_runtime_state(pid) {
        for thread in threads.iter() {
            if thread.state != LINUX_THREAD_FREE && thread.tid != 0 {
                tids[count] = thread.tid;
                count += 1;
            }
        }
    }
    if count == 0 && linux_process::live_process_status(pid).is_some() {
        tids[0] = pid;
        count = 1;
    }
    count
}

/// The /proc/sys directory at `path` (from the root, "proc/sys/..."), with
/// or without a trailing slash: its place in `LINUX_PROC_SYS_DIRECTORIES`.
pub(super) fn linux_proc_sys_directory_index(path: &[u8]) -> Option<usize> {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    LINUX_PROC_SYS_DIRECTORIES
        .iter()
        .position(|directory| *directory == path)
}

pub(super) fn linux_proc_sys_directory_kind(index: usize) -> u16 {
    LINUX_PROC_PID1_DIRECTORY | (LINUX_PROC_SYS_DIRECTORY_FIRST_NODE + ((index as u16) << 8))
}

/// The /proc/sys directory a directory kind names.
pub(super) fn linux_proc_sys_directory_of(kind: u16) -> Option<usize> {
    if kind & (LINUX_DEVICE_DIRECTORY | LINUX_FILE_MASK) != LINUX_PROC_PID1_DIRECTORY {
        return None;
    }
    let index = usize::from(
        (kind & LINUX_ROOT_NODE_MASK).checked_sub(LINUX_PROC_SYS_DIRECTORY_FIRST_NODE)? >> 8,
    );
    (index < LINUX_PROC_SYS_DIRECTORIES.len()).then_some(index)
}

/// The entries of /proc/sys directory `directory` (from the root): its
/// subdirectories, then its values, then the values with kinds of their
/// own that live there, as (inode, dirent type, name).
pub(super) fn linux_proc_sys_children(
    directory: &'static [u8],
) -> impl Iterator<Item = (u64, u8, &'static [u8])> {
    // The values' paths are under /proc.
    let relative = &directory[b"proc/".len()..];
    let child = move |path: &'static [u8]| {
        path.strip_prefix(relative)?
            .strip_prefix(b"/")
            .filter(|name| !name.is_empty() && !name.contains(&b'/'))
    };
    let directories =
        LINUX_PROC_SYS_DIRECTORIES
            .iter()
            .enumerate()
            .filter_map(move |(index, path)| {
                child(&path[b"proc/".len()..])
                    .map(|name| (LINUX_PROC_SYS_DIRECTORY_INODES + index as u64, 4, name))
            });
    let values = LINUX_PROC_SYSCTLS
        .iter()
        .enumerate()
        .filter_map(move |(index, (_, path, _))| {
            child(path).map(|name| (LINUX_PROC_SYSCTL_INODES + index as u64, 8, name))
        });
    let own_kinds: [(&'static [u8], u16); 3] = [
        (b"sys/fs/file-max", LINUX_FILE_PROC_FILE_MAX),
        (b"sys/kernel/hostname", LINUX_FILE_PROC_HOSTNAME),
        (b"sys/kernel/random/boot_id", LINUX_FILE_PROC_BOOT_ID),
    ];
    let own = own_kinds.into_iter().filter_map(move |(path, kind)| {
        child(path).map(|name| (linux_regular_file_inode(kind).unwrap_or(0), 8, name))
    });
    directories.chain(values).chain(own)
}

/// The inode of process `pid`'s /proc directory, as /proc lists it.
pub(super) fn linux_proc_pid_directory_inode(pid: u32) -> u64 {
    match pid {
        1 => 16,
        2 => 23,
        _ => 0x1_0000_0000 + u64::from(pid),
    }
}

/// The process a /proc/PID directory descriptor was opened for (open keeps
/// its pid with the descriptor).
pub(super) fn linux_proc_directory_descriptor_pid(descriptor: u64) -> Option<u32> {
    matches!(
        linux_device_descriptor(descriptor) & !3,
        LINUX_PROC_PID1_DIRECTORY | LINUX_PROC_PID2_DIRECTORY
    )
    .then(|| linux_descriptor_tmp_generation(descriptor))
    .flatten()?
    .checked_sub(1)
}

/// The inode of thread `tid`'s /proc/PID/task directory.
pub(super) fn linux_proc_task_directory_inode(tid: u32) -> u64 {
    0x2_0000_0000 + u64::from(tid)
}

pub(super) fn write_linux_decimal(mut value: u64, output: &mut [u8]) -> usize {
    let mut reversed = [0_u8; 20];
    let mut digits = 0_usize;
    loop {
        reversed[digits] = b'0' + (value % 10) as u8;
        digits += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    if output.len() < digits {
        return 0;
    }
    for index in 0..digits {
        output[index] = reversed[digits - index - 1];
    }
    digits
}

/// The Uid and Gid lines of /proc/PID/status: real, effective, saved and
/// filesystem ids (a domain has one identity, shared by its processes).
/// The capability lines of `/proc/PID/status` for process `pid`: its
/// inheritable, permitted, effective, bounding and ambient sets, as
/// Linux's `%016llx`.
pub(super) fn linux_capability_status(pid: u32) -> Vec<u8> {
    let caps = linux_process::live_process_credentials(pid)
        .unwrap_or(linux_user::Credentials::ROOT)
        .capabilities;
    alloc::format!(
        "CapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\nCapBnd:\t{:016x}\nCapAmb:\t{:016x}\n",
        caps.inheritable, caps.permitted, caps.effective, caps.bounding, caps.ambient,
    )
    .into_bytes()
}

pub(super) fn append_linux_credentials_status(output: &mut [u8], used: &mut usize) -> bool {
    let credentials = current_linux_credentials().unwrap_or(linux_user::Credentials::ROOT);
    [
        (b"Uid:" as &[u8], credentials.user),
        (b"Gid:", credentials.group),
    ]
    .map(|(label, ids)| (label, [ids.real, ids.effective, ids.saved, ids.filesystem]))
    .into_iter()
    .all(|(label, ids)| {
        append_linux_bytes(output, used, label)
            && ids.into_iter().all(|id| {
                append_linux_bytes(output, used, b"\t")
                    && append_linux_decimal(output, used, u64::from(id))
            })
            && append_linux_bytes(output, used, b"\n")
    })
}

pub(super) fn append_linux_bytes(output: &mut [u8], used: &mut usize, bytes: &[u8]) -> bool {
    let Some(destination) = output.get_mut(*used..used.saturating_add(bytes.len())) else {
        return false;
    };
    destination.copy_from_slice(bytes);
    *used += bytes.len();
    true
}

fn linux_generated_chunk(
    chunk: &[u8],
    address: u64,
    requested: usize,
    offset: usize,
    logical: &mut usize,
    copied: &mut usize,
) -> bool {
    let start = *logical;
    *logical = logical.saturating_add(chunk.len());
    if *copied == requested || offset >= *logical || offset.saturating_add(requested) <= start {
        return true;
    }
    let chunk_start = offset.saturating_sub(start);
    let chunk_end = chunk
        .len()
        .min(offset.saturating_add(requested).saturating_sub(start));
    if chunk_start >= chunk_end {
        return true;
    }
    let Some(destination) = address.checked_add(*copied as u64) else {
        return false;
    };
    if !copy_to_linux_user(destination, &chunk[chunk_start..chunk_end]) {
        return false;
    }
    *copied += chunk_end - chunk_start;
    true
}

pub(super) fn linux_cpuinfo_record(cpu: usize, count: usize, output: &mut [u8]) -> Option<usize> {
    let mut used = 0;
    let prefix = b"processor\t: ";
    let middle = b"\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 158\nmodel name\t: Linox virtual x86-64 CPU\nstepping\t: 10\ncpu MHz\t\t: 1000.000\ncache size\t: 16384 KB\nphysical id\t: 0\nsiblings\t: ";
    if !append_linux_bytes(output, &mut used, prefix)
        || !append_linux_decimal(output, &mut used, cpu as u64)
        || !append_linux_bytes(output, &mut used, middle)
        || !append_linux_decimal(output, &mut used, count as u64)
        || !append_linux_bytes(output, &mut used, b"\ncore id\t\t: ")
        || !append_linux_decimal(output, &mut used, cpu as u64)
        || !append_linux_bytes(output, &mut used, b"\ncpu cores\t: ")
        || !append_linux_decimal(output, &mut used, count as u64)
        || !append_linux_bytes(output, &mut used, b"\nfpu\t\t: yes\ncpuid level\t: 13\nflags\t\t: fpu tsc msr pae cx8 apic sep mtrr pge cmov pat clflush mmx fxsr sse sse2 syscall nx lm constant_tsc rep_good nopl xtopology cpuid tsc_known_freq pni ssse3 cx16 sse4_1 sse4_2 x2apic popcnt aes xsave avx rdrand hypervisor\nbogomips\t: 2000.00\nclflush size\t: 64\ncache_alignment\t: 64\naddress sizes\t: 46 bits physical, 48 bits virtual\n\n")
    {
        return None;
    }
    Some(used)
}

pub(super) fn linux_proc_cpuinfo_read(address: u64, count: u64, offset: u64) -> u64 {
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    let Ok(offset) = usize::try_from(offset) else {
        return 0;
    };
    let cpu_count = linux_available_cpu_count();
    let mut logical = 0;
    let mut copied = 0;
    for cpu in 0..cpu_count {
        let mut record = [0_u8; 768];
        let Some(used) = linux_cpuinfo_record(cpu, cpu_count, &mut record) else {
            return LINUX_EIO;
        };
        if !linux_generated_chunk(
            &record[..used],
            address,
            requested,
            offset,
            &mut logical,
            &mut copied,
        ) {
            return LINUX_EFAULT;
        }
    }
    copied as u64
}

/// `/proc/stat`: per CPU, the time spent in user code, in the kernel and
/// idle (`crate::cpu_time`), in USER_HZ (100 per second) units as Linux
/// reports them, and their sum on the `cpu` line.
pub(super) fn linux_proc_stat_file(output: &mut [u8]) -> Option<usize> {
    const USER_HZ: u64 = 100;
    let cpu_count = linux_available_cpu_count();
    let frequency = timer::monotonic_frequency().unwrap_or(1).max(1);
    let ticks =
        |cycles: u64| (u128::from(cycles) * u128::from(USER_HZ) / u128::from(frequency)) as u64;
    let rows: [[u64; 3]; CPU_ENTRY_STATE_LIMIT] = core::array::from_fn(|cpu| {
        crate::cpu_time::times(cpu).map_or([0; 3], |[total, user, idle, _]| {
            let kernel = total.saturating_sub(user).saturating_sub(idle);
            [ticks(user), ticks(kernel), ticks(idle)]
        })
    });
    let shown = cpu_count.min(CPU_ENTRY_STATE_LIMIT);
    let sum = |field: usize| rows[..shown].iter().map(|row| row[field]).sum::<u64>();
    let mut used = 0;
    let line =
        |output: &mut [u8], used: &mut usize, label: &[u8], cpu: Option<u64>, row: [u64; 3]| {
            append_linux_bytes(output, used, label)
                && cpu.is_none_or(|cpu| append_linux_decimal(output, used, cpu))
                && append_linux_bytes(output, used, b" ")
                && append_linux_decimal(output, used, row[0])
                && append_linux_bytes(output, used, b" 0 ")
                && append_linux_decimal(output, used, row[1])
                && append_linux_bytes(output, used, b" ")
                && append_linux_decimal(output, used, row[2])
                && append_linux_bytes(output, used, b" 0 0 0 0 0 0\n")
        };
    if !line(output, &mut used, b"cpu ", None, [sum(0), sum(1), sum(2)]) {
        return None;
    }
    for (cpu, row) in rows[..shown].iter().enumerate() {
        if !line(output, &mut used, b"cpu", Some(cpu as u64), *row) {
            return None;
        }
    }
    if !append_linux_bytes(output, &mut used, b"intr 0\nctxt 1\nbtime 0\nprocesses 1\nprocs_running 1\nprocs_blocked 0\nsoftirq 0 0 0 0 0 0 0 0 0 0 0\n") {
        return None;
    }
    Some(used)
}

pub(super) fn linux_proc_stat_read(address: u64, count: u64, offset: u64) -> u64 {
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    let Ok(offset) = usize::try_from(offset) else {
        return 0;
    };
    let mut file = [0_u8; 2048];
    let Some(used) = linux_proc_stat_file(&mut file) else {
        return LINUX_EIO;
    };
    let mut logical = 0;
    let mut copied = 0;
    if linux_generated_chunk(
        &file[..used],
        address,
        requested,
        offset,
        &mut logical,
        &mut copied,
    ) {
        copied as u64
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn append_linux_decimal(output: &mut [u8], used: &mut usize, value: u64) -> bool {
    let length = write_linux_decimal(value, output.get_mut(*used..).unwrap_or(&mut []));
    if length == 0 {
        return false;
    }
    *used += length;
    true
}

/// `/proc/PID/timens_offsets`: the CLOCK_MONOTONIC and CLOCK_BOOTTIME
/// offsets of the time namespace process `pid`'s children are born into,
/// as Linux prints them (`monotonic  SECONDS NANOSECONDS`).
pub(super) fn linux_proc_timens_offsets(pid: u32, file: &mut [u8], used: &mut usize) -> bool {
    let Some(set) = linux_process::live_process_namespaces(pid) else {
        return false;
    };
    let offsets = linux_namespace::time_offsets(linux_execution_instance(), set.time_for_children);
    let field = |bytes: &[u8], width: usize, file: &mut [u8], used: &mut usize| {
        (bytes.len()..width).all(|_| append_linux_bytes(file, used, b" "))
            && append_linux_bytes(file, used, bytes)
    };
    [
        (b"monotonic" as &[u8], offsets[0]),
        (b"boottime", offsets[1]),
    ]
    .into_iter()
    .all(|(name, offset)| {
        let seconds = offset.div_euclid(NANOSECONDS_PER_SECOND as i64);
        let nanoseconds = offset.rem_euclid(NANOSECONDS_PER_SECOND as i64);
        let mut number = [0_u8; 24];
        let mut length = 0;
        let mut nanosecond_text = [0_u8; 24];
        let mut nanosecond_length = 0;
        append_linux_bytes(file, used, name)
            && (name.len()..10).all(|_| append_linux_bytes(file, used, b" "))
            && append_linux_bytes(file, used, b" ")
            && (seconds >= 0 || append_linux_bytes(&mut number, &mut length, b"-"))
            && append_linux_decimal(&mut number, &mut length, seconds.unsigned_abs())
            && field(&number[..length], 10, file, used)
            && append_linux_bytes(file, used, b" ")
            && append_linux_decimal(
                &mut nanosecond_text,
                &mut nanosecond_length,
                nanoseconds as u64,
            )
            && field(&nanosecond_text[..nanosecond_length], 9, file, used)
            && append_linux_bytes(file, used, b"\n")
    })
}

/// Sets the offsets `/proc/PID/timens_offsets` shows, from lines of a clock
/// (`monotonic` or 1, `boottime` or 7), seconds and nanoseconds: only
/// before a process entered the namespace (EACCES), and only for root over
/// it (EPERM).
pub(super) fn linux_proc_timens_offsets_write(
    descriptor: u64,
    device: u16,
    address: u64,
    count: u64,
) -> u64 {
    if device & 3 & LINUX_DESCRIPTOR_OUTPUT == 0 {
        return LINUX_EBADF;
    }
    let Some(pid) = linux_proc_dynamic_descriptor_pid(descriptor) else {
        return LINUX_EBADF;
    };
    let mut text = [0_u8; 128];
    let Some(length) = usize::try_from(count)
        .ok()
        .filter(|length| *length < text.len())
    else {
        return LINUX_EINVAL;
    };
    if !copy_from_linux_user(address, &mut text[..length]) {
        return LINUX_EFAULT;
    }
    let mut offsets = [None; 2];
    for line in text[..length]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .take(2)
    {
        let mut fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty());
        let (Some(clock), Some(seconds), Some(nanoseconds)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return LINUX_EINVAL;
        };
        let index = match clock {
            b"monotonic" | b"1" => 0,
            b"boottime" | b"7" => 1,
            _ => return LINUX_EINVAL,
        };
        let parse = |field: &[u8]| core::str::from_utf8(field).ok()?.parse::<i64>().ok();
        let (Some(seconds), Some(nanoseconds)) = (parse(seconds), parse(nanoseconds)) else {
            return LINUX_EINVAL;
        };
        if !(0..NANOSECONDS_PER_SECOND as i64).contains(&nanoseconds) {
            return LINUX_EINVAL;
        }
        // The clock moved by the offset stays within what it can show.
        let Some(offset) = seconds
            .checked_mul(NANOSECONDS_PER_SECOND as i64)
            .and_then(|offset| offset.checked_add(nanoseconds))
            .filter(|offset| {
                linux_elapsed_nanoseconds()
                    .is_some_and(|now| i128::from(now) + i128::from(*offset) >= 0)
            })
        else {
            return LINUX_ERANGE;
        };
        offsets[index] = Some(offset);
    }
    let Some(set) = linux_process::live_process_namespaces(pid) else {
        return LINUX_ESRCH;
    };
    let instance = linux_execution_instance();
    if !linux_namespace_capable(linux_namespace::owner(instance, set.time_for_children)) {
        return LINUX_EPERM;
    }
    match linux_namespace::set_time_offsets(instance, set.time_for_children, offsets[0], offsets[1])
    {
        Ok(()) => count,
        Err(linux_namespace::Error::Frozen) => LINUX_EACCES,
        Err(_) => LINUX_EINVAL,
    }
}

pub(super) fn linux_proc_oom_score_adj_write(
    descriptor: u64,
    device: u16,
    address: u64,
    count: u64,
) -> u64 {
    if device & 3 & LINUX_DESCRIPTOR_OUTPUT == 0 {
        return LINUX_EBADF;
    }
    let Some(pid) = linux_proc_dynamic_descriptor_pid(descriptor) else {
        return LINUX_EBADF;
    };
    let mut text = [0_u8; 12];
    let length = usize::try_from(count).map_or(text.len(), |count| count.min(text.len()));
    if !copy_from_linux_user(address, &mut text[..length]) {
        return LINUX_EFAULT;
    }
    let text = text[..length]
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default();
    let Some(value) = linux_parse_kernel_integer(text.trim_ascii())
        .filter(|value| (-1000..=1000).contains(value))
        .and_then(|value| i16::try_from(value).ok())
    else {
        return LINUX_EINVAL;
    };
    if linux_process::set_live_process_oom_score_adj(pid, value) {
        length as u64
    } else {
        LINUX_ESRCH
    }
}

/// Parses an integer as Linux's `kstrtoint(text, 0, ...)`: an optional sign,
/// then decimal, `0x` hexadecimal or `0`-prefixed octal digits.
pub(super) fn linux_parse_kernel_integer(text: &[u8]) -> Option<i64> {
    let (negative, digits) = match text {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, text),
    };
    let (radix, digits) = match digits {
        [b'0', b'x' | b'X', rest @ ..] => (16, rest),
        [b'0', rest @ ..] if !rest.is_empty() => (8, rest),
        _ => (10, digits),
    };
    if digits.is_empty() {
        return None;
    }
    let magnitude = digits.iter().try_fold(0_i64, |value, digit| {
        value
            .checked_mul(i64::from(radix))?
            .checked_add(i64::from(char::from(*digit).to_digit(radix)?))
    })?;
    Some(if negative { -magnitude } else { magnitude })
}

/// /proc/PID/maps: the process's memory areas from its page tables, named
/// where the kernel placed them.
/// Appends one `/proc/PID/maps` line for `[start, end)` of `area`, naming
/// the file `recorded` maps there, or `name` when nothing is recorded.
fn append_linux_maps_line(
    text: &mut Vec<u8>,
    (start, end): (u64, u64),
    area: &address_space::LinuxMemoryArea,
    recorded: Option<&crate::linux_areas::Area>,
    name: &[u8],
) -> Option<()> {
    use crate::linux_areas::Backing;
    // A recorded area keeps the protection and sharing the program asked
    // for (PROT_WRITE alone, a shared PROT_NONE mapping), which the page
    // tables cannot always express.
    let (protection, shared) = recorded.map_or((area.protection, area.shared), |part| {
        (part.protection.bits(), part.shared)
    });
    let flags = [
        if protection & LINUX_PROT_READ as u8 != 0 {
            b'r'
        } else {
            b'-'
        },
        if protection & LINUX_PROT_WRITE as u8 != 0 {
            b'w'
        } else {
            b'-'
        },
        if protection & LINUX_PROT_EXEC as u8 != 0 {
            b'x'
        } else {
            b'-'
        },
        if shared { b's' } else { b'p' },
    ];
    let (offset, device, inode, name) = match recorded.map(|part| (part, &part.backing)) {
        Some((
            part,
            Backing::File {
                device,
                inode,
                offset,
                path,
            },
        )) => (offset + (start - part.start), *device, *inode, &path[..]),
        Some((_, Backing::Heap)) => (0, 0, 0, &b"[heap]"[..]),
        Some((_, Backing::Stack)) => (0, 0, 0, &b"[stack]"[..]),
        _ => (0, 0, 0, name),
    };
    // Linux's encoding: the major number in bits 8-19, the minor in bits
    // 0-7 and 20-31.
    let major = (device >> 8) & 0xfff;
    let minor = device & 0xff | (device >> 12) & 0xfff00;
    let mut line = [0_u8; 160];
    let mut used = 0;
    let fixed = append_linux_hex(&mut line, &mut used, start)
        && append_linux_bytes(&mut line, &mut used, b"-")
        && append_linux_hex(&mut line, &mut used, end)
        && append_linux_bytes(&mut line, &mut used, b" ")
        && append_linux_bytes(&mut line, &mut used, &flags)
        && append_linux_bytes(&mut line, &mut used, b" ")
        && append_linux_padded_hex(&mut line, &mut used, offset, 8)
        && append_linux_bytes(&mut line, &mut used, b" ")
        && append_linux_padded_hex(&mut line, &mut used, major, 2)
        && append_linux_bytes(&mut line, &mut used, b":")
        && append_linux_padded_hex(&mut line, &mut used, minor, 2)
        && append_linux_bytes(&mut line, &mut used, b" ")
        && append_linux_decimal(&mut line, &mut used, inode);
    if !fixed {
        return None;
    }
    // The name starts at column 73, as Linux pads it.
    let padding = if name.is_empty() {
        0
    } else {
        73_usize.saturating_sub(used).max(1)
    };
    text.try_reserve(used + padding + name.len() + 1).ok()?;
    text.extend_from_slice(&line[..used]);
    text.extend(core::iter::repeat_n(b' ', padding));
    text.extend_from_slice(name);
    text.push(b'\n');
    Some(())
}

/// For /proc/PID/smaps (`details` is Some, true for the calling process,
/// whose pages can be counted): the sizes of the area `[start, end)`.
/// Rss counts the pages present (in the caller's own address space; a
/// lazily reserved area of 64 MiB or more is not walked), and Locked is
/// Rss for a locked area.
/// The pages process `pid` has paged out to swap (VmSwap).
pub(super) fn linux_process_swap_pages(pid: u32) -> u64 {
    if pid == current_linux_process_pid() {
        return address_space::current_linux_swap_pages(0, 0).0;
    }
    linux_process::live_process_root(pid)
        .and_then(|root| {
            address_space::with_live_linux_process_root(root, || {
                address_space::current_linux_swap_pages(0, 0).0
            })
        })
        .unwrap_or(0)
}

fn append_linux_smaps_details(
    text: &mut Vec<u8>,
    (start, end): (u64, u64),
    area: &address_space::LinuxMemoryArea,
    recorded: Option<&crate::linux_areas::Area>,
    details: Option<bool>,
) -> Option<()> {
    let Some(countable) = details else {
        return Some(());
    };
    let size = (end - start) / 1024;
    let resident = if countable && end - start < 64 << 20 {
        (start..end)
            .step_by(PAGE_SIZE)
            .filter(|page| {
                address_space::current_linux_runtime_page(*page)
                    .frame
                    .is_some()
            })
            .count() as u64
            * (PAGE_SIZE as u64 / 1024)
    } else {
        0
    };
    // Pages out in swap: the area's own, and for a shared mapping its
    // file's (shared memory's) pages that are.
    let swapped = if countable {
        let shared = recorded
            .filter(|part| part.shared && end - start < 64 << 20)
            .map_or(0, |part| {
                linux_swapon::linux_shared_swapped_pages(part, start, end)
            });
        (address_space::current_linux_swap_pages(start, end).1 + shared) * (PAGE_SIZE as u64 / 1024)
    } else {
        0
    };
    let locked = if recorded.is_some_and(|part| part.locked) {
        resident
    } else {
        0
    };
    let anonymous = if area.shared { 0 } else { resident };
    let fields: [(&[u8], u64); 18] = [
        (b"Size", size),
        (b"KernelPageSize", PAGE_SIZE as u64 / 1024),
        (b"MMUPageSize", PAGE_SIZE as u64 / 1024),
        (b"Rss", resident),
        (b"Pss", resident),
        (b"Pss_Dirty", resident),
        (b"Shared_Clean", 0),
        (b"Shared_Dirty", 0),
        (b"Private_Clean", 0),
        (b"Private_Dirty", resident),
        (b"Referenced", resident),
        (b"Anonymous", anonymous),
        (b"LazyFree", 0),
        (b"AnonHugePages", 0),
        (b"ShmemPmdMapped", 0),
        (b"Swap", swapped),
        (b"SwapPss", swapped),
        (b"Locked", locked),
    ];
    for (name, value) in fields {
        let mut line = [0_u8; 64];
        let mut used = 0;
        let mut value_text = [0_u8; 24];
        let mut value_used = 0;
        if !append_linux_decimal(&mut value_text, &mut value_used, value) {
            return None;
        }
        // "Name:" padded to 16 columns, the value right-aligned in 8.
        let label_ok = append_linux_bytes(&mut line, &mut used, name)
            && append_linux_bytes(&mut line, &mut used, b":");
        if !label_ok {
            return None;
        }
        let pad = 16_usize.saturating_sub(used) + 8_usize.saturating_sub(value_used);
        text.try_reserve(used + pad + value_used + 4).ok()?;
        text.extend_from_slice(&line[..used]);
        text.extend(core::iter::repeat_n(b' ', pad.max(1)));
        text.extend_from_slice(&value_text[..value_used]);
        text.extend_from_slice(b" kB\n");
    }
    let mut flags = Vec::new();
    flags.try_reserve(40).ok()?;
    flags.extend_from_slice(b"VmFlags:");
    for (bit, flag) in [
        (LINUX_PROT_READ as u8, &b" rd"[..]),
        (LINUX_PROT_WRITE as u8, &b" wr"[..]),
        (LINUX_PROT_EXEC as u8, &b" ex"[..]),
    ] {
        if area.protection & bit != 0 {
            flags.extend_from_slice(flag);
        }
    }
    if area.shared {
        flags.extend_from_slice(b" sh");
    }
    flags.extend_from_slice(b" mr mw me");
    if recorded.is_some_and(|part| part.locked) {
        flags.extend_from_slice(b" lo");
    }
    flags.push(b'\n');
    text.try_reserve(flags.len()).ok()?;
    text.extend_from_slice(&flags);
    Some(())
}

/// Appends `value` in lowercase hex, zero-padded to at least `width` digits.
fn append_linux_padded_hex(output: &mut [u8], used: &mut usize, value: u64, width: usize) -> bool {
    let digits = (64 - value.leading_zeros() as usize).div_ceil(4).max(width);
    let Some(field) = output.get_mut(*used..*used + digits) else {
        return false;
    };
    for (index, byte) in field.iter_mut().enumerate() {
        let shift = 4 * (digits - 1 - index);
        let nibble = if shift < 64 {
            (value >> shift) & 0xf
        } else {
            0
        } as u8;
        *byte = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
    }
    *used += digits;
    true
}

/// /proc/PID/maps, or with `smaps` /proc/PID/smaps: each line followed by
/// the area's sizes.
/// PROCMAP_QUERY: the memory area of the process a /proc/PID/maps
/// descriptor names that holds `query_addr` (or, with
/// COVERING_OR_NEXT_VMA, the first one ending above it) and has the
/// permissions `query_flags` asks for, as /proc/PID/maps shows it: its
/// range, permissions, file offset, device, inode and name (ioctl10).
pub(super) fn linux_procmap_query(descriptor: u64, argument: u64) -> u64 {
    const QUERY_SIZE: usize = 104;
    const VMA_READABLE: u64 = 1;
    const VMA_WRITABLE: u64 = 2;
    const VMA_EXECUTABLE: u64 = 4;
    const VMA_SHARED: u64 = 8;
    const COVERING_OR_NEXT_VMA: u64 = 0x10;
    const FILE_BACKED_VMA: u64 = 0x20;
    let mut query = [0_u8; QUERY_SIZE];
    if !copy_from_linux_user(argument, &mut query[..8]) {
        return LINUX_EFAULT;
    }
    let size = u64::from_ne_bytes(query[..8].try_into().unwrap());
    if size < 24 {
        return LINUX_EINVAL;
    }
    if size > PAGE_SIZE as u64 {
        return LINUX_E2BIG;
    }
    let used = (size as usize).min(QUERY_SIZE);
    if !copy_from_linux_user(argument, &mut query[..used]) {
        return LINUX_EFAULT;
    }
    let field = |offset: usize| u64::from_ne_bytes(query[offset..offset + 8].try_into().unwrap());
    let flags = field(8);
    let address = field(16);
    let name_size = u32::from_ne_bytes(query[80..84].try_into().unwrap());
    let name_address = field(88);
    if flags
        & !(VMA_READABLE
            | VMA_WRITABLE
            | VMA_EXECUTABLE
            | VMA_SHARED
            | COVERING_OR_NEXT_VMA
            | FILE_BACKED_VMA)
        != 0
        || name_size != 0 && name_address == 0
    {
        return LINUX_EINVAL;
    }
    let Some(pid) = linux_proc_dynamic_descriptor_pid(descriptor) else {
        return LINUX_ESRCH;
    };
    let Some(maps) = linux_proc_maps(pid, false) else {
        return LINUX_ESRCH;
    };
    let hex = |text: &[u8]| {
        text.iter().try_fold(0_u64, |value, byte| {
            let digit = char::from(*byte).to_digit(16)?;
            value.checked_mul(16)?.checked_add(u64::from(digit))
        })
    };
    let wanted = flags & (VMA_READABLE | VMA_WRITABLE | VMA_EXECUTABLE | VMA_SHARED);
    for line in maps.split(|byte| *byte == b'\n') {
        let mut fields = line
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty());
        let (Some(range), Some(permissions), Some(offset), Some(device), Some(inode)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let name = fields.next().unwrap_or(&[]);
        let Some(dash) = range.iter().position(|byte| *byte == b'-') else {
            continue;
        };
        let (Some(start), Some(end), Some(offset)) =
            (hex(&range[..dash]), hex(&range[dash + 1..]), hex(offset))
        else {
            continue;
        };
        if end <= address || flags & COVERING_OR_NEXT_VMA == 0 && start > address {
            continue;
        }
        let vma_flags = [
            (b'r', VMA_READABLE),
            (b'w', VMA_WRITABLE),
            (b'x', VMA_EXECUTABLE),
            (b's', VMA_SHARED),
        ]
        .into_iter()
        .filter(|(letter, _)| permissions.contains(letter))
        .fold(0, |flags, (_, flag)| flags | flag);
        let inode = core::str::from_utf8(inode)
            .ok()
            .and_then(|inode| inode.parse::<u64>().ok())
            .unwrap_or(0);
        let matches = vma_flags & wanted == wanted && (flags & FILE_BACKED_VMA == 0 || inode != 0);
        if !matches {
            if flags & COVERING_OR_NEXT_VMA != 0 {
                continue;
            }
            return LINUX_ENOENT;
        }
        let (major, minor) = device
            .iter()
            .position(|byte| *byte == b':')
            .map_or((0, 0), |colon| {
                (
                    hex(&device[..colon]).unwrap_or(0),
                    hex(&device[colon + 1..]).unwrap_or(0),
                )
            });
        query[24..32].copy_from_slice(&start.to_ne_bytes());
        query[32..40].copy_from_slice(&end.to_ne_bytes());
        query[40..48].copy_from_slice(&vma_flags.to_ne_bytes());
        query[48..56].copy_from_slice(&(PAGE_SIZE as u64).to_ne_bytes());
        query[56..64].copy_from_slice(&offset.to_ne_bytes());
        query[64..72].copy_from_slice(&inode.to_ne_bytes());
        query[72..76].copy_from_slice(&(major as u32).to_ne_bytes());
        query[76..80].copy_from_slice(&(minor as u32).to_ne_bytes());
        // No build ID is kept.
        query[84..88].copy_from_slice(&0_u32.to_ne_bytes());
        if name_size != 0 {
            let named = if name.is_empty() {
                0
            } else {
                if (name.len() + 1) as u64 > u64::from(name_size) {
                    return LINUX_ENAMETOOLONG;
                }
                let mut text = [0_u8; 512];
                let length = name.len().min(text.len() - 1);
                text[..length].copy_from_slice(&name[..length]);
                if !copy_to_linux_user(name_address, &text[..length + 1]) {
                    return LINUX_EFAULT;
                }
                length as u32 + 1
            };
            query[80..84].copy_from_slice(&named.to_ne_bytes());
        }
        return if copy_to_linux_user(argument, &query[..used]) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    LINUX_ENOENT
}

pub(super) fn linux_proc_maps(pid: u32, smaps: bool) -> Option<Vec<u8>> {
    let current = pid == current_linux_process_pid();
    let details = smaps.then_some(current);
    let root = if current {
        address_space::current_root_address()
    } else {
        linux_process::live_process_root(pid)?.address()
    };
    let stack = current.then(|| {
        X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst)
            ..X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst)
    });
    // Ranges and protections come from the page tables; the process's
    // recorded areas add the file, offset and name of what it mapped.
    let recorded =
        crate::linux_areas::snapshot(linux_execution_instance(), pid).unwrap_or_default();
    let mut text = Vec::new();
    for area in address_space::linux_memory_areas(root) {
        let name: &[u8] = if area.start == crate::linux_elf::VVAR_ADDRESS {
            b"[vvar]"
        } else if area.start == crate::linux_elf::VDSO_ADDRESS {
            b"[vdso]"
        } else if stack
            .as_ref()
            .is_some_and(|stack| stack.contains(&area.start))
        {
            b"[stack]"
        } else {
            b""
        };
        let mut cursor = area.start;
        for part in recorded
            .iter()
            .filter(|part| part.start < area.end && area.start < part.end)
        {
            if part.start > cursor {
                append_linux_maps_line(&mut text, (cursor, part.start), &area, None, name)?;
                append_linux_smaps_details(&mut text, (cursor, part.start), &area, None, details)?;
            }
            let start = cursor.max(part.start);
            let end = part.end.min(area.end);
            append_linux_maps_line(&mut text, (start, end), &area, Some(part), name)?;
            append_linux_smaps_details(&mut text, (start, end), &area, Some(part), details)?;
            cursor = end;
        }
        if cursor < area.end {
            append_linux_maps_line(&mut text, (cursor, area.end), &area, None, name)?;
            append_linux_smaps_details(&mut text, (cursor, area.end), &area, None, details)?;
        }
    }
    Some(text)
}

/// Appends `value` in lowercase hex, at least eight digits, as /proc/PID/maps
/// prints addresses.
pub(super) fn append_linux_hex(output: &mut [u8], used: &mut usize, value: u64) -> bool {
    let digits = (16 - value.leading_zeros() as usize / 4).max(8);
    let Some(target) = output.get_mut(*used..*used + digits) else {
        return false;
    };
    for (index, byte) in target.iter_mut().enumerate() {
        let shift = (digits - 1 - index) * 4;
        *byte = b"0123456789abcdef"[(value >> shift & 15) as usize];
    }
    *used += digits;
    true
}

/// Whether descriptors of kind `state` keep a /proc value of their own in
/// the generation slot open fills (`linux_openat_path`) instead of an
/// overlay or tmpfs node's generation.
pub(super) fn linux_proc_generation_kind(state: u16) -> bool {
    matches!(
        state & !3,
        LINUX_FILE_PROC_DYNAMIC_STAT
            | LINUX_FILE_PROC_DYNAMIC_STATUS
            | LINUX_FILE_PROC_DYNAMIC_STATM
            | LINUX_FILE_PROC_DYNAMIC_IO
            | LINUX_FILE_PROC_DYNAMIC_MAPS
            | LINUX_FILE_PROC_DYNAMIC_SMAPS
            | LINUX_FILE_PROC_DYNAMIC_PAGEMAP
            | LINUX_FILE_PROC_OOM_SCORE_ADJ
            | LINUX_FILE_PROC_TASK_COMM
            | LINUX_FILE_PROC_TASK_STAT
            | LINUX_PROC_TASK_DIRECTORY
            | LINUX_PROC_PID1_DIRECTORY
            | LINUX_PROC_PID2_DIRECTORY
            | LINUX_FILE_PROC_FDINFO
            | LINUX_FILE_PROC_MOUNTS
    )
}

/// The process whose /proc directory `descriptor` has open (`/proc/PID`
/// or `/proc/self`), while that process lives: Linux's pidfd_send_signal
/// takes such a descriptor as a pidfd.
pub(super) fn linux_proc_directory_descriptor_process(descriptor: u64) -> Option<u32> {
    if !matches!(
        linux_device_descriptor(descriptor) & !3,
        LINUX_PROC_PID1_DIRECTORY | LINUX_PROC_PID2_DIRECTORY
    ) {
        return None;
    }
    let pid = linux_descriptor_tmp_generation(descriptor)?.checked_sub(1)?;
    linux_process::live_process_status(pid)
        .filter(|status| status.state != linux_process::LiveProcessState::Zombie)
        .map(|_| pid)
}

pub(super) fn linux_proc_dynamic_descriptor_pid(descriptor: u64) -> Option<u32> {
    matches!(
        linux_device_descriptor(descriptor) & !3,
        LINUX_FILE_PROC_DYNAMIC_STAT
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
            | LINUX_PROC_TASK_DIRECTORY
    )
    .then(|| linux_descriptor_tmp_generation(descriptor))
    .flatten()?
    .checked_sub(1)
}

pub(super) fn linux_proc_file(state: u16) -> bool {
    let kind = state & !3;
    matches!(
        kind,
        LINUX_FILE_PROC_STATUS
            | LINUX_FILE_PROC_PID2_STATUS
            | LINUX_FILE_PROC_MOUNTINFO
            | LINUX_FILE_PROC_UID_MAP
            | LINUX_FILE_PROC_GID_MAP
            | LINUX_FILE_PROC_SETGROUPS
            | LINUX_FILE_PROC_CPUINFO
            | LINUX_FILE_PROC_SYSVIPC_MSG
            | LINUX_FILE_PROC_SYSVIPC_SHM
            | LINUX_FILE_PROC_SYSVIPC_SEM
            | LINUX_FILE_PROC_MEMINFO
            | LINUX_FILE_PROC_STAT
            | LINUX_FILE_PROC_UPTIME
            | LINUX_FILE_PROC_LOADAVG
            | LINUX_FILE_PROC_FILESYSTEMS
            | LINUX_FILE_PROC_MODULES
            | LINUX_FILE_PROC_KEYS
            | LINUX_FILE_PROC_KEY_USERS
            | LINUX_FILE_PROC_SWAPS
            | LINUX_FILE_PROC_CONFIG
            | LINUX_FILE_PROC_CMDLINE
            | LINUX_FILE_PROC_PID1_STAT
            | LINUX_FILE_PROC_PID1_STATM
            | LINUX_FILE_PROC_PID2_STAT
            | LINUX_FILE_PROC_PID2_STATM
            | LINUX_FILE_PROC_CGROUP
            | LINUX_FILE_PROC_COREDUMP_FILTER
            | LINUX_FILE_PROC_PROCESS_CMDLINE
            | LINUX_FILE_PROC_PROCESS_ENVIRON
            | LINUX_FILE_PROC_FILE_MAX
            | LINUX_FILE_PROC_NR_OPEN
            | LINUX_FILE_PROC_OOM_SCORE_ADJ
            | LINUX_FILE_PROC_TIMENS_OFFSETS
            | LINUX_FILE_PROC_SYSRQ_TRIGGER
            | LINUX_FILE_PROC_USER_NAMESPACE
            | LINUX_FILE_PROC_FDINFO
            | LINUX_FILE_PROC_HOSTNAME
            | LINUX_FILE_PROC_BOOT_ID
            | LINUX_FILE_PROC_DYNAMIC_STAT
            | LINUX_FILE_PROC_DYNAMIC_STATUS
            | LINUX_FILE_PROC_DYNAMIC_STATM
            | LINUX_FILE_PROC_DYNAMIC_IO
            | LINUX_FILE_PROC_DYNAMIC_MAPS
            | LINUX_FILE_PROC_DYNAMIC_SMAPS
            | LINUX_FILE_PROC_DYNAMIC_PAGEMAP
            | LINUX_FILE_PROC_DYNAMIC_MEM
            | LINUX_FILE_PROC_TASK_COMM
            | LINUX_FILE_PROC_TASK_STAT
            | LINUX_FILE_PROC_MOUNTS
    ) || linux_proc_sysctl(state).is_some()
}

/// `/proc/PID/mountinfo` (`mountinfo`) or `/proc/mounts`: the kernel's
/// own mounts, then the domain mounts of the current mount namespace that
/// lie under the process's root, as Linux formats them (mountinfo's
/// optional fields show peer groups and masters).
pub(super) fn linux_proc_mount_table(mountinfo: bool) -> Option<Vec<u8>> {
    let kernel = if mountinfo {
        linux_mount::current_mountinfo()?
    } else {
        linux_mount::current_mounts()?
    };
    let mut file = Vec::new();
    file.try_reserve(kernel.len() + 256).ok()?;
    file.extend_from_slice(kernel);
    // Spaces, tabs, newlines and backslashes in names are octal escapes.
    let escaped = |text: &[u8], line: &mut [u8], used: &mut usize| {
        text.iter().all(|byte| match byte {
            b' ' | b'\t' | b'\n' | b'\\' => append_linux_bytes(
                line,
                used,
                &[
                    b'\\',
                    b'0' + (byte >> 6),
                    b'0' + ((byte >> 3) & 7),
                    b'0' + (byte & 7),
                ],
            ),
            _ => append_linux_bytes(line, used, &[*byte]),
        })
    };
    let mut complete = true;
    crate::linux_mounts::for_each(linux_mount_space(), |mount| {
        let mut point = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
        let mut point_length = 0;
        if linux_shown_mount_point(&mount.path, &mut point, &mut point_length).is_none() {
            return;
        }
        let mut line = [0_u8; 4 * crate::linux_overlay::PATH_CAPACITY + 256];
        let mut used = 0;
        let sharing = mount.sharing;
        let written = if mountinfo {
            append_linux_decimal(&mut line, &mut used, u64::from(mount.id))
                && append_linux_bytes(&mut line, &mut used, b" ")
                && append_linux_decimal(&mut line, &mut used, u64::from(mount.parent))
                && append_linux_bytes(&mut line, &mut used, b" ")
                && append_linux_decimal(
                    &mut line,
                    &mut used,
                    u64::from(linux_device_numbers(mount.device).0),
                )
                && append_linux_bytes(&mut line, &mut used, b":")
                && append_linux_decimal(
                    &mut line,
                    &mut used,
                    u64::from(linux_device_numbers(mount.device).1),
                )
                && append_linux_bytes(&mut line, &mut used, b" /")
                && escaped(&mount.root, &mut line, &mut used)
                && append_linux_bytes(&mut line, &mut used, b" ")
                && escaped(&point[..point_length], &mut line, &mut used)
                && append_linux_bytes(&mut line, &mut used, b" ")
                && linux_mount_options(mount.flags, &mut line, &mut used)
                && (sharing.peer_group == 0
                    || append_linux_bytes(&mut line, &mut used, b" shared:")
                        && append_linux_decimal(
                            &mut line,
                            &mut used,
                            u64::from(sharing.peer_group),
                        ))
                && (sharing.master == 0
                    || append_linux_bytes(&mut line, &mut used, b" master:")
                        && append_linux_decimal(&mut line, &mut used, u64::from(sharing.master)))
                && (!sharing.unbindable || append_linux_bytes(&mut line, &mut used, b" unbindable"))
                && append_linux_bytes(&mut line, &mut used, b" - ")
                && escaped(&mount.filesystem, &mut line, &mut used)
                && append_linux_bytes(&mut line, &mut used, b" ")
                && escaped(&mount.source, &mut line, &mut used)
                && append_linux_bytes(
                    &mut line,
                    &mut used,
                    if mount.flags & crate::linux_mounts::READ_ONLY != 0 {
                        b" ro"
                    } else {
                        b" rw"
                    },
                )
                && append_linux_bytes(&mut line, &mut used, &linux_super_options(mount))
                && append_linux_bytes(&mut line, &mut used, b"\n")
        } else {
            escaped(&mount.source, &mut line, &mut used)
                && append_linux_bytes(&mut line, &mut used, b" ")
                && escaped(&point[..point_length], &mut line, &mut used)
                && append_linux_bytes(&mut line, &mut used, b" ")
                && escaped(&mount.filesystem, &mut line, &mut used)
                && append_linux_bytes(&mut line, &mut used, b" ")
                && linux_mount_options(mount.flags, &mut line, &mut used)
                && append_linux_bytes(&mut line, &mut used, &linux_super_options(mount))
                && append_linux_bytes(&mut line, &mut used, b" 0 0\n")
        };
        if written && file.try_reserve(used).is_ok() {
            file.extend_from_slice(&line[..used]);
        } else {
            complete = false;
        }
    });
    complete.then_some(file)
}

/// The filesystem's own options a mount shows after its mount options
/// (ext4's errors= and quota options), each with its comma.
fn linux_super_options(mount: &crate::linux_mounts::Mount) -> Vec<u8> {
    if linux_volume_type(&mount.filesystem).is_some() {
        crate::linux_blockfs::shown_options(mount.device)
    } else {
        Vec::new()
    }
}

pub(super) fn linux_mountinfo_file(state: u16) -> bool {
    state & !3 == LINUX_FILE_PROC_MOUNTINFO
}

pub(super) fn linux_writable_proc_file(state: u16) -> bool {
    matches!(
        state & !3,
        LINUX_FILE_PROC_FILE_MAX
            | LINUX_FILE_PROC_NR_OPEN
            | LINUX_FILE_PROC_OOM_SCORE_ADJ
            | LINUX_FILE_PROC_DYNAMIC_MEM
            | LINUX_FILE_PROC_TIMENS_OFFSETS
            | LINUX_FILE_PROC_SYSRQ_TRIGGER
            | LINUX_FILE_PROC_UID_MAP
            | LINUX_FILE_PROC_GID_MAP
            | LINUX_FILE_PROC_SETGROUPS
    ) || linux_proc_sysctl_index(state).is_some()
}

pub(super) fn linux_user_namespace_file(state: u16) -> Option<&'static [u8]> {
    let namespace = current_linux_user_namespace()?;
    match state & !3 {
        LINUX_FILE_PROC_UID_MAP | LINUX_FILE_PROC_GID_MAP => Some(linux_user::id_map(namespace)),
        LINUX_FILE_PROC_SETGROUPS => Some(linux_user::setgroups_file(namespace)),
        _ => None,
    }
}

/// Renders /proc/meminfo from the frame allocator's counts.
/// /proc/uptime: seconds since boot, and idle time, which Linox does not
/// account and reports as zero.
pub(super) fn linux_proc_uptime() -> Option<RegularFile> {
    // CLOCK_BOOTTIME as the reader's time namespace shows it.
    let centiseconds = linux_elapsed_nanoseconds()
        .unwrap_or(0)
        .saturating_add_signed(linux_time_namespace_offset(LINUX_CLOCK_BOOTTIME))
        / 10_000_000;
    let mut digits = [0_u8; 20];
    let mut value = centiseconds / 100;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut buffer = [0_u8; 32];
    let mut length = 0;
    for digit in digits[..count].iter().rev() {
        buffer[length] = *digit;
        length += 1;
    }
    let fraction = centiseconds % 100;
    for byte in [
        b'.',
        b'0' + (fraction / 10) as u8,
        b'0' + (fraction % 10) as u8,
    ]
    .into_iter()
    .chain(*b" 0.00\n")
    {
        buffer[length] = byte;
        length += 1;
    }
    RegularFile::generated(&buffer[..length])
}

/// The frames the current domain counts as its memory (total, free): the
/// machine's, bounded by the domain's memory budget (CONTAINER_MEMORY_MIB)
/// less what is in use, so a program checking for space before writing a
/// large file into the domain's ramfs stops at the budget instead of
/// running the domain out of memory (sendfile09's 5 GB file).
pub(super) fn linux_domain_frame_counts() -> (u64, u64) {
    let (total, free) = memory::frame_counts().unwrap_or((0, 0));
    let Some(budget) = current_container_slot()
        .map(|slot| X86_RUNTIME.CONTAINER_MEMORY_MIB[slot].load(Ordering::Acquire))
        .filter(|mib| *mib != 0)
        .map(|mib| mib * (1 << 20) / PAGE_SIZE as u64)
    else {
        return (total, free);
    };
    let used = total.saturating_sub(free);
    (total.min(budget), free.min(budget.saturating_sub(used)))
}

pub(super) fn linux_proc_meminfo() -> Option<RegularFile> {
    struct Buffer {
        bytes: [u8; 1024],
        length: usize,
    }
    impl core::fmt::Write for Buffer {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let end = self.length + text.len();
            self.bytes
                .get_mut(self.length..end)
                .ok_or(core::fmt::Error)?
                .copy_from_slice(text.as_bytes());
            self.length = end;
            Ok(())
        }
    }
    let (total, free) = linux_domain_frame_counts();
    let (total, free) = (total * 4, free * 4);
    let used = total - free;
    let huge = linux_huge_page_counts();
    let kernel_stack = activation::kernel_stack_bytes() / 1024;
    let slab = crate::heap::slab_bytes() / 1024;
    let (swap_total, swap_free) = crate::linux_swap::totals(linux_execution_instance());
    let swap_cached = crate::linux_swap::cached_pages(linux_execution_instance()) * 4;
    let mut buffer = Buffer {
        bytes: [0; 1024],
        length: 0,
    };
    let _ = core::fmt::Write::write_fmt(
        &mut buffer,
        format_args!(
            "MemTotal:       {total:>10} kB\nMemFree:        {free:>10} kB\n\
             MemAvailable:   {free:>10} kB\nBuffers:        {zero:>10} kB\n\
             Cached:         {zero:>10} kB\nSwapCached:     {swap_cached:>10} kB\n\
             Active:         {used:>10} kB\nInactive:       {zero:>10} kB\n\
             SwapTotal:      {swap_total:>10} kB\nSwapFree:       {swap_free:>10} kB\n\
             Slab:           {slab:>10} kB\nSReclaimable:   {zero:>10} kB\n\
             SUnreclaim:     {slab:>10} kB\nKernelStack:    {kernel_stack:>10} kB\n\
             CommitLimit:    {total:>10} kB\nCommitted_AS:   {used:>10} kB\n\
             VmallocTotal:   13743895347199 kB\n\
             HugePages_Total:   {huge_total:>5}\nHugePages_Free:    {huge_free:>5}\n\
             HugePages_Rsvd:    {huge_reserved:>5}\nHugePages_Surp:    {huge_surplus:>5}\n\
             Hugepagesize:       2048 kB\nHugetlb:        {hugetlb:>10} kB\n\
             DirectMap4k:    {total:>10} kB\n",
            zero = 0,
            huge_total = huge.total,
            huge_free = huge.free,
            huge_reserved = huge.reserved,
            huge_surplus = huge.surplus,
            hugetlb = huge.total * 2048,
        ),
    );
    RegularFile::generated(&buffer.bytes[..buffer.length])
}

/// The program the link at absolute `path` names, when it is
/// /proc/self/exe, /proc/thread-self/exe or /proc/PID/exe: the file that
/// process executed (Linux's proc_exe_link). ENOENT for no such process or
/// one with no program recorded, EACCES for a process the caller may not
/// look into (ptrace_may_access). None for any other path.
pub(super) fn linux_proc_exe_link(path: &[u8]) -> Option<Result<Vec<u8>, u64>> {
    let process = path.strip_prefix(b"/proc/")?.strip_suffix(b"/exe")?;
    let caller = current_linux_process_pid();
    let pid = match process {
        b"self" | b"thread-self" => caller,
        digits if !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) => {
            match core::str::from_utf8(digits)
                .ok()
                .and_then(|digits| digits.parse::<u32>().ok())
            {
                Some(pid) => pid,
                None => return Some(Err(LINUX_ENOENT)),
            }
        }
        _ => return None,
    };
    if pid != caller {
        if linux_process::live_process_status(pid).is_none() {
            return Some(Err(LINUX_ENOENT));
        }
        if !linux_ptrace_access_permitted(pid) {
            return Some(Err(LINUX_EACCES));
        }
    }
    Some(
        crate::linux_exe::lookup(
            X86_RUNTIME.LINUX_EXECUTION_INSTANCE.load(Ordering::SeqCst),
            pid,
        )
        .ok_or(LINUX_ENOENT),
    )
}

/// The path of the program the calling process runs, when `path` (from
/// `directory`) is its /proc/self/exe or /proc/PID/exe.
pub(super) fn linux_proc_self_exe_target(directory: u64, path: &[u8]) -> Option<Vec<u8>> {
    let pid = current_linux_process_pid();
    let process = path.strip_prefix(b"/proc/")?.strip_suffix(b"/exe")?;
    let own = process == b"self"
        || !process.is_empty()
            && process.iter().all(u8::is_ascii_digit)
            && core::str::from_utf8(process)
                .ok()
                .and_then(|digits| digits.parse::<u32>().ok())
                == Some(pid);
    if directory as u32 != LINUX_AT_FDCWD || !own {
        return None;
    }
    crate::linux_exe::lookup(
        X86_RUNTIME.LINUX_EXECUTION_INSTANCE.load(Ordering::SeqCst),
        pid,
    )
}

/// stat or lstat (`follow` false) of /proc/self/exe or /proc/PID/exe of the
/// calling process: the symlink itself, or the file it runs. `None` for
/// any other path. rustup's installer checks `test -L /proc/self/exe`.
pub(super) fn linux_proc_self_exe_stat(
    directory: u64,
    path: &[u8],
    follow: bool,
) -> Option<[u8; LINUX_STAT_SIZE]> {
    const SYMLINK_MODE: u32 = 0o120_777;
    let executable = linux_proc_self_exe_target(directory, path)?;
    if !follow {
        let mut stat = linux_stat(SYMLINK_MODE, 0);
        stat[48..56].copy_from_slice(&(executable.len() as u64).to_ne_bytes());
        return Some(stat);
    }
    let relative = executable.strip_prefix(b"/")?;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    canonical
        .get_mut(..relative.len())?
        .copy_from_slice(relative);
    match linux_overlay_lookup_following(&mut canonical, relative.len(), true).ok()? {
        (_, _, Some(metadata)) => Some(linux_overlay_stat(metadata)),
        (length, _, None) => {
            let mut absolute = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
            absolute[0] = b'/';
            absolute[1..=length].copy_from_slice(&canonical[..length]);
            let (handle, entry) =
                linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), &absolute[..=length])?;
            Some(linux_rootfs_stat(handle, entry))
        }
    }
}

pub(super) fn linux_sysfs(option: u64, first: u64, second: u64) -> u64 {
    const FILE_SYSTEMS: [&[u8]; 4] = [b"rootfs", b"proc", b"tmpfs", b"devtmpfs"];

    match u64::from(option as u32) {
        1 => {
            let mut name = [0_u8; 32];
            let length = match copy_linux_c_string(first, &mut name) {
                Ok(length) => length,
                Err(error) => return error,
            };
            FILE_SYSTEMS
                .iter()
                .position(|candidate| *candidate == &name[..length])
                .map_or(LINUX_EINVAL, |index| index as u64)
        }
        2 => {
            let Some(name) = usize::try_from(first)
                .ok()
                .and_then(|index| FILE_SYSTEMS.get(index))
            else {
                return LINUX_EINVAL;
            };
            let mut output = [0_u8; 9];
            output[..name.len()].copy_from_slice(name);
            if copy_to_linux_user(second, &output[..name.len() + 1]) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        3 => FILE_SYSTEMS.len() as u64,
        _ => LINUX_EINVAL,
    }
}
