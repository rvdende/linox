use super::*;

pub(super) fn linux_default_resource_limit(resource: u64, runtime: bool) -> Option<[u64; 2]> {
    let value = match resource {
        LINUX_RLIMIT_STACK if runtime => return Some([LINUX_STACK_DEFAULT_LIMIT, u64::MAX]),
        LINUX_RLIMIT_STACK => PAGE_SIZE as u64,
        // Linux's defaults (INR_OPEN_CUR, INR_OPEN_MAX): a process may raise
        // its soft limit to 4096 and, with CAP_SYS_RESOURCE, its hard limit
        // to /proc/sys/fs/nr_open; descriptors past the fixed table live in
        // `linux_fd_table`.
        LINUX_RLIMIT_NOFILE if runtime => return Some([LINUX_DESCRIPTOR_TABLE_LIMIT, 4096]),
        LINUX_RLIMIT_NOFILE => LINUX_AUX_DESCRIPTOR_LIMIT,
        // Linux counts every task; the process table and thread slots bound
        // the real capacity.
        LINUX_RLIMIT_NPROC => (linux_process::PROCESS_LIMIT + LINUX_THREAD_LIMIT) as u64,
        // RLIMIT_SIGPENDING: queued signals now count against it, so it is
        // Linux's order of magnitude (max_threads / 2), not one per signal.
        LINUX_RLIMIT_SIGPENDING => 16_384,
        13 | 14 => 0,
        resource if resource < LINUX_RLIMIT_NLIMITS => u64::MAX,
        _ => return None,
    };
    Some([value, value])
}

/// Writes a core file for the current process, ending by `signal`, a
/// core-dumping one, when its RLIMIT_CORE allows: named by the domain's
/// core_pattern (from its working directory; Linux's "core" unless set),
/// an ELF core with the process's NT_PRPSINFO note and a PT_LOAD segment
/// for each area of anonymous memory coredump_filter's default dumps, not
/// marked MADV_DONTDUMP, with the pages it has (the others read as zeros).
/// Whether one was written, which the wait status reports (WCOREDUMP,
/// CLD_DUMPED).
pub(super) fn linux_write_core_file(signal: u64) -> bool {
    use crate::linux_areas::Backing;
    const RLIMIT_CORE: u64 = 4;
    const O_WRONLY: u64 = 1;
    const O_TRUNC: u64 = 0o1000;
    const NOTE_SIZE: usize = 20 + 136;
    const ELF_HEADER: usize = 64;
    const PROGRAM_HEADER: usize = 56;
    const PF_R: u32 = 4;
    const PF_W: u32 = 2;
    const PF_X: u32 = 1;
    let limit = linux_resource_limit_values(RLIMIT_CORE, true).map_or(0, |values| values[0]);
    let pid = current_linux_process_pid();
    let instance = linux_execution_instance();
    // The areas dumped: anonymous memory (the heap and stack too), private
    // and shared, which the default filter 0x33 names.
    let segments: Vec<crate::linux_areas::Area> = crate::linux_areas::snapshot(instance, pid)
        .map(|areas| {
            areas
                .iter()
                .filter(|area| {
                    !area.dont_dump
                        && matches!(
                            area.backing,
                            Backing::Anonymous
                                | Backing::Heap
                                | Backing::Stack
                                | Backing::Droppable
                        )
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let headers = 1 + segments.len();
    let note_offset = ELF_HEADER + headers * PROGRAM_HEADER;
    let data_offset = (note_offset + NOTE_SIZE).next_multiple_of(PAGE_SIZE);
    let size = segments
        .iter()
        .fold(data_offset as u64, |size, area| size + area.len());
    if limit < (note_offset + NOTE_SIZE) as u64 {
        return false;
    }
    let mut core = Vec::new();
    if core.try_reserve_exact(note_offset + NOTE_SIZE).is_err() {
        return false;
    }
    core.resize(note_offset + NOTE_SIZE, 0);
    // ELF header: 64-bit, little-endian, ET_CORE for x86-64, the program
    // headers (PT_NOTE, then the PT_LOADs) right after it.
    core[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    core[16..18].copy_from_slice(&4_u16.to_le_bytes());
    core[18..20].copy_from_slice(&62_u16.to_le_bytes());
    core[20..24].copy_from_slice(&1_u32.to_le_bytes());
    core[32..40].copy_from_slice(&(ELF_HEADER as u64).to_le_bytes());
    core[52..54].copy_from_slice(&(ELF_HEADER as u16).to_le_bytes());
    core[54..56].copy_from_slice(&(PROGRAM_HEADER as u16).to_le_bytes());
    core[56..58].copy_from_slice(&(headers as u16).to_le_bytes());
    let header = ELF_HEADER;
    core[header..header + 4].copy_from_slice(&4_u32.to_le_bytes());
    core[header + 8..header + 16].copy_from_slice(&(note_offset as u64).to_le_bytes());
    core[header + 32..header + 40].copy_from_slice(&(NOTE_SIZE as u64).to_le_bytes());
    core[header + 48..header + 56].copy_from_slice(&4_u64.to_le_bytes());
    let mut offset = data_offset as u64;
    for (index, area) in segments.iter().enumerate() {
        let at = ELF_HEADER + (index + 1) * PROGRAM_HEADER;
        let flags = if area.protection.readable() { PF_R } else { 0 }
            | if area.protection.writable() { PF_W } else { 0 }
            | if area.protection.executable() {
                PF_X
            } else {
                0
            };
        core[at..at + 4].copy_from_slice(&1_u32.to_le_bytes());
        core[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        core[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
        core[at + 16..at + 24].copy_from_slice(&area.start.to_le_bytes());
        core[at + 32..at + 40].copy_from_slice(&area.len().to_le_bytes());
        core[at + 40..at + 48].copy_from_slice(&area.len().to_le_bytes());
        core[at + 48..at + 56].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
        offset += area.len();
    }
    // NT_PRPSINFO: name "CORE", then elf_prpsinfo.
    let note = note_offset;
    core[note..note + 4].copy_from_slice(&5_u32.to_le_bytes());
    core[note + 4..note + 8].copy_from_slice(&136_u32.to_le_bytes());
    core[note + 8..note + 12].copy_from_slice(&3_u32.to_le_bytes());
    core[note + 12..note + 16].copy_from_slice(b"CORE");
    let info = note + 20;
    core[info] = b'R';
    core[info + 1] = b'R';
    if let Some(credentials) = current_linux_credentials() {
        core[info + 16..info + 20].copy_from_slice(&credentials.user.real.to_le_bytes());
        core[info + 20..info + 24].copy_from_slice(&credentials.group.real.to_le_bytes());
    }
    core[info + 24..info + 28].copy_from_slice(&pid.to_le_bytes());
    let parent = linux_process::live_process_parent_pid(pid).unwrap_or(0);
    core[info + 28..info + 32].copy_from_slice(&parent.to_le_bytes());
    let mut name = [0_u8; 16];
    let name = linux_process_name(pid, &mut name);
    let length = name.len().min(15);
    core[info + 40..info + 40 + length].copy_from_slice(&name[..length]);
    core[info + 56..info + 56 + length].copy_from_slice(&name[..length]);
    let (uid, gid) = current_linux_credentials().map_or((0, 0), |credentials| {
        (credentials.user.real, credentials.group.real)
    });
    let mut hostname = [0_u8; LINUX_UTS_NAME_CAPACITY];
    let hostname_length = linux_uts_name(LINUX_UTS_HOST, &mut hostname);
    let uses_pid =
        linux_proc_sysctl_value(b"sys/kernel/core_uses_pid").is_some_and(|value| value != 0);
    let Some(file_name) = crate::linux_core::file_name(
        &crate::linux_core::pattern(instance),
        uses_pid,
        &crate::linux_core::Process {
            pid,
            uid,
            gid,
            signal: signal as u32,
            seconds: linux_realtime_now().0.max(0) as u64,
            name,
            hostname: &hostname[..hostname_length],
        },
    ) else {
        return false;
    };
    let mut path = [0_u8; LINUX_PATH_MAX];
    let Some(target) = path
        .get_mut(..file_name.len())
        .filter(|_| !file_name.is_empty())
    else {
        return false;
    };
    target.copy_from_slice(&file_name);
    let descriptor = linux_openat_path(
        u64::from(LINUX_AT_FDCWD),
        path,
        file_name.len(),
        O_WRONLY | LINUX_O_CREAT | O_TRUNC | LINUX_O_NOFOLLOW,
        0o600,
    );
    if descriptor > u64::MAX - 4096 {
        return false;
    }
    let Some(handle) = linux_overlay_descriptor_handle(descriptor) else {
        let _ = linux_descriptor_close(descriptor);
        return false;
    };
    // The headers and note, then each segment's pages as far as
    // RLIMIT_CORE lets the file grow: a page the process never touched is
    // a hole, which reads as zeros.
    let mut written = crate::linux_overlay::write(handle, 0, &core) == Some(core.len());
    let mut offset = data_offset as u64;
    let mut page = [0_u8; PAGE_SIZE];
    for area in &segments {
        for address in (area.start..area.end).step_by(PAGE_SIZE) {
            let at = offset + (address - area.start);
            if !written || at + PAGE_SIZE as u64 > limit {
                break;
            }
            let state = address_space::current_linux_runtime_page(address);
            if state.frame.is_none() || !copy_from_linux_user(address, &mut page) {
                continue;
            }
            written = crate::linux_overlay::write(handle, at as usize, &page) == Some(PAGE_SIZE);
        }
        offset += area.len();
    }
    // The file is as long as its segments say, holes and all.
    if written && size <= limit {
        let _ = crate::linux_overlay::truncate(handle, size as usize);
    }
    let _ = linux_descriptor_close(descriptor);
    written
}

pub(super) fn linux_resource_limit_values(resource: u64, runtime: bool) -> Option<[u64; 2]> {
    let defaults = linux_default_resource_limit(resource, runtime)?;
    if !X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst) {
        return Some(defaults);
    }
    let index = resource as usize * 2;
    Some([
        X86_RUNTIME.ELF_PROBE_RLIMITS[index].load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_RLIMITS[index + 1].load(Ordering::SeqCst),
    ])
}

fn linux_resource_limit(resource: u64, runtime: bool) -> Option<[u8; 16]> {
    let values = linux_resource_limit_values(resource, runtime)?;
    let mut limit = [0_u8; 16];
    limit[..8].copy_from_slice(&values[0].to_ne_bytes());
    limit[8..].copy_from_slice(&values[1].to_ne_bytes());
    Some(limit)
}

pub(super) fn linux_process_resource_limit_values(pid: u32, resource: u64) -> Option<[u64; 2]> {
    linux_default_resource_limit(
        resource,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    )?;
    if pid == current_linux_process_pid() {
        return linux_resource_limit_values(
            resource,
            X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
        );
    }
    let state = linux_process_runtime_state(pid).filter(|state| state.valid)?;
    let index = resource as usize * 2;
    Some([state.rlimits[index], state.rlimits[index + 1]])
}

pub(super) fn linux_set_process_resource_limit(
    pid: u32,
    resource: u64,
    requested: [u64; 2],
) -> u64 {
    let Some(current) = linux_process_resource_limit_values(pid, resource) else {
        return LINUX_ESRCH;
    };
    if requested[0] > requested[1] {
        return LINUX_EINVAL;
    }
    // Raising a hard limit takes CAP_SYS_RESOURCE: root here. No one
    // raises RLIMIT_NOFILE past nr_open (setrlimit03).
    if requested[1] > current[1]
        && !current_linux_credentials().is_some_and(|credentials| credentials.privileged())
        || resource == LINUX_RLIMIT_NOFILE && requested[1] > linux_nr_open()
    {
        return LINUX_EPERM;
    }
    // RLIMIT_CPU (seconds of CPU time): SIGXCPU at the soft limit and
    // every second after, SIGKILL at the hard one, as timers on the
    // process's CPU clock (interval-timer slots 3 and 4).
    if resource == 0 {
        const SECOND: u64 = 1_000_000_000;
        const SIGXCPU: u8 = 24;
        let deadline = |limit: u64| {
            if limit == u64::MAX {
                0
            } else {
                limit.max(1).saturating_mul(SECOND)
            }
        };
        let _ = linux_process::set_live_process_interval_timer(
            pid,
            3,
            SIGXCPU,
            (SECOND, deadline(requested[0])),
        );
        let _ = linux_process::set_live_process_interval_timer(
            pid,
            4,
            LINUX_SIGKILL as u8,
            (0, deadline(requested[1])),
        );
        linux_refresh_posix_timer_cache(pid);
    }
    let index = resource as usize * 2;
    if pid == current_linux_process_pid() {
        X86_RUNTIME.ELF_PROBE_RLIMITS[index].store(requested[0], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_RLIMITS[index + 1].store(requested[1], Ordering::SeqCst);
        return 0;
    }
    let Some(state) = linux_process_runtime_state(pid).filter(|state| state.valid) else {
        return LINUX_ESRCH;
    };
    state.rlimits[index] = requested[0];
    state.rlimits[index + 1] = requested[1];
    0
}

pub(super) fn linux_prlimit_target(pid: u64) -> Result<u32, u64> {
    let pid = pid as u32 as i32;
    let pid = if pid == 0 {
        current_linux_process_pid()
    } else if pid > 0 {
        pid as u32
    } else {
        return Err(LINUX_ESRCH);
    };
    linux_process::live_process_status(pid)
        .map(|_| pid)
        .ok_or(LINUX_ESRCH)
}

pub(super) fn linux_prlimit_permitted(pid: u32) -> bool {
    if pid == current_linux_process_pid() {
        return true;
    }
    let (Some(caller), Some(target)) = (
        current_linux_credentials(),
        linux_process::live_process_credentials(pid),
    ) else {
        return false;
    };
    caller.privileged() || linux_ids_match(&caller, &target)
}

/// Every user and group id of `target` is `caller`'s real one: what ptrace
/// and prlimit require of a caller without the capability.
pub(super) fn linux_ids_match(
    caller: &linux_user::Credentials,
    target: &linux_user::Credentials,
) -> bool {
    let all_are = |ids: linox_credentials::Ids, id: u32| {
        [ids.real, ids.effective, ids.saved]
            .into_iter()
            .all(|candidate| candidate == id)
    };
    all_are(target.user, caller.user.real) && all_are(target.group, caller.group.real)
}

pub(super) fn linux_prlimit64(pid: u64, resource: u64, new_limit: u64, old_limit: u64) -> u64 {
    let resource = u64::from(resource as u32);
    if resource >= LINUX_RLIMIT_NLIMITS {
        return LINUX_EINVAL;
    }
    let requested = if new_limit == 0 {
        None
    } else {
        let mut bytes = [0_u8; 16];
        if !copy_from_linux_user(new_limit, &mut bytes) {
            return LINUX_EFAULT;
        }
        let values = [
            u64::from_ne_bytes(bytes[..8].try_into().unwrap()),
            u64::from_ne_bytes(bytes[8..].try_into().unwrap()),
        ];
        if values[0] > values[1] {
            return LINUX_EINVAL;
        }
        Some(values)
    };
    let pid = match linux_prlimit_target(pid) {
        Ok(pid) => pid,
        Err(error) => return error,
    };
    if !linux_prlimit_permitted(pid) {
        return LINUX_EPERM;
    }
    let Some(previous) = linux_process_resource_limit_values(pid, resource) else {
        return LINUX_ESRCH;
    };
    if let Some(requested) = requested {
        let result = linux_set_process_resource_limit(pid, resource, requested);
        if result != 0 {
            return result;
        }
    }
    if old_limit != 0 {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&previous[0].to_ne_bytes());
        bytes[8..].copy_from_slice(&previous[1].to_ne_bytes());
        if !copy_to_linux_user(old_limit, &bytes) {
            return LINUX_EFAULT;
        }
    }
    0
}

pub(super) fn linux_file_size_limit() -> u64 {
    linux_resource_limit_values(
        LINUX_RLIMIT_FSIZE,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    )
    .map_or(0, |limit| limit[0])
}

pub(super) fn linux_file_write_limit(start: usize, requested: usize) -> Result<usize, u64> {
    if requested == 0 {
        return Ok(0);
    }
    let limit = linux_file_size_limit();
    if limit == u64::MAX {
        return Ok(requested);
    }
    let start = start as u64;
    if start >= limit {
        X86_RUNTIME
            .LINUX_FSIZE_LIMIT_HIT
            .store(true, Ordering::SeqCst);
        return Err(LINUX_EFBIG);
    }
    Ok(requested.min((limit - start) as usize))
}

pub(super) fn linux_file_extension_limit(size: usize) -> Result<(), u64> {
    if (size as u64) <= linux_file_size_limit() {
        Ok(())
    } else {
        X86_RUNTIME
            .LINUX_FSIZE_LIMIT_HIT
            .store(true, Ordering::SeqCst);
        Err(LINUX_EFBIG)
    }
}

pub(super) fn linux_address_space_limit_allows(additional_pages: usize) -> bool {
    let Some(limit) = linux_resource_limit_values(
        LINUX_RLIMIT_AS,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    ) else {
        return false;
    };
    if limit[0] == u64::MAX {
        return true;
    }
    let Some(current_pages) = address_space::current_linux_user_page_count() else {
        return false;
    };
    current_pages
        .checked_add(additional_pages)
        .and_then(|pages| pages.checked_mul(PAGE_SIZE))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .is_some_and(|bytes| bytes <= limit[0])
}

pub(super) fn linux_nproc_limit_reached() -> bool {
    let Some(limit) = linux_resource_limit_values(
        LINUX_RLIMIT_NPROC,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    ) else {
        return true;
    };
    if limit[0] == u64::MAX {
        return false;
    }
    let Some(processes) = linux_process::live_process_count() else {
        return true;
    };
    let threads = X86_RUNTIME
        .LINUX_THREAD_STATES
        .iter()
        .filter(|state| state.load(Ordering::SeqCst) != LINUX_THREAD_FREE)
        .count() as u64;
    u64::from(processes).saturating_add(threads.saturating_sub(1)) >= limit[0]
}

pub(super) fn linux_getrlimit(
    resource: u64,
    address: u64,
    runtime: bool,
    copy: fn(u64, &[u8]) -> bool,
) -> u64 {
    let resource = u64::from(resource as u32);
    let Some(limit) = linux_resource_limit(resource, runtime) else {
        return LINUX_EINVAL;
    };
    if copy(address, &limit) {
        0
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_setrlimit(resource: u64, address: u64) -> u64 {
    let resource = u64::from(resource as u32);
    if resource >= LINUX_RLIMIT_NLIMITS {
        return LINUX_EINVAL;
    }
    let mut requested = [0_u8; 16];
    if !copy_from_linux_user(address, &mut requested) {
        return LINUX_EFAULT;
    }
    let requested = [
        u64::from_ne_bytes(requested[..8].try_into().unwrap()),
        u64::from_ne_bytes(requested[8..].try_into().unwrap()),
    ];
    linux_set_process_resource_limit(current_linux_process_pid(), resource, requested)
}
