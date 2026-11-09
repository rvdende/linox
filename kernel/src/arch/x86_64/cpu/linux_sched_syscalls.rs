use super::*;

pub(super) fn linux_scheduler_priority_range(policy: u64, maximum: bool) -> u64 {
    let policy = u64::from(policy as u32);
    match policy {
        1 | 2 if maximum => 99,
        1 | 2 => 1,
        0 | 3 | 5 | 6 => 0,
        _ => LINUX_EINVAL,
    }
}

pub(super) const LINUX_PRIO_PROCESS: u32 = 0;
pub(super) const LINUX_PRIO_PGRP: u32 = 1;
pub(super) const LINUX_PRIO_USER: u32 = 2;

fn linux_priority_targets(which: u64, who: u64) -> Result<(Vec<u32>, usize), u64> {
    let which = which as u32;
    let who = who as u32;
    if which > LINUX_PRIO_USER {
        return Err(LINUX_EINVAL);
    }
    let current_pid = current_linux_process_pid();
    let current_credentials = current_linux_credentials().ok_or(LINUX_ESRCH)?;
    let selector = match which {
        LINUX_PRIO_PROCESS => who,
        LINUX_PRIO_PGRP if who == 0 => {
            linux_process::live_process_group(current_pid).ok_or(LINUX_ESRCH)?
        }
        LINUX_PRIO_USER if who == 0 => current_credentials.user.real,
        _ => who,
    };
    let mut targets = Vec::new();
    for slot in 0..linux_process::live_process_slots() {
        let Some(pid) = linux_process::live_process_pid_at(slot) else {
            continue;
        };
        let selected = match which {
            LINUX_PRIO_PROCESS => pid == if selector == 0 { current_pid } else { selector },
            LINUX_PRIO_PGRP => linux_process::live_process_group(pid) == Some(selector),
            LINUX_PRIO_USER => linux_process::live_process_credentials(pid)
                .is_some_and(|credentials| credentials.user.real == selector),
            _ => false,
        };
        if selected {
            targets.try_reserve(1).map_err(|_| LINUX_ENOMEM)?;
            targets.push(pid);
        }
    }
    let count = targets.len();
    if count == 0 {
        Err(LINUX_ESRCH)
    } else {
        Ok((targets, count))
    }
}

fn linux_process_nice(pid: u32) -> Option<u8> {
    if pid == current_linux_process_pid() {
        Some(X86_RUNTIME.ELF_PROBE_NICE.load(Ordering::SeqCst))
    } else {
        linux_process_runtime_state(pid)
            .filter(|state| state.valid)
            .map(|state| state.nice)
    }
}

fn linux_set_process_nice(pid: u32, nice: u8) -> bool {
    if !linux_process::set_live_process_scheduler_nice(pid, nice) {
        return false;
    }
    if pid == current_linux_process_pid() {
        X86_RUNTIME.ELF_PROBE_NICE.store(nice, Ordering::SeqCst);
        if let Some(handle) = linux_thread_handle_by_tid(u64::from(pid)) {
            X86_RUNTIME.LINUX_THREAD_NICES[usize::from(handle.slot)].store(nice, Ordering::SeqCst);
        }
        true
    } else if let Some(state) = linux_process_runtime_state(pid).filter(|state| state.valid) {
        state.nice = nice;
        if let Some(threads) = linux_process_thread_runtime_state(pid) {
            for thread in threads.iter_mut().filter(|thread| thread.tid == pid) {
                thread.nice = nice;
            }
        }
        true
    } else {
        false
    }
}

fn linux_process_ioprio(pid: u32) -> Option<u16> {
    if pid == current_linux_process_pid() {
        Some(X86_RUNTIME.ELF_PROBE_IOPRIO.load(Ordering::SeqCst))
    } else {
        linux_process_runtime_state(pid)
            .filter(|state| state.valid)
            .map(|state| state.ioprio)
    }
}

fn linux_set_process_ioprio(pid: u32, priority: u16) -> bool {
    if pid == current_linux_process_pid() {
        X86_RUNTIME
            .ELF_PROBE_IOPRIO
            .store(priority, Ordering::SeqCst);
        true
    } else if let Some(state) = linux_process_runtime_state(pid).filter(|state| state.valid) {
        state.ioprio = priority;
        true
    } else {
        false
    }
}

/// The thread slot `who` names for PRIO_PROCESS in the calling process: the
/// calling thread for 0 or its own id, another thread by its id; None for a
/// process id (its main thread's, or another process).
fn linux_priority_thread_slot(which: u64, who: u64) -> Option<usize> {
    if which as u32 != LINUX_PRIO_PROCESS {
        return None;
    }
    let who = who as u32;
    if who == 0 {
        return current_linux_thread_slot();
    }
    if who == current_linux_process_pid() {
        return None;
    }
    linux_thread_handle_by_tid(u64::from(who)).map(|handle| usize::from(handle.slot))
}

pub(super) fn linux_getpriority(which: u64, who: u64) -> u64 {
    // A thread's own nice (nice() and getpriority(PRIO_PROCESS, 0) in a
    // thread are the thread's), as Linux keeps nice per task.
    if let Some(slot) = linux_priority_thread_slot(which, who) {
        let nice = X86_RUNTIME.LINUX_THREAD_NICES[slot].load(Ordering::SeqCst);
        return u64::from(40 - nice.min(39));
    }
    let (targets, count) = match linux_priority_targets(which, who) {
        Ok(targets) => targets,
        Err(error) => return error,
    };
    // A zombie among them has no nice left and counts for nothing, as
    // setpriority skips it too.
    let best = targets[..count]
        .iter()
        .filter_map(|pid| linux_process_nice(*pid))
        .min();
    best.map_or(LINUX_ESRCH, |best| u64::from(40 - best))
}

pub(super) fn linux_setpriority(which: u64, who: u64, priority: u64) -> u64 {
    let (targets, count) = match linux_priority_targets(which, who) {
        Ok(targets) => targets,
        Err(error) => return error,
    };
    let requested = (priority as u32 as i32).clamp(-20, 19);
    let encoded = (requested + 20) as u8;
    let Some(caller) = current_linux_credentials() else {
        return LINUX_ESRCH;
    };
    if let Some(slot) = linux_priority_thread_slot(which, who) {
        let current = X86_RUNTIME.LINUX_THREAD_NICES[slot].load(Ordering::SeqCst);
        if !caller.privileged() && encoded < current {
            return LINUX_EACCES;
        }
        X86_RUNTIME.LINUX_THREAD_NICES[slot].store(encoded, Ordering::SeqCst);
        // The main thread's nice is the process's.
        if X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst) == current_linux_process_pid()
            && !linux_set_process_nice(current_linux_process_pid(), encoded)
        {
            return LINUX_ESRCH;
        }
        return 0;
    }
    let mut result = LINUX_ESRCH;
    for pid in targets[..count].iter().copied() {
        let Some(target) = linux_process::live_process_credentials(pid) else {
            continue;
        };
        let Some(current) = linux_process_nice(pid) else {
            continue;
        };
        if !caller.privileged()
            && caller.user.effective != target.user.real
            && caller.user.effective != target.user.effective
        {
            result = LINUX_EPERM;
            continue;
        }
        if !caller.privileged() && encoded < current {
            result = LINUX_EACCES;
            continue;
        }
        if linux_set_process_nice(pid, encoded) && result == LINUX_ESRCH {
            result = 0;
        }
    }
    result
}

fn linux_scheduler_process(pid: u64) -> Result<u32, u64> {
    let pid = pid as i32;
    if pid < 0 {
        return Err(LINUX_EINVAL);
    }
    let pid = if pid == 0 {
        current_linux_process_pid()
    } else {
        pid as u32
    };
    linux_process::live_process_status(pid)
        .map(|_| pid)
        .ok_or(LINUX_ESRCH)
}

pub(super) fn linux_sched_getscheduler(pid: u64) -> u64 {
    match linux_scheduler_process(pid) {
        Ok(pid) => {
            linux_process::live_process_scheduling(pid).map_or(LINUX_ESRCH, |(policy, _)| {
                let reset = policy & linux_process::SCHED_RESET_ON_FORK != 0;
                u64::from(policy & !linux_process::SCHED_RESET_ON_FORK)
                    | if reset { 0x4000_0000 } else { 0 }
            })
        }
        Err(error) => error,
    }
}

pub(super) fn linux_sched_getparam(pid: u64, address: u64) -> u64 {
    if (pid as i32) < 0 {
        return LINUX_EINVAL;
    }
    if address == 0 {
        return LINUX_EINVAL;
    }
    let target = match linux_scheduler_process(pid) {
        Ok(target) => target,
        Err(error) => return error,
    };
    let Some((_, priority)) = linux_process::live_process_scheduling(target) else {
        return LINUX_ESRCH;
    };
    if copy_to_linux_user(address, &u32::from(priority).to_ne_bytes()) {
        0
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_sched_rr_get_interval(pid: u64, address: u64) -> u64 {
    const SCHED_FIFO: u8 = 1;
    let pid = match linux_scheduler_process(pid) {
        Ok(pid) => pid,
        Err(error) => return error,
    };
    // A SCHED_FIFO task runs until it yields: no time slice, as Linux
    // reports it; the others' is the 100 ms round-robin slice.
    let fifo = linux_process::live_process_scheduling(pid)
        .is_some_and(|(policy, _)| policy & 0x7f == SCHED_FIFO);
    let mut interval = [0_u8; 16];
    if !fifo {
        interval[8..].copy_from_slice(&100_000_000_u64.to_ne_bytes());
    }
    if copy_to_linux_user(address, &interval) {
        0
    } else {
        LINUX_EFAULT
    }
}

fn linux_affinity_process(pid: u64) -> Result<u32, u64> {
    let pid = pid as i32;
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

pub(super) fn linux_sched_getaffinity(pid: u64, length: u64, address: u64) -> u64 {
    if length < size_of::<u64>() as u64 || !length.is_multiple_of(size_of::<u64>() as u64) {
        return LINUX_EINVAL;
    }
    let pid = match linux_affinity_process(pid) {
        Ok(pid) => pid,
        Err(error) => return error,
    };
    let Some(mask) = linux_process::live_process_cpu_affinity(pid)
        .map(|mask| mask & linux_available_cpu_mask())
        .filter(|mask| *mask != 0)
    else {
        return LINUX_ESRCH;
    };
    if copy_to_linux_user(address, &mask.to_ne_bytes()) {
        size_of::<u64>() as u64
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_sched_setaffinity(pid: u64, length: u64, address: u64) -> u64 {
    let length = length.min(size_of::<u64>() as u64) as usize;
    let mut mask = [0_u8; size_of::<u64>()];
    if length != 0 && !copy_from_linux_user(address, &mut mask[..length]) {
        return LINUX_EFAULT;
    }
    let pid = match linux_affinity_process(pid) {
        Ok(pid) => pid,
        Err(error) => return error,
    };
    // Another process is the caller's to change with the same effective
    // or real user, or as root (sched_setaffinity01).
    if pid != current_linux_process_pid() {
        let Some(caller) = current_linux_credentials() else {
            return LINUX_EPERM;
        };
        let same_owner = linux_process::live_process_credentials(pid).is_some_and(|target| {
            target.user.effective == caller.user.effective
                || target.user.real == caller.user.effective
        });
        if !same_owner && !caller.privileged() {
            return LINUX_EPERM;
        }
    }
    let mask = u64::from_ne_bytes(mask) & linux_available_cpu_mask();
    if linux_process::set_live_process_cpu_affinity(pid, mask) {
        0
    } else {
        LINUX_EINVAL
    }
}

/// sched_setaffinity that leaves this CPU when the new mask excludes it: a
/// thread on the light path is parked ready and a process on the owner
/// yields, so a CPU the mask allows runs the thread next and getcpu() there
/// reports one it was pinned to. The mask itself is stored either way.
pub(super) fn linux_sched_setaffinity_live_return(
    pid: u64,
    length: u64,
    address: u64,
    registers: LinuxSyscallFrame,
    user_stack: u64,
    user_rip: u64,
    user_rflags: u64,
) -> u64 {
    let result = linux_sched_setaffinity(pid, length, address);
    if result != 0 {
        return result;
    }
    let Ok(target) = linux_affinity_process(pid) else {
        return 0;
    };
    if target != current_linux_process_pid() {
        return 0;
    }
    let cpu = linux_cpu_slot();
    let excluded = linux_process::live_process_cpu_affinity(target)
        .is_some_and(|mask| mask & (1_u64 << cpu) == 0);
    if !excluded {
        return 0;
    }
    let Some(current) = current_linux_thread_handle() else {
        return 0;
    };
    let Some(caller) = linux_thread_context(current).map(|tls| LinuxUserContext {
        registers,
        rip: user_rip,
        rsp: user_stack,
        rflags: user_rflags,
        rax: 0,
        fs_base: tls.thread_pointer as u64,
    }) else {
        return 0;
    };
    if yield_current_linux_process(caller, 0) {
        LINUX_RETURN_TO_KERNEL
    } else {
        0
    }
}

pub(super) fn linux_available_cpu_mask() -> u64 {
    let count = linux_available_cpu_count();
    if count == u64::BITS as usize {
        u64::MAX
    } else {
        (1_u64 << count).saturating_sub(1)
    }
}

pub(super) fn linux_available_cpu_count() -> usize {
    let online = crate::arch::x86_64::smp::online_count().max(1);
    let domain_limit = current_container_slot()
        .map(|slot| usize::from(X86_RUNTIME.CONTAINER_CPU_COUNTS[slot].load(Ordering::Acquire)))
        .unwrap_or(online);
    online.min(domain_limit.max(1)).min(u64::BITS as usize)
}

pub(super) fn linux_ioprio_get(which: u64, who: u64) -> u64 {
    let which = which as u32;
    if !matches!(which, 1..=3) {
        return LINUX_EINVAL;
    }
    let (targets, count) = match linux_priority_targets(u64::from(which - 1), who) {
        Ok(targets) => targets,
        Err(error) => return error,
    };
    let mut best = 0_u16;
    for pid in targets[..count].iter().copied() {
        let Some(priority) = linux_process_ioprio(pid) else {
            return LINUX_ESRCH;
        };
        if best == 0
            || priority != 0 && ((priority >> 13, priority & 0x1fff) < (best >> 13, best & 0x1fff))
        {
            best = priority;
        }
    }
    u64::from(best)
}

pub(super) fn linux_ioprio_set(which: u64, who: u64, priority: u64) -> u64 {
    let which = which as u32;
    let priority = priority as u32;
    if !matches!(which, 1..=3) {
        return LINUX_EINVAL;
    }
    let class = priority >> 13;
    let data = priority & 0x1fff;
    if priority > u16::MAX as u32
        || class > 3
        || class == 0 && data != 0
        || matches!(class, 1 | 2) && data >= 8
    {
        return LINUX_EINVAL;
    }
    let (targets, count) = match linux_priority_targets(u64::from(which - 1), who) {
        Ok(targets) => targets,
        Err(error) => return error,
    };
    let Some(caller) = current_linux_credentials() else {
        return LINUX_ESRCH;
    };
    for pid in targets[..count].iter().copied() {
        let Some(target) = linux_process::live_process_credentials(pid) else {
            return LINUX_ESRCH;
        };
        let owner = [caller.user.real, caller.user.effective].contains(&target.user.real);
        if !caller.privileged() && (!owner || class == 1) {
            return LINUX_EPERM;
        }
    }
    for pid in targets[..count].iter().copied() {
        if !linux_set_process_ioprio(pid, priority as u16) {
            return LINUX_ESRCH;
        }
    }
    0
}

pub(super) const MEMBARRIER_CMD_QUERY: u32 = 0;
pub(super) const MEMBARRIER_CMD_GLOBAL: u32 = 1 << 0;
pub(super) const MEMBARRIER_CMD_GLOBAL_EXPEDITED: u32 = 1 << 1;
pub(super) const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: u32 = 1 << 2;
pub(super) const MEMBARRIER_CMD_PRIVATE_EXPEDITED: u32 = 1 << 3;
pub(super) const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: u32 = 1 << 4;
pub(super) const MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ: u32 = 1 << 7;
pub(super) const MEMBARRIER_CMD_GET_REGISTRATIONS: u32 = 1 << 9;
pub(super) const MEMBARRIER_CMD_FLAG_CPU: u32 = 1;
pub(super) const MEMBARRIER_SUPPORTED_COMMANDS: u32 = MEMBARRIER_CMD_GLOBAL
    | MEMBARRIER_CMD_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_GET_REGISTRATIONS;

/// sched_setscheduler(2): SCHED_OTHER, BATCH and IDLE take priority 0 from
/// anyone; FIFO and RR take 1..=99 from a privileged caller (CAP_SYS_NICE);
/// SCHED_DEADLINE needs sched_setattr. The policy and priority are kept
/// per process for sched_getscheduler and sched_getparam, with
/// SCHED_RESET_ON_FORK, which gives the process's children SCHED_OTHER.
pub(super) fn linux_set_scheduler(pid: u64, policy: u64, parameter_address: u64) -> u64 {
    const SCHED_RESET_ON_FORK: u64 = 0x4000_0000;
    let reset = u64::from(policy as u32) & SCHED_RESET_ON_FORK != 0;
    let policy = u64::from(policy as u32) & !SCHED_RESET_ON_FORK;
    if !matches!(policy, 0 | 1 | 2 | 3 | 5 | 6) {
        return LINUX_EINVAL;
    }
    let flag = if reset {
        linux_process::SCHED_RESET_ON_FORK
    } else {
        0
    };
    linux_set_scheduling(pid, policy as u8 | flag, parameter_address)
}

/// sched_setparam(2): a priority for the process's current policy.
pub(super) fn linux_sched_setparam(pid: u64, parameter_address: u64) -> u64 {
    let target = match linux_scheduler_process(pid) {
        Ok(target) => target,
        Err(error) => return error,
    };
    let Some((policy, _)) = linux_process::live_process_scheduling(target) else {
        return LINUX_ESRCH;
    };
    linux_set_scheduling(pid, policy, parameter_address)
}

fn linux_set_scheduling(pid: u64, policy: u8, parameter_address: u64) -> u64 {
    const SCHED_FIFO: u8 = 1;
    const SCHED_RR: u8 = 2;
    const SCHED_DEADLINE: u8 = 6;
    let target = match linux_scheduler_process(pid) {
        Ok(target) => target,
        Err(error) => return error,
    };
    if parameter_address == 0 {
        return LINUX_EINVAL;
    }
    let mut priority = [0_u8; 4];
    if !copy_from_linux_user(parameter_address, &mut priority) {
        return LINUX_EFAULT;
    }
    let priority = i32::from_ne_bytes(priority);
    let kind = policy & !linux_process::SCHED_RESET_ON_FORK;
    let realtime = matches!(kind, SCHED_FIFO | SCHED_RR);
    if kind == SCHED_DEADLINE
        || realtime && !(1..=99).contains(&priority)
        || !realtime && priority != 0
    {
        return LINUX_EINVAL;
    }
    let Some(caller) = current_linux_credentials() else {
        return LINUX_EPERM;
    };
    let other = target != current_linux_process_pid()
        && !linux_process::live_process_credentials(target).is_some_and(|credentials| {
            credentials.user.effective == caller.user.effective
                || credentials.user.real == caller.user.effective
        });
    if (realtime || other) && !caller.privileged() {
        return LINUX_EPERM;
    }
    if !linux_process::set_live_process_scheduling(target, policy, priority as u8) {
        return LINUX_ESRCH;
    }
    0
}

/// sched_setattr(2), in Linux's order: no attributes, a negative pid or
/// flags are EINVAL; the size is read next (0 meaning version 0; smaller,
/// past a page, or with nonzero bytes past what Linox knows is E2BIG, with
/// the size it takes written back); then a negative policy (EINVAL), the
/// process (ESRCH), the flags, policy and priority (EINVAL), SCHED_DEADLINE's
/// runtime <= deadline <= period, 100 us to 4 s (EINVAL), and permission
/// for a real-time or deadline policy (EPERM). The policy, priority,
/// SCHED_RESET_ON_FORK and deadline parameters are kept for
/// sched_getattr; a normal policy's nice goes through setpriority.
pub(super) fn linux_sched_setattr(pid: u64, attribute_address: u64, flags: u64) -> u64 {
    const SCHED_ATTR_VER0: usize = 48;
    const SCHED_ATTR_SIZE: usize = 56;
    const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
    const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;
    const SCHED_FLAG_KEEP_PARAMS: u64 = 0x10;
    const SCHED_FLAG_ALL: u64 = 0x7f;
    const SCHED_FIFO: u32 = 1;
    const SCHED_RR: u32 = 2;
    const SCHED_DEADLINE: u32 = 6;
    const DL_RUNTIME_MIN: u64 = 1 << 10;
    const DL_PERIOD_MIN: u64 = 100 * 1_000;
    const DL_PERIOD_MAX: u64 = (1 << 22) * 1_000;
    if attribute_address == 0 || (pid as i32) < 0 || flags as u32 != 0 {
        return LINUX_EINVAL;
    }
    let mut header = [0_u8; 4];
    if !copy_from_linux_user(attribute_address, &mut header) {
        return LINUX_EFAULT;
    }
    let size = match u32::from_ne_bytes(header) as usize {
        0 => SCHED_ATTR_VER0,
        size => size,
    };
    let too_big = || {
        let _ = copy_to_linux_user(attribute_address, &(SCHED_ATTR_SIZE as u32).to_ne_bytes());
        LINUX_E2BIG
    };
    if !(SCHED_ATTR_VER0..=PAGE_SIZE).contains(&size) {
        return too_big();
    }
    let mut attribute = [0_u8; SCHED_ATTR_SIZE];
    let copied = size.min(attribute.len());
    if !copy_from_linux_user(attribute_address, &mut attribute[..copied]) {
        return LINUX_EFAULT;
    }
    let mut extension_offset = attribute.len();
    let mut extension = [0_u8; 64];
    while extension_offset < size {
        let length = (size - extension_offset).min(extension.len());
        let Some(address) = attribute_address.checked_add(extension_offset as u64) else {
            return LINUX_EFAULT;
        };
        if !copy_from_linux_user(address, &mut extension[..length]) {
            return LINUX_EFAULT;
        }
        if extension[..length].iter().any(|byte| *byte != 0) {
            return too_big();
        }
        extension_offset += length;
    }
    let mut policy = u32::from_ne_bytes(attribute[4..8].try_into().unwrap());
    let scheduler_flags = u64::from_ne_bytes(attribute[8..16].try_into().unwrap());
    let nice = i32::from_ne_bytes(attribute[16..20].try_into().unwrap()).clamp(-20, 19);
    let mut priority = u32::from_ne_bytes(attribute[20..24].try_into().unwrap());
    let mut deadline = [
        u64::from_ne_bytes(attribute[24..32].try_into().unwrap()),
        u64::from_ne_bytes(attribute[32..40].try_into().unwrap()),
        u64::from_ne_bytes(attribute[40..48].try_into().unwrap()),
    ];
    if (policy as i32) < 0 {
        return LINUX_EINVAL;
    }
    let target = match linux_scheduler_process(pid) {
        Ok(target) => target,
        Err(error) => return error,
    };
    if scheduler_flags & !SCHED_FLAG_ALL != 0 {
        return LINUX_EINVAL;
    }
    let Some((current_policy, current_priority)) = linux_process::live_process_scheduling(target)
    else {
        return LINUX_ESRCH;
    };
    let current_kind = u32::from(current_policy & !linux_process::SCHED_RESET_ON_FORK);
    if scheduler_flags & SCHED_FLAG_KEEP_POLICY != 0 {
        policy = current_kind;
    }
    if scheduler_flags & SCHED_FLAG_KEEP_PARAMS != 0 {
        priority = u32::from(current_priority);
        deadline = linux_process::live_process_deadline_parameters(target).unwrap_or([0; 3]);
    }
    if !matches!(policy, 0 | 1 | 2 | 3 | 5 | SCHED_DEADLINE) {
        return LINUX_EINVAL;
    }
    let realtime = matches!(policy, SCHED_FIFO | SCHED_RR);
    if realtime && !(1..=99).contains(&priority) || !realtime && priority != 0 {
        return LINUX_EINVAL;
    }
    if policy == SCHED_DEADLINE {
        let [runtime, relative_deadline, period] = deadline;
        let period = if period == 0 {
            relative_deadline
        } else {
            period
        };
        if relative_deadline == 0
            || runtime < DL_RUNTIME_MIN
            || relative_deadline & 1 << 63 != 0
            || deadline[2] & 1 << 63 != 0
            || period < relative_deadline
            || relative_deadline < runtime
            || !(DL_PERIOD_MIN..=DL_PERIOD_MAX).contains(&period)
        {
            return LINUX_EINVAL;
        }
    }
    let Some(caller) = current_linux_credentials() else {
        return LINUX_EPERM;
    };
    if (realtime || policy == SCHED_DEADLINE)
        && !caller.has(linox_credentials::capability::SYS_NICE)
    {
        return LINUX_EPERM;
    }
    if !realtime && policy != SCHED_DEADLINE {
        let result = linux_setpriority(0, u64::from(target), nice as i64 as u64);
        if result != 0 {
            return result;
        }
    }
    let reset = if scheduler_flags & SCHED_FLAG_RESET_ON_FORK != 0 {
        linux_process::SCHED_RESET_ON_FORK
    } else {
        0
    };
    if !linux_process::set_live_process_scheduling(target, policy as u8 | reset, priority as u8)
        || !linux_process::set_live_process_deadline_parameters(
            target,
            if policy == SCHED_DEADLINE {
                deadline
            } else {
                [0; 3]
            },
        )
    {
        return LINUX_ESRCH;
    }
    0
}

/// sched_getattr(2): no attributes, a negative pid, a size below version 0
/// or past a page, or flags are EINVAL; then the process (ESRCH). Its
/// policy, SCHED_RESET_ON_FORK, nice, priority and deadline parameters
/// are written, in as much of the caller's struct as Linox's fills, and
/// any larger rest zeroed.
pub(super) fn linux_sched_getattr(pid: u64, attribute_address: u64, size: u64, flags: u64) -> u64 {
    const SCHED_ATTR_VER0: u64 = 48;
    const SCHED_ATTR_SIZE: usize = 56;
    const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
    let size = u64::from(size as u32);
    if attribute_address == 0
        || (pid as i32) < 0
        || size > PAGE_SIZE as u64
        || size < SCHED_ATTR_VER0
        || flags as u32 != 0
    {
        return LINUX_EINVAL;
    }
    let target = match linux_scheduler_process(pid) {
        Ok(target) => target,
        Err(error) => return error,
    };
    let Some((policy, priority)) = linux_process::live_process_scheduling(target) else {
        return LINUX_ESRCH;
    };
    let reset = policy & linux_process::SCHED_RESET_ON_FORK != 0;
    let policy = policy & !linux_process::SCHED_RESET_ON_FORK;
    let deadline = linux_process::live_process_deadline_parameters(target).unwrap_or([0; 3]);
    let nice = 20 - linux_getpriority(0, u64::from(target)).min(40) as i32;
    let written = (size as usize).min(SCHED_ATTR_SIZE);
    let mut attribute = [0_u8; SCHED_ATTR_SIZE];
    attribute[..4].copy_from_slice(&(written as u32).to_ne_bytes());
    attribute[4..8].copy_from_slice(&u32::from(policy).to_ne_bytes());
    let flags = if reset { SCHED_FLAG_RESET_ON_FORK } else { 0 };
    attribute[8..16].copy_from_slice(&flags.to_ne_bytes());
    if matches!(policy, 0 | 3 | 5) {
        attribute[16..20].copy_from_slice(&nice.to_ne_bytes());
    }
    attribute[20..24].copy_from_slice(&u32::from(priority).to_ne_bytes());
    attribute[24..32].copy_from_slice(&deadline[0].to_ne_bytes());
    attribute[32..40].copy_from_slice(&deadline[1].to_ne_bytes());
    attribute[40..48].copy_from_slice(&deadline[2].to_ne_bytes());
    // sched_util_max: no clamping, the whole range.
    attribute[52..56].copy_from_slice(&1024_u32.to_ne_bytes());
    if !copy_to_linux_user(attribute_address, &attribute[..written]) {
        return LINUX_EFAULT;
    }
    let mut extension_offset = written;
    let zeros = [0_u8; 64];
    while extension_offset < size as usize {
        let length = (size as usize - extension_offset).min(zeros.len());
        let Some(address) = attribute_address.checked_add(extension_offset as u64) else {
            return LINUX_EFAULT;
        };
        if !copy_to_linux_user(address, &zeros[..length]) {
            return LINUX_EFAULT;
        }
        extension_offset += length;
    }
    0
}
