use super::*;

pub(super) fn linux_personality(requested: u64) -> u64 {
    let requested = requested as u32;
    let current = X86_RUNTIME.ELF_PROBE_PERSONALITY.load(Ordering::SeqCst);
    if requested == LINUX_PERSONALITY_QUERY {
        return u64::from(current);
    }
    // Any personality is kept and read back, as Linux does; UNAME26 is the
    // one with an effect here (uname's release).
    X86_RUNTIME
        .ELF_PROBE_PERSONALITY
        .store(requested, Ordering::SeqCst);
    u64::from(current)
}

pub(super) fn linux_arch_prctl(option: u64, argument: u64) -> u64 {
    const ARCH_GET_CPUID: u64 = 0x1011;
    const ARCH_SET_CPUID: u64 = 0x1012;
    match u64::from(option as u32) {
        LINUX_ARCH_SET_FS if argument >= 1 << 47 => LINUX_EPERM,
        LINUX_ARCH_SET_FS => {
            if update_current_linux_fs_base(argument) {
                0
            } else {
                LINUX_ESRCH
            }
        }
        LINUX_ARCH_GET_FS => {
            if copy_to_linux_user(argument, &active_fs_base().to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        // CPUID stays available: Linox does not offer CPUID faulting
        // (no "cpuid_fault" in /proc/cpuinfo), so setting it is ENODEV.
        ARCH_GET_CPUID => 1,
        ARCH_SET_CPUID => LINUX_ENODEV,
        _ => LINUX_EINVAL,
    }
}

pub(super) fn linux_prctl(
    option: u64,
    argument2: u64,
    argument3: u64,
    argument4: u64,
    argument5: u64,
) -> u64 {
    match u64::from(option as u32) {
        LINUX_PR_SET_PDEATHSIG if argument2 <= LINUX_SIGNAL_COUNT as u64 => {
            X86_RUNTIME
                .ELF_PROBE_PARENT_DEATH_SIGNAL
                .store(argument2 as u32, Ordering::SeqCst);
            0
        }
        LINUX_PR_SET_PDEATHSIG => LINUX_EINVAL,
        LINUX_PR_GET_PDEATHSIG => {
            let signal = X86_RUNTIME
                .ELF_PROBE_PARENT_DEATH_SIGNAL
                .load(Ordering::SeqCst);
            if copy_to_linux_user(argument2, &signal.to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_PR_GET_DUMPABLE => u64::from(X86_RUNTIME.ELF_PROBE_DUMPABLE.load(Ordering::SeqCst)),
        LINUX_PR_SET_DUMPABLE if argument2 <= 1 => {
            X86_RUNTIME
                .ELF_PROBE_DUMPABLE
                .store(argument2 != 0, Ordering::SeqCst);
            0
        }
        LINUX_PR_SET_DUMPABLE => LINUX_EINVAL,
        LINUX_PR_GET_TIMING => LINUX_PR_TIMING_STATISTICAL,
        LINUX_PR_SET_TIMING if argument2 == LINUX_PR_TIMING_STATISTICAL => 0,
        LINUX_PR_SET_TIMING => LINUX_EINVAL,
        LINUX_PR_SET_NAME => linux_set_process_name(argument2),
        LINUX_PR_GET_NAME => linux_get_process_name(argument2),
        LINUX_PR_GET_SECCOMP => {
            if X86_RUNTIME
                .ELF_PROBE_SECCOMP_FILTERED
                .load(Ordering::SeqCst)
            {
                2
            } else {
                u64::from(X86_RUNTIME.ELF_PROBE_SECCOMP_STRICT.load(Ordering::SeqCst))
            }
        }
        LINUX_PR_SET_SECCOMP if argument2 == 1 => linux_seccomp(0, argument3, 0),
        LINUX_PR_SET_SECCOMP if argument2 == 2 => linux_seccomp(1, 0, argument3),
        LINUX_PR_SET_SECCOMP => LINUX_EINVAL,
        LINUX_PR_GET_SECUREBITS => {
            u64::from(X86_RUNTIME.ELF_PROBE_SECUREBITS.load(Ordering::SeqCst))
        }
        LINUX_PR_SET_SECUREBITS if argument2 & !u64::from(LINUX_SECUREBITS_VALID_MASK) != 0 => {
            LINUX_EINVAL
        }
        LINUX_PR_SET_SECUREBITS
            if !current_linux_credentials().is_some_and(|credentials| {
                credentials.has(linox_credentials::capability::SETPCAP)
            }) =>
        {
            LINUX_EPERM
        }
        LINUX_PR_SET_SECUREBITS => {
            let requested = argument2 as u32;
            let current = X86_RUNTIME.ELF_PROBE_SECUREBITS.load(Ordering::SeqCst);
            let locked = current & 0xaa;
            let protected = locked | (locked >> 1);
            if requested & locked != locked || (requested ^ current) & protected != 0 {
                LINUX_EPERM
            } else {
                X86_RUNTIME
                    .ELF_PROBE_SECUREBITS
                    .store(requested, Ordering::SeqCst);
                0
            }
        }
        LINUX_PR_SET_NO_NEW_PRIVS
            if argument2 == 1 && argument3 == 0 && argument4 == 0 && argument5 == 0 =>
        {
            X86_RUNTIME
                .ELF_PROBE_NO_NEW_PRIVS
                .store(true, Ordering::SeqCst);
            0
        }
        LINUX_PR_SET_NO_NEW_PRIVS => LINUX_EINVAL,
        LINUX_PR_GET_NO_NEW_PRIVS
            if argument2 == 0 && argument3 == 0 && argument4 == 0 && argument5 == 0 =>
        {
            u64::from(X86_RUNTIME.ELF_PROBE_NO_NEW_PRIVS.load(Ordering::SeqCst))
        }
        LINUX_PR_GET_NO_NEW_PRIVS => LINUX_EINVAL,
        LINUX_PR_CAPBSET_READ => linux_current_credentials_result(|credentials| {
            credentials
                .bounding_has(argument2.min(u64::from(u32::MAX)) as u32)
                .map(u64::from)
        }),
        LINUX_PR_CAPBSET_DROP => linux_current_credentials_result(|credentials| {
            credentials
                .drop_bounding(argument2.min(u64::from(u32::MAX)) as u32)
                .map(|()| 0)
        }),
        LINUX_PR_GET_TSC => {
            let mode = if X86_RUNTIME.ELF_PROBE_TSC_SIGSEGV.load(Ordering::SeqCst) {
                LINUX_PR_TSC_SIGSEGV
            } else {
                LINUX_PR_TSC_ENABLE
            };
            if copy_to_linux_user(argument2, &(mode as u32).to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_PR_SET_TSC if matches!(argument2, LINUX_PR_TSC_ENABLE | LINUX_PR_TSC_SIGSEGV) => {
            X86_RUNTIME
                .ELF_PROBE_TSC_SIGSEGV
                .store(argument2 == LINUX_PR_TSC_SIGSEGV, Ordering::SeqCst);
            0
        }
        LINUX_PR_SET_TSC => LINUX_EINVAL,
        // The timer slack is kept per process for prctl to read back; the
        // timers themselves fire on the tick (prctl08).
        LINUX_PR_SET_TIMERSLACK => {
            if linux_process::set_live_process_timer_slack(current_linux_process_pid(), argument2) {
                0
            } else {
                LINUX_ESRCH
            }
        }
        LINUX_PR_GET_TIMERSLACK => {
            linux_process::live_process_timer_slack(current_linux_process_pid())
                .unwrap_or(linux_process::DEFAULT_TIMER_SLACK)
        }
        // A subreaper adopts the orphans of its descendants
        // (linux_process's reaper); a child does not inherit the mark.
        LINUX_PR_SET_CHILD_SUBREAPER => {
            if linux_process::set_live_process_child_subreaper(
                current_linux_process_pid(),
                argument2 != 0,
            ) {
                0
            } else {
                LINUX_ESRCH
            }
        }
        LINUX_PR_GET_CHILD_SUBREAPER => {
            let marked = linux_process::live_process_child_subreaper(current_linux_process_pid())
                .unwrap_or(false);
            if copy_to_linux_user(argument2, &i32::from(marked).to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_PR_TASK_PERF_EVENTS_DISABLE => linux_perf_task_events(false),
        LINUX_PR_TASK_PERF_EVENTS_ENABLE => linux_perf_task_events(true),
        LINUX_PR_CAP_AMBIENT => {
            let no_raise = X86_RUNTIME.ELF_PROBE_SECUREBITS.load(Ordering::SeqCst)
                & LINUX_SECBIT_NO_CAP_AMBIENT_RAISE
                != 0;
            let pid = current_linux_process_pid();
            let Some(mut credentials) = linux_process::live_process_credentials(pid) else {
                return LINUX_ESRCH;
            };
            match credentials.ambient(argument2, argument3, [argument4, argument5], no_raise) {
                Ok(set) if linux_process::set_live_process_credentials(pid, credentials) => {
                    u64::from(set)
                }
                Ok(_) => LINUX_ESRCH,
                Err(linox_credentials::Error::Permission) => LINUX_EPERM,
                Err(linox_credentials::Error::Invalid) => LINUX_EINVAL,
            }
        }
        _ => LINUX_EINVAL,
    }
}

fn linux_set_process_name(address: u64) -> u64 {
    let mut name = [0_u8; LINUX_PROCESS_NAME_SIZE];
    for index in 0..LINUX_PROCESS_NAME_SIZE - 1 {
        let Some(source) = address.checked_add(index as u64) else {
            return LINUX_EFAULT;
        };
        if !copy_from_linux_user(source, &mut name[index..=index]) {
            return LINUX_EFAULT;
        }
        if name[index] == 0 {
            break;
        }
    }
    let mut low = [0_u8; 8];
    let mut high = [0_u8; 8];
    low.copy_from_slice(&name[..8]);
    high.copy_from_slice(&name[8..]);
    X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_LOW
        .store(u64::from_ne_bytes(low), Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_HIGH
        .store(u64::from_ne_bytes(high), Ordering::SeqCst);
    0
}

pub(super) fn linux_modify_ldt(function: u64, address: u64, byte_count: u64) -> u64 {
    match u64::from(function as u32) {
        // No process can install an LDT yet, so the current LDT is empty.
        0 => 0,
        // Linux x86-64 retains this Linux 2.4 compatibility operation and
        // returns at most 128 zero bytes.
        2 => {
            let length = usize::try_from(byte_count.min(128)).unwrap_or(128);
            let zeros = [0_u8; 64];
            let mut copied = 0;
            while copied < length {
                let count = (length - copied).min(zeros.len());
                let Some(destination) = address.checked_add(copied as u64) else {
                    return LINUX_EFAULT;
                };
                if !copy_to_linux_user(destination, &zeros[..count]) {
                    return LINUX_EFAULT;
                }
                copied += count;
            }
            length as u64
        }
        // Installing a per-mm LDT requires context-switch integration that
        // is deliberately not exposed by the current long-mode-only profile.
        _ => LINUX_ENOSYS,
    }
}

fn linux_get_process_name(address: u64) -> u64 {
    let mut name = [0_u8; LINUX_PROCESS_NAME_SIZE];
    name[..8].copy_from_slice(
        &X86_RUNTIME
            .ELF_PROBE_PROCESS_NAME_LOW
            .load(Ordering::SeqCst)
            .to_ne_bytes(),
    );
    name[8..].copy_from_slice(
        &X86_RUNTIME
            .ELF_PROBE_PROCESS_NAME_HIGH
            .load(Ordering::SeqCst)
            .to_ne_bytes(),
    );
    if copy_to_linux_user(address, &name) {
        0
    } else {
        LINUX_EFAULT
    }
}
