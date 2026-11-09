#![forbid(unsafe_code)]
use super::*;
use crate::owned_state::OwnedState;
use crate::trusted::random::Rdrand;

pub(crate) fn linux_startup_random() -> Option<[u8; 16]> {
    let rdrand = Rdrand::detect()?;
    let mut output = [0_u8; 16];
    for chunk in output.as_chunks_mut::<8>().0 {
        let generated = (0..16).find_map(|_| rdrand.read());
        chunk.copy_from_slice(&generated?.to_ne_bytes());
    }
    Some(output)
}

/// /proc/sys/kernel/random/boot_id, made on first read.
static LINUX_BOOT_ID: OwnedState<[u8; 37]> = OwnedState::empty();

pub(super) fn linux_boot_id() -> &'static [u8] {
    if X86_RUNTIME.LINUX_BOOT_ID_STATE.load(Ordering::Acquire) != 2
        && X86_RUNTIME
            .LINUX_BOOT_ID_STATE
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        let mut random = linux_startup_random().unwrap_or([0x47; 16]);
        random[6] = random[6] & 0x0f | 0x40;
        random[8] = random[8] & 0x3f | 0x80;
        let mut output = [0_u8; 37];
        let hex = b"0123456789abcdef";
        let mut target = 0;
        for (index, byte) in random.into_iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                output[target] = b'-';
                target += 1;
            }
            output[target] = hex[usize::from(byte >> 4)];
            output[target + 1] = hex[usize::from(byte & 0x0f)];
            target += 2;
        }
        output[36] = b'\n';
        // Only the reader that moved the state from 0 to 1 gets here, so
        // the slot is still empty.
        let _ = LINUX_BOOT_ID.try_install(output);
        X86_RUNTIME.LINUX_BOOT_ID_STATE.store(2, Ordering::Release);
    }
    loop {
        if let Some(boot_id) = LINUX_BOOT_ID.get() {
            return boot_id;
        }
        core::hint::spin_loop();
    }
}

pub(super) fn linux_getrandom(address: u64, length: u64, flags: u64) -> u64 {
    linux_getrandom_with_copy(address, length, flags, copy_to_linux_user)
}

pub(super) fn linux_getrandom_with_copy(
    address: u64,
    length: u64,
    flags: u64,
    copy: fn(u64, &[u8]) -> bool,
) -> u64 {
    const LINUX_GRND_NONBLOCK: u64 = 1;
    const LINUX_GRND_RANDOM: u64 = 2;
    const LINUX_GRND_INSECURE: u64 = 4;
    const LINUX_GRND_SUPPORTED: u64 = LINUX_GRND_NONBLOCK | LINUX_GRND_RANDOM | LINUX_GRND_INSECURE;
    if flags & !LINUX_GRND_SUPPORTED != 0
        || flags & (LINUX_GRND_RANDOM | LINUX_GRND_INSECURE)
            == LINUX_GRND_RANDOM | LINUX_GRND_INSECURE
    {
        return LINUX_EINVAL;
    }
    let Ok(length) = usize::try_from(length) else {
        return LINUX_EFAULT;
    };
    let mut written = 0_usize;
    while written < length {
        let Some(random) = linux_startup_random() else {
            return if written == 0 {
                if flags & LINUX_GRND_NONBLOCK != 0 {
                    LINUX_EAGAIN
                } else {
                    LINUX_EIO
                }
            } else {
                written as u64
            };
        };
        let count = (length - written).min(random.len());
        let Some(destination) = address.checked_add(written as u64) else {
            return if written == 0 {
                LINUX_EFAULT
            } else {
                written as u64
            };
        };
        if !copy(destination, &random[..count]) {
            return if written == 0 {
                LINUX_EFAULT
            } else {
                written as u64
            };
        }
        written += count;
    }
    written as u64
}

/// reboot(2) in a domain set `privileged=true` acts on the machine:
/// restart, halt and power-off stop the domain and shut the kernel down
/// cleanly, ending in a cold reset for a restart.
pub(super) fn linux_reboot(magic: u64, magic2: u64, command: u64, argument: u64) -> u64 {
    const MAGIC: u32 = 0xfee1_dead;
    const MAGIC2: [u32; 4] = [672_274_793, 85_072_278, 369_367_448, 537_993_216];
    const RESTART: u32 = 0x0123_4567;
    const HALT: u32 = 0xcdef_0123;
    const CAD_ON: u32 = 0x89ab_cdef;
    const CAD_OFF: u32 = 0;
    const POWER_OFF: u32 = 0x4321_fedc;
    const RESTART2: u32 = 0xa1b2_c3d4;
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ManageKernel)
        || !linux_has_capability(linox_credentials::capability::SYS_BOOT)
    {
        return LINUX_EPERM;
    }
    if magic as u32 != MAGIC || !MAGIC2.contains(&(magic2 as u32)) {
        return LINUX_EINVAL;
    }
    match command as u32 {
        CAD_ON | CAD_OFF => {
            crate::machine_control::set_ctrl_alt_del(command as u32 == CAD_ON);
            0
        }
        RESTART | RESTART2 | HALT | POWER_OFF => {
            if command as u32 == RESTART2 {
                let mut reason = [0_u8; 256];
                if copy_linux_c_string(argument, &mut reason) == Err(LINUX_EFAULT) {
                    return LINUX_EFAULT;
                }
            }
            crate::machine_control::set_reset_kind(
                if matches!(command as u32, RESTART | RESTART2) {
                    crate::machine_control::RESET_COLD
                } else {
                    crate::machine_control::RESET_SHUTDOWN
                },
            );
            crate::serial_write("linox: privileged domain requested machine reset\r\n");
            X86_RUNTIME
                .CONTAINER_HOST_SHUTDOWN_REQUESTED
                .store(true, Ordering::SeqCst);
            if let Some(slot) = active_container_slot() {
                X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                    .store(control_abi::DOMAIN_STATE_STOPPED as u8, Ordering::SeqCst);
            }
            0
        }
        _ => LINUX_EINVAL,
    }
}

/// The time of day as (seconds, nanoseconds) since the epoch, or zero
/// before the clock is known: what files' times are set to.
pub(crate) fn linux_realtime_now() -> (i64, i64) {
    linux_time::linux_realtime_time().map_or((0, 0), |(seconds, nanoseconds)| {
        (seconds as i64, nanoseconds as i64)
    })
}

/// Nanoseconds since boot.
pub(crate) fn linux_uptime_nanoseconds() -> u64 {
    linux_time::linux_elapsed_nanoseconds().unwrap_or(0)
}

/// acct(2), in a domain set `privileged=true`: names the file a record is
/// appended to as each process of the domain exits, or turns accounting
/// off. The file is opened as Linux opens it (write-only, append), so
/// the same errors come back, and must be a regular file.
pub(super) fn linux_acct(path_address: u64) -> u64 {
    const O_WRONLY: u64 = 1;
    const O_APPEND: u64 = 0o2000;
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ProcessAccounting)
        || !linux_has_capability(linox_credentials::capability::SYS_PACCT)
    {
        return LINUX_EPERM;
    }
    let instance = linux_execution_instance();
    if path_address == 0 {
        crate::linux_accounting::set_file(instance, 0);
        return 0;
    }
    let descriptor = linux_openat(
        u64::from(LINUX_AT_FDCWD),
        path_address,
        O_WRONLY | O_APPEND,
        0,
    );
    if descriptor > u64::MAX - 4096 {
        return descriptor;
    }
    let handle = linux_overlay_descriptor_handle(descriptor).filter(|handle| {
        crate::linux_overlay::metadata(*handle)
            .is_some_and(|metadata| metadata.kind == crate::linux_overlay::NodeKind::File)
    });
    let _ = linux_descriptor_close(descriptor);
    let Some(handle) = handle else {
        return LINUX_EACCES;
    };
    crate::linux_accounting::set_file(
        instance,
        u64::from(crate::linux_overlay::generation(handle)),
    );
    0
}

/// Linux's comp_t: a 13-bit mantissa with a 3-bit base-8 exponent.
fn linux_comp_t(mut value: u64) -> u16 {
    let mut exponent = 0;
    while value > 0x1fff {
        value = (value + 4) >> 3;
        exponent += 1;
    }
    if exponent > 7 {
        return u16::MAX;
    }
    (exponent << 13 | value) as u16
}

/// Appends the accounting record (Linux's version 2 `struct acct`) of the
/// current process, exiting with wait status `status`, to its domain's
/// accounting file, if accounting is on.
pub(super) fn linux_account_exit(status: u32) {
    const AHZ: u64 = 100;
    let Some(generation) = crate::linux_accounting::file(linux_execution_instance()) else {
        return;
    };
    let Some(handle) = crate::linux_overlay::from_generation(generation as u32) else {
        return;
    };
    let Some(size) = crate::linux_overlay::metadata(handle).map(|metadata| metadata.size) else {
        return;
    };
    let pid = current_linux_process_pid();
    let credentials = current_linux_credentials();
    let (uid, gid) = credentials.map_or((0, 0), |credentials| {
        (credentials.user.real, credentials.group.real)
    });
    let now = linux_uptime_nanoseconds();
    let elapsed =
        now.saturating_sub(linux_process::live_process_started_nanoseconds(pid).unwrap_or(now));
    let started = linux_time::linux_realtime_time().map_or(0, |(seconds, _)| {
        seconds.saturating_sub(elapsed / 1_000_000_000)
    });
    let elapsed_ticks = elapsed / (1_000_000_000 / AHZ);
    let cpu_ticks = linux_time::linux_process_cpu_ticks(pid);
    let mut name = [0_u8; 16];
    let name = linux_process_name(pid, &mut name);
    let mut record = [0_u8; 64];
    record[1] = 2; // version
    record[2..4].copy_from_slice(&(uid.min(0xffff) as u16).to_ne_bytes());
    record[4..6].copy_from_slice(&(gid.min(0xffff) as u16).to_ne_bytes());
    record[8..12].copy_from_slice(&(started as u32).to_ne_bytes());
    record[12..14].copy_from_slice(&linux_comp_t(cpu_ticks).to_ne_bytes());
    record[16..18].copy_from_slice(&linux_comp_t(elapsed_ticks).to_ne_bytes());
    record[32..36].copy_from_slice(&status.to_ne_bytes());
    let name_length = name.len().min(16);
    record[36..36 + name_length].copy_from_slice(&name[..name_length]);
    record[53] = (elapsed_ticks >> 16) as u8;
    record[54..56].copy_from_slice(&(elapsed_ticks as u16).to_ne_bytes());
    record[56..60].copy_from_slice(&uid.to_ne_bytes());
    record[60..64].copy_from_slice(&gid.to_ne_bytes());
    let _ = crate::linux_overlay::write(handle, size, &record);
}

/// ioperm(2): checks the range as Linux does, then refuses to open I/O
/// ports in every domain, privileged ones too, since port access would
/// reach around the drivers' isolation. Closing ports is a no-op.
pub(super) fn linux_ioperm(from: u64, count: u64, turn_on: u64) -> u64 {
    const PORTS: u64 = 65_536;
    if from
        .checked_add(count)
        .is_none_or(|end| end <= from || end > PORTS)
    {
        return LINUX_EINVAL;
    }
    if turn_on != 0 {
        LINUX_EPERM
    } else {
        0
    }
}

/// iopl(2): levels above 3 are EINVAL; raising the level is refused in
/// every domain (see `linux_ioperm`), keeping level 0 is allowed.
pub(super) fn linux_iopl(level: u64) -> u64 {
    match level as u32 {
        0 => 0,
        1..=3 => LINUX_EPERM,
        _ => LINUX_EINVAL,
    }
}

/// vhangup(2): the caller has no controlling terminal of its own to hang
/// up in a domain, so it only checks authority.
pub(super) fn linux_vhangup() -> u64 {
    if linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ManageTerminal)
        && linux_has_capability(linox_credentials::capability::SYS_TTY_CONFIG)
    {
        0
    } else {
        LINUX_EPERM
    }
}

/// delete_module(2): Linox loads no kernel modules, so none is found.
pub(super) fn linux_delete_module(name: u64) -> u64 {
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ManageKernel)
        || !linux_has_capability(linox_credentials::capability::SYS_MODULE)
    {
        return LINUX_EPERM;
    }
    // Linux reads at most MODULE_NAME_LEN - 1 bytes of the name.
    let mut module = [0_u8; 56];
    match copy_linux_c_string(name, &mut module) {
        Err(LINUX_EFAULT) => LINUX_EFAULT,
        _ => LINUX_ENOENT,
    }
}

/// syslog(2) on the machine's kernel log (`kernel_log`), for a domain set
/// `privileged=true`. READ does not wait for new messages.
pub(super) fn linux_syslog(action: u64, buffer: u64, length: u64) -> u64 {
    let (action, length) = (action as i32, length as i32);
    // Anyone may read the whole log or ask its size (dmesg_restrict off);
    // the rest needs CAP_SYSLOG (or CAP_SYS_ADMIN).
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ObserveKernelLog)
        || !matches!(action, 3 | 10)
            && !linux_has_capability(linox_credentials::capability::SYSLOG)
            && !linux_has_capability(linox_credentials::capability::SYS_ADMIN)
    {
        return LINUX_EPERM;
    }
    match action {
        0 | 1 | 5..=7 => {
            if action == 5 {
                crate::kernel_log::clear();
            }
            0
        }
        2..=4 => {
            if buffer == 0 || length < 0 {
                return LINUX_EINVAL;
            }
            if length == 0 {
                return 0;
            }
            let mut bytes = alloc::vec![0_u8; (length as usize).min(crate::kernel_log::CAPACITY)];
            let count = if action == 2 {
                crate::kernel_log::read_unread(&mut bytes)
            } else {
                crate::kernel_log::read_recent(&mut bytes)
            };
            if !copy_to_linux_user(buffer, &bytes[..count]) {
                return LINUX_EFAULT;
            }
            if action == 4 {
                crate::kernel_log::clear();
            }
            count as u64
        }
        8 if (1..=8).contains(&length) => 0,
        9 => crate::kernel_log::unread(),
        10 => crate::kernel_log::CAPACITY as u64,
        _ => LINUX_EINVAL,
    }
}

pub(super) fn linux_deny_privileged_operation(number: u64) -> u64 {
    let Some(namespace) = current_linux_user_namespace() else {
        return LINUX_ESRCH;
    };
    let Some(operation) = linux_privileged_operation(number) else {
        return LINUX_ENOSYS;
    };
    if linux_user::privileged_operation_denied(namespace, operation) {
        return LINUX_EPERM;
    }
    // Allowed here but not implemented yet: a caller without the Linux
    // capability the operation needs is refused as Linux would refuse it.
    use linox_credentials::capability;
    use linux_user::PrivilegedOperation;
    let needed = match operation {
        PrivilegedOperation::ChangeRoot => capability::SYS_CHROOT,
        PrivilegedOperation::RawIo => capability::SYS_RAWIO,
        PrivilegedOperation::ObserveKernelLog => capability::SYSLOG,
        PrivilegedOperation::ManageClock => capability::SYS_TIME,
        PrivilegedOperation::ProcessAccounting => capability::SYS_PACCT,
        PrivilegedOperation::ManageTerminal => capability::SYS_TTY_CONFIG,
        PrivilegedOperation::TraceProcesses => capability::SYS_PTRACE,
        PrivilegedOperation::ManageKernel => capability::SYS_BOOT,
        PrivilegedOperation::ManageMounts
        | PrivilegedOperation::ManageNamespaces
        | PrivilegedOperation::LoadBpf
        | PrivilegedOperation::ManageStorageQuota => capability::SYS_ADMIN,
    };
    if linux_has_capability(needed) {
        LINUX_ENOSYS
    } else {
        LINUX_EPERM
    }
}

/// The contents of a `/proc/sys` value file (`LINUX_PROC_SYSCTLS`) as
/// built in; a value the domain wrote is served by `linux_regular_file_read_at`.
pub(super) fn linux_proc_sysctl(state: u16) -> Option<&'static [u8]> {
    LINUX_PROC_SYSCTLS
        .iter()
        .find(|(node, ..)| state & !3 == LINUX_FILE_MASK | node)
        .map(|(.., contents)| *contents)
}

/// The index in `LINUX_PROC_SYSCTLS` of the value file a descriptor state names.
pub(super) fn linux_proc_sysctl_index(state: u16) -> Option<usize> {
    LINUX_PROC_SYSCTLS
        .iter()
        .position(|(node, ..)| state & !3 == LINUX_FILE_MASK | node)
}

/// Each domain's wall-clock offset from the host clock in nanoseconds:
/// clock_settime, settimeofday and adjtimex move a domain's CLOCK_REALTIME
/// without touching the host's or another domain's.
static LINUX_REALTIME_OFFSET_NANOSECONDS: [core::sync::atomic::AtomicI64;
    control_abi::DOMAIN_LIMIT] =
    [const { core::sync::atomic::AtomicI64::new(0) }; control_abi::DOMAIN_LIMIT];

/// Each domain's NTP status word (adjtimex's STA_* bits, as ADJ_STATUS set
/// them) and, while STA_INS is set, the wall-clock second at which the
/// leap second it asks for is due (the next midnight UTC when it was set).
static LINUX_NTP_STATUS: [AtomicU32; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU32::new(0) }; control_abi::DOMAIN_LIMIT];
static LINUX_NTP_LEAP_SECOND: [AtomicU64; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU64::new(0) }; control_abi::DOMAIN_LIMIT];

/// Sets the current domain's NTP status to `status` (its writable bits)
/// at wall-clock second `now`, scheduling a leap second at the next
/// midnight when STA_INS or STA_DEL is newly set.
pub(super) fn linux_set_ntp_status(status: u32, now: u64) {
    const STA_INS: u32 = 0x0010;
    const STA_DEL: u32 = 0x0020;
    // STA_PPSSIGNAL, PPSJITTER, PPSWANDER, PPSERROR, CLOCKERR, NANO, MODE
    // and CLK are the kernel's to report, not to set.
    const READ_ONLY: u32 = 0xff00;
    let Some(slot) = current_container_slot() else {
        return;
    };
    let old = LINUX_NTP_STATUS[slot].swap(status & !READ_ONLY, Ordering::AcqRel);
    if status & (STA_INS | STA_DEL) != 0 && old & (STA_INS | STA_DEL) == 0 {
        LINUX_NTP_LEAP_SECOND[slot].store(now - now % 86_400 + 86_400, Ordering::Release);
    }
}

/// The current domain's NTP status and its clock state at wall-clock second
/// `now`, as adjtimex returns it: TIME_INS or TIME_DEL until a scheduled
/// leap second, TIME_WAIT after it while the flag stays set, TIME_ERROR
/// for an unsynchronized clock, else TIME_OK.
pub(super) fn linux_ntp_state(now: u64) -> (u32, u64) {
    const STA_INS: u32 = 0x0010;
    const STA_DEL: u32 = 0x0020;
    const STA_UNSYNC: u32 = 0x0040;
    let Some(slot) = current_container_slot() else {
        return (0, 0);
    };
    let status = LINUX_NTP_STATUS[slot].load(Ordering::Acquire);
    let leap = LINUX_NTP_LEAP_SECOND[slot].load(Ordering::Acquire);
    let state = if status & (STA_INS | STA_DEL) != 0 {
        if now >= leap {
            4
        } else if status & STA_INS != 0 {
            1
        } else {
            2
        }
    } else if status & STA_UNSYNC != 0 {
        5
    } else {
        0
    };
    (status, state)
}

/// The current domain's wall-clock offset (`LINUX_REALTIME_OFFSET_NANOSECONDS`).
pub(super) fn linux_realtime_offset_nanoseconds() -> i64 {
    current_container_slot().map_or(0, |slot| {
        LINUX_REALTIME_OFFSET_NANOSECONDS[slot].load(Ordering::Acquire)
    })
}

/// Moves the current domain's wall clock by `delta` nanoseconds.
pub(super) fn linux_adjust_realtime_offset(delta: i64) -> bool {
    let Some(slot) = current_container_slot() else {
        return false;
    };
    let offset = &LINUX_REALTIME_OFFSET_NANOSECONDS[slot];
    offset.store(
        offset.load(Ordering::Acquire).saturating_add(delta),
        Ordering::Release,
    );
    // The vDSO page shows the new time at once, not at its next refresh.
    let _ = refresh_linux_vvar();
    true
}

/// A domain has not written this `/proc/sys` value.
const LINUX_SYSCTL_UNSET: i64 = i64::MIN;

/// The `/proc/sys` values each domain wrote, by index in `LINUX_PROC_SYSCTLS`:
/// reads then show the written number instead of the built-in text, and the
/// kernel consults the ones it acts on (`linux_proc_sysctl_value`). Each
/// domain has its own, as it has its own hostname.
static LINUX_SYSCTL_OVERRIDES: [[core::sync::atomic::AtomicI64; LINUX_PROC_SYSCTLS.len()];
    control_abi::DOMAIN_LIMIT] = [const {
    [const { core::sync::atomic::AtomicI64::new(LINUX_SYSCTL_UNSET) }; LINUX_PROC_SYSCTLS.len()]
}; control_abi::DOMAIN_LIMIT];

/// Each domain's host and domain name (Linux's UTS namespace: a domain
/// has its own), as sethostname, setdomainname and
/// /proc/sys/kernel/domainname set them; unset, the built-in ones. Bytes and
/// a length (0: unset) per name; names are short and rarely written, so a
/// torn read shows at worst a name being changed.
pub(super) const LINUX_UTS_NAME_CAPACITY: usize = 64;
pub(super) const LINUX_UTS_HOST: usize = 0;
pub(super) const LINUX_UTS_DOMAIN: usize = 1;
static LINUX_UTS_NAMES: [[[AtomicU8; LINUX_UTS_NAME_CAPACITY]; 2]; control_abi::DOMAIN_LIMIT] =
    [const { [const { [const { AtomicU8::new(0) }; LINUX_UTS_NAME_CAPACITY] }; 2] };
        control_abi::DOMAIN_LIMIT];
static LINUX_UTS_LENGTHS: [[AtomicU8; 2]; control_abi::DOMAIN_LIMIT] =
    [const { [const { AtomicU8::new(0) }; 2] }; control_abi::DOMAIN_LIMIT];

/// The current process's host (`LINUX_UTS_HOST`) or domain name into
/// `output`, its length returned: its UTS namespace's, or the domain's.
pub(super) fn linux_uts_name(kind: usize, output: &mut [u8; LINUX_UTS_NAME_CAPACITY]) -> usize {
    let namespace = current_linux_namespaces().uts;
    if namespace != 0 {
        if let Some(length) =
            linux_namespace::uts_name(linux_execution_instance(), namespace, kind, output)
        {
            return length;
        }
    }
    let set = current_container_slot().and_then(|slot| {
        let length = usize::from(LINUX_UTS_LENGTHS[slot][kind].load(Ordering::Acquire));
        (length != 0).then(|| {
            let length = length - 1;
            for (byte, stored) in output
                .iter_mut()
                .zip(&LINUX_UTS_NAMES[slot][kind][..length])
            {
                *byte = stored.load(Ordering::Relaxed);
            }
            length
        })
    });
    set.unwrap_or_else(|| {
        let default: &[u8] = if kind == LINUX_UTS_HOST {
            b"linox"
        } else {
            b"localdomain"
        };
        output[..default.len()].copy_from_slice(default);
        default.len()
    })
}

fn linux_uts_set(kind: usize, name: &[u8]) -> bool {
    let namespace = current_linux_namespaces().uts;
    if namespace != 0 {
        return linux_namespace::set_uts_name(linux_execution_instance(), namespace, kind, name);
    }
    let Some(slot) = current_container_slot() else {
        return false;
    };
    if name.len() > LINUX_UTS_NAME_CAPACITY {
        return false;
    }
    for (stored, byte) in LINUX_UTS_NAMES[slot][kind].iter().zip(name) {
        stored.store(*byte, Ordering::Relaxed);
    }
    LINUX_UTS_LENGTHS[slot][kind].store(name.len() as u8 + 1, Ordering::Release);
    true
}

/// sethostname(2) and setdomainname(2): at most 64 bytes (EINVAL, as is a
/// negative length), readable (EFAULT), by root of the domain (EPERM).
pub(super) fn linux_set_uts_name(kind: usize, address: u64, length: u64) -> u64 {
    let length = length as i64;
    if !(0..=LINUX_UTS_NAME_CAPACITY as i64).contains(&length) {
        return LINUX_EINVAL;
    }
    if !current_linux_credentials().is_some_and(|credentials| credentials.privileged()) {
        return LINUX_EPERM;
    }
    let mut name = [0_u8; LINUX_UTS_NAME_CAPACITY];
    let length = length as usize;
    if !copy_from_linux_user(address, &mut name[..length]) {
        return LINUX_EFAULT;
    }
    if linux_uts_set(kind, &name[..length]) {
        0
    } else {
        LINUX_EIO
    }
}

/// The number the current domain wrote to `/proc/sys` value `index`, if any.
pub(super) fn linux_proc_sysctl_override(index: usize) -> Option<i64> {
    // A network namespace made in the domain has /proc/sys/net of its own.
    if let Some(number) = linux_net_sysctl_number(index) {
        let network = current_linux_namespaces().net;
        if network != 0 {
            return linux_namespace::net_sysctl(linux_execution_instance(), network, number);
        }
    }
    let slot = current_container_slot()?;
    let value = LINUX_SYSCTL_OVERRIDES[slot][index].load(Ordering::Acquire);
    (value != LINUX_SYSCTL_UNSET).then_some(value)
}

/// The number the current domain wrote to the `/proc/sys` value at `path`
/// (under `/proc`, as `LINUX_PROC_SYSCTLS` names it), for the values the
/// kernel acts on: pipe-max-size, msg_next_id and shm_next_id.
pub(super) fn linux_proc_sysctl_value(path: &[u8]) -> Option<i64> {
    let index = LINUX_PROC_SYSCTLS
        .iter()
        .position(|(_, name, _)| *name == path)?;
    linux_proc_sysctl_override(index)
}

/// Sets the current domain's `/proc/sys` value at `path`: the kernel puts
/// msg_next_id and shm_next_id back to -1 once a creation used them.
pub(super) fn linux_proc_sysctl_set(path: &[u8], value: i64) {
    let Some(index) = LINUX_PROC_SYSCTLS
        .iter()
        .position(|(_, name, _)| *name == path)
    else {
        return;
    };
    let Some(slot) = current_container_slot() else {
        return;
    };
    LINUX_SYSCTL_OVERRIDES[slot][index].store(value, Ordering::Release);
}

/// The most descriptors a process of the current domain may have:
/// `/proc/sys/fs/nr_open` as written, else the built-in.
pub(super) fn linux_nr_open() -> u64 {
    linux_proc_sysctl_value(b"sys/fs/nr_open")
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(LINUX_NR_OPEN)
}

/// The most memory areas a process of the current domain may have:
/// `/proc/sys/vm/max_map_count` as written, else the built-in.
pub(super) fn linux_max_map_count() -> usize {
    linux_proc_sysctl_value(b"sys/vm/max_map_count")
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(LINUX_MAX_MAP_COUNT)
}

/// The largest pipe an unprivileged process of the current domain may ask
/// for or get: `/proc/sys/fs/pipe-max-size` as written, else the built-in.
pub(super) fn linux_pipe_max_size() -> u64 {
    linux_proc_sysctl_value(b"sys/fs/pipe-max-size")
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(LINUX_PIPE_MAX_SIZE)
}

/// Writes a `/proc/sys` value: a number in Linux's integer syntax, from a
/// process with root's effective user id, as Linux wants CAP_SYS_ADMIN.
/// A write of /proc/sys/kernel/domainname: the name up to a newline, as
/// setdomainname sets it, by root.
pub(super) fn linux_proc_domainname_write(device: u16, address: u64, count: u64) -> u64 {
    let mut text = [0_u8; LINUX_UTS_NAME_CAPACITY + 1];
    let length = usize::try_from(count).map_or(text.len(), |count| count.min(text.len()));
    if device & 3 & LINUX_DESCRIPTOR_OUTPUT != 0
        && current_linux_credentials().is_some_and(|credentials| credentials.user.effective == 0)
        && !copy_from_linux_user(address, &mut text[..length])
    {
        return LINUX_EFAULT;
    }
    linux_proc_domainname_write_bytes(device, &text[..length]).map_or_else(|error| error, |_| count)
}

/// The domainname write of `text`, from the kernel's own buffer (splice):
/// the bytes taken, or the error.
pub(super) fn linux_proc_domainname_write_bytes(device: u16, text: &[u8]) -> Result<usize, u64> {
    if device & 3 & LINUX_DESCRIPTOR_OUTPUT == 0 {
        return Err(LINUX_EBADF);
    }
    if current_linux_credentials().is_none_or(|credentials| credentials.user.effective != 0) {
        return Err(LINUX_EACCES);
    }
    let name = text
        .split(|byte| *byte == b'\n' || *byte == 0)
        .next()
        .unwrap_or_default();
    if name.len() > LINUX_UTS_NAME_CAPACITY || !linux_uts_set(LINUX_UTS_DOMAIN, name) {
        return Err(LINUX_EINVAL);
    }
    Ok(text.len())
}

pub(super) fn linux_proc_sysctl_write(device: u16, index: usize, address: u64, count: u64) -> u64 {
    let mut text = [0_u8; LINUX_SYSCTL_TEXT_CAPACITY];
    let length = usize::try_from(count).map_or(text.len(), |count| count.min(text.len()));
    if device & 3 & LINUX_DESCRIPTOR_OUTPUT != 0
        && current_linux_credentials().is_some_and(|credentials| credentials.user.effective == 0)
        && !copy_from_linux_user(address, &mut text[..length])
    {
        return LINUX_EFAULT;
    }
    linux_proc_sysctl_write_bytes(device, index, &text[..length])
        .map_or_else(|error| error, |_| count)
}

/// The /proc/sys write of `text` to value `index`, from the kernel's own
/// buffer (splice): the bytes taken, or the error.
pub(super) fn linux_proc_sysctl_write_bytes(
    device: u16,
    index: usize,
    text: &[u8],
) -> Result<usize, u64> {
    if device & 3 & LINUX_DESCRIPTOR_OUTPUT == 0 {
        return Err(LINUX_EBADF);
    }
    if current_linux_credentials().is_none_or(|credentials| credentials.user.effective != 0) {
        return Err(LINUX_EACCES);
    }
    // core_pattern is text: up to a newline, as Linux's proc_dostring
    // takes it.
    if LINUX_PROC_SYSCTLS[index].1 == b"sys/kernel/core_pattern" {
        let pattern = text
            .split(|byte| *byte == b'\n' || *byte == 0)
            .next()
            .unwrap_or_default();
        return if crate::linux_core::set_pattern(linux_execution_instance(), pattern) {
            Ok(text.len())
        } else {
            Err(LINUX_EINVAL)
        };
    }
    let Some(slot) = current_container_slot() else {
        return Err(LINUX_EIO);
    };
    let value = if LINUX_PROC_SYSCTLS[index].1 == LINUX_PING_GROUP_RANGE {
        linux_ping_group_range_parse(text)?
    } else {
        text.split(|byte| *byte == 0)
            .next()
            .and_then(|text| linux_parse_kernel_integer(text.trim_ascii()))
            .ok_or(LINUX_EINVAL)?
    };
    // Values with bounds (proc_dointvec_minmax): io_uring_disabled is 0, 1
    // or 2, the link restrictions are off or on, and key quotas are from 1
    // to INT_MAX.
    let bounds = match LINUX_PROC_SYSCTLS[index].1 {
        b"sys/kernel/io_uring_disabled" => Some(0..=2),
        b"sys/fs/protected_hardlinks" | b"sys/fs/protected_symlinks" => Some(0..=1),
        b"sys/vm/drop_caches" => Some(1..=4),
        b"sys/vm/swappiness" => Some(0..=200),
        b"sys/vm/nr_hugepages"
        | b"sys/vm/nr_overcommit_hugepages"
        | b"sys/vm/vfs_cache_pressure"
        | b"sys/vm/min_free_kbytes" => Some(0..=i64::from(i32::MAX)),
        b"sys/vm/hugetlb_shm_group" => Some(0..=i64::from(u32::MAX)),
        // Any int, as Linux's proc_dointvec takes; the sample rate at
        // least 1.
        b"sys/kernel/perf_event_paranoid" | b"sys/kernel/perf_event_max_stack" => {
            Some(i64::from(i32::MIN)..=i64::from(i32::MAX))
        }
        b"sys/kernel/perf_event_max_sample_rate" => Some(1..=i64::from(i32::MAX)),
        b"sys/kernel/perf_event_mlock_kb" => Some(0..=i64::from(i32::MAX)),
        b"sys/kernel/keys/maxkeys"
        | b"sys/kernel/keys/maxbytes"
        | b"sys/kernel/keys/root_maxkeys"
        | b"sys/kernel/keys/root_maxbytes" => Some(1..=i64::from(i32::MAX)),
        b"sys/kernel/keys/gc_delay" => Some(0..=i64::from(i32::MAX)),
        _ => None,
    };
    if bounds.is_some_and(|bounds| !bounds.contains(&value)) {
        return Err(LINUX_EINVAL);
    }
    if let Some(number) = linux_net_sysctl_number(index) {
        let network = current_linux_namespaces().net;
        if network != 0 {
            return if linux_namespace::set_net_sysctl(
                linux_execution_instance(),
                network,
                number,
                value,
            ) {
                Ok(text.len())
            } else {
                Err(LINUX_EIO)
            };
        }
    }
    if let Some(set) = linux_fanotify_set_limit(LINUX_PROC_SYSCTLS[index].1, value) {
        return if set {
            Ok(text.len())
        } else {
            Err(LINUX_EINVAL)
        };
    }
    if LINUX_PROC_SYSCTLS[index].1 == b"sys/vm/drop_caches" {
        if value & 1 != 0 {
            crate::linux_blockfs::drop_caches();
        }
        // 2 drops the inode and dentry caches, and the evictable fanotify
        // marks with them.
        if value & 2 != 0 {
            crate::linux_fanotify::evict(linux_execution_instance());
        }
    }
    // The pool gets as many huge pages as memory allows, which reads back.
    let value = if LINUX_PROC_SYSCTLS[index].1 == b"sys/vm/nr_hugepages" {
        linux_huge_pool_size_for(value)
    } else {
        value
    };
    LINUX_SYSCTL_OVERRIDES[slot][index].store(value, Ordering::Release);
    Ok(text.len())
}

/// A two-number /proc/sys value as its one stored number: the first in the
/// high half. Both are at most `LINUX_PING_GROUP_MAX`, so the result never
/// meets `LINUX_SYSCTL_UNSET`.
fn linux_sysctl_pack_pair(low: u64, high: u64) -> i64 {
    ((low << 32) | high) as i64
}

pub(super) fn linux_sysctl_unpack_pair(value: i64) -> (u64, u64) {
    let value = value as u64;
    (value >> 32, value & 0xffff_ffff)
}

/// The current namespace's ping_group_range: the lowest and highest gid
/// that may make ping sockets.
fn linux_ping_group_range() -> (u64, u64) {
    linux_proc_sysctl_value(LINUX_PING_GROUP_RANGE)
        .map_or((0, LINUX_PING_GROUP_MAX as u64), linux_sysctl_unpack_pair)
}

/// A write of ping_group_range: one or two numbers from 0 to
/// `LINUX_PING_GROUP_MAX` (EINVAL otherwise, as proc_dointvec_minmax
/// answers); one number sets the low end alone. A range whose high end is
/// below its low end is stored as Linux stores it, "1 0" (none).
fn linux_ping_group_range_parse(text: &[u8]) -> Result<i64, u64> {
    let text = text.split(|byte| *byte == 0).next().unwrap_or_default();
    let mut numbers = text
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .map(|field| {
            linux_parse_kernel_integer(field)
                .filter(|value| (0..=LINUX_PING_GROUP_MAX).contains(value))
                .map(|value| value as u64)
                .ok_or(LINUX_EINVAL)
        });
    let low = numbers.next().ok_or(LINUX_EINVAL)??;
    let high = match numbers.next() {
        Some(high) => high?,
        None => linux_ping_group_range().1,
    };
    if numbers.next().is_some() {
        return Err(LINUX_EINVAL);
    }
    Ok(if high < low {
        linux_sysctl_pack_pair(1, 0)
    } else {
        linux_sysctl_pack_pair(low, high)
    })
}

/// Whether the current process may make a ping socket: its effective group
/// or one of its supplementary groups is in ping_group_range (Linux's
/// ping_init_sock; CAP_NET_RAW does not matter).
pub(super) fn linux_ping_allowed() -> bool {
    let (low, high) = linux_ping_group_range();
    let within = |group: u32| (low..=high).contains(&u64::from(group));
    let Some(credentials) = current_linux_credentials() else {
        return false;
    };
    within(credentials.group.effective)
        || linux_process::with_live_process_groups(current_linux_process_pid(), |groups| {
            groups.iter().any(|group| within(*group))
        })
        .unwrap_or(false)
}

/// Where among the /proc/sys/net values, which each network namespace
/// keeps for itself, `LINUX_PROC_SYSCTLS` value `index` is.
fn linux_net_sysctl_number(index: usize) -> Option<usize> {
    let is_net = |path: &[u8]| path.starts_with(b"sys/net/");
    is_net(LINUX_PROC_SYSCTLS.get(index)?.1).then(|| {
        LINUX_PROC_SYSCTLS[..index]
            .iter()
            .filter(|(_, path, _)| is_net(path))
            .count()
    })
}

/// The longest /proc/sys value text: a core pattern and its newline.
pub(super) const LINUX_SYSCTL_TEXT_CAPACITY: usize = crate::linux_core::PATTERN_MAX + 2;

pub(super) fn linux_membarrier(command: u64, flags: u64, _cpu_id: u64) -> u64 {
    let command = command as u32;
    let flags = flags as u32;
    if command == MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ {
        if !matches!(flags, 0 | MEMBARRIER_CMD_FLAG_CPU) {
            return LINUX_EINVAL;
        }
    } else if flags != 0 {
        return LINUX_EINVAL;
    }
    match command {
        MEMBARRIER_CMD_QUERY => u64::from(MEMBARRIER_SUPPORTED_COMMANDS),
        MEMBARRIER_CMD_GLOBAL | MEMBARRIER_CMD_GLOBAL_EXPEDITED => {
            core::sync::atomic::fence(Ordering::SeqCst);
            0
        }
        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED => {
            X86_RUNTIME
                .ELF_PROBE_MEMBARRIER_REGISTRATIONS
                .fetch_or(command, Ordering::SeqCst);
            0
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED => {
            if X86_RUNTIME
                .ELF_PROBE_MEMBARRIER_REGISTRATIONS
                .load(Ordering::SeqCst)
                & MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
                == 0
            {
                return LINUX_EPERM;
            }
            core::sync::atomic::fence(Ordering::SeqCst);
            0
        }
        MEMBARRIER_CMD_GET_REGISTRATIONS => u64::from(
            X86_RUNTIME
                .ELF_PROBE_MEMBARRIER_REGISTRATIONS
                .load(Ordering::SeqCst),
        ),
        _ => LINUX_EINVAL,
    }
}
