use super::*;

pub(super) fn linux_privileged_operation(number: u64) -> Option<linux_user::PrivilegedOperation> {
    use linux_user::PrivilegedOperation;
    match number {
        LINUX_CHROOT_SYSCALL | LINUX_PIVOT_ROOT_SYSCALL => Some(PrivilegedOperation::ChangeRoot),
        LINUX_MOUNT_SYSCALL
        | LINUX_SWAPON_SYSCALL
        | LINUX_SWAPOFF_SYSCALL
        | LINUX_OPEN_TREE_SYSCALL
        | LINUX_MOVE_MOUNT_SYSCALL
        | LINUX_FSOPEN_SYSCALL
        | LINUX_FSCONFIG_SYSCALL
        | LINUX_FSMOUNT_SYSCALL
        | LINUX_FSPICK_SYSCALL
        | LINUX_MOUNT_SETATTR_SYSCALL
        | LINUX_OPEN_TREE_ATTR_SYSCALL => Some(PrivilegedOperation::ManageMounts),
        LINUX_REBOOT_SYSCALL
        | LINUX_INIT_MODULE_SYSCALL
        | LINUX_DELETE_MODULE_SYSCALL
        | LINUX_KEXEC_LOAD_SYSCALL
        | LINUX_FINIT_MODULE_SYSCALL
        | LINUX_KEXEC_FILE_LOAD_SYSCALL => Some(PrivilegedOperation::ManageKernel),
        LINUX_SETNS_SYSCALL => Some(PrivilegedOperation::ManageNamespaces),
        LINUX_IOPL_SYSCALL | LINUX_IOPERM_SYSCALL => Some(PrivilegedOperation::RawIo),
        LINUX_BPF_SYSCALL => Some(PrivilegedOperation::LoadBpf),
        LINUX_SYSLOG_SYSCALL => Some(PrivilegedOperation::ObserveKernelLog),
        LINUX_ADJTIMEX_SYSCALL
        | LINUX_SETTIMEOFDAY_SYSCALL
        | LINUX_CLOCK_SETTIME_SYSCALL
        | LINUX_CLOCK_ADJTIME_SYSCALL => Some(PrivilegedOperation::ManageClock),
        LINUX_VHANGUP_SYSCALL => Some(PrivilegedOperation::ManageTerminal),
        LINUX_ACCT_SYSCALL => Some(PrivilegedOperation::ProcessAccounting),
        LINUX_QUOTACTL_SYSCALL | LINUX_QUOTACTL_FD_SYSCALL => {
            Some(PrivilegedOperation::ManageStorageQuota)
        }
        LINUX_PTRACE_SYSCALL => Some(PrivilegedOperation::TraceProcesses),
        _ => None,
    }
}

/// Whether the current process's domain lets root use `operation` (a
/// domain set `privileged=true`, `linux_user::domain_privileged`).
pub(super) fn linux_privileged_operation_allowed(
    operation: linux_user::PrivilegedOperation,
) -> bool {
    current_linux_user_namespace()
        .is_some_and(|namespace| !linux_user::privileged_operation_denied(namespace, operation))
}

pub(super) fn linux_has_capability(capability: u32) -> bool {
    current_linux_credentials().is_some_and(|credentials| credentials.has(capability))
}

pub(super) fn current_linux_user_namespace() -> Option<linux_user::UserNamespaceHandle> {
    linux_process::live_process_user_namespace(current_linux_process_pid())
}

pub(super) fn current_linux_credentials() -> Option<linux_user::Credentials> {
    linux_process::live_process_credentials(current_linux_process_pid())
}

/// The mode a new file (not a directory) at canonical `path` is made with:
/// `mode` without set-group-ID where the creator may not have it (see
/// [`linux_new_file_identity`]), judged before the umask, then the umask,
/// as Linux's `vfs_prepare_mode` orders them.
pub(super) fn linux_file_creation_mode(path: &[u8], mode: u32) -> u32 {
    let (_, _, mode) = linux_new_file_identity(path, false, mode);
    mode & !(X86_RUNTIME.ELF_PROBE_UMASK.load(Ordering::SeqCst) as u32)
}

/// The owner, group and mode of a file the current process creates at
/// canonical `path`: its filesystem ids (root outside a process). In a
/// set-group-ID directory the file takes the directory's group, a new
/// directory keeps the bit, and a set-group-ID, group-executable file whose
/// creator is neither root nor in that group loses it.
pub(crate) fn linux_new_file_identity(path: &[u8], directory: bool, mode: u32) -> (u32, u32, u32) {
    let credentials = current_linux_credentials().unwrap_or(linux_user::Credentials::ROOT);
    let owner = credentials.user.filesystem;
    let Some(parent) = linux_path_access(linux_parent_path(path))
        .filter(|parent| parent.directory && parent.mode & 0o2000 != 0)
    else {
        return (owner, credentials.group.filesystem, mode);
    };
    let mode = if directory {
        mode | 0o2000
    } else if mode & 0o2010 == 0o2010
        && !credentials.filesystem_privileged()
        && !linux_process::with_live_process_groups(current_linux_process_pid(), |groups| {
            credentials.in_group(groups, parent.group)
        })
        .unwrap_or(false)
    {
        mode & !0o2000
    } else {
        mode
    };
    (owner, parent.group, mode)
}

/// The set*id system calls, under the rules in `linox-credentials`; what
/// the process may switch to comes from `linux_user::identity_authority`.
pub(super) fn linux_set_current_identity(number: u64, first: u64, second: u64, third: u64) -> u64 {
    let pid = current_linux_process_pid();
    let (Some(namespace), Some(mut credentials)) = (
        current_linux_user_namespace(),
        linux_process::live_process_credentials(pid),
    ) else {
        return LINUX_ESRCH;
    };
    let authority = linux_user::identity_authority(namespace, &credentials);
    let old_user = credentials.user;
    let [first, second, third] = [first, second, third].map(|id| id as u32);
    let result = match number {
        LINUX_SETUID_SYSCALL => credentials.user.set(first, authority),
        LINUX_SETGID_SYSCALL => credentials.group.set(first, authority),
        LINUX_SETREUID_SYSCALL => credentials
            .user
            .set_real_effective(first, second, authority),
        LINUX_SETREGID_SYSCALL => credentials
            .group
            .set_real_effective(first, second, authority),
        LINUX_SETRESUID_SYSCALL => credentials
            .user
            .set_real_effective_saved(first, second, third, authority),
        LINUX_SETRESGID_SYSCALL => credentials
            .group
            .set_real_effective_saved(first, second, third, authority),
        LINUX_SETFSUID_SYSCALL | LINUX_SETFSGID_SYSCALL => {
            let ids = if number == LINUX_SETFSUID_SYSCALL {
                &mut credentials.user
            } else {
                &mut credentials.group
            };
            let old = ids.set_filesystem(first, authority);
            credentials.after_user_change(old_user);
            if !linux_process::set_live_process_credentials(pid, credentials) {
                return LINUX_ESRCH;
            }
            return u64::from(old);
        }
        _ => return LINUX_ENOSYS,
    };
    if result.is_ok() {
        credentials.after_user_change(old_user);
    }
    match result {
        Ok(()) if linux_process::set_live_process_credentials(pid, credentials) => 0,
        Ok(()) => LINUX_ESRCH,
        Err(linox_credentials::Error::Permission) => LINUX_EPERM,
        Err(linox_credentials::Error::Invalid) => LINUX_EINVAL,
    }
}

/// setgroups(2): only a process that may switch ids sets its groups.
pub(super) fn linux_set_current_groups(size: u64, address: u64) -> u64 {
    let pid = current_linux_process_pid();
    let (Some(namespace), Some(credentials)) = (
        current_linux_user_namespace(),
        linux_process::live_process_credentials(pid),
    ) else {
        return LINUX_ESRCH;
    };
    let authority = linux_user::identity_authority(namespace, &credentials);
    if !authority.privileged {
        return LINUX_EPERM;
    }
    let count = match usize::try_from(size as i32) {
        Ok(count) if count <= linox_credentials::GROUPS_LIMIT => count,
        _ => return LINUX_EINVAL,
    };
    let mut groups = Vec::new();
    if groups.try_reserve_exact(count).is_err() {
        return LINUX_ENOMEM;
    }
    for index in 0..count {
        let mut group = [0_u8; size_of::<u32>()];
        if !copy_from_linux_user(address + (index * size_of::<u32>()) as u64, &mut group) {
            return LINUX_EFAULT;
        }
        groups.push(u32::from_ne_bytes(group));
    }
    match linox_credentials::set_groups(&mut groups, authority) {
        Ok(()) if linux_process::set_live_process_groups(pid, groups) => 0,
        Ok(()) => LINUX_ESRCH,
        Err(linox_credentials::Error::Permission) => LINUX_EPERM,
        Err(linox_credentials::Error::Invalid) => LINUX_EINVAL,
    }
}

/// getgroups(2): the count when `size` is 0, else the sorted groups.
pub(super) fn linux_get_current_groups(size: u64, address: u64) -> u64 {
    let Ok(size) = usize::try_from(size as i32) else {
        return LINUX_EINVAL;
    };
    // The groups are copied out of the process table first: a copy to user
    // memory may fault, which must not happen under the table's lock.
    let bytes = linux_process::with_live_process_groups(current_linux_process_pid(), |groups| {
        if size == 0 {
            return Err(groups.len() as u64);
        }
        if size < groups.len() {
            return Err(LINUX_EINVAL);
        }
        let mut bytes = Vec::new();
        if bytes
            .try_reserve_exact(core::mem::size_of_val(groups))
            .is_err()
        {
            return Err(LINUX_ENOMEM);
        }
        bytes.extend(groups.iter().flat_map(|group| group.to_ne_bytes()));
        Ok(bytes)
    });
    match bytes {
        None => LINUX_ESRCH,
        Some(Err(result)) => result,
        Some(Ok(bytes)) if copy_to_linux_user(address, &bytes) => {
            (bytes.len() / core::mem::size_of::<u32>()) as u64
        }
        Some(Ok(_)) => LINUX_EFAULT,
    }
}

pub(super) fn copy_linux_id_triple(
    first: u64,
    second: u64,
    third: u64,
    ids: (u32, u32, u32),
) -> u64 {
    for (address, id) in [(first, ids.0), (second, ids.1), (third, ids.2)] {
        if !copy_to_linux_user(address, &id.to_ne_bytes()) {
            return LINUX_EFAULT;
        }
    }
    0
}

/// capget(2): a process's effective, permitted and inheritable sets, in
/// the layout of the header's version (one 32-bit word each for version
/// 1, two for 2 and 3); another version is EINVAL with version 3 written
/// back, as Linux prefers it.
pub(super) fn linux_capget(header_address: u64, data_address: u64) -> u64 {
    let mut header = [0_u8; 8];
    if !copy_from_linux_user(header_address, &mut header) {
        return LINUX_EFAULT;
    }
    let version = u32::from_ne_bytes(header[..4].try_into().unwrap());
    let words = match version {
        0x1998_0330 => 1,
        0x2007_1026 | LINUX_CAPABILITY_VERSION_3 => 2,
        _ => {
            return if copy_to_linux_user(header_address, &LINUX_CAPABILITY_VERSION_3.to_ne_bytes())
            {
                LINUX_EINVAL
            } else {
                LINUX_EFAULT
            };
        }
    };
    let pid = i32::from_ne_bytes(header[4..].try_into().unwrap());
    if pid < 0 {
        return LINUX_EINVAL;
    }
    let target = if pid == 0 {
        current_linux_process_pid()
    } else {
        pid as u32
    };
    let Some(credentials) = linux_process::live_process_credentials(target) else {
        return LINUX_ESRCH;
    };
    // With no data the call only checks the version (libcap probes so).
    if data_address == 0 {
        return 0;
    }
    let capabilities = credentials.capabilities;
    let mut data = [0_u8; LINUX_CAPABILITY_DATA_SIZE];
    for word in 0..words {
        let shift = 32 * word;
        for (index, set) in [
            capabilities.effective,
            capabilities.permitted,
            capabilities.inheritable,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = word * 12 + index * 4;
            data[offset..offset + 4].copy_from_slice(&((set >> shift) as u32).to_ne_bytes());
        }
    }
    if copy_to_linux_user(data_address, &data[..words * 12]) {
        0
    } else {
        LINUX_EFAULT
    }
}

/// capset(2): the caller's own sets (another pid is EPERM), within what
/// capabilities(7) allows (EPERM).
pub(super) fn linux_capset(header_address: u64, data_address: u64) -> u64 {
    let mut header = [0_u8; 8];
    if !copy_from_linux_user(header_address, &mut header) {
        return LINUX_EFAULT;
    }
    let version = u32::from_ne_bytes(header[..4].try_into().unwrap());
    let words = match version {
        0x1998_0330 => 1,
        0x2007_1026 | LINUX_CAPABILITY_VERSION_3 => 2,
        _ => {
            return if copy_to_linux_user(header_address, &LINUX_CAPABILITY_VERSION_3.to_ne_bytes())
            {
                LINUX_EINVAL
            } else {
                LINUX_EFAULT
            };
        }
    };
    let pid = i32::from_ne_bytes(header[4..].try_into().unwrap());
    let current = current_linux_process_pid();
    if pid != 0 && u32::try_from(pid).ok() != Some(current) {
        return LINUX_EPERM;
    }
    let mut data = [0_u8; LINUX_CAPABILITY_DATA_SIZE];
    if !copy_from_linux_user(data_address, &mut data[..words * 12]) {
        return LINUX_EFAULT;
    }
    let mut sets = [0_u64; 3];
    for word in 0..words {
        for (index, set) in sets.iter_mut().enumerate() {
            let offset = word * 12 + index * 4;
            let value = u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap());
            *set |= u64::from(value) << (32 * word);
        }
    }
    let Some(mut credentials) = linux_process::live_process_credentials(current) else {
        return LINUX_ESRCH;
    };
    let new = linox_credentials::Capabilities {
        effective: sets[0] & linox_credentials::capability::ALL,
        permitted: sets[1] & linox_credentials::capability::ALL,
        inheritable: sets[2] & linox_credentials::capability::ALL,
        bounding: credentials.capabilities.bounding,
        ambient: credentials.capabilities.ambient,
    };
    match credentials.set_capabilities(new) {
        Ok(()) if linux_process::set_live_process_credentials(current, credentials) => 0,
        Ok(()) => LINUX_ESRCH,
        Err(_) => LINUX_EPERM,
    }
}

/// Runs `change` on the calling process's credentials and keeps what it
/// leaves: its result, or EINVAL or EPERM for its error.
pub(super) fn linux_current_credentials_result(
    change: impl FnOnce(&mut linox_credentials::Credentials) -> Result<u64, linox_credentials::Error>,
) -> u64 {
    let current = current_linux_process_pid();
    let Some(mut credentials) = linux_process::live_process_credentials(current) else {
        return LINUX_ESRCH;
    };
    match change(&mut credentials) {
        Ok(result) if linux_process::set_live_process_credentials(current, credentials) => result,
        Ok(_) => LINUX_ESRCH,
        Err(linox_credentials::Error::Invalid) => LINUX_EINVAL,
        Err(linox_credentials::Error::Permission) => LINUX_EPERM,
    }
}
