use super::*;

/// The namespace `/proc/PID/ns/NAME` names: process PID's (`self` and
/// `thread-self` for the caller) namespace of that kind. `None` for any
/// other path; `Some(Err(ENOENT))` when the process or the name is unknown.
pub(super) fn linux_proc_namespace_at(
    path: &[u8],
) -> Option<Result<linux_namespace::Reference, u64>> {
    use linux_namespace::{Kind, Reference};
    let rest = path.strip_prefix(b"/proc/")?;
    let slash = rest.iter().position(|byte| *byte == b'/')?;
    let name = rest[slash + 1..].strip_prefix(b"ns/")?;
    let owner = &rest[..slash];
    let pid = match owner {
        b"self" | b"thread-self" => current_linux_process_pid(),
        digits if !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) => {
            core::str::from_utf8(digits).ok()?.parse::<u32>().ok()?
        }
        _ => return None,
    };
    let Some(set) = linux_process::live_process_namespaces(pid) else {
        return Some(Err(LINUX_ENOENT));
    };
    let other = |kind, id| {
        Ok(Reference {
            kind,
            id,
            handle: 0,
        })
    };
    Some(match name {
        b"user" => linux_process::live_process_user_namespace(pid)
            .map(|handle| Reference {
                kind: Kind::User,
                id: handle.id(),
                handle: handle.to_word(),
            })
            .ok_or(LINUX_ENOENT),
        b"mnt" => if pid == current_linux_process_pid() {
            linux_mount::current_handle()
        } else {
            with_valid_linux_process_runtime_state(pid, |state| state.mount_namespace).flatten()
        }
        .map(|handle| Reference {
            kind: Kind::Mount,
            id: handle.id(),
            handle: handle.to_word(),
        })
        .ok_or(LINUX_ENOENT),
        b"uts" => other(Kind::Uts, set.uts),
        b"ipc" => other(Kind::Ipc, set.ipc),
        b"pid" => other(Kind::Pid, set.pid),
        b"pid_for_children" => other(Kind::Pid, set.pid_for_children),
        b"time" => other(Kind::Time, set.time),
        b"time_for_children" => other(Kind::Time, set.time_for_children),
        b"net" => other(Kind::Net, set.net),
        // One cgroup namespace per domain so far.
        b"cgroup" => other(Kind::Cgroup, 0),
        _ => Err(LINUX_ENOENT),
    })
}

/// What readlink shows for a namespace: `uts:[4026531838]`.
pub(super) fn linux_namespace_link(
    reference: linux_namespace::Reference,
    output: &mut [u8; 32],
) -> usize {
    let mut used = 0;
    let _ = append_linux_bytes(output, &mut used, reference.kind.name())
        && append_linux_bytes(output, &mut used, b":[")
        && append_linux_decimal(output, &mut used, reference.inode())
        && append_linux_bytes(output, &mut used, b"]");
    used
}

/// stat of a namespace file (nsfs): a read-only regular file whose inode
/// tells namespaces apart; or with `follow` false, of the /proc/PID/ns
/// link to it.
pub(super) fn linux_namespace_stat(
    reference: linux_namespace::Reference,
    follow: bool,
) -> [u8; LINUX_STAT_SIZE] {
    const NSFS_DEVICE: u64 = 4;
    if !follow {
        let mut link = [0_u8; 32];
        let length = linux_namespace_link(reference, &mut link);
        let mut stat = linux_stat(0o120_777, 0);
        stat[48..56].copy_from_slice(&(length as u64).to_ne_bytes());
        return stat;
    }
    let mut stat = linux_stat(0o100_444, reference.inode());
    stat[..8].copy_from_slice(&NSFS_DEVICE.to_ne_bytes());
    stat
}

/// stat, lstat (`follow` false) and statx of a /proc/PID/ns path: `None`
/// for any other path.
pub(super) fn linux_proc_namespace_stat(
    path: &[u8],
    follow: bool,
) -> Option<Result<[u8; LINUX_STAT_SIZE], u64>> {
    Some(linux_proc_namespace_at(path)?.map(|reference| linux_namespace_stat(reference, follow)))
}

pub(super) fn linux_namespace_descriptor(descriptor: u64) -> bool {
    linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_NAMESPACE
}

/// The namespace a namespace descriptor (from /proc/PID/ns) refers to.
pub(super) fn linux_namespace_reference(descriptor: u64) -> Option<linux_namespace::Reference> {
    if !linux_namespace_descriptor(descriptor) {
        return None;
    }
    linux_namespace::Reference::from_word(
        linux_descriptor_offset(descriptor).load(Ordering::SeqCst),
    )
}

/// A new descriptor for namespace `reference`, as opening /proc/PID/ns/NAME
/// or a NS_GET_* ioctl makes one.
pub(super) fn linux_open_namespace(
    reference: linux_namespace::Reference,
    close_on_exec: bool,
) -> u64 {
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(
        LINUX_DEVICE_NAMESPACE | LINUX_DESCRIPTOR_INPUT,
        Ordering::SeqCst,
    );
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(0, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(reference.to_word(), Ordering::SeqCst);
    set_linux_descriptor_close_on_exec(descriptor, close_on_exec);
    descriptor
}

/// Whether the caller holds CAP_SYS_ADMIN over a namespace owned by
/// `owner` (`None`: the domain's initial user namespace): it does in its
/// own user namespace and in those made below it.
pub(super) fn linux_namespace_capable(owner: Option<linux_user::UserNamespaceHandle>) -> bool {
    let Some(caller) = current_linux_user_namespace() else {
        return false;
    };
    linux_has_capability(linox_credentials::capability::SYS_ADMIN)
        && match owner {
            Some(owner) => linux_user::may_signal(caller, owner),
            None => linux_user::parent(caller).is_none(),
        }
}

/// The user namespace owning namespace `reference` (for a user namespace,
/// the one it was made in), if the caller's user namespace is it or lies
/// above it (EPERM otherwise, as Linux's ns_get_owner).
fn linux_namespace_owner(
    reference: linux_namespace::Reference,
) -> Result<linux_namespace::Reference, u64> {
    let caller = current_linux_user_namespace().ok_or(LINUX_EPERM)?;
    let owner = match reference.kind {
        linux_namespace::Kind::User => linux_user::from_word(reference.handle)
            .and_then(linux_user::parent)
            .ok_or(LINUX_EPERM)?,
        _ => linux_namespace::owner(linux_execution_instance(), reference.id)
            .or_else(linux_user::initial)
            .ok_or(LINUX_EPERM)?,
    };
    if !linux_user::may_signal(caller, owner) {
        return Err(LINUX_EPERM);
    }
    Ok(linux_namespace::Reference {
        kind: linux_namespace::Kind::User,
        id: owner.id(),
        handle: owner.to_word(),
    })
}

/// The nsfs ioctls (Linux's fs/nsfs.c): the owning user namespace, the
/// parent PID or user namespace (each as a new descriptor), the kind, and
/// a user namespace's owner.
pub(super) fn linux_namespace_ioctl(descriptor: u64, request: u64, argument: u64) -> u64 {
    const NS_GET_USERNS: u32 = 0xb701;
    const NS_GET_PARENT: u32 = 0xb702;
    const NS_GET_NSTYPE: u32 = 0xb703;
    const NS_GET_OWNER_UID: u32 = 0xb704;
    const NS_GET_MNTNS_ID: u32 = 0x8008_b705;
    let Some(reference) = linux_namespace_reference(descriptor) else {
        return LINUX_EBADF;
    };
    let related = match request as u32 {
        // A mount namespace's id, as statmount's mnt_ns_id shows it.
        NS_GET_MNTNS_ID => {
            if reference.kind != linux_namespace::Kind::Mount {
                return LINUX_EINVAL;
            }
            return if copy_to_linux_user(argument, &u64::from(reference.id).to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            };
        }
        NS_GET_USERNS => linux_namespace_owner(reference),
        NS_GET_PARENT => match reference.kind {
            linux_namespace::Kind::User => linux_namespace_owner(reference),
            // The parent must be the caller's PID namespace or lie below it.
            linux_namespace::Kind::Pid => {
                let instance = linux_execution_instance();
                let own = current_linux_namespaces().pid;
                linux_namespace::pid_parent(instance, reference.id)
                    .filter(|parent| linux_namespace::pid_within(instance, own, *parent))
                    .map(|parent| linux_namespace::Reference {
                        id: parent,
                        ..reference
                    })
                    .ok_or(LINUX_EPERM)
            }
            _ => Err(LINUX_EINVAL),
        },
        NS_GET_NSTYPE => return reference.kind.clone_flag(),
        NS_GET_OWNER_UID => {
            if reference.kind != linux_namespace::Kind::User {
                return LINUX_EINVAL;
            }
            // Root of the domain makes every user namespace here.
            return if copy_to_linux_user(argument, &0_u32.to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            };
        }
        _ => return LINUX_ENOTTY,
    };
    match related {
        Ok(related) => linux_open_namespace(related, true),
        Err(error) => error,
    }
}

/// setns(2) with a /proc/PID/ns descriptor: joins that namespace, checked
/// as Linux's install operations check (EINVAL for a kind other than
/// `kind` asks for, EPERM without CAP_SYS_ADMIN over it). A pidfd joins
/// the namespaces of `kind` its process is in.
pub(super) fn linux_setns(descriptor: u64, kind: u64) -> u64 {
    const CLONE_NEWCGROUP: u64 = 0x0200_0000;
    const JOINABLE: u64 =
        LINUX_CLONE_NEWNS | LINUX_CLONE_NEWUSER | LINUX_CLONE_NEW_KEPT | CLONE_NEWCGROUP;
    let descriptor = u64::from(descriptor as u32);
    let kind = u64::from(kind as u32);
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    if let Some(reference) = linux_namespace_reference(descriptor) {
        if kind != 0 && kind != reference.kind.clone_flag() {
            return LINUX_EINVAL;
        }
        return linux_setns_join(reference);
    }
    if !linux_pidfd_descriptor(descriptor) || kind == 0 || kind & !JOINABLE != 0 {
        return LINUX_EINVAL;
    }
    let Some(pid) = linux_pidfd_process(descriptor) else {
        return LINUX_ESRCH;
    };
    // The user namespace first, which may grant the rights for the rest.
    let mut kinds = linux_namespace::Kind::ALL;
    kinds.sort_by_key(|candidate| *candidate != linux_namespace::Kind::User);
    for candidate in kinds {
        if kind & candidate.clone_flag() == 0 {
            continue;
        }
        let mut path = [0_u8; 48];
        let mut used = 0;
        let built = append_linux_bytes(&mut path, &mut used, b"/proc/")
            && append_linux_decimal(&mut path, &mut used, u64::from(pid))
            && append_linux_bytes(&mut path, &mut used, b"/ns/")
            && append_linux_bytes(&mut path, &mut used, candidate.name());
        let reference = match built
            .then(|| linux_proc_namespace_at(&path[..used]))
            .flatten()
        {
            Some(Ok(reference)) => reference,
            _ => return LINUX_ESRCH,
        };
        // Joining the user namespace the caller is in already changes nothing.
        if candidate == linux_namespace::Kind::User
            && current_linux_user_namespace().is_some_and(|own| own.to_word() == reference.handle)
        {
            continue;
        }
        let joined = linux_setns_join(reference);
        if joined != 0 {
            return joined;
        }
    }
    0
}

/// Moves the calling process into namespace `reference`.
fn linux_setns_join(reference: linux_namespace::Reference) -> u64 {
    use linux_namespace::Kind;
    let pid = current_linux_process_pid();
    let instance = linux_execution_instance();
    let threads = X86_RUNTIME
        .LINUX_THREAD_STATES
        .iter()
        .filter(|state| state.load(Ordering::SeqCst) != LINUX_THREAD_FREE)
        .count();
    match reference.kind {
        Kind::User => {
            let Some(target) = linux_user::from_word(reference.handle) else {
                return LINUX_EINVAL;
            };
            if current_linux_user_namespace() == Some(target) || threads > 1 {
                return LINUX_EINVAL;
            }
            if !linux_namespace_capable(Some(target)) {
                return LINUX_EPERM;
            }
            return if linux_process::set_live_process_user_namespace(pid, target) {
                0
            } else {
                LINUX_ESRCH
            };
        }
        Kind::Mount => {
            let Some(target) = linux_mount::from_word(reference.handle) else {
                return LINUX_EINVAL;
            };
            if threads > 1 {
                return LINUX_EINVAL;
            }
            if !linux_namespace_capable(None) {
                return LINUX_EPERM;
            }
            // The process record says which namespace is current: it
            // changes first, then the installed one, and the namespace left
            // goes if nothing else uses it.
            let Some(previous) = with_valid_linux_process_runtime_state(pid, |state| {
                state.mount_namespace.replace(target)
            }) else {
                return LINUX_ESRCH;
            };
            if !linux_mount::switch_to(target) {
                let _ = with_linux_process_runtime_state(pid, |state| {
                    state.mount_namespace = previous;
                });
                return LINUX_ENOMEM;
            }
            if let Some(previous) = previous.filter(|previous| *previous != target) {
                linux_release_mount_namespace(previous);
            }
            return 0;
        }
        // One cgroup namespace per domain: joining it changes nothing.
        Kind::Cgroup => {
            return if linux_namespace_capable(None) {
                0
            } else {
                LINUX_EPERM
            };
        }
        Kind::Uts | Kind::Ipc | Kind::Pid | Kind::Time | Kind::Net => {}
    }
    if !linux_namespace::exists(instance, reference.kind, reference.id) {
        return LINUX_EINVAL;
    }
    if reference.kind == Kind::Time && threads > 1 {
        return LINUX_EUSERS;
    }
    if !linux_namespace_capable(linux_namespace::owner(instance, reference.id)) {
        return LINUX_EPERM;
    }
    let mut set = current_linux_namespaces();
    match reference.kind {
        Kind::Uts => set.uts = reference.id,
        Kind::Ipc => set.ipc = reference.id,
        Kind::Net => set.net = reference.id,
        // Children are born into a PID namespace at or below the caller's.
        Kind::Pid => {
            if !linux_namespace::pid_within(instance, set.pid, reference.id) {
                return LINUX_EINVAL;
            }
            set.pid_for_children = reference.id;
        }
        _ => {
            set.time = reference.id;
            set.time_for_children = reference.id;
        }
    }
    if !linux_process::set_live_process_namespaces(pid, set) {
        return LINUX_ESRCH;
    }
    if reference.kind == Kind::Time {
        linux_namespace::freeze_time(instance, reference.id);
        let _ = refresh_linux_vvar();
    }
    0
}

/// CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWPID, CLONE_NEWTIME and
/// CLONE_NEWNET: the namespaces `linux_namespace` keeps.
pub(super) const LINUX_CLONE_NEW_KEPT: u64 = LINUX_CLONE_NEWUTS
    | LINUX_CLONE_NEWIPC
    | LINUX_CLONE_NEWPID
    | LINUX_CLONE_NEWTIME
    | LINUX_CLONE_NEWNET;
const LINUX_CLONE_NEWNET: u64 = 0x4000_0000;
const LINUX_CLONE_NEWTIME: u64 = 0x80;
/// The namespaces clone(2) (not clone3) may make for a new process; its
/// CLONE_NEWTIME bit is the exit signal's.
pub(super) const LINUX_CLONE_PROCESS_NAMESPACES: u64 = LINUX_CLONE_NEWNS
    | LINUX_CLONE_NEWUSER
    | LINUX_CLONE_NEWUTS
    | LINUX_CLONE_NEWIPC
    | LINUX_CLONE_NEWPID
    | LINUX_CLONE_NEWNET;
const LINUX_CLONE_NEWUTS: u64 = 0x0400_0000;
const LINUX_CLONE_NEWIPC: u64 = 0x0800_0000;
const LINUX_CLONE_NEWPID: u64 = 0x2000_0000;

/// Process `global` as process `observer` sees it: its number in the PID
/// namespace `observer` lives in, or 0 when it lies outside that one.
pub(super) fn linux_pid_seen_by(observer: u32, global: u32) -> u32 {
    if !linux_namespace::any(linux_namespace::Kind::Pid) {
        return global;
    }
    let namespace = linux_process::live_process_namespaces(observer).map_or(0, |set| set.pid);
    linux_namespace::pid_seen_from(linux_execution_instance(), namespace, global).unwrap_or(0)
}

/// The process the current process calls `local` (its own PID namespace's
/// number), by global number: `None` when it sees no such process.
fn linux_pid_from_caller(local: u32) -> Option<u32> {
    if !linux_namespace::any(linux_namespace::Kind::Pid) {
        return Some(local);
    }
    linux_namespace::pid_global(
        linux_execution_instance(),
        current_linux_namespaces().pid,
        local,
    )
}

/// A pid argument of the current process's (kill, wait4) as the kernel
/// numbers processes: positive ones are translated from its PID namespace,
/// and one it sees no process for is `Err(())`.
pub(super) fn linux_pid_argument(argument: u64) -> Result<u64, ()> {
    let pid = argument as i32;
    if pid <= 0 {
        return Ok(argument);
    }
    linux_pid_from_caller(pid as u32).map(u64::from).ok_or(())
}

/// A thread id of the current process's: a process's main thread by its
/// number in the caller's PID namespace; other threads keep their ids.
pub(super) fn linux_tid_argument(argument: u64) -> u64 {
    let tid = argument as i32;
    if tid <= 0 {
        return argument;
    }
    linux_pid_from_caller(tid as u32).map_or(argument, u64::from)
}

/// The current thread's id as it sees it: the main thread's is its
/// process's number in its PID namespace.
pub(super) fn linux_tid_seen(tid: u32) -> u32 {
    let pid = current_linux_process_pid();
    if tid == pid {
        linux_pid_seen_by(pid, pid)
    } else {
        tid
    }
}

/// A PID namespace's first process (its init, number 1 there) exiting
/// takes every other process of the namespace with it (SIGKILL), as Linux's
/// zap_pid_ns_processes does.
pub(super) fn linux_end_pid_namespace(pid: u32) {
    if !linux_namespace::any(linux_namespace::Kind::Pid) {
        return;
    }
    let Some(namespace) = linux_process::live_process_namespaces(pid)
        .map(|set| set.pid)
        .filter(|namespace| *namespace != 0)
    else {
        return;
    };
    if linux_pid_seen_by(pid, pid) != 1 {
        return;
    }
    for member in linux_namespace::pid_members(linux_execution_instance(), namespace) {
        if member != pid
            && linux_process::live_process_status(member)
                .is_some_and(|status| status.state != linux_process::LiveProcessState::Zombie)
        {
            let _ = linux_queue_process_signal(member, LINUX_SIGKILL, LINUX_SI_KERNEL, None);
        }
    }
}

/// The namespaces of the current process (all initial when it has none).
pub(super) fn current_linux_namespaces() -> linux_namespace::Set {
    linux_process::live_process_namespaces(current_linux_process_pid()).unwrap_or_default()
}

/// `set` with the new namespaces CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWPID
/// and CLONE_NEWTIME in `flags` ask for, owned by `owner`, and copied from
/// the current process's: as a fork child's (`child`), which lives in the
/// new PID and time namespaces, or as unshare's caller's, whose children
/// will.
pub(super) fn linux_create_namespaces(
    mut set: linux_namespace::Set,
    flags: u64,
    owner: linux_user::UserNamespaceHandle,
    child: bool,
) -> Result<linux_namespace::Set, u64> {
    let instance = linux_execution_instance();
    let failed = |error| match error {
        linux_namespace::Error::NoMemory => LINUX_ENOMEM,
        linux_namespace::Error::Invalid => LINUX_EINVAL,
        _ => LINUX_ENOSPC,
    };
    if flags & LINUX_CLONE_NEWUTS != 0 {
        let mut host = [0_u8; LINUX_UTS_NAME_CAPACITY];
        let mut domain = [0_u8; LINUX_UTS_NAME_CAPACITY];
        let host_length = linux_uts_name(LINUX_UTS_HOST, &mut host);
        let domain_length = linux_uts_name(LINUX_UTS_DOMAIN, &mut domain);
        set.uts = linux_namespace::create_uts(
            instance,
            owner,
            &host[..host_length],
            &domain[..domain_length],
        )
        .map_err(failed)?;
    }
    if flags & LINUX_CLONE_NEWIPC != 0 {
        set.ipc = linux_namespace::create_ipc(instance, owner).map_err(failed)?;
    }
    if flags & LINUX_CLONE_NEWPID != 0 {
        // Only a process whose children are born where it lives makes one
        // below it (Linux's copy_pid_ns).
        if !child && set.pid_for_children != set.pid {
            return Err(LINUX_EINVAL);
        }
        set.pid_for_children =
            linux_namespace::create_pid(instance, owner, set.pid_for_children).map_err(failed)?;
        if child {
            set.pid = set.pid_for_children;
        }
    }
    if flags & LINUX_CLONE_NEWNET != 0 {
        set.net = linux_namespace::create_net(instance, owner).map_err(failed)?;
    }
    if flags & LINUX_CLONE_NEWTIME != 0 {
        set.time_for_children =
            linux_namespace::create_time(instance, owner, set.time_for_children).map_err(failed)?;
        if child {
            set.time = set.time_for_children;
        }
    }
    Ok(set)
}

/// unshare(2). Unsharing what a single-threaded process already has alone
/// (its filesystem context, signal handlers, address space, SysV semaphore
/// undo) does nothing; a descriptor table a CLONE_FILES child was given
/// becomes its own (EMFILE if it holds a descriptor above nr_open); a new
/// user, mount, UTS, IPC or network namespace replaces the caller's, and a
/// new PID or time namespace is where its children will be born. Cgroup
/// namespaces are not implemented yet.
pub(super) fn linux_unshare(flags: u64) -> u64 {
    const CLONE_NEWCGROUP: u64 = 0x0200_0000;
    const UNIMPLEMENTED: u64 = CLONE_NEWCGROUP;
    const SHARED_WITH_THREADS: u64 = LINUX_CLONE_THREAD | LINUX_CLONE_SIGHAND | LINUX_CLONE_VM;
    const KNOWN: u64 = UNIMPLEMENTED
        | LINUX_CLONE_NEW_KEPT
        | SHARED_WITH_THREADS
        | LINUX_CLONE_FS
        | LINUX_CLONE_FILES
        | LINUX_CLONE_SYSVSEM
        | LINUX_CLONE_NEWNS
        | LINUX_CLONE_NEWUSER;
    let flags = u64::from(flags as u32);
    if flags & !KNOWN != 0 {
        return LINUX_EINVAL;
    }
    let threads = X86_RUNTIME
        .LINUX_THREAD_STATES
        .iter()
        .filter(|state| state.load(Ordering::SeqCst) != LINUX_THREAD_FREE)
        .count();
    if flags & (SHARED_WITH_THREADS | LINUX_CLONE_NEWUSER) != 0 && threads > 1 {
        return LINUX_EINVAL;
    }
    let (Some(namespace), Some(credentials)) =
        (current_linux_user_namespace(), current_linux_credentials())
    else {
        return LINUX_ESRCH;
    };
    // Making namespaces other than a user namespace needs CAP_SYS_ADMIN,
    // which a new user namespace grants its creator.
    let new_namespaces = flags & (UNIMPLEMENTED | LINUX_CLONE_NEW_KEPT | LINUX_CLONE_NEWNS);
    if new_namespaces != 0
        && flags & LINUX_CLONE_NEWUSER == 0
        && !credentials.has(linox_credentials::capability::SYS_ADMIN)
    {
        return LINUX_EPERM;
    }
    if flags & UNIMPLEMENTED != 0 {
        return LINUX_EINVAL;
    }
    let pid = current_linux_process_pid();
    // A descriptor table shared with another process (clone's CLONE_FILES)
    // becomes the caller's own copy, which fails when it holds a descriptor
    // at or above nr_open (Linux's dup_fd); a table the process has alone
    // stays as it is. So does a shared filesystem context (CLONE_FS), and a
    // new mount namespace needs one of its own too.
    if flags & LINUX_CLONE_FILES != 0
        && linux_process::live_process_resource_shared(
            pid,
            linux_process::SharedResource::Descriptors,
        )
    {
        let nr_open = linux_nr_open();
        if linux_descriptor_numbers()
            .filter(|descriptor| *descriptor >= nr_open)
            .any(linux_descriptor_open)
        {
            return LINUX_EMFILE;
        }
        if !unshare_linux_descriptors(pid) {
            return LINUX_ENOMEM;
        }
    }
    if flags & (LINUX_CLONE_FS | LINUX_CLONE_NEWNS) != 0
        && linux_process::live_process_resource_shared(
            pid,
            linux_process::SharedResource::Filesystem,
        )
        && !linux_process::share_live_process_resource(
            pid,
            linux_process::SharedResource::Filesystem,
            None,
        )
    {
        return LINUX_ENOMEM;
    }
    let mut owner = namespace;
    if flags & LINUX_CLONE_NEWUSER != 0 {
        let Some(child) = linux_user::clone_namespace(namespace) else {
            return LINUX_ENOSPC;
        };
        if !linux_process::set_live_process_user_namespace(pid, child) {
            let _ = linux_user::retire(child);
            return LINUX_ENOMEM;
        }
        owner = child;
    }
    if flags & LINUX_CLONE_NEW_KEPT != 0 {
        let namespaces =
            match linux_create_namespaces(current_linux_namespaces(), flags, owner, false) {
                Ok(namespaces) => namespaces,
                Err(error) => return error,
            };
        if !linux_process::set_live_process_namespaces(pid, namespaces) {
            return LINUX_ESRCH;
        }
    }
    if flags & LINUX_CLONE_NEWNS != 0 {
        if with_valid_linux_process_runtime_state(pid, |_| ()).is_none() {
            return LINUX_ESRCH;
        }
        let previous = linux_mount::current_handle();
        let Some(mount_namespace) = linux_clone_mount_namespace() else {
            return LINUX_ENOMEM;
        };
        // The process's record names its namespace from here on.
        let _ = with_linux_process_runtime_state(pid, |state| {
            state.mount_namespace = Some(mount_namespace);
        });
        if !linux_mount::switch_to(mount_namespace) {
            let _ = with_linux_process_runtime_state(pid, |state| {
                state.mount_namespace = previous;
            });
            linux_release_mount_namespace(mount_namespace);
            return LINUX_ENOMEM;
        }
        if let Some(previous) = previous {
            linux_release_mount_namespace(previous);
        }
    }
    0
}

/// A new mount namespace (unshare or clone with CLONE_NEWNS): a copy of
/// the current one, with copies of its mounts.
pub(super) fn linux_clone_mount_namespace() -> Option<linux_mount::MountNamespaceHandle> {
    let from = linux_mount_space();
    let namespace = linux_mount::clone_current()?;
    let to = crate::linux_mounts::Space {
        instance: from.instance,
        namespace: namespace.id(),
    };
    if crate::linux_mounts::copy_space(from, to).is_err() {
        crate::linux_mounts::drop_space(to, |_| {});
        let _ = linux_mount::retire(namespace);
        return None;
    }
    Some(namespace)
}

/// Retires mount namespace `namespace` with its mounts once no process
/// of the domain uses it any more (Linux frees a namespace with its last
/// reference); a tmpfs no other namespace has mounted takes its files.
pub(super) fn linux_release_mount_namespace(namespace: linux_mount::MountNamespaceHandle) {
    if linux_mount::is_domain_root(namespace) {
        return;
    }
    let mut in_use = false;
    for_each_allocated_linux_process_record(|record| {
        in_use |= record.runtime().mount_namespace == Some(namespace);
    });
    if in_use {
        return;
    }
    // An exiting process's namespace may still be the one installed.
    if linux_mount::vacate(namespace) && linux_mount::retire(namespace) {
        crate::linux_mounts::drop_space(
            crate::linux_mounts::Space {
                instance: linux_execution_instance(),
                namespace: namespace.id(),
            },
            linux_filesystem_gone,
        );
    }
}
