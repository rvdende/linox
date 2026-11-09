#![forbid(unsafe_code)]

use crate::{
    arch::x86_64::cpu,
    control_abi, domain,
    sync::{LockRank, SpinLock},
};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// The most user namespaces one domain may hold at once.
const NAMESPACE_LIMIT: usize = 64;
/// How deep user namespaces may nest (Linux's limit).
const NESTING_LIMIT: usize = 32;
const ROOT_INSIDE_ID: u32 = 0;
const ROOT_OUTSIDE_ID: u32 = 100_000;
const ROOT_ID_COUNT: u32 = 1;
const HOST_INSTANCE: usize = control_abi::DOMAIN_LIMIT;
const INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;

/// The ids a domain that allows switching users maps: the 16-bit range, as
/// a container's subordinate id range usually is (65534 is `nobody`).
const SWITCHING_ID_COUNT: u32 = 65_536;

const ROOT_ID_MAP: &[u8] = b"0 100000 1\n";
const SWITCHING_ID_MAP: &[u8] = b"0 100000 65536\n";

pub(crate) use linox_credentials::{Authority, Credentials};

/// Set once the host's initial namespace exists (`install_initial`).
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Each domain's user namespaces, and the host's at `HOST_INSTANCE`. A
/// leaf: records are copied in and out, nothing is called and nothing is
/// allocated while one is held (a table's storage is reserved before it
/// is taken, `reserve_table`).
static TABLES: [SpinLock<UserNamespaceTable>; INSTANCE_LIMIT] =
    [const { SpinLock::new(LockRank::USER_NAMESPACES, UserNamespaceTable::new()) }; INSTANCE_LIMIT];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserNamespaceHandle {
    owner_domain: u64,
    slot: u8,
    generation: u32,
    id: u32,
}

impl UserNamespaceHandle {
    /// The namespace's number in its domain, which its nsfs inode is made of.
    pub(crate) fn id(self) -> u32 {
        self.id
    }

    /// The handle as a word a /proc/PID/ns descriptor keeps (`from_word`).
    pub(crate) fn to_word(self) -> u64 {
        u64::from(self.slot) << 24 | u64::from(self.generation & 0xff_ffff)
    }
}

/// The live user namespace of the current domain that `to_word` gave `word` for.
pub(crate) fn from_word(word: u64) -> Option<UserNamespaceHandle> {
    let (index, owner_domain) = current_instance_and_owner()?;
    let slot = usize::try_from(word >> 24).ok()?;
    with_table(index, |table| {
        if table.owner_domain != owner_domain {
            return None;
        }
        let namespace = table.namespaces.get(slot)?.as_ref()?;
        (u64::from(namespace.handle.generation & 0xff_ffff) == word & 0xff_ffff)
            .then_some(namespace.handle)
    })?
}

/// The namespace `handle` was made in: `None` for the domain's initial one.
pub(crate) fn parent(handle: UserNamespaceHandle) -> Option<UserNamespaceHandle> {
    live_namespace(handle)?.parent
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivilegedOperation {
    ChangeRoot,
    ManageMounts,
    ManageKernel,
    ManageNamespaces,
    RawIo,
    LoadBpf,
    ObserveKernelLog,
    ManageClock,
    ProcessAccounting,
    ManageTerminal,
    ManageStorageQuota,
    TraceProcesses,
}

impl PrivilegedOperation {
    const fn bit(self) -> u32 {
        1 << self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdMap {
    inside: u32,
    outside: u32,
    count: u32,
}

impl IdMap {
    const ROOT: Self = Self {
        inside: ROOT_INSIDE_ID,
        outside: ROOT_OUTSIDE_ID,
        count: ROOT_ID_COUNT,
    };

    fn outside(self, inside: u32) -> Option<u32> {
        let offset = inside.checked_sub(self.inside)?;
        (offset < self.count).then(|| self.outside + offset)
    }

    fn inside(self, outside: u32) -> Option<u32> {
        let offset = outside.checked_sub(self.outside)?;
        (offset < self.count).then(|| self.inside + offset)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserNamespace {
    handle: UserNamespaceHandle,
    parent: Option<UserNamespaceHandle>,
    uid_map: IdMap,
    gid_map: IdMap,
    setgroups_allowed: bool,
    linux_capabilities: u64,
    privileged_operations: u32,
}

struct UserNamespaceTable {
    owner_domain: u64,
    /// Grows on demand up to NAMESPACE_LIMIT and never shrinks, so slots
    /// stay valid.
    namespaces: Vec<Option<UserNamespace>>,
    /// The generation each slot last handed out, parallel to `namespaces`.
    generations: Vec<u32>,
    next_id: u32,
    initial: Option<UserNamespaceHandle>,
}

impl UserNamespaceTable {
    const fn new() -> Self {
        Self {
            owner_domain: 0,
            namespaces: Vec::new(),
            generations: Vec::new(),
            next_id: 1,
            initial: None,
        }
    }

    fn create(
        &mut self,
        uid_map: IdMap,
        gid_map: IdMap,
        parent: Option<UserNamespaceHandle>,
    ) -> Option<UserNamespaceHandle> {
        if uid_map != IdMap::ROOT || gid_map != IdMap::ROOT {
            return None;
        }
        let slot = match self.namespaces.iter().position(Option::is_none) {
            Some(slot) => slot,
            // Within the reserved storage only: a table is grown before
            // its lock is taken (`reserve_table`), never under it.
            None if self.namespaces.len() < NAMESPACE_LIMIT
                && self.namespaces.len() < self.namespaces.capacity()
                && self.generations.len() < self.generations.capacity() =>
            {
                self.namespaces.push(None);
                self.generations.push(0);
                self.namespaces.len() - 1
            }
            None => return None,
        };
        let generation = self.generations[slot].checked_add(1)?;
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1)?;
        let handle = UserNamespaceHandle {
            owner_domain: self.owner_domain,
            slot: u8::try_from(slot).ok()?,
            generation,
            id,
        };
        self.generations[slot] = generation;
        self.namespaces[slot] = Some(UserNamespace {
            handle,
            parent,
            uid_map,
            gid_map,
            setgroups_allowed: false,
            linux_capabilities: 0,
            privileged_operations: 0,
        });
        Some(handle)
    }

    fn namespace(&self, handle: UserNamespaceHandle) -> Option<&UserNamespace> {
        self.namespaces
            .get(usize::from(handle.slot))?
            .as_ref()
            .filter(|namespace| namespace.handle == handle)
    }

    fn retire(&mut self, handle: UserNamespaceHandle) -> bool {
        if self.initial == Some(handle) || self.namespace(handle).is_none() {
            return false;
        }
        self.namespaces[usize::from(handle.slot)] = None;
        true
    }

    /// Takes over `namespaces` and `generations`, empty vectors with room
    /// for the whole table, if this table has less room, and hands back
    /// the storage it gave up (to be freed after the lock is released).
    fn adopt_storage(
        &mut self,
        mut namespaces: Vec<Option<UserNamespace>>,
        mut generations: Vec<u32>,
    ) -> (Vec<Option<UserNamespace>>, Vec<u32>) {
        if self.namespaces.capacity() >= NAMESPACE_LIMIT
            && self.generations.capacity() >= NAMESPACE_LIMIT
        {
            return (namespaces, generations);
        }
        namespaces.extend_from_slice(&self.namespaces);
        generations.extend_from_slice(&self.generations);
        core::mem::swap(&mut self.namespaces, &mut namespaces);
        core::mem::swap(&mut self.generations, &mut generations);
        (namespaces, generations)
    }
}

pub(crate) fn verify_contract() -> bool {
    let mut table = UserNamespaceTable::new();
    let mut namespaces = Vec::new();
    let mut generations = Vec::new();
    if namespaces.try_reserve_exact(NAMESPACE_LIMIT).is_err()
        || generations.try_reserve_exact(NAMESPACE_LIMIT).is_err()
    {
        return false;
    }
    let _ = table.adopt_storage(namespaces, generations);
    let invalid = IdMap {
        inside: 1,
        ..IdMap::ROOT
    };
    if table.create(invalid, IdMap::ROOT, None).is_some() {
        return false;
    }
    let Some(first) = table.create(IdMap::ROOT, IdMap::ROOT, None) else {
        return false;
    };
    table.initial = Some(first);
    let stale = UserNamespaceHandle {
        generation: first.generation.saturating_add(1),
        ..first
    };
    let Some(namespace) = table.namespace(first) else {
        return false;
    };
    if first.id != 1
        || namespace.uid_map.outside(0) != Some(ROOT_OUTSIDE_ID)
        || namespace.uid_map.inside(ROOT_OUTSIDE_ID) != Some(0)
        || namespace.uid_map.outside(1).is_some()
        || namespace.gid_map.inside(ROOT_OUTSIDE_ID + 1).is_some()
        || namespace.setgroups_allowed
        || namespace.linux_capabilities != 0
        || [
            PrivilegedOperation::ChangeRoot,
            PrivilegedOperation::ManageMounts,
            PrivilegedOperation::ManageKernel,
            PrivilegedOperation::ManageNamespaces,
            PrivilegedOperation::RawIo,
            PrivilegedOperation::LoadBpf,
            PrivilegedOperation::ObserveKernelLog,
            PrivilegedOperation::ManageClock,
            PrivilegedOperation::ProcessAccounting,
            PrivilegedOperation::ManageTerminal,
            PrivilegedOperation::ManageStorageQuota,
            PrivilegedOperation::TraceProcesses,
        ]
        .into_iter()
        .any(|operation| !privileged_operation_denied_in(namespace, operation))
        || table.namespace(stale).is_some()
        || table.retire(first)
    {
        return false;
    }
    let mut disposable = [None; NAMESPACE_LIMIT - 1];
    for handle in &mut disposable {
        *handle = table.create(IdMap::ROOT, IdMap::ROOT, Some(first));
        if handle.is_none() {
            return false;
        }
    }
    if table
        .create(IdMap::ROOT, IdMap::ROOT, Some(first))
        .is_some()
    {
        return false;
    }
    let retired = disposable[0].is_some_and(|handle| table.retire(handle));
    let Some(replacement) = table.create(IdMap::ROOT, IdMap::ROOT, Some(first)) else {
        return false;
    };
    retired
        && replacement.slot == disposable[0].unwrap().slot
        && replacement.generation > disposable[0].unwrap().generation
        && replacement.id > disposable[0].unwrap().id
        && table.namespace(disposable[0].unwrap()).is_none()
}

pub(crate) fn install_initial() -> bool {
    if INSTALLED.load(Ordering::Acquire) || reserve_table(HOST_INSTANCE).is_none() {
        return false;
    }
    let handle = with_table_mut(HOST_INSTANCE, |table| {
        if table.initial.is_some() {
            return None;
        }
        let handle = table.create(IdMap::ROOT, IdMap::ROOT, None)?;
        table.initial = Some(handle);
        Some(handle)
    });
    let Some(handle) = handle.flatten() else {
        return false;
    };
    INSTALLED.store(true, Ordering::Release);
    credentials(handle).is_some()
}

pub(crate) fn initial() -> Option<UserNamespaceHandle> {
    let (index, owner_domain) = current_instance_and_owner()?;
    if with_table_mut(index, |table| table.initial.is_none())? {
        reserve_table(index)?;
    }
    with_table_mut(index, |table| {
        if table.initial.is_none() {
            table.owner_domain = owner_domain;
            let handle = table.create(IdMap::ROOT, IdMap::ROOT, None)?;
            table.initial = Some(handle);
        }
        (table.owner_domain == owner_domain)
            .then_some(table.initial)
            .flatten()
    })?
}

pub(crate) fn clone_namespace(parent: UserNamespaceHandle) -> Option<UserNamespaceHandle> {
    let namespace = live_namespace(parent)?;
    let (index, owner_domain) = current_instance_and_owner()?;
    if namespace.handle.owner_domain != owner_domain {
        return None;
    }
    reserve_table(index)?;
    with_table_mut(index, |table| {
        if table.owner_domain != owner_domain {
            return None;
        }
        table.create(namespace.uid_map, namespace.gid_map, Some(parent))
    })?
}

pub(crate) fn may_signal(sender: UserNamespaceHandle, mut target: UserNamespaceHandle) -> bool {
    if sender.owner_domain != target.owner_domain {
        return false;
    }
    with_table_for_handle(sender, |table| {
        for _ in 0..NESTING_LIMIT {
            if target == sender {
                return true;
            }
            let Some(parent) = table
                .namespace(target)
                .and_then(|namespace| namespace.parent)
            else {
                return false;
            };
            target = parent;
        }
        false
    })
    .unwrap_or(false)
}

pub(crate) fn retire(handle: UserNamespaceHandle) -> bool {
    let index = if handle.owner_domain == 0 {
        HOST_INSTANCE
    } else {
        let Some(index) = domain::container_slot_for_domain(handle.owner_domain) else {
            return false;
        };
        index
    };
    with_table_mut(index, |table| table.retire(handle)).unwrap_or(false)
}

pub(crate) fn credentials(handle: UserNamespaceHandle) -> Option<Credentials> {
    let namespace = live_namespace(handle)?;
    if namespace.uid_map.outside(0) != Some(ROOT_OUTSIDE_ID)
        || namespace.gid_map.outside(0) != Some(ROOT_OUTSIDE_ID)
        || namespace.setgroups_allowed
        || namespace.linux_capabilities != 0
    {
        return None;
    }
    Some(Credentials::ROOT)
}

/// The single gate on changing identity. Root in a domain may take other
/// user and group ids (setuid, setgid, setgroups and their relatives) only
/// when the domain was configured with `user-switching=true`. The domain's
/// user namespace then maps 65536 ids; otherwise it maps only id 0, so
/// every process stays root. Every identity change asks here and nowhere
/// else, so this is the one place to secure.
pub(crate) fn user_switching_allowed(handle: UserNamespaceHandle) -> bool {
    handle.owner_domain != 0
        && domain::container_slot_for_domain(handle.owner_domain)
            .is_some_and(cpu::container_user_switching)
}

/// What a process with `credentials` in `handle` may do when it changes
/// its ids: it holds CAP_SETUID and CAP_SETGID while its effective user id
/// is 0 and its domain allows switching users.
pub(crate) fn identity_authority(
    handle: UserNamespaceHandle,
    credentials: &Credentials,
) -> Authority {
    let switching = user_switching_allowed(handle);
    Authority {
        privileged: switching && credentials.privileged(),
        id_count: if switching {
            SWITCHING_ID_COUNT
        } else {
            ROOT_ID_COUNT
        },
    }
}

/// `/proc/PID/uid_map` and `gid_map`: the ids the namespace maps.
pub(crate) fn id_map(handle: UserNamespaceHandle) -> &'static [u8] {
    if user_switching_allowed(handle) {
        SWITCHING_ID_MAP
    } else {
        ROOT_ID_MAP
    }
}

/// `/proc/PID/setgroups`: whether setgroups(2) may be used.
pub(crate) fn setgroups_file(handle: UserNamespaceHandle) -> &'static [u8] {
    if user_switching_allowed(handle) {
        b"allow\n"
    } else {
        b"deny\n"
    }
}

/// The single gate on machine-level authority: the domain was configured
/// with `privileged=true`. Its root, in the domain's own user namespace
/// (not one made inside it), may then use every privileged operation but
/// raw I/O ports, which would reach around the drivers' isolation; reboot
/// resets the machine and syslog reads its kernel log.
pub(crate) fn domain_privileged(handle: UserNamespaceHandle) -> bool {
    handle.owner_domain != 0
        && domain::container_slot_for_domain(handle.owner_domain)
            .is_some_and(cpu::container_privileged)
}

pub(crate) fn privileged_operation_denied(
    handle: UserNamespaceHandle,
    operation: PrivilegedOperation,
) -> bool {
    if operation != PrivilegedOperation::RawIo
        && domain_privileged(handle)
        && live_namespace(handle).is_some_and(|namespace| namespace.parent.is_none())
    {
        return false;
    }
    // A domain's root user may administer only that domain's mount namespace.
    // The syscall implementation independently requires a live domain context,
    // so this authority can never mutate the control domain or another domain.
    if operation == PrivilegedOperation::ManageMounts && handle.owner_domain != 0 {
        return false;
    }
    live_namespace(handle)
        .is_some_and(|namespace| privileged_operation_denied_in(&namespace, operation))
}

fn privileged_operation_denied_in(
    namespace: &UserNamespace,
    operation: PrivilegedOperation,
) -> bool {
    namespace.linux_capabilities == 0 && namespace.privileged_operations & operation.bit() == 0
}

/// A copy of the live namespace `handle` names.
fn live_namespace(handle: UserNamespaceHandle) -> Option<UserNamespace> {
    with_table_for_handle(handle, |table| table.namespace(handle).copied())?
}

/// Runs `f` on the table of `handle`'s domain, if it is that domain's.
fn with_table_for_handle<R>(
    handle: UserNamespaceHandle,
    f: impl FnOnce(&UserNamespaceTable) -> R,
) -> Option<R> {
    let index = if handle.owner_domain == 0 {
        HOST_INSTANCE
    } else {
        domain::container_slot_for_domain(handle.owner_domain)?
    };
    with_table(index, |table| {
        (table.owner_domain == handle.owner_domain).then(|| f(table))
    })?
}

/// Runs `f` on table `index` under its lock, once the tables are
/// installed.
fn with_table<R>(index: usize, f: impl FnOnce(&UserNamespaceTable) -> R) -> Option<R> {
    if !INSTALLED.load(Ordering::Acquire) {
        return None;
    }
    Some(f(&TABLES.get(index)?.lock()))
}

/// Runs `f` on table `index` under its lock to change it: the host's at
/// any time (`install_initial` makes the first namespace there), a
/// domain's once the tables are installed.
fn with_table_mut<R>(index: usize, f: impl FnOnce(&mut UserNamespaceTable) -> R) -> Option<R> {
    if !INSTALLED.load(Ordering::Acquire) && index != HOST_INSTANCE {
        return None;
    }
    Some(f(&mut TABLES.get(index)?.lock()))
}

/// Makes sure table `index` has room for all its namespaces, allocating
/// that room with no lock held, so `create` never allocates under the
/// table's lock.
fn reserve_table(index: usize) -> Option<()> {
    let table = TABLES.get(index)?;
    {
        let table = table.lock();
        if table.namespaces.capacity() >= NAMESPACE_LIMIT
            && table.generations.capacity() >= NAMESPACE_LIMIT
        {
            return Some(());
        }
    }
    let mut namespaces = Vec::new();
    let mut generations = Vec::new();
    namespaces.try_reserve_exact(NAMESPACE_LIMIT).ok()?;
    generations.try_reserve_exact(NAMESPACE_LIMIT).ok()?;
    let spare = table.lock().adopt_storage(namespaces, generations);
    drop(spare);
    Some(())
}

fn current_instance_and_owner() -> Option<(usize, u64)> {
    let Some(slot) = cpu::current_container_slot() else {
        return Some((HOST_INSTANCE, 0));
    };
    Some((slot, cpu::container_domain_id(slot)?))
}
