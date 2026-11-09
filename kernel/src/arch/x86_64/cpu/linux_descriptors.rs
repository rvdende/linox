use super::*;

pub(super) fn linux_descriptor_open(descriptor: u64) -> bool {
    linux_console_descriptor_open(descriptor)
        || descriptor == 2 && X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::SeqCst)
        || linux_device_descriptor(descriptor) != 0
        || linux_epoll_descriptor(descriptor)
        || linux_eventfd_descriptor(descriptor)
        || linux_timerfd_descriptor(descriptor)
        || linux_pipe_descriptor(descriptor)
}

/// A field of an eventfd or timerfd: a shared open file's
/// (`crate::linux_event_files`) or the boot probe's own.
pub(super) trait LinuxFileCell<T> {
    fn load(&self, ordering: Ordering) -> T;
    fn store(&self, value: T, ordering: Ordering);
}

macro_rules! linux_file_cell {
    ($($cell:ty => $value:ty),*) => {$(
        impl LinuxFileCell<$value> for $cell {
            fn load(&self, ordering: Ordering) -> $value {
                <$cell>::load(self, ordering)
            }

            fn store(&self, value: $value, ordering: Ordering) {
                <$cell>::store(self, value, ordering)
            }
        }
    )*};
}

linux_file_cell!(
    AtomicU8 => u8,
    AtomicU32 => u32,
    AtomicU64 => u64,
    BankedAtomicU8 => u8,
    BankedAtomicU32 => u32,
    BankedAtomicU64 => u64
);

impl<V, T: LinuxFileCell<V>> LinuxFileCell<V> for RuntimeRef<T> {
    fn load(&self, ordering: Ordering) -> V {
        self.0.load(ordering)
    }

    fn store(&self, value: V, ordering: Ordering) {
        self.0.store(value, ordering)
    }
}

pub(super) fn linux_aux_descriptor_free(descriptor: u64) -> bool {
    (2..linux_nofile_soft_limit()).contains(&descriptor)
        && !linux_console_descriptor_open(descriptor)
        && !(descriptor == 2 && X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::SeqCst))
        && linux_device_descriptor(descriptor) == 0
        && linux_socket_slot(descriptor).is_none()
        && !linux_epoll_descriptor(descriptor)
        && !linux_eventfd_descriptor(descriptor)
        && !linux_timerfd_descriptor(descriptor)
        && !linux_pipe_descriptor(descriptor)
}

/// The current process's descriptor `descriptor`, when it lies above the
/// fixed table (`linux_fd_table`); None for one in the fixed table or not
/// open.
pub(super) fn linux_overflow_entry(descriptor: u64) -> Option<crate::linux_fd_table::Entry> {
    if descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT {
        return None;
    }
    crate::linux_fd_table::get(
        X86_RUNTIME
            .ELF_PROBE_DESCRIPTOR_OVERFLOW
            .load(Ordering::SeqCst),
        descriptor,
    )
    .filter(|entry| !entry.vacant())
}

/// Changes the current process's descriptor `descriptor` above the fixed
/// table; false if it is not open there.
fn update_linux_overflow_entry(
    descriptor: u64,
    change: impl FnOnce(&mut crate::linux_fd_table::Entry),
) -> bool {
    descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT
        && linux_overflow_entry(descriptor).is_some()
        && linux_own_overflow_table()
            .is_some_and(|table| crate::linux_fd_table::update(table, descriptor, change))
}

/// Opens descriptor `descriptor` above the fixed table as `entry`, the
/// current process's table there made on first use; false without memory.
pub(super) fn install_linux_overflow_descriptor(
    descriptor: u64,
    entry: crate::linux_fd_table::Entry,
) -> bool {
    linux_writable_overflow_table()
        .is_some_and(|table| crate::linux_fd_table::set(table, descriptor, entry))
}

/// The current process's table above the fixed one, to change: its own
/// (`linux_own_overflow_table`), made on first use. None without memory.
fn linux_writable_overflow_table() -> Option<u32> {
    if let Some(table) = linux_own_overflow_table() {
        return Some(table);
    }
    if X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OVERFLOW
        .load(Ordering::SeqCst)
        != 0
    {
        return None;
    }
    let created = crate::linux_fd_table::create(linux_execution_instance())?;
    X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OVERFLOW
        .store(created, Ordering::SeqCst);
    Some(created)
}

/// A per-descriptor field of the current process's descriptor table, which
/// `linux_fd_cell` reaches wherever the descriptor lives: the standard
/// descriptors' arrays (the fields they have), the fixed table's, or the
/// table above it (`linux_fd_table`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxFdField {
    /// The kind and access bits (`linux_device_descriptor`).
    Device,
    /// The image entry open.
    Rootfs,
    /// The socket slot + 1.
    Socket,
    /// The status flags (O_NONBLOCK, O_APPEND, the private marks).
    Flags,
    /// The overlay or tmpfs generation open.
    Generation,
    /// An eventfd (non-zero).
    EventFd,
    /// A timerfd (non-zero).
    TimerFd,
    /// An epoll instance (non-zero).
    Epoll,
    /// The descriptor + 1 owning the epoll instance this one duplicates.
    EpollAlias,
}

impl LinuxFdField {
    fn get(self, entry: &crate::linux_fd_table::Entry) -> u64 {
        match self {
            Self::Device => entry.state.into(),
            Self::Rootfs => entry.rootfs.into(),
            Self::Socket => entry.socket.into(),
            Self::Flags => entry.socket_flags.into(),
            Self::Generation => entry.generation.into(),
            Self::EventFd => u64::from(entry.event == 1),
            Self::TimerFd => u64::from(entry.event == 2),
            Self::Epoll => entry.epoll.into(),
            Self::EpollAlias => entry.epoll_alias.into(),
        }
    }

    fn set(self, entry: &mut crate::linux_fd_table::Entry, value: u64) {
        match self {
            Self::Device => entry.state = value as u16,
            Self::Rootfs => entry.rootfs = value as u16,
            Self::Socket => entry.socket = value as u16,
            Self::Flags => entry.socket_flags = value as u32,
            Self::Generation => entry.generation = value as u32,
            Self::EventFd | Self::TimerFd => {
                let kind = if self == Self::EventFd { 1 } else { 2 };
                if value != 0 {
                    entry.event = kind;
                } else if entry.event == kind {
                    entry.event = 0;
                }
            }
            Self::Epoll => entry.epoll = value as u8,
            Self::EpollAlias => entry.epoll_alias = value as u32,
        }
    }
}

/// Field `field` of the current process's descriptor `descriptor`, read
/// and written as the atomic it is in the fixed table: `T` is the field's
/// width there.
pub(super) struct LinuxFdCell<T> {
    descriptor: u64,
    field: LinuxFdField,
    width: core::marker::PhantomData<T>,
}

pub(super) fn linux_fd_cell<T>(descriptor: u64, field: LinuxFdField) -> LinuxFdCell<T> {
    LinuxFdCell {
        descriptor,
        field,
        width: core::marker::PhantomData,
    }
}

impl<T: Copy + Default + Into<u64> + TryFrom<u64>> LinuxFdCell<T> {
    pub(super) fn load(&self, ordering: Ordering) -> T {
        T::try_from(linux_fd_field_swap(
            self.descriptor,
            self.field,
            None,
            ordering,
        ))
        .unwrap_or_default()
    }

    pub(super) fn store(&self, value: T, ordering: Ordering) {
        linux_fd_field_swap(self.descriptor, self.field, Some(value.into()), ordering);
    }

    fn swap(&self, value: T, ordering: Ordering) -> T {
        T::try_from(linux_fd_field_swap(
            self.descriptor,
            self.field,
            Some(value.into()),
            ordering,
        ))
        .unwrap_or_default()
    }
}

impl LinuxFileCell<u32> for LinuxFdCell<u32> {
    fn load(&self, ordering: Ordering) -> u32 {
        LinuxFdCell::load(self, ordering)
    }

    fn store(&self, value: u32, ordering: Ordering) {
        LinuxFdCell::store(self, value, ordering)
    }
}

impl LinuxFdCell<u32> {
    pub(super) fn fetch_or(&self, bits: u32, ordering: Ordering) -> u32 {
        let old = self.load(ordering);
        self.store(old | bits, ordering);
        old
    }
}

/// Reads field `field` of descriptor `descriptor`, and stores `value` in
/// it when given, returning what it held. A field the descriptor has no
/// place for (an epoll mark on a standard descriptor) reads 0 and keeps
/// nothing; a store above the fixed table opens the entry it needs there.
fn linux_fd_field_swap(
    descriptor: u64,
    field: LinuxFdField,
    value: Option<u64>,
    ordering: Ordering,
) -> u64 {
    macro_rules! cell {
        ($cell:expr, $width:ty) => {{
            let cell = $cell;
            match value {
                Some(value) => u64::from(cell.swap(value as $width, ordering)),
                None => u64::from(cell.load(ordering)),
            }
        }};
    }
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        let mut old = 0;
        match value {
            None => {
                if let Some(entry) = linux_overflow_entry(descriptor) {
                    old = field.get(&entry);
                }
            }
            Some(value) => {
                if value == 0 && linux_overflow_entry(descriptor).is_none() {
                    return 0;
                }
                if let Some(table) = linux_writable_overflow_table() {
                    crate::linux_fd_table::upsert(table, descriptor, |entry| {
                        old = field.get(entry);
                        field.set(entry, value);
                    });
                }
            }
        }
        return old;
    }
    let index = descriptor as usize;
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
        return match field {
            LinuxFdField::Device => {
                cell!(&X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index], u16)
            }
            LinuxFdField::Rootfs => {
                cell!(&X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS[index], u16)
            }
            LinuxFdField::Socket => cell!(&X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS[index], u16),
            LinuxFdField::Flags => cell!(&X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[index], u32),
            LinuxFdField::Generation => {
                cell!(
                    &X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index],
                    u32
                )
            }
            _ => 0,
        };
    }
    let index = index - LINUX_AUX_DESCRIPTOR_FIRST as usize;
    match field {
        LinuxFdField::Device => cell!(&X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS[index], u16),
        LinuxFdField::Rootfs => cell!(&X86_RUNTIME.ELF_PROBE_ROOTFS_DESCRIPTORS[index], u16),
        LinuxFdField::Socket => cell!(&X86_RUNTIME.ELF_PROBE_SOCKET_SLOTS[index], u16),
        LinuxFdField::Flags => cell!(&X86_RUNTIME.ELF_PROBE_SOCKET_FLAGS[index], u32),
        LinuxFdField::Generation => cell!(&X86_RUNTIME.ELF_PROBE_TMP_FILE_GENERATIONS[index], u32),
        LinuxFdField::EventFd => cell!(&X86_RUNTIME.LINUX_RUNTIME_EVENTFD_ACTIVE[index], u8),
        LinuxFdField::TimerFd => cell!(&X86_RUNTIME.LINUX_RUNTIME_TIMERFD_ACTIVE[index], u8),
        LinuxFdField::Epoll => cell!(&X86_RUNTIME.LINUX_RUNTIME_EPOLL_ACTIVE[index], u8),
        LinuxFdField::EpollAlias => cell!(&X86_RUNTIME.LINUX_RUNTIME_EPOLL_ALIASES[index], u32),
    }
}

/// The current process's open descriptors above the fixed table, in order.
pub(super) fn linux_overflow_descriptors() -> Vec<(u64, crate::linux_fd_table::Entry)> {
    crate::linux_fd_table::entries(
        X86_RUNTIME
            .ELF_PROBE_DESCRIPTOR_OVERFLOW
            .load(Ordering::SeqCst),
    )
}

/// Every descriptor number the current process may hold open: the fixed
/// table's, then those open above it. A scan for open descriptors walks
/// these instead of the fixed table alone.
pub(super) fn linux_descriptor_numbers() -> impl Iterator<Item = u64> {
    let above = if crate::linux_fd_table::active() {
        linux_overflow_descriptors()
    } else {
        Vec::new()
    };
    (0..LINUX_DESCRIPTOR_TABLE_LIMIT).chain(above.into_iter().map(|(descriptor, _)| descriptor))
}

pub(super) fn linux_device_descriptor(descriptor: u64) -> u16 {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_overflow_entry(descriptor).map_or(0, |entry| entry.state);
    }
    if let Some(state) = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS.get(index))
    {
        return state.load(Ordering::SeqCst);
    }
    descriptor
        .checked_sub(LINUX_AUX_DESCRIPTOR_FIRST)
        .and_then(|index| X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS.get(index as usize))
        .map(|state| state.load(Ordering::SeqCst))
        .unwrap_or(0)
}

pub(super) fn linux_tmp_file(state: u16) -> bool {
    state & LINUX_DEVICE_DIRECTORY == 0
        && state & LINUX_FILE_MASK == LINUX_FILE_MASK
        && state & LINUX_ROOT_NODE_MASK == LINUX_TMP_FILE_NODE
}

pub(super) fn linux_tmp_descriptor_handle(
    descriptor: u64,
    state: u16,
) -> Option<linux_tmpfs::FileHandle> {
    if !linux_tmp_file(state) {
        return None;
    }
    let generation = linux_descriptor_tmp_generation(descriptor)?;
    linux_tmpfs::from_generation(generation)
}

pub(super) fn linux_proc_fdinfo_descriptor_target(descriptor: u64) -> Option<u64> {
    if linux_device_descriptor(descriptor) & !3 != LINUX_FILE_PROC_FDINFO {
        return None;
    }
    linux_descriptor_tmp_generation(descriptor)
        .and_then(|encoded| u64::from(encoded).checked_sub(1))
}

/// Sets the value `linux_descriptor_tmp_generation` reads.
pub(super) fn linux_set_descriptor_tmp_generation(descriptor: u64, value: u32) {
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Generation).store(value, Ordering::SeqCst);
}

/// Whether /proc/mounts descriptor `descriptor` was opened or last read
/// before the mount table's latest change.
pub(super) fn linux_proc_mounts_changed(descriptor: u64) -> bool {
    linux_descriptor_tmp_generation(descriptor).is_some_and(|seen| {
        seen != crate::linux_mounts::changes(linux_execution_instance()).wrapping_add(1)
    })
}

pub(super) fn linux_descriptor_tmp_generation(descriptor: u64) -> Option<u32> {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return Some(linux_overflow_entry(descriptor).map_or(0, |entry| entry.generation));
    }
    if let Some(value) = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS.get(index))
    {
        Some(value.load(Ordering::SeqCst))
    } else {
        let index = descriptor.checked_sub(LINUX_AUX_DESCRIPTOR_FIRST)? as usize;
        Some(
            X86_RUNTIME
                .ELF_PROBE_TMP_FILE_GENERATIONS
                .get(index)?
                .load(Ordering::SeqCst),
        )
    }
}

pub(super) fn linux_regular_file(state: u16) -> Option<&'static [u8]> {
    if !linux_mount::current_root_is_read_only() {
        return None;
    }
    if state & LINUX_DEVICE_DIRECTORY != 0 {
        return None;
    }
    if state & !3 == LINUX_FILE_RESOLV_CONF {
        return Some(b"");
    }
    if linux_mountinfo_file(state) {
        return linux_mount::current_mountinfo();
    }
    if state & !3 == LINUX_FILE_PROC_MOUNTS {
        return linux_mount::current_mounts();
    }
    if let Some(contents) = linux_proc_sysctl(state) {
        return Some(contents);
    }
    if let Some(file) = linux_user_namespace_file(state) {
        return Some(file);
    }
    if state & !3 == LINUX_FILE_PROC_STATUS {
        return Some(LINUX_PROC_PID1_STATUS);
    }
    if state & !3 == LINUX_FILE_PROC_PID2_STATUS {
        let status = linux_process::live_process_status(2)?;
        if status.pid != 2 || status.parent_pid != 1 {
            return None;
        }
        return match status.state {
            linux_process::LiveProcessState::Running
            | linux_process::LiveProcessState::Sleeping => Some(LINUX_PROC_PID2_RUNNING_STATUS),
            linux_process::LiveProcessState::Stopped => Some(LINUX_PROC_PID2_STOPPED_STATUS),
            linux_process::LiveProcessState::Zombie => Some(LINUX_PROC_PID2_ZOMBIE_STATUS),
        };
    }
    match state & !3 {
        LINUX_FILE_PROC_CPUINFO => return Some(LINUX_PROC_CPUINFO),
        LINUX_FILE_PROC_SYSVIPC_MSG => return Some(LINUX_PROC_SYSVIPC_MSG_HEADER),
        LINUX_FILE_PROC_SYSVIPC_SHM => return Some(LINUX_PROC_SYSVIPC_SHM_HEADER),
        LINUX_FILE_PROC_SYSVIPC_SEM => return Some(LINUX_PROC_SYSVIPC_SEM_HEADER),
        LINUX_FILE_PROC_MEMINFO => return Some(linux_proc_meminfo()),
        LINUX_FILE_PROC_STAT => return Some(LINUX_PROC_STAT),
        LINUX_FILE_PROC_UPTIME => return Some(linux_proc_uptime()),
        LINUX_FILE_PROC_LOADAVG => return Some(LINUX_PROC_LOADAVG),
        LINUX_FILE_PROC_FILESYSTEMS => return Some(LINUX_PROC_FILESYSTEMS),
        LINUX_FILE_PROC_MODULES => return Some(b""),
        LINUX_FILE_PROC_CONFIG => return Some(&LINUX_PROC_CONFIG_GZ),
        LINUX_FILE_PROC_CMDLINE => return Some(LINUX_PROC_CMDLINE),
        LINUX_FILE_PROC_CGROUP => return Some(linux_proc_cgroup()),
        // Linux's default filter: anonymous private and shared memory, ELF
        // headers and private huge pages (only anonymous memory is dumped).
        LINUX_FILE_PROC_COREDUMP_FILTER => return Some(b"00000033\n"),
        LINUX_FILE_PROC_PROCESS_CMDLINE => return Some(LINUX_PROC_PROCESS_CMDLINE),
        LINUX_FILE_PROC_PROCESS_ENVIRON => return Some(LINUX_PROC_PROCESS_ENVIRON),
        LINUX_FILE_PROC_FILE_MAX => return Some(LINUX_PROC_FILE_MAX),
        LINUX_FILE_PROC_USER_NAMESPACE => return Some(b""),
        LINUX_FILE_PROC_FDINFO => return Some(b""),
        LINUX_FILE_PROC_HOSTNAME => return Some(b"linox\n"),
        LINUX_FILE_PROC_BOOT_ID => return Some(linux_boot_id()),
        LINUX_FILE_PROC_DYNAMIC_STAT
        | LINUX_FILE_PROC_DYNAMIC_STATUS
        | LINUX_FILE_PROC_DYNAMIC_STATM
        | LINUX_FILE_PROC_DYNAMIC_IO
        | LINUX_FILE_PROC_DYNAMIC_MAPS
        | LINUX_FILE_PROC_DYNAMIC_SMAPS
        | LINUX_FILE_PROC_DYNAMIC_PAGEMAP
        | LINUX_FILE_PROC_DYNAMIC_MEM
        | LINUX_FILE_PROC_TASK_COMM
        | LINUX_FILE_PROC_TASK_STAT => return None,
        LINUX_FILE_PROC_PID1_STAT => return Some(LINUX_PROC_PID1_STAT),
        LINUX_FILE_PROC_PID1_STATM => return Some(LINUX_PROC_PID1_STATM),
        LINUX_FILE_PROC_PID2_STATM => {
            return linux_process::live_process_status(2).map(|_| LINUX_PROC_PID2_STATM)
        }
        LINUX_FILE_PROC_PID2_STAT => {
            let status = linux_process::live_process_status(2)?;
            return match status.state {
                linux_process::LiveProcessState::Running
                | linux_process::LiveProcessState::Sleeping => Some(LINUX_PROC_PID2_RUNNING_STAT),
                linux_process::LiveProcessState::Stopped => Some(LINUX_PROC_PID2_STOPPED_STAT),
                linux_process::LiveProcessState::Zombie => Some(LINUX_PROC_PID2_ZOMBIE_STAT),
            };
        }
        _ => {}
    }
    if linux_tmp_file(state) {
        return None;
    }
    let node = ((state & LINUX_ROOT_NODE_MASK) >> LINUX_ROOT_NODE_SHIFT) as u8;
    if node != 0 {
        return initramfs::published_file_by_node(node);
    }
    None
}

pub(super) fn linux_regular_file_inode(state: u16) -> Option<u64> {
    if state & LINUX_DEVICE_DIRECTORY != 0 {
        return None;
    }
    if state & !3 == LINUX_FILE_PROC_MOUNTS {
        return Some(60);
    }
    if let Some(index) = LINUX_PROC_SYSCTLS
        .iter()
        .position(|(node, ..)| state & !3 == LINUX_FILE_MASK | node)
    {
        return Some(LINUX_PROC_SYSCTL_INODES + index as u64);
    }
    if state & !3 == LINUX_FILE_RESOLV_CONF {
        return Some(36);
    }
    if state & !3 == LINUX_FILE_PROC_STATUS {
        return Some(17);
    }
    if state & !3 == LINUX_FILE_PROC_PID2_STATUS {
        return linux_process::live_process_status(2).map(|_| 24);
    }
    if linux_mountinfo_file(state) {
        return Some(19);
    }
    match state & !3 {
        LINUX_FILE_PROC_UID_MAP => return Some(20),
        LINUX_FILE_PROC_GID_MAP => return Some(21),
        LINUX_FILE_PROC_SETGROUPS => return Some(22),
        _ => {}
    }
    match state & !3 {
        LINUX_FILE_PROC_CPUINFO => return Some(25),
        LINUX_FILE_PROC_SYSVIPC_MSG => {
            return Some(linux_proc_node_inode(LINUX_FILE_PROC_SYSVIPC_MSG))
        }
        LINUX_FILE_PROC_SYSVIPC_SHM => {
            return Some(linux_proc_node_inode(LINUX_FILE_PROC_SYSVIPC_SHM))
        }
        LINUX_FILE_PROC_SYSVIPC_SEM => {
            return Some(linux_proc_node_inode(LINUX_FILE_PROC_SYSVIPC_SEM))
        }
        LINUX_FILE_PROC_MEMINFO => return Some(26),
        LINUX_FILE_PROC_STAT => return Some(27),
        LINUX_FILE_PROC_UPTIME => return Some(28),
        LINUX_FILE_PROC_LOADAVG => return Some(29),
        LINUX_FILE_PROC_FILESYSTEMS => return Some(30),
        LINUX_FILE_PROC_MODULES => return Some(linux_proc_node_inode(LINUX_FILE_PROC_MODULES)),
        LINUX_FILE_PROC_KEYS => return Some(linux_proc_node_inode(LINUX_FILE_PROC_KEYS)),
        LINUX_FILE_PROC_KEY_USERS => return Some(linux_proc_node_inode(LINUX_FILE_PROC_KEY_USERS)),
        LINUX_FILE_PROC_SWAPS => return Some(linux_proc_node_inode(LINUX_FILE_PROC_SWAPS)),
        LINUX_FILE_PROC_CONFIG => return Some(linux_proc_node_inode(LINUX_FILE_PROC_CONFIG)),
        LINUX_FILE_PROC_CMDLINE => return Some(31),
        LINUX_FILE_PROC_PID1_STAT => return Some(32),
        LINUX_FILE_PROC_PID1_STATM => return Some(33),
        LINUX_FILE_PROC_PID2_STAT => return linux_process::live_process_status(2).map(|_| 34),
        LINUX_FILE_PROC_PID2_STATM => return linux_process::live_process_status(2).map(|_| 35),
        LINUX_FILE_PROC_CGROUP => return Some(37),
        LINUX_FILE_PROC_COREDUMP_FILTER => {
            return Some(linux_proc_node_inode(LINUX_FILE_PROC_COREDUMP_FILTER))
        }
        LINUX_FILE_PROC_PROCESS_CMDLINE => return Some(40),
        LINUX_FILE_PROC_PROCESS_ENVIRON => return Some(41),
        LINUX_FILE_PROC_FILE_MAX => return Some(42),
        LINUX_FILE_PROC_NR_OPEN => return Some(43),
        LINUX_FILE_PROC_OOM_SCORE_ADJ => return Some(44),
        LINUX_FILE_PROC_TIMENS_OFFSETS => {
            return Some(linux_proc_node_inode(LINUX_FILE_PROC_TIMENS_OFFSETS))
        }
        LINUX_FILE_PROC_USER_NAMESPACE => return Some(45),
        LINUX_FILE_PROC_FDINFO => return Some(46),
        LINUX_FILE_PROC_HOSTNAME => return Some(linux_proc_node_inode(LINUX_FILE_PROC_HOSTNAME)),
        LINUX_FILE_PROC_BOOT_ID => return Some(49),
        LINUX_FILE_PROC_SYSRQ_TRIGGER => return Some(50),
        LINUX_FILE_PROC_DYNAMIC_STAT
        | LINUX_FILE_PROC_DYNAMIC_STATUS
        | LINUX_FILE_PROC_DYNAMIC_STATM
        | LINUX_FILE_PROC_DYNAMIC_IO
        | LINUX_FILE_PROC_DYNAMIC_MAPS
        | LINUX_FILE_PROC_DYNAMIC_SMAPS
        | LINUX_FILE_PROC_DYNAMIC_PAGEMAP
        | LINUX_FILE_PROC_DYNAMIC_MEM => return Some(linux_proc_node_inode(state & !3)),
        LINUX_FILE_PROC_TASK_COMM => return Some(linux_proc_node_inode(LINUX_FILE_PROC_TASK_COMM)),
        LINUX_FILE_PROC_TASK_STAT => return Some(linux_proc_node_inode(LINUX_FILE_PROC_TASK_STAT)),
        _ => {}
    }
    if linux_tmp_file(state) {
        return linux_tmpfs::open(b"linox-ready").map(linux_tmpfs::inode);
    }
    match state & LINUX_FILE_MASK {
        LINUX_FILE_INIT => Some(5),
        LINUX_FILE_INTERPRETER => Some(6),
        LINUX_FILE_DEPENDENCY => Some(7),
        LINUX_FILE_AUXILIARY_DEPENDENCY => Some(8),
        LINUX_FILE_ROOT_HOSTNAME => Some(9),
        LINUX_FILE_ROOT_GENERIC => {
            let node = (state & LINUX_ROOT_NODE_MASK) >> LINUX_ROOT_NODE_SHIFT;
            (node != 0).then_some(32 + u64::from(node))
        }
        _ => None,
    }
}

pub(super) fn linux_regular_file_seek(
    descriptor: u64,
    state: u16,
    offset: u64,
    whence: u64,
) -> u64 {
    const SEEK_DATA: u64 = 3;
    const SEEK_HOLE: u64 = 4;
    let size = || {
        linux_overlay_descriptor_handle(descriptor)
            .and_then(crate::linux_overlay::metadata)
            .map_or_else(
                || {
                    linux_rootfs_entry(descriptor)
                        .map_or_else(|| linux_file_size(state), |entry| entry.data.len() as u64)
                },
                |metadata| metadata.size as u64,
            )
    };
    let base = match whence {
        0 => 0_i128,
        1 => i128::from(linux_descriptor_offset(descriptor).load(Ordering::SeqCst)),
        2 => i128::from(size()),
        // A volume's file has its holes; elsewhere holes are not tracked:
        // the whole file is data, with the implicit hole at its end, as
        // Linux's generic llseek has it.
        SEEK_DATA | SEEK_HOLE => {
            if let Some(handle) = linux_overlay_descriptor_handle(descriptor)
                .filter(|handle| crate::linux_blockfs::owns(*handle))
            {
                if (offset as i64) < 0 {
                    return LINUX_ENXIO;
                }
                return match crate::linux_blockfs::seek(handle, offset, whence == SEEK_DATA) {
                    Some(Some(next)) => {
                        linux_descriptor_offset(descriptor).store(next, Ordering::SeqCst);
                        next
                    }
                    Some(None) => LINUX_ENXIO,
                    None => LINUX_EIO,
                };
            }
            // A paged tmpfs file (a memfd, or one with a hole punched)
            // keeps its holes too.
            if let Some(found) = linux_overlay_descriptor_handle(descriptor).and_then(|handle| {
                crate::linux_overlay::seek(handle, offset as usize, whence == SEEK_DATA)
            }) {
                return match found {
                    Some(next) if (offset as i64) >= 0 => {
                        linux_descriptor_offset(descriptor).store(next as u64, Ordering::SeqCst);
                        next as u64
                    }
                    _ => LINUX_ENXIO,
                };
            }
            let size = size();
            if (offset as i64) < 0 || offset >= size {
                return LINUX_ENXIO;
            }
            let next = if whence == SEEK_DATA { offset } else { size };
            linux_descriptor_offset(descriptor).store(next, Ordering::SeqCst);
            return next;
        }
        _ => return LINUX_EINVAL,
    };
    let next = base + i128::from(offset as i64);
    let Ok(next) = u64::try_from(next) else {
        return LINUX_EINVAL;
    };
    linux_descriptor_offset(descriptor).store(next, Ordering::SeqCst);
    next
}

pub(super) fn linux_tmp_read(descriptor: u64, state: u16, address: u64, count: u64) -> u64 {
    if state & 3 != LINUX_DESCRIPTOR_INPUT && state & 3 != 3 {
        return LINUX_EBADF;
    }
    let Some(handle) = linux_tmp_descriptor_handle(descriptor, state) else {
        return LINUX_EBADF;
    };
    let Ok(start) = usize::try_from(linux_descriptor_offset(descriptor).load(Ordering::SeqCst))
    else {
        return LINUX_EINVAL;
    };
    let requested = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(linux_tmpfs::FILE_CAPACITY);
    let mut output = [0_u8; linux_tmpfs::FILE_CAPACITY];
    let Some(length) = linux_tmpfs::read(handle, start, &mut output[..requested]) else {
        return LINUX_EBADF;
    };
    if length != 0 && !copy_to_linux_user(address, &output[..length]) {
        return LINUX_EFAULT;
    }
    linux_descriptor_offset(descriptor).store((start + length) as u64, Ordering::SeqCst);
    length as u64
}

pub(super) fn linux_overlay_read(
    descriptor: u64,
    state: u16,
    address: u64,
    count: u64,
) -> Option<u64> {
    let handle = linux_overlay_descriptor_handle(descriptor)?;
    if state & 3 != LINUX_DESCRIPTOR_INPUT && state & 3 != 3 {
        return Some(LINUX_EBADF);
    }
    let metadata = crate::linux_overlay::metadata(handle)?;
    if metadata.kind == crate::linux_overlay::NodeKind::Directory {
        return Some(LINUX_EISDIR);
    }
    let Ok(start) = usize::try_from(linux_descriptor_offset(descriptor).load(Ordering::SeqCst))
    else {
        return Some(LINUX_EINVAL);
    };
    let result = linux_overlay_copy_to_user(handle, start, address, count);
    if result < LINUX_RETURN_TO_KERNEL {
        linux_note_read(descriptor, handle);
        linux_descriptor_offset(descriptor).store(
            start.saturating_add(result as usize) as u64,
            Ordering::SeqCst,
        );
    }
    Some(result)
}

pub(super) fn linux_tmp_write(descriptor: u64, state: u16, address: u64, count: u64) -> u64 {
    if state & 3 != LINUX_DESCRIPTOR_OUTPUT && state & 3 != 3 {
        return LINUX_EBADF;
    }
    let Ok(start) = usize::try_from(linux_descriptor_offset(descriptor).load(Ordering::SeqCst))
    else {
        return LINUX_EINVAL;
    };
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    let length = match linux_file_write_limit(start, requested) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let Some(end) = start.checked_add(length) else {
        return LINUX_EINVAL;
    };
    if end > linux_tmpfs::FILE_CAPACITY {
        return LINUX_ENOSPC;
    }
    if length == 0 {
        return 0;
    }
    let Some(handle) = linux_tmp_descriptor_handle(descriptor, state) else {
        return LINUX_EBADF;
    };
    let mut input = [0_u8; linux_tmpfs::FILE_CAPACITY];
    if !copy_from_linux_user(address, &mut input[..length]) {
        return LINUX_EFAULT;
    }
    if linux_tmpfs::write(handle, start, &input[..length]) != Some(length) {
        return LINUX_EBADF;
    }
    linux_descriptor_offset(descriptor).store(end as u64, Ordering::SeqCst);
    length as u64
}

pub(super) fn linux_overlay_write(
    descriptor: u64,
    state: u16,
    address: u64,
    count: u64,
) -> Option<u64> {
    let handle = linux_overlay_descriptor_handle(descriptor)?;
    if state & 3 != LINUX_DESCRIPTOR_OUTPUT && state & 3 != 3 {
        return Some(LINUX_EBADF);
    }
    // hugetlbfs has no write(2) (memfd_create03).
    if linux_overlay_huge(handle) {
        return Some(LINUX_EINVAL);
    }
    let start = if linux_socket_flags(descriptor)
        .is_some_and(|flags| flags & LINUX_O_APPEND as u32 != 0)
    {
        crate::linux_overlay::metadata(handle)?.size
    } else {
        let Ok(start) = usize::try_from(linux_descriptor_offset(descriptor).load(Ordering::SeqCst))
        else {
            return Some(LINUX_EINVAL);
        };
        start
    };
    let result = linux_overlay_copy_from_user(handle, start, address, count);
    if result < LINUX_RETURN_TO_KERNEL {
        linux_descriptor_offset(descriptor).store(
            start.saturating_add(result as usize) as u64,
            Ordering::SeqCst,
        );
        linux_hugepages_sysfs_written(handle);
    }
    Some(result)
}

pub(super) fn linux_overlay_copy_to_user(
    handle: crate::linux_overlay::Handle,
    start: usize,
    address: u64,
    count: u64,
) -> u64 {
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    linux_cgroup_refresh_control(handle);
    let mut output = [0_u8; PAGE_SIZE];
    let mut total = 0_usize;
    while total < requested {
        let chunk = (requested - total).min(output.len());
        let Some(length) =
            crate::linux_overlay::read(handle, start.saturating_add(total), &mut output[..chunk])
        else {
            return if total == 0 {
                LINUX_EBADF
            } else {
                total as u64
            };
        };
        if length == 0 {
            break;
        }
        let Some(destination) = address.checked_add(total as u64) else {
            return if total == 0 {
                LINUX_EFAULT
            } else {
                total as u64
            };
        };
        if !copy_to_linux_user(destination, &output[..length]) {
            return if total == 0 {
                LINUX_EFAULT
            } else {
                total as u64
            };
        }
        total += length;
        if length < chunk {
            break;
        }
    }
    total as u64
}

pub(super) fn linux_overlay_copy_from_user(
    handle: crate::linux_overlay::Handle,
    start: usize,
    address: u64,
    count: u64,
) -> u64 {
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if requested == 0 {
        return 0;
    }
    if let Some(result) = linux_cgroup_user_write(handle, address, requested) {
        return result;
    }
    if let Some(seals) = crate::linux_overlay::file_seals(handle) {
        if seals & (LINUX_F_SEAL_WRITE | LINUX_F_SEAL_FUTURE_WRITE) != 0 {
            return LINUX_EPERM;
        }
        let Some(end) = start.checked_add(requested) else {
            return LINUX_EFBIG;
        };
        if seals & LINUX_F_SEAL_GROW != 0
            && crate::linux_overlay::metadata(handle).is_none_or(|metadata| end > metadata.size)
        {
            return LINUX_EPERM;
        }
    }
    let requested = match linux_file_write_limit(start, requested) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let mut input = [0_u8; PAGE_SIZE];
    let mut total = 0_usize;
    while total < requested {
        let chunk = (requested - total).min(input.len());
        let Some(source) = address.checked_add(total as u64) else {
            return if total == 0 {
                LINUX_EFAULT
            } else {
                total as u64
            };
        };
        if !copy_from_linux_user(source, &mut input[..chunk]) {
            return if total == 0 {
                LINUX_EFAULT
            } else {
                total as u64
            };
        }
        if crate::linux_overlay::write(handle, start.saturating_add(total), &input[..chunk])
            != Some(chunk)
        {
            return if total == 0 {
                LINUX_ENOSPC
            } else {
                total as u64
            };
        }
        total += chunk;
    }
    total as u64
}

/// A descriptor's 64-bit field: in the fixed table's banked arrays, or in
/// its entry above the fixed table (`linux_fd_table`).
#[derive(Clone, Copy)]
pub(super) enum LinuxDescriptorCell {
    Banked(&'static AtomicU64),
    /// The entry's offset (`false`) or open-file id (`true`).
    Overflow {
        descriptor: u64,
        open_file_id: bool,
    },
}

impl LinuxDescriptorCell {
    pub(super) fn load(self, ordering: Ordering) -> u64 {
        match self {
            Self::Banked(cell) => cell.load(ordering),
            Self::Overflow {
                descriptor,
                open_file_id,
            } => linux_overflow_entry(descriptor).map_or(0, |entry| {
                if open_file_id {
                    entry.open_file_id
                } else {
                    entry.offset
                }
            }),
        }
    }

    pub(super) fn store(self, value: u64, ordering: Ordering) {
        match self {
            Self::Banked(cell) => cell.store(value, ordering),
            Self::Overflow {
                descriptor,
                open_file_id,
            } => {
                // An entry above the fixed table may get its offset (an
                // eventfd's open file) before what it is: the store makes it.
                if value == 0 && linux_overflow_entry(descriptor).is_none() {
                    return;
                }
                if let Some(table) = linux_writable_overflow_table() {
                    crate::linux_fd_table::upsert(table, descriptor, |entry| {
                        if open_file_id {
                            entry.open_file_id = value;
                        } else {
                            entry.offset = value;
                        }
                    });
                }
            }
        }
    }
}

pub(super) fn linux_legacy_descriptor_offset(descriptor: u64) -> LinuxDescriptorCell {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return LinuxDescriptorCell::Overflow {
            descriptor,
            open_file_id: false,
        };
    }
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
        return LinuxDescriptorCell::Banked(
            &X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS[descriptor as usize],
        );
    }
    LinuxDescriptorCell::Banked(
        &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_OFFSETS
            [(descriptor - LINUX_AUX_DESCRIPTOR_FIRST) as usize],
    )
}

pub(super) fn linux_descriptor_open_file_id_cell(descriptor: u64) -> Option<LinuxDescriptorCell> {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_overflow_entry(descriptor).map(|_| LinuxDescriptorCell::Overflow {
            descriptor,
            open_file_id: true,
        });
    }
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
        return X86_RUNTIME
            .ELF_PROBE_STDIO_OPEN_FILE_IDS
            .get(descriptor as usize)
            .map(LinuxDescriptorCell::Banked);
    }
    X86_RUNTIME
        .ELF_PROBE_OPEN_FILE_IDS
        .get((descriptor - LINUX_AUX_DESCRIPTOR_FIRST) as usize)
        .map(LinuxDescriptorCell::Banked)
}

pub(super) fn linux_descriptor_open_file_id(descriptor: u64) -> Option<u64> {
    if !linux_descriptor_open(descriptor) {
        return None;
    }
    let cell = linux_descriptor_open_file_id_cell(descriptor)?;
    let current = cell.load(Ordering::SeqCst);
    if current != 0 {
        return Some(current);
    }
    let id = loop {
        let id = X86_RUNTIME
            .LINUX_NEXT_OPEN_FILE_ID
            .fetch_add(1, Ordering::SeqCst);
        if id != 0 {
            break id;
        }
    };
    cell.store(id, Ordering::SeqCst);
    Some(id)
}

fn linux_copy_descriptor_open_file(source: u64, target: u64) -> bool {
    let Some(id) = linux_descriptor_open_file_id(source) else {
        return false;
    };
    let Some(target_cell) = linux_descriptor_open_file_id_cell(target) else {
        return false;
    };
    target_cell.store(id, Ordering::SeqCst);
    true
}

#[derive(Clone, Copy)]
pub(super) struct LinuxDescriptorOffset {
    descriptor: u64,
}

/// The offset cells of the current table's descriptors that share open
/// file `id`, in descriptor order. The banked tables are looked up once,
/// not once per descriptor: that lookup was most of a read's cost.
fn linux_open_file_offset_cells(id: u64) -> impl Iterator<Item = &'static AtomicU64> {
    let stdio_ids: &'static [AtomicU64] = &X86_RUNTIME.ELF_PROBE_STDIO_OPEN_FILE_IDS[..];
    let stdio_offsets: &'static [AtomicU64] = &X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS[..];
    let ids: &'static [AtomicU64] = &X86_RUNTIME.ELF_PROBE_OPEN_FILE_IDS[..];
    let offsets: &'static [AtomicU64] = &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_OFFSETS[..];
    stdio_ids
        .iter()
        .zip(stdio_offsets)
        .chain(ids.iter().zip(offsets))
        .take(LINUX_DESCRIPTOR_TABLE_LIMIT as usize)
        .filter(move |(cell, _)| cell.load(Ordering::SeqCst) == id)
        .map(|(_, offset)| offset)
}

impl LinuxDescriptorOffset {
    pub(super) fn load(self, ordering: Ordering) -> u64 {
        let Some(id) = linux_descriptor_open_file_id(self.descriptor) else {
            return linux_legacy_descriptor_offset(self.descriptor).load(ordering);
        };
        linux_open_file_offset_cells(id)
            .next()
            .map_or_else(
                || linux_legacy_descriptor_offset(self.descriptor),
                LinuxDescriptorCell::Banked,
            )
            .load(ordering)
    }

    pub(super) fn store(self, value: u64, ordering: Ordering) {
        let Some(id) = linux_descriptor_open_file_id(self.descriptor) else {
            linux_legacy_descriptor_offset(self.descriptor).store(value, ordering);
            return;
        };
        for offset in linux_open_file_offset_cells(id) {
            offset.store(value, ordering);
        }
        // The descriptors above the fixed tables that share the file.
        crate::linux_fd_table::sync_offset(id, value);
        sync_saved_linux_open_file_offset(id, value);
    }
}

fn sync_saved_linux_open_file_offset(id: u64, value: u64) {
    sync_live_linux_open_file_offset(id, value);
    // Every saved table is looked at only if it can hold the id: with a
    // thousand processes, looking through each one's descriptors on every
    // read made a read of a file opened since take a millisecond.
    for record in allocated_linux_process_records() {
        let state = &mut record.runtime;
        if !state.valid || id > state.descriptors.max_open_file_id {
            continue;
        }
        for descriptor in 0..state.descriptors.stdio_open_file_ids.len() {
            if state.descriptors.stdio_open_file_ids[descriptor] == id {
                state.descriptors.stdio_offsets[descriptor] = value;
            }
        }
        for descriptor in 0..state.descriptors.open_file_ids.len() {
            if state.descriptors.open_file_ids[descriptor] == id {
                state.descriptors.offsets[descriptor] = value;
            }
        }
    }
}

/// Sets open file `id`'s offset to `value` in the live banks of this
/// domain other than this CPU's: a process that runs on another CPU, or has
/// threads there, holds its descriptor table in its bank, and the save when
/// it leaves that CPU would put back the offset it had. A parent and the
/// children it forked share an open file and run on different CPUs at once
/// now that the parent goes on after a fork (fork07: a hundred children each
/// read one byte, and the parent then read past them).
fn sync_live_linux_open_file_offset(id: u64, value: u64) {
    let current = linux_cpu_bank();
    let instance = linux_execution_instance();
    for bank in 0..LINUX_CPU_BANK_LIMIT {
        if bank == current
            || LINUX_BANK_USERS[bank].load(Ordering::Acquire) == 0
            || LINUX_BANK_PID[bank].load(Ordering::Acquire) == 0
            || usize::from(LINUX_BANK_INSTANCE[bank].load(Ordering::Acquire)) != instance
        {
            continue;
        }
        let tables = [
            (
                &X86_RUNTIME.ELF_PROBE_STDIO_OPEN_FILE_IDS.at_bank(bank)[..],
                &X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS.at_bank(bank)[..],
            ),
            (
                &X86_RUNTIME.ELF_PROBE_OPEN_FILE_IDS.at_bank(bank)[..],
                &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_OFFSETS.at_bank(bank)[..],
            ),
        ];
        for (ids, offsets) in tables {
            for (cell, offset) in ids.iter().zip(offsets) {
                if cell.load(Ordering::SeqCst) == id {
                    offset.store(value, Ordering::SeqCst);
                }
            }
        }
    }
}

pub(super) fn linux_descriptor_offset(descriptor: u64) -> LinuxDescriptorOffset {
    LinuxDescriptorOffset { descriptor }
}

pub(super) fn linux_descriptor_close_on_exec(descriptor: u64) -> bool {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_overflow_entry(descriptor).is_some_and(|entry| entry.close_on_exec);
    }
    let word = descriptor as usize / u64::BITS as usize;
    let mask = 1_u64 << (descriptor % u64::BITS as u64);
    X86_RUNTIME.ELF_PROBE_CONSOLE_CLOEXEC[word].load(Ordering::SeqCst) & mask != 0
}

/// One bit per descriptor in `table`, as the close-on-exec bits are kept.
pub(super) fn linux_descriptor_flag(
    table: &[CpuBankedAtomicU64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
    descriptor: u64,
) -> bool {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        // Above the fixed table only F_CREATED_QUERY's bit is kept.
        return core::ptr::eq(table, &*X86_RUNTIME.ELF_PROBE_DESCRIPTOR_CREATED)
            && linux_overflow_entry(descriptor).is_some_and(|entry| entry.created);
    }
    let word = descriptor as usize / u64::BITS as usize;
    let mask = 1_u64 << (descriptor % u64::BITS as u64);
    table[word].load(Ordering::SeqCst) & mask != 0
}

fn set_linux_descriptor_flag(
    table: &[CpuBankedAtomicU64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
    descriptor: u64,
    enabled: bool,
) {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        if core::ptr::eq(table, &*X86_RUNTIME.ELF_PROBE_DESCRIPTOR_CREATED) {
            let _ = update_linux_overflow_entry(descriptor, |entry| entry.created = enabled);
        }
        return;
    }
    let word = descriptor as usize / u64::BITS as usize;
    let mask = 1_u64 << (descriptor % u64::BITS as u64);
    if enabled {
        table[word].fetch_or(mask, Ordering::SeqCst);
    } else {
        table[word].fetch_and(!mask, Ordering::SeqCst);
    }
}

/// A descriptor number taken for a new open file: nothing of an earlier
/// use is kept for it.
pub(super) fn reset_linux_descriptor_flags(descriptor: u64, created: bool) {
    set_linux_descriptor_flag(
        &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_CREATED,
        descriptor,
        created,
    );
    set_linux_descriptor_flag(
        &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_READ_LEASES,
        descriptor,
        false,
    );
    set_linux_descriptor_flag(
        &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_WRITE_LEASES,
        descriptor,
        false,
    );
}

pub(super) fn set_linux_descriptor_close_on_exec(descriptor: u64, enabled: bool) {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        let _ = update_linux_overflow_entry(descriptor, |entry| entry.close_on_exec = enabled);
        return;
    }
    let word = descriptor as usize / u64::BITS as usize;
    let mask = 1_u64 << (descriptor % u64::BITS as u64);
    if enabled {
        X86_RUNTIME.ELF_PROBE_CONSOLE_CLOEXEC[word].fetch_or(mask, Ordering::SeqCst);
    } else {
        X86_RUNTIME.ELF_PROBE_CONSOLE_CLOEXEC[word].fetch_and(!mask, Ordering::SeqCst);
    }
}

pub(super) fn clear_linux_descriptor_close_on_exec() -> bool {
    let mut clear = true;
    for word in &X86_RUNTIME.ELF_PROBE_CONSOLE_CLOEXEC {
        clear &= word.swap(0, Ordering::SeqCst) == 0;
    }
    clear
}

pub(super) fn linux_console_descriptor(descriptor: u64) -> u8 {
    if descriptor == 2 && X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::SeqCst) {
        return LINUX_DESCRIPTOR_OUTPUT as u8;
    }
    if descriptor >= 2 {
        return 0;
    }
    (X86_RUNTIME
        .ELF_PROBE_CONSOLE_DESCRIPTORS
        .load(Ordering::SeqCst)
        >> (descriptor * 2))
        & 0b11
}

fn linux_console_close(descriptor: u64) -> u64 {
    if descriptor >= 2 {
        return LINUX_EBADF;
    }
    let shift = descriptor * 2;
    let mask = 0b11_u8 << shift;
    loop {
        let current = X86_RUNTIME
            .ELF_PROBE_CONSOLE_DESCRIPTORS
            .load(Ordering::SeqCst);
        if current & mask == 0 {
            return LINUX_EBADF;
        }
        if X86_RUNTIME
            .ELF_PROBE_CONSOLE_DESCRIPTORS
            .compare_exchange(current, current & !mask, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            set_linux_descriptor_close_on_exec(descriptor, false);
            return 0;
        }
    }
}

pub(super) fn linux_descriptor_close(descriptor: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    linux_descriptor_close_with_wake(descriptor, true)
}

pub(super) fn linux_close_all_descriptors() -> bool {
    crate::framebuffer::set_owned(false);
    crate::linux_input::flush();
    if linux_close_overflow_range(LINUX_DESCRIPTOR_TABLE_LIMIT, u64::MAX, false) != 0 {
        serial_write("linox: descriptor teardown failed above the fixed table\r\n");
        return false;
    }
    for descriptor in 0..LINUX_DESCRIPTOR_TABLE_LIMIT {
        if linux_descriptor_open(descriptor) {
            let result = linux_descriptor_close(descriptor);
            if result != 0 {
                serial_write("linox: descriptor teardown failed fd/result ");
                serial_write_u64(descriptor);
                serial_write(" ");
                serial_write_u64(result);
                serial_write("\r\n");
                return false;
            }
        }
    }
    for descriptor in 0..LINUX_DESCRIPTOR_TABLE_LIMIT {
        if linux_descriptor_open(descriptor) {
            serial_write("linox: descriptor remained open after teardown fd ");
            serial_write_u64(descriptor);
            serial_write("\r\n");
            return false;
        }
    }
    true
}

/// Closes every open descriptor of the current process above the fixed
/// table, or marks them close-on-exec (`close_on_exec`), from `first` to
/// `last`; the first error.
fn linux_close_overflow_range(first: u64, last: u64, close_on_exec: bool) -> u64 {
    let table = X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OVERFLOW
        .load(Ordering::SeqCst);
    for (descriptor, _) in crate::linux_fd_table::entries(table) {
        if descriptor < first || descriptor > last {
            continue;
        }
        if close_on_exec {
            set_linux_descriptor_close_on_exec(descriptor, true);
        } else if linux_descriptor_close(descriptor) != 0 {
            return LINUX_EBADF;
        }
    }
    0
}

/// exec: the descriptors above the fixed table marked close-on-exec close.
pub(super) fn linux_close_overflow_on_exec() {
    let table = X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OVERFLOW
        .load(Ordering::SeqCst);
    for (descriptor, entry) in crate::linux_fd_table::entries(table) {
        if entry.close_on_exec {
            let _ = linux_descriptor_close(descriptor);
        }
    }
}

pub(super) fn linux_close_range(first: u64, last: u64, flags: u64) -> u64 {
    let first = u64::from(first as u32);
    let last = u64::from(last as u32);
    let flags = u64::from(flags as u32);
    if first > last || flags & !(LINUX_CLOSE_RANGE_CLOEXEC | LINUX_CLOSE_RANGE_UNSHARE) != 0 {
        return LINUX_EINVAL;
    }
    // CLOSE_RANGE_UNSHARE: the caller gets a table of its own first, so
    // what it closes stays open for those it shared the table with.
    if flags & LINUX_CLOSE_RANGE_UNSHARE != 0
        && !unshare_linux_descriptors(current_linux_process_pid())
    {
        return LINUX_ENOMEM;
    }
    let end = last.min(LINUX_DESCRIPTOR_TABLE_LIMIT - 1);
    if first <= end {
        for descriptor in first..=end {
            if !linux_descriptor_open(descriptor) {
                continue;
            }
            if flags & LINUX_CLOSE_RANGE_CLOEXEC != 0 {
                set_linux_descriptor_close_on_exec(descriptor, true);
            } else if linux_descriptor_close(descriptor) != 0 {
                return LINUX_EBADF;
            }
        }
    }
    if last >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_close_overflow_range(first, last, flags & LINUX_CLOSE_RANGE_CLOEXEC != 0);
    }
    0
}

fn linux_descriptor_close_with_wake(descriptor: u64, wake_waiters: bool) -> u64 {
    // A dnotify registration and F_SETSIG choice end with the descriptor.
    crate::linux_inotify::dnotify_closed(
        linux_execution_instance(),
        current_linux_process_pid(),
        descriptor as u32,
    );
    crate::linux_async_io::closed(
        linux_execution_instance(),
        current_linux_process_pid(),
        descriptor as u32,
    );
    // Closing any descriptor of a file drops the process's record locks on
    // it, and closing a description's descriptor drops its OFD locks.
    let owners = [
        Some(crate::linux_record_lock::Owner::Process(
            current_linux_process_pid(),
        )),
        linux_descriptor_open_file_id(descriptor).map(crate::linux_record_lock::Owner::Description),
    ];
    for owner in owners.into_iter().flatten() {
        if crate::linux_record_lock::holds_any(owner) {
            if let Some(file) = linux_record_lock_file(descriptor) {
                crate::linux_record_lock::release(owner, file);
            }
        }
    }
    // The last descriptor of the description to close drops its flock lock.
    if let Some(description) = linux_descriptor_open_file_id(descriptor) {
        let shared = linux_descriptor_numbers().any(|other| {
            other != descriptor && linux_descriptor_open_file_id(other) == Some(description)
        });
        if !shared {
            crate::linux_record_lock::flock_release(description);
        }
    }
    let result = linux_descriptor_close_with_wake_inner(descriptor, wake_waiters);
    if result == 0 {
        if let Some(cell) = linux_descriptor_open_file_id_cell(descriptor) {
            cell.store(0, Ordering::SeqCst);
        }
        linux_legacy_descriptor_offset(descriptor).store(0, Ordering::SeqCst);
        // Whatever the close left of an entry above the fixed table goes.
        if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT && linux_overflow_entry(descriptor).is_some()
        {
            if let Some(table) = linux_own_overflow_table() {
                let _ = crate::linux_fd_table::remove(table, descriptor);
            }
        }
        linux_reclaim_unlinked_files();
    }
    result
}

fn linux_descriptor_close_with_wake_inner(descriptor: u64, wake_waiters: bool) -> u64 {
    // Above the fixed table, a table shared with a copy (after a fork) is
    // copied before what the descriptor refers to is let go of: the copy
    // holds it again, and this close lets go of the copy's hold.
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT
        && linux_overflow_entry(descriptor).is_some()
        && linux_own_overflow_table().is_none()
    {
        return LINUX_ENOMEM;
    }
    linux_epoll_forget_descriptor(descriptor);
    if let Some(slot) = linux_socket_slot(descriptor) {
        let closed = crate::linux_socket::close(slot);
        linux_release_objects();
        linux_pty_send_hangups();
        if let Some(index) = usize::try_from(descriptor)
            .ok()
            .filter(|index| *index < X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS.len())
        {
            X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS[index].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[index].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS[index].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS[index].store(0, Ordering::SeqCst);
            if descriptor == 2 {
                X86_RUNTIME
                    .ELF_PROBE_STDERR_OPEN
                    .store(false, Ordering::SeqCst);
            }
        } else {
            set_linux_descriptor_close_on_exec(descriptor, false);
            linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(0, Ordering::SeqCst);
            linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(0, Ordering::SeqCst);
            linux_fd_cell::<u16>(descriptor, LinuxFdField::Socket).store(0, Ordering::SeqCst);
        }
        set_linux_descriptor_close_on_exec(descriptor, false);
        if wake_waiters {
            wake_linux_descriptor_waits();
        }
        return if closed { 0 } else { LINUX_EBADF };
    }
    if descriptor == 2
        && X86_RUNTIME
            .ELF_PROBE_STDERR_OPEN
            .swap(false, Ordering::SeqCst)
    {
        X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[2].store(0, Ordering::SeqCst);
        set_linux_descriptor_close_on_exec(descriptor, false);
        if linux_device_descriptor(descriptor) == 0 {
            return 0;
        }
    }
    if linux_inotify_descriptor(descriptor) {
        linux_inotify_release(descriptor);
    }
    if linux_fanotify_descriptor(descriptor) {
        linux_fanotify_release(descriptor);
    }
    if linux_io_uring_descriptor(descriptor) {
        linux_io_uring_release(descriptor);
    }
    if let Some(id) = linux_mq_descriptor_id(descriptor) {
        match crate::linux_sysv_ipc::posix_queue_close_by(id, current_linux_process_pid()) {
            Ok((destroyed, removed)) => {
                if let Some(removed) = removed {
                    linux_mq_finish_registration(removed, false);
                }
                if !linux_release_posix_queue_charge(destroyed) {
                    return LINUX_EIO;
                }
            }
            Err(_) => return LINUX_EBADF,
        }
    }
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST && linux_device_descriptor(descriptor) != 0 {
        let index = descriptor as usize;
        X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS[index].store(0, Ordering::SeqCst);
        set_linux_descriptor_close_on_exec(descriptor, false);
        return 0;
    }
    if linux_epoll_descriptor(descriptor) {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            // The alias first: clearing the mark may free the entry above
            // the fixed table.
            let alias = linux_fd_cell::<u32>(descriptor, LinuxFdField::EpollAlias)
                .swap(0, Ordering::SeqCst);
            linux_fd_cell::<u8>(descriptor, LinuxFdField::Epoll).store(0, Ordering::SeqCst);
            if alias == 0 && !linux_epoll_hand_over(descriptor) {
                linux_epoll_forget_owner(descriptor);
            }
        } else {
            X86_RUNTIME
                .ELF_PROBE_EPOLL_DESCRIPTOR
                .store(0, Ordering::SeqCst);
            for target in 0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize {
                X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[target].store(0, Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_EPOLL_DATA[target].store(0, Ordering::SeqCst);
            }
        }
        set_linux_descriptor_close_on_exec(descriptor, false);
        if wake_waiters {
            wake_linux_descriptor_waits();
        }
        return 0;
    }
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST
        && !linux_eventfd_descriptor(descriptor)
        && !linux_timerfd_descriptor(descriptor)
        && !linux_pipe_descriptor(descriptor)
    {
        return linux_console_close(descriptor);
    }
    if linux_eventfd_descriptor(descriptor) {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            if let Some(id) = linux_eventfd_file(descriptor) {
                crate::linux_event_files::release(crate::linux_event_files::Kind::EventFd, id);
            }
            set_linux_descriptor_close_on_exec(descriptor, false);
            linux_legacy_descriptor_offset(descriptor).store(0, Ordering::SeqCst);
            linux_fd_cell::<u8>(descriptor, LinuxFdField::EventFd).store(0, Ordering::SeqCst);
        } else {
            X86_RUNTIME
                .ELF_PROBE_EVENTFD_DESCRIPTOR
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_EVENTFD_COUNTER
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_EVENTFD_FLAGS
                .store(0, Ordering::SeqCst);
        }
        set_linux_descriptor_close_on_exec(descriptor, false);
        if wake_waiters {
            wake_linux_descriptor_waits();
        }
        return 0;
    }
    if linux_timerfd_descriptor(descriptor) {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            if let Some(id) = linux_timerfd_file(descriptor) {
                crate::linux_event_files::release(crate::linux_event_files::Kind::TimerFd, id);
            }
            set_linux_descriptor_close_on_exec(descriptor, false);
            linux_legacy_descriptor_offset(descriptor).store(0, Ordering::SeqCst);
            linux_fd_cell::<u8>(descriptor, LinuxFdField::TimerFd).store(0, Ordering::SeqCst);
        } else {
            X86_RUNTIME
                .ELF_PROBE_TIMERFD_DESCRIPTOR
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_TIMERFD_CLOCK
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_TIMERFD_FLAGS
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_TIMERFD_INTERVAL
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_TIMERFD_DEADLINE
                .store(0, Ordering::SeqCst);
        }
        set_linux_descriptor_close_on_exec(descriptor, false);
        if wake_waiters {
            wake_linux_descriptor_waits();
        }
        return 0;
    }
    if linux_pipe_read_descriptor(descriptor) {
        X86_RUNTIME
            .ELF_PROBE_PIPE_READ_DESCRIPTOR
            .store(0, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_PIPE_READ_FLAGS
            .store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.store(0, Ordering::SeqCst);
        for byte in &X86_RUNTIME.ELF_PROBE_PIPE_BUFFER {
            byte.store(0, Ordering::SeqCst);
        }
        set_linux_descriptor_close_on_exec(descriptor, false);
        if wake_waiters {
            wake_linux_descriptor_waits();
        }
        return 0;
    }
    if linux_pipe_write_descriptor(descriptor) {
        X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
            .store(0, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_FLAGS
            .store(0, Ordering::SeqCst);
        if X86_RUNTIME
            .ELF_PROBE_PIPE_READ_DESCRIPTOR
            .load(Ordering::SeqCst)
            == 0
        {
            X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.store(0, Ordering::SeqCst);
        }
        set_linux_descriptor_close_on_exec(descriptor, false);
        if wake_waiters {
            wake_linux_descriptor_waits();
        }
        return 0;
    }
    if linux_device_descriptor(descriptor) == 0 {
        return LINUX_EBADF;
    }
    // The fields first, the kind last: above the fixed table, clearing
    // the kind frees the entry.
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Rootfs).store(0, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Generation).store(0, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(0, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(0, Ordering::SeqCst);
    set_linux_descriptor_close_on_exec(descriptor, false);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(0, Ordering::SeqCst);
    0
}

pub(super) fn linux_descriptor_close_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    descriptor: u64,
) -> u64 {
    let closes_pipe_reader = linux_pipe_read_descriptor(descriptor);
    let blocked_writer = closes_pipe_reader.then(blocked_linux_pipe_writer).flatten();
    let result = linux_descriptor_close_with_wake(descriptor, false);
    if result != 0 {
        // EBADF is an ordinary answer: shells close descriptors that may
        // not be open.
        return result;
    }
    let Some(target) = blocked_writer else {
        wake_linux_descriptor_waits();
        return 0;
    };
    let slot = usize::from(target.slot);
    let signal_bit = 1 << (LINUX_SIGPIPE - 1);
    let signal_mask = X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].load(Ordering::SeqCst);
    let index = LINUX_SIGPIPE as usize - 1;
    let handler = X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].load(Ordering::SeqCst);
    if signal_mask & signal_bit != 0 {
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index]
            .store(LINUX_SI_KERNEL as u32, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_PENDING_SIGNALS
            .fetch_or(signal_bit, Ordering::SeqCst);
        wake_linux_descriptor_waits();
        return 0;
    }
    if handler == 1 {
        wake_linux_descriptor_waits();
        return 0;
    }
    if handler == 0 {
        return linux_terminate_by_default_signal(LINUX_SIGPIPE);
    }
    let delivered = linux_deliver_signal_to_blocked_wait(
        target,
        (LINUX_SIGPIPE, LINUX_SI_KERNEL),
        output,
        caller,
        LINUX_EPIPE,
        true,
    );
    if delivered != 0 {
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index]
            .store(LINUX_SI_KERNEL as u32, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_PENDING_SIGNALS
            .fetch_or(signal_bit, Ordering::SeqCst);
    }
    wake_linux_descriptor_waits();
    0
}

pub(super) fn linux_console_dup(descriptor: u64) -> u64 {
    linux_console_dup_at_least(u64::from(descriptor as u32), 0, false)
}

pub(super) fn linux_console_dup_at_least(
    descriptor: u64,
    minimum: u64,
    close_on_exec: bool,
) -> u64 {
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    let limit = linux_nofile_soft_limit();
    if minimum >= limit {
        return LINUX_EINVAL;
    }
    let Some(target) = (minimum..limit.min(LINUX_DESCRIPTOR_TABLE_LIMIT))
        .find(|target| !linux_descriptor_open(*target))
        .or_else(|| linux_free_overflow_descriptor(minimum))
    else {
        return LINUX_EMFILE;
    };
    let result = linux_console_dup2(descriptor, target);
    if result != target {
        return result;
    }
    set_linux_descriptor_close_on_exec(target, close_on_exec);
    target
}

fn linux_finish_descriptor_dup(source: u64, target: u64) -> u64 {
    if linux_copy_descriptor_open_file(source, target) {
        target
    } else {
        let _ = linux_descriptor_close(target);
        LINUX_EMFILE
    }
}

pub(super) fn linux_console_dup2(source: u64, target: u64) -> u64 {
    let source = u64::from(source as u32);
    let target = u64::from(target as u32);
    // A target above the fixed table needs room in the table there.
    if target >= LINUX_DESCRIPTOR_TABLE_LIMIT
        && target < linux_nofile_soft_limit()
        && source != target
        && linux_descriptor_open(source)
        && linux_writable_overflow_table().is_none()
    {
        return LINUX_ENOMEM;
    }
    if linux_epoll_descriptor(source) {
        return linux_epoll_dup(source, target);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && (linux_eventfd_descriptor(source) || linux_timerfd_descriptor(source))
    {
        return linux_event_file_dup(source, target);
    }
    let device = linux_device_descriptor(source);
    if device != 0 {
        if source == target {
            return target;
        }
        if target >= linux_nofile_soft_limit() {
            return LINUX_EBADF;
        }
        if linux_descriptor_open(target) && linux_descriptor_close(target) != 0 {
            return LINUX_EBADF;
        }
        if let Some(id) = linux_mq_descriptor_id(source) {
            if crate::linux_sysv_ipc::posix_queue_duplicate(id).is_err() {
                return LINUX_EBADF;
            }
        }
        if let Some(slot) = linux_socket_slot(source) {
            if !crate::linux_socket::duplicate(slot) {
                return LINUX_EBADF;
            }
            let flags = linux_socket_flags(source).unwrap_or(0);
            if target < LINUX_AUX_DESCRIPTOR_FIRST {
                let target_index = target as usize;
                X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS[target_index]
                    .store(slot + 1, Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[target_index]
                    .store(flags, Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[target_index]
                    .store(device, Ordering::SeqCst);
                if target == 2 {
                    X86_RUNTIME
                        .ELF_PROBE_STDERR_OPEN
                        .store(false, Ordering::SeqCst);
                }
            } else {
                linux_fd_cell::<u16>(target, LinuxFdField::Socket)
                    .store(slot + 1, Ordering::SeqCst);
                linux_fd_cell::<u32>(target, LinuxFdField::Flags).store(flags, Ordering::SeqCst);
                linux_fd_cell::<u16>(target, LinuxFdField::Device).store(device, Ordering::SeqCst);
            }
            set_linux_descriptor_close_on_exec(target, false);
            return linux_finish_descriptor_dup(source, target);
        }
        let source_offset = linux_descriptor_offset(source).load(Ordering::SeqCst);
        let source_flags = linux_socket_flags(source).unwrap_or(0);
        let source_rootfs = linux_rootfs_descriptor(source);
        let source_tmp = linux_descriptor_tmp_generation(source).unwrap_or(0);
        if device & LINUX_DEVICE_CONSOLE != 0 {
            if target == 2 {
                X86_RUNTIME
                    .ELF_PROBE_STDERR_OPEN
                    .store(true, Ordering::SeqCst);
                set_linux_descriptor_close_on_exec(target, false);
                return linux_finish_descriptor_dup(source, target);
            }
            if target >= LINUX_AUX_DESCRIPTOR_FIRST {
                linux_fd_cell::<u16>(target, LinuxFdField::Device).store(device, Ordering::SeqCst);
                set_linux_descriptor_close_on_exec(target, false);
                return linux_finish_descriptor_dup(source, target);
            }
            let shift = target * 2;
            X86_RUNTIME
                .ELF_PROBE_CONSOLE_DESCRIPTORS
                .fetch_or((device as u8 & 3) << shift, Ordering::SeqCst);
            set_linux_descriptor_close_on_exec(target, false);
            return linux_finish_descriptor_dup(source, target);
        }
        if target >= LINUX_AUX_DESCRIPTOR_FIRST {
            linux_fd_cell::<u16>(target, LinuxFdField::Device).store(device, Ordering::SeqCst);
            linux_fd_cell::<u16>(target, LinuxFdField::Rootfs)
                .store(source_rootfs, Ordering::SeqCst);
            linux_fd_cell::<u32>(target, LinuxFdField::Generation)
                .store(source_tmp, Ordering::SeqCst);
            linux_fd_cell::<u32>(target, LinuxFdField::Flags).store(source_flags, Ordering::SeqCst);
            linux_legacy_descriptor_offset(target).store(source_offset, Ordering::SeqCst);
        } else {
            let index = target as usize;
            X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index].store(device, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS[index]
                .store(source_rootfs, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index]
                .store(source_tmp, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[index].store(source_flags, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS[index].store(source_offset, Ordering::SeqCst);
        }
        set_linux_descriptor_close_on_exec(target, false);
        return linux_finish_descriptor_dup(source, target);
    }
    let state = linux_console_descriptor(source);
    if state == 0 {
        return LINUX_EBADF;
    }
    if source == target {
        return target;
    }
    if target >= linux_nofile_soft_limit() {
        return LINUX_EBADF;
    }
    if linux_descriptor_open(target) && linux_descriptor_close(target) != 0 {
        return LINUX_EBADF;
    }
    if target == 2 {
        if state & LINUX_DESCRIPTOR_OUTPUT as u8 == 0 {
            return LINUX_EBADF;
        }
        X86_RUNTIME
            .ELF_PROBE_STDERR_OPEN
            .store(true, Ordering::SeqCst);
        set_linux_descriptor_close_on_exec(target, false);
        return linux_finish_descriptor_dup(source, target);
    }
    if target >= LINUX_AUX_DESCRIPTOR_FIRST {
        linux_fd_cell::<u16>(target, LinuxFdField::Device)
            .store(LINUX_DEVICE_CONSOLE | u16::from(state), Ordering::SeqCst);
        set_linux_descriptor_close_on_exec(target, false);
        return linux_finish_descriptor_dup(source, target);
    }
    loop {
        let current = X86_RUNTIME
            .ELF_PROBE_CONSOLE_DESCRIPTORS
            .load(Ordering::SeqCst);
        let shift = target * 2;
        let mask = 0b11_u8 << shift;
        if X86_RUNTIME
            .ELF_PROBE_CONSOLE_DESCRIPTORS
            .compare_exchange(
                current,
                (current & !mask) | (state << shift),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            set_linux_descriptor_close_on_exec(target, false);
            return linux_finish_descriptor_dup(source, target);
        }
    }
}

pub(super) fn linux_dup3(source: u64, target: u64, flags: u64) -> u64 {
    let source = u64::from(source as u32);
    let target = u64::from(target as u32);
    let flags = u64::from(flags as u32);
    if flags & !LINUX_O_CLOEXEC != 0 || source == target {
        return LINUX_EINVAL;
    }
    let result = linux_console_dup2(source, target);
    if result == target {
        set_linux_descriptor_close_on_exec(target, flags & LINUX_O_CLOEXEC != 0);
    }
    result
}

pub(super) fn linux_device_dup_at_least(source: u64, minimum: u64, close_on_exec: bool) -> u64 {
    let state = linux_device_descriptor(source);
    let limit = linux_nofile_soft_limit();
    if state == 0 || minimum >= limit {
        return if state == 0 {
            LINUX_EBADF
        } else {
            LINUX_EINVAL
        };
    }
    let Some(target) = (minimum..limit.min(LINUX_DESCRIPTOR_TABLE_LIMIT))
        .find(|descriptor| !linux_descriptor_open(*descriptor))
        .or_else(|| linux_free_overflow_descriptor(minimum))
    else {
        return LINUX_EMFILE;
    };
    let result = linux_console_dup2(source, target);
    if result != target {
        return result;
    }
    set_linux_descriptor_close_on_exec(target, close_on_exec);
    target
}

/// The status flags (O_NONBLOCK, O_APPEND) of socket or pipe `descriptor`.
pub(super) fn linux_socket_flags_cell(descriptor: u64) -> Option<LinuxFdCell<u32>> {
    linux_socket_slot(descriptor)?;
    Some(linux_fd_cell(descriptor, LinuxFdField::Flags))
}

pub(super) fn linux_descriptor_set_nonblocking(
    flags: &dyn LinuxFileCell<u32>,
    argument: u64,
) -> u64 {
    linux_descriptor_set_status_flags(flags, argument, LINUX_O_NONBLOCK)
}

pub(super) fn linux_descriptor_set_status_flags(
    flags: &dyn LinuxFileCell<u32>,
    argument: u64,
    supported: u64,
) -> u64 {
    // Linux changes only the flags F_SETFL supports and ignores the rest,
    // so callers may pass back what F_GETFL returned.
    let current = flags.load(Ordering::SeqCst);
    flags.store(
        (current & !(supported as u32)) | (argument as u32 & supported as u32),
        Ordering::SeqCst,
    );
    0
}

/// getdents cookies from here on walk a merged directory's overlay entries
/// (`linux_getdents`); those below it walk the image's.
pub(super) const LINUX_DIRENT_OVERLAY_PHASE: u64 = 1 << 40;

pub(super) fn linux_nofile_soft_limit() -> u64 {
    let runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    linux_resource_limit_values(LINUX_RLIMIT_NOFILE, runtime).map_or(0, |limit| {
        // Only a running Linux process has a table above the fixed one.
        if runtime {
            limit[0].min(linux_nr_open())
        } else {
            limit[0].min(LINUX_DESCRIPTOR_TABLE_LIMIT)
        }
    })
}

/// The lowest descriptor at or above `first` past the fixed table that
/// the current process may open (below its RLIMIT_NOFILE soft limit), for
/// a kind of file the table above it holds, when the fixed table has no
/// room.
pub(super) fn linux_free_overflow_descriptor(first: u64) -> Option<u64> {
    let limit = linux_nofile_soft_limit();
    if limit <= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return None;
    }
    crate::linux_fd_table::first_free(
        X86_RUNTIME
            .ELF_PROBE_DESCRIPTOR_OVERFLOW
            .load(Ordering::SeqCst),
        first.max(LINUX_DESCRIPTOR_TABLE_LIMIT),
        limit,
    )
}

/// The `N` lowest free descriptors from `first`: in the fixed table, then
/// above it, for a kind of file the table above it holds (a socket, a
/// pipe, a regular file).
pub(super) fn linux_free_descriptors<const N: usize>(first: u64) -> Option<[u64; N]> {
    let mut found = [0_u64; N];
    let mut count = 0;
    for descriptor in first..LINUX_AUX_DESCRIPTOR_LIMIT {
        if count == N {
            break;
        }
        if linux_aux_descriptor_free(descriptor) {
            found[count] = descriptor;
            count += 1;
        }
    }
    let mut next = first.max(LINUX_DESCRIPTOR_TABLE_LIMIT);
    while count < N {
        let descriptor = linux_free_overflow_descriptor(next)?;
        found[count] = descriptor;
        count += 1;
        next = descriptor + 1;
    }
    Some(found)
}

/// `linux_free_descriptors` for one descriptor.
pub(super) fn linux_free_descriptor(first: u64) -> Option<u64> {
    linux_free_descriptors::<1>(first).map(|[descriptor]| descriptor)
}

/// The lowest free descriptor from `first`, in the fixed table or above
/// it (EMFILE when none is below RLIMIT_NOFILE), with the table above it
/// ready to hold it (ENOMEM).
pub(super) fn linux_allocate_descriptor(first: u64) -> Result<u64, u64> {
    let descriptor = linux_free_descriptor(first).ok_or(LINUX_EMFILE)?;
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT && linux_writable_overflow_table().is_none() {
        return Err(LINUX_ENOMEM);
    }
    Ok(descriptor)
}

/// Opens descriptor `descriptor` (free) on socket slot `slot` as `state`
/// with descriptor flags `flags`, in the fixed table or above it; false
/// without memory for the table above it.
pub(super) fn install_linux_socket_descriptor(
    descriptor: u64,
    slot: crate::linux_socket::SlotId,
    state: u16,
    flags: u32,
    close_on_exec: bool,
) -> bool {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return install_linux_overflow_descriptor(
            descriptor,
            crate::linux_fd_table::Entry {
                state,
                socket: slot + 1,
                socket_flags: flags,
                close_on_exec,
                ..Default::default()
            },
        );
    }
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
        let index = descriptor as usize;
        X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS[index].store(slot + 1, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[index].store(flags, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index].store(state, Ordering::SeqCst);
    } else {
        linux_fd_cell::<u16>(descriptor, LinuxFdField::Socket).store(slot + 1, Ordering::SeqCst);
        linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(flags, Ordering::SeqCst);
        linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(state, Ordering::SeqCst);
    }
    set_linux_descriptor_close_on_exec(descriptor, close_on_exec);
    true
}
