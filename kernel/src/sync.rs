//! Lock ranks, the kernel-entry lock and the spin locks.
//!
//! The spin locks themselves (`SpinLock`, `IrqSpinLock` and their guards)
//! live in the trusted core (`trusted::lock`, which holds their `unsafe`)
//! and are re-exported here; this module keeps what needs no `unsafe`: the
//! per-CPU rank bookkeeping each lock acquire checks, and the kernel-entry
//! lock, which serializes kernel work across CPUs and hands out no data.
#![forbid(unsafe_code)]

use core::arch::x86_64::__cpuid;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use crate::trusted::interrupts::{self, InterruptState};
pub(crate) use crate::trusted::lock::{IrqSpinLock, IrqSpinLockGuard, SpinLock, SpinLockGuard};

const CPU_SLOT_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct LockRank(u16);

impl LockRank {
    pub(crate) const PRIMITIVE_TEST_LOW: Self = Self(1);
    pub(crate) const PRIMITIVE_TEST_HIGH: Self = Self(2);
    pub(crate) const ARCHITECTURE: Self = Self(100);
    /// Each IPC instance's System V and POSIX IPC objects: system calls
    /// copy to and from user memory while holding it, so it ranks just
    /// above system-call level, below anything a user copy may take.
    pub(crate) const SYSV_IPC: Self = Self(101);
    /// The image store (`image_store`): held while a pull stages layers
    /// and while a root filesystem is unpacked and published, at system
    /// call or boot level, so it ranks just above system-call level.
    pub(crate) const IMAGE_STORE: Self = Self(102);
    /// The control plane's IPC channel (`ipc`): taken by native service
    /// calls at system-call level, never under another lock; a send wakes
    /// the receiver through the scheduler while it is held, so it ranks
    /// below the scheduler's locks.
    pub(crate) const CONTROL_CHANNEL: Self = Self(103);
    /// The native packet mailboxes (`packet`): taken by native service
    /// calls at system-call level, never under another lock. A consume
    /// copies the packet to user memory while it is held, so it ranks
    /// just above system-call level, below anything a user copy may take.
    pub(crate) const PACKET_MAILBOXES: Self = Self(104);
    /// The mounts domains made; ranks below the heap so the table may grow
    /// while held, and above ARCHITECTURE, which system calls run under.
    pub(crate) const MOUNTS: Self = Self(105);
    /// The auxiliary (native service) domains' address spaces
    /// (`address_space`): taken by native service calls and the user-fault
    /// path at system-call level, never under another lock. Held while it
    /// binds and quiesces a domain's virtio device, so the domain manager,
    /// the frame allocator, the I/O MMU and the scheduler are taken under
    /// it and it ranks below them all; user copies are made before it is
    /// taken.
    pub(crate) const AUXILIARY_ADDRESS_SPACES: Self = Self(106);
    /// The UTS, IPC, PID and time namespaces domains made; ranks below the
    /// heap so the table may grow while held.
    pub(crate) const NAMESPACES: Self = Self(107);
    /// Processes' memory areas; ranks just below the heap so the sets may
    /// grow while held, and above the socket, inotify and futex locks, under
    /// which a copy to user memory may look up a lazily reserved page.
    pub(crate) const MEMORY_AREAS: Self = Self(185);
    /// The executables behind /proc/PID/exe; ranks below the heap so the
    /// list may grow while held.
    pub(crate) const EXECUTABLES: Self = Self(110);
    /// The mounts processes reached their open files through; ranks below
    /// the heap so the table may grow while held.
    pub(crate) const PATH_VIEWS: Self = Self(111);
    /// Each domain's keys; ranks below the heap so the keys may grow while
    /// held.
    pub(crate) const KEYRINGS: Self = Self(115);
    /// Each domain's AIO contexts and their queued events: a leaf, below
    /// the heap so the queues may grow while held.
    pub(crate) const AIO_CONTEXTS: Self = Self(116);
    /// Each domain's in-kernel file store (`linux_tmpfs`): a leaf, below
    /// the heap so files may grow while held.
    pub(crate) const TMPFS_FILES: Self = Self(117);
    /// Deadlines of timed waits set to restart; ranks below the heap so the
    /// list may grow while held.
    pub(crate) const RESTART_DEADLINES: Self = Self(120);
    /// The socket table with smoltcp and the network device under it; ranks
    /// below the heap so the table and socket buffers may grow while held.
    pub(crate) const SOCKETS: Self = Self(140);
    /// Open DRM render node files and dma-bufs; ranks below the heap so
    /// the tables may grow while held.
    pub(crate) const DRM: Self = Self(145);
    /// Each domain's loop devices and their opens; ranks below the heap so
    /// the tables may grow while held.
    pub(crate) const LOOP: Self = Self(150);
    /// Open /dev/kmsg readers; ranks below the heap so the table may grow
    /// while held.
    pub(crate) const KMSG: Self = Self(155);
    /// Pseudo-terminal pairs; ranks below the heap so their queues may grow
    /// while held, and below inotify, which removing a slave's node under it
    /// may reach.
    pub(crate) const PTYS: Self = Self(158);
    /// userfaultfd contexts; ranks below the heap so their tables may grow
    /// while held.
    pub(crate) const USERFAULTFD: Self = Self(159);
    /// The new mount API's filesystem contexts and detached mounts; ranks
    /// below the heap so the tables may grow while held.
    pub(crate) const FS_CONTEXTS: Self = Self(157);
    /// The record (fcntl) lock table; ranks below the heap so the table may
    /// grow while held.
    pub(crate) const RECORD_LOCKS: Self = Self(160);
    /// File leases (`linux_lease`): a leaf, taken from fcntl and open.
    pub(crate) const LEASES: Self = Self(161);
    /// The domains' core patterns (`linux_core`): a leaf.
    pub(crate) const CORE_PATTERNS: Self = Self(162);
    /// The descriptor tables' parts above the fixed table
    /// (`linux_fd_table`): a leaf.
    pub(crate) const DESCRIPTOR_TABLES: Self = Self(163);
    /// The large poll and select wait sets (`linux_wait_sets`): a leaf.
    pub(crate) const WAIT_SETS: Self = Self(164);
    /// inotify instances, watches and queues; ranks below the heap so the
    /// queues may grow while held.
    pub(crate) const INOTIFY: Self = Self(165);
    /// fanotify groups, marks, queues and permission requests; ranks below
    /// the heap so the queues may grow while held.
    pub(crate) const FANOTIFY: Self = Self(166);
    /// io_uring rings and their registered buffers; ranks below the heap
    /// so the tables may grow while held.
    pub(crate) const IO_URING: Self = Self(167);
    /// The pool of Linux activation stacks; ranks below the heap so the
    /// pool may grow while held.
    pub(crate) const KERNEL_STACKS: Self = Self(170);
    /// Frames taken out of service (`memory_failure`); ranks below the
    /// heap so the list may grow while held.
    pub(crate) const MEMORY_FAILURE: Self = Self(175);
    pub(crate) const FUTEX_COORDINATION: Self = Self(180);
    /// Each mount namespace's mount tree as path resolution walks it; every
    /// path a file call is given passes through it, so it ranks above the
    /// tables whose holders make and remove files, and the mount table
    /// publishes to it while held.
    pub(crate) const MOUNT_ROUTES: Self = Self(181);
    /// The overlay mounts (overlayfs) and the files they handed out; every
    /// path walk looks at them, so they rank above the tables whose holders
    /// make and remove files (loop devices, pseudo-terminals). Nothing else
    /// is taken while they are held.
    pub(crate) const OVERLAY_MOUNTS: Self = Self(182);
    /// The wait statuses of reaped processes that pidfds report; ranks
    /// below the heap so the list may grow while held.
    pub(crate) const PIDFS_EXITS: Self = Self(183);
    /// Landlock rulesets and domains; asked at system call level, under no
    /// file, volume or memory-area lock, and ranks below the heap so the
    /// tables may grow while held.
    pub(crate) const LANDLOCK: Self = Self(184);
    /// perf events (cpu/linux_perf.rs); held only to copy or update an
    /// event, never while counting, and below the heap so the table may
    /// grow while held.
    pub(crate) const PERF_EVENTS: Self = Self(178);
    /// The mounted volumes (filesystems on block devices): every path walk
    /// looks at them, so they rank above the device and file tables whose
    /// holders make and remove files (loop devices, pseudo-terminals), and
    /// below the RAM disks and the heap, which volume I/O uses.
    pub(crate) const VOLUMES: Self = Self(186);
    /// Each domain's RAM disks and their opens; ranks below the heap so the
    /// disks may grow while held.
    pub(crate) const RAM_DISKS: Self = Self(187);
    /// Overlay files that lost their last name, waiting for their last
    /// close; ranks above the tables under which files are unlinked.
    pub(crate) const UNLINKED_FILES: Self = Self(188);
    /// The limits of tmpfs mounts and their use, charged as overlay files
    /// grow, which they may under the volumes' lock (a loop device's
    /// backing file).
    pub(crate) const TMPFS_LIMITS: Self = Self(189);
    /// The swap areas swapon turned on: taken under the volumes and the
    /// unlinked files (whether a file is in use), never with the tmpfs
    /// limits; only the heap is taken while held.
    pub(crate) const SWAPS: Self = Self(189);
    /// The kernel heap refills from the frame allocator while holding its
    /// lock, so it ranks just below it.
    pub(crate) const KERNEL_HEAP: Self = Self(190);
    /// Each domain's overlay nodes (`linux_overlay`): a leaf held only to
    /// read and write node fields, its hint tables and file data through
    /// frame copies. It allocates, frees and calls nothing while held: the
    /// heap memory, frames and pages back from swap an operation needs are
    /// got with it released, and the tmpfs limits, the unlinked-file list,
    /// the swap areas and memory cgroup charges are called after. The
    /// overlay is called under the volumes, the overlay mounts, the
    /// pseudo-terminals, the loop devices, the swap areas and the
    /// unlinked-file list, so it ranks above them all and the heap, below
    /// the other leaves (none of which calls it).
    pub(crate) const OVERLAY_NODES: Self = Self(191);
    /// The mount namespace table (`linux_mount`): a leaf that copies its
    /// fixed records in and out and calls nothing while held. Path walks
    /// ask for the current namespace under the route, overlay and volume
    /// tables, so it ranks above every lock a system call may hold, below
    /// the frame allocator.
    pub(crate) const MOUNT_NAMESPACES: Self = Self(192);
    /// Each domain's user namespaces (`linux_user`): a leaf that copies its
    /// records in and out, calls nothing and allocates nothing while held
    /// (a table's room is reserved before it is taken). Credential and
    /// privilege checks ask it under whatever lock a system call holds, so
    /// it ranks above them all, below the frame allocator.
    pub(crate) const USER_NAMESPACES: Self = Self(194);
    /// Each domain's file cache index (`linux_file_cache`): a leaf held
    /// only to probe or fill a table that has room, never to allocate or
    /// free. Copy-on-write faults ask it during copies to user memory under
    /// whatever lock a system call holds, so it ranks above every such
    /// lock (all below the heap), below the frame allocator.
    pub(crate) const FILE_CACHE: Self = Self(196);
    /// Each domain slot's published root filesystem (`published_rootfs`):
    /// a leaf held only to clone, take or put a reference. Path walks ask
    /// it under the mount, overlay and volume tables, so it ranks above
    /// them, below the frame allocator.
    pub(crate) const PUBLISHED_ROOTFS: Self = Self(197);
    /// The unpacked root filesystem images and the slots that use them
    /// (`image_store`): a leaf, taken after the image store and the
    /// published root filesystems; images are freed after it is released.
    pub(crate) const ROOTFS_IMAGES: Self = Self(198);
    /// Each domain slot's suspended init frames (`address_space`): a leaf
    /// held only to copy the leases in or out.
    pub(crate) const SUSPENDED_INIT_FRAMES: Self = Self(193);
    /// The address-space clone and validation work lists
    /// (`address_space::take_scratch`): a leaf held only to take a list out
    /// or put it back; the lists are freed with it released.
    pub(crate) const ADDRESS_SPACE_SCRATCH: Self = Self(199);
    pub(crate) const PHYSICAL_MEMORY: Self = Self(200);
    pub(crate) const ADDRESS_SPACE: Self = Self(300);
    pub(crate) const SCHEDULER: Self = Self(400);
    /// The domain manager (`domain`): an interrupt-safe leaf that takes
    /// nothing while held (frame counts are read before it is taken).
    /// Capability and credential checks ask it under whatever lock a call
    /// holds, and the scheduler asks it for service classes and CPU limits
    /// while choosing what to run, so it ranks above the scheduler's locks.
    pub(crate) const DOMAINS: Self = Self(450);
    pub(crate) const DOMAIN_PROCESS: Self = Self(500);
    pub(crate) const FILESYSTEM: Self = Self(600);
    pub(crate) const IPC_SIGNAL: Self = Self(700);
    pub(crate) const DEVICE_NETWORK: Self = Self(800);
    /// The live (in-memory) volume (`volume::install_live`): a leaf that
    /// only scans and writes its slots, so it ranks above the locks its
    /// callers may hold.
    pub(crate) const LIVE_VOLUME: Self = Self(880);
    /// The wakeups subsystems queue for the scheduler
    /// (`linux_wait_queue::notify`): a leaf, taken under any subsystem's
    /// lock (the sockets', System V IPC's), with nothing taken while held.
    pub(crate) const WAKEUPS: Self = Self(885);
    pub(crate) const DIAGNOSTICS: Self = Self(900);
    /// The evdev input queues (`linux_input`): drivers queue events from
    /// interrupt handlers, over whatever lock the interrupted code holds,
    /// so it ranks above every other lock, is only ever tried, and nothing
    /// is taken while it is held.
    pub(crate) const INPUT_EVENTS: Self = Self(950);
}

static HELD_RANKS: [AtomicU16; CPU_SLOT_LIMIT] = [const { AtomicU16::new(0) }; CPU_SLOT_LIMIT];
static KERNEL_ENTRY_LOCK: KernelEntryLock = KernelEntryLock::new();

pub(crate) fn kernel_entry_lock() -> KernelEntryGuard {
    KERNEL_ENTRY_LOCK.lock()
}

/// The kernel-entry lock if no CPU holds or waits for it (`try_lock`).
pub(crate) fn kernel_entry_try_lock() -> Option<KernelEntryGuard> {
    KERNEL_ENTRY_LOCK.try_lock()
}

/// Called just before this CPU returns to a Linux process's user mode:
/// releases the kernel-entry lock, keeping its depth (the entries of the
/// calls this CPU is nested in) for `kernel_entry_return_from_user`. User
/// code never holds the lock, so other CPUs enter the kernel while it runs.
/// Interrupts must be off.
pub(crate) fn kernel_entry_leave_to_user() {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if lock.cpu_owner.load(Ordering::Acquire) != cpu as u16 + 1 {
        return;
    }
    let depth = lock.depths[cpu].swap(0, Ordering::AcqRel);
    lock.user_depths[cpu].store(depth, Ordering::Release);
    lock.release(cpu);
}

/// Called when this CPU enters the kernel from a Linux process's user mode
/// by a system call or fault, which may return to the kernel instead of the
/// process: takes the lock back with the depth `kernel_entry_leave_to_user`
/// kept. Interrupts must be off.
pub(crate) fn kernel_entry_return_from_user() {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if lock.cpu_owner.load(Ordering::Acquire) == cpu as u16 + 1 {
        return;
    }
    let depth = lock.user_depths[cpu].swap(0, Ordering::AcqRel);
    if depth != 0 {
        lock.acquire(cpu, depth);
    }
}

/// Lets the CPUs waiting for the kernel-entry lock have it before this one
/// goes on: a scheduling loop that holds it round after round (resuming
/// parked calls that only check their waits again) never reaches user mode
/// or a halt, where it would let go, and starved the other CPUs' system
/// calls.
pub(crate) fn kernel_entry_yield() {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if lock.cpu_owner.load(Ordering::Acquire) != cpu as u16 + 1
        || lock.next.load(Ordering::Acquire) == lock.owner.load(Ordering::Acquire).wrapping_add(1)
    {
        return;
    }
    kernel_entry_leave_to_user();
    spin_loop();
    kernel_entry_return_from_user();
}

/// This CPU's depth in the kernel-entry lock: 0 unless it holds it.
pub(crate) fn kernel_entry_depth() -> u32 {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if lock.cpu_owner.load(Ordering::Acquire) == cpu as u16 + 1 {
        lock.depths[cpu].load(Ordering::Acquire)
    } else {
        0
    }
}

/// Takes `count` entries off this CPU's depth: those of a system call that
/// parks (see `cpu::activation`), whose frames wait on its own stack while
/// this CPU goes on with others. The CPU keeps at least its own entry.
pub(crate) fn kernel_entry_detach(count: u32) {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if count == 0 {
        return;
    }
    if lock.cpu_owner.load(Ordering::Acquire) != cpu as u16 + 1
        || lock.depths[cpu].load(Ordering::Acquire) <= count
    {
        crate::serial_write("linox: kernel-entry detach cpu/owner/depth/count: ");
        for value in [
            cpu as u64,
            u64::from(lock.cpu_owner.load(Ordering::Acquire)),
            u64::from(lock.depths[cpu].load(Ordering::Acquire)),
            u64::from(count),
        ] {
            crate::serial_write_u64(value);
            crate::serial_write(" ");
        }
        crate::serial_write("\r\n");
        crate::kernel_fail("linox: invalid kernel-entry detach\r\n");
    }
    lock.depths[cpu].fetch_sub(count, Ordering::AcqRel);
}

/// Adds the `count` entries a parked system call took off its CPU's depth
/// (`kernel_entry_detach`) to this CPU's, which resumes the call, on
/// whichever CPU that is.
pub(crate) fn kernel_entry_attach(count: u32) {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if count == 0 {
        return;
    }
    if lock.cpu_owner.load(Ordering::Acquire) != cpu as u16 + 1 {
        crate::kernel_fail("linox: invalid kernel-entry attach\r\n");
    }
    lock.depths[cpu].fetch_add(count, Ordering::AcqRel);
}

/// The kernel-entry lock serializes kernel work across CPUs. It is
/// recursive per CPU: each entry on the owning CPU adds to its depth, and
/// the lock is released when the depth returns to zero, whichever entry
/// leaves last. Entries need not leave in the order they came: a system
/// call parked on its own stack (see `cpu::activation`) takes its entries
/// with it and gives them to the CPU that resumes it. A CPU running user
/// code holds no lock: it releases it on the way out to user mode and takes
/// it back, at the same depth, when a system call or fault comes in.
struct KernelEntryLock {
    next: AtomicU32,
    owner: AtomicU32,
    cpu_owner: AtomicU16,
    depths: [AtomicU32; CPU_SLOT_LIMIT],
    /// Each CPU's depth while it runs user code.
    user_depths: [AtomicU32; CPU_SLOT_LIMIT],
    /// The lock rank each CPU held before it took the lock, put back when
    /// it releases it.
    previous_ranks: [AtomicU16; CPU_SLOT_LIMIT],
}

impl KernelEntryLock {
    const fn new() -> Self {
        Self {
            next: AtomicU32::new(0),
            owner: AtomicU32::new(0),
            cpu_owner: AtomicU16::new(0),
            depths: [const { AtomicU32::new(0) }; CPU_SLOT_LIMIT],
            user_depths: [const { AtomicU32::new(0) }; CPU_SLOT_LIMIT],
            previous_ranks: [const { AtomicU16::new(0) }; CPU_SLOT_LIMIT],
        }
    }

    fn lock(&'static self) -> KernelEntryGuard {
        let interrupt_state = interrupts::save_and_disable();
        let cpu = cpu_slot();
        if self.cpu_owner.load(Ordering::Acquire) == cpu as u16 + 1 {
            let previous = self.depths[cpu].fetch_add(1, Ordering::AcqRel);
            if previous == 0 {
                crate::kernel_fail("linox: invalid recursive kernel-entry depth\r\n");
            }
            return KernelEntryGuard {
                lock: self,
                interrupt_state,
            };
        }
        self.acquire(cpu, 1);
        KernelEntryGuard {
            lock: self,
            interrupt_state,
        }
    }

    /// Takes the lock only when no CPU holds or waits for it, else None with
    /// this CPU's interrupts as they were. The ticket serves waiters in
    /// order, so an idle CPU that merely looks for work must not queue: three
    /// idle application processors re-queuing after every look would take
    /// three turns in four from the owner CPU's system calls.
    fn try_lock(&'static self) -> Option<KernelEntryGuard> {
        let interrupt_state = interrupts::save_and_disable();
        let cpu = cpu_slot();
        if self.cpu_owner.load(Ordering::Acquire) == cpu as u16 + 1 {
            let previous = self.depths[cpu].fetch_add(1, Ordering::AcqRel);
            if previous == 0 {
                crate::kernel_fail("linox: invalid recursive kernel-entry depth\r\n");
            }
            return Some(KernelEntryGuard {
                lock: self,
                interrupt_state,
            });
        }
        // Free when the next ticket to hand out is the owner's: take exactly
        // that ticket, or nothing.
        let ticket = self.owner.load(Ordering::Acquire);
        if self
            .next
            .compare_exchange(
                ticket,
                ticket.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            interrupts::restore(interrupt_state);
            return None;
        }
        let previous_rank = enter_rank(LockRank::ARCHITECTURE);
        self.previous_ranks[cpu].store(previous_rank, Ordering::Release);
        self.depths[cpu].store(1, Ordering::Release);
        self.cpu_owner.store(cpu as u16 + 1, Ordering::Release);
        Some(KernelEntryGuard {
            lock: self,
            interrupt_state,
        })
    }

    /// Takes the lock for `cpu` (this CPU) at `depth`.
    fn acquire(&'static self, cpu: usize, depth: u32) {
        let previous_rank = enter_rank(LockRank::ARCHITECTURE);
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        if self.owner.load(Ordering::Acquire) != ticket {
            let started = crate::arch::x86_64::timer::timestamp_counter();
            while self.owner.load(Ordering::Acquire) != ticket {
                spin_loop();
            }
            crate::cpu_time::add_lock_wait(
                crate::arch::x86_64::timer::timestamp_counter().saturating_sub(started),
            );
        }
        self.previous_ranks[cpu].store(previous_rank, Ordering::Release);
        self.depths[cpu].store(depth, Ordering::Release);
        self.cpu_owner.store(cpu as u16 + 1, Ordering::Release);
    }

    /// Lets the next CPU in; `cpu` (this CPU) held the lock.
    fn release(&'static self, cpu: usize) {
        self.cpu_owner.store(0, Ordering::Release);
        leave_rank(
            LockRank::ARCHITECTURE,
            self.previous_ranks[cpu].load(Ordering::Acquire),
        );
        self.owner.fetch_add(1, Ordering::Release);
    }
}

/// An entry into the kernel-entry lock. It counts against the CPU that drops
/// it, which for a parked system call resumed elsewhere is not the one that
/// took it.
pub(crate) struct KernelEntryGuard {
    lock: &'static KernelEntryLock,
    interrupt_state: InterruptState,
}

impl Drop for KernelEntryGuard {
    fn drop(&mut self) {
        let cpu = cpu_slot();
        let previous = self.lock.depths[cpu].fetch_sub(1, Ordering::AcqRel);
        if previous == 0 {
            crate::kernel_fail("linox: invalid kernel-entry release depth\r\n");
        }
        // The last entry on this CPU to leave releases the lock.
        if previous == 1 {
            self.lock.release(cpu);
        }
        interrupts::restore(self.interrupt_state);
    }
}

/// The slot of the executing CPU in the per-CPU lock tables: its index from
/// the per-CPU entry state once that is installed, and its initial APIC ID
/// before. The entry state is found through the GS base, which hypervisors
/// let the guest read directly, whereas CPUID always exits to the hypervisor;
/// every lock acquisition and release asks for the slot, so CPUID here made
/// allocator-heavy system calls tens of times slower under KVM.
fn cpu_slot() -> usize {
    crate::arch::x86_64::cpu::current_cpu_index_checked()
        .unwrap_or_else(|| usize::from((__cpuid(1).ebx >> 24) as u8))
}

/// Whether this CPU may take a lock of `rank` now: it holds none ranked
/// at or above it.
pub(crate) fn rank_available(rank: LockRank) -> bool {
    HELD_RANKS[cpu_slot()].load(Ordering::Acquire) < rank.0
}

/// Whether this CPU holds a spin lock other than the kernel-entry lock
/// (which ranks as `ARCHITECTURE`): a system call must not park (and maybe
/// continue on another CPU) while it does.
pub(crate) fn spin_lock_held() -> bool {
    held_rank() > LockRank::ARCHITECTURE.0
}

/// The rank of the highest lock this CPU holds (0: none).
pub(crate) fn held_rank() -> u16 {
    HELD_RANKS[cpu_slot()].load(Ordering::Acquire)
}

/// Records that this CPU takes a lock of `rank`, failing closed if it
/// holds one ranked at or above it; returns the rank it held before. Only
/// the spin locks (`trusted::lock`) and the kernel-entry lock call this.
pub(crate) fn enter_rank(rank: LockRank) -> u16 {
    crate::linux_profile::count_lock(rank.0);
    let held = &HELD_RANKS[cpu_slot()];
    let previous = held.load(Ordering::Acquire);
    if previous >= rank.0 {
        crate::kernel_fail("linox: synchronization lock-order violation\r\n");
    }
    held.store(rank.0, Ordering::Release);
    previous
}

/// Records that this CPU released its lock of `rank`, back to `previous`
/// (what `enter_rank` returned), failing closed on an out-of-order release.
pub(crate) fn leave_rank(rank: LockRank, previous: u16) {
    let held = &HELD_RANKS[cpu_slot()];
    if held.load(Ordering::Acquire) != rank.0 {
        crate::kernel_fail("linox: synchronization unlock-order violation\r\n");
    }
    held.store(previous, Ordering::Release);
}

pub(crate) fn verify_primitives() -> bool {
    static LOW: IrqSpinLock<u64> = IrqSpinLock::new(LockRank::PRIMITIVE_TEST_LOW, 0);
    static HIGH: IrqSpinLock<u64> = IrqSpinLock::new(LockRank::PRIMITIVE_TEST_HIGH, 0);
    static PLAIN: SpinLock<u64> = SpinLock::new(LockRank::ARCHITECTURE, 0);

    let ranks = [
        LockRank::ARCHITECTURE,
        LockRank::PHYSICAL_MEMORY,
        LockRank::ADDRESS_SPACE,
        LockRank::SCHEDULER,
        LockRank::DOMAIN_PROCESS,
        LockRank::FILESYSTEM,
        LockRank::IPC_SIGNAL,
        LockRank::DEVICE_NETWORK,
        LockRank::DIAGNOSTICS,
    ];
    if !ranks.windows(2).all(|pair| pair[0] < pair[1]) {
        return false;
    }

    {
        let mut low = LOW.lock();
        *low = 1;
        let mut high = HIGH.lock();
        *high = *low + 1;
    }
    {
        let Some(mut plain) = PLAIN.try_lock() else {
            return false;
        };
        *plain = 3;
    }
    let Some(low) = LOW.try_lock() else {
        return false;
    };
    *low == 1 && *HIGH.lock() == 2 && *PLAIN.lock() == 3
}
