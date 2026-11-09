//! The Linux process table: each domain instance's processes, their
//! address-space lists and their scheduling and wait state.
//!
//! Each instance's table sits behind its own lock (`PROCESS_TABLES`,
//! `LockRank::PROCESS_TABLE`), held only for short table updates: never
//! across a park, a copy to or from user memory, or a call into an owner
//! ranked at or below the table (the namespaces, System V IPC, the memory
//! areas, the swap areas through page-table teardown). Work like that runs
//! between two holds, which look the process up again by its handle.
#![forbid(unsafe_code)]

use alloc::vec::Vec;
use core::{
    mem::size_of,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering},
};

use crate::linux_debug_registers::{DebugRegisters, Error as DebugRegisterError};
use crate::sync::{IrqSpinLock, LockRank};
use crate::trusted::frame::Frame;
use crate::{
    address_space, arch::x86_64::cpu, control_abi, linux_namespace, linux_user, memory, scheduler,
};

/// Processes a domain's table holds, zombies included. The table, and every
/// table kept per process slot, grows on demand up to this (slots are u16):
/// the bound is what a domain's memory allows, not what was reserved.
pub(crate) const PROCESS_LIMIT: usize = 4096;
/// Processes with an address space at once: a zombie releases its runtime
/// slot when it exits, so many unreaped zombies need table slots only.
/// Processes of one domain that can exist at once (as many as its process
/// table holds): each takes a runtime slot, whose saved state and address-
/// space lists are allocated when the slot is first used.
pub(crate) const PROCESS_RUNTIME_LIMIT: usize = PROCESS_LIMIT;
const PAGE_SIZE: usize = 4096;
const FORK_PRIVATE_PAGE_LIMIT: usize = 2;
/// Process slots up to which a fork checks its new frames against every
/// process's lists (`ProcessTable::resources_available`).
const FORK_CHECK_ALL_LIMIT: usize = 256;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const NO_EXECUTE: u64 = 1 << 63;
const TEST_USER_ADDRESS: usize = 1usize << 39;
const PROCESS_RAX_INDEX: usize = 0;
const HOST_PROCESS_INSTANCE: usize = control_abi::DOMAIN_LIMIT;
const PROCESS_INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;
const PROCESS_INSTANCE_NONE: u8 = u8::MAX;

/// The work areas of a fork (`commit_cloned_fork`), each as long as the
/// largest address space forked lately: they grow with the process instead
/// of bounding it. A fork takes them out of `FORK_SCRATCH` and puts them back
/// when it is done, so no lock is held across the fork's work; a fork that
/// finds them taken works with empty ones.
struct LiveForkScratch {
    lists: ForkLists,
    /// The frames allocated for the child's page tables and private pages.
    hierarchy_allocation: Vec<memory::FrameLease>,
    page_allocation: Vec<memory::FrameLease>,
}

impl LiveForkScratch {
    const EMPTY: Self = Self {
        lists: ForkLists {
            child_mappings: Vec::new(),
            parent_pages: Vec::new(),
            parent_mappings: Vec::new(),
            parent_hierarchy: Vec::new(),
        },
        hierarchy_allocation: Vec::new(),
        page_allocation: Vec::new(),
    };

    /// Takes the work areas, leaving empty ones (which allocate nothing).
    fn take() -> Self {
        core::mem::replace(&mut *FORK_SCRATCH.lock(), Self::EMPTY)
    }

    /// Puts the work areas back for the next fork. Areas another fork put
    /// back meanwhile are freed after the lock is released.
    fn put_back(self) {
        let previous = core::mem::replace(&mut *FORK_SCRATCH.lock(), self);
        drop(previous);
    }
}

/// A leaf held only to swap the work areas in or out (`LockRank::PROCESS_SCRATCH`).
static FORK_SCRATCH: IrqSpinLock<LiveForkScratch> =
    IrqSpinLock::new(LockRank::PROCESS_SCRATCH, LiveForkScratch::EMPTY);

/// `list` resized to `count` empty leases for a fork to allocate into; false
/// (so the allocation is not tried and the fork backs out) without the memory.
fn fork_frame_scratch(list: &mut Vec<memory::FrameLease>, count: usize) -> bool {
    address_space::fill_list(list, count, memory::FrameLease::EMPTY).is_some()
}

/// The fork's progress markers and the per-instance flags, all atomics.
struct ProcessRuntimeState {
    table_initialized: [AtomicBool; PROCESS_INSTANCE_LIMIT],
    refresh_count: [AtomicU32; PROCESS_INSTANCE_LIMIT],
    active_instance: AtomicU8,
    fork_execution_stage: AtomicU32,
    fork_child_diagnostic: AtomicU32,
}

static PROCESS_RUNTIME: ProcessRuntimeState = ProcessRuntimeState {
    table_initialized: [const { AtomicBool::new(false) }; PROCESS_INSTANCE_LIMIT],
    refresh_count: [const { AtomicU32::new(0) }; PROCESS_INSTANCE_LIMIT],
    active_instance: AtomicU8::new(PROCESS_INSTANCE_NONE),
    fork_execution_stage: AtomicU32::new(0),
    fork_child_diagnostic: AtomicU32::new(0),
};

/// Each instance's process table, behind a lock of its own. The tables are
/// const-initialized and their vectors keep their memory across domains.
static PROCESS_TABLES: [IrqSpinLock<ProcessTable>; PROCESS_INSTANCE_LIMIT] =
    [const { IrqSpinLock::new(LockRank::PROCESS_TABLE, ProcessTable::new()) };
        PROCESS_INSTANCE_LIMIT];

fn process_runtime() -> &'static ProcessRuntimeState {
    &PROCESS_RUNTIME
}

fn mapping_requires_fork_copy(mapping: &cpu::LinuxActiveImageMapping) -> bool {
    !mapping.dontfork
        && !mapping.shared
        && (mapping.writable || !memory::frame_lease_is_runtime(mapping.frame))
}

const PROCESS_CHILD_PROGRAM: [u8; 42] = [
    0x48, 0x85, 0xc0, // test rax, rax
    0x75, 0x23, // jne failure
    0x48, 0x83, 0xfb, 0x55, // cmp rbx, 0x55
    0x75, 0x1d, // jne failure
    0x49, 0x83, 0xff, 0x55, // cmp r15, 0x55
    0x75, 0x17, // jne failure
    0x64, 0xc6, 0x04, 0x25, 0, 0, 0, 0, 0x5a, // mov byte ptr fs:[0], 0x5a
    0xcd, 0x80, // context-check trap
    0xb8, 0x3c, 0, 0, 0, // mov eax, 60 (__NR_exit)
    0xbf, 0x2a, 0, 0, 0, // mov edi, 42
    0xcd, 0x80, // exit(42)
    0x0f, 0x0b, // failure: ud2
];
const CONCURRENT_PROCESS_PROGRAM: [u8; 36] = [
    0x48, 0xb8, 0x00, 0x10, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // mov rax, 0x8000001000
    0xf0, 0xff, 0x00, // lock inc dword ptr [rax]
    0x83, 0x38, 0x02, // wait: cmp dword ptr [rax], 2
    0x75, 0xfb, // jne wait
    0x31, 0xc0, // xor eax, eax
    0xcd, 0x80, // context-check trap
    0xb8, 0x3c, 0, 0, 0, // mov eax, 60 (__NR_exit)
    0xbf, 0x2a, 0, 0, 0, // mov edi, 42
    0xcd, 0x80, // exit(42)
    0x0f, 0x0b, // failure: ud2
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessHandle {
    slot: u16,
    generation: u32,
    pid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessState {
    Preparing,
    Running,
    Stopped { signal: u8 },
    Exiting,
    Zombie { status: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessExecutionContext {
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
}

impl ProcessExecutionContext {
    fn is_valid(self, address_space: &ProcessAddressSpace, lists: &SpaceLists) -> bool {
        self.validation_error(address_space, lists).is_none()
    }

    /// Whether the registers alone are a context a process may resume in:
    /// canonical user addresses and no privileged flags.
    fn registers_valid(self) -> bool {
        const REQUIRED_RFLAGS: u64 = (1 << 1) | (1 << 9);
        const FORBIDDEN_RFLAGS: u64 = (3 << 12) | (1 << 14) | (1 << 17);
        !(self.rip == 0
            || self.rip >= 1 << 47
            || self.rsp == 0
            || self.rsp >= 1 << 47
            || self.fs_base >= 1 << 47
            || self.rflags & REQUIRED_RFLAGS != REQUIRED_RFLAGS
            || self.rflags & FORBIDDEN_RFLAGS != 0)
    }

    fn validation_error(
        self,
        address_space: &ProcessAddressSpace,
        lists: &SpaceLists,
    ) -> Option<u8> {
        if !self.registers_valid() {
            return Some(1);
        }
        // A stale list may lack the pages the context runs on; the context
        // was checked against the live page tables when it was recorded
        // (`refresh_live_process_context_for_wait`).
        if address_space.stale {
            return None;
        }
        let contains = |mapping: &cpu::LinuxActiveImageMapping, address: u64| {
            u64::try_from(mapping.address).ok().is_some_and(|start| {
                start
                    .checked_add(PAGE_SIZE as u64)
                    .is_some_and(|end| address >= start && address < end)
            })
        };
        let mappings = address_space.mappings(lists);
        let executable = mappings
            .iter()
            .any(|mapping| mapping.executable && contains(mapping, self.rip));
        let writable_stack = mappings.iter().any(|mapping| {
            u64::try_from(mapping.address).ok().is_some_and(|start| {
                mapping.writable
                    && start
                        .checked_add(PAGE_SIZE as u64)
                        .is_some_and(|end| self.rsp >= start && self.rsp <= end)
            })
        });
        if !executable {
            Some(2)
        } else if !writable_stack {
            Some(3)
        } else {
            None
        }
    }

    fn fork_child(self) -> Self {
        let mut child = self;
        child.general[PROCESS_RAX_INDEX] = 0;
        child
    }

    fn scheduler_context(
        self,
        address_space: &ProcessAddressSpace,
        lists: &SpaceLists,
    ) -> Option<scheduler::ProcessSchedulerContext> {
        self.is_valid(address_space, lists).then_some(())?;
        scheduler::process_user_context(
            self.general,
            self.rip,
            self.rsp,
            self.rflags,
            address_space.root(lists).address(),
            self.fs_base,
        )
    }
}

/// A process's address space as the table records it: the slot of the
/// table's `SpaceLists` that holds its lists, and how much of them is its.
#[derive(Clone, Copy, Eq, PartialEq)]
struct ProcessAddressSpace {
    storage_slot: u16,
    hierarchy_count: u32,
    mapping_count: u32,
    /// The process changed its mappings after this snapshot, so its lists
    /// may name frames it already freed and that now belong to others.
    stale: bool,
}

/// A process's page-table frames and mapped pages as its last snapshot found
/// them, each list as long as the process needs.
#[derive(Default)]
struct ProcessAddressSpaceStorage {
    hierarchy: Vec<memory::FrameLease>,
    mappings: Vec<cpu::LinuxActiveImageMapping>,
}

impl ProcessAddressSpaceStorage {
    fn store(
        &mut self,
        hierarchy: &[memory::FrameLease],
        mappings: &[cpu::LinuxActiveImageMapping],
    ) -> Option<()> {
        replace_list(&mut self.hierarchy, hierarchy)?;
        replace_list(&mut self.mappings, mappings)
    }
}

/// A table's address-space lists by runtime slot, as long as the highest
/// slot used so far. They live in the table, under its lock; a slot's lists
/// are kept, and reused, until its process gives back its runtime slot.
struct SpaceLists(Vec<ProcessAddressSpaceStorage>);

impl SpaceLists {
    const fn new() -> Self {
        Self(Vec::new())
    }

    /// The lists of `slot`, made on first use.
    fn slot_mut(&mut self, slot: usize) -> Option<&mut ProcessAddressSpaceStorage> {
        if slot >= PROCESS_RUNTIME_LIMIT {
            return None;
        }
        if self.0.len() <= slot {
            self.0.try_reserve(slot + 1 - self.0.len()).ok()?;
            self.0
                .resize_with(slot + 1, ProcessAddressSpaceStorage::default);
        }
        self.0.get_mut(slot)
    }

    fn slot(&self, slot: u16) -> Option<&ProcessAddressSpaceStorage> {
        self.0.get(usize::from(slot))
    }
}

/// Makes `list` a copy of `items`, reusing its buffer, and gives back memory
/// when the list has shrunk to a fraction of it.
fn replace_list<T: Copy>(list: &mut Vec<T>, items: &[T]) -> Option<()> {
    list.clear();
    list.try_reserve_exact(items.len()).ok()?;
    list.extend_from_slice(items);
    if list.capacity() > items.len().saturating_mul(4).max(64) {
        list.shrink_to(items.len());
    }
    Some(())
}

/// Whether `hierarchy` and `mappings` are lists a process may hold: owned
/// and distinct frames, page-aligned user pages never writable and
/// executable at once, and page tables that map exactly those pages. Asked
/// before the table's lock is taken: it walks the page tables.
fn address_space_lists_valid(
    hierarchy: &[memory::FrameLease],
    mappings: &[cpu::LinuxActiveImageMapping],
) -> bool {
    !(hierarchy.len() < 4
        || mappings.is_empty()
        || !memory::frames_owned_by(memory::FrameOwner::KERNEL, hierarchy)
        || hierarchy
            .iter()
            .enumerate()
            .any(|(index, frame)| hierarchy[..index].contains(frame))
        || mappings.iter().enumerate().any(|(index, mapping)| {
            mapping.address == 0
                || !mapping.address.is_multiple_of(PAGE_SIZE)
                || mapping.writable && mapping.executable
                || !(memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
                    || memory::frame_lease_is_runtime(mapping.frame))
                || hierarchy.contains(&mapping.frame)
                || mappings[..index].iter().any(|prior| {
                    prior.address == mapping.address
                        || prior.frame == mapping.frame && !(mapping.shared && prior.shared)
                })
        })
        || !address_space::validate_linux_process_address_space(hierarchy, mappings))
}

impl ProcessAddressSpace {
    /// Checks `hierarchy` and `mappings` (`address_space_lists_valid`) and
    /// stores them in `storage_slot` of `lists`.
    fn new(
        lists: &mut SpaceLists,
        storage_slot: usize,
        hierarchy: &[memory::FrameLease],
        mappings: &[cpu::LinuxActiveImageMapping],
    ) -> Option<Self> {
        if storage_slot >= PROCESS_RUNTIME_LIMIT || !address_space_lists_valid(hierarchy, mappings)
        {
            return None;
        }
        Self::from_validated_snapshot(lists, storage_slot, hierarchy, mappings)
    }

    fn from_validated_snapshot(
        lists: &mut SpaceLists,
        storage_slot: usize,
        hierarchy: &[memory::FrameLease],
        mappings: &[cpu::LinuxActiveImageMapping],
    ) -> Option<Self> {
        if storage_slot >= PROCESS_RUNTIME_LIMIT || hierarchy.len() < 4 || mappings.is_empty() {
            return None;
        }
        lists.slot_mut(storage_slot)?.store(hierarchy, mappings)?;
        Some(Self {
            storage_slot: u16::try_from(storage_slot).ok()?,
            hierarchy_count: u32::try_from(hierarchy.len()).ok()?,
            mapping_count: u32::try_from(mappings.len()).ok()?,
            stale: false,
        })
    }

    // A copy of the address space made before its lists were last stored
    // can count more entries than they hold; it then sees none (and fails
    // validation) instead of reading past them.
    fn hierarchy<'a>(&self, lists: &'a SpaceLists) -> &'a [memory::FrameLease] {
        lists
            .slot(self.storage_slot)
            .and_then(|storage| storage.hierarchy.get(..self.hierarchy_count as usize))
            .unwrap_or(&[])
    }

    fn root(&self, lists: &SpaceLists) -> memory::FrameLease {
        self.hierarchy(lists)
            .first()
            .copied()
            .unwrap_or(memory::FrameLease::EMPTY)
    }

    fn mappings<'a>(&self, lists: &'a SpaceLists) -> &'a [cpu::LinuxActiveImageMapping] {
        lists
            .slot(self.storage_slot)
            .and_then(|storage| storage.mappings.get(..self.mapping_count as usize))
            .unwrap_or(&[])
    }

    fn is_valid(&self, lists: &SpaceLists) -> bool {
        self.is_owned(lists)
            && address_space::validate_linux_process_address_space(
                self.hierarchy(lists),
                self.mappings(lists),
            )
    }

    fn is_owned(&self, lists: &SpaceLists) -> bool {
        memory::frames_owned_by(memory::FrameOwner::KERNEL, self.hierarchy(lists))
            && self.mappings(lists).iter().all(|mapping| {
                memory::frame_lease_is_runtime(mapping.frame)
                    || memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
            })
    }

    fn hierarchy_is_owned(&self, lists: &SpaceLists) -> bool {
        memory::frames_owned_by(memory::FrameOwner::KERNEL, self.hierarchy(lists))
    }

    fn is_live(&self, lists: &SpaceLists) -> bool {
        memory::any_frame_lease_live(self.hierarchy(lists))
            || self.mappings(lists).iter().any(|mapping| {
                !mapping.shared
                    && !memory::frame_lease_is_runtime(mapping.frame)
                    && memory::any_frame_lease_live(&[mapping.frame])
            })
    }

    /// The page-table frames and private pages of the space.
    fn private_frames<'a>(
        &self,
        lists: &'a SpaceLists,
    ) -> impl Iterator<Item = &'a memory::FrameLease> + 'a {
        self.hierarchy(lists).iter().chain(
            self.mappings(lists)
                .iter()
                .filter(|mapping| !mapping.shared && !memory::frame_lease_is_runtime(mapping.frame))
                .map(|mapping| &mapping.frame),
        )
    }

    fn overlaps(&self, other: &Self, lists: &SpaceLists) -> bool {
        self.private_frames(lists).any(|left| {
            other
                .private_frames(lists)
                .any(|right| left.address() == right.address())
        })
    }

    fn scrub_and_release(&self, lists: &SpaceLists) -> bool {
        let (hierarchy, mappings) = (self.hierarchy(lists), self.mappings(lists));
        if !memory::frame_leases_releasable(memory::FrameOwner::KERNEL, hierarchy)
            || mappings.iter().any(|mapping| {
                !mapping.shared
                    && !memory::frame_lease_is_runtime(mapping.frame)
                    && !memory::frame_leases_releasable(
                        memory::FrameOwner::KERNEL,
                        &[mapping.frame],
                    )
            })
        {
            return false;
        }
        let mut released = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, hierarchy);
        for mapping in mappings {
            if !mapping.shared && !memory::frame_lease_is_runtime(mapping.frame) {
                released &=
                    memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[mapping.frame]);
            }
        }
        released
    }
}
#[derive(Clone, Copy)]
struct Process {
    handle: ProcessHandle,
    parent: Option<ProcessHandle>,
    process_group: u32,
    session: u32,
    executed: bool,
    user_namespace: linux_user::UserNamespaceHandle,
    /// Its UTS, IPC, PID and time namespaces: a child starts in its
    /// parent's (those for children, of PID and time).
    namespaces: linux_namespace::Set,
    /// The namespaces a clone it asked for made for its next child (clone
    /// with CLONE_NEWPID and the like), taken when that child is made.
    child_namespaces: Option<linux_namespace::Set>,
    /// Its user and group ids: inherited across fork, kept across exec.
    credentials: linux_user::Credentials,
    runtime_slot: Option<u16>,
    address_space: Option<ProcessAddressSpace>,
    retiring_address_space: Option<ProcessAddressSpace>,
    context: Option<ProcessExecutionContext>,
    scheduler_thread: Option<scheduler::ProcessThreadHandle>,
    cpu_affinity: u64,
    /// sched_setscheduler's policy and static priority, inherited across
    /// fork and kept across exec (what sched_getscheduler and
    /// sched_getparam report; the scheduler itself does not consult them).
    scheduling: (u8, u8),
    /// prctl's timer slack (current, default), in nanoseconds: a child's
    /// both start as the parent's current one, and setting 0 restores the
    /// default.
    timer_slack: (u64, u64),
    /// Stopped by a stop signal while waiting in its kill call: the call
    /// parks until SIGCONT, so the state stays Running for the wait engine
    /// and this marks the stop (what /proc and the parent's wait see).
    stopped_in_call: bool,
    /// POSIX timers (timer_create) by id - 1: none across fork and exec.
    posix_timers: [Option<PosixTimer>; POSIX_TIMER_LIMIT],
    /// setitimer's ITIMER_VIRTUAL and ITIMER_PROF, as timers on the
    /// process's CPU clock (SIGVTALRM, SIGPROF): none in a new child, kept
    /// across exec.
    /// and RLIMIT_CPU's soft (SIGXCPU, then every second) and hard
    /// (SIGKILL) limits as two more.
    itimers: [Option<PosixTimer>; 4],
    /// getrusage's ru_maxrss in KiB: the most the process was seen to hold
    /// resident (at getrusage and as it exits), and the most any child it
    /// waited for (or that child's own waited children) held. A new child
    /// starts with neither.
    maxrss_kib: u64,
    children_maxrss_kib: u64,
    /// SCHED_DEADLINE's runtime, deadline and period in nanoseconds, as
    /// sched_setattr set them (zero for other policies).
    deadline_parameters: [u64; 3],
    /// `/proc/PID/oom_score_adj`: inherited across fork, kept across exec.
    oom_score_adj: i16,
    /// `/proc/PID/io`'s counts: none in a new child, kept across exec.
    io: IoAccounting,
    /// Marked a child subreaper (PR_SET_CHILD_SUBREAPER): its
    /// descendants' orphans are reparented to it rather than to init. Not
    /// inherited across fork, kept across exec.
    child_subreaper: bool,
    /// Its memory policy (set_mempolicy): inherited across fork, kept
    /// across exec, as Linux's task policy is. Linux keeps one per thread;
    /// here the process's threads share it.
    memory_policy: crate::linux_areas::Policy,
    /// The signal whose default action terminated the process, or 0.
    killed_by_signal: u8,
    /// Chosen by a memory cgroup's OOM killer: dying for its memory, so no
    /// other process is killed for the same shortage meanwhile.
    oom_victim: bool,
    /// Its newest seccomp filter (index + 1 in the table's filters), or 0:
    /// inherited across fork, kept across exec.
    seccomp_filter: u32,
    /// The pid of the process tracing this one (ptrace), or 0: not
    /// inherited across fork, kept across exec.
    tracer: u32,
    /// The signal PTRACE_CONT asked to deliver as the tracee resumes from
    /// its trace stop (0: none), and whether that delivery is past the stop.
    ptrace_resume_signal: u8,
    ptrace_bypass: bool,
    /// The debug registers its tracer set (PTRACE_POKEUSER): none in a new
    /// child or after exec.
    debug_registers: DebugRegisters,
    state: ProcessState,
    wait_event: Option<ProcessWaitEvent>,
    /// A child forked onto its parent's pages (CLONE_VM, or a vfork child
    /// with its own stack) that has not executed yet: every page it maps is
    /// its parent's.
    shares_parent_vm: bool,
    /// The objects clone can share between processes, by id: processes
    /// holding the same id share that object (see `SharedResource`).
    shared: [u32; SHARED_RESOURCE_COUNT],
    /// The signal its parent gets when it ends (clone's exit signal): 0 for
    /// none. A child whose signal is not SIGCHLD is a "clone" child, which
    /// only a wait with __WCLONE or __WALL reports.
    exit_signal: u8,
    /// It ended while its parent ignored SIGCHLD (or set SA_NOCLDWAIT): its
    /// parent reaps it at once, leaving no zombie to wait for. A child that
    /// ended before its parent did so stays a zombie, as in Linux.
    reaped_by_parent: bool,
    /// Its cgroup, by the cgroup directory's generation, or 0 for the
    /// domain's root: its parent's, unless it was cloned into another
    /// (CLONE_INTO_CGROUP) or moved (a write to `cgroup.procs`).
    cgroup_generation: u32,
    /// The memory cgroup its user pages are charged to (`linux_cgroup`),
    /// that cgroup's; 0 until it is known (the domain's root then).
    memcg: u16,
    /// The process that cloned this one when that is not its parent
    /// (CLONE_PARENT): the fork transaction that runs it first resumes that
    /// one, not the parent.
    cloned_by: Option<ProcessHandle>,
    /// The child of a vfork (CLONE_VFORK) this process is suspended for
    /// until that child executes or exits, or 0.
    vfork_child: u32,
    /// Gave up the CPU in a blocking system call and has not been dispatched
    /// since: Linux's interruptible sleep ('S'). A wake clears it.
    waiting: bool,
    /// Blocked in that call (docs/SCHEDULER.md, step 5): what it waits for
    /// and until when. While `waiting` holds and the deadline has not
    /// passed, the scheduler passes over it (`Process::is_asleep`); a
    /// waker for one of its events, a signal or a child's change of state
    /// clears `waiting`. Every dispatch clears both.
    block: Option<crate::linux_wait_queue::WaitOn>,
    /// CPU time used, in timestamp-counter cycles, and the part of it in
    /// user mode (the rest is system time).
    cpu_cycles: u64,
    user_cycles: u64,
    /// The user and system time of the children it waited for, theirs
    /// included (times' tms_cutime and tms_cstime). A new child starts
    /// with none.
    children_cycles: (u64, u64),
    /// Its task events (`cpu_time::TaskEvent`), and those of the children
    /// it waited for (theirs included), which perf's software counters
    /// count.
    task_events: [u64; crate::cpu_time::TASK_EVENTS],
    children_task_events: [u64; crate::cpu_time::TASK_EVENTS],
    /// When the process was created, in nanoseconds since boot (process
    /// accounting's start time and elapsed time).
    started_nanoseconds: u64,
}

/// What clone can share between processes rather than copy (CLONE_VM,
/// CLONE_FILES, CLONE_FS, CLONE_SIGHAND, CLONE_IO, CLONE_SYSVSEM). Each
/// process names each of these by an id; processes that share one hold the
/// same id, and an id is never handed out twice in a domain, so kcmp(2)
/// compares them and the runtime keeps the shared state of processes with
/// the same id in step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SharedResource {
    Memory,
    Descriptors,
    Filesystem,
    SignalHandlers,
    Io,
    SemaphoreUndo,
}

const SHARED_RESOURCE_COUNT: usize = 6;

/// The signal a child's end sends its parent unless clone named another.
const DEFAULT_EXIT_SIGNAL: u8 = 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessWaitEvent {
    Stopped { signal: u8 },
    Continued,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaitResult {
    pid: u32,
    status: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildWaitState {
    Running,
    Stopped {
        pid: u32,
        signal: u8,
    },
    Continued {
        pid: u32,
    },
    /// `signal` is the signal that killed the process, or 0 if it exited
    /// with `status`.
    Exited {
        pid: u32,
        status: u8,
        signal: u8,
    },
}

#[derive(Clone, Copy)]
pub(crate) struct LiveProcessDispatch {
    pub(crate) pid: u32,
    pub(crate) root: memory::FrameLease,
    pub(crate) general: [u64; 15],
    pub(crate) rip: u64,
    pub(crate) rsp: u64,
    pub(crate) rflags: u64,
    pub(crate) fs_base: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveProcessState {
    Running,
    /// Waiting in a blocking system call.
    Sleeping,
    Stopped,
    Zombie,
}

impl LiveProcessState {
    /// Running or waiting in a system call: neither stopped nor exited.
    pub(crate) const fn is_running(self) -> bool {
        matches!(self, Self::Running | Self::Sleeping)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LiveProcessStatus {
    pub(crate) pid: u32,
    pub(crate) parent_pid: u32,
    pub(crate) state: LiveProcessState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessGroupError {
    Access,
    NoSuchProcess,
    Permission,
}

struct ProcessTable {
    owner_domain: u64,
    /// Indexed by a handle's slot; grows on demand up to PROCESS_LIMIT and
    /// never shrinks, so slots stay valid.
    processes: Vec<Option<Process>>,
    /// The slot of every process by pid, sorted by pid: a lookup by pid
    /// would otherwise walk thousands of slots.
    pid_slots: Vec<(u32, u16)>,
    /// The generation each slot last handed out, parallel to `processes`.
    generations: Vec<u32>,
    /// Each slot's supplementary groups, sorted, parallel to `processes`:
    /// inherited across fork, emptied when the slot is freed.
    groups: Vec<Vec<u32>>,
    /// Each slot's root directory (chroot) as a canonical path without a
    /// leading slash, parallel to `processes`; empty for the domain's root.
    /// Inherited across fork, kept across exec, emptied when the slot is
    /// freed.
    roots: Vec<Vec<u8>>,
    /// seccomp filters, each with the one installed before it; a process
    /// names its newest. One no process reaches is reused (`install`).
    seccomp_filters: Vec<Option<SeccompFilter>>,
    next_pid: u32,
    /// The next id of a shared object (`Process::shared`).
    next_shared_id: u32,
    /// Some process was cloned sharing runtime state with another (see
    /// `live_processes_share_state`).
    sharing: bool,
    /// The pid the boot CPU's runtime loop last ran from the run queue: the
    /// next turn goes to the ready process after it (`next_ready_live_process`).
    dispatch_cursor: u32,
    init: Option<ProcessHandle>,
    /// The deadlines of blocked processes (`Process::block`), by pid: one
    /// entry per block, checked against the process when looked at
    /// (`next_live_block_deadline`) rather than taken out wherever a
    /// block ends. Lossy after an allocation failure, until rebuilt.
    sleepers: linox_deadline_heap::DeadlineHeap<u32>,
    sleepers_lossy: bool,
    /// Some process may be blocked (`Process::block`): wakers look only
    /// then.
    blocked: bool,
    /// The threads blocked in calls of their own, each parked on its own
    /// activation (docs/SCHEDULER.md, "Activations per thread"). A process
    /// runs while any of its threads can; it blocks as a whole only when
    /// all of them wait, on what any of them waits for.
    thread_blocks: Vec<ThreadBlock>,
    /// The processes' address-space lists, by runtime slot.
    spaces: SpaceLists,
    /// Calls into the namespaces that table operations leave for after the
    /// table's lock is released (`with_live_table`).
    deferred: DeferredWork,
}

/// Namespace bookkeeping a table operation owes: the namespaces rank below
/// the table (`LockRank::NAMESPACES`), so it is done once the table's lock
/// is released.
struct DeferredWork {
    /// Processes reaped or never made, whose PID-namespace numbers go.
    forget_pids: Vec<u32>,
    /// The namespace sets processes still use: the others are dropped.
    collect: Option<Vec<linux_namespace::Set>>,
}

impl DeferredWork {
    const NONE: Self = Self {
        forget_pids: Vec::new(),
        collect: None,
    };

    /// Does the work, in the order it was owed: a reaped process's numbers
    /// go before the sets are collected, which keep a namespace that still
    /// numbers a live process.
    fn run(self) {
        if self.forget_pids.is_empty() && self.collect.is_none() {
            return;
        }
        let instance = cpu::current_linux_execution_instance();
        for pid in self.forget_pids {
            linux_namespace::forget_pid(instance, pid);
        }
        if let Some(sets) = self.collect {
            linux_namespace::collect(instance, &sets, crate::linux_sysv_ipc::release_instance);
        }
    }
}

/// A thread of a live process blocked in a system call, parked on its own
/// activation until a waker for what it waits on, a signal or its deadline
/// ends the block.
#[derive(Clone, Copy, Debug)]
struct ThreadBlock {
    pid: u32,
    tid: u32,
    /// Its slot in the process's thread table (its signal queue's).
    slot: u8,
    wait: crate::linux_wait_queue::WaitOn,
    /// Still blocked: a wake clears it, and the scheduler resumes the
    /// thread to look at its wait again.
    waiting: bool,
}

impl ThreadBlock {
    /// Its wait is over by `now`: woken, or its deadline passed.
    fn due(&self, now: u64) -> bool {
        !self.waiting || self.wait.deadline() != 0 && self.wait.deadline() <= now
    }
}

/// One installed seccomp program and the filter before it in its chain.
struct SeccompFilter {
    program: linox_seccomp::Program,
    /// Index + 1 of the previous filter, or 0.
    previous: u32,
    /// The chain's instructions up to here, each filter counting 4 more,
    /// as Linux limits them (MAX_INSNS_PER_PATH).
    path_instructions: usize,
}

/// The most instructions a chain may hold (Linux's MAX_INSNS_PER_PATH).
const SECCOMP_PATH_LIMIT: usize = 32_768;

impl ProcessTable {
    const fn new() -> Self {
        Self {
            owner_domain: 0,
            processes: Vec::new(),
            pid_slots: Vec::new(),
            generations: Vec::new(),
            groups: Vec::new(),
            roots: Vec::new(),
            seccomp_filters: Vec::new(),
            next_pid: 1,
            next_shared_id: 1,
            sharing: false,
            dispatch_cursor: 0,
            init: None,
            sleepers: linox_deadline_heap::DeadlineHeap::new(),
            sleepers_lossy: false,
            blocked: false,
            thread_blocks: Vec::new(),
            spaces: SpaceLists::new(),
            deferred: DeferredWork::NONE,
        }
    }

    /// Owes `forget_pid` for `pid` (see `DeferredWork`). Only PID
    /// namespaces number processes, so with none there is nothing to owe.
    fn defer_forget_pid(&mut self, pid: u32) {
        if !linux_namespace::any(linux_namespace::Kind::Pid) {
            return;
        }
        if self.deferred.forget_pids.try_reserve(1).is_ok() {
            self.deferred.forget_pids.push(pid);
        }
    }

    /// Ends the blocks of `pid`'s threads (all of them, or the one in
    /// thread slot `slot`): each looks at its wait again when it runs, as
    /// for a signal, which any of them may take.
    fn wake_threads(&mut self, pid: u32, slot: Option<u8>) {
        for block in self
            .thread_blocks
            .iter_mut()
            .filter(|block| block.pid == pid && slot.is_none_or(|slot| block.slot == slot))
        {
            block.waiting = false;
        }
    }

    /// A shared-object id no process holds yet.
    fn new_shared_id(&mut self) -> u32 {
        let id = self.next_shared_id;
        self.next_shared_id = id.wrapping_add(1).max(1);
        id
    }

    fn create_init(
        &mut self,
        address_space: ProcessAddressSpace,
        context: ProcessExecutionContext,
    ) -> Option<ProcessHandle> {
        // The page-table tree was checked as the lists were stored
        // (`ProcessAddressSpace::new`), before the table's lock was taken.
        if self.init.is_some()
            || self.next_pid != 1
            || !address_space.is_owned(&self.spaces)
            || !context.is_valid(&address_space, &self.spaces)
        {
            return None;
        }
        let user_namespace = linux_user::initial()?;
        let handle = self.allocate(
            None,
            user_namespace,
            Some(address_space),
            Some(context),
            ProcessState::Running,
        )?;
        if handle.pid != 1 {
            return None;
        }
        self.init = Some(handle);
        Some(handle)
    }

    fn scheduler_domain(&self) -> u64 {
        if self.owner_domain == 0 {
            1
        } else {
            self.owner_domain
        }
    }

    /// The lowest runtime slot no process holds: one pass marks the slots
    /// in use, as a table of thousands of processes would otherwise be
    /// scanned once per slot tried.
    fn free_runtime_slot(&self) -> Option<usize> {
        let mut used = [0_u64; PROCESS_RUNTIME_LIMIT.div_ceil(64)];
        for slot in self
            .processes
            .iter()
            .flatten()
            .filter_map(|process| process.runtime_slot)
        {
            if let Some(word) = used.get_mut(usize::from(slot) / 64) {
                *word |= 1 << (slot % 64);
            }
        }
        used.iter()
            .enumerate()
            .find(|(_, word)| **word != u64::MAX)
            .map(|(index, word)| index * 64 + word.trailing_ones() as usize)
            .filter(|slot| *slot < PROCESS_RUNTIME_LIMIT)
    }

    fn prepare_fork(&mut self, parent: ProcessHandle) -> Option<ProcessHandle> {
        let parent_process = self.process(parent)?;
        if parent_process.state != ProcessState::Running
            || parent_process.address_space.is_none()
            || parent_process.context.is_none()
        {
            return None;
        }
        let user_namespace = parent_process.user_namespace;
        linux_user::credentials(user_namespace)?;
        self.allocate(
            Some(parent),
            user_namespace,
            None,
            None,
            ProcessState::Preparing,
        )
    }

    fn refresh_process_inner(
        &mut self,
        handle: ProcessHandle,
        address_space: ProcessAddressSpace,
        context: ProcessExecutionContext,
        validate_address_space: bool,
    ) -> bool {
        // The snapshot's page-table tree was checked before the table's lock
        // was taken (`address_space_lists_valid`); its frames still have to
        // be owned.
        if validate_address_space && !address_space.is_owned(&self.spaces)
            || !context.is_valid(&address_space, &self.spaces)
        {
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if linux_user::credentials(process.user_namespace).is_none()
            || process.retiring_address_space.is_some()
            || process.state != ProcessState::Running
        {
            return false;
        }
        process.address_space = Some(address_space);
        process.runtime_slot = Some(address_space.storage_slot);
        process.context = Some(context);
        true
    }

    fn commit_fork(
        &mut self,
        handle: ProcessHandle,
        address_space: ProcessAddressSpace,
        context: ProcessExecutionContext,
    ) -> bool {
        self.commit_fork_inner(handle, address_space, context, true)
    }

    fn commit_fork_inner(
        &mut self,
        handle: ProcessHandle,
        address_space: ProcessAddressSpace,
        context: ProcessExecutionContext,
        validate_address_space: bool,
    ) -> bool {
        let lists = &self.spaces;
        if !context.is_valid(&address_space, lists)
            || validate_address_space
                && (!address_space.is_valid(lists)
                    || self.processes.iter().flatten().any(|process| {
                        // A stale list may name frames freed since and now
                        // another's; the live page tables are its record.
                        process.address_space.is_some_and(|existing| {
                            !existing.stale && existing.overlaps(&address_space, lists)
                        }) || process
                            .retiring_address_space
                            .is_some_and(|existing| existing.overlaps(&address_space, lists))
                    }))
        {
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.state != ProcessState::Preparing
            || process.address_space.is_some()
            || process.retiring_address_space.is_some()
            || process.context.is_some()
            || process.scheduler_thread.is_some()
        {
            return false;
        }
        process.address_space = Some(address_space);
        process.runtime_slot = Some(address_space.storage_slot);
        process.context = Some(context);
        process.state = ProcessState::Running;
        true
    }

    fn admit_to_scheduler(
        &mut self,
        handle: ProcessHandle,
        run_queue: &mut scheduler::ProcessScheduler,
        domain: u64,
    ) -> bool {
        let Some(process) = self.process(handle).copied() else {
            return false;
        };
        let (Some(address_space), Some(context)) = (process.address_space, process.context) else {
            return false;
        };
        if process.state != ProcessState::Running || process.scheduler_thread.is_some() {
            return false;
        }
        let Some(scheduler_context) = context.scheduler_context(&address_space, &self.spaces)
        else {
            return false;
        };
        let Some(thread) = run_queue.admit(domain, scheduler_context) else {
            return false;
        };
        if !run_queue.set_affinity(thread, process.cpu_affinity) {
            let _ = run_queue.retire(thread);
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            let _ = run_queue.retire(thread);
            return false;
        };
        if process.state != ProcessState::Running || process.scheduler_thread.is_some() {
            let _ = run_queue.retire(thread);
            return false;
        }
        process.scheduler_thread = Some(thread);
        true
    }

    fn withdraw_from_scheduler(
        &mut self,
        handle: ProcessHandle,
        run_queue: &mut scheduler::ProcessScheduler,
    ) -> bool {
        let Some(thread) = self
            .process(handle)
            .and_then(|process| process.scheduler_thread)
        else {
            crate::serial_write(
                "linox: process withdraw missing scheduler thread pid/slot/generation: ",
            );
            crate::serial_write_u64(u64::from(handle.pid));
            crate::serial_write(" ");
            crate::serial_write_u64(u64::from(handle.slot));
            crate::serial_write(" ");
            crate::serial_write_u64(u64::from(handle.generation));
            crate::serial_write("\r\n");
            return false;
        };
        if !run_queue.retire(thread) {
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.scheduler_thread != Some(thread) {
            return false;
        }
        process.scheduler_thread = None;
        true
    }

    /// The first part of `commit_cloned_fork`, under the table's lock:
    /// checks the prepared child `handle`, its parent and the frames
    /// allocated for the child, and copies what the rest needs (the
    /// parent's lists, the child's mapping list, the parent pages to copy)
    /// into `lists`. Backs the fork out (`abort_fork`) when it refuses.
    fn plan_cloned_fork(
        &mut self,
        handle: ProcessHandle,
        child_hierarchy: &[memory::FrameLease],
        child_pages: &[memory::FrameLease],
        share_vm: bool,
        lists: &mut ForkLists,
    ) -> Option<ForkCopy> {
        process_runtime()
            .fork_execution_stage
            .store(1131, Ordering::Release);
        let preparing = self.process(handle)?;
        if preparing.state != ProcessState::Preparing
            || preparing.address_space.is_some()
            || preparing.retiring_address_space.is_some()
        {
            return None;
        }
        let Some((parent_handle, parent_space, parent_context, parent_running)) =
            preparing.parent.and_then(|parent_handle| {
                let parent = self.process(parent_handle)?;
                Some((
                    parent_handle,
                    parent.address_space?,
                    parent.context?,
                    parent.state == ProcessState::Running,
                ))
            })
        else {
            let _ = self.abort_fork(handle);
            return None;
        };
        process_runtime()
            .fork_execution_stage
            .store(1132, Ordering::Release);
        // Each reason the commit can refuse the prepared child has a stage
        // of its own, so a fork that fails with EAGAIN names it in the log.
        let parent_pid = parent_handle.pid;
        let spaces = &self.spaces;
        let hierarchy_owned = if share_vm {
            parent_space.hierarchy_is_owned(spaces)
        } else {
            parent_space.is_owned(spaces)
        };
        let parent_mappings = parent_space.mappings(spaces);
        let copy_count = parent_mappings
            .iter()
            .filter(|mapping| !mapping.dontfork && mapping_requires_fork_copy(mapping))
            .count();
        let refused = if !parent_running {
            Some(1191)
        } else if !hierarchy_owned {
            Some(1192)
        } else if child_hierarchy.len() != parent_space.hierarchy(spaces).len() {
            Some(1193)
        } else if !child_pages.is_empty() && child_pages.len() != copy_count {
            Some(1194)
        } else {
            None
        };
        if let Some(stage) = refused {
            process_runtime()
                .fork_execution_stage
                .store(stage, Ordering::Release);
            let _ = self.abort_fork(handle);
            return None;
        }
        // Sets stages 1195..=1199 itself, one per check that can refuse.
        if !self.resources_available(parent_pid, child_hierarchy, child_pages) {
            let _ = self.abort_fork(handle);
            return None;
        }

        process_runtime()
            .fork_execution_stage
            .store(1133, Ordering::Release);
        let spaces = &self.spaces;
        let parent_mappings = parent_space.mappings(spaces);
        if address_space::fill_list(
            &mut lists.child_mappings,
            parent_mappings.len(),
            cpu::LinuxActiveImageMapping::EMPTY,
        )
        .is_none()
            || address_space::fill_list(
                &mut lists.parent_pages,
                child_pages.len(),
                memory::FrameLease::EMPTY,
            )
            .is_none()
            || replace_list(&mut lists.parent_mappings, parent_mappings).is_none()
            || replace_list(&mut lists.parent_hierarchy, parent_space.hierarchy(spaces)).is_none()
        {
            let _ = self.abort_fork(handle);
            return None;
        }
        let mut private_index = 0;
        let mut child_mapping_count = 0;
        for parent in parent_mappings {
            if parent.dontfork && !share_vm {
                continue;
            }
            let frame = if child_pages.is_empty() || !mapping_requires_fork_copy(parent) {
                parent.frame
            } else {
                let frame = *child_pages
                    .get(private_index)
                    .unwrap_or(&memory::FrameLease::EMPTY);
                private_index += 1;
                frame
            };
            lists.child_mappings[child_mapping_count] = cpu::LinuxActiveImageMapping {
                address: parent.address,
                frame,
                writable: parent.writable,
                executable: parent.executable,
                shared: share_vm || parent.shared,
                dontfork: false,
            };
            child_mapping_count += 1;
        }
        let mut parent_page_count = 0;
        if !child_pages.is_empty() {
            for mapping in parent_mappings
                .iter()
                .filter(|mapping| !mapping.dontfork && mapping_requires_fork_copy(mapping))
            {
                lists.parent_pages[parent_page_count] = mapping.frame;
                parent_page_count += 1;
            }
        }
        Some(ForkCopy {
            parent_pid,
            parent_root: parent_space.root(spaces),
            parent_context,
            child_mapping_count,
            parent_page_count,
            private_index,
        })
    }

    /// Stores the child's lists of a fork whose pages were copied, in the
    /// lowest free runtime slot, which the prepared child holds from now
    /// on so no other fork takes it. Err(()) when every slot is taken.
    fn store_cloned_fork_space(
        &mut self,
        handle: ProcessHandle,
        child_hierarchy: &[memory::FrameLease],
        child_mappings: &[cpu::LinuxActiveImageMapping],
    ) -> Result<Option<ProcessAddressSpace>, ()> {
        process_runtime()
            .fork_execution_stage
            .store(11361, Ordering::Release);
        let storage_slot = self.free_runtime_slot().ok_or(())?;
        let Some(space) = ProcessAddressSpace::from_validated_snapshot(
            &mut self.spaces,
            storage_slot,
            child_hierarchy,
            child_mappings,
        ) else {
            return Ok(None);
        };
        let Some(child) = self
            .process_mut(handle)
            .filter(|child| child.state == ProcessState::Preparing)
        else {
            return Ok(None);
        };
        child.runtime_slot = Some(space.storage_slot);
        Ok(Some(space))
    }

    /// The last part of `commit_cloned_fork`, under the table's lock: makes
    /// `child_space` the prepared child's and the child runnable.
    fn finish_cloned_fork(
        &mut self,
        handle: ProcessHandle,
        child_space: ProcessAddressSpace,
        context: ProcessExecutionContext,
        share_vm: bool,
    ) -> bool {
        if self.commit_fork_inner(handle, child_space, context, false) {
            if let Some(child) = self.process_mut(handle) {
                child.shares_parent_vm = share_vm;
            }
            process_runtime()
                .fork_execution_stage
                .store(1139, Ordering::Release);
            return true;
        }
        process_runtime()
            .fork_execution_stage
            .store(11382, Ordering::Release);
        crate::serial_write("linox: runtime fork child context validation error: ");
        crate::serial_write_u64(u64::from(
            context
                .validation_error(&child_space, &self.spaces)
                .unwrap_or(0),
        ));
        crate::serial_write("\r\n");
        false
    }
    fn resources_available(
        &self,
        parent_pid: u32,
        hierarchy: &[memory::FrameLease],
        pages: &[memory::FrameLease],
    ) -> bool {
        // The candidates, sorted: each is checked against every frame the
        // processes use by binary search, since a large process's lists made
        // a pairwise check take seconds.
        let mut candidates = Vec::new();
        if candidates
            .try_reserve_exact(hierarchy.len() + pages.len())
            .is_err()
        {
            return false;
        }
        candidates.extend(
            hierarchy
                .iter()
                .chain(pages)
                .map(|frame| (frame.address(), frame.generation())),
        );
        candidates.sort_unstable();
        // Distinct, within and between the two lists.
        let unique = candidates.windows(2).all(|pair| pair[0].0 != pair[1].0);
        // A process's registry lists are a snapshot that goes stale while it
        // runs (a thread on another CPU frees page tables without a refresh):
        // a lease behind the frame's current generation names a frame freed
        // and reused since, not one still held. Only a lease of the same
        // generation marks a frame as published.
        let candidate = |frame: &memory::FrameLease| {
            candidates
                .binary_search(&(frame.address(), frame.generation()))
                .is_ok()
        };
        // Every process's lists are checked while the table is small; past
        // that, the parent's, which the child's frames are copies of: every
        // process's at every fork made forking a thousand children take
        // seconds per hundred (futex_cmp_requeue01), and a frame lease of
        // the frame's current generation in another list would be the
        // allocator issuing it twice, not a stale list.
        let checked = |process: &&Process| {
            self.processes.len() <= FORK_CHECK_ALL_LIMIT || process.handle.pid == parent_pid
        };
        let unpublished = self
            .processes
            .iter()
            .flatten()
            .filter(checked)
            .all(|process| {
                process.address_space.into_iter().all(|space| {
                    !space.hierarchy(&self.spaces).iter().any(candidate)
                        && !space.mappings(&self.spaces).iter().any(|mapping| {
                            !mapping.shared
                                && !memory::frame_lease_is_runtime(mapping.frame)
                                && candidate(&mapping.frame)
                        })
                })
            });
        let refuse = |stage: u32| {
            process_runtime()
                .fork_execution_stage
                .store(stage, Ordering::Release);
            false
        };
        if hierarchy.len() < 4 {
            return refuse(1195);
        }
        if !memory::frames_owned_by(memory::FrameOwner::KERNEL, hierarchy) {
            return refuse(1196);
        }
        if !(pages.is_empty() || memory::frames_owned_by(memory::FrameOwner::KERNEL, pages)) {
            return refuse(1197);
        }
        if !unique {
            return refuse(1198);
        }
        if !unpublished {
            // Which process still lists a candidate frame, for the log: a
            // child that exited on another CPU may not have dropped its list
            // yet when the allocator hands its frames to this fork.
            let listed = self.processes.iter().flatten().find_map(|process| {
                let space = process.address_space.as_ref()?;
                let in_hierarchy = space
                    .hierarchy(&self.spaces)
                    .iter()
                    .find(|frame| candidate(frame));
                let in_mappings = space.mappings(&self.spaces).iter().find(|mapping| {
                    !mapping.shared
                        && !memory::frame_lease_is_runtime(mapping.frame)
                        && candidate(&mapping.frame)
                });
                match (in_hierarchy, in_mappings) {
                    (Some(frame), _) => Some((process, frame.address(), 0_u64, 0_u64)),
                    (None, Some(mapping)) => {
                        Some((process, mapping.frame.address(), 1, mapping.address as u64))
                    }
                    (None, None) => None,
                }
            });
            if let Some((process, frame, in_mapping, address)) = listed {
                // The listing process's lease generation against the new
                // allocation's: behind it, the frame was freed under that
                // process and reused; equal, the allocator issued it twice.
                let listed_generation = process
                    .address_space
                    .as_ref()
                    .and_then(|space| {
                        space
                            .hierarchy(&self.spaces)
                            .iter()
                            .copied()
                            .chain(
                                space
                                    .mappings(&self.spaces)
                                    .iter()
                                    .map(|mapping| mapping.frame),
                            )
                            .find(|lease| lease.address() == frame)
                    })
                    .map_or(0, |lease| u64::from(lease.generation()));
                let new_generation = hierarchy
                    .iter()
                    .chain(pages)
                    .find(|lease| lease.address() == frame)
                    .map_or(0, |lease| u64::from(lease.generation()));
                crate::serial_write(
                    "linox: fork frames still listed by pid/not-running/frame/in-mapping/address/its-generation/new-generation, forking parent: ",
                );
                for value in [
                    u64::from(process.handle.pid),
                    u64::from(process.state != ProcessState::Running),
                    frame,
                    in_mapping,
                    address,
                    listed_generation,
                    new_generation,
                    u64::from(parent_pid),
                ] {
                    crate::serial_write_u64(value);
                    crate::serial_write(" ");
                }
                crate::serial_write("\r\n");
            }
            return refuse(1199);
        }
        true
    }

    fn abort_fork(&mut self, handle: ProcessHandle) -> bool {
        let Some(process) = self.process(handle) else {
            return false;
        };
        if process.state != ProcessState::Preparing
            || process.address_space.is_some()
            || process.retiring_address_space.is_some()
            || process.context.is_some()
            || process.scheduler_thread.is_some()
        {
            return false;
        }
        self.processes[usize::from(handle.slot)] = None;
        self.forget_pid_slot(handle.pid);
        self.groups[usize::from(handle.slot)] = Vec::new();
        self.roots[usize::from(handle.slot)] = Vec::new();
        self.defer_forget_pid(handle.pid);
        true
    }

    fn begin_exit(
        &mut self,
        handle: ProcessHandle,
        expected_space: ProcessAddressSpace,
    ) -> Option<ProcessAddressSpace> {
        if !expected_space.is_owned(&self.spaces) {
            return None;
        }
        let process = self.process_mut(handle)?;
        if process.state != ProcessState::Running
            || process.address_space != Some(expected_space)
            || process.retiring_address_space.is_some()
            || process.context.is_none()
            || process.scheduler_thread.is_some()
        {
            return None;
        }
        process.address_space = None;
        process.retiring_address_space = Some(expected_space);
        process.context = None;
        process.state = ProcessState::Exiting;
        // However it ends, a tracer leaves its tracees running.
        self.detach_tracees(handle.pid);
        Some(expected_space)
    }

    /// Detaches every process `tracer` traces and continues the stopped
    /// ones, as Linux's exit_ptrace does.
    fn detach_tracees(&mut self, tracer: u32) {
        if tracer == 0 {
            return;
        }
        for slot in 0..self.processes.len() {
            let Some(handle) = self.processes[slot]
                .as_ref()
                .filter(|process| process.tracer == tracer)
                .map(|process| process.handle)
            else {
                continue;
            };
            if let Some(process) = self.process_mut(handle) {
                process.tracer = 0;
                process.ptrace_resume_signal = 0;
            }
            let _ = self.continue_process(handle);
        }
    }

    /// Clears `waiting` of whoever waits for `handle` to change state: its
    /// parent and its tracer. A process asleep in a wait for its children
    /// (`Process::is_asleep`) is skipped by the scheduler until then; any
    /// other wait it is in only looks again.
    fn wake_state_waiters(&mut self, handle: ProcessHandle) {
        let Some((parent, tracer)) = self
            .process(handle)
            .map(|process| (process.parent, process.tracer))
        else {
            return;
        };
        let tracer = (tracer != 0).then(|| self.handle_by_pid(tracer)).flatten();
        for waiter in [parent, tracer].into_iter().flatten() {
            if let Some(process) = self.process_mut(waiter) {
                process.waiting = false;
            }
            self.wake_threads(waiter.pid, None);
        }
    }

    fn exit(&mut self, handle: ProcessHandle, status: u8) -> bool {
        let Some(process) = self.process(handle) else {
            return false;
        };
        if process.state != ProcessState::Exiting
            || process.address_space.is_some()
            || process.context.is_some()
            || process.scheduler_thread.is_some()
        {
            return false;
        }
        let Some(retiring) = process.retiring_address_space else {
            return false;
        };
        if retiring.is_live(&self.spaces) {
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        process.retiring_address_space = None;
        process.wait_event = None;
        process.state = ProcessState::Zombie { status };
        self.wake_state_waiters(handle);
        self.reparent_children_to_init(handle);
        true
    }

    /// Hands the children of an exiting process, running or already zombies,
    /// to its nearest living ancestor marked a child subreaper
    /// (PR_SET_CHILD_SUBREAPER), or else to the domain's init, as Linux's
    /// find_new_reaper does, so that their exit status can still be
    /// collected and their slots reused.
    fn reparent_children_to_init(&mut self, handle: ProcessHandle) {
        let alive = |table: &Self, candidate: ProcessHandle| {
            candidate != handle
                && table.process(candidate).is_some_and(|process| {
                    matches!(
                        process.state,
                        ProcessState::Running | ProcessState::Stopped { .. }
                    )
                })
        };
        let init = self.handle_by_pid(1).filter(|init| alive(self, *init));
        let mut subreaper = None;
        let mut ancestor = self.process(handle).and_then(|process| process.parent);
        for _ in 0..PROCESS_LIMIT {
            let Some(candidate) = ancestor.filter(|candidate| Some(*candidate) != init) else {
                break;
            };
            let Some(process) = self.process(candidate) else {
                break;
            };
            if process.child_subreaper && alive(self, candidate) {
                subreaper = Some(candidate);
                break;
            }
            ancestor = process.parent;
        }
        let Some(init) = subreaper.or(init) else {
            return;
        };
        // An adopted child ends with SIGCHLD to init, whatever its clone
        // asked of its first parent, as in Linux.
        let mut adopted = false;
        for process in self.processes.iter_mut().flatten() {
            if process.parent == Some(handle) {
                process.parent = Some(init);
                process.exit_signal = DEFAULT_EXIT_SIGNAL;
                adopted = true;
            }
        }
        // Init may wait for children already gone.
        if adopted {
            if let Some(init) = self.process_mut(init) {
                init.waiting = false;
            }
            self.wake_threads(init.pid, None);
        }
    }

    fn exit_after_current_address_space_retired(
        &mut self,
        handle: ProcessHandle,
        status: u8,
    ) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.state != ProcessState::Running || process.scheduler_thread.is_some() {
            return false;
        }
        process.address_space = None;
        process.retiring_address_space = None;
        process.context = None;
        process.wait_event = None;
        process.state = ProcessState::Zombie { status };
        self.thread_blocks.retain(|block| block.pid != handle.pid);
        self.wake_state_waiters(handle);
        self.reparent_children_to_init(handle);
        true
    }

    fn exit_after_retiring_address_space_released(
        &mut self,
        handle: ProcessHandle,
        expected_space: ProcessAddressSpace,
        status: u8,
    ) -> bool {
        let Some(process) = self.process(handle) else {
            return false;
        };
        if process.state != ProcessState::Exiting
            || process.address_space.is_some()
            || process.retiring_address_space != Some(expected_space)
            || process.context.is_some()
            || process.scheduler_thread.is_some()
            || expected_space
                .hierarchy(&self.spaces)
                .iter()
                .any(|frame| memory::frames_owned_by(memory::FrameOwner::KERNEL, &[*frame]))
        {
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        process.retiring_address_space = None;
        process.wait_event = None;
        process.state = ProcessState::Zombie { status };
        self.wake_state_waiters(handle);
        self.reparent_children_to_init(handle);
        true
    }

    fn wait(&mut self, parent: ProcessHandle, pid: u32) -> Option<WaitResult> {
        if self.process(parent)?.state != ProcessState::Running {
            return None;
        }
        let slot = self.processes.iter().position(|candidate| {
            candidate.is_some_and(|process| {
                process.handle.pid == pid
                    && process.parent == Some(parent)
                    && matches!(process.state, ProcessState::Zombie { .. })
            })
        })?;
        let process = self.processes[slot].take()?;
        self.forget_pid_slot(process.handle.pid);
        self.groups[slot] = Vec::new();
        self.roots[slot] = Vec::new();
        let ProcessState::Zombie { status } = process.state else {
            return None;
        };
        // The child's CPU time, and its own children's, joins the parent's
        // children's, as Linux adds it when a wait reaps the child.
        if let Some(parent) = self.process_mut(parent) {
            let system = process.cpu_cycles.saturating_sub(process.user_cycles);
            parent.children_cycles.0 = parent
                .children_cycles
                .0
                .saturating_add(process.user_cycles)
                .saturating_add(process.children_cycles.0);
            parent.children_cycles.1 = parent
                .children_cycles
                .1
                .saturating_add(system)
                .saturating_add(process.children_cycles.1);
            for event in 0..crate::cpu_time::TASK_EVENTS {
                parent.children_task_events[event] = parent.children_task_events[event]
                    .saturating_add(process.task_events[event])
                    .saturating_add(process.children_task_events[event]);
            }
        }
        if self
            .processes
            .iter()
            .flatten()
            .all(|candidate| candidate.user_namespace != process.user_namespace)
        {
            let _ = linux_user::retire(process.user_namespace);
        }
        self.defer_forget_pid(pid);
        self.collect_namespaces();
        Some(WaitResult { pid, status })
    }

    fn child_wait_state(
        &self,
        parent: ProcessHandle,
        pid: Option<u32>,
        report_stopped: bool,
        report_continued: bool,
    ) -> Option<ChildWaitState> {
        self.child_wait_state_matching(
            parent,
            |process| pid.is_none_or(|pid| process.handle.pid == pid),
            true,
            report_stopped,
            report_continued,
        )
    }

    fn child_group_wait_state(
        &self,
        parent: ProcessHandle,
        process_group: u32,
        report_stopped: bool,
        report_continued: bool,
    ) -> Option<ChildWaitState> {
        self.child_wait_state_matching(
            parent,
            |process| process.process_group == process_group,
            true,
            report_stopped,
            report_continued,
        )
    }

    /// The wait-visible state of the first matching child. Exited children
    /// are reported only with `report_exited`: waitid(2) without WEXITED
    /// must not see, and so must not reap, them.
    fn child_wait_state_matching(
        &self,
        parent: ProcessHandle,
        matches: impl Fn(&Process) -> bool,
        report_exited: bool,
        report_stopped: bool,
        report_continued: bool,
    ) -> Option<ChildWaitState> {
        if self.process(parent)?.state != ProcessState::Running {
            return None;
        }
        // A tracer waits for its tracees as for its children.
        let parent_pid = parent.pid;
        let mut children = self.processes.iter().flatten().filter(|process| {
            (process.parent == Some(parent) || process.tracer == parent_pid && parent_pid != 0)
                && matches(process)
        });
        // A tracer is told of its tracee's stops without WUNTRACED.
        let stops_reported =
            |process: &Process| report_stopped || process.tracer == parent_pid && parent_pid != 0;
        let child = children
            .clone()
            .find(|process| {
                report_exited
                    && process.parent == Some(parent)
                    && matches!(process.state, ProcessState::Zombie { .. })
            })
            .or_else(|| {
                children.clone().find(|process| {
                    stops_reported(process)
                        && matches!(process.wait_event, Some(ProcessWaitEvent::Stopped { .. }))
                        || report_continued
                            && process.parent == Some(parent)
                            && process.wait_event == Some(ProcessWaitEvent::Continued)
                })
            })
            .or_else(|| children.next())?;
        if stops_reported(child) {
            if let Some(ProcessWaitEvent::Stopped { signal }) = child.wait_event {
                return Some(ChildWaitState::Stopped {
                    pid: child.handle.pid,
                    signal,
                });
            }
        }
        // A tracee that is not a child is the tracer's to see stop only:
        // its parent reaps it.
        if child.parent != Some(parent) {
            return Some(ChildWaitState::Running);
        }
        if report_continued && child.wait_event == Some(ProcessWaitEvent::Continued) {
            return Some(ChildWaitState::Continued {
                pid: child.handle.pid,
            });
        }
        match child.state {
            ProcessState::Running
            | ProcessState::Stopped { .. }
            | ProcessState::Preparing
            | ProcessState::Exiting => Some(ChildWaitState::Running),
            ProcessState::Zombie { .. } if !report_exited => Some(ChildWaitState::Running),
            ProcessState::Zombie { status } => Some(ChildWaitState::Exited {
                pid: child.handle.pid,
                status,
                signal: child.killed_by_signal,
            }),
        }
    }

    /// Stops a running process with stop signal `signal`: `in_call` for one
    /// that parks in its kill call (its state stays Running for the wait
    /// engine), else one that left the CPU and is not dispatched again
    /// until continued.
    fn stop(&mut self, handle: ProcessHandle, signal: u8, in_call: bool) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.state != ProcessState::Running || process.stopped_in_call || signal == 0 {
            return false;
        }
        if in_call {
            process.stopped_in_call = true;
        } else {
            process.state = ProcessState::Stopped { signal };
        }
        process.wait_event = Some(ProcessWaitEvent::Stopped { signal });
        self.wake_state_waiters(handle);
        true
    }

    fn continue_process(&mut self, handle: ProcessHandle) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.stopped_in_call {
            process.stopped_in_call = false;
        } else if matches!(process.state, ProcessState::Stopped { .. }) {
            process.state = ProcessState::Running;
        } else {
            return false;
        }
        process.wait_event = Some(ProcessWaitEvent::Continued);
        self.wake_state_waiters(handle);
        true
    }

    fn consume_wait_event(&mut self, parent: ProcessHandle, pid: u32) -> bool {
        let Some(handle) = self.handle_by_pid(pid) else {
            return false;
        };
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        let traced = process.tracer == parent.pid && parent.pid != 0;
        if process.parent != Some(parent) && !traced || process.wait_event.is_none() {
            return false;
        }
        process.wait_event = None;
        true
    }

    fn reap_init_zombies(&mut self) -> bool {
        let Some(init) = self.init else {
            return false;
        };
        loop {
            let Some(pid) = self
                .processes
                .iter()
                .flatten()
                .find(|process| {
                    process.parent == Some(init)
                        && matches!(process.state, ProcessState::Zombie { .. })
                })
                .map(|process| process.handle.pid)
            else {
                return true;
            };
            if self.wait(init, pid).is_none() {
                return false;
            }
        }
    }

    fn reap_all_zombies(&mut self) -> bool {
        for slot in 0..self.processes.len() {
            let Some(candidate) = self.processes[slot].as_ref() else {
                continue;
            };
            if matches!(candidate.state, ProcessState::Zombie { .. }) {
                if candidate.address_space.is_some()
                    || candidate.retiring_address_space.is_some()
                    || candidate.scheduler_thread.is_some()
                {
                    return false;
                }
                let pid = candidate.handle.pid;
                self.processes[slot] = None;
                self.forget_pid_slot(pid);
            }
        }
        true
    }

    fn handle_by_pid(&self, pid: u32) -> Option<ProcessHandle> {
        let index = self
            .pid_slots
            .binary_search_by_key(&pid, |(pid, _)| *pid)
            .ok()?;
        let slot = usize::from(self.pid_slots[index].1);
        self.processes
            .get(slot)?
            .as_ref()
            .filter(|process| process.handle.pid == pid)
            .map(|process| process.handle)
    }

    /// Forgets slot `slot`'s process (`pid`) in the pid index.
    fn forget_pid_slot(&mut self, pid: u32) {
        if let Ok(index) = self.pid_slots.binary_search_by_key(&pid, |(pid, _)| *pid) {
            self.pid_slots.remove(index);
        }
    }

    fn set_return_value(&mut self, handle: ProcessHandle, value: u64) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        let Some(mut context) = process.context else {
            return false;
        };
        if process.state != ProcessState::Running {
            return false;
        }
        context.general[PROCESS_RAX_INDEX] = value;
        process.context = Some(context);
        true
    }

    fn set_stack_pointer(&mut self, handle: ProcessHandle, stack: u64) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        let Some(mut context) = process.context else {
            return false;
        };
        if process.state != ProcessState::Running || stack == 0 {
            return false;
        }
        context.rsp = stack;
        process.context = Some(context);
        true
    }

    fn dispatch(&mut self, handle: ProcessHandle) -> Option<LiveProcessDispatch> {
        let process = self.process_mut(handle)?;
        process.waiting = false;
        process.block = None;
        let process = self.process(handle)?;
        let address_space = process.address_space.as_ref()?;
        let context = process.context?;
        if process.state != ProcessState::Running || !context.is_valid(address_space, &self.spaces)
        {
            return None;
        }
        Some(LiveProcessDispatch {
            pid: handle.pid,
            root: address_space.root(&self.spaces),
            general: context.general,
            rip: context.rip,
            rsp: context.rsp,
            rflags: context.rflags,
            fs_base: context.fs_base,
        })
    }

    fn allocate(
        &mut self,
        parent: Option<ProcessHandle>,
        user_namespace: linux_user::UserNamespaceHandle,
        address_space: Option<ProcessAddressSpace>,
        context: Option<ProcessExecutionContext>,
        state: ProcessState,
    ) -> Option<ProcessHandle> {
        let slot = match self.processes.iter().position(Option::is_none) {
            Some(slot) => slot,
            None if self.processes.len() < PROCESS_LIMIT => {
                self.processes.try_reserve(1).ok()?;
                self.generations.try_reserve(1).ok()?;
                self.groups.try_reserve(1).ok()?;
                self.roots.try_reserve(1).ok()?;
                self.processes.push(None);
                self.generations.push(0);
                self.groups.push(Vec::new());
                self.roots.push(Vec::new());
                self.processes.len() - 1
            }
            None => return None,
        };
        self.pid_slots.try_reserve(1).ok()?;
        let generation = self.generations[slot].checked_add(1)?;
        let pid = self.next_pid;
        self.next_pid = self.next_pid.checked_add(1)?;
        let handle = ProcessHandle {
            slot: u16::try_from(slot).ok()?,
            generation,
            pid,
        };
        let (process_group, session, cpu_affinity, scheduling, oom_score_adj, credentials) =
            parent.and_then(|parent| self.process(parent)).map_or(
                (pid, pid, u64::MAX, (0, 0), 0, linux_user::Credentials::ROOT),
                |parent| {
                    (
                        parent.process_group,
                        parent.session,
                        parent.cpu_affinity,
                        if parent.scheduling.0 & SCHED_RESET_ON_FORK == 0 {
                            parent.scheduling
                        } else {
                            (0, 0)
                        },
                        parent.oom_score_adj,
                        parent.credentials,
                    )
                },
            );
        let timer_slack = parent
            .and_then(|parent| self.process(parent))
            .map_or((DEFAULT_TIMER_SLACK, DEFAULT_TIMER_SLACK), |parent| {
                (parent.timer_slack.0, parent.timer_slack.0)
            });
        let seccomp_filter = parent
            .and_then(|parent| self.process(parent))
            .map_or(0, |parent| parent.seccomp_filter);
        // A child starts in its parent's cgroup.
        let (cgroup_generation, memcg) = parent
            .and_then(|parent| self.process(parent))
            .map_or((0, 0), |parent| (parent.cgroup_generation, parent.memcg));
        let memory_policy = parent
            .and_then(|parent| self.process(parent))
            .map_or(crate::linux_areas::Policy::DEFAULT, |parent| {
                parent.memory_policy
            });
        let namespaces = match parent.and_then(|parent| self.process_mut(parent)) {
            Some(parent) => parent
                .child_namespaces
                .take()
                .unwrap_or_else(|| parent.namespaces.for_child()),
            None => linux_namespace::Set::default(),
        };
        // A child born into a PID namespace gets its numbers there, and the
        // time namespace it enters keeps its offsets from now on: the caller
        // enters them once the table's lock is released (`enter_namespaces`),
        // and backs the child out if that fails. A process without a parent
        // starts in the initial ones, which need neither.
        // A new process's groups are its parent's; the first is in group 0.
        let inherited: &[u32] = match parent {
            Some(parent) => self.groups.get(usize::from(parent.slot))?,
            None => &[0],
        };
        let mut groups = Vec::new();
        groups.try_reserve_exact(inherited.len()).ok()?;
        groups.extend_from_slice(inherited);
        self.groups[slot] = groups;
        // A child starts in its parent's root directory.
        let mut root = Vec::new();
        if let Some(parent_root) =
            parent.and_then(|parent| self.roots.get(usize::from(parent.slot)))
        {
            root.try_reserve_exact(parent_root.len()).ok()?;
            root.extend_from_slice(parent_root);
        }
        self.roots[slot] = root;
        self.generations[slot] = generation;
        let shared = core::array::from_fn(|_| self.new_shared_id());
        self.processes[slot] = Some(Process {
            handle,
            parent,
            process_group,
            session,
            executed: false,
            user_namespace,
            namespaces,
            child_namespaces: None,
            credentials,
            runtime_slot: address_space.map(|space| space.storage_slot),
            address_space,
            retiring_address_space: None,
            context,
            scheduler_thread: None,
            cpu_affinity,
            scheduling,
            timer_slack,
            stopped_in_call: false,
            oom_score_adj,
            io: IoAccounting::default(),
            child_subreaper: false,
            memory_policy,
            killed_by_signal: 0,
            oom_victim: false,
            seccomp_filter,
            tracer: 0,
            ptrace_resume_signal: 0,
            ptrace_bypass: false,
            debug_registers: DebugRegisters::RESET,
            state,
            wait_event: None,
            shares_parent_vm: false,
            shared,
            exit_signal: DEFAULT_EXIT_SIGNAL,
            reaped_by_parent: false,
            cgroup_generation,
            memcg,
            cloned_by: None,
            vfork_child: 0,
            waiting: false,
            block: None,
            cpu_cycles: 0,
            user_cycles: 0,
            children_cycles: (0, 0),
            task_events: [0; crate::cpu_time::TASK_EVENTS],
            children_task_events: [0; crate::cpu_time::TASK_EVENTS],
            started_nanoseconds: crate::arch::x86_64::cpu::linux_uptime_nanoseconds(),
            posix_timers: [None; POSIX_TIMER_LIMIT],
            itimers: [None; 4],
            maxrss_kib: 0,
            children_maxrss_kib: 0,
            deadline_parameters: [0; 3],
        });
        let index = self.pid_slots.partition_point(|(other, _)| *other < pid);
        self.pid_slots.insert(index, (pid, handle.slot));
        Some(handle)
    }

    /// Drops the namespaces no process of the table uses any more, once
    /// the table's lock is released (`DeferredWork`).
    fn collect_namespaces(&mut self) {
        let mut sets = Vec::new();
        if sets.try_reserve(self.processes.len()).is_err() {
            return;
        }
        sets.extend(
            self.processes
                .iter()
                .flatten()
                .map(|process| process.namespaces),
        );
        // A later collection sees every set an earlier one would have.
        self.deferred.collect = Some(sets);
    }

    fn process_group(&self, pid: u32) -> Option<(u32, u32)> {
        let process = self.process(self.handle_by_pid(pid)?)?;
        matches!(
            process.state,
            ProcessState::Running | ProcessState::Stopped { .. } | ProcessState::Zombie { .. }
        )
        .then_some((process.process_group, process.session))
    }

    fn set_process_group(
        &mut self,
        caller_pid: u32,
        target_pid: u32,
        process_group: u32,
    ) -> Result<(), ProcessGroupError> {
        let caller = self
            .handle_by_pid(caller_pid)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        let target = self
            .handle_by_pid(target_pid)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        let caller_process = self
            .process(caller)
            .filter(|process| process.state == ProcessState::Running)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        let target_process = self
            .process(target)
            .filter(|process| process.state == ProcessState::Running)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        if target != caller && target_process.parent != Some(caller) {
            return Err(ProcessGroupError::NoSuchProcess);
        }
        if target != caller && target_process.executed {
            return Err(ProcessGroupError::Access);
        }
        if target_process.session != caller_process.session
            || target_process.session == target_process.handle.pid
        {
            return Err(ProcessGroupError::Permission);
        }
        let requested = if process_group == 0 {
            target_process.handle.pid
        } else {
            process_group
        };
        if requested != target_process.handle.pid
            && !self.processes.iter().flatten().any(|process| {
                process.process_group == requested && process.session == caller_process.session
            })
        {
            return Err(ProcessGroupError::Permission);
        }
        self.process_mut(target)
            .ok_or(ProcessGroupError::NoSuchProcess)?
            .process_group = requested;
        Ok(())
    }

    fn create_session(&mut self, pid: u32) -> Result<u32, ProcessGroupError> {
        let handle = self
            .handle_by_pid(pid)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        if self
            .processes
            .iter()
            .flatten()
            .any(|process| process.process_group == pid)
        {
            return Err(ProcessGroupError::Permission);
        }
        let process = self
            .process_mut(handle)
            .filter(|process| process.state == ProcessState::Running)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        process.process_group = pid;
        process.session = pid;
        Ok(pid)
    }

    fn mark_executed(&mut self, pid: u32) -> bool {
        let Some(handle) = self.handle_by_pid(pid) else {
            return false;
        };
        let Some(process) = self
            .process_mut(handle)
            .filter(|process| process.state == ProcessState::Running)
        else {
            return false;
        };
        process.executed = true;
        process.posix_timers = [None; POSIX_TIMER_LIMIT];
        process.debug_registers = DebugRegisters::RESET;
        // A vfork parent waits for this.
        self.wake_state_waiters(handle);
        true
    }

    fn set_exec_context(&mut self, pid: u32, rip: u64, rsp: u64) -> bool {
        let Some(handle) = self.handle_by_pid(pid) else {
            return false;
        };
        let context = ProcessExecutionContext {
            general: [0; 15],
            rip,
            rsp,
            rflags: (1 << 1) | (1 << 9),
            fs_base: 0,
        };
        if self
            .process(handle)
            .filter(|process| process.state == ProcessState::Running)
            .and_then(|process| process.address_space)
            .is_none_or(|space| !context.is_valid(&space, &self.spaces))
        {
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        process.context = Some(context);
        process.executed = true;
        process.posix_timers = [None; POSIX_TIMER_LIMIT];
        process.debug_registers = DebugRegisters::RESET;
        process.shares_parent_vm = false;
        let memory = self.new_shared_id();
        if let Some(process) = self.process_mut(handle) {
            process.shared[SharedResource::Memory as usize] = memory;
        }
        // A vfork parent waits for this.
        self.wake_state_waiters(handle);
        true
    }

    /// Process `pid`'s address space and its lists, to change both.
    fn space_lists_mut(
        &mut self,
        pid: u32,
    ) -> Option<(&mut ProcessAddressSpace, &mut ProcessAddressSpaceStorage)> {
        let handle = self.handle_by_pid(pid)?;
        let Self {
            processes, spaces, ..
        } = self;
        let space = processes
            .get_mut(usize::from(handle.slot))?
            .as_mut()
            .filter(|process| process.handle == handle)?
            .address_space
            .as_mut()?;
        let storage = spaces.slot_mut(usize::from(space.storage_slot))?;
        Some((space, storage))
    }

    fn process(&self, handle: ProcessHandle) -> Option<&Process> {
        self.processes
            .get(usize::from(handle.slot))?
            .as_ref()
            .filter(|process| process.handle == handle)
    }

    fn process_mut(&mut self, handle: ProcessHandle) -> Option<&mut Process> {
        self.processes
            .get_mut(usize::from(handle.slot))?
            .as_mut()
            .filter(|process| process.handle == handle)
    }
}

/// How fork code reaches a table: a domain's live table through its lock
/// (`LiveTable`), or a table the caller owns (the lifecycle check's).
trait TableAccess {
    /// Runs `f` on the table, then the namespace work it owes; None when
    /// there is no table.
    fn with<R>(&mut self, f: impl FnOnce(&mut ProcessTable) -> R) -> Option<R>;
}

/// The active instance's live table, through `with_live_table`.
struct LiveTable;

impl TableAccess for LiveTable {
    fn with<R>(&mut self, f: impl FnOnce(&mut ProcessTable) -> R) -> Option<R> {
        with_live_table(f)
    }
}

impl TableAccess for ProcessTable {
    fn with<R>(&mut self, f: impl FnOnce(&mut ProcessTable) -> R) -> Option<R> {
        let result = f(self);
        core::mem::replace(&mut self.deferred, DeferredWork::NONE).run();
        Some(result)
    }
}

/// The lists a fork works from (see `LiveForkScratch`).
struct ForkLists {
    /// The child's mapping list, built from the parent's.
    child_mappings: Vec<cpu::LinuxActiveImageMapping>,
    /// The parent's pages the child gets copies of.
    parent_pages: Vec<memory::FrameLease>,
    /// The parent's lists as the fork found them, for the page copies and
    /// the page-table clone made with the table's lock released.
    parent_mappings: Vec<cpu::LinuxActiveImageMapping>,
    parent_hierarchy: Vec<memory::FrameLease>,
}

/// What `ProcessTable::plan_cloned_fork` found, for the copy made with the
/// table's lock released.
struct ForkCopy {
    parent_pid: u32,
    parent_root: memory::FrameLease,
    parent_context: ProcessExecutionContext,
    /// How much of `ForkLists::child_mappings` and `parent_pages` is filled.
    child_mapping_count: usize,
    parent_page_count: usize,
    /// The private pages handed to the child's mappings.
    private_index: usize,
}

/// Commits the prepared fork child `handle`: copies its parent's private
/// pages into `child_pages` (none: the child maps the parent's
/// copy-on-write, or all of them with `share_vm`), clones the parent's page
/// tables into `child_hierarchy`, registers the child's lists and makes it
/// runnable. The table's lock is held only to check and to record: the
/// page copies, the page-table clone (which duplicates swap entries) and the
/// System V attachments the child inherits are done between holds. On
/// failure the child's frames are released and the fork backed out.
fn commit_cloned_fork(
    table: &mut impl TableAccess,
    handle: ProcessHandle,
    child_hierarchy: &[memory::FrameLease],
    child_pages: &[memory::FrameLease],
    share_vm: bool,
    lists: &mut ForkLists,
) -> bool {
    let Some(copy) = table
        .with(|table| table.plan_cloned_fork(handle, child_hierarchy, child_pages, share_vm, lists))
        .flatten()
    else {
        return false;
    };
    process_runtime()
        .fork_execution_stage
        .store(1134, Ordering::Release);
    let published = child_pages.is_empty()
        || copy.private_index == child_pages.len()
            && copy.parent_page_count == child_pages.len()
            && copy_validated_private_pages(
                &lists.parent_mappings,
                copy.parent_root,
                &lists.parent_pages[..copy.parent_page_count],
                child_pages,
            );
    process_runtime()
        .fork_execution_stage
        .store(1135, Ordering::Release);
    let published = published
        && address_space::clone_validated_linux_process_hierarchy(
            &lists.parent_mappings,
            &lists.parent_hierarchy,
            child_hierarchy,
            child_pages,
            share_vm,
        );
    process_runtime()
        .fork_execution_stage
        .store(1136, Ordering::Release);
    let child_mappings = &lists.child_mappings[..copy.child_mapping_count];
    let child_space = if published {
        let stored = table
            .with(|table| table.store_cloned_fork_space(handle, child_hierarchy, child_mappings))
            .unwrap_or(Ok(None));
        let Ok(child_space) = stored else {
            if child_pages.is_empty() {
                let _ = address_space::release_linux_leaf_pages(child_hierarchy[0]);
            }
            let _ = scrub_candidate_resources(child_hierarchy, child_pages);
            let _ = table.with(|table| table.abort_fork(handle));
            return false;
        };
        child_space
    } else {
        None
    };
    process_runtime()
        .fork_execution_stage
        .store(1137, Ordering::Release);
    if child_space.is_none() {
        crate::serial_write("linox: runtime fork clone state published/hierarchy/mappings: ");
        crate::serial_write_u64(u64::from(published));
        crate::serial_write(" ");
        crate::serial_write_u64(child_hierarchy.len() as u64);
        crate::serial_write(" ");
        crate::serial_write_u64(copy.child_mapping_count as u64);
        crate::serial_write("\r\n");
    }
    if let Some(child_space) = child_space {
        process_runtime()
            .fork_execution_stage
            .store(1138, Ordering::Release);
        let attachments_inherited =
            crate::linux_sysv_ipc::inherit_process_attachments(copy.parent_pid, handle.pid).is_ok();
        process_runtime().fork_execution_stage.store(
            if attachments_inherited { 11381 } else { 11380 },
            Ordering::Release,
        );
        if attachments_inherited
            && table
                .with(|table| {
                    table.finish_cloned_fork(
                        handle,
                        child_space,
                        copy.parent_context.fork_child(),
                        share_vm,
                    )
                })
                .unwrap_or(false)
        {
            return true;
        }
        if attachments_inherited {
            let _ = crate::linux_sysv_ipc::drop_process_attachments(handle.pid);
        }
    }
    if published && child_pages.is_empty() {
        let _ = address_space::release_linux_leaf_pages(child_hierarchy[0]);
    }
    let _ = scrub_candidate_resources(child_hierarchy, child_pages);
    let _ = table.with(|table| table.abort_fork(handle));
    false
}

fn test_mapping(
    address: usize,
    frame: memory::FrameLease,
    writable: bool,
    executable: bool,
) -> cpu::LinuxActiveImageMapping {
    cpu::LinuxActiveImageMapping {
        address,
        frame,
        writable,
        executable,
        shared: false,
        dontfork: false,
    }
}

fn write_test_hierarchy(
    hierarchy: &[memory::FrameLease],
    mappings: &[cpu::LinuxActiveImageMapping],
) -> bool {
    if hierarchy.len() != 4 || mappings.is_empty() {
        return false;
    }
    let mut tables = [None; 4];
    for (table, frame) in tables.iter_mut().zip(hierarchy) {
        *table = Frame::leased(*frame);
    }
    let [Some(top), Some(upper), Some(middle), Some(leaf)] = tables else {
        return false;
    };
    for table in tables.into_iter().flatten() {
        table.zero();
    }
    let branch_flags = PRESENT | WRITABLE | USER;
    for mapping in mappings {
        let indexes = [
            (mapping.address >> 39) & 0x1ff,
            (mapping.address >> 30) & 0x1ff,
            (mapping.address >> 21) & 0x1ff,
            (mapping.address >> 12) & 0x1ff,
        ];
        top.write_u64(indexes[0], hierarchy[1].address() | branch_flags);
        upper.write_u64(indexes[1], hierarchy[2].address() | branch_flags);
        middle.write_u64(indexes[2], hierarchy[3].address() | branch_flags);
        leaf.write_u64(
            indexes[3],
            mapping.frame.address()
                | PRESENT
                | USER
                | if mapping.writable { WRITABLE } else { 0 }
                | if mapping.executable { 0 } else { NO_EXECUTE },
        );
    }
    true
}

fn test_context() -> ProcessExecutionContext {
    ProcessExecutionContext {
        general: [0x55; 15],
        rip: TEST_USER_ADDRESS as u64,
        rsp: (TEST_USER_ADDRESS + 2 * PAGE_SIZE) as u64,
        rflags: (1 << 1) | (1 << 9),
        fs_base: (TEST_USER_ADDRESS + PAGE_SIZE) as u64,
    }
}

fn verify_user_kernel_mapping_rejected(root: memory::FrameLease) -> bool {
    let Some(table) = Frame::leased(root) else {
        return false;
    };
    let original = table.read_u64(256);
    table.write_u64(256, original | USER);
    let rejected = !address_space::verify_linux_process_root_activation(root);
    table.write_u64(256, original);
    rejected && table.read_u64(256) == original
}

pub(crate) fn verify_lifecycle_contract() -> bool {
    // The check's own table, which only it reaches. Its address-space lists
    // are allocated on first use: allocate the slots this check uses (0 to
    // 5) first, so the frame count it compares at the end covers only the
    // frames the lifecycle takes and returns.
    let mut table = ProcessTable::new();
    let mut fork_lists = LiveForkScratch::EMPTY.lists;
    if table.spaces.slot_mut(5).is_none() {
        return false;
    }
    // The heap keeps the frames it grows by (the test table's slots live
    // there): count the frames outside it.
    let Some(before) = crate::heap::kernel_frames_outside_heap() else {
        return false;
    };
    let Some(frames) = memory::allocate_frames::<18>(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let init_mappings = [
        test_mapping(TEST_USER_ADDRESS, frames[4], false, true),
        test_mapping(TEST_USER_ADDRESS + PAGE_SIZE, frames[5], true, false),
    ];
    if !write_test_hierarchy(&frames[0..4], &init_mappings) {
        crate::serial_write("linox: lifecycle stage hierarchy failed\r\n");
        return false;
    }
    if !address_space::set_linux_mapping_wipe_on_fork(
        frames[0],
        TEST_USER_ADDRESS + PAGE_SIZE,
        true,
    ) {
        crate::serial_write("linox: lifecycle stage wipe policy failed\r\n");
        return false;
    }
    if address_space::verify_linux_process_root_activation(frames[0])
        || !address_space::inherit_linux_process_kernel_mappings(frames[0])
    {
        crate::serial_write("linox: lifecycle stage kernel inheritance failed\r\n");
        return false;
    }
    let Some(init_space) =
        ProcessAddressSpace::new(&mut table.spaces, 0, &frames[0..4], &init_mappings)
    else {
        return false;
    };
    let init_context = test_context();
    let mut invalid_context = init_context;
    invalid_context.rip = (TEST_USER_ADDRESS + PAGE_SIZE) as u64;
    if table.create_init(init_space, invalid_context).is_some() {
        return false;
    }
    invalid_context = init_context;
    invalid_context.rsp = TEST_USER_ADDRESS as u64;
    if table.create_init(init_space, invalid_context).is_some() {
        return false;
    }
    invalid_context = init_context;
    invalid_context.rflags |= 3 << 12;
    if table.create_init(init_space, invalid_context).is_some() {
        return false;
    }
    invalid_context = init_context;
    invalid_context.fs_base = 1 << 47;
    if table.create_init(init_space, invalid_context).is_some() {
        return false;
    }
    let Some(init) = table.create_init(init_space, init_context) else {
        return false;
    };
    let Some(init_scheduler_context) = init_context.scheduler_context(&init_space, &table.spaces)
    else {
        return false;
    };
    let mut run_queue = scheduler::ProcessScheduler::new();
    if table.admit_to_scheduler(init, &mut run_queue, 0)
        || !table.admit_to_scheduler(init, &mut run_queue, 1)
        || table.admit_to_scheduler(init, &mut run_queue, 1)
    {
        return false;
    }
    let Some(rejected_child) = table.prepare_fork(init) else {
        return false;
    };
    let shared_page_mappings = [
        test_mapping(TEST_USER_ADDRESS, frames[4], false, true),
        test_mapping(TEST_USER_ADDRESS + PAGE_SIZE, frames[11], true, false),
    ];
    if !write_test_hierarchy(&frames[6..10], &shared_page_mappings)
        || !address_space::inherit_linux_process_kernel_mappings(frames[6])
    {
        return false;
    }
    let Some(shared_page_space) =
        ProcessAddressSpace::new(&mut table.spaces, 1, &frames[6..10], &shared_page_mappings)
    else {
        return false;
    };
    if table.commit_fork(rejected_child, shared_page_space, init_context.fork_child()) {
        return false;
    }
    let first_mappings = [
        test_mapping(TEST_USER_ADDRESS, frames[10], false, true),
        test_mapping(TEST_USER_ADDRESS + PAGE_SIZE, frames[11], true, false),
    ];
    let second_mappings = [
        test_mapping(TEST_USER_ADDRESS, frames[16], false, true),
        test_mapping(TEST_USER_ADDRESS + PAGE_SIZE, frames[17], true, false),
    ];
    if !write_test_hierarchy(&frames[6..10], &first_mappings)
        || !address_space::inherit_linux_process_kernel_mappings(frames[6])
        || !verify_user_kernel_mapping_rejected(frames[6])
        || !write_test_hierarchy(&frames[12..16], &second_mappings)
        || !address_space::inherit_linux_process_kernel_mappings(frames[12])
    {
        return false;
    }
    let mut wrong_permission = first_mappings;
    wrong_permission[0].writable = true;
    wrong_permission[0].executable = false;
    let mut wrong_address = first_mappings;
    wrong_address[0].address += 2 * PAGE_SIZE;
    if ProcessAddressSpace::new(&mut table.spaces, 4, &frames[6..10], &wrong_permission)
        .is_some_and(|space| space.is_valid(&table.spaces))
        || ProcessAddressSpace::new(&mut table.spaces, 5, &frames[6..10], &wrong_address)
            .is_some_and(|space| space.is_valid(&table.spaces))
    {
        return false;
    }
    let (Some(first_space), Some(mut second_space)) = (
        ProcessAddressSpace::new(&mut table.spaces, 1, &frames[6..10], &first_mappings),
        ProcessAddressSpace::new(&mut table.spaces, 2, &frames[12..16], &second_mappings),
    ) else {
        return false;
    };
    let Some(stale_generation) = frames[6].generation().checked_add(1) else {
        return false;
    };
    let Some(stale_root) = memory::FrameLease::from_parts(frames[6].address(), stale_generation)
    else {
        return false;
    };
    let mut stale_hierarchy: [memory::FrameLease; 4] =
        core::array::from_fn(|index| frames[6 + index]);
    stale_hierarchy[0] = stale_root;
    let stale_space =
        ProcessAddressSpace::new(&mut table.spaces, 3, &stale_hierarchy, &first_mappings);
    let stale_expected = ProcessAddressSpace {
        storage_slot: 3,
        hierarchy_count: first_space.hierarchy_count,
        mapping_count: first_space.mapping_count,
        stale: false,
    };
    if init.pid != 1
        || rejected_child.pid != 2
        || table.process_group(init.pid) != Some((1, 1))
        || table.create_session(init.pid) != Err(ProcessGroupError::Permission)
        || table.create_init(first_space, init_context).is_some()
        || table.commit_fork(rejected_child, init_space, init_context.fork_child())
        || stale_space.is_some_and(|space| space.is_valid(&table.spaces))
        || address_space::verify_linux_process_root_activation(stale_root)
        || table.wait(init, rejected_child.pid).is_some()
        || table.exit(rejected_child, 1)
        || commit_cloned_fork(
            &mut table,
            rejected_child,
            &frames[0..4],
            &frames[4..6],
            false,
            &mut fork_lists,
        )
        || !init_space.is_valid(&table.spaces)
        || table.commit_fork(rejected_child, first_space, init_context.fork_child())
        || table.abort_fork(rejected_child)
    {
        return false;
    }
    let Some(first_child) = table.prepare_fork(init) else {
        return false;
    };
    let (Some(parent_page), Some(parent_stack), Some(child_page), Some(child_stack)) = (
        Frame::leased(frames[4]),
        Frame::leased(frames[5]),
        Frame::leased(frames[10]),
        Frame::leased(frames[11]),
    ) else {
        return false;
    };
    parent_page.write_bytes(0, &PROCESS_CHILD_PROGRAM);
    parent_page.write_u8(PAGE_SIZE - 1, 0x32);
    parent_stack.write_u8(0, 0x44);
    if first_child.pid != 3 {
        crate::serial_write("linox: lifecycle stage child identity failed\r\n");
        return false;
    }
    if !commit_cloned_fork(
        &mut table,
        first_child,
        &frames[6..10],
        &frames[10..12],
        false,
        &mut fork_lists,
    ) {
        crate::serial_write("linox: lifecycle stage cloned fork failed\r\n");
        return false;
    }
    if !child_page.bytes_match(0, &PROCESS_CHILD_PROGRAM)
        || child_page.read_u8(PAGE_SIZE - 1) != 0x32
        || table.commit_fork(first_child, second_space, init_context.fork_child())
        || table.wait(init, first_child.pid).is_some()
        || table.exit(first_child, 42)
        || table.begin_exit(first_child, second_space).is_some()
        || table.begin_exit(first_child, stale_expected).is_some()
    {
        crate::serial_write("linox: lifecycle stage cloned fork state failed\r\n");
        return false;
    }
    if child_stack.read_u8(0) != 0 {
        crate::serial_write("linox: lifecycle stage wipe contents failed\r\n");
        return false;
    }
    if table.process_group(first_child.pid) != Some((1, 1))
        || table.child_wait_state(init, Some(first_child.pid), false, false)
            != Some(ChildWaitState::Running)
        || table.set_process_group(init.pid, first_child.pid, first_child.pid) != Ok(())
        || table.process_group(first_child.pid) != Some((3, 1))
        || table.child_group_wait_state(init, first_child.pid, false, false)
            != Some(ChildWaitState::Running)
        || table
            .child_group_wait_state(init, init.pid, false, false)
            .is_some()
        || table.set_process_group(init.pid, first_child.pid, init.pid) != Ok(())
        || !table.mark_executed(first_child.pid)
        || table.set_process_group(init.pid, first_child.pid, first_child.pid)
            != Err(ProcessGroupError::Access)
        || table.create_session(first_child.pid) != Ok(first_child.pid)
        || table.process_group(first_child.pid) != Some((3, 3))
        || table.set_process_group(init.pid, first_child.pid, init.pid)
            != Err(ProcessGroupError::Access)
        || table.set_process_group(first_child.pid, init.pid, init.pid)
            != Err(ProcessGroupError::NoSuchProcess)
    {
        return false;
    }
    if !table.stop(first_child, 19, false)
        || table.child_wait_state(init, Some(first_child.pid), false, false)
            != Some(ChildWaitState::Running)
        || table.child_wait_state(init, Some(first_child.pid), true, false)
            != Some(ChildWaitState::Stopped {
                pid: first_child.pid,
                signal: 19,
            })
        || !table.consume_wait_event(init, first_child.pid)
        || !table.continue_process(first_child)
        || table.child_wait_state(init, Some(first_child.pid), false, true)
            != Some(ChildWaitState::Continued {
                pid: first_child.pid,
            })
        || !table.consume_wait_event(init, first_child.pid)
        || table.child_wait_state(init, Some(first_child.pid), true, true)
            != Some(ChildWaitState::Running)
    {
        return false;
    }
    let Some(child_context) = table
        .process(first_child)
        .and_then(|process| process.context)
    else {
        return false;
    };
    if child_context != init_context.fork_child()
        || child_context.general[PROCESS_RAX_INDEX] != 0
        || table.process(init).and_then(|process| process.context) != Some(init_context)
    {
        return false;
    }
    let Some(child_scheduler_context) =
        child_context.scheduler_context(&first_space, &table.spaces)
    else {
        return false;
    };
    if !table.admit_to_scheduler(first_child, &mut run_queue, 1)
        || table.admit_to_scheduler(first_child, &mut run_queue, 1)
    {
        return false;
    }
    let (Some(init_thread), Some(child_thread)) = (
        table
            .process(init)
            .and_then(|process| process.scheduler_thread),
        table
            .process(first_child)
            .and_then(|process| process.scheduler_thread),
    ) else {
        return false;
    };
    let Some(initial) = run_queue.schedule_next() else {
        return false;
    };
    let Some(selected_child) = run_queue.yield_current(init_thread, init_scheduler_context) else {
        return false;
    };
    if selected_child.handle() != child_thread
        || selected_child.context() != child_scheduler_context
    {
        return false;
    }
    let child_exit_status = if crate::arch::x86_64::smp::online_count() > 1 {
        crate::arch::x86_64::smp::execute_linux_process(
            1,
            first_space.root(&table.spaces),
            child_context.rip,
            child_context.rsp,
            child_context.fs_base,
            child_context.general,
        )
    } else {
        address_space::execute_linux_process_child(
            first_space.root(&table.spaces),
            child_context.rip,
            child_context.rsp,
            child_context.fs_base,
            child_context.general,
        )
    };
    let Some(child_exit_status) = child_exit_status else {
        return false;
    };
    if crate::arch::x86_64::smp::online_count() > 1 {
        crate::serial_write("linox: scheduled Linux child executed on application processor\r\n");
    }
    if child_exit_status != 42 || child_stack.read_u8(0) != 0x5a || parent_stack.read_u8(0) != 0x44
    {
        crate::serial_write("linox: lifecycle stage wipe execution failed\r\n");
        return false;
    }
    if crate::arch::x86_64::smp::online_count() > 1 {
        let (Some(second_page), Some(shared_page)) =
            (Frame::leased(frames[16]), Frame::leased(frames[11]))
        else {
            return false;
        };
        let concurrent_second_mappings = [
            test_mapping(TEST_USER_ADDRESS, frames[16], false, true),
            // Alias the first process's writable page only for this bounded
            // rendezvous. Neither test program uses its user stack while the
            // alias exists, and the original second mapping is restored before
            // lifecycle teardown resumes.
            test_mapping(TEST_USER_ADDRESS + PAGE_SIZE, frames[11], true, false),
        ];
        if !write_test_hierarchy(&frames[12..16], &concurrent_second_mappings)
            || !address_space::inherit_linux_process_kernel_mappings(frames[12])
        {
            return false;
        }
        let Some(concurrent_second_space) = ProcessAddressSpace::new(
            &mut table.spaces,
            2,
            &frames[12..16],
            &concurrent_second_mappings,
        ) else {
            return false;
        };
        child_page.write_bytes(0, &CONCURRENT_PROCESS_PROGRAM);
        second_page.write_bytes(0, &CONCURRENT_PROCESS_PROGRAM);
        shared_page.write_bytes(0, &0_u32.to_ne_bytes());
        let concurrent_context = init_context.fork_child();
        let ticket = crate::arch::x86_64::smp::begin_linux_process(
            1,
            first_space.root(&table.spaces),
            concurrent_context.rip,
            concurrent_context.rsp,
            concurrent_context.fs_base,
            concurrent_context.general,
        );
        let Some(ticket) = ticket else {
            crate::serial_write("linox: concurrent Linux process dispatch failed\r\n");
            return false;
        };
        let mut remote_entered = false;
        for _ in 0..20_000_000 {
            if shared_page.read_volatile_u32(0) == 1 {
                remote_entered = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !remote_entered {
            let _ = crate::arch::x86_64::smp::finish_linux_process(ticket);
            crate::serial_write("linox: concurrent Linux process rendezvous failed\r\n");
            return false;
        }
        let local_status = address_space::execute_linux_process_child(
            concurrent_second_space.root(&table.spaces),
            concurrent_context.rip,
            concurrent_context.rsp,
            concurrent_context.fs_base,
            concurrent_context.general,
        );
        let remote_status = crate::arch::x86_64::smp::finish_linux_process(ticket);
        if local_status != Some(42)
            || remote_status != Some(42)
            || shared_page.read_volatile_u32(0) != 2
        {
            return false;
        }
        crate::serial_write("linox: concurrent Linux processes executed across processors\r\n");
        if !write_test_hierarchy(&frames[12..16], &second_mappings)
            || !address_space::inherit_linux_process_kernel_mappings(frames[12])
        {
            return false;
        }
        let Some(restored_second_space) =
            ProcessAddressSpace::new(&mut table.spaces, 2, &frames[12..16], &second_mappings)
        else {
            return false;
        };
        second_space = restored_second_space;
    }
    let Some(resumed_parent) = run_queue.yield_current(child_thread, child_scheduler_context)
    else {
        return false;
    };
    if initial.handle() != init_thread
        || initial.context() != init_scheduler_context
        || resumed_parent.handle() != init_thread
        || resumed_parent.context() != init_scheduler_context
        || table.begin_exit(first_child, first_space).is_some()
        || !table.withdraw_from_scheduler(first_child, &mut run_queue)
        || !table.withdraw_from_scheduler(init, &mut run_queue)
        || run_queue.retire(child_thread)
        || table.withdraw_from_scheduler(first_child, &mut run_queue)
    {
        return false;
    }
    if parent_page.read_u8(0) != PROCESS_CHILD_PROGRAM[0] {
        return false;
    }
    let Some(first_resources) = table.begin_exit(first_child, first_space) else {
        return false;
    };
    let Some(first_root) = first_resources.hierarchy(&table.spaces).first().copied() else {
        return false;
    };
    if table.exit(first_child, child_exit_status)
        || !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[first_root])
        || table.exit(first_child, child_exit_status)
        || !memory::scrub_and_release_frames(
            memory::FrameOwner::KERNEL,
            &first_resources.hierarchy(&table.spaces)[1..],
        )
        || first_resources
            .mappings(&table.spaces)
            .iter()
            .any(|mapping| {
                !mapping.shared
                    && !memory::frame_lease_is_runtime(mapping.frame)
                    && !memory::scrub_and_release_frames(
                        memory::FrameOwner::KERNEL,
                        &[mapping.frame],
                    )
            })
        || !table.exit(first_child, child_exit_status)
        || table.child_wait_state(init, Some(first_child.pid), false, false)
            != Some(ChildWaitState::Exited {
                pid: first_child.pid,
                status: child_exit_status,
                signal: 0,
            })
        || table.child_group_wait_state(init, first_child.pid, false, false)
            != Some(ChildWaitState::Exited {
                pid: first_child.pid,
                status: child_exit_status,
                signal: 0,
            })
        || table.wait(first_child, first_child.pid).is_some()
        || table.wait(init, first_child.pid)
            != Some(WaitResult {
                pid: 3,
                status: child_exit_status,
            })
        || table.exit(first_child, child_exit_status)
    {
        return false;
    }
    let Some(second_child) = table.prepare_fork(init) else {
        return false;
    };
    if second_child.slot != first_child.slot
        || second_child.generation <= first_child.generation
        || second_child.pid != 4
        || table.begin_exit(first_child, second_space).is_some()
        || table.commit_fork(second_child, first_space, init_context.fork_child())
        || table.commit_fork(second_child, second_space, invalid_context)
        || !table.commit_fork(second_child, second_space, init_context.fork_child())
    {
        return false;
    }
    let Some(second_resources) = table.begin_exit(second_child, second_space) else {
        return false;
    };
    if !second_resources.scrub_and_release(&table.spaces)
        || !table.exit(second_child, 7)
        || table.wait(init, second_child.pid) != Some(WaitResult { pid: 4, status: 7 })
    {
        return false;
    }
    let Some(init_resources) = table.begin_exit(init, init_space) else {
        return false;
    };
    let released = init_resources.scrub_and_release(&table.spaces) && table.exit(init, 0);
    // The namespace work the table owes (none for the initial namespaces
    // its processes were in).
    core::mem::replace(&mut table.deferred, DeferredWork::NONE).run();
    released && crate::heap::kernel_frames_outside_heap() == Some(before)
}

pub(crate) fn install_live_process_registry(
    snapshot: &cpu::LinuxProcessAddressSpaceSnapshot,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    let instance = current_process_instance();
    if process_runtime().table_initialized[instance].load(Ordering::Acquire)
        || process_runtime().active_instance.load(Ordering::Acquire) != PROCESS_INSTANCE_NONE
    {
        return false;
    }
    // The page-table tree is walked before the table's lock is taken.
    if !address_space_lists_valid(snapshot.hierarchy(), snapshot.mappings()) {
        return false;
    }
    let context = ProcessExecutionContext {
        general,
        rip,
        rsp,
        rflags,
        fs_base,
    };
    let owner_domain = cpu::current_container_slot()
        .and_then(cpu::container_domain_id)
        .unwrap_or(0);
    let installed = {
        let mut table = PROCESS_TABLES[instance].lock();
        let table = &mut *table;
        let Some(address_space) = ProcessAddressSpace::from_validated_snapshot(
            &mut table.spaces,
            0,
            snapshot.hierarchy(),
            snapshot.mappings(),
        ) else {
            return false;
        };
        let mut invalid = context;
        invalid.rip = 0;
        if invalid.is_valid(&address_space, &table.spaces)
            || !context.is_valid(&address_space, &table.spaces)
        {
            return false;
        }
        table.owner_domain = owner_domain;
        // Emptying the vectors keeps their memory for the next domain.
        table.processes.clear();
        table.pid_slots.clear();
        table.generations.clear();
        table.groups.clear();
        table.roots.clear();
        table.seccomp_filters.clear();
        table.next_pid = 1;
        table.init = None;
        table.create_init(address_space, context).is_some()
    };
    if !installed {
        return false;
    }
    process_runtime().refresh_count[instance].store(0, Ordering::Release);
    process_runtime().table_initialized[instance].store(true, Ordering::Release);
    process_runtime()
        .active_instance
        .store(instance as u8, Ordering::Release);
    true
}
pub(crate) fn refresh_live_process_registry(
    pid: u32,
    snapshot: &cpu::LinuxProcessAddressSpaceSnapshot,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    refresh_live_process_registry_inner(pid, snapshot, general, rip, rsp, rflags, fs_base, true)
}

pub(crate) fn refresh_validated_runtime_process_registry(
    pid: u32,
    snapshot: &cpu::LinuxProcessAddressSpaceSnapshot,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    refresh_live_process_registry_inner(pid, snapshot, general, rip, rsp, rflags, fs_base, false)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn refresh_live_process_context_from_syscall_entry(
    pid: u32,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    let Some(instruction_mapping) = address_space::current_linux_active_mapping(rip) else {
        return false;
    };
    let Some(stack_address) = rsp.checked_sub(1) else {
        return false;
    };
    let Some(stack_mapping) = address_space::current_linux_active_mapping(stack_address) else {
        return false;
    };
    let context = ProcessExecutionContext {
        general,
        rip,
        rsp,
        rflags,
        fs_base,
    };
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        let ProcessTable {
            processes, spaces, ..
        } = table;
        let Some(process) = processes
            .get_mut(usize::from(handle.slot))
            .and_then(Option::as_mut)
            .filter(|process| process.handle == handle)
        else {
            return false;
        };
        if process.state != ProcessState::Running {
            return false;
        }
        let Some(space) = process.address_space.as_mut() else {
            return false;
        };
        let Some(storage) = spaces.slot_mut(usize::from(space.storage_slot)) else {
            return false;
        };
        let mut count = space.mapping_count as usize;
        if count != storage.mappings.len() {
            return false;
        }
        let context_mappings = [instruction_mapping, stack_mapping];
        let missing = context_mappings
            .iter()
            .enumerate()
            .filter(|(index, mapping)| {
                context_mappings[..*index]
                    .iter()
                    .all(|prior| prior.address != mapping.address)
                    && storage.mappings[..count]
                        .iter()
                        .all(|existing| existing.address != mapping.address)
            })
            .count();
        if storage.mappings.try_reserve(missing).is_err() {
            return false;
        }
        for mapping in context_mappings {
            if let Some(existing) = storage.mappings[..count]
                .iter_mut()
                .find(|existing| existing.address == mapping.address)
            {
                let shared = existing.shared;
                let dontfork = existing.dontfork;
                *existing = mapping;
                existing.shared = shared;
                existing.dontfork = dontfork;
            } else {
                storage.mappings.push(mapping);
                count += 1;
            }
        }
        space.mapping_count = count as u32;
        if !context.is_valid(space, spaces) {
            return false;
        }
        process.context = Some(context);
        true
    })
    .unwrap_or(false)
}
/// Records the context the current process `pid` waits in, checked against
/// its live page tables (the instruction executable, the stack writable)
/// rather than its registered mapping list, which this marks stale: a wait
/// costs a few lookups instead of a pass over every mapped page. Its
/// release then frees what the live page tables map, and fork and exec
/// take a full snapshot again.
pub(crate) fn refresh_live_process_context_for_wait(
    pid: u32,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    let context = ProcessExecutionContext {
        general,
        rip,
        rsp,
        rflags,
        fs_base,
    };
    let mapped = context.registers_valid()
        && address_space::current_linux_active_mapping(rip).is_some_and(|page| page.executable)
        && rsp
            .checked_sub(1)
            .and_then(address_space::current_linux_active_mapping)
            .is_some_and(|page| page.writable);
    mapped && set_live_process_context(pid, context)
}

/// Records the saved user context of the thread the current process `pid`
/// is next entered at (one that waited ready, its stack perhaps not mapped
/// in yet: its first touch faults it in), checking only that the registers
/// are a user context; the registered mapping list is marked stale.
pub(crate) fn set_live_process_thread_context(
    pid: u32,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    let context = ProcessExecutionContext {
        general,
        rip,
        rsp,
        rflags,
        fs_base,
    };
    context.registers_valid() && set_live_process_context(pid, context)
}

/// Makes `context` running process `pid`'s registry context, its mapping
/// list stale.
fn set_live_process_context(pid: u32, context: ProcessExecutionContext) -> bool {
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        let Some(process) = table.process_mut(handle) else {
            return false;
        };
        if process.state != ProcessState::Running {
            return false;
        }
        let Some(space) = process.address_space.as_mut() else {
            return false;
        };
        space.stale = true;
        process.context = Some(context);
        true
    })
    .unwrap_or(false)
}

pub(crate) fn refresh_live_process_hierarchy(pid: u32, hierarchy: &[memory::FrameLease]) -> bool {
    if hierarchy.len() < 4 || !memory::frames_owned_by(memory::FrameOwner::KERNEL, hierarchy) {
        return false;
    }
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        let Some(space) = table
            .process(handle)
            .and_then(|process| process.address_space)
        else {
            return false;
        };
        let Some(storage) = table.spaces.slot_mut(usize::from(space.storage_slot)) else {
            return false;
        };
        if replace_list(&mut storage.hierarchy, hierarchy).is_none() {
            return false;
        }
        let Some(process) = table.process_mut(handle) else {
            return false;
        };
        let Some(mut updated) = process.address_space else {
            return false;
        };
        updated.hierarchy_count = hierarchy.len() as u32;
        process.address_space = Some(updated);
        true
    })
    .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
fn refresh_live_process_registry_inner(
    pid: u32,
    snapshot: &cpu::LinuxProcessAddressSpaceSnapshot,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
    validate_address_space: bool,
) -> bool {
    // The snapshot's page-table tree is walked before the table's lock is
    // taken; the lists stored under it are copies of what was checked.
    let snapshot_valid = !validate_address_space
        || address_space_lists_valid(snapshot.hierarchy(), snapshot.mappings());
    let context = ProcessExecutionContext {
        general,
        rip,
        rsp,
        rflags,
        fs_base,
    };
    let refreshed = with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            crate::serial_write("linox: live registry refresh has no process\r\n");
            return (false, false);
        };
        let Some(storage_slot) = table
            .process(handle)
            .and_then(|process| process.address_space)
            .map(|space| usize::from(space.storage_slot))
        else {
            crate::serial_write("linox: live registry refresh has no address space\r\n");
            return (false, false);
        };
        let address_space = if snapshot_valid {
            ProcessAddressSpace::from_validated_snapshot(
                &mut table.spaces,
                storage_slot,
                snapshot.hierarchy(),
                snapshot.mappings(),
            )
        } else {
            None
        };
        let Some(address_space) = address_space else {
            crate::serial_write("linox: live registry refresh rejected address space\r\n");
            return (false, false);
        };
        let context_error = context.validation_error(&address_space, &table.spaces);
        let refreshed =
            table.refresh_process_inner(handle, address_space, context, validate_address_space);
        // Reported for the first few only: a call that retries after a
        // rejection would otherwise flood the serial console.
        let reported = !refreshed && REFRESH_REJECTIONS.fetch_add(1, Ordering::Relaxed) < 8;
        if reported {
            report_refresh_rejection(table, handle, &address_space, context_error, &context);
        }
        (refreshed, reported)
    });
    let Some((refreshed, reported)) = refreshed else {
        crate::serial_write("linox: live registry refresh has no table\r\n");
        return false;
    };
    if refreshed {
        let instance = active_process_instance().unwrap_or(HOST_PROCESS_INSTANCE);
        process_runtime().refresh_count[instance].fetch_add(1, Ordering::SeqCst);
    } else if reported {
        let (root, leaf) = address_space::current_linux_leaf_report(rsp.wrapping_sub(1));
        let snapshot_root = snapshot
            .hierarchy()
            .first()
            .map_or(0, |frame| frame.address());
        crate::serial_write("linox: live registry refresh cr3/snapshot-root/stack-leaf: ");
        for value in [root, snapshot_root, leaf] {
            crate::serial_write_u64(value);
            crate::serial_write(" ");
        }
        crate::serial_write("\r\n");
    }
    refreshed
}

/// Says why the table refused process `handle`'s refreshed context.
fn report_refresh_rejection(
    table: &ProcessTable,
    handle: ProcessHandle,
    address_space: &ProcessAddressSpace,
    context_error: Option<u8>,
    context: &ProcessExecutionContext,
) {
    crate::serial_write(
        "linox: live registry refresh rejected process context pid/state/error/rip/rsp/rflags: ",
    );
    let (state, retiring) = table
        .process(handle)
        .map(|process| {
            (
                match process.state {
                    ProcessState::Preparing => 1,
                    ProcessState::Running => 2,
                    ProcessState::Stopped { .. } => 3,
                    ProcessState::Exiting => 4,
                    ProcessState::Zombie { .. } => 5,
                },
                u64::from(process.retiring_address_space.is_some()),
            )
        })
        .unwrap_or((0, 0));
    let error = u64::from(context_error.unwrap_or(0))
        | u64::from(
            table
                .process(handle)
                .is_some_and(|process| linux_user::credentials(process.user_namespace).is_none()),
        ) << 4
        | (address_space.mapping_count as u64) << 16;
    for value in [
        u64::from(handle.pid),
        state,
        error | retiring << 8,
        context.rip,
        context.rsp,
        context.rflags,
    ] {
        crate::serial_write_u64(value);
        crate::serial_write(" ");
    }
    crate::serial_write("\r\n");
}
/// Registry refreshes rejected, for the report above.
static REFRESH_REJECTIONS: AtomicU32 = AtomicU32::new(0);

pub(crate) fn finish_live_process_registry(refresh_floor: u32) -> bool {
    finish_live_process_registry_with_refresh_floor(refresh_floor)
}

pub(crate) fn finish_runtime_process_registry() -> bool {
    finish_live_process_registry_with_refresh_floor(0)
}

pub(crate) fn force_stop_runtime_process_registry() -> bool {
    let Some(instance) = active_process_instance() else {
        return true;
    };
    if !process_runtime().table_initialized[instance].load(Ordering::Acquire) {
        return false;
    }
    let withdrawn = with_live_table(|table| {
        let init = table.init?;
        let run_queue = scheduler::active_process_scheduler_workspace()?;
        run_queue.retire_all();
        table.thread_blocks.clear();
        for process in table.processes.iter_mut().flatten() {
            process.scheduler_thread = None;
        }
        scheduler::release_process_scheduler_workspace().then_some(init)
    })
    .flatten();
    let Some(init) = withdrawn else {
        return false;
    };
    // Every process but init goes, one at a time: its memory and its
    // System V attachments with the table's lock released, then its record.
    let mut slot = 0;
    loop {
        let next = with_live_table(|table| {
            let (index, process) = table
                .processes
                .iter()
                .enumerate()
                .skip(slot)
                .filter_map(|(index, process)| Some((index, (*process)?)))
                .find(|(_, process)| process.handle != init)?;
            let spaces = [process.address_space, process.retiring_address_space]
                .map(|space| space.map(|space| (space, space.root(&table.spaces))));
            Some((index, process.handle, spaces))
        })
        .flatten();
        let Some((index, handle, spaces)) = next else {
            break;
        };
        slot = index + 1;
        for (space, root) in spaces.into_iter().flatten() {
            if !retire_live_process_page_tables(root)
                || !with_live_table(|table| release_space_hierarchy(&space, &table.spaces))
                    .unwrap_or(false)
            {
                return false;
            }
        }
        if crate::linux_sysv_ipc::drop_process_attachments(handle.pid).is_err() {
            return false;
        }
        let removed = with_live_table(|table| {
            if table.process(handle).is_none() {
                return false;
            }
            let Some(process) = table.processes[usize::from(handle.slot)].take() else {
                return false;
            };
            table.forget_pid_slot(handle.pid);
            table.groups[usize::from(handle.slot)] = Vec::new();
            table.roots[usize::from(handle.slot)] = Vec::new();
            if table
                .processes
                .iter()
                .flatten()
                .all(|candidate| candidate.user_namespace != process.user_namespace)
            {
                let _ = linux_user::retire(process.user_namespace);
            }
            true
        })
        .unwrap_or(false);
        if !removed {
            return false;
        }
    }
    with_live_table(|table| {
        let Some(process) = table.process_mut(init) else {
            return false;
        };
        process.parent = None;
        process.retiring_address_space = None;
        process.scheduler_thread = None;
        process.state = ProcessState::Running;
        process.wait_event = None;
        true
    })
    .unwrap_or(false)
}
pub(crate) fn suspend_runtime_process_registry() -> bool {
    let Some(instance) = active_process_instance() else {
        return false;
    };
    if instance != current_process_instance()
        || !process_runtime().table_initialized[instance].load(Ordering::Acquire)
    {
        return false;
    }
    process_runtime()
        .active_instance
        .store(PROCESS_INSTANCE_NONE, Ordering::Release);
    true
}

pub(crate) fn resume_runtime_process_registry() -> bool {
    let instance = current_process_instance();
    if !process_runtime().table_initialized[instance].load(Ordering::Acquire)
        || process_runtime()
            .active_instance
            .compare_exchange(
                PROCESS_INSTANCE_NONE,
                instance as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        return false;
    }
    let owner_domain = cpu::current_container_slot()
        .and_then(cpu::container_domain_id)
        .unwrap_or(0);
    let valid = with_live_table(|table| table.owner_domain == owner_domain && table.init.is_some())
        .unwrap_or(false);
    if !valid {
        process_runtime()
            .active_instance
            .store(PROCESS_INSTANCE_NONE, Ordering::Release);
    }
    valid
}

fn finish_live_process_registry_with_refresh_floor(refresh_floor: u32) -> bool {
    let Some(instance) = active_process_instance() else {
        return true;
    };
    if !process_runtime().table_initialized[instance].load(Ordering::Acquire) {
        return false;
    }
    let valid = with_live_table(|table| {
        let valid = table.reap_init_zombies()
            && table.reap_all_zombies()
            && table.init.is_some()
            && process_runtime().refresh_count[instance].load(Ordering::Acquire) >= refresh_floor
            && table.processes.iter().flatten().count() == 1
            && table.processes.iter().flatten().all(|process| {
                process.parent.is_none()
                    && linux_user::credentials(process.user_namespace).is_some()
                    && process.state == ProcessState::Running
                    && process.retiring_address_space.is_none()
                    && process.scheduler_thread.is_none()
            });
        if !valid {
            crate::serial_write("linox: live process registry finish state: ");
            crate::serial_write_u64(u64::from(table.init.is_some()));
            crate::serial_write(" ");
            crate::serial_write_u64(u64::from(
                process_runtime().refresh_count[instance].load(Ordering::Acquire),
            ));
            crate::serial_write(" ");
            crate::serial_write_u64(table.processes.iter().flatten().count() as u64);
            crate::serial_write("\r\n");
            write_process_table(table);
        }
        valid
    });
    if valid != Some(true) {
        return false;
    }
    process_runtime().table_initialized[instance].store(false, Ordering::Release);
    process_runtime().refresh_count[instance].store(0, Ordering::Release);
    process_runtime()
        .active_instance
        .store(PROCESS_INSTANCE_NONE, Ordering::Release);
    true
}

pub(crate) fn live_process_user_namespace(pid: u32) -> Option<linux_user::UserNamespaceHandle> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let namespace = table.process(handle)?.user_namespace;
        linux_user::credentials(namespace).map(|_| namespace)
    })
    .flatten()
}

pub(crate) fn live_process_credentials(pid: u32) -> Option<linux_user::Credentials> {
    with_live_table(|table| Some(table.process(table.handle_by_pid(pid)?)?.credentials)).flatten()
}

pub(crate) fn set_live_process_credentials(pid: u32, credentials: linux_user::Credentials) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        process.credentials = credentials;
        true
    })
    .unwrap_or(false)
}

/// Runs `inspect` on the supplementary groups of `pid`, sorted. It runs
/// under the process table's lock, so it may only look at them (or copy
/// them): no copy to user memory, no lock ranked at or below the table, no
/// call back into this module.
pub(crate) fn with_live_process_groups<R>(
    pid: u32,
    inspect: impl FnOnce(&[u32]) -> R,
) -> Option<R> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        table.process(handle)?;
        Some(inspect(table.groups.get(usize::from(handle.slot))?))
    })
    .flatten()
}

/// Runs `inspect` on the root directory of `pid` (its chroot, a canonical
/// path without a leading slash; empty for the domain's root), under the
/// process table's lock as `with_live_process_groups` runs its `inspect`.
pub(crate) fn with_live_process_root<R>(pid: u32, inspect: impl FnOnce(&[u8]) -> R) -> Option<R> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        table.process(handle)?;
        Some(inspect(table.roots.get(usize::from(handle.slot))?))
    })
    .flatten()
}

/// Makes `root` the root directory of `pid` (chroot).
pub(crate) fn set_live_process_root(pid: u32, root: Vec<u8>) -> bool {
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        if table.process(handle).is_none() {
            return false;
        }
        let Some(slot) = table.roots.get_mut(usize::from(handle.slot)) else {
            return false;
        };
        *slot = root;
        true
    })
    .unwrap_or(false)
}

/// Replaces the supplementary groups of `pid` with `groups`, sorted.
pub(crate) fn set_live_process_groups(pid: u32, groups: Vec<u32>) -> bool {
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        if table.process(handle).is_none() {
            return false;
        }
        let Some(slot) = table.groups.get_mut(usize::from(handle.slot)) else {
            return false;
        };
        *slot = groups;
        true
    })
    .unwrap_or(false)
}

/// Sets the namespaces process `pid`'s next child is made in (`None`:
/// its own, as a fork's child has).
pub(crate) fn set_live_process_child_namespaces(
    pid: u32,
    namespaces: Option<linux_namespace::Set>,
) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        process.child_namespaces = namespaces;
        true
    })
    .unwrap_or(false)
}

/// Process `pid`'s UTS, IPC, PID and time namespaces.
pub(crate) fn live_process_namespaces(pid: u32) -> Option<linux_namespace::Set> {
    with_live_table(|table| Some(table.process(table.handle_by_pid(pid)?)?.namespaces)).flatten()
}

/// Moves running process `pid` to `namespaces`, then drops the ones it
/// left that nothing else uses.
pub(crate) fn set_live_process_namespaces(pid: u32, namespaces: linux_namespace::Set) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        if process.state != ProcessState::Running {
            return false;
        }
        process.namespaces = namespaces;
        table.collect_namespaces();
        true
    })
    .unwrap_or(false)
}

pub(crate) fn set_live_process_user_namespace(
    pid: u32,
    namespace: linux_user::UserNamespaceHandle,
) -> bool {
    if linux_user::credentials(namespace).is_none() {
        return false;
    }
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        let Some(process) = table.process_mut(handle) else {
            return false;
        };
        if process.state != ProcessState::Running {
            return false;
        }
        process.user_namespace = namespace;
        true
    })
    .unwrap_or(false)
}

pub(crate) fn live_process_status(pid: u32) -> Option<LiveProcessStatus> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let process = table.process(handle)?;
        let state = match process.state {
            ProcessState::Running if process.stopped_in_call => LiveProcessState::Stopped,
            ProcessState::Running if process.waiting => LiveProcessState::Sleeping,
            ProcessState::Running => LiveProcessState::Running,
            ProcessState::Stopped { .. } => LiveProcessState::Stopped,
            ProcessState::Zombie { .. } => LiveProcessState::Zombie,
            ProcessState::Preparing | ProcessState::Exiting => return None,
        };
        Some(LiveProcessStatus {
            pid: process.handle.pid,
            parent_pid: process.parent.map_or(0, |parent| parent.pid),
            state,
        })
    })
    .flatten()
}

/// Charges the CPU time since the last charge to the process that ran
/// meanwhile, at timestamp `now`. Saving a process's state charges it;
/// switching another one in starts its interval. Each CPU keeps its own
/// interval (`cpu_time::process_interval`), so the threads of one process
/// on several CPUs each add theirs, and an interval goes to the process it
/// was opened for.
pub(crate) fn charge_live_process_cpu(now: u64) {
    if let Some(interval) = crate::cpu_time::process_interval(now, true) {
        charge_process_interval(interval);
    }
}

fn charge_process_interval(interval: crate::cpu_time::ProcessInterval) {
    let _ = with_live_process(interval.pid, |process| {
        process.cpu_cycles = process.cpu_cycles.saturating_add(interval.total);
        process.user_cycles = process.user_cycles.saturating_add(interval.user);
        for (total, added) in process.task_events.iter_mut().zip(interval.events) {
            *total = total.saturating_add(added);
        }
    });
}

/// The task events of the live processes of the domain `pid` is in, the
/// open interval on this CPU included (a CPU-wide perf event's counts).
pub(crate) fn live_domain_task_events(pid: u32, now: u64) -> [u64; crate::cpu_time::TASK_EVENTS] {
    let mut events = [0_u64; crate::cpu_time::TASK_EVENTS];
    with_live_table(|table| {
        if table.handle_by_pid(pid).is_none() {
            return events;
        }
        for process in table.processes.iter().flatten() {
            for (total, added) in events.iter_mut().zip(process.task_events) {
                *total = total.saturating_add(added);
            }
        }
        if let Some(interval) = crate::cpu_time::process_interval(now, false) {
            for (total, added) in events.iter_mut().zip(interval.events) {
                *total = total.saturating_add(added);
            }
        }
        events
    })
    .unwrap_or(events)
}

/// The task events of `pid` (`cpu_time::TaskEvent`), its open interval on
/// this CPU included when `running`, and with `children` those of the
/// children it waited for.
pub(crate) fn live_process_task_events(
    pid: u32,
    running: bool,
    children: bool,
    now: u64,
) -> Option<[u64; crate::cpu_time::TASK_EVENTS]> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        let mut events = process.task_events;
        if children {
            for (total, added) in events.iter_mut().zip(process.children_task_events) {
                *total = total.saturating_add(added);
            }
        }
        if running {
            if let Some(interval) =
                crate::cpu_time::process_interval(now, false).filter(|interval| interval.pid == pid)
            {
                for (total, added) in events.iter_mut().zip(interval.events) {
                    *total = total.saturating_add(added);
                }
            }
        }
        Some(events)
    })
    .flatten()
}

/// Starts the CPU interval of process `pid`, switched in at timestamp
/// `now`; the interval open until then goes to its process.
pub(crate) fn start_live_process_cpu(pid: u32, now: u64) {
    if let Some(open) = crate::cpu_time::start_process_interval(pid, now) {
        charge_process_interval(open);
    }
}

/// When `pid` was created, in nanoseconds since boot.
pub(crate) fn live_process_started_nanoseconds(pid: u32) -> Option<u64> {
    with_live_table(|table| {
        Some(
            table
                .process(table.handle_by_pid(pid)?)?
                .started_nanoseconds,
        )
    })
    .flatten()
}

/// The CPU time `pid` has used, in timestamp-counter cycles, at `now`; for
/// the running process this includes its current interval.
pub(crate) fn live_process_cpu_cycles(pid: u32, running: bool, now: u64) -> Option<u64> {
    live_process_cpu_times(pid, running, now).map(|(user, system)| user + system)
}

/// The user and system time `pid` has used, in timestamp-counter cycles,
/// at `now`, as `live_process_cpu_cycles` counts it.
pub(crate) fn live_process_cpu_times(pid: u32, running: bool, now: u64) -> Option<(u64, u64)> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        let (mut total, mut user) = (process.cpu_cycles, process.user_cycles);
        if running {
            if let Some(interval) =
                crate::cpu_time::process_interval(now, false).filter(|interval| interval.pid == pid)
            {
                total = total.saturating_add(interval.total);
                user = user.saturating_add(interval.user);
            }
        }
        let user = user.min(total);
        Some((user, total - user))
    })
    .flatten()
}

/// The user and system time of the children `pid` waited for, theirs
/// included, in timestamp-counter cycles.
pub(crate) fn live_process_children_cpu_times(pid: u32) -> Option<(u64, u64)> {
    with_live_table(|table| Some(table.process(table.handle_by_pid(pid)?)?.children_cycles))
        .flatten()
}

/// Records whether a process waits in a blocking system call: set when it
/// gives up the CPU there, cleared when it is woken or next dispatched.
pub(crate) fn set_live_process_waiting(pid: u32, waiting: bool) {
    let _ = with_live_table(|table| {
        if let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        {
            process.waiting = waiting;
        } else {
            return;
        }
        if waiting {
            table.note_sleeper(pid);
        } else {
            table.wake_threads(pid, None);
        }
    });
}

/// Blocks thread `tid` (in thread slot `slot`) of process `pid` in its
/// system call until `wait` ends, its activation parked meanwhile
/// (docs/SCHEDULER.md, "Activations per thread"): a waker for what it
/// waits on, a signal for it or its process, or its deadline makes it due
/// to run again. The process runs on while another of its threads can.
pub(crate) fn block_live_thread(
    pid: u32,
    tid: u32,
    slot: u8,
    wait: crate::linux_wait_queue::WaitOn,
) -> bool {
    with_live_table(|table| {
        if table.handle_by_pid(pid).is_none() {
            return false;
        }
        let block = ThreadBlock {
            pid,
            tid,
            slot,
            wait,
            waiting: true,
        };
        match table
            .thread_blocks
            .iter_mut()
            .find(|block| block.pid == pid && block.tid == tid)
        {
            Some(existing) => *existing = block,
            None => {
                if table.thread_blocks.try_reserve(1).is_err() {
                    return false;
                }
                table.thread_blocks.push(block);
            }
        }
        table.blocked = true;
        table.push_sleeper(pid, wait.deadline());
        true
    })
    .unwrap_or(false)
}

/// Ends the block of thread `tid` of process `pid`, which runs again;
/// false when it had none.
pub(crate) fn take_live_thread_block(pid: u32, tid: u32) -> bool {
    with_live_table(|table| {
        let Some(index) = table
            .thread_blocks
            .iter()
            .position(|block| block.pid == pid && block.tid == tid)
        else {
            return false;
        };
        table.thread_blocks.remove(index);
        true
    })
    .unwrap_or(false)
}

/// Drops the blocks of process `pid`'s threads: thread `tid`'s, or with
/// None all of them (the threads ended).
pub(crate) fn drop_live_thread_blocks(pid: u32, tid: Option<u32>) {
    let _ = with_live_table(|table| {
        table
            .thread_blocks
            .retain(|block| block.pid != pid || tid.is_some_and(|tid| block.tid != tid));
    });
}

/// The thread of process `pid` blocked in a call whose wait is over by
/// `now` (woken, or its deadline passed), the longest blocked first.
pub(crate) fn due_live_thread(pid: u32, now: u64) -> Option<u32> {
    with_live_table(|table| {
        table
            .thread_blocks
            .iter()
            .find(|block| block.pid == pid && block.due(now))
            .map(|block| block.tid)
    })
    .flatten()
}

/// Blocks process `pid`, none of whose threads can run, as a whole: on
/// what its threads blocked in calls wait for and `others` (what its
/// threads that waited the old way wait for). Unless one of those blocked
/// threads is due by `now` already (woken while its sibling ran, or past
/// its deadline): the process then stays ready, to resume it.
pub(crate) fn block_live_process_threads(
    pid: u32,
    others: crate::linux_wait_queue::WaitOn,
    now: u64,
) {
    let _ = with_live_table(|table| {
        let mut wait = others;
        for block in table.thread_blocks.iter().filter(|block| block.pid == pid) {
            if block.due(now) {
                return;
            }
            wait = wait.and(block.wait);
        }
        table.block_process(pid, wait);
    });
}

/// Makes thread `tid` of process `pid` due to run if it is blocked, and
/// its process ready: a futex wake of its record.
pub(crate) fn wake_live_thread(pid: u32, tid: u32) {
    let _ = with_live_table(|table| {
        for block in table
            .thread_blocks
            .iter_mut()
            .filter(|block| block.pid == pid && block.tid == tid)
        {
            block.waiting = false;
        }
        if let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        {
            process.waiting = false;
        }
    });
}

/// What process `pid` is blocked on, if it is (waiting, not yet woken).
pub(crate) fn live_process_block(pid: u32) -> Option<crate::linux_wait_queue::WaitOn> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        process.block.filter(|_| process.waiting)
    })
    .flatten()
}

/// Makes every process blocked in a wait that event `events` on `key` ends
/// ready again (None: every key); returns how many it woke.
pub(crate) fn wake_live_processes(events: u16, key: Option<u64>) -> u32 {
    with_live_table(|table| {
        if !table.blocked {
            return 0;
        }
        let mut woken = 0;
        let mut blocked = false;
        for index in 0..table.thread_blocks.len() {
            let block = table.thread_blocks[index];
            if !block.waiting {
                continue;
            }
            if block.wait.woken_by(events, key) {
                table.thread_blocks[index].waiting = false;
                if let Some(process) = table
                    .handle_by_pid(block.pid)
                    .and_then(|handle| table.process_mut(handle))
                {
                    process.waiting = false;
                }
                woken += 1;
            } else {
                blocked = true;
            }
        }
        for process in table.processes.iter_mut().flatten() {
            let Some(block) = process.block.filter(|_| process.waiting) else {
                continue;
            };
            if block.woken_by(events, key) {
                process.waiting = false;
                woken += 1;
            } else {
                blocked = true;
            }
        }
        table.blocked = blocked;
        woken
    })
    .unwrap_or(0)
}

/// Makes every blocked process ready again, to look at its wait once more:
/// what woke them may have been missed (a domain resumed after other
/// domains ran, whose events this one's scheduler never saw).
pub(crate) fn wake_all_live_processes() -> u32 {
    wake_live_processes(u16::MAX, None)
}

/// Whether process `pid` is parked asleep with its block's deadline passed
/// by `now`: due to run, to find its wait over.
pub(crate) fn live_process_sleep_due(pid: u32, now: u64) -> bool {
    with_live_table(|table| {
        table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .and_then(Process::marked_asleep_until)
            .is_some_and(|deadline| deadline <= now)
    })
    .unwrap_or(false)
}

/// The earliest deadline a process marked asleep in a wait of its own
/// (`Process::is_asleep`) is due at, passed already or not: a CPU that
/// halts until its next tick would resume it late, and one that halts with
/// it due (its deadline came between the look for work and the halt) a
/// whole tick late.
pub(crate) fn next_live_block_deadline() -> Option<u64> {
    with_live_table(|table| {
        if table.sleepers_lossy {
            table.rebuild_sleepers();
        }
        if table.sleepers_lossy {
            return table
                .processes
                .iter()
                .flatten()
                .filter_map(|process| process.marked_asleep_until())
                .chain(
                    table
                        .thread_blocks
                        .iter()
                        .filter_map(ThreadBlock::marked_until),
                )
                .min();
        }
        let mut sleepers = core::mem::take(&mut table.sleepers);
        let earliest = sleepers.earliest(|pid, deadline| table.sleeper_holds(pid, deadline));
        table.sleepers = sleepers;
        earliest.map(|(deadline, _)| deadline)
    })
    .flatten()
}

impl ProcessTable {
    /// Blocks process `pid` in its system call until `wait` ends: it waits
    /// (`set_live_process_waiting`) and the scheduler passes over it until a
    /// waker, a signal or the wait's deadline makes it ready again.
    fn block_process(&mut self, pid: u32, wait: crate::linux_wait_queue::WaitOn) {
        if let Some(process) = self
            .handle_by_pid(pid)
            .and_then(|handle| self.process_mut(handle))
        {
            process.waiting = true;
            process.block = Some(wait);
        } else {
            return;
        }
        self.blocked = true;
        self.note_sleeper(pid);
    }

    /// Records `pid`'s deadline if it is now marked asleep (both its mark
    /// and its `waiting`, which are set apart, hold), dropping the entries
    /// no longer marked once they outnumber the processes.
    fn note_sleeper(&mut self, pid: u32) {
        let Some(deadline) = self
            .handle_by_pid(pid)
            .and_then(|handle| self.process(handle))
            .and_then(Process::marked_asleep_until)
        else {
            return;
        };
        self.push_sleeper(pid, deadline);
    }

    /// Records deadline `deadline` (0: none) of a block of `pid`'s or of
    /// one of its threads'.
    fn push_sleeper(&mut self, pid: u32, deadline: u64) {
        if self.sleepers_lossy || deadline == 0 {
            return;
        }
        if self.sleepers.len() >= 2 * self.pid_slots.len() + self.thread_blocks.len() + 64 {
            let mut sleepers = core::mem::take(&mut self.sleepers);
            sleepers.retain(|pid, deadline| self.sleeper_holds(pid, deadline));
            self.sleepers = sleepers;
        }
        if self.sleepers.push(deadline, pid).is_err() {
            self.sleepers.clear();
            self.sleepers_lossy = true;
        }
    }

    /// Whether `pid`, or a thread of it, is still marked asleep until
    /// `deadline`.
    fn sleeper_holds(&self, pid: u32, deadline: u64) -> bool {
        self.handle_by_pid(pid)
            .and_then(|handle| self.process(handle))
            .and_then(Process::marked_asleep_until)
            == Some(deadline)
            || self
                .thread_blocks
                .iter()
                .any(|block| block.pid == pid && block.marked_until() == Some(deadline))
    }

    /// Puts every current mark back after an allocation failure lost some.
    fn rebuild_sleepers(&mut self) {
        let mut sleepers = linox_deadline_heap::DeadlineHeap::new();
        for process in self.processes.iter().flatten() {
            if let Some(deadline) = process.marked_asleep_until() {
                if sleepers.push(deadline, process.handle.pid).is_err() {
                    return;
                }
            }
        }
        for block in &self.thread_blocks {
            if let Some(deadline) = block.marked_until() {
                if sleepers.push(deadline, block.pid).is_err() {
                    return;
                }
            }
        }
        self.sleepers = sleepers;
        self.sleepers_lossy = false;
    }
}

impl ThreadBlock {
    /// The deadline the thread is blocked until, if it is.
    fn marked_until(&self) -> Option<u64> {
        Some(self.wait.deadline()).filter(|deadline| self.waiting && *deadline != 0)
    }
}

impl Process {
    /// The deadline the process is blocked until, if it is: running,
    /// waiting, with a deadline to its block.
    fn marked_asleep_until(&self) -> Option<u64> {
        (self.state == ProcessState::Running && self.waiting)
            .then_some(self.block)
            .flatten()
            .map(|block| block.deadline())
            .filter(|deadline| *deadline != 0)
    }

    /// Blocked in a wait that no wake (which clears `waiting`), signal it
    /// takes (likewise) or deadline has ended by `now`.
    fn is_asleep(&self, now: u64) -> bool {
        self.waiting
            && self.block.is_some_and(|block| {
                let deadline = block.deadline();
                deadline == 0 || now < deadline
            })
    }
}

/// POSIX timers per process (timer_create); Linux allows far more, this
/// table is fixed like the rest of the process record.
pub(crate) const POSIX_TIMER_LIMIT: usize = 16;

/// A POSIX interval timer of a process. Deadlines are the monotonic
/// nanoseconds `linux_elapsed_nanoseconds` counts (wall-clock values are
/// converted at timer_settime), 0 while disarmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PosixTimer {
    pub(crate) clock: u32,
    /// SIGEV_SIGNAL (0), SIGEV_NONE (1) or SIGEV_THREAD_ID (4).
    pub(crate) notify: u32,
    pub(crate) signal: u8,
    /// The thread a SIGEV_THREAD_ID timer signals, else 0.
    pub(crate) tid: u32,
    /// sigev_value, delivered as si_value.
    pub(crate) value: u64,
    pub(crate) deadline: u64,
    pub(crate) interval: u64,
    /// Expirations the queued signal stands for beyond its own, counted on
    /// while the signal stays pending (DELAYTIMER_MAX saturates it).
    pub(crate) overrun: u32,
    /// The overrun of the last signal delivered (timer_getoverrun).
    pub(crate) delivered_overrun: u32,
}

/// Notes the delivery of `signal` with `value` to `pid`: the overrun the
/// timer that queued it counted is what timer_getoverrun reports from now
/// on, as Linux freezes it at delivery (timer_settime03 reads it in the
/// handler).
pub(crate) fn note_posix_timer_delivery(pid: u32, signal: u8, value: u64) {
    let _ = with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return;
        };
        for timer in process.posix_timers.iter_mut().flatten() {
            if timer.signal == signal && timer.value == value {
                timer.delivered_overrun = timer.overrun;
            }
        }
    });
}

/// What an expired timer delivers.
#[derive(Clone, Copy)]
pub(crate) struct PosixTimerExpiry {
    pub(crate) notify: u32,
    pub(crate) signal: u8,
    pub(crate) tid: u32,
    pub(crate) value: u64,
    /// An interval timer's (setitimer): its signal comes from the kernel
    /// (SI_KERNEL), not a POSIX timer (SI_TIMER).
    pub(crate) interval_timer: bool,
}

/// The most expiries one check reports: every POSIX timer, both CPU
/// interval timers and the two RLIMIT_CPU limits.
pub(crate) const TIMER_EXPIRY_LIMIT: usize = POSIX_TIMER_LIMIT + 4;

impl PosixTimerExpiry {
    pub(crate) const NONE: Self = Self {
        notify: 0,
        signal: 0,
        tid: 0,
        value: 0,
        interval_timer: false,
    };
}

/// Creates a POSIX timer for `pid`: its id, from 1, the first free one.
pub(crate) fn create_posix_timer(pid: u32, timer: PosixTimer) -> Option<u32> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let process = table.process_mut(handle)?;
        let index = process.posix_timers.iter().position(Option::is_none)?;
        process.posix_timers[index] = Some(timer);
        Some(index as u32 + 1)
    })
    .flatten()
}

/// Timer `id` of `pid`.
pub(crate) fn posix_timer(pid: u32, id: u32) -> Option<PosixTimer> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let process = table.process(handle)?;
        let index = usize::try_from(id.checked_sub(1)?).ok()?;
        process.posix_timers.get(index).copied().flatten()
    })
    .flatten()
}

/// Changes timer `id` of `pid` with `change`; None without such a timer.
/// `change` runs under the process table's lock: it only sets fields.
pub(crate) fn update_posix_timer(
    pid: u32,
    id: u32,
    change: impl FnOnce(&mut PosixTimer),
) -> Option<PosixTimer> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let process = table.process_mut(handle)?;
        let index = usize::try_from(id.checked_sub(1)?).ok()?;
        let timer = process.posix_timers.get_mut(index)?.as_mut()?;
        change(timer);
        Some(*timer)
    })
    .flatten()
}

/// Deletes timer `id` of `pid`.
pub(crate) fn delete_posix_timer(pid: u32, id: u32) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        let Some(index) = id
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
        else {
            return false;
        };
        match process.posix_timers.get_mut(index) {
            Some(slot @ Some(_)) => {
                *slot = None;
                true
            }
            _ => false,
        }
    })
    .unwrap_or(false)
}

/// The earliest armed deadline among `pid`'s timers, 0 with none armed.
pub(crate) fn earliest_posix_timer_deadline(pid: u32) -> u64 {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
        else {
            return 0;
        };
        process
            .posix_timers
            .iter()
            .chain(process.itimers.iter())
            .flatten()
            .map(|timer| timer.deadline)
            .filter(|deadline| *deadline != 0)
            .min()
            .unwrap_or(0)
    })
    .unwrap_or(0)
}

/// Expires `pid`'s timers whose deadline passed by `now`: a periodic one
/// moves on past `now` (the expirations in between are its overrun), a
/// one-shot one disarms. Lists what each delivers. `pending` is the mask
/// of signals the process has pending: a timer whose signal is still
/// queued counts these expirations on its overrun instead of queueing
/// again, as Linux does until the signal is delivered.
/// Whether a POSIX timer's clock counts CPU time: CLOCK_PROCESS_CPUTIME_ID,
/// CLOCK_THREAD_CPUTIME_ID, or a clock id clock_getcpuclockid or
/// pthread_getcpuclockid made (negative). Its deadlines are CPU nanoseconds.
pub(crate) fn posix_clock_is_cpu(clock: u32) -> bool {
    matches!(clock, 2 | 3) || (clock as i32) < 0
}

/// Whether a CPU clock counts one thread's time (CLOCK_THREAD_CPUTIME_ID,
/// or a pthread_getcpuclockid id: bit 2 set).
pub(crate) fn posix_clock_is_thread_cpu(clock: u32) -> bool {
    clock == 3 || (clock as i32) < 0 && clock & 4 != 0
}

/// setitimer's ITIMER_VIRTUAL (`which` 1) or ITIMER_PROF (2) of `pid`:
/// its interval and its deadline on the process CPU clock (0: disarmed).
pub(crate) fn live_process_interval_timer(pid: u32, which: usize) -> Option<(u64, u64)> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        let timer = process.itimers.get(which.checked_sub(1)?)?;
        Some(timer.map_or((0, 0), |timer| (timer.interval, timer.deadline)))
    })
    .flatten()
}

/// Arms (`deadline` nonzero, on the process CPU clock) or disarms
/// `pid`'s ITIMER_VIRTUAL or ITIMER_PROF, which sends `signal`.
pub(crate) fn set_live_process_interval_timer(
    pid: u32,
    which: usize,
    signal: u8,
    (interval, deadline): (u64, u64),
) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        let Some(timer) = which
            .checked_sub(1)
            .and_then(|index| process.itimers.get_mut(index))
        else {
            return false;
        };
        // CLOCK_PROCESS_CPUTIME_ID, signalled as SIGEV_SIGNAL.
        *timer = (deadline != 0).then_some(PosixTimer {
            clock: 2,
            notify: 0,
            signal,
            tid: 0,
            value: 0,
            deadline,
            interval,
            overrun: 0,
            delivered_overrun: 0,
        });
        true
    })
    .unwrap_or(false)
}

/// Fires process `pid`'s timers whose deadline passed: `now` on the
/// monotonic clock, `cpu_now` the process's CPU time, for timers on a CPU
/// clock (timer_settime01).
pub(crate) fn expire_posix_timers(
    pid: u32,
    (monotonic_now, cpu_now, thread_now): (u64, u64, u64),
    pending: u64,
    expiries: &mut [PosixTimerExpiry; TIMER_EXPIRY_LIMIT],
) -> usize {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return 0;
        };
        let mut count = 0;
        let posix_count = process.posix_timers.len();
        for (index, timer) in process
            .posix_timers
            .iter_mut()
            .chain(process.itimers.iter_mut())
            .enumerate()
            .filter_map(|(index, timer)| Some((index, timer.as_mut()?)))
        {
            let now = if posix_clock_is_thread_cpu(timer.clock) {
                thread_now
            } else if posix_clock_is_cpu(timer.clock) {
                cpu_now
            } else {
                monotonic_now
            };
            if timer.deadline == 0 || now < timer.deadline {
                continue;
            }
            let expirations = match (now - timer.deadline).checked_div(timer.interval) {
                // A one-shot timer (no interval) disarms.
                None => {
                    timer.deadline = 0;
                    1
                }
                Some(missed) => {
                    timer.deadline = timer
                        .deadline
                        .saturating_add((missed + 1).saturating_mul(timer.interval));
                    missed + 1
                }
            };
            let overrun = u32::try_from(expirations - 1).unwrap_or(u32::MAX);
            if timer.signal != 0 && pending & (1_u64 << (timer.signal - 1)) != 0 {
                timer.overrun = timer.overrun.saturating_add(overrun).saturating_add(1);
                continue;
            }
            timer.overrun = overrun;
            expiries[count] = PosixTimerExpiry {
                notify: timer.notify,
                signal: timer.signal,
                tid: timer.tid,
                value: timer.value,
                interval_timer: index >= posix_count,
            };
            count += 1;
        }
        count
    })
    .unwrap_or(0)
}

pub(crate) fn live_process_cpu_affinity(pid: u32) -> Option<u64> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let process = table.process(handle)?;
        matches!(
            process.state,
            ProcessState::Running | ProcessState::Stopped { .. } | ProcessState::Zombie { .. }
        )
        .then_some(process.cpu_affinity)
    })
    .flatten()
}

/// Stops process `pid` with stop signal `signal` (SIGSTOP, SIGTSTP, SIGTTIN
/// or SIGTTOU): its parent's wait (WUNTRACED) reports it. `in_call` for a
/// process parking in its kill call until SIGCONT; otherwise the scheduler
/// no longer dispatches it. False unless it was running.
pub(crate) fn stop_live_process(pid: u32, signal: u8, in_call: bool) -> bool {
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        table.stop(handle, signal, in_call)
    })
    .unwrap_or(false)
}

/// Whether process `pid` is stopped (by a stop signal, until SIGCONT).
pub(crate) fn live_process_stopped(pid: u32) -> bool {
    live_process_status(pid).is_some_and(|status| status.state == LiveProcessState::Stopped)
}

/// Continues stopped process `pid` (SIGCONT): it runs again, and its
/// parent's wait (WCONTINUED) reports it. False unless it was stopped.
pub(crate) fn continue_live_process(pid: u32) -> bool {
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        table.continue_process(handle)
    })
    .unwrap_or(false)
}

/// Set in a process's policy byte by SCHED_RESET_ON_FORK: its children
/// start with SCHED_OTHER and priority 0.
pub(crate) const SCHED_RESET_ON_FORK: u8 = 0x80;

/// sched_getscheduler and sched_getparam: `pid`'s policy and priority.
pub(crate) fn live_process_scheduling(pid: u32) -> Option<(u8, u8)> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        matches!(
            process.state,
            ProcessState::Running | ProcessState::Stopped { .. } | ProcessState::Zombie { .. }
        )
        .then_some(process.scheduling)
    })
    .flatten()
}

/// sched_setscheduler: gives `pid` `policy` and `priority`.
pub(crate) fn set_live_process_scheduling(pid: u32, policy: u8, priority: u8) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        if !matches!(
            process.state,
            ProcessState::Running | ProcessState::Stopped { .. }
        ) {
            return false;
        }
        process.scheduling = (policy, priority);
        true
    })
    .unwrap_or(false)
}

/// Linux's timer slack for a new process, in nanoseconds.
pub(crate) const DEFAULT_TIMER_SLACK: u64 = 50_000;

/// prctl(PR_GET_TIMERSLACK): `pid`'s current timer slack.
/// Why a seccomp filter was not installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeccompError {
    /// No such live process.
    NoProcess,
    /// The chain would pass MAX_INSNS_PER_PATH, or no memory (ENOMEM).
    NoMemory,
}

impl ProcessTable {
    /// Adds `program` in front of `pid`'s filters. Filters no process
    /// reaches any more (their processes exited) are freed first.
    fn install_seccomp_filter(
        &mut self,
        pid: u32,
        program: linox_seccomp::Program,
    ) -> Result<(), SeccompError> {
        let handle = self.handle_by_pid(pid).ok_or(SeccompError::NoProcess)?;
        let previous = self
            .process(handle)
            .ok_or(SeccompError::NoProcess)?
            .seccomp_filter;
        let path_instructions = self
            .seccomp_filter(previous)
            .map_or(0, |filter| filter.path_instructions)
            .saturating_add(program.len() + 4);
        if path_instructions > SECCOMP_PATH_LIMIT {
            return Err(SeccompError::NoMemory);
        }
        self.free_unreached_seccomp_filters();
        let filter = SeccompFilter {
            program,
            previous,
            path_instructions,
        };
        let index = match self.seccomp_filters.iter().position(Option::is_none) {
            Some(index) => {
                self.seccomp_filters[index] = Some(filter);
                index
            }
            None => {
                self.seccomp_filters
                    .try_reserve(1)
                    .map_err(|_| SeccompError::NoMemory)?;
                self.seccomp_filters.push(Some(filter));
                self.seccomp_filters.len() - 1
            }
        };
        let id = u32::try_from(index + 1).map_err(|_| SeccompError::NoMemory)?;
        self.process_mut(handle)
            .ok_or(SeccompError::NoProcess)?
            .seccomp_filter = id;
        Ok(())
    }

    fn seccomp_filter(&self, id: u32) -> Option<&SeccompFilter> {
        self.seccomp_filters
            .get(usize::try_from(id).ok()?.checked_sub(1)?)?
            .as_ref()
    }

    /// Frees the filters no process's chain reaches.
    fn free_unreached_seccomp_filters(&mut self) {
        let mut reached = Vec::new();
        if reached
            .try_reserve_exact(self.seccomp_filters.len())
            .is_err()
        {
            return;
        }
        reached.resize(self.seccomp_filters.len(), false);
        for process in self.processes.iter().flatten() {
            let mut id = process.seccomp_filter;
            while let Some(filter) = self.seccomp_filter(id) {
                let index = id as usize - 1;
                if reached[index] {
                    break;
                }
                reached[index] = true;
                id = filter.previous;
            }
        }
        for (slot, reached) in self.seccomp_filters.iter_mut().zip(reached) {
            if !reached {
                *slot = None;
            }
        }
    }

    /// The strictest return value of `pid`'s filters for `data`, or None
    /// when it has none.
    fn seccomp_return(&self, pid: u32, data: &linox_seccomp::Data) -> Option<u32> {
        let mut id = self.process(self.handle_by_pid(pid)?)?.seccomp_filter;
        let mut result = None;
        while let Some(filter) = self.seccomp_filter(id) {
            let value = filter.program.run(data);
            result = Some(result.map_or(value, |old| linox_seccomp::strictest(old, value)));
            id = filter.previous;
        }
        result
    }
}

/// seccomp(SECCOMP_SET_MODE_FILTER) for `pid`.
pub(crate) fn install_live_process_seccomp_filter(
    pid: u32,
    program: linox_seccomp::Program,
) -> Result<(), SeccompError> {
    with_live_table(|table| table.install_seccomp_filter(pid, program))
        .ok_or(SeccompError::NoProcess)?
}

/// What `pid`'s seccomp filters return for a system call, or None without
/// filters.
pub(crate) fn live_process_seccomp_return(pid: u32, data: &linox_seccomp::Data) -> Option<u32> {
    with_live_table(|table| table.seccomp_return(pid, data)).flatten()
}

pub(crate) fn live_process_timer_slack(pid: u32) -> Option<u64> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        matches!(
            process.state,
            ProcessState::Running | ProcessState::Stopped { .. }
        )
        .then_some(process.timer_slack.0)
    })
    .flatten()
}

/// prctl(PR_SET_TIMERSLACK): 0 restores the process's default.
pub(crate) fn set_live_process_timer_slack(pid: u32, slack: u64) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        if !matches!(
            process.state,
            ProcessState::Running | ProcessState::Stopped { .. }
        ) {
            return false;
        }
        process.timer_slack.0 = if slack == 0 {
            process.timer_slack.1
        } else {
            slack
        };
        true
    })
    .unwrap_or(false)
}

/// A process's I/O as `/proc/PID/io` counts it (Linux's task_io_accounting):
/// bytes passed by read and write calls and how many such calls it made,
/// and the bytes its file I/O read from and wrote to storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct IoAccounting {
    pub(crate) rchar: u64,
    pub(crate) wchar: u64,
    pub(crate) syscr: u64,
    pub(crate) syscw: u64,
    pub(crate) read_bytes: u64,
    pub(crate) write_bytes: u64,
    pub(crate) cancelled_write_bytes: u64,
}

/// The I/O process `pid` did (`/proc/PID/io`).
pub(crate) fn live_process_io(pid: u32) -> Option<IoAccounting> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        Some(process.io)
    })
    .flatten()
}

/// Adds to the I/O counts of process `pid`; `account` runs under the
/// process table's lock and only adds.
pub(crate) fn account_live_process_io(pid: u32, account: impl FnOnce(&mut IoAccounting)) {
    // `account` only adds to the counts.
    let _ = with_live_process(pid, |process| account(&mut process.io));
}

pub(crate) fn live_process_oom_score_adj(pid: u32) -> Option<i16> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        matches!(
            process.state,
            ProcessState::Running | ProcessState::Stopped { .. } | ProcessState::Zombie { .. }
        )
        .then_some(process.oom_score_adj)
    })
    .flatten()
}

/// Whether `pid` is marked a child subreaper (PR_GET_CHILD_SUBREAPER).
pub(crate) fn live_process_child_subreaper(pid: u32) -> Option<bool> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        Some(process.child_subreaper)
    })
    .flatten()
}

/// Marks `pid` a child subreaper or not (PR_SET_CHILD_SUBREAPER).
pub(crate) fn set_live_process_child_subreaper(pid: u32, marked: bool) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        process.child_subreaper = marked;
        true
    })
    .unwrap_or(false)
}

/// The memory policy of `pid` (set_mempolicy).
pub(crate) fn live_process_memory_policy(pid: u32) -> Option<crate::linux_areas::Policy> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        Some(process.memory_policy)
    })
    .flatten()
}

/// Sets the memory policy of `pid` (set_mempolicy).
pub(crate) fn set_live_process_memory_policy(pid: u32, policy: crate::linux_areas::Policy) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        process.memory_policy = policy;
        true
    })
    .unwrap_or(false)
}

/// Records that a signal's default action is terminating `pid`, so its
/// parent's wait reports it as killed by that signal rather than as an exit.
pub(crate) fn set_live_process_killed_by_signal(pid: u32, signal: u8) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        process.killed_by_signal = signal;
        true
    })
    .unwrap_or(false)
}

/// Sets `/proc/PID/oom_score_adj`; the caller has checked the Linux range
/// -1000..=1000.
pub(crate) fn set_live_process_oom_score_adj(pid: u32, value: i16) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        if !matches!(
            process.state,
            ProcessState::Running | ProcessState::Stopped { .. }
        ) {
            return false;
        }
        process.oom_score_adj = value;
        true
    })
    .unwrap_or(false)
}

pub(crate) fn set_live_process_cpu_affinity(pid: u32, mask: u64) -> bool {
    if mask == 0 {
        return false;
    }
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        let Some(process) = table.process_mut(handle) else {
            return false;
        };
        if !matches!(
            process.state,
            ProcessState::Running | ProcessState::Stopped { .. }
        ) {
            return false;
        }
        process.cpu_affinity = mask;
        process.scheduler_thread.is_none_or(|thread| {
            scheduler::active_process_scheduler_workspace()
                .is_some_and(|run_queue| run_queue.set_affinity(thread, mask))
        })
    })
    .unwrap_or(false)
}

/// Lets only CPU `cpu` run process `pid` (`Some`), or again the CPUs its
/// affinity names (`None`): for a CPU that made the process ready but will
/// switch back to it, such as the parent of the fork it runs, so that no
/// other CPU takes it meanwhile. Its affinity as the process sees it does
/// not change.
pub(crate) fn pin_live_process(pid: u32, cpu: Option<usize>) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
        else {
            return false;
        };
        let mask = cpu.map_or(process.cpu_affinity, |cpu| 1_u64 << cpu);
        process.scheduler_thread.is_none_or(|thread| {
            scheduler::active_process_scheduler_workspace()
                .is_some_and(|run_queue| run_queue.set_affinity(thread, mask))
        })
    })
    .unwrap_or(false)
}

pub(crate) fn set_live_process_scheduler_nice(pid: u32, nice: u8) -> bool {
    if nice > 39 {
        return false;
    }
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        let Some(thread) = table
            .process(handle)
            .and_then(|process| process.scheduler_thread)
        else {
            return true;
        };
        let Some(run_queue) = scheduler::active_process_scheduler_workspace() else {
            return false;
        };
        run_queue.set_priority(thread, 39_i8 - nice as i8)
    })
    .unwrap_or(false)
}

/// The pid of the process tracing `pid` (ptrace), if one is.
pub(crate) fn live_process_tracer(pid: u32) -> Option<u32> {
    with_live_table(|table| {
        let tracer = table.process(table.handle_by_pid(pid)?)?.tracer;
        (tracer != 0).then_some(tracer)
    })
    .flatten()
}

/// Makes `tracer` (0: none) trace `pid`, clearing any resume signal.
pub(crate) fn set_live_process_tracer(pid: u32, tracer: u32) -> bool {
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        let Some(process) = table.process_mut(handle) else {
            return false;
        };
        process.tracer = tracer;
        process.ptrace_resume_signal = 0;
        true
    })
    .unwrap_or(false)
}

/// Records the signal a tracee delivers as it resumes (PTRACE_CONT).
pub(crate) fn set_live_process_ptrace_resume_signal(pid: u32, signal: u8) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        process.ptrace_resume_signal = signal;
        true
    })
    .unwrap_or(false)
}

/// Takes the signal a tracee resuming from its trace stop delivers.
pub(crate) fn take_live_process_ptrace_resume_signal(pid: u32) -> u8 {
    with_live_process(pid, |process| {
        core::mem::take(&mut process.ptrace_resume_signal)
    })
    .unwrap_or(0)
}

/// Marks (or, taking it, reads and clears) that the tracee's next signal
/// delivery is the one its tracer let through, which does not stop again.
pub(crate) fn set_live_process_ptrace_bypass(pid: u32, bypass: bool) {
    let _ = with_live_process(pid, |process| {
        process.ptrace_bypass = bypass;
    });
}

/// Tracee `pid`'s debug register `index` (PTRACE_PEEKUSER).
pub(crate) fn live_process_debug_register(pid: u32, index: usize) -> Option<u64> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        Some(process.debug_registers.read(index))
    })
    .flatten()
}

/// Writes tracee `pid`'s debug register `index` (PTRACE_POKEUSER); None
/// for no such process.
pub(crate) fn set_live_process_debug_register(
    pid: u32,
    index: usize,
    value: u64,
) -> Option<Result<(), DebugRegisterError>> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let process = table.process_mut(handle)?;
        Some(process.debug_registers.write(index, value))
    })
    .flatten()
}

pub(crate) fn take_live_process_ptrace_bypass(pid: u32) -> bool {
    with_live_process(pid, |process| core::mem::take(&mut process.ptrace_bypass)).unwrap_or(false)
}

pub(crate) fn live_process_parent_pid(pid: u32) -> Option<u32> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let process = table.process(handle)?;
        Some(
            process
                .parent
                .and_then(|parent| table.process(parent).map(|parent| parent.handle.pid))
                .unwrap_or(0),
        )
    })
    .flatten()
}

pub(crate) fn live_running_child_pid(parent_pid: u32) -> Option<u32> {
    with_live_table(|table| {
        let parent = table.handle_by_pid(parent_pid)?;
        table
            .processes
            .iter()
            .flatten()
            .find(|process| {
                process.parent == Some(parent) && process.state == ProcessState::Running
            })
            .map(|process| process.handle.pid)
    })
    .flatten()
}

/// Whether a child of `parent_pid` can run: running and not waiting in a
/// system call.
pub(crate) fn live_runnable_child_exists(parent_pid: u32) -> bool {
    with_live_table(|table| {
        table.handle_by_pid(parent_pid).is_some_and(|parent| {
            table.processes.iter().flatten().any(|process| {
                process.parent == Some(parent)
                    && process.state == ProcessState::Running
                    && !process.waiting
            })
        })
    })
    .unwrap_or(false)
}

pub(crate) fn live_process_group(pid: u32) -> Option<u32> {
    with_live_table(|table| table.process_group(pid))
        .flatten()
        .map(|group| group.0)
}

pub(crate) fn live_process_session(pid: u32) -> Option<u32> {
    with_live_table(|table| table.process_group(pid))
        .flatten()
        .map(|group| group.1)
}

pub(crate) fn set_live_process_group(
    caller_pid: u32,
    target_pid: u32,
    process_group: u32,
) -> Result<(), ProcessGroupError> {
    with_live_table(|table| table.set_process_group(caller_pid, target_pid, process_group))
        .ok_or(ProcessGroupError::NoSuchProcess)?
}

pub(crate) fn create_live_process_session(pid: u32) -> Result<u32, ProcessGroupError> {
    with_live_table(|table| table.create_session(pid)).ok_or(ProcessGroupError::NoSuchProcess)?
}

pub(crate) fn mark_live_process_executed(pid: u32) -> bool {
    with_live_table(|table| table.mark_executed(pid)).unwrap_or(false)
}

pub(crate) fn set_live_process_exec_context(pid: u32, rip: u64, rsp: u64) -> bool {
    with_live_table(|table| table.set_exec_context(pid, rip, rsp)).unwrap_or(false)
}

/// Makes the process in table slot `slot` ready if it waits in a call: a
/// signal was queued for it (for its thread in thread slot `thread`),
/// which ends any wait (or is looked at and the call waits on). A signal
/// for the process ends every thread's block, since any thread that does
/// not block it may take it.
pub(crate) fn wake_live_process_at_slot(slot: usize, thread: Option<u8>) {
    let _ = with_live_table(|table| {
        let Some(process) = table.processes.get_mut(slot).and_then(Option::as_mut) else {
            return;
        };
        process.waiting = false;
        let pid = process.handle.pid;
        table.wake_threads(pid, thread);
    });
}

pub(crate) fn live_process_slot(pid: u32) -> Option<usize> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        Some(usize::from(handle.slot))
    })
    .flatten()
}

pub(crate) fn live_process_runtime_slot(pid: u32) -> Option<usize> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        table.process(handle)?.runtime_slot.map(usize::from)
    })
    .flatten()
}

pub(crate) fn release_live_process_runtime_slot(pid: u32) -> bool {
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        let Some(process) = table.process_mut(handle) else {
            return false;
        };
        if !matches!(process.state, ProcessState::Zombie { .. }) || process.runtime_slot.is_none() {
            return false;
        }
        let slot = process.runtime_slot.take();
        // Give back the slot's lists: a large process's are many megabytes and
        // would otherwise stay until another process takes the slot.
        let referenced = table.processes.iter().flatten().any(|process| {
            process.runtime_slot == slot
                || [process.address_space, process.retiring_address_space]
                    .into_iter()
                    .flatten()
                    .any(|space| Some(space.storage_slot) == slot)
        });
        if let (false, Some(slot)) = (referenced, slot) {
            if let Some(storage) = table.spaces.slot_mut(usize::from(slot)) {
                *storage = ProcessAddressSpaceStorage::default();
            }
        }
        true
    })
    .unwrap_or(false)
}

pub(crate) fn live_process_generation(pid: u32) -> Option<u32> {
    with_live_table(|table| Some(table.handle_by_pid(pid)?.generation)).flatten()
}

/// How many slots the process table has now (`live_process_pid_at` is
/// None at and past them).
pub(crate) fn live_process_slots() -> usize {
    with_live_table(|table| table.processes.len()).unwrap_or(0)
}

pub(crate) fn live_process_pid_at(slot: usize) -> Option<u32> {
    with_live_table(|table| {
        table
            .processes
            .get(slot)?
            .as_ref()
            .map(|process| process.handle.pid)
    })
    .flatten()
}

/// The smallest pid at least `from` of a process in the table, as /proc
/// lists them (zombies included, processes still being made or ended not).
pub(crate) fn next_live_pid(from: u32) -> Option<u32> {
    with_live_table(|table| {
        let start = table.pid_slots.partition_point(|(pid, _)| *pid < from);
        table.pid_slots[start..].iter().find_map(|(pid, slot)| {
            table
                .processes
                .get(usize::from(*slot))?
                .as_ref()
                .filter(|process| {
                    process.handle.pid == *pid
                        && !matches!(
                            process.state,
                            ProcessState::Preparing | ProcessState::Exiting
                        )
                })
                .map(|_| *pid)
        })
    })
    .flatten()
}

pub(crate) fn live_process_count() -> Option<u16> {
    with_live_table(|table| {
        table
            .processes
            .iter()
            .filter(|process| process.is_some())
            .count()
            .try_into()
            .ok()
    })
    .flatten()
}

pub(crate) fn host_live_process_count() -> Option<u16> {
    let mut count = 0_usize;
    for (instance, initialized) in process_runtime().table_initialized.iter().enumerate() {
        if initialized.load(Ordering::Acquire) {
            let processes = PROCESS_TABLES[instance]
                .lock()
                .processes
                .iter()
                .filter(|process| process.is_some())
                .count();
            count = count.checked_add(processes)?;
        }
    }
    count.try_into().ok()
}

pub(crate) fn live_process_mapping(
    pid: u32,
    address: usize,
) -> Option<cpu::LinuxActiveImageMapping> {
    // A stale list lacks pages mapped since its snapshot; the live page
    // tables have them, walked with the table's lock released.
    enum Found {
        Listed(Option<cpu::LinuxActiveImageMapping>),
        Stale(memory::FrameLease),
    }
    let found = with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let space = table.process(handle)?.address_space?;
        if space.stale {
            return Some(Found::Stale(space.root(&table.spaces)));
        }
        Some(Found::Listed(
            space
                .mappings(&table.spaces)
                .iter()
                .copied()
                .find(|mapping| mapping.address == address),
        ))
    })
    .flatten()?;
    match found {
        Found::Listed(mapping) => mapping,
        Found::Stale(root) => address_space::linux_active_mapping_in_root(root, address as u64),
    }
}

/// Takes the next process ID for a new thread, so thread and process IDs
/// never repeat each other, as in Linux's shared PID space.
pub(crate) fn allocate_live_thread_id() -> Option<u32> {
    with_live_table(|table| {
        let tid = table.next_pid;
        table.next_pid = tid.checked_add(1)?;
        Some(tid)
    })
    .flatten()
}

/// Marks `pid`'s registered address space as older than its mappings, when
/// a final snapshot could not be taken, so its release frees only what the
/// live page tables show.
pub(crate) fn mark_live_process_address_space_stale(pid: u32) -> bool {
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        let Some(space) = table
            .process_mut(handle)
            .and_then(|process| process.address_space.as_mut())
        else {
            return false;
        };
        space.stale = true;
        true
    })
    .unwrap_or(false)
}

/// Whether `pid`'s registered mapping list is stale (see
/// `refresh_live_process_context_for_wait`), so a fork must snapshot its
/// address space before copying the list.
pub(crate) fn live_process_address_space_stale(pid: u32) -> bool {
    with_live_table(|table| {
        table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .and_then(|process| process.address_space)
            .is_some_and(|space| space.stale)
    })
    .unwrap_or(false)
}

/// Whether `pid` is a child forked onto its parent's pages that has not
/// executed yet, whose pages all belong to its parent.
pub(crate) fn live_process_shares_parent_vm(pid: u32) -> bool {
    with_live_table(|table| {
        table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .is_some_and(|process| process.shares_parent_vm)
    })
    .unwrap_or(false)
}

/// The id of the `resource` process `pid` uses (`SharedResource`).
pub(crate) fn live_process_shared_id(pid: u32, resource: SharedResource) -> Option<u32> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        Some(process.shared[resource as usize])
    })
    .flatten()
}

/// Makes process `pid` use `resource` of process `owner` (a clone that
/// shares it), or one of its own when `owner` is None (unshare, exec).
pub(crate) fn share_live_process_resource(
    pid: u32,
    resource: SharedResource,
    owner: Option<u32>,
) -> bool {
    with_live_table(|table| {
        let id = match owner {
            Some(owner) => {
                let Some(owner) = table
                    .handle_by_pid(owner)
                    .and_then(|handle| table.process(handle))
                else {
                    return false;
                };
                owner.shared[resource as usize]
            }
            None => table.new_shared_id(),
        };
        table.sharing |= owner.is_some()
            && matches!(
                resource,
                SharedResource::Descriptors
                    | SharedResource::Filesystem
                    | SharedResource::SignalHandlers
            );
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        process.shared[resource as usize] = id;
        true
    })
    .unwrap_or(false)
}

/// The other processes that share `resource` with process `pid` and have
/// not ended (a zombie holds nothing any more), by pid; empty when memory
/// for the list runs out.
pub(crate) fn live_processes_sharing(pid: u32, resource: SharedResource) -> Vec<u32> {
    with_live_table(|table| {
        let mut sharing = Vec::new();
        let Some(id) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .map(|process| process.shared[resource as usize])
        else {
            return sharing;
        };
        for process in table.processes.iter().flatten() {
            if process.handle.pid != pid
                && process.shared[resource as usize] == id
                && matches!(
                    process.state,
                    ProcessState::Running | ProcessState::Stopped { .. }
                )
            {
                if sharing.try_reserve(1).is_err() {
                    return Vec::new();
                }
                sharing.push(process.handle.pid);
            }
        }
        sharing
    })
    .unwrap_or_default()
}

/// Whether process `pid` shares `resource` with another that has not ended.
pub(crate) fn live_process_resource_shared(pid: u32, resource: SharedResource) -> bool {
    let tracked = matches!(
        resource,
        SharedResource::Memory | SharedResource::Io | SharedResource::SemaphoreUndo
    ) || live_processes_share_state();
    if !tracked {
        return false;
    }
    with_live_table(|table| {
        let Some(id) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .map(|process| process.shared[resource as usize])
        else {
            return false;
        };
        table.processes.iter().flatten().any(|process| {
            process.handle.pid != pid
                && process.shared[resource as usize] == id
                && matches!(
                    process.state,
                    ProcessState::Running | ProcessState::Stopped { .. }
                )
        })
    })
    .unwrap_or(false)
}

/// Whether any process of the domain was ever cloned to share runtime
/// state (descriptors, filesystem context, signal handlers) with another:
/// until then no system call needs to keep any in step.
pub(crate) fn live_processes_share_state() -> bool {
    with_live_table(|table| table.sharing).unwrap_or(false)
}

/// Places process `pid` in the cgroup of generation `generation` (0: the
/// root), whose memory cgroup is `memcg`, and gives back the one it was in.
pub(crate) fn replace_live_process_cgroup(pid: u32, generation: u32, memcg: u16) -> Option<u32> {
    with_live_table(|table| {
        let process = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))?;
        process.memcg = memcg;
        Some(core::mem::replace(
            &mut process.cgroup_generation,
            generation,
        ))
    })
    .flatten()
}

/// Marks process `pid` as an OOM victim (`oom_victim`).
pub(crate) fn note_live_process_killed(pid: u32) {
    let _ = with_live_table(|table| {
        if let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        {
            process.oom_victim = true;
        }
    });
}

/// Whether process `pid` is an OOM victim not yet gone.
pub(crate) fn live_process_killed(pid: u32) -> bool {
    with_live_table(|table| {
        table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .is_some_and(|process| {
                process.oom_victim
                    && matches!(
                        process.state,
                        ProcessState::Running | ProcessState::Stopped { .. }
                    )
            })
    })
    .unwrap_or(false)
}

/// The memory cgroup process `pid`'s pages are charged to (0: not known).
pub(crate) fn live_process_memcg(pid: u32) -> Option<u16> {
    with_live_table(|table| Some(table.process(table.handle_by_pid(pid)?)?.memcg)).flatten()
}

/// The running or stopped processes charged to memory cgroups for which
/// `within` holds, with their `oom_score_adj`.
pub(crate) fn live_memcg_members(within: impl Fn(u16) -> bool) -> impl Iterator<Item = (u32, i32)> {
    LiveMemcgMembers {
        next_slot: 0,
        within,
    }
}

/// `live_memcg_members`' iterator: each step takes the table's lock to find
/// the next running or stopped process by slot, and asks `within` with the
/// lock released, so its user may call into the table between steps (and
/// nothing is allocated, which an OOM killer that walks it needs).
struct LiveMemcgMembers<F> {
    next_slot: usize,
    within: F,
}

impl<F: Fn(u16) -> bool> Iterator for LiveMemcgMembers<F> {
    type Item = (u32, i32);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let start = self.next_slot;
            let (slot, memcg, member) = with_live_table(|table| {
                table
                    .processes
                    .iter()
                    .enumerate()
                    .skip(start)
                    .find_map(|(slot, process)| {
                        let process = process.as_ref().filter(|process| {
                            matches!(
                                process.state,
                                ProcessState::Running | ProcessState::Stopped { .. }
                            )
                        })?;
                        Some((
                            slot,
                            process.memcg,
                            (process.handle.pid, i32::from(process.oom_score_adj)),
                        ))
                    })
            })
            .flatten()?;
            self.next_slot = slot + 1;
            if (self.within)(memcg) {
                return Some(member);
            }
        }
    }
}

/// The signal process `pid`'s end sends its parent (clone's exit signal).
pub(crate) fn live_process_exit_signal(pid: u32) -> Option<u8> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        Some(process.exit_signal)
    })
    .flatten()
}

/// Process `pid` ended while its parent reaped its children automatically.
pub(crate) fn set_live_process_reaped_by_parent(pid: u32) {
    let _ = with_live_table(|table| {
        if let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        {
            process.reaped_by_parent = true;
        }
    });
}

pub(crate) fn set_live_process_exit_signal(pid: u32, signal: u8) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        process.exit_signal = signal;
        true
    })
    .unwrap_or(false)
}

/// Makes process `pid`, a child just cloned, the child of its parent's
/// parent instead (CLONE_PARENT): that process waits for it and gets its
/// exit signal.
pub(crate) fn adopt_live_process_by_grandparent(pid: u32) -> bool {
    with_live_table(|table| {
        let Some(grandparent) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .and_then(|process| process.parent)
            .and_then(|parent| table.process(parent))
            .and_then(|parent| parent.parent)
        else {
            return false;
        };
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        process.cloned_by = process.parent;
        process.parent = Some(grandparent);
        true
    })
    .unwrap_or(false)
}

/// Records that process `parent` is suspended in a vfork until `child`
/// executes or exits (0: no longer).
pub(crate) fn set_live_process_vfork_child(parent: u32, child: u32) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(parent)
            .and_then(|handle| table.process_mut(handle))
        else {
            return false;
        };
        process.vfork_child = child;
        true
    })
    .unwrap_or(false)
}

/// The vfork child process `parent` is suspended for, and whether it still
/// is: true until the child has executed or ended.
pub(crate) fn live_process_vfork_child(parent: u32) -> Option<(u32, bool)> {
    with_live_table(|table| {
        let child = table.process(table.handle_by_pid(parent)?)?.vfork_child;
        if child == 0 {
            return None;
        }
        let pending = table
            .handle_by_pid(child)
            .and_then(|handle| table.process(handle))
            .is_some_and(|process| {
                !process.executed
                    && matches!(
                        process.state,
                        ProcessState::Running
                            | ProcessState::Stopped { .. }
                            | ProcessState::Preparing
                    )
            });
        Some((child, pending))
    })
    .flatten()
}

pub(crate) fn replace_live_process_mapping(
    pid: u32,
    address: usize,
    expected: memory::FrameLease,
    replacement: memory::FrameLease,
    writable: bool,
    executable: bool,
) -> bool {
    replace_live_process_mapping_inner(
        pid,
        address,
        expected,
        replacement,
        writable,
        executable,
        false,
    )
}

pub(crate) fn replace_live_process_mapping_for_exec(
    pid: u32,
    address: usize,
    expected: memory::FrameLease,
    replacement: memory::FrameLease,
    writable: bool,
    executable: bool,
) -> bool {
    replace_live_process_mapping_inner(
        pid,
        address,
        expected,
        replacement,
        writable,
        executable,
        true,
    )
}

fn replace_live_process_mapping_inner(
    pid: u32,
    address: usize,
    expected: memory::FrameLease,
    replacement: memory::FrameLease,
    writable: bool,
    executable: bool,
    private_exec_mapping: bool,
) -> bool {
    if writable && executable
        || !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[replacement])
    {
        return false;
    }
    with_live_table(|table| {
        let Some((space, storage)) = table.space_lists_mut(pid) else {
            return false;
        };
        let Some(mapping) = storage
            .mappings
            .get_mut(..space.mapping_count as usize)
            .into_iter()
            .flatten()
            .find(|mapping| mapping.address == address && mapping.frame == expected)
        else {
            return false;
        };
        mapping.frame = replacement;
        mapping.writable = writable;
        mapping.executable = executable;
        if private_exec_mapping {
            mapping.shared = false;
            mapping.dontfork = false;
        }
        true
    })
    .unwrap_or(false)
}

/// Drops `pid`'s registered mapping at `address`, whose page its page
/// tables no longer hold; false if there was none.
pub(crate) fn remove_live_process_mapping(pid: u32, address: usize) -> bool {
    with_live_process_mappings(pid, |mappings| {
        let index = mappings
            .iter()
            .position(|mapping| mapping.address == address)?;
        mappings.remove(index);
        Some(())
    })
    .is_some()
}

/// Moves `pid`'s registered mapping at `from` to `to`, as its page-table
/// entry moved (exec moving the stack); false if there was none at `from`
/// or there is one at `to`.
pub(crate) fn move_live_process_mapping(pid: u32, from: usize, to: usize) -> bool {
    with_live_process_mappings(pid, |mappings| {
        if mappings.iter().any(|mapping| mapping.address == to) {
            return None;
        }
        mappings
            .iter_mut()
            .find(|mapping| mapping.address == from)?
            .address = to;
        Some(())
    })
    .is_some()
}

/// Runs `change` on `pid`'s registered mapping list, keeping its count in
/// step with the list.
fn with_live_process_mappings<T>(
    pid: u32,
    change: impl FnOnce(&mut Vec<cpu::LinuxActiveImageMapping>) -> Option<T>,
) -> Option<T> {
    with_live_table(|table| {
        let (space, storage) = table.space_lists_mut(pid)?;
        if space.mapping_count as usize != storage.mappings.len() {
            return None;
        }
        let result = change(&mut storage.mappings)?;
        space.mapping_count = storage.mappings.len().try_into().ok()?;
        Some(result)
    })
    .flatten()
}

pub(crate) fn add_live_process_mapping(pid: u32, mapping: cpu::LinuxActiveImageMapping) -> bool {
    if mapping.address == 0
        || !mapping.address.is_multiple_of(PAGE_SIZE)
        || mapping.writable && mapping.executable
        || !(memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
            || memory::frame_lease_is_runtime(mapping.frame))
    {
        return false;
    }
    with_live_table(|table| {
        let Some((space, storage)) = table.space_lists_mut(pid) else {
            return false;
        };
        let count = space.mapping_count as usize;
        if count != storage.mappings.len()
            || storage
                .mappings
                .iter()
                .any(|existing| existing.address == mapping.address)
            || storage.mappings.try_reserve(1).is_err()
        {
            return false;
        }
        storage.mappings.push(mapping);
        space.mapping_count += 1;
        true
    })
    .unwrap_or(false)
}

pub(crate) fn import_live_process_mapping_from_hardware(pid: u32, address: u64) -> bool {
    let Some(current) = address_space::current_linux_active_mapping(address) else {
        return false;
    };
    if let Some(existing) = live_process_mapping(pid, current.address) {
        return existing.frame == current.frame
            && existing.writable == current.writable
            && existing.executable == current.executable;
    }
    add_live_process_mapping(pid, current)
}

pub(crate) fn live_process_hierarchy_frame(pid: u32, index: usize) -> Option<memory::FrameLease> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        table
            .process(handle)?
            .address_space?
            .hierarchy(&table.spaces)
            .get(index)
            .copied()
    })
    .flatten()
}

pub(crate) fn write_live_process_u32(pid: u32, address: u64, value: u32) -> bool {
    let Ok(address) = usize::try_from(address) else {
        return false;
    };
    let page = address & !(PAGE_SIZE - 1);
    let offset = address & (PAGE_SIZE - 1);
    if offset + size_of::<u32>() > PAGE_SIZE {
        return false;
    }
    let Some(mapping) = live_process_mapping(pid, page).filter(|mapping| mapping.writable) else {
        return false;
    };
    let Some(frame) = Frame::leased(mapping.frame) else {
        return false;
    };
    frame.write_bytes(offset, &value.to_ne_bytes());
    true
}

pub(crate) fn copy_from_live_process(pid: u32, address: u64, output: &mut [u8]) -> bool {
    for_each_live_process_page(pid, address, output.len(), false, |frame, offset, range| {
        frame.read_bytes(offset, &mut output[range]);
    })
}

pub(crate) fn copy_to_live_process(pid: u32, address: u64, input: &[u8]) -> bool {
    for_each_live_process_page(pid, address, input.len(), true, |frame, offset, range| {
        frame.write_bytes(offset, &input[range]);
    })
}

pub(crate) fn live_process_range_mapped(
    pid: u32,
    address: u64,
    length: usize,
    writable: bool,
) -> bool {
    let Ok(address) = usize::try_from(address) else {
        return false;
    };
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    if length == 0 {
        return true;
    }
    let mut page = address & !(PAGE_SIZE - 1);
    while page < end {
        if live_process_mapping(pid, page).is_none_or(|mapping| writable && !mapping.writable) {
            return false;
        }
        let Some(next) = page.checked_add(PAGE_SIZE) else {
            return false;
        };
        page = next;
    }
    true
}

/// Runs `copy` on each page of process `pid`'s `length` bytes from
/// `address`, with the offset in the page and the part of the caller's
/// buffer that page holds. `write` makes each page the process's own first
/// (a copy-on-write page is copied). Each page is looked up in the table
/// and copied with the table's lock released: the kernel-entry lock keeps
/// the page the process's meanwhile.
fn for_each_live_process_page(
    pid: u32,
    address: u64,
    length: usize,
    write: bool,
    mut copy: impl FnMut(Frame, usize, core::ops::Range<usize>),
) -> bool {
    let Ok(mut address) = usize::try_from(address) else {
        return false;
    };
    let mut copied = 0;
    while copied < length {
        let page = address & !(PAGE_SIZE - 1);
        let offset = address & (PAGE_SIZE - 1);
        let chunk = (length - copied).min(PAGE_SIZE - offset);
        if write && !prepare_live_process_write(pid, page) {
            return false;
        }
        let Some(mapping) =
            live_process_mapping(pid, page).filter(|mapping| !write || mapping.writable)
        else {
            return false;
        };
        let Some(frame) = Frame::leased(mapping.frame) else {
            return false;
        };
        copy(frame, offset, copied..copied + chunk);
        copied += chunk;
        address += chunk;
    }
    true
}

pub(crate) fn prepare_live_process_write(pid: u32, address: usize) -> bool {
    let Some(mapping) =
        live_process_mapping(pid, address).filter(|mapping| mapping.writable && !mapping.shared)
    else {
        return live_process_mapping(pid, address).is_some_and(|mapping| mapping.writable);
    };
    let Some(root) = live_process_root(pid) else {
        return false;
    };
    if address_space::linux_cow_page_in_root(root, address as u64) != Some(mapping.frame) {
        return true;
    }
    let Some([replacement]) = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL) else {
        return false;
    };
    if !address_space::copy_linux_frame(mapping.frame, replacement)
        || !replace_live_process_mapping(
            pid,
            address,
            mapping.frame,
            replacement,
            true,
            mapping.executable,
        )
        || !address_space::replace_linux_cow_page_in_root(
            root,
            address as u64,
            mapping.frame,
            replacement,
            mapping.executable,
        )
    {
        let _ = replace_live_process_mapping(
            pid,
            address,
            replacement,
            mapping.frame,
            true,
            mapping.executable,
        );
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[replacement]);
        return false;
    }
    address_space::release_linux_private_page(mapping.frame)
}

pub(crate) fn live_process_root(pid: u32) -> Option<memory::FrameLease> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        Some(table.process(handle)?.address_space?.root(&table.spaces))
    })
    .flatten()
}

/// Whether `visit` holds for the page-table root of some process of the
/// domain (zombies whose memory has not gone yet included).
///
/// Each process's roots are looked up under the table's lock and visited
/// with it released (`visit` walks page tables).
pub(crate) fn any_live_process_root(mut visit: impl FnMut(u64) -> bool) -> bool {
    let mut next_slot = 0;
    loop {
        let found = with_live_table(|table| {
            table
                .processes
                .iter()
                .enumerate()
                .skip(next_slot)
                .find_map(|(slot, process)| {
                    let process = process.as_ref()?;
                    let roots = [process.address_space, process.retiring_address_space]
                        .map(|space| space.map(|space| space.root(&table.spaces).address()));
                    Some((slot, roots))
                })
        })
        .flatten();
        let Some((slot, roots)) = found else {
            return false;
        };
        if roots.into_iter().flatten().any(&mut visit) {
            return true;
        }
        next_slot = slot + 1;
    }
}

pub(crate) fn dispatch_live_init_with_return(value: u64) -> Option<LiveProcessDispatch> {
    with_live_table(|table| {
        let init = table.init?;
        if !table.set_return_value(init, value) {
            return None;
        }
        table.dispatch(init)
    })
    .flatten()
}

/// Sets the value a running process's interrupted system call returns.
pub(crate) fn set_live_process_return_value(pid: u32, value: u64) -> bool {
    with_live_table(|table| {
        table
            .handle_by_pid(pid)
            .is_some_and(|handle| table.set_return_value(handle, value))
    })
    .unwrap_or(false)
}

pub(crate) fn dispatch_live_process(pid: u32) -> Option<LiveProcessDispatch> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        table.dispatch(handle)
    })
    .flatten()
}

#[inline(never)]
/// Says why `prepare_fork` refused: the parent's registry state, or a full
/// process table.
fn report_fork_preparation_failure(table: &ProcessTable, parent: ProcessHandle) {
    let used = table.processes.iter().flatten().count();
    let zombies = table
        .processes
        .iter()
        .flatten()
        .filter(|process| matches!(process.state, ProcessState::Zombie { .. }))
        .count();
    crate::serial_write("linox: fork refused; parent pid/state/space/context/credentials: ");
    crate::serial_write_u64(u64::from(parent.pid));
    if let Some(process) = table.process(parent) {
        let state = match process.state {
            ProcessState::Preparing => 1,
            ProcessState::Running => 2,
            ProcessState::Stopped { .. } => 3,
            ProcessState::Exiting => 4,
            ProcessState::Zombie { .. } => 5,
        };
        for value in [
            state,
            u64::from(process.address_space.is_some()),
            u64::from(process.context.is_some()),
            u64::from(linux_user::credentials(process.user_namespace).is_some()),
        ] {
            crate::serial_write(" ");
            crate::serial_write_u64(value);
        }
    }
    crate::serial_write("; processes used/zombie/limit: ");
    for value in [used, zombies, PROCESS_LIMIT] {
        crate::serial_write_u64(value as u64);
        crate::serial_write(" ");
    }
    crate::serial_write("\r\n");
}

/// One line per process: pid, state (0 preparing, 1 running, 2 stopped,
/// 3 exiting, 4 zombie), parent, and whether it has an address space, a
/// retiring one and a run-queue thread.
fn write_process_table(table: &ProcessTable) {
    for process in table.processes.iter().flatten() {
        let state = match process.state {
            ProcessState::Preparing => 0,
            ProcessState::Running => 1,
            ProcessState::Stopped { .. } => 2,
            ProcessState::Exiting => 3,
            ProcessState::Zombie { .. } => 4,
        };
        crate::serial_write("linox: process pid/state/parent/space/retiring/thread: ");
        for value in [
            u64::from(process.handle.pid),
            state,
            process.parent.map_or(0, |parent| u64::from(parent.pid)),
            u64::from(process.address_space.is_some()),
            u64::from(process.retiring_address_space.is_some()),
            u64::from(process.scheduler_thread.is_some()),
        ] {
            crate::serial_write_u64(value);
            crate::serial_write(" ");
        }
        crate::serial_write("\r\n");
    }
}

/// A fork child `begin_live_fork` prepared: its parent, itself, the
/// namespaces it was made in and how many frames its copy needs.
struct PreparedFork {
    parent: ProcessHandle,
    child: ProcessHandle,
    namespaces: linux_namespace::Set,
    hierarchy_count: usize,
    private_count: usize,
}

/// The first part of `begin_live_fork`, under the table's lock: checks the
/// parent and prepares the child's record. Sets the fork stage that says
/// why it refused.
fn prepare_live_fork(
    table: &mut ProcessTable,
    parent_pid: u32,
    eager_private_copy: bool,
    share_vm: bool,
) -> Option<PreparedFork> {
    let Some(parent_handle) = table.handle_by_pid(parent_pid) else {
        process_runtime()
            .fork_execution_stage
            .store(102, Ordering::Release);
        return None;
    };
    let Some(parent) = table.process(parent_handle) else {
        process_runtime()
            .fork_execution_stage
            .store(103, Ordering::Release);
        return None;
    };
    let Some(parent_space) = parent.address_space.as_ref() else {
        process_runtime()
            .fork_execution_stage
            .store(104, Ordering::Release);
        return None;
    };
    let spaces = &table.spaces;
    let parent_space_owned = if share_vm {
        parent_space.hierarchy_is_owned(spaces)
    } else {
        parent_space.is_owned(spaces)
    };
    if parent.state != ProcessState::Running || !parent_space_owned {
        crate::serial_write("linox: fork parent ownership pid/state/hierarchy/mappings: ");
        crate::serial_write_u64(u64::from(parent_pid));
        crate::serial_write(" ");
        crate::serial_write_u64(u64::from(parent.state == ProcessState::Running));
        crate::serial_write(" ");
        crate::serial_write_u64(u64::from(parent_space.hierarchy_is_owned(spaces)));
        crate::serial_write(" ");
        crate::serial_write_u64(parent_space.mappings(spaces).len() as u64);
        crate::serial_write("\r\n");
        for mapping in parent_space
            .mappings(spaces)
            .iter()
            .filter(|mapping| {
                !memory::frame_lease_is_runtime(mapping.frame)
                    && !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
            })
            .take(4)
        {
            crate::serial_write("linox: fork parent unowned mapping address/frame/generation: ");
            crate::serial_write_u64(mapping.address as u64);
            crate::serial_write(" ");
            crate::serial_write_u64(mapping.frame.address());
            crate::serial_write(" ");
            crate::serial_write_u64(u64::from(mapping.frame.generation()));
            crate::serial_write("\r\n");
        }
        process_runtime().fork_execution_stage.store(
            if parent.state != ProcessState::Running {
                105
            } else {
                106
            },
            Ordering::Release,
        );
        return None;
    }
    let hierarchy_count = parent_space.hierarchy(spaces).len();
    let private_count = if eager_private_copy && !share_vm {
        parent_space
            .mappings(spaces)
            .iter()
            .filter(|mapping| !mapping.dontfork && mapping_requires_fork_copy(mapping))
            .count()
    } else {
        0
    };
    process_runtime()
        .fork_execution_stage
        .store(11, Ordering::Release);
    let Some(child_handle) = table.prepare_fork(parent_handle) else {
        report_fork_preparation_failure(table, parent_handle);
        return None;
    };
    let namespaces = table.process(child_handle)?.namespaces;
    Some(PreparedFork {
        parent: parent_handle,
        child: child_handle,
        namespaces,
        hierarchy_count,
        private_count,
    })
}

/// Enters new process `pid` in its PID namespace (where it gets its
/// numbers) and freezes the offsets of its time namespace, as `allocate`
/// leaves for after the table's lock is released.
fn enter_namespaces(pid: u32, namespaces: linux_namespace::Set) -> bool {
    let instance = cpu::current_linux_execution_instance();
    if linux_namespace::enter_pid(instance, namespaces.pid, pid).is_err() {
        return false;
    }
    if namespaces.time != 0 {
        linux_namespace::freeze_time(instance, namespaces.time);
    }
    true
}

/// Creates a forked child of `parent_pid`. With `child_first` the run queue
/// switches to the child, which the caller runs before resuming the parent;
/// otherwise the parent stays current and the child waits, ready, for its
/// turn.
pub(crate) fn begin_live_fork(
    parent_pid: u32,
    eager_private_copy: bool,
    share_vm: bool,
    child_stack: Option<u64>,
    child_first: bool,
) -> Option<LiveProcessDispatch> {
    process_runtime()
        .fork_execution_stage
        .store(10, Ordering::Release);
    let Some(prepared) =
        with_live_table(|table| prepare_live_fork(table, parent_pid, eager_private_copy, share_vm))
    else {
        process_runtime()
            .fork_execution_stage
            .store(101, Ordering::Release);
        return None;
    };
    let PreparedFork {
        parent: parent_handle,
        child: child_handle,
        namespaces,
        hierarchy_count,
        private_count,
    } = prepared?;
    process_runtime()
        .fork_execution_stage
        .store(111, Ordering::Release);
    let abort = || {
        let _ = with_live_table(|table| table.abort_fork(child_handle));
    };
    if !enter_namespaces(child_handle.pid, namespaces) {
        abort();
        return None;
    }
    // The frames and lists the copy works with, taken out of the scratch so
    // no lock is held across the copy.
    let mut scratch = LiveForkScratch::take();
    let published = 'publish: {
        if !fork_frame_scratch(&mut scratch.hierarchy_allocation, hierarchy_count)
            || !memory::allocate_frame_prefix_into(
                memory::FrameOwner::KERNEL,
                &mut scratch.hierarchy_allocation,
                hierarchy_count,
            )
        {
            abort();
            break 'publish false;
        }
        let child_hierarchy = &scratch.hierarchy_allocation[..hierarchy_count];
        process_runtime()
            .fork_execution_stage
            .store(112, Ordering::Release);
        if !fork_frame_scratch(&mut scratch.page_allocation, private_count)
            || private_count != 0
                && !memory::allocate_frame_prefix_into(
                    memory::FrameOwner::KERNEL,
                    &mut scratch.page_allocation,
                    private_count,
                )
        {
            let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, child_hierarchy);
            abort();
            break 'publish false;
        }
        process_runtime()
            .fork_execution_stage
            .store(113, Ordering::Release);
        commit_cloned_fork(
            &mut LiveTable,
            child_handle,
            child_hierarchy,
            &scratch.page_allocation[..private_count],
            share_vm,
            &mut scratch.lists,
        )
    };
    scratch.put_back();
    if !published {
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(12, Ordering::Release);
    // fork returns the child's number in the parent's PID namespace.
    let parent_namespace = with_live_table(|table| {
        table
            .process(parent_handle)
            .map_or(0, |parent| parent.namespaces.pid)
    })
    .unwrap_or(0);
    let child_seen = linux_namespace::pid_seen_from(
        cpu::current_linux_execution_instance(),
        parent_namespace,
        child_handle.pid,
    )
    .unwrap_or(child_handle.pid);
    let scheduled = with_live_table(|table| {
        schedule_live_fork(
            table,
            parent_handle,
            child_handle,
            child_seen,
            child_stack,
            child_first,
        )
    });
    match scheduled {
        Some(Ok(dispatch)) => dispatch,
        Some(Err(())) => {
            let _ = discard_live_fork(parent_handle, child_handle);
            None
        }
        None => None,
    }
}

/// The last part of `begin_live_fork`, under the table's lock: gives the
/// parent its result and the child its stack, and puts both in the run
/// queue. Err(()) when the child has to be discarded (`discard_live_fork`),
/// after the run queue was put back as it was.
fn schedule_live_fork(
    table: &mut ProcessTable,
    parent_handle: ProcessHandle,
    child_handle: ProcessHandle,
    child_seen: u32,
    child_stack: Option<u64>,
    child_first: bool,
) -> Result<Option<LiveProcessDispatch>, ()> {
    let refuse = |stage: u32| {
        process_runtime()
            .fork_execution_stage
            .store(stage, Ordering::Release);
        Err(())
    };
    if !table.set_return_value(parent_handle, u64::from(child_seen)) {
        return refuse(121);
    }
    if child_stack.is_some_and(|stack| !table.set_stack_pointer(child_handle, stack)) {
        return refuse(122);
    }
    let Some(parent_context) = table
        .process(parent_handle)
        .and_then(|process| process.context)
    else {
        return refuse(123);
    };
    let Some(parent_space) = table
        .process(parent_handle)
        .and_then(|process| process.address_space)
    else {
        return refuse(124);
    };
    let Some(parent_scheduler_context) =
        parent_context.scheduler_context(&parent_space, &table.spaces)
    else {
        return refuse(125);
    };
    let Some(child) = table.process(child_handle) else {
        return Err(());
    };
    let (Some(child_space), Some(child_context)) = (child.address_space, child.context) else {
        return refuse(126);
    };
    let Some(child_scheduler_context) =
        child_context.scheduler_context(&child_space, &table.spaces)
    else {
        process_runtime()
            .fork_execution_stage
            .store(127, Ordering::Release);
        crate::serial_write("linox: fork child context validation error/rip/rsp/fs/mappings: ");
        crate::serial_write_u64(u64::from(
            child_context
                .validation_error(&child_space, &table.spaces)
                .unwrap_or(0),
        ));
        crate::serial_write(" ");
        crate::serial_write_u64(child_context.rip);
        crate::serial_write(" ");
        crate::serial_write_u64(child_context.rsp);
        crate::serial_write(" ");
        crate::serial_write_u64(child_context.fs_base);
        crate::serial_write(" ");
        crate::serial_write_u64(child_space.mappings(&table.spaces).len() as u64);
        crate::serial_write("\r\n");
        return Err(());
    };
    process_runtime()
        .fork_execution_stage
        .store(13, Ordering::Release);
    let scheduler_domain = table.scheduler_domain();
    let nested = table
        .process(parent_handle)
        .is_some_and(|process| process.scheduler_thread.is_some());
    let run_queue = if nested {
        scheduler::active_process_scheduler_workspace()
    } else {
        scheduler::acquire_process_scheduler_workspace()
    };
    let Some(run_queue) = run_queue else {
        return Ok(None);
    };
    if !nested && !table.admit_to_scheduler(parent_handle, run_queue, scheduler_domain) {
        let _ = scheduler::release_process_scheduler_workspace();
        return Err(());
    }
    if !table.admit_to_scheduler(child_handle, run_queue, scheduler_domain) {
        if !nested {
            let _ = table.withdraw_from_scheduler(parent_handle, run_queue);
            let _ = scheduler::release_process_scheduler_workspace();
        }
        return Err(());
    }
    let scheduled = (|| {
        let parent_thread = table.process(parent_handle)?.scheduler_thread?;
        let child_thread = table.process(child_handle)?.scheduler_thread?;
        if !nested {
            let initial = run_queue.schedule_next()?;
            if initial.handle() != parent_thread || initial.context() != parent_scheduler_context {
                return None;
            }
        }
        if !child_first {
            return Some(());
        }
        let selected =
            run_queue.switch_current(parent_thread, parent_scheduler_context, child_thread)?;
        (selected.handle() == child_thread && selected.context() == child_scheduler_context)
            .then_some(())
    })()
    .is_some();
    if !scheduled {
        let _ = table.withdraw_from_scheduler(child_handle, run_queue);
        if !nested {
            let _ = table.withdraw_from_scheduler(parent_handle, run_queue);
            let _ = scheduler::release_process_scheduler_workspace();
        }
        return Err(());
    }
    process_runtime()
        .fork_execution_stage
        .store(14, Ordering::Release);
    Ok(table.dispatch(child_handle))
}

/// Backs out a fork whose child was committed but not scheduled: the
/// parent's result goes back to 0 and the child's memory and attachments
/// go, the child reaped at once.
fn discard_live_fork(parent_handle: ProcessHandle, child_handle: ProcessHandle) -> bool {
    let Some((return_restored, retiring, root)) = with_live_table(|table| {
        let child_space = table.process(child_handle)?.address_space?;
        let return_restored = table.set_return_value(parent_handle, 0);
        let retiring = table.begin_exit(child_handle, child_space)?;
        Some((return_restored, retiring, retiring.root(&table.spaces)))
    })
    .flatten() else {
        return false;
    };
    return_restored
        && retire_live_process_page_tables(root)
        && with_live_table(|table| release_space_hierarchy(&retiring, &table.spaces))
            .unwrap_or(false)
        && crate::linux_sysv_ipc::drop_process_attachments(child_handle.pid).is_ok()
        && with_live_table(|table| {
            table.exit_after_retiring_address_space_released(child_handle, retiring, 0)
                && table.wait(parent_handle, child_handle.pid)
                    == Some(WaitResult {
                        pid: child_handle.pid,
                        status: 0,
                    })
        })
        .unwrap_or(false)
}

/// Retires a process's page tables, rooted at `root`, with the table's lock
/// released: retiring releases each private page they map (pages no other
/// address space maps are freed, shared ones lose this mapping) and drops
/// the swap entries of pages paged out (`LockRank::SWAPS`). The tables are
/// the record of what the process maps; its registry may be a stale
/// snapshot (a process killed by a signal has no final refresh).
fn retire_live_process_page_tables(root: memory::FrameLease) -> bool {
    let page_table_started = crate::arch::x86_64::timer::timestamp_counter();
    let retired = address_space::retire_linux_child_address_space(root);
    if retired && cfg!(feature = "linux-boot-profile") {
        crate::arch::x86_64::cpu::linux_boot_profile_record_lifecycle_phase(7, page_table_started);
    }
    retired
}

/// Frees the page-table frames `space`'s hierarchy list names, after
/// `retire_live_process_page_tables`, under the table's lock (the frame
/// allocator ranks above it). A stale list may name tables already freed
/// and handed out again; the live tree's tables were freed with it.
fn release_space_hierarchy(space: &ProcessAddressSpace, lists: &SpaceLists) -> bool {
    const RELEASE_BATCH_SIZE: usize = 64;
    if space.stale {
        return true;
    }
    let frame_release_started = crate::arch::x86_64::timer::timestamp_counter();
    let mut release_batch = [memory::FrameLease::EMPTY; RELEASE_BATCH_SIZE];
    let mut release_count = 0;
    for frame in space.hierarchy(lists) {
        let ownership_started = crate::arch::x86_64::timer::timestamp_counter();
        let owned = memory::frames_owned_by(memory::FrameOwner::KERNEL, &[*frame]);
        if cfg!(feature = "linux-boot-profile") {
            crate::arch::x86_64::cpu::linux_boot_profile_record_lifecycle_phase(
                10,
                ownership_started,
            );
        }
        if owned && !release_batch[..release_count].contains(frame) {
            release_batch[release_count] = *frame;
            release_count += 1;
            if release_count == release_batch.len() {
                let scrub_started = crate::arch::x86_64::timer::timestamp_counter();
                if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &release_batch) {
                    return false;
                }
                if cfg!(feature = "linux-boot-profile") {
                    crate::arch::x86_64::cpu::linux_boot_profile_record_lifecycle_phase(
                        11,
                        scrub_started,
                    );
                }
                release_count = 0;
            }
        }
    }
    let scrub_started = crate::arch::x86_64::timer::timestamp_counter();
    let released = release_count == 0
        || memory::scrub_and_release_frames(
            memory::FrameOwner::KERNEL,
            &release_batch[..release_count],
        );
    if cfg!(feature = "linux-boot-profile") && release_count != 0 {
        crate::arch::x86_64::cpu::linux_boot_profile_record_lifecycle_phase(11, scrub_started);
    }
    if cfg!(feature = "linux-boot-profile") {
        crate::arch::x86_64::cpu::linux_boot_profile_record_lifecycle_phase(
            8,
            frame_release_started,
        );
    }
    released
}

/// Ends process `handle`, out of the run queue already, whose address space
/// `space` (rooted at `root`) is still its own: its memory and System V
/// attachments go with the table's lock released, then it becomes a zombie
/// with `status`.
fn release_and_exit_live_process(
    handle: ProcessHandle,
    space: ProcessAddressSpace,
    root: memory::FrameLease,
    status: u8,
) -> bool {
    retire_live_process_page_tables(root)
        && with_live_table(|table| release_space_hierarchy(&space, &table.spaces)).unwrap_or(false)
        && crate::linux_sysv_ipc::drop_process_attachments(handle.pid).is_ok()
        && with_live_table(|table| table.exit_after_current_address_space_retired(handle, status))
            .unwrap_or(false)
}

#[inline(never)]
/// Ends a process from another process's context: withdraws it from the
/// run queue, frees its address space and leaves it a zombie for its
/// parent. A domain's init uses this on exit for killed processes the
/// scheduler can no longer switch to, so they cannot run their own exit.
pub(crate) fn force_exit_live_process(pid: u32, status: u8) -> bool {
    let withdrawn = with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let process = table.process(handle)?;
        if process.state != ProcessState::Running {
            return None;
        }
        let space = process.address_space?;
        if process.scheduler_thread.is_some() {
            let run_queue = scheduler::active_process_scheduler_workspace()?;
            if !table.withdraw_from_scheduler(handle, run_queue) {
                return None;
            }
        }
        Some((handle, space, space.root(&table.spaces)))
    })
    .flatten();
    let Some((handle, space, root)) = withdrawn else {
        return false;
    };
    release_and_exit_live_process(handle, space, root, status)
}

pub(crate) fn complete_live_child_exit(pid: u32, status: u8) -> Option<LiveProcessDispatch> {
    process_runtime()
        .fork_execution_stage
        .store(15, Ordering::Release);
    let (child_handle, parent_handle, child_space, child_root) = with_live_table(|table| {
        process_runtime()
            .fork_execution_stage
            .store(151, Ordering::Release);
        let child_handle = table.handle_by_pid(pid)?;
        let child = table.process(child_handle)?;
        let parent_handle = child.cloned_by.or(child.parent)?;
        let parent = table.process(parent_handle)?;
        if child.state != ProcessState::Running {
            return None;
        }
        let parent_space = parent.address_space?;
        let parent_context = parent.context?;
        let child_space = child.address_space?;
        let child_context = child.context?;
        process_runtime()
            .fork_execution_stage
            .store(152, Ordering::Release);
        let parent_scheduler_context =
            parent_context.scheduler_context(&parent_space, &table.spaces)?;
        let child_scheduler_context =
            child_context.scheduler_context(&child_space, &table.spaces)?;
        let parent_thread = parent.scheduler_thread?;
        let child_thread = child.scheduler_thread?;
        let nested = parent.parent.is_some();
        let run_queue = scheduler::active_process_scheduler_workspace()?;
        process_runtime()
            .fork_execution_stage
            .store(153, Ordering::Release);
        let resumed =
            run_queue.switch_current(child_thread, child_scheduler_context, parent_thread)?;
        process_runtime()
            .fork_execution_stage
            .store(154, Ordering::Release);
        if resumed.handle() != parent_thread || resumed.context() != parent_scheduler_context {
            return None;
        }
        process_runtime()
            .fork_execution_stage
            .store(16, Ordering::Release);
        let standalone_transaction = table
            .processes
            .iter()
            .flatten()
            .filter(|process| process.scheduler_thread.is_some())
            .count()
            == 2;
        if !table.withdraw_from_scheduler(child_handle, run_queue) {
            return None;
        }
        if !nested
            && standalone_transaction
            && (!table.withdraw_from_scheduler(parent_handle, run_queue)
                || !scheduler::release_process_scheduler_workspace())
        {
            return None;
        }
        process_runtime()
            .fork_execution_stage
            .store(161, Ordering::Release);
        Some((
            child_handle,
            parent_handle,
            child_space,
            child_space.root(&table.spaces),
        ))
    })
    .flatten()?;
    if !retire_live_process_page_tables(child_root)
        || !with_live_table(|table| release_space_hierarchy(&child_space, &table.spaces))
            .unwrap_or(false)
    {
        process_runtime()
            .fork_execution_stage
            .store(162, Ordering::Release);
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(163, Ordering::Release);
    if crate::linux_sysv_ipc::drop_process_attachments(pid).is_err()
        || !with_live_table(|table| {
            table.exit_after_current_address_space_retired(child_handle, status)
        })
        .unwrap_or(false)
    {
        process_runtime()
            .fork_execution_stage
            .store(164, Ordering::Release);
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(17, Ordering::Release);
    with_live_table(|table| table.dispatch(parent_handle)).flatten()
}
pub(crate) fn resume_live_parent_after_child_exec(pid: u32) -> Option<LiveProcessDispatch> {
    with_live_table(|table| {
        let child_handle = table.handle_by_pid(pid)?;
        let child = table.process(child_handle)?;
        let parent_handle = child.cloned_by.or(child.parent)?;
        let parent = table.process(parent_handle)?;
        let child_space = child.address_space.as_ref()?;
        let parent_space = parent.address_space.as_ref()?;
        let child_context = child.context?;
        let parent_context = parent.context?;
        let child_thread = child.scheduler_thread?;
        let parent_thread = parent.scheduler_thread?;
        let child_scheduler_context =
            child_context.scheduler_context(child_space, &table.spaces)?;
        let parent_scheduler_context =
            parent_context.scheduler_context(parent_space, &table.spaces)?;
        let run_queue = scheduler::active_process_scheduler_workspace()?;
        let resumed =
            run_queue.switch_current(child_thread, child_scheduler_context, parent_thread)?;
        if resumed.handle() != parent_thread || resumed.context() != parent_scheduler_context {
            return None;
        }
        table.dispatch(parent_handle)
    })
    .flatten()
}

/// Makes process `pid`, ready in the run queue, current on this CPU, which
/// runs no process: a CPU's scheduler loop taking it to run. The registry's
/// context is the one entered: a write to it while the process waited (a
/// signal's frame, a call's result, a restart) is newer than the copy the
/// run queue kept from its last release.
pub(crate) fn claim_live_process(pid: u32) -> Option<LiveProcessDispatch> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let process = table.process(handle)?;
        if process.state != ProcessState::Running {
            return None;
        }
        let space = process.address_space.as_ref()?;
        let context = process.context?.scheduler_context(space, &table.spaces)?;
        let thread = process.scheduler_thread?;
        let run_queue = scheduler::active_process_scheduler_workspace()?;
        run_queue.claim(thread)?;
        let dispatched = table.dispatch(handle);
        if dispatched.is_none() {
            let _ = run_queue.release(thread, context);
        }
        dispatched
    })
    .flatten()
}

/// Starts a domain runtime's run queue with its init, ready: the runtime
/// loop owns the queue from the start and picks every process from it, init
/// included (docs/SCHEDULER.md), so a fork only adds its child. The queue
/// goes when the runtime ends (`retire_lone_live_process`).
pub(crate) fn start_runtime_scheduler() -> bool {
    with_live_table(|table| {
        let Some(init) = table.init else {
            return false;
        };
        if table
            .process(init)
            .is_some_and(|process| process.scheduler_thread.is_some())
        {
            return true;
        }
        let domain = table.scheduler_domain();
        let Some(run_queue) = scheduler::acquire_process_scheduler_workspace() else {
            return false;
        };
        if !table.admit_to_scheduler(init, run_queue, domain) {
            let _ = scheduler::release_process_scheduler_workspace();
            return false;
        }
        true
    })
    .unwrap_or(false)
}

/// Makes running process `pid` issue system call `number` again when it is
/// next entered: its saved instruction pointer goes back over the
/// `syscall` instruction (two bytes) and its rax names the call, as a
/// restarted call is re-issued. False when it has no context.
pub(crate) fn restart_live_process_call(pid: u32, number: u64) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
            .filter(|process| process.state == ProcessState::Running)
        else {
            return false;
        };
        let Some(mut context) = process.context else {
            return false;
        };
        context.rip = context.rip.wrapping_sub(2);
        context.general[PROCESS_RAX_INDEX] = number;
        process.context = Some(context);
        true
    })
    .unwrap_or(false)
}

/// The value process `pid`'s interrupted system call returns when it is
/// next entered (its saved rax).
pub(crate) fn live_process_return_value(pid: u32) -> Option<u64> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        Some(process.context?.general[PROCESS_RAX_INDEX])
    })
    .flatten()
}

/// After the last other scheduled process of the domain ended: process
/// `pid`, current on this CPU and at the top of the tree, leaves the run queue
/// and the queue is released, as when no fork had been scheduled. True too
/// when other processes still run.
pub(crate) fn retire_lone_live_process(pid: u32) -> bool {
    with_live_table(|table| {
        let Some(handle) = table.handle_by_pid(pid) else {
            return false;
        };
        let lone = table
            .process(handle)
            .is_some_and(|process| process.parent.is_none() && process.scheduler_thread.is_some())
            && table
                .processes
                .iter()
                .flatten()
                .filter(|process| process.scheduler_thread.is_some())
                .count()
                == 1;
        if !lone {
            return true;
        }
        let Some(run_queue) = scheduler::active_process_scheduler_workspace() else {
            return false;
        };
        table.withdraw_from_scheduler(handle, run_queue)
            && scheduler::release_process_scheduler_workspace()
    })
    .unwrap_or(false)
}

/// Puts process `pid`, current on this CPU, back among the ready ones with
/// the context its registry records, leaving the CPU with no process.
pub(crate) fn release_live_process(pid: u32) -> bool {
    with_live_table(|table| {
        let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
        else {
            return false;
        };
        let (Some(space), Some(context), Some(thread)) = (
            process.address_space.as_ref(),
            process.context,
            process.scheduler_thread,
        ) else {
            return false;
        };
        let (Some(context), Some(run_queue)) = (
            context.scheduler_context(space, &table.spaces),
            scheduler::active_process_scheduler_workspace(),
        ) else {
            return false;
        };
        run_queue.release(thread, context)
    })
    .unwrap_or(false)
}

/// The first live process after `after` (in pid order, wrapping) that is
/// ready in the run queue, may run on this CPU and `accept` takes, for a CPU
/// looking for one to run.
pub(crate) fn ready_live_process_after(
    after: u32,
    now: u64,
    mut accept: impl FnMut(u32) -> bool,
) -> Option<u32> {
    // A process asleep in a futex wait (`Process::is_asleep`) is passed
    // over here, before `accept`'s costlier tests and without a place in
    // the list: a thousand of them would otherwise be sorted and tested on
    // every pass. `accept` asks the table itself, so it runs with the
    // table's lock released.
    let mut ready: Vec<u32> = with_live_table(|table| {
        let run_queue = scheduler::active_process_scheduler_workspace()?;
        let mut ready = Vec::new();
        for process in table.processes.iter().flatten() {
            if process.state == ProcessState::Running
                && !process.is_asleep(now)
                && process
                    .scheduler_thread
                    .is_some_and(|thread| run_queue.is_ready_here(thread))
                && ready.try_reserve(1).is_ok()
            {
                ready.push(process.handle.pid);
            }
        }
        Some(ready)
    })
    .flatten()?;
    ready.sort_unstable();
    let start = ready.iter().position(|pid| *pid > after).unwrap_or(0);
    (0..ready.len())
        .map(|offset| ready[(start + offset) % ready.len()])
        .find(|pid| accept(*pid))
}

/// Whether a process other than `pid` is ready in the run queue and may
/// run on this CPU (not blocked, not claimed by a CPU): `pid` has the CPU to
/// itself otherwise.
pub(crate) fn other_live_process_ready(pid: u32, now: u64) -> bool {
    with_live_table(|table| {
        let Some(run_queue) = scheduler::active_process_scheduler_workspace() else {
            return true;
        };
        table.processes.iter().flatten().any(|process| {
            process.handle.pid != pid
                && process.state == ProcessState::Running
                && !process.is_asleep(now)
                && process
                    .scheduler_thread
                    .is_some_and(|thread| run_queue.is_ready_here(thread))
        })
    })
    .unwrap_or(true)
}

/// The ready process to run next in turn, after the one the last call
/// chose, that `accept` takes; it becomes the turn's.
pub(crate) fn next_ready_live_process(now: u64, accept: impl FnMut(u32) -> bool) -> Option<u32> {
    let after = with_live_table(|table| table.dispatch_cursor)?;
    let next = ready_live_process_after(after, now, accept)?;
    with_live_table(|table| table.dispatch_cursor = next)?;
    Some(next)
}

/// Ends process `pid`, current on this CPU, with `status`: it leaves the
/// run queue, its memory goes and it becomes a zombie for its parent to
/// reap, which runs elsewhere or waits. The CPU is left with no process.
pub(crate) fn complete_live_process_exit_detached(pid: u32, status: u8) -> bool {
    let withdrawn = with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        let space = table
            .process(handle)
            .filter(|process| process.state == ProcessState::Running)
            .and_then(|process| process.address_space)?;
        let run_queue = scheduler::active_process_scheduler_workspace()?;
        table
            .withdraw_from_scheduler(handle, run_queue)
            .then(|| (handle, space, space.root(&table.spaces)))
    })
    .flatten();
    let Some((handle, space, root)) = withdrawn else {
        return false;
    };
    release_and_exit_live_process(handle, space, root, status)
}

/// `pid`'s SCHED_DEADLINE runtime, deadline and period.
pub(crate) fn live_process_deadline_parameters(pid: u32) -> Option<[u64; 3]> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        Some(process.deadline_parameters)
    })
    .flatten()
}

/// Sets `pid`'s SCHED_DEADLINE runtime, deadline and period.
pub(crate) fn set_live_process_deadline_parameters(pid: u32, parameters: [u64; 3]) -> bool {
    with_live_process(pid, |process| {
        process.deadline_parameters = parameters;
        true
    })
    .unwrap_or(false)
}

/// Notes that `pid` holds `kib` KiB resident now (its ru_maxrss peak).
pub(crate) fn note_live_process_rss(pid: u32, kib: u64) {
    let _ = with_live_process(pid, |process| {
        process.maxrss_kib = process.maxrss_kib.max(kib);
    });
}

/// `pid`'s ru_maxrss peaks: its own and its waited children's, in KiB.
pub(crate) fn live_process_maxrss(pid: u32) -> Option<(u64, u64)> {
    with_live_table(|table| {
        let process = table.process(table.handle_by_pid(pid)?)?;
        Some((process.maxrss_kib, process.children_maxrss_kib))
    })
    .flatten()
}

/// A wait reaped `child` of `parent`: the child's peaks join the
/// parent's children's (RUSAGE_CHILDREN's ru_maxrss).
pub(crate) fn add_waited_child_maxrss(parent: u32, (own, children): (u64, u64)) {
    let _ = with_live_process(parent, |process| {
        process.children_maxrss_kib = process.children_maxrss_kib.max(own).max(children);
    });
}

pub(crate) fn wait_live_child(parent_pid: u32, child_pid: u32) -> Option<(u32, u8)> {
    with_live_table(|table| {
        let parent = table.handle_by_pid(parent_pid)?;
        table
            .wait(parent, child_pid)
            .map(|result| (result.pid, result.status))
    })
    .flatten()
}

pub(crate) fn live_child_wait_state(
    parent_pid: u32,
    child_pid: Option<u32>,
    events: ChildWaitEvents,
) -> Option<ChildWaitState> {
    with_live_table(|table| {
        let parent = table.handle_by_pid(parent_pid)?;
        table.child_wait_state_matching(
            parent,
            |process| {
                child_pid.is_none_or(|pid| process.handle.pid == pid)
                    && events.scope.includes(process)
            },
            events.exited,
            events.stopped,
            events.continued,
        )
    })
    .flatten()
}

/// An exited child of `parent_pid` that ended while it reaped its
/// children automatically.
pub(crate) fn live_child_reaped_by_parent(parent_pid: u32) -> Option<u32> {
    with_live_table(|table| {
        let parent = table.handle_by_pid(parent_pid)?;
        match table.child_wait_state_matching(
            parent,
            |process| process.reaped_by_parent,
            true,
            false,
            false,
        )? {
            ChildWaitState::Exited { pid, .. } => Some(pid),
            _ => None,
        }
    })
    .flatten()
}

pub(crate) fn live_child_group_wait_state(
    parent_pid: u32,
    process_group: u32,
    events: ChildWaitEvents,
) -> Option<ChildWaitState> {
    with_live_table(|table| {
        let parent = table.handle_by_pid(parent_pid)?;
        table.child_wait_state_matching(
            parent,
            |process| process.process_group == process_group && events.scope.includes(process),
            events.exited,
            events.stopped,
            events.continued,
        )
    })
    .flatten()
}

/// Which child state changes a wait reports (WEXITED, WUNTRACED/WSTOPPED,
/// WCONTINUED).
#[derive(Clone, Copy)]
pub(crate) struct ChildWaitEvents {
    pub(crate) exited: bool,
    pub(crate) stopped: bool,
    pub(crate) continued: bool,
    pub(crate) scope: ChildScope,
}

/// Which children a wait looks at, by the signal they end with: those
/// ending with SIGCHLD (the default), the others ("clone" children,
/// __WCLONE) or all of them (__WALL).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildScope {
    Plain,
    Clone,
    All,
}

impl ChildScope {
    fn includes(self, process: &Process) -> bool {
        match self {
            Self::Plain => process.exit_signal == DEFAULT_EXIT_SIGNAL,
            Self::Clone => process.exit_signal != DEFAULT_EXIT_SIGNAL,
            Self::All => true,
        }
    }
}

pub(crate) fn consume_live_child_wait_event(parent_pid: u32, child_pid: u32) -> bool {
    with_live_table(|table| {
        let Some(parent) = table.handle_by_pid(parent_pid) else {
            return false;
        };
        table.consume_wait_event(parent, child_pid)
    })
    .unwrap_or(false)
}

pub(crate) fn live_fork_execution_stage() -> u32 {
    process_runtime()
        .fork_execution_stage
        .load(Ordering::Acquire)
}

pub(crate) fn live_fork_child_diagnostic() -> u32 {
    process_runtime()
        .fork_child_diagnostic
        .load(Ordering::Acquire)
}

/// Runs `f` on the active instance's table under its lock, then does the
/// namespace work `f` left owed (`DeferredWork`) with the lock released;
/// None when no table is active. `f` must not park, copy to or from user
/// memory, call back into this module's public functions, or take a lock
/// ranked at or below `LockRank::PROCESS_TABLE`: the rank check refuses
/// the last two and fails closed.
fn with_live_table<R>(f: impl FnOnce(&mut ProcessTable) -> R) -> Option<R> {
    let instance = active_process_instance()?;
    if !process_runtime().table_initialized[instance].load(Ordering::Acquire) {
        return None;
    }
    let (result, deferred) = {
        let mut table = PROCESS_TABLES[instance].lock();
        let result = f(&mut table);
        (
            result,
            core::mem::replace(&mut table.deferred, DeferredWork::NONE),
        )
    };
    deferred.run();
    Some(result)
}

/// Runs `f` on the record of process `pid` of the active instance's table,
/// under the table's lock (see `with_live_table` for what `f` may do).
fn with_live_process<R>(pid: u32, f: impl FnOnce(&mut Process) -> R) -> Option<R> {
    with_live_table(|table| {
        let handle = table.handle_by_pid(pid)?;
        table.process_mut(handle).map(f)
    })
    .flatten()
}

fn current_process_instance() -> usize {
    cpu::current_container_slot().unwrap_or(HOST_PROCESS_INSTANCE)
}

/// The System V instance the current process's IPC namespace keeps its
/// objects in: the domain's own unless it made one.
pub(crate) fn current_ipc_instance() -> usize {
    let instance = current_process_instance();
    if !linux_namespace::any(linux_namespace::Kind::Ipc) {
        return instance;
    }
    live_process_namespaces(cpu::current_linux_process_id())
        .filter(|set| set.ipc != 0)
        .and_then(|set| {
            linux_namespace::ipc_instance(cpu::current_linux_execution_instance(), set.ipc)
        })
        .unwrap_or(instance)
}

fn active_process_instance() -> Option<usize> {
    let instance = usize::from(process_runtime().active_instance.load(Ordering::Acquire));
    (instance < PROCESS_INSTANCE_LIMIT).then_some(instance)
}

fn scrub_candidate_resources(
    hierarchy: &[memory::FrameLease],
    pages: &[memory::FrameLease],
) -> bool {
    if !memory::frame_leases_releasable(memory::FrameOwner::KERNEL, hierarchy)
        || !memory::frame_leases_releasable(memory::FrameOwner::KERNEL, pages)
    {
        return false;
    }
    memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, hierarchy)
        && memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, pages)
}

pub(crate) fn copy_private_pages(
    source: &[memory::FrameLease],
    destination: &[memory::FrameLease],
) -> bool {
    if source.is_empty()
        || source.len() != destination.len()
        || !source.iter().all(|frame| {
            memory::frames_owned_by(memory::FrameOwner::KERNEL, &[*frame])
                || memory::frame_lease_is_runtime(*frame)
        })
        || !memory::frames_owned_by(memory::FrameOwner::KERNEL, destination)
        || source
            .iter()
            .enumerate()
            .any(|(index, frame)| source[..index].contains(frame) || destination.contains(frame))
        || destination
            .iter()
            .enumerate()
            .any(|(index, frame)| destination[..index].contains(frame))
    {
        return false;
    }
    // Every frame is checked before the first is written.
    if source
        .iter()
        .chain(destination)
        .any(|frame| Frame::leased(*frame).is_none())
    {
        return false;
    }
    for (source, destination) in source.iter().zip(destination) {
        let (Some(source), Some(destination)) =
            (Frame::leased(*source), Frame::leased(*destination))
        else {
            return false;
        };
        destination.copy_from(source);
    }
    true
}

fn copy_validated_private_pages(
    mappings: &[cpu::LinuxActiveImageMapping],
    root: memory::FrameLease,
    source: &[memory::FrameLease],
    destination: &[memory::FrameLease],
) -> bool {
    if source.is_empty()
        || source.len() != destination.len()
        || mappings
            .iter()
            .filter(|mapping| mapping_requires_fork_copy(mapping))
            .count()
            != source.len()
        || !memory::frames_owned_by(memory::FrameOwner::KERNEL, destination)
    {
        return false;
    }
    for ((mapping, source_frame), destination_frame) in mappings
        .iter()
        .filter(|mapping| mapping_requires_fork_copy(mapping))
        .zip(source)
        .zip(destination)
    {
        let (Some(source_page), Some(destination_page)) = (
            Frame::leased(*source_frame),
            Frame::leased(*destination_frame),
        ) else {
            return false;
        };
        let Some(wipeonfork) = address_space::linux_mapping_wipe_on_fork(root, mapping.address)
        else {
            return false;
        };
        if wipeonfork {
            destination_page.zero();
        } else {
            destination_page.copy_from(source_page);
        }
    }
    true
}

pub(crate) fn verify_private_page_copy_contract() -> bool {
    let Some(before) = memory::owner_live_frame_count(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let Some(source) =
        memory::allocate_frames::<FORK_PRIVATE_PAGE_LIMIT>(memory::FrameOwner::KERNEL)
    else {
        return false;
    };
    let Some(destination) =
        memory::allocate_frames::<FORK_PRIVATE_PAGE_LIMIT>(memory::FrameOwner::KERNEL)
    else {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &source);
        return false;
    };

    let result = (|| {
        let source_pages = source.map(Frame::leased);
        let destination_pages = destination.map(Frame::leased);
        if source_pages.iter().any(Option::is_none) || destination_pages.iter().any(Option::is_none)
        {
            return None;
        }
        for (index, page) in source_pages.iter().enumerate() {
            let page = (*page)?;
            page.write_u8(0, 0x41 + index as u8);
            page.write_u8(PAGE_SIZE - 1, 0x61 + index as u8);
        }

        let stale_generation = destination[0].generation().checked_add(1)?;
        let stale = memory::FrameLease::from_parts(destination[0].address(), stale_generation)?;
        let mut stale_destination = destination;
        stale_destination[0] = stale;
        if copy_private_pages(&source, &stale_destination)
            || copy_private_pages(&source, &source)
            || destination_pages
                .iter()
                .any(|page| page.is_none_or(|page| !page.is_zero()))
            || !copy_private_pages(&source, &destination)
        {
            return None;
        }

        for (source_page, destination_page) in source_pages.iter().zip(destination_pages.iter()) {
            let (source_page, destination_page) = ((*source_page)?, (*destination_page)?);
            if (0..PAGE_SIZE / size_of::<u64>())
                .any(|word| source_page.read_u64(word) != destination_page.read_u64(word))
            {
                return None;
            }
        }

        let first_source = source_pages[0]?;
        let first_destination = destination_pages[0]?;
        first_destination.write_u8(0, 0xff);
        Some(first_source.read_u8(0) == 0x41)
    })()
    .unwrap_or(false);

    let destination_released =
        memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &destination);
    let source_released = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &source);
    result
        && destination_released
        && source_released
        && memory::owner_live_frame_count(memory::FrameOwner::KERNEL) == Some(before)
}
