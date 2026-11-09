#![forbid(unsafe_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::x86_64::{__cpuid, __cpuid_count};

use crate::sync::{IrqSpinLock, LockRank};
use crate::trusted::claim::{Claim, ClaimCell};
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use smoltcp::wire::IpAddress;

use super::{paging, timer};
use crate::trusted::control::{self, Cr4Feature};
use crate::trusted::cpu_tables;
use crate::trusted::entry::{EntryStub, FatalFrame, LinuxSyscallFrameHandle};
use crate::trusted::msr::{self, configure_linux_syscall, restore_linux_syscall, SyscallMsrs};

mod activation;
mod architecture;
mod boot_verify;
mod boot_verify_elf;
mod execution;
mod fanotify;
mod linux_abi;
mod linux_aio;
mod linux_cgroupfs;
mod linux_controller;
mod linux_credentials;
mod linux_descriptors;
mod linux_devices;
mod linux_diagnostics;
mod linux_directories;
mod linux_domain_runtime;
mod linux_epoll;
mod linux_event_fds;
mod linux_exec;
mod linux_fcntl;
mod linux_file_open;
mod linux_file_ops;
mod linux_fsmount;
mod linux_futex;
mod linux_hugetlb;
mod linux_inotify;
mod linux_ipc;
mod linux_keys;
mod linux_ktls;
mod linux_memory_protection;
mod linux_mmap;
mod linux_mounts;
mod linux_namespaces;
mod linux_numa;
mod linux_path_walk;
mod linux_perf;
mod linux_pipes;
mod linux_poll;
mod linux_prctl;
mod linux_process_lifecycle;
mod linux_process_state;
mod linux_process_vm;
mod linux_procfs;
mod linux_pty;
mod linux_quota;
mod linux_read_write;
mod linux_rlimit;
mod linux_rtnetlink;
mod linux_runtime_loop;
mod linux_sched_syscalls;
mod linux_scheduler;
mod linux_security;
mod linux_signal;
mod linux_sockets;
mod linux_swapon;
mod linux_syscall;
mod linux_system;
mod linux_thread;
mod linux_time;
mod linux_timers;
mod linux_tun;
mod linux_user_memory;
mod linux_userfaultfd;
mod native_services;
pub(crate) use architecture::{
    clear_interrupt_gate, current_cpu_index, current_cpu_index_checked, double_fault_guard_page,
    double_fault_stack_top, install, install_for_cpu, install_interrupt_gate,
    kernel_stack_top_for_cpu, machine_check_guard_page, machine_check_stack_top, nmi_guard_page,
    nmi_stack_top, privilege_stack_guard_page, privilege_stack_top, stack_guard_pages,
    task_register_denies_user_io, user_interrupt_surface_is_minimal,
};
use architecture::{install_user_interrupt_gate, CPU_ARCHITECTURE};
pub(crate) use boot_verify::*;
pub(crate) use boot_verify_elf::*;
pub(crate) use execution::enable_extended_user_state;
use execution::{
    clone_linux_process_extended_state, discard_container_extended_state,
    discard_linux_process_extended_state, discard_linux_thread_extended_state,
    initialize_linux_thread_extended_state, linux_thread_xstate, linux_xstate_size,
    reset_extended_user_state, restore_container_extended_state,
    restore_linux_process_extended_state, restore_linux_thread_extended_state,
    save_container_extended_state, save_linux_process_extended_state,
    save_linux_thread_extended_state, set_linux_thread_xstate, switch_linux_thread_extended_state,
    ExtendedState, EXTENDED_STATE_SIZE,
};
use fanotify::*;
pub(crate) use linux_abi::*;
use linux_aio::*;
use linux_cgroupfs::*;
pub(crate) use linux_cgroupfs::{
    charge_linux_user_pages, linux_cache_charge_slot, reclaim_linux_user_pages,
};
use linux_controller::*;
pub(crate) use linux_credentials::*;
use linux_descriptors::*;
pub(crate) use linux_devices::*;
pub(crate) use linux_diagnostics::*;
use linux_directories::*;
pub(crate) use linux_domain_runtime::*;
pub(super) use linux_epoll::*;
use linux_event_fds::*;
pub(crate) use linux_exec::*;
pub(super) use linux_fcntl::*;
pub(super) use linux_file_open::*;
use linux_file_ops::*;
use linux_fsmount::*;
use linux_futex::*;
use linux_hugetlb::*;
pub(crate) use linux_inotify::*;
use linux_ipc::*;
use linux_keys::*;
use linux_ktls::*;
use linux_memory_protection::*;
pub(crate) use linux_mmap::*;
pub(crate) use linux_mounts::*;
use linux_namespaces::*;
use linux_numa::*;
pub(super) use linux_path_walk::*;
use linux_perf::*;
use linux_pipes::*;
use linux_poll::*;
use linux_prctl::*;
pub(crate) use linux_process_lifecycle::*;
use linux_process_state::*;
use linux_process_vm::*;
use linux_procfs::*;
use linux_pty::*;
use linux_quota::*;
use linux_read_write::*;
use linux_rlimit::*;
use linux_rtnetlink::*;
pub(crate) use linux_runtime_loop::*;
use linux_sched_syscalls::*;
pub(crate) use linux_scheduler::*;
use linux_security::*;
use linux_signal::*;
pub(crate) use linux_signal::{
    expire_linux_waits_from_timer, linux_nanoseconds_to_next_wait_deadline, sample_linux_profile,
};
use linux_sockets::*;
pub(crate) use linux_swapon::linux_swap_read_page;
use linux_swapon::*;
use linux_swapon::{linux_own_pages_reclaimable, linux_swap_out_current};
pub(crate) use linux_syscall::linux_syscall_handler;
pub(crate) use linux_system::*;
use linux_thread::*;
use linux_time::*;
pub(super) use linux_timers::*;
use linux_tun::*;
use linux_user_memory::*;
use linux_userfaultfd::*;
pub(crate) use native_services::*;

use crate::linux_wait_queue::{events as wait_events, WaitOn};
use crate::{
    address_space,
    capability::Rights,
    control_abi, domain, image_store, initramfs, ipc, linux_mount, linux_namespace, linux_process,
    linux_tmpfs, linux_user, memory, network, scheduler,
    scheduler::{
        RuntimeAction, UserFaultContext, UserFaultFrame, UserInterruptFrame, UserTrapFrame,
    },
    serial_write, serial_write_hex, serial_write_u64, volume,
};

const KERNEL_CODE_SELECTOR: u16 = 0x08;
const KERNEL_DATA_SELECTOR: u16 = 0x10;
const TSS_SELECTOR: u16 = 0x18;
pub(crate) use crate::trusted::cpu_tables::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};
const SYSCALL_VECTOR: u8 = 0x80;
const CALL_BUDGET_EXHAUSTED: u64 = u64::MAX - 3;
const DOUBLE_FAULT_IST: u8 = 1;
const NMI_IST: u8 = 2;
const MACHINE_CHECK_IST: u8 = 3;
const BOOT_CPU_INDEX: usize = 0;
const CPU_ENTRY_STATE_LIMIT: usize = 4;
const PAGE_SIZE: usize = 4096;
pub(crate) const LINUX_MMAP_SLOT_COUNT: usize = 4;
const LINUX_RUNTIME_MMAP_SLOT_COUNT: usize = 32;
const LINUX_RUNTIME_DYNAMIC_MMAP_BASE: u64 = 1 << 39;
/// Where MAP_32BIT mappings go: the second gigabyte, as on x86-64 Linux,
/// above the program image and heap and below 2 GiB. The 2 MiB regions
/// the kernel keeps in every address space (its image, wherever the
/// firmware put it, `paging::linux_low_template`) are taken there.
const LINUX_LOW_MMAP_BASE: u64 = 0x4000_0000;
const LINUX_LOW_MMAP_LIMIT: u64 = 0x8000_0000;
/// The lowest address a program may map at with MAP_FIXED (or unmap and
/// protect) below the mmap area, up to it: above the kernel's own
/// placements (heap, stack, vDSO and the program image near 4 MiB), so only
/// the program's own mappings are there (munmap04 maps from 256 MiB up).
/// The kernel's own regions there (the low template's) are EEXIST, or
/// ENOMEM for MAP_FIXED. munmap, mprotect and madvise from here up take
/// the runtime's paths, and exec drops what is mapped from here up.
const LINUX_FIXED_LOW_BASE: u64 = 0x1000_0000;

/// Whether `[address, end)` lies in the fixed-mapping window below the mmap
/// area (`LINUX_FIXED_LOW_BASE`) and holds no page of the program image.
fn linux_in_fixed_low_window(address: u64, end: u64) -> bool {
    address >= LINUX_FIXED_LOW_BASE
        && end <= LINUX_RUNTIME_DYNAMIC_MMAP_BASE
        && !linux_range_holds_image_page(address, end)
}
pub(crate) const LINUX_RUNTIME_STACK_PAGES: usize = 1;
pub(crate) const LINUX_RUNTIME_HEAP_PAGES: usize = 16;
const EXCEPTION_STACK_SIZE: usize = 4 * 1024 * 1024;
const EXCEPTION_STACK_STORAGE_SIZE: usize = PAGE_SIZE + EXCEPTION_STACK_SIZE + PAGE_SIZE;
const EXCEPTION_STACK_TOP_OFFSET: usize = PAGE_SIZE + EXCEPTION_STACK_SIZE;
// A CPU's own kernel stack holds its scheduler loop and, on an application
// processor, the process it runs and that process's system calls (the boot
// CPU runs them on activation stacks). Processes once ran nested inside
// their parents' calls here, where 512 KiB overflowed; it keeps the boot
// CPU's size.
const CPU_KERNEL_STACK_SIZE: usize = 2 * 1024 * 1024;
const CPU_KERNEL_STACK_STORAGE_SIZE: usize = PAGE_SIZE + CPU_KERNEL_STACK_SIZE + PAGE_SIZE;
const CPU_KERNEL_STACK_TOP_OFFSET: usize = PAGE_SIZE + CPU_KERNEL_STACK_SIZE;
const IST_STACK_SIZE: usize = 64 * 1024;
const IST_STACK_STORAGE_SIZE: usize = PAGE_SIZE + IST_STACK_SIZE + PAGE_SIZE;
const IST_STACK_TOP_OFFSET: usize = PAGE_SIZE + IST_STACK_SIZE;
const CPUID_STRUCTURED_FEATURES: u32 = 7;
const CPUID_EXTENDED_STATE: u32 = 0x0d;
const CPUID_EXTENDED_MAX: u32 = 0x8000_0000;
const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
const CPUID_NX: u32 = 1 << 20;
const CPUID_SMEP: u32 = 1 << 7;
const CPUID_SMAP: u32 = 1 << 20;
const CPUID_UMIP: u32 = 1 << 2;
const CPUID_XSAVE: u32 = 1 << 26;
const CPUID_AVX: u32 = 1 << 28;
const CPUID_SSE: u32 = 1 << 25;
const GS_BASE_MSR: u32 = 0xc000_0101;
const KERNEL_GS_BASE_MSR: u32 = 0xc000_0102;

static BREAKPOINT_HANDLED: AtomicBool = AtomicBool::new(false);
static SYSCALL_STATE: AtomicU8 = AtomicU8::new(0);
struct RuntimeRef<T: ?Sized + 'static>(&'static T);

impl<T: ?Sized> Copy for RuntimeRef<T> {}

impl<T: ?Sized> Clone for RuntimeRef<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> core::ops::Deref for RuntimeRef<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a RuntimeRef<[T; N]> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[allow(non_snake_case)]
struct X86RuntimeOwner {
    CONTAINER_ACTIVE_SLOT: RuntimeRef<AtomicU8>,
    CONTAINER_BACKGROUND_SUSPENDED: RuntimeRef<[AtomicBool; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_CONFIG_FLAGS: RuntimeRef<[AtomicU16; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_CONSOLE_ATTACHED: RuntimeRef<[AtomicBool; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_CONSOLE_BYTES:
        RuntimeRef<[[AtomicU8; CONTAINER_CONSOLE_CAPACITY]; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_CONSOLE_CURSOR: RuntimeRef<[AtomicU64; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_CONTROL_STATES: RuntimeRef<[AtomicU8; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_CPU_COUNTS: RuntimeRef<[AtomicU16; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_DOMAIN_IDS: RuntimeRef<[AtomicU64; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_EXEC_ARGUMENTS: RuntimeRef<
        [[[AtomicU8; DOMAIN_EXEC_ARGUMENT_CAPACITY]; control_abi::DOMAIN_EXEC_MAX_ARGUMENTS];
            control_abi::DOMAIN_LIMIT],
    >,
    CONTAINER_EXEC_ARGUMENT_COUNTS: RuntimeRef<[AtomicU8; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_EXEC_ARGUMENT_SIZES: RuntimeRef<
        [[AtomicU16; control_abi::DOMAIN_EXEC_MAX_ARGUMENTS]; control_abi::DOMAIN_LIMIT],
    >,
    CONTAINER_EXEC_INTERACTIVE: RuntimeRef<[AtomicBool; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_EXEC_REQUESTED: RuntimeRef<[AtomicBool; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_EXTENDED_STATE_VALID: RuntimeRef<[AtomicBool; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_HOST_SHUTDOWN_REQUESTED: RuntimeRef<AtomicBool>,
    CONTAINER_IMAGES:
        RuntimeRef<[[AtomicU8; control_abi::DOMAIN_MAX_IMAGE_SIZE]; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_IMAGE_SIZES: RuntimeRef<[AtomicU8; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_INITS:
        RuntimeRef<[[AtomicU8; control_abi::DOMAIN_MAX_INIT_SIZE]; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_INIT_SIZES: RuntimeRef<[AtomicU8; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_INSTALL_REQUESTED: RuntimeRef<AtomicBool>,
    CONTAINER_LAST_RESUMED_SLOT: RuntimeRef<AtomicU8>,
    CONTAINER_MANAGEMENT_ENABLED: RuntimeRef<AtomicBool>,
    CONTAINER_MEMORY_MIB: RuntimeRef<[AtomicU64; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_NAMES:
        RuntimeRef<[[AtomicU8; control_abi::DOMAIN_MAX_NAME_SIZE]; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_NAME_SIZES: RuntimeRef<[AtomicU8; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_PULL_REQUESTED: RuntimeRef<AtomicBool>,
    CONTAINER_RESTART_REQUESTED: RuntimeRef<AtomicBool>,
    CONTAINER_SELECTED_SLOT: RuntimeRef<AtomicU8>,
    CONTAINER_START_PENDING: RuntimeRef<[AtomicBool; control_abi::DOMAIN_LIMIT]>,
    CONTAINER_STOP_REQUESTED: RuntimeRef<[AtomicBool; control_abi::DOMAIN_LIMIT]>,
    DOMAIN_PERSONALITIES: RuntimeRef<
        [[AtomicU8; control_abi::DOMAIN_MAX_PERSONALITY_SIZE]; control_abi::DOMAIN_LIMIT],
    >,
    DOMAIN_PERSONALITY_SIZES: RuntimeRef<[AtomicU8; control_abi::DOMAIN_LIMIT]>,
    ELF_PROBE_ACTIVE: RuntimeRef<CpuBankedAtomicBool>,
    ELF_PROBE_ACTIVE_IMAGE_ADDRESSES:
        RuntimeRef<[BankedAtomicU64; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT]>,
    ELF_PROBE_ACTIVE_IMAGE_COUNT: RuntimeRef<BankedAtomicU16>,
    ELF_PROBE_ACTIVE_IMAGE_FLAGS: RuntimeRef<[CpuBankedAtomicU8; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT]>,
    ELF_PROBE_ACTIVE_IMAGE_FRAMES:
        RuntimeRef<[CpuBankedAtomicU64; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT]>,
    ELF_PROBE_ACTIVE_IMAGE_GENERATIONS:
        RuntimeRef<[CpuBankedAtomicU32; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT]>,
    ELF_PROBE_ALT_STACK_FLAGS: RuntimeRef<CpuBankedAtomicU32>,
    ELF_PROBE_ALT_STACK_POINTER: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_ALT_STACK_SIZE: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_BRK: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_BRK_LIMIT: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_CLOCK_EPOCH: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_CLOCK_FREQUENCY: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_CODE_BASE: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_CODE_SIZE: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_COMPLETED: RuntimeRef<CpuBankedAtomicBool>,
    ELF_PROBE_CONSOLE_CLOEXEC: RuntimeRef<[CpuBankedAtomicU64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT]>,
    /// Per descriptor: its open created the file (F_CREATED_QUERY), and
    /// the lease it holds (F_SETLEASE), one bit per descriptor.
    ELF_PROBE_DESCRIPTOR_CREATED:
        RuntimeRef<[CpuBankedAtomicU64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT]>,
    ELF_PROBE_DESCRIPTOR_READ_LEASES:
        RuntimeRef<[CpuBankedAtomicU64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT]>,
    ELF_PROBE_DESCRIPTOR_WRITE_LEASES:
        RuntimeRef<[CpuBankedAtomicU64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT]>,
    ELF_PROBE_CONSOLE_DESCRIPTORS: RuntimeRef<CpuBankedAtomicU8>,
    ELF_PROBE_CWD: RuntimeRef<CpuBankedAtomicU16>,
    ELF_PROBE_DATA: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_DATA_SIZE: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_DEPENDENCY_BASE_END: RuntimeRef<[BankedAtomicU64; LINUX_DEPENDENCY_COUNT]>,
    ELF_PROBE_DEPENDENCY_BASE_MIN: RuntimeRef<[BankedAtomicU64; LINUX_DEPENDENCY_COUNT]>,
    ELF_PROBE_DEPENDENCY_FILE_SIZES: RuntimeRef<[BankedAtomicU64; LINUX_DEPENDENCY_STATE_COUNT]>,
    ELF_PROBE_DEPENDENCY_FRAMES: RuntimeRef<[BankedAtomicU64; LINUX_DEPENDENCY_STATE_COUNT]>,
    ELF_PROBE_DEPENDENCY_GENERATIONS: RuntimeRef<[BankedAtomicU32; LINUX_DEPENDENCY_STATE_COUNT]>,
    ELF_PROBE_DEPENDENCY_MAPPINGS: RuntimeRef<[BankedAtomicU8; LINUX_DEPENDENCY_COUNT]>,
    ELF_PROBE_DEPENDENCY_OFFSETS: RuntimeRef<[BankedAtomicU64; LINUX_DEPENDENCY_STATE_COUNT]>,
    ELF_PROBE_DEPENDENCY_PROTECTIONS: RuntimeRef<[BankedAtomicU8; LINUX_DEPENDENCY_STATE_COUNT]>,
    ELF_PROBE_DEPENDENCY_RELATIVES: RuntimeRef<[BankedAtomicU64; LINUX_DEPENDENCY_STATE_COUNT]>,
    ELF_PROBE_DEPENDENCY_SELECTED_BASE: RuntimeRef<[BankedAtomicU64; LINUX_DEPENDENCY_COUNT]>,
    ELF_PROBE_DESCRIPTOR_OFFSETS:
        RuntimeRef<CpuBankedAtomicArray<AtomicU64, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    ELF_PROBE_DEVICE_DESCRIPTORS:
        RuntimeRef<CpuBankedAtomicArray<AtomicU16, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    ELF_PROBE_DUMPABLE: RuntimeRef<CpuBankedAtomicBool>,
    ELF_PROBE_TSC_SIGSEGV: RuntimeRef<CpuBankedAtomicBool>,
    ELF_PROBE_EPOLL_DATA:
        RuntimeRef<CpuBankedAtomicArray<AtomicU64, { LINUX_DESCRIPTOR_TABLE_LIMIT as usize }>>,
    ELF_PROBE_EPOLL_DESCRIPTOR: RuntimeRef<CpuBankedAtomicU16>,
    /// The `linux_fd_table` id of the current process's descriptors above
    /// the fixed table (0: none).
    ELF_PROBE_DESCRIPTOR_OVERFLOW: RuntimeRef<CpuBankedAtomicU32>,
    ELF_PROBE_EPOLL_EVENTS:
        RuntimeRef<CpuBankedAtomicArray<AtomicU32, { LINUX_DESCRIPTOR_TABLE_LIMIT as usize }>>,
    ELF_PROBE_EVENTFD_COUNTER: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_EVENTFD_DESCRIPTOR: RuntimeRef<BankedAtomicU16>,
    ELF_PROBE_EVENTFD_FLAGS: RuntimeRef<BankedAtomicU32>,
    ELF_PROBE_EXEC_ENTRY: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_EXEC_IGNORED_SIGNALS: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_EXEC_MAPPING_ADDRESSES: RuntimeRef<[BankedAtomicU64; LINUX_EXEC_MAPPING_LIMIT]>,
    ELF_PROBE_EXEC_MAPPING_FLAGS: RuntimeRef<[BankedAtomicU8; LINUX_EXEC_MAPPING_LIMIT]>,
    ELF_PROBE_EXEC_MAPPING_FRAMES: RuntimeRef<[CpuBankedAtomicU64; LINUX_EXEC_MAPPING_LIMIT]>,
    ELF_PROBE_EXEC_MAPPING_GENERATIONS: RuntimeRef<[CpuBankedAtomicU32; LINUX_EXEC_MAPPING_LIMIT]>,
    ELF_PROBE_EXEC_NODE: RuntimeRef<BankedAtomicU8>,
    ELF_PROBE_EXEC_REPLACED: RuntimeRef<BankedAtomicBool>,
    ELF_PROBE_EXITED_CLEAR_CHILD_TID: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_EXITED_ROBUST_LIST: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_EXIT_STATUS: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_HEAP_FRAME: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_HEAP_GENERATION: RuntimeRef<CpuBankedAtomicU32>,
    ELF_PROBE_IOPRIO: RuntimeRef<CpuBankedAtomicU16>,
    ELF_PROBE_LOADER_CODE_BASE: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_LOADER_CODE_SIZE: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_MAIN_ADDRESSES: RuntimeRef<[BankedAtomicU64; LINUX_MAIN_MAPPING_COUNT]>,
    ELF_PROBE_MAIN_FILE_SIZES: RuntimeRef<[BankedAtomicU64; LINUX_MAIN_MAPPING_COUNT]>,
    ELF_PROBE_MAIN_FRAMES: RuntimeRef<[BankedAtomicU64; LINUX_MAIN_MAPPING_COUNT]>,
    ELF_PROBE_MAIN_GENERATIONS: RuntimeRef<[BankedAtomicU32; LINUX_MAIN_MAPPING_COUNT]>,
    ELF_PROBE_MAIN_MAPPINGS: RuntimeRef<BankedAtomicU8>,
    ELF_PROBE_MAIN_OFFSETS: RuntimeRef<[BankedAtomicU64; LINUX_MAIN_MAPPING_COUNT]>,
    ELF_PROBE_MAIN_PROTECTIONS: RuntimeRef<[BankedAtomicU8; LINUX_MAIN_MAPPING_COUNT]>,
    ELF_PROBE_MEMBARRIER_REGISTRATIONS: RuntimeRef<CpuBankedAtomicU32>,
    ELF_PROBE_MMAP: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_MMAP_FILE: RuntimeRef<[CpuBankedAtomicU8; LINUX_RUNTIME_MMAP_SLOT_COUNT]>,
    ELF_PROBE_MMAP_FRAMES: RuntimeRef<[CpuBankedAtomicU64; LINUX_RUNTIME_MMAP_SLOT_COUNT]>,
    ELF_PROBE_MMAP_GENERATIONS: RuntimeRef<[CpuBankedAtomicU32; LINUX_RUNTIME_MMAP_SLOT_COUNT]>,
    ELF_PROBE_MMAP_NEXT: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_MMAP_PAGES: RuntimeRef<[CpuBankedAtomicU8; LINUX_RUNTIME_MMAP_SLOT_COUNT]>,
    ELF_PROBE_MMAP_PROTECTION: RuntimeRef<[CpuBankedAtomicU8; LINUX_RUNTIME_MMAP_SLOT_COUNT]>,
    ELF_PROBE_MMAP_SEALED: RuntimeRef<[CpuBankedAtomicBool; LINUX_RUNTIME_MMAP_SLOT_COUNT]>,
    ELF_PROBE_NICE: RuntimeRef<CpuBankedAtomicU8>,
    ELF_PROBE_NO_NEW_PRIVS: RuntimeRef<CpuBankedAtomicBool>,
    ELF_PROBE_OPEN_FILE_IDS:
        RuntimeRef<CpuBankedAtomicArray<AtomicU64, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    ELF_PROBE_OVERLAY_CWD: RuntimeRef<CpuBankedAtomicU32>,
    ELF_PROBE_PAGE_TABLE_FRAMES: RuntimeRef<[CpuBankedAtomicU64; 6]>,
    ELF_PROBE_PAGE_TABLE_GENERATIONS: RuntimeRef<[CpuBankedAtomicU32; 6]>,
    ELF_PROBE_PARENT_DEATH_SIGNAL: RuntimeRef<CpuBankedAtomicU32>,
    ELF_PROBE_PENDING_SIGNALS: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_PENDING_SIGNAL_CODES: RuntimeRef<[CpuBankedAtomicU32; LINUX_SIGNAL_COUNT]>,
    ELF_PROBE_PENDING_SIGNAL_VALUES: RuntimeRef<[CpuBankedAtomicU64; LINUX_SIGNAL_COUNT]>,
    ELF_PROBE_PERSONALITY: RuntimeRef<CpuBankedAtomicU32>,
    ELF_PROBE_PIPE_BUFFER: RuntimeRef<[BankedAtomicU8; LINUX_PIPE_CAPACITY]>,
    ELF_PROBE_PIPE_LENGTH: RuntimeRef<BankedAtomicU32>,
    ELF_PROBE_PIPE_READ_DESCRIPTOR: RuntimeRef<BankedAtomicU16>,
    ELF_PROBE_PIPE_READ_FLAGS: RuntimeRef<BankedAtomicU32>,
    ELF_PROBE_PIPE_WRITE_DESCRIPTOR: RuntimeRef<BankedAtomicU16>,
    ELF_PROBE_PIPE_WRITE_FLAGS: RuntimeRef<BankedAtomicU32>,
    ELF_PROBE_POSIX_MQ_BYTES: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_POSIX_TIMER_ACTIVE: RuntimeRef<BankedAtomicBool>,
    /// The earliest armed POSIX timer deadline of the process (the tick's
    /// check before the process table), kept per process bank like the
    /// interval timer's and saved with the process's state.
    ELF_PROBE_POSIX_TIMER_DEADLINE: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_POSIX_TIMER_INTERVAL: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_PROCESS_NAME_HIGH: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_PROCESS_NAME_LOW: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_READ_ONLY_DATA_PAGE: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_REAL_TIMER_DEADLINE: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_REAL_TIMER_INTERVAL: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_RECLAIM_HEAP_FRAME: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_RECLAIM_HEAP_GENERATION: RuntimeRef<BankedAtomicU32>,
    ELF_PROBE_RECLAIM_PAGE_TABLE_FRAMES: RuntimeRef<[BankedAtomicU64; 6]>,
    ELF_PROBE_RECLAIM_PAGE_TABLE_GENERATIONS: RuntimeRef<[BankedAtomicU32; 6]>,
    ELF_PROBE_RECLAIM_SIBLING_STACK_FRAME: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_RECLAIM_SIBLING_STACK_GENERATION: RuntimeRef<BankedAtomicU32>,
    ELF_PROBE_RECLAIM_TLS_FRAMES: RuntimeRef<[BankedAtomicU64; 2]>,
    ELF_PROBE_RECLAIM_TLS_GENERATIONS: RuntimeRef<[BankedAtomicU32; 2]>,
    ELF_PROBE_RELRO: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_RELRO_SIZE: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_RETIRED_IMAGE_ADDRESSES:
        RuntimeRef<[BankedAtomicU64; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT]>,
    ELF_PROBE_RETIRED_IMAGE_COUNT: RuntimeRef<BankedAtomicU8>,
    ELF_PROBE_RETIRED_IMAGE_FLAGS: RuntimeRef<[BankedAtomicU8; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT]>,
    ELF_PROBE_RETIRED_IMAGE_FRAMES: RuntimeRef<[BankedAtomicU64; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT]>,
    ELF_PROBE_RETIRED_IMAGE_GENERATIONS:
        RuntimeRef<[BankedAtomicU32; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT]>,
    ELF_PROBE_RLIMITS: RuntimeRef<[CpuBankedAtomicU64; LINUX_RLIMIT_WORDS]>,
    ELF_PROBE_ROOTFS_CWD: RuntimeRef<CpuBankedAtomicU16>,
    ELF_PROBE_ROOTFS_DESCRIPTORS:
        RuntimeRef<CpuBankedAtomicArray<AtomicU16, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    ELF_PROBE_SECCOMP_FILTERED: RuntimeRef<CpuBankedAtomicBool>,
    ELF_PROBE_SECCOMP_STRICT: RuntimeRef<CpuBankedAtomicBool>,
    ELF_PROBE_SECUREBITS: RuntimeRef<CpuBankedAtomicU32>,
    ELF_PROBE_SIBLING_FS_BASE: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_SIBLING_STACK: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_SIBLING_STACK_FRAME: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_SIBLING_STACK_GENERATION: RuntimeRef<BankedAtomicU32>,
    ELF_PROBE_SIBLING_TLS: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_SIGNAL_ACTION_MASKS: RuntimeRef<[CpuBankedAtomicU64; LINUX_SIGNAL_COUNT]>,
    ELF_PROBE_SIGNAL_FLAGS: RuntimeRef<[CpuBankedAtomicU64; LINUX_SIGNAL_COUNT]>,
    ELF_PROBE_SIGNAL_HANDLERS: RuntimeRef<[CpuBankedAtomicU64; LINUX_SIGNAL_COUNT]>,
    ELF_PROBE_SIGNAL_MASK: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_SIGNAL_RESTORERS: RuntimeRef<[CpuBankedAtomicU64; LINUX_SIGNAL_COUNT]>,
    ELF_PROBE_SOCKET_FLAGS:
        RuntimeRef<CpuBankedAtomicArray<AtomicU32, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    ELF_PROBE_SOCKET_SLOTS:
        RuntimeRef<CpuBankedAtomicArray<AtomicU16, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    ELF_PROBE_STACK: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_STACK_FRAME: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_STACK_GENERATION: RuntimeRef<CpuBankedAtomicU32>,
    ELF_PROBE_STACK_LOW: RuntimeRef<CpuBankedAtomicU64>,
    ELF_PROBE_STDERR_OPEN: RuntimeRef<CpuBankedAtomicBool>,
    ELF_PROBE_STDIO_DEVICE_DESCRIPTORS: RuntimeRef<[CpuBankedAtomicU16; 3]>,
    ELF_PROBE_STDIO_OFFSETS: RuntimeRef<CpuBankedAtomicArray<AtomicU64, 3>>,
    ELF_PROBE_STDIO_OPEN_FILE_IDS: RuntimeRef<CpuBankedAtomicArray<AtomicU64, 3>>,
    ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS: RuntimeRef<[CpuBankedAtomicU16; 3]>,
    ELF_PROBE_STDIO_SOCKET_FLAGS: RuntimeRef<CpuBankedAtomicArray<AtomicU32, 3>>,
    ELF_PROBE_STDIO_SOCKET_SLOTS: RuntimeRef<[CpuBankedAtomicU16; 3]>,
    ELF_PROBE_STDIO_TMP_FILE_GENERATIONS: RuntimeRef<CpuBankedAtomicArray<AtomicU32, 3>>,
    ELF_PROBE_SYSTEM_INIT: RuntimeRef<AtomicBool>,
    ELF_PROBE_TERMINATION_SIGNAL: RuntimeRef<CpuBankedAtomicU32>,
    ELF_PROBE_TIMERFD_CLOCK: RuntimeRef<BankedAtomicU8>,
    ELF_PROBE_TIMERFD_DEADLINE: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_TIMERFD_DESCRIPTOR: RuntimeRef<BankedAtomicU16>,
    ELF_PROBE_TIMERFD_FLAGS: RuntimeRef<BankedAtomicU32>,
    ELF_PROBE_TIMERFD_INTERVAL: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_TLS: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_TLS_FRAMES: RuntimeRef<[BankedAtomicU64; 2]>,
    ELF_PROBE_TLS_GENERATIONS: RuntimeRef<[BankedAtomicU32; 2]>,
    ELF_PROBE_TLS_SIZE: RuntimeRef<BankedAtomicU64>,
    ELF_PROBE_TMP_FILE_GENERATIONS:
        RuntimeRef<CpuBankedAtomicArray<AtomicU32, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    ELF_PROBE_UMASK: RuntimeRef<CpuBankedAtomicU64>,
    LINUX_BOOT_ID_STATE: RuntimeRef<AtomicU8>,
    LINUX_BOOT_PROFILE_LIFECYCLE_COUNTS:
        RuntimeRef<[BankedAtomicU64; LINUX_BOOT_PROFILE_LIFECYCLE_PHASES]>,
    LINUX_BOOT_PROFILE_LIFECYCLE_TICKS:
        RuntimeRef<[BankedAtomicU64; LINUX_BOOT_PROFILE_LIFECYCLE_PHASES]>,
    LINUX_BOOT_PROFILE_RESTORE_COUNT: RuntimeRef<BankedAtomicU64>,
    LINUX_BOOT_PROFILE_RESTORE_TICKS: RuntimeRef<BankedAtomicU64>,
    LINUX_BOOT_PROFILE_SAVE_COUNT: RuntimeRef<BankedAtomicU64>,
    LINUX_BOOT_PROFILE_SAVE_TICKS: RuntimeRef<BankedAtomicU64>,
    LINUX_BOOT_PROFILE_SYSCALL_COUNTS:
        RuntimeRef<[BankedAtomicU64; LINUX_BOOT_PROFILE_SYSCALL_LIMIT]>,
    LINUX_BOOT_PROFILE_SYSCALL_TICKS:
        RuntimeRef<[BankedAtomicU64; LINUX_BOOT_PROFILE_SYSCALL_LIMIT]>,
    LINUX_CHILD_EXIT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_CHILD_GETTID_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_CLONE_BUSY_REJECTION_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_CLONE_DISPATCH_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_CLONE_INVALID_REJECTION_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_CLONE_REUSE_VALIDATED: RuntimeRef<BankedAtomicBool>,
    LINUX_CLONE_TID_FAULT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_CONTROLLER_CONSOLE: RuntimeRef<AtomicU64>,
    LINUX_CONTROLLER_DOMAIN: RuntimeRef<AtomicU64>,
    LINUX_CONTROLLER_HOST: RuntimeRef<AtomicU64>,
    LINUX_CONTROLLER_NETWORK: RuntimeRef<AtomicU64>,
    LINUX_CONTROLLER_ROOT: RuntimeRef<AtomicU64>,
    LINUX_CROSS_PROCESS_PRLIMIT_VALIDATED: RuntimeRef<BankedAtomicBool>,
    LINUX_CURRENT_PROCESS_PID: RuntimeRef<CpuBankedAtomicU32>,
    LINUX_CURRENT_THREAD_SLOT: RuntimeRef<ThreadCpuAtomicU8>,
    LINUX_DESCRIPTOR_WAITS_ACTIVE: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_DOMAIN_EXEC_INJECT: RuntimeRef<AtomicBool>,
    LINUX_EPOLL_LAST_READY_DESCRIPTOR: RuntimeRef<BankedAtomicU64>,
    LINUX_EPOLL_LAST_READY_EVENTS: RuntimeRef<BankedAtomicU64>,
    LINUX_EPOLL_PWAIT_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EPOLL_PWAIT_TIMEOUT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EPOLL_PWAIT_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EPOLL_WAIT_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EPOLL_WAIT_INTERRUPT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EPOLL_WAIT_TIMEOUT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EPOLL_WAIT_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EVENTFD_READ_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EVENTFD_READ_INTERRUPT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EVENTFD_READ_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EVENTFD_WRITE_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EVENTFD_WRITE_INTERRUPT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EVENTFD_WRITE_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_EXECUTION_INSTANCE: RuntimeRef<PerCpuAtomicU8>,
    LINUX_FIRST_CHILD_TID: RuntimeRef<CpuBankedAtomicU32>,
    LINUX_FORK_CGROUP_GENERATION: RuntimeRef<CpuBankedAtomicU32>,
    LINUX_FORK_CHILD_STACK: RuntimeRef<CpuBankedAtomicU64>,
    LINUX_FORK_SHARE_VM: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_FORK_CHILD_TID_ADDRESS: RuntimeRef<CpuBankedAtomicU64>,
    /// clone3's CLONE_PARENT_SETTID: where the parent gets the child's pid.
    LINUX_FORK_PARENT_TID_ADDRESS: RuntimeRef<CpuBankedAtomicU64>,
    LINUX_FORK_CLEAR_SIGHAND: RuntimeRef<CpuBankedAtomicBool>,
    /// A fork on a child stack whose pages are the child's own copy
    /// (clone(SIGCHLD, stack), clone3 with a stack), not shared as
    /// posix_spawn's CLONE_VM form shares them.
    LINUX_FORK_OWN_PAGES: RuntimeRef<CpuBankedAtomicBool>,
    /// The clone flags of a process clone that the fork transaction acts
    /// on (`LinuxProcessClone`), the exit signal in the low byte.
    LINUX_FORK_CLONE_FLAGS: RuntimeRef<CpuBankedAtomicU64>,
    /// CLONE_SETTLS: the child's thread pointer.
    LINUX_FORK_TLS: RuntimeRef<CpuBankedAtomicU64>,
    /// CLONE_CHILD_CLEARTID: the word the child's exit clears and wakes.
    LINUX_FORK_CLEAR_TID_ADDRESS: RuntimeRef<CpuBankedAtomicU64>,
    LINUX_FORK_NEW_MOUNT_NAMESPACE: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_FORK_NEW_USER_NAMESPACE: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_FORK_PIDFD_ADDRESS: RuntimeRef<CpuBankedAtomicU64>,
    LINUX_FORK_REQUESTED: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_FSIZE_LIMIT_HIT: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_FUTEX_EXIT_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_FUTEX_EXPLICIT_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_FUTEX_WAIT_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_FUTEX_WAIT_TIMEOUT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_INIT_EXIT_KILL_ROUNDS: RuntimeRef<BankedAtomicU32>,
    LINUX_LAST_PREEMPTED_THREAD_SLOT: RuntimeRef<ThreadCpuAtomicU8>,
    LINUX_LIVE_RETURN_VALIDATED: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_MASKED_WAIT_INTERRUPT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_NEXT_OPEN_FILE_ID: RuntimeRef<BankedAtomicU64>,
    LINUX_NEXT_TID: RuntimeRef<CpuBankedAtomicU32>,
    LINUX_PARENT_RESUMED: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_PIPE_READ_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_PIPE_READ_INTERRUPT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_PIPE_READ_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_PIPE_WRITE_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_PIPE_WRITE_INTERRUPT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_PIPE_WRITE_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_POLL_WAIT_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_POLL_WAIT_INTERRUPT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_POLL_WAIT_TIMEOUT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_POLL_WAIT_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_PPOLL_WAIT_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_PPOLL_WAIT_TIMEOUT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_PPOLL_WAIT_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_PROCESS_CHILD_EXECUTED: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_PROCESS_CHILD_EXEC_PID: RuntimeRef<CpuBankedAtomicU32>,
    LINUX_PROCESS_CHILD_EXITED: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_PROCESS_CHILD_EXIT_PID: RuntimeRef<CpuBankedAtomicU32>,
    LINUX_PROCESS_CHILD_STATUS: RuntimeRef<CpuBankedAtomicU8>,
    LINUX_PROCESS_CHILD_YIELDED: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_PROCESS_CHILD_YIELD_PID: RuntimeRef<CpuBankedAtomicU32>,
    CONTAINER_EXEC_CHILD: RuntimeRef<[AtomicU32; control_abi::DOMAIN_LIMIT]>,
    LINUX_PROCESS_RELEASE_PARENT_ON_EXEC: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_PROCESS_SNAPSHOT_SCRATCH: RuntimeRef<ClaimCell<LinuxProcessAddressSpaceSnapshot>>,
    LINUX_PROCESS_SNAPSHOT_STAGE: RuntimeRef<CpuBankedAtomicU8>,
    LINUX_PROCESS_SNAPSHOT_VALIDATED: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_PROCESS_WAIT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_RUNTIME_BACKGROUND_QUANTA: RuntimeRef<AtomicU32>,
    LINUX_RUNTIME_BACKGROUND_SUSPENDED: RuntimeRef<BankedAtomicBool>,
    LINUX_RUNTIME_BACKGROUND_TICKS: RuntimeRef<BankedAtomicU32>,
    LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED: RuntimeRef<BankedAtomicBool>,
    LINUX_RUNTIME_CONSOLE_TIMING_WRITTEN: RuntimeRef<BankedAtomicBool>,
    LINUX_RUNTIME_EINVAL_SYSCALLS: RuntimeRef<[BankedAtomicU64; LINUX_RUNTIME_UNSUPPORTED_WORDS]>,
    LINUX_RUNTIME_EPOLL_ACTIVE:
        RuntimeRef<CpuBankedAtomicArray<AtomicU8, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    LINUX_RUNTIME_EPOLL_ALIASES:
        RuntimeRef<CpuBankedAtomicArray<AtomicU32, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    LINUX_RUNTIME_EPOLL_WATCH_EPOLL:
        RuntimeRef<CpuBankedAtomicArray<AtomicU32, { LINUX_DESCRIPTOR_TABLE_LIMIT as usize }>>,
    LINUX_RUNTIME_EPOLL_WATCH_SEEN:
        RuntimeRef<CpuBankedAtomicArray<AtomicU64, { LINUX_DESCRIPTOR_TABLE_LIMIT as usize }>>,
    LINUX_RUNTIME_EPOLL_WATCH_TARGET:
        RuntimeRef<CpuBankedAtomicArray<AtomicU32, { LINUX_DESCRIPTOR_TABLE_LIMIT as usize }>>,
    LINUX_RUNTIME_EVENTFD_ACTIVE:
        RuntimeRef<CpuBankedAtomicArray<AtomicU8, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    LINUX_RUNTIME_EXIT_STATUS: RuntimeRef<BankedAtomicU64>,
    LINUX_RUNTIME_FIRST_UNSUPPORTED_SYSCALL: RuntimeRef<BankedAtomicU64>,
    LINUX_RUNTIME_LATE_DIAGNOSTIC_WRITTEN: RuntimeRef<BankedAtomicBool>,
    LINUX_RUNTIME_MODE: RuntimeRef<AtomicBool>,
    LINUX_RUNTIME_PREEMPT_TICKS: RuntimeRef<ThreadCpuAtomicU8>,
    LINUX_RUNTIME_SLOW_DIAGNOSTIC_WRITTEN: RuntimeRef<BankedAtomicBool>,
    LINUX_RUNTIME_STALLED_DIAGNOSTIC_WRITTEN: RuntimeRef<BankedAtomicBool>,
    LINUX_RUNTIME_SUSPENDED: RuntimeRef<BankedAtomicBool>,
    LINUX_RUNTIME_SUSPEND_ADDRESS: RuntimeRef<BankedAtomicU64>,
    LINUX_RUNTIME_SUSPEND_COUNT: RuntimeRef<BankedAtomicU64>,
    LINUX_RUNTIME_SUSPEND_FS_BASE: RuntimeRef<BankedAtomicU64>,
    LINUX_RUNTIME_SUSPEND_PID: RuntimeRef<BankedAtomicU32>,
    LINUX_RUNTIME_SUSPEND_REGISTERS: RuntimeRef<[BankedAtomicU64; LINUX_SYSCALL_FRAME_REGISTERS]>,
    LINUX_RUNTIME_SUSPEND_REQUESTED: RuntimeRef<BankedAtomicBool>,
    LINUX_RUNTIME_SUSPEND_RESULT: RuntimeRef<BankedAtomicU64>,
    LINUX_RUNTIME_SUSPEND_RFLAGS: RuntimeRef<BankedAtomicU64>,
    LINUX_RUNTIME_SUSPEND_RIP: RuntimeRef<BankedAtomicU64>,
    LINUX_RUNTIME_SUSPEND_RSP: RuntimeRef<BankedAtomicU64>,
    LINUX_RUNTIME_SYSCALL_RESULT_TRACE:
        RuntimeRef<[BankedAtomicU64; LINUX_RUNTIME_SYSCALL_TRACE_LIMIT]>,
    LINUX_RUNTIME_SYSCALL_TRACE: RuntimeRef<[BankedAtomicU64; LINUX_RUNTIME_SYSCALL_TRACE_LIMIT]>,
    LINUX_RUNTIME_SYSCALL_TRACE_COUNT: RuntimeRef<BankedAtomicU64>,
    LINUX_RUNTIME_TIMERFD_ACTIVE:
        RuntimeRef<CpuBankedAtomicArray<AtomicU8, LINUX_DEVICE_DESCRIPTOR_COUNT>>,
    LINUX_RUNTIME_UNSUPPORTED_SYSCALLS:
        RuntimeRef<[BankedAtomicU64; LINUX_RUNTIME_UNSUPPORTED_WORDS]>,
    LINUX_SIGNAL_ACTIVE: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_SIGNAL_DELIVERY_COUNT: RuntimeRef<BankedAtomicU64>,
    LINUX_SIGNAL_RETURN_COUNT: RuntimeRef<BankedAtomicU64>,
    LINUX_SIGNAL_WAIT_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_SIGNAL_WAIT_INTERRUPT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_SIGNAL_WAIT_TIMEOUT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_SIGNAL_WAIT_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_SLEEP_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_SLEEP_INTERRUPT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_SLEEP_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_SOCKET_SINGLE_ATTEMPT: RuntimeRef<AtomicBool>,
    LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_THREAD_CLEAR_CHILD_TIDS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_GENERATIONS: RuntimeRef<[CpuBankedAtomicU32; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_IOV_ADDRESSES:
        RuntimeRef<[[CpuBankedAtomicU64; LINUX_IOV_LIMIT]; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_IOV_LENGTHS:
        RuntimeRef<[[CpuBankedAtomicU64; LINUX_IOV_LIMIT]; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_POINTERS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_POLL_DESCRIPTORS:
        RuntimeRef<[[CpuBankedAtomicU32; LINUX_POLLFD_LIMIT]; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_POLL_EVENTS:
        RuntimeRef<[[CpuBankedAtomicU16; LINUX_POLLFD_LIMIT]; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_R11S: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_RAXS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_RCXS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_REGISTERS:
        RuntimeRef<[[CpuBankedAtomicU64; LINUX_SYSCALL_FRAME_REGISTERS]; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_RFLAGS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_RIPS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_ROBUST_LISTS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_RSEQ_LENGTHS: RuntimeRef<[CpuBankedAtomicU32; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_RSEQ_POINTERS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_RSEQ_SIGNATURES: RuntimeRef<[CpuBankedAtomicU32; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_RSPS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_SELECT_EXCEPTION_SETS:
        RuntimeRef<[[CpuBankedAtomicU64; LINUX_SELECT_WORD_LIMIT]; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_SELECT_READ_ADDRESSES: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_SELECT_READ_SETS:
        RuntimeRef<[[CpuBankedAtomicU64; LINUX_SELECT_WORD_LIMIT]; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_SELECT_WRITE_ADDRESSES: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_SELECT_WRITE_SETS:
        RuntimeRef<[[CpuBankedAtomicU64; LINUX_SELECT_WORD_LIMIT]; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_SIGNAL_MASKS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_STACK_BASES: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_STACK_SIZES: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_STATES: RuntimeRef<[CpuBankedAtomicU8; LINUX_THREAD_LIMIT]>,
    /// Per thread slot: the thread, ready, waits for the process's owner
    /// to run it (its system call is not for the light path).
    LINUX_THREAD_OWNER_ONLY: RuntimeRef<CpuBankedAtomicArray<AtomicU8, LINUX_THREAD_LIMIT>>,
    LINUX_THREAD_TIDS: RuntimeRef<[CpuBankedAtomicU32; LINUX_THREAD_LIMIT]>,
    /// Per thread, its nice value plus 20 (0..=39), as Linux keeps nice per
    /// task: a thread's time slice follows it.
    LINUX_THREAD_NICES: RuntimeRef<[CpuBankedAtomicU8; LINUX_THREAD_LIMIT]>,
    /// Per thread, the timestamp-counter cycles it has run, charged when it
    /// leaves a CPU (`linux_charge_thread_cpu`).
    LINUX_THREAD_CPU_CYCLES: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    /// Per thread, the CPU it last ran on plus 1 (0: not run yet), for
    /// perf's CPU_MIGRATIONS.
    LINUX_THREAD_LAST_CPUS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_TLS_EXTENTS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_TLS_SIZES: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_WAIT_DEADLINES: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_WAIT_KEYS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_WAIT_KINDS: RuntimeRef<[CpuBankedAtomicU8; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_WAIT_OUTPUTS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS: RuntimeRef<[CpuBankedAtomicU64; LINUX_THREAD_LIMIT]>,
    LINUX_TIMED_WAITS_ACTIVE: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_TIMERFD_READ_BLOCK_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_TIMERFD_READ_INTERRUPT_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_TIMERFD_READ_WAKE_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_TIMER_WAIT_EXPIRY_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_TIMER_WAIT_PREEMPTION_COUNT: RuntimeRef<BankedAtomicU32>,
    LINUX_TTY_CONTROL_CHARACTERS: RuntimeRef<[BankedAtomicU8; 19]>,
    LINUX_TTY_FOREGROUND_GROUP: RuntimeRef<BankedAtomicU32>,
    LINUX_TTY_LINE: RuntimeRef<BankedAtomicU8>,
    LINUX_TTY_SESSION: RuntimeRef<BankedAtomicU32>,
    LINUX_TTY_TERMIOS_FLAGS: RuntimeRef<[BankedAtomicU32; 4]>,
    LINUX_YIELD_SWITCH_COUNT: RuntimeRef<BankedAtomicU32>,
    LIVE_FORK_PUBLIC_DIAGNOSTIC: RuntimeRef<BankedAtomicU8>,
    NETWORK_DHCP_REQUESTED: RuntimeRef<AtomicBool>,
    NETWORK_DHCP_RESULT: RuntimeRef<AtomicU8>,
    NETWORK_PING_ACTIVE: RuntimeRef<AtomicU64>,
    NETWORK_PING_REQUESTED: RuntimeRef<AtomicU64>,
    NETWORK_PING_RESULT: RuntimeRef<AtomicU8>,
    PROCESS_CHILD_CONTEXT_VALID: RuntimeRef<[AtomicBool; CPU_ENTRY_STATE_LIMIT]>,
    PROCESS_CHILD_EXECUTION_DIAGNOSTIC: RuntimeRef<[AtomicU8; CPU_ENTRY_STATE_LIMIT]>,
    PROCESS_CHILD_EXIT_STATUS: RuntimeRef<[AtomicU8; CPU_ENTRY_STATE_LIMIT]>,
    PROCESS_CHILD_EXPECTED_FS_BASE: RuntimeRef<[AtomicU64; CPU_ENTRY_STATE_LIMIT]>,
    PROCESS_CHILD_EXPECTED_REGISTERS: RuntimeRef<[[AtomicU64; 15]; CPU_ENTRY_STATE_LIMIT]>,
    PROCESS_CHILD_PROBE_STATE: RuntimeRef<[AtomicU8; CPU_ENTRY_STATE_LIMIT]>,
}

#[allow(non_snake_case)]
static X86_RUNTIME: X86RuntimeOwner = X86RuntimeOwner {
    CONTAINER_ACTIVE_SLOT: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_ACTIVE_SLOT),
    CONTAINER_BACKGROUND_SUSPENDED: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_BACKGROUND_SUSPENDED),
    CONTAINER_CONFIG_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_CONFIG_FLAGS),
    CONTAINER_CONSOLE_ATTACHED: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_CONSOLE_ATTACHED),
    CONTAINER_CONSOLE_BYTES: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_CONSOLE_BYTES),
    CONTAINER_CONSOLE_CURSOR: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_CONSOLE_CURSOR),
    CONTAINER_CONTROL_STATES: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_CONTROL_STATES),
    CONTAINER_CPU_COUNTS: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_CPU_COUNTS),
    CONTAINER_DOMAIN_IDS: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_DOMAIN_IDS),
    CONTAINER_EXEC_ARGUMENTS: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_EXEC_ARGUMENTS),
    CONTAINER_EXEC_ARGUMENT_COUNTS: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_EXEC_ARGUMENT_COUNTS),
    CONTAINER_EXEC_ARGUMENT_SIZES: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_EXEC_ARGUMENT_SIZES),
    CONTAINER_EXEC_INTERACTIVE: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_EXEC_INTERACTIVE),
    CONTAINER_EXEC_REQUESTED: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_EXEC_REQUESTED),
    CONTAINER_EXTENDED_STATE_VALID: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_EXTENDED_STATE_VALID),
    CONTAINER_HOST_SHUTDOWN_REQUESTED: RuntimeRef(
        &X86_RUNTIME_BACKING_CONTAINER_HOST_SHUTDOWN_REQUESTED,
    ),
    CONTAINER_IMAGES: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_IMAGES),
    CONTAINER_IMAGE_SIZES: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_IMAGE_SIZES),
    CONTAINER_INITS: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_INITS),
    CONTAINER_INIT_SIZES: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_INIT_SIZES),
    CONTAINER_INSTALL_REQUESTED: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_INSTALL_REQUESTED),
    CONTAINER_LAST_RESUMED_SLOT: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_LAST_RESUMED_SLOT),
    CONTAINER_MANAGEMENT_ENABLED: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_MANAGEMENT_ENABLED),
    CONTAINER_MEMORY_MIB: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_MEMORY_MIB),
    CONTAINER_NAMES: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_NAMES),
    CONTAINER_NAME_SIZES: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_NAME_SIZES),
    CONTAINER_PULL_REQUESTED: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_PULL_REQUESTED),
    CONTAINER_RESTART_REQUESTED: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_RESTART_REQUESTED),
    CONTAINER_SELECTED_SLOT: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_SELECTED_SLOT),
    CONTAINER_START_PENDING: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_START_PENDING),
    CONTAINER_STOP_REQUESTED: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_STOP_REQUESTED),
    DOMAIN_PERSONALITIES: RuntimeRef(&X86_RUNTIME_BACKING_DOMAIN_PERSONALITIES),
    DOMAIN_PERSONALITY_SIZES: RuntimeRef(&X86_RUNTIME_BACKING_DOMAIN_PERSONALITY_SIZES),
    ELF_PROBE_ACTIVE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE),
    ELF_PROBE_ACTIVE_IMAGE_ADDRESSES: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE_IMAGE_ADDRESSES,
    ),
    ELF_PROBE_ACTIVE_IMAGE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE_IMAGE_COUNT),
    ELF_PROBE_ACTIVE_IMAGE_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE_IMAGE_FLAGS),
    ELF_PROBE_ACTIVE_IMAGE_FRAMES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE_IMAGE_FRAMES),
    ELF_PROBE_ACTIVE_IMAGE_GENERATIONS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE_IMAGE_GENERATIONS,
    ),
    ELF_PROBE_ALT_STACK_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_ALT_STACK_FLAGS),
    ELF_PROBE_ALT_STACK_POINTER: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_ALT_STACK_POINTER),
    ELF_PROBE_ALT_STACK_SIZE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_ALT_STACK_SIZE),
    ELF_PROBE_BRK: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_BRK),
    ELF_PROBE_BRK_LIMIT: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_BRK_LIMIT),
    ELF_PROBE_CLOCK_EPOCH: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_CLOCK_EPOCH),
    ELF_PROBE_CLOCK_FREQUENCY: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_CLOCK_FREQUENCY),
    ELF_PROBE_CODE_BASE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_CODE_BASE),
    ELF_PROBE_CODE_SIZE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_CODE_SIZE),
    ELF_PROBE_COMPLETED: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_COMPLETED),
    ELF_PROBE_CONSOLE_CLOEXEC: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_CONSOLE_CLOEXEC),
    ELF_PROBE_DESCRIPTOR_CREATED: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DESCRIPTOR_CREATED),
    ELF_PROBE_DESCRIPTOR_READ_LEASES: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_DESCRIPTOR_READ_LEASES,
    ),
    ELF_PROBE_DESCRIPTOR_WRITE_LEASES: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_DESCRIPTOR_WRITE_LEASES,
    ),
    ELF_PROBE_CONSOLE_DESCRIPTORS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_CONSOLE_DESCRIPTORS),
    ELF_PROBE_CWD: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_CWD),
    ELF_PROBE_DATA: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DATA),
    ELF_PROBE_DATA_SIZE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DATA_SIZE),
    ELF_PROBE_DEPENDENCY_BASE_END: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_BASE_END),
    ELF_PROBE_DEPENDENCY_BASE_MIN: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_BASE_MIN),
    ELF_PROBE_DEPENDENCY_FILE_SIZES: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_FILE_SIZES,
    ),
    ELF_PROBE_DEPENDENCY_FRAMES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_FRAMES),
    ELF_PROBE_DEPENDENCY_GENERATIONS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_GENERATIONS,
    ),
    ELF_PROBE_DEPENDENCY_MAPPINGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_MAPPINGS),
    ELF_PROBE_DEPENDENCY_OFFSETS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_OFFSETS),
    ELF_PROBE_DEPENDENCY_PROTECTIONS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_PROTECTIONS,
    ),
    ELF_PROBE_DEPENDENCY_RELATIVES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_RELATIVES),
    ELF_PROBE_DEPENDENCY_SELECTED_BASE: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_SELECTED_BASE,
    ),
    ELF_PROBE_DESCRIPTOR_OFFSETS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DESCRIPTOR_OFFSETS),
    ELF_PROBE_DEVICE_DESCRIPTORS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DEVICE_DESCRIPTORS),
    ELF_PROBE_DUMPABLE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DUMPABLE),
    ELF_PROBE_TSC_SIGSEGV: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TSC_SIGSEGV),
    ELF_PROBE_EPOLL_DATA: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EPOLL_DATA),
    ELF_PROBE_EPOLL_DESCRIPTOR: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EPOLL_DESCRIPTOR),
    ELF_PROBE_DESCRIPTOR_OVERFLOW: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_DESCRIPTOR_OVERFLOW),
    ELF_PROBE_EPOLL_EVENTS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EPOLL_EVENTS),
    ELF_PROBE_EVENTFD_COUNTER: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EVENTFD_COUNTER),
    ELF_PROBE_EVENTFD_DESCRIPTOR: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EVENTFD_DESCRIPTOR),
    ELF_PROBE_EVENTFD_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EVENTFD_FLAGS),
    ELF_PROBE_EXEC_ENTRY: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EXEC_ENTRY),
    ELF_PROBE_EXEC_IGNORED_SIGNALS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EXEC_IGNORED_SIGNALS),
    ELF_PROBE_EXEC_MAPPING_ADDRESSES: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_EXEC_MAPPING_ADDRESSES,
    ),
    ELF_PROBE_EXEC_MAPPING_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EXEC_MAPPING_FLAGS),
    ELF_PROBE_EXEC_MAPPING_FRAMES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EXEC_MAPPING_FRAMES),
    ELF_PROBE_EXEC_MAPPING_GENERATIONS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_EXEC_MAPPING_GENERATIONS,
    ),
    ELF_PROBE_EXEC_NODE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EXEC_NODE),
    ELF_PROBE_EXEC_REPLACED: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EXEC_REPLACED),
    ELF_PROBE_EXITED_CLEAR_CHILD_TID: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_EXITED_CLEAR_CHILD_TID,
    ),
    ELF_PROBE_EXITED_ROBUST_LIST: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EXITED_ROBUST_LIST),
    ELF_PROBE_EXIT_STATUS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_EXIT_STATUS),
    ELF_PROBE_HEAP_FRAME: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_HEAP_FRAME),
    ELF_PROBE_HEAP_GENERATION: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_HEAP_GENERATION),
    ELF_PROBE_IOPRIO: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_IOPRIO),
    ELF_PROBE_LOADER_CODE_BASE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_LOADER_CODE_BASE),
    ELF_PROBE_LOADER_CODE_SIZE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_LOADER_CODE_SIZE),
    ELF_PROBE_MAIN_ADDRESSES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MAIN_ADDRESSES),
    ELF_PROBE_MAIN_FILE_SIZES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MAIN_FILE_SIZES),
    ELF_PROBE_MAIN_FRAMES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MAIN_FRAMES),
    ELF_PROBE_MAIN_GENERATIONS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MAIN_GENERATIONS),
    ELF_PROBE_MAIN_MAPPINGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MAIN_MAPPINGS),
    ELF_PROBE_MAIN_OFFSETS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MAIN_OFFSETS),
    ELF_PROBE_MAIN_PROTECTIONS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MAIN_PROTECTIONS),
    ELF_PROBE_MEMBARRIER_REGISTRATIONS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_MEMBARRIER_REGISTRATIONS,
    ),
    ELF_PROBE_MMAP: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MMAP),
    ELF_PROBE_MMAP_FILE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MMAP_FILE),
    ELF_PROBE_MMAP_FRAMES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MMAP_FRAMES),
    ELF_PROBE_MMAP_GENERATIONS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MMAP_GENERATIONS),
    ELF_PROBE_MMAP_NEXT: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MMAP_NEXT),
    ELF_PROBE_MMAP_PAGES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MMAP_PAGES),
    ELF_PROBE_MMAP_PROTECTION: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MMAP_PROTECTION),
    ELF_PROBE_MMAP_SEALED: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_MMAP_SEALED),
    ELF_PROBE_NICE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_NICE),
    ELF_PROBE_NO_NEW_PRIVS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_NO_NEW_PRIVS),
    ELF_PROBE_OPEN_FILE_IDS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_OPEN_FILE_IDS),
    ELF_PROBE_OVERLAY_CWD: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_OVERLAY_CWD),
    ELF_PROBE_PAGE_TABLE_FRAMES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PAGE_TABLE_FRAMES),
    ELF_PROBE_PAGE_TABLE_GENERATIONS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_PAGE_TABLE_GENERATIONS,
    ),
    ELF_PROBE_PARENT_DEATH_SIGNAL: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PARENT_DEATH_SIGNAL),
    ELF_PROBE_PENDING_SIGNALS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PENDING_SIGNALS),
    ELF_PROBE_PENDING_SIGNAL_CODES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PENDING_SIGNAL_CODES),
    ELF_PROBE_PENDING_SIGNAL_VALUES: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_PENDING_SIGNAL_VALUES,
    ),
    ELF_PROBE_PERSONALITY: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PERSONALITY),
    ELF_PROBE_PIPE_BUFFER: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PIPE_BUFFER),
    ELF_PROBE_PIPE_LENGTH: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PIPE_LENGTH),
    ELF_PROBE_PIPE_READ_DESCRIPTOR: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PIPE_READ_DESCRIPTOR),
    ELF_PROBE_PIPE_READ_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PIPE_READ_FLAGS),
    ELF_PROBE_PIPE_WRITE_DESCRIPTOR: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_PIPE_WRITE_DESCRIPTOR,
    ),
    ELF_PROBE_PIPE_WRITE_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PIPE_WRITE_FLAGS),
    ELF_PROBE_POSIX_MQ_BYTES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_POSIX_MQ_BYTES),
    ELF_PROBE_POSIX_TIMER_ACTIVE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_POSIX_TIMER_ACTIVE),
    ELF_PROBE_POSIX_TIMER_DEADLINE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_POSIX_TIMER_DEADLINE),
    ELF_PROBE_POSIX_TIMER_INTERVAL: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_POSIX_TIMER_INTERVAL),
    ELF_PROBE_PROCESS_NAME_HIGH: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PROCESS_NAME_HIGH),
    ELF_PROBE_PROCESS_NAME_LOW: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_PROCESS_NAME_LOW),
    ELF_PROBE_READ_ONLY_DATA_PAGE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_READ_ONLY_DATA_PAGE),
    ELF_PROBE_REAL_TIMER_DEADLINE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_REAL_TIMER_DEADLINE),
    ELF_PROBE_REAL_TIMER_INTERVAL: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_REAL_TIMER_INTERVAL),
    ELF_PROBE_RECLAIM_HEAP_FRAME: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_HEAP_FRAME),
    ELF_PROBE_RECLAIM_HEAP_GENERATION: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_HEAP_GENERATION,
    ),
    ELF_PROBE_RECLAIM_PAGE_TABLE_FRAMES: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_PAGE_TABLE_FRAMES,
    ),
    ELF_PROBE_RECLAIM_PAGE_TABLE_GENERATIONS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_PAGE_TABLE_GENERATIONS,
    ),
    ELF_PROBE_RECLAIM_SIBLING_STACK_FRAME: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_SIBLING_STACK_FRAME,
    ),
    ELF_PROBE_RECLAIM_SIBLING_STACK_GENERATION: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_SIBLING_STACK_GENERATION,
    ),
    ELF_PROBE_RECLAIM_TLS_FRAMES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_TLS_FRAMES),
    ELF_PROBE_RECLAIM_TLS_GENERATIONS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_TLS_GENERATIONS,
    ),
    ELF_PROBE_RELRO: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_RELRO),
    ELF_PROBE_RELRO_SIZE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_RELRO_SIZE),
    ELF_PROBE_RETIRED_IMAGE_ADDRESSES: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_RETIRED_IMAGE_ADDRESSES,
    ),
    ELF_PROBE_RETIRED_IMAGE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_RETIRED_IMAGE_COUNT),
    ELF_PROBE_RETIRED_IMAGE_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_RETIRED_IMAGE_FLAGS),
    ELF_PROBE_RETIRED_IMAGE_FRAMES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_RETIRED_IMAGE_FRAMES),
    ELF_PROBE_RETIRED_IMAGE_GENERATIONS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_RETIRED_IMAGE_GENERATIONS,
    ),
    ELF_PROBE_RLIMITS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_RLIMITS),
    ELF_PROBE_ROOTFS_CWD: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_ROOTFS_CWD),
    ELF_PROBE_ROOTFS_DESCRIPTORS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_ROOTFS_DESCRIPTORS),
    ELF_PROBE_SECCOMP_FILTERED: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SECCOMP_FILTERED),
    ELF_PROBE_SECCOMP_STRICT: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SECCOMP_STRICT),
    ELF_PROBE_SECUREBITS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SECUREBITS),
    ELF_PROBE_SIBLING_FS_BASE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SIBLING_FS_BASE),
    ELF_PROBE_SIBLING_STACK: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SIBLING_STACK),
    ELF_PROBE_SIBLING_STACK_FRAME: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SIBLING_STACK_FRAME),
    ELF_PROBE_SIBLING_STACK_GENERATION: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_SIBLING_STACK_GENERATION,
    ),
    ELF_PROBE_SIBLING_TLS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SIBLING_TLS),
    ELF_PROBE_SIGNAL_ACTION_MASKS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SIGNAL_ACTION_MASKS),
    ELF_PROBE_SIGNAL_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SIGNAL_FLAGS),
    ELF_PROBE_SIGNAL_HANDLERS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SIGNAL_HANDLERS),
    ELF_PROBE_SIGNAL_MASK: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SIGNAL_MASK),
    ELF_PROBE_SIGNAL_RESTORERS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SIGNAL_RESTORERS),
    ELF_PROBE_SOCKET_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SOCKET_FLAGS),
    ELF_PROBE_SOCKET_SLOTS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SOCKET_SLOTS),
    ELF_PROBE_STACK: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_STACK),
    ELF_PROBE_STACK_FRAME: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_STACK_FRAME),
    ELF_PROBE_STACK_GENERATION: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_STACK_GENERATION),
    ELF_PROBE_STACK_LOW: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_STACK_LOW),
    ELF_PROBE_STDERR_OPEN: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_STDERR_OPEN),
    ELF_PROBE_STDIO_DEVICE_DESCRIPTORS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_STDIO_DEVICE_DESCRIPTORS,
    ),
    ELF_PROBE_STDIO_OFFSETS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_STDIO_OFFSETS),
    ELF_PROBE_STDIO_OPEN_FILE_IDS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_STDIO_OPEN_FILE_IDS),
    ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS,
    ),
    ELF_PROBE_STDIO_SOCKET_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_STDIO_SOCKET_FLAGS),
    ELF_PROBE_STDIO_SOCKET_SLOTS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_STDIO_SOCKET_SLOTS),
    ELF_PROBE_STDIO_TMP_FILE_GENERATIONS: RuntimeRef(
        &X86_RUNTIME_BACKING_ELF_PROBE_STDIO_TMP_FILE_GENERATIONS,
    ),
    ELF_PROBE_SYSTEM_INIT: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_SYSTEM_INIT),
    ELF_PROBE_TERMINATION_SIGNAL: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TERMINATION_SIGNAL),
    ELF_PROBE_TIMERFD_CLOCK: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TIMERFD_CLOCK),
    ELF_PROBE_TIMERFD_DEADLINE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TIMERFD_DEADLINE),
    ELF_PROBE_TIMERFD_DESCRIPTOR: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TIMERFD_DESCRIPTOR),
    ELF_PROBE_TIMERFD_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TIMERFD_FLAGS),
    ELF_PROBE_TIMERFD_INTERVAL: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TIMERFD_INTERVAL),
    ELF_PROBE_TLS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TLS),
    ELF_PROBE_TLS_FRAMES: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TLS_FRAMES),
    ELF_PROBE_TLS_GENERATIONS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TLS_GENERATIONS),
    ELF_PROBE_TLS_SIZE: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TLS_SIZE),
    ELF_PROBE_TMP_FILE_GENERATIONS: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_TMP_FILE_GENERATIONS),
    ELF_PROBE_UMASK: RuntimeRef(&X86_RUNTIME_BACKING_ELF_PROBE_UMASK),
    LINUX_BOOT_ID_STATE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_BOOT_ID_STATE),
    LINUX_BOOT_PROFILE_LIFECYCLE_COUNTS: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_LIFECYCLE_COUNTS,
    ),
    LINUX_BOOT_PROFILE_LIFECYCLE_TICKS: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_LIFECYCLE_TICKS,
    ),
    LINUX_BOOT_PROFILE_RESTORE_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_RESTORE_COUNT,
    ),
    LINUX_BOOT_PROFILE_RESTORE_TICKS: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_RESTORE_TICKS,
    ),
    LINUX_BOOT_PROFILE_SAVE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_SAVE_COUNT),
    LINUX_BOOT_PROFILE_SAVE_TICKS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_SAVE_TICKS),
    LINUX_BOOT_PROFILE_SYSCALL_COUNTS: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_SYSCALL_COUNTS,
    ),
    LINUX_BOOT_PROFILE_SYSCALL_TICKS: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_SYSCALL_TICKS,
    ),
    LINUX_CHILD_EXIT_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CHILD_EXIT_COUNT),
    LINUX_CHILD_GETTID_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CHILD_GETTID_COUNT),
    LINUX_CLONE_BUSY_REJECTION_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_CLONE_BUSY_REJECTION_COUNT,
    ),
    LINUX_CLONE_DISPATCH_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CLONE_DISPATCH_COUNT),
    LINUX_CLONE_INVALID_REJECTION_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_CLONE_INVALID_REJECTION_COUNT,
    ),
    LINUX_CLONE_REUSE_VALIDATED: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CLONE_REUSE_VALIDATED),
    LINUX_CLONE_TID_FAULT_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CLONE_TID_FAULT_COUNT),
    LINUX_CONTROLLER_CONSOLE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CONTROLLER_CONSOLE),
    LINUX_CONTROLLER_DOMAIN: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CONTROLLER_DOMAIN),
    LINUX_CONTROLLER_HOST: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CONTROLLER_HOST),
    LINUX_CONTROLLER_NETWORK: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CONTROLLER_NETWORK),
    LINUX_CONTROLLER_ROOT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CONTROLLER_ROOT),
    LINUX_CROSS_PROCESS_PRLIMIT_VALIDATED: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_CROSS_PROCESS_PRLIMIT_VALIDATED,
    ),
    LINUX_CURRENT_PROCESS_PID: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CURRENT_PROCESS_PID),
    LINUX_CURRENT_THREAD_SLOT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_CURRENT_THREAD_SLOT),
    LINUX_DESCRIPTOR_WAITS_ACTIVE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_DESCRIPTOR_WAITS_ACTIVE),
    LINUX_DOMAIN_EXEC_INJECT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_DOMAIN_EXEC_INJECT),
    LINUX_EPOLL_LAST_READY_DESCRIPTOR: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_EPOLL_LAST_READY_DESCRIPTOR,
    ),
    LINUX_EPOLL_LAST_READY_EVENTS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_EPOLL_LAST_READY_EVENTS),
    LINUX_EPOLL_PWAIT_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_EPOLL_PWAIT_BLOCK_COUNT),
    LINUX_EPOLL_PWAIT_TIMEOUT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_EPOLL_PWAIT_TIMEOUT_COUNT,
    ),
    LINUX_EPOLL_PWAIT_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_EPOLL_PWAIT_WAKE_COUNT),
    LINUX_EPOLL_WAIT_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_EPOLL_WAIT_BLOCK_COUNT),
    LINUX_EPOLL_WAIT_INTERRUPT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_EPOLL_WAIT_INTERRUPT_COUNT,
    ),
    LINUX_EPOLL_WAIT_TIMEOUT_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_EPOLL_WAIT_TIMEOUT_COUNT),
    LINUX_EPOLL_WAIT_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_EPOLL_WAIT_WAKE_COUNT),
    LINUX_EVENTFD_READ_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_EVENTFD_READ_BLOCK_COUNT),
    LINUX_EVENTFD_READ_INTERRUPT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_EVENTFD_READ_INTERRUPT_COUNT,
    ),
    LINUX_EVENTFD_READ_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_EVENTFD_READ_WAKE_COUNT),
    LINUX_EVENTFD_WRITE_BLOCK_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_EVENTFD_WRITE_BLOCK_COUNT,
    ),
    LINUX_EVENTFD_WRITE_INTERRUPT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_EVENTFD_WRITE_INTERRUPT_COUNT,
    ),
    LINUX_EVENTFD_WRITE_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_EVENTFD_WRITE_WAKE_COUNT),
    LINUX_EXECUTION_INSTANCE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_EXECUTION_INSTANCE),
    LINUX_FIRST_CHILD_TID: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FIRST_CHILD_TID),
    LINUX_FORK_CGROUP_GENERATION: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_CGROUP_GENERATION),
    LINUX_FORK_CHILD_STACK: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_CHILD_STACK),
    LINUX_FORK_SHARE_VM: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_SHARE_VM),
    LINUX_FORK_CHILD_TID_ADDRESS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_CHILD_TID_ADDRESS),
    LINUX_FORK_PARENT_TID_ADDRESS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_PARENT_TID_ADDRESS),
    LINUX_FORK_CLEAR_SIGHAND: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_CLEAR_SIGHAND),
    LINUX_FORK_OWN_PAGES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_OWN_PAGES),
    LINUX_FORK_CLONE_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_CLONE_FLAGS),
    LINUX_FORK_TLS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_TLS),
    LINUX_FORK_CLEAR_TID_ADDRESS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_CLEAR_TID_ADDRESS),
    LINUX_FORK_NEW_MOUNT_NAMESPACE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_NEW_MOUNT_NAMESPACE),
    LINUX_FORK_NEW_USER_NAMESPACE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_NEW_USER_NAMESPACE),
    LINUX_FORK_PIDFD_ADDRESS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_PIDFD_ADDRESS),
    LINUX_FORK_REQUESTED: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FORK_REQUESTED),
    LINUX_FSIZE_LIMIT_HIT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FSIZE_LIMIT_HIT),
    LINUX_FUTEX_EXIT_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FUTEX_EXIT_WAKE_COUNT),
    LINUX_FUTEX_EXPLICIT_WAKE_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_FUTEX_EXPLICIT_WAKE_COUNT,
    ),
    LINUX_FUTEX_WAIT_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FUTEX_WAIT_BLOCK_COUNT),
    LINUX_FUTEX_WAIT_TIMEOUT_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_FUTEX_WAIT_TIMEOUT_COUNT),
    LINUX_INIT_EXIT_KILL_ROUNDS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_INIT_EXIT_KILL_ROUNDS),
    LINUX_LAST_PREEMPTED_THREAD_SLOT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_LAST_PREEMPTED_THREAD_SLOT,
    ),
    LINUX_LIVE_RETURN_VALIDATED: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_LIVE_RETURN_VALIDATED),
    LINUX_MASKED_WAIT_INTERRUPT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_MASKED_WAIT_INTERRUPT_COUNT,
    ),
    LINUX_NEXT_OPEN_FILE_ID: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_NEXT_OPEN_FILE_ID),
    LINUX_NEXT_TID: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_NEXT_TID),
    LINUX_PARENT_RESUMED: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PARENT_RESUMED),
    LINUX_PIPE_READ_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PIPE_READ_BLOCK_COUNT),
    LINUX_PIPE_READ_INTERRUPT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_PIPE_READ_INTERRUPT_COUNT,
    ),
    LINUX_PIPE_READ_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PIPE_READ_WAKE_COUNT),
    LINUX_PIPE_WRITE_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PIPE_WRITE_BLOCK_COUNT),
    LINUX_PIPE_WRITE_INTERRUPT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_PIPE_WRITE_INTERRUPT_COUNT,
    ),
    LINUX_PIPE_WRITE_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PIPE_WRITE_WAKE_COUNT),
    LINUX_POLL_WAIT_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_POLL_WAIT_BLOCK_COUNT),
    LINUX_POLL_WAIT_INTERRUPT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_POLL_WAIT_INTERRUPT_COUNT,
    ),
    LINUX_POLL_WAIT_TIMEOUT_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_POLL_WAIT_TIMEOUT_COUNT),
    LINUX_POLL_WAIT_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_POLL_WAIT_WAKE_COUNT),
    LINUX_PPOLL_WAIT_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PPOLL_WAIT_BLOCK_COUNT),
    LINUX_PPOLL_WAIT_TIMEOUT_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PPOLL_WAIT_TIMEOUT_COUNT),
    LINUX_PPOLL_WAIT_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PPOLL_WAIT_WAKE_COUNT),
    LINUX_PROCESS_CHILD_EXECUTED: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_EXECUTED),
    LINUX_PROCESS_CHILD_EXEC_PID: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_EXEC_PID),
    LINUX_PROCESS_CHILD_EXITED: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_EXITED),
    LINUX_PROCESS_CHILD_EXIT_PID: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_EXIT_PID),
    LINUX_PROCESS_CHILD_STATUS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_STATUS),
    LINUX_PROCESS_CHILD_YIELDED: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_YIELDED),
    LINUX_PROCESS_CHILD_YIELD_PID: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_YIELD_PID),
    CONTAINER_EXEC_CHILD: RuntimeRef(&X86_RUNTIME_BACKING_CONTAINER_EXEC_CHILD),
    LINUX_PROCESS_RELEASE_PARENT_ON_EXEC: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_PROCESS_RELEASE_PARENT_ON_EXEC,
    ),
    LINUX_PROCESS_SNAPSHOT_SCRATCH: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_SNAPSHOT_SCRATCH),
    LINUX_PROCESS_SNAPSHOT_STAGE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_SNAPSHOT_STAGE),
    LINUX_PROCESS_SNAPSHOT_VALIDATED: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_PROCESS_SNAPSHOT_VALIDATED,
    ),
    LINUX_PROCESS_WAIT_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_WAIT_COUNT),
    LINUX_RUNTIME_BACKGROUND_QUANTA: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_BACKGROUND_QUANTA,
    ),
    LINUX_RUNTIME_BACKGROUND_SUSPENDED: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_BACKGROUND_SUSPENDED,
    ),
    LINUX_RUNTIME_BACKGROUND_TICKS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_BACKGROUND_TICKS),
    LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED,
    ),
    LINUX_RUNTIME_CONSOLE_TIMING_WRITTEN: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_CONSOLE_TIMING_WRITTEN,
    ),
    LINUX_RUNTIME_EINVAL_SYSCALLS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_EINVAL_SYSCALLS),
    LINUX_RUNTIME_EPOLL_ACTIVE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_EPOLL_ACTIVE),
    LINUX_RUNTIME_EPOLL_ALIASES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_EPOLL_ALIASES),
    LINUX_RUNTIME_EPOLL_WATCH_EPOLL: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_EPOLL_WATCH_EPOLL,
    ),
    LINUX_RUNTIME_EPOLL_WATCH_SEEN: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_EPOLL_WATCH_SEEN),
    LINUX_RUNTIME_EPOLL_WATCH_TARGET: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_EPOLL_WATCH_TARGET,
    ),
    LINUX_RUNTIME_EVENTFD_ACTIVE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_EVENTFD_ACTIVE),
    LINUX_RUNTIME_EXIT_STATUS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_EXIT_STATUS),
    LINUX_RUNTIME_FIRST_UNSUPPORTED_SYSCALL: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_FIRST_UNSUPPORTED_SYSCALL,
    ),
    LINUX_RUNTIME_LATE_DIAGNOSTIC_WRITTEN: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_LATE_DIAGNOSTIC_WRITTEN,
    ),
    LINUX_RUNTIME_MODE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_MODE),
    LINUX_RUNTIME_PREEMPT_TICKS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_PREEMPT_TICKS),
    LINUX_RUNTIME_SLOW_DIAGNOSTIC_WRITTEN: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_SLOW_DIAGNOSTIC_WRITTEN,
    ),
    LINUX_RUNTIME_STALLED_DIAGNOSTIC_WRITTEN: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_STALLED_DIAGNOSTIC_WRITTEN,
    ),
    LINUX_RUNTIME_SUSPENDED: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPENDED),
    LINUX_RUNTIME_SUSPEND_ADDRESS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_ADDRESS),
    LINUX_RUNTIME_SUSPEND_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_COUNT),
    LINUX_RUNTIME_SUSPEND_FS_BASE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_FS_BASE),
    LINUX_RUNTIME_SUSPEND_PID: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_PID),
    LINUX_RUNTIME_SUSPEND_REGISTERS: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_REGISTERS,
    ),
    LINUX_RUNTIME_SUSPEND_REQUESTED: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_REQUESTED,
    ),
    LINUX_RUNTIME_SUSPEND_RESULT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_RESULT),
    LINUX_RUNTIME_SUSPEND_RFLAGS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_RFLAGS),
    LINUX_RUNTIME_SUSPEND_RIP: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_RIP),
    LINUX_RUNTIME_SUSPEND_RSP: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_RSP),
    LINUX_RUNTIME_SYSCALL_RESULT_TRACE: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_SYSCALL_RESULT_TRACE,
    ),
    LINUX_RUNTIME_SYSCALL_TRACE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_SYSCALL_TRACE),
    LINUX_RUNTIME_SYSCALL_TRACE_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_SYSCALL_TRACE_COUNT,
    ),
    LINUX_RUNTIME_TIMERFD_ACTIVE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_RUNTIME_TIMERFD_ACTIVE),
    LINUX_RUNTIME_UNSUPPORTED_SYSCALLS: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_RUNTIME_UNSUPPORTED_SYSCALLS,
    ),
    LINUX_SIGNAL_ACTIVE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_SIGNAL_ACTIVE),
    LINUX_SIGNAL_DELIVERY_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_SIGNAL_DELIVERY_COUNT),
    LINUX_SIGNAL_RETURN_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_SIGNAL_RETURN_COUNT),
    LINUX_SIGNAL_WAIT_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_SIGNAL_WAIT_BLOCK_COUNT),
    LINUX_SIGNAL_WAIT_INTERRUPT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_SIGNAL_WAIT_INTERRUPT_COUNT,
    ),
    LINUX_SIGNAL_WAIT_TIMEOUT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_SIGNAL_WAIT_TIMEOUT_COUNT,
    ),
    LINUX_SIGNAL_WAIT_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_SIGNAL_WAIT_WAKE_COUNT),
    LINUX_SLEEP_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_SLEEP_BLOCK_COUNT),
    LINUX_SLEEP_INTERRUPT_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_SLEEP_INTERRUPT_COUNT),
    LINUX_SLEEP_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_SLEEP_WAKE_COUNT),
    LINUX_SOCKET_SINGLE_ATTEMPT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_SOCKET_SINGLE_ATTEMPT),
    LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT,
    ),
    LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT,
    ),
    LINUX_THREAD_CLEAR_CHILD_TIDS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_CLEAR_CHILD_TIDS),
    LINUX_THREAD_GENERATIONS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_GENERATIONS),
    LINUX_THREAD_IOV_ADDRESSES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_IOV_ADDRESSES),
    LINUX_THREAD_IOV_LENGTHS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_IOV_LENGTHS),
    LINUX_THREAD_POINTERS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_POINTERS),
    LINUX_THREAD_POLL_DESCRIPTORS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_POLL_DESCRIPTORS),
    LINUX_THREAD_POLL_EVENTS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_POLL_EVENTS),
    LINUX_THREAD_R11S: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_R11S),
    LINUX_THREAD_RAXS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_RAXS),
    LINUX_THREAD_RCXS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_RCXS),
    LINUX_THREAD_REGISTERS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_REGISTERS),
    LINUX_THREAD_RFLAGS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_RFLAGS),
    LINUX_THREAD_RIPS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_RIPS),
    LINUX_THREAD_ROBUST_LISTS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_ROBUST_LISTS),
    LINUX_THREAD_RSEQ_LENGTHS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_RSEQ_LENGTHS),
    LINUX_THREAD_RSEQ_POINTERS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_RSEQ_POINTERS),
    LINUX_THREAD_RSEQ_SIGNATURES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_RSEQ_SIGNATURES),
    LINUX_THREAD_RSPS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_RSPS),
    LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES,
    ),
    LINUX_THREAD_SELECT_EXCEPTION_SETS: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_EXCEPTION_SETS,
    ),
    LINUX_THREAD_SELECT_READ_ADDRESSES: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_READ_ADDRESSES,
    ),
    LINUX_THREAD_SELECT_READ_SETS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_READ_SETS),
    LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES,
    ),
    LINUX_THREAD_SELECT_WRITE_ADDRESSES: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_WRITE_ADDRESSES,
    ),
    LINUX_THREAD_SELECT_WRITE_SETS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_WRITE_SETS),
    LINUX_THREAD_SIGNAL_MASKS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_SIGNAL_MASKS),
    LINUX_THREAD_STACK_BASES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_STACK_BASES),
    LINUX_THREAD_STACK_SIZES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_STACK_SIZES),
    LINUX_THREAD_STATES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_STATES),
    LINUX_THREAD_OWNER_ONLY: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_OWNER_ONLY),
    LINUX_THREAD_TIDS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_TIDS),
    LINUX_THREAD_NICES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_NICES),
    LINUX_THREAD_CPU_CYCLES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_CPU_CYCLES),
    LINUX_THREAD_LAST_CPUS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_LAST_CPUS),
    LINUX_THREAD_TLS_EXTENTS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_TLS_EXTENTS),
    LINUX_THREAD_TLS_SIZES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_TLS_SIZES),
    LINUX_THREAD_WAIT_DEADLINES: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_WAIT_DEADLINES),
    LINUX_THREAD_WAIT_KEYS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_WAIT_KEYS),
    LINUX_THREAD_WAIT_KINDS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_WAIT_KINDS),
    LINUX_THREAD_WAIT_OUTPUTS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_THREAD_WAIT_OUTPUTS),
    LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS,
    ),
    LINUX_TIMED_WAITS_ACTIVE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_TIMED_WAITS_ACTIVE),
    LINUX_TIMERFD_READ_BLOCK_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_TIMERFD_READ_BLOCK_COUNT),
    LINUX_TIMERFD_READ_INTERRUPT_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_TIMERFD_READ_INTERRUPT_COUNT,
    ),
    LINUX_TIMERFD_READ_WAKE_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_TIMERFD_READ_WAKE_COUNT),
    LINUX_TIMER_WAIT_EXPIRY_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_TIMER_WAIT_EXPIRY_COUNT),
    LINUX_TIMER_WAIT_PREEMPTION_COUNT: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_TIMER_WAIT_PREEMPTION_COUNT,
    ),
    LINUX_TTY_CONTROL_CHARACTERS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_TTY_CONTROL_CHARACTERS),
    LINUX_TTY_FOREGROUND_GROUP: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_TTY_FOREGROUND_GROUP),
    LINUX_TTY_LINE: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_TTY_LINE),
    LINUX_TTY_SESSION: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_TTY_SESSION),
    LINUX_TTY_TERMIOS_FLAGS: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_TTY_TERMIOS_FLAGS),
    LINUX_YIELD_SWITCH_COUNT: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_YIELD_SWITCH_COUNT),
    LIVE_FORK_PUBLIC_DIAGNOSTIC: RuntimeRef(&X86_RUNTIME_BACKING_LIVE_FORK_PUBLIC_DIAGNOSTIC),
    NETWORK_DHCP_REQUESTED: RuntimeRef(&X86_RUNTIME_BACKING_NETWORK_DHCP_REQUESTED),
    NETWORK_DHCP_RESULT: RuntimeRef(&X86_RUNTIME_BACKING_NETWORK_DHCP_RESULT),
    NETWORK_PING_ACTIVE: RuntimeRef(&X86_RUNTIME_BACKING_NETWORK_PING_ACTIVE),
    NETWORK_PING_REQUESTED: RuntimeRef(&X86_RUNTIME_BACKING_NETWORK_PING_REQUESTED),
    NETWORK_PING_RESULT: RuntimeRef(&X86_RUNTIME_BACKING_NETWORK_PING_RESULT),
    PROCESS_CHILD_CONTEXT_VALID: RuntimeRef(&X86_RUNTIME_BACKING_PROCESS_CHILD_CONTEXT_VALID),
    PROCESS_CHILD_EXECUTION_DIAGNOSTIC: RuntimeRef(
        &X86_RUNTIME_BACKING_PROCESS_CHILD_EXECUTION_DIAGNOSTIC,
    ),
    PROCESS_CHILD_EXIT_STATUS: RuntimeRef(&X86_RUNTIME_BACKING_PROCESS_CHILD_EXIT_STATUS),
    PROCESS_CHILD_EXPECTED_FS_BASE: RuntimeRef(&X86_RUNTIME_BACKING_PROCESS_CHILD_EXPECTED_FS_BASE),
    PROCESS_CHILD_EXPECTED_REGISTERS: RuntimeRef(
        &X86_RUNTIME_BACKING_PROCESS_CHILD_EXPECTED_REGISTERS,
    ),
    PROCESS_CHILD_PROBE_STATE: RuntimeRef(&X86_RUNTIME_BACKING_PROCESS_CHILD_PROBE_STATE),
};

static X86_RUNTIME_BACKING_LINUX_CONTROLLER_DOMAIN: AtomicU64 = AtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_CONTROLLER_CONSOLE: AtomicU64 = AtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_CONTROLLER_HOST: AtomicU64 = AtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_CONTROLLER_ROOT: AtomicU64 = AtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_CONTROLLER_NETWORK: AtomicU64 = AtomicU64::new(0);

const LINUX_RUNTIME_HOST_INSTANCE: u8 = control_abi::DOMAIN_LIMIT as u8;
const LINUX_RUNTIME_INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;
static X86_RUNTIME_BACKING_LINUX_EXECUTION_INSTANCE: PerCpuAtomicU8 =
    PerCpuAtomicU8::new(LINUX_RUNTIME_HOST_INSTANCE);

/// A value each CPU keeps for itself, such as the domain instance whose
/// processes it runs.
struct PerCpuAtomicU8([AtomicU8; CPU_ENTRY_STATE_LIMIT]);

#[allow(dead_code)]
impl PerCpuAtomicU8 {
    const fn new(value: u8) -> Self {
        let mut values = [const { AtomicU8::new(0) }; CPU_ENTRY_STATE_LIMIT];
        let mut cpu = 0;
        while cpu < CPU_ENTRY_STATE_LIMIT {
            values[cpu] = AtomicU8::new(value);
            cpu += 1;
        }
        Self(values)
    }

    fn current(&self) -> &AtomicU8 {
        let cpu = current_cpu_index_checked()
            .filter(|cpu| *cpu < CPU_ENTRY_STATE_LIMIT)
            .unwrap_or(0);
        &self.0[cpu]
    }

    fn load(&self, order: Ordering) -> u8 {
        self.current().load(order)
    }

    fn store(&self, value: u8, order: Ordering) {
        self.current().store(value, order);
    }

    fn swap(&self, value: u8, order: Ordering) -> u8 {
        self.current().swap(value, order)
    }
}

macro_rules! banked_atomic_integer {
    ($name:ident, $atomic:ty, $value:ty) => {
        banked_atomic_integer!(
            $name,
            $atomic,
            $value,
            LINUX_RUNTIME_INSTANCE_LIMIT,
            linux_execution_instance
        );
    };
    ($name:ident, $atomic:ty, $value:ty, $banks:expr, $bank:path) => {
        struct $name {
            values: [$atomic; $banks],
            states: [AtomicU8; $banks],
            initial: $value,
        }

        #[allow(dead_code)]
        impl $name {
            const fn new(value: $value) -> Self {
                Self {
                    values: [const { <$atomic>::new(0) }; $banks],
                    states: [const { AtomicU8::new(0) }; $banks],
                    initial: value,
                }
            }

            fn current(&self) -> &$atomic {
                let instance = $bank();
                if self.states[instance].load(Ordering::Acquire) != 2 {
                    if self.states[instance]
                        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire)
                        .is_ok()
                    {
                        self.values[instance].store(self.initial, Ordering::Relaxed);
                        self.states[instance].store(2, Ordering::Release);
                    } else {
                        while self.states[instance].load(Ordering::Acquire) != 2 {
                            core::hint::spin_loop();
                        }
                    }
                }
                &self.values[instance]
            }

            fn load(&self, order: Ordering) -> $value {
                self.current().load(order)
            }

            /// The value in bank `bank`, which need not be this CPU's.
            fn at_bank(&self, bank: usize) -> &$atomic {
                if self.states[bank].load(Ordering::Acquire) != 2 {
                    let _ = self.current();
                    if self.states[bank]
                        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire)
                        .is_ok()
                    {
                        self.values[bank].store(self.initial, Ordering::Relaxed);
                        self.states[bank].store(2, Ordering::Release);
                    } else {
                        while self.states[bank].load(Ordering::Acquire) != 2 {
                            core::hint::spin_loop();
                        }
                    }
                }
                &self.values[bank]
            }

            fn store(&self, value: $value, order: Ordering) {
                self.current().store(value, order);
            }

            fn swap(&self, value: $value, order: Ordering) -> $value {
                self.current().swap(value, order)
            }

            fn fetch_add(&self, value: $value, order: Ordering) -> $value {
                self.current().fetch_add(value, order)
            }

            fn fetch_and(&self, value: $value, order: Ordering) -> $value {
                self.current().fetch_and(value, order)
            }

            fn fetch_or(&self, value: $value, order: Ordering) -> $value {
                self.current().fetch_or(value, order)
            }

            fn compare_exchange(
                &self,
                current: $value,
                new: $value,
                success: Ordering,
                failure: Ordering,
            ) -> Result<$value, $value> {
                self.current()
                    .compare_exchange(current, new, success, failure)
            }
        }
    };
}

macro_rules! banked_atomic_bool {
    ($name:ident, $banks:expr, $bank:path) => {
        struct $name {
            values: [AtomicBool; $banks],
            states: [AtomicU8; $banks],
            initial: bool,
        }

        #[allow(dead_code)]
        impl $name {
            const fn new(value: bool) -> Self {
                Self {
                    values: [const { AtomicBool::new(false) }; $banks],
                    states: [const { AtomicU8::new(0) }; $banks],
                    initial: value,
                }
            }

            fn current(&self) -> &AtomicBool {
                let instance = $bank();
                if self.states[instance].load(Ordering::Acquire) != 2 {
                    if self.states[instance]
                        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire)
                        .is_ok()
                    {
                        self.values[instance].store(self.initial, Ordering::Relaxed);
                        self.states[instance].store(2, Ordering::Release);
                    } else {
                        while self.states[instance].load(Ordering::Acquire) != 2 {
                            core::hint::spin_loop();
                        }
                    }
                }
                &self.values[instance]
            }

            fn load(&self, order: Ordering) -> bool {
                self.current().load(order)
            }

            /// The value in bank `bank`, which need not be this CPU's.
            fn at_bank(&self, bank: usize) -> &AtomicBool {
                if self.states[bank].load(Ordering::Acquire) != 2 {
                    if self.states[bank]
                        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire)
                        .is_ok()
                    {
                        self.values[bank].store(self.initial, Ordering::Relaxed);
                        self.states[bank].store(2, Ordering::Release);
                    } else {
                        while self.states[bank].load(Ordering::Acquire) != 2 {
                            core::hint::spin_loop();
                        }
                    }
                }
                &self.values[bank]
            }

            fn store(&self, value: bool, order: Ordering) {
                self.current().store(value, order);
            }

            fn swap(&self, value: bool, order: Ordering) -> bool {
                self.current().swap(value, order)
            }

            fn fetch_and(&self, value: bool, order: Ordering) -> bool {
                self.current().fetch_and(value, order)
            }

            fn fetch_or(&self, value: bool, order: Ordering) -> bool {
                self.current().fetch_or(value, order)
            }

            fn compare_exchange(
                &self,
                current: bool,
                new: bool,
                success: Ordering,
                failure: Ordering,
            ) -> Result<bool, bool> {
                self.current()
                    .compare_exchange(current, new, success, failure)
            }
        }
    };
}

banked_atomic_bool!(
    BankedAtomicBool,
    LINUX_RUNTIME_INSTANCE_LIMIT,
    linux_execution_instance
);
banked_atomic_bool!(CpuBankedAtomicBool, LINUX_CPU_BANK_LIMIT, linux_cpu_bank);

/// A table banked per execution instance and laid out instance by instance,
/// so the current instance's table is one contiguous array: a process switch
/// copies it in one sequential pass. (An array of `BankedAtomicU16` and the
/// like interleaves the instances element by element, and copying one table
/// touched a cache line per element.) Every element starts at zero.
struct BankedAtomicArray<A, const N: usize>([[A; N]; LINUX_RUNTIME_INSTANCE_LIMIT]);

impl<A, const N: usize> core::ops::Deref for BankedAtomicArray<A, N> {
    type Target = [A; N];
    fn deref(&self) -> &[A; N] {
        &self.0[linux_execution_instance()]
    }
}

impl<'a, A, const N: usize> IntoIterator for &'a RuntimeRef<BankedAtomicArray<A, N>> {
    type Item = &'a A;
    type IntoIter = core::slice::Iter<'a, A>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

macro_rules! banked_array {
    ($($atomic:ty => $value:ty),*) => {$(
        #[allow(dead_code)]
        impl<const N: usize> BankedAtomicArray<$atomic, N> {
            const fn new() -> Self {
                Self([const { [const { <$atomic>::new(0) }; N] }; LINUX_RUNTIME_INSTANCE_LIMIT])
            }

            /// The current instance's table, read in one pass with relaxed
            /// loads (the caller orders the pass as a whole).
            fn snapshot(&self) -> [$value; N] {
                let table: &[$atomic; N] = self;
                core::array::from_fn(|index| table[index].load(Ordering::Relaxed))
            }

            /// Overwrites the current instance's table with relaxed stores.
            fn install(&self, values: &[$value; N]) {
                let table: &[$atomic; N] = self;
                for (cell, value) in table.iter().zip(values) {
                    cell.store(*value, Ordering::Relaxed);
                }
            }
        }
    )*};
}

banked_array!(AtomicU8 => u8, AtomicU16 => u16, AtomicU32 => u32, AtomicU64 => u64);

/// A `BankedAtomicArray` banked per CPU as well (see `linux_cpu_bank`): the
/// tables of the process each CPU runs.
struct CpuBankedAtomicArray<A, const N: usize>([[A; N]; LINUX_CPU_BANK_LIMIT]);

impl<A, const N: usize> core::ops::Deref for CpuBankedAtomicArray<A, N> {
    type Target = [A; N];
    fn deref(&self) -> &[A; N] {
        &self.0[linux_cpu_bank()]
    }
}

impl<A, const N: usize> CpuBankedAtomicArray<A, N> {
    /// The table of bank `bank`, which need not be this CPU's.
    fn at_bank(&self, bank: usize) -> &[A; N] {
        &self.0[bank]
    }
}

impl<'a, A, const N: usize> IntoIterator for &'a RuntimeRef<CpuBankedAtomicArray<A, N>> {
    type Item = &'a A;
    type IntoIter = core::slice::Iter<'a, A>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

macro_rules! cpu_banked_array {
    ($($atomic:ty => $value:ty),*) => {$(
        #[allow(dead_code)]
        impl<const N: usize> CpuBankedAtomicArray<$atomic, N> {
            const fn new() -> Self {
                Self([const { [const { <$atomic>::new(0) }; N] }; LINUX_CPU_BANK_LIMIT])
            }

            /// The current bank's table, read in one pass with relaxed
            /// loads (the caller orders the pass as a whole).
            fn snapshot(&self) -> [$value; N] {
                let table: &[$atomic; N] = self;
                core::array::from_fn(|index| table[index].load(Ordering::Relaxed))
            }

            /// Overwrites the current bank's table with relaxed stores.
            fn install(&self, values: &[$value; N]) {
                let table: &[$atomic; N] = self;
                for (cell, value) in table.iter().zip(values) {
                    cell.store(*value, Ordering::Relaxed);
                }
            }
        }
    )*};
}

cpu_banked_array!(AtomicU8 => u8, AtomicU16 => u16, AtomicU32 => u32, AtomicU64 => u64);

banked_atomic_integer!(BankedAtomicU8, AtomicU8, u8);
banked_atomic_integer!(BankedAtomicU16, AtomicU16, u16);
banked_atomic_integer!(BankedAtomicU32, AtomicU32, u32);
banked_atomic_integer!(BankedAtomicU64, AtomicU64, u64);

banked_atomic_integer!(
    CpuBankedAtomicU8,
    AtomicU8,
    u8,
    LINUX_CPU_BANK_LIMIT,
    linux_cpu_bank
);
banked_atomic_integer!(
    ThreadCpuAtomicU8,
    AtomicU8,
    u8,
    LINUX_CPU_BANK_LIMIT,
    linux_thread_cpu_bank
);
banked_atomic_integer!(
    CpuBankedAtomicU16,
    AtomicU16,
    u16,
    LINUX_CPU_BANK_LIMIT,
    linux_cpu_bank
);
banked_atomic_integer!(
    CpuBankedAtomicU32,
    AtomicU32,
    u32,
    LINUX_CPU_BANK_LIMIT,
    linux_cpu_bank
);
banked_atomic_integer!(
    CpuBankedAtomicU64,
    AtomicU64,
    u64,
    LINUX_CPU_BANK_LIMIT,
    linux_cpu_bank
);

static X86_RUNTIME_BACKING_LINUX_BOOT_ID_STATE: AtomicU8 = AtomicU8::new(0);
static CONTROL_DISCOVERY_OVERRIDE_DOMAIN: AtomicU64 = AtomicU64::new(0);
static CONTROL_DISCOVERY_OVERRIDE_WORD: AtomicU64 = AtomicU64::new(0);
static CONTROL_DESCRIPTOR_OVERRIDE_DOMAIN: AtomicU64 = AtomicU64::new(0);
const PROCESS_CHILD_PROBE_IDLE: u8 = 0;
const PROCESS_CHILD_PROBE_EXPECT_CONTEXT: u8 = 1;
const PROCESS_CHILD_PROBE_EXPECT_EXIT: u8 = 2;
const PROCESS_CHILD_PROBE_COMPLETE: u8 = 3;
const CROSS_CPU_RUNTIME_SIGNAL: u64 = 1;
const CROSS_CPU_RUNTIME_FUTEX_WAKE: u64 = 2;
const CROSS_CPU_RUNTIME_SOCKET_SEND: u64 = 3;
const CROSS_CPU_RUNTIME_PIPE_SEND: u64 = 4;
const CROSS_CPU_RUNTIME_SCHEDULE: u64 = 5;
const CROSS_CPU_RUNTIME_KEY: u64 = 0x4749_4e55_585f_534d;
static X86_RUNTIME_BACKING_PROCESS_CHILD_PROBE_STATE: [AtomicU8; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU8::new(PROCESS_CHILD_PROBE_IDLE) }; CPU_ENTRY_STATE_LIMIT];
static X86_RUNTIME_BACKING_PROCESS_CHILD_CONTEXT_VALID: [AtomicBool; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicBool::new(false) }; CPU_ENTRY_STATE_LIMIT];
static X86_RUNTIME_BACKING_PROCESS_CHILD_EXECUTION_DIAGNOSTIC: [AtomicU8; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU8::new(0) }; CPU_ENTRY_STATE_LIMIT];
static X86_RUNTIME_BACKING_PROCESS_CHILD_EXIT_STATUS: [AtomicU8; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU8::new(0) }; CPU_ENTRY_STATE_LIMIT];
static X86_RUNTIME_BACKING_PROCESS_CHILD_EXPECTED_REGISTERS: [[AtomicU64; 15];
    CPU_ENTRY_STATE_LIMIT] = [const { [const { AtomicU64::new(0) }; 15] }; CPU_ENTRY_STATE_LIMIT];
static X86_RUNTIME_BACKING_PROCESS_CHILD_EXPECTED_FS_BASE: [AtomicU64; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU64::new(0) }; CPU_ENTRY_STATE_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE: CpuBankedAtomicBool = CpuBankedAtomicBool::new(false);
// Execution mode describes the currently running CPU context, not persistent
// per-domain state. Keeping it in a domain bank can strand the temporary
// runtime value when a verification helper changes the active instance.
static X86_RUNTIME_BACKING_LINUX_RUNTIME_MODE: AtomicBool = AtomicBool::new(false);
static X86_RUNTIME_BACKING_ELF_PROBE_COMPLETED: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_ELF_PROBE_EXIT_STATUS: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_TERMINATION_SIGNAL: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PARENT_DEATH_SIGNAL: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_EXEC_REPLACED: BankedAtomicBool = BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_ELF_PROBE_EXEC_NODE: BankedAtomicU8 = BankedAtomicU8::new(0);
static X86_RUNTIME_BACKING_LINUX_LIVE_RETURN_VALIDATED: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_CHILD_EXIT_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PARENT_RESUMED: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_FORK_REQUESTED: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_FORK_NEW_MOUNT_NAMESPACE: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_FORK_NEW_USER_NAMESPACE: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_FORK_CHILD_TID_ADDRESS: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_FORK_PARENT_TID_ADDRESS: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_FORK_CHILD_STACK: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_FORK_SHARE_VM: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_FORK_PIDFD_ADDRESS: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_FORK_CGROUP_GENERATION: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_FORK_CLEAR_SIGHAND: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_FORK_OWN_PAGES: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_FORK_CLONE_FLAGS: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_FORK_TLS: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_FORK_CLEAR_TID_ADDRESS: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_EXITED: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_EXECUTED: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_YIELDED: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_EXIT_PID: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_EXEC_PID: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_YIELD_PID: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
/// Times a domain's init exit has waited for the processes it killed.
static X86_RUNTIME_BACKING_LINUX_INIT_EXIT_KILL_ROUNDS: BankedAtomicU32 = BankedAtomicU32::new(0);
const LINUX_INIT_EXIT_KILL_ROUND_LIMIT: u32 = 10_000;
/// Rounds after which init's exit ends killed processes itself.
const LINUX_INIT_EXIT_FORCE_ROUND: u32 = 100;
/// Per domain, the process its last `domain exec` runs (0: none): the
/// console is the command's until it exits (`load_linux_domain_exec`).
static X86_RUNTIME_BACKING_CONTAINER_EXEC_CHILD: [AtomicU32; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU32::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_LINUX_PROCESS_RELEASE_PARENT_ON_EXEC: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_STATUS: CpuBankedAtomicU8 =
    CpuBankedAtomicU8::new(0);
static X86_RUNTIME_BACKING_LINUX_CURRENT_PROCESS_PID: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(1);
static X86_RUNTIME_BACKING_LINUX_PROCESS_WAIT_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_TTY_SESSION: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_TTY_FOREGROUND_GROUP: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_TTY_TERMIOS_FLAGS: [BankedAtomicU32; 4] = [
    BankedAtomicU32::new(0x500),
    BankedAtomicU32::new(0x5),
    BankedAtomicU32::new(0xbf),
    BankedAtomicU32::new(0x8a3b),
];
static X86_RUNTIME_BACKING_LINUX_TTY_LINE: BankedAtomicU8 = BankedAtomicU8::new(0);
static X86_RUNTIME_BACKING_LINUX_TTY_CONTROL_CHARACTERS: [BankedAtomicU8; 19] =
    [const { BankedAtomicU8::new(0) }; 19];
const LINUX_TTY_DEFAULT_CONTROL_CHARACTERS: [u8; 19] = [
    3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0,
];
static X86_RUNTIME_BACKING_LIVE_FORK_PUBLIC_DIAGNOSTIC: BankedAtomicU8 = BankedAtomicU8::new(0);
static X86_RUNTIME_BACKING_LINUX_PROCESS_SNAPSHOT_VALIDATED: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_PROCESS_SNAPSHOT_STAGE: CpuBankedAtomicU8 =
    CpuBankedAtomicU8::new(0);
static X86_RUNTIME_BACKING_LINUX_CLONE_DISPATCH_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_FIRST_CHILD_TID: CpuBankedAtomicU32 = CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_CLONE_REUSE_VALIDATED: BankedAtomicBool =
    BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_CHILD_GETTID_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_YIELD_SWITCH_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_LAST_PREEMPTED_THREAD_SLOT: ThreadCpuAtomicU8 =
    ThreadCpuAtomicU8::new(LINUX_THREAD_SLOT_NONE);
static X86_RUNTIME_BACKING_LINUX_CLONE_BUSY_REJECTION_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_CLONE_INVALID_REJECTION_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_CLONE_TID_FAULT_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_FUTEX_WAIT_BLOCK_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_FUTEX_EXPLICIT_WAKE_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_FUTEX_EXIT_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_FUTEX_WAIT_TIMEOUT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_SLEEP_BLOCK_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_SLEEP_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_SLEEP_INTERRUPT_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_TIMER_WAIT_EXPIRY_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_TIMER_WAIT_PREEMPTION_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_PREEMPT_TICKS: ThreadCpuAtomicU8 =
    ThreadCpuAtomicU8::new(0);
static X86_RUNTIME_BACKING_LINUX_POLL_WAIT_BLOCK_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_POLL_WAIT_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_POLL_WAIT_TIMEOUT_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_POLL_WAIT_INTERRUPT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EPOLL_WAIT_BLOCK_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EPOLL_WAIT_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EPOLL_WAIT_TIMEOUT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EPOLL_WAIT_INTERRUPT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EVENTFD_READ_BLOCK_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EVENTFD_READ_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EVENTFD_READ_INTERRUPT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EVENTFD_WRITE_BLOCK_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EVENTFD_WRITE_WAKE_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EVENTFD_WRITE_INTERRUPT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PIPE_READ_BLOCK_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PIPE_READ_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PIPE_READ_INTERRUPT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PIPE_WRITE_BLOCK_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PIPE_WRITE_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PIPE_WRITE_INTERRUPT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_TIMERFD_READ_BLOCK_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_TIMERFD_READ_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_TIMERFD_READ_INTERRUPT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PPOLL_WAIT_BLOCK_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PPOLL_WAIT_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PPOLL_WAIT_TIMEOUT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EPOLL_PWAIT_BLOCK_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EPOLL_PWAIT_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_EPOLL_PWAIT_TIMEOUT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_MASKED_WAIT_INTERRUPT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_SIGNAL_WAIT_INTERRUPT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_STACK: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_STACK_LOW: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_STACK_FRAME: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_STACK_GENERATION: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_HEAP_FRAME: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_HEAP_GENERATION: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_HEAP_FRAME: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_HEAP_GENERATION: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_CODE_BASE: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_CODE_SIZE: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_LOADER_CODE_BASE: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_LOADER_CODE_SIZE: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_DATA: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_DATA_SIZE: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_EXEC_ENTRY: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_EXEC_MAPPING_ADDRESSES: [BankedAtomicU64;
    LINUX_EXEC_MAPPING_LIMIT] = [const { BankedAtomicU64::new(0) }; LINUX_EXEC_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_EXEC_MAPPING_FRAMES: [CpuBankedAtomicU64;
    LINUX_EXEC_MAPPING_LIMIT] = [const { CpuBankedAtomicU64::new(0) }; LINUX_EXEC_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_EXEC_MAPPING_GENERATIONS: [CpuBankedAtomicU32;
    LINUX_EXEC_MAPPING_LIMIT] = [const { CpuBankedAtomicU32::new(0) }; LINUX_EXEC_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_EXEC_MAPPING_FLAGS: [BankedAtomicU8;
    LINUX_EXEC_MAPPING_LIMIT] = [const { BankedAtomicU8::new(0) }; LINUX_EXEC_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE_IMAGE_ADDRESSES: [BankedAtomicU64;
    LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
    [const { BankedAtomicU64::new(0) }; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE_IMAGE_FRAMES: [CpuBankedAtomicU64;
    LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE_IMAGE_GENERATIONS: [CpuBankedAtomicU32;
    LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
    [const { CpuBankedAtomicU32::new(0) }; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE_IMAGE_FLAGS: [CpuBankedAtomicU8;
    LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
    [const { CpuBankedAtomicU8::new(0) }; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_ACTIVE_IMAGE_COUNT: BankedAtomicU16 = BankedAtomicU16::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_RETIRED_IMAGE_ADDRESSES: [BankedAtomicU64;
    LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
    [const { BankedAtomicU64::new(0) }; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_RETIRED_IMAGE_FRAMES: [BankedAtomicU64;
    LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
    [const { BankedAtomicU64::new(0) }; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_RETIRED_IMAGE_GENERATIONS: [BankedAtomicU32;
    LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
    [const { BankedAtomicU32::new(0) }; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_RETIRED_IMAGE_FLAGS: [BankedAtomicU8;
    LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
    [const { BankedAtomicU8::new(0) }; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_RETIRED_IMAGE_COUNT: BankedAtomicU8 = BankedAtomicU8::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_TLS: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_TLS_SIZE: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_TLS_FRAMES: [BankedAtomicU64; 2] =
    [const { BankedAtomicU64::new(0) }; 2];
static X86_RUNTIME_BACKING_ELF_PROBE_TLS_GENERATIONS: [BankedAtomicU32; 2] =
    [const { BankedAtomicU32::new(0) }; 2];
static X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_TLS_FRAMES: [BankedAtomicU64; 2] =
    [const { BankedAtomicU64::new(0) }; 2];
static X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_TLS_GENERATIONS: [BankedAtomicU32; 2] =
    [const { BankedAtomicU32::new(0) }; 2];
static X86_RUNTIME_BACKING_ELF_PROBE_SIBLING_FS_BASE: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_SIBLING_TLS: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_SIBLING_STACK: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_SIBLING_STACK_FRAME: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_SIBLING_STACK_GENERATION: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_SIBLING_STACK_FRAME: BankedAtomicU64 =
    BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_SIBLING_STACK_GENERATION: BankedAtomicU32 =
    BankedAtomicU32::new(0);
/// Threads per process. LTP sizes thread pools by the CPU count (fcntl36
/// runs 9 per CPU, futex_wake02 55), so a cpu=4 domain needs well over 32.
const LINUX_THREAD_LIMIT: usize = 128;
const LINUX_THREAD_FREE: u8 = 0;
const LINUX_THREAD_READY: u8 = 1;
const LINUX_THREAD_RUNNING: u8 = 2;
const LINUX_THREAD_BLOCKED: u8 = 3;
/// Waiting in a system call parked on the thread's own activation, until
/// the scheduler resumes it there (docs/SCHEDULER.md, "Activations per
/// thread"); what it waits for is its block in the process registry.
const LINUX_THREAD_PARKED: u8 = 4;
const LINUX_THREAD_SLOT_NONE: u8 = u8::MAX;
const LINUX_THREAD_WAIT_NONE: u8 = 0;
const LINUX_THREAD_WAIT_FUTEX: u8 = 1;
const LINUX_THREAD_WAIT_SIGNAL: u8 = 2;
const LINUX_THREAD_WAIT_SLEEP: u8 = 3;
const LINUX_THREAD_WAIT_POLL: u8 = 4;
const LINUX_THREAD_WAIT_EPOLL: u8 = 5;
const LINUX_THREAD_WAIT_EVENTFD_READ: u8 = 6;
const LINUX_THREAD_WAIT_PPOLL: u8 = 7;
const LINUX_THREAD_WAIT_EPOLL_PWAIT: u8 = 8;
const LINUX_THREAD_WAIT_PIPE_READ: u8 = 9;
const LINUX_THREAD_WAIT_TIMERFD_READ: u8 = 10;
const LINUX_THREAD_WAIT_PIPE_WRITE: u8 = 11;
const LINUX_THREAD_WAIT_EVENTFD_WRITE: u8 = 12;
const LINUX_THREAD_WAIT_PAUSE: u8 = 13;
const LINUX_THREAD_WAIT_SIGSUSPEND: u8 = 14;
const LINUX_THREAD_WAIT_SELECT: u8 = 15;
const LINUX_THREAD_WAIT_PSELECT: u8 = 16;
/// Waits a moment, then issues system call `key` again (its saved context
/// is rewound to the `syscall` instruction): for waits with no waker of
/// their own, such as a record lock another thread holds.
const LINUX_THREAD_WAIT_RETRY: u8 = 17;
/// Stopped by a stop signal in its kill call, until SIGCONT.
const LINUX_THREAD_WAIT_STOPPED: u8 = 18;
const LINUX_SYSCALL_FRAME_REGISTERS: usize = 12;
static X86_RUNTIME_BACKING_LINUX_THREAD_STATES: [CpuBankedAtomicU8; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU8::new(LINUX_THREAD_FREE) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_OWNER_ONLY: CpuBankedAtomicArray<
    AtomicU8,
    LINUX_THREAD_LIMIT,
> = CpuBankedAtomicArray::<AtomicU8, LINUX_THREAD_LIMIT>::new();
static X86_RUNTIME_BACKING_LINUX_THREAD_GENERATIONS: [CpuBankedAtomicU32; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU32::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_TIDS: [CpuBankedAtomicU32; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU32::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_NICES: [CpuBankedAtomicU8; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU8::new(LINUX_NICE_DEFAULT) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_LAST_CPUS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_CPU_CYCLES: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_POINTERS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_TLS_EXTENTS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_TLS_SIZES: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_STACK_BASES: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_STACK_SIZES: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_RIPS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_RSPS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_RFLAGS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_RAXS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_RCXS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_R11S: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_REGISTERS: [[CpuBankedAtomicU64;
    LINUX_SYSCALL_FRAME_REGISTERS];
    LINUX_THREAD_LIMIT] =
    [const { [const { CpuBankedAtomicU64::new(0) }; LINUX_SYSCALL_FRAME_REGISTERS] };
        LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_CLEAR_CHILD_TIDS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_ROBUST_LISTS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_RSEQ_POINTERS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_RSEQ_LENGTHS: [CpuBankedAtomicU32; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU32::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_RSEQ_SIGNATURES: [CpuBankedAtomicU32; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU32::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_SIGNAL_MASKS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_WAIT_KINDS: [CpuBankedAtomicU8; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU8::new(LINUX_THREAD_WAIT_NONE) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_WAIT_KEYS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_WAIT_OUTPUTS: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_WAIT_DEADLINES: [CpuBankedAtomicU64; LINUX_THREAD_LIMIT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS: [CpuBankedAtomicU64;
    LINUX_THREAD_LIMIT] = [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static LINUX_FUTEX_COORDINATION: crate::sync::SpinLock<Vec<LinuxProcessFutexWait>> =
    crate::sync::SpinLock::new(crate::sync::LockRank::FUTEX_COORDINATION, Vec::new());
/// Absolute deadlines of timed waits (poll, nanosleep, epoll_wait) whose
/// process yielded to another and will execute the same call again, so the
/// restarted call keeps its deadline instead of starting a new timeout.
static LINUX_RESTART_DEADLINES: crate::sync::SpinLock<Vec<LinuxRestartDeadline>> =
    crate::sync::SpinLock::new(crate::sync::LockRank::RESTART_DEADLINES, Vec::new());
static X86_RUNTIME_BACKING_LINUX_THREAD_POLL_DESCRIPTORS: [[CpuBankedAtomicU32;
    LINUX_POLLFD_LIMIT];
    LINUX_THREAD_LIMIT] =
    [const { [const { CpuBankedAtomicU32::new(0) }; LINUX_POLLFD_LIMIT] }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_POLL_EVENTS: [[CpuBankedAtomicU16; LINUX_POLLFD_LIMIT];
    LINUX_THREAD_LIMIT] =
    [const { [const { CpuBankedAtomicU16::new(0) }; LINUX_POLLFD_LIMIT] }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_READ_ADDRESSES: [CpuBankedAtomicU64;
    LINUX_THREAD_LIMIT] = [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_WRITE_ADDRESSES: [CpuBankedAtomicU64;
    LINUX_THREAD_LIMIT] = [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES: [CpuBankedAtomicU64;
    LINUX_THREAD_LIMIT] = [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES: [CpuBankedAtomicU64;
    LINUX_THREAD_LIMIT] = [const { CpuBankedAtomicU64::new(0) }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_READ_SETS: [[CpuBankedAtomicU64;
    LINUX_SELECT_WORD_LIMIT];
    LINUX_THREAD_LIMIT] =
    [const { [const { CpuBankedAtomicU64::new(0) }; LINUX_SELECT_WORD_LIMIT] }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_WRITE_SETS: [[CpuBankedAtomicU64;
    LINUX_SELECT_WORD_LIMIT];
    LINUX_THREAD_LIMIT] =
    [const { [const { CpuBankedAtomicU64::new(0) }; LINUX_SELECT_WORD_LIMIT] }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_SELECT_EXCEPTION_SETS: [[CpuBankedAtomicU64;
    LINUX_SELECT_WORD_LIMIT];
    LINUX_THREAD_LIMIT] =
    [const { [const { CpuBankedAtomicU64::new(0) }; LINUX_SELECT_WORD_LIMIT] }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_IOV_ADDRESSES: [[CpuBankedAtomicU64; LINUX_IOV_LIMIT];
    LINUX_THREAD_LIMIT] =
    [const { [const { CpuBankedAtomicU64::new(0) }; LINUX_IOV_LIMIT] }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_THREAD_IOV_LENGTHS: [[CpuBankedAtomicU64; LINUX_IOV_LIMIT];
    LINUX_THREAD_LIMIT] =
    [const { [const { CpuBankedAtomicU64::new(0) }; LINUX_IOV_LIMIT] }; LINUX_THREAD_LIMIT];
static X86_RUNTIME_BACKING_LINUX_CURRENT_THREAD_SLOT: ThreadCpuAtomicU8 =
    ThreadCpuAtomicU8::new(LINUX_THREAD_SLOT_NONE);
static X86_RUNTIME_BACKING_LINUX_NEXT_TID: CpuBankedAtomicU32 = CpuBankedAtomicU32::new(1);
static X86_RUNTIME_BACKING_ELF_PROBE_RELRO: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_RELRO_SIZE: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_BRK: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_BRK_LIMIT: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_MMAP: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_MMAP_NEXT: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_MMAP_FRAMES: [CpuBankedAtomicU64;
    LINUX_RUNTIME_MMAP_SLOT_COUNT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_RUNTIME_MMAP_SLOT_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MMAP_GENERATIONS: [CpuBankedAtomicU32;
    LINUX_RUNTIME_MMAP_SLOT_COUNT] =
    [const { CpuBankedAtomicU32::new(0) }; LINUX_RUNTIME_MMAP_SLOT_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_PAGE_TABLE_FRAMES: [CpuBankedAtomicU64; 6] =
    [const { CpuBankedAtomicU64::new(0) }; 6];
static X86_RUNTIME_BACKING_ELF_PROBE_PAGE_TABLE_GENERATIONS: [CpuBankedAtomicU32; 6] =
    [const { CpuBankedAtomicU32::new(0) }; 6];
static X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_PAGE_TABLE_FRAMES: [BankedAtomicU64; 6] =
    [const { BankedAtomicU64::new(0) }; 6];
static X86_RUNTIME_BACKING_ELF_PROBE_RECLAIM_PAGE_TABLE_GENERATIONS: [BankedAtomicU32; 6] =
    [const { BankedAtomicU32::new(0) }; 6];
static X86_RUNTIME_BACKING_ELF_PROBE_MMAP_PAGES: [CpuBankedAtomicU8;
    LINUX_RUNTIME_MMAP_SLOT_COUNT] =
    [const { CpuBankedAtomicU8::new(0) }; LINUX_RUNTIME_MMAP_SLOT_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MMAP_PROTECTION: [CpuBankedAtomicU8;
    LINUX_RUNTIME_MMAP_SLOT_COUNT] =
    [const { CpuBankedAtomicU8::new(0) }; LINUX_RUNTIME_MMAP_SLOT_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MMAP_FILE: [CpuBankedAtomicU8; LINUX_RUNTIME_MMAP_SLOT_COUNT] =
    [const { CpuBankedAtomicU8::new(0) }; LINUX_RUNTIME_MMAP_SLOT_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MMAP_SEALED: [CpuBankedAtomicBool;
    LINUX_RUNTIME_MMAP_SLOT_COUNT] =
    [const { CpuBankedAtomicBool::new(false) }; LINUX_RUNTIME_MMAP_SLOT_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MAIN_ADDRESSES: [BankedAtomicU64; LINUX_MAIN_MAPPING_COUNT] =
    [const { BankedAtomicU64::new(0) }; LINUX_MAIN_MAPPING_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MAIN_FRAMES: [BankedAtomicU64; LINUX_MAIN_MAPPING_COUNT] =
    [const { BankedAtomicU64::new(0) }; LINUX_MAIN_MAPPING_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MAIN_OFFSETS: [BankedAtomicU64; LINUX_MAIN_MAPPING_COUNT] =
    [const { BankedAtomicU64::new(0) }; LINUX_MAIN_MAPPING_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MAIN_FILE_SIZES: [BankedAtomicU64; LINUX_MAIN_MAPPING_COUNT] =
    [const { BankedAtomicU64::new(0) }; LINUX_MAIN_MAPPING_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MAIN_PROTECTIONS: [BankedAtomicU8; LINUX_MAIN_MAPPING_COUNT] =
    [const { BankedAtomicU8::new(0) }; LINUX_MAIN_MAPPING_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MAIN_GENERATIONS: [BankedAtomicU32; LINUX_MAIN_MAPPING_COUNT] =
    [const { BankedAtomicU32::new(0) }; LINUX_MAIN_MAPPING_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_MAIN_MAPPINGS: BankedAtomicU8 = BankedAtomicU8::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_BASE_MIN: [BankedAtomicU64;
    LINUX_DEPENDENCY_COUNT] = [const { BankedAtomicU64::new(0) }; LINUX_DEPENDENCY_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_BASE_END: [BankedAtomicU64;
    LINUX_DEPENDENCY_COUNT] = [const { BankedAtomicU64::new(0) }; LINUX_DEPENDENCY_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_SELECTED_BASE: [BankedAtomicU64;
    LINUX_DEPENDENCY_COUNT] = [const { BankedAtomicU64::new(0) }; LINUX_DEPENDENCY_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_RELATIVES: [BankedAtomicU64;
    LINUX_DEPENDENCY_STATE_COUNT] =
    [const { BankedAtomicU64::new(0) }; LINUX_DEPENDENCY_STATE_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_FRAMES: [BankedAtomicU64;
    LINUX_DEPENDENCY_STATE_COUNT] =
    [const { BankedAtomicU64::new(0) }; LINUX_DEPENDENCY_STATE_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_GENERATIONS: [BankedAtomicU32;
    LINUX_DEPENDENCY_STATE_COUNT] =
    [const { BankedAtomicU32::new(0) }; LINUX_DEPENDENCY_STATE_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_OFFSETS: [BankedAtomicU64;
    LINUX_DEPENDENCY_STATE_COUNT] =
    [const { BankedAtomicU64::new(0) }; LINUX_DEPENDENCY_STATE_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_FILE_SIZES: [BankedAtomicU64;
    LINUX_DEPENDENCY_STATE_COUNT] =
    [const { BankedAtomicU64::new(0) }; LINUX_DEPENDENCY_STATE_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_PROTECTIONS: [BankedAtomicU8;
    LINUX_DEPENDENCY_STATE_COUNT] =
    [const { BankedAtomicU8::new(0) }; LINUX_DEPENDENCY_STATE_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DEPENDENCY_MAPPINGS: [BankedAtomicU8; LINUX_DEPENDENCY_COUNT] =
    [const { BankedAtomicU8::new(0) }; LINUX_DEPENDENCY_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_EXITED_CLEAR_CHILD_TID: BankedAtomicU64 =
    BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_EXITED_ROBUST_LIST: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_READ_ONLY_DATA_PAGE: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_UMASK: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_RLIMITS: [CpuBankedAtomicU64; LINUX_RLIMIT_WORDS] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_RLIMIT_WORDS];
static X86_RUNTIME_BACKING_ELF_PROBE_POSIX_MQ_BYTES: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_CROSS_PROCESS_PRLIMIT_VALIDATED: BankedAtomicBool =
    BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_FSIZE_LIMIT_HIT: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_ELF_PROBE_CONSOLE_DESCRIPTORS: CpuBankedAtomicU8 =
    CpuBankedAtomicU8::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_STDERR_OPEN: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_ELF_PROBE_CONSOLE_CLOEXEC: [CpuBankedAtomicU64;
    LINUX_DESCRIPTOR_FLAG_WORD_COUNT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_DESCRIPTOR_FLAG_WORD_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DESCRIPTOR_CREATED: [CpuBankedAtomicU64;
    LINUX_DESCRIPTOR_FLAG_WORD_COUNT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_DESCRIPTOR_FLAG_WORD_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DESCRIPTOR_READ_LEASES: [CpuBankedAtomicU64;
    LINUX_DESCRIPTOR_FLAG_WORD_COUNT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_DESCRIPTOR_FLAG_WORD_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DESCRIPTOR_WRITE_LEASES: [CpuBankedAtomicU64;
    LINUX_DESCRIPTOR_FLAG_WORD_COUNT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_DESCRIPTOR_FLAG_WORD_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_DEVICE_DESCRIPTORS: CpuBankedAtomicArray<
    AtomicU16,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU16, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_ROOTFS_DESCRIPTORS: CpuBankedAtomicArray<
    AtomicU16,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU16, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_SOCKET_SLOTS: CpuBankedAtomicArray<
    AtomicU16,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU16, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_SOCKET_FLAGS: CpuBankedAtomicArray<
    AtomicU32,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU32, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_STDIO_SOCKET_SLOTS: [CpuBankedAtomicU16; 3] =
    [const { CpuBankedAtomicU16::new(0) }; 3];
static X86_RUNTIME_BACKING_ELF_PROBE_STDIO_SOCKET_FLAGS: CpuBankedAtomicArray<AtomicU32, 3> =
    CpuBankedAtomicArray::<AtomicU32, 3>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_TMP_FILE_GENERATIONS: CpuBankedAtomicArray<
    AtomicU32,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU32, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_STDIO_DEVICE_DESCRIPTORS: [CpuBankedAtomicU16; 3] =
    [const { CpuBankedAtomicU16::new(0) }; 3];
static X86_RUNTIME_BACKING_ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS: [CpuBankedAtomicU16; 3] =
    [const { CpuBankedAtomicU16::new(0) }; 3];
static X86_RUNTIME_BACKING_ELF_PROBE_STDIO_TMP_FILE_GENERATIONS: CpuBankedAtomicArray<
    AtomicU32,
    3,
> = CpuBankedAtomicArray::<AtomicU32, 3>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_STDIO_OFFSETS: CpuBankedAtomicArray<AtomicU64, 3> =
    CpuBankedAtomicArray::<AtomicU64, 3>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_STDIO_OPEN_FILE_IDS: CpuBankedAtomicArray<AtomicU64, 3> =
    CpuBankedAtomicArray::<AtomicU64, 3>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_OPEN_FILE_IDS: CpuBankedAtomicArray<
    AtomicU64,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU64, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
static X86_RUNTIME_BACKING_LINUX_NEXT_OPEN_FILE_ID: BankedAtomicU64 = BankedAtomicU64::new(1);
static X86_RUNTIME_BACKING_ELF_PROBE_CWD: CpuBankedAtomicU16 =
    CpuBankedAtomicU16::new(LINUX_ROOT_DIRECTORY);
static X86_RUNTIME_BACKING_ELF_PROBE_ROOTFS_CWD: CpuBankedAtomicU16 =
    CpuBankedAtomicU16::new(crate::published_rootfs::ROOT_HANDLE);
static X86_RUNTIME_BACKING_ELF_PROBE_OVERLAY_CWD: CpuBankedAtomicU32 = CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_EPOLL_DESCRIPTOR: CpuBankedAtomicU16 =
    CpuBankedAtomicU16::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_DESCRIPTOR_OVERFLOW: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_EPOLL_EVENTS: CpuBankedAtomicArray<
    AtomicU32,
    { LINUX_DESCRIPTOR_TABLE_LIMIT as usize },
> = CpuBankedAtomicArray::<AtomicU32, { LINUX_DESCRIPTOR_TABLE_LIMIT as usize }>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_EPOLL_DATA: CpuBankedAtomicArray<
    AtomicU64,
    { LINUX_DESCRIPTOR_TABLE_LIMIT as usize },
> = CpuBankedAtomicArray::<AtomicU64, { LINUX_DESCRIPTOR_TABLE_LIMIT as usize }>::new();
static X86_RUNTIME_BACKING_LINUX_RUNTIME_EPOLL_ACTIVE: CpuBankedAtomicArray<
    AtomicU8,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU8, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
/// For an epoll descriptor duplicated from another, the descriptor (+ 1)
/// that owns the shared instance's watches; 0 when it owns them itself.
static X86_RUNTIME_BACKING_LINUX_RUNTIME_EPOLL_ALIASES: CpuBankedAtomicArray<
    AtomicU32,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU32, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
/// Set while a blocking call on a local socket makes its single attempt, so
/// the socket layer reports EAGAIN instead of spinning.
static X86_RUNTIME_BACKING_LINUX_SOCKET_SINGLE_ATTEMPT: AtomicBool = AtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_EPOLL_WATCH_EPOLL: CpuBankedAtomicArray<
    AtomicU32,
    { LINUX_DESCRIPTOR_TABLE_LIMIT as usize },
> = CpuBankedAtomicArray::<AtomicU32, { LINUX_DESCRIPTOR_TABLE_LIMIT as usize }>::new();
static X86_RUNTIME_BACKING_LINUX_RUNTIME_EPOLL_WATCH_TARGET: CpuBankedAtomicArray<
    AtomicU32,
    { LINUX_DESCRIPTOR_TABLE_LIMIT as usize },
> = CpuBankedAtomicArray::<AtomicU32, { LINUX_DESCRIPTOR_TABLE_LIMIT as usize }>::new();
/// Per edge-triggered watch, the event counts of its socket or pipe it saw
/// last (input low, output high; see `linux_epoll_event_counts`), valid
/// while the watch's events word has LINUX_EPOLL_SEEN_VALID.
static X86_RUNTIME_BACKING_LINUX_RUNTIME_EPOLL_WATCH_SEEN: CpuBankedAtomicArray<
    AtomicU64,
    { LINUX_DESCRIPTOR_TABLE_LIMIT as usize },
> = CpuBankedAtomicArray::<AtomicU64, { LINUX_DESCRIPTOR_TABLE_LIMIT as usize }>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_EVENTFD_DESCRIPTOR: BankedAtomicU16 = BankedAtomicU16::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_EVENTFD_COUNTER: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_EVENTFD_FLAGS: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_EVENTFD_ACTIVE: CpuBankedAtomicArray<
    AtomicU8,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU8, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_TIMERFD_DESCRIPTOR: BankedAtomicU16 = BankedAtomicU16::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_TIMERFD_CLOCK: BankedAtomicU8 = BankedAtomicU8::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_TIMERFD_FLAGS: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_TIMERFD_INTERVAL: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_TIMERFD_DEADLINE: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_TIMERFD_ACTIVE: CpuBankedAtomicArray<
    AtomicU8,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU8, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_POSIX_TIMER_ACTIVE: BankedAtomicBool =
    BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_ELF_PROBE_POSIX_TIMER_INTERVAL: BankedAtomicU64 =
    BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_POSIX_TIMER_DEADLINE: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_REAL_TIMER_INTERVAL: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_REAL_TIMER_DEADLINE: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PIPE_READ_DESCRIPTOR: BankedAtomicU16 =
    BankedAtomicU16::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PIPE_WRITE_DESCRIPTOR: BankedAtomicU16 =
    BankedAtomicU16::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PIPE_READ_FLAGS: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PIPE_WRITE_FLAGS: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PIPE_LENGTH: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PIPE_BUFFER: [BankedAtomicU8; LINUX_PIPE_CAPACITY] =
    [const { BankedAtomicU8::new(0) }; LINUX_PIPE_CAPACITY];
static X86_RUNTIME_BACKING_ELF_PROBE_DESCRIPTOR_OFFSETS: CpuBankedAtomicArray<
    AtomicU64,
    LINUX_DEVICE_DESCRIPTOR_COUNT,
> = CpuBankedAtomicArray::<AtomicU64, LINUX_DEVICE_DESCRIPTOR_COUNT>::new();
static X86_RUNTIME_BACKING_ELF_PROBE_CLOCK_EPOCH: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_CLOCK_FREQUENCY: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PROCESS_NAME_LOW: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PROCESS_NAME_HIGH: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_DUMPABLE: CpuBankedAtomicBool = CpuBankedAtomicBool::new(true);
/// PR_SET_TSC's PR_TSC_SIGSEGV: rdtsc in the process's user mode faults
/// (CR4.TSD while its code runs). Inherited across fork, kept across exec.
static X86_RUNTIME_BACKING_ELF_PROBE_TSC_SIGSEGV: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_ELF_PROBE_SECUREBITS: CpuBankedAtomicU32 = CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PERSONALITY: CpuBankedAtomicU32 = CpuBankedAtomicU32::new(0);
// Linux exposes nice values in the signed range -20..=19. Store nice + 20 so
// the per-domain bank can use the same compact atomic machinery as other
// process runtime state.
static X86_RUNTIME_BACKING_ELF_PROBE_NICE: CpuBankedAtomicU8 = CpuBankedAtomicU8::new(20);
static X86_RUNTIME_BACKING_ELF_PROBE_IOPRIO: CpuBankedAtomicU16 = CpuBankedAtomicU16::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_EXIT_STATUS: BankedAtomicU64 =
    BankedAtomicU64::new(u64::MAX);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_FIRST_UNSUPPORTED_SYSCALL: BankedAtomicU64 =
    BankedAtomicU64::new(u64::MAX);
const LINUX_RUNTIME_SYSCALL_TRACE_LIMIT: usize = 128;
const LINUX_BOOT_PROFILE_SYSCALL_LIMIT: usize = 512;
const LINUX_BOOT_PROFILE_LIFECYCLE_PHASES: usize = 15;
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SYSCALL_TRACE: [BankedAtomicU64;
    LINUX_RUNTIME_SYSCALL_TRACE_LIMIT] =
    [const { BankedAtomicU64::new(u64::MAX) }; LINUX_RUNTIME_SYSCALL_TRACE_LIMIT];
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SYSCALL_RESULT_TRACE: [BankedAtomicU64;
    LINUX_RUNTIME_SYSCALL_TRACE_LIMIT] =
    [const { BankedAtomicU64::new(0) }; LINUX_RUNTIME_SYSCALL_TRACE_LIMIT];
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SYSCALL_TRACE_COUNT: BankedAtomicU64 =
    BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_SYSCALL_COUNTS: [BankedAtomicU64;
    LINUX_BOOT_PROFILE_SYSCALL_LIMIT] =
    [const { BankedAtomicU64::new(0) }; LINUX_BOOT_PROFILE_SYSCALL_LIMIT];
static X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_SYSCALL_TICKS: [BankedAtomicU64;
    LINUX_BOOT_PROFILE_SYSCALL_LIMIT] =
    [const { BankedAtomicU64::new(0) }; LINUX_BOOT_PROFILE_SYSCALL_LIMIT];
static X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_SAVE_COUNT: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_SAVE_TICKS: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_RESTORE_COUNT: BankedAtomicU64 =
    BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_RESTORE_TICKS: BankedAtomicU64 =
    BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_LIFECYCLE_COUNTS: [BankedAtomicU64;
    LINUX_BOOT_PROFILE_LIFECYCLE_PHASES] =
    [const { BankedAtomicU64::new(0) }; LINUX_BOOT_PROFILE_LIFECYCLE_PHASES];
static X86_RUNTIME_BACKING_LINUX_BOOT_PROFILE_LIFECYCLE_TICKS: [BankedAtomicU64;
    LINUX_BOOT_PROFILE_LIFECYCLE_PHASES] =
    [const { BankedAtomicU64::new(0) }; LINUX_BOOT_PROFILE_LIFECYCLE_PHASES];
static X86_RUNTIME_BACKING_LINUX_RUNTIME_CONSOLE_TIMING_WRITTEN: BankedAtomicBool =
    BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_TIMED_WAITS_ACTIVE: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_DESCRIPTOR_WAITS_ACTIVE: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SLOW_DIAGNOSTIC_WRITTEN: BankedAtomicBool =
    BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_LATE_DIAGNOSTIC_WRITTEN: BankedAtomicBool =
    BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_STALLED_DIAGNOSTIC_WRITTEN: BankedAtomicBool =
    BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_EPOLL_LAST_READY_DESCRIPTOR: BankedAtomicU64 =
    BankedAtomicU64::new(u64::MAX);
static X86_RUNTIME_BACKING_LINUX_EPOLL_LAST_READY_EVENTS: BankedAtomicU64 = BankedAtomicU64::new(0);
const LINUX_RUNTIME_UNSUPPORTED_WORDS: usize = 8;
static X86_RUNTIME_BACKING_LINUX_RUNTIME_UNSUPPORTED_SYSCALLS: [BankedAtomicU64;
    LINUX_RUNTIME_UNSUPPORTED_WORDS] =
    [const { BankedAtomicU64::new(0) }; LINUX_RUNTIME_UNSUPPORTED_WORDS];
static X86_RUNTIME_BACKING_LINUX_RUNTIME_EINVAL_SYSCALLS: [BankedAtomicU64;
    LINUX_RUNTIME_UNSUPPORTED_WORDS] =
    [const { BankedAtomicU64::new(0) }; LINUX_RUNTIME_UNSUPPORTED_WORDS];
static X86_RUNTIME_BACKING_ELF_PROBE_NO_NEW_PRIVS: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_ELF_PROBE_SECCOMP_STRICT: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
/// The process has seccomp filters (the process table holds them).
static X86_RUNTIME_BACKING_ELF_PROBE_SECCOMP_FILTERED: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_ELF_PROBE_MEMBARRIER_REGISTRATIONS: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_SIGNAL_MASK: CpuBankedAtomicU64 = CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PENDING_SIGNALS: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_PENDING_SIGNAL_CODES: [CpuBankedAtomicU32;
    LINUX_SIGNAL_COUNT] = [const { CpuBankedAtomicU32::new(0) }; LINUX_SIGNAL_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_PENDING_SIGNAL_VALUES: [CpuBankedAtomicU64;
    LINUX_SIGNAL_COUNT] = [const { CpuBankedAtomicU64::new(0) }; LINUX_SIGNAL_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_EXEC_IGNORED_SIGNALS: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_SIGNAL_HANDLERS: [CpuBankedAtomicU64; LINUX_SIGNAL_COUNT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_SIGNAL_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_SIGNAL_FLAGS: [CpuBankedAtomicU64; LINUX_SIGNAL_COUNT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_SIGNAL_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_SIGNAL_RESTORERS: [CpuBankedAtomicU64; LINUX_SIGNAL_COUNT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_SIGNAL_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_SIGNAL_ACTION_MASKS: [CpuBankedAtomicU64; LINUX_SIGNAL_COUNT] =
    [const { CpuBankedAtomicU64::new(0) }; LINUX_SIGNAL_COUNT];
static X86_RUNTIME_BACKING_ELF_PROBE_ALT_STACK_POINTER: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_ALT_STACK_SIZE: CpuBankedAtomicU64 =
    CpuBankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_ELF_PROBE_ALT_STACK_FLAGS: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(LINUX_SS_DISABLE);
static X86_RUNTIME_BACKING_LINUX_SIGNAL_ACTIVE: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_SIGNAL_DELIVERY_COUNT: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_SIGNAL_RETURN_COUNT: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_SIGNAL_WAIT_BLOCK_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_SIGNAL_WAIT_WAKE_COUNT: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_SIGNAL_WAIT_TIMEOUT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT: BankedAtomicU32 =
    BankedAtomicU32::new(0);
const CONTAINER_SLOT_NONE: u8 = u8::MAX;
pub(crate) const PERSISTENT_DOMAIN_CONFIG_SIZE: usize =
    16 + control_abi::DOMAIN_LIMIT * control_abi::DOMAIN_REQUEST_SIZE;
static X86_RUNTIME_BACKING_CONTAINER_CONTROL_STATES: [AtomicU8; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU8::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_DOMAIN_IDS: [AtomicU64; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU64::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_CONFIG_FLAGS: [AtomicU16; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU16::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_CPU_COUNTS: [AtomicU16; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU16::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_MEMORY_MIB: [AtomicU64; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU64::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_NAME_SIZES: [AtomicU8; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU8::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_NAMES: [[AtomicU8; control_abi::DOMAIN_MAX_NAME_SIZE];
    control_abi::DOMAIN_LIMIT] =
    [const { [const { AtomicU8::new(0) }; control_abi::DOMAIN_MAX_NAME_SIZE] };
        control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_INIT_SIZES: [AtomicU8; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU8::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_INITS: [[AtomicU8; control_abi::DOMAIN_MAX_INIT_SIZE];
    control_abi::DOMAIN_LIMIT] =
    [const { [const { AtomicU8::new(0) }; control_abi::DOMAIN_MAX_INIT_SIZE] };
        control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_IMAGE_SIZES: [AtomicU8; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU8::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_IMAGES: [[AtomicU8; control_abi::DOMAIN_MAX_IMAGE_SIZE];
    control_abi::DOMAIN_LIMIT] =
    [const { [const { AtomicU8::new(0) }; control_abi::DOMAIN_MAX_IMAGE_SIZE] };
        control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_DOMAIN_PERSONALITY_SIZES: [AtomicU8; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU8::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_DOMAIN_PERSONALITIES: [[AtomicU8;
    control_abi::DOMAIN_MAX_PERSONALITY_SIZE];
    control_abi::DOMAIN_LIMIT] =
    [const { [const { AtomicU8::new(0) }; control_abi::DOMAIN_MAX_PERSONALITY_SIZE] };
        control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_SELECTED_SLOT: AtomicU8 = AtomicU8::new(CONTAINER_SLOT_NONE);
static X86_RUNTIME_BACKING_CONTAINER_ACTIVE_SLOT: AtomicU8 = AtomicU8::new(CONTAINER_SLOT_NONE);
static X86_RUNTIME_BACKING_CONTAINER_RESTART_REQUESTED: AtomicBool = AtomicBool::new(false);
/// The background domain resumed last, where the round-robin search for
/// the next one starts.
static X86_RUNTIME_BACKING_CONTAINER_LAST_RESUMED_SLOT: AtomicU8 = AtomicU8::new(0);
/// Detached starts waiting behind another domain's start, which holds the
/// single selected-slot lifecycle request until the controller goes idle.
static X86_RUNTIME_BACKING_CONTAINER_START_PENDING: [AtomicBool; control_abi::DOMAIN_LIMIT] =
    [const { AtomicBool::new(false) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_HOST_SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static X86_RUNTIME_BACKING_CONTAINER_MANAGEMENT_ENABLED: AtomicBool = AtomicBool::new(false);
static LINUX_ABI_TEST_RESULTS: AtomicU64 = AtomicU64::new(0);
static X86_RUNTIME_BACKING_NETWORK_PING_REQUESTED: AtomicU64 = AtomicU64::new(0);
static X86_RUNTIME_BACKING_NETWORK_PING_ACTIVE: AtomicU64 = AtomicU64::new(0);
static X86_RUNTIME_BACKING_NETWORK_PING_RESULT: AtomicU8 = AtomicU8::new(0);
static X86_RUNTIME_BACKING_NETWORK_DHCP_REQUESTED: AtomicBool = AtomicBool::new(false);
static X86_RUNTIME_BACKING_NETWORK_DHCP_RESULT: AtomicU8 = AtomicU8::new(0);
static X86_RUNTIME_BACKING_CONTAINER_PULL_REQUESTED: AtomicBool = AtomicBool::new(false);
static X86_RUNTIME_BACKING_CONTAINER_INSTALL_REQUESTED: AtomicBool = AtomicBool::new(false);
const DOMAIN_EXEC_ARGUMENT_CAPACITY: usize = 256;
static X86_RUNTIME_BACKING_CONTAINER_EXEC_REQUESTED: [AtomicBool; control_abi::DOMAIN_LIMIT] =
    [const { AtomicBool::new(false) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_EXEC_INTERACTIVE: [AtomicBool; control_abi::DOMAIN_LIMIT] =
    [const { AtomicBool::new(false) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_EXEC_ARGUMENT_COUNTS: [AtomicU8; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU8::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_EXEC_ARGUMENT_SIZES: [[AtomicU16;
    control_abi::DOMAIN_EXEC_MAX_ARGUMENTS];
    control_abi::DOMAIN_LIMIT] =
    [const { [const { AtomicU16::new(0) }; control_abi::DOMAIN_EXEC_MAX_ARGUMENTS] };
        control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_EXEC_ARGUMENTS: [[[AtomicU8; DOMAIN_EXEC_ARGUMENT_CAPACITY];
    control_abi::DOMAIN_EXEC_MAX_ARGUMENTS];
    control_abi::DOMAIN_LIMIT] = [const {
    [const { [const { AtomicU8::new(0) }; DOMAIN_EXEC_ARGUMENT_CAPACITY] };
        control_abi::DOMAIN_EXEC_MAX_ARGUMENTS]
}; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_LINUX_DOMAIN_EXEC_INJECT: AtomicBool = AtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_REQUESTED: BankedAtomicBool =
    BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED: BankedAtomicBool =
    BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_BACKGROUND_SUSPENDED: BankedAtomicBool =
    BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_BACKGROUND_TICKS: BankedAtomicU32 =
    BankedAtomicU32::new(0);
/// Background checks since a detached domain last gave other domains a turn.
static X86_RUNTIME_BACKING_LINUX_RUNTIME_BACKGROUND_QUANTA: AtomicU32 = AtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPENDED: BankedAtomicBool = BankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_ADDRESS: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_COUNT: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_RIP: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_RSP: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_RFLAGS: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_FS_BASE: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_RESULT: BankedAtomicU64 = BankedAtomicU64::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_PID: BankedAtomicU32 = BankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_RUNTIME_SUSPEND_REGISTERS: [BankedAtomicU64;
    LINUX_SYSCALL_FRAME_REGISTERS] =
    [const { BankedAtomicU64::new(0) }; LINUX_SYSCALL_FRAME_REGISTERS];
const CONTAINER_CONSOLE_CAPACITY: usize = 4096;
const CONTAINER_CONSOLE_DETACH: u8 = 0x1d;
static X86_RUNTIME_BACKING_CONTAINER_CONSOLE_ATTACHED: [AtomicBool; control_abi::DOMAIN_LIMIT] =
    [const { AtomicBool::new(false) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_STOP_REQUESTED: [AtomicBool; control_abi::DOMAIN_LIMIT] =
    [const { AtomicBool::new(false) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_BACKGROUND_SUSPENDED: [AtomicBool; control_abi::DOMAIN_LIMIT] =
    [const { AtomicBool::new(false) }; control_abi::DOMAIN_LIMIT];

static X86_RUNTIME_BACKING_CONTAINER_EXTENDED_STATE_VALID: [AtomicBool; control_abi::DOMAIN_LIMIT] =
    [const { AtomicBool::new(false) }; control_abi::DOMAIN_LIMIT];
const LINUX_PROCESS_RUNTIME_INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;
static X86_RUNTIME_BACKING_CONTAINER_CONSOLE_CURSOR: [AtomicU64; control_abi::DOMAIN_LIMIT] =
    [const { AtomicU64::new(0) }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_CONTAINER_CONSOLE_BYTES: [[AtomicU8; CONTAINER_CONSOLE_CAPACITY];
    control_abi::DOMAIN_LIMIT] =
    [const { [const { AtomicU8::new(0) }; CONTAINER_CONSOLE_CAPACITY] }; control_abi::DOMAIN_LIMIT];
static X86_RUNTIME_BACKING_ELF_PROBE_SYSTEM_INIT: AtomicBool = AtomicBool::new(false);
static SERVICE_STACK_SCRUBBED: AtomicBool = AtomicBool::new(false);
static SERVICE_FRAMES_TRANSFERRED: AtomicBool = AtomicBool::new(false);
use crate::trusted::entry::{
    PRIVILEGE_ENTRY_NMI_PROBE_HITS, PRIVILEGE_ENTRY_NMI_PROBE_MASK, PRIVILEGE_ENTRY_NMI_STAGE_COUNT,
};
const PRIVILEGE_ENTRY_NMI_STAGE_MASK: u64 = (1 << PRIVILEGE_ENTRY_NMI_STAGE_COUNT) - 1;
/// Enters a Linux process's user mode until one of its system calls
/// returns to the kernel (`trusted::entry::enter_process_user`). The
/// kernel-entry lock is released while it runs user code and held again on
/// the way back (`sync::kernel_entry_leave_to_user`).
pub(super) fn process_user_enter(entry: usize, stack: usize, general: &[u64; 15], rflags: u64) {
    crate::sync::kernel_entry_leave_to_user();
    crate::cpu_time::leave_for_user();
    set_user_time_stamp_access(linux_user_time_stamp_allowed());
    let _ = crate::trusted::entry::enter_process_user(entry, stack, general, rflags);
    // A return the entry stub refused (a non-canonical user address) comes
    // back here without passing the system call's lock re-entry.
    set_user_time_stamp_access(true);
    crate::cpu_time::back_from_user();
    crate::sync::kernel_entry_return_from_user();
}

/// Enters the current Linux runtime process. On the boot CPU its activation
/// gets a kernel stack of its own (see `activation`); a thread dispatched to
/// another CPU, and any entry when no stack can be allocated, runs below the
/// caller's frames as before.
fn enter_linux_runtime_process(entry: usize, stack: usize, general: &[u64; 15], rflags: u64) {
    LINUX_PROCESS_SLICE[linux_cpu_slot()].store(0, Ordering::SeqCst);
    let entered = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && current_linux_runtime_cpu_index() == 0
        && activation::enter_on_own_stack(
            linux_thread_activation_owner(
                current_linux_process_pid(),
                current_linux_tid().unwrap_or(0),
            ),
            entry,
            stack,
            general,
            rflags,
        )
        .is_some();
    if !entered {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
            && current_linux_runtime_cpu_index() == 0
            && LINUX_PARK_REFUSALS.fetch_add(1, Ordering::Relaxed) < 8
        {
            serial_write("linox: process entered without an activation pid/cpu: ");
            serial_write_u64(u64::from(current_linux_process_pid()));
            serial_write(" ");
            serial_write_u64(current_cpu_index_checked().unwrap_or(99) as u64);
            serial_write("\r\n");
        }
        process_user_enter(entry, stack, general, rflags);
    }
}

/// Enters a native domain's ring-3 code (`trusted::entry::enter_native_user`)
/// once the loaded address space is checked to map `entry` and `stack` as
/// its code and stack; false without entering otherwise.
#[allow(clippy::too_many_arguments)]
fn enter_user(
    entry: usize,
    stack: usize,
    host_handle: u64,
    console_handle: u64,
    ipc_handle: u64,
    identity: u64,
    service_domain: u64,
    service_identity: u64,
    root_handle: u64,
) -> bool {
    address_space::current_user_entry_context_is_valid(entry as u64, stack as u64)
        && crate::trusted::entry::enter_native_user(
            entry,
            stack,
            crate::trusted::entry::NativeEntryValues {
                host_handle,
                console_handle,
                ipc_handle,
                identity,
                service_domain,
                service_identity,
                root_handle,
            },
        )
}

pub(crate) fn verify_user_copy_fault_fixups(mapped_end: u64, unmapped: u64) -> bool {
    crate::trusted::user_copy::verify_fault_fixups(mapped_end, unmapped)
}

pub(crate) fn enable_supervisor_execution_prevention() -> bool {
    if __cpuid(0).eax < CPUID_STRUCTURED_FEATURES
        || __cpuid_count(CPUID_STRUCTURED_FEATURES, 0).ebx & CPUID_SMEP == 0
    {
        return false;
    }
    control::enable_cr4_feature(Cr4Feature::Smep)
}

pub(crate) fn enable_execute_disable() -> bool {
    if __cpuid(CPUID_EXTENDED_MAX).eax < CPUID_EXTENDED_FEATURES
        || __cpuid(CPUID_EXTENDED_FEATURES).edx & CPUID_NX == 0
    {
        return false;
    }
    msr::enable_execute_disable()
}

pub(crate) fn execute_disable_enabled() -> bool {
    __cpuid(CPUID_EXTENDED_MAX).eax >= CPUID_EXTENDED_FEATURES && msr::execute_disable_enabled()
}

pub(crate) fn supervisor_execution_prevention_enabled() -> bool {
    control::cr4_feature_enabled(Cr4Feature::Smep)
}

pub(crate) fn enable_supervisor_access_prevention() -> bool {
    if __cpuid(0).eax < CPUID_STRUCTURED_FEATURES
        || __cpuid_count(CPUID_STRUCTURED_FEATURES, 0).ebx & CPUID_SMAP == 0
    {
        return false;
    }
    control::enable_cr4_feature(Cr4Feature::Smap)
}

pub(crate) fn supervisor_access_prevention_enabled() -> bool {
    control::cr4_feature_enabled(Cr4Feature::Smap)
}

pub(crate) fn enable_user_mode_instruction_prevention() -> bool {
    if __cpuid(0).eax < CPUID_STRUCTURED_FEATURES
        || __cpuid_count(CPUID_STRUCTURED_FEATURES, 0).ecx & CPUID_UMIP == 0
    {
        return false;
    }
    control::enable_cr4_feature(Cr4Feature::Umip)
}

/// Lets this CPU's user mode read the timestamp counter, or makes rdtsc
/// and rdtscp fault there (CR4.TSD) while a process that asked for that
/// with PR_SET_TSC runs: set as the CPU leaves for such a process's user
/// mode, cleared as it comes back, and written only when it changes.
pub(super) fn set_user_time_stamp_access(allowed: bool) {
    control::set_user_time_stamp_access(allowed);
}

/// Whether the Linux process this CPU is about to run in user mode may read
/// the timestamp counter (PR_SET_TSC).
pub(super) fn linux_user_time_stamp_allowed() -> bool {
    !(X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::Relaxed)
        && X86_RUNTIME.ELF_PROBE_TSC_SIGSEGV.load(Ordering::Relaxed))
}

pub(crate) fn user_mode_instruction_prevention_enabled() -> bool {
    control::cr4_feature_enabled(Cr4Feature::Umip)
}

pub(crate) fn initialize_user_call_gate() -> bool {
    install_user_interrupt_gate(SYSCALL_VECTOR, EntryStub::native_system_call())
        && user_interrupt_surface_is_minimal()
}

/// A process's page-table frames and mapped pages. The lists are work
/// areas as long as the largest address space seen lately (they grow when a
/// walk fills them and shrink back); the first `*_count` entries are the
/// snapshot and the rest are empty.
pub(crate) struct LinuxProcessAddressSpaceSnapshot {
    hierarchy: Vec<memory::FrameLease>,
    hierarchy_count: usize,
    mappings: Vec<LinuxActiveImageMapping>,
    mapping_count: usize,
}

/// The snapshot work lists, claimed by the one snapshot taken at a time
/// (a claim that finds them busy fails the snapshot).
static X86_RUNTIME_BACKING_LINUX_PROCESS_SNAPSHOT_SCRATCH: ClaimCell<
    LinuxProcessAddressSpaceSnapshot,
> = ClaimCell::new(LinuxProcessAddressSpaceSnapshot {
    hierarchy: Vec::new(),
    hierarchy_count: 0,
    mappings: Vec::new(),
    mapping_count: 0,
});

/// Starting lengths of the snapshot lists.
const LINUX_SNAPSHOT_MIN_HIERARCHY: usize = 64;
const LINUX_SNAPSHOT_MIN_MAPPINGS: usize = 4096;

impl LinuxProcessAddressSpaceSnapshot {
    /// Empties the lists for a new walk, sized for what the last one found
    /// (`grow` doubles the list that was full and keeps the other); false
    /// without the memory.
    fn reset(&mut self, grow: (bool, bool)) -> bool {
        let growing = grow.0 || grow.1;
        let length = |current: usize, used: usize, minimum: usize, grow: bool| {
            if grow {
                current.saturating_mul(2).max(minimum)
            } else if !growing && current > used.saturating_mul(4).max(minimum) {
                used.saturating_mul(2).max(minimum)
            } else {
                current.max(minimum)
            }
        };
        let hierarchy = length(
            self.hierarchy.len(),
            self.hierarchy_count,
            LINUX_SNAPSHOT_MIN_HIERARCHY,
            grow.0,
        );
        let mappings = length(
            self.mappings.len(),
            self.mapping_count,
            LINUX_SNAPSHOT_MIN_MAPPINGS,
            grow.1,
        );
        self.hierarchy_count = 0;
        self.mapping_count = 0;
        address_space::fill_list(&mut self.hierarchy, hierarchy, memory::FrameLease::EMPTY)
            .is_some()
            && address_space::fill_list(
                &mut self.mappings,
                mappings,
                LinuxActiveImageMapping::EMPTY,
            )
            .is_some()
    }

    pub(crate) fn hierarchy(&self) -> &[memory::FrameLease] {
        &self.hierarchy[..self.hierarchy_count]
    }

    pub(crate) fn mappings(&self) -> &[LinuxActiveImageMapping] {
        &self.mappings[..self.mapping_count]
    }

    fn counts_are_in_bounds(&self, hierarchy_count: usize, mapping_count: usize) -> bool {
        hierarchy_count <= self.hierarchy.len() && mapping_count <= self.mappings.len()
    }

    fn is_valid(&self) -> bool {
        self.counts_are_in_bounds(self.hierarchy_count, self.mapping_count)
            && self.hierarchy[self.hierarchy_count..]
                .iter()
                .all(|frame| *frame == memory::FrameLease::EMPTY)
            && self.mappings[self.mapping_count..]
                .iter()
                .all(|mapping| *mapping == LinuxActiveImageMapping::EMPTY)
            && address_space::validate_linux_process_address_space(
                self.hierarchy(),
                self.mappings(),
            )
    }

    fn is_valid_runtime_walk(&self) -> bool {
        (4..=self.hierarchy.len()).contains(&self.hierarchy_count)
            && (1..=self.mappings.len()).contains(&self.mapping_count)
            && self.hierarchy[self.hierarchy_count..]
                .iter()
                .all(|frame| *frame == memory::FrameLease::EMPTY)
            && self.mappings[self.mapping_count..]
                .iter()
                .all(|mapping| *mapping == LinuxActiveImageMapping::EMPTY)
            && memory::frames_owned_by(memory::FrameOwner::KERNEL, self.hierarchy())
            && self.mappings().iter().enumerate().all(|(index, mapping)| {
                mapping.address != 0
                    && mapping.address.is_multiple_of(PAGE_SIZE)
                    && !(mapping.writable && mapping.executable)
                    && (memory::frames_owned_by(
                        memory::FrameOwner::KERNEL,
                        core::slice::from_ref(&mapping.frame),
                    ) || memory::frame_lease_is_runtime(mapping.frame))
                    && (index == 0 || self.mappings[index - 1].address < mapping.address)
            })
    }
}

#[derive(Clone, Copy)]
struct LinuxTlsContext {
    thread_pointer: usize,
    extent: usize,
    extent_size: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LinuxThreadHandle {
    slot: u8,
    generation: u32,
    tid: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LinuxThreadSignalTarget {
    Active(LinuxThreadHandle),
    Saved {
        pid: u32,
        process_slot: usize,
        thread_slot: usize,
    },
}

#[derive(Clone, Copy)]
struct LinuxCloneRequest {
    flags: u64,
    child_stack: u64,
    parent_tid: u64,
    child_tid: u64,
    tls: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct LinuxSyscallFrame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
}

impl LinuxSyscallFrame {
    const ZERO: Self = Self::from_array([0; LINUX_SYSCALL_FRAME_REGISTERS]);

    const fn from_array(registers: [u64; LINUX_SYSCALL_FRAME_REGISTERS]) -> Self {
        Self {
            r15: registers[0],
            r14: registers[1],
            r13: registers[2],
            r12: registers[3],
            rbp: registers[4],
            rbx: registers[5],
            r10: registers[6],
            r9: registers[7],
            r8: registers[8],
            rdx: registers[9],
            rsi: registers[10],
            rdi: registers[11],
        }
    }

    const fn into_array(self) -> [u64; LINUX_SYSCALL_FRAME_REGISTERS] {
        [
            self.r15, self.r14, self.r13, self.r12, self.rbp, self.rbx, self.r10, self.r9, self.r8,
            self.rdx, self.rsi, self.rdi,
        ]
    }

    fn argument(self, index: usize) -> Option<u64> {
        self.into_array().get(index.checked_add(6)?).copied()
    }

    fn process_general(self, rax: u64, rcx: u64, r11: u64) -> [u64; 15] {
        [
            rax, self.rbx, rcx, self.rdx, self.rsi, self.rdi, self.rbp, self.r8, self.r9, self.r10,
            r11, self.r12, self.r13, self.r14, self.r15,
        ]
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LinuxSignalContext {
    registers: LinuxSyscallFrame,
    rax: u64,
    rcx: u64,
    r11: u64,
    rip: u64,
    rsp: u64,
    rflags: u64,
    signal_stack: u64,
    signal_restorer: u64,
    signal_mask: u64,
    alt_stack_pointer: u64,
    alt_stack_size: u64,
    alt_stack_flags: u32,
}

/// Words of a `LinuxSignalContext` as each CPU bank keeps it.
const LINUX_SIGNAL_CONTEXT_WORDS: usize = LINUX_SYSCALL_FRAME_REGISTERS + 12;

impl LinuxSignalContext {
    /// The context as words, for the per-bank atomic copy.
    const fn into_words(self) -> [u64; LINUX_SIGNAL_CONTEXT_WORDS] {
        let registers = self.registers.into_array();
        let mut words = [0; LINUX_SIGNAL_CONTEXT_WORDS];
        let mut index = 0;
        while index < LINUX_SYSCALL_FRAME_REGISTERS {
            words[index] = registers[index];
            index += 1;
        }
        let rest = [
            self.rax,
            self.rcx,
            self.r11,
            self.rip,
            self.rsp,
            self.rflags,
            self.signal_stack,
            self.signal_restorer,
            self.signal_mask,
            self.alt_stack_pointer,
            self.alt_stack_size,
            self.alt_stack_flags as u64,
        ];
        let mut rest_index = 0;
        while rest_index < rest.len() {
            words[LINUX_SYSCALL_FRAME_REGISTERS + rest_index] = rest[rest_index];
            rest_index += 1;
        }
        words
    }

    fn from_words(words: [u64; LINUX_SIGNAL_CONTEXT_WORDS]) -> Self {
        let mut registers = [0; LINUX_SYSCALL_FRAME_REGISTERS];
        registers.copy_from_slice(&words[..LINUX_SYSCALL_FRAME_REGISTERS]);
        let rest = &words[LINUX_SYSCALL_FRAME_REGISTERS..];
        Self {
            registers: LinuxSyscallFrame::from_array(registers),
            rax: rest[0],
            rcx: rest[1],
            r11: rest[2],
            rip: rest[3],
            rsp: rest[4],
            rflags: rest[5],
            signal_stack: rest[6],
            signal_restorer: rest[7],
            signal_mask: rest[8],
            alt_stack_pointer: rest[9],
            alt_stack_size: rest[10],
            alt_stack_flags: rest[11] as u32,
        }
    }

    const ZERO: Self = Self {
        registers: LinuxSyscallFrame::ZERO,
        rax: 0,
        rcx: 0,
        r11: 0,
        rip: 0,
        rsp: 0,
        rflags: 0,
        signal_stack: 0,
        signal_restorer: 0,
        signal_mask: 0,
        alt_stack_pointer: 0,
        alt_stack_size: 0,
        alt_stack_flags: 0,
    };

    fn from_fault(
        context: UserFaultContext,
        signal_stack: u64,
        signal_restorer: u64,
        signal_mask: u64,
        alt_stack_flags: u32,
    ) -> Self {
        Self {
            registers: LinuxSyscallFrame {
                r15: context.r15,
                r14: context.r14,
                r13: context.r13,
                r12: context.r12,
                rbp: context.rbp,
                rbx: context.rbx,
                r10: context.r10,
                r9: context.r9,
                r8: context.r8,
                rdx: context.rdx,
                rsi: context.rsi,
                rdi: context.rdi,
            },
            rax: context.rax,
            rcx: context.rcx,
            r11: context.r11,
            rip: context.rip,
            rsp: context.rsp,
            rflags: context.rflags,
            signal_stack,
            signal_restorer,
            signal_mask,
            alt_stack_pointer: X86_RUNTIME
                .ELF_PROBE_ALT_STACK_POINTER
                .load(Ordering::SeqCst),
            alt_stack_size: X86_RUNTIME.ELF_PROBE_ALT_STACK_SIZE.load(Ordering::SeqCst),
            alt_stack_flags,
        }
    }

    fn user_context(self) -> LinuxUserContext {
        LinuxUserContext {
            registers: self.registers,
            rip: self.rip,
            rsp: self.rsp,
            rflags: self.rflags,
            rax: self.rax,
            fs_base: active_fs_base(),
        }
    }

    fn from_syscall(
        context: LinuxUserContext,
        return_registers: (u64, u64),
        signal_frame: (u64, u64),
        signal_mask: u64,
        alt_stack_flags: u32,
    ) -> Self {
        Self {
            registers: context.registers,
            rax: context.rax,
            rcx: return_registers.0,
            r11: return_registers.1,
            rip: context.rip,
            rsp: context.rsp,
            rflags: context.rflags,
            signal_stack: signal_frame.0,
            signal_restorer: signal_frame.1,
            signal_mask,
            alt_stack_pointer: X86_RUNTIME
                .ELF_PROBE_ALT_STACK_POINTER
                .load(Ordering::SeqCst),
            alt_stack_size: X86_RUNTIME.ELF_PROBE_ALT_STACK_SIZE.load(Ordering::SeqCst),
            alt_stack_flags,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct LinuxSignalStack {
    pub(crate) pointer: u64,
    pub(crate) flags: u32,
    pub(crate) padding: u32,
    pub(crate) size: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct LinuxSignalMachineContext {
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) rdi: u64,
    pub(crate) rsi: u64,
    pub(crate) rbp: u64,
    pub(crate) rbx: u64,
    pub(crate) rdx: u64,
    pub(crate) rax: u64,
    pub(crate) rcx: u64,
    pub(crate) rsp: u64,
    pub(crate) rip: u64,
    pub(crate) rflags: u64,
    pub(crate) cs: u16,
    pub(crate) gs: u16,
    pub(crate) fs: u16,
    pub(crate) ss: u16,
    pub(crate) error: u64,
    pub(crate) trap: u64,
    pub(crate) old_mask: u64,
    pub(crate) cr2: u64,
    pub(crate) fpstate: u64,
    pub(crate) reserved: [u64; 8],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct LinuxSignalUserContext {
    pub(crate) flags: u64,
    pub(crate) link: u64,
    pub(crate) stack: LinuxSignalStack,
    pub(crate) machine: LinuxSignalMachineContext,
    pub(crate) signal_mask: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct LinuxSignalInformation {
    pub(crate) signal: i32,
    pub(crate) error: i32,
    pub(crate) code: i32,
    pub(crate) padding: i32,
    pub(crate) fields: [u8; 112],
}

impl LinuxSignalInformation {
    const ZERO: Self = Self {
        signal: 0,
        error: 0,
        code: 0,
        padding: 0,
        fields: [0; 112],
    };

    const fn generated(signal: u64, code: i32) -> Self {
        Self::queued(signal, code, 0)
    }

    const fn queued(signal: u64, code: i32, value: u64) -> Self {
        Self::queued_from(signal, code, value, 1, 0)
    }

    const fn queued_from(
        signal: u64,
        code: i32,
        value: u64,
        sender_pid: u32,
        sender_uid: u32,
    ) -> Self {
        let mut fields = [0; 112];
        let sender = sender_pid.to_ne_bytes();
        fields[0] = sender[0];
        fields[1] = sender[1];
        fields[2] = sender[2];
        fields[3] = sender[3];
        let sender = sender_uid.to_ne_bytes();
        fields[4] = sender[0];
        fields[5] = sender[1];
        fields[6] = sender[2];
        fields[7] = sender[3];
        let value = value.to_ne_bytes();
        fields[8] = value[0];
        fields[9] = value[1];
        fields[10] = value[2];
        fields[11] = value[3];
        fields[12] = value[4];
        fields[13] = value[5];
        fields[14] = value[6];
        fields[15] = value[7];
        Self {
            signal: signal as i32,
            error: 0,
            code,
            padding: 0,
            fields,
        }
    }

    const fn fault(signal: u64, code: i32, address: u64) -> Self {
        let mut fields = [0; 112];
        let address = address.to_ne_bytes();
        fields[0] = address[0];
        fields[1] = address[1];
        fields[2] = address[2];
        fields[3] = address[3];
        fields[4] = address[4];
        fields[5] = address[5];
        fields[6] = address[6];
        fields[7] = address[7];
        Self {
            signal: signal as i32,
            error: 0,
            code,
            padding: 0,
            fields,
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct LinuxRtSignalFrame {
    pub(crate) restorer: u64,
    pub(crate) context: LinuxSignalUserContext,
    pub(crate) information: LinuxSignalInformation,
}

struct LinuxRestoredSignalContext {
    user: LinuxUserContext,
    signal_mask: u64,
    rcx: u64,
    r11: u64,
}

// Their `Pod` impls (they are copied to and from user memory as bytes)
// are in trusted/pod.rs.
const _: [(); 24] = [(); size_of::<LinuxSignalStack>()];
const _: [(); 256] = [(); size_of::<LinuxSignalMachineContext>()];
const _: [(); 304] = [(); size_of::<LinuxSignalUserContext>()];
const _: [(); 128] = [(); size_of::<LinuxSignalInformation>()];
const _: [(); LINUX_SIGNAL_FRAME_SIZE] = [(); size_of::<LinuxRtSignalFrame>()];
const _: [(); LINUX_SIGNAL_FRAME_CONTEXT_OFFSET as usize] =
    [(); core::mem::offset_of!(LinuxRtSignalFrame, context)];
const _: [(); LINUX_SIGNAL_FRAME_INFO_OFFSET as usize] =
    [(); core::mem::offset_of!(LinuxRtSignalFrame, information)];

#[derive(Clone, Copy, Eq, PartialEq)]
struct LinuxUserContext {
    registers: LinuxSyscallFrame,
    rip: u64,
    rsp: u64,
    rflags: u64,
    rax: u64,
    fs_base: u64,
}

#[derive(Clone, Copy)]
struct LinuxCloneResult {
    parent_rax: u64,
    child: LinuxUserContext,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LinuxClonePublishError {
    InvalidRequest,
    TidFault,
}

impl LinuxUserContext {
    fn is_valid(self) -> bool {
        const REQUIRED_RFLAGS: u64 = (1 << 1) | (1 << 9);
        const FORBIDDEN_RFLAGS: u64 = (3 << 12) | (1 << 14) | (1 << 17);
        self.rip != 0
            && self.rip < 1 << 47
            && self.rsp != 0
            && self.rsp < 1 << 47
            && self.rflags & REQUIRED_RFLAGS == REQUIRED_RFLAGS
            && self.rflags & FORBIDDEN_RFLAGS == 0
            && self.fs_base < 1 << 47
    }
}

impl LinuxTlsContext {
    fn is_valid(self) -> bool {
        if self.thread_pointer >= 1 << 47 {
            return false;
        }
        if self.extent_size == 0 {
            return self.extent == 0;
        }
        self.extent != 0
            && self
                .extent
                .checked_add(self.extent_size)
                .is_some_and(|end| end <= 1 << 47)
    }
}

pub(crate) fn verify_breakpoint() -> bool {
    BREAKPOINT_HANDLED.store(false, Ordering::SeqCst);
    control::raise_breakpoint();
    BREAKPOINT_HANDLED.load(Ordering::SeqCst)
}

pub(crate) extern "sysv64" fn breakpoint_handler() {
    BREAKPOINT_HANDLED.store(true, Ordering::SeqCst);
    serial_write("linox: breakpoint exception handled\r\n");
}

pub(crate) extern "sysv64" fn syscall_handler(
    number: u64,
    capability: u64,
    frame: &mut UserTrapFrame,
) -> u64 {
    let _kernel_entry = crate::sync::kernel_entry_lock();
    let cpu = current_cpu_index();
    let Some(probe_state) = X86_RUNTIME.PROCESS_CHILD_PROBE_STATE.get(cpu) else {
        return u64::MAX;
    };
    match probe_state.load(Ordering::SeqCst) {
        PROCESS_CHILD_PROBE_EXPECT_CONTEXT => {
            let valid = Some(&*frame).is_some_and(|frame| {
                frame
                    .process_general_registers(number)
                    .into_iter()
                    .zip(&X86_RUNTIME.PROCESS_CHILD_EXPECTED_REGISTERS[cpu])
                    .all(|(observed, expected)| observed == expected.load(Ordering::SeqCst))
                    && active_fs_base()
                        == X86_RUNTIME
                            .PROCESS_CHILD_EXPECTED_FS_BASE
                            .get(cpu)
                            .expect("current processor index is bounded")
                            .load(Ordering::SeqCst)
            });
            X86_RUNTIME
                .PROCESS_CHILD_CONTEXT_VALID
                .get(cpu)
                .expect("current processor index is bounded")
                .store(valid, Ordering::SeqCst);
            probe_state.store(
                if valid {
                    PROCESS_CHILD_PROBE_EXPECT_EXIT
                } else {
                    PROCESS_CHILD_PROBE_IDLE
                },
                Ordering::SeqCst,
            );
            return if valid { 0 } else { u64::MAX };
        }
        PROCESS_CHILD_PROBE_EXPECT_EXIT => {
            let exit_status = (number == LINUX_EXIT_SYSCALL
                && active_fs_base()
                    == X86_RUNTIME
                        .PROCESS_CHILD_EXPECTED_FS_BASE
                        .get(cpu)
                        .expect("current processor index is bounded")
                        .load(Ordering::SeqCst))
            .then_some(&*frame)
            .and_then(|frame| u8::try_from(frame.process_general_registers(number)[5]).ok());
            if let Some(status) = exit_status {
                X86_RUNTIME
                    .PROCESS_CHILD_EXIT_STATUS
                    .get(cpu)
                    .expect("current processor index is bounded")
                    .store(status, Ordering::SeqCst);
                probe_state.store(PROCESS_CHILD_PROBE_COMPLETE, Ordering::SeqCst);
            } else {
                probe_state.store(PROCESS_CHILD_PROBE_IDLE, Ordering::SeqCst);
            }
            return u64::MAX;
        }
        _ => {}
    }
    let Some(caller_domain) = scheduler::current_domain() else {
        return u64::MAX;
    };
    let _ = timer::cancel_packet_wait_timer_for_domain(caller_domain);
    // Termination must remain available after a domain exhausts its budget.
    if number == 2 {
        SYSCALL_STATE.fetch_or(4, Ordering::SeqCst);
        return exit_result(caller_domain, Some(frame));
    }
    if !domain::begin_operation(caller_domain) {
        return u64::MAX;
    }
    let result = if !domain::charge_call(caller_domain) {
        CALL_BUDGET_EXHAUSTED
    } else {
        dispatch_charged_call(number, capability, caller_domain, Some(frame))
    };
    if !domain::end_operation(caller_domain) {
        return u64::MAX;
    }
    result
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LinuxMmapRuntimeState {
    base: u64,
    next: u64,
    pages: [u8; LINUX_RUNTIME_MMAP_SLOT_COUNT],
    protection: [u8; LINUX_RUNTIME_MMAP_SLOT_COUNT],
    file: [u8; LINUX_RUNTIME_MMAP_SLOT_COUNT],
    sealed: [bool; LINUX_RUNTIME_MMAP_SLOT_COUNT],
    frames: [u64; LINUX_RUNTIME_MMAP_SLOT_COUNT],
    generations: [u32; LINUX_RUNTIME_MMAP_SLOT_COUNT],
}

#[derive(Clone, Copy)]
struct LinuxDescriptorRuntimeState {
    console: u8,
    stderr_open: bool,
    close_on_exec: [u64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
    created: [u64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
    read_leases: [u64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
    write_leases: [u64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
    devices: [u16; LINUX_DEVICE_DESCRIPTOR_COUNT],
    rootfs: [u16; LINUX_DEVICE_DESCRIPTOR_COUNT],
    sockets: [crate::linux_socket::SlotId; LINUX_DEVICE_DESCRIPTOR_COUNT],
    socket_flags: [u32; LINUX_DEVICE_DESCRIPTOR_COUNT],
    stdio_sockets: [crate::linux_socket::SlotId; 3],
    stdio_socket_flags: [u32; 3],
    tmp_generations: [u32; LINUX_DEVICE_DESCRIPTOR_COUNT],
    offsets: [u64; LINUX_DEVICE_DESCRIPTOR_COUNT],
    stdio_devices: [u16; 3],
    stdio_rootfs: [u16; 3],
    stdio_tmp_generations: [u32; 3],
    stdio_offsets: [u64; 3],
    open_file_ids: [u64; LINUX_DEVICE_DESCRIPTOR_COUNT],
    stdio_open_file_ids: [u64; 3],
    /// The highest of the open-file ids above (0 for none): an offset
    /// change of a file opened since the table was saved need not look
    /// through it (`sync_saved_linux_open_file_offset`).
    max_open_file_id: u64,
    epoll_descriptor: u16,
    epoll_events: [u32; LINUX_DESCRIPTOR_TABLE_LIMIT as usize],
    epoll_data: [u64; LINUX_DESCRIPTOR_TABLE_LIMIT as usize],
    runtime_epoll_active: [u8; LINUX_DEVICE_DESCRIPTOR_COUNT],
    runtime_epoll_aliases: [u32; LINUX_DEVICE_DESCRIPTOR_COUNT],
    runtime_epoll_watch_epoll: [u32; LINUX_DESCRIPTOR_TABLE_LIMIT as usize],
    runtime_epoll_watch_seen: [u64; LINUX_DESCRIPTOR_TABLE_LIMIT as usize],
    runtime_epoll_watch_target: [u32; LINUX_DESCRIPTOR_TABLE_LIMIT as usize],
    runtime_eventfd_active: [u64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
    runtime_timerfd_active: [u64; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
    /// The `linux_fd_table` id of the descriptors above the fixed table
    /// (0: none): processes sharing the table (CLONE_FILES) name the same.
    overflow: u32,
}

impl LinuxMmapRuntimeState {
    const EMPTY: Self = Self {
        base: 0,
        next: 0,
        pages: [0; LINUX_RUNTIME_MMAP_SLOT_COUNT],
        protection: [0; LINUX_RUNTIME_MMAP_SLOT_COUNT],
        file: [0; LINUX_RUNTIME_MMAP_SLOT_COUNT],
        sealed: [false; LINUX_RUNTIME_MMAP_SLOT_COUNT],
        frames: [0; LINUX_RUNTIME_MMAP_SLOT_COUNT],
        generations: [0; LINUX_RUNTIME_MMAP_SLOT_COUNT],
    };
}

impl LinuxDescriptorRuntimeState {
    const EMPTY: Self = Self {
        console: 0,
        stderr_open: false,
        close_on_exec: [0; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
        created: [0; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
        read_leases: [0; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
        write_leases: [0; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
        devices: [0; LINUX_DEVICE_DESCRIPTOR_COUNT],
        rootfs: [0; LINUX_DEVICE_DESCRIPTOR_COUNT],
        sockets: [0; LINUX_DEVICE_DESCRIPTOR_COUNT],
        socket_flags: [0; LINUX_DEVICE_DESCRIPTOR_COUNT],
        stdio_sockets: [0; 3],
        stdio_socket_flags: [0; 3],
        tmp_generations: [0; LINUX_DEVICE_DESCRIPTOR_COUNT],
        offsets: [0; LINUX_DEVICE_DESCRIPTOR_COUNT],
        stdio_devices: [0; 3],
        stdio_rootfs: [0; 3],
        stdio_tmp_generations: [0; 3],
        stdio_offsets: [0; 3],
        open_file_ids: [0; LINUX_DEVICE_DESCRIPTOR_COUNT],
        stdio_open_file_ids: [0; 3],
        max_open_file_id: 0,
        epoll_descriptor: 0,
        epoll_events: [0; LINUX_DESCRIPTOR_TABLE_LIMIT as usize],
        epoll_data: [0; LINUX_DESCRIPTOR_TABLE_LIMIT as usize],
        runtime_epoll_active: [0; LINUX_DEVICE_DESCRIPTOR_COUNT],
        runtime_epoll_aliases: [0; LINUX_DEVICE_DESCRIPTOR_COUNT],
        runtime_epoll_watch_epoll: [0; LINUX_DESCRIPTOR_TABLE_LIMIT as usize],
        runtime_epoll_watch_seen: [0; LINUX_DESCRIPTOR_TABLE_LIMIT as usize],
        runtime_epoll_watch_target: [0; LINUX_DESCRIPTOR_TABLE_LIMIT as usize],
        runtime_eventfd_active: [0; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
        runtime_timerfd_active: [0; LINUX_DESCRIPTOR_FLAG_WORD_COUNT],
        overflow: 0,
    };
}

#[derive(Clone, Copy)]
struct LinuxThreadRuntimeState {
    state: u8,
    generation: u32,
    tid: u32,
    pointer: u64,
    tls_extent: u64,
    tls_size: u64,
    stack_base: u64,
    stack_size: u64,
    registers: [u64; LINUX_SYSCALL_FRAME_REGISTERS],
    rip: u64,
    rsp: u64,
    rflags: u64,
    rax: u64,
    rcx: u64,
    r11: u64,
    clear_child_tid: u64,
    robust_list: u64,
    rseq_pointer: u64,
    rseq_length: u32,
    rseq_signature: u32,
    signal_mask: u64,
    wait_kind: u8,
    wait_key: u64,
    wait_output: u64,
    wait_deadline: u64,
    wait_prior_signal_mask: u64,
    poll_descriptors: [u32; LINUX_POLLFD_LIMIT],
    poll_events: [u16; LINUX_POLLFD_LIMIT],
    select_read_address: u64,
    select_write_address: u64,
    select_exception_address: u64,
    select_timeout_address: u64,
    select_read_set: [u64; LINUX_SELECT_WORD_LIMIT],
    select_write_set: [u64; LINUX_SELECT_WORD_LIMIT],
    select_exception_set: [u64; LINUX_SELECT_WORD_LIMIT],
    iov_addresses: [u64; LINUX_IOV_LIMIT],
    iov_lengths: [u64; LINUX_IOV_LIMIT],
    owner_only: u8,
    nice: u8,
    cpu_cycles: u64,
    last_cpu: u64,
}

impl LinuxThreadRuntimeState {
    const EMPTY: Self = Self {
        owner_only: 0,
        nice: LINUX_NICE_DEFAULT,
        cpu_cycles: 0,
        last_cpu: 0,
        state: LINUX_THREAD_FREE,
        generation: 0,
        tid: 0,
        pointer: 0,
        tls_extent: 0,
        tls_size: 0,
        stack_base: 0,
        stack_size: 0,
        registers: [0; LINUX_SYSCALL_FRAME_REGISTERS],
        rip: 0,
        rsp: 0,
        rflags: 0,
        rax: 0,
        rcx: 0,
        r11: 0,
        clear_child_tid: 0,
        robust_list: 0,
        rseq_pointer: 0,
        rseq_length: 0,
        rseq_signature: 0,
        signal_mask: 0,
        wait_kind: LINUX_THREAD_WAIT_NONE,
        wait_key: 0,
        wait_output: 0,
        wait_deadline: 0,
        wait_prior_signal_mask: 0,
        poll_descriptors: [0; LINUX_POLLFD_LIMIT],
        poll_events: [0; LINUX_POLLFD_LIMIT],
        select_read_address: 0,
        select_write_address: 0,
        select_exception_address: 0,
        select_timeout_address: 0,
        select_read_set: [0; LINUX_SELECT_WORD_LIMIT],
        select_write_set: [0; LINUX_SELECT_WORD_LIMIT],
        select_exception_set: [0; LINUX_SELECT_WORD_LIMIT],
        iov_addresses: [0; LINUX_IOV_LIMIT],
        iov_lengths: [0; LINUX_IOV_LIMIT],
    };
}

#[derive(Clone, Copy)]
struct LinuxProcessRuntimeState {
    valid: bool,
    active: bool,
    completed: bool,
    exit_status: u64,
    termination_signal: u32,
    parent_death_signal: u32,
    mount_namespace: Option<linux_mount::MountNamespaceHandle>,
    mmap: LinuxMmapRuntimeState,
    descriptors: LinuxDescriptorRuntimeState,
    image_extents: [u64; 8],
    brk: u64,
    /// The main stack's top (exec moves it), and how far down it has grown.
    stack: u64,
    stack_low: u64,
    cwd: u16,
    rootfs_cwd: u16,
    overlay_cwd: u32,
    umask: u64,
    rlimits: [u64; LINUX_RLIMIT_WORDS],
    process_name: [u64; 2],
    dumpable: bool,
    tsc_sigsegv: bool,
    securebits: u32,
    personality: u32,
    nice: u8,
    ioprio: u16,
    no_new_privileges: bool,
    seccomp_strict: bool,
    seccomp_filtered: bool,
    membarrier_registrations: u32,
    real_timer_interval: u64,
    real_timer_deadline: u64,
    /// The earliest POSIX timer deadline (the tick's cache of the table).
    posix_timer_deadline: u64,
    pending_signals: u64,
    pending_signal_codes: [u32; LINUX_SIGNAL_COUNT],
    pending_signal_values: [u64; LINUX_SIGNAL_COUNT],
    signal_active: bool,
    signal_context: LinuxSignalContext,
    exec_ignored_signals: u64,
    signal_handlers: [u64; LINUX_SIGNAL_COUNT],
    signal_flags: [u64; LINUX_SIGNAL_COUNT],
    signal_restorers: [u64; LINUX_SIGNAL_COUNT],
    signal_action_masks: [u64; LINUX_SIGNAL_COUNT],
    alternate_signal_stack: [u64; 2],
    alternate_signal_stack_flags: u32,
    current_thread_slot: u8,
    last_preempted_thread_slot: u8,
    next_tid: u32,
}

impl LinuxProcessRuntimeState {
    const EMPTY: Self = Self {
        valid: false,
        active: false,
        completed: false,
        exit_status: 0,
        termination_signal: 0,
        parent_death_signal: 0,
        mount_namespace: None,
        mmap: LinuxMmapRuntimeState::EMPTY,
        descriptors: LinuxDescriptorRuntimeState::EMPTY,
        image_extents: [0; 8],
        brk: 0,
        stack: 0,
        stack_low: 0,
        cwd: LINUX_ROOT_DIRECTORY,
        rootfs_cwd: crate::published_rootfs::ROOT_HANDLE,
        overlay_cwd: 0,
        umask: 0o022,
        rlimits: [0; LINUX_RLIMIT_WORDS],
        process_name: [0; 2],
        dumpable: true,
        tsc_sigsegv: false,
        securebits: 0,
        personality: 0,
        nice: 20,
        ioprio: 0,
        no_new_privileges: false,
        seccomp_strict: false,
        seccomp_filtered: false,
        membarrier_registrations: 0,
        real_timer_interval: 0,
        real_timer_deadline: 0,
        posix_timer_deadline: 0,
        pending_signals: 0,
        pending_signal_codes: [0; LINUX_SIGNAL_COUNT],
        pending_signal_values: [0; LINUX_SIGNAL_COUNT],
        signal_active: false,
        signal_context: LinuxSignalContext::ZERO,
        exec_ignored_signals: 0,
        signal_handlers: [0; LINUX_SIGNAL_COUNT],
        signal_flags: [0; LINUX_SIGNAL_COUNT],
        signal_restorers: [0; LINUX_SIGNAL_COUNT],
        signal_action_masks: [0; LINUX_SIGNAL_COUNT],
        alternate_signal_stack: [0; 2],
        alternate_signal_stack_flags: LINUX_SS_DISABLE,
        current_thread_slot: LINUX_THREAD_SLOT_NONE,
        last_preempted_thread_slot: LINUX_THREAD_SLOT_NONE,
        next_tid: 0,
    };
}

/// Everything the runtime keeps for one process slot while the process is
/// not running: its process-wide state, its thread table, and each thread's
/// extended (x87/SSE/AVX) register state. Over 300 KiB in all, so each part
/// is a heap allocation of its own, made whole on the heap (never as a
/// record-sized temporary on the kernel stack) the first time a process
/// occupies the slot. Reached only under its domain instance's record lock
/// (`with_linux_process_record` in cpu/linux_process_state.rs).
struct LinuxProcessRecord {
    /// One element: the process state is built in place on the heap, which
    /// `Box::new` does not promise.
    runtime: Box<[LinuxProcessRuntimeState; 1]>,
    threads: Box<[LinuxThreadRuntimeState; LINUX_THREAD_LIMIT]>,
    extended_states: Box<[ExtendedState; LINUX_THREAD_LIMIT]>,
    extended_state_valid: [bool; LINUX_THREAD_LIMIT],
}

impl LinuxProcessRecord {
    /// An empty record, or None without memory.
    #[inline(never)]
    fn allocate() -> Option<Self> {
        Some(Self {
            runtime: crate::heap::try_boxed_array(LinuxProcessRuntimeState::EMPTY)?,
            threads: crate::heap::try_boxed_array(LinuxThreadRuntimeState::EMPTY)?,
            extended_states: crate::heap::try_boxed_array(ExtendedState::ZERO)?,
            extended_state_valid: [false; LINUX_THREAD_LIMIT],
        })
    }

    fn runtime(&mut self) -> &mut LinuxProcessRuntimeState {
        &mut self.runtime[0]
    }
}

/// Process slots whose records stay allocated once their process ended,
/// for the next process to reuse: a domain's usual processes. A record of
/// a slot above them is freed with its process, so a burst of thousands
/// of processes does not keep its records.
const LINUX_PROCESS_RECORDS_KEPT: usize = 256;

/// One domain instance's process records, by runtime slot, as long as the
/// highest slot used. Held under an interrupt-safe leaf lock
/// (`LockRank::PROCESS_RECORDS`): nothing is allocated or freed while it
/// is held (records and room for them are made before it is taken, and a
/// released record is dropped after), and nothing else is locked.
struct LinuxProcessRecordTable {
    records: Vec<Option<LinuxProcessRecord>>,
}

impl LinuxProcessRecordTable {
    const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    fn record(&mut self, slot: usize) -> Option<&mut LinuxProcessRecord> {
        self.records.get_mut(slot)?.as_mut()
    }

    /// The records of two different slots.
    fn pair(
        &mut self,
        first: usize,
        second: usize,
    ) -> Option<(&mut LinuxProcessRecord, &mut LinuxProcessRecord)> {
        if first == second {
            return None;
        }
        let (low, high) = (first.min(second), first.max(second));
        let length = self.records.len();
        let (head, tail) = self.records.split_at_mut(high.min(length));
        let low_record = head.get_mut(low)?.as_mut()?;
        let high_record = tail.first_mut()?.as_mut()?;
        Some(if first < second {
            (low_record, high_record)
        } else {
            (high_record, low_record)
        })
    }
}

/// `process_records` holds one record table per domain instance, each
/// behind its own lock.
struct X86MutableRuntimeOwner {
    process_records: [IrqSpinLock<LinuxProcessRecordTable>; LINUX_PROCESS_RUNTIME_INSTANCE_LIMIT],
    /// The running process's signal context, per CPU (`linux_cpu_bank`):
    /// CPUs run different processes, each with its handler's saved context.
    /// Words copied in and out atomically; a bank is used by the CPU that
    /// holds it, under the kernel-entry lock.
    signal_context: [[AtomicU64; LINUX_SIGNAL_CONTEXT_WORDS]; LINUX_CPU_BANK_LIMIT],
    /// Each domain's saved extended state while another runs, claimed by
    /// the one saving or restoring it.
    container_extended_states: [ClaimCell<ExtendedState>; control_abi::DOMAIN_LIMIT],
}

static X86_MUTABLE_RUNTIME: X86MutableRuntimeOwner = X86MutableRuntimeOwner {
    container_extended_states: [const { ClaimCell::new(ExtendedState::ZERO) };
        control_abi::DOMAIN_LIMIT],
    process_records: [const {
        IrqSpinLock::new(LockRank::PROCESS_RECORDS, LinuxProcessRecordTable::new())
    }; LINUX_PROCESS_RUNTIME_INSTANCE_LIMIT],
    signal_context: [const { [const { AtomicU64::new(0) }; LINUX_SIGNAL_CONTEXT_WORDS] };
        LINUX_CPU_BANK_LIMIT],
};

pub(crate) extern "sysv64" fn user_fault_handler(frame: &mut UserFaultFrame) -> u64 {
    set_user_time_stamp_access(true);
    crate::cpu_time::back_from_user();
    crate::sync::kernel_entry_return_from_user();
    let result = crate::linux_profile::span(crate::linux_profile::Span::UserFault, || {
        handle_user_fault(frame)
    });
    // Back to user mode unless the fault returns to the kernel.
    if result != u64::MAX {
        crate::sync::kernel_entry_leave_to_user();
        crate::cpu_time::leave_for_user();
        set_user_time_stamp_access(linux_user_time_stamp_allowed());
    }
    result
}

fn resume_action(action: RuntimeAction) -> u64 {
    match action {
        RuntimeAction::Resume {
            result,
            address_space_root,
            fs_base,
        } if activate_user_context(address_space_root, fs_base) => result,
        RuntimeAction::Resume { .. } => u64::MAX,
        RuntimeAction::Complete | RuntimeAction::Invalid => u64::MAX,
    }
}

pub(crate) fn active_fs_base() -> u64 {
    msr::fs_base()
}

pub(crate) fn verify_user_fs_base_installation() -> bool {
    let saved = active_fs_base();
    let first_installed = install_user_fs_base(0x1110);
    let second_installed = install_user_fs_base(0x2220);
    msr::set_fs_base(saved) && first_installed && second_installed
}

/// The kernel page-fault path's copy-on-write handler, as the exception
/// stub in `trusted::entry` calls it.
pub(crate) extern "sysv64" fn kernel_cow_fault_handler(error: u64, address: u64) -> u64 {
    kernel_linux_cow_fault_handler(error, address)
}

fn install_current_scheduler_fs_base() -> bool {
    scheduler::current_fs_base().is_some_and(install_user_fs_base)
}

fn install_user_fs_base(fs_base: u64) -> bool {
    msr::set_fs_base(fs_base)
}

pub(crate) fn activate_user_context(root: u64, fs_base: u64) -> bool {
    fs_base < 1 << 47 && activate_user_root(root) && install_user_fs_base(fs_base)
}

pub(crate) fn activate_user_root(root: u64) -> bool {
    const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
    if root == 0
        || root & !ADDRESS_MASK != 0
        || scheduler::current_address_space_root() != Some(root)
    {
        return false;
    }
    let Some(owner) = scheduler::current_domain().and_then(memory::FrameOwner::domain) else {
        return false;
    };
    let Some((instruction, stack)) = scheduler::current_instruction_and_stack() else {
        return false;
    };
    let Some(frames) = paging::validated_user_root_frames(root) else {
        return false;
    };
    if !frames.context_matches(instruction, stack)
        || !frames.frames_owned_by(owner)
        || frames
            .dma()
            .is_some_and(|dma| !memory::frame_addresses_owned_by(owner, &[dma]))
    {
        return false;
    }
    crate::trusted::root::activate(crate::trusted::root::Root::from(&frames));
    crate::trusted::root::current() & ADDRESS_MASK == root
}

/// Set while a fatal kernel exception is being reported, so a fault in the
/// report itself prints one line instead of recursing into a triple fault.
static FATAL_EXCEPTION_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Writes `label` and `value` in hex straight to the UART and framebuffer,
/// bypassing the domain console path, which may itself be what faulted.
fn fatal_write_hex(label: &str, value: u64) {
    let mut text = [0_u8; 18];
    text[0] = b'0';
    text[1] = b'x';
    for (index, digit) in text[2..].iter_mut().enumerate() {
        let nibble = (value >> ((15 - index) * 4)) & 0xf;
        *digit = b"0123456789abcdef"[nibble as usize];
    }
    crate::serial_write_raw(label.as_bytes());
    crate::serial_write_raw(&text);
}

/// Reports a fatal kernel exception: the vector and fault details, every
/// saved register, control registers, kernel return addresses found on the
/// interrupted stack (with the image base, for symbolizing them), and then
/// the Linux state, which is read last since it is the likeliest to fault.
pub(crate) extern "sysv64" fn fatal_exception_handler(
    vector: u64,
    error: u64,
    fault_address: u64,
    instruction: u64,
    frame: &FatalFrame,
) -> ! {
    if FATAL_EXCEPTION_ACTIVE.swap(true, Ordering::SeqCst) {
        fatal_write_hex("\r\nlinox: nested fatal exception vector ", vector);
        fatal_write_hex(" at ", instruction);
        crate::serial_write_raw(b"\r\nLINOX_KERNEL_PANIC\r\n");
        loop {
            core::hint::spin_loop();
        }
    }
    const REGISTERS: [&str; 15] = [
        "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "rbp", "rdi", "rsi", "rdx", "rcx",
        "rbx", "rax",
    ];
    fatal_write_hex("\r\nlinox: fatal exception vector ", vector);
    fatal_write_hex(" error ", error);
    fatal_write_hex(" rip ", instruction);
    if vector == 14 {
        fatal_write_hex(" cr2 ", fault_address);
    }
    let saved = |index: usize| frame.0[index];
    crate::serial_write_raw(b"\r\nlinox: registers");
    for (index, name) in REGISTERS.iter().enumerate() {
        if index % 5 == 0 {
            crate::serial_write_raw(b"\r\n ");
        }
        crate::serial_write_raw(b" ");
        fatal_write_hex(name, saved(index));
    }
    fatal_write_hex("\r\n  cs ", saved(18));
    fatal_write_hex(" rflags ", saved(19));
    fatal_write_hex(" rsp ", saved(20));
    fatal_write_hex(" ss ", saved(21));
    let [cr0, _, cr3, cr4] = control::registers();
    fatal_write_hex("\r\n  cr0 ", cr0);
    fatal_write_hex(" cr2 ", fault_address);
    fatal_write_hex(" cr3 ", cr3);
    fatal_write_hex(" cr4 ", cr4);
    let (image_base, image_size) = crate::kernel_image_range();
    fatal_write_hex("\r\nlinox: kernel image base ", image_base);
    fatal_write_hex(" size ", image_size);
    // Kernel-mode faults only: scan the interrupted stack for values that
    // point into the kernel image, which include the return addresses.
    let interrupted_stack = saved(20);
    if saved(18) & 3 == 0 && image_size != 0 {
        crate::serial_write_raw(b"\r\nlinox: kernel addresses on stack:");
        let mut found = 0;
        // An overflow faults with rsp on the guard page; scanning then starts
        // on the first mapped page above it.
        let mut start = interrupted_stack;
        for _ in 0..2 {
            if crate::arch::x86_64::paging::kernel_address_is_mapped(start) {
                break;
            }
            start = (start | 0xfff) + 1;
        }
        for slot in 0..512_u64 {
            let address = start.wrapping_add(slot * 8);
            if !crate::arch::x86_64::paging::kernel_address_is_mapped(address) {
                break;
            }
            // The report halts: the stack's owner never runs again.
            let Some(value) = crate::trusted::crash::stack_word(address) else {
                break;
            };
            if value > image_base && value < image_base + image_size {
                crate::serial_write_raw(b" ");
                fatal_write_hex("", value);
                found += 1;
                if found == 24 {
                    break;
                }
            }
        }
    }
    crate::serial_write_raw(b"\r\nlinox: Linux snapshot/fork/pid: ");
    serial_write_u64(u64::from(
        X86_RUNTIME
            .LINUX_PROCESS_SNAPSHOT_STAGE
            .load(Ordering::SeqCst),
    ));
    serial_write(" ");
    serial_write_u64(u64::from(linux_process::live_fork_execution_stage()));
    serial_write(" ");
    serial_write_u64(u64::from(current_linux_process_pid()));
    serial_write(" tid ");
    serial_write_u64(u64::from(current_linux_tid().unwrap_or(0)));
    crate::serial_write_raw(b"\r\n");
    write_linux_runtime_syscall_trace();
    crate::serial_write_raw(b"LINOX_KERNEL_PANIC\r\n");
    loop {
        core::hint::spin_loop();
    }
}
