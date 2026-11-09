use alloc::vec::Vec;
use core::arch::{
    asm, global_asm,
    x86_64::{__cpuid, __cpuid_count},
};
use core::cell::UnsafeCell;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use smoltcp::wire::IpAddress;

use super::{paging, timer};

mod activation;
mod architecture;
mod boot_verify;
mod boot_verify_elf;
mod execution;
mod fanotify;
mod linux_abi;
mod linux_cgroupfs;
mod linux_descriptors;
mod linux_diagnostics;
mod linux_directories;
mod linux_exec;
mod linux_fcntl;
mod linux_file_open;
mod linux_file_ops;
mod linux_fsmount;
mod linux_futex;
mod linux_hugetlb;
mod linux_inotify;
mod linux_ktls;
mod linux_memory_protection;
mod linux_mmap;
mod linux_mounts;
mod linux_numa;
mod linux_path_walk;
mod linux_perf;
mod linux_poll;
mod linux_process_lifecycle;
mod linux_process_state;
mod linux_process_vm;
mod linux_procfs;
mod linux_pty;
mod linux_quota;
mod linux_read_write;
mod linux_rtnetlink;
mod linux_runtime_loop;
mod linux_scheduler;
mod linux_security;
mod linux_signal;
mod linux_swapon;
mod linux_syscall;
mod linux_thread;
mod linux_time;
mod linux_tun;
mod linux_user_memory;
mod linux_userfaultfd;
pub(crate) use architecture::{
    clear_interrupt_gate, current_cpu_index, current_cpu_index_checked, double_fault_guard_page,
    double_fault_stack_top, install, install_for_cpu, install_interrupt_gate,
    kernel_stack_top_for_cpu, machine_check_guard_page, machine_check_stack_top, nmi_guard_page,
    nmi_stack_top, privilege_stack_guard_page, privilege_stack_top, stack_guard_pages,
    task_register_denies_user_io, user_interrupt_surface_is_minimal,
};
use architecture::{current_entry_state, install_user_interrupt_gate, CPU_ARCHITECTURE};
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
use linux_cgroupfs::*;
pub(crate) use linux_cgroupfs::{
    charge_linux_user_pages, linux_cache_charge_slot, reclaim_linux_user_pages,
};
use linux_descriptors::*;
pub(crate) use linux_diagnostics::*;
use linux_directories::*;
pub(crate) use linux_exec::*;
pub(super) use linux_fcntl::*;
pub(super) use linux_file_open::*;
use linux_file_ops::*;
use linux_fsmount::*;
use linux_futex::*;
use linux_hugetlb::*;
pub(crate) use linux_inotify::*;
use linux_ktls::*;
use linux_memory_protection::*;
pub(crate) use linux_mmap::*;
pub(crate) use linux_mounts::*;
use linux_numa::*;
pub(super) use linux_path_walk::*;
use linux_perf::*;
use linux_poll::*;
pub(crate) use linux_process_lifecycle::*;
pub(crate) use linux_process_state::*;
use linux_process_vm::*;
use linux_procfs::*;
use linux_pty::*;
use linux_quota::*;
use linux_read_write::*;
use linux_rtnetlink::*;
pub(crate) use linux_runtime_loop::*;
pub(crate) use linux_scheduler::*;
use linux_security::*;
use linux_signal::*;
pub(crate) use linux_signal::{
    expire_linux_waits_from_timer, linux_nanoseconds_to_next_wait_deadline, sample_linux_profile,
};
pub(crate) use linux_swapon::linux_swap_read_page;
use linux_swapon::*;
use linux_swapon::{linux_own_pages_reclaimable, linux_swap_out_current};
use linux_syscall::linux_syscall_handler;
use linux_thread::*;
use linux_time::*;
use linux_tun::*;
use linux_user_memory::*;
use linux_userfaultfd::*;

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
pub(crate) const USER_DATA_SELECTOR: u16 = 0x2b;
pub(crate) const USER_CODE_SELECTOR: u16 = 0x33;
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
// Linux processes run nested inside their parents' system calls on the kernel
// stack of the CPU that entered the domain, so a process tree such as
// sh > cargo > rustc > cc > collect2 > ld needs far more than one syscall's
// worth; 512 KiB overflowed. Match the boot CPU's stack.
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
const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_NE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_OSXSAVE: u64 = 1 << 18;
const CR4_UMIP: u64 = 1 << 11;
const CR4_TSD: u64 = 1 << 2;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;
const EFER_MSR: u32 = 0xc000_0080;
const STAR_MSR: u32 = 0xc000_0081;
const LSTAR_MSR: u32 = 0xc000_0082;
const FMASK_MSR: u32 = 0xc000_0084;
const FS_BASE_MSR: u32 = 0xc000_0100;
const GS_BASE_MSR: u32 = 0xc000_0101;
const KERNEL_GS_BASE_MSR: u32 = 0xc000_0102;
const EFER_SCE: u64 = 1;
const EFER_NXE: u64 = 1 << 11;

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
    LINUX_BOOT_ID: RuntimeRef<LinuxBootIdCell>,
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
    LINUX_PROCESS_LAST_BLOCKED_PID: RuntimeRef<CpuBankedAtomicU32>,
    LINUX_DOMAIN_EXEC_DEPTH: RuntimeRef<CpuBankedAtomicU32>,
    LINUX_PROCESS_RELEASE_PARENT_ON_EXEC: RuntimeRef<CpuBankedAtomicBool>,
    LINUX_PROCESS_SCHEDULER_NESTING: RuntimeRef<CpuBankedAtomicU32>,
    LINUX_PROCESS_SNAPSHOT_SCRATCH: RuntimeRef<LinuxProcessSnapshotScratch>,
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
    LINUX_BOOT_ID: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_BOOT_ID),
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
    LINUX_PROCESS_LAST_BLOCKED_PID: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_PROCESS_LAST_BLOCKED_PID),
    LINUX_DOMAIN_EXEC_DEPTH: RuntimeRef(&X86_RUNTIME_BACKING_LINUX_DOMAIN_EXEC_DEPTH),
    LINUX_PROCESS_RELEASE_PARENT_ON_EXEC: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_PROCESS_RELEASE_PARENT_ON_EXEC,
    ),
    LINUX_PROCESS_SCHEDULER_NESTING: RuntimeRef(
        &X86_RUNTIME_BACKING_LINUX_PROCESS_SCHEDULER_NESTING,
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

pub(crate) fn linux_startup_random() -> Option<[u8; 16]> {
    if core::arch::x86_64::__cpuid(1).ecx & (1 << 30) == 0 {
        return None;
    }
    let mut output = [0_u8; 16];
    for chunk in output.as_chunks_mut::<8>().0 {
        let mut generated = None;
        for _ in 0..16 {
            let mut value: u64;
            let mut ready: u8;
            unsafe {
                asm!(
                    "rdrand {value}",
                    "setc {ready}",
                    value = out(reg) value,
                    ready = out(reg_byte) ready,
                    options(nostack, preserves_flags)
                );
            }
            if ready != 0 {
                generated = Some(value);
                break;
            }
        }
        chunk.copy_from_slice(&generated?.to_ne_bytes());
    }
    Some(output)
}

struct LinuxBootIdCell(UnsafeCell<[u8; 37]>);

unsafe impl Sync for LinuxBootIdCell {}

static X86_RUNTIME_BACKING_LINUX_BOOT_ID_STATE: AtomicU8 = AtomicU8::new(0);
static X86_RUNTIME_BACKING_LINUX_BOOT_ID: LinuxBootIdCell =
    LinuxBootIdCell(UnsafeCell::new([0; 37]));

fn linux_boot_id() -> &'static [u8] {
    if X86_RUNTIME.LINUX_BOOT_ID_STATE.load(Ordering::Acquire) != 2
        && X86_RUNTIME
            .LINUX_BOOT_ID_STATE
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        let mut random = linux_startup_random().unwrap_or([0x47; 16]);
        random[6] = random[6] & 0x0f | 0x40;
        random[8] = random[8] & 0x3f | 0x80;
        let output = unsafe { &mut *X86_RUNTIME.LINUX_BOOT_ID.0 .0.get() };
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
        X86_RUNTIME.LINUX_BOOT_ID_STATE.store(2, Ordering::Release);
    }
    while X86_RUNTIME.LINUX_BOOT_ID_STATE.load(Ordering::Acquire) != 2 {
        core::hint::spin_loop();
    }
    unsafe { &*X86_RUNTIME.LINUX_BOOT_ID.0 .0.get() }
}

fn linux_getrandom(address: u64, length: u64, flags: u64) -> u64 {
    linux_getrandom_with_copy(address, length, flags, copy_to_linux_user)
}

fn linux_getrandom_with_copy(
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
/// The process that most recently yielded because it could not make
/// progress; see run_other_linux_processes.
static X86_RUNTIME_BACKING_LINUX_PROCESS_LAST_BLOCKED_PID: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
/// How many domain-exec fork transactions are running; see
/// LinuxDomainExecGuard.
static X86_RUNTIME_BACKING_LINUX_DOMAIN_EXEC_DEPTH: CpuBankedAtomicU32 = CpuBankedAtomicU32::new(0);
static X86_RUNTIME_BACKING_LINUX_PROCESS_RELEASE_PARENT_ON_EXEC: CpuBankedAtomicBool =
    CpuBankedAtomicBool::new(false);
static X86_RUNTIME_BACKING_LINUX_PROCESS_CHILD_STATUS: CpuBankedAtomicU8 =
    CpuBankedAtomicU8::new(0);
static X86_RUNTIME_BACKING_LINUX_CURRENT_PROCESS_PID: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(1);
static X86_RUNTIME_BACKING_LINUX_PROCESS_SCHEDULER_NESTING: CpuBankedAtomicU32 =
    CpuBankedAtomicU32::new(0);
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
const PRIVILEGE_ENTRY_NMI_STAGE_COUNT: u8 = 6;
const PRIVILEGE_ENTRY_NMI_STAGE_MASK: u64 = (1 << PRIVILEGE_ENTRY_NMI_STAGE_COUNT) - 1;
static PRIVILEGE_ENTRY_NMI_PROBE_MASK: AtomicU64 = AtomicU64::new(0);
static PRIVILEGE_ENTRY_NMI_PROBE_HITS: AtomicU8 = AtomicU8::new(0);
global_asm!(
    r#"
    .text
    .global linox_raw_copy_from_user
    .global linox_copy_from_user_fault_begin
    .global linox_copy_from_user_fault_end
    .global linox_copy_from_user_fixup
linox_raw_copy_from_user:
    mov rax, rdx
    test rax, rax
    jz 2f
    stac
linox_copy_from_user_fault_begin:
1:
    mov cl, byte ptr [rsi]
    mov byte ptr [rdi], cl
    inc rsi
    inc rdi
    dec rax
    jnz 1b
linox_copy_from_user_fault_end:
    clac
2:
    ret
linox_copy_from_user_fixup:
    clac
    ret

    .global linox_raw_copy_to_user
    .global linox_copy_to_user_fault_begin
    .global linox_copy_to_user_fault_end
    .global linox_copy_to_user_fixup
linox_raw_copy_to_user:
    mov rax, rdx
    test rax, rax
    jz 4f
    stac
linox_copy_to_user_fault_begin:
3:
    mov cl, byte ptr [rsi]
    mov byte ptr [rdi], cl
    inc rsi
    inc rdi
    dec rax
    jnz 3b
linox_copy_to_user_fault_end:
    clac
4:
    ret
linox_copy_to_user_fixup:
    clac
    ret

    .global linox_breakpoint_entry
linox_breakpoint_entry:
    test qword ptr [rsp + 8], 3
    jz 1f
    swapgs
1:
    clac
    cld
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov r12, rsp
    and rsp, -16
    call {breakpoint_handler}
    mov rsp, r12
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    test qword ptr [rsp + 8], 3
    jz 2f
    swapgs
2:
    iretq

    .macro LINOX_EXCEPTION_NO_ERROR vector
    .global linox_exception_\vector
linox_exception_\vector:
    push 0
    push \vector
    jmp linox_fatal_exception_common
    .endm

    .macro LINOX_EXCEPTION_ERROR vector
    .global linox_exception_\vector
linox_exception_\vector:
    push \vector
    jmp linox_fatal_exception_common
    .endm

    LINOX_EXCEPTION_NO_ERROR 0
    LINOX_EXCEPTION_NO_ERROR 1
    .global linox_nmi_entry
linox_nmi_entry:
    clac
    cld
    lock inc byte ptr [rip + {entry_nmi_probe_hits}]
    push rax
    mov rax, qword ptr [rip + {tlb_shootdown_address}]
    test rax, rax
    jz 1f
    invlpg [rax]
    lock inc dword ptr [rip + {tlb_shootdown_acknowledged}]
1:
    pop rax
    iretq
    LINOX_EXCEPTION_NO_ERROR 4
    LINOX_EXCEPTION_NO_ERROR 5
    LINOX_EXCEPTION_NO_ERROR 6
    LINOX_EXCEPTION_NO_ERROR 7
    .global linox_double_fault_entry
linox_double_fault_entry:
    push 8
    jmp linox_fatal_exception_common
    LINOX_EXCEPTION_NO_ERROR 9
    LINOX_EXCEPTION_ERROR 10
    LINOX_EXCEPTION_ERROR 11
    LINOX_EXCEPTION_ERROR 12
    LINOX_EXCEPTION_ERROR 13
    LINOX_EXCEPTION_ERROR 14
    LINOX_EXCEPTION_NO_ERROR 15
    LINOX_EXCEPTION_NO_ERROR 16
    LINOX_EXCEPTION_ERROR 17
    LINOX_EXCEPTION_NO_ERROR 18
    LINOX_EXCEPTION_NO_ERROR 19
    LINOX_EXCEPTION_NO_ERROR 20
    LINOX_EXCEPTION_ERROR 21
    LINOX_EXCEPTION_NO_ERROR 22
    LINOX_EXCEPTION_NO_ERROR 23
    LINOX_EXCEPTION_NO_ERROR 24
    LINOX_EXCEPTION_NO_ERROR 25
    LINOX_EXCEPTION_NO_ERROR 26
    LINOX_EXCEPTION_NO_ERROR 27
    LINOX_EXCEPTION_NO_ERROR 28
    LINOX_EXCEPTION_ERROR 29
    LINOX_EXCEPTION_ERROR 30
    LINOX_EXCEPTION_NO_ERROR 31

linox_fatal_exception_common:
    cli
    clac
    cld
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov r12, rsp
    test qword ptr [rsp + 144], 3
    jnz linox_user_fault_common
    cmp qword ptr [rsp + 120], 14
    jne linox_fatal_exception_call
    mov rax, [rsp + 136]
    lea rbx, [rip + linox_copy_from_user_fault_begin]
    cmp rax, rbx
    jb 1f
    lea rbx, [rip + linox_copy_from_user_fault_end]
    cmp rax, rbx
    jae 1f
    lea rax, [rip + linox_copy_from_user_fixup]
    mov [rsp + 136], rax
    jmp linox_fault_return
1:
    lea rbx, [rip + linox_copy_to_user_fault_begin]
    cmp rax, rbx
    jb 2f
    lea rbx, [rip + linox_copy_to_user_fault_end]
    cmp rax, rbx
    jae 2f
    lea rax, [rip + linox_copy_to_user_fixup]
    mov [rsp + 136], rax
    jmp linox_fault_return
2:
    mov r12, rsp
    mov rdi, [rsp + 128]
    mov rsi, cr2
    and rsp, -16
    call {kernel_linux_cow_fault_handler}
    test rax, rax
    jnz linox_fault_return
    mov rsp, r12
linox_fatal_exception_call:
    mov rdi, [rsp + 120]
    mov rsi, [rsp + 128]
    mov rdx, cr2
    mov rcx, [rsp + 136]
    mov r8, rsp
    and rsp, -16
    call {fatal_exception_handler}
    ud2

linox_user_fault_common:
    swapgs
    mov r12, rsp
    mov rdi, rsp
    and rsp, -16
    call {user_fault_handler}
    cmp rax, -1
    je linox_user_return_kernel
    mov rsp, r12
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    swapgs
    iretq
linox_fault_return:
    mov rsp, r12
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    iretq

    .section .rodata
    .align 8
    .global linox_exception_entries
linox_exception_entries:
    .quad linox_exception_0
    .quad linox_exception_1
    .quad linox_nmi_entry
    .quad linox_breakpoint_entry
    .quad linox_exception_4
    .quad linox_exception_5
    .quad linox_exception_6
    .quad linox_exception_7
    .quad linox_double_fault_entry
    .quad linox_exception_9
    .quad linox_exception_10
    .quad linox_exception_11
    .quad linox_exception_12
    .quad linox_exception_13
    .quad linox_exception_14
    .quad linox_exception_15
    .quad linox_exception_16
    .quad linox_exception_17
    .quad linox_exception_18
    .quad linox_exception_19
    .quad linox_exception_20
    .quad linox_exception_21
    .quad linox_exception_22
    .quad linox_exception_23
    .quad linox_exception_24
    .quad linox_exception_25
    .quad linox_exception_26
    .quad linox_exception_27
    .quad linox_exception_28
    .quad linox_exception_29
    .quad linox_exception_30
    .quad linox_exception_31

    .text
    .global linox_user_enter
linox_user_enter:
    mov r10, [rsp + 8]
    mov r11, [rsp + 16]
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov gs:[{entry_return_stack}], rsp
    mov r14, [rsp + 72]
    mov rbx, rdx
    push {user_data}
    push rsi
    push 0x202
    push {user_code}
    push rdi
    swapgs
    iretq

    .global linox_process_user_enter
linox_process_user_enter:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov gs:[{entry_return_stack}], rsp
    push {user_data}
    push rsi
    push rcx
    push {user_code}
    push rdi
    mov rax, rdx
    mov rbx, [rax + 8]
    mov rcx, [rax + 16]
    mov rdx, [rax + 24]
    mov rsi, [rax + 32]
    mov rdi, [rax + 40]
    mov rbp, [rax + 48]
    mov r8, [rax + 56]
    mov r9, [rax + 64]
    mov r10, [rax + 72]
    mov r11, [rax + 80]
    mov r12, [rax + 88]
    mov r13, [rax + 96]
    mov r14, [rax + 104]
    mov r15, [rax + 112]
    mov rax, [rax]
    swapgs
    iretq

    .global linox_syscall_entry
linox_syscall_entry:
    cli
    swapgs
    clac
    cld
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov r12, rsp
    mov rdi, rax
    mov rsi, [r12 + 72]
    mov rdx, r12
    and rsp, -16
    call {syscall_handler}
    cmp rax, -1
    je linox_user_return_kernel
    mov rsp, r12
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    swapgs
    iretq

    .global linox_linux_syscall_entry
linox_linux_syscall_entry:
    cli
    swapgs
    clac
    cld
    lock btr qword ptr [rip + {entry_nmi_probe_mask}], 0
    jnc 1f
    int 2
1:
    mov gs:[{entry_user_rsp}], rsp
    mov gs:[{entry_user_rip}], rcx
    mov gs:[{entry_user_rflags}], r11
    lock btr qword ptr [rip + {entry_nmi_probe_mask}], 1
    jnc 2f
    int 2
2:
    mov rsp, gs:[{entry_return_stack}]
    lock btr qword ptr [rip + {entry_nmi_probe_mask}], 2
    jnc 3f
    int 2
3:
    push rdi
    push rsi
    push rdx
    push r8
    push r9
    push r10
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov gs:[{entry_kernel_frame}], rsp
    lock btr qword ptr [rip + {entry_nmi_probe_mask}], 3
    jnc 4f
    int 2
4:
    mov rdi, rax
    mov rsi, rsp
    mov rdx, gs:[{entry_user_rsp}]
    mov rcx, gs:[{entry_user_rip}]
    mov r8, gs:[{entry_user_rflags}]
    and rsp, -16
    call {linux_syscall_handler}
    lock btr qword ptr [rip + {entry_nmi_probe_mask}], 4
    jnc 5f
    int 2
5:
    cmp rax, {linux_return_to_kernel}
    je linox_user_return_kernel
    cmp rax, {linux_return_from_iret}
    je linox_linux_iret_return
    mov gs:[{entry_syscall_result}], rax
    mov rsp, gs:[{entry_kernel_frame}]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rsi
    pop rdi
    mov rax, gs:[{entry_syscall_result}]
    mov rcx, gs:[{entry_user_rip}]
    shr rcx, 47
    jne linox_invalid_user_return
    mov rcx, gs:[{entry_user_rsp}]
    shr rcx, 47
    jne linox_invalid_user_return
    mov rcx, gs:[{entry_user_rip}]
    mov r11, gs:[{entry_user_rflags}]
    lock btr qword ptr [rip + {entry_nmi_probe_mask}], 5
    jnc 6f
    int 2
6:
    mov rsp, gs:[{entry_user_rsp}]
    swapgs
    sysretq
linox_invalid_user_return:
    mov rsp, gs:[{entry_return_stack}]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
linox_linux_iret_return:
    mov rsp, gs:[{entry_kernel_frame}]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rsi
    pop rdi
    push {user_data}
    push gs:[{entry_user_rsp}]
    push gs:[{entry_user_rflags}]
    push {user_code}
    push gs:[{entry_user_rip}]
    mov rax, gs:[{entry_signal_rax}]
    mov rcx, gs:[{entry_signal_rcx}]
    mov r11, gs:[{entry_signal_r11}]
    swapgs
    iretq
linox_user_return_kernel:
    mov rsp, gs:[{entry_return_stack}]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
"#,
    breakpoint_handler = sym breakpoint_handler,
    fatal_exception_handler = sym fatal_exception_handler,
    kernel_linux_cow_fault_handler = sym kernel_linux_cow_fault_handler,
    user_fault_handler = sym user_fault_handler,
    syscall_handler = sym syscall_handler,
    linux_syscall_handler = sym linux_syscall_handler,
    entry_return_stack = const 0,
    entry_user_rsp = const 8,
    entry_user_rip = const 16,
    entry_user_rflags = const 24,
    entry_kernel_frame = const 32,
    entry_syscall_result = const 40,
    entry_signal_rax = const 48,
    entry_signal_rcx = const 56,
    entry_signal_r11 = const 64,
    entry_nmi_probe_mask = sym PRIVILEGE_ENTRY_NMI_PROBE_MASK,
    entry_nmi_probe_hits = sym PRIVILEGE_ENTRY_NMI_PROBE_HITS,
    tlb_shootdown_address = sym super::smp::TLB_SHOOTDOWN_ADDRESS,
    tlb_shootdown_acknowledged = sym super::smp::TLB_SHOOTDOWN_ACKNOWLEDGED,
    linux_return_to_kernel = const LINUX_RETURN_TO_KERNEL as i64,
    linux_return_from_iret = const LINUX_RETURN_FROM_IRET as i64,
    user_data = const USER_DATA_SELECTOR as u64,
    user_code = const USER_CODE_SELECTOR as u64,
);

extern "C" {
    static linox_exception_entries: [usize; 32];
    fn linox_syscall_entry();
    fn linox_linux_syscall_entry();
}

unsafe fn enter_linux_process(entry: usize, stack: usize, general: *const u64, rflags: u64) {
    let entry_state = current_entry_state();
    let previous_return_stack = (*entry_state).return_stack;
    process_user_enter(entry, stack, general, rflags);
    (*entry_state).return_stack = previous_return_stack;
}

/// Enters a Linux process's user mode until it returns to the kernel. The
/// kernel-entry lock is released while it runs user code and held again on
/// the way back (`sync::kernel_entry_leave_to_user`).
///
/// # Safety
///
/// As for `linox_process_user_enter`.
pub(super) unsafe fn process_user_enter(
    entry: usize,
    stack: usize,
    general: *const u64,
    rflags: u64,
) {
    crate::sync::kernel_entry_leave_to_user();
    crate::cpu_time::leave_for_user();
    set_user_time_stamp_access(linux_user_time_stamp_allowed());
    linox_process_user_enter(entry, stack, general, rflags);
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
unsafe fn enter_linux_runtime_process(
    entry: usize,
    stack: usize,
    general: *const u64,
    rflags: u64,
) {
    let entry_state = current_entry_state();
    let previous_return_stack = (*entry_state).return_stack;
    LINUX_PROCESS_SLICE[linux_cpu_slot()].store(0, Ordering::SeqCst);
    let entered = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && current_linux_runtime_cpu_index() == 0
        && activation::enter_on_own_stack(
            linux_activation_owner(current_linux_process_pid()),
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
    (*entry_state).return_stack = previous_return_stack;
}

#[allow(clippy::too_many_arguments)]
unsafe fn enter_user(
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
    if !address_space::current_user_entry_context_is_valid(entry as u64, stack as u64) {
        return false;
    }
    linox_user_enter(
        entry,
        stack,
        host_handle,
        console_handle,
        ipc_handle,
        identity,
        service_domain,
        service_identity,
        root_handle,
    );
    true
}

extern "sysv64" {
    fn linox_raw_copy_from_user(output: *mut u8, input: *const u8, length: usize) -> usize;
    fn linox_raw_copy_to_user(output: *mut u8, input: *const u8, length: usize) -> usize;
    fn linox_user_enter(
        entry: usize,
        stack: usize,
        host_handle: u64,
        console_handle: u64,
        ipc_handle: u64,
        identity: u64,
        service_domain: u64,
        service_identity: u64,
        root_handle: u64,
    );
    fn linox_process_user_enter(entry: usize, stack: usize, general: *const u64, rflags: u64);
}

pub(crate) unsafe fn raw_copy_from_user(output: *mut u8, input: *const u8, length: usize) -> usize {
    linox_raw_copy_from_user(output, input, length)
}

pub(crate) unsafe fn raw_copy_to_user(output: *mut u8, input: *const u8, length: usize) -> usize {
    linox_raw_copy_to_user(output, input, length)
}

pub(crate) fn verify_user_copy_fault_fixups(mapped_end: u64, unmapped: u64) -> bool {
    let mut output = [0_u8; 2];
    let input = [0x5a_u8, 0xa5];
    let partial_from = unsafe {
        raw_copy_from_user(
            output.as_mut_ptr(),
            (mapped_end - 1) as *const u8,
            output.len(),
        )
    };
    let partial_to =
        unsafe { raw_copy_to_user((mapped_end - 1) as *mut u8, input.as_ptr(), input.len()) };
    let rejected_from =
        unsafe { raw_copy_from_user(output.as_mut_ptr(), unmapped as *const u8, output.len()) };
    let rejected_to = unsafe { raw_copy_to_user(unmapped as *mut u8, input.as_ptr(), input.len()) };
    let flags: u64;
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem)) };
    partial_from == 1
        && partial_to == 1
        && rejected_from == output.len()
        && rejected_to == input.len()
        && flags & (1 << 18) == 0
}

pub(crate) fn enable_supervisor_execution_prevention() -> bool {
    if __cpuid(0).eax < CPUID_STRUCTURED_FEATURES
        || __cpuid_count(CPUID_STRUCTURED_FEATURES, 0).ebx & CPUID_SMEP == 0
    {
        return false;
    }
    let mut cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= CR4_SMEP;
        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    supervisor_execution_prevention_enabled()
}

pub(crate) fn enable_execute_disable() -> bool {
    if __cpuid(CPUID_EXTENDED_MAX).eax < CPUID_EXTENDED_FEATURES
        || __cpuid(CPUID_EXTENDED_FEATURES).edx & CPUID_NX == 0
    {
        return false;
    }
    unsafe {
        let efer = read_msr(EFER_MSR);
        write_msr(EFER_MSR, efer | EFER_NXE);
        read_msr(EFER_MSR) & EFER_NXE != 0
    }
}

pub(crate) fn execute_disable_enabled() -> bool {
    if __cpuid(CPUID_EXTENDED_MAX).eax < CPUID_EXTENDED_FEATURES {
        return false;
    }
    unsafe { read_msr(EFER_MSR) & EFER_NXE != 0 }
}

pub(crate) fn supervisor_execution_prevention_enabled() -> bool {
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    cr4 & CR4_SMEP != 0
}

pub(crate) fn enable_supervisor_access_prevention() -> bool {
    if __cpuid(0).eax < CPUID_STRUCTURED_FEATURES
        || __cpuid_count(CPUID_STRUCTURED_FEATURES, 0).ebx & CPUID_SMAP == 0
    {
        return false;
    }
    let mut cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= CR4_SMAP;
        asm!(
            "mov cr4, {cr4}",
            "clac",
            cr4 = in(reg) cr4,
            options(nomem, nostack)
        );
    }
    supervisor_access_prevention_enabled()
}

pub(crate) fn supervisor_access_prevention_enabled() -> bool {
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    cr4 & CR4_SMAP != 0
}

pub(crate) fn enable_user_mode_instruction_prevention() -> bool {
    if __cpuid(0).eax < CPUID_STRUCTURED_FEATURES
        || __cpuid_count(CPUID_STRUCTURED_FEATURES, 0).ecx & CPUID_UMIP == 0
    {
        return false;
    }
    let mut cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= CR4_UMIP;
        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    user_mode_instruction_prevention_enabled()
}

/// Lets this CPU's user mode read the timestamp counter, or makes rdtsc
/// and rdtscp fault there (CR4.TSD) while a process that asked for that
/// with PR_SET_TSC runs: set as the CPU leaves for such a process's user
/// mode, cleared as it comes back, and written only when it changes.
pub(super) fn set_user_time_stamp_access(allowed: bool) {
    let mut cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    if (cr4 & CR4_TSD == 0) == allowed {
        return;
    }
    cr4 ^= CR4_TSD;
    unsafe {
        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
    }
}

/// Whether the Linux process this CPU is about to run in user mode may read
/// the timestamp counter (PR_SET_TSC).
pub(super) fn linux_user_time_stamp_allowed() -> bool {
    !(X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::Relaxed)
        && X86_RUNTIME.ELF_PROBE_TSC_SIGSEGV.load(Ordering::Relaxed))
}

pub(crate) fn user_mode_instruction_prevention_enabled() -> bool {
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    cr4 & CR4_UMIP != 0
}

pub(crate) fn initialize_user_call_gate() -> bool {
    install_user_interrupt_gate(SYSCALL_VECTOR, linox_syscall_entry as *const () as usize)
        && user_interrupt_surface_is_minimal()
}

pub(crate) unsafe fn with_supervisor_user_access<T>(operation: impl FnOnce() -> T) -> T {
    asm!("stac", options(nostack));
    let result = operation();
    asm!("clac", options(nostack));
    result
}

pub(crate) fn execute_auxiliary(
    entry: usize,
    stack: usize,
    console_handle: u64,
    domain_id: u64,
    service_identity: u64,
) {
    if !install_current_scheduler_fs_base() {
        return;
    }
    unsafe {
        let _ = enter_user(
            entry,
            stack,
            0,
            console_handle,
            0,
            4,
            domain_id,
            service_identity,
            0,
        );
    };
}

pub(crate) fn execute_packet_consumer(
    entry: usize,
    stack: usize,
    packet_handle: u64,
    expected_sequence: u64,
    more_pending: bool,
    domain_id: u64,
    service_identity: u64,
) {
    if !install_current_scheduler_fs_base() {
        return;
    }
    unsafe {
        let _ = enter_user(
            entry,
            stack,
            expected_sequence,
            packet_handle,
            u64::from(more_pending),
            4,
            domain_id,
            service_identity,
            0,
        );
    };
}

pub(crate) fn execute_native_auxiliary(
    entry: usize,
    stack: usize,
    boot_info: u64,
    capability: u64,
    domain_id: u64,
    service_identity: u64,
) {
    if !install_current_scheduler_fs_base() {
        return;
    }
    unsafe {
        let _ = enter_user(
            entry,
            stack,
            boot_info,
            capability,
            0,
            4,
            domain_id,
            service_identity,
            0,
        );
    };
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_native_controller(
    entry: usize,
    stack: usize,
    console_handle: u64,
    host_handle: u64,
    root_handle: u64,
    network_handle: u64,
    domain_id: u64,
    service_identity: u64,
) {
    if !install_current_scheduler_fs_base()
        || X86_RUNTIME
            .LINUX_CONTROLLER_DOMAIN
            .compare_exchange(0, domain_id, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return;
    }
    X86_RUNTIME
        .LINUX_CONTROLLER_CONSOLE
        .store(console_handle, Ordering::Release);
    X86_RUNTIME
        .LINUX_CONTROLLER_HOST
        .store(host_handle, Ordering::Release);
    X86_RUNTIME
        .LINUX_CONTROLLER_ROOT
        .store(root_handle, Ordering::Release);
    X86_RUNTIME
        .LINUX_CONTROLLER_NETWORK
        .store(network_handle, Ordering::Release);
    if configure_linux_syscall().is_none() {
        X86_RUNTIME
            .LINUX_CONTROLLER_DOMAIN
            .store(0, Ordering::Release);
        return;
    }
    unsafe {
        let _ = enter_user(
            entry,
            stack,
            console_handle,
            host_handle,
            network_handle,
            4,
            domain_id,
            service_identity,
            root_handle,
        );
    };
}

pub(crate) fn resume_native_controller(domain_id: u64) -> bool {
    let Some(context) = scheduler::resume_container_lifecycle(domain_id) else {
        return false;
    };
    let (Ok(entry), Ok(stack)) = (
        usize::try_from(context.instruction()),
        usize::try_from(context.stack()),
    ) else {
        return false;
    };
    if !activate_user_root(context.address_space_root()) || !install_user_fs_base(context.fs_base())
    {
        return false;
    }
    let general = context.general();
    // SAFETY: the scheduler retained the complete validated controller trap
    // context while its lifecycle request was serviced by the kernel.
    unsafe { enter_linux_process(entry, stack, general.as_ptr(), context.flags()) };
    true
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

struct LinuxProcessSnapshotScratch(UnsafeCell<LinuxProcessAddressSpaceSnapshot>);

unsafe impl Sync for LinuxProcessSnapshotScratch {}

static X86_RUNTIME_BACKING_LINUX_PROCESS_SNAPSHOT_SCRATCH: LinuxProcessSnapshotScratch =
    LinuxProcessSnapshotScratch(UnsafeCell::new(LinuxProcessAddressSpaceSnapshot {
        hierarchy: Vec::new(),
        hierarchy_count: 0,
        mappings: Vec::new(),
        mapping_count: 0,
    }));

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

fn prepare_domain_exec_stdio() -> bool {
    for descriptor in 0..3 {
        if linux_descriptor_open(descriptor) && linux_descriptor_close(descriptor) != 0 {
            return false;
        }
        let index = descriptor as usize;
        X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_OPEN_FILE_IDS[index].store(0, Ordering::Release);
        set_linux_descriptor_close_on_exec(descriptor, false);
    }
    X86_RUNTIME.ELF_PROBE_CONSOLE_DESCRIPTORS.store(
        (LINUX_DESCRIPTOR_INPUT | (LINUX_DESCRIPTOR_OUTPUT << 2)) as u8,
        Ordering::Release,
    );
    X86_RUNTIME
        .ELF_PROBE_STDERR_OPEN
        .store(true, Ordering::Release);
    true
}

fn resume_linux_system_supervisor() -> bool {
    if X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT
        .load(Ordering::SeqCst)
        != 1
        || X86_RUNTIME
            .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
            .load(Ordering::SeqCst)
            != 0
        || current_linux_thread_handle().is_some()
        || linux_process::live_process_status(1)
            != Some(linux_process::LiveProcessStatus {
                pid: 1,
                parent_pid: 0,
                state: linux_process::LiveProcessState::Running,
            })
    {
        if cfg!(feature = "verification-boot") {
            serial_write(
                "linox: Linux supervisor resume preconditions wait/shutdown/thread/status: ",
            );
            serial_write_u64(u64::from(
                X86_RUNTIME
                    .LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT
                    .load(Ordering::SeqCst),
            ));
            serial_write(" ");
            serial_write_u64(u64::from(
                X86_RUNTIME
                    .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
                    .load(Ordering::SeqCst),
            ));
            serial_write(" ");
            serial_write_u64(u64::from(current_linux_thread_handle().is_some()));
            serial_write(" ");
            serial_write_u64(u64::from(linux_process::live_process_status(1).is_some()));
            serial_write("\r\n");
        }
        return false;
    }
    if !X86_RUNTIME
        .CONTAINER_MANAGEMENT_ENABLED
        .load(Ordering::SeqCst)
    {
        return resume_linux_system_supervisor_legacy();
    }
    let Some(slot) = selected_container_slot() else {
        return false;
    };
    X86_RUNTIME
        .CONTAINER_ACTIVE_SLOT
        .store(slot as u8, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .store(slot as u8, Ordering::SeqCst);
    X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
        .store(control_abi::DOMAIN_STATE_RUNNING as u8, Ordering::SeqCst);
    crate::serial_write("linox: configured runtime domain reached ready state\r\n");
    let controller_completed = address_space::run_installed_interactive_controller();
    let shutdown_requested = X86_RUNTIME
        .CONTAINER_HOST_SHUTDOWN_REQUESTED
        .load(Ordering::SeqCst);
    if !controller_completed && !shutdown_requested {
        return false;
    }
    if !controller_completed {
        crate::serial_write(
            "linox: authorized shutdown retained after controller teardown failure\r\n",
        );
    }
    if X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
        .load(Ordering::SeqCst)
        == 0
        && !shutdown_linux_system_supervisor(false)
    {
        return false;
    }
    X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
        .load(Ordering::SeqCst)
        == 1
}

fn resume_linux_system_supervisor_legacy() -> bool {
    if !wake_linux_signal_wait(LINUX_SIGTERM, LINUX_SI_KERNEL, None) {
        return false;
    }
    let Some(thread) = ready_linux_thread_handle() else {
        return false;
    };
    let Some(context) = linux_thread_return_context(thread) else {
        return false;
    };
    let Some(process) = linux_process::dispatch_live_init_with_return(LINUX_SIGTERM) else {
        return false;
    };
    if process.pid != 1
        || context.rax != LINUX_SIGTERM
        || process.general
            != context
                .registers
                .process_general(context.rax, context.rip, context.rflags)
        || process.rip != context.rip
        || process.rsp != context.rsp
        || process.rflags != context.rflags
        || process.fs_base != context.fs_base
        || !switch_linux_thread(thread)
    {
        return false;
    }
    X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
        .fetch_add(1, Ordering::SeqCst);
    run_dispatched_linux_process(&process)
}

fn shutdown_linux_system_supervisor(failed: bool) -> bool {
    if X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT
        .load(Ordering::SeqCst)
        != 1
        || X86_RUNTIME
            .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
            .load(Ordering::SeqCst)
            != 0
        || current_linux_thread_handle().is_some()
        || linux_process::live_process_status(1)
            != Some(linux_process::LiveProcessStatus {
                pid: 1,
                parent_pid: 0,
                state: linux_process::LiveProcessState::Running,
            })
        || !wake_linux_signal_wait(LINUX_SIGTERM, LINUX_SI_KERNEL, None)
    {
        return false;
    }
    let Some(thread) = ready_linux_thread_handle() else {
        return false;
    };
    let Some(context) = linux_thread_return_context(thread) else {
        return false;
    };
    let Some(process) = linux_process::dispatch_live_init_with_return(LINUX_SIGTERM) else {
        return false;
    };
    if process.pid != 1
        || context.rax != LINUX_SIGTERM
        || process.general
            != context
                .registers
                .process_general(context.rax, context.rip, context.rflags)
        || process.rip != context.rip
        || process.rsp != context.rsp
        || process.rflags != context.rflags
        || process.fs_base != context.fs_base
        || !switch_linux_thread(thread)
    {
        return false;
    }
    X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
        .fetch_add(1, Ordering::SeqCst);
    let resumed = run_dispatched_linux_process(&process);
    if resumed {
        let Some(slot) = active_container_slot() else {
            return false;
        };
        if X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst)
            != control_abi::DOMAIN_STATE_RUNNING as u8
        {
            return resumed;
        }
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].store(
            if failed {
                control_abi::DOMAIN_STATE_FAILED as u8
            } else {
                control_abi::DOMAIN_STATE_STOPPED as u8
            },
            Ordering::SeqCst,
        );
        X86_RUNTIME
            .CONTAINER_ACTIVE_SLOT
            .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
        X86_RUNTIME
            .CONTAINER_SELECTED_SLOT
            .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
    }
    resumed
}

pub(crate) fn take_container_restart_request() -> bool {
    X86_RUNTIME
        .CONTAINER_RESTART_REQUESTED
        .swap(false, Ordering::SeqCst)
}

pub(crate) fn take_container_host_shutdown_request() -> bool {
    X86_RUNTIME
        .CONTAINER_HOST_SHUTDOWN_REQUESTED
        .swap(false, Ordering::SeqCst)
}

pub(crate) fn fail_configured_container() {
    if let Some(slot) = selected_or_active_container_slot() {
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
            .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::SeqCst);
    }
    X86_RUNTIME
        .CONTAINER_ACTIVE_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
    X86_RUNTIME
        .CONTAINER_SELECTED_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .store(LINUX_RUNTIME_HOST_INSTANCE, Ordering::SeqCst);
}

pub(crate) fn begin_configured_container() {
    if let Some(slot) = selected_container_slot() {
        let Some(container_domain) = container_domain_id(slot) else {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::SeqCst);
            return;
        };
        if domain::container_domain_limits(container_domain).is_none() {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::SeqCst);
            return;
        }
        if domain::container_network_mode(container_domain).is_none() {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::SeqCst);
            return;
        }
        X86_RUNTIME
            .CONTAINER_ACTIVE_SLOT
            .store(slot as u8, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_EXECUTION_INSTANCE
            .store(slot as u8, Ordering::SeqCst);
        if container_state(slot) != control_abi::DOMAIN_STATE_BOOTING {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_RUNNING as u8, Ordering::SeqCst);
        }
    }
}

pub(crate) fn mark_configured_container_booting() {
    if let Some(slot) = selected_container_slot() {
        if container_state(slot) == control_abi::DOMAIN_STATE_STARTING
            && !container_image_is_embedded(slot)
            && crate::published_rootfs::is_installed(slot)
        {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_BOOTING as u8, Ordering::Release);
        }
    }
}

pub(crate) fn stop_configured_container() {
    activation::discard_parked(linux_execution_instance() as u32);
    crate::linux_exe::forget_instance(X86_RUNTIME.LINUX_EXECUTION_INSTANCE.load(Ordering::SeqCst));
    crate::linux_areas::forget_instance(linux_execution_instance());
    linux_perf_forget_instance(linux_execution_instance());
    crate::linux_mounts::forget_instance(linux_execution_instance());
    crate::linux_lease::forget_domain(linux_execution_instance());
    crate::linux_core::forget_domain(linux_execution_instance());
    crate::linux_fd_table::forget_domain(linux_execution_instance());
    crate::linux_wait_sets::forget_domain(linux_execution_instance());
    crate::linux_tmpfs_quota::forget_instance(linux_execution_instance());
    crate::linux_swap::forget_instance(linux_execution_instance());
    crate::linux_pidfs::forget_instance(linux_execution_instance());
    crate::linux_fscontext::forget_instance(linux_execution_instance());
    linux_namespace::forget_instance(
        linux_execution_instance(),
        crate::linux_sysv_ipc::release_instance,
    );
    if let Some(slot) = active_container_slot() {
        if matches!(
            u64::from(X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst)),
            control_abi::DOMAIN_STATE_BOOTING | control_abi::DOMAIN_STATE_RUNNING
        ) {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_STOPPED as u8, Ordering::SeqCst);
        }
    }
    X86_RUNTIME
        .CONTAINER_ACTIVE_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
    X86_RUNTIME
        .CONTAINER_SELECTED_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .store(LINUX_RUNTIME_HOST_INSTANCE, Ordering::SeqCst);
}

pub(crate) fn suspend_configured_container() {
    X86_RUNTIME
        .CONTAINER_ACTIVE_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::Release);
    X86_RUNTIME
        .CONTAINER_SELECTED_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::Release);
    X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .store(LINUX_RUNTIME_HOST_INSTANCE, Ordering::Release);
}

pub(crate) fn enable_container_management() -> bool {
    X86_RUNTIME
        .CONTAINER_MANAGEMENT_ENABLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

pub(crate) fn export_persistent_domain_configuration(
    output: &mut [u8; PERSISTENT_DOMAIN_CONFIG_SIZE],
) -> bool {
    if !X86_RUNTIME
        .CONTAINER_MANAGEMENT_ENABLED
        .load(Ordering::Acquire)
    {
        return false;
    }
    output.fill(0);
    output[..8].copy_from_slice(b"LINOXDC1");
    output[8..12].copy_from_slice(&1_u32.to_le_bytes());
    output[12..14].copy_from_slice(&(control_abi::DOMAIN_LIMIT as u16).to_le_bytes());
    for slot in 0..control_abi::DOMAIN_LIMIT {
        if container_state(slot) == 0 {
            continue;
        }
        let mut request = [0_u8; control_abi::DOMAIN_REQUEST_SIZE];
        write_container_request(&mut request, slot, control_abi::DOMAIN_CURSOR_END);
        let start = 16 + slot * control_abi::DOMAIN_REQUEST_SIZE;
        output[start..start + control_abi::DOMAIN_REQUEST_SIZE].copy_from_slice(&request);
    }
    true
}

pub(crate) fn import_persistent_domain_configuration(
    input: &[u8; PERSISTENT_DOMAIN_CONFIG_SIZE],
) -> bool {
    if !X86_RUNTIME
        .CONTAINER_MANAGEMENT_ENABLED
        .load(Ordering::Acquire)
        || &input[..8] != b"LINOXDC1"
        || u32::from_le_bytes(input[8..12].try_into().unwrap_or([0; 4])) != 1
        || usize::from(u16::from_le_bytes(
            input[12..14].try_into().unwrap_or([0; 2]),
        )) != control_abi::DOMAIN_LIMIT
        || input[14..16].iter().any(|byte| *byte != 0)
        || (0..control_abi::DOMAIN_LIMIT).any(|slot| container_state(slot) != 0)
    {
        return false;
    }
    let Some(supervisor) = domain::control_plane_id() else {
        return false;
    };
    for slot in 0..control_abi::DOMAIN_LIMIT {
        let start = 16 + slot * control_abi::DOMAIN_REQUEST_SIZE;
        let request: &[u8; control_abi::DOMAIN_REQUEST_SIZE] =
            match input[start..start + control_abi::DOMAIN_REQUEST_SIZE].try_into() {
                Ok(request) => request,
                Err(_) => return false,
            };
        if request.iter().all(|byte| *byte == 0) {
            continue;
        }
        let name = container_request_name(request);
        let init = container_request_init(request);
        let image = container_request_image(request);
        let personality = domain_request_personality(request);
        let flags = read_u16_at(request, 34);
        let cpu_count = read_u16_at(request, 70);
        let memory_mib = read_u64_at(request, 200);
        if read_u32_at(request, 0) != control_abi::DOMAIN_REQUEST_SIZE as u32
            || read_u16_at(request, 4) != control_abi::DOMAIN_REQUEST_VERSION
            || !valid_container_name(name)
            || container_slot_by_name(name).is_some()
            || !valid_container_init(init)
            || !valid_container_image(image)
            || !valid_domain_personality(personality)
            || cpu_count == 0
            || memory_mib == 0
            || flags
                & !(control_abi::DOMAIN_CONFIG_COMPLETE
                    | control_abi::DOMAIN_CONFIG_AUTOSTART
                    | control_abi::DOMAIN_CONFIG_USER_SWITCHING
                    | control_abi::DOMAIN_CONFIG_WRITE_EXECUTE
                    | control_abi::DOMAIN_CONFIG_PRIVILEGED)
                != 0
            || flags
                & (control_abi::DOMAIN_CONFIG_INIT
                    | control_abi::DOMAIN_CONFIG_CPU
                    | control_abi::DOMAIN_CONFIG_MEMORY
                    | control_abi::DOMAIN_CONFIG_PERSONALITY)
                != control_abi::DOMAIN_CONFIG_INIT
                    | control_abi::DOMAIN_CONFIG_CPU
                    | control_abi::DOMAIN_CONFIG_MEMORY
                    | control_abi::DOMAIN_CONFIG_PERSONALITY
        {
            return false;
        }
        let Some(container_domain) =
            domain::create_container_domain(supervisor, slot, cpu_count, memory_mib)
        else {
            return false;
        };
        X86_RUNTIME.CONTAINER_DOMAIN_IDS[slot].store(container_domain, Ordering::Release);
        X86_RUNTIME.CONTAINER_CPU_COUNTS[slot].store(cpu_count, Ordering::Release);
        X86_RUNTIME.CONTAINER_MEMORY_MIB[slot].store(memory_mib, Ordering::Release);
        store_container_name(slot, name);
        store_container_value(
            init,
            &X86_RUNTIME.CONTAINER_INITS[slot],
            &X86_RUNTIME.CONTAINER_INIT_SIZES[slot],
        );
        store_container_value(
            image,
            &X86_RUNTIME.CONTAINER_IMAGES[slot],
            &X86_RUNTIME.CONTAINER_IMAGE_SIZES[slot],
        );
        store_container_value(
            personality,
            &X86_RUNTIME.DOMAIN_PERSONALITIES[slot],
            &X86_RUNTIME.DOMAIN_PERSONALITY_SIZES[slot],
        );
        X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot].store(flags, Ordering::Release);
        let state =
            if flags & control_abi::DOMAIN_CONFIG_COMPLETE == control_abi::DOMAIN_CONFIG_COMPLETE {
                control_abi::DOMAIN_STATE_CONFIGURED
            } else {
                control_abi::DOMAIN_STATE_CREATED
            };
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].store(state as u8, Ordering::Release);
    }
    true
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
struct LinuxSyscallFrame {
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

impl LinuxSignalContext {
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
struct LinuxSignalStack {
    pointer: u64,
    flags: u32,
    padding: u32,
    size: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct LinuxSignalMachineContext {
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rax: u64,
    rcx: u64,
    rsp: u64,
    rip: u64,
    rflags: u64,
    cs: u16,
    gs: u16,
    fs: u16,
    ss: u16,
    error: u64,
    trap: u64,
    old_mask: u64,
    cr2: u64,
    fpstate: u64,
    reserved: [u64; 8],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct LinuxSignalUserContext {
    flags: u64,
    link: u64,
    stack: LinuxSignalStack,
    machine: LinuxSignalMachineContext,
    signal_mask: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct LinuxSignalInformation {
    signal: i32,
    error: i32,
    code: i32,
    padding: i32,
    fields: [u8; 112],
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
struct LinuxRtSignalFrame {
    restorer: u64,
    context: LinuxSignalUserContext,
    information: LinuxSignalInformation,
}

struct LinuxRestoredSignalContext {
    user: LinuxUserContext,
    signal_mask: u64,
    rcx: u64,
    r11: u64,
}

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

fn configure_linux_syscall() -> Option<[u64; 5]> {
    // SYSRET loads SS from STAR[63:48] + 8 and CS from STAR[63:48] + 16.
    // Intel forces RPL 3 on both selectors, but AMD copies SS unchanged, so
    // the base must already carry RPL 3 or the next IRET to user mode faults.
    let sysret_base = u64::from(USER_DATA_SELECTOR) - 8;
    let star = (sysret_base << 48) | (u64::from(KERNEL_CODE_SELECTOR) << 32);
    let lstar = linox_linux_syscall_entry as *const () as u64;
    let fmask = (1_u64 << 9) | (1_u64 << 10) | (1_u64 << 18);
    unsafe {
        let saved = [
            read_msr(EFER_MSR),
            read_msr(STAR_MSR),
            read_msr(LSTAR_MSR),
            read_msr(FMASK_MSR),
            read_msr(FS_BASE_MSR),
        ];
        write_msr(STAR_MSR, star);
        write_msr(LSTAR_MSR, lstar);
        write_msr(FMASK_MSR, fmask);
        write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_SCE);
        let valid = read_msr(STAR_MSR) == star
            && read_msr(LSTAR_MSR) == lstar
            && read_msr(FMASK_MSR) == fmask
            && read_msr(EFER_MSR) & EFER_SCE != 0;
        if valid {
            Some(saved)
        } else {
            let _ = restore_linux_syscall(saved);
            None
        }
    }
}

fn restore_linux_syscall(saved: [u64; 5]) -> bool {
    unsafe {
        write_msr(FS_BASE_MSR, saved[4]);
        write_msr(FMASK_MSR, saved[3]);
        write_msr(LSTAR_MSR, saved[2]);
        write_msr(STAR_MSR, saved[1]);
        write_msr(EFER_MSR, saved[0]);
        read_msr(EFER_MSR) == saved[0]
            && read_msr(STAR_MSR) == saved[1]
            && read_msr(LSTAR_MSR) == saved[2]
            && read_msr(FMASK_MSR) == saved[3]
            && read_msr(FS_BASE_MSR) == saved[4]
    }
}

pub(crate) fn verify_breakpoint() -> bool {
    BREAKPOINT_HANDLED.store(false, Ordering::SeqCst);
    // SAFETY: Vector 3 is installed as a present interrupt gate and its handler
    // preserves the interrupted register state before returning with IRETQ.
    unsafe { asm!("int3", options(nomem, nostack)) };
    BREAKPOINT_HANDLED.load(Ordering::SeqCst)
}

extern "sysv64" fn breakpoint_handler() {
    BREAKPOINT_HANDLED.store(true, Ordering::SeqCst);
    serial_write("linox: breakpoint exception handled\r\n");
}

extern "sysv64" fn syscall_handler(number: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    let _kernel_entry = crate::sync::kernel_entry_lock();
    let cpu = current_cpu_index();
    let Some(probe_state) = X86_RUNTIME.PROCESS_CHILD_PROBE_STATE.get(cpu) else {
        return u64::MAX;
    };
    match probe_state.load(Ordering::SeqCst) {
        PROCESS_CHILD_PROBE_EXPECT_CONTEXT => {
            let valid = (!frame.is_null())
                .then(|| unsafe { &*frame })
                .is_some_and(|frame| {
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
            let exit_status = (!frame.is_null())
                .then(|| unsafe { &*frame })
                .filter(|_| {
                    number == LINUX_EXIT_SYSCALL
                        && active_fs_base()
                            == X86_RUNTIME
                                .PROCESS_CHILD_EXPECTED_FS_BASE
                                .get(cpu)
                                .expect("current processor index is bounded")
                                .load(Ordering::SeqCst)
                })
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
        return exit_result(caller_domain, frame);
    }
    if !domain::begin_operation(caller_domain) {
        return u64::MAX;
    }
    let result = if !domain::charge_call(caller_domain) {
        CALL_BUDGET_EXHAUSTED
    } else {
        dispatch_charged_call(number, capability, caller_domain, frame)
    };
    if !domain::end_operation(caller_domain) {
        return u64::MAX;
    }
    result
}

fn linux_controller_syscall(
    number: u64,
    registers: LinuxSyscallFrame,
    user_stack: u64,
    user_rip: u64,
    user_rflags: u64,
) -> Option<u64> {
    let domain_id = X86_RUNTIME.LINUX_CONTROLLER_DOMAIN.load(Ordering::Acquire);
    if domain_id == 0 || scheduler::current_domain() != Some(domain_id) {
        return None;
    }
    let first = registers.rdi;
    let second = registers.rsi;
    let third = registers.rdx;
    match number {
        LINUX_READ_SYSCALL if linux_socket_pipe_descriptor(first, LINUX_DESCRIPTOR_INPUT) => {
            Some(linux_controller_pipe_read(first, second, third))
        }
        LINUX_READ_SYSCALL if first == 0 && third != 0 => {
            let capability = X86_RUNTIME.LINUX_CONTROLLER_CONSOLE.load(Ordering::Acquire);
            if !domain::handle_permits(domain_id, capability, 2, Rights::READ) {
                return Some(LINUX_EBADF);
            }
            if !crate::serial_input_ready() && queue_background_container_work() {
                let mut frame = UserTrapFrame::from_linux_syscall(
                    registers.into_array(),
                    user_rip,
                    user_stack,
                    user_rflags,
                    second,
                    third,
                );
                if !scheduler::suspend_container_lifecycle(
                    &mut frame,
                    USER_CODE_SELECTOR,
                    USER_DATA_SELECTOR,
                    0,
                    active_fs_base(),
                ) {
                    return Some(LINUX_EIO);
                }
                return Some(LINUX_RETURN_TO_KERNEL);
            }
            let byte = crate::serial_read_byte_blocking();
            if !address_space::copy_to_current_user(second, &[byte]) {
                return Some(LINUX_EFAULT);
            }
            Some(1)
        }
        LINUX_READ_SYSCALL => Some(if first == 0 { 0 } else { LINUX_EBADF }),
        LINUX_WRITE_SYSCALL if linux_socket_pipe_descriptor(first, LINUX_DESCRIPTOR_OUTPUT) => {
            Some(linux_controller_pipe_write(first, second, third))
        }
        LINUX_WRITE_SYSCALL if matches!(first, 1 | 2) => {
            let Ok(length) = usize::try_from(third) else {
                return Some(LINUX_EINVAL);
            };
            if length == 0 {
                return Some(0);
            }
            if length > control_abi::MAX_BUFFERED_CONSOLE_BYTES as usize {
                return Some(LINUX_EINVAL);
            }
            let capability = X86_RUNTIME.LINUX_CONTROLLER_CONSOLE.load(Ordering::Acquire);
            let mut bytes = [0_u8; control_abi::MAX_BUFFERED_CONSOLE_BYTES as usize];
            if !domain::handle_permits(domain_id, capability, 2, Rights::WRITE)
                || !address_space::copy_from_current_user(second, &mut bytes[..length])
            {
                return Some(LINUX_EFAULT);
            }
            crate::serial_write_bytes(&bytes[..length]);
            Some(third)
        }
        LINUX_WRITE_SYSCALL => Some(LINUX_EBADF),
        LINUX_IOCTL_SYSCALL if second == linox_native_abi::LINOX_CONTROL_IOCTL => {
            let capability = match first {
                1 | 2 => X86_RUNTIME.LINUX_CONTROLLER_CONSOLE.load(Ordering::Acquire),
                3 => X86_RUNTIME.LINUX_CONTROLLER_HOST.load(Ordering::Acquire),
                4 => X86_RUNTIME.LINUX_CONTROLLER_ROOT.load(Ordering::Acquire),
                5 => X86_RUNTIME.LINUX_CONTROLLER_NETWORK.load(Ordering::Acquire),
                _ => return Some(LINUX_EBADF),
            };
            let mut request = [0_u8; linox_native_abi::LINOX_CONTROL_IOCTL_SIZE as usize];
            if !address_space::copy_from_current_user(third, &mut request)
                || u32::from_ne_bytes(request[0..4].try_into().unwrap())
                    != linox_native_abi::LINOX_CONTROL_IOCTL_SIZE
                || u16::from_ne_bytes(request[4..6].try_into().unwrap())
                    != linox_native_abi::LINOX_CONTROL_IOCTL_VERSION
                || request[6..8] != [0, 0]
            {
                return Some(LINUX_EFAULT);
            }
            let operation = u64::from_ne_bytes(request[8..16].try_into().unwrap());
            let operation_first = u64::from_ne_bytes(request[16..24].try_into().unwrap());
            let operation_second = u64::from_ne_bytes(request[24..32].try_into().unwrap());
            let mut frame = UserTrapFrame::from_linux_syscall(
                registers.into_array(),
                user_rip,
                user_stack,
                user_rflags,
                operation_first,
                operation_second,
            );
            let result = syscall_handler(operation, capability, &mut frame);
            Some(if scheduler::current_domain() == Some(domain_id) {
                result
            } else {
                LINUX_RETURN_TO_KERNEL
            })
        }
        LINUX_IOCTL_SYSCALL if linux_socket_pipe_descriptor(first, LINUX_DESCRIPTOR_INPUT) => {
            Some(linux_controller_pipe_ioctl(first, second, third))
        }
        LINUX_IOCTL_SYSCALL => Some(if linux_descriptor_open(first) {
            LINUX_ENOTTY
        } else {
            LINUX_EBADF
        }),
        LINUX_PIPE_SYSCALL => Some(linux_socket_pipe(
            first,
            0,
            6,
            address_space::copy_to_current_user,
        )),
        LINUX_PIPE2_SYSCALL => Some(linux_socket_pipe(
            first,
            second,
            6,
            address_space::copy_to_current_user,
        )),
        LINUX_POLL_SYSCALL => Some(linux_controller_poll(first, second, third)),
        LINUX_SELECT_SYSCALL | LINUX_PSELECT6_SYSCALL => Some(linux_select_with_copy(
            LinuxSelectInput {
                descriptor_count: first,
                read_address: second,
                write_address: third,
                exception_address: registers.r10,
                timeout_address: registers.r8,
                signal_mask_address: registers.r9,
            },
            number == LINUX_PSELECT6_SYSCALL,
            address_space::copy_from_current_user,
            address_space::copy_to_current_user,
        )),
        LINUX_DUP_SYSCALL => Some(linux_device_dup_at_least(first, 6, false)),
        LINUX_DUP2_SYSCALL => Some(linux_console_dup2(first, second)),
        LINUX_DUP3_SYSCALL => Some(linux_dup3(first, second, third)),
        LINUX_FCNTL_SYSCALL => Some(linux_descriptor_fcntl(first, second, third)),
        LINUX_CLOSE_SYSCALL => Some(linux_descriptor_close(first)),
        LINUX_SCHED_YIELD_SYSCALL => Some(0),
        LINUX_GETPID_SYSCALL | LINUX_GETTID_SYSCALL | LINUX_GETPGRP_SYSCALL => Some(1),
        LINUX_GETPPID_SYSCALL => Some(0),
        LINUX_GETUID_SYSCALL
        | LINUX_GETGID_SYSCALL
        | LINUX_GETEUID_SYSCALL
        | LINUX_GETEGID_SYSCALL => Some(0),
        LINUX_GETPGID_SYSCALL | LINUX_GETSID_SYSCALL => Some(if matches!(first as i32, 0 | 1) {
            1
        } else {
            LINUX_ESRCH
        }),
        LINUX_GETGROUPS_SYSCALL => Some(linux_controller_getgroups(first, second)),
        LINUX_UNAME_SYSCALL => Some(linux_uname_with_copy(
            first,
            address_space::copy_to_current_user,
        )),
        LINUX_CLOCK_GETTIME_SYSCALL => Some(linux_controller_clock_gettime(first, second)),
        LINUX_CLOCK_GETRES_SYSCALL => Some(linux_controller_clock_getres(first, second)),
        LINUX_GETTIMEOFDAY_SYSCALL => Some(linux_controller_gettimeofday(first, second)),
        LINUX_TIME_SYSCALL => Some(linux_controller_time(first)),
        LINUX_TIMES_SYSCALL => Some(linux_controller_times(first)),
        LINUX_GETRLIMIT_SYSCALL => Some(linux_getrlimit(
            first,
            second,
            true,
            address_space::copy_to_current_user,
        )),
        LINUX_SYSINFO_SYSCALL => {
            let Some(processes) =
                linux_process::host_live_process_count().and_then(|count| count.checked_add(1))
            else {
                return Some(LINUX_EOVERFLOW);
            };
            let Some(uptime) = linux_system_elapsed_time() else {
                return Some(LINUX_ENOSYS);
            };
            let information = match linux_sysinfo_information(processes, uptime) {
                Ok(information) => information,
                Err(error) => return Some(error),
            };
            Some(
                if address_space::copy_to_current_user(first, &information) {
                    0
                } else {
                    LINUX_EFAULT
                },
            )
        }
        LINUX_GETRANDOM_SYSCALL => Some(linux_getrandom_with_copy(
            first,
            second,
            third,
            address_space::copy_to_current_user,
        )),
        LINUX_EXIT_SYSCALL | LINUX_EXIT_GROUP_SYSCALL => {
            let mut frame = UserTrapFrame::from_linux_syscall(
                registers.into_array(),
                user_rip,
                user_stack,
                user_rflags,
                first,
                0,
            );
            let result = syscall_handler(2, 0, &mut frame);
            X86_RUNTIME
                .LINUX_CONTROLLER_DOMAIN
                .store(0, Ordering::Release);
            X86_RUNTIME
                .LINUX_CONTROLLER_CONSOLE
                .store(0, Ordering::Release);
            X86_RUNTIME
                .LINUX_CONTROLLER_HOST
                .store(0, Ordering::Release);
            X86_RUNTIME
                .LINUX_CONTROLLER_ROOT
                .store(0, Ordering::Release);
            X86_RUNTIME
                .LINUX_CONTROLLER_NETWORK
                .store(0, Ordering::Release);
            Some(if result == u64::MAX {
                LINUX_RETURN_TO_KERNEL
            } else {
                result
            })
        }
        _ => Some(LINUX_ENOSYS),
    }
}

fn linux_socket_pipe_descriptor(descriptor: u64, access: u16) -> bool {
    let device = linux_device_descriptor(descriptor);
    linux_socket_slot(descriptor).is_some()
        && device & (LINUX_DEVICE_SOCKET | LINUX_DEVICE_PIPE)
            == LINUX_DEVICE_SOCKET | LINUX_DEVICE_PIPE
        && device & 3 & access == access
}

fn linux_controller_getgroups(size: u64, output: u64) -> u64 {
    let size = size as i32;
    if size < 0 {
        return LINUX_EINVAL;
    }
    if size == 0 {
        return 1;
    }
    if !address_space::copy_to_current_user(output, &0_u32.to_ne_bytes()) {
        return LINUX_EFAULT;
    }
    1
}

fn linux_controller_poll(address: u64, count: u64, timeout: u64) -> u64 {
    let Ok(descriptor_count) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if descriptor_count > LINUX_POLLFD_LIMIT {
        return LINUX_EINVAL;
    }
    let timeout = timeout as u32 as i32;
    let duration = if timeout < 0 {
        None
    } else {
        Some((timeout as u64).saturating_mul(1_000_000))
    };
    let deadline = match duration {
        Some(0) | None => None,
        Some(duration) => {
            let Some(deadline) =
                linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
            else {
                return LINUX_EINVAL;
            };
            Some(deadline)
        }
    };
    let mut pollfds = [0_u8; LINUX_POLLFD_LIMIT * 8];
    let active = &mut pollfds[..descriptor_count * 8];
    if descriptor_count != 0 && !address_space::copy_from_current_user(address, active) {
        return LINUX_EFAULT;
    }
    loop {
        let mut ready = 0_u64;
        for pollfd in active.as_chunks_mut::<8>().0 {
            let descriptor = i32::from_ne_bytes(pollfd[..4].try_into().unwrap());
            let events = u16::from_ne_bytes(pollfd[4..6].try_into().unwrap());
            let returned = linux_descriptor_poll_events(descriptor, events);
            pollfd[6..8].copy_from_slice(&returned.to_ne_bytes());
            ready += u64::from(returned != 0);
        }
        let timed_out = duration == Some(0)
            || deadline.is_some_and(|deadline| {
                linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline)
            });
        if ready != 0 || timed_out {
            return if descriptor_count == 0 || address_space::copy_to_current_user(address, active)
            {
                ready
            } else {
                LINUX_EFAULT
            };
        }
        core::hint::spin_loop();
    }
}

fn linux_controller_clock_value(clock: u64) -> Option<(u64, u64)> {
    let clock = u64::from(clock as u32);
    let mut value = if matches!(
        clock,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_REALTIME_COARSE
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_TAI
    ) {
        linux_host_realtime_time()
    } else if matches!(
        clock,
        LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_PROCESS_CPUTIME_ID
            | LINUX_CLOCK_THREAD_CPUTIME_ID
            | LINUX_CLOCK_MONOTONIC_RAW
            | LINUX_CLOCK_MONOTONIC_COARSE
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_BOOTTIME_ALARM
    ) {
        linux_system_elapsed_time()
    } else {
        None
    }?;
    if matches!(
        clock,
        LINUX_CLOCK_REALTIME_COARSE | LINUX_CLOCK_MONOTONIC_COARSE
    ) {
        let resolution = NANOSECONDS_PER_SECOND / LINUX_CLOCK_TICKS_PER_SECOND;
        value.1 -= value.1 % resolution;
    }
    Some(value)
}

fn linux_controller_clock_gettime(clock: u64, output: u64) -> u64 {
    let Some((seconds, nanoseconds)) = linux_controller_clock_value(clock) else {
        return LINUX_EINVAL;
    };
    let mut timespec = [0_u8; 16];
    timespec[..8].copy_from_slice(&seconds.to_ne_bytes());
    timespec[8..].copy_from_slice(&nanoseconds.to_ne_bytes());
    if address_space::copy_to_current_user(output, &timespec) {
        0
    } else {
        LINUX_EFAULT
    }
}

fn linux_controller_clock_getres(clock: u64, output: u64) -> u64 {
    let clock = u64::from(clock as u32);
    if !linux_clock_supported(clock) {
        return LINUX_EINVAL;
    }
    if output == 0 {
        return 0;
    }
    let nanoseconds = if matches!(
        clock,
        LINUX_CLOCK_REALTIME_COARSE | LINUX_CLOCK_MONOTONIC_COARSE
    ) {
        NANOSECONDS_PER_SECOND / LINUX_CLOCK_TICKS_PER_SECOND
    } else {
        let Some(frequency) = timer::monotonic_frequency() else {
            return LINUX_ENOSYS;
        };
        NANOSECONDS_PER_SECOND.div_ceil(frequency).max(1)
    };
    let mut timespec = [0_u8; 16];
    timespec[8..].copy_from_slice(&nanoseconds.to_ne_bytes());
    if address_space::copy_to_current_user(output, &timespec) {
        0
    } else {
        LINUX_EFAULT
    }
}

fn linux_controller_gettimeofday(timeval: u64, timezone: u64) -> u64 {
    if timeval == 0 && timezone == 0 {
        return 0;
    }
    let Some((seconds, nanoseconds)) = linux_host_realtime_time() else {
        return LINUX_ENOSYS;
    };
    let mut output = [0_u8; 16];
    output[..8].copy_from_slice(&seconds.to_ne_bytes());
    output[8..].copy_from_slice(&(nanoseconds / 1_000).to_ne_bytes());
    if timeval != 0 && !address_space::copy_to_current_user(timeval, &output) {
        return LINUX_EFAULT;
    }
    if timezone != 0 && !address_space::copy_to_current_user(timezone, &[0; 8]) {
        return LINUX_EFAULT;
    }
    0
}

fn linux_controller_time(output: u64) -> u64 {
    let Some((seconds, _)) = linux_host_realtime_time() else {
        return LINUX_ENOSYS;
    };
    if output != 0 && !address_space::copy_to_current_user(output, &seconds.to_ne_bytes()) {
        return LINUX_EFAULT;
    }
    seconds
}

fn linux_controller_times(output: u64) -> u64 {
    let Some((seconds, nanoseconds)) = linux_system_elapsed_time() else {
        return LINUX_ENOSYS;
    };
    let ticks = seconds
        .saturating_mul(LINUX_CLOCK_TICKS_PER_SECOND)
        .saturating_add(
            nanoseconds.saturating_mul(LINUX_CLOCK_TICKS_PER_SECOND) / NANOSECONDS_PER_SECOND,
        );
    if output != 0 {
        let mut accounting = [0_u8; 32];
        accounting[..8].copy_from_slice(&ticks.to_ne_bytes());
        if !address_space::copy_to_current_user(output, &accounting) {
            return LINUX_EFAULT;
        }
    }
    ticks
}

fn linux_controller_pipe_read(descriptor: u64, address: u64, count: u64) -> u64 {
    let Some(slot) = linux_socket_slot(descriptor) else {
        return LINUX_EBADF;
    };
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if requested == 0 {
        return 0;
    }
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut total = 0_usize;
    while total < requested {
        let chunk = (requested - total).min(bytes.len());
        let result = if linux_socket_nonblocking(descriptor) {
            crate::linux_socket::recv(slot, &mut bytes[..chunk])
        } else {
            crate::linux_socket::recv_blocking(slot, &mut bytes[..chunk])
        };
        let received = match result {
            Ok((received, _)) => received,
            Err(error) => {
                return if total == 0 {
                    linux_socket_error(error)
                } else {
                    total as u64
                };
            }
        };
        if received != 0
            && !address_space::copy_to_current_user(address + total as u64, &bytes[..received])
        {
            return if total == 0 {
                LINUX_EFAULT
            } else {
                total as u64
            };
        }
        total += received;
        if received < chunk {
            break;
        }
    }
    total as u64
}

fn linux_controller_pipe_write(descriptor: u64, address: u64, count: u64) -> u64 {
    let Some(slot) = linux_socket_slot(descriptor) else {
        return LINUX_EBADF;
    };
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if requested == 0 {
        return 0;
    }
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut total = 0_usize;
    while total < requested {
        let chunk = (requested - total).min(bytes.len());
        if !address_space::copy_from_current_user(address + total as u64, &mut bytes[..chunk]) {
            return if total == 0 {
                LINUX_EFAULT
            } else {
                total as u64
            };
        }
        let result = if linux_socket_nonblocking(descriptor) {
            crate::linux_socket::send(slot, &bytes[..chunk], None)
        } else {
            crate::linux_socket::send_blocking(slot, &bytes[..chunk], None)
        };
        let sent = match result {
            Ok(sent) => sent,
            Err(error) => {
                return if total == 0 {
                    linux_socket_error(error)
                } else {
                    total as u64
                };
            }
        };
        total += sent;
        if sent < chunk {
            break;
        }
    }
    total as u64
}

/// Handles the ioctls Linux applies to every descriptor before asking the
/// file's own driver, by way of the equivalent fcntl calls.
/// The socket ioctls of Linux's sock_ioctl and inet: SIOCATMARK on TCP
/// (no urgent data is ever pending), and the interface queries SIOCGIF*
/// over the domain's loopback and eth0 (`linux_socket::interfaces`).
/// None for a request this is not, or a descriptor that is no socket.
fn linux_socket_ioctl(descriptor: u64, request: u64, argument: u64) -> Option<u64> {
    const SIOCATMARK: u64 = 0x8905;
    const SIOCGIFNAME: u64 = 0x8910;
    const SIOCGIFCONF: u64 = 0x8912;
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCSIFFLAGS: u64 = 0x8914;
    const SIOCGIFADDR: u64 = 0x8915;
    const SIOCGIFNETMASK: u64 = 0x891b;
    const SIOCGIFMTU: u64 = 0x8921;
    const SIOCSIFMTU: u64 = 0x8922;
    const SIOCGIFHWADDR: u64 = 0x8927;
    const SIOCGIFINDEX: u64 = 0x8933;
    const SIOCGIFTXQLEN: u64 = 0x8942;
    const IFREQ_SIZE: usize = 40;
    let request = u64::from(request as u32);
    if !matches!(
        request,
        SIOCATMARK
            | SIOCGIFNAME
            | SIOCGIFCONF
            | SIOCGIFFLAGS
            | SIOCSIFFLAGS
            | SIOCGIFADDR
            | SIOCGIFNETMASK
            | SIOCGIFMTU
            | SIOCSIFMTU
            | SIOCGIFHWADDR
            | SIOCGIFINDEX
            | SIOCGIFTXQLEN
    ) {
        return None;
    }
    let descriptor = u64::from(descriptor as u32);
    let slot = linux_socket_slot(descriptor).filter(|_| !linux_pipe_descriptor(descriptor))?;
    let kind = crate::linux_socket::kind(slot);
    if request == SIOCATMARK {
        if kind != Some(crate::linux_socket::Kind::Tcp) {
            return Some(LINUX_ENOTTY);
        }
        return Some(if copy_to_linux_user(argument, &0_i32.to_ne_bytes()) {
            0
        } else {
            LINUX_EFAULT
        });
    }
    let interfaces = linux_network_interfaces();
    let sockaddr_in = |address: u32| {
        let mut sockaddr = [0_u8; 16];
        sockaddr[..2].copy_from_slice(&2_u16.to_ne_bytes());
        sockaddr[4..8].copy_from_slice(&address.to_be_bytes());
        sockaddr
    };
    if request == SIOCGIFCONF {
        // struct ifconf: the buffer's length, then the buffer: one ifreq
        // (name and address) per interface, or the length needed when the
        // buffer is null.
        let mut ifconf = [0_u8; 16];
        if !copy_from_linux_user(argument, &mut ifconf) {
            return Some(LINUX_EFAULT);
        }
        let capacity = i32::from_ne_bytes(ifconf[..4].try_into().unwrap()).max(0) as usize;
        let buffer = u64::from_ne_bytes(ifconf[8..16].try_into().unwrap());
        let mut written = 0_usize;
        for interface in &interfaces {
            if buffer != 0 {
                if written + IFREQ_SIZE > capacity {
                    break;
                }
                let mut entry = [0_u8; IFREQ_SIZE];
                let name = interface.name.as_bytes();
                entry[..name.len()].copy_from_slice(name);
                entry[16..32].copy_from_slice(&sockaddr_in(interface.ipv4));
                if !copy_to_linux_user(buffer + written as u64, &entry) {
                    return Some(LINUX_EFAULT);
                }
            }
            written += IFREQ_SIZE;
        }
        return Some(
            if copy_to_linux_user(argument, &(written as i32).to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            },
        );
    }
    let mut ifreq = [0_u8; IFREQ_SIZE];
    if !copy_from_linux_user(argument, &mut ifreq) {
        return Some(LINUX_EFAULT);
    }
    let interface = if request == SIOCGIFNAME {
        let index = i32::from_ne_bytes(ifreq[16..20].try_into().unwrap());
        interfaces.iter().find(|interface| interface.index == index)
    } else {
        let name_length = ifreq[..16].iter().position(|byte| *byte == 0).unwrap_or(16);
        interfaces
            .iter()
            .find(|interface| interface.name.as_bytes() == &ifreq[..name_length])
    };
    let Some(interface) = interface else {
        return Some(LINUX_ENODEV);
    };
    match request {
        SIOCGIFNAME => {
            ifreq[..16].fill(0);
            let name = interface.name.as_bytes();
            ifreq[..name.len()].copy_from_slice(name);
        }
        SIOCGIFFLAGS => ifreq[16..18].copy_from_slice(&interface.flags.to_ne_bytes()),
        // Changing an interface takes CAP_NET_ADMIN. The domain's own stay
        // as the kernel set them up (EOPNOTSUPP for a change; setting what
        // they have is a success); a TUN or TAP device, and a network
        // namespace's loopback, go up and down and take another MTU.
        SIOCSIFFLAGS | SIOCSIFMTU => {
            if !current_linux_credentials().is_some_and(|credentials| {
                credentials.has(linox_credentials::capability::NET_ADMIN)
            }) {
                return Some(LINUX_EPERM);
            }
            let flags = u16::from_ne_bytes(ifreq[16..18].try_into().unwrap());
            let mtu = i32::from_ne_bytes(ifreq[16..20].try_into().unwrap());
            if request == SIOCSIFMTU && !(68..=65_536).contains(&mtu) {
                return Some(LINUX_EINVAL);
            }
            let network = current_linux_namespaces().net;
            let unchanged = if request == SIOCSIFMTU {
                mtu == interface.mtu
            } else {
                (flags ^ interface.flags) & LINUX_IFF_UP == 0
            };
            if interface.tun {
                let result = if request == SIOCSIFMTU {
                    crate::linux_socket::tun_set_link(
                        interface.index,
                        None,
                        u32::try_from(mtu).ok(),
                    )
                } else {
                    crate::linux_socket::tun_set_link(
                        interface.index,
                        Some(flags & LINUX_IFF_UP != 0),
                        None,
                    )
                };
                return Some(result.map_or_else(|errno| (-i64::from(errno)) as u64, |()| 0));
            }
            if network == 0 && !unchanged {
                return Some(LINUX_EOPNOTSUPP);
            }
            if network != 0 {
                let changed = linux_namespace::set_loopback(
                    linux_execution_instance(),
                    network,
                    |loopback| {
                        if request == SIOCSIFMTU {
                            loopback.mtu = mtu;
                        } else {
                            loopback.up = flags & LINUX_IFF_UP != 0;
                        }
                    },
                );
                if !changed {
                    return Some(LINUX_ENODEV);
                }
            }
            return Some(0);
        }
        SIOCGIFADDR => ifreq[16..32].copy_from_slice(&sockaddr_in(interface.ipv4)),
        SIOCGIFNETMASK => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(interface.prefix))
                .unwrap_or(0);
            ifreq[16..32].copy_from_slice(&sockaddr_in(mask));
        }
        SIOCGIFMTU => ifreq[16..20].copy_from_slice(&interface.mtu.to_ne_bytes()),
        // ifr_qlen: Linux's defaults, 500 for a TUN or TAP device's queue
        // and 1000 for the others.
        SIOCGIFTXQLEN => {
            let length: i32 = if interface.tun { 500 } else { 1000 };
            ifreq[16..20].copy_from_slice(&length.to_ne_bytes());
        }
        SIOCGIFHWADDR => {
            ifreq[16..18].copy_from_slice(&interface.hardware.0.to_ne_bytes());
            ifreq[18..24].copy_from_slice(&interface.hardware.1);
        }
        _ => ifreq[16..20].copy_from_slice(&interface.index.to_ne_bytes()),
    }
    Some(if copy_to_linux_user(argument, &ifreq) {
        0
    } else {
        LINUX_EFAULT
    })
}

/// Whether the current process's network namespace reaches `endpoint`
/// (INADDR_ANY is the local host, as connect takes it).
fn linux_endpoint_reachable(endpoint: smoltcp::wire::IpEndpoint) -> bool {
    match endpoint.addr {
        smoltcp::wire::IpAddress::Ipv4(address) if address.is_unspecified() => {
            linux_network_reaches(0x7f00_0001)
        }
        smoltcp::wire::IpAddress::Ipv4(address) => {
            linux_network_reaches(u32::from_be_bytes(address.octets()))
        }
        // IPv6 has loopback alone: no address or route on eth0.
        smoltcp::wire::IpAddress::Ipv6(address) => {
            (address.is_loopback() || address.is_unspecified())
                && linux_network_reaches(0x7f00_0001)
        }
    }
}

/// IFF_UP: an interface carries traffic.
const LINUX_IFF_UP: u16 = 0x1;

/// The interfaces the current process's network namespace has: the
/// domain's (loopback and eth0), or a namespace's own loopback alone,
/// with 127.0.0.1 only while it is up.
fn linux_network_interfaces() -> Vec<crate::linux_socket::InterfaceInfo> {
    const IFF_LOOPBACK: u16 = 0x8;
    const IFF_RUNNING: u16 = 0x40;
    const ARPHRD_LOOPBACK: u16 = 772;
    let network = current_linux_namespaces().net;
    if network == 0 {
        return crate::linux_socket::interfaces();
    }
    let loopback = linux_namespace::loopback(linux_execution_instance(), network).map(|loopback| {
        crate::linux_socket::InterfaceInfo {
            name: linox_tun::Name::new(b"lo").unwrap_or_else(|| unreachable!("a valid name")),
            index: 1,
            ipv4: if loopback.up { 0x7f00_0001 } else { 0 },
            prefix: if loopback.up { 8 } else { 0 },
            more_ipv4: Vec::new(),
            tun: false,
            flags: IFF_LOOPBACK
                | if loopback.up {
                    LINUX_IFF_UP | IFF_RUNNING
                } else {
                    0
                },
            mtu: loopback.mtu,
            hardware: (ARPHRD_LOOPBACK, [0; 6]),
        }
    });
    loopback.into_iter().collect()
}

/// Whether the current process's network namespace reaches IPv4 address
/// `address` (host order): the domain's reaches what its interfaces do; a
/// namespace made inside it only its loopback's 127.0.0.0/8, and only while
/// that is up.
fn linux_network_reaches(address: u32) -> bool {
    let network = current_linux_namespaces().net;
    network == 0
        || address >> 24 == 127
            && linux_namespace::loopback(linux_execution_instance(), network)
                .is_some_and(|loopback| loopback.up)
}

fn linux_generic_ioctl(descriptor: u64, request: u64, argument: u64) -> Option<u64> {
    if let Some(result) = linux_socket_ioctl(descriptor, request, argument) {
        return Some(result);
    }
    // PROCMAP_QUERY (_IOWR('f', 17, struct procmap_query)) on /proc/PID/maps.
    const PROCMAP_QUERY: u64 = 0xc068_6611;
    if u64::from(request as u32) == PROCMAP_QUERY
        && linux_device_descriptor(descriptor) & !3 == LINUX_FILE_PROC_DYNAMIC_MAPS
    {
        return Some(linux_procmap_query(descriptor, argument));
    }
    // RNDGETENTCNT on /dev/random and /dev/urandom: the pool is always
    // full (Linux reports 256 since 5.18), as entropy_avail says.
    const RNDGETENTCNT: u64 = 0x8004_5200;
    if u64::from(request as u32) == RNDGETENTCNT
        && linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_RANDOM
    {
        return Some(if copy_to_linux_user(argument, &256_i32.to_ne_bytes()) {
            0
        } else {
            LINUX_EFAULT
        });
    }
    match u64::from(request as u32) {
        LINUX_FIOCLEX => Some(linux_descriptor_fcntl(
            descriptor,
            LINUX_F_SETFD,
            u64::from(LINUX_FD_CLOEXEC),
        )),
        LINUX_FIONCLEX => Some(linux_descriptor_fcntl(descriptor, LINUX_F_SETFD, 0)),
        LINUX_FIONBIO => {
            let mut value = [0_u8; size_of::<i32>()];
            if !copy_from_linux_user(argument, &mut value) {
                return Some(LINUX_EFAULT);
            }
            let flags = linux_descriptor_fcntl(descriptor, LINUX_F_GETFL, 0);
            if flags >= u64::MAX - 4095 {
                return Some(flags);
            }
            let flags = if i32::from_ne_bytes(value) != 0 {
                flags | LINUX_O_NONBLOCK
            } else {
                flags & !LINUX_O_NONBLOCK
            };
            Some(linux_descriptor_fcntl(
                descriptor,
                LINUX_F_SETFL,
                flags & !LINUX_O_ACCMODE,
            ))
        }
        // FIOASYNC sets or clears O_ASYNC, as F_SETFL would (a file with
        // no signal-driven I/O keeps the flag and nothing comes of it).
        LINUX_FIOASYNC => {
            const O_ASYNC: u64 = 0o20_000;
            let mut value = [0_u8; size_of::<i32>()];
            if !copy_from_linux_user(argument, &mut value) {
                return Some(LINUX_EFAULT);
            }
            let flags = linux_descriptor_fcntl(descriptor, LINUX_F_GETFL, 0);
            if flags >= u64::MAX - 4095 {
                return Some(flags);
            }
            let flags = if i32::from_ne_bytes(value) != 0 {
                flags | O_ASYNC
            } else {
                flags & !O_ASYNC
            };
            let result =
                linux_descriptor_fcntl(descriptor, LINUX_F_SETFL, flags & !LINUX_O_ACCMODE);
            Some(if result < LINUX_RETURN_TO_KERNEL {
                0
            } else {
                result
            })
        }
        // FIONREAD on a regular file: the bytes from the file position to
        // its end (other files answer it themselves).
        LINUX_FIONREAD => {
            let stat = linux_descriptor_stat(descriptor)?;
            let mode = u32::from_ne_bytes(stat[24..28].try_into().unwrap());
            if mode & 0o170_000 != 0o100_000 || linux_socket_slot(descriptor).is_some() {
                return None;
            }
            let size = i64::from_ne_bytes(stat[48..56].try_into().unwrap());
            let position = linux_descriptor_offset(descriptor).load(Ordering::SeqCst) as i64;
            let remaining = size.saturating_sub(position) as i32;
            Some(if copy_to_linux_user(argument, &remaining.to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            })
        }
        _ => None,
    }
}

fn linux_controller_pipe_ioctl(descriptor: u64, request: u64, output: u64) -> u64 {
    if request != LINUX_FIONREAD {
        return LINUX_ENOTTY;
    }
    let Some(slot) = linux_socket_slot(descriptor) else {
        return LINUX_EBADF;
    };
    let available = match crate::linux_socket::local_queued_bytes(slot) {
        Ok(available) => available.min(i32::MAX as usize) as u32,
        Err(error) => return linux_socket_error(error),
    };
    if !address_space::copy_to_current_user(output, &available.to_ne_bytes()) {
        return LINUX_EFAULT;
    }
    0
}

pub(crate) fn linux_runtime_diagnostics() -> (Option<u8>, Option<u64>) {
    let status = X86_RUNTIME.LINUX_RUNTIME_EXIT_STATUS.load(Ordering::SeqCst);
    let syscall = X86_RUNTIME
        .LINUX_RUNTIME_FIRST_UNSUPPORTED_SYSCALL
        .load(Ordering::SeqCst);
    (
        u8::try_from(status).ok(),
        (syscall != u64::MAX).then_some(syscall),
    )
}

fn prepare_configured_linux_system_domain() -> bool {
    linux_prepare_securityfs();
    linux_prepare_hugetlbfs();
    linux_prepare_numa_sysfs();
    if !prepare_linux_package_platform() {
        return false;
    }
    let mut init = [0_u8; control_abi::DOMAIN_MAX_INIT_SIZE];
    let Some(init_size) = configured_container_init(&mut init) else {
        return false;
    };
    prepare_linux_system_domain(&init[..init_size])
}

fn prepare_linux_package_platform() -> bool {
    let rpm = b"usr/bin/rpm";
    let platform = b"etc/rpm/platform";
    let lower_has_rpm =
        crate::published_rootfs::lookup_metadata_at(crate::published_rootfs::ROOT_HANDLE, rpm)
            .and_then(|(_, entry)| entry)
            .is_some();
    let lower_has_platform =
        crate::published_rootfs::lookup_metadata_at(crate::published_rootfs::ROOT_HANDLE, platform)
            .and_then(|(_, entry)| entry)
            .is_some();
    !lower_has_rpm
        || lower_has_platform
        || crate::linux_overlay::lookup(platform).is_some()
        || crate::linux_overlay::create_file(platform, 0o644, b"x86_64-linux\n").is_some()
}

fn prepare_linux_system_domain(init: &[u8]) -> bool {
    if !matches!(
        init,
        b"/sbin/init" | b"sbin/init" | b"/usr/lib/systemd/systemd" | b"usr/lib/systemd/systemd"
    ) {
        return true;
    }
    for path in [
        &b"etc/systemd/system/console-getty.service"[..],
        &b"etc/systemd/system/getty.target"[..],
    ] {
        let masked =
            crate::published_rootfs::lookup_metadata_at(crate::published_rootfs::ROOT_HANDLE, path)
                .and_then(|(_, entry)| entry)
                .is_some_and(|entry| {
                    entry.kind == crate::published_rootfs::EntryKind::Symlink
                        && entry.link == b"/dev/null"
                });
        if masked && !crate::linux_overlay::whiteout(path) {
            return false;
        }
    }
    // Domain attachment grants access to the console, not an authenticated
    // root session. Use the distribution's login stack so the console has the
    // same authentication boundary as a physical Linux console.
    let contents = b"[Unit]\nDescription=Linox Domain Console Login\nAfter=systemd-user-sessions.service\n\n[Service]\nExecStart=-/sbin/agetty --noclear --keep-baud 115200,57600,38400,9600 - linux\nType=idle\nRestart=always\nStandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTTYReset=yes\nTTYVHangup=yes\nEnvironment=TERM=linux\n\n[Install]\nWantedBy=getty.target\n";
    let vendor_console = &b"usr/lib/systemd/system/console-getty.service"[..];
    if crate::linux_overlay::lookup(vendor_console).is_none()
        && crate::linux_overlay::create_file(vendor_console, 0o644, contents).is_none()
    {
        return false;
    }
    let configured_console = &b"etc/systemd/system/console-getty.service"[..];
    if crate::linux_overlay::lookup(configured_console).is_none()
        && crate::linux_overlay::create_symlink(
            configured_console,
            b"/usr/lib/systemd/system/console-getty.service",
        )
        .is_none()
    {
        return false;
    }
    let configured_getty_target = &b"etc/systemd/system/getty.target"[..];
    if crate::linux_overlay::lookup(configured_getty_target).is_none()
        && crate::linux_overlay::create_symlink(
            configured_getty_target,
            b"/usr/lib/systemd/system/getty.target",
        )
        .is_none()
    {
        return false;
    }
    // The OCI root is ephemeral today, so journald must remain volatile; a
    // persistent flush has no valid destination. configfs is implemented by
    // the Linox kernel directly and does not require a domain-side module.
    for (unit, description) in [
        (
            &b"usr/lib/systemd/system/systemd-journal-flush.service"[..],
            &b"Linox Volatile Journal"[..],
        ),
        (
            &b"usr/lib/systemd/system/modprobe@.service"[..],
            &b"Linox Built-in Kernel Facility"[..],
        ),
    ] {
        let mut replacement = [0_u8; 192];
        let prefix = b"[Unit]\nDescription=";
        let suffix = b"\nDefaultDependencies=no\n\n[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n";
        let length = prefix.len() + description.len() + suffix.len();
        replacement[..prefix.len()].copy_from_slice(prefix);
        replacement[prefix.len()..prefix.len() + description.len()].copy_from_slice(description);
        replacement[prefix.len() + description.len()..length].copy_from_slice(suffix);
        if crate::linux_overlay::lookup(unit).is_none()
            && crate::linux_overlay::create_file(unit, 0o644, &replacement[..length]).is_none()
        {
            return false;
        }
    }
    true
}

fn linux_privileged_operation(number: u64) -> Option<linux_user::PrivilegedOperation> {
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

/// The namespace `/proc/PID/ns/NAME` names: process PID's (`self` and
/// `thread-self` for the caller) namespace of that kind. `None` for any
/// other path; `Some(Err(ENOENT))` when the process or the name is unknown.
fn linux_proc_namespace_at(path: &[u8]) -> Option<Result<linux_namespace::Reference, u64>> {
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
            linux_process_runtime_state(pid)
                .filter(|state| state.valid)
                .and_then(|state| state.mount_namespace)
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
fn linux_namespace_link(reference: linux_namespace::Reference, output: &mut [u8; 32]) -> usize {
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
fn linux_namespace_stat(
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
fn linux_proc_namespace_stat(
    path: &[u8],
    follow: bool,
) -> Option<Result<[u8; LINUX_STAT_SIZE], u64>> {
    Some(linux_proc_namespace_at(path)?.map(|reference| linux_namespace_stat(reference, follow)))
}

fn linux_namespace_descriptor(descriptor: u64) -> bool {
    linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_NAMESPACE
}

/// The namespace a namespace descriptor (from /proc/PID/ns) refers to.
fn linux_namespace_reference(descriptor: u64) -> Option<linux_namespace::Reference> {
    if !linux_namespace_descriptor(descriptor) {
        return None;
    }
    linux_namespace::Reference::from_word(
        linux_descriptor_offset(descriptor).load(Ordering::SeqCst),
    )
}

/// A new descriptor for namespace `reference`, as opening /proc/PID/ns/NAME
/// or a NS_GET_* ioctl makes one.
fn linux_open_namespace(reference: linux_namespace::Reference, close_on_exec: bool) -> u64 {
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
fn linux_namespace_capable(owner: Option<linux_user::UserNamespaceHandle>) -> bool {
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
fn linux_namespace_ioctl(descriptor: u64, request: u64, argument: u64) -> u64 {
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
fn linux_setns(descriptor: u64, kind: u64) -> u64 {
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
            let Some(state) = linux_process_runtime_state(pid).filter(|state| state.valid) else {
                return LINUX_ESRCH;
            };
            // The process record says which namespace is current: it
            // changes first, then the installed one, and the namespace left
            // goes if nothing else uses it.
            let previous = state.mount_namespace.replace(target);
            if !linux_mount::switch_to(target) {
                state.mount_namespace = previous;
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
const LINUX_CLONE_NEW_KEPT: u64 = LINUX_CLONE_NEWUTS
    | LINUX_CLONE_NEWIPC
    | LINUX_CLONE_NEWPID
    | LINUX_CLONE_NEWTIME
    | LINUX_CLONE_NEWNET;
const LINUX_CLONE_NEWNET: u64 = 0x4000_0000;
const LINUX_CLONE_NEWTIME: u64 = 0x80;
/// The namespaces clone(2) (not clone3) may make for a new process; its
/// CLONE_NEWTIME bit is the exit signal's.
const LINUX_CLONE_PROCESS_NAMESPACES: u64 = LINUX_CLONE_NEWNS
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
fn linux_pid_seen_by(observer: u32, global: u32) -> u32 {
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
fn linux_pid_argument(argument: u64) -> Result<u64, ()> {
    let pid = argument as i32;
    if pid <= 0 {
        return Ok(argument);
    }
    linux_pid_from_caller(pid as u32).map(u64::from).ok_or(())
}

/// A thread id of the current process's: a process's main thread by its
/// number in the caller's PID namespace; other threads keep their ids.
fn linux_tid_argument(argument: u64) -> u64 {
    let tid = argument as i32;
    if tid <= 0 {
        return argument;
    }
    linux_pid_from_caller(tid as u32).map_or(argument, u64::from)
}

/// The current thread's id as it sees it: the main thread's is its
/// process's number in its PID namespace.
fn linux_tid_seen(tid: u32) -> u32 {
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
fn linux_end_pid_namespace(pid: u32) {
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
fn current_linux_namespaces() -> linux_namespace::Set {
    linux_process::live_process_namespaces(current_linux_process_pid()).unwrap_or_default()
}

/// `set` with the new namespaces CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWPID
/// and CLONE_NEWTIME in `flags` ask for, owned by `owner`, and copied from
/// the current process's: as a fork child's (`child`), which lives in the
/// new PID and time namespaces, or as unshare's caller's, whose children
/// will.
fn linux_create_namespaces(
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
fn linux_unshare(flags: u64) -> u64 {
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
        let Some(state) = linux_process_runtime_state(pid).filter(|state| state.valid) else {
            return LINUX_ESRCH;
        };
        let previous = linux_mount::current_handle();
        let Some(mount_namespace) = linux_clone_mount_namespace() else {
            return LINUX_ENOMEM;
        };
        // The process's record names its namespace from here on.
        state.mount_namespace = Some(mount_namespace);
        if !linux_mount::switch_to(mount_namespace) {
            state.mount_namespace = previous;
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
fn linux_clone_mount_namespace() -> Option<linux_mount::MountNamespaceHandle> {
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
fn linux_release_mount_namespace(namespace: linux_mount::MountNamespaceHandle) {
    if linux_mount::is_domain_root(namespace)
        || allocated_linux_process_records()
            .any(|record| record.runtime.mount_namespace == Some(namespace))
    {
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

/// Whether the current process's domain lets root use `operation` (a
/// domain set `privileged=true`, `linux_user::domain_privileged`).
fn linux_privileged_operation_allowed(operation: linux_user::PrivilegedOperation) -> bool {
    current_linux_user_namespace()
        .is_some_and(|namespace| !linux_user::privileged_operation_denied(namespace, operation))
}

fn linux_has_capability(capability: u32) -> bool {
    current_linux_credentials().is_some_and(|credentials| credentials.has(capability))
}

/// reboot(2) in a domain set `privileged=true` acts on the machine:
/// restart, halt and power-off stop the domain and shut the kernel down
/// cleanly, ending in a cold reset for a restart.
fn linux_reboot(magic: u64, magic2: u64, command: u64, argument: u64) -> u64 {
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
fn linux_acct(path_address: u64) -> u64 {
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
fn linux_account_exit(status: u32) {
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
fn linux_ioperm(from: u64, count: u64, turn_on: u64) -> u64 {
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
fn linux_iopl(level: u64) -> u64 {
    match level as u32 {
        0 => 0,
        1..=3 => LINUX_EPERM,
        _ => LINUX_EINVAL,
    }
}

/// vhangup(2): the caller has no controlling terminal of its own to hang
/// up in a domain, so it only checks authority.
fn linux_vhangup() -> u64 {
    if linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ManageTerminal)
        && linux_has_capability(linox_credentials::capability::SYS_TTY_CONFIG)
    {
        0
    } else {
        LINUX_EPERM
    }
}

/// delete_module(2): Linox loads no kernel modules, so none is found.
fn linux_delete_module(name: u64) -> u64 {
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
fn linux_syslog(action: u64, buffer: u64, length: u64) -> u64 {
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

fn linux_deny_privileged_operation(number: u64) -> u64 {
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

fn current_linux_user_namespace() -> Option<linux_user::UserNamespaceHandle> {
    linux_process::live_process_user_namespace(current_linux_process_pid())
}

fn current_linux_credentials() -> Option<linux_user::Credentials> {
    linux_process::live_process_credentials(current_linux_process_pid())
}

/// The mode a new file (not a directory) at canonical `path` is made with:
/// `mode` without set-group-ID where the creator may not have it (see
/// [`linux_new_file_identity`]), judged before the umask, then the umask,
/// as Linux's `vfs_prepare_mode` orders them.
fn linux_file_creation_mode(path: &[u8], mode: u32) -> u32 {
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
fn linux_set_current_identity(number: u64, first: u64, second: u64, third: u64) -> u64 {
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
fn linux_set_current_groups(size: u64, address: u64) -> u64 {
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
fn linux_get_current_groups(size: u64, address: u64) -> u64 {
    let Ok(size) = usize::try_from(size as i32) else {
        return LINUX_EINVAL;
    };
    linux_process::with_live_process_groups(current_linux_process_pid(), |groups| {
        if size == 0 {
            return groups.len() as u64;
        }
        if size < groups.len() {
            return LINUX_EINVAL;
        }
        let mut bytes = Vec::new();
        if bytes
            .try_reserve_exact(core::mem::size_of_val(groups))
            .is_err()
        {
            return LINUX_ENOMEM;
        }
        bytes.extend(groups.iter().flat_map(|group| group.to_ne_bytes()));
        if copy_to_linux_user(address, &bytes) {
            groups.len() as u64
        } else {
            LINUX_EFAULT
        }
    })
    .unwrap_or(LINUX_ESRCH)
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
/// extended (x87/SSE/AVX) register state.
struct LinuxProcessRecord {
    runtime: LinuxProcessRuntimeState,
    threads: [LinuxThreadRuntimeState; LINUX_THREAD_LIMIT],
    extended_states: [ExtendedState; LINUX_THREAD_LIMIT],
    extended_state_valid: [bool; LINUX_THREAD_LIMIT],
}

/// A process slot's record, once allocated: where it is and the frames it
/// was allocated from.
#[derive(Clone, Copy)]
struct LinuxProcessRecordSlot {
    record: *mut LinuxProcessRecord,
    first: memory::FrameLease,
}

impl LinuxProcessRecordSlot {
    const EMPTY: Self = Self {
        record: core::ptr::null_mut(),
        first: memory::FrameLease::EMPTY,
    };
}

/// Process slots whose records stay allocated once their process ended,
/// for the next process to reuse: a domain's usual processes. A record of
/// a slot above them is freed with its process, so a burst of thousands
/// of processes does not keep its records.
const LINUX_PROCESS_RECORDS_KEPT: usize = 256;

struct X86MutableRuntimeOwner {
    container_extended_states: UnsafeCell<[ExtendedState; control_abi::DOMAIN_LIMIT]>,
    /// One record per process slot of every domain instance, each table as
    /// long as the highest slot used. A record is over 100 KiB, so it is
    /// allocated from the frame allocator the first time a process
    /// occupies its slot instead of being reserved in the kernel image.
    process_records:
        UnsafeCell<[Vec<LinuxProcessRecordSlot>; LINUX_PROCESS_RUNTIME_INSTANCE_LIMIT]>,
    /// The running process's signal context, per CPU (`linux_cpu_bank`):
    /// CPUs run different processes, each with its handler's saved context.
    signal_context: [UnsafeCell<LinuxSignalContext>; LINUX_CPU_BANK_LIMIT],
}

// SAFETY: Gate 5 centralizes the legacy mutable runtime banks behind this
// owner. Gate 8 supplies cross-CPU synchronization before SMP activates them.
unsafe impl Sync for X86MutableRuntimeOwner {}

static X86_MUTABLE_RUNTIME: X86MutableRuntimeOwner = X86MutableRuntimeOwner {
    container_extended_states: UnsafeCell::new(
        [ExtendedState([0; EXTENDED_STATE_SIZE]); control_abi::DOMAIN_LIMIT],
    ),
    process_records: UnsafeCell::new([const { Vec::new() }; LINUX_PROCESS_RUNTIME_INSTANCE_LIMIT]),
    signal_context: [const { UnsafeCell::new(LinuxSignalContext::ZERO) }; LINUX_CPU_BANK_LIMIT],
};

/// The caller as System V IPC checks it.
fn linux_ipc_caller() -> crate::linux_sysv_ipc::Caller {
    current_linux_credentials().map_or(
        crate::linux_sysv_ipc::Caller {
            uid: 0,
            gid: 0,
            privileged: true,
        },
        |credentials| crate::linux_sysv_ipc::Caller {
            uid: credentials.user.effective,
            gid: credentials.group.effective,
            privileged: credentials.privileged(),
        },
    )
}

/// Wall-clock seconds for IPC times.
fn linux_ipc_now() -> i64 {
    linux_realtime_time().map_or(0, |(seconds, _)| seconds as i64)
}

/// After a get: the first get of a new object makes the caller its owner
/// and creator; a get of an existing key needs the access its mode bits
/// ask for (EACCES: msgget02, semget02, shmget04).
fn linux_ipc_got(
    kind: crate::linux_sysv_ipc::Kind,
    result: Result<u32, crate::linux_sysv_ipc::Error>,
    key: i32,
    flags: u64,
) -> u64 {
    let id = match result {
        Ok(id) => id,
        Err(error) => return linux_sysv_ipc_error(error),
    };
    let caller = linux_ipc_caller();
    match crate::linux_sysv_ipc::adopt(kind, id, caller, linux_ipc_now()) {
        Ok(false) if key != 0 => {
            crate::linux_sysv_ipc::check_access(kind, id, caller, flags as u16 & 0o777)
                .map_or_else(linux_sysv_ipc_error, |()| u64::from(id))
        }
        _ => u64::from(id),
    }
}

/// Fills an `ipc_perm`'s owner fields and an object's times into a
/// `*id_ds` (times at `time_offsets`, 0 to leave one out).
fn linux_ipc_fill_header(
    output: &mut [u8],
    kind: crate::linux_sysv_ipc::Kind,
    id: u32,
    time_offsets: [usize; 3],
) {
    let Ok((owner, times)) = crate::linux_sysv_ipc::header(kind, id) else {
        return;
    };
    output[4..8].copy_from_slice(&owner.uid.to_ne_bytes());
    output[8..12].copy_from_slice(&owner.gid.to_ne_bytes());
    output[12..16].copy_from_slice(&owner.cuid.to_ne_bytes());
    output[16..20].copy_from_slice(&owner.cgid.to_ne_bytes());
    for (offset, time) in time_offsets.into_iter().zip(times) {
        if offset != 0 {
            output[offset..offset + 8].copy_from_slice(&time.to_ne_bytes());
        }
    }
}

fn linux_sysv_ipc_error(error: crate::linux_sysv_ipc::Error) -> u64 {
    match error {
        crate::linux_sysv_ipc::Error::Access => LINUX_EACCES,
        crate::linux_sysv_ipc::Error::Permission => LINUX_EPERM,
        crate::linux_sysv_ipc::Error::Exists => LINUX_EEXIST,
        crate::linux_sysv_ipc::Error::Invalid => LINUX_EINVAL,
        crate::linux_sysv_ipc::Error::NoEntry => LINUX_ENOENT,
        crate::linux_sysv_ipc::Error::NoMemory => LINUX_ENOMEM,
        crate::linux_sysv_ipc::Error::NoSpace => LINUX_ENOSPC,
        crate::linux_sysv_ipc::Error::Range => LINUX_ERANGE,
        crate::linux_sysv_ipc::Error::WouldBlock => LINUX_EAGAIN,
        crate::linux_sysv_ipc::Error::TooBig => LINUX_E2BIG,
        crate::linux_sysv_ipc::Error::Fault => LINUX_EFAULT,
        crate::linux_sysv_ipc::Error::Busy => LINUX_EBUSY,
    }
}

fn linux_shmget(key: u64, size: u64, flags: u64) -> u64 {
    const IPC_CREAT: u64 = 0o1000;
    const IPC_EXCL: u64 = 0o2000;
    let flags = u64::from(flags as u32);
    if flags & !(0o777 | IPC_CREAT | IPC_EXCL | LINUX_SHM_HUGE_FLAGS) != 0 {
        return LINUX_EINVAL;
    }
    let key = key as u32 as i32;
    // A new segment of huge pages needs the caller's right to them and the
    // pool's pages (hugetlb_file_setup); an existing one is only found.
    let huge = flags & LINUX_SHM_HUGETLB != 0;
    if huge
        && (key == 0 || flags & IPC_CREAT != 0)
        && (key == 0
            || crate::linux_sysv_ipc::segments()
                .iter()
                .all(|(_, segment)| segment.key != key))
        && size >= 1
        && linux_proc_sysctl_value(b"sys/kernel/shmmax")
            .and_then(|largest| u64::try_from(largest).ok())
            .is_none_or(|largest| size <= largest)
    {
        if let Err(error) = linux_shm_huge_allowed(size, flags) {
            return error;
        }
    }
    let requested =
        linux_proc_sysctl_value(b"sys/kernel/shm_next_id").and_then(|id| u32::try_from(id).ok());
    let limit = linux_proc_sysctl_value(b"sys/kernel/shmmni")
        .and_then(|limit| usize::try_from(limit).ok())
        .unwrap_or(4096);
    let result = crate::linux_sysv_ipc::get_or_create(
        key,
        size,
        flags as u16,
        key == 0 || flags & IPC_CREAT != 0,
        flags & IPC_EXCL != 0,
        current_linux_process_pid(),
        crate::linux_sysv_ipc::SegmentIds {
            requested,
            limit,
            largest: linux_proc_sysctl_value(b"sys/kernel/shmmax")
                .and_then(|largest| u64::try_from(largest).ok())
                .unwrap_or(u64::MAX),
            huge,
        },
    );
    // shm_next_id is used up by the segment it named.
    if requested.is_some_and(|id| result == Ok(id)) {
        linux_proc_sysctl_set(b"sys/kernel/shm_next_id", -1);
    }
    linux_ipc_got(crate::linux_sysv_ipc::Kind::Segment, result, key, flags)
}

fn linux_shmat(id: u64, requested: u64, flags: u64) -> u64 {
    const SHM_RDONLY: u64 = 0o10_000;
    const SHM_RND: u64 = 0o20_000;
    const SHM_REMAP: u64 = 0o40_000;
    const SHM_EXEC: u64 = 0o100_000;
    const SHMLBA: u64 = PAGE_SIZE as u64;
    let id = id as i32;
    let flags = u64::from(flags as u32);
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return LINUX_ENOSYS;
    }
    if id < 0
        || flags & !(SHM_RDONLY | SHM_RND | SHM_REMAP | SHM_EXEC) != 0
        || flags & SHM_REMAP != 0
    {
        return LINUX_EINVAL;
    }
    if flags & SHM_EXEC != 0 && flags & SHM_RDONLY == 0 {
        return LINUX_EACCES;
    }
    let Ok(segment) = crate::linux_sysv_ipc::segment(id as u32) else {
        return LINUX_EINVAL;
    };
    // Reading needs read permission, and writing write (shmat02).
    let wanted = if flags & SHM_RDONLY != 0 {
        0o444
    } else {
        0o666
    };
    if let Err(error) = crate::linux_sysv_ipc::check_access(
        crate::linux_sysv_ipc::Kind::Segment,
        id as u32,
        linux_ipc_caller(),
        wanted,
    ) {
        return linux_sysv_ipc_error(error);
    }
    let _ = crate::linux_sysv_ipc::stamp(
        crate::linux_sysv_ipc::Kind::Segment,
        id as u32,
        crate::linux_sysv_ipc::TIME_OPERATION,
        linux_ipc_now(),
    );
    let Ok(pages) = usize::try_from(segment.size.div_ceil(PAGE_SIZE as u64)) else {
        return LINUX_ENOMEM;
    };
    let requested = if requested != 0 && flags & SHM_RND != 0 {
        requested & !(SHMLBA - 1)
    } else {
        requested
    };
    if requested != 0 && !requested.is_multiple_of(SHMLBA) {
        return LINUX_EINVAL;
    }
    let Some(address) = linux_runtime_select_mapping(requested, pages, requested != 0, false)
    else {
        return LINUX_ENOMEM;
    };
    if !linux_runtime_range_available(address, pages) {
        return LINUX_EINVAL;
    }
    let protection = if flags & SHM_EXEC != 0 {
        5
    } else if flags & SHM_RDONLY != 0 {
        1
    } else {
        3
    };
    for index in 0..pages {
        let Ok(frame) = crate::linux_sysv_ipc::frame(id as u32, index) else {
            let _ = rollback_linux_runtime_mapping(address, index);
            return LINUX_EINVAL;
        };
        if !address_space::install_current_linux_shared_page(
            address + (index * PAGE_SIZE) as u64,
            frame,
            protection,
        ) {
            let _ = rollback_linux_runtime_mapping(address, index);
            return LINUX_ENOMEM;
        }
    }
    if let Err(error) =
        crate::linux_sysv_ipc::attach(id as u32, address, current_linux_process_pid())
    {
        let _ = rollback_linux_runtime_mapping(address, pages);
        return linux_sysv_ipc_error(error);
    }
    address
}

fn linux_shmdt(address: u64) -> u64 {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || !address.is_multiple_of(PAGE_SIZE as u64)
    {
        return LINUX_EINVAL;
    }
    let Ok((id, length)) =
        crate::linux_sysv_ipc::attachment_at(address, current_linux_process_pid())
    else {
        return LINUX_EINVAL;
    };
    let result = linux_runtime_munmap(address, length);
    if result != 0 {
        return result;
    }
    let _ = crate::linux_sysv_ipc::stamp(
        crate::linux_sysv_ipc::Kind::Segment,
        id,
        crate::linux_sysv_ipc::TIME_DETACH,
        linux_ipc_now(),
    );
    crate::linux_sysv_ipc::detach(address, current_linux_process_pid())
        .map_or_else(linux_sysv_ipc_error, |()| 0)
}

fn linux_shmctl(id: u64, command: u64, address: u64) -> u64 {
    const IPC_RMID: u64 = 0;
    const IPC_SET: u64 = 1;
    const IPC_STAT: u64 = 2;
    const IPC_64: u64 = 0x100;
    let id = id as i32;
    let command = u64::from(command as u32);
    if id < 0 || command & !(IPC_64 | 0xff) != 0 {
        return LINUX_EINVAL;
    }
    let kind = crate::linux_sysv_ipc::Kind::Segment;
    let caller = linux_ipc_caller();
    const IPC_INFO: u64 = 3;
    const SHM_LOCK: u64 = 11;
    const SHM_UNLOCK: u64 = 12;
    const SHM_STAT: u64 = 13;
    const SHM_INFO: u64 = 14;
    const SHM_STAT_ANY: u64 = 15;
    const SHM_LOCKED: u16 = 0o2000;
    match command & !IPC_64 {
        // The limits (shmctl03), or the use (SHM_INFO); both return the
        // highest id in use, which is its index here.
        IPC_INFO | SHM_INFO => {
            let segments = crate::linux_sysv_ipc::segments();
            let highest = segments.iter().map(|(id, _)| *id).max().unwrap_or(0);
            let mut output = [0_u8; 48];
            if command & !IPC_64 == IPC_INFO {
                let sysctl = |path: &[u8], default: u64| {
                    linux_proc_sysctl_value(path).map_or(default, |value| value as u64)
                };
                let values = [
                    sysctl(b"sys/kernel/shmmax", 18_446_744_073_692_774_399),
                    1,
                    sysctl(b"sys/kernel/shmmni", 4096),
                    4096,
                    sysctl(b"sys/kernel/shmall", 18_446_744_073_692_774_399),
                ];
                for (index, value) in values.into_iter().enumerate() {
                    output[index * 8..index * 8 + 8].copy_from_slice(&value.to_ne_bytes());
                }
            } else {
                let pages: u64 = segments
                    .iter()
                    .map(|(_, segment)| segment.size.div_ceil(PAGE_SIZE as u64))
                    .sum();
                // Resident and swapped pages as /proc/sysvipc/shm lists
                // them: none counted (shmctl04 sums the listing).
                output[0..4].copy_from_slice(&(segments.len() as u32).to_ne_bytes());
                output[8..16].copy_from_slice(&pages.to_ne_bytes());
            }
            if copy_to_linux_user(address, &output) {
                u64::from(highest)
            } else {
                LINUX_EFAULT
            }
        }
        // By index (the id here): IPC_STAT's buffer, and the id.
        SHM_STAT | SHM_STAT_ANY => {
            let stat = if command & !IPC_64 == SHM_STAT_ANY {
                LINUX_IPC_STAT_UNCHECKED
            } else {
                IPC_STAT
            };
            let result = linux_shmctl(id as u64, stat | IPC_64, address);
            if result == 0 {
                id as u64
            } else {
                result
            }
        }
        // Locking needs the owner, the creator or root (shmctl02, shmctl07).
        SHM_LOCK | SHM_UNLOCK => {
            if let Err(error) = crate::linux_sysv_ipc::check_owner(kind, id as u32, caller) {
                return linux_sysv_ipc_error(error);
            }
            let (set, clear) = if command & !IPC_64 == SHM_LOCK {
                (SHM_LOCKED, 0)
            } else {
                (0, SHM_LOCKED)
            };
            crate::linux_sysv_ipc::update_mode(kind, id as u32, set, clear)
                .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        IPC_RMID => crate::linux_sysv_ipc::check_owner(kind, id as u32, caller)
            .and_then(|()| {
                crate::linux_sysv_ipc::mark_for_removal(id as u32, current_linux_process_pid())
            })
            .map_or_else(linux_sysv_ipc_error, |()| 0),
        IPC_SET => {
            let mut input = [0_u8; 112];
            if !copy_from_linux_user(address, &mut input) {
                return LINUX_EFAULT;
            }
            if let Err(error) = crate::linux_sysv_ipc::check_owner(kind, id as u32, caller) {
                return linux_sysv_ipc_error(error);
            }
            let _ = crate::linux_sysv_ipc::set_owner(
                kind,
                id as u32,
                u32::from_ne_bytes(input[4..8].try_into().unwrap()),
                u32::from_ne_bytes(input[8..12].try_into().unwrap()),
                linux_ipc_now(),
            );
            crate::linux_sysv_ipc::set_mode(
                id as u32,
                u16::from_ne_bytes(input[20..22].try_into().unwrap()),
                current_linux_process_pid(),
            )
            .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        IPC_STAT | LINUX_IPC_STAT_UNCHECKED => {
            let Ok(segment) = crate::linux_sysv_ipc::segment(id as u32) else {
                return LINUX_EINVAL;
            };
            if command & !IPC_64 == IPC_STAT {
                if let Err(error) =
                    crate::linux_sysv_ipc::check_access(kind, id as u32, caller, 0o444)
                {
                    return linux_sysv_ipc_error(error);
                }
            }
            let mut output = [0_u8; 112];
            linux_ipc_fill_header(&mut output, kind, id as u32, [56, 64, 72]);
            output[0..4].copy_from_slice(&segment.key.to_ne_bytes());
            output[20..22].copy_from_slice(&segment.mode.to_ne_bytes());
            output[48..56].copy_from_slice(&segment.size.to_ne_bytes());
            output[80..84].copy_from_slice(&segment.creator_pid.to_ne_bytes());
            output[84..88].copy_from_slice(&segment.last_pid.to_ne_bytes());
            output[88..96].copy_from_slice(&segment.attachments.to_ne_bytes());
            if !copy_to_linux_user(address, &output) {
                LINUX_EFAULT
            } else {
                0
            }
        }
        _ => LINUX_EINVAL,
    }
}

fn linux_semget(key: u64, count: u64, flags: u64) -> u64 {
    const IPC_CREAT: u64 = 0o1000;
    const IPC_EXCL: u64 = 0o2000;
    const LINUX_SEMMSL: u64 = 32_000;
    let count = count as i32;
    let flags = u64::from(flags as u32);
    if count < 0 || flags & !(0o777 | IPC_CREAT | IPC_EXCL) != 0 || count as u64 > LINUX_SEMMSL {
        return LINUX_EINVAL;
    }
    let key = key as u32 as i32;
    let result = crate::linux_sysv_ipc::semaphore_get_or_create(
        key,
        count as u64,
        flags as u16,
        key == 0 || flags & IPC_CREAT != 0,
        flags & IPC_EXCL != 0,
        current_linux_process_pid(),
    );
    linux_ipc_got(crate::linux_sysv_ipc::Kind::Semaphores, result, key, flags)
}

fn linux_semaphore_operation(
    address: u64,
    index: usize,
) -> Option<crate::linux_sysv_ipc::SemaphoreOperation> {
    let address = address.checked_add((index as u64).checked_mul(6)?)?;
    let mut bytes = [0_u8; 6];
    copy_from_linux_user(address, &mut bytes).then_some(crate::linux_sysv_ipc::SemaphoreOperation {
        number: u16::from_ne_bytes(bytes[0..2].try_into().ok()?),
        operation: i16::from_ne_bytes(bytes[2..4].try_into().ok()?),
        flags: u16::from_ne_bytes(bytes[4..6].try_into().ok()?),
    })
}

/// `semop` and `semtimedop`: applies the operations, or waits until they
/// can be applied, the timeout passes, a signal arrives or the set is
/// removed (EIDRM). The wait outlives the call's restarts (a process other
/// than init yields by restarting the call), so `GETNCNT`/`GETZCNT` see it
/// and a timeout counts from the first attempt.
fn linux_semop_live(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    (id, operations, count, timeout): (u64, u64, u64, u64),
) -> u64 {
    let timeout = if timeout == 0 {
        None
    } else {
        let mut bytes = [0_u8; 16];
        if !copy_from_linux_user(timeout, &mut bytes) {
            return LINUX_EFAULT;
        }
        let Some(timeout) = linux_timespec_nanoseconds(&bytes) else {
            return LINUX_EINVAL;
        };
        Some(timeout)
    };
    let pid = current_linux_process_pid();
    loop {
        let earlier = crate::linux_sysv_ipc::semaphore_wait(pid)
            .filter(|wait| u64::from(wait.id) == id as u32 as u64);
        let block = match linux_semop(id, operations, count) {
            Ok(None) => {
                crate::linux_sysv_ipc::end_semaphore_wait(pid);
                return 0;
            }
            Err(error) => {
                crate::linux_sysv_ipc::end_semaphore_wait(pid);
                return if error == LINUX_EINVAL && earlier.is_some() {
                    LINUX_EIDRM
                } else {
                    error
                };
            }
            Ok(Some(block)) => block,
        };
        let now = linux_elapsed_nanoseconds().unwrap_or(0);
        let deadline = earlier.map_or_else(
            || timeout.map(|timeout| now.saturating_add(timeout)),
            |wait| wait.deadline,
        );
        if deadline.is_some_and(|deadline| now >= deadline) {
            crate::linux_sysv_ipc::end_semaphore_wait(pid);
            return LINUX_EAGAIN;
        }
        let wait = crate::linux_sysv_ipc::SemaphoreWait {
            pid,
            id: id as u32,
            block,
            deadline,
        };
        if crate::linux_sysv_ipc::begin_semaphore_wait(wait).is_err() {
            return LINUX_ENOMEM;
        }
        match run_other_linux_processes(output, caller, number) {
            Some(LinuxBlockedWait::Recheck) => {}
            // Yielded: the call starts again and finds its wait.
            Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL)) => {
                return LINUX_RETURN_TO_KERNEL;
            }
            Some(LinuxBlockedWait::Return(result)) => {
                crate::linux_sysv_ipc::end_semaphore_wait(pid);
                return result;
            }
            None => {
                crate::linux_sysv_ipc::end_semaphore_wait(pid);
                return LINUX_EINTR;
            }
        }
    }
}

/// Applies `semop`'s operations once: `Ok(None)` when applied,
/// `Ok(Some(block))` when the call has to wait.
fn linux_semop(
    id: u64,
    operations: u64,
    count: u64,
) -> Result<Option<crate::linux_sysv_ipc::SemaphoreBlock>, u64> {
    const LINUX_SEMOPM: usize = 500;
    let id = id as i32;
    if id < 0 {
        return Err(LINUX_EINVAL);
    }
    let Ok(count) = usize::try_from(count) else {
        return Err(LINUX_E2BIG);
    };
    if count == 0 || count > LINUX_SEMOPM {
        return Err(if count > LINUX_SEMOPM {
            LINUX_E2BIG
        } else {
            LINUX_EINVAL
        });
    }
    // Unreadable operations are EFAULT, a semaphore past the set's EFBIG
    // (semop02), before anything is applied.
    let Ok(set) = crate::linux_sysv_ipc::semaphore_set(id as u32) else {
        return Err(LINUX_EINVAL);
    };
    for index in 0..count {
        let Some(operation) = linux_semaphore_operation(operations, index) else {
            return Err(LINUX_EFAULT);
        };
        if u64::from(operation.number) >= set.count {
            return Err(LINUX_EFBIG);
        }
    }
    // Any operation that changes a value needs write permission, waiting
    // for zero read.
    let alters = (0..count).any(|index| {
        linux_semaphore_operation(operations, index)
            .is_some_and(|operation| operation.operation != 0)
    });
    crate::linux_sysv_ipc::check_access(
        crate::linux_sysv_ipc::Kind::Semaphores,
        id as u32,
        linux_ipc_caller(),
        if alters { 0o222 } else { 0o444 },
    )
    .map_err(linux_sysv_ipc_error)?;
    let applied = crate::linux_sysv_ipc::semaphore_apply(
        id as u32,
        count,
        current_linux_process_pid(),
        |index| linux_semaphore_operation(operations, index),
    )
    .map_err(linux_sysv_ipc_error)?;
    if applied.is_none() {
        let _ = crate::linux_sysv_ipc::stamp(
            crate::linux_sysv_ipc::Kind::Semaphores,
            id as u32,
            crate::linux_sysv_ipc::TIME_OPERATION,
            linux_ipc_now(),
        );
    }
    Ok(applied)
}

fn linux_semctl(id: u64, number: u64, command: u64, argument: u64) -> u64 {
    const IPC_RMID: u64 = 0;
    const IPC_SET: u64 = 1;
    const IPC_STAT: u64 = 2;
    const IPC_64: u64 = 0x100;
    const GETPID: u64 = 11;
    const GETVAL: u64 = 12;
    const GETALL: u64 = 13;
    const GETNCNT: u64 = 14;
    const GETZCNT: u64 = 15;
    const SETVAL: u64 = 16;
    const SETALL: u64 = 17;
    let id = id as i32;
    let number = number as i32;
    let command = u64::from(command as u32);
    if id < 0 || number < 0 || command & !(IPC_64 | 0xff) != 0 {
        return LINUX_EINVAL;
    }
    let id = id as u32;
    let number = number as usize;
    let kind = crate::linux_sysv_ipc::Kind::Semaphores;
    let caller = linux_ipc_caller();
    // Reading values needs read permission, changing them write
    // (semctl02, semctl04).
    let wanted = match command & !IPC_64 {
        IPC_STAT | GETPID | GETVAL | GETALL | GETNCNT | GETZCNT => Some(0o444),
        SETVAL | SETALL => Some(0o222),
        _ => None,
    };
    if let Some(wanted) = wanted {
        if let Err(error) = crate::linux_sysv_ipc::check_access(kind, id, caller, wanted) {
            return linux_sysv_ipc_error(error);
        }
    }
    if matches!(command & !IPC_64, IPC_RMID | IPC_SET) {
        if let Err(error) = crate::linux_sysv_ipc::check_owner(kind, id, caller) {
            return linux_sysv_ipc_error(error);
        }
    }
    if matches!(command & !IPC_64, SETVAL | SETALL) {
        let _ = crate::linux_sysv_ipc::stamp(
            kind,
            id,
            crate::linux_sysv_ipc::TIME_CHANGE,
            linux_ipc_now(),
        );
    }
    const IPC_INFO: u64 = 3;
    const SEM_STAT: u64 = 18;
    const SEM_INFO: u64 = 19;
    const SEM_STAT_ANY: u64 = 20;
    match command & !IPC_64 {
        // struct seminfo: the limits, or with SEM_INFO the sets and
        // semaphores in use; the highest id in use (semctl01, semop02).
        IPC_INFO | SEM_INFO => {
            let sets = crate::linux_sysv_ipc::semaphore_sets();
            let highest = sets.iter().map(|(id, _)| *id).max().unwrap_or(0);
            let (usz, aem) = if command & !IPC_64 == IPC_INFO {
                (20, 32_767)
            } else {
                (
                    sets.len() as i32,
                    sets.iter().map(|(_, set)| set.count as i32).sum::<i32>(),
                )
            };
            let values = [
                32_000,
                crate::linux_sysv_ipc::SEMAPHORE_SET_LIMIT as i32,
                1_024_000_000,
                32_000,
                32_000,
                500,
                500,
                usz,
                32_767,
                aem,
            ];
            let mut output = [0_u8; 40];
            for (index, value) in values.into_iter().enumerate() {
                output[index * 4..index * 4 + 4].copy_from_slice(&value.to_ne_bytes());
            }
            if copy_to_linux_user(argument, &output) {
                u64::from(highest)
            } else {
                LINUX_EFAULT
            }
        }
        SEM_STAT | SEM_STAT_ANY => {
            let stat = if command & !IPC_64 == SEM_STAT_ANY {
                LINUX_IPC_STAT_UNCHECKED
            } else {
                IPC_STAT
            };
            let result = linux_semctl(u64::from(id), number as u64, stat | IPC_64, argument);
            if result == 0 {
                u64::from(id)
            } else {
                result
            }
        }
        IPC_RMID => {
            crate::linux_sysv_ipc::semaphore_remove(id).map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        IPC_SET => {
            let mut input = [0_u8; 104];
            if !copy_from_linux_user(argument, &mut input) {
                return LINUX_EFAULT;
            }
            let _ = crate::linux_sysv_ipc::set_owner(
                kind,
                id,
                u32::from_ne_bytes(input[4..8].try_into().unwrap()),
                u32::from_ne_bytes(input[8..12].try_into().unwrap()),
                linux_ipc_now(),
            );
            crate::linux_sysv_ipc::semaphore_set_mode(
                id,
                u16::from_ne_bytes(input[20..22].try_into().unwrap()),
                current_linux_process_pid(),
            )
            .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        IPC_STAT | LINUX_IPC_STAT_UNCHECKED => {
            let Ok(set) = crate::linux_sysv_ipc::semaphore_set(id) else {
                return LINUX_EINVAL;
            };
            let mut output = [0_u8; 104];
            linux_ipc_fill_header(&mut output, kind, id, [48, 0, 64]);
            output[0..4].copy_from_slice(&set.key.to_ne_bytes());
            output[20..22].copy_from_slice(&set.mode.to_ne_bytes());
            output[80..88].copy_from_slice(&set.count.to_ne_bytes());
            if copy_to_linux_user(argument, &output) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        GETPID | GETVAL | GETNCNT | GETZCNT => {
            let Ok((value, pid, waiting_increase, waiting_zero)) =
                crate::linux_sysv_ipc::semaphore_get(id, number)
            else {
                return LINUX_EINVAL;
            };
            match command & !IPC_64 {
                GETPID => u64::from(pid),
                GETVAL => u64::from(value),
                GETNCNT => u64::from(waiting_increase),
                GETZCNT => u64::from(waiting_zero),
                _ => unreachable!(),
            }
        }
        SETVAL => {
            // The value is the union semun's int: Linux reads the low 32
            // bits of the argument (musl passes the whole union, whose
            // upper half is whatever the caller's stack held).
            let value = argument as u32 as i32;
            if value < 0 || value > i32::from(crate::linux_sysv_ipc::SEM_VALUE_MAX) {
                return LINUX_ERANGE;
            }
            crate::linux_sysv_ipc::semaphore_set_value(
                id,
                number,
                value as u16,
                current_linux_process_pid(),
            )
            .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        GETALL => {
            let Ok(set) = crate::linux_sysv_ipc::semaphore_set(id) else {
                return LINUX_EINVAL;
            };
            let Ok(count) = usize::try_from(set.count) else {
                return LINUX_EINVAL;
            };
            for index in 0..count {
                let Ok((value, _, _, _)) = crate::linux_sysv_ipc::semaphore_get(id, index) else {
                    return LINUX_EINVAL;
                };
                let Some(address) = argument.checked_add((index * 2) as u64) else {
                    return LINUX_EFAULT;
                };
                if !copy_to_linux_user(address, &value.to_ne_bytes()) {
                    return LINUX_EFAULT;
                }
            }
            0
        }
        SETALL => {
            crate::linux_sysv_ipc::semaphore_set_all(id, current_linux_process_pid(), |index| {
                let address = argument.checked_add((index * 2) as u64)?;
                let mut bytes = [0_u8; 2];
                copy_from_linux_user(address, &mut bytes).then_some(u16::from_ne_bytes(bytes))
            })
            .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        _ => LINUX_EINVAL,
    }
}

fn linux_msgget(key: u64, flags: u64) -> u64 {
    const IPC_CREAT: u64 = 0o1000;
    const IPC_EXCL: u64 = 0o2000;
    let flags = u64::from(flags as u32);
    if flags & !(0o777 | IPC_CREAT | IPC_EXCL) != 0 {
        return LINUX_EINVAL;
    }
    let key = key as u32 as i32;
    let requested =
        linux_proc_sysctl_value(b"sys/kernel/msg_next_id").and_then(|id| u32::try_from(id).ok());
    let limit = linux_proc_sysctl_value(b"sys/kernel/msgmni")
        .and_then(|limit| usize::try_from(limit).ok())
        .unwrap_or(32_000);
    let result = crate::linux_sysv_ipc::message_get_or_create(
        key,
        flags as u16,
        key == 0 || flags & IPC_CREAT != 0,
        flags & IPC_EXCL != 0,
        requested,
        limit,
    );
    // msg_next_id is used up by the queue it named.
    if requested.is_some_and(|id| result == Ok(id)) {
        linux_proc_sysctl_set(b"sys/kernel/msg_next_id", -1);
    }
    linux_ipc_got(crate::linux_sysv_ipc::Kind::Messages, result, key, flags)
}

/// msgsnd and msgrcv: `attempt` runs the call once. Without IPC_NOWAIT a
/// full queue or a missing message waits until the call completes, a signal
/// arrives (EINTR: neither call restarts after an SA_RESTART handler) or the
/// queue is removed (EIDRM); with it msgsnd fails with EAGAIN and msgrcv
/// with ENOMSG. The wait outlives the call's restarts, so a removal is seen
/// as one.
fn linux_message_wait_live(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    (id, flags): (u64, u64),
    mut attempt: impl FnMut() -> u64,
) -> u64 {
    const IPC_NOWAIT: u64 = 0o4000;
    let pid = current_linux_process_pid();
    loop {
        let waited = crate::linux_sysv_ipc::message_wait(pid) == Some(id as u32);
        let result = attempt();
        if result != LINUX_EAGAIN {
            crate::linux_sysv_ipc::end_message_wait(pid);
            return if result == LINUX_EINVAL && waited {
                LINUX_EIDRM
            } else {
                result
            };
        }
        if flags & IPC_NOWAIT != 0 {
            crate::linux_sysv_ipc::end_message_wait(pid);
            return if number == LINUX_MSGRCV_SYSCALL {
                LINUX_ENOMSG
            } else {
                LINUX_EAGAIN
            };
        }
        if crate::linux_sysv_ipc::begin_message_wait(pid, id as u32).is_err() {
            return LINUX_ENOMEM;
        }
        match run_other_linux_processes(output, caller, number) {
            Some(LinuxBlockedWait::Recheck) => {}
            // Yielded: the call starts again and finds its wait.
            Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL)) => {
                return LINUX_RETURN_TO_KERNEL;
            }
            Some(LinuxBlockedWait::Return(result)) => {
                crate::linux_sysv_ipc::end_message_wait(pid);
                return result;
            }
            None => {
                crate::linux_sysv_ipc::end_message_wait(pid);
                return LINUX_EINTR;
            }
        }
    }
}

fn linux_msgsnd(id: u64, message: u64, size: u64, flags: u64) -> u64 {
    const IPC_NOWAIT: u64 = 0o4000;
    const LINUX_MSGMAX: usize = 8192;
    let id = id as i32;
    let flags = u64::from(flags as u32);
    if id < 0 || flags & !IPC_NOWAIT != 0 {
        return LINUX_EINVAL;
    }
    let Ok(size) = usize::try_from(size) else {
        return LINUX_EINVAL;
    };
    if size > LINUX_MSGMAX {
        return LINUX_EINVAL;
    }
    if let Err(error) = crate::linux_sysv_ipc::check_access(
        crate::linux_sysv_ipc::Kind::Messages,
        id as u32,
        linux_ipc_caller(),
        0o222,
    ) {
        return linux_sysv_ipc_error(error);
    }
    let mut message_type = [0_u8; 8];
    if !copy_from_linux_user(message, &mut message_type) {
        return LINUX_EFAULT;
    }
    let sent = crate::linux_sysv_ipc::message_send(
        id as u32,
        i64::from_ne_bytes(message_type),
        size,
        current_linux_process_pid(),
        |offset, output| {
            message
                .checked_add(8)
                .and_then(|address| address.checked_add(offset as u64))
                .is_some_and(|address| copy_from_linux_user(address, output))
        },
    );
    if sent.is_ok() {
        let _ = crate::linux_sysv_ipc::stamp(
            crate::linux_sysv_ipc::Kind::Messages,
            id as u32,
            crate::linux_sysv_ipc::TIME_OPERATION,
            linux_ipc_now(),
        );
    }
    sent.map_or_else(linux_sysv_ipc_error, |()| 0)
}

fn linux_msgrcv(id: u64, message: u64, size: u64, selector: u64, flags: u64) -> u64 {
    const IPC_NOWAIT: u64 = 0o4000;
    const MSG_NOERROR: u64 = 0o10_000;
    const MSG_EXCEPT: u64 = 0o20_000;
    const MSG_COPY: u64 = 0o40_000;
    let id = id as i32;
    let flags = u64::from(flags as u32);
    if id < 0
        || flags & !(IPC_NOWAIT | MSG_NOERROR | MSG_EXCEPT | MSG_COPY) != 0
        || flags & MSG_COPY != 0
            && (flags & IPC_NOWAIT == 0 || flags & MSG_EXCEPT != 0 || (selector as i64) < 0)
    {
        return LINUX_EINVAL;
    }
    // MSG_EXCEPT only changes a positive type's search, as in Linux: a
    // negative one still takes the lowest type up to it (msgrcv02).
    let except = flags & MSG_EXCEPT != 0 && (selector as i64) > 0;
    // A negative size (as a long) is EINVAL (msgrcv02).
    if (size as i64) < 0 {
        return LINUX_EINVAL;
    }
    let Ok(size) = usize::try_from(size) else {
        return LINUX_EINVAL;
    };
    if let Err(error) = crate::linux_sysv_ipc::check_access(
        crate::linux_sysv_ipc::Kind::Messages,
        id as u32,
        linux_ipc_caller(),
        0o444,
    ) {
        return linux_sysv_ipc_error(error);
    }
    let received = crate::linux_sysv_ipc::message_receive(
        id as u32,
        size,
        selector as i64,
        flags & MSG_NOERROR != 0,
        except,
        flags & MSG_COPY != 0,
        current_linux_process_pid(),
        |message_type, offset, bytes| {
            (offset != 0 || copy_to_linux_user(message, &message_type.to_ne_bytes()))
                && message
                    .checked_add(8)
                    .and_then(|address| address.checked_add(offset as u64))
                    .is_some_and(|address| copy_to_linux_user(address, bytes))
        },
    );
    if received.is_ok() && flags & MSG_COPY == 0 {
        let _ = crate::linux_sysv_ipc::stamp(
            crate::linux_sysv_ipc::Kind::Messages,
            id as u32,
            crate::linux_sysv_ipc::TIME_RECEIVE,
            linux_ipc_now(),
        );
    }
    received.map_or_else(linux_sysv_ipc_error, |size| size as u64)
}

fn linux_msgctl(id: u64, command: u64, address: u64) -> u64 {
    const IPC_RMID: u64 = 0;
    const IPC_SET: u64 = 1;
    const IPC_STAT: u64 = 2;
    const IPC_64: u64 = 0x100;
    let id = id as i32;
    let command = u64::from(command as u32);
    if id < 0 || command & !(IPC_64 | 0xff) != 0 {
        return LINUX_EINVAL;
    }
    let id = id as u32;
    let kind = crate::linux_sysv_ipc::Kind::Messages;
    let caller = linux_ipc_caller();
    const IPC_INFO: u64 = 3;
    const MSG_STAT: u64 = 11;
    const MSG_INFO: u64 = 12;
    const MSG_STAT_ANY: u64 = 13;
    match command & !IPC_64 {
        // struct msginfo: the limits, or with MSG_INFO the queues, messages
        // and bytes in use; the highest id in use, its index (msgctl12).
        IPC_INFO | MSG_INFO => {
            let queues = crate::linux_sysv_ipc::message_queues();
            let highest = queues.iter().map(|(id, _)| *id).max().unwrap_or(0);
            let msgmni =
                linux_proc_sysctl_value(b"sys/kernel/msgmni").map_or(32_000, |value| value as i32);
            let (pool, map, tql) = if command & !IPC_64 == IPC_INFO {
                (msgmni.saturating_mul(16), 16_384, 16_384)
            } else {
                (
                    queues.len() as i32,
                    queues
                        .iter()
                        .map(|(_, queue)| queue.messages as i32)
                        .sum::<i32>(),
                    queues
                        .iter()
                        .map(|(_, queue)| queue.bytes as i32)
                        .sum::<i32>(),
                )
            };
            let mut output = [0_u8; 32];
            for (index, value) in [pool, map, 8192, 16_384, msgmni, 16, tql]
                .into_iter()
                .enumerate()
            {
                output[index * 4..index * 4 + 4].copy_from_slice(&value.to_ne_bytes());
            }
            output[28..30].copy_from_slice(&u16::MAX.to_ne_bytes());
            if copy_to_linux_user(address, &output) {
                u64::from(highest)
            } else {
                LINUX_EFAULT
            }
        }
        MSG_STAT | MSG_STAT_ANY => {
            let stat = if command & !IPC_64 == MSG_STAT_ANY {
                LINUX_IPC_STAT_UNCHECKED
            } else {
                IPC_STAT
            };
            let result = linux_msgctl(u64::from(id), stat | IPC_64, address);
            if result == 0 {
                u64::from(id)
            } else {
                result
            }
        }
        IPC_RMID => crate::linux_sysv_ipc::check_owner(kind, id, caller)
            .and_then(|()| crate::linux_sysv_ipc::message_queue_remove(id))
            .map_or_else(linux_sysv_ipc_error, |()| 0),
        IPC_SET => {
            let mut input = [0_u8; 120];
            if !copy_from_linux_user(address, &mut input) {
                return LINUX_EFAULT;
            }
            if let Err(error) = crate::linux_sysv_ipc::check_owner(kind, id, caller) {
                return linux_sysv_ipc_error(error);
            }
            let _ = crate::linux_sysv_ipc::set_owner(
                kind,
                id,
                u32::from_ne_bytes(input[4..8].try_into().unwrap()),
                u32::from_ne_bytes(input[8..12].try_into().unwrap()),
                linux_ipc_now(),
            );
            crate::linux_sysv_ipc::message_queue_set(
                id,
                u16::from_ne_bytes(input[20..22].try_into().unwrap()),
                u64::from_ne_bytes(input[88..96].try_into().unwrap()),
            )
            .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        IPC_STAT | LINUX_IPC_STAT_UNCHECKED => {
            let Ok(queue) = crate::linux_sysv_ipc::message_queue_info(id) else {
                return LINUX_EINVAL;
            };
            if command & !IPC_64 == IPC_STAT {
                if let Err(error) = crate::linux_sysv_ipc::check_access(kind, id, caller, 0o444) {
                    return linux_sysv_ipc_error(error);
                }
            }
            let mut output = [0_u8; 120];
            linux_ipc_fill_header(&mut output, kind, id, [48, 56, 64]);
            output[0..4].copy_from_slice(&queue.key.to_ne_bytes());
            output[20..22].copy_from_slice(&queue.mode.to_ne_bytes());
            output[72..80].copy_from_slice(&queue.bytes.to_ne_bytes());
            output[80..88].copy_from_slice(&queue.messages.to_ne_bytes());
            output[88..96].copy_from_slice(&queue.byte_limit.to_ne_bytes());
            output[96..100].copy_from_slice(&queue.last_sender.to_ne_bytes());
            output[100..104].copy_from_slice(&queue.last_receiver.to_ne_bytes());
            if copy_to_linux_user(address, &output) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        _ => LINUX_EINVAL,
    }
}

/// A message queue's name as the kernel receives it: the C library drops
/// the leading slash, so what remains is one path component of at most
/// NAME_MAX bytes (ENAMETOOLONG); a slash, ".", or ".." is EACCES, as a
/// lookup in Linux's mqueue filesystem answers.
fn linux_mq_name(address: u64, output: &mut [u8; 256]) -> Result<usize, u64> {
    let length = copy_linux_c_string(address, output)?;
    let name = &output[..length];
    // Linux finds no entry for an empty name (ENOENT); glibc reports EINVAL
    // before asking, and musl does not check, so programs see EINVAL here.
    if name.is_empty() {
        return Err(LINUX_EINVAL);
    }
    if name.contains(&b'/') || name == b"." || name == b".." {
        return Err(LINUX_EACCES);
    }
    Ok(length)
}

fn linux_mq_descriptor_id(descriptor: u64) -> Option<u32> {
    (linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_POSIX_MQ)
        .then(|| u32::try_from(linux_descriptor_offset(descriptor).load(Ordering::SeqCst)).ok())
        .flatten()
}

const LINUX_MQ_PRIO_MAX: u64 = 32_768;
const LINUX_MSG_MSG_SIZE: u64 = 48;
const LINUX_POSIX_MSG_TREE_NODE_SIZE: u64 = 48;

fn linux_posix_queue_charge(info: crate::linux_sysv_ipc::PosixQueueInfo) -> Option<u64> {
    info.max_messages
        .checked_mul(info.max_message_size)?
        .checked_add(info.max_messages.checked_mul(LINUX_MSG_MSG_SIZE)?)?
        .checked_add(
            info.max_messages
                .min(LINUX_MQ_PRIO_MAX)
                .checked_mul(LINUX_POSIX_MSG_TREE_NODE_SIZE)?,
        )
}

fn linux_reserve_posix_queue_charge(info: crate::linux_sysv_ipc::PosixQueueInfo) -> bool {
    let Some(charge) = linux_posix_queue_charge(info) else {
        return false;
    };
    let limit = linux_resource_limit_values(
        LINUX_RLIMIT_MSGQUEUE,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    )
    .map_or(0, |values| values[0]);
    let mut used = X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::Acquire);
    loop {
        let Some(next) = used.checked_add(charge).filter(|next| *next <= limit) else {
            return false;
        };
        match X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.compare_exchange(
            used,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(current) => used = current,
        }
    }
}

fn linux_release_posix_queue_charge(
    destroyed: Option<crate::linux_sysv_ipc::PosixQueueInfo>,
) -> bool {
    let Some(info) = destroyed else {
        return true;
    };
    let Some(charge) = linux_posix_queue_charge(info) else {
        return false;
    };
    let mut used = X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::Acquire);
    loop {
        let Some(next) = used.checked_sub(charge) else {
            return false;
        };
        match X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.compare_exchange(
            used,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(current) => used = current,
        }
    }
}

fn linux_mq_open(name_address: u64, flags: u64, mode: u64, attributes: u64) -> u64 {
    let flags = u64::from(flags as u32);
    let mode = u64::from(mode as u32);
    let valid = 3 | LINUX_O_CREAT | LINUX_O_EXCL | LINUX_O_NONBLOCK | LINUX_O_CLOEXEC;
    if flags & !valid != 0
        || flags & 3 == 3
        || flags & LINUX_O_EXCL != 0 && flags & LINUX_O_CREAT == 0
    {
        return LINUX_EINVAL;
    }
    let mut name = [0_u8; 256];
    let length = match linux_mq_name(name_address, &mut name) {
        Ok(length) => length,
        Err(error) => return error,
    };
    // Linux's hard ceilings (HARD_MSGMAX, HARD_MSGSIZEMAX); below them an
    // unprivileged creator is held to /proc/sys/fs/mqueue's msg_max and
    // msgsize_max, and to queues_max queues.
    const HARD_MESSAGES: i64 = 65_536;
    const HARD_MESSAGE_SIZE: i64 = 16 * 1024 * 1024;
    let resource_privileged = current_linux_credentials()
        .is_some_and(|credentials| credentials.has(linox_credentials::capability::SYS_RESOURCE));
    let (max_messages, max_message_size) = if flags & LINUX_O_CREAT != 0 && attributes != 0 {
        let mut attr = [0_u8; 64];
        if !copy_from_linux_user(attributes, &mut attr) {
            return LINUX_EFAULT;
        }
        let max_messages = i64::from_ne_bytes(attr[8..16].try_into().unwrap());
        let max_message_size = i64::from_ne_bytes(attr[16..24].try_into().unwrap());
        let over_soft = max_messages > linux_mq_limit(b"sys/fs/mqueue/msg_max") as i64
            || max_message_size > linux_mq_limit(b"sys/fs/mqueue/msgsize_max") as i64;
        if max_messages <= 0
            || max_message_size <= 0
            || max_messages > HARD_MESSAGES
            || max_message_size > HARD_MESSAGE_SIZE
            || over_soft && !resource_privileged
        {
            return LINUX_EINVAL;
        }
        (max_messages as u32, max_message_size as u32)
    } else {
        (
            linux_mq_limit(b"sys/fs/mqueue/msg_default") as u32,
            linux_mq_limit(b"sys/fs/mqueue/msgsize_default") as u32,
        )
    };
    let requested = match flags & 3 {
        0 => 0o444,
        1 => 0o222,
        _ => 0o666,
    };
    let queues_limit =
        (!resource_privileged).then(|| linux_mq_limit(b"sys/fs/mqueue/queues_max") as usize);
    let info = match crate::linux_sysv_ipc::posix_queue_open(
        &name[..length],
        flags & LINUX_O_CREAT != 0,
        flags & LINUX_O_EXCL != 0,
        mode as u16 & !(X86_RUNTIME.ELF_PROBE_UMASK.load(Ordering::SeqCst) as u16),
        (max_messages, max_message_size),
        linux_ipc_caller(),
        requested,
        queues_limit,
    ) {
        Ok(info) => info,
        Err(error) => return linux_sysv_ipc_error(error),
    };
    if info.created && !linux_reserve_posix_queue_charge(info) {
        let unlinked = matches!(
            crate::linux_sysv_ipc::posix_queue_unlink(&name[..length]),
            Ok(None)
        );
        let destroyed = matches!(
            crate::linux_sysv_ipc::posix_queue_close(info.id),
            Ok(Some(_))
        );
        return if unlinked && destroyed {
            LINUX_EMFILE
        } else {
            LINUX_EIO
        };
    }
    let Ok(descriptor) = linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        if info.created {
            let _ = crate::linux_sysv_ipc::posix_queue_unlink(&name[..length]);
        }
        let closed = crate::linux_sysv_ipc::posix_queue_close(info.id)
            .ok()
            .is_some_and(linux_release_posix_queue_charge);
        if info.created && !closed {
            return LINUX_EIO;
        }
        return LINUX_EMFILE;
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device)
        .store(LINUX_DEVICE_POSIX_MQ | flags as u16 & 3, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags)
        .store((flags & LINUX_O_NONBLOCK) as u32, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(u64::from(info.id), Ordering::SeqCst);
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    descriptor
}

fn linux_mq_unlink(name_address: u64) -> u64 {
    let mut name = [0_u8; 256];
    let length = match linux_mq_name(name_address, &mut name) {
        Ok(length) => length,
        Err(error) => return error,
    };
    match crate::linux_sysv_ipc::posix_queue_unlink_by(&name[..length], linux_ipc_caller()) {
        Ok(destroyed) if linux_release_posix_queue_charge(destroyed) => 0,
        Ok(_) => LINUX_EIO,
        Err(error) => linux_sysv_ipc_error(error),
    }
}

/// A /proc/sys/fs/mqueue value: as the domain wrote it, else the default.
fn linux_mq_limit(path: &[u8]) -> u64 {
    linux_proc_sysctl_value(path)
        .and_then(|value| u64::try_from(value).ok())
        .or_else(|| {
            let (_, _, contents) = LINUX_PROC_SYSCTLS
                .iter()
                .find(|(_, name, _)| *name == path)?;
            core::str::from_utf8(contents).ok()?.trim().parse().ok()
        })
        .unwrap_or(0)
}

/// An mq_timedsend or mq_timedreceive timeout: an absolute CLOCK_REALTIME
/// time, in nanoseconds; None waits for ever.
fn linux_mq_timeout(address: u64) -> Result<Option<u64>, u64> {
    if address == 0 {
        return Ok(None);
    }
    let mut timeout = [0_u8; 16];
    if !copy_from_linux_user(address, &mut timeout) {
        return Err(LINUX_EFAULT);
    }
    linux_timespec_nanoseconds(&timeout)
        .map(Some)
        .ok_or(LINUX_EINVAL)
}

/// The domain's CLOCK_REALTIME in nanoseconds.
fn linux_mq_now() -> u64 {
    linux_realtime_time().map_or(0, |(seconds, nanoseconds)| {
        seconds
            .saturating_mul(NANOSECONDS_PER_SECOND)
            .saturating_add(nanoseconds)
    })
}

/// mq_timedsend and mq_timedreceive: `attempt` once, then, while the
/// queue is full (or empty) and the descriptor blocks, let the rest of
/// the domain run and try again, until the absolute `timeout` passes
/// (ETIMEDOUT) or a signal comes (EINTR).
fn linux_mq_wait_live(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    (descriptor, timeout): (u64, u64),
    mut attempt: impl FnMut() -> u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let Some(id) = linux_mq_descriptor_id(descriptor) else {
        return attempt();
    };
    let deadline = match linux_mq_timeout(timeout) {
        Ok(deadline) => deadline,
        Err(error) => return error,
    };
    let receiving = number == LINUX_MQ_TIMEDRECEIVE_SYSCALL;
    let waited = if receiving {
        id | crate::linux_sysv_ipc::RECEIVE_WAIT
    } else {
        id
    };
    let pid = current_linux_process_pid();
    loop {
        let result = attempt();
        let nonblocking =
            linux_socket_flags(descriptor).unwrap_or(0) & LINUX_O_NONBLOCK as u32 != 0;
        if result != LINUX_EAGAIN || nonblocking {
            crate::linux_sysv_ipc::end_message_wait(pid);
            return result;
        }
        if deadline.is_some_and(|deadline| linux_mq_now() >= deadline) {
            crate::linux_sysv_ipc::end_message_wait(pid);
            return LINUX_ETIMEDOUT;
        }
        if crate::linux_sysv_ipc::begin_message_wait(pid, waited).is_err() {
            return LINUX_ENOMEM;
        }
        match run_other_linux_processes(output, caller, number) {
            Some(LinuxBlockedWait::Recheck) => {}
            // Yielded: the call starts again and finds its wait.
            Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL)) => {
                return LINUX_RETURN_TO_KERNEL;
            }
            Some(LinuxBlockedWait::Return(result)) => {
                crate::linux_sysv_ipc::end_message_wait(pid);
                return result;
            }
            None => {
                crate::linux_sysv_ipc::end_message_wait(pid);
                return LINUX_EINTR;
            }
        }
    }
}

fn linux_mq_timedsend(
    descriptor: u64,
    message: u64,
    length: u64,
    priority: u64,
    timeout: u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let priority = u64::from(priority as u32);
    let Some(id) = linux_mq_descriptor_id(descriptor) else {
        return LINUX_EBADF;
    };
    if linux_device_descriptor(descriptor) & 3 == 0 {
        return LINUX_EBADF;
    }
    if priority >= 32_768 {
        return LINUX_EINVAL;
    }
    let _ = timeout;
    let Ok(info) = crate::linux_sysv_ipc::posix_queue_info(id) else {
        return LINUX_EBADF;
    };
    if length > info.max_message_size || info.messages >= info.max_messages {
        return if length > info.max_message_size {
            LINUX_EMSGSIZE
        } else {
            LINUX_EAGAIN
        };
    }
    let Ok(length_usize) = usize::try_from(length) else {
        return LINUX_EMSGSIZE;
    };
    if let Err(error) = crate::linux_sysv_ipc::message_send(
        id,
        (32_768 - priority) as i64,
        length_usize,
        current_linux_process_pid(),
        |offset, output| {
            // An empty message reads nothing (mq_timedsend01).
            output.is_empty()
                || message
                    .checked_add(offset as u64)
                    .is_some_and(|address| copy_from_linux_user(address, output))
        },
    ) {
        return linux_sysv_ipc_error(error);
    }
    // A message reaching an empty queue that no receiver waits on tells the
    // process registered with mq_notify, once (SI_MESGQ, from the sender).
    let waiting = crate::linux_sysv_ipc::posix_queue_receiver_waiting(id);
    if let Some(registration) = crate::linux_sysv_ipc::posix_queue_take_notification(id, waiting) {
        linux_mq_finish_registration(registration, true);
    }
    0
}

/// Ends an mq_notify registration: notified (a message came) or removed.
/// SIGEV_SIGNAL sends its signal when notified (SI_MESGQ, from the
/// sender); SIGEV_THREAD sends its cookie on its netlink socket with the
/// last byte NOTIFY_WOKENUP or NOTIFY_REMOVED, as Linux does, and lets go
/// of the socket.
fn linux_mq_finish_registration(registration: crate::linux_sysv_ipc::Registration, notified: bool) {
    const SI_MESGQ: i32 = -3;
    const NOTIFY_WOKENUP: u8 = 1;
    const NOTIFY_REMOVED: u8 = 2;
    match registration.notification {
        crate::linux_sysv_ipc::Notification::Signal { signal, value } if notified => {
            let _ = linux_queue_process_signal(
                registration.pid,
                u64::from(signal),
                SI_MESGQ,
                Some(value),
            );
        }
        crate::linux_sysv_ipc::Notification::Thread { socket, mut cookie } => {
            cookie[31] = if notified {
                NOTIFY_WOKENUP
            } else {
                NOTIFY_REMOVED
            };
            let _ = crate::linux_socket::deliver_netlink(socket, &cookie);
            let _ = crate::linux_socket::close(socket);
        }
        _ => {}
    }
}

fn linux_mq_timedreceive(
    descriptor: u64,
    message: u64,
    length: u64,
    priority: u64,
    timeout: u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let Some(id) = linux_mq_descriptor_id(descriptor) else {
        return LINUX_EBADF;
    };
    if linux_device_descriptor(descriptor) & 3 == 1 {
        return LINUX_EBADF;
    }
    let _ = timeout;
    let Ok(info) = crate::linux_sysv_ipc::posix_queue_info(id) else {
        return LINUX_EBADF;
    };
    if length < info.max_message_size {
        return LINUX_EMSGSIZE;
    }
    let Ok(length) = usize::try_from(length) else {
        return LINUX_EMSGSIZE;
    };
    crate::linux_sysv_ipc::message_receive(
        id,
        length,
        -32_768,
        false,
        false,
        false,
        current_linux_process_pid(),
        |kind, offset, bytes| {
            let priority_written = priority == 0
                || offset != 0
                || copy_to_linux_user(priority, &((32_768 - kind) as u32).to_ne_bytes());
            priority_written
                && (bytes.is_empty()
                    || message
                        .checked_add(offset as u64)
                        .is_some_and(|address| copy_to_linux_user(address, bytes)))
        },
    )
    .map_or_else(linux_sysv_ipc_error, |size| size as u64)
}

/// mq_notify: SIGEV_NONE, SIGEV_SIGNAL or SIGEV_THREAD registers the
/// caller for the queue's next message to an empty queue (EBUSY while
/// another process holds it), a null event removes its registration. The
/// event is checked before the descriptor, as Linux does. SIGEV_THREAD
/// names a netlink socket (sigev_signo) and a 32-byte cookie (sigev_value
/// points at it), which the C library's helper thread reads back.
fn linux_mq_notify(descriptor: u64, event: u64) -> u64 {
    const SIGEV_SIGNAL: i32 = 0;
    const SIGEV_NONE: i32 = 1;
    const SIGEV_THREAD: i32 = 2;
    let descriptor = u64::from(descriptor as u32);
    let notification = if event == 0 {
        None
    } else {
        let mut value = [0_u8; 16];
        if !copy_from_linux_user(event, &mut value) {
            return LINUX_EFAULT;
        }
        let signal = i32::from_ne_bytes(value[8..12].try_into().unwrap());
        match i32::from_ne_bytes(value[12..16].try_into().unwrap()) {
            SIGEV_NONE => Some(crate::linux_sysv_ipc::Notification::Quiet),
            SIGEV_SIGNAL if (1..=LINUX_SIGNAL_COUNT as i32).contains(&signal) => {
                Some(crate::linux_sysv_ipc::Notification::Signal {
                    signal: signal as u8,
                    value: u64::from_ne_bytes(value[..8].try_into().unwrap()),
                })
            }
            SIGEV_THREAD => {
                let mut cookie = [0_u8; 32];
                let cookie_address = u64::from_ne_bytes(value[..8].try_into().unwrap());
                if !copy_from_linux_user(cookie_address, &mut cookie) {
                    return LINUX_EFAULT;
                }
                let socket_descriptor = u64::from(signal as u32);
                let Some(socket) = linux_socket_slot(socket_descriptor) else {
                    return linux_not_socket_error(socket_descriptor);
                };
                if crate::linux_socket::kind(socket) != Some(crate::linux_socket::Kind::Netlink) {
                    return LINUX_ECONNREFUSED;
                }
                Some(crate::linux_sysv_ipc::Notification::Thread { socket, cookie })
            }
            _ => return LINUX_EINVAL,
        }
    };
    let Some(id) = linux_mq_descriptor_id(descriptor) else {
        return LINUX_EBADF;
    };
    // The registration holds a reference to its socket until it ends.
    if let Some(crate::linux_sysv_ipc::Notification::Thread { socket, .. }) = notification {
        if !crate::linux_socket::duplicate(socket) {
            return LINUX_ENOMEM;
        }
    }
    match crate::linux_sysv_ipc::posix_queue_set_notification(
        id,
        current_linux_process_pid(),
        notification,
    ) {
        Ok(removed) => {
            if let Some(removed) = removed {
                linux_mq_finish_registration(removed, false);
            }
            0
        }
        Err(error) => {
            if let Some(crate::linux_sysv_ipc::Notification::Thread { socket, .. }) = notification {
                let _ = crate::linux_socket::close(socket);
            }
            linux_sysv_ipc_error(error)
        }
    }
}

fn linux_mq_getsetattr(descriptor: u64, new: u64, old: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let Some(id) = linux_mq_descriptor_id(descriptor) else {
        return LINUX_EBADF;
    };
    let Ok(info) = crate::linux_sysv_ipc::posix_queue_info(id) else {
        return LINUX_EBADF;
    };
    let flags = linux_socket_flags(descriptor).unwrap_or(0) & LINUX_O_NONBLOCK as u32;
    if old != 0 {
        let mut attr = [0_u8; 64];
        attr[..8].copy_from_slice(&u64::from(flags).to_ne_bytes());
        attr[8..16].copy_from_slice(&info.max_messages.to_ne_bytes());
        attr[16..24].copy_from_slice(&info.max_message_size.to_ne_bytes());
        attr[24..32].copy_from_slice(&info.messages.to_ne_bytes());
        if !copy_to_linux_user(old, &attr) {
            return LINUX_EFAULT;
        }
    }
    if new != 0 {
        let mut attr = [0_u8; 64];
        if !copy_from_linux_user(new, &mut attr) {
            return LINUX_EFAULT;
        }
        let requested = u64::from_ne_bytes(attr[..8].try_into().unwrap());
        if requested & !LINUX_O_NONBLOCK != 0 {
            return LINUX_EINVAL;
        }
        linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags)
            .store(requested as u32, Ordering::SeqCst);
    }
    0
}

fn linux_aio_error(error: crate::linux_aio::Error) -> u64 {
    match error {
        crate::linux_aio::Error::Invalid => LINUX_EINVAL,
        crate::linux_aio::Error::NoMemory => LINUX_ENOMEM,
        crate::linux_aio::Error::Full => LINUX_EAGAIN,
    }
}

fn linux_io_setup(events: u64, output: u64) -> u64 {
    // nr_events is a 32-bit unsigned count: zero and counts whose event ring
    // would pass 256 MiB are invalid, and more than aio-max-nr is EAGAIN.
    const LINUX_AIO_EVENTS_LIMIT: u64 = 0x1000_0000 / 32;
    let events = u64::from(events as u32);
    if events == 0
        || events > LINUX_AIO_EVENTS_LIMIT
        || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
    {
        return LINUX_EINVAL;
    }
    if events > LINUX_AIO_MAX_NR {
        return LINUX_EAGAIN;
    }
    let mut old = [0_u8; 8];
    if !copy_from_linux_user(output, &mut old) {
        return LINUX_EFAULT;
    }
    if u64::from_ne_bytes(old) != 0 {
        return LINUX_EINVAL;
    }
    let Some(bytes) = events
        .checked_mul(32)
        .and_then(|bytes| bytes.checked_add(32))
    else {
        return LINUX_EINVAL;
    };
    let pages = bytes.div_ceil(PAGE_SIZE as u64);
    let mapping = linux_runtime_mmap(
        0,
        pages * PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if mapping >= LINUX_RETURN_TO_KERNEL {
        return mapping;
    }
    if let Err(error) =
        crate::linux_aio::create(current_linux_process_pid(), mapping, events, pages)
    {
        let _ = linux_runtime_munmap(mapping, pages * PAGE_SIZE as u64);
        return linux_aio_error(error);
    }
    let mut header = [0_u8; 32];
    header[..4].copy_from_slice(&(mapping as u32).to_ne_bytes());
    header[4..8].copy_from_slice(&(events as u32).to_ne_bytes());
    header[16..20].copy_from_slice(&0xa10a_10a1_u32.to_ne_bytes());
    header[28..32].copy_from_slice(&32_u32.to_ne_bytes());
    if !copy_to_linux_user(mapping, &header) || !copy_to_linux_user(output, &mapping.to_ne_bytes())
    {
        let _ = crate::linux_aio::destroy(current_linux_process_pid(), mapping);
        let _ = linux_runtime_munmap(mapping, pages * PAGE_SIZE as u64);
        return LINUX_EFAULT;
    }
    0
}

fn linux_io_destroy(context: u64) -> u64 {
    let pages = match crate::linux_aio::destroy(current_linux_process_pid(), context) {
        Ok(pages) => pages,
        Err(error) => return linux_aio_error(error),
    };
    linux_runtime_munmap(context, pages * PAGE_SIZE as u64)
}

fn linux_io_submit(context: u64, count: u64, pointers: u64) -> u64 {
    // As Linux: an unknown context, then a negative count, are EINVAL; a
    // count past the context's size submits what fits.
    if crate::linux_aio::info(current_linux_process_pid(), context).is_err() {
        return LINUX_EINVAL;
    }
    if (count as i64) < 0 {
        return LINUX_EINVAL;
    }
    let count = count.min(1024);
    let mut submitted = 0_u64;
    for index in 0..count {
        match crate::linux_aio::can_submit(current_linux_process_pid(), context) {
            Ok(true) => {}
            Ok(false) => {
                return if submitted == 0 {
                    LINUX_EAGAIN
                } else {
                    submitted
                }
            }
            Err(error) => {
                return if submitted == 0 {
                    linux_aio_error(error)
                } else {
                    submitted
                }
            }
        }
        let Some(pointer_address) = pointers.checked_add(index * 8) else {
            return if submitted == 0 {
                LINUX_EFAULT
            } else {
                submitted
            };
        };
        let mut pointer = [0_u8; 8];
        if !copy_from_linux_user(pointer_address, &mut pointer) {
            return if submitted == 0 {
                LINUX_EFAULT
            } else {
                submitted
            };
        }
        let object = u64::from_ne_bytes(pointer);
        let mut control = [0_u8; 64];
        if !copy_from_linux_user(object, &mut control) {
            return if submitted == 0 {
                LINUX_EFAULT
            } else {
                submitted
            };
        }
        let data = u64::from_ne_bytes(control[..8].try_into().unwrap());
        let opcode = u16::from_ne_bytes(control[16..18].try_into().unwrap());
        let descriptor = u32::from_ne_bytes(control[20..24].try_into().unwrap()) as u64;
        let buffer = u64::from_ne_bytes(control[24..32].try_into().unwrap());
        let length = u64::from_ne_bytes(control[32..40].try_into().unwrap());
        let offset = i64::from_ne_bytes(control[40..48].try_into().unwrap());
        let reserved = u64::from_ne_bytes(control[48..56].try_into().unwrap());
        // A request is checked as it is submitted, as Linux's io_submit_one:
        // its reserved field, its descriptor (EBADF), and that the
        // descriptor was opened for the transfer's direction (EBADF).
        let state = linux_device_descriptor(descriptor);
        let refusal = if reserved != 0 || offset < 0 {
            Some(LINUX_EINVAL)
        } else if !linux_descriptor_open(descriptor)
            || opcode == 0 && state & LINUX_DESCRIPTOR_INPUT == 0 && state & 3 != 0
            || opcode == 1 && state & LINUX_DESCRIPTOR_OUTPUT == 0 && state & 3 != 0
        {
            Some(LINUX_EBADF)
        } else {
            None
        };
        if let Some(error) = refusal {
            return if submitted == 0 { error } else { submitted };
        }
        let stream = linux_pipe_descriptor(descriptor) || linux_socket_slot(descriptor).is_some();
        let result = match opcode {
            // A pipe or socket has no offset to read at: the read takes what
            // is there now, EAGAIN when nothing is (io_submit04).
            0 if stream => linux_aio_stream_read(descriptor, buffer, length),
            0 => linux_regular_file_read_at(descriptor, buffer, length, offset as u64),
            1 => linux_regular_file_write_at(descriptor, buffer, length, offset as u64),
            2 | 3 => {
                if linux_descriptor_open(descriptor) {
                    0
                } else {
                    LINUX_EBADF
                }
            }
            _ => {
                return if submitted == 0 {
                    LINUX_EINVAL
                } else {
                    submitted
                }
            }
        };
        let event = crate::linux_aio::Event {
            data,
            object,
            result: result as i64,
            result2: 0,
        };
        if let Err(error) = crate::linux_aio::push(current_linux_process_pid(), context, event) {
            return if submitted == 0 {
                linux_aio_error(error)
            } else {
                submitted
            };
        }
        // IOCB_FLAG_RESFD: the completion also signals the eventfd named.
        const IOCB_FLAG_RESFD: u32 = 1;
        if u32::from_ne_bytes(control[56..60].try_into().unwrap()) & IOCB_FLAG_RESFD != 0 {
            linux_eventfd_signal(u64::from(u32::from_ne_bytes(
                control[60..64].try_into().unwrap(),
            )));
        }
        submitted += 1;
    }
    submitted
}

fn linux_io_getevents(
    context: u64,
    minimum: u64,
    maximum: u64,
    output: u64,
    timeout: u64,
    signal: u64,
) -> u64 {
    if minimum > maximum
        || maximum > 1024
        || crate::linux_aio::info(current_linux_process_pid(), context).is_err()
    {
        return LINUX_EINVAL;
    }
    let mut zero_timeout = false;
    if timeout != 0 {
        let mut value = [0_u8; 16];
        if !copy_from_linux_user(timeout, &mut value) {
            return LINUX_EFAULT;
        }
        let Some(duration) = linux_timespec_nanoseconds(&value) else {
            return LINUX_EINVAL;
        };
        zero_timeout = duration == 0;
    }
    if signal != 0 {
        let mut descriptor = [0_u8; 16];
        if !copy_from_linux_user(signal, &mut descriptor) {
            return LINUX_EFAULT;
        }
        let set = u64::from_ne_bytes(descriptor[..8].try_into().unwrap());
        let size = u64::from_ne_bytes(descriptor[8..].try_into().unwrap());
        // struct __aio_sigset: a null set means no mask, whatever the size.
        let mut mask = [0_u8; 8];
        if set != 0 && (size != 8 || !copy_from_linux_user(set, &mut mask)) {
            return if size != 8 {
                LINUX_EINVAL
            } else {
                LINUX_EFAULT
            };
        }
    }
    let mut received = 0_u64;
    while received < maximum {
        let event = match crate::linux_aio::pop(current_linux_process_pid(), context) {
            Ok(Some(event)) => event,
            Ok(None) => break,
            Err(error) => {
                return if received == 0 {
                    linux_aio_error(error)
                } else {
                    received
                }
            }
        };
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&event.data.to_ne_bytes());
        bytes[8..16].copy_from_slice(&event.object.to_ne_bytes());
        bytes[16..24].copy_from_slice(&event.result.to_ne_bytes());
        bytes[24..].copy_from_slice(&event.result2.to_ne_bytes());
        let Some(destination) = received
            .checked_mul(32)
            .and_then(|offset| output.checked_add(offset))
        else {
            return if received == 0 {
                LINUX_EFAULT
            } else {
                received
            };
        };
        if !copy_to_linux_user(destination, &bytes) {
            return if received == 0 {
                LINUX_EFAULT
            } else {
                received
            };
        }
        received += 1;
    }
    if received < minimum && !zero_timeout {
        return LINUX_EAGAIN;
    }
    received
}

/// io_cancel: the request's key is read first (EFAULT), must be 0
/// (KIOCB_KEY, else EINVAL), and the context must exist (EINVAL). Requests
/// complete as they are submitted here, so none is left to cancel
/// (EINVAL, as Linux answers for a completed one).
fn linux_io_cancel(context: u64, control: u64, _result: u64) -> u64 {
    let mut key = [0_u8; 4];
    if control
        .checked_add(8)
        .is_none_or(|address| !copy_from_linux_user(address, &mut key))
    {
        return LINUX_EFAULT;
    }
    let _ = crate::linux_aio::info(current_linux_process_pid(), context);
    LINUX_EINVAL
}

/// An AIO read from a pipe or socket: what is queued now, without waiting.
fn linux_aio_stream_read(descriptor: u64, buffer: u64, length: u64) -> u64 {
    let Some(slot) = linux_socket_slot(descriptor) else {
        return LINUX_EBADF;
    };
    let mut bytes = [0_u8; PAGE_SIZE];
    let length = usize::try_from(length).unwrap_or(PAGE_SIZE).min(PAGE_SIZE);
    match crate::linux_socket::recv(slot, &mut bytes[..length]) {
        Ok((received, _)) => {
            if received != 0 && !copy_to_linux_user(buffer, &bytes[..received]) {
                LINUX_EFAULT
            } else {
                received as u64
            }
        }
        Err(error) => linux_socket_error(error),
    }
}

fn linux_io_uring_descriptor(descriptor: u64) -> bool {
    linux_socket_flags(descriptor)
        .is_some_and(|flags| flags & LINUX_PRIVATE_IO_URING_DESCRIPTOR != 0)
}

/// The ring a descriptor stands for: its domain and its open file
/// description's id.
fn linux_io_uring_key(descriptor: u64) -> Option<(usize, u64)> {
    if !linux_io_uring_descriptor(descriptor) {
        return None;
    }
    linux_descriptor_open_file_id(descriptor).map(|id| (linux_execution_instance(), id))
}

/// Whether the current process may make a ring, as
/// /proc/sys/kernel/io_uring_disabled decides: 0 lets everyone, 1 only
/// those with CAP_SYS_ADMIN, 2 nobody.
fn linux_io_uring_allowed() -> bool {
    match linux_proc_sysctl_value(b"sys/kernel/io_uring_disabled").unwrap_or(0) {
        0 => true,
        1 => linux_has_capability(linox_credentials::capability::SYS_ADMIN),
        _ => false,
    }
}

fn linux_io_uring_setup(entries: u64, parameters: u64) -> u64 {
    use crate::linux_io_uring::{
        CQ_CQES, CQ_FLAGS, CQ_HEAD, CQ_OVERFLOW, CQ_RING_ENTRIES, CQ_RING_MASK, CQ_TAIL, SQ_ARRAY,
        SQ_DROPPED, SQ_FLAGS, SQ_HEAD, SQ_RING_ENTRIES, SQ_RING_MASK, SQ_TAIL,
    };
    const SETUP_CQSIZE: u32 = 1 << 3;
    const SETUP_CLAMP: u32 = 1 << 4;
    const FEAT_NODROP: u32 = 1 << 1;
    const FEAT_SUBMIT_STABLE: u32 = 1 << 2;
    const FEAT_RW_CUR_POS: u32 = 1 << 3;
    let entries = entries as u32;
    if !linux_io_uring_allowed() {
        return LINUX_EPERM;
    }
    let mut params = [0_u8; 120];
    if !copy_from_linux_user(parameters, &mut params) {
        return LINUX_EFAULT;
    }
    let field = |params: &[u8; 120], offset: usize| {
        u32::from_ne_bytes(params[offset..offset + 4].try_into().unwrap())
    };
    let flags = field(&params, 8);
    // Polling threads, other ring layouts and the rest are not offered.
    if flags & !(SETUP_CQSIZE | SETUP_CLAMP) != 0 || params[28..40].iter().any(|byte| *byte != 0) {
        return LINUX_EINVAL;
    }
    let cq_entries = (flags & SETUP_CQSIZE != 0).then(|| field(&params, 4));
    let Some((sq_entries, cq_entries)) =
        crate::linux_io_uring::sizes(entries, cq_entries, flags & SETUP_CLAMP != 0)
    else {
        return LINUX_EINVAL;
    };
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    params[..4].copy_from_slice(&sq_entries.to_ne_bytes());
    params[4..8].copy_from_slice(&cq_entries.to_ne_bytes());
    params[20..24]
        .copy_from_slice(&(FEAT_NODROP | FEAT_SUBMIT_STABLE | FEAT_RW_CUR_POS).to_ne_bytes());
    let sq_offsets = [
        SQ_HEAD,
        SQ_TAIL,
        SQ_RING_MASK,
        SQ_RING_ENTRIES,
        SQ_FLAGS,
        SQ_DROPPED,
        SQ_ARRAY,
    ];
    let cq_offsets = [
        CQ_HEAD,
        CQ_TAIL,
        CQ_RING_MASK,
        CQ_RING_ENTRIES,
        CQ_OVERFLOW,
        CQ_CQES,
        CQ_FLAGS,
    ];
    for (base, offsets) in [(40, &sq_offsets), (80, &cq_offsets)] {
        params[base..base + 40].fill(0);
        for (index, offset) in offsets.iter().enumerate() {
            let at = base + index * 4;
            params[at..at + 4].copy_from_slice(&(*offset as u32).to_ne_bytes());
        }
    }
    if !copy_to_linux_user(parameters, &params) {
        return LINUX_EFAULT;
    }
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device)
        .store(LINUX_DEVICE_ZERO | 3, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags)
        .store(LINUX_PRIVATE_IO_URING_DESCRIPTOR, Ordering::SeqCst);
    let created = linux_descriptor_open_file_id(descriptor).is_some_and(|id| {
        crate::linux_io_uring::create(
            linux_execution_instance(),
            id,
            current_linux_process_pid(),
            sq_entries,
            cq_entries,
        )
    });
    if !created {
        linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(0, Ordering::SeqCst);
        linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(0, Ordering::SeqCst);
        return LINUX_ENOMEM;
    }
    // A ring's descriptor is always close-on-exec, as in Linux.
    set_linux_descriptor_close_on_exec(descriptor, true);
    descriptor
}

/// mmap of a ring's descriptor: a shared area for the submission ring,
/// the completion ring or the submission entries, by `offset`.
fn linux_io_uring_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    descriptor: u64,
    offset: u64,
) -> u64 {
    use crate::linux_io_uring::{
        Region, CQ_RING_ENTRIES, CQ_RING_MASK, SQ_RING_ENTRIES, SQ_RING_MASK,
    };
    const MAP_TYPE: u64 = 0xf;
    let Some((domain, id)) = linux_io_uring_key(descriptor) else {
        return LINUX_EBADF;
    };
    let Some(region) = Region::from_offset(offset) else {
        return LINUX_EINVAL;
    };
    let Some(rings) = crate::linux_io_uring::rings(domain, id) else {
        return LINUX_EBADF;
    };
    if length == 0
        || length > region.size(&rings).next_multiple_of(PAGE_SIZE as u64)
        || !matches!(
            flags & MAP_TYPE,
            LINUX_MAP_SHARED | LINUX_MAP_SHARED_VALIDATE
        )
    {
        return LINUX_EINVAL;
    }
    let mapping = linux_runtime_mmap(
        address,
        length,
        protection,
        flags & !MAP_TYPE | LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if mapping >= LINUX_RETURN_TO_KERNEL {
        return mapping;
    }
    let (entries, mask, count) = match region {
        Region::SubmissionRing => (rings.sq_entries, SQ_RING_MASK, SQ_RING_ENTRIES),
        Region::CompletionRing => (rings.cq_entries, CQ_RING_MASK, CQ_RING_ENTRIES),
        Region::SubmissionEntries => (0, 0, 0),
    };
    let initialized = entries == 0
        || copy_to_linux_user(mapping + mask, &(entries - 1).to_ne_bytes())
            && copy_to_linux_user(mapping + count, &entries.to_ne_bytes());
    if initialized && crate::linux_io_uring::mapped(domain, id, region, mapping) {
        mapping
    } else {
        let _ = linux_runtime_munmap(mapping, length);
        LINUX_EFAULT
    }
}

/// One submission entry (struct io_uring_sqe), as io_uring_enter reads it.
struct LinuxIoUringEntry {
    opcode: u8,
    flags: u8,
    descriptor: u64,
    offset: u64,
    address: u64,
    length: u64,
    operation_flags: u64,
    user_data: [u8; 8],
    buffer_index: u16,
}

impl LinuxIoUringEntry {
    fn parse(sqe: &[u8; 64]) -> Self {
        let word = |offset: usize| u32::from_ne_bytes(sqe[offset..offset + 4].try_into().unwrap());
        let double =
            |offset: usize| u64::from_ne_bytes(sqe[offset..offset + 8].try_into().unwrap());
        Self {
            opcode: sqe[0],
            flags: sqe[1],
            descriptor: u64::from(word(4)),
            offset: double(8),
            address: double(16),
            length: u64::from(word(24)),
            operation_flags: u64::from(word(28)),
            user_data: sqe[32..40].try_into().unwrap(),
            buffer_index: u16::from_ne_bytes(sqe[40..42].try_into().unwrap()),
        }
    }
}

const LINUX_IORING_OP_NOP: u8 = 0;
const LINUX_IORING_OP_READV: u8 = 1;
const LINUX_IORING_OP_WRITEV: u8 = 2;
const LINUX_IORING_OP_FSYNC: u8 = 3;
const LINUX_IORING_OP_READ_FIXED: u8 = 4;
const LINUX_IORING_OP_WRITE_FIXED: u8 = 5;
const LINUX_IORING_OP_SENDMSG: u8 = 9;
const LINUX_IORING_OP_READ: u8 = 22;
const LINUX_IORING_OP_WRITE: u8 = 23;
/// The operations a ring runs, as IORING_REGISTER_PROBE reports them.
const LINUX_IORING_SUPPORTED_OPS: [u8; 9] = [
    LINUX_IORING_OP_NOP,
    LINUX_IORING_OP_READV,
    LINUX_IORING_OP_WRITEV,
    LINUX_IORING_OP_FSYNC,
    LINUX_IORING_OP_READ_FIXED,
    LINUX_IORING_OP_WRITE_FIXED,
    LINUX_IORING_OP_SENDMSG,
    LINUX_IORING_OP_READ,
    LINUX_IORING_OP_WRITE,
];
/// The highest operation Linux 6.12 knows (IORING_OP_LAST - 1).
const LINUX_IORING_OP_LAST: u8 = 57;

/// Runs one submission entry of ring `ring` and returns its result.
fn linux_io_uring_run(ring: (usize, u64), entry: &LinuxIoUringEntry) -> u64 {
    const FIXED_FILE: u8 = 1 << 0;
    const BUFFER_SELECT: u8 = 1 << 5;
    const VALID_FLAGS: u8 = 0x7f;
    if entry.flags & !VALID_FLAGS != 0 || entry.flags & BUFFER_SELECT != 0 {
        return LINUX_EINVAL;
    }
    // No files are registered, so no fixed file index names one.
    if entry.flags & FIXED_FILE != 0 {
        return LINUX_EBADF;
    }
    let descriptor = entry.descriptor;
    // A file without a position (a pipe or socket) reads and writes at its
    // stream whatever the offset; -1 uses and moves the file position.
    let positioned = |result: u64, streamed: &dyn Fn() -> u64| {
        if result == LINUX_ESPIPE {
            streamed()
        } else {
            result
        }
    };
    match entry.opcode {
        LINUX_IORING_OP_NOP => 0,
        LINUX_IORING_OP_READV | LINUX_IORING_OP_WRITEV => {
            let write = entry.opcode == LINUX_IORING_OP_WRITEV;
            let streamed = || {
                if write {
                    linux_descriptor_writev(descriptor, entry.address, entry.length)
                } else {
                    linux_descriptor_readv(descriptor, entry.address, entry.length)
                }
            };
            if entry.offset == u64::MAX {
                streamed()
            } else {
                positioned(
                    linux_positioned_iov(
                        descriptor,
                        entry.address,
                        entry.length,
                        entry.offset,
                        entry.operation_flags,
                        write,
                    ),
                    &streamed,
                )
            }
        }
        LINUX_IORING_OP_FSYNC => {
            const FSYNC_DATASYNC: u64 = 1;
            if entry.operation_flags & !FSYNC_DATASYNC != 0 {
                LINUX_EINVAL
            } else {
                linux_fsync(descriptor)
            }
        }
        LINUX_IORING_OP_READ_FIXED
        | LINUX_IORING_OP_WRITE_FIXED
        | LINUX_IORING_OP_READ
        | LINUX_IORING_OP_WRITE => {
            let fixed = matches!(
                entry.opcode,
                LINUX_IORING_OP_READ_FIXED | LINUX_IORING_OP_WRITE_FIXED
            );
            if fixed
                && !crate::linux_io_uring::buffer(ring.0, ring.1, usize::from(entry.buffer_index))
                    .is_some_and(|buffer| buffer.holds(entry.address, entry.length))
            {
                return LINUX_EFAULT;
            }
            let write = matches!(
                entry.opcode,
                LINUX_IORING_OP_WRITE_FIXED | LINUX_IORING_OP_WRITE
            );
            let streamed = || {
                if write {
                    linux_descriptor_write(descriptor, entry.address, entry.length)
                } else {
                    linux_descriptor_read(descriptor, entry.address, entry.length)
                }
            };
            if entry.offset == u64::MAX {
                streamed()
            } else if write {
                positioned(
                    linux_regular_file_write_at(
                        descriptor,
                        entry.address,
                        entry.length,
                        linux_pwrite_offset(descriptor, entry.offset),
                    ),
                    &streamed,
                )
            } else {
                positioned(
                    linux_regular_file_read_at(
                        descriptor,
                        entry.address,
                        entry.length,
                        entry.offset,
                    ),
                    &streamed,
                )
            }
        }
        LINUX_IORING_OP_SENDMSG => {
            linux_socket_sendmsg(descriptor, entry.address, entry.operation_flags)
        }
        _ => LINUX_EINVAL,
    }
}

fn linux_io_uring_enter(
    descriptor: u64,
    to_submit: u64,
    minimum_complete: u64,
    flags: u64,
    argument: u64,
    argument_size: u64,
) -> u64 {
    use crate::linux_io_uring::{
        CQE_SIZE, CQ_CQES, CQ_HEAD, CQ_TAIL, SQE_SIZE, SQ_ARRAY, SQ_DROPPED, SQ_HEAD, SQ_TAIL,
    };
    const GETEVENTS: u64 = 1 << 0;
    const SQ_WAKEUP: u64 = 1 << 1;
    const SQ_WAIT: u64 = 1 << 2;
    const EXT_ARG: u64 = 1 << 3;
    const REGISTERED_RING: u64 = 1 << 4;
    const IO_LINK: u8 = 1 << 2;
    const IO_HARDLINK: u8 = 1 << 3;
    const CQE_SKIP_SUCCESS: u8 = 1 << 6;
    let descriptor = u64::from(descriptor as u32);
    let to_submit = to_submit as u32;
    let minimum_complete = minimum_complete as u32;
    let flags = u64::from(flags as u32);
    if flags & !(GETEVENTS | SQ_WAKEUP | SQ_WAIT | EXT_ARG | REGISTERED_RING) != 0 {
        return LINUX_EINVAL;
    }
    // No ring descriptors are registered (IORING_REGISTER_RING_FDS).
    if flags & REGISTERED_RING != 0 {
        return if descriptor >= 16 {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    }
    let Some(ring) = linux_io_uring_key(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EOPNOTSUPP
        } else {
            LINUX_EBADF
        };
    };
    // Extended arguments (IORING_FEAT_EXT_ARG) are not offered.
    if flags & EXT_ARG != 0 {
        return LINUX_EINVAL;
    }
    let Some(rings) = crate::linux_io_uring::rings(ring.0, ring.1) else {
        return LINUX_EBADF;
    };
    let read_u32 = |address| {
        let mut value = [0_u8; 4];
        copy_from_linux_user(address, &mut value).then(|| u32::from_ne_bytes(value))
    };
    let mut submitted = 0_u32;
    if to_submit != 0 {
        if rings.sq == 0 || rings.cq == 0 || rings.sqes == 0 {
            return LINUX_EFAULT;
        }
        let (Some(mut sq_head), Some(sq_tail), Some(mut cq_tail)) = (
            read_u32(rings.sq + SQ_HEAD),
            read_u32(rings.sq + SQ_TAIL),
            read_u32(rings.cq + CQ_TAIL),
        ) else {
            return LINUX_EFAULT;
        };
        let available = sq_tail.wrapping_sub(sq_head).min(rings.sq_entries);
        // A link chain whose earlier entry failed ends its later entries
        // with ECANCELED.
        let mut chain_failed = false;
        for _ in 0..available.min(to_submit) {
            // The completion ring holds what is not yet reaped; a full one
            // stops the submissions (EBUSY when none went in).
            let Some(cq_head) = read_u32(rings.cq + CQ_HEAD) else {
                return LINUX_EFAULT;
            };
            if cq_tail.wrapping_sub(cq_head) >= rings.cq_entries {
                if submitted == 0 {
                    return LINUX_EBUSY;
                }
                break;
            }
            let slot = u64::from(sq_head & (rings.sq_entries - 1));
            let Some(index) = read_u32(rings.sq + SQ_ARRAY + slot * 4) else {
                return LINUX_EFAULT;
            };
            sq_head = sq_head.wrapping_add(1);
            if index >= rings.sq_entries {
                // An index past the entries is dropped and counted.
                let dropped = read_u32(rings.sq + SQ_DROPPED).unwrap_or(0);
                let _ = copy_to_linux_user(
                    rings.sq + SQ_DROPPED,
                    &dropped.wrapping_add(1).to_ne_bytes(),
                );
                continue;
            }
            let mut sqe = [0_u8; SQE_SIZE as usize];
            if !copy_from_linux_user(rings.sqes + u64::from(index) * SQE_SIZE, &mut sqe) {
                return LINUX_EFAULT;
            }
            let entry = LinuxIoUringEntry::parse(&sqe);
            let result = if chain_failed {
                LINUX_ECANCELED
            } else {
                linux_io_uring_run(ring, &entry)
            };
            let failed = result >= LINUX_RETURN_TO_KERNEL;
            if entry.flags & (IO_LINK | IO_HARDLINK) == 0 {
                chain_failed = false;
            } else if failed && entry.flags & IO_HARDLINK == 0 {
                chain_failed = true;
            }
            submitted += 1;
            if !failed && entry.flags & CQE_SKIP_SUCCESS != 0 {
                continue;
            }
            let mut cqe = [0_u8; CQE_SIZE as usize];
            cqe[..8].copy_from_slice(&entry.user_data);
            cqe[8..12].copy_from_slice(&(result as i32).to_ne_bytes());
            let slot = u64::from(cq_tail & (rings.cq_entries - 1));
            if !copy_to_linux_user(rings.cq + CQ_CQES + slot * CQE_SIZE, &cqe) {
                return LINUX_EFAULT;
            }
            cq_tail = cq_tail.wrapping_add(1);
            if !copy_to_linux_user(rings.cq + CQ_TAIL, &cq_tail.to_ne_bytes()) {
                return LINUX_EFAULT;
            }
        }
        if !copy_to_linux_user(rings.sq + SQ_HEAD, &sq_head.to_ne_bytes()) {
            return LINUX_EFAULT;
        }
    }
    // Every entry completes as it is submitted, so there is nothing to wait
    // for; a signal mask for the wait must still be a sigset_t's size.
    if flags & GETEVENTS != 0 && minimum_complete != 0 && rings.cq != 0 {
        let ready = match (read_u32(rings.cq + CQ_HEAD), read_u32(rings.cq + CQ_TAIL)) {
            (Some(head), Some(tail)) => tail.wrapping_sub(head),
            _ => return LINUX_EFAULT,
        };
        if ready < minimum_complete.min(rings.cq_entries) && argument != 0 && argument_size != 8 {
            return LINUX_EINVAL;
        }
    }
    u64::from(submitted)
}

fn linux_io_uring_register(descriptor: u64, opcode: u64, argument: u64, count: u64) -> u64 {
    const REGISTER_BUFFERS: u32 = 0;
    const UNREGISTER_BUFFERS: u32 = 1;
    const REGISTER_PROBE: u32 = 8;
    const REGISTER_CLONE_BUFFERS: u32 = 30;
    const REGISTER_USE_REGISTERED_RING: u32 = 1 << 31;
    let descriptor = u64::from(descriptor as u32);
    let opcode = opcode as u32;
    let count = count as u32;
    if opcode & REGISTER_USE_REGISTERED_RING != 0 {
        return if descriptor >= 16 {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    }
    let Some((domain, id)) = linux_io_uring_key(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EOPNOTSUPP
        } else {
            LINUX_EBADF
        };
    };
    match opcode {
        REGISTER_BUFFERS => {
            if argument == 0 || count == 0 || count > crate::linux_io_uring::MAX_BUFFERS {
                return LINUX_EINVAL;
            }
            let mut buffers = Vec::new();
            if buffers.try_reserve_exact(count as usize).is_err() {
                return LINUX_ENOMEM;
            }
            for index in 0..u64::from(count) {
                let mut iovec = [0_u8; 16];
                if !copy_from_linux_user(argument + index * 16, &mut iovec) {
                    return LINUX_EFAULT;
                }
                let address = u64::from_ne_bytes(iovec[..8].try_into().unwrap());
                let length = u64::from_ne_bytes(iovec[8..].try_into().unwrap());
                // A null buffer of no length is a sparse slot; any other
                // must be mapped user memory of at most 1 GiB.
                let valid = address == 0 && length == 0
                    || address != 0
                        && length != 0
                        && length <= crate::linux_io_uring::MAX_BUFFER_LENGTH
                        && linux_writable_user_range_contains(address, length as usize);
                if !valid {
                    return LINUX_EFAULT;
                }
                buffers.push(crate::linux_io_uring::Buffer { address, length });
            }
            match crate::linux_io_uring::register_buffers(domain, id, buffers) {
                Ok(()) => 0,
                Err(crate::linux_io_uring::Error::Busy) => LINUX_EBUSY,
                Err(_) => LINUX_EBADF,
            }
        }
        UNREGISTER_BUFFERS => {
            if argument != 0 || count != 0 {
                return LINUX_EINVAL;
            }
            match crate::linux_io_uring::unregister_buffers(domain, id) {
                Ok(()) => 0,
                Err(crate::linux_io_uring::Error::NoBuffers) => LINUX_ENXIO,
                Err(_) => LINUX_EBADF,
            }
        }
        REGISTER_PROBE => linux_io_uring_probe(argument, count),
        REGISTER_CLONE_BUFFERS => {
            const SOURCE_REGISTERED: u32 = 1 << 0;
            const DESTINATION_REPLACE: u32 = 1 << 1;
            if count != 1 {
                return LINUX_EINVAL;
            }
            let mut clone = [0_u8; 32];
            if !copy_from_linux_user(argument, &mut clone) {
                return LINUX_EFAULT;
            }
            let field = |index: usize| {
                u32::from_ne_bytes(clone[index * 4..index * 4 + 4].try_into().unwrap())
            };
            let flags = field(1);
            if flags & !(SOURCE_REGISTERED | DESTINATION_REPLACE) != 0
                || clone[20..].iter().any(|byte| *byte != 0)
            {
                return LINUX_EINVAL;
            }
            let source = u64::from(field(0));
            if flags & SOURCE_REGISTERED != 0 {
                return if source >= 16 {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                };
            }
            let Some((_, source_id)) = linux_io_uring_key(source) else {
                return if linux_descriptor_open(source) {
                    LINUX_EOPNOTSUPP
                } else {
                    LINUX_EBADF
                };
            };
            match crate::linux_io_uring::clone_buffers(
                domain,
                id,
                source_id,
                (field(2), field(3), field(4)),
                flags & DESTINATION_REPLACE != 0,
            ) {
                Ok(()) => 0,
                Err(crate::linux_io_uring::Error::Busy) => LINUX_EBUSY,
                Err(crate::linux_io_uring::Error::NoBuffers) => LINUX_ENXIO,
                Err(crate::linux_io_uring::Error::NoMemory) => LINUX_ENOMEM,
                Err(crate::linux_io_uring::Error::NotFound) => LINUX_EBADF,
                Err(crate::linux_io_uring::Error::Invalid) => LINUX_EINVAL,
            }
        }
        _ => LINUX_EINVAL,
    }
}

/// IORING_REGISTER_PROBE: which of the operations Linux knows the ring
/// runs (struct io_uring_probe with `count` entries at most).
fn linux_io_uring_probe(argument: u64, count: u32) -> u64 {
    const PROBE_HEADER: usize = 16;
    const PROBE_ENTRY: usize = 8;
    const OP_SUPPORTED: u16 = 1;
    const OPERATIONS: usize = LINUX_IORING_OP_LAST as usize + 1;
    // Entries past the operations Linux knows are left alone.
    let entries = (count as usize).min(OPERATIONS);
    let mut probe = [0_u8; PROBE_HEADER + OPERATIONS * PROBE_ENTRY];
    let size = PROBE_HEADER + entries * PROBE_ENTRY;
    if !copy_from_linux_user(argument, &mut probe[..size]) {
        return LINUX_EFAULT;
    }
    // The structure must come zeroed.
    if probe[..size].iter().any(|byte| *byte != 0) {
        return LINUX_EINVAL;
    }
    probe[0] = LINUX_IORING_OP_LAST;
    probe[1] = entries as u8;
    for operation in 0..entries {
        let offset = PROBE_HEADER + operation * PROBE_ENTRY;
        probe[offset] = operation as u8;
        if LINUX_IORING_SUPPORTED_OPS.contains(&(operation as u8)) {
            probe[offset + 2..offset + 4].copy_from_slice(&OP_SUPPORTED.to_ne_bytes());
        }
    }
    if copy_to_linux_user(argument, &probe[..size]) {
        0
    } else {
        LINUX_EFAULT
    }
}

/// Closing a ring's descriptor: the ring goes when its creator closes its
/// last descriptor of it.
fn linux_io_uring_release(descriptor: u64) {
    let Some((domain, id)) = linux_io_uring_key(descriptor) else {
        return;
    };
    if linux_descriptor_numbers().any(|candidate| {
        candidate != descriptor
            && linux_io_uring_descriptor(candidate)
            && linux_descriptor_open_file_id(candidate) == Some(id)
    }) {
        return;
    }
    crate::linux_io_uring::release(domain, Some(id), current_linux_process_pid());
}

fn linux_seccomp_strict_syscall_allowed(number: u64) -> bool {
    matches!(
        number,
        LINUX_READ_SYSCALL | LINUX_WRITE_SYSCALL | LINUX_EXIT_SYSCALL | LINUX_RT_SIGRETURN_SYSCALL
    )
}

/// Runs the process's seccomp filters on system call `number`: None lets
/// it run; otherwise its result: an errno, ENOSYS for an action that needs
/// a listener or tracer (there is none), SIGSYS delivered to a handler
/// (SECCOMP_RET_TRAP), or the process killed by SIGSYS.
fn linux_seccomp_filter_syscall(
    number: u64,
    arguments: [u64; 6],
    output: *mut LinuxSyscallFrame,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> Option<u64> {
    let user_rip = return_registers.0;
    let data = linox_seccomp::Data {
        number: number as u32 as i32,
        arch: linox_seccomp::AUDIT_ARCH_X86_64,
        instruction_pointer: user_rip,
        arguments,
    };
    let value = linux_process::live_process_seccomp_return(current_linux_process_pid(), &data)?;
    match linox_seccomp::Verdict::from_return(value) {
        linox_seccomp::Verdict::Allow | linox_seccomp::Verdict::Log => None,
        linox_seccomp::Verdict::Errno(errno) => Some(u64::from(errno).wrapping_neg()),
        linox_seccomp::Verdict::NoHandler => Some(LINUX_ENOSYS),
        linox_seccomp::Verdict::KillThread | linox_seccomp::Verdict::KillProcess => {
            Some(linux_terminate_by_default_signal(LINUX_SIGSYS))
        }
        linox_seccomp::Verdict::Trap(_) => {
            const SYS_SECCOMP: i32 = 1;
            let index = LINUX_SIGSYS as usize - 1;
            let handler = X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].load(Ordering::SeqCst);
            let blocked = X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst)
                & (1 << (LINUX_SIGSYS - 1))
                != 0;
            // Linux forces the signal: ignored or blocked, it kills.
            if handler <= 1 || blocked {
                return Some(linux_terminate_by_default_signal(LINUX_SIGSYS));
            }
            // siginfo's _sigsys fields are the call address, then the
            // system call's number and architecture: where a queued
            // signal's information keeps the sender's pid and uid, then
            // its value (si_errno is left 0).
            let value = (number & 0xffff_ffff) | u64::from(linox_seccomp::AUDIT_ARCH_X86_64) << 32;
            Some(linux_kill_current(
                (LINUX_SIGSYS, SYS_SECCOMP, Some(value)),
                Some((user_rip as u32, (user_rip >> 32) as u32)),
                output,
                interrupted,
                return_registers,
            ))
        }
    }
}

fn linux_seccomp(operation: u64, flags: u64, arguments: u64) -> u64 {
    const SET_MODE_STRICT: u64 = 0;
    const SET_MODE_FILTER: u64 = 1;
    const GET_ACTION_AVAIL: u64 = 2;

    match operation {
        SET_MODE_STRICT => {
            if flags != 0 || arguments != 0 {
                return LINUX_EINVAL;
            }
            // A filtered process cannot change to strict mode.
            if X86_RUNTIME
                .ELF_PROBE_SECCOMP_FILTERED
                .load(Ordering::SeqCst)
            {
                return LINUX_EINVAL;
            }
            if X86_RUNTIME
                .ELF_PROBE_SECCOMP_STRICT
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return LINUX_EINVAL;
            }
            0
        }
        SET_MODE_FILTER => {
            // The program header (struct sock_fprog: a u16 length, then
            // the instructions' address) must be readable, its length
            // 1..=4096, and a process without no_new_privs needs
            // CAP_SYS_ADMIN, as Linux checks before installing it.
            const KNOWN_FLAGS: u64 = 0x3f;
            if flags & !KNOWN_FLAGS != 0 {
                return LINUX_EINVAL;
            }
            let mut program = [0_u8; 16];
            if !copy_from_linux_user(arguments, &mut program) {
                return LINUX_EFAULT;
            }
            let length = u16::from_ne_bytes([program[0], program[1]]);
            if length == 0 || length > 4096 {
                return LINUX_EINVAL;
            }
            if !X86_RUNTIME.ELF_PROBE_NO_NEW_PRIVS.load(Ordering::SeqCst)
                && !current_linux_credentials().is_some_and(|credentials| {
                    credentials.has(linox_credentials::capability::SYS_ADMIN)
                })
            {
                return LINUX_EACCES;
            }
            // There is no user-space listener (SECCOMP_FILTER_FLAG_NEW_LISTENER
            // and the flags that need one); TSYNC holds, as the filters are
            // the process's.
            const NEW_LISTENER: u64 = 8;
            const TSYNC_ESRCH: u64 = 16;
            const WAIT_KILLABLE_RECV: u64 = 32;
            if flags & (NEW_LISTENER | TSYNC_ESRCH | WAIT_KILLABLE_RECV) != 0 {
                return LINUX_EINVAL;
            }
            let filter = u64::from_ne_bytes(program[8..16].try_into().unwrap());
            let mut instructions = Vec::new();
            if instructions.try_reserve_exact(usize::from(length)).is_err() {
                return LINUX_ENOMEM;
            }
            let mut bytes = [0_u8; 8];
            for index in 0..u64::from(length) {
                let Some(address) = filter.checked_add(index * 8) else {
                    return LINUX_EFAULT;
                };
                if !copy_from_linux_user(address, &mut bytes) {
                    return LINUX_EFAULT;
                }
                instructions.push(linox_seccomp::Instruction::from_bytes(bytes));
            }
            let Ok(program) = linox_seccomp::Program::new(instructions) else {
                return LINUX_EINVAL;
            };
            match linux_process::install_live_process_seccomp_filter(
                current_linux_process_pid(),
                program,
            ) {
                Ok(()) => {
                    X86_RUNTIME
                        .ELF_PROBE_SECCOMP_FILTERED
                        .store(true, Ordering::SeqCst);
                    0
                }
                Err(linux_process::SeccompError::NoMemory) => LINUX_ENOMEM,
                Err(linux_process::SeccompError::NoProcess) => LINUX_ESRCH,
            }
        }
        GET_ACTION_AVAIL => {
            if flags != 0 {
                return LINUX_EINVAL;
            }
            let mut action = [0_u8; 4];
            if !copy_from_linux_user(arguments, &mut action) {
                return LINUX_EFAULT;
            }
            if linox_seccomp::action_available(u32::from_ne_bytes(action)) {
                0
            } else {
                LINUX_EOPNOTSUPP
            }
        }
        _ => LINUX_EINVAL,
    }
}

/// The contents of a `/proc/sys` value file (`LINUX_PROC_SYSCTLS`) as
/// built in; a value the domain wrote is served by `linux_regular_file_read_at`.
fn linux_proc_sysctl(state: u16) -> Option<&'static [u8]> {
    LINUX_PROC_SYSCTLS
        .iter()
        .find(|(node, ..)| state & !3 == LINUX_FILE_MASK | node)
        .map(|(.., contents)| *contents)
}

/// The index in `LINUX_PROC_SYSCTLS` of the value file a descriptor state names.
fn linux_proc_sysctl_index(state: u16) -> Option<usize> {
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
fn linux_set_ntp_status(status: u32, now: u64) {
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
fn linux_ntp_state(now: u64) -> (u32, u64) {
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
fn linux_realtime_offset_nanoseconds() -> i64 {
    current_container_slot().map_or(0, |slot| {
        LINUX_REALTIME_OFFSET_NANOSECONDS[slot].load(Ordering::Acquire)
    })
}

/// Moves the current domain's wall clock by `delta` nanoseconds.
fn linux_adjust_realtime_offset(delta: i64) -> bool {
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
const LINUX_UTS_NAME_CAPACITY: usize = 64;
const LINUX_UTS_HOST: usize = 0;
const LINUX_UTS_DOMAIN: usize = 1;
static LINUX_UTS_NAMES: [[[AtomicU8; LINUX_UTS_NAME_CAPACITY]; 2]; control_abi::DOMAIN_LIMIT] =
    [const { [const { [const { AtomicU8::new(0) }; LINUX_UTS_NAME_CAPACITY] }; 2] };
        control_abi::DOMAIN_LIMIT];
static LINUX_UTS_LENGTHS: [[AtomicU8; 2]; control_abi::DOMAIN_LIMIT] =
    [const { [const { AtomicU8::new(0) }; 2] }; control_abi::DOMAIN_LIMIT];

/// The current process's host (`LINUX_UTS_HOST`) or domain name into
/// `output`, its length returned: its UTS namespace's, or the domain's.
fn linux_uts_name(kind: usize, output: &mut [u8; LINUX_UTS_NAME_CAPACITY]) -> usize {
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
fn linux_set_uts_name(kind: usize, address: u64, length: u64) -> u64 {
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
fn linux_proc_sysctl_override(index: usize) -> Option<i64> {
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
fn linux_proc_sysctl_value(path: &[u8]) -> Option<i64> {
    let index = LINUX_PROC_SYSCTLS
        .iter()
        .position(|(_, name, _)| *name == path)?;
    linux_proc_sysctl_override(index)
}

/// Sets the current domain's `/proc/sys` value at `path`: the kernel puts
/// msg_next_id and shm_next_id back to -1 once a creation used them.
fn linux_proc_sysctl_set(path: &[u8], value: i64) {
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
fn linux_nr_open() -> u64 {
    linux_proc_sysctl_value(b"sys/fs/nr_open")
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(LINUX_NR_OPEN)
}

/// The most memory areas a process of the current domain may have:
/// `/proc/sys/vm/max_map_count` as written, else the built-in.
fn linux_max_map_count() -> usize {
    linux_proc_sysctl_value(b"sys/vm/max_map_count")
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(LINUX_MAX_MAP_COUNT)
}

/// The largest pipe an unprivileged process of the current domain may ask
/// for or get: `/proc/sys/fs/pipe-max-size` as written, else the built-in.
fn linux_pipe_max_size() -> u64 {
    linux_proc_sysctl_value(b"sys/fs/pipe-max-size")
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(LINUX_PIPE_MAX_SIZE)
}

/// Writes a `/proc/sys` value: a number in Linux's integer syntax, from a
/// process with root's effective user id, as Linux wants CAP_SYS_ADMIN.
/// A write of /proc/sys/kernel/domainname: the name up to a newline, as
/// setdomainname sets it, by root.
fn linux_proc_domainname_write(device: u16, address: u64, count: u64) -> u64 {
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
fn linux_proc_domainname_write_bytes(device: u16, text: &[u8]) -> Result<usize, u64> {
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

fn linux_proc_sysctl_write(device: u16, index: usize, address: u64, count: u64) -> u64 {
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
fn linux_proc_sysctl_write_bytes(device: u16, index: usize, text: &[u8]) -> Result<usize, u64> {
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

fn linux_sysctl_unpack_pair(value: i64) -> (u64, u64) {
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
fn linux_ping_allowed() -> bool {
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
const LINUX_SYSCTL_TEXT_CAPACITY: usize = crate::linux_core::PATTERN_MAX + 2;

/// Makes the kernel's devices and Linux's standard links in the domain's
/// `/dev` (in its overlay) the first time a path under `/dev` is walked, so
/// listing it and lstat find what open and stat already do: `null`,
/// `zero`, `console` and `tty` (`LinuxCharacterDevice`), `fd`, `stdin`,
/// `stdout` and `stderr` linking into `/proc/self/fd`, and `shm` for POSIX
/// shared memory.
fn linux_ensure_dev_nodes() {
    const LINKS: [(&[u8], &[u8]); 4] = [
        (b"dev/fd", b"/proc/self/fd"),
        (b"dev/stdin", b"/proc/self/fd/0"),
        (b"dev/stdout", b"/proc/self/fd/1"),
        (b"dev/stderr", b"/proc/self/fd/2"),
    ];
    // dev/stderr is made last: once it exists, everything does (or the
    // domain removed some on purpose).
    if crate::linux_overlay::lookup(b"dev/stderr").is_some()
        || crate::linux_overlay::hidden(b"dev/stderr")
        || LINUX_MAKING_DEV_NODES.swap(true, Ordering::Acquire)
    {
        return;
    }
    let root_owned = |handle: Option<crate::linux_overlay::Handle>| {
        if let Some(handle) = handle {
            let _ = crate::linux_overlay::set_owner(handle, 0, 0);
        }
    };
    let image_has = |path: &[u8]| crate::published_rootfs::exact_entry(path).is_some();
    if !image_has(b"dev") && crate::linux_overlay::lookup(b"dev").is_none() {
        root_owned(crate::linux_overlay::create_directory(b"dev", 0o755));
    }
    if !image_has(b"dev/shm") && crate::linux_overlay::lookup(b"dev/shm").is_none() {
        root_owned(crate::linux_overlay::create_directory(b"dev/shm", 0o1777));
    }
    if !image_has(b"dev/net") && crate::linux_overlay::lookup(b"dev/net").is_none() {
        root_owned(crate::linux_overlay::create_directory(b"dev/net", 0o755));
    }
    for device in LinuxCharacterDevice::ALL {
        let mut path = [0_u8; 16];
        let name = device.name();
        path[..4].copy_from_slice(b"dev/");
        path[4..4 + name.len()].copy_from_slice(name);
        let name = &path[..4 + name.len()];
        if crate::linux_overlay::lookup(name).is_none() {
            let (_, major, minor, permissions) = device.identity();
            root_owned(crate::linux_overlay::create_device(
                name,
                crate::linux_overlay::NodeKind::CharacterDevice,
                permissions,
                major << 8 | minor,
            ));
        }
    }
    if crate::linux_overlay::lookup(b"dev/kmsg").is_none() {
        root_owned(crate::linux_overlay::create_device(
            b"dev/kmsg",
            crate::linux_overlay::NodeKind::CharacterDevice,
            0o644,
            linux_device_number(crate::linux_kmsg::MAJOR, crate::linux_kmsg::MINOR),
        ));
    }
    // /dev/pts lists the pty slaves; /dev/ptmx makes them.
    if !image_has(b"dev/pts") && crate::linux_overlay::lookup(b"dev/pts").is_none() {
        root_owned(crate::linux_overlay::create_directory(b"dev/pts", 0o755));
    }
    for (name, device, permissions) in [
        (&b"dev/ptmx"[..], crate::linux_pty::MASTER_DEVICE, 0o666),
        (b"dev/userfaultfd", LINUX_USERFAULTFD_DEVICE, 0o600),
        (b"dev/net/tun", LINUX_TUN_DEVICE, 0o666),
    ] {
        if crate::linux_overlay::lookup(name).is_none() {
            root_owned(crate::linux_overlay::create_device(
                name,
                crate::linux_overlay::NodeKind::CharacterDevice,
                permissions,
                device,
            ));
        }
    }
    for (name, target) in LINKS {
        if crate::linux_overlay::lookup(name).is_none() {
            root_owned(crate::linux_overlay::create_symlink(name, target));
        }
    }
    LINUX_MAKING_DEV_NODES.store(false, Ordering::Release);
}

/// The major and minor numbers of a device number as mknod(2) and stat(2)
/// encode it (Linux's new_decode_dev).
fn linux_device_numbers(device: u32) -> (u32, u32) {
    (
        (device & 0xf_ff00) >> 8,
        (device & 0xff) | ((device >> 12) & 0xf_ff00),
    )
}

/// The device number of `major`:`minor` as stat(2) encodes it (Linux's
/// new_encode_dev).
pub(crate) fn linux_device_number(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

/// A device a device file opens.
enum LinuxDeviceNode {
    /// One of the kernel's character devices, by descriptor kind.
    Character(u16),
    /// Block device `major`:`minor`: a loop device (7) or RAM disk (1).
    Block(u32, u32),
    /// /dev/loop-control (10:237).
    LoopControl,
    /// /dev/kmsg (1:11).
    KernelLog,
    /// /dev/ptmx (5:2): a new pseudo-terminal pair.
    PtyMaster,
    /// /dev/pts/N (136:N and up): pair N's slave.
    PtySlave(u64),
    /// /dev/userfaultfd (10:126).
    Userfaultfd,
    /// /dev/net/tun (10:200).
    Tun,
}

/// What opening the device file `handle` opens: the kernel's null, zero and
/// console devices, loop devices, RAM disks, /dev/ptmx and pty slaves, and
/// /dev/userfaultfd for their numbers; no other device is reachable through
/// a device file (ENXIO), and none on a nodev mount (EACCES).
fn linux_device_node_kind(
    handle: crate::linux_overlay::Handle,
    kind: crate::linux_overlay::NodeKind,
) -> Result<LinuxDeviceNode, u64> {
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = crate::linux_overlay::copy_path(handle, &mut path).ok_or(LINUX_ENOENT)?;
    if crate::linux_mounts::flags_at(linux_mount_space(), &path[..length])
        & crate::linux_mounts::NO_DEVICES
        != 0
    {
        return Err(LINUX_EACCES);
    }
    let device = crate::linux_overlay::metadata(handle)
        .ok_or(LINUX_ENOENT)?
        .device;
    let character = kind == crate::linux_overlay::NodeKind::CharacterDevice;
    if character && device == crate::linux_pty::MASTER_DEVICE {
        return Ok(LinuxDeviceNode::PtyMaster);
    }
    if character && device == LINUX_USERFAULTFD_DEVICE {
        return Ok(LinuxDeviceNode::Userfaultfd);
    }
    if character && device == LINUX_TUN_DEVICE {
        return Ok(LinuxDeviceNode::Tun);
    }
    if let Some(index) = crate::linux_pty::slave_index(device).filter(|_| character) {
        return Ok(LinuxDeviceNode::PtySlave(index));
    }
    match (kind, linux_device_numbers(device)) {
        (
            crate::linux_overlay::NodeKind::BlockDevice,
            (major @ (crate::linux_loop::MAJOR | crate::linux_ramdisk::MAJOR), minor),
        ) => Ok(LinuxDeviceNode::Block(major, minor)),
        (
            crate::linux_overlay::NodeKind::CharacterDevice,
            (crate::linux_loop::CONTROL_MAJOR, crate::linux_loop::CONTROL_MINOR),
        ) => Ok(LinuxDeviceNode::LoopControl),
        (
            crate::linux_overlay::NodeKind::CharacterDevice,
            (crate::linux_kmsg::MAJOR, crate::linux_kmsg::MINOR),
        ) => Ok(LinuxDeviceNode::KernelLog),
        (crate::linux_overlay::NodeKind::CharacterDevice, numbers) => LinuxCharacterDevice::ALL
            .into_iter()
            .find(|device| {
                let (_, major, minor, _) = device.identity();
                (major, minor) == numbers
            })
            .map(|device| LinuxDeviceNode::Character(device.kind()))
            .ok_or(LINUX_ENXIO),
        _ => Err(LINUX_ENXIO),
    }
}

fn linux_socket_slot(descriptor: u64) -> Option<crate::linux_socket::SlotId> {
    let descriptor = u64::from(descriptor as u32);
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_overflow_entry(descriptor).and_then(|entry| entry.socket.checked_sub(1));
    }
    if let Some(slot) = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS.get(index))
        .map(|slot| slot.load(Ordering::SeqCst))
        .filter(|slot| *slot != 0)
    {
        return Some(slot - 1);
    }
    descriptor
        .checked_sub(LINUX_AUX_DESCRIPTOR_FIRST)
        .and_then(|index| X86_RUNTIME.ELF_PROBE_SOCKET_SLOTS.get(index as usize))
        .map(|slot| slot.load(Ordering::SeqCst))
        .filter(|slot| *slot != 0)
        .map(|slot| slot - 1)
}

fn linux_socket_error(error: crate::linux_socket::Error) -> u64 {
    match error {
        crate::linux_socket::Error::WrongType => LINUX_EPROTOTYPE,
        crate::linux_socket::Error::Unavailable => LINUX_ENETUNREACH,
        crate::linux_socket::Error::Exhausted => LINUX_ENFILE,
        crate::linux_socket::Error::AddressInUse => LINUX_EADDRINUSE,
        crate::linux_socket::Error::AddressNotAvailable => LINUX_EADDRNOTAVAIL,
        crate::linux_socket::Error::Invalid => LINUX_EINVAL,
        crate::linux_socket::Error::InProgress => LINUX_EINPROGRESS,
        crate::linux_socket::Error::WouldBlock => LINUX_EAGAIN,
        crate::linux_socket::Error::NotConnected => LINUX_ENOTCONN,
        crate::linux_socket::Error::BrokenPipe => LINUX_EPIPE,
        crate::linux_socket::Error::Reset => LINUX_ECONNRESET,
        crate::linux_socket::Error::Refused => LINUX_ECONNREFUSED,
        crate::linux_socket::Error::IsConnected => LINUX_EISCONN,
        crate::linux_socket::Error::Already => LINUX_EALREADY,
        crate::linux_socket::Error::Errno(errno) => (-i64::from(errno)) as u64,
    }
}

fn linux_socket_descriptor_index(descriptor: u64) -> Option<usize> {
    let descriptor = u64::from(descriptor as u32);
    let index = descriptor.checked_sub(LINUX_AUX_DESCRIPTOR_FIRST)? as usize;
    (index < LINUX_DEVICE_DESCRIPTOR_COUNT).then_some(index)
}

fn linux_socket_nonblocking(descriptor: u64) -> bool {
    if X86_RUNTIME
        .LINUX_SOCKET_SINGLE_ATTEMPT
        .load(Ordering::SeqCst)
    {
        return true;
    }
    let descriptor = u64::from(descriptor as u32);
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_overflow_entry(descriptor)
            .is_some_and(|entry| entry.socket_flags & LINUX_O_NONBLOCK as u32 != 0);
    }
    if let Some(flags) = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS.get(index))
    {
        return flags.load(Ordering::SeqCst) & LINUX_O_NONBLOCK as u32 != 0;
    }
    linux_socket_descriptor_index(descriptor).is_some_and(|index| {
        X86_RUNTIME.ELF_PROBE_SOCKET_FLAGS[index].load(Ordering::SeqCst) & LINUX_O_NONBLOCK as u32
            != 0
    })
}

fn linux_socket_flags(descriptor: u64) -> Option<u32> {
    let descriptor = u64::from(descriptor as u32);
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_overflow_entry(descriptor).map(|entry| entry.socket_flags);
    }
    if let Some(flags) = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS.get(index))
    {
        return Some(flags.load(Ordering::SeqCst));
    }
    linux_socket_descriptor_index(descriptor)
        .map(|index| X86_RUNTIME.ELF_PROBE_SOCKET_FLAGS[index].load(Ordering::SeqCst))
}

/// socket(AF_NETLINK, SOCK_RAW or SOCK_DGRAM, protocol): a netlink socket
/// that receives the kernel's messages to it (`linux_socket::Kind::Netlink`).
fn linux_netlink_socket_create(socket_type: u64, protocol: u64) -> u64 {
    const SOCK_DGRAM: u64 = 2;
    const SOCK_RAW: u64 = 3;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x8_0000;
    const NETLINK_PROTOCOLS: u64 = 32;
    if socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    if !matches!(socket_type & 0xf, SOCK_DGRAM | SOCK_RAW) {
        return LINUX_ESOCKTNOSUPPORT;
    }
    if protocol >= NETLINK_PROTOCOLS {
        return LINUX_EPROTONOSUPPORT;
    }
    let Some(descriptor) = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        return LINUX_EMFILE;
    };
    let slot = match crate::linux_socket::open_netlink(protocol as u8) {
        Ok(slot) => slot,
        Err(error) => return linux_socket_error(error),
    };
    linux_socket_descriptor_installed(
        descriptor,
        slot,
        LINUX_DEVICE_SOCKET | 3,
        (socket_type & SOCK_NONBLOCK) as u32,
        socket_type & SOCK_CLOEXEC != 0,
    )
}

/// `install_linux_socket_descriptor`, the descriptor (or ENOMEM, the
/// socket closed again) returned.
fn linux_socket_descriptor_installed(
    descriptor: u64,
    slot: crate::linux_socket::SlotId,
    state: u16,
    flags: u32,
    close_on_exec: bool,
) -> u64 {
    if install_linux_socket_descriptor(descriptor, slot, state, flags, close_on_exec) {
        descriptor
    } else {
        let _ = crate::linux_socket::close(slot);
        LINUX_ENOMEM
    }
}

fn linux_socket_create(family: u64, socket_type: u64, protocol: u64) -> u64 {
    const AF_UNIX: u64 = 1;
    const AF_INET: u64 = 2;
    const AF_INET6: u64 = 10;
    const SOCK_STREAM: u64 = 1;
    const SOCK_DGRAM: u64 = 2;
    const SOCK_RAW: u64 = 3;
    const SOCK_SEQPACKET: u64 = 5;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x8_0000;
    const IPPROTO_ICMP: u64 = 1;
    const IPPROTO_ICMPV6: u64 = 58;
    const IPPROTO_UDPLITE: u64 = 136;
    const AF_NETLINK: u64 = 16;
    const AF_PACKET: u64 = 17;
    let family = u64::from(family as u32);
    let socket_type = u64::from(socket_type as u32);
    let protocol = u64::from(protocol as u32);
    if family == AF_NETLINK {
        return linux_netlink_socket_create(socket_type, protocol);
    }
    if family == AF_PACKET {
        return linux_packet_socket_create(socket_type, protocol);
    }
    if !matches!(family, AF_UNIX | AF_INET | AF_INET6) {
        return LINUX_EAFNOSUPPORT;
    }
    let base = socket_type & 0xf;
    if socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    let kind = match (family, base) {
        (AF_UNIX, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) if protocol == 0 => {
            crate::linux_socket::Kind::Unix
        }
        (AF_UNIX, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) => {
            return LINUX_EPROTONOSUPPORT;
        }
        (AF_INET, SOCK_STREAM) if matches!(protocol, 0 | 6) => crate::linux_socket::Kind::Tcp,
        (AF_INET, SOCK_DGRAM) if matches!(protocol, 0 | 17) => crate::linux_socket::Kind::Udp,
        (AF_INET | AF_INET6, SOCK_DGRAM) if protocol == IPPROTO_UDPLITE => {
            crate::linux_socket::Kind::UdpLite
        }
        // Ping sockets, which Linux grants to the groups in ping_group_range
        // (every group on Ubuntu), and raw ICMP sockets.
        (AF_INET, SOCK_DGRAM | SOCK_RAW) if protocol == IPPROTO_ICMP => {
            crate::linux_socket::Kind::Icmp
        }
        (AF_INET, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW) => return LINUX_EPROTONOSUPPORT,
        // AF_INET6 TCP and UDP, and ICMPv6 ping and raw sockets; raw
        // sockets of other IPv6 protocols are not made here.
        (AF_INET6, SOCK_STREAM) if matches!(protocol, 0 | 6) => crate::linux_socket::Kind::Tcp,
        (AF_INET6, SOCK_DGRAM) if matches!(protocol, 0 | 17) => crate::linux_socket::Kind::Udp,
        (AF_INET6, SOCK_DGRAM | SOCK_RAW) if protocol == IPPROTO_ICMPV6 => {
            crate::linux_socket::Kind::Icmp
        }
        (AF_INET6, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW) => return LINUX_EPROTONOSUPPORT,
        _ => return LINUX_EINVAL,
    };
    // A raw socket needs CAP_NET_RAW, checked once the protocol is known,
    // as Linux's inet_create and inet6_create do; a ping socket a group in
    // ping_group_range (EACCES).
    if base == SOCK_RAW && !linux_has_capability(linox_credentials::capability::NET_RAW) {
        return LINUX_EPERM;
    }
    if base == SOCK_DGRAM && kind == crate::linux_socket::Kind::Icmp && !linux_ping_allowed() {
        return LINUX_EACCES;
    }
    let Some(descriptor) = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        return LINUX_EMFILE;
    };
    let slot = match if kind == crate::linux_socket::Kind::Unix {
        crate::linux_socket::open_unix(base as u8)
    } else if kind == crate::linux_socket::Kind::Icmp && family == AF_INET6 {
        crate::linux_socket::open_icmpv6(base == SOCK_RAW)
    } else if kind == crate::linux_socket::Kind::Icmp {
        crate::linux_socket::open_icmp(base == SOCK_RAW)
    } else if family == AF_INET6 {
        crate::linux_socket::open_ipv6(kind)
    } else {
        crate::linux_socket::open(kind)
    } {
        Ok(slot) => slot,
        Err(error) => {
            let result = linux_socket_error(error);
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                serial_write("linox: Linux IPv4 socket creation failed: ");
                serial_write_u64(result);
                serial_write(" socket/device/pipe/event/timer/stderr ");
                serial_write_u64(linux_socket_slot(descriptor).map_or(u64::MAX, u64::from));
                serial_write(" ");
                serial_write_u64(u64::from(linux_device_descriptor(descriptor)));
                serial_write(" ");
                serial_write_u64(u64::from(linux_pipe_descriptor(descriptor)));
                serial_write(" ");
                serial_write_u64(u64::from(linux_eventfd_descriptor(descriptor)));
                serial_write(" ");
                serial_write_u64(u64::from(linux_timerfd_descriptor(descriptor)));
                serial_write(" ");
                serial_write_u64(u64::from(
                    X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::SeqCst),
                ));
                serial_write("\r\n");
            }
            return result;
        }
    };
    linux_socket_descriptor_installed(
        descriptor,
        slot,
        LINUX_DEVICE_SOCKET | 3,
        (socket_type & SOCK_NONBLOCK) as u32,
        socket_type & SOCK_CLOEXEC != 0,
    )
}

/// socket(AF_PACKET, ...): a packet socket of base type SOCK_RAW or
/// SOCK_DGRAM, which needs CAP_NET_RAW in the domain's user namespace. The
/// socket lives in the caller's network namespace; it carries the TPACKET
/// options its setsockopt validates but delivers no frames.
fn linux_packet_socket_create(socket_type: u64, protocol: u64) -> u64 {
    const SOCK_DGRAM: u64 = 2;
    const SOCK_RAW: u64 = 3;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x8_0000;
    let base = socket_type & 0xf;
    if socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    if !matches!(base, SOCK_DGRAM | SOCK_RAW) {
        return LINUX_ESOCKTNOSUPPORT;
    }
    if !linux_has_capability(linox_credentials::capability::NET_RAW) {
        return LINUX_EPERM;
    }
    let Some(descriptor) = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        return LINUX_EMFILE;
    };
    let slot = match crate::linux_socket::open_packet(base as u8, protocol as u16) {
        Ok(slot) => slot,
        Err(error) => return linux_socket_error(error),
    };
    linux_socket_descriptor_installed(
        descriptor,
        slot,
        LINUX_DEVICE_SOCKET | 3,
        (socket_type & SOCK_NONBLOCK) as u32,
        socket_type & SOCK_CLOEXEC != 0,
    )
}

fn linux_socket_pair(family: u64, socket_type: u64, protocol: u64, output: u64) -> u64 {
    const AF_UNIX: u64 = 1;
    const SOCK_STREAM: u64 = 1;
    const SOCK_DGRAM: u64 = 2;
    const SOCK_SEQPACKET: u64 = 5;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x8_0000;
    const AF_INET: u64 = 2;
    const AF_INET6: u64 = 10;
    const SOCK_RAW: u64 = 3;
    let family = u64::from(family as u32);
    let socket_type = u64::from(socket_type as u32);
    let protocol = u64::from(protocol as u32);
    let base = socket_type & 0xf;
    // An inet socket is made first, as Linux makes it (a bad type EINVAL,
    // a protocol the type lacks EPROTONOSUPPORT), and then has no pairs
    // (EOPNOTSUPP: socketpair01).
    if matches!(family, AF_INET | AF_INET6) {
        if socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0
            || !matches!(base, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW)
        {
            return LINUX_EINVAL;
        }
        let made = matches!(
            (family, base, protocol),
            (_, SOCK_STREAM, 0 | 6)
                | (_, SOCK_DGRAM, 0 | 17 | 136)
                | (AF_INET, SOCK_DGRAM | SOCK_RAW, 1)
                | (AF_INET6, SOCK_DGRAM | SOCK_RAW, 58)
        );
        return if made {
            LINUX_EOPNOTSUPP
        } else {
            LINUX_EPROTONOSUPPORT
        };
    }
    if family != AF_UNIX {
        return LINUX_EAFNOSUPPORT;
    }
    if !matches!(base, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET)
        || socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0
        || protocol != 0
    {
        return LINUX_EPROTONOSUPPORT;
    }
    let Some(descriptors) = linux_free_descriptors::<2>(2) else {
        return LINUX_EMFILE;
    };
    let (first, second) = match crate::linux_socket::open_pair(base as u8) {
        Ok(pair) => pair,
        Err(error) => return linux_socket_error(error),
    };
    let Some(credentials) = current_linux_credentials() else {
        let _ = crate::linux_socket::close(first);
        let _ = crate::linux_socket::close(second);
        return LINUX_ESRCH;
    };
    if !crate::linux_socket::set_unix_pair_credentials(
        first,
        second,
        (
            current_linux_process_pid(),
            credentials.user.effective,
            credentials.group.effective,
        ),
    ) {
        let _ = crate::linux_socket::close(first);
        let _ = crate::linux_socket::close(second);
        return LINUX_EINVAL;
    }
    let mut bytes = [0_u8; 8];
    bytes[..4].copy_from_slice(&(descriptors[0] as u32).to_ne_bytes());
    bytes[4..].copy_from_slice(&(descriptors[1] as u32).to_ne_bytes());
    if !copy_to_linux_user(output, &bytes) {
        let _ = crate::linux_socket::close(first);
        let _ = crate::linux_socket::close(second);
        return LINUX_EFAULT;
    }
    let mut installed = [first, second].map(|slot| (slot, false));
    for (descriptor, (slot, done)) in descriptors.into_iter().zip(installed.iter_mut()) {
        *done = install_linux_socket_descriptor(
            descriptor,
            *slot,
            LINUX_DEVICE_SOCKET | 3,
            (socket_type & SOCK_NONBLOCK) as u32,
            socket_type & SOCK_CLOEXEC != 0,
        );
    }
    if installed.iter().any(|(_, done)| !done) {
        for (descriptor, (slot, done)) in descriptors.into_iter().zip(installed) {
            if done {
                let _ = linux_descriptor_close(descriptor);
            } else {
                let _ = crate::linux_socket::close(slot);
            }
        }
        return LINUX_ENOMEM;
    }
    0
}

/// The internet address user memory holds for socket `slot`: a
/// sockaddr_in, or for an AF_INET6 socket a sockaddr_in6 (at least the 24
/// bytes of RFC 2133's, without the scope id, as Linux takes). A shorter
/// one is EINVAL, another family EAFNOSUPPORT.
fn linux_inet_address(
    slot: crate::linux_socket::SlotId,
    address: u64,
    length: u64,
) -> Result<(IpAddress, u16), u64> {
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    let ipv6 = crate::linux_socket::is_ipv6(slot);
    let length = u64::from(length as u32);
    let size = if ipv6 { 24 } else { 16 };
    if length < size as u64 {
        return Err(LINUX_EINVAL);
    }
    let mut sockaddr = [0_u8; 24];
    if !copy_from_linux_user(address, &mut sockaddr[..size]) {
        return Err(LINUX_EFAULT);
    }
    let family = u16::from_ne_bytes([sockaddr[0], sockaddr[1]]);
    if family != if ipv6 { AF_INET6 } else { AF_INET } {
        return Err(LINUX_EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
    let ip = if ipv6 {
        let octets: [u8; 16] = sockaddr[8..24].try_into().unwrap_or([0; 16]);
        IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from_octets(octets))
    } else {
        IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(
            sockaddr[4],
            sockaddr[5],
            sockaddr[6],
            sockaddr[7],
        ))
    };
    Ok((ip, port))
}

/// A destination for socket `slot` (connect, sendto, sendmsg): port 0 is
/// EINVAL, except for ICMP sockets, which have none; an AF_INET6 socket reaches an IPv4-mapped address over IPv4,
/// which an IPV6_V6ONLY one cannot (ENETUNREACH). The unspecified address
/// stays: the socket table takes it as the local host, as Linux does.
fn linux_socket_address(
    slot: crate::linux_socket::SlotId,
    address: u64,
    length: u64,
) -> Result<smoltcp::wire::IpEndpoint, u64> {
    let (ip, port) = linux_inet_address(slot, address, length)?;
    if port == 0 && crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Icmp) {
        return Err(LINUX_EINVAL);
    }
    let ip = match crate::linux_socket::ipv4_of(ip) {
        Some(ipv4) if matches!(ip, IpAddress::Ipv6(_)) => {
            if crate::linux_socket::v6only(slot) == Some(true) {
                return Err(LINUX_ENETUNREACH);
            }
            IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_octets(ipv4.to_be_bytes()))
        }
        _ => ip,
    };
    Ok(smoltcp::wire::IpEndpoint::new(ip, port))
}

/// Whether user memory holds an AF_UNSPEC address (connect's
/// disconnect): the family alone, as Linux reads it.
fn linux_socket_unspecified_address(address: u64, length: u64) -> Result<bool, u64> {
    if u64::from(length as u32) < 2 {
        return Err(LINUX_EINVAL);
    }
    let mut family = [0_u8; 2];
    if !copy_from_linux_user(address, &mut family) {
        return Err(LINUX_EFAULT);
    }
    Ok(u16::from_ne_bytes(family) == 0)
}

/// The canonical path of the file Unix socket pathname `path` leads to,
/// from the caller's root and directory as Linux walks it: the walk's
/// error, or ENOENT when nothing is there.
fn linux_unix_socket_file(
    path: &[u8],
    canonical: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Result<usize, u64> {
    let length = linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), path, canonical)?;
    let file = &canonical[..length];
    if crate::linux_overlay::lookup(file).is_some() || linux_path_access(file).is_some() {
        Ok(length)
    } else {
        Err(LINUX_ENOENT)
    }
}

fn linux_unix_socket_path(address: u64, length: u64, output: &mut [u8; 108]) -> Result<usize, u64> {
    let length = usize::try_from(u64::from(length as u32)).map_err(|_| LINUX_EINVAL)?;
    if !(3..=110).contains(&length) {
        return Err(LINUX_EINVAL);
    }
    let mut sockaddr = [0_u8; 110];
    if !copy_from_linux_user(address, &mut sockaddr[..length]) {
        return Err(LINUX_EFAULT);
    }
    if u16::from_ne_bytes(sockaddr[..2].try_into().unwrap()) != 1 {
        return Err(LINUX_EAFNOSUPPORT);
    }
    let supplied = &sockaddr[2..length];
    let path_length = if supplied[0] == 0 {
        supplied.len()
    } else {
        supplied
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(supplied.len())
    };
    if path_length == 0 {
        return Err(LINUX_EINVAL);
    }
    output[..path_length].copy_from_slice(&supplied[..path_length]);
    Ok(path_length)
}

/// The socket-table slot behind `descriptor` for a call only sockets take
/// (bind, accept, setsockopt...): none for the table's other objects, such
/// as a userfaultfd or a pseudo-terminal, which are no sockets (accept03).
fn linux_socket_call_slot(descriptor: u64) -> Option<crate::linux_socket::SlotId> {
    linux_socket_slot(descriptor)
        .filter(|slot| crate::linux_socket::kind(*slot) != Some(crate::linux_socket::Kind::Object))
}

/// The error for a socket call on `descriptor` that is not a socket: ENOTSOCK
/// when it is an open descriptor of another kind, EBADF when it is not open.
/// A socket call's error for a descriptor that is no socket: EBADF when
/// it is closed or an O_PATH descriptor (which socket calls cannot use, as
/// in Linux), ENOTSOCK otherwise.
fn linux_not_socket_error(descriptor: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    if linux_descriptor_open(descriptor) && !linux_path_descriptor(descriptor) {
        LINUX_ENOTSOCK
    } else {
        LINUX_EBADF
    }
}

fn linux_socket_bind(descriptor: u64, address: u64, length: u64) -> u64 {
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Netlink) {
        // struct sockaddr_nl: family, padding, port id, multicast groups.
        let mut sockaddr = [0_u8; 12];
        if length < sockaddr.len() as u64 {
            return LINUX_EINVAL;
        }
        if !copy_from_linux_user(address, &mut sockaddr) {
            return LINUX_EFAULT;
        }
        if u16::from_ne_bytes([sockaddr[0], sockaddr[1]]) != 16 {
            return LINUX_EINVAL;
        }
        let port = u32::from_ne_bytes(sockaddr[4..8].try_into().unwrap());
        return match crate::linux_socket::bind_netlink(slot, port, current_linux_process_pid()) {
            Ok(_) => 0,
            Err(error) => linux_socket_error(error),
        };
    }
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Packet) {
        // struct sockaddr_ll: family, protocol, ifindex, hatype, pkttype,
        // halen, addr[8]. bind takes the family, the interface to bind to
        // (ifindex 0 unbinds) and the protocol; a frame ring is never mapped.
        let mut sockaddr = [0_u8; 20];
        if length < sockaddr.len() as u64 {
            return LINUX_EINVAL;
        }
        if !copy_from_linux_user(address, &mut sockaddr) {
            return LINUX_EFAULT;
        }
        if u16::from_ne_bytes([sockaddr[0], sockaddr[1]]) != 17 {
            return LINUX_EINVAL;
        }
        let protocol = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
        let ifindex = i32::from_ne_bytes(sockaddr[4..8].try_into().unwrap());
        // A non-zero index must name an interface of this network namespace.
        if ifindex != 0
            && !linux_network_interfaces()
                .iter()
                .any(|interface| interface.index == ifindex)
        {
            return LINUX_ENODEV;
        }
        return if crate::linux_socket::set_packet_bind(slot, ifindex, protocol) {
            0
        } else {
            linux_not_socket_error(descriptor)
        };
    }
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Unix) {
        let mut path = [0_u8; 108];
        let path_length = match linux_unix_socket_path(address, length, &mut path) {
            Ok(length) => length,
            Err(error) => return error,
        };
        // A pathname becomes a socket file where the path leads, as Linux
        // makes one (bind04 unlinks it after the test): a name already there
        // is EADDRINUSE, a missing parent ENOENT. An abstract name has none.
        let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let node_length = if path[0] != 0 {
            let length = match linux_canonical_path_at(
                u64::from(LINUX_AT_FDCWD),
                &path[..path_length],
                &mut canonical,
            ) {
                Ok(length) => length,
                Err(error) => return error,
            };
            if crate::linux_overlay::lookup(&canonical[..length]).is_some()
                || linux_path_access(&canonical[..length]).is_some()
            {
                return LINUX_EADDRINUSE;
            }
            if !linux_overlay_parent_exists(&canonical[..length]) {
                return linux_missing_path_error(&canonical[..length]);
            }
            Some(length)
        } else {
            None
        };
        if let Err(error) = crate::linux_socket::bind_unix(slot, &path[..path_length]) {
            return linux_socket_error(error);
        }
        linux_landlock_bound_unix(slot, &path[..path_length]);
        if let Some(length) = node_length {
            let mode = 0o777 & !(X86_RUNTIME.ELF_PROBE_UMASK.load(Ordering::SeqCst) as u32);
            let _ = crate::linux_overlay::create_socket(&canonical[..length], mode);
        }
        return 0;
    }
    let (address, port) = match linux_inet_address(slot, address, length) {
        Ok(endpoint) => endpoint,
        Err(error) => return error,
    };
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Tcp) {
        if let Err(error) = linux_landlock_check_port(port, false) {
            return error;
        }
    }
    // Ports below 1024 need CAP_NET_BIND_SERVICE.
    if (1..1024).contains(&port)
        && !linux_has_capability(linox_credentials::capability::NET_BIND_SERVICE)
    {
        return LINUX_EACCES;
    }
    // A network namespace's sockets bind only to its own addresses (IPv6
    // loopback as its IPv4 loopback).
    let reaches = match address {
        _ if address.is_unspecified() => true,
        IpAddress::Ipv6(ipv6) if ipv6.is_loopback() => linux_network_reaches(0x7f00_0001),
        _ => crate::linux_socket::ipv4_of(address).is_none_or(linux_network_reaches),
    };
    if !reaches {
        return LINUX_EADDRNOTAVAIL;
    }
    crate::linux_socket::bind(slot, address, port).map_or_else(linux_socket_error, |_| 0)
}

fn linux_socket_listen(descriptor: u64, backlog: u64) -> u64 {
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // Linux reads the backlog as an unsigned int capped at somaxconn, so a
    // negative backlog, which Rust's standard library passes, means the
    // largest one.
    let backlog = backlog as u32 as usize;
    if !matches!(
        crate::linux_socket::kind(slot),
        Some(crate::linux_socket::Kind::Tcp | crate::linux_socket::Kind::Unix)
    ) {
        return LINUX_EOPNOTSUPP;
    }
    crate::linux_socket::listen(slot, backlog).map_or_else(linux_socket_error, |()| 0)
}

fn linux_socket_accept_address_valid(address: u64, length: u64, size: u32) -> bool {
    if address == 0 {
        return true;
    }
    let mut supplied = [0_u8; 4];
    if length == 0 || !copy_from_linux_user(length, &mut supplied) {
        return false;
    }
    let address_length = usize::try_from(u32::from_ne_bytes(supplied).min(size)).unwrap_or(16);
    linux_writable_user_range_contains(length, 4)
        && linux_writable_user_range_contains(address, address_length)
}

fn linux_socket_accept(descriptor: u64, address: u64, length: u64, flags: u64) -> u64 {
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x8_0000;
    let flags = u64::from(flags as u32);
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    // A pipe end is no socket here, though pipes are socket pairs inside.
    let Some(listener_slot) = linux_socket_call_slot(descriptor)
        .filter(|_| !linux_pipe_descriptor(u64::from(descriptor as u32)))
    else {
        return linux_not_socket_error(descriptor);
    };
    // As Linux's order: a datagram socket cannot accept (EOPNOTSUPP), one
    // not listening has nothing to accept (EINVAL), before the address is
    // looked at (accept01).
    if matches!(
        crate::linux_socket::kind(listener_slot),
        Some(
            crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
                | crate::linux_socket::Kind::Icmp
        )
    ) || crate::linux_socket::socket_type(listener_slot) == Some(2)
    {
        return LINUX_EOPNOTSUPP;
    }
    if !crate::linux_socket::is_listening(listener_slot) {
        return LINUX_EINVAL;
    }
    let Some(accepted_descriptor) = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        return LINUX_EMFILE;
    };
    let ipv6 = crate::linux_socket::is_ipv6(listener_slot);
    if !linux_socket_accept_address_valid(address, length, linux_inet_address_size(ipv6)) {
        return LINUX_EFAULT;
    }
    let accepted = if linux_socket_nonblocking(descriptor)
        || X86_RUNTIME
            .LINUX_SOCKET_SINGLE_ATTEMPT
            .load(Ordering::SeqCst)
    {
        crate::linux_socket::accept(listener_slot)
    } else {
        crate::linux_socket::accept_blocking(listener_slot)
    };
    let (accepted_slot, remote) = match accepted {
        Ok(accepted) => accepted,
        Err(error) => return linux_socket_error(error),
    };
    let written =
        if crate::linux_socket::kind(listener_slot) == Some(crate::linux_socket::Kind::Unix) {
            linux_write_unnamed_unix_address(address, length)
        } else {
            linux_write_socket_address(address, length, remote, ipv6)
        };
    if address != 0 && !written {
        let _ = crate::linux_socket::close(accepted_slot);
        return LINUX_EFAULT;
    }
    linux_socket_descriptor_installed(
        accepted_descriptor,
        accepted_slot,
        LINUX_DEVICE_SOCKET | 3,
        (flags & SOCK_NONBLOCK) as u32,
        flags & SOCK_CLOEXEC != 0,
    )
}

/// accept(2) (system call `number`) on a blocking listener waits as a
/// blocking read does: one attempt, then a ready sibling thread or the
/// other processes run and the call starts again, until SO_RCVTIMEO passes.
/// A listener that spun inside the kernel with the entry lock held kept the
/// peer that would connect, a thread or a child on another CPU, from ever
/// entering it (bind04, connect01, setsockopt10).
#[allow(clippy::too_many_arguments)]
fn linux_socket_accept_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    descriptor: u64,
    address: u64,
    length: u64,
    flags: u64,
) -> u64 {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire)
        && linux_socket_slot(descriptor).is_some()
        && !linux_socket_nonblocking(descriptor)
    {
        return linux_local_socket_io_live_return(output, caller, number, descriptor, || {
            linux_socket_accept(descriptor, address, length, flags)
        });
    }
    linux_socket_accept(descriptor, address, length, flags)
}

fn linux_socket_connect(descriptor: u64, address: u64, length: u64) -> u64 {
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Unix) {
        let mut path = [0_u8; 108];
        let path_length = match linux_unix_socket_path(address, length, &mut path) {
            Ok(length) => length,
            Err(error) => return error,
        };
        // A pathname names the socket file the caller's path walk reaches
        // (from its root: a chrooted process cannot reach sockets outside),
        // and connecting through it needs write permission on it.
        if path[0] != 0 {
            let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            let length = match linux_unix_socket_file(&path[..path_length], &mut canonical) {
                Ok(length) => length,
                Err(error) => return error,
            };
            if let Some(metadata) = crate::linux_overlay::lookup(&canonical[..length])
                .filter(|metadata| metadata.kind == crate::linux_overlay::NodeKind::Socket)
            {
                if let Err(error) = linux_check_access(
                    Some(linux_overlay_file_access(metadata)),
                    linox_credentials::access::WRITE,
                    false,
                ) {
                    return error;
                }
            }
        }
        let credentials = current_linux_credentials().map_or((0, 0), |credentials| {
            (credentials.user.effective, credentials.group.effective)
        });
        if let Some(peer) = crate::linux_socket::unix_connect_target(slot, &path[..path_length]) {
            if let Err(error) = linux_landlock_check_unix_peer(peer, &path[..path_length]) {
                return error;
            }
        }
        // No socket bound to the name: Linux fails a path that does not
        // exist with ENOENT and an abstract name with ECONNREFUSED (musl's
        // nscd lookup treats both as "no daemon").
        return match crate::linux_socket::connect_unix(
            slot,
            &path[..path_length],
            (current_linux_process_pid(), credentials.0, credentials.1),
        ) {
            Ok(()) => 0,
            Err(crate::linux_socket::Error::NotConnected) if path[0] == 0 => LINUX_ECONNREFUSED,
            // A socket file nothing is bound to any more refuses; a path
            // with no file is ENOENT.
            Err(crate::linux_socket::Error::NotConnected) => {
                let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
                match linux_canonical_path_at(
                    u64::from(LINUX_AT_FDCWD),
                    &path[..path_length],
                    &mut canonical,
                ) {
                    Ok(length)
                        if crate::linux_overlay::lookup(&canonical[..length]).is_some_and(
                            |metadata| metadata.kind == crate::linux_overlay::NodeKind::Socket,
                        ) =>
                    {
                        LINUX_ECONNREFUSED
                    }
                    _ => LINUX_ENOENT,
                }
            }
            Err(error) => linux_socket_error(error),
        };
    }
    // AF_UNSPEC ends a TCP connection or forgets a datagram socket's peer.
    if matches!(
        crate::linux_socket::kind(slot),
        Some(
            crate::linux_socket::Kind::Tcp
                | crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
                | crate::linux_socket::Kind::Icmp
        )
    ) {
        match linux_socket_unspecified_address(address, length) {
            Ok(true) => {
                return crate::linux_socket::disconnect(slot)
                    .map_or_else(linux_socket_error, |()| 0)
            }
            Ok(false) => {}
            Err(error) => return error,
        }
    }
    let endpoint = match linux_socket_address(slot, address, length) {
        Ok(endpoint) => endpoint,
        Err(error) => return error,
    };
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Tcp) {
        if let Err(error) = linux_landlock_check_port(endpoint.port, true) {
            return error;
        }
    }
    if !linux_endpoint_reachable(endpoint) {
        return LINUX_ENETUNREACH;
    }
    match crate::linux_socket::connect(slot, endpoint) {
        Ok(()) => 0,
        Err(crate::linux_socket::Error::InProgress) if !linux_socket_nonblocking(descriptor) => {
            crate::linux_socket::complete_connect(slot).map_or_else(linux_socket_error, |()| 0)
        }
        Err(error) => linux_socket_error(error),
    }
}

fn linux_socket_sendto(
    descriptor: u64,
    address: u64,
    count: u64,
    flags: u64,
    destination: u64,
    destination_length: u64,
) -> u64 {
    const MSG_OOB: u64 = 1;
    const SUPPORTED_FLAGS: u64 = MSG_OOB | 0x40 | 0x4000 | LINUX_MSG_MORE;
    // The largest UDP payload over IPv4.
    const UDP_PAYLOAD_LIMIT: u64 = 65_507;
    let flags = u64::from(flags as u32);
    // Pipes are socket pairs inside, and write(2) on one comes here too.
    let Some(slot) = linux_socket_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    if flags & !SUPPORTED_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    let kind = crate::linux_socket::kind(slot);
    let tcp = kind == Some(crate::linux_socket::Kind::Tcp);
    // Only TCP has urgent data (MSG_OOB is EOPNOTSUPP elsewhere; sent as
    // ordinary data here).
    if flags & MSG_OOB != 0 && !tcp {
        return LINUX_EOPNOTSUPP;
    }
    // The address is read before anything else, as Linux copies it in: a
    // length past sockaddr_storage is EINVAL, an unreadable one EFAULT.
    if destination != 0 && (destination_length as u32 as i32) < 0
        || destination != 0 && u64::from(destination_length as u32) > 128
    {
        return LINUX_EINVAL;
    }
    if tcp && destination != 0 && !copy_from_linux_user(destination, &mut [0_u8; 16]) {
        return LINUX_EFAULT;
    }
    if matches!(
        kind,
        Some(crate::linux_socket::Kind::Udp | crate::linux_socket::Kind::UdpLite)
    ) && count > UDP_PAYLOAD_LIMIT
    {
        return LINUX_EMSGSIZE;
    }
    let netlink = kind == Some(crate::linux_socket::Kind::Netlink);
    let unix = kind == Some(crate::linux_socket::Kind::Unix);
    // A Unix datagram sent to a name goes to the socket bound to it.
    let _target = if unix && destination != 0 {
        match linux_unix_send_target(slot, destination, destination_length) {
            Ok(target) => target,
            Err(error) => return error,
        }
    } else {
        None
    };
    // A TCP socket sends to its peer, whatever address it is given.
    let remote = if destination == 0 || netlink || tcp || unix {
        None
    } else {
        match linux_socket_address(slot, destination, destination_length) {
            Ok(endpoint) => Some(endpoint),
            Err(error) => return error,
        }
    };
    // A stream (a pipe, a socketpair, TCP) takes as much of the write as it
    // has room for in one call; a UDP or ICMP datagram stays within a page.
    let limit = if matches!(
        crate::linux_socket::kind(slot),
        Some(
            crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
                | crate::linux_socket::Kind::Icmp
        )
    ) {
        PAGE_SIZE
    } else {
        1 << 20
    };
    let length = usize::try_from(count).unwrap_or(usize::MAX).min(limit);
    if length == 0 && limit != PAGE_SIZE {
        return 0;
    }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(length).is_err() {
        return LINUX_ENOMEM;
    }
    bytes.resize(length, 0);
    if !copy_from_linux_user(address, &mut bytes) {
        return LINUX_EFAULT;
    }
    let automatic_credentials = if crate::linux_socket::kind(slot)
        == Some(crate::linux_socket::Kind::Unix)
        && crate::linux_socket::unix_peer_passes_credentials(slot).unwrap_or(false)
    {
        let Some(credentials) = current_linux_credentials() else {
            return LINUX_ESRCH;
        };
        if let Err(error) = crate::linux_socket::unix_credentials_queue_available(slot) {
            return linux_socket_error(error);
        }
        Some((
            current_linux_process_pid(),
            credentials.user.effective,
            credentials.group.effective,
        ))
    } else {
        None
    };
    let result = linux_socket_send_corked(slot, descriptor, flags, &bytes[..length], remote);
    match result {
        Ok(written) => {
            if let Some(credentials) = automatic_credentials {
                if let Err(error) = crate::linux_socket::queue_unix_credentials(slot, credentials) {
                    return linux_socket_error(error);
                }
            }
            if written != 0 {
                linux_notify_async_io(slot);
            }
            written as u64
        }
        // A TCP socket never connected cannot send: EPIPE, as Linux's
        // stream send answers (with SIGPIPE).
        Err(crate::linux_socket::Error::NotConnected) if tcp => LINUX_EPIPE,
        Err(error) => linux_socket_error(error),
    }
}

fn linux_socket_recvfrom(
    live: Option<(*mut LinuxSyscallFrame, LinuxUserContext, u64)>,
    descriptor: u64,
    address: u64,
    count: u64,
    flags: u64,
    source: u64,
    source_length: u64,
) -> u64 {
    const MSG_PEEK: u64 = 0x2;
    const MSG_TRUNC: u64 = 0x20;
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_WAITALL: u64 = 0x100;
    // MSG_NOSIGNAL means nothing to a receive; Linux accepts it.
    const MSG_NOSIGNAL: u64 = 0x4000;
    const SUPPORTED_FLAGS: u64 = MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT | MSG_WAITALL | MSG_NOSIGNAL;
    let flags = u64::from(flags as u32);
    let Some(slot) = linux_socket_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // A TLS record that is not application data needs recvmsg's control
    // buffer: here it is EIO.
    linux_tls_receive_control(slot, 0);
    // Linox keeps no socket error queues, so reading one finds it empty.
    if flags & LINUX_MSG_ERRQUEUE != 0 {
        return LINUX_EAGAIN;
    }
    if flags & !SUPPORTED_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    let length = usize::try_from(count).unwrap_or(usize::MAX).min(PAGE_SIZE);
    let mut bytes = [0_u8; PAGE_SIZE];
    let nonblocking = flags & MSG_DONTWAIT != 0 || linux_socket_nonblocking(descriptor);
    let peek_only = flags & MSG_PEEK != 0;
    let wait_all = flags & MSG_WAITALL != 0;
    let result = if nonblocking {
        crate::linux_socket::recv_message(slot, &mut bytes[..length], peek_only)
    } else if matches!(
        crate::linux_socket::kind(slot),
        Some(crate::linux_socket::Kind::Unix | crate::linux_socket::Kind::Netlink)
    ) && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && live.is_some()
    {
        let (output, caller, syscall) = live.unwrap();
        loop {
            match crate::linux_socket::recv_message(slot, &mut bytes[..length], peek_only) {
                // The peer, often a forked child on a socketpair, runs; the
                // receive is retried, or the call restarts later.
                Err(crate::linux_socket::Error::WouldBlock) => {
                    match run_other_linux_processes(output, caller, syscall) {
                        Some(LinuxBlockedWait::Recheck) => continue,
                        Some(LinuxBlockedWait::Return(result)) => return result,
                        // Nothing else can run now: the call waits parked
                        // and starts again, as a blocking receive never
                        // answers EAGAIN (mq_notify03's helper thread).
                        None => return linux_retry_later_live_return(output, caller, syscall),
                    }
                }
                result => break result,
            }
        }
    } else {
        crate::linux_socket::recv_message_blocking(slot, &mut bytes[..length], peek_only, wait_all)
    };
    let (received, message_length, endpoint) = match result {
        Ok(result) => result,
        Err(error) => return linux_socket_error(error),
    };
    if received != 0 && !copy_to_linux_user(address, &bytes[..received]) {
        return LINUX_EFAULT;
    }
    // A netlink message comes from the kernel: sockaddr_nl with port 0.
    if source != 0 && crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Netlink) {
        let mut sockaddr = [0_u8; 12];
        sockaddr[..2].copy_from_slice(&16_u16.to_ne_bytes());
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(source_length, &mut supplied) {
            return LINUX_EFAULT;
        }
        let output_length = (u32::from_ne_bytes(supplied) as usize).min(sockaddr.len());
        if !copy_to_linux_user(source, &sockaddr[..output_length])
            || !copy_to_linux_user(source_length, &(sockaddr.len() as u32).to_ne_bytes())
        {
            return LINUX_EFAULT;
        }
    } else if source != 0 && endpoint.is_none() && crate::linux_socket::unix_type(slot) == Some(2) {
        // A Unix datagram names its sender (bind05 answers it), an unbound
        // one with length 0.
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(source_length, &mut supplied) {
            return LINUX_EFAULT;
        }
        if i32::from_ne_bytes(supplied) < 0 {
            return LINUX_EINVAL;
        }
        if !linux_write_unix_address(
            source,
            source_length,
            &crate::linux_socket::unix_last_sender(slot),
        ) {
            return LINUX_EFAULT;
        }
    } else if source != 0 && endpoint.is_none() {
        // A connected stream names no sender: the length reads back 0 and
        // the address is left alone (recvfrom01's bad address); a negative
        // length is still EINVAL.
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(source_length, &mut supplied) {
            return LINUX_EFAULT;
        }
        if i32::from_ne_bytes(supplied) < 0 {
            return LINUX_EINVAL;
        }
        if !copy_to_linux_user(source_length, &0_u32.to_ne_bytes()) {
            return LINUX_EFAULT;
        }
    } else if source != 0 {
        let Some(endpoint) = endpoint else {
            return LINUX_EINVAL;
        };
        if !linux_write_socket_address(
            source,
            source_length,
            endpoint,
            crate::linux_socket::is_ipv6(slot),
        ) {
            return LINUX_EFAULT;
        }
    }
    if received != 0
        && !peek_only
        && crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Unix)
    {
        let _ = crate::linux_socket::discard_unix_ancillary(slot);
    }
    if flags & MSG_TRUNC != 0
        && matches!(
            crate::linux_socket::kind(slot),
            Some(
                crate::linux_socket::Kind::Udp
                    | crate::linux_socket::Kind::UdpLite
                    | crate::linux_socket::Kind::Icmp
                    | crate::linux_socket::Kind::Netlink
            )
        )
    {
        message_length as u64
    } else {
        received as u64
    }
}

fn linux_socket_sendmsg(descriptor: u64, message: u64, flags: u64) -> u64 {
    const MSG_OOB: u64 = 1;
    const SUPPORTED_FLAGS: u64 = 0x40 | 0x4000 | LINUX_MSG_MORE;
    let flags = u64::from(flags as u32);
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // Only TCP has urgent data, as sendto answers (sendmsg01).
    if flags & MSG_OOB != 0
        && crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Tcp)
    {
        return LINUX_EOPNOTSUPP;
    }
    if flags & !SUPPORTED_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    let mut header = [0_u8; 56];
    if !copy_from_linux_user(message, &mut header) {
        return LINUX_EFAULT;
    }
    let name = u64::from_ne_bytes(header[0..8].try_into().unwrap());
    let name_length = u32::from_ne_bytes(header[8..12].try_into().unwrap()) as u64;
    let iov_address = u64::from_ne_bytes(header[16..24].try_into().unwrap());
    let iov_count = u64::from_ne_bytes(header[24..32].try_into().unwrap());
    let control = u64::from_ne_bytes(header[32..40].try_into().unwrap());
    let control_length = u64::from_ne_bytes(header[40..48].try_into().unwrap());
    let Ok(iov_count) = usize::try_from(iov_count) else {
        return LINUX_EINVAL;
    };
    if iov_count > LINUX_IOV_LIMIT {
        return LINUX_EINVAL;
    }
    let kind = crate::linux_socket::kind(slot);
    let tcp = kind == Some(crate::linux_socket::Kind::Tcp);
    let unix = kind == Some(crate::linux_socket::Kind::Unix);
    // A Unix datagram sent to a name goes to the socket bound to it, its
    // rights and credentials too.
    let _target = if unix && name != 0 {
        match linux_unix_send_target(slot, name, name_length) {
            Ok(target) => target,
            Err(error) => return error,
        }
    } else {
        None
    };
    // A TCP socket sends to its peer, whatever address it is given, as
    // sendto does (sendmsg01).
    let remote = if name == 0 || tcp || unix || kind == Some(crate::linux_socket::Kind::Netlink) {
        None
    } else {
        match linux_socket_address(slot, name, name_length) {
            Ok(endpoint) => Some(endpoint),
            Err(error) => return error,
        }
    };
    // A UDP datagram past the largest IPv4 payload is EMSGSIZE, however
    // its parts are laid out.
    if matches!(
        kind,
        Some(crate::linux_socket::Kind::Udp | crate::linux_socket::Kind::UdpLite)
    ) {
        const UDP_PAYLOAD_LIMIT: u64 = 65_507;
        let mut total = 0_u64;
        for index in 0..iov_count {
            let mut iov = [0_u8; 16];
            if !iov_address
                .checked_add((index * 16) as u64)
                .is_some_and(|entry| copy_from_linux_user(entry, &mut iov))
            {
                return LINUX_EFAULT;
            }
            total = total.saturating_add(u64::from_ne_bytes(iov[8..].try_into().unwrap()));
        }
        if total > UDP_PAYLOAD_LIMIT {
            return LINUX_EMSGSIZE;
        }
    }
    let mut passed_rights = [(0, 0_u32); crate::linux_socket::PASSED_RIGHT_LIMIT];
    let mut passed_files = [None; crate::linux_socket::PASSED_RIGHT_LIMIT];
    let mut passed_right_count = 0_usize;
    let mut passed_credentials = None;
    // A TLS socket's control messages say what record type it sends.
    let tls_sends = crate::linux_socket::tls_sends(slot);
    if control_length != 0 && tls_sends {
        if let Some(error) =
            linux_tls_send_control(slot, control, control_length, flags & LINUX_MSG_MORE != 0)
        {
            return error;
        }
    }
    if control_length != 0 && !tls_sends {
        if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Unix) {
            return LINUX_EINVAL;
        }
        let maximum_right_length = 16 + 4 * crate::linux_socket::PASSED_RIGHT_LIMIT as u64;
        if !(20..=maximum_right_length).contains(&control_length) {
            return LINUX_EINVAL;
        }
        let mut ancillary = [0_u8; 16 + 4 * crate::linux_socket::PASSED_RIGHT_LIMIT];
        let copied = usize::try_from(control_length)
            .unwrap_or(usize::MAX)
            .min(ancillary.len());
        if !copy_from_linux_user(control, &mut ancillary[..copied]) {
            return LINUX_EFAULT;
        }
        let ancillary_length = u64::from_ne_bytes(ancillary[..8].try_into().unwrap());
        let level = i32::from_ne_bytes(ancillary[8..12].try_into().unwrap());
        let kind = i32::from_ne_bytes(ancillary[12..16].try_into().unwrap());
        if level != 1 {
            return LINUX_EINVAL;
        }
        match kind {
            1 => {
                let Some(payload_length) = ancillary_length.checked_sub(16) else {
                    return LINUX_EINVAL;
                };
                if payload_length == 0
                    || payload_length % 4 != 0
                    || ancillary_length > maximum_right_length
                    || control_length < ancillary_length
                    || control_length > ((ancillary_length + 7) & !7)
                {
                    return LINUX_EINVAL;
                }
                passed_right_count = payload_length as usize / 4;
                let mut right_slots = [0; crate::linux_socket::PASSED_RIGHT_LIMIT];
                for index in 0..passed_right_count {
                    let start = 16 + index * 4;
                    let descriptor =
                        i32::from_ne_bytes(ancillary[start..start + 4].try_into().unwrap());
                    let Ok(descriptor) = u64::try_from(descriptor) else {
                        return LINUX_EBADF;
                    };
                    if let Some(right_slot) = linux_socket_slot(descriptor) {
                        let Some(right_flags) = linux_socket_flags(descriptor) else {
                            return LINUX_EBADF;
                        };
                        passed_rights[index] = (right_slot, right_flags);
                        right_slots[index] = right_slot;
                    } else {
                        let Some(file) = linux_file_right(descriptor) else {
                            return LINUX_EBADF;
                        };
                        passed_files[index] = Some(file);
                        right_slots[index] = crate::linux_socket::SlotId::MAX;
                    }
                }
                if let Err(error) = crate::linux_socket::unix_right_queue_available(
                    slot,
                    &right_slots[..passed_right_count],
                ) {
                    return linux_socket_error(error);
                }
                if linux_unix_inflight_limit_exceeded() {
                    return LINUX_ETOOMANYREFS;
                }
            }
            2 if ancillary_length == 28 && (28..=32).contains(&control_length) => {
                let pid = i32::from_ne_bytes(ancillary[16..20].try_into().unwrap());
                let uid = u32::from_ne_bytes(ancillary[20..24].try_into().unwrap());
                let gid = u32::from_ne_bytes(ancillary[24..28].try_into().unwrap());
                let Some(credentials) = current_linux_credentials() else {
                    return LINUX_ESRCH;
                };
                let held = |ids: linox_credentials::Ids, id: u32| {
                    credentials.privileged() || [ids.real, ids.effective, ids.saved].contains(&id)
                };
                if pid < 0
                    || pid as u32 != current_linux_process_pid()
                    || !held(credentials.user, uid)
                    || !held(credentials.group, gid)
                {
                    return LINUX_EPERM;
                }
                if let Err(error) = crate::linux_socket::unix_credentials_queue_available(slot) {
                    return linux_socket_error(error);
                }
                passed_credentials = Some((pid as u32, uid, gid));
            }
            _ => return LINUX_EINVAL,
        }
    }
    if passed_credentials.is_none()
        && crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Unix)
        && crate::linux_socket::unix_peer_passes_credentials(slot).unwrap_or(false)
    {
        let Some(credentials) = current_linux_credentials() else {
            return LINUX_ESRCH;
        };
        if let Err(error) = crate::linux_socket::unix_credentials_queue_available(slot) {
            return linux_socket_error(error);
        }
        passed_credentials = Some((
            current_linux_process_pid(),
            credentials.user.effective,
            credentials.group.effective,
        ));
    }
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut used = 0_usize;
    for index in 0..iov_count {
        let Some(entry) = iov_address.checked_add((index * 16) as u64) else {
            return LINUX_EFAULT;
        };
        let mut iov = [0_u8; 16];
        if !copy_from_linux_user(entry, &mut iov) {
            return LINUX_EFAULT;
        }
        let source = u64::from_ne_bytes(iov[..8].try_into().unwrap());
        let length = usize::try_from(u64::from_ne_bytes(iov[8..].try_into().unwrap()))
            .unwrap_or(usize::MAX)
            .min(PAGE_SIZE - used);
        if !copy_from_linux_user(source, &mut bytes[used..used + length]) {
            return LINUX_EFAULT;
        }
        used += length;
        if used == PAGE_SIZE {
            break;
        }
    }
    if (passed_right_count != 0 || passed_credentials.is_some()) && used == 0 {
        return LINUX_EINVAL;
    }
    for retained_rights in 0..passed_right_count {
        let retained = match passed_files[retained_rights] {
            Some(file) => crate::linux_socket::queue_file_right(file)
                .map(|right| passed_rights[retained_rights].0 = right)
                .is_some(),
            None => crate::linux_socket::duplicate(passed_rights[retained_rights].0),
        };
        if !retained {
            for (rollback, _) in passed_rights.iter().copied().take(retained_rights) {
                let _ = crate::linux_socket::close(rollback);
            }
            return LINUX_ENFILE;
        }
    }
    let result = linux_socket_send_corked(slot, descriptor, flags, &bytes[..used], remote);
    match result {
        Ok(written) => {
            if passed_right_count != 0 {
                if let Err(error) = crate::linux_socket::queue_unix_rights(
                    slot,
                    &passed_rights[..passed_right_count],
                ) {
                    for (passed_slot, _) in passed_rights.iter().copied().take(passed_right_count) {
                        let _ = crate::linux_socket::close(passed_slot);
                    }
                    return linux_socket_error(error);
                }
            }
            if let Some(credentials) = passed_credentials {
                if let Err(error) = crate::linux_socket::queue_unix_credentials(slot, credentials) {
                    let _ = crate::linux_socket::discard_unix_peer_ancillary(slot);
                    return linux_socket_error(error);
                }
            }
            written as u64
        }
        Err(error) => {
            for (passed_slot, _) in passed_rights.iter().copied().take(passed_right_count) {
                let _ = crate::linux_socket::close(passed_slot);
            }
            // A TCP socket never connected cannot send: EPIPE, as sendto.
            if tcp && error == crate::linux_socket::Error::NotConnected {
                return LINUX_EPIPE;
            }
            linux_socket_error(error)
        }
    }
}

fn linux_install_received_socket(
    slot: crate::linux_socket::SlotId,
    flags: u32,
    close_on_exec: bool,
) -> Option<u64> {
    let descriptor = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST)?;
    install_linux_socket_descriptor(
        descriptor,
        slot,
        LINUX_DEVICE_SOCKET | 3,
        flags,
        close_on_exec,
    )
    .then_some(descriptor)
}

// Describes a non-socket descriptor for SCM_RIGHTS with the same state a
// dup(2) copies, so Wayland clients can pass memfd pools and other files.
fn linux_file_right(descriptor: u64) -> Option<crate::linux_socket::FileRight> {
    let device = linux_device_descriptor(descriptor);
    if device == 0
        || device & LINUX_DEVICE_CONSOLE != 0
        || linux_mq_descriptor_id(descriptor).is_some()
        || linux_fanotify_descriptor(descriptor)
        || linux_io_uring_descriptor(descriptor)
    {
        return None;
    }
    let generation = linux_descriptor_tmp_generation(descriptor).unwrap_or(0);
    Some(crate::linux_socket::FileRight {
        device,
        rootfs: linux_rootfs_descriptor(descriptor),
        generation,
        flags: linux_socket_flags(descriptor).unwrap_or(0),
        offset: linux_descriptor_offset(descriptor).load(Ordering::SeqCst),
    })
}

fn linux_install_received_file(
    file: crate::linux_socket::FileRight,
    close_on_exec: bool,
) -> Option<u64> {
    let descriptor = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST)?;
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return install_linux_overflow_descriptor(
            descriptor,
            crate::linux_fd_table::Entry {
                state: file.device,
                rootfs: file.rootfs,
                generation: file.generation,
                socket_flags: file.flags,
                offset: file.offset,
                close_on_exec,
                ..Default::default()
            },
        )
        .then_some(descriptor);
    }
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(file.device, Ordering::SeqCst);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Rootfs).store(file.rootfs, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Generation)
        .store(file.generation, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(file.flags, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(file.offset, Ordering::SeqCst);
    set_linux_descriptor_close_on_exec(descriptor, close_on_exec);
    Some(descriptor)
}

fn linux_unix_inflight_limit_exceeded() -> bool {
    crate::linux_socket::unix_inflight_rights() > linux_nofile_soft_limit() as usize
}

fn linux_socket_recvmsg(
    live: Option<(*mut LinuxSyscallFrame, LinuxUserContext, u64)>,
    descriptor: u64,
    message: u64,
    flags: u64,
) -> u64 {
    const MSG_PEEK: u64 = 0x2;
    const MSG_TRUNC: u64 = 0x20;
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_WAITALL: u64 = 0x100;
    const MSG_CTRUNC: u32 = 0x8;
    const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
    const MSG_NOSIGNAL: u64 = 0x4000;
    const SUPPORTED_FLAGS: u64 =
        MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT | MSG_WAITALL | MSG_CMSG_CLOEXEC | MSG_NOSIGNAL;
    let flags = u64::from(flags as u32);
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // Linux's order: MSG_CMSG_COMPAT is EINVAL, then the header is read
    // (EFAULT) and checked (a negative name length EINVAL, more vectors
    // than UIO_MAXIOV EMSGSIZE), then the flags (recvmsg01).
    const MSG_CMSG_COMPAT: u64 = 0x8000_0000;
    if flags & MSG_CMSG_COMPAT != 0 {
        return LINUX_EINVAL;
    }
    let mut header = [0_u8; 56];
    if !copy_from_linux_user(message, &mut header) {
        return LINUX_EFAULT;
    }
    let name = u64::from_ne_bytes(header[0..8].try_into().unwrap());
    let iov_address = u64::from_ne_bytes(header[16..24].try_into().unwrap());
    let iov_count = usize::try_from(u64::from_ne_bytes(header[24..32].try_into().unwrap()))
        .unwrap_or(usize::MAX);
    let control = u64::from_ne_bytes(header[32..40].try_into().unwrap());
    let control_capacity = u64::from_ne_bytes(header[40..48].try_into().unwrap());
    if i32::from_ne_bytes(header[8..12].try_into().unwrap()) < 0 {
        return LINUX_EINVAL;
    }
    if iov_count > LINUX_IOV_LIMIT {
        return LINUX_EMSGSIZE;
    }
    // Linox keeps no socket error queues, so reading one finds it empty.
    if flags & LINUX_MSG_ERRQUEUE != 0 {
        return LINUX_EAGAIN;
    }
    if flags & !SUPPORTED_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    let right_count = crate::linux_socket::unix_right_count(slot);
    let credentials_pending = crate::linux_socket::unix_credentials_pending(slot);
    let mut right_output_count = right_count;
    while right_output_count != 0
        && ((16 + 4 * right_output_count as u64 + 7) & !7) > control_capacity
    {
        right_output_count -= 1;
    }
    let right_output_space = if right_output_count == 0 {
        0
    } else {
        (16 + 4 * right_output_count as u64 + 7) & !7
    };
    let credentials_output =
        credentials_pending && control_capacity.saturating_sub(right_output_space) >= 32;
    let writable_control =
        usize::try_from(right_output_space + if credentials_output { 32 } else { 0 })
            .unwrap_or(usize::MAX);
    if writable_control != 0
        && (control == 0 || !linux_writable_user_range_contains(control, writable_control))
    {
        return LINUX_EFAULT;
    }
    let mut capacity = 0_usize;
    let mut iovs = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
    for (index, output) in iovs.iter_mut().enumerate().take(iov_count) {
        let Some(entry) = iov_address.checked_add((index * 16) as u64) else {
            return LINUX_EFAULT;
        };
        let mut iov = [0_u8; 16];
        if !copy_from_linux_user(entry, &mut iov) {
            return LINUX_EFAULT;
        }
        output.0 = u64::from_ne_bytes(iov[..8].try_into().unwrap());
        output.1 = usize::try_from(u64::from_ne_bytes(iov[8..].try_into().unwrap()))
            .unwrap_or(usize::MAX)
            .min(PAGE_SIZE.saturating_sub(capacity));
        capacity += output.1;
    }
    let mut bytes = [0_u8; PAGE_SIZE];
    let nonblocking = flags & MSG_DONTWAIT != 0 || linux_socket_nonblocking(descriptor);
    let peek_only = flags & MSG_PEEK != 0;
    let wait_all = flags & MSG_WAITALL != 0;
    linux_tls_receive_control(slot, if control == 0 { 0 } else { control_capacity });
    let result = if nonblocking {
        crate::linux_socket::recv_message(slot, &mut bytes[..capacity], peek_only)
    } else if matches!(
        crate::linux_socket::kind(slot),
        Some(crate::linux_socket::Kind::Unix | crate::linux_socket::Kind::Netlink)
    ) && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && live.is_some()
    {
        let (output, caller, syscall) = live.unwrap();
        loop {
            match crate::linux_socket::recv_message(slot, &mut bytes[..capacity], peek_only) {
                // The peer, often a forked child on a socketpair, runs; the
                // receive is retried, or the call restarts later.
                Err(crate::linux_socket::Error::WouldBlock) => {
                    match run_other_linux_processes(output, caller, syscall) {
                        Some(LinuxBlockedWait::Recheck) => continue,
                        Some(LinuxBlockedWait::Return(result)) => return result,
                        // Nothing else can run now: the call waits parked
                        // and starts again, as a blocking receive never
                        // answers EAGAIN (mq_notify03's helper thread).
                        None => return linux_retry_later_live_return(output, caller, syscall),
                    }
                }
                result => break result,
            }
        }
    } else {
        crate::linux_socket::recv_message_blocking(
            slot,
            &mut bytes[..capacity],
            peek_only,
            wait_all,
        )
    };
    let (received, message_length, endpoint) = match result {
        Ok(result) => result,
        Err(error) => return linux_socket_error(error),
    };
    let mut copied = 0_usize;
    for (destination, length) in iovs.into_iter().take(iov_count) {
        let length = length.min(received - copied);
        if length != 0 && !copy_to_linux_user(destination, &bytes[copied..copied + length]) {
            return LINUX_EFAULT;
        }
        copied += length;
        if copied == received {
            break;
        }
    }
    if name != 0 {
        if let Some(endpoint) = endpoint {
            let name_length_address = message + 8;
            let ipv6 = crate::linux_socket::is_ipv6(slot);
            if !linux_write_socket_address(name, name_length_address, endpoint, ipv6) {
                return LINUX_EFAULT;
            }
            header[8..12].copy_from_slice(&linux_inet_address_size(ipv6).to_ne_bytes());
        } else if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Netlink) {
            // A netlink message comes from the kernel: sockaddr_nl, port 0.
            let mut sockaddr = [0_u8; 12];
            sockaddr[..2].copy_from_slice(&16_u16.to_ne_bytes());
            let supplied = u32::from_ne_bytes(header[8..12].try_into().unwrap());
            let length = (supplied as usize).min(sockaddr.len());
            if !copy_to_linux_user(name, &sockaddr[..length]) {
                return LINUX_EFAULT;
            }
            header[8..12].copy_from_slice(&(sockaddr.len() as u32).to_ne_bytes());
        } else if crate::linux_socket::unix_type(slot) == Some(2) {
            // A Unix datagram's sender, as recvfrom gives it.
            let name_length_address = message + 8;
            if !linux_write_unix_address(
                name,
                name_length_address,
                &crate::linux_socket::unix_last_sender(slot),
            ) {
                return LINUX_EFAULT;
            }
            let mut written = [0_u8; 4];
            if !copy_from_linux_user(name_length_address, &mut written) {
                return LINUX_EFAULT;
            }
            header[8..12].copy_from_slice(&written);
        }
    }
    let mut output_flags = if message_length > received {
        MSG_TRUNC as u32
    } else {
        0
    };
    let mut control_length = 0_u64;
    if right_count != 0 {
        if right_output_count == 0 {
            output_flags |= MSG_CTRUNC;
            if !peek_only {
                let _ = crate::linux_socket::discard_unix_rights(slot);
            }
        } else {
            let mut rights = [(0, 0_u32); crate::linux_socket::PASSED_RIGHT_LIMIT];
            let received_rights =
                match crate::linux_socket::receive_unix_rights(slot, &mut rights, peek_only) {
                    Ok(count) if count == right_count => count,
                    Ok(_) => return LINUX_EINVAL,
                    Err(error) => return linux_socket_error(error),
                };
            let mut ancillary = [0_u8; 16 + 4 * crate::linux_socket::PASSED_RIGHT_LIMIT];
            ancillary[8..12].copy_from_slice(&1_i32.to_ne_bytes());
            ancillary[12..16].copy_from_slice(&1_i32.to_ne_bytes());
            let mut installed = 0_usize;
            for (right_slot, right_flags) in rights
                .iter()
                .copied()
                .take(received_rights.min(right_output_count))
            {
                let close_on_exec = flags & MSG_CMSG_CLOEXEC != 0;
                let received_descriptor = match crate::linux_socket::file_right(right_slot) {
                    // The new descriptor copies the file's state, so the
                    // queued reference to the right is dropped either way.
                    Some(file) => {
                        let installed = linux_install_received_file(file, close_on_exec);
                        let _ = crate::linux_socket::close(right_slot);
                        installed
                    }
                    None => linux_install_received_socket(right_slot, right_flags, close_on_exec),
                };
                let Some(received_descriptor) = received_descriptor else {
                    break;
                };
                let start = 16 + installed * 4;
                ancillary[start..start + 4]
                    .copy_from_slice(&(received_descriptor as i32).to_ne_bytes());
                installed += 1;
            }
            for (right_slot, _) in rights
                .iter()
                .copied()
                .skip(installed)
                .take(received_rights - installed)
            {
                let _ = crate::linux_socket::close(right_slot);
            }
            if installed != received_rights {
                output_flags |= MSG_CTRUNC;
            }
            if installed != 0 {
                let ancillary_length = 16 + installed * 4;
                let ancillary_space = (ancillary_length + 7) & !7;
                ancillary[..8].copy_from_slice(&(ancillary_length as u64).to_ne_bytes());
                if !copy_to_linux_user(control, &ancillary[..ancillary_space]) {
                    for offset in 0..installed {
                        let start = 16 + offset * 4;
                        let descriptor =
                            i32::from_ne_bytes(ancillary[start..start + 4].try_into().unwrap());
                        let _ = linux_descriptor_close(descriptor as u64);
                    }
                    return LINUX_EFAULT;
                }
                control_length = ancillary_space as u64;
            }
        }
    }
    if credentials_pending {
        let remaining = control_capacity.saturating_sub(control_length);
        if remaining < 32 {
            output_flags |= MSG_CTRUNC;
            if !peek_only {
                let _ = crate::linux_socket::receive_unix_credentials(slot, false);
            }
        } else {
            let credentials = match crate::linux_socket::receive_unix_credentials(slot, peek_only) {
                Ok(Some(credentials)) => credentials,
                Ok(None) => return LINUX_EINVAL,
                Err(error) => return linux_socket_error(error),
            };
            let mut ancillary = [0_u8; 32];
            ancillary[..8].copy_from_slice(&28_u64.to_ne_bytes());
            ancillary[8..12].copy_from_slice(&1_i32.to_ne_bytes());
            ancillary[12..16].copy_from_slice(&2_i32.to_ne_bytes());
            ancillary[16..20].copy_from_slice(&(credentials.0 as i32).to_ne_bytes());
            ancillary[20..24].copy_from_slice(&credentials.1.to_ne_bytes());
            ancillary[24..28].copy_from_slice(&credentials.2.to_ne_bytes());
            if !copy_to_linux_user(control + control_length, &ancillary) {
                return LINUX_EFAULT;
            }
            control_length += 32;
        }
    }
    // TLS_GET_RECORD_TYPE: the type of the TLS records read.
    if let Some(written) = linux_tls_record_type_message(
        slot,
        control + control_length,
        if control == 0 {
            0
        } else {
            control_capacity.saturating_sub(control_length)
        },
    ) {
        match written {
            Ok(space) => control_length += space,
            Err(0) => output_flags |= MSG_CTRUNC,
            Err(error) => return error,
        }
    }
    // IP_RECVTTL: the datagram's TTL (SOL_IP, IP_TTL), which ping prints.
    if let Some(ttl) = crate::linux_socket::received_ttl(slot).filter(|_| {
        crate::linux_socket::boolean_option(slot, crate::linux_socket::BooleanOption::ReceiveTtl)
            .unwrap_or(false)
    }) {
        if control_capacity.saturating_sub(control_length) < 24 {
            output_flags |= MSG_CTRUNC;
        } else {
            let mut ancillary = [0_u8; 24];
            ancillary[..8].copy_from_slice(&20_u64.to_ne_bytes());
            ancillary[12..16].copy_from_slice(&2_i32.to_ne_bytes());
            ancillary[16..20].copy_from_slice(&i32::from(ttl).to_ne_bytes());
            if !copy_to_linux_user(control + control_length, &ancillary) {
                return LINUX_EFAULT;
            }
            control_length += 24;
        }
    }
    // IPV6_RECVHOPLIMIT and IPV6_2292HOPLIMIT: the hop limit an ICMPv6
    // datagram arrived with (SOL_IPV6, IPV6_HOPLIMIT, or the RFC 2292 type).
    for (option, kind) in [
        (crate::linux_socket::BooleanOption::ReceiveHopLimit, 52_i32),
        (
            crate::linux_socket::BooleanOption::ReceiveHopLimit2292,
            8_i32,
        ),
    ] {
        let Some(hop_limit) = crate::linux_socket::received_ttl(slot).filter(|_| {
            crate::linux_socket::is_ipv6(slot)
                && crate::linux_socket::boolean_option(slot, option).unwrap_or(false)
        }) else {
            continue;
        };
        if control_capacity.saturating_sub(control_length) < 24 {
            output_flags |= MSG_CTRUNC;
            continue;
        }
        let mut ancillary = [0_u8; 24];
        ancillary[..8].copy_from_slice(&20_u64.to_ne_bytes());
        ancillary[8..12].copy_from_slice(&41_i32.to_ne_bytes());
        ancillary[12..16].copy_from_slice(&kind.to_ne_bytes());
        ancillary[16..20].copy_from_slice(&i32::from(hop_limit).to_ne_bytes());
        if !copy_to_linux_user(control + control_length, &ancillary) {
            return LINUX_EFAULT;
        }
        control_length += 24;
    }
    header[40..48].copy_from_slice(&control_length.to_ne_bytes());
    header[48..52].copy_from_slice(&output_flags.to_ne_bytes());
    if !copy_to_linux_user(message, &header) {
        return LINUX_EFAULT;
    }
    if flags & MSG_TRUNC != 0
        && matches!(
            crate::linux_socket::kind(slot),
            Some(
                crate::linux_socket::Kind::Udp
                    | crate::linux_socket::Kind::UdpLite
                    | crate::linux_socket::Kind::Icmp
                    | crate::linux_socket::Kind::Netlink
            )
        )
    {
        message_length as u64
    } else {
        received as u64
    }
}

fn linux_socket_sendmmsg(descriptor: u64, messages: u64, count: u64, flags: u64) -> (u64, bool) {
    const MMSGHDR_SIZE: u64 = 64;
    let flags = u64::from(flags as u32);
    let Ok(count) = usize::try_from(count) else {
        return (LINUX_EINVAL, false);
    };
    if count > LINUX_IOV_LIMIT {
        return (LINUX_EINVAL, false);
    }
    let mut completed = 0_u64;
    for index in 0..count {
        let Some(message) = messages.checked_add((index as u64) * MMSGHDR_SIZE) else {
            return (
                if completed == 0 {
                    LINUX_EFAULT
                } else {
                    completed
                },
                false,
            );
        };
        let result = linux_socket_sendmsg(descriptor, message, flags);
        if result >= u64::MAX - 4095 {
            return (
                if completed == 0 { result } else { completed },
                result == LINUX_EPIPE,
            );
        }
        let Some(length) = u32::try_from(result).ok() else {
            return (
                if completed == 0 {
                    LINUX_EINVAL
                } else {
                    completed
                },
                false,
            );
        };
        if !copy_to_linux_user(message + 56, &length.to_ne_bytes()) {
            return (
                if completed == 0 {
                    LINUX_EFAULT
                } else {
                    completed
                },
                false,
            );
        }
        completed += 1;
    }
    (completed, false)
}

fn linux_socket_send_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    descriptor: u64,
    result: u64,
    flags: u64,
    broken_pipe: bool,
) -> u64 {
    const MSG_NOSIGNAL: u64 = 0x4000;
    if (result == LINUX_EPIPE || broken_pipe) && flags & MSG_NOSIGNAL == 0 {
        linux_broken_pipe_live_return(output, caller)
    } else if result < u64::MAX - 4095
        && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && crate::linux_socket::kind(
            linux_socket_slot(descriptor).unwrap_or(crate::linux_socket::SlotId::MAX),
        ) == Some(crate::linux_socket::Kind::Unix)
        && X86_RUNTIME
            .LINUX_PROCESS_SCHEDULER_NESTING
            .load(Ordering::SeqCst)
            != 0
        && yield_current_linux_process(caller, result)
    {
        LINUX_RETURN_TO_KERNEL
    } else {
        result
    }
}

fn linux_socket_recvmmsg(
    descriptor: u64,
    messages: u64,
    count: u64,
    flags: u64,
    timeout: u64,
) -> u64 {
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_WAITFORONE: u64 = 0x1_0000;
    const MMSGHDR_SIZE: u64 = 64;
    let flags = u64::from(flags as u32);
    if flags & !(MSG_DONTWAIT | MSG_WAITFORONE) != 0 {
        return LINUX_EINVAL;
    }
    let Ok(count) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if count > LINUX_IOV_LIMIT {
        return LINUX_EINVAL;
    }
    if timeout != 0 {
        let mut value = [0_u8; 16];
        if !copy_from_linux_user(timeout, &mut value) {
            return LINUX_EFAULT;
        }
        if linux_timespec_nanoseconds(&value).is_none() {
            return LINUX_EINVAL;
        }
    }
    let mut completed = 0_u64;
    for index in 0..count {
        let Some(message) = messages.checked_add((index as u64) * MMSGHDR_SIZE) else {
            return if completed == 0 {
                LINUX_EFAULT
            } else {
                completed
            };
        };
        let receive_flags = (flags & MSG_DONTWAIT)
            | (u64::from(flags & MSG_WAITFORONE != 0 && completed != 0) * MSG_DONTWAIT);
        let result = linux_socket_recvmsg(None, descriptor, message, receive_flags);
        if result >= u64::MAX - 4095 {
            return if completed == 0 { result } else { completed };
        }
        let Some(length) = u32::try_from(result).ok() else {
            return if completed == 0 {
                LINUX_EINVAL
            } else {
                completed
            };
        };
        if !copy_to_linux_user(message + 56, &length.to_ne_bytes()) {
            return if completed == 0 {
                LINUX_EFAULT
            } else {
                completed
            };
        }
        completed += 1;
    }
    if timeout != 0 && !copy_to_linux_user(timeout, &[0_u8; 16]) {
        return if completed == 0 {
            LINUX_EFAULT
        } else {
            completed
        };
    }
    completed
}

/// Reports an AF_UNIX peer with no bound name: just the address family, as
/// Linux returns for the client end of a connection to a named listener.
fn linux_write_unnamed_unix_address(address: u64, length_address: u64) -> bool {
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length_address, &mut supplied) {
        return false;
    }
    let length = u32::from_ne_bytes(supplied).min(2) as usize;
    copy_to_linux_user(address, &1_u16.to_ne_bytes()[..length])
        && copy_to_linux_user(length_address, &2_u32.to_ne_bytes())
}

/// MSG_MORE: more data follows, so the send is held back.
const LINUX_MSG_MORE: u64 = 0x8000;

/// Sends `payload` on socket `slot` (descriptor `descriptor`), waiting
/// unless MSG_DONTWAIT or the descriptor says not to. On TCP and UDP,
/// MSG_MORE holds the data back, and the next send without it goes out
/// with what was held, as one datagram on UDP (send02); the count returned
/// is this call's.
fn linux_socket_send_corked(
    slot: crate::linux_socket::SlotId,
    descriptor: u64,
    flags: u64,
    payload: &[u8],
    remote: Option<smoltcp::wire::IpEndpoint>,
) -> Result<usize, crate::linux_socket::Error> {
    if remote.is_some_and(|remote| !linux_endpoint_reachable(remote)) {
        return Err(crate::linux_socket::Error::Unavailable);
    }
    if linux_rtnetlink_socket(slot) {
        return linux_rtnetlink_send(slot, payload);
    }
    let corks = matches!(
        crate::linux_socket::kind(slot),
        Some(
            crate::linux_socket::Kind::Tcp
                | crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
        )
    );
    if corks && flags & LINUX_MSG_MORE != 0 {
        return crate::linux_socket::cork(slot, payload);
    }
    let mut corked = if corks {
        crate::linux_socket::take_corked(slot)
    } else {
        Vec::new()
    };
    let held = corked.len();
    let combined = if held == 0 {
        payload
    } else {
        corked
            .try_reserve(payload.len())
            .map_err(|_| crate::linux_socket::Error::Exhausted)?;
        corked.extend_from_slice(payload);
        &corked
    };
    let sent = if flags & 0x40 != 0 || linux_socket_nonblocking(descriptor) {
        crate::linux_socket::send(slot, combined, remote)
    } else {
        crate::linux_socket::send_blocking(slot, combined, remote)
    };
    sent.map(|written| written.saturating_sub(held))
}

/// A Unix datagram socket's send to a name in progress: its sends go to the
/// socket bound to the name until this is dropped.
struct LinuxUnixSendTarget(crate::linux_socket::SlotId);

impl Drop for LinuxUnixSendTarget {
    fn drop(&mut self) {
        let _ = crate::linux_socket::set_unix_send_target(self.0, None);
    }
}

/// Points Unix socket `slot`'s sends at the datagram socket bound to the
/// sockaddr_un at `address`, as sendto and sendmsg with a name do. A
/// stream socket given a name is EISCONN when connected, else EOPNOTSUPP;
/// no socket at the name is ECONNREFUSED (an abstract name, or a socket
/// file nothing is bound to) or ENOENT.
fn linux_unix_send_target(
    slot: crate::linux_socket::SlotId,
    address: u64,
    length: u64,
) -> Result<Option<LinuxUnixSendTarget>, u64> {
    let mut path = [0_u8; 108];
    let path_length = linux_unix_socket_path(address, length, &mut path)?;
    if crate::linux_socket::unix_type(slot) != Some(2) {
        return Err(if crate::linux_socket::unix_peer_name(slot).is_some() {
            LINUX_EISCONN
        } else {
            LINUX_EOPNOTSUPP
        });
    }
    // A pathname must lead to a file from the sender's root.
    if path[0] != 0 {
        let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        linux_unix_socket_file(&path[..path_length], &mut canonical)?;
    }
    let target = match crate::linux_socket::unix_datagram_target(slot, &path[..path_length]) {
        Ok(target) => {
            linux_landlock_check_unix_peer(target, &path[..path_length])?;
            target
        }
        Err(crate::linux_socket::Error::WrongType) => return Err(LINUX_EPROTOTYPE),
        Err(_) if path[0] == 0 => return Err(LINUX_ECONNREFUSED),
        Err(_) => {
            let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            let socket_file = linux_canonical_path_at(
                u64::from(LINUX_AT_FDCWD),
                &path[..path_length],
                &mut canonical,
            )
            .is_ok_and(|length| {
                crate::linux_overlay::lookup(&canonical[..length])
                    .is_some_and(|metadata| metadata.kind == crate::linux_overlay::NodeKind::Socket)
            });
            return Err(if socket_file {
                LINUX_ECONNREFUSED
            } else {
                LINUX_ENOENT
            });
        }
    };
    crate::linux_socket::set_unix_send_target(slot, Some(target)).map_err(linux_socket_error)?;
    Ok(Some(LinuxUnixSendTarget(slot)))
}

/// Writes Unix socket name `name` as a sockaddr_un at `address`, cut to the
/// length at `length_address`, which then holds the whole length: an
/// unbound socket's name is empty and its length 0.
fn linux_write_unix_address(address: u64, length_address: u64, name: &[u8]) -> bool {
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length_address, &mut supplied) {
        return false;
    }
    if name.is_empty() {
        return copy_to_linux_user(length_address, &0_u32.to_ne_bytes());
    }
    let mut sockaddr = [0_u8; 110];
    let name = &name[..name.len().min(108)];
    sockaddr[..2].copy_from_slice(&1_u16.to_ne_bytes());
    sockaddr[2..2 + name.len()].copy_from_slice(name);
    // A pathname's length takes in its terminating NUL; an abstract one's
    // does not.
    let actual = (2 + name.len() + usize::from(name[0] != 0)).min(sockaddr.len());
    let output_length = (u32::from_ne_bytes(supplied) as usize).min(actual);
    copy_to_linux_user(address, &sockaddr[..output_length])
        && copy_to_linux_user(length_address, &(actual as u32).to_ne_bytes())
}

/// The size of an internet socket's address: sockaddr_in6 for an AF_INET6
/// socket, else sockaddr_in.
fn linux_inet_address_size(ipv6: bool) -> u32 {
    if ipv6 {
        28
    } else {
        16
    }
}

/// Writes `endpoint` as a socket's address: a sockaddr_in, or for an
/// AF_INET6 socket (`ipv6`) a sockaddr_in6 with an IPv4 address mapped
/// (::ffff:a.b.c.d), as much as the length at `length_address` has room
/// for, and the full length there.
fn linux_write_socket_address(
    address: u64,
    length_address: u64,
    endpoint: smoltcp::wire::IpEndpoint,
    ipv6: bool,
) -> bool {
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length_address, &mut supplied) {
        return false;
    }
    let size = linux_inet_address_size(ipv6);
    let length = u32::from_ne_bytes(supplied).min(size);
    let mut sockaddr = [0_u8; 28];
    sockaddr[2..4].copy_from_slice(&endpoint.port.to_be_bytes());
    match endpoint.addr {
        IpAddress::Ipv6(address) => {
            sockaddr[..2].copy_from_slice(&10_u16.to_ne_bytes());
            sockaddr[8..24].copy_from_slice(&address.octets());
        }
        IpAddress::Ipv4(address) if ipv6 => {
            sockaddr[..2].copy_from_slice(&10_u16.to_ne_bytes());
            sockaddr[18..20].copy_from_slice(&[0xff, 0xff]);
            sockaddr[20..24].copy_from_slice(&address.octets());
        }
        IpAddress::Ipv4(address) => {
            sockaddr[..2].copy_from_slice(&2_u16.to_ne_bytes());
            sockaddr[4..8].copy_from_slice(&address.octets());
        }
    }
    copy_to_linux_user(address, &sockaddr[..length as usize])
        && copy_to_linux_user(length_address, &size.to_ne_bytes())
}

fn linux_socket_shutdown(descriptor: u64, how: u64) -> u64 {
    let how = u64::from(how as u32);
    let Some(slot) = linux_socket_slot(descriptor) else {
        let descriptor = u64::from(descriptor as u32);
        return if linux_descriptor_open(descriptor) {
            LINUX_ENOTSOCK
        } else {
            LINUX_EBADF
        };
    };
    if how > 2 {
        return LINUX_EINVAL;
    }
    crate::linux_socket::shutdown_socket(slot, how as u8).map_or_else(linux_socket_error, |()| 0)
}

fn linux_socket_name(descriptor: u64, address: u64, length: u64, peer: bool) -> u64 {
    let Some(slot) = linux_socket_slot(descriptor)
        .filter(|_| !linux_pipe_descriptor(u64::from(descriptor as u32)))
    else {
        return linux_not_socket_error(descriptor);
    };
    // The length is read first: unreadable is EFAULT, negative EINVAL
    // (getsockname01).
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    if i32::from_ne_bytes(supplied) < 0 {
        return LINUX_EINVAL;
    }
    if let Some((_, port)) = crate::linux_socket::netlink_address(slot) {
        // Its own port id; the peer is the kernel (port 0).
        let mut sockaddr = [0_u8; 12];
        sockaddr[..2].copy_from_slice(&16_u16.to_ne_bytes());
        if !peer {
            sockaddr[4..8].copy_from_slice(&port.to_ne_bytes());
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(length, &mut supplied) {
            return LINUX_EFAULT;
        }
        let output_length = (u32::from_ne_bytes(supplied) as usize).min(sockaddr.len());
        return if copy_to_linux_user(address, &sockaddr[..output_length])
            && copy_to_linux_user(length, &(sockaddr.len() as u32).to_ne_bytes())
        {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Unix) {
        let name = if peer {
            let Some(name) = crate::linux_socket::unix_peer_name(slot) else {
                return LINUX_ENOTCONN;
            };
            name
        } else {
            crate::linux_socket::unix_name(slot).unwrap_or_default()
        };
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(length, &mut supplied) {
            return LINUX_EFAULT;
        }
        let mut sockaddr = [0_u8; 110];
        sockaddr[..2].copy_from_slice(&1_u16.to_ne_bytes());
        sockaddr[2..2 + name.len()].copy_from_slice(&name);
        let actual = 2 + name.len() + usize::from(name.first().is_some_and(|byte| *byte != 0));
        let output_length = (u32::from_ne_bytes(supplied) as usize).min(actual);
        return if copy_to_linux_user(address, &sockaddr[..output_length])
            && copy_to_linux_user(length, &(actual as u32).to_ne_bytes())
        {
            0
        } else {
            LINUX_EFAULT
        };
    }
    let Some((local, remote)) = crate::linux_socket::names(slot) else {
        return LINUX_EBADF;
    };
    let endpoint = if peer {
        let Some(remote) = remote else {
            return LINUX_ENOTCONN;
        };
        remote
    } else {
        local
    };
    if linux_write_socket_address(
        address,
        length,
        endpoint,
        crate::linux_socket::is_ipv6(slot),
    ) {
        0
    } else {
        LINUX_EFAULT
    }
}

/// The TPACKET header length (bytes) for version `version` (0: V1, 1: V2,
/// 2: V3): the aligned per-frame header plus the sockaddr_ll a frame carries,
/// as Linux's TPACKET_HDRLEN macros compute. Used to reject a ring whose
/// frame is too small to hold a packet's header.
fn linux_tpacket_hdrlen(version: u8) -> u64 {
    match version {
        // TPACKET_ALIGN(sizeof(tpacket_hdr)) + sizeof(sockaddr_ll) = 32 + 20,
        // and the V2 header aligns to the same 32.
        0 | 1 => 52,
        // TPACKET_ALIGN(sizeof(tpacket3_hdr)) + sizeof(sockaddr_ll) = 48 + 20.
        _ => 68,
    }
}

/// `setsockopt(SOL_PACKET)` on AF_PACKET socket `slot`, validating options in
/// Linux's order and errno (the packet-ring CVE regression tests). No ring is
/// mapped: the geometry is validated and remembered, not allocated.
fn linux_packet_setsockopt(slot: u16, option: u64, value: u64, length: u64) -> u64 {
    const PACKET_RX_RING: u64 = 5;
    const PACKET_VERSION: u64 = 10;
    const PACKET_RESERVE: u64 = 12;
    const PACKET_TX_RING: u64 = 13;
    const PACKET_VNET_HDR: u64 = 15;
    const TPACKET_ALIGNMENT: u64 = 16;
    let Some(info) = crate::linux_socket::packet_info(slot) else {
        return LINUX_ENOTSOCK;
    };
    let read_int = || -> Result<u32, u64> {
        if length < 4 {
            return Err(LINUX_EINVAL);
        }
        let mut supplied = [0_u8; 4];
        if copy_from_linux_user(value, &mut supplied) {
            Ok(u32::from_ne_bytes(supplied))
        } else {
            Err(LINUX_EFAULT)
        }
    };
    match option {
        PACKET_VERSION => {
            // optlen must be exactly an int; the value is V1, V2 or V3.
            if length != 4 {
                return LINUX_EINVAL;
            }
            let version = match read_int() {
                Ok(version) => version,
                Err(error) => return error,
            };
            let version = match version {
                0..=2 => version as u8,
                _ => return LINUX_EINVAL,
            };
            if info.has_ring {
                return LINUX_EBUSY;
            }
            crate::linux_socket::set_packet_version(slot, version);
            0
        }
        PACKET_RESERVE => {
            if length != 4 {
                return LINUX_EINVAL;
            }
            let reserve = match read_int() {
                Ok(reserve) => reserve,
                Err(error) => return error,
            };
            // Capped at INT_MAX (CVE-2017-1000111 / bcc5364bdcfe).
            if reserve > i32::MAX as u32 {
                return LINUX_EINVAL;
            }
            if info.has_ring {
                return LINUX_EBUSY;
            }
            crate::linux_socket::set_packet_reserve(slot, reserve);
            0
        }
        PACKET_VNET_HDR => {
            // A virtio-net header is a SOCK_RAW option; it may not change
            // while a ring is set.
            if info.socket_type != 3 {
                return LINUX_EINVAL;
            }
            if length < 4 {
                return LINUX_EINVAL;
            }
            let enabled = match read_int() {
                Ok(value) => value != 0,
                Err(error) => return error,
            };
            if info.has_ring {
                return LINUX_EBUSY;
            }
            crate::linux_socket::set_packet_vnet_hdr(slot, enabled);
            0
        }
        PACKET_RX_RING | PACKET_TX_RING => {
            // struct tpacket_req is four u32s; the V3 request adds
            // tp_retire_blk_tov, tp_sizeof_priv and tp_feature_req_word.
            let minimum = if info.version == 2 { 28 } else { 16 };
            if length < minimum {
                return LINUX_EINVAL;
            }
            let mut request = [0_u8; 28];
            let wanted = minimum as usize;
            if !copy_from_linux_user(value, &mut request[..wanted]) {
                return LINUX_EFAULT;
            }
            let field = |index: usize| {
                u32::from_ne_bytes(request[index * 4..index * 4 + 4].try_into().unwrap())
            };
            let block_size = field(0);
            let block_nr = field(1);
            let frame_size = field(2);
            let frame_nr = field(3);
            // Tearing a ring down: block_nr 0 needs frame_nr 0, then frees it.
            if block_nr == 0 {
                if frame_nr != 0 {
                    return LINUX_EINVAL;
                }
                crate::linux_socket::set_packet_ring(slot, false);
                return 0;
            }
            // Creating one while another exists is EBUSY (CVE-2016-8655).
            if info.has_ring {
                return LINUX_EBUSY;
            }
            // A virtio-net header with a ring is not supported here.
            if info.vnet_hdr {
                return LINUX_EINVAL;
            }
            // tp_block_size must be a positive, page-aligned size.
            if block_size == 0
                || block_size & 0x8000_0000 != 0
                || !u64::from(block_size).is_multiple_of(PAGE_SIZE as u64)
            {
                return LINUX_EINVAL;
            }
            let min_frame_size = linux_tpacket_hdrlen(info.version) + u64::from(info.reserve);
            // V3 keeps per-block private space ahead of the frames: the block
            // must hold the aligned block descriptor, that space and a frame
            // (CVE-2017-7308, computed in u64 so a huge tp_sizeof_priv cannot
            // overflow into an acceptable value).
            if info.version == 2 {
                let sizeof_priv = u64::from(field(5));
                if u64::from(block_size) < 48 + sizeof_priv + min_frame_size {
                    return LINUX_EINVAL;
                }
            }
            if u64::from(frame_size) < min_frame_size {
                return LINUX_EINVAL;
            }
            if u64::from(frame_size) & (TPACKET_ALIGNMENT - 1) != 0 {
                return LINUX_EINVAL;
            }
            let frames_per_block = block_size / frame_size;
            if frames_per_block == 0 {
                return LINUX_EINVAL;
            }
            if frames_per_block > u32::MAX / block_nr {
                return LINUX_EINVAL;
            }
            if frames_per_block * block_nr != frame_nr {
                return LINUX_EINVAL;
            }
            crate::linux_socket::set_packet_ring(slot, true);
            0
        }
        _ => LINUX_ENOPROTOOPT,
    }
}

/// `getsockopt(SOL_PACKET)` on AF_PACKET socket `slot`: PACKET_VERSION and
/// PACKET_RESERVE return their stored int; other options are unsupported.
fn linux_packet_getsockopt(slot: u16, option: u64, value: u64, length: u64) -> u64 {
    const PACKET_VERSION: u64 = 10;
    const PACKET_RESERVE: u64 = 12;
    let Some(info) = crate::linux_socket::packet_info(slot) else {
        return LINUX_ENOTSOCK;
    };
    let result = match option {
        PACKET_VERSION => u32::from(info.version),
        PACKET_RESERVE => info.reserve,
        _ => return LINUX_ENOPROTOOPT,
    };
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    let Ok(wanted) = usize::try_from(i32::from_ne_bytes(supplied)) else {
        return LINUX_EINVAL;
    };
    let copied = wanted.min(4);
    if copied != 0 && !copy_to_linux_user(value, &result.to_ne_bytes()[..copied])
        || !copy_to_linux_user(length, &(copied as u32).to_ne_bytes())
    {
        return LINUX_EFAULT;
    }
    0
}

fn linux_socket_setsockopt(
    descriptor: u64,
    level: u64,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    let level = u64::from(level as u32);
    let option = u64::from(option as u32);
    let length = u64::from(length as u32);
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // SOL_PACKET options on an AF_PACKET socket.
    if level == 263 {
        return linux_packet_setsockopt(slot, option, value, length);
    }
    if level == 41 {
        return linux_ipv6_setsockopt(slot, option, value, length);
    }
    if level == LINUX_SOL_ICMPV6 && crate::linux_socket::is_ipv6(slot) {
        return linux_icmpv6_setsockopt(slot, option, value, length);
    }
    if level == linox_ktls::SOL_TLS {
        return linux_tls_setsockopt(slot, option, value, length);
    }
    if let Some(coverage) = linux_udplite_coverage_option(level, option) {
        if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::UdpLite) {
            return LINUX_ENOPROTOOPT;
        }
        if length < 4 {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(value, &mut supplied) {
            return LINUX_EFAULT;
        }
        return crate::linux_socket::set_udplite_coverage(
            slot,
            coverage,
            i32::from_ne_bytes(supplied),
        )
        .map_or_else(linux_socket_error, |()| 0);
    }
    // SO_OOBINLINE: an int, read and checked as Linux does (a short length
    // EINVAL, an unreadable value EFAULT); urgent data is not kept apart.
    if level == 1 && option == 10 {
        if length < 4 {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 4];
        return if copy_from_linux_user(value, &mut supplied) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if level == 1 && matches!(option, 20 | 21) {
        if length < 16 {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 16];
        if !copy_from_linux_user(value, &mut supplied) {
            return LINUX_EFAULT;
        }
        let seconds = i64::from_ne_bytes(supplied[..8].try_into().unwrap());
        let microseconds = i64::from_ne_bytes(supplied[8..].try_into().unwrap());
        if seconds < 0 || !(0..1_000_000).contains(&microseconds) {
            return LINUX_EDOM;
        }
        let Some(timeout) = (seconds as u64)
            .checked_mul(1_000_000)
            .and_then(|seconds| seconds.checked_add(microseconds as u64))
        else {
            return LINUX_EDOM;
        };
        let timeout_option = if option == 20 {
            crate::linux_socket::TimeoutOption::Receive
        } else {
            crate::linux_socket::TimeoutOption::Send
        };
        return crate::linux_socket::set_timeout_option(slot, timeout_option, timeout)
            .map_or_else(linux_socket_error, |()| 0);
    }
    // Multicast membership: MCAST_JOIN_GROUP and MCAST_LEAVE_GROUP take a
    // group_req (interface, then a sockaddr_in at offset 8),
    // IP_ADD_MEMBERSHIP and IP_DROP_MEMBERSHIP an ip_mreq (group first).
    // Each socket keeps its own groups; an accepted one has none (accept02).
    if level == 0 && matches!(option, 35 | 36 | 42 | 45) {
        let group_request = matches!(option, 42 | 45);
        let minimum = if group_request { 136 } else { 8 };
        if length < minimum {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 136];
        if !copy_from_linux_user(value, &mut supplied[..minimum as usize]) {
            return LINUX_EFAULT;
        }
        let group = if group_request {
            if u16::from_ne_bytes([supplied[8], supplied[9]]) != 2 {
                return LINUX_EINVAL;
            }
            u32::from_be_bytes(supplied[12..16].try_into().unwrap())
        } else {
            u32::from_be_bytes(supplied[..4].try_into().unwrap())
        };
        if group >> 28 != 0xe {
            return LINUX_EINVAL;
        }
        return crate::linux_socket::change_group(slot, group, matches!(option, 35 | 42))
            .map_or_else(linux_socket_error, |()| 0);
    }
    // SOL_RAW IPV6_CHECKSUM of a raw ICMPv6 socket: an int offset.
    if (level, option) == (255, 7) && crate::linux_socket::is_ipv6(slot) {
        if !crate::linux_socket::is_raw(slot) {
            return LINUX_ENOPROTOOPT;
        }
        if length < 4 {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(value, &mut supplied) {
            return LINUX_EFAULT;
        }
        return crate::linux_socket::set_icmpv6_checksum(slot, i32::from_ne_bytes(supplied))
            .map_or_else(linux_socket_error, |()| 0);
    }
    if matches!((level, option), (0, 2) | (255, 1)) {
        if length < 4 {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(value, &mut supplied) {
            return LINUX_EFAULT;
        }
        let value = i32::from_ne_bytes(supplied);
        if level == 255 {
            return crate::linux_socket::set_icmp_filter(slot, value as u32)
                .map_or(LINUX_EOPNOTSUPP, |()| 0);
        }
        // IP_TTL: 1 to 255, or -1 for the default.
        let ttl = match value {
            -1 => 0,
            1..=255 => value as u8,
            _ => return LINUX_EINVAL,
        };
        return crate::linux_socket::set_ttl(slot, ttl).map_or(LINUX_ENOPROTOOPT, |()| 0);
    }
    let boolean_option = match (level, option) {
        // IP_RETOPTS: received IP options; smoltcp keeps none to return.
        (0, 7) => None,
        (0, 11) => Some(crate::linux_socket::BooleanOption::ReceiveErrors),
        (0, 12) => Some(crate::linux_socket::BooleanOption::ReceiveTtl),
        // IP_HDRINCL: raw sockets only.
        (0, 3) => {
            if !crate::linux_socket::is_raw(slot) {
                return LINUX_ENOPROTOOPT;
            }
            Some(crate::linux_socket::BooleanOption::HeaderIncluded)
        }
        (1, 2) => Some(crate::linux_socket::BooleanOption::ReuseAddress),
        (1, 6) => Some(crate::linux_socket::BooleanOption::Broadcast),
        (1, 9) => Some(crate::linux_socket::BooleanOption::KeepAlive),
        (1, 11) => Some(crate::linux_socket::BooleanOption::NoCheck),
        (1, 16) => Some(crate::linux_socket::BooleanOption::PassCredentials),
        (1, 29) => Some(crate::linux_socket::BooleanOption::Timestamp),
        // These options are advisory for the current in-kernel socket
        // transport. Accept them so service managers can configure standard
        // Linux logging sockets without a compatibility warning.
        (1, 32..=34) => None,
        (6, 1) => {
            if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Tcp) {
                return LINUX_EOPNOTSUPP;
            }
            Some(crate::linux_socket::BooleanOption::NoDelay)
        }
        (1, 7 | 8) => None,
        // TCP_ULP: "tls" is the upper layer there is (kernel TLS).
        (6, LINUX_TCP_ULP) => return linux_set_ulp(slot, value, length),
        _ => return LINUX_ENOPROTOOPT,
    };
    if length < 4 {
        return LINUX_EINVAL;
    }
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(value, &mut supplied) {
        return LINUX_EFAULT;
    }
    let enabled = i32::from_ne_bytes(supplied) != 0;
    boolean_option.map_or(0, |option| {
        crate::linux_socket::set_boolean_option(slot, option, enabled)
            .map_or_else(linux_socket_error, |()| 0)
    })
}

/// UDPLITE_SEND_CSCOV (10) or UDPLITE_RECV_CSCOV (11), at SOL_UDP or
/// SOL_UDPLITE, as Linux takes either level for them.
fn linux_udplite_coverage_option(level: u64, option: u64) -> Option<crate::linux_socket::Coverage> {
    match (level, option) {
        (17 | 136, 10) => Some(crate::linux_socket::Coverage::Send),
        (17 | 136, 11) => Some(crate::linux_socket::Coverage::Receive),
        _ => None,
    }
}

/// SOL_ICMPV6 (IPPROTO_ICMPV6), the level of ICMPV6_FILTER.
const LINUX_SOL_ICMPV6: u64 = 58;
/// ICMPV6_FILTER: a raw ICMPv6 socket's struct icmp6_filter.
const LINUX_ICMPV6_FILTER: u64 = 1;

/// setsockopt(SOL_ICMPV6, ...) on AF_INET6 socket `slot`: ICMPV6_FILTER
/// on a raw ICMPv6 socket, as many bytes of the filter as are given (up to
/// its 32). Other sockets lack the level (ENOPROTOOPT, as ipv6_setsockopt
/// answers a ping, TCP or UDP socket).
fn linux_icmpv6_setsockopt(
    slot: crate::linux_socket::SlotId,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    if !crate::linux_socket::is_raw(slot) {
        return LINUX_ENOPROTOOPT;
    }
    if option != LINUX_ICMPV6_FILTER {
        return LINUX_ENOPROTOOPT;
    }
    let mut filter = [0_u8; 32];
    let length = usize::try_from(length)
        .unwrap_or(usize::MAX)
        .min(filter.len());
    if !copy_from_linux_user(value, &mut filter[..length]) {
        return LINUX_EFAULT;
    }
    crate::linux_socket::set_icmpv6_filter(slot, &filter[..length])
        .map_or_else(linux_socket_error, |()| 0)
}

/// getsockopt(SOL_ICMPV6, ICMPV6_FILTER) on a raw ICMPv6 socket: as much
/// of the filter as the length has room for (a negative one EINVAL).
fn linux_icmpv6_getsockopt(
    slot: crate::linux_socket::SlotId,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    if !crate::linux_socket::is_raw(slot) || option != LINUX_ICMPV6_FILTER {
        return LINUX_ENOPROTOOPT;
    }
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    let Ok(supplied) = usize::try_from(i32::from_ne_bytes(supplied)) else {
        return LINUX_EINVAL;
    };
    let filter = match crate::linux_socket::icmpv6_filter(slot) {
        Ok(filter) => filter,
        Err(error) => return linux_socket_error(error),
    };
    let copied = supplied.min(filter.len());
    if !copy_to_linux_user(length, &(copied as u32).to_ne_bytes())
        || copied != 0 && !copy_to_linux_user(value, &filter[..copied])
    {
        return LINUX_EFAULT;
    }
    0
}

/// IPV6_V6ONLY (an int).
const LINUX_IPV6_V6ONLY: u64 = 26;
/// IPV6_ADDRFORM: an int, the family to turn an AF_INET6 socket into.
const LINUX_IPV6_ADDRFORM: u64 = 1;
/// IPV6_MTU: the path MTU a socket sends with (an int, 0 for the route's).
const LINUX_IPV6_MTU: u64 = 24;

/// setsockopt(IPPROTO_IPV6, ...) on socket `slot`, which must be an AF_INET6
/// one (ENOPROTOOPT otherwise, as IPv4 sockets lack the level).
fn linux_ipv6_setsockopt(
    slot: crate::linux_socket::SlotId,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    if !crate::linux_socket::is_ipv6(slot) {
        return LINUX_ENOPROTOOPT;
    }
    // Every option here is an int; Linux reads it before acting.
    let read_int = || -> Result<i32, u64> {
        if length < 4 {
            return Err(LINUX_EINVAL);
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(value, &mut supplied) {
            return Err(LINUX_EFAULT);
        }
        Ok(i32::from_ne_bytes(supplied))
    };
    match option {
        LINUX_IPV6_V6ONLY => match read_int() {
            Ok(enabled) => crate::linux_socket::set_v6only(slot, enabled != 0)
                .map_or_else(linux_socket_error, |()| 0),
            Err(error) => error,
        },
        // Only AF_INET is a family to turn into.
        LINUX_IPV6_ADDRFORM => match read_int() {
            Ok(2) => {
                crate::linux_socket::address_form_ipv4(slot).map_or_else(linux_socket_error, |()| 0)
            }
            Ok(_) => LINUX_EINVAL,
            Err(error) => error,
        },
        // The largest fragment to send: 0 (the route's) or at least IPv6's
        // minimum link MTU, 1280. Datagrams here are not fragmented, so the
        // size is only checked.
        LINUX_IPV6_MTU => match read_int() {
            Ok(mtu) if mtu == 0 || mtu >= 1280 => 0,
            Ok(_) => LINUX_EINVAL,
            Err(error) => error,
        },
        // IPV6_RECVHOPLIMIT and IPV6_2292HOPLIMIT: an int, nonzero to
        // receive each datagram's hop limit.
        51 | 8 => match read_int() {
            Ok(enabled) => crate::linux_socket::set_boolean_option(
                slot,
                if option == 51 {
                    crate::linux_socket::BooleanOption::ReceiveHopLimit
                } else {
                    crate::linux_socket::BooleanOption::ReceiveHopLimit2292
                },
                enabled != 0,
            )
            .map_or_else(linux_socket_error, |()| 0),
            Err(error) => error,
        },
        // IPV6_RTHDR: routing headers are not sent here, so none is taken
        // (EINVAL, as Linux answers a type it does not build).
        57 => {
            if length == 0 {
                0
            } else {
                LINUX_EINVAL
            }
        }
        _ => LINUX_ENOPROTOOPT,
    }
}

/// getsockopt(IPPROTO_IPV6, ...) on AF_INET6 socket `slot`.
fn linux_ipv6_getsockopt(
    slot: crate::linux_socket::SlotId,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    if !crate::linux_socket::is_ipv6(slot) {
        return LINUX_EOPNOTSUPP;
    }
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    let Ok(supplied) = usize::try_from(i32::from_ne_bytes(supplied)) else {
        return LINUX_EINVAL;
    };
    let result = match option {
        LINUX_IPV6_V6ONLY => i32::from(crate::linux_socket::v6only(slot).unwrap_or(false)),
        51 | 8 => i32::from(
            crate::linux_socket::boolean_option(
                slot,
                if option == 51 {
                    crate::linux_socket::BooleanOption::ReceiveHopLimit
                } else {
                    crate::linux_socket::BooleanOption::ReceiveHopLimit2292
                },
            )
            .unwrap_or(false),
        ),
        // A connected socket's route MTU: loopback's 65536, eth0's 1500;
        // ENOTCONN with no route yet, as in Linux.
        LINUX_IPV6_MTU => match crate::linux_socket::names(slot).and_then(|(_, remote)| remote) {
            Some(remote)
                if match remote.addr {
                    IpAddress::Ipv4(address) => address.is_loopback(),
                    IpAddress::Ipv6(address) => address.is_loopback(),
                } =>
            {
                65_536
            }
            Some(_) => 1500,
            None => return LINUX_ENOTCONN,
        },
        _ => return LINUX_ENOPROTOOPT,
    };
    let copied = supplied.min(4);
    if copied != 0 && !copy_to_linux_user(value, &result.to_ne_bytes()[..copied])
        || !copy_to_linux_user(length, &(copied as u32).to_ne_bytes())
    {
        return LINUX_EFAULT;
    }
    0
}

fn linux_socket_getsockopt(
    descriptor: u64,
    level: u64,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    let level = u64::from(level as u32);
    let option = u64::from(option as u32);
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // SOL_PACKET options on an AF_PACKET socket.
    if level == 263 {
        return linux_packet_getsockopt(slot, option, value, length);
    }
    if level == 41 {
        return linux_ipv6_getsockopt(slot, option, value, length);
    }
    if level == LINUX_SOL_ICMPV6 && crate::linux_socket::is_ipv6(slot) {
        return linux_icmpv6_getsockopt(slot, option, value, length);
    }
    if level == linox_ktls::SOL_TLS {
        return linux_tls_getsockopt(slot, option, value, length);
    }
    if (level, option) == (6, LINUX_TCP_ULP)
        && crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Tcp)
    {
        return linux_get_ulp(slot, value, length);
    }
    if level == 1 && option == 17 {
        if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Unix) {
            return LINUX_ENOPROTOOPT;
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(length, &mut supplied) {
            return LINUX_EFAULT;
        }
        if u32::from_ne_bytes(supplied) < 12 {
            return LINUX_EINVAL;
        }
        let Some(credentials) = crate::linux_socket::unix_peer_credentials(slot) else {
            return LINUX_ENOTCONN;
        };
        let mut output = [0_u8; 12];
        output[..4].copy_from_slice(&(credentials.0 as i32).to_ne_bytes());
        output[4..8].copy_from_slice(&credentials.1.to_ne_bytes());
        output[8..].copy_from_slice(&credentials.2.to_ne_bytes());
        return if copy_to_linux_user(value, &output)
            && copy_to_linux_user(length, &12_u32.to_ne_bytes())
        {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if level == 1 && matches!(option, 20 | 21) {
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(length, &mut supplied) {
            return LINUX_EFAULT;
        }
        if u32::from_ne_bytes(supplied) < 16 {
            return LINUX_EINVAL;
        }
        let timeout_option = if option == 20 {
            crate::linux_socket::TimeoutOption::Receive
        } else {
            crate::linux_socket::TimeoutOption::Send
        };
        let timeout = match crate::linux_socket::timeout_option(slot, timeout_option) {
            Ok(timeout) => timeout,
            Err(error) => return linux_socket_error(error),
        };
        let mut output = [0_u8; 16];
        output[..8].copy_from_slice(&(timeout / 1_000_000).to_ne_bytes());
        output[8..].copy_from_slice(&(timeout % 1_000_000).to_ne_bytes());
        return if copy_to_linux_user(value, &output)
            && copy_to_linux_user(length, &16_u32.to_ne_bytes())
        {
            0
        } else {
            LINUX_EFAULT
        };
    }
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    let Ok(supplied) = usize::try_from(i32::from_ne_bytes(supplied)) else {
        return LINUX_EINVAL;
    };
    // A level the socket's family does not have is EOPNOTSUPP, as Linux's
    // protocol handlers answer (getsockopt01): SOL_SOCKET everywhere, IP
    // on inet sockets, TCP or UDP on their own, ICMP's on a raw ICMP one.
    let kind = crate::linux_socket::kind(slot);
    let level_known = match level {
        1 => true,
        0 => matches!(
            kind,
            Some(
                crate::linux_socket::Kind::Tcp
                    | crate::linux_socket::Kind::Udp
                    | crate::linux_socket::Kind::UdpLite
                    | crate::linux_socket::Kind::Icmp
            )
        ),
        6 => kind == Some(crate::linux_socket::Kind::Tcp),
        17 => matches!(
            kind,
            Some(crate::linux_socket::Kind::Udp | crate::linux_socket::Kind::UdpLite)
        ),
        136 => kind == Some(crate::linux_socket::Kind::UdpLite),
        255 => kind == Some(crate::linux_socket::Kind::Icmp),
        _ => false,
    };
    if !level_known {
        return LINUX_EOPNOTSUPP;
    }
    let read_boolean = |option| match crate::linux_socket::boolean_option(slot, option) {
        Ok(value) => Ok(i32::from(value)),
        Err(error) => Err(linux_socket_error(error)),
    };
    let result = match (level, option) {
        (0, 2) => match crate::linux_socket::ttl(slot) {
            Ok(ttl) => i32::from(ttl),
            Err(_) => return LINUX_ENOPROTOOPT,
        },
        (0, 11) => match read_boolean(crate::linux_socket::BooleanOption::ReceiveErrors) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (0, 12) => match read_boolean(crate::linux_socket::BooleanOption::ReceiveTtl) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (0, 3) if crate::linux_socket::is_raw(slot) => {
            match read_boolean(crate::linux_socket::BooleanOption::HeaderIncluded) {
                Ok(value) => value,
                Err(error) => return error,
            }
        }
        // ICMP_FILTER of a raw ICMP socket.
        (255, 1) => match crate::linux_socket::icmp_filter(slot) {
            Ok(filter) => filter as i32,
            Err(_) => return LINUX_EOPNOTSUPP,
        },
        (1, 2) => match read_boolean(crate::linux_socket::BooleanOption::ReuseAddress) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (1, 6) => match read_boolean(crate::linux_socket::BooleanOption::Broadcast) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (255, 7) if crate::linux_socket::is_ipv6(slot) => {
            match crate::linux_socket::icmpv6_checksum(slot) {
                Ok(offset) => offset,
                Err(_) => return LINUX_ENOPROTOOPT,
            }
        }
        (1, 11) => match read_boolean(crate::linux_socket::BooleanOption::NoCheck) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (1, 3) => match crate::linux_socket::socket_type(slot) {
            Some(socket_type) => i32::from(socket_type),
            None => return LINUX_EBADF,
        },
        (1, 4) => {
            crate::linux_socket::readiness(slot).is_some_and(|(_, _, error)| error) as i32 * 111
        }
        (1, 7 | 8) => 64 * 1024,
        // SO_OOBINLINE: urgent data is not kept apart here.
        (1, 10) => 0,
        (1, 9) => match read_boolean(crate::linux_socket::BooleanOption::KeepAlive) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (1, 16) => match read_boolean(crate::linux_socket::BooleanOption::PassCredentials) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (1, 29) => match read_boolean(crate::linux_socket::BooleanOption::Timestamp) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (1, 30) => i32::from(crate::linux_socket::is_listening(slot)),
        (1, 32 | 33) => 64 * 1024,
        (1, 34) => 0,
        (1, 38) => match crate::linux_socket::kind(slot) {
            Some(crate::linux_socket::Kind::Tcp) => 6,
            Some(crate::linux_socket::Kind::Udp) => 17,
            Some(crate::linux_socket::Kind::UdpLite) => 136,
            Some(crate::linux_socket::Kind::Icmp) if crate::linux_socket::is_ipv6(slot) => 58,
            Some(crate::linux_socket::Kind::Icmp) => 1,
            Some(crate::linux_socket::Kind::Unix) => 0,
            Some(crate::linux_socket::Kind::Netlink) => crate::linux_socket::netlink_address(slot)
                .map_or(0, |(protocol, _)| i32::from(protocol)),
            // SO_PROTOCOL on an AF_PACKET socket: no single IP protocol.
            Some(crate::linux_socket::Kind::Packet) => 0,
            Some(crate::linux_socket::Kind::Object) => return LINUX_ENOTSOCK,
            None => return LINUX_EBADF,
        },
        (1, 39) => match crate::linux_socket::kind(slot) {
            Some(
                crate::linux_socket::Kind::Tcp
                | crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
                | crate::linux_socket::Kind::Icmp,
            ) if crate::linux_socket::is_ipv6(slot) => 10,
            Some(
                crate::linux_socket::Kind::Tcp
                | crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
                | crate::linux_socket::Kind::Icmp,
            ) => 2,
            Some(crate::linux_socket::Kind::Unix) => 1,
            Some(crate::linux_socket::Kind::Netlink) => 16,
            Some(crate::linux_socket::Kind::Packet) => 17,
            Some(crate::linux_socket::Kind::Object) => return LINUX_ENOTSOCK,
            None => return LINUX_EBADF,
        },
        (17 | 136, 10 | 11) => match crate::linux_socket::udplite_coverage(
            slot,
            if option == 10 {
                crate::linux_socket::Coverage::Send
            } else {
                crate::linux_socket::Coverage::Receive
            },
        ) {
            Ok(coverage) => i32::from(coverage),
            Err(_) => return LINUX_ENOPROTOOPT,
        },
        (6, 1) => {
            if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Tcp) {
                return LINUX_EOPNOTSUPP;
            }
            match read_boolean(crate::linux_socket::BooleanOption::NoDelay) {
                Ok(value) => value,
                Err(error) => return error,
            }
        }
        _ => return LINUX_ENOPROTOOPT,
    };
    // A shorter buffer gets the first bytes of the int, as in Linux.
    let copied = supplied.min(4);
    if copied != 0 && !copy_to_linux_user(value, &result.to_ne_bytes()[..copied])
        || !copy_to_linux_user(length, &(copied as u32).to_ne_bytes())
    {
        return LINUX_EFAULT;
    }
    0
}

fn clear_linux_poll_snapshot(slot: usize) {
    for descriptor in &X86_RUNTIME.LINUX_THREAD_POLL_DESCRIPTORS[slot] {
        descriptor.store(0, Ordering::SeqCst);
    }
    for events in &X86_RUNTIME.LINUX_THREAD_POLL_EVENTS[slot] {
        events.store(0, Ordering::SeqCst);
    }
    crate::linux_wait_sets::remove(linux_wait_set_key(slot));
}

/// The `linux_wait_sets` key of the current process's thread `slot`.
fn linux_wait_set_key(slot: usize) -> crate::linux_wait_sets::Key {
    (
        linux_execution_instance(),
        current_linux_process_pid(),
        slot as u16,
    )
}

/// How many descriptors the current process's table has room for, as
/// Linux's fdtable max_fds (what select looks at, at most): the fixed
/// table, or a size past it covering the highest descriptor open there,
/// grown as Linux grows its table (a power of two times 128).
fn linux_descriptor_table_size() -> u64 {
    let Some(&(highest, _)) = linux_overflow_descriptors().last() else {
        return LINUX_DESCRIPTOR_TABLE_LIMIT;
    };
    ((highest / 128 + 1).next_power_of_two() * 128)
        .min(linux_nr_open().max(highest + 1))
        .max(LINUX_DESCRIPTOR_TABLE_LIMIT)
}

fn clear_linux_select_snapshot(slot: usize) {
    X86_RUNTIME.LINUX_THREAD_SELECT_READ_ADDRESSES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_ADDRESSES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES[slot].store(0, Ordering::SeqCst);
    for value in &X86_RUNTIME.LINUX_THREAD_SELECT_READ_SETS[slot] {
        value.store(0, Ordering::SeqCst);
    }
    for value in &X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_SETS[slot] {
        value.store(0, Ordering::SeqCst);
    }
    for value in &X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_SETS[slot] {
        value.store(0, Ordering::SeqCst);
    }
    crate::linux_wait_sets::remove(linux_wait_set_key(slot));
}

fn clear_linux_iov_snapshot(slot: usize) {
    for address in &X86_RUNTIME.LINUX_THREAD_IOV_ADDRESSES[slot] {
        address.store(0, Ordering::SeqCst);
    }
    for length in &X86_RUNTIME.LINUX_THREAD_IOV_LENGTHS[slot] {
        length.store(0, Ordering::SeqCst);
    }
}

fn complete_linux_poll_wait(slot: usize, timed_out: bool) -> bool {
    let kind = if slot < LINUX_THREAD_LIMIT {
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
    } else {
        LINUX_THREAD_WAIT_NONE
    };
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || !matches!(kind, LINUX_THREAD_WAIT_POLL | LINUX_THREAD_WAIT_PPOLL)
    {
        return false;
    }
    let count = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst) as usize;
    // More pollfds than the fixed snapshot holds wait in linux_wait_sets.
    let stored = if count > LINUX_POLLFD_LIMIT {
        match crate::linux_wait_sets::load(linux_wait_set_key(slot)) {
            Some(words) if words.len() == count => Some(words),
            _ => return false,
        }
    } else {
        None
    };
    let mut small = [0_u8; LINUX_POLLFD_LIMIT * 8];
    let mut large = Vec::new();
    let pollfds: &mut [u8] = if stored.is_some() {
        if large.try_reserve_exact(count * 8).is_err() {
            return false;
        }
        large.resize(count * 8, 0);
        &mut large[..]
    } else {
        &mut small[..]
    };
    let mut ready = 0_u64;
    for index in 0..count {
        let (descriptor, events) = match &stored {
            Some(words) => (words[index] as u32, (words[index] >> 32) as u16),
            None => (
                X86_RUNTIME.LINUX_THREAD_POLL_DESCRIPTORS[slot][index].load(Ordering::SeqCst),
                X86_RUNTIME.LINUX_THREAD_POLL_EVENTS[slot][index].load(Ordering::SeqCst),
            ),
        };
        let returned = linux_descriptor_poll_events(descriptor as i32, events);
        let offset = index * 8;
        pollfds[offset..offset + 4].copy_from_slice(&descriptor.to_ne_bytes());
        pollfds[offset + 4..offset + 6].copy_from_slice(&events.to_ne_bytes());
        pollfds[offset + 6..offset + 8].copy_from_slice(&returned.to_ne_bytes());
        ready += u64::from(returned != 0);
    }
    if ready == 0 && !timed_out {
        return false;
    }
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = if count == 0 || copy_to_linux_user(address, &pollfds[..count * 8]) {
        ready
    } else {
        LINUX_EFAULT
    };
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    if kind == LINUX_THREAD_WAIT_PPOLL {
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(
            X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].swap(0, Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
    clear_linux_poll_snapshot(slot);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    match (kind, timed_out) {
        (LINUX_THREAD_WAIT_POLL, true) => {
            X86_RUNTIME
                .LINUX_POLL_WAIT_TIMEOUT_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_POLL, false) => {
            X86_RUNTIME
                .LINUX_POLL_WAIT_WAKE_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_PPOLL, true) => {
            X86_RUNTIME
                .LINUX_PPOLL_WAIT_TIMEOUT_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_PPOLL, false) => {
            X86_RUNTIME
                .LINUX_PPOLL_WAIT_WAKE_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        _ => {}
    }
    true
}

fn linux_eventfd(initial: u64, flags: u64) -> u64 {
    let flags = u64::from(flags as u32);
    if flags & !(LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_O_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && X86_RUNTIME
            .ELF_PROBE_EVENTFD_DESCRIPTOR
            .load(Ordering::SeqCst)
            != 0
    {
        return LINUX_EMFILE;
    }
    let descriptor_start = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        LINUX_AUX_DESCRIPTOR_FIRST
    } else {
        2
    };
    let descriptor = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        match linux_allocate_descriptor(descriptor_start) {
            Ok(descriptor) => descriptor,
            Err(error) => return error,
        }
    } else {
        let Some(descriptor) = (descriptor_start..LINUX_AUX_DESCRIPTOR_LIMIT)
            .find(|descriptor| linux_aux_descriptor_free(*descriptor))
        else {
            return LINUX_EMFILE;
        };
        descriptor
    };
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let Some(id) =
            crate::linux_event_files::create_eventfd(u64::from(initial as u32), flags as u32)
        else {
            return LINUX_ENFILE;
        };
        linux_legacy_descriptor_offset(descriptor).store(id, Ordering::SeqCst);
        linux_fd_cell::<u8>(descriptor, LinuxFdField::EventFd).store(1, Ordering::SeqCst);
    } else {
        X86_RUNTIME
            .ELF_PROBE_EVENTFD_COUNTER
            .store(u64::from(initial as u32), Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_EVENTFD_FLAGS
            .store(flags as u32, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_EVENTFD_DESCRIPTOR
            .store(descriptor as u16, Ordering::SeqCst);
    }
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    descriptor
}

/// An eventfd descriptor's counter and flags: its open file's, or the boot
/// probe's own.
fn linux_eventfd_state(
    descriptor: u64,
) -> Option<(
    &'static dyn LinuxFileCell<u64>,
    &'static dyn LinuxFileCell<u32>,
)> {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let id = linux_eventfd_file(descriptor)?;
        let file = crate::linux_event_files::eventfd(id)?;
        Some((&file.counter, &file.flags))
    } else {
        let stored = X86_RUNTIME
            .ELF_PROBE_EVENTFD_DESCRIPTOR
            .load(Ordering::SeqCst);
        (stored != 0 && u64::from(stored) == descriptor).then_some((
            &X86_RUNTIME.ELF_PROBE_EVENTFD_COUNTER,
            &X86_RUNTIME.ELF_PROBE_EVENTFD_FLAGS,
        ))
    }
}

/// The open file id of eventfd `descriptor` (in its offset cell).
fn linux_eventfd_file(descriptor: u64) -> Option<u64> {
    let descriptor = u64::from(descriptor as u32);
    (descriptor >= LINUX_AUX_DESCRIPTOR_FIRST
        && linux_fd_cell::<u8>(descriptor, LinuxFdField::EventFd).load(Ordering::SeqCst) != 0)
        .then(|| linux_legacy_descriptor_offset(descriptor).load(Ordering::SeqCst))
}

/// The open file id of timerfd `descriptor`.
fn linux_timerfd_file(descriptor: u64) -> Option<u64> {
    let descriptor = u64::from(descriptor as u32);
    (descriptor >= LINUX_AUX_DESCRIPTOR_FIRST
        && linux_fd_cell::<u8>(descriptor, LinuxFdField::TimerFd).load(Ordering::SeqCst) != 0)
        .then(|| linux_legacy_descriptor_offset(descriptor).load(Ordering::SeqCst))
}

/// Puts a new descriptor `target` on the eventfd or timerfd open file of
/// `source`, as dup2 does, closing what `target` held.
fn linux_event_file_dup(source: u64, target: u64) -> u64 {
    let (kind, id) = match (linux_eventfd_file(source), linux_timerfd_file(source)) {
        (Some(id), _) => (crate::linux_event_files::Kind::EventFd, id),
        (_, Some(id)) => (crate::linux_event_files::Kind::TimerFd, id),
        _ => return LINUX_EBADF,
    };
    if source == target {
        return target;
    }
    // The descriptor kinds below 3 have no eventfd or timerfd slot.
    if target < LINUX_AUX_DESCRIPTOR_FIRST || target >= linux_nofile_soft_limit() {
        return LINUX_EBADF;
    }
    if linux_descriptor_open(target) && linux_descriptor_close(target) != 0 {
        return LINUX_EBADF;
    }
    if !crate::linux_event_files::retain(kind, id) {
        return LINUX_EBADF;
    }
    linux_legacy_descriptor_offset(target).store(id, Ordering::SeqCst);
    match kind {
        crate::linux_event_files::Kind::EventFd => {
            linux_fd_cell::<u8>(target, LinuxFdField::EventFd).store(1, Ordering::SeqCst)
        }
        crate::linux_event_files::Kind::TimerFd => {
            linux_fd_cell::<u8>(target, LinuxFdField::TimerFd).store(1, Ordering::SeqCst)
        }
    }
    set_linux_descriptor_close_on_exec(target, false);
    target
}

fn linux_eventfd_read(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    if !linux_eventfd_descriptor(descriptor) {
        return None;
    }
    if count != 8 {
        return Some(LINUX_EINVAL);
    }
    let (counter, state_flags) = linux_eventfd_state(descriptor)?;
    let current = counter.load(Ordering::SeqCst);
    if current == 0 {
        return Some(
            if state_flags.load(Ordering::SeqCst) & LINUX_EFD_NONBLOCK as u32 != 0 {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    }
    let semaphore = state_flags.load(Ordering::SeqCst) & LINUX_EFD_SEMAPHORE as u32 != 0;
    let result = if semaphore { 1 } else { current };
    if !copy_to_linux_user(address, &result.to_ne_bytes()) {
        return Some(LINUX_EFAULT);
    }
    counter.store(if semaphore { current - 1 } else { 0 }, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    Some(8)
}

fn complete_linux_eventfd_read_wait(slot: usize) -> bool {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_EVENTFD_READ
    {
        return false;
    }
    let descriptor = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = linux_eventfd_read(descriptor, address, 8).unwrap_or(LINUX_EBADF);
    if result == LINUX_ENOSYS {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EVENTFD_READ_WAKE_COUNT
        .fetch_add(1, Ordering::SeqCst);
    true
}

fn wake_linux_eventfd_read_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_eventfd_read_wait(slot));
    }
    woken
}

fn complete_linux_eventfd_write_wait(slot: usize) -> bool {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_EVENTFD_WRITE
    {
        return false;
    }
    let increment = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let descriptor = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let result = linux_eventfd_write_value(descriptor, increment, false).unwrap_or(LINUX_EBADF);
    if result == LINUX_ENOSYS {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EVENTFD_WRITE_WAKE_COUNT
        .fetch_add(1, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    true
}

fn wake_linux_eventfd_write_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_eventfd_write_wait(slot));
    }
    woken
}

fn complete_linux_pipe_read_wait(slot: usize) -> bool {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_PIPE_READ
    {
        return false;
    }
    let packed = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let descriptor = packed & 0xff;
    let count = (packed & !LINUX_PIPE_READV_WAIT_FLAG) >> 8;
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = if packed & LINUX_PIPE_READV_WAIT_FLAG != 0 {
        let Ok(vector_count) = usize::try_from(count) else {
            return false;
        };
        if !(1..=LINUX_IOV_LIMIT).contains(&vector_count) {
            return false;
        }
        let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
        for (index, range) in ranges[..vector_count].iter_mut().enumerate() {
            let Ok(length) = usize::try_from(
                X86_RUNTIME.LINUX_THREAD_IOV_LENGTHS[slot][index].load(Ordering::SeqCst),
            ) else {
                return false;
            };
            *range = (
                X86_RUNTIME.LINUX_THREAD_IOV_ADDRESSES[slot][index].load(Ordering::SeqCst),
                length,
            );
        }
        linux_pipe_readv_ranges(descriptor, &ranges[..vector_count])
    } else if let Some(slot) = linux_socket_slot(descriptor)
        .filter(|_| linux_socket_pipe_descriptor(descriptor, LINUX_DESCRIPTOR_INPUT))
    {
        linux_socket_pipe_read_wait_result(slot, address, count)
    } else {
        linux_pipe_read(descriptor, address, count).unwrap_or(LINUX_EBADF)
    };
    if result == LINUX_ENOSYS {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    clear_linux_iov_snapshot(slot);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PIPE_READ_WAKE_COUNT
        .fetch_add(1, Ordering::SeqCst);
    true
}

/// A blocked read of up to `count` bytes (at most a page) from the pipe in
/// socket table `slot` into `address`: its result once the pipe has data or
/// no writer, and ENOSYS while the read must still wait.
fn linux_socket_pipe_read_wait_result(
    slot: crate::linux_socket::SlotId,
    address: u64,
    count: u64,
) -> u64 {
    let mut bytes = [0_u8; PAGE_SIZE];
    let length = usize::try_from(count).unwrap_or(PAGE_SIZE).min(PAGE_SIZE);
    match crate::linux_socket::recv(slot, &mut bytes[..length]) {
        Ok((received, _)) => {
            if copy_to_linux_user(address, &bytes[..received]) {
                received as u64
            } else {
                LINUX_EFAULT
            }
        }
        Err(crate::linux_socket::Error::WouldBlock | crate::linux_socket::Error::InProgress) => {
            LINUX_ENOSYS
        }
        Err(error) => linux_socket_error(error),
    }
}

fn wake_linux_pipe_read_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_pipe_read_wait(slot));
    }
    woken
}

fn complete_linux_pipe_write_wait(slot: usize) -> bool {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_PIPE_WRITE
    {
        return false;
    }
    let packed = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let descriptor = packed & 0xff;
    let count = (packed & !LINUX_PIPE_WRITEV_WAIT_FLAG) >> 8;
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = if packed & LINUX_PIPE_WRITEV_WAIT_FLAG != 0 {
        let Ok(vector_count) = usize::try_from(count) else {
            return false;
        };
        if !(1..=LINUX_IOV_LIMIT).contains(&vector_count) {
            return false;
        }
        let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
        for (index, range) in ranges[..vector_count].iter_mut().enumerate() {
            let Ok(length) = usize::try_from(
                X86_RUNTIME.LINUX_THREAD_IOV_LENGTHS[slot][index].load(Ordering::SeqCst),
            ) else {
                return false;
            };
            *range = (
                X86_RUNTIME.LINUX_THREAD_IOV_ADDRESSES[slot][index].load(Ordering::SeqCst),
                length,
            );
        }
        linux_pipe_writev_ranges(descriptor, &ranges[..vector_count])
    } else {
        linux_pipe_write(descriptor, address, count).unwrap_or(LINUX_EBADF)
    };
    if result == LINUX_ENOSYS {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    clear_linux_iov_snapshot(slot);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PIPE_WRITE_WAKE_COUNT
        .fetch_add(1, Ordering::SeqCst);
    true
}

fn wake_linux_pipe_write_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_pipe_write_wait(slot));
    }
    woken
}

fn blocked_linux_pipe_writer() -> Option<LinuxThreadHandle> {
    (0..LINUX_THREAD_LIMIT).find_map(|slot| {
        (X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_BLOCKED
            && X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
                == LINUX_THREAD_WAIT_PIPE_WRITE)
            .then(|| linux_thread_handle(slot))
            .flatten()
    })
}

fn complete_linux_timerfd_read_wait(slot: usize) -> bool {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_TIMERFD_READ
    {
        return false;
    }
    let descriptor = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = linux_timerfd_read(descriptor, address, 8).unwrap_or(LINUX_EBADF);
    if result == LINUX_ENOSYS {
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(
            linux_timerfd_state(descriptor)
                .map(|state| state.deadline.load(Ordering::SeqCst))
                .unwrap_or(0),
            Ordering::SeqCst,
        );
        if X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::SeqCst) != 0 {
            X86_RUNTIME
                .LINUX_TIMED_WAITS_ACTIVE
                .store(true, Ordering::Release);
        }
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_TIMERFD_READ_WAKE_COUNT
        .fetch_add(1, Ordering::SeqCst);
    true
}

fn wake_linux_timerfd_read_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_timerfd_read_wait(slot));
    }
    woken
}

fn linux_eventfd_write(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    if !linux_eventfd_descriptor(descriptor) {
        return None;
    }
    if count != 8 {
        return Some(LINUX_EINVAL);
    }
    let mut bytes = [0_u8; 8];
    if !copy_from_linux_user(address, &mut bytes) {
        return Some(LINUX_EFAULT);
    }
    linux_eventfd_write_value(descriptor, u64::from_ne_bytes(bytes), true)
}

/// The kernel's own signal on an eventfd (an AIO completion): adds one,
/// stopping at ULLONG_MAX, the overflow state a read returns and poll
/// reports as POLLERR, as Linux's eventfd_signal does.
fn linux_eventfd_signal(descriptor: u64) {
    if !linux_eventfd_descriptor(descriptor) {
        return;
    }
    let Some((counter, _)) = linux_eventfd_state(descriptor) else {
        return;
    };
    counter.store(
        counter.load(Ordering::SeqCst).saturating_add(1),
        Ordering::SeqCst,
    );
    wake_linux_descriptor_waits();
}

fn linux_eventfd_write_value(descriptor: u64, increment: u64, wake: bool) -> Option<u64> {
    if !linux_eventfd_descriptor(descriptor) {
        return None;
    }
    if increment == u64::MAX {
        return Some(LINUX_EINVAL);
    }
    let (counter, state_flags) = linux_eventfd_state(descriptor)?;
    let current = counter.load(Ordering::SeqCst);
    let Some(next) = current.checked_add(increment) else {
        return Some(
            if state_flags.load(Ordering::SeqCst) & LINUX_EFD_NONBLOCK as u32 != 0 {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    };
    if next == u64::MAX {
        return Some(
            if state_flags.load(Ordering::SeqCst) & LINUX_EFD_NONBLOCK as u32 != 0 {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    }
    counter.store(next, Ordering::SeqCst);
    if wake {
        wake_linux_descriptor_waits();
    }
    Some(8)
}

fn linux_timerfd_create(clock: u64, flags: u64) -> u64 {
    let clock = u64::from(clock as u32);
    let flags = u64::from(flags as u32);
    if !matches!(
        clock,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_BOOTTIME_ALARM
    ) || flags & !(LINUX_TFD_NONBLOCK | LINUX_O_CLOEXEC) != 0
    {
        return LINUX_EINVAL;
    }
    let runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    if !runtime
        && X86_RUNTIME
            .ELF_PROBE_TIMERFD_DESCRIPTOR
            .load(Ordering::SeqCst)
            != 0
    {
        return LINUX_EMFILE;
    }
    let start = if runtime {
        LINUX_AUX_DESCRIPTOR_FIRST
    } else {
        2
    };
    let descriptor = if runtime {
        match linux_allocate_descriptor(start) {
            Ok(descriptor) => descriptor,
            Err(error) => return error,
        }
    } else {
        let Some(descriptor) = (start..LINUX_AUX_DESCRIPTOR_LIMIT)
            .find(|descriptor| linux_aux_descriptor_free(*descriptor))
        else {
            return LINUX_EMFILE;
        };
        descriptor
    };
    if runtime {
        let Some(id) = crate::linux_event_files::create_timerfd(clock as u8, flags as u32) else {
            return LINUX_ENFILE;
        };
        linux_legacy_descriptor_offset(descriptor).store(id, Ordering::SeqCst);
        linux_fd_cell::<u8>(descriptor, LinuxFdField::TimerFd).store(1, Ordering::SeqCst);
    } else {
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_CLOCK
            .store(clock as u8, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_FLAGS
            .store(flags as u32, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_INTERVAL
            .store(0, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_DEADLINE
            .store(0, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_DESCRIPTOR
            .store(descriptor as u16, Ordering::SeqCst);
    }
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    descriptor
}

/// The clocks a POSIX timer may follow: wall-clock ones are converted to
/// the monotonic nanoseconds deadlines count in at timer_settime; the CPU
/// time clocks run as the monotonic clock here.
fn linux_posix_timer_clock_supported(clock: u64) -> bool {
    matches!(
        clock,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_PROCESS_CPUTIME_ID
            | LINUX_CLOCK_THREAD_CPUTIME_ID
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_BOOTTIME_ALARM
    )
}

/// Whether a timer's clock counts wall time, whose absolute values need
/// converting to the monotonic clock.
/// Timestamp-counter cycles in nanoseconds.
fn linux_cycles_nanoseconds(cycles: u64) -> u64 {
    let frequency = X86_RUNTIME.ELF_PROBE_CLOCK_FREQUENCY.load(Ordering::SeqCst);
    if frequency == 0 {
        return 0;
    }
    cycles / frequency * NANOSECONDS_PER_SECOND
        + cycles % frequency * NANOSECONDS_PER_SECOND / frequency
}

/// The CPU time the current process's threads have used, the running one's
/// current interval included: each thread's charged time only grows, where
/// the process's running interval is marked once per runtime and moves
/// with every CPU that takes one of its threads up.
fn linux_current_process_cpu_cycles() -> u64 {
    (0..LINUX_THREAD_LIMIT)
        .filter(|slot| {
            X86_RUNTIME.LINUX_THREAD_STATES[*slot].load(Ordering::Relaxed) != LINUX_THREAD_FREE
        })
        .map(linux_thread_cpu_cycles)
        .fold(0_u64, u64::saturating_add)
}

fn linux_current_process_cpu_nanoseconds() -> u64 {
    linux_cycles_nanoseconds(linux_current_process_cpu_cycles())
}

fn linux_current_thread_cpu_nanoseconds() -> u64 {
    linux_cycles_nanoseconds(current_linux_thread_slot().map_or(0, linux_thread_cpu_cycles))
}

/// "Now" on a POSIX timer's clock: CPU nanoseconds for a CPU clock (the
/// thread's for a thread clock), else the monotonic clock.
fn linux_posix_timer_now(clock: u32) -> Option<u64> {
    if linux_process::posix_clock_is_thread_cpu(clock) {
        Some(linux_current_thread_cpu_nanoseconds())
    } else if linux_process::posix_clock_is_cpu(clock) {
        Some(linux_current_process_cpu_nanoseconds())
    } else {
        linux_elapsed_nanoseconds()
    }
}

fn linux_posix_timer_clock_is_wall(clock: u32) -> bool {
    matches!(
        u64::from(clock),
        LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_ALARM
    )
}

/// Keeps the banked earliest deadline, the check before the process table.
fn linux_refresh_posix_timer_cache(pid: u32) {
    X86_RUNTIME.ELF_PROBE_POSIX_TIMER_DEADLINE.store(
        linux_process::earliest_posix_timer_deadline(pid),
        Ordering::SeqCst,
    );
}

/// timer_create(2): a timer of the calling process, numbered from 1. A
/// null sigevent means SIGALRM with the timer's id as the value, as Linux.
fn linux_timer_create(clock: u64, event_address: u64, timer_address: u64) -> u64 {
    const SIGEV_SIGNAL: u32 = 0;
    const SIGEV_NONE: u32 = 1;
    const SIGEV_THREAD: u32 = 2;
    const SIGEV_THREAD_ID: u32 = 4;
    let clock = u64::from(clock as u32);
    if !linux_posix_timer_clock_supported(clock) {
        return LINUX_EINVAL;
    }
    if !linux_writable_user_range_contains(timer_address, size_of::<i32>()) {
        return LINUX_EFAULT;
    }
    let pid = current_linux_process_pid();
    let mut timer = linux_process::PosixTimer {
        clock: clock as u32,
        notify: SIGEV_SIGNAL,
        signal: LINUX_SIGALRM as u8,
        tid: 0,
        value: 0,
        deadline: 0,
        interval: 0,
        overrun: 0,
        delivered_overrun: 0,
    };
    if event_address != 0 {
        let mut event = [0_u8; 64];
        if !copy_from_linux_user(event_address, &mut event) {
            return LINUX_EFAULT;
        }
        let value = u64::from_ne_bytes(event[..8].try_into().unwrap());
        let signal = i32::from_ne_bytes(event[8..12].try_into().unwrap());
        let notify = u32::from_ne_bytes(event[12..16].try_into().unwrap());
        let tid = i32::from_ne_bytes(event[16..20].try_into().unwrap());
        // SIGEV_THREAD is the C library's own: it asks the kernel for a
        // signal to a thread of its (SIGEV_THREAD_ID) or for none.
        match notify {
            SIGEV_NONE => {}
            SIGEV_SIGNAL | SIGEV_THREAD => {
                if !(1..=64).contains(&signal) {
                    return LINUX_EINVAL;
                }
            }
            SIGEV_THREAD_ID => {
                if !(1..=64).contains(&signal)
                    || u32::try_from(tid)
                        .ok()
                        .and_then(linux_thread_state_by_tid)
                        .is_none_or(|(owner, _)| owner != pid)
                {
                    return LINUX_EINVAL;
                }
            }
            _ => return LINUX_EINVAL,
        }
        timer.notify = if notify == SIGEV_THREAD {
            SIGEV_SIGNAL
        } else {
            notify
        };
        timer.signal = if notify == SIGEV_NONE {
            0
        } else {
            signal as u8
        };
        timer.tid = if notify == SIGEV_THREAD_ID {
            tid as u32
        } else {
            0
        };
        timer.value = value;
    }
    let Some(id) = linux_process::create_posix_timer(pid, timer) else {
        return LINUX_EAGAIN;
    };
    if event_address == 0 {
        let _ = linux_process::update_posix_timer(pid, id, |timer| timer.value = u64::from(id));
    }
    if copy_to_linux_user(timer_address, &(id as i32).to_ne_bytes()) {
        0
    } else {
        let _ = linux_process::delete_posix_timer(pid, id);
        LINUX_EFAULT
    }
}

/// timer_settime(2): arms a timer, or disarms it with a zero value; the
/// time it had left and its interval go to `old_address`.
fn linux_timer_settime(timer: u64, flags: u64, new_address: u64, old_address: u64) -> u64 {
    const TIMER_ABSTIME: u64 = 1;
    let id = timer as u32;
    let flags = u64::from(flags as u32);
    let pid = current_linux_process_pid();
    let Some(current) = linux_process::posix_timer(pid, id) else {
        return LINUX_EINVAL;
    };
    if flags & !TIMER_ABSTIME != 0 {
        return LINUX_EINVAL;
    }
    // No new value is EINVAL, as Linux; an unreadable one EFAULT.
    if new_address == 0 {
        return LINUX_EINVAL;
    }
    if old_address != 0 && !linux_writable_user_range_contains(old_address, 32) {
        return LINUX_EFAULT;
    }
    let mut specification = [0_u8; 32];
    if !copy_from_linux_user(new_address, &mut specification) {
        return LINUX_EFAULT;
    }
    let Some(interval) = linux_timespec_nanoseconds(&specification[..16]) else {
        return LINUX_EINVAL;
    };
    let Some(value) = linux_timespec_nanoseconds(&specification[16..]) else {
        return LINUX_EINVAL;
    };
    let Some(now) = linux_posix_timer_now(current.clock) else {
        return LINUX_ENOSYS;
    };
    let old = linux_timer_specification(current.interval, current.deadline, now);
    let deadline = if value == 0 {
        0
    } else if flags & TIMER_ABSTIME == 0 {
        let Some(deadline) = now.checked_add(value) else {
            return LINUX_EINVAL;
        };
        deadline
    } else if linux_posix_timer_clock_is_wall(current.clock) {
        // An absolute wall time: as far ahead of (or behind) the monotonic
        // clock as it is of the wall clock now. A past one fires at once,
        // and keeps its distance so its overrun counts the intervals since
        // (timer_settime03 expects that count saturated).
        let Some((seconds, nanoseconds)) = linux_realtime_time() else {
            return LINUX_ENOSYS;
        };
        let wall_now = seconds
            .saturating_mul(NANOSECONDS_PER_SECOND)
            .saturating_add(nanoseconds);
        if value >= wall_now {
            now.saturating_add(value - wall_now)
        } else {
            now.saturating_sub(wall_now - value).max(1)
        }
    } else {
        linux_time_namespace_host(u64::from(current.clock), value).max(1)
    };
    if old_address != 0 && !copy_to_linux_user(old_address, &old) {
        return LINUX_EFAULT;
    }
    if linux_process::update_posix_timer(pid, id, |timer| {
        timer.deadline = deadline;
        timer.interval = interval;
        timer.overrun = 0;
        timer.delivered_overrun = 0;
    })
    .is_none()
    {
        return LINUX_EINVAL;
    }
    linux_refresh_posix_timer_cache(pid);
    0
}

/// timer_gettime(2): the time a timer has left and its interval.
fn linux_timer_gettime(timer: u64, address: u64) -> u64 {
    let pid = current_linux_process_pid();
    let Some(current) = linux_process::posix_timer(pid, timer as u32) else {
        return LINUX_EINVAL;
    };
    let Some(now) = linux_posix_timer_now(current.clock) else {
        return LINUX_ENOSYS;
    };
    let specification = linux_timer_specification(current.interval, current.deadline, now);
    if copy_to_linux_user(address, &specification) {
        0
    } else {
        LINUX_EFAULT
    }
}

/// timer_getoverrun(2): the expirations the last delivered signal stood
/// for beyond its own, at most DELAYTIMER_MAX.
fn linux_timer_getoverrun(timer: u64) -> u64 {
    let pid = current_linux_process_pid();
    match linux_process::posix_timer(pid, timer as u32) {
        Some(current) => u64::from(current.delivered_overrun.min(i32::MAX as u32)),
        None => LINUX_EINVAL,
    }
}

/// timer_delete(2).
fn linux_timer_delete(timer: u64) -> u64 {
    let pid = current_linux_process_pid();
    if !linux_process::delete_posix_timer(pid, timer as u32) {
        return LINUX_EINVAL;
    }
    linux_refresh_posix_timer_cache(pid);
    0
}

/// Fires the current process's POSIX timers whose deadline passed: queues
/// each one's signal (si_code SI_TIMER, si_value as created) and moves a
/// periodic timer on. Checked where the interval timer is; the banked
/// earliest deadline decides without the process table.
pub(super) fn refresh_linux_posix_timers() -> bool {
    const SIGEV_NONE: u32 = 1;
    const SIGEV_THREAD_ID: u32 = 4;
    let earliest = X86_RUNTIME
        .ELF_PROBE_POSIX_TIMER_DEADLINE
        .load(Ordering::SeqCst);
    if earliest == 0 {
        return false;
    }
    let Some(now) = linux_elapsed_nanoseconds() else {
        return false;
    };
    if now < earliest {
        return false;
    }
    let pid = current_linux_process_pid();
    // Called in a system call, where the signal queues may be consulted.
    let pending = X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst)
        | linux_dynamic_pending_masks().map_or(0, |(process, thread)| process | thread);
    let mut expiries = [linux_process::PosixTimerExpiry::NONE; linux_process::TIMER_EXPIRY_LIMIT];
    let cpu_now = linux_current_process_cpu_nanoseconds();
    let thread_now = linux_current_thread_cpu_nanoseconds();
    let count =
        linux_process::expire_posix_timers(pid, (now, cpu_now, thread_now), pending, &mut expiries);
    let mut queued = false;
    for expiry in &expiries[..count] {
        if expiry.notify == SIGEV_NONE || expiry.signal == 0 {
            continue;
        }
        // A thread-directed signal reaches the process until threads have
        // queues of their own a timer can reach; the thread is recorded.
        let _thread = (expiry.notify == SIGEV_THREAD_ID).then_some(expiry.tid);
        // Queued as kill queues a signal; its delivery freezes the overrun.
        // An interval timer's signal comes from the kernel (SI_KERNEL).
        let code = if expiry.interval_timer {
            0x80
        } else {
            LINUX_SI_TIMER
        };
        if linux_queue_process_signal(
            pid,
            u64::from(expiry.signal),
            code,
            (!expiry.interval_timer).then_some(expiry.value),
        ) == 0
        {
            queued = true;
        }
    }
    linux_refresh_posix_timer_cache(pid);
    queued
}

fn linux_timerfd_settime(descriptor: u64, flags: u64, new_address: u64, old_address: u64) -> u64 {
    const TFD_TIMER_CANCEL_ON_SET: u64 = 2;
    let descriptor = u64::from(descriptor as u32);
    let flags = u64::from(flags as u32);
    // An open descriptor that is no timerfd is EINVAL, as in Linux.
    let Some(state) = linux_timerfd_state(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    };
    let clock = u64::from(state.clock.load(Ordering::SeqCst));
    if flags & !(LINUX_TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0
        || flags & TFD_TIMER_CANCEL_ON_SET != 0
            && (flags & LINUX_TFD_TIMER_ABSTIME == 0
                || !matches!(clock, LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_ALARM))
    {
        return LINUX_EINVAL;
    }
    if old_address != 0 && !linux_writable_user_range_contains(old_address, 32) {
        return LINUX_EFAULT;
    }
    let mut specification = [0_u8; 32];
    if !copy_from_linux_user(new_address, &mut specification) {
        return LINUX_EFAULT;
    }
    let Some(interval) = linux_timespec_nanoseconds_saturating(&specification[..16]) else {
        return LINUX_EINVAL;
    };
    let Some(value) = linux_timespec_nanoseconds_saturating(&specification[16..]) else {
        return LINUX_EINVAL;
    };
    let Some(now) = linux_elapsed_nanoseconds() else {
        return LINUX_ENOSYS;
    };
    let old = linux_timer_specification(
        state.interval.load(Ordering::SeqCst),
        state.deadline.load(Ordering::SeqCst),
        now,
    );
    let deadline = if value == 0 {
        0
    } else if flags & LINUX_TFD_TIMER_ABSTIME != 0
        && matches!(clock, LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_ALARM)
    {
        let Some((seconds, nanoseconds)) = linux_realtime_time() else {
            return LINUX_ENOSYS;
        };
        let Some(realtime_now) = seconds
            .checked_mul(NANOSECONDS_PER_SECOND)
            .and_then(|seconds| seconds.checked_add(nanoseconds))
        else {
            return LINUX_EINVAL;
        };
        now.saturating_add(value.saturating_sub(realtime_now))
    } else if flags & LINUX_TFD_TIMER_ABSTIME != 0 {
        linux_time_namespace_host(clock, value)
    } else {
        let Some(deadline) = now.checked_add(value) else {
            return LINUX_EINVAL;
        };
        deadline
    };
    if old_address != 0 && !copy_to_linux_user(old_address, &old) {
        return LINUX_EFAULT;
    }
    state.interval.store(interval, Ordering::SeqCst);
    state.deadline.store(deadline, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    0
}

fn linux_timerfd_gettime(descriptor: u64, address: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    // An open descriptor that is no timerfd is EINVAL, as in Linux.
    let Some(state) = linux_timerfd_state(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    };
    let Some(now) = linux_elapsed_nanoseconds() else {
        return LINUX_ENOSYS;
    };
    let specification = linux_timer_specification(
        state.interval.load(Ordering::SeqCst),
        state.deadline.load(Ordering::SeqCst),
        now,
    );
    if !copy_to_linux_user(address, &specification) {
        return LINUX_EFAULT;
    }
    0
}

fn linux_timerfd_read(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    let state = linux_timerfd_state(descriptor)?;
    if count != 8 {
        return Some(LINUX_EINVAL);
    }
    let Some(now) = linux_elapsed_nanoseconds() else {
        return Some(LINUX_ENOSYS);
    };
    let deadline = state.deadline.load(Ordering::SeqCst);
    if deadline == 0 || now < deadline {
        return Some(
            if state.flags.load(Ordering::SeqCst) & LINUX_TFD_NONBLOCK as u32 != 0 {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    }
    let interval = state.interval.load(Ordering::SeqCst);
    let expirations = now
        .saturating_sub(deadline)
        .checked_div(interval)
        .map_or(1, |elapsed| elapsed + 1);
    if !copy_to_linux_user(address, &expirations.to_ne_bytes()) {
        return Some(LINUX_EFAULT);
    }
    let next = if interval == 0 {
        0
    } else {
        deadline.saturating_add(expirations.saturating_mul(interval))
    };
    state.deadline.store(next, Ordering::SeqCst);
    Some(8)
}

fn linux_timespec_nanoseconds(timespec: &[u8]) -> Option<u64> {
    let seconds = i64::from_ne_bytes(timespec[..8].try_into().ok()?);
    let nanoseconds = i64::from_ne_bytes(timespec[8..16].try_into().ok()?);
    if seconds < 0 || !(0..NANOSECONDS_PER_SECOND as i64).contains(&nanoseconds) {
        return None;
    }
    (seconds as u64)
        .checked_mul(NANOSECONDS_PER_SECOND)
        .and_then(|value| value.checked_add(nanoseconds as u64))
}

fn linux_timespec_nanoseconds_saturating(timespec: &[u8]) -> Option<u64> {
    let seconds = i64::from_ne_bytes(timespec.get(..8)?.try_into().ok()?);
    let nanoseconds = i64::from_ne_bytes(timespec.get(8..16)?.try_into().ok()?);
    if seconds < 0 || !(0..NANOSECONDS_PER_SECOND as i64).contains(&nanoseconds) {
        return None;
    }
    Some(
        (seconds as u64)
            .saturating_mul(NANOSECONDS_PER_SECOND)
            .saturating_add(nanoseconds as u64),
    )
}

fn linux_timer_specification(interval: u64, deadline: u64, now: u64) -> [u8; 32] {
    let remaining = if deadline == 0 {
        0
    } else if now < deadline {
        deadline - now
    } else if interval == 0 {
        0
    } else {
        interval - (now - deadline) % interval
    };
    let mut specification = [0_u8; 32];
    linux_store_timespec(&mut specification[..16], interval);
    linux_store_timespec(&mut specification[16..], remaining);
    specification
}

fn linux_store_timespec(timespec: &mut [u8], nanoseconds: u64) {
    timespec[..8].copy_from_slice(&(nanoseconds / NANOSECONDS_PER_SECOND).to_ne_bytes());
    timespec[8..16].copy_from_slice(&(nanoseconds % NANOSECONDS_PER_SECOND).to_ne_bytes());
}

fn linux_pipe(address: u64, flags: u64) -> u64 {
    let flags = u64::from(flags as u32);
    // Packet-mode (O_DIRECT) pipes are the runtime's (linux_socket_pipe).
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return linux_runtime_pipe(address, flags);
    }
    if flags & !(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    if X86_RUNTIME
        .ELF_PROBE_PIPE_READ_DESCRIPTOR
        .load(Ordering::SeqCst)
        != 0
        || X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
            .load(Ordering::SeqCst)
            != 0
    {
        return LINUX_EMFILE;
    }
    let mut descriptors = [0_u64; 2];
    let mut found = 0;
    for descriptor in 2..LINUX_AUX_DESCRIPTOR_LIMIT {
        if linux_aux_descriptor_free(descriptor) {
            descriptors[found] = descriptor;
            found += 1;
            if found == descriptors.len() {
                break;
            }
        }
    }
    if found != descriptors.len() {
        return LINUX_EMFILE;
    }
    let mut output = [0_u8; 8];
    output[..4].copy_from_slice(&(descriptors[0] as u32).to_ne_bytes());
    output[4..].copy_from_slice(&(descriptors[1] as u32).to_ne_bytes());
    if !copy_to_linux_user(address, &output) {
        return LINUX_EFAULT;
    }
    for byte in &X86_RUNTIME.ELF_PROBE_PIPE_BUFFER {
        byte.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_READ_FLAGS
        .store(flags as u32, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_WRITE_FLAGS
        .store(flags as u32, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_READ_DESCRIPTOR
        .store(descriptors[0] as u16, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
        .store(descriptors[1] as u16, Ordering::SeqCst);
    for descriptor in descriptors {
        set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    }
    0
}

/// Releases the kernel objects whose last descriptor has closed: DRM
/// render node files and dma-bufs, open loop devices, RAM disks,
/// /dev/kmsg, pseudo-terminals, userfaultfds and Landlock rulesets.
pub(crate) fn linux_release_objects() {
    for (class, id) in crate::linux_socket::take_released_objects() {
        crate::linux_drm::release(class, id);
        crate::linux_loop::release(class, id);
        crate::linux_ramdisk::release(class, id);
        crate::linux_kmsg::release(class, id);
        crate::linux_pty::release(class, id);
        crate::linux_fscontext::release(class, id);
        linux_userfaultfd_release(class, id);
        crate::linux_landlock::release(class, id);
        linux_tun_release(class, id);
        linux_perf_release(class, id);
    }
}

/// The kernel object (class and id) an object descriptor refers to: a
/// DRM render node file, a GPU fence or a dma-buf, an open loop device or
/// /dev/loop-control.
fn linux_object_descriptor(descriptor: u64) -> Option<(u8, u64)> {
    linux_socket_slot(descriptor).and_then(crate::linux_socket::object)
}

/// Makes a descriptor for object `slot`, the lowest free one.
fn linux_install_object_descriptor(slot: crate::linux_socket::SlotId, flags: u64) -> u64 {
    linux_install_object_descriptor_with_access(slot, flags, 3)
}

/// `linux_install_object_descriptor` open for `access` (input, output or
/// both).
fn linux_install_object_descriptor_with_access(
    slot: crate::linux_socket::SlotId,
    flags: u64,
    access: u16,
) -> u64 {
    let Some(descriptor) = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        let _ = crate::linux_socket::close(slot);
        linux_release_objects();
        return LINUX_EMFILE;
    };
    let installed = linux_socket_descriptor_installed(
        descriptor,
        slot,
        LINUX_DEVICE_SOCKET | access,
        (flags & LINUX_O_NONBLOCK) as u32,
        flags & LINUX_O_CLOEXEC != 0,
    );
    if installed >= LINUX_RETURN_TO_KERNEL {
        linux_release_objects();
    }
    installed
}

/// /dev/userfaultfd (10:126), whose USERFAULTFD_IOC_NEW makes userfaultfds:
/// an object slot of a class that keeps no state to release. Classes 1 to
/// 9 belong to DRM, loop devices, RAM disks, /dev/kmsg and ptys.
const LINUX_USERFAULTFD_DEVICE: u32 = (10 << 8) | 126;
const LINUX_USERFAULTFD_DEVICE_CLASS: u8 = 10;

fn linux_open_userfaultfd_device(flags: u64) -> u64 {
    linux_open_object(LINUX_USERFAULTFD_DEVICE_CLASS, 0, flags)
}

/// Opens /dev/dri/renderD128.
fn linux_open_render_node(flags: u64) -> u64 {
    match crate::linux_drm::open() {
        Some(slot) => linux_install_object_descriptor(slot, flags),
        None => LINUX_ENOMEM,
    }
}

/// Opens /dev/kmsg: the machine's kernel log, which only a domain set
/// `privileged=true` reads or writes (EPERM, as Linux refuses a reader that
/// syslog would).
fn linux_open_kernel_log(flags: u64) -> u64 {
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ObserveKernelLog) {
        return LINUX_EPERM;
    }
    let access = flags & 3;
    let id = crate::linux_kmsg::open(access != 1, access != 0);
    match crate::linux_socket::open_object(crate::linux_kmsg::CLASS_READER, id) {
        Ok(slot) => linux_install_object_descriptor(slot, flags),
        Err(_) => {
            crate::linux_kmsg::release(crate::linux_kmsg::CLASS_READER, id);
            LINUX_ENOMEM
        }
    }
}

/// Opens block device `major`:`minor`: a loop device (/dev/loopN) or a RAM
/// disk (/dev/ramN).
fn linux_open_block_device(major: u32, minor: u32, flags: u64) -> u64 {
    // An exclusive open of a disk a filesystem is mounted from is EBUSY
    // (mkfs refuses a mounted device this way).
    if flags & (LINUX_O_EXCL | LINUX_O_CREAT) == LINUX_O_EXCL
        && crate::linux_blockfs::device_mounted(linux_device_number(major, minor))
    {
        return LINUX_EBUSY;
    }
    let access = flags & 3;
    let (readable, writable) = (access != 1, access != 0);
    let (class, opened) = if major == crate::linux_ramdisk::MAJOR {
        (
            crate::linux_ramdisk::CLASS_DISK,
            crate::linux_ramdisk::open(minor, readable, writable),
        )
    } else {
        (
            crate::linux_loop::CLASS_DEVICE,
            crate::linux_loop::open(minor, readable, writable),
        )
    };
    let id = match opened {
        Ok(id) => id,
        Err(error) => return linux_loop_errno(error),
    };
    match crate::linux_socket::open_object(class, id) {
        Ok(slot) => linux_install_object_descriptor(slot, flags),
        Err(_) => {
            crate::linux_loop::release(class, id);
            crate::linux_ramdisk::release(class, id);
            LINUX_ENOMEM
        }
    }
}

fn linux_loop_errno(error: crate::linux_loop::Error) -> u64 {
    error.number().wrapping_neg()
}

/// The class and id of a block device (loop device or RAM disk),
/// /dev/loop-control or /dev/kmsg descriptor.
fn linux_block_descriptor(descriptor: u64) -> Option<(u8, u64)> {
    linux_object_descriptor(descriptor).filter(|(class, _)| {
        matches!(
            *class,
            crate::linux_loop::CLASS_DEVICE
                | crate::linux_loop::CLASS_CONTROL
                | crate::linux_ramdisk::CLASS_DISK
                | crate::linux_kmsg::CLASS_READER
        )
    })
}

/// read, write and lseek on /dev/kmsg open `id`: a record at a time.
fn linux_kernel_log_syscall(number: u64, id: u64, buffer: u64, count: u64) -> u64 {
    let result = match number {
        LINUX_READ_SYSCALL => match crate::linux_kmsg::read(id, count as usize) {
            Ok(record) if !copy_to_linux_user(buffer, &record) => return LINUX_EFAULT,
            Ok(record) => Ok(record.len() as u64),
            Err(error) => Err(error),
        },
        // Linux refuses a write longer than a record before reading it.
        LINUX_WRITE_SYSCALL if count > crate::linux_kmsg::RECORD_MAX as u64 => {
            Err(crate::linux_kmsg::Error::Invalid)
        }
        LINUX_WRITE_SYSCALL => {
            let mut input = alloc::vec![0_u8; count as usize];
            if !copy_from_linux_user(buffer, &mut input) {
                return LINUX_EFAULT;
            }
            crate::linux_kmsg::write(id, &input).map(|written| written as u64)
        }
        LINUX_LSEEK_SYSCALL => crate::linux_kmsg::seek(id, buffer as i64, count as u32),
        LINUX_PREAD64_SYSCALL | LINUX_PWRITE64_SYSCALL => return LINUX_ESPIPE,
        LINUX_IOCTL_SYSCALL => return LINUX_ENOTTY,
        _ => Ok(0),
    };
    result.unwrap_or_else(|error| error.number().wrapping_neg())
}

/// Whether a read of /dev/kmsg descriptor `descriptor` that found no new
/// record waits for one (no O_NONBLOCK).
fn linux_kernel_log_read_waits(number: u64, descriptor: u64) -> bool {
    number == LINUX_READ_SYSCALL
        && linux_block_descriptor(descriptor)
            .is_some_and(|(class, _)| class == crate::linux_kmsg::CLASS_READER)
        && linux_socket_flags(descriptor).is_some_and(|flags| flags & LINUX_O_NONBLOCK as u32 == 0)
}

/// The device number (as stat(2) shows it) and whether it is a block
/// device, of block device or /dev/loop-control descriptor `class`/`id`.
fn linux_block_descriptor_device(class: u8, id: u64) -> Option<(u32, bool)> {
    match class {
        crate::linux_loop::CLASS_DEVICE => crate::linux_loop::minor(id)
            .map(|minor| (linux_device_number(crate::linux_loop::MAJOR, minor), true)),
        crate::linux_ramdisk::CLASS_DISK => crate::linux_ramdisk::minor(id).map(|minor| {
            (
                linux_device_number(crate::linux_ramdisk::MAJOR, minor),
                true,
            )
        }),
        crate::linux_loop::CLASS_CONTROL => Some((
            linux_device_number(
                crate::linux_loop::CONTROL_MAJOR,
                crate::linux_loop::CONTROL_MINOR,
            ),
            false,
        )),
        _ => None,
    }
}

/// The calling process, for a block device ioctl.
struct LinuxLoopCaller;

impl crate::linux_loop::Caller for LinuxLoopCaller {
    fn copy_in(&self, address: u64, output: &mut [u8]) -> bool {
        copy_from_linux_user(address, output)
    }

    fn copy_out(&mut self, address: u64, input: &[u8]) -> bool {
        copy_to_linux_user(address, input)
    }

    fn backing(
        &mut self,
        descriptor: u32,
    ) -> Result<crate::linux_loop::Backing, crate::linux_loop::Error> {
        use crate::linux_loop::{Backing, Error};
        let descriptor = u64::from(descriptor);
        if !linux_descriptor_open(descriptor) || linux_path_descriptor(descriptor) {
            return Err(Error::BadDescriptor);
        }
        if let Some((crate::linux_loop::CLASS_DEVICE, id)) = linux_object_descriptor(descriptor) {
            return Ok(Backing::Loop(id));
        }
        let writable = linux_device_descriptor(descriptor) & LINUX_DESCRIPTOR_OUTPUT != 0;
        let regular_image_file = linux_rootfs_entry(descriptor).is_some_and(|entry| {
            matches!(
                entry.kind,
                crate::published_rootfs::EntryKind::File
                    | crate::published_rootfs::EntryKind::Hardlink
            )
        });
        let handle = match linux_overlay_descriptor_handle(descriptor) {
            Some(handle) => handle,
            // An image file is copied up to have a handle to keep.
            None if regular_image_file => {
                linux_copy_up_descriptor(descriptor).map_err(|_| Error::Io)?
            }
            None => return Ok(Backing::Other),
        };
        Ok(
            match crate::linux_overlay::metadata(handle).map(|metadata| metadata.kind) {
                Some(crate::linux_overlay::NodeKind::File) => Backing::File { handle, writable },
                _ => Backing::Other,
            },
        )
    }

    fn administrator(&self) -> bool {
        current_linux_credentials()
            .is_some_and(|credentials| credentials.has(linox_credentials::capability::SYS_ADMIN))
    }
}

/// read, write, lseek, pread64, pwrite64, fsync, fdatasync and ioctl on a
/// block device or /dev/loop-control descriptor; `offset` is pread64's and
/// pwrite64's.
fn linux_block_syscall(number: u64, descriptor: u64, buffer: u64, count: u64, offset: u64) -> u64 {
    let Some((class, id)) = linux_block_descriptor(descriptor) else {
        return LINUX_EBADF;
    };
    if number == LINUX_IOCTL_SYSCALL {
        if let Some(result) = linux_generic_ioctl(descriptor, buffer, count) {
            return result;
        }
    }
    if class == crate::linux_kmsg::CLASS_READER {
        return linux_kernel_log_syscall(number, id, buffer, count);
    }
    let disk = class == crate::linux_ramdisk::CLASS_DISK;
    let result = if class == crate::linux_loop::CLASS_CONTROL {
        match number {
            LINUX_IOCTL_SYSCALL => crate::linux_loop::control(buffer as u32, count),
            // The control device has no data, and seeking it does nothing.
            LINUX_LSEEK_SYSCALL => Ok(0),
            _ => Err(crate::linux_loop::Error::Invalid),
        }
    } else {
        match number {
            LINUX_IOCTL_SYSCALL if disk => {
                crate::linux_ramdisk::ioctl(id, buffer as u32, count, &mut LinuxLoopCaller)
            }
            LINUX_IOCTL_SYSCALL => {
                crate::linux_loop::ioctl(id, buffer as u32, count, &mut LinuxLoopCaller)
            }
            LINUX_LSEEK_SYSCALL if disk => {
                crate::linux_ramdisk::seek(id, buffer as i64, count as u32)
            }
            LINUX_LSEEK_SYSCALL => crate::linux_loop::seek(id, buffer as i64, count as u32),
            LINUX_READ_SYSCALL => {
                return linux_block_transfer(class, id, buffer, count, None, false)
            }
            LINUX_WRITE_SYSCALL => {
                return linux_block_transfer(class, id, buffer, count, None, true)
            }
            LINUX_PREAD64_SYSCALL | LINUX_PWRITE64_SYSCALL if (offset as i64) < 0 => {
                Err(crate::linux_loop::Error::Invalid)
            }
            LINUX_PREAD64_SYSCALL => {
                return linux_block_transfer(class, id, buffer, count, Some(offset), false)
            }
            LINUX_PWRITE64_SYSCALL => {
                return linux_block_transfer(class, id, buffer, count, Some(offset), true)
            }
            // Writes reach the backing file or memory at once.
            _ => Ok(0),
        }
    };
    result.unwrap_or_else(linux_loop_errno)
}

/// Reads or writes `count` bytes at `address` from or to the block device
/// of open `class`/`id`, at `offset` or else at (and advancing) the file
/// position.
fn linux_block_transfer(
    class: u8,
    id: u64,
    address: u64,
    count: u64,
    offset: Option<u64>,
    write: bool,
) -> u64 {
    let disk = class == crate::linux_ramdisk::CLASS_DISK;
    let position = || {
        if disk {
            crate::linux_ramdisk::position(id)
        } else {
            crate::linux_loop::position(id)
        }
    };
    let start = match offset.map_or_else(position, Ok) {
        Ok(start) => start,
        Err(error) => return linux_loop_errno(error),
    };
    let requested = count.min(i64::MAX as u64 & !(PAGE_SIZE as u64 - 1));
    let mut buffer = [0_u8; PAGE_SIZE];
    let mut total = 0_u64;
    // A zero-length transfer still checks the descriptor and the device.
    loop {
        let chunk = (requested - total).min(PAGE_SIZE as u64) as usize;
        let at = start + total;
        let result = if write {
            if !copy_from_linux_user(address.wrapping_add(total), &mut buffer[..chunk]) {
                Err(crate::linux_loop::Error::Fault)
            } else if disk {
                crate::linux_ramdisk::write_at(id, at, &buffer[..chunk])
            } else {
                crate::linux_loop::write_at(id, at, &buffer[..chunk])
            }
        } else {
            let read = if disk {
                crate::linux_ramdisk::read_at(id, at, &mut buffer[..chunk])
            } else {
                crate::linux_loop::read_at(id, at, &mut buffer[..chunk])
            };
            read.and_then(|length| {
                // Nothing read (the end of the device) copies nothing.
                if length == 0 || copy_to_linux_user(address.wrapping_add(total), &buffer[..length])
                {
                    Ok(length)
                } else {
                    Err(crate::linux_loop::Error::Fault)
                }
            })
        };
        match result {
            Ok(length) => {
                total += length as u64;
                if length < chunk || total == requested {
                    break;
                }
            }
            Err(error) if total == 0 => return linux_loop_errno(error),
            Err(_) => break,
        }
    }
    if offset.is_none() {
        if disk {
            crate::linux_ramdisk::set_position(id, start + total);
        } else {
            crate::linux_loop::set_position(id, start + total);
        }
    }
    total
}

/// A new descriptor for object `class`/`id`, given its first reference.
fn linux_open_object(class: u8, id: u64, flags: u64) -> u64 {
    match crate::linux_socket::open_object(class, id) {
        Ok(slot) => linux_install_object_descriptor(slot, flags),
        Err(_) => LINUX_ENOMEM,
    }
}

/// The calling process's memory for `linox_drm`.
struct LinuxUserMemory;

impl linox_drm::UserMemory for LinuxUserMemory {
    fn read(&self, address: u64, output: &mut [u8]) -> bool {
        copy_from_linux_user(address, output)
    }

    fn write(&mut self, address: u64, input: &[u8]) -> bool {
        copy_to_linux_user(address, input)
    }
}

fn linux_drm_errno(error: linox_drm::Errno) -> u64 {
    (-i64::from(error.number())) as u64
}

/// read, write and ioctl on an object descriptor.
fn linux_object_syscall(number: u64, descriptor: u64, buffer: u64, count: u64) -> u64 {
    const DMA_BUF_IOCTL_SYNC: u64 = 0x4008_6200;
    let Some((class, id)) = linux_object_descriptor(descriptor) else {
        return LINUX_EBADF;
    };
    match (number, class) {
        (LINUX_IOCTL_SYSCALL, crate::linux_drm::CLASS_FILE) => {
            linux_drm_ioctl(id, buffer as u32, count)
        }
        // USERFAULTFD_IOC_NEW: a userfaultfd, as userfaultfd(2) makes one;
        // opening the device was the permission check.
        (LINUX_IOCTL_SYSCALL, LINUX_USERFAULTFD_DEVICE_CLASS) if buffer & 0xffff_ffff == 0xaa00 => {
            linux_userfaultfd_create(count, true)
        }
        (LINUX_IOCTL_SYSCALL, crate::linux_userfaultfd::CLASS_CONTEXT) => {
            linux_userfaultfd_ioctl(descriptor, buffer, count)
        }
        (LINUX_READ_SYSCALL, crate::linux_userfaultfd::CLASS_CONTEXT) => {
            linux_userfaultfd_read(descriptor, buffer, count)
        }
        (LINUX_IOCTL_SYSCALL, LINUX_TUN_CLASS) => linux_tun_ioctl(id, buffer as u32, count),
        (LINUX_READ_SYSCALL, LINUX_TUN_CLASS) => linux_tun_read(id, buffer, count),
        (LINUX_WRITE_SYSCALL, LINUX_TUN_CLASS) => linux_tun_write(id, buffer, count),
        (LINUX_READ_SYSCALL, LINUX_PERF_CLASS) => linux_perf_read(descriptor, buffer, count),
        (LINUX_IOCTL_SYSCALL, LINUX_PERF_CLASS) => linux_perf_ioctl(descriptor, buffer, count),
        // Host memory is coherent: there is nothing to flush.
        (LINUX_IOCTL_SYSCALL, crate::linux_drm::CLASS_DMABUF)
            if buffer & 0xffff_ffff == DMA_BUF_IOCTL_SYNC =>
        {
            0
        }
        (LINUX_IOCTL_SYSCALL, _) => LINUX_ENOTTY,
        _ => LINUX_EINVAL,
    }
}

/// A DRM ioctl on render node file `file`: copies the argument in (Linux
/// takes the caller's size, zero-extending a shorter structure), runs it,
/// makes the descriptors it asks for, and copies the argument back.
/// A DRM ioctl's result: what the call returns, or EAGAIN when it waits for
/// the GPU (an input fence, a busy buffer, a full queue), which the system
/// call layer turns into running other work and issuing the call again.
fn linux_drm_ioctl(file: u64, command: u32, address: u64) -> u64 {
    let started = timer::timestamp_counter();
    let result = linux_drm_ioctl_inner(file, command, address);
    crate::linux_drm::record_ioctl(
        command,
        result == LINUX_EAGAIN,
        timer::timestamp_counter().wrapping_sub(started),
    );
    if result >= LINUX_RETURN_TO_KERNEL && result != LINUX_EAGAIN {
        crate::linux_drm::log_failure(command, result.wrapping_neg());
    }
    result
}

fn linux_drm_ioctl_inner(file: u64, command: u32, address: u64) -> u64 {
    let (request, user_size) = match linox_drm::Request::decode(command) {
        Ok(decoded) => decoded,
        Err(error) => return linux_drm_errno(error),
    };
    let size = request.size();
    let copied = user_size.min(size);
    let mut argument = [0_u8; 64];
    if copied != 0 && !copy_from_linux_user(address, &mut argument[..copied]) {
        return LINUX_EFAULT;
    }
    // An execbuffer waits for its input fence first.
    if request == linox_drm::Request::Execbuffer {
        if let Some(fence) = linox_drm::execbuffer_in_fence(&argument[..size]) {
            let Some((crate::linux_drm::CLASS_FENCE, fence)) =
                linux_object_descriptor(u64::from(fence as u32))
            else {
                return LINUX_EINVAL;
            };
            if !crate::drivers::virtio_gpu::fence_signaled(fence) {
                return LINUX_EAGAIN;
            }
        }
    }
    let mut gpu = crate::drivers::virtio_gpu::VirtioGpu;
    let outcome = crate::linux_profile::span(crate::linux_profile::Span::DrmFileIoctl, || {
        crate::linux_drm::with_file(file, |open| {
            open.ioctl(
                &mut gpu,
                &mut LinuxUserMemory,
                request,
                &mut argument[..size],
            )
        })
    });
    let outcome = match outcome {
        None => return LINUX_EBADF,
        Some(Err(error)) => return linux_drm_errno(error),
        Some(Ok(outcome)) => outcome,
    };
    match outcome {
        linox_drm::Outcome::Done => {}
        linox_drm::Outcome::FenceDescriptor { fence, offset } => {
            let descriptor =
                crate::linux_profile::span(crate::linux_profile::Span::DrmFenceDescriptor, || {
                    linux_open_object(crate::linux_drm::CLASS_FENCE, fence, LINUX_O_CLOEXEC)
                });
            if descriptor >= LINUX_RETURN_TO_KERNEL {
                return descriptor;
            }
            argument[offset..offset + 4].copy_from_slice(&(descriptor as u32).to_le_bytes());
        }
        linox_drm::Outcome::Export {
            resource,
            size: length,
            flags,
            offset,
        } => {
            let Some(id) = crate::linux_drm::export(crate::linux_drm::DmaBuf {
                resource,
                size: length,
                memory: 2,
            }) else {
                return LINUX_ENOMEM;
            };
            linox_drm::Gpu::retain(&mut gpu, resource);
            let descriptor = linux_open_object(
                crate::linux_drm::CLASS_DMABUF,
                id,
                u64::from(flags) & LINUX_O_CLOEXEC,
            );
            if descriptor >= LINUX_RETURN_TO_KERNEL {
                return descriptor;
            }
            argument[offset..offset + 4].copy_from_slice(&(descriptor as u32).to_le_bytes());
        }
        linox_drm::Outcome::Import { descriptor } => {
            let Some((crate::linux_drm::CLASS_DMABUF, id)) =
                linux_object_descriptor(u64::from(descriptor as u32))
            else {
                return LINUX_EBADF;
            };
            let Some(dmabuf) = crate::linux_drm::dmabuf(id) else {
                return LINUX_EBADF;
            };
            let imported = crate::linux_drm::with_file(file, |open| {
                open.import(
                    &mut gpu,
                    dmabuf.resource,
                    dmabuf.size,
                    dmabuf.memory,
                    &mut argument[..size],
                )
            });
            match imported {
                None => return LINUX_EBADF,
                Some(Err(error)) => return linux_drm_errno(error),
                Some(Ok(())) => {}
            }
        }
    }
    // _IOC_READ: the caller wants the structure back.
    if command >> 31 != 0 && copied != 0 && !copy_to_linux_user(address, &argument[..copied]) {
        return LINUX_EFAULT;
    }
    0
}

/// mmap of an object descriptor: a render node maps a blob at the fake
/// offset DRM_IOCTL_VIRTGPU_MAP gave, and a dma-buf its blob, if mapped.
fn linux_object_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    descriptor: u64,
    offset: u64,
) -> u64 {
    let Some((class, id)) = linux_object_descriptor(descriptor) else {
        return LINUX_EBADF;
    };
    // Counted with the ioctls, as number 0xff, for a SysRq `l` profile.
    crate::linux_drm::record_ioctl(0xff, false, 0);
    if flags & LINUX_MAP_SHARED == 0 || length == 0 || !offset.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let (physical, cache) = match class {
        crate::linux_drm::CLASS_FILE => {
            match crate::linux_drm::with_file(id, |open| open.mmap(offset, length)) {
                Some(Ok(mapping)) => (mapping.physical, mapping.cache),
                Some(Err(error)) => return linux_drm_errno(error),
                None => return LINUX_EBADF,
            }
        }
        crate::linux_drm::CLASS_DMABUF => {
            let Some(dmabuf) = crate::linux_drm::dmabuf(id) else {
                return LINUX_EBADF;
            };
            if offset
                .checked_add(length)
                .is_none_or(|end| end > dmabuf.size.next_multiple_of(PAGE_SIZE as u64))
            {
                return LINUX_EINVAL;
            }
            match crate::drivers::virtio_gpu::mapped_physical(dmabuf.resource) {
                Some((physical, cache)) => (physical + offset, cache),
                None => return LINUX_ENODEV,
            }
        }
        _ => return LINUX_ENODEV,
    };
    let pages = length.div_ceil(PAGE_SIZE as u64) as usize;
    let fixed = flags & LINUX_MAP_FIXED != 0;
    let Some(mapping) = linux_runtime_select_mapping(address, pages, fixed, false) else {
        return LINUX_ENOMEM;
    };
    if !linux_runtime_range_available(mapping, pages)
        && (!fixed || linux_runtime_munmap(mapping, (pages * PAGE_SIZE) as u64) != 0)
    {
        return LINUX_ENOMEM;
    }
    for page in 0..pages {
        let installed = address_space::install_current_linux_device_page(
            mapping + (page * PAGE_SIZE) as u64,
            physical + (page * PAGE_SIZE) as u64,
            protection & LINUX_PROT_WRITE != 0,
            match cache {
                linox_drm::Cache::Cached => address_space::DeviceCaching::WriteBack,
                linox_drm::Cache::WriteCombined => address_space::DeviceCaching::WriteCombining,
                linox_drm::Cache::Uncached => address_space::DeviceCaching::Uncached,
            },
        );
        if !installed {
            let _ = rollback_linux_runtime_mapping(mapping, page);
            return LINUX_ENOMEM;
        }
    }
    mapping
}

fn linux_open_named_fifo(flags: u64, handle: crate::linux_overlay::Handle) -> u64 {
    let access = flags & 3;
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    // A nonblocking open for writing finds no reader on a FIFO nobody has
    // open (ENXIO), as Linux answers (open06).
    if access == 1
        && flags & LINUX_O_NONBLOCK != 0
        && crate::linux_overlay::fifo_socket(handle)
            .is_none_or(|slot| crate::linux_socket::kind(slot).is_none())
    {
        return LINUX_ENXIO;
    }
    let slot = match crate::linux_overlay::fifo_socket(handle) {
        Some(slot) if crate::linux_socket::duplicate(slot) => slot,
        _ => match crate::linux_socket::open_loopback(1) {
            Ok(slot) if crate::linux_overlay::set_fifo_socket(handle, slot) => slot,
            Ok(slot) => {
                let _ = crate::linux_socket::close(slot);
                return LINUX_EIO;
            }
            Err(error) => return linux_socket_error(error),
        },
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Socket).store(slot + 1, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags)
        .store((flags & LINUX_O_NONBLOCK) as u32, Ordering::SeqCst);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(
        LINUX_DEVICE_SOCKET | LINUX_DEVICE_PIPE | (access + 1) as u16,
        Ordering::SeqCst,
    );
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    descriptor
}

/// vmsplice(2): writes the vectors into a pipe opened for writing, or reads
/// a pipe opened only for reading into them; SPLICE_F_NONBLOCK makes one
/// attempt (EAGAIN), and otherwise the call waits as writev or readv does.
fn linux_vmsplice_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    descriptor: u64,
    vectors: u64,
    count: u64,
    flags: u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let flags = u64::from(flags as u32);
    if flags & !LINUX_SPLICE_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    let writes = linux_pipe_write_descriptor(descriptor);
    if !writes && !linux_pipe_read_descriptor(descriptor) {
        return LINUX_EBADF;
    }
    if flags & LINUX_SPLICE_F_NONBLOCK == 0 {
        return if writes {
            linux_descriptor_writev_live_return(output, caller, descriptor, vectors, count)
        } else {
            linux_descriptor_readv_live_return(output, caller, descriptor, vectors, count)
        };
    }
    X86_RUNTIME
        .LINUX_SOCKET_SINGLE_ATTEMPT
        .store(true, Ordering::SeqCst);
    let result = if writes {
        linux_descriptor_writev(descriptor, vectors, count)
    } else {
        linux_descriptor_readv(descriptor, vectors, count)
    };
    X86_RUNTIME
        .LINUX_SOCKET_SINGLE_ATTEMPT
        .store(false, Ordering::SeqCst);
    if result == LINUX_EPIPE && writes {
        linux_broken_pipe_live_return(output, caller)
    } else {
        result
    }
}

const LINUX_SPLICE_F_MOVE: u64 = 1;
const LINUX_SPLICE_F_NONBLOCK: u64 = 2;
const LINUX_SPLICE_F_MORE: u64 = 4;
const LINUX_SPLICE_F_GIFT: u64 = 8;
const LINUX_SPLICE_FLAGS: u64 =
    LINUX_SPLICE_F_MOVE | LINUX_SPLICE_F_NONBLOCK | LINUX_SPLICE_F_MORE | LINUX_SPLICE_F_GIFT;

/// What one side of splice(2) or tee(2) is; only these move data.
#[derive(Clone, Copy)]
enum LinuxSpliceEnd {
    Pipe(crate::linux_socket::SlotId),
    Socket(crate::linux_socket::SlotId),
    File,
    Other,
}

impl LinuxSpliceEnd {
    fn of(descriptor: u64) -> Self {
        let state = linux_device_descriptor(descriptor);
        // An io_uring is kept as a scratch file but is none to splice.
        if linux_io_uring_descriptor(descriptor) {
            return Self::Other;
        }
        match linux_socket_slot(descriptor) {
            Some(slot) if state & LINUX_DEVICE_PIPE != 0 => Self::Pipe(slot),
            // A kernel object shared like a socket (an io_uring, a DRM
            // file) is no socket: splice refuses it at once rather than
            // waiting on the pipe (splice07 hung on pipe -> io_uring).
            Some(slot)
                if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Object) =>
            {
                Self::Other
            }
            Some(slot) => Self::Socket(slot),
            // /dev/zero, /dev/full and /dev/urandom read as files do, so
            // they can be spliced into a pipe (splice08).
            None if linux_overlay_descriptor_handle(descriptor).is_some()
                || linux_rootfs_descriptor(descriptor) != 0
                || linux_tmp_descriptor_handle(descriptor, state).is_some()
                || linux_proc_sysctl_index(state).is_some()
                || state & LINUX_DEVICE_ZERO != 0 && state & LINUX_DEVICE_DIRECTORY == 0 =>
            {
                Self::File
            }
            None => Self::Other,
        }
    }
}

/// How a splice(2) or tee(2) step ended: with the call's result, or unable
/// to start because the pipe or socket it reads is empty, or the one it
/// fills is full.
enum LinuxSpliceStep {
    Done(u64),
    Blocked,
}

/// A step that cannot go on: blocked if nothing moved yet, and otherwise
/// done with what moved.
fn linux_splice_blocked(moved: usize) -> LinuxSpliceStep {
    if moved == 0 {
        LinuxSpliceStep::Blocked
    } else {
        LinuxSpliceStep::Done(moved as u64)
    }
}

/// A step that ended after `moved` bytes, with `failure` if it stopped on an
/// error: the bytes already moved are the result, as with a short write.
fn linux_splice_moved(moved: usize, failure: Option<u64>) -> LinuxSpliceStep {
    LinuxSpliceStep::Done(match failure {
        Some(error) if moved == 0 => error,
        _ => moved as u64,
    })
}

/// The system call's result for `step`. A blocked call fails with EAGAIN
/// when nonblocking; otherwise the rest of the domain runs and the call
/// starts again, as a blocking pipe read does. Filling a pipe or socket with
/// no reader raises SIGPIPE.
fn linux_splice_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    nonblocking: bool,
    step: LinuxSpliceStep,
) -> u64 {
    match step {
        LinuxSpliceStep::Done(LINUX_EPIPE) => linux_broken_pipe_live_return(output, caller),
        LinuxSpliceStep::Done(result) => result,
        LinuxSpliceStep::Blocked
            if nonblocking || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire) =>
        {
            LINUX_EAGAIN
        }
        LinuxSpliceStep::Blocked => linux_retry_later_live_return(output, caller, number),
    }
}

/// splice(2) and tee(2) need `source` open for reading and `sink` for
/// writing (EBADF), checked before what kind of files they are.
fn linux_splice_access(source: u64, sink: u64) -> Result<(), u64> {
    if !linux_descriptor_open(source)
        || !linux_descriptor_open(sink)
        || !matches!(
            linux_device_descriptor(source) & 3,
            LINUX_DESCRIPTOR_INPUT | 3
        )
        || !matches!(
            linux_device_descriptor(sink) & 3,
            LINUX_DESCRIPTOR_OUTPUT | 3
        )
    {
        return Err(LINUX_EBADF);
    }
    Ok(())
}

/// Whether a splice(2) or tee(2) between `ends` waits: not with
/// SPLICE_F_NONBLOCK or a pipe or socket end opened O_NONBLOCK.
fn linux_splice_nonblocking(flags: u64, ends: [(u64, LinuxSpliceEnd); 2]) -> bool {
    flags & LINUX_SPLICE_F_NONBLOCK != 0
        || ends.iter().any(|(descriptor, end)| {
            matches!(end, LinuxSpliceEnd::Pipe(_) | LinuxSpliceEnd::Socket(_))
                && linux_socket_nonblocking(*descriptor)
        })
}

/// splice(2): moves up to `length` bytes between `source` and `sink`, one
/// of which is a pipe; the other may be a pipe, a socket or a regular file,
/// whose offset is the pointed-to value if given (left as it was in the
/// file) or else the file position.
fn linux_splice(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    (source, source_offset): (u64, u64),
    (sink, sink_offset): (u64, u64),
    length: u64,
    flags: u64,
) -> u64 {
    let source = u64::from(source as u32);
    let sink = u64::from(sink as u32);
    let flags = u64::from(flags as u32);
    if length == 0 {
        return 0;
    }
    if flags & !LINUX_SPLICE_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    if let Err(error) = linux_splice_access(source, sink) {
        return error;
    }
    let (from, to) = (LinuxSpliceEnd::of(source), LinuxSpliceEnd::of(sink));
    let nonblocking = linux_splice_nonblocking(flags, [(source, from), (sink, to)]);
    let step = match (from, to) {
        (LinuxSpliceEnd::Pipe(from), LinuxSpliceEnd::Pipe(to)) => {
            if source_offset != 0 || sink_offset != 0 {
                return LINUX_ESPIPE;
            }
            if crate::linux_socket::same_pipe(from, to) {
                return LINUX_EINVAL;
            }
            linux_splice_between_pipes(from, to, length, true)
        }
        (LinuxSpliceEnd::Pipe(from), to) => {
            if source_offset != 0 {
                return LINUX_ESPIPE;
            }
            linux_splice_from_pipe(from, (sink, sink_offset), to, length)
        }
        (from, LinuxSpliceEnd::Pipe(to)) => {
            if sink_offset != 0 {
                return LINUX_ESPIPE;
            }
            linux_splice_to_pipe((source, source_offset), from, to, length)
        }
        _ => return LINUX_EINVAL,
    };
    linux_splice_live_return(output, caller, LINUX_SPLICE_SYSCALL, nonblocking, step)
}

/// tee(2): copies up to `length` bytes from one pipe to another without
/// consuming them.
fn linux_tee(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    source: u64,
    sink: u64,
    length: u64,
    flags: u64,
) -> u64 {
    let source = u64::from(source as u32);
    let sink = u64::from(sink as u32);
    let flags = u64::from(flags as u32);
    if flags & !LINUX_SPLICE_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    if length == 0 {
        return 0;
    }
    if let Err(error) = linux_splice_access(source, sink) {
        return error;
    }
    let (from, to) = (LinuxSpliceEnd::of(source), LinuxSpliceEnd::of(sink));
    let (LinuxSpliceEnd::Pipe(from_slot), LinuxSpliceEnd::Pipe(to_slot)) = (from, to) else {
        return LINUX_EINVAL;
    };
    if crate::linux_socket::same_pipe(from_slot, to_slot) {
        return LINUX_EINVAL;
    }
    let nonblocking = linux_splice_nonblocking(flags, [(source, from), (sink, to)]);
    let step = linux_splice_between_pipes(from_slot, to_slot, length, false);
    linux_splice_live_return(output, caller, LINUX_TEE_SYSCALL, nonblocking, step)
}

/// Moves (or, for tee, copies: `consume` false) bytes from one pipe to
/// another, as many as are queued and fit, up to `length`.
fn linux_splice_between_pipes(
    from: crate::linux_socket::SlotId,
    to: crate::linux_socket::SlotId,
    length: u64,
    consume: bool,
) -> LinuxSpliceStep {
    let requested = usize::try_from(length).unwrap_or(usize::MAX);
    let mut buffer = [0_u8; PAGE_SIZE];
    let mut moved = 0_usize;
    while moved < requested {
        let Some(room) = crate::linux_socket::pipe_room(to) else {
            return linux_splice_moved(moved, Some(LINUX_EPIPE));
        };
        let chunk = (requested - moved).min(buffer.len()).min(room);
        if chunk == 0 {
            return linux_splice_blocked(moved);
        }
        let available = match crate::linux_socket::peek_local(from, &mut buffer[..chunk]) {
            Ok(0) => break,
            Ok(available) => available,
            Err(crate::linux_socket::Error::WouldBlock) => return linux_splice_blocked(moved),
            Err(error) => return linux_splice_moved(moved, Some(linux_socket_error(error))),
        };
        let sent = match crate::linux_socket::send(to, &buffer[..available], None) {
            Ok(sent) => sent,
            Err(crate::linux_socket::Error::WouldBlock) => return linux_splice_blocked(moved),
            Err(error) => return linux_splice_moved(moved, Some(linux_socket_error(error))),
        };
        if consume
            && !matches!(
                crate::linux_socket::recv(from, &mut buffer[..sent]),
                Ok((received, _)) if received == sent
            )
        {
            return linux_splice_moved(moved, Some(LINUX_EIO));
        }
        moved += sent;
        // tee copies what the pipe holds once: another pass would see the
        // same bytes again.
        if !consume || sent < available {
            break;
        }
    }
    LinuxSpliceStep::Done(moved as u64)
}

/// Moves bytes from pipe `from` into a socket or regular file `sink`.
/// Whether `descriptor` is /dev/null or /dev/zero (`Some(false)`), which
/// take and drop what is written, or /dev/full (`Some(true)`), which takes
/// nothing (ENOSPC).
fn linux_discard_sink(descriptor: u64) -> Option<bool> {
    let state = linux_device_descriptor(descriptor);
    if !linux_descriptor_open(descriptor)
        || linux_console_descriptor(descriptor) != 0
        || linux_socket_slot(descriptor).is_some()
        || linux_overlay_descriptor_handle(descriptor).is_some()
        || linux_rootfs_descriptor(descriptor) != 0
        || linux_tmp_descriptor_handle(descriptor, state).is_some()
        || linux_io_uring_descriptor(descriptor)
        || linux_graphics_device(state).is_some()
        || state & (LINUX_FILE_MASK | LINUX_DEVICE_DIRECTORY | LINUX_DEVICE_CONSOLE) != 0
    {
        return None;
    }
    match state & !3 {
        0 | LINUX_DEVICE_ZERO => Some(false),
        LINUX_DEVICE_FULL => Some(true),
        _ => None,
    }
}

fn linux_splice_from_pipe(
    from: crate::linux_socket::SlotId,
    (sink, sink_offset): (u64, u64),
    to: LinuxSpliceEnd,
    length: u64,
) -> LinuxSpliceStep {
    // Into /dev/null or /dev/zero the bytes are taken from the pipe and
    // dropped, as writing them would; /dev/full takes none (splice09).
    if let Some(full) = linux_discard_sink(sink) {
        if full {
            return LinuxSpliceStep::Done(LINUX_ENOSPC);
        }
        let requested = usize::try_from(length).unwrap_or(usize::MAX);
        let mut buffer = [0_u8; PAGE_SIZE];
        let mut moved = 0_usize;
        while moved < requested {
            let chunk = (requested - moved).min(buffer.len());
            match crate::linux_socket::recv(from, &mut buffer[..chunk]) {
                Ok((0, _)) => break,
                Ok((received, _)) => moved += received,
                Err(crate::linux_socket::Error::WouldBlock) if moved == 0 => {
                    return LinuxSpliceStep::Blocked;
                }
                Err(crate::linux_socket::Error::WouldBlock) => break,
                Err(error) => return linux_splice_moved(moved, Some(linux_socket_error(error))),
            }
        }
        return linux_splice_moved(moved, None);
    }
    let (mut offset, explicit) = match to {
        LinuxSpliceEnd::File => {
            if linux_socket_flags(sink).is_some_and(|flags| flags & LINUX_O_APPEND as u32 != 0) {
                return LinuxSpliceStep::Done(LINUX_EINVAL);
            }
            match linux_file_range_offset(sink_offset, sink) {
                Ok(offset) => offset,
                Err(error) => return LinuxSpliceStep::Done(error),
            }
        }
        LinuxSpliceEnd::Socket(_) if sink_offset == 0 => (0, false),
        _ => return LinuxSpliceStep::Done(LINUX_EINVAL),
    };
    let requested = usize::try_from(length).unwrap_or(usize::MAX);
    let mut buffer = [0_u8; PAGE_SIZE];
    let mut moved = 0_usize;
    let mut failure = None;
    while moved < requested {
        let chunk = (requested - moved).min(buffer.len());
        let available = match crate::linux_socket::peek_local(from, &mut buffer[..chunk]) {
            Ok(0) => break,
            Ok(available) => available,
            Err(crate::linux_socket::Error::WouldBlock) if moved == 0 => {
                return LinuxSpliceStep::Blocked;
            }
            Err(crate::linux_socket::Error::WouldBlock) => break,
            Err(error) => {
                failure = Some(linux_socket_error(error));
                break;
            }
        };
        let written = match to {
            LinuxSpliceEnd::Socket(slot) => {
                match crate::linux_socket::send(slot, &buffer[..available], None) {
                    Ok(written) => written,
                    Err(crate::linux_socket::Error::WouldBlock) if moved == 0 => {
                        return LinuxSpliceStep::Blocked;
                    }
                    Err(crate::linux_socket::Error::WouldBlock) => break,
                    Err(error) => {
                        failure = Some(linux_socket_error(error));
                        break;
                    }
                }
            }
            _ => match linux_regular_file_write_kernel(sink, offset, &buffer[..available]) {
                Ok(written) => written,
                Err(error) => {
                    failure = Some(if error == LINUX_EISDIR {
                        LINUX_EINVAL
                    } else {
                        error
                    });
                    break;
                }
            },
        };
        if written == 0 {
            break;
        }
        if !matches!(
            crate::linux_socket::recv(from, &mut buffer[..written]),
            Ok((received, _)) if received == written
        ) {
            failure = Some(LINUX_EIO);
            break;
        }
        offset = offset.saturating_add(written);
        moved += written;
        if written < available {
            break;
        }
    }
    if matches!(to, LinuxSpliceEnd::File)
        && linux_commit_file_range_offset(sink_offset, sink, explicit, offset).is_err()
    {
        failure = Some(LINUX_EFAULT);
    }
    linux_splice_moved(moved, failure)
}

/// Moves bytes from a socket or regular file `source` into pipe `to`, no
/// more than fit, so nothing read is lost.
fn linux_splice_to_pipe(
    (source, source_offset): (u64, u64),
    from: LinuxSpliceEnd,
    to: crate::linux_socket::SlotId,
    length: u64,
) -> LinuxSpliceStep {
    let (mut offset, explicit) = match from {
        LinuxSpliceEnd::File => match linux_file_range_offset(source_offset, source) {
            Ok(offset) => offset,
            Err(error) => return LinuxSpliceStep::Done(error),
        },
        LinuxSpliceEnd::Socket(slot)
            if source_offset == 0 && !crate::linux_socket::unix_stream_unconnected(slot) =>
        {
            (0, false)
        }
        _ => return LinuxSpliceStep::Done(LINUX_EINVAL),
    };
    let requested = usize::try_from(length).unwrap_or(usize::MAX);
    let mut buffer = [0_u8; PAGE_SIZE];
    let mut moved = 0_usize;
    let mut failure = None;
    while moved < requested {
        let Some(room) = crate::linux_socket::pipe_room(to) else {
            failure = Some(LINUX_EPIPE);
            break;
        };
        let chunk = (requested - moved).min(buffer.len()).min(room);
        if chunk == 0 {
            if moved == 0 {
                return LinuxSpliceStep::Blocked;
            }
            break;
        }
        let read = match from {
            LinuxSpliceEnd::Socket(slot) => {
                match crate::linux_socket::recv(slot, &mut buffer[..chunk]) {
                    Ok((read, _)) => read,
                    Err(crate::linux_socket::Error::WouldBlock) if moved == 0 => {
                        return LinuxSpliceStep::Blocked;
                    }
                    Err(crate::linux_socket::Error::WouldBlock) => break,
                    Err(error) => {
                        failure = Some(linux_socket_error(error));
                        break;
                    }
                }
            }
            // A directory has nothing to splice (EINVAL), as in Linux.
            _ => match linux_regular_file_read_kernel(source, offset, &mut buffer[..chunk]) {
                Ok(read) => read,
                Err(error) => {
                    failure = Some(if error == LINUX_EISDIR {
                        LINUX_EINVAL
                    } else {
                        error
                    });
                    break;
                }
            },
        };
        if read == 0 {
            break;
        }
        let sent = match crate::linux_socket::send(to, &buffer[..read], None) {
            Ok(sent) => sent,
            Err(error) => {
                failure = Some(linux_socket_error(error));
                break;
            }
        };
        offset = offset.saturating_add(sent);
        moved += sent;
        if sent < read {
            break;
        }
    }
    if matches!(from, LinuxSpliceEnd::File)
        && linux_commit_file_range_offset(source_offset, source, explicit, offset).is_err()
    {
        failure = Some(LINUX_EFAULT);
    }
    linux_splice_moved(moved, failure)
}

fn linux_runtime_pipe(address: u64, flags: u64) -> u64 {
    linux_socket_pipe(
        address,
        flags,
        LINUX_AUX_DESCRIPTOR_FIRST,
        copy_to_linux_user,
    )
}

fn linux_socket_pipe(
    address: u64,
    flags: u64,
    first_descriptor: u64,
    copy: impl FnOnce(u64, &[u8]) -> bool,
) -> u64 {
    if flags & !(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC | LINUX_O_DIRECT) != 0 {
        return LINUX_EINVAL;
    }
    let Some(descriptors) = linux_free_descriptors::<2>(first_descriptor) else {
        return LINUX_EMFILE;
    };
    // A packet-mode (O_DIRECT) pipe keeps each write as one packet, which a
    // read returns on its own: a sequenced-packet pair, where a plain pipe
    // is a byte stream.
    let socket_type = if flags & LINUX_O_DIRECT != 0 { 5 } else { 1 };
    let (reader, writer) = match crate::linux_socket::open_pair(socket_type) {
        Ok(pair) => pair,
        Err(error) => return linux_socket_error(error),
    };
    // An unprivileged process gets no pipe larger than pipe-max-size: Linux
    // caps the default capacity, not only F_SETPIPE_SZ requests.
    if !current_linux_credentials().is_some_and(|value| value.user.effective == 0) {
        let limit = linux_pipe_max_size() as usize;
        if crate::linux_socket::local_capacity(reader).is_ok_and(|capacity| capacity > limit) {
            let _ = crate::linux_socket::set_local_capacity(reader, limit);
        }
    }
    let mut output = [0_u8; 8];
    output[..4].copy_from_slice(&(descriptors[0] as u32).to_ne_bytes());
    output[4..].copy_from_slice(&(descriptors[1] as u32).to_ne_bytes());
    if !copy(address, &output) {
        let _ = crate::linux_socket::close(reader);
        let _ = crate::linux_socket::close(writer);
        return LINUX_EFAULT;
    }
    let ends = [
        (descriptors[0], reader, LINUX_DESCRIPTOR_INPUT),
        (descriptors[1], writer, LINUX_DESCRIPTOR_OUTPUT),
    ];
    let installed = ends.map(|(descriptor, slot, access)| {
        install_linux_socket_descriptor(
            descriptor,
            slot,
            LINUX_DEVICE_SOCKET | LINUX_DEVICE_PIPE | access,
            (flags & (LINUX_O_NONBLOCK | LINUX_O_DIRECT)) as u32,
            flags & LINUX_O_CLOEXEC != 0,
        )
    });
    if installed.contains(&false) {
        // Out of memory for the table above the fixed one: neither end
        // stays open (closing an installed end closes its socket).
        for ((descriptor, slot, _), installed) in ends.into_iter().zip(installed) {
            if installed {
                let _ = linux_descriptor_close(descriptor);
            } else {
                let _ = crate::linux_socket::close(slot);
            }
        }
        return LINUX_ENOMEM;
    }
    0
}

fn linux_pipe_read(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    if !linux_pipe_read_descriptor(descriptor) {
        return None;
    }
    if count == 0 {
        return Some(0);
    }
    let length = X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst) as usize;
    if length == 0 {
        if X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
            .load(Ordering::SeqCst)
            == 0
        {
            return Some(0);
        }
        return Some(
            if X86_RUNTIME.ELF_PROBE_PIPE_READ_FLAGS.load(Ordering::SeqCst)
                & LINUX_O_NONBLOCK as u32
                != 0
            {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    }
    let requested = usize::try_from(count).unwrap_or(usize::MAX);
    let returned = length.min(requested);
    let mut output = [0_u8; LINUX_PIPE_CAPACITY];
    for (target, source) in output[..returned]
        .iter_mut()
        .zip(&X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[..returned])
    {
        *target = source.load(Ordering::SeqCst);
    }
    if !copy_to_linux_user(address, &output[..returned]) {
        return Some(LINUX_EFAULT);
    }
    for index in 0..length - returned {
        let value = X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[index + returned].load(Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[index].store(value, Ordering::SeqCst);
    }
    for byte in &X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[length - returned..length] {
        byte.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_PIPE_LENGTH
        .store((length - returned) as u32, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    Some(returned as u64)
}

fn linux_pipe_write(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    if !linux_pipe_write_descriptor(descriptor) {
        return None;
    }
    if count == 0 {
        return Some(0);
    }
    if X86_RUNTIME
        .ELF_PROBE_PIPE_READ_DESCRIPTOR
        .load(Ordering::SeqCst)
        == 0
    {
        return Some(LINUX_EPIPE);
    }
    let Ok(requested) = usize::try_from(count) else {
        return Some(LINUX_EINVAL);
    };
    if requested > LINUX_PIPE_CAPACITY {
        return Some(LINUX_EINVAL);
    }
    let length = X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst) as usize;
    if requested > LINUX_PIPE_CAPACITY - length {
        return Some(
            if X86_RUNTIME
                .ELF_PROBE_PIPE_WRITE_FLAGS
                .load(Ordering::SeqCst)
                & LINUX_O_NONBLOCK as u32
                != 0
            {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    }
    let mut input = [0_u8; LINUX_PIPE_CAPACITY];
    if !copy_from_linux_user(address, &mut input[..requested]) {
        return Some(LINUX_EFAULT);
    }
    for (target, source) in X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[length..length + requested]
        .iter()
        .zip(&input[..requested])
    {
        target.store(*source, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_PIPE_LENGTH
        .store((length + requested) as u32, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    Some(count)
}

fn linux_pipe_writev(descriptor: u64, vectors: u64, count: u64) -> Option<u64> {
    if !linux_pipe_write_descriptor(descriptor) {
        return None;
    }
    let (ranges, vector_count) = match linux_writev_ranges(vectors, count) {
        Ok(snapshot) => snapshot,
        Err(error) => return Some(error),
    };
    Some(linux_pipe_writev_ranges(
        descriptor,
        &ranges[..vector_count],
    ))
}

fn linux_writev_ranges(
    vectors: u64,
    count: u64,
) -> Result<([(u64, usize); LINUX_IOV_LIMIT], usize), u64> {
    let Ok(vector_count) = usize::try_from(count) else {
        return Err(LINUX_EINVAL);
    };
    if vector_count > LINUX_IOV_LIMIT {
        return Err(LINUX_EINVAL);
    }
    let mut table = [0_u8; LINUX_IOV_LIMIT * 16];
    if !copy_from_linux_user(vectors, &mut table[..vector_count * 16]) {
        return Err(LINUX_EFAULT);
    }
    let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
    let mut total = 0_usize;
    for (index, vector) in table[..vector_count * 16]
        .as_chunks::<16>()
        .0
        .iter()
        .enumerate()
    {
        let address = u64::from_ne_bytes(vector[..8].try_into().unwrap());
        let length = u64::from_ne_bytes(vector[8..].try_into().unwrap());
        let Ok(length) = usize::try_from(length) else {
            return Err(LINUX_EINVAL);
        };
        let Some(end) = total.checked_add(length) else {
            return Err(LINUX_EINVAL);
        };
        if end > LINUX_PIPE_CAPACITY {
            return Err(LINUX_EINVAL);
        }
        if length != 0 && !linux_readable_user_range_contains(address, length) {
            return Err(LINUX_EFAULT);
        }
        ranges[index] = (address, length);
        total = end;
    }
    Ok((ranges, vector_count))
}

fn linux_pipe_writev_ranges(descriptor: u64, ranges: &[(u64, usize)]) -> u64 {
    if !linux_pipe_write_descriptor(descriptor) {
        return LINUX_EBADF;
    }
    if X86_RUNTIME
        .ELF_PROBE_PIPE_READ_DESCRIPTOR
        .load(Ordering::SeqCst)
        == 0
    {
        return LINUX_EPIPE;
    }
    let mut total = 0_usize;
    for (_, length) in ranges.iter().copied() {
        let Some(end) = total.checked_add(length) else {
            return LINUX_EINVAL;
        };
        if length == 0 || end > LINUX_PIPE_CAPACITY {
            return LINUX_EINVAL;
        }
        total = end;
    }
    let current = X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst) as usize;
    if total > LINUX_PIPE_CAPACITY - current {
        return if X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_FLAGS
            .load(Ordering::SeqCst)
            & LINUX_O_NONBLOCK as u32
            != 0
        {
            LINUX_EAGAIN
        } else {
            LINUX_ENOSYS
        };
    }
    let mut input = [0_u8; LINUX_PIPE_CAPACITY];
    let mut copied = 0;
    for (address, length) in ranges.iter().copied() {
        if !copy_from_linux_user(address, &mut input[copied..copied + length]) {
            return LINUX_EFAULT;
        }
        copied += length;
    }
    for (target, source) in X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[current..current + total]
        .iter()
        .zip(&input[..total])
    {
        target.store(*source, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_PIPE_LENGTH
        .store((current + total) as u32, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    total as u64
}

fn linux_pipe_readv(descriptor: u64, vectors: u64, count: u64) -> Option<u64> {
    if !linux_pipe_read_descriptor(descriptor) {
        return None;
    }
    let (ranges, vector_count) = match linux_readv_ranges(vectors, count) {
        Ok(snapshot) => snapshot,
        Err(error) => return Some(error),
    };
    Some(linux_pipe_readv_ranges(descriptor, &ranges[..vector_count]))
}

fn linux_readv_ranges(
    vectors: u64,
    count: u64,
) -> Result<([(u64, usize); LINUX_IOV_LIMIT], usize), u64> {
    let Ok(vector_count) = usize::try_from(count) else {
        return Err(LINUX_EINVAL);
    };
    if vector_count > LINUX_IOV_LIMIT {
        return Err(LINUX_EINVAL);
    }
    let mut table = [0_u8; LINUX_IOV_LIMIT * 16];
    if !copy_from_linux_user(vectors, &mut table[..vector_count * 16]) {
        return Err(LINUX_EFAULT);
    }
    let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
    let mut capacity = 0_usize;
    for (index, vector) in table[..vector_count * 16]
        .as_chunks::<16>()
        .0
        .iter()
        .enumerate()
    {
        let address = u64::from_ne_bytes(vector[..8].try_into().unwrap());
        let length = u64::from_ne_bytes(vector[8..].try_into().unwrap());
        let Ok(length) = usize::try_from(length) else {
            return Err(LINUX_EINVAL);
        };
        let Some(end) = capacity.checked_add(length) else {
            return Err(LINUX_EINVAL);
        };
        if length == 0 || end > LINUX_PIPE_CAPACITY {
            return Err(LINUX_EINVAL);
        }
        if !linux_writable_user_range_contains(address, length) {
            return Err(LINUX_EFAULT);
        }
        ranges[index] = (address, length);
        capacity = end;
    }
    Ok((ranges, vector_count))
}

fn linux_pipe_readv_ranges(descriptor: u64, ranges: &[(u64, usize)]) -> u64 {
    if !linux_pipe_read_descriptor(descriptor) || ranges.is_empty() {
        return LINUX_EBADF;
    }
    let mut capacity = 0_usize;
    for (address, range_length) in ranges.iter().copied() {
        let Some(end) = capacity.checked_add(range_length) else {
            return LINUX_EINVAL;
        };
        if range_length == 0
            || end > LINUX_PIPE_CAPACITY
            || !linux_writable_user_range_contains(address, range_length)
        {
            return if range_length == 0 || end > LINUX_PIPE_CAPACITY {
                LINUX_EINVAL
            } else {
                LINUX_EFAULT
            };
        }
        capacity = end;
    }
    let length = X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst) as usize;
    if length == 0 {
        if X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
            .load(Ordering::SeqCst)
            == 0
        {
            return 0;
        }
        return if X86_RUNTIME.ELF_PROBE_PIPE_READ_FLAGS.load(Ordering::SeqCst)
            & LINUX_O_NONBLOCK as u32
            != 0
        {
            LINUX_EAGAIN
        } else {
            LINUX_ENOSYS
        };
    }
    let returned = length.min(capacity);
    let mut output = [0_u8; LINUX_PIPE_CAPACITY];
    for (target, source) in output[..returned]
        .iter_mut()
        .zip(&X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[..returned])
    {
        *target = source.load(Ordering::SeqCst);
    }
    let mut copied = 0;
    for (address, range_length) in ranges.iter().copied() {
        let amount = range_length.min(returned - copied);
        if amount == 0 {
            break;
        }
        if !copy_to_linux_user(address, &output[copied..copied + amount]) {
            return LINUX_EFAULT;
        }
        copied += amount;
    }
    for index in 0..length - returned {
        let value = X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[index + returned].load(Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[index].store(value, Ordering::SeqCst);
    }
    for byte in &X86_RUNTIME.ELF_PROBE_PIPE_BUFFER[length - returned..length] {
        byte.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_PIPE_LENGTH
        .store((length - returned) as u32, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    returned as u64
}

fn linux_epoll_ctl(epoll: u64, operation: u64, descriptor: u64, event_address: u64) -> u64 {
    let epoll = u64::from(epoll as u32);
    let operation = u64::from(operation as u32);
    let descriptor = u64::from(descriptor as u32);
    if !linux_epoll_descriptor(epoll) {
        return LINUX_EBADF;
    }
    if descriptor == epoll {
        return LINUX_EINVAL;
    }
    let epoll = linux_epoll_instance(epoll);
    // An O_PATH descriptor is no file to watch (EBADF, as in Linux), nor
    // a detached mount's, which is one.
    if !linux_descriptor_open(descriptor)
        || linux_path_descriptor(descriptor)
        || linux_detached_mount_descriptor(descriptor).is_some()
    {
        return LINUX_EBADF;
    }
    if !linux_descriptor_epollable(descriptor) {
        return LINUX_EPERM;
    }
    let runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    let existing = if runtime {
        (0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize).find(|slot| {
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[*slot].load(Ordering::SeqCst)
                == (epoll as u32).wrapping_add(1)
                && X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[*slot].load(Ordering::SeqCst)
                    == (descriptor as u32).wrapping_add(1)
        })
    } else {
        Some(descriptor as usize).filter(|target| {
            X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[*target].load(Ordering::SeqCst) != 0
        })
    };
    if operation == LINUX_EPOLL_CTL_DEL {
        let Some(slot) = existing else {
            return LINUX_ENOENT;
        };
        X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EPOLL_DATA[slot].store(0, Ordering::SeqCst);
        if runtime {
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].store(0, Ordering::SeqCst);
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].store(0, Ordering::SeqCst);
        }
        return 0;
    }
    if !matches!(operation, LINUX_EPOLL_CTL_ADD | LINUX_EPOLL_CTL_MOD) {
        return LINUX_EINVAL;
    }
    if operation == LINUX_EPOLL_CTL_ADD && existing.is_some() {
        return LINUX_EEXIST;
    }
    // An epoll instance watching another: a cycle back to this one is
    // ELOOP, and a chain deeper than Linux's EP_MAX_NESTS (4 below the
    // top) is EINVAL (epoll_ctl04, 05, 07).
    if runtime && operation == LINUX_EPOLL_CTL_ADD && linux_epoll_descriptor(descriptor) {
        let target = linux_epoll_instance(descriptor);
        if linux_epoll_reaches(target, epoll, 0) {
            return LINUX_ELOOP;
        }
        if linux_epoll_depth_below(target, 0) + linux_epoll_depth_above(epoll, 0) >= 4 {
            return LINUX_EINVAL;
        }
    }
    if operation == LINUX_EPOLL_CTL_MOD && existing.is_none() {
        return LINUX_ENOENT;
    }
    let mut event = [0_u8; 12];
    if !copy_from_linux_user(event_address, &mut event) {
        return LINUX_EFAULT;
    }
    let events = u32::from_ne_bytes(event[..4].try_into().unwrap());
    if events & !LINUX_EPOLL_SUPPORTED_EVENTS != 0 {
        return LINUX_EINVAL;
    }
    // EPOLLEXCLUSIVE is given at EPOLL_CTL_ADD only, never for an epoll
    // instance and with no events beyond LINUX_EPOLLEXCLUSIVE_OK_BITS; an
    // exclusive watch cannot be modified either.
    let exclusive_refused = events & LINUX_EPOLLEXCLUSIVE != 0
        && (operation == LINUX_EPOLL_CTL_MOD
            || linux_epoll_descriptor(descriptor)
            || events & !LINUX_EPOLLEXCLUSIVE_OK_BITS != 0);
    let exclusive_modified = operation == LINUX_EPOLL_CTL_MOD
        && existing.is_some_and(|slot| {
            X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].load(Ordering::SeqCst) & LINUX_EPOLLEXCLUSIVE
                != 0
        });
    if exclusive_refused || exclusive_modified {
        return LINUX_EINVAL;
    }
    let data = u64::from_ne_bytes(event[4..].try_into().unwrap());
    let slot = if let Some(slot) = existing {
        slot
    } else if runtime {
        let Some(slot) = (0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize).find(|slot| {
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[*slot].load(Ordering::SeqCst) == 0
        }) else {
            return LINUX_ENOSPC;
        };
        X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot]
            .store((epoll as u32).wrapping_add(1), Ordering::SeqCst);
        X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot]
            .store((descriptor as u32).wrapping_add(1), Ordering::SeqCst);
        slot
    } else {
        descriptor as usize
    };
    X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(events, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_EPOLL_DATA[slot].store(data, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    0
}

/// What kind of object a descriptor refers to, for diagnostics.
pub(super) fn linux_descriptor_kind_name(descriptor: u64) -> &'static str {
    if !linux_descriptor_open(descriptor) {
        "closed"
    } else if linux_pipe_descriptor(descriptor) {
        "pipe"
    } else if linux_socket_slot(descriptor).is_some() {
        "socket"
    } else if linux_eventfd_descriptor(descriptor) {
        "eventfd"
    } else if linux_pidfd_descriptor(descriptor) {
        "pidfd"
    } else if linux_signalfd_descriptor(descriptor) {
        "signalfd"
    } else if linux_timerfd_descriptor(descriptor) {
        "timerfd"
    } else if linux_epoll_descriptor(descriptor) {
        "epoll"
    } else if linux_console_descriptor_open(descriptor)
        || linux_device_descriptor(descriptor) & LINUX_DEVICE_CONSOLE != 0
    {
        "console"
    } else {
        "file"
    }
}

fn linux_descriptor_epollable(descriptor: u64) -> bool {
    let device = linux_device_descriptor(descriptor);
    linux_console_descriptor_open(descriptor)
        || descriptor == 2 && X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::SeqCst)
        || device & LINUX_DEVICE_CONSOLE != 0
        || linux_pidfd_descriptor(descriptor)
        || linux_signalfd_descriptor(descriptor)
        || linux_inotify_descriptor(descriptor)
        || linux_fanotify_descriptor(descriptor)
        // A filesystem context has no poll (EPERM, as in Linux).
        || linux_socket_slot(descriptor).is_some()
            && linux_fs_context_descriptor(descriptor).is_none()
        || linux_epoll_descriptor(descriptor)
        || linux_eventfd_descriptor(descriptor)
        || linux_timerfd_descriptor(descriptor)
        || linux_pipe_descriptor(descriptor)
        // io_uring (its completions), userfaultfd (its events) and
        // /proc/mounts (a mount table change) can be polled in Linux too.
        || linux_io_uring_descriptor(descriptor)
        || linux_userfaultfd_descriptor(descriptor)
        || device & !3 == LINUX_FILE_PROC_MOUNTS
}

/// Bits of a watch's stored events word that hold the readiness last reported
/// for an edge-triggered (EPOLLET) watch; Linux defines no epoll flags there.
const LINUX_EPOLL_REPORTED_SHIFT: u32 = 16;
const LINUX_EPOLL_REPORTED_MASK: u32 = 0x1f << LINUX_EPOLL_REPORTED_SHIFT;
/// Set in an edge-triggered watch's events word once
/// LINUX_RUNTIME_EPOLL_WATCH_SEEN holds the event counts it saw; clear after
/// EPOLL_CTL_ADD or MOD, which report readiness at once as Linux does.
const LINUX_EPOLL_SEEN_VALID: u32 = 1 << 21;
/// The events an input wakeup (new data, a hangup) concerns.
const LINUX_EPOLL_INPUT_EVENTS: u16 =
    LINUX_POLLIN | LINUX_POLLPRI | LINUX_POLLRDNORM | 0x80 | LINUX_POLLRDHUP;

/// The wakeup counts of the socket or pipe behind `descriptor`, input in
/// the low half and output in the high (see `linux_socket::event_counts`),
/// or None for a descriptor whose wakeups are not counted.
fn linux_epoll_event_counts(descriptor: u64) -> Option<u64> {
    let (input, output) = crate::linux_socket::event_counts(linux_socket_slot(descriptor)?)?;
    Some(u64::from(input) | u64::from(output) << 32)
}

/// Re-arms the edge-triggered watches on the descriptor a system call is
/// about to read, write, accept on or reap (a pidfd for waitid), so that
/// readiness after the call is reported again. Linux reports an edge for
/// each new event; consumers such as mio read until EAGAIN, so re-arming on
/// use reports every new event and at most adds a spurious one. Sockets and
/// pipes need none: their wakeups are counted (linux_epoll_event_counts).
pub(super) fn linux_epoll_rearm_for_syscall(number: u64, first: u64, second: u64) {
    let descriptor = match number {
        LINUX_READ_SYSCALL
        | LINUX_WRITE_SYSCALL
        | LINUX_PREAD64_SYSCALL
        | LINUX_PWRITE64_SYSCALL
        | LINUX_READV_SYSCALL
        | LINUX_WRITEV_SYSCALL
        | LINUX_PREADV_SYSCALL
        | LINUX_PWRITEV_SYSCALL
        | LINUX_PREADV2_SYSCALL
        | LINUX_PWRITEV2_SYSCALL
        | LINUX_SENDTO_SYSCALL
        | LINUX_RECVFROM_SYSCALL
        | LINUX_SENDMSG_SYSCALL
        | LINUX_RECVMSG_SYSCALL
        | LINUX_SENDMMSG_SYSCALL
        | LINUX_RECVMMSG_SYSCALL
        | LINUX_ACCEPT_SYSCALL
        | LINUX_ACCEPT4_SYSCALL => first,
        LINUX_WAITID_SYSCALL if first == LINUX_P_PIDFD => second,
        _ => return,
    };
    // Regular files, the bulk of a compiler's reads, cannot be watched.
    if !linux_descriptor_epollable(descriptor) {
        return;
    }
    let Some(target) = u32::try_from(descriptor)
        .ok()
        .and_then(|descriptor| descriptor.checked_add(1))
    else {
        return;
    };
    let mut counted = None;
    for slot in 0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize {
        if X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst) != target {
            continue;
        }
        let events = X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].load(Ordering::SeqCst);
        if events & LINUX_EPOLL_REPORTED_MASK != 0 {
            if *counted.get_or_insert_with(|| linux_epoll_event_counts(descriptor).is_some()) {
                return;
            }
            X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot]
                .store(events & !LINUX_EPOLL_REPORTED_MASK, Ordering::SeqCst);
        }
    }
}

/// The next event of an epoll instance. A caller that delivers the event
/// `consume`s it, so an edge-triggered watch waits for its next edge; a
/// readiness check leaves the watch armed. EPOLLONESHOT is accepted but not
/// yet honoured (the watch stays armed): some paths that take an event can
/// still drop it, which would leave a one-shot watch disarmed for good.
fn linux_epoll_event(epoll: u64, consume: bool) -> Result<Option<[u8; 12]>, u64> {
    linux_epoll_event_from(epoll, consume, 0).map(|event| event.map(|(_, event)| event))
}

/// Per epoll descriptor, the watch slot the next epoll_wait starts its scan
/// at: ready descriptors are reported in turn when more are ready than
/// `maxevents` (epoll_wait14).
static LINUX_EPOLL_CURSORS: [AtomicU16; LINUX_DESCRIPTOR_TABLE_LIMIT as usize] =
    [const { AtomicU16::new(0) }; LINUX_DESCRIPTOR_TABLE_LIMIT as usize];

/// Collects up to `maximum` ready events of epoll descriptor `epoll` into
/// the user array at `address`, as epoll_wait does: each watch at most
/// once, starting where the last call stopped. The count, EFAULT when
/// nothing could be written, or the instance's error.
fn linux_epoll_collect(epoll: u64, address: u64, maximum: u64) -> Result<u64, u64> {
    let limit = LINUX_DESCRIPTOR_TABLE_LIMIT as usize;
    let cursor = &LINUX_EPOLL_CURSORS[(epoll as usize) % limit];
    let start = usize::from(cursor.load(Ordering::Relaxed)) % limit;
    let mut next = start;
    let mut travelled = 0;
    let mut count = 0_u64;
    while count < maximum && travelled < limit {
        let Some((slot, event)) = linux_epoll_event_from(epoll, true, next)? else {
            break;
        };
        let distance = (slot + limit - next) % limit;
        travelled += distance + 1;
        if travelled > limit {
            break;
        }
        if !copy_to_linux_user(address + count * 12, &event) {
            return if count == 0 {
                Err(LINUX_EFAULT)
            } else {
                Ok(count)
            };
        }
        count += 1;
        next = (slot + 1) % limit;
    }
    cursor.store(next as u16, Ordering::Relaxed);
    Ok(count)
}

/// The first ready event of epoll descriptor `epoll` at or after watch slot
/// `start`, round the table, with its slot. An EPOLLONESHOT watch reports
/// once, then waits for EPOLL_CTL_MOD.
fn linux_epoll_event_from(
    epoll: u64,
    consume: bool,
    start: usize,
) -> Result<Option<(usize, [u8; 12])>, u64> {
    // A descriptor that is open but no epoll instance is EINVAL (epoll_wait03).
    if !linux_epoll_descriptor(epoll) {
        return Err(if linux_descriptor_open(epoll) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        });
    }
    let epoll = linux_epoll_instance(epoll);
    let runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    let limit = LINUX_DESCRIPTOR_TABLE_LIMIT as usize;
    for step in 0..limit {
        let slot = (start + step) % limit;
        let target = if runtime {
            if X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].load(Ordering::SeqCst)
                != (epoll as u32).wrapping_add(1)
            {
                continue;
            }
            let target = X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst);
            if target == 0 {
                continue;
            }
            (target - 1) as usize
        } else {
            slot
        };
        let stored = X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].load(Ordering::SeqCst);
        let requested = stored as u16;
        if requested == 0 {
            continue;
        }
        // Taken before the readiness, so that a wakeup in between is seen
        // again next time rather than lost.
        let counts = if stored & LINUX_EPOLLET != 0 {
            linux_epoll_event_counts(target as u64)
        } else {
            None
        };
        let ready = linux_descriptor_poll_events(target as i32, requested)
            & (LINUX_POLLIN
                | LINUX_POLLPRI
                | LINUX_POLLOUT
                | LINUX_POLLERR
                | LINUX_POLLHUP
                | LINUX_POLLRDHUP);
        if stored & LINUX_EPOLLET != 0 {
            // Edge-triggered: report readiness not reported since it was
            // last seen absent (the record keeps the low five event bits),
            // or since the descriptor was last used
            // (linux_epoll_rearm_for_syscall).
            let reported = (stored & LINUX_EPOLL_REPORTED_MASK) >> LINUX_EPOLL_REPORTED_SHIFT;
            let mut now = (stored & !LINUX_EPOLL_REPORTED_MASK)
                | (u32::from(ready & 0x1f) << LINUX_EPOLL_REPORTED_SHIFT);
            let mut edge = u32::from(ready) & !reported != 0;
            if let Some(counts) = counts {
                // A socket or pipe also has an edge on each wakeup since the
                // watch last looked, ready as it may have stayed: a write to
                // it, room a read made for its writer, a hangup. Linux queues
                // the watch on every such wakeup that concerns its events
                // (ep_poll_callback).
                now |= LINUX_EPOLL_SEEN_VALID;
                let seen = X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_SEEN[slot].load(Ordering::SeqCst);
                let added = stored & LINUX_EPOLL_SEEN_VALID == 0;
                let input =
                    counts as u32 != seen as u32 && requested & LINUX_EPOLL_INPUT_EVENTS != 0;
                let output = counts >> 32 != seen >> 32 && requested & LINUX_POLLOUT != 0;
                edge = if stored & LINUX_EPOLLEXCLUSIVE != 0 && input && !added {
                    // One exclusive watch takes each input wakeup: the
                    // first to look, which in a waiting instance is the
                    // first woken.
                    crate::linux_socket::claim_exclusive_event(
                        linux_socket_slot(target as u64).unwrap_or_default(),
                        counts as u32,
                        consume,
                    )
                } else {
                    edge || added || input || output
                };
                if consume && counts != seen {
                    X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_SEEN[slot]
                        .store(counts, Ordering::SeqCst);
                }
            }
            if consume && now != stored {
                X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(now, Ordering::SeqCst);
            }
            if !edge {
                continue;
            }
        }
        if ready != 0 {
            X86_RUNTIME
                .LINUX_EPOLL_LAST_READY_DESCRIPTOR
                .store(target as u64, Ordering::SeqCst);
            X86_RUNTIME
                .LINUX_EPOLL_LAST_READY_EVENTS
                .store(u64::from(ready), Ordering::SeqCst);
            let mut event = [0_u8; 12];
            event[..4].copy_from_slice(&u32::from(ready).to_ne_bytes());
            event[4..].copy_from_slice(
                &X86_RUNTIME.ELF_PROBE_EPOLL_DATA[slot]
                    .load(Ordering::SeqCst)
                    .to_ne_bytes(),
            );
            if consume && stored & LINUX_EPOLLONESHOT != 0 {
                // Disarmed: the flags stay, the events are gone.
                X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(stored & !0xffff, Ordering::SeqCst);
            }
            return Ok(Some((slot, event)));
        }
    }
    Ok(None)
}

/// The epoll instances epoll instance `epoll` watches directly.
fn linux_epoll_watched_instances(epoll: u64) -> impl Iterator<Item = u64> {
    (0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize).filter_map(move |slot| {
        if X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].load(Ordering::SeqCst)
            != (epoll as u32).wrapping_add(1)
        {
            return None;
        }
        let target = X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst);
        let target = u64::from(target.checked_sub(1)?);
        linux_epoll_descriptor(target).then(|| linux_epoll_instance(target))
    })
}

/// Whether epoll instance `from` reaches `to` through the instances it
/// watches (bounded, as Linux bounds its walk).
fn linux_epoll_reaches(from: u64, to: u64, depth: usize) -> bool {
    from == to
        || depth < 8
            && linux_epoll_watched_instances(from)
                .any(|next| linux_epoll_reaches(next, to, depth + 1))
}

/// How many epoll levels lie below instance `epoll` (0: it watches none).
fn linux_epoll_depth_below(epoll: u64, depth: usize) -> usize {
    if depth >= 8 {
        return depth;
    }
    linux_epoll_watched_instances(epoll)
        .map(|next| 1 + linux_epoll_depth_below(next, depth + 1))
        .max()
        .unwrap_or(0)
}

/// How many epoll instances watch instance `epoll`, level over level.
fn linux_epoll_depth_above(epoll: u64, depth: usize) -> usize {
    if depth >= 8 {
        return depth;
    }
    (0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize)
        .filter_map(|slot| {
            let target = X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst);
            let owner = X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].load(Ordering::SeqCst);
            let target = u64::from(target.checked_sub(1)?);
            let owner = u64::from(owner.checked_sub(1)?);
            (linux_epoll_descriptor(target) && linux_epoll_instance(target) == epoll)
                .then_some(owner)
        })
        .map(|owner| 1 + linux_epoll_depth_above(owner, depth + 1))
        .max()
        .unwrap_or(0)
}

/// The descriptor that owns an epoll instance's watches: the descriptor
/// itself, unless it was duplicated from another epoll descriptor.
fn linux_epoll_instance(descriptor: u64) -> u64 {
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
        return descriptor;
    }
    match linux_fd_cell::<u32>(descriptor, LinuxFdField::EpollAlias).load(Ordering::SeqCst) {
        0 => descriptor,
        alias => u64::from(alias - 1),
    }
}

/// Makes `target` another descriptor for the epoll instance `source` refers
/// to, as dup(2) does; tokio duplicates its epoll descriptor this way.
fn linux_epoll_dup(source: u64, target: u64) -> u64 {
    if source == target {
        return target;
    }
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || target < LINUX_AUX_DESCRIPTOR_FIRST
        || target >= linux_nofile_soft_limit()
    {
        return LINUX_EBADF;
    }
    if linux_descriptor_open(target) && linux_descriptor_close(target) != 0 {
        return LINUX_EBADF;
    }
    let instance = linux_epoll_instance(source);
    linux_fd_cell::<u8>(target, LinuxFdField::Epoll).store(1, Ordering::SeqCst);
    linux_fd_cell::<u32>(target, LinuxFdField::EpollAlias)
        .store(instance as u32 + 1, Ordering::SeqCst);
    if !linux_epoll_descriptor(target) {
        return LINUX_ENOMEM;
    }
    set_linux_descriptor_close_on_exec(target, false);
    target
}

/// When the descriptor owning an epoll instance closes while duplicates
/// remain, moves the instance's watches to the first duplicate and points
/// the others at it. Returns false if there was no duplicate.
fn linux_epoll_hand_over(owner: u64) -> bool {
    let owner_value = owner as u32 + 1;
    let alias = |descriptor: u64| linux_fd_cell::<u32>(descriptor, LinuxFdField::EpollAlias);
    let Some(heir) = linux_descriptor_numbers()
        .filter(|descriptor| *descriptor >= LINUX_AUX_DESCRIPTOR_FIRST)
        .find(|descriptor| alias(*descriptor).load(Ordering::SeqCst) == owner_value)
    else {
        return false;
    };
    let heir_value = heir as u32 + 1;
    alias(heir).store(0, Ordering::SeqCst);
    for descriptor in linux_descriptor_numbers().filter(|descriptor| {
        *descriptor >= LINUX_AUX_DESCRIPTOR_FIRST
            && alias(*descriptor).load(Ordering::SeqCst) == owner_value
    }) {
        alias(descriptor).store(heir_value, Ordering::SeqCst);
    }
    for watch in &X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL {
        let _ = watch.compare_exchange(owner_value, heir_value, Ordering::SeqCst, Ordering::SeqCst);
    }
    true
}

fn linux_epoll_forget_descriptor(descriptor: u64) {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        for slot in 0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize {
            if X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst)
                == (descriptor as u32).wrapping_add(1)
            {
                X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].store(0, Ordering::SeqCst);
                X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].store(0, Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(0, Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_EPOLL_DATA[slot].store(0, Ordering::SeqCst);
            }
        }
    } else if descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT {
        X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[descriptor as usize].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EPOLL_DATA[descriptor as usize].store(0, Ordering::SeqCst);
    }
}

fn linux_epoll_forget_owner(descriptor: u64) {
    for slot in 0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize {
        if X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].load(Ordering::SeqCst)
            == (descriptor as u32).wrapping_add(1)
        {
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].store(0, Ordering::SeqCst);
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_EPOLL_DATA[slot].store(0, Ordering::SeqCst);
        }
    }
}

fn complete_linux_epoll_wait(slot: usize, timed_out: bool) -> bool {
    let kind = if slot < LINUX_THREAD_LIMIT {
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
    } else {
        LINUX_THREAD_WAIT_NONE
    };
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || !matches!(
            kind,
            LINUX_THREAD_WAIT_EPOLL | LINUX_THREAD_WAIT_EPOLL_PWAIT
        )
    {
        return false;
    }
    let output = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let (epoll, maximum) = (output & u64::from(u32::MAX), (output >> 32).max(1));
    if matches!(linux_epoll_event(epoll, false), Ok(None)) && !timed_out {
        return false;
    }
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = linux_epoll_collect(epoll, address, maximum).unwrap_or_else(|error| error);
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    if kind == LINUX_THREAD_WAIT_EPOLL_PWAIT {
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(
            X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].swap(0, Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    match (kind, timed_out) {
        (LINUX_THREAD_WAIT_EPOLL, true) => {
            X86_RUNTIME
                .LINUX_EPOLL_WAIT_TIMEOUT_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_EPOLL, false) => {
            X86_RUNTIME
                .LINUX_EPOLL_WAIT_WAKE_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_EPOLL_PWAIT, true) => {
            X86_RUNTIME
                .LINUX_EPOLL_PWAIT_TIMEOUT_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_EPOLL_PWAIT, false) => {
            X86_RUNTIME
                .LINUX_EPOLL_PWAIT_WAKE_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        _ => {}
    }
    true
}

fn wake_linux_epoll_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_epoll_wait(slot, false));
    }
    woken
}

fn wake_linux_descriptor_waits() -> u32 {
    if !X86_RUNTIME
        .LINUX_DESCRIPTOR_WAITS_ACTIVE
        .load(Ordering::Acquire)
    {
        return 0;
    }
    // Completing a wait copies its result into the waiting thread's memory:
    // the live thread table's process, whose address space is not always
    // the active one (a fork transaction wakes the parent's waits once its
    // child has gone, and the child's exit is what made them ready).
    match linux_process::live_process_root(current_linux_process_pid()) {
        Some(root) if root.address() != address_space::current_root_address() => {
            address_space::with_live_linux_process_root(root, wake_linux_descriptor_waits_here)
                .unwrap_or(0)
        }
        _ => wake_linux_descriptor_waits_here(),
    }
}

/// `wake_linux_descriptor_waits` in the active address space.
fn wake_linux_descriptor_waits_here() -> u32 {
    let woken = wake_linux_poll_waits()
        + wake_linux_select_waits()
        + wake_linux_epoll_waits()
        + wake_linux_eventfd_read_waits()
        + wake_linux_eventfd_write_waits()
        + wake_linux_pipe_read_waits()
        + wake_linux_pipe_write_waits()
        + wake_linux_timerfd_read_waits();
    let active = (0..LINUX_THREAD_LIMIT).any(|slot| {
        X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::Relaxed) == LINUX_THREAD_BLOCKED
            && matches!(
                X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::Relaxed),
                LINUX_THREAD_WAIT_POLL
                    | LINUX_THREAD_WAIT_PPOLL
                    | LINUX_THREAD_WAIT_EPOLL
                    | LINUX_THREAD_WAIT_EPOLL_PWAIT
                    | LINUX_THREAD_WAIT_SELECT
                    | LINUX_THREAD_WAIT_PSELECT
                    | LINUX_THREAD_WAIT_EVENTFD_READ
                    | LINUX_THREAD_WAIT_EVENTFD_WRITE
                    | LINUX_THREAD_WAIT_PIPE_READ
                    | LINUX_THREAD_WAIT_PIPE_WRITE
                    | LINUX_THREAD_WAIT_TIMERFD_READ
            )
    });
    X86_RUNTIME
        .LINUX_DESCRIPTOR_WAITS_ACTIVE
        .store(active, Ordering::Release);
    woken
}

#[derive(Clone, Copy)]
struct LinuxEpollWaitInput {
    epoll: u64,
    address: u64,
    maximum: u64,
}

#[derive(Clone, Copy)]
struct LinuxSignalMaskInput {
    address: u64,
    size: u64,
}

fn linux_epoll_wait_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    input: LinuxEpollWaitInput,
    timeout: u64,
) -> u64 {
    let timeout = timeout as u32 as i32;
    let duration = if timeout < 0 {
        None
    } else {
        let Some(duration) = (timeout as u64).checked_mul(1_000_000) else {
            return LINUX_EINVAL;
        };
        Some(duration)
    };
    linux_epoll_wait_duration_live_return(
        output,
        caller,
        input,
        duration,
        LINUX_EPOLL_WAIT_SYSCALL,
        None,
    )
}

/// Waits in epoll_wait, epoll_pwait or epoll_pwait2 (system call `number`,
/// which a yield restarts). `temporary_signal_mask` is the mask an
/// epoll_pwait call gave; without one the call waits as epoll_wait does.
fn linux_epoll_wait_duration_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    input: LinuxEpollWaitInput,
    duration: Option<u64>,
    number: u64,
    temporary_signal_mask: Option<u64>,
) -> u64 {
    let wait_kind = if temporary_signal_mask.is_some() {
        LINUX_THREAD_WAIT_EPOLL_PWAIT
    } else {
        LINUX_THREAD_WAIT_EPOLL
    };
    let maximum = input.maximum as u32 as i32;
    if maximum <= 0 {
        return LINUX_EINVAL;
    }
    let input = LinuxEpollWaitInput {
        epoll: u64::from(input.epoll as u32),
        maximum: maximum as u64,
        ..input
    };
    match linux_epoll_collect(input.epoll, input.address, input.maximum) {
        Ok(0) if duration == Some(0) => return 0,
        Ok(0) => {}
        Ok(count) => return count,
        Err(error) => return error,
    }
    if !linux_writable_user_range_contains(input.address, 12) {
        return LINUX_EFAULT;
    }
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    // The deadline of a wait that began below, if it goes on as a thread
    // wait because a sibling thread became ready meanwhile.
    let mut continued_deadline = None;
    let target = 'target: {
        if let Some(target) = ready_linux_thread_handle() {
            break 'target target;
        }
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            // Only init runs other processes from its own waits, as in
            // run_other_linux_processes. Any other process yields to whatever
            // runs it: a child running inside its parent's fork must not run
            // that parent nested in its own system call, where the parent's
            // exit would later return into the child's freed address space.
            if X86_RUNTIME
                .LINUX_PROCESS_SCHEDULER_NESTING
                .load(Ordering::SeqCst)
                != 0
                || current_linux_process_pid() != 1
            {
                // epoll_wait waits as poll does: other processes run, the
                // call restarts with its deadline, and a signal interrupts
                // it (EINTR). epoll_pwait waits under its temporary mask as
                // ppoll does: a signal it blocks stays pending, one it
                // unblocks ends the wait (epoll_pwait01), and a handler's
                // frame restores the caller's mask.
                let deadline = take_linux_restart_deadline(caller.rip).or_else(|| {
                    duration.and_then(|duration| {
                        linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
                    })
                });
                let slot = usize::from(current.slot);
                let prior = temporary_signal_mask.map(|mask| {
                    begin_linux_lone_masked_wait(slot, LINUX_THREAD_WAIT_SIGSUSPEND, mask)
                });
                // Resumed after a park with no signal, the call looks at
                // the instance and its deadline again. Once a sibling thread
                // is ready, this thread waits as a thread wait while it runs.
                let ended = loop {
                    if deadline.is_some_and(|deadline| {
                        linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline)
                    }) {
                        break Ok(0);
                    }
                    let turn = linux_timed_wait_run_others(output, caller, number, deadline);
                    if let LinuxWaitTurn::Done(result) = turn {
                        break Ok(result);
                    }
                    if let Some(target) = ready_linux_thread_handle() {
                        break Err((target, deadline));
                    }
                    match linux_epoll_collect(input.epoll, input.address, input.maximum) {
                        Ok(0) => {}
                        Ok(count) => break Ok(count),
                        Err(error) => break Ok(error),
                    }
                    // Nothing else can run: halt until an interrupt (the
                    // deadline's tick, or a waker on another CPU).
                    if let LinuxWaitTurn::Idle = turn {
                        if let Some((deadline, now)) = deadline.zip(linux_elapsed_nanoseconds()) {
                            timer::request_linux_tick_within(deadline.saturating_sub(now));
                        }
                        linux_wait_for_interrupt();
                    }
                };
                if let Some(prior) = prior {
                    end_linux_lone_masked_wait(slot, prior);
                }
                match ended {
                    Ok(result) => return result,
                    Err((target, deadline)) => {
                        continued_deadline = Some(deadline.unwrap_or(0));
                        break 'target target;
                    }
                }
            }
            let parent_pid = current_linux_process_pid();
            if refresh_linux_process_registry_for_wait(caller)
                && run_next_scheduled_linux_process(parent_pid)
            {
                if X86_RUNTIME.LINUX_RUNTIME_SUSPENDED.load(Ordering::Acquire) {
                    return LINUX_RETURN_TO_KERNEL;
                }
                let result = linux_epoll_collect(input.epoll, input.address, input.maximum)
                    .unwrap_or_else(|error| error);
                if !restore_linux_process_live_return(output, parent_pid) {
                    return LINUX_EINVAL;
                }
                // An event already taken from the instance is the call's
                // result even if a signal arrived meanwhile; Linux returns it
                // and runs the handler on the way out. Only an empty wait is
                // interrupted (EINTR).
                let mut interrupted = caller;
                interrupted.rax = if result == 0 { LINUX_EINTR } else { result };
                let delivered =
                    linux_deliver_pending_signal(output, interrupted, (caller.rip, caller.rflags));
                return if delivered != 0 {
                    delivered
                } else if X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
                    0
                } else {
                    result
                };
            }
        }
        // The static verification executor has no peer thread to advance a
        // blocking wait. Report that harness limitation deterministically;
        // runtime domains continue through the scheduler-backed path above.
        return if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            0
        } else {
            LINUX_ENOSYS
        };
    };
    let Some(tls) = linux_thread_context(current) else {
        return LINUX_ESRCH;
    };
    let deadline = if let Some(deadline) = continued_deadline {
        deadline
    } else if let Some(duration) = duration {
        let Some(deadline) = linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
        else {
            return LINUX_EINVAL;
        };
        deadline
    } else {
        0
    };
    let slot = usize::from(current.slot);
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(
            wait_kind,
            input.address,
            input.epoll | input.maximum.min(u64::from(u32::MAX)) << 32,
            deadline,
        )
    {
        return LINUX_EINVAL;
    }
    let prior_signal_mask = X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst);
    if let Some(mask) = temporary_signal_mask {
        X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot]
            .store(prior_signal_mask, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(mask, Ordering::SeqCst);
    }
    let mut target_registers = LinuxSyscallFrame::ZERO;
    let mut target_rip = 0;
    let mut target_rsp = 0;
    let mut target_rflags = 0;
    let mut target_rax = 0;
    if !install_linux_thread_return(
        target,
        &mut target_registers,
        &mut target_rip,
        &mut target_rsp,
        &mut target_rflags,
        &mut target_rax,
    ) {
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_RUNNING, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_CURRENT_THREAD_SLOT
            .store(current.slot, Ordering::SeqCst);
        let _ = install_linux_tls_context(tls);
        if temporary_signal_mask.is_some() {
            store_current_linux_signal_mask(prior_signal_mask);
        }
        return LINUX_EINVAL;
    }
    let selected = LinuxUserContext {
        registers: target_registers,
        rip: target_rip,
        rsp: target_rsp,
        rflags: target_rflags,
        rax: target_rax,
        fs_base: active_fs_base(),
    };
    if !write_linux_thread_live_return(output, target, selected) {
        return LINUX_EINVAL;
    }
    X86_RUNTIME
        .LINUX_LIVE_RETURN_VALIDATED
        .store(true, Ordering::SeqCst);
    if wait_kind == LINUX_THREAD_WAIT_EPOLL_PWAIT {
        X86_RUNTIME
            .LINUX_EPOLL_PWAIT_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else {
        X86_RUNTIME
            .LINUX_EPOLL_WAIT_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
    }
    LINUX_RETURN_FROM_IRET
}

fn linux_temporary_signal_mask(input: LinuxSignalMaskInput) -> Result<u64, u64> {
    if input.address == 0 {
        return Ok(X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst));
    }
    if input.size != LINUX_SIGNAL_SET_SIZE {
        return Err(LINUX_EINVAL);
    }
    let mut signal_mask = [0_u8; LINUX_SIGNAL_SET_SIZE as usize];
    if !copy_from_linux_user(input.address, &mut signal_mask) {
        return Err(LINUX_EFAULT);
    }
    Ok(u64::from_ne_bytes(signal_mask) & !LINUX_UNBLOCKABLE_SIGNALS)
}

fn linux_epoll_pwait_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    input: LinuxEpollWaitInput,
    timeout: u64,
    signal_mask: LinuxSignalMaskInput,
) -> u64 {
    let signal_mask = match linux_epoll_signal_mask(signal_mask) {
        Ok(mask) => mask,
        Err(error) => return error,
    };
    let timeout = timeout as u32 as i32;
    let duration = if timeout < 0 {
        None
    } else {
        let Some(duration) = (timeout as u64).checked_mul(1_000_000) else {
            return LINUX_EINVAL;
        };
        Some(duration)
    };
    linux_epoll_wait_duration_live_return(
        output,
        caller,
        input,
        duration,
        LINUX_EPOLL_PWAIT_SYSCALL,
        signal_mask,
    )
}

/// The temporary mask an epoll_pwait or epoll_pwait2 call gives, or `None`
/// for a null mask (musl's epoll_wait passes one).
fn linux_epoll_signal_mask(input: LinuxSignalMaskInput) -> Result<Option<u64>, u64> {
    if input.address == 0 {
        return Ok(None);
    }
    linux_temporary_signal_mask(input).map(Some)
}

fn linux_epoll_pwait2_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    input: LinuxEpollWaitInput,
    timeout_address: u64,
    signal_mask: LinuxSignalMaskInput,
) -> u64 {
    let duration = if timeout_address == 0 {
        None
    } else {
        let mut timeout = [0_u8; 16];
        if !copy_from_linux_user(timeout_address, &mut timeout) {
            return LINUX_EFAULT;
        }
        let seconds = i64::from_ne_bytes(timeout[..8].try_into().unwrap());
        let nanoseconds = i64::from_ne_bytes(timeout[8..].try_into().unwrap());
        if seconds < 0 || !(0..NANOSECONDS_PER_SECOND as i64).contains(&nanoseconds) {
            return LINUX_EINVAL;
        }
        let Some(duration) = (seconds as u64)
            .checked_mul(NANOSECONDS_PER_SECOND)
            .and_then(|seconds| seconds.checked_add(nanoseconds as u64))
        else {
            return LINUX_EINVAL;
        };
        Some(duration)
    };
    let signal_mask = match linux_epoll_signal_mask(signal_mask) {
        Ok(mask) => mask,
        Err(error) => return error,
    };
    linux_epoll_wait_duration_live_return(
        output,
        caller,
        input,
        duration,
        LINUX_EPOLL_PWAIT2_SYSCALL,
        signal_mask,
    )
}

fn linux_epoll_descriptor(descriptor: u64) -> bool {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return descriptor >= LINUX_AUX_DESCRIPTOR_FIRST
            && linux_fd_cell::<u8>(descriptor, LinuxFdField::Epoll).load(Ordering::SeqCst) != 0;
    }
    u64::from(
        X86_RUNTIME
            .ELF_PROBE_EPOLL_DESCRIPTOR
            .load(Ordering::SeqCst),
    )
    .checked_sub(1)
        == Some(descriptor)
}

fn linux_eventfd_descriptor(descriptor: u64) -> bool {
    linux_eventfd_state(descriptor).is_some()
}

struct LinuxTimerfdState {
    clock: &'static dyn LinuxFileCell<u8>,
    flags: &'static dyn LinuxFileCell<u32>,
    interval: &'static dyn LinuxFileCell<u64>,
    deadline: &'static dyn LinuxFileCell<u64>,
}

fn linux_timerfd_state(descriptor: u64) -> Option<LinuxTimerfdState> {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let file = crate::linux_event_files::timerfd(linux_timerfd_file(descriptor)?)?;
        return Some(LinuxTimerfdState {
            clock: &file.clock,
            flags: &file.flags,
            interval: &file.interval,
            deadline: &file.deadline,
        });
    }
    (descriptor >= 2
        && u64::from(
            X86_RUNTIME
                .ELF_PROBE_TIMERFD_DESCRIPTOR
                .load(Ordering::SeqCst),
        ) == descriptor)
        .then_some(LinuxTimerfdState {
            clock: &X86_RUNTIME.ELF_PROBE_TIMERFD_CLOCK,
            flags: &X86_RUNTIME.ELF_PROBE_TIMERFD_FLAGS,
            interval: &X86_RUNTIME.ELF_PROBE_TIMERFD_INTERVAL,
            deadline: &X86_RUNTIME.ELF_PROBE_TIMERFD_DEADLINE,
        })
}

fn linux_timerfd_descriptor(descriptor: u64) -> bool {
    linux_timerfd_state(descriptor).is_some()
}

fn linux_pipe_read_descriptor(descriptor: u64) -> bool {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return linux_socket_pipe_descriptor(descriptor, LINUX_DESCRIPTOR_INPUT);
    }
    descriptor >= 2
        && u64::from(
            X86_RUNTIME
                .ELF_PROBE_PIPE_READ_DESCRIPTOR
                .load(Ordering::SeqCst),
        ) == descriptor
}

fn linux_pipe_write_descriptor(descriptor: u64) -> bool {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return linux_socket_pipe_descriptor(descriptor, LINUX_DESCRIPTOR_OUTPUT);
    }
    descriptor >= 2
        && u64::from(
            X86_RUNTIME
                .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
                .load(Ordering::SeqCst),
        ) == descriptor
}

fn linux_pipe_descriptor(descriptor: u64) -> bool {
    linux_pipe_read_descriptor(descriptor) || linux_pipe_write_descriptor(descriptor)
}

fn linux_pidfd_descriptor(descriptor: u64) -> bool {
    linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_PIDFD
}

fn linux_pidfd_process(descriptor: u64) -> Option<u32> {
    if !linux_pidfd_descriptor(descriptor) {
        return None;
    }
    let identity = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
    let pid = identity as u32;
    let generation = (identity >> 32) as u32;
    (pid != 0 && linux_process::live_process_generation(pid) == Some(generation)).then_some(pid)
}

/// Process `pid`'s slot generation and PID namespace, read before a wait
/// reaps it, for `linux_pidfd_record_exit`.
fn linux_pidfd_identity(pid: u32) -> Option<(u32, u32)> {
    let generation = linux_process::live_process_generation(pid)?;
    let namespace = linux_process::live_process_namespaces(pid).map_or(0, |set| set.pid);
    Some((generation, namespace))
}

/// Keeps reaped process `pid`'s wait status for its pidfds
/// (PIDFD_INFO_EXIT); `identity` is from `linux_pidfd_identity`.
fn linux_pidfd_record_exit(pid: u32, identity: Option<(u32, u32)>, status: u32) {
    if let Some((generation, namespace)) = identity {
        crate::linux_pidfs::reaped(
            linux_execution_instance(),
            pid,
            generation,
            namespace,
            status,
        );
    }
}

/// ioctl on a pidfd: PIDFD_GET_INFO (Linux 6.15's: the process's ids and
/// credentials while it is unreaped, its wait status once reaped when
/// PIDFD_INFO_EXIT asks); other requests are ENOTTY.
fn linux_pidfd_ioctl(descriptor: u64, request: u64, argument: u64) -> u64 {
    const PIDFS_IOCTL_MAGIC: u64 = 0xff;
    const PIDFD_GET_INFO_NUMBER: u64 = 11;
    const PIDFD_INFO_PID: u64 = 1 << 0;
    const PIDFD_INFO_CREDS: u64 = 1 << 1;
    const PIDFD_INFO_EXIT: u64 = 1 << 3;
    /// struct pidfd_info's first version (up to the spare fields), the
    /// least a caller may pass, and its size now.
    const PIDFD_INFO_SIZE_VER0: usize = 64;
    const PIDFD_INFO_SIZE: usize = 72;
    let request = u64::from(request as u32);
    if (request >> 8) & 0xff != PIDFS_IOCTL_MAGIC || request & 0xff != PIDFD_GET_INFO_NUMBER {
        return LINUX_ENOTTY;
    }
    let size = ((request >> 16) & 0x3fff) as usize;
    if argument == 0 || size < PIDFD_INFO_SIZE_VER0 {
        return LINUX_EINVAL;
    }
    let mut mask = [0_u8; 8];
    if !copy_from_linux_user(argument, &mut mask) {
        return LINUX_EFAULT;
    }
    let mask = u64::from_ne_bytes(mask);
    let identity = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
    let (pid, generation) = (identity as u32, (identity >> 32) as u32);
    let caller = current_linux_process_pid();
    let observer = current_linux_namespaces().pid;
    let instance = linux_execution_instance();
    let live = linux_process::live_process_generation(pid) == Some(generation);
    let exit = (!live)
        .then(|| crate::linux_pidfs::exit(instance, pid, generation))
        .flatten();
    // Only processes in the caller's PID namespace or below it.
    let namespace = if live {
        linux_process::live_process_namespaces(pid).map_or(0, |set| set.pid)
    } else {
        exit.map_or(0, |exit| exit.namespace)
    };
    if !linux_namespace::pid_within(instance, observer, namespace) {
        return LINUX_ESRCH;
    }
    let mut info = [0_u8; PIDFD_INFO_SIZE];
    let mut reported = 0;
    if !live {
        // A reaped process tells only how it ended, and only when asked.
        let Some(exit) = exit.filter(|_| mask & PIDFD_INFO_EXIT != 0) else {
            return LINUX_ESRCH;
        };
        reported |= PIDFD_INFO_EXIT;
        info[60..64].copy_from_slice(&exit.status.to_ne_bytes());
    } else {
        let Some(credentials) = linux_process::live_process_credentials(pid) else {
            return LINUX_ESRCH;
        };
        let parent = linux_process::live_process_parent_pid(pid).unwrap_or(0);
        let seen = linux_pid_seen_by(caller, pid);
        if seen == 0 {
            return LINUX_ESRCH;
        }
        let parent = if parent == 0 {
            0
        } else {
            linux_pid_seen_by(caller, parent)
        };
        let words = [
            seen,
            seen,
            parent,
            credentials.user.real,
            credentials.group.real,
            credentials.user.effective,
            credentials.group.effective,
            credentials.user.saved,
            credentials.group.saved,
            credentials.user.filesystem,
            credentials.group.filesystem,
        ];
        for (index, word) in words.iter().enumerate() {
            info[16 + index * 4..20 + index * 4].copy_from_slice(&word.to_ne_bytes());
        }
        reported |= PIDFD_INFO_PID | PIDFD_INFO_CREDS;
    }
    info[..8].copy_from_slice(&reported.to_ne_bytes());
    // As copy_struct_to_user: a shorter struct gets its part, a longer
    // one zeros past ours.
    if !copy_to_linux_user(argument, &info[..size.min(PIDFD_INFO_SIZE)]) {
        return LINUX_EFAULT;
    }
    let zeros = [0_u8; 256];
    let mut offset = PIDFD_INFO_SIZE;
    while offset < size {
        let length = (size - offset).min(zeros.len());
        if !copy_to_linux_user(argument + offset as u64, &zeros[..length]) {
            return LINUX_EFAULT;
        }
        offset += length;
    }
    0
}

fn linux_signalfd_descriptor(descriptor: u64) -> bool {
    linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_SIGNALFD
}

fn linux_signalfd(descriptor: u64, mask_address: u64, mask_size: u64, flags: u64) -> u64 {
    const SFD_NONBLOCK: u64 = 0x800;
    const SFD_CLOEXEC: u64 = 0x8_0000;
    let descriptor = u64::from(descriptor as u32);
    let flags = u64::from(flags as u32);
    if mask_size != LINUX_SIGNAL_SET_SIZE || flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    let mut bytes = [0_u8; LINUX_SIGNAL_SET_SIZE as usize];
    if !copy_from_linux_user(mask_address, &mut bytes) {
        return LINUX_EFAULT;
    }
    let mask = u64::from_ne_bytes(bytes) & !LINUX_UNBLOCKABLE_SIGNALS;
    let descriptor = if descriptor == u64::from(u32::MAX) {
        match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
            Ok(descriptor) => descriptor,
            Err(error) => return error,
        }
    } else if linux_signalfd_descriptor(descriptor) {
        // An existing signalfd takes the new mask only; its flags stay.
        linux_legacy_descriptor_offset(descriptor).store(mask, Ordering::SeqCst);
        return descriptor;
    } else {
        // An open descriptor that is no signalfd is EINVAL, as in Linux.
        return if linux_descriptor_open(descriptor) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device)
        .store(LINUX_DEVICE_SIGNALFD, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(flags as u32, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(mask, Ordering::SeqCst);
    set_linux_descriptor_close_on_exec(descriptor, flags & SFD_CLOEXEC != 0);
    descriptor
}

fn linux_signalfd_read(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    if !linux_signalfd_descriptor(descriptor) {
        return None;
    }
    if count < 128 {
        return Some(LINUX_EINVAL);
    }
    let mask = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
    let pending = X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst) & mask;
    let dynamic = linux_peek_dynamic_signal(mask);
    if pending == 0 && dynamic.is_none() {
        return Some(LINUX_EAGAIN);
    }
    let legacy_signal = (pending != 0).then(|| u64::from(pending.trailing_zeros()) + 1);
    let use_dynamic = dynamic.is_some_and(|(scope, queued)| {
        scope == crate::linux_signal::Scope::Thread
            || legacy_signal.is_none_or(|legacy| u64::from(queued.signal) <= legacy)
    });
    let dynamic = use_dynamic.then_some(dynamic).flatten();
    let signal = dynamic.map_or_else(
        || legacy_signal.unwrap_or(0),
        |(_, queued)| u64::from(queued.signal),
    );
    let index = signal as usize - 1;
    let code = dynamic.map_or_else(
        || X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].load(Ordering::SeqCst) as i32,
        |(_, queued)| queued.code,
    );
    let value = dynamic.map_or_else(
        || X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].load(Ordering::SeqCst),
        |(_, queued)| queued.value,
    );
    let (sender_pid, sender_uid) = dynamic.map_or_else(linux_signal_sender, |(_, queued)| {
        (queued.sender_pid, queued.sender_uid)
    });
    let mut information = [0_u8; 128];
    information[..4].copy_from_slice(&(signal as u32).to_ne_bytes());
    information[8..12].copy_from_slice(&code.to_ne_bytes());
    information[12..16].copy_from_slice(&sender_pid.to_ne_bytes());
    information[16..20].copy_from_slice(&sender_uid.to_ne_bytes());
    if signal == LINUX_SIGCHLD {
        information[40..44].copy_from_slice(&(value as u32).to_ne_bytes());
    } else {
        information[44..48].copy_from_slice(&(value as u32).to_ne_bytes());
        information[48..56].copy_from_slice(&value.to_ne_bytes());
    }
    if !copy_to_linux_user(address, &information) {
        return Some(LINUX_EFAULT);
    }
    let signal_bit = 1_u64 << (signal - 1);
    if let Some((scope, _)) = dynamic {
        let _ = linux_dequeue_dynamic_signal(scope, signal_bit);
    } else {
        X86_RUNTIME
            .ELF_PROBE_PENDING_SIGNALS
            .fetch_and(!signal_bit, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].store(0, Ordering::SeqCst);
    }
    Some(128)
}

fn linux_pidfd_open(process: u64, flags: u64) -> u64 {
    const PIDFD_NONBLOCK: u64 = 0x800;
    let process = process as i32;
    let flags = u64::from(flags as u32);
    if flags & !PIDFD_NONBLOCK != 0 {
        return LINUX_EINVAL;
    }
    if process <= 0 {
        return LINUX_EINVAL;
    }
    let process = process as u32;
    let Some(generation) = linux_process::live_process_generation(process) else {
        return LINUX_ESRCH;
    };
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device)
        .store(LINUX_DEVICE_PIDFD, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(flags as u32, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(
        u64::from(process) | (u64::from(generation) << 32),
        Ordering::SeqCst,
    );
    set_linux_descriptor_close_on_exec(descriptor, true);
    descriptor
}

fn linux_pidfd_getfd(pid_descriptor: u64, target: u64, flags: u64) -> u64 {
    let target = u64::from(target as u32);
    let flags = u64::from(flags as u32);
    if flags != 0 {
        return LINUX_EINVAL;
    }
    if !linux_pidfd_descriptor(pid_descriptor) {
        return LINUX_EBADF;
    }
    let Some(process) = linux_pidfd_process(pid_descriptor) else {
        return LINUX_ESRCH;
    };
    if process == current_linux_process_pid() {
        return linux_console_dup(target);
    }
    if linux_process::live_process_status(process).is_none_or(|status| !status.state.is_running()) {
        return LINUX_ESRCH;
    }
    if !linux_ptrace_access_permitted(process) {
        return LINUX_EPERM;
    }
    let Some((device, oci, socket, socket_flags, tmp_generation, offset, open_file_id)) =
        linux_process_runtime_state(process)
            .filter(|state| state.valid)
            .and_then(|state| linux_saved_descriptor(&state.descriptors, target))
    else {
        return LINUX_EBADF;
    };
    if socket != 0 || device & (LINUX_FILE_MASK | LINUX_DEVICE_CONSOLE) == 0 {
        return LINUX_EOPNOTSUPP;
    }
    let descriptor = match linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) {
        Ok(descriptor) => descriptor,
        Err(error) => return error,
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(device, Ordering::SeqCst);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Rootfs).store(oci, Ordering::SeqCst);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Socket).store(0, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(socket_flags, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Generation)
        .store(tmp_generation, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(offset, Ordering::SeqCst);
    if let Some(cell) = linux_descriptor_open_file_id_cell(descriptor) {
        cell.store(open_file_id, Ordering::SeqCst);
    }
    set_linux_descriptor_close_on_exec(descriptor, true);
    descriptor
}

fn linux_saved_descriptor(
    state: &LinuxDescriptorRuntimeState,
    descriptor: u64,
) -> Option<(u16, u16, crate::linux_socket::SlotId, u32, u32, u64, u64)> {
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        let entry = crate::linux_fd_table::get(state.overflow, descriptor)
            .filter(|entry| !entry.vacant() && entry.open_file_id != 0)?;
        return Some((
            entry.state,
            entry.rootfs,
            entry.socket,
            entry.socket_flags,
            entry.generation,
            entry.offset,
            entry.open_file_id,
        ));
    }
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
        let index = descriptor as usize;
        let id = state.stdio_open_file_ids[index];
        let explicit_device = state.stdio_devices[index];
        let console_access = if descriptor < 2 {
            u16::from((state.console >> (descriptor * 2)) & 0b11)
        } else if state.stderr_open {
            LINUX_DESCRIPTOR_OUTPUT
        } else {
            0
        };
        let device = if explicit_device != 0 {
            explicit_device
        } else if console_access != 0 {
            LINUX_DEVICE_CONSOLE | console_access
        } else {
            0
        };
        return (id != 0).then_some((
            device,
            state.stdio_rootfs[index],
            state.stdio_sockets[index],
            state.stdio_socket_flags[index],
            state.stdio_tmp_generations[index],
            state.stdio_offsets[index],
            id,
        ));
    }
    let index = (descriptor - LINUX_AUX_DESCRIPTOR_FIRST) as usize;
    let id = state.open_file_ids[index];
    (id != 0).then_some((
        state.devices[index],
        state.rootfs[index],
        state.sockets[index],
        state.socket_flags[index],
        state.tmp_generations[index],
        state.offsets[index],
        id,
    ))
}

#[allow(clippy::too_many_arguments)]
fn linux_pidfd_send_signal(
    descriptor: u64,
    signal: u64,
    information: u64,
    flags: u64,
    output: *mut LinuxSyscallFrame,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> u64 {
    const SI_TKILL: i32 = -6;
    let signal = u64::from(signal as u32);
    let flags = u64::from(flags as u32);
    if flags != 0 {
        return LINUX_EINVAL;
    }
    // A pidfd, or a process's /proc directory.
    let process = if linux_pidfd_descriptor(descriptor) {
        linux_pidfd_process(descriptor)
    } else if matches!(
        linux_device_descriptor(descriptor) & !3,
        LINUX_PROC_PID1_DIRECTORY | LINUX_PROC_PID2_DIRECTORY
    ) {
        linux_proc_directory_descriptor_process(descriptor)
    } else {
        return LINUX_EBADF;
    };
    let Some(process) = process else {
        return LINUX_ESRCH;
    };
    let generated = if information == 0 {
        (signal, LINUX_SI_USER, None)
    } else {
        let mut bytes = [0_u8; size_of::<LinuxSignalInformation>()];
        if !copy_from_linux_user(information, &mut bytes) {
            return LINUX_EFAULT;
        }
        // The information names the signal sent (EINVAL otherwise); only
        // a process signalling itself may pass a code the kernel's own
        // signals use (si_code >= 0, or SI_TKILL).
        if u64::from(u32::from_ne_bytes(bytes[..4].try_into().unwrap())) != signal {
            return LINUX_EINVAL;
        }
        let code = i32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        if process != current_linux_process_pid() && (code >= 0 || code == SI_TKILL) {
            return LINUX_EPERM;
        }
        (
            signal,
            code,
            Some(u64::from_ne_bytes(bytes[24..32].try_into().unwrap())),
        )
    };
    linux_kill(
        u64::from(process),
        generated,
        output,
        interrupted,
        return_registers,
    )
}

fn linux_descriptor_poll_events(descriptor: i32, requested: u16) -> u16 {
    let Ok(descriptor) = u64::try_from(descriptor) else {
        return 0;
    };
    match linux_graphics_descriptor(descriptor) {
        Some(LinuxGraphicsDevice::Input(device)) => {
            return if crate::linux_input::pending(device) {
                requested & LINUX_POLLIN
            } else {
                0
            };
        }
        Some(LinuxGraphicsDevice::Framebuffer) => {
            return requested & (LINUX_POLLIN | LINUX_POLLOUT);
        }
        None => {}
    }
    // /proc/mounts reads at once, and a mount table change since it was
    // last read is POLLPRI and POLLERR, as in Linux.
    if linux_device_descriptor(descriptor) & !3 == LINUX_FILE_PROC_MOUNTS {
        let readable = requested & (LINUX_POLLIN | LINUX_POLLRDNORM);
        return if linux_proc_mounts_changed(descriptor) {
            readable | LINUX_POLLPRI | LINUX_POLLERR
        } else {
            readable
        };
    }
    if linux_pidfd_descriptor(descriptor) {
        let Some(process) = linux_pidfd_process(descriptor) else {
            return LINUX_POLLHUP;
        };
        return if linux_process::live_process_status(process)
            .is_some_and(|status| status.state == linux_process::LiveProcessState::Zombie)
        {
            requested & LINUX_POLLIN
        } else {
            0
        };
    }
    if linux_signalfd_descriptor(descriptor) {
        let mask = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
        let dynamic = linux_dynamic_pending_masks().map_or(0, |(process, thread)| process | thread);
        return if (X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst) | dynamic) & mask
            != 0
        {
            requested & LINUX_POLLIN
        } else {
            0
        };
    }
    if linux_inotify_descriptor(descriptor) {
        return if linux_inotify_ready(descriptor) {
            requested & LINUX_POLLIN
        } else {
            0
        };
    }
    if linux_fanotify_descriptor(descriptor) {
        return if linux_fanotify_ready(descriptor) {
            requested & LINUX_POLLIN
        } else {
            0
        };
    }
    if let Some((end, index)) = linux_pty_descriptor(descriptor) {
        return linux_pty_poll_events(end, index, requested);
    }
    if let Some((crate::linux_userfaultfd::CLASS_CONTEXT, id)) = linux_object_descriptor(descriptor)
    {
        return linux_userfaultfd_poll_events(descriptor, id, requested);
    }
    if let Some(id) = linux_tun_file(descriptor) {
        return linux_tun_poll_events(id, requested);
    }
    if let Some(slot) = linux_socket_slot(descriptor) {
        if let Some((class, id)) = crate::linux_socket::object(slot) {
            return match class {
                // A sync file is readable once its fence has signalled.
                crate::linux_drm::CLASS_FENCE => {
                    if crate::drivers::virtio_gpu::fence_signaled(id) {
                        requested & LINUX_POLLIN
                    } else {
                        0
                    }
                }
                crate::linux_drm::CLASS_DMABUF => requested & (LINUX_POLLIN | LINUX_POLLOUT),
                // A render node has no DRM events to read.
                _ => 0,
            };
        }
        let Some((readable, writable, error)) = crate::linux_socket::readiness(slot) else {
            return LINUX_POLLNVAL;
        };
        let device = linux_device_descriptor(descriptor);
        let pipe = device & LINUX_DEVICE_PIPE != 0;
        // A pipe's other end is gone: its read end hangs up (POLLHUP) when
        // no writer is left, and its write end reports an error (POLLERR)
        // when no reader is.
        let peer_gone = pipe && crate::linux_socket::local_peer_write_closed(slot) == Some(true);
        let write_end = device & 3 == LINUX_DESCRIPTOR_OUTPUT;
        let hangup = peer_gone && !write_end;
        let error = error || peer_gone && write_end;
        // A pipe is readable only with data queued; end-of-file is POLLHUP
        // alone, where a socket also reports POLLIN.
        let readable = readable
            && (!pipe
                || crate::linux_socket::local_queued_bytes(slot).is_ok_and(|queued| queued != 0));
        let writable = writable && (!pipe || crate::linux_socket::pipe_writable(slot));
        return (if readable {
            requested & LINUX_POLLIN
        } else {
            0
        }) | (if writable {
            requested & LINUX_POLLOUT
        } else {
            0
        }) | if error { LINUX_POLLERR } else { 0 }
            | if hangup { LINUX_POLLHUP } else { 0 }
            | if requested & LINUX_POLLRDHUP != 0 && crate::linux_socket::read_hung_up(slot) {
                LINUX_POLLRDHUP
            } else {
                0
            };
    }
    let console = u16::from(linux_console_descriptor(descriptor));
    if console != 0 {
        let readable = if console & LINUX_DESCRIPTOR_INPUT != 0 {
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                if crate::serial_input_ready() {
                    requested & LINUX_POLLIN
                } else {
                    0
                }
            } else {
                LINUX_POLLHUP
            }
        } else {
            0
        };
        let writable = if console & LINUX_DESCRIPTOR_OUTPUT != 0 {
            requested & LINUX_POLLOUT
        } else {
            0
        };
        return readable | writable;
    }
    if linux_epoll_descriptor(descriptor) {
        return if linux_epoll_event(descriptor, false)
            .ok()
            .flatten()
            .is_some()
        {
            requested & LINUX_POLLIN
        } else {
            0
        };
    }
    if linux_eventfd_descriptor(descriptor) {
        let counter = linux_eventfd_state(descriptor)
            .map(|(counter, _)| counter.load(Ordering::SeqCst))
            .unwrap_or(0);
        let mut returned = 0;
        if counter != 0 {
            returned |= requested & LINUX_POLLIN;
        }
        if counter < u64::MAX - 1 {
            returned |= requested & LINUX_POLLOUT;
        }
        // The overflow state an AIO completion can reach (eventfd06).
        if counter == u64::MAX {
            returned |= LINUX_POLLERR;
        }
        return returned;
    }
    if let Some(state) = linux_timerfd_state(descriptor) {
        let deadline = state.deadline.load(Ordering::SeqCst);
        let ready = deadline != 0 && linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline);
        return if ready { requested & LINUX_POLLIN } else { 0 };
    }
    if linux_pipe_read_descriptor(descriptor) {
        let mut returned = 0;
        if X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst) != 0 {
            returned |= requested & LINUX_POLLIN;
        }
        if X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
            .load(Ordering::SeqCst)
            == 0
        {
            returned |= LINUX_POLLHUP;
        }
        return returned;
    }
    if linux_pipe_write_descriptor(descriptor) {
        if X86_RUNTIME
            .ELF_PROBE_PIPE_READ_DESCRIPTOR
            .load(Ordering::SeqCst)
            == 0
        {
            return LINUX_POLLERR;
        }
        return if X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst)
            < LINUX_PIPE_CAPACITY as u32
        {
            requested & LINUX_POLLOUT
        } else {
            0
        };
    }
    let device = linux_device_descriptor(descriptor);
    if device == 0 {
        return LINUX_POLLNVAL;
    }
    let access = device & 3;
    let mut returned = 0;
    if matches!(access, LINUX_DESCRIPTOR_INPUT | 3)
        && (device & LINUX_DEVICE_CONSOLE == 0 || crate::serial_input_ready())
    {
        returned |= requested & LINUX_POLLIN;
    }
    if matches!(access, LINUX_DESCRIPTOR_OUTPUT | 3) {
        returned |= requested & LINUX_POLLOUT;
    }
    returned
}

fn linux_socket_iov_ranges(
    vectors: u64,
    count: u64,
    writable: bool,
) -> Result<([(u64, usize); LINUX_IOV_LIMIT], usize), u64> {
    let Ok(vector_count) = usize::try_from(count) else {
        return Err(LINUX_EINVAL);
    };
    if vector_count > LINUX_IOV_LIMIT {
        return Err(LINUX_EINVAL);
    }
    let mut table = [0_u8; LINUX_IOV_LIMIT * 16];
    if vector_count != 0 && !copy_from_linux_user(vectors, &mut table[..vector_count * 16]) {
        return Err(LINUX_EFAULT);
    }
    let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
    for (range, vector) in ranges
        .iter_mut()
        .zip(table[..vector_count * 16].as_chunks::<16>().0)
    {
        *range = (
            u64::from_ne_bytes(vector[..8].try_into().unwrap()),
            usize::from_ne_bytes(vector[8..].try_into().unwrap()),
        );
    }
    // As Linux, every length is checked (each and their sum must fit an
    // ssize_t) before any buffer is.
    let total = ranges[..vector_count]
        .iter()
        .try_fold(0_usize, |total, (_, length)| total.checked_add(*length))
        .filter(|total| *total <= isize::MAX as usize);
    if total.is_none() {
        return Err(LINUX_EINVAL);
    }
    let accessible = |(address, length): &(u64, usize)| {
        *length == 0
            || if writable {
                linux_writable_user_range_contains(*address, *length)
            } else {
                linux_readable_user_range_contains(*address, *length)
            }
    };
    if !ranges[..vector_count].iter().all(accessible) {
        return Err(LINUX_EFAULT);
    }
    Ok((ranges, vector_count))
}

fn linux_socket_writev(descriptor: u64, vectors: u64, count: u64) -> Option<u64> {
    let slot = linux_socket_slot(descriptor)?;
    let device = linux_device_descriptor(descriptor);
    if device & LINUX_DEVICE_PIPE != 0 && device & 3 & LINUX_DESCRIPTOR_OUTPUT == 0 {
        return Some(LINUX_EBADF);
    }
    let (ranges, vector_count) = match linux_socket_iov_ranges(vectors, count, false) {
        Ok(ranges) => ranges,
        Err(error) => return Some(error),
    };
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut written = 0_usize;
    for (address, length) in ranges[..vector_count].iter().copied() {
        let mut offset = 0_usize;
        while offset < length {
            let chunk = (length - offset).min(bytes.len());
            if !copy_from_linux_user(address + offset as u64, &mut bytes[..chunk]) {
                return Some(if written == 0 {
                    LINUX_EFAULT
                } else {
                    written as u64
                });
            }
            let result = if linux_socket_nonblocking(descriptor) {
                crate::linux_socket::send(slot, &bytes[..chunk], None)
            } else {
                crate::linux_socket::send_blocking(slot, &bytes[..chunk], None)
            };
            let sent = match result {
                Ok(sent) => sent,
                Err(error) => {
                    return Some(if written == 0 {
                        linux_socket_error(error)
                    } else {
                        written as u64
                    });
                }
            };
            written += sent;
            offset += sent;
            if sent < chunk {
                return Some(written as u64);
            }
        }
    }
    Some(written as u64)
}

fn linux_socket_readv(descriptor: u64, vectors: u64, count: u64) -> Option<u64> {
    let slot = linux_socket_slot(descriptor)?;
    let device = linux_device_descriptor(descriptor);
    if device & LINUX_DEVICE_PIPE != 0 && device & 3 & LINUX_DESCRIPTOR_INPUT == 0 {
        return Some(LINUX_EBADF);
    }
    let (ranges, vector_count) = match linux_socket_iov_ranges(vectors, count, true) {
        Ok(ranges) => ranges,
        Err(error) => return Some(error),
    };
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut received_total = 0_usize;
    for (address, length) in ranges[..vector_count].iter().copied() {
        let mut offset = 0_usize;
        while offset < length {
            let chunk = (length - offset).min(bytes.len());
            let result = if linux_socket_nonblocking(descriptor) {
                crate::linux_socket::recv(slot, &mut bytes[..chunk])
            } else {
                crate::linux_socket::recv_blocking(slot, &mut bytes[..chunk])
            };
            let received = match result {
                Ok((received, _)) => received,
                Err(error) => {
                    return Some(if received_total == 0 {
                        linux_socket_error(error)
                    } else {
                        received_total as u64
                    });
                }
            };
            if received != 0 && !copy_to_linux_user(address + offset as u64, &bytes[..received]) {
                return Some(if received_total == 0 {
                    LINUX_EFAULT
                } else {
                    received_total as u64
                });
            }
            received_total += received;
            offset += received;
            if received < chunk {
                return Some(received_total as u64);
            }
        }
    }
    Some(received_total as u64)
}

fn container_console_read_byte() -> Option<u8> {
    let slot = active_container_slot()?;
    // An init waiting for console input has finished booting, whether or not
    // the console stays attached.
    let _ = X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].compare_exchange(
        control_abi::DOMAIN_STATE_BOOTING as u8,
        control_abi::DOMAIN_STATE_RUNNING as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    if !X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire) {
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
            .store(control_abi::DOMAIN_STATE_RUNNING as u8, Ordering::Release);
        X86_RUNTIME.CONTAINER_BACKGROUND_SUSPENDED[slot].store(false, Ordering::Release);
        X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_REQUESTED
            .store(true, Ordering::Release);
        return None;
    }
    let byte = crate::serial_read_byte_blocking();
    if byte == CONTAINER_CONSOLE_DETACH {
        X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].store(false, Ordering::Release);
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
            .store(control_abi::DOMAIN_STATE_RUNNING as u8, Ordering::Release);
        X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_REQUESTED
            .store(true, Ordering::Release);
        crate::serial_write_bytes(
            b"\r\n[detached from domain; use 'domain attach NAME' to return]\r\n",
        );
        None
    } else {
        Some(byte)
    }
}

fn container_console_write(bytes: &[u8]) {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire) {
        crate::serial_write_bytes(bytes);
        return;
    }
    let Some(slot) = active_container_slot() else {
        crate::serial_write_bytes(bytes);
        return;
    };
    let start = X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot].load(Ordering::Relaxed);
    for (offset, byte) in bytes.iter().copied().enumerate() {
        let index = start.wrapping_add(offset as u64) as usize % CONTAINER_CONSOLE_CAPACITY;
        X86_RUNTIME.CONTAINER_CONSOLE_BYTES[slot][index].store(byte, Ordering::Relaxed);
    }
    X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot]
        .store(start.wrapping_add(bytes.len() as u64), Ordering::Release);
    if X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire) {
        crate::serial_write_bytes(bytes);
    }
}

pub(crate) fn buffer_configured_container_console(bytes: &[u8]) -> bool {
    let Some(slot) = selected_or_active_container_slot() else {
        return false;
    };
    let start = X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot].load(Ordering::Relaxed);
    for (offset, byte) in bytes.iter().copied().enumerate() {
        let index = start.wrapping_add(offset as u64) as usize % CONTAINER_CONSOLE_CAPACITY;
        X86_RUNTIME.CONTAINER_CONSOLE_BYTES[slot][index].store(byte, Ordering::Relaxed);
    }
    X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot]
        .store(start.wrapping_add(bytes.len() as u64), Ordering::Release);
    true
}

fn reset_container_console(slot: usize, attached: bool) {
    X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot].store(0, Ordering::Release);
    X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].store(attached, Ordering::Release);
}

fn redraw_container_console(slot: usize) {
    crate::serial_write_bytes(b"\x1b[2J\x1b[H");
    let cursor = X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot].load(Ordering::Acquire);
    let count = cursor.min(CONTAINER_CONSOLE_CAPACITY as u64);
    let start = cursor.wrapping_sub(count);
    for offset in 0..count {
        let index = start.wrapping_add(offset) as usize % CONTAINER_CONSOLE_CAPACITY;
        crate::serial_write_bytes(&[
            X86_RUNTIME.CONTAINER_CONSOLE_BYTES[slot][index].load(Ordering::Relaxed)
        ]);
    }
}

fn linux_console_descriptor_open(descriptor: u64) -> bool {
    linux_console_descriptor(descriptor) != 0
}

fn linux_tty_get_termios(address: u64) -> u64 {
    let mut termios = [0_u8; 36];
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        for (index, flag) in X86_RUNTIME.LINUX_TTY_TERMIOS_FLAGS.iter().enumerate() {
            termios[index * 4..index * 4 + 4]
                .copy_from_slice(&flag.load(Ordering::SeqCst).to_ne_bytes());
        }
        termios[16] = X86_RUNTIME.LINUX_TTY_LINE.load(Ordering::SeqCst);
        for (index, character) in X86_RUNTIME.LINUX_TTY_CONTROL_CHARACTERS.iter().enumerate() {
            termios[17 + index] = character.load(Ordering::SeqCst);
        }
    }
    if copy_to_linux_user(address, &termios) {
        0
    } else {
        LINUX_EFAULT
    }
}

fn linux_tty_set_termios(address: u64) -> u64 {
    let mut termios = [0_u8; 36];
    if !copy_from_linux_user(address, &mut termios) {
        return LINUX_EFAULT;
    }
    for (index, flag) in X86_RUNTIME.LINUX_TTY_TERMIOS_FLAGS.iter().enumerate() {
        flag.store(
            u32::from_ne_bytes(termios[index * 4..index * 4 + 4].try_into().unwrap()),
            Ordering::SeqCst,
        );
    }
    X86_RUNTIME
        .LINUX_TTY_LINE
        .store(termios[16], Ordering::SeqCst);
    for (index, character) in X86_RUNTIME.LINUX_TTY_CONTROL_CHARACTERS.iter().enumerate() {
        character.store(termios[17 + index], Ordering::SeqCst);
    }
    0
}

fn linux_tty_ioctl(request: u64, argument: u64) -> u64 {
    let pid = current_linux_process_pid();
    match request {
        LINUX_TCGETS => linux_tty_get_termios(argument),
        LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF => {
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                linux_tty_set_termios(argument)
            } else {
                LINUX_ENOTTY
            }
        }
        // termios2: the same settings followed by the input and output
        // speeds, which the console reports as 38400 baud and ignores.
        LINUX_TCGETS2 => {
            let result = linux_tty_get_termios(argument);
            let speeds = [38_400_u32.to_ne_bytes(), 38_400_u32.to_ne_bytes()].concat();
            if result != 0 {
                result
            } else if argument
                .checked_add(36)
                .is_some_and(|address| copy_to_linux_user(address, &speeds))
            {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_TCSETS2 | LINUX_TCSETSW2 | LINUX_TCSETSF2 => {
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                linux_tty_set_termios(argument)
            } else {
                LINUX_ENOTTY
            }
        }
        LINUX_TIOCSCTTY => {
            let Some(session) = linux_process::live_process_session(pid) else {
                return LINUX_ESRCH;
            };
            if session != pid {
                return LINUX_EPERM;
            }
            let owner = X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst);
            let privileged_force = argument == 1
                && current_linux_credentials()
                    .is_some_and(|credentials| credentials.user.effective == 0);
            if owner != 0 && owner != session && !privileged_force {
                return LINUX_EPERM;
            }
            X86_RUNTIME
                .LINUX_TTY_SESSION
                .store(session, Ordering::SeqCst);
            X86_RUNTIME.LINUX_TTY_FOREGROUND_GROUP.store(
                linux_process::live_process_group(pid).unwrap_or(pid),
                Ordering::SeqCst,
            );
            0
        }
        LINUX_TIOCGPGRP => {
            let Some(session) = linux_process::live_process_session(pid) else {
                return LINUX_ESRCH;
            };
            if X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst) != session {
                return LINUX_ENOTTY;
            }
            let group = X86_RUNTIME
                .LINUX_TTY_FOREGROUND_GROUP
                .load(Ordering::SeqCst);
            if copy_to_linux_user(argument, &(group as i32).to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_TIOCSPGRP => {
            let Some(session) = linux_process::live_process_session(pid) else {
                return LINUX_ESRCH;
            };
            if X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst) != session {
                return LINUX_ENOTTY;
            }
            let mut bytes = [0_u8; 4];
            if !copy_from_linux_user(argument, &mut bytes) {
                return LINUX_EFAULT;
            }
            let group = i32::from_ne_bytes(bytes);
            if group <= 0
                || !(0..linux_process::live_process_slots()).any(|slot| {
                    linux_process::live_process_pid_at(slot).is_some_and(|candidate| {
                        linux_process::live_process_group(candidate) == Some(group as u32)
                            && linux_process::live_process_session(candidate) == Some(session)
                    })
                })
            {
                return LINUX_EPERM;
            }
            X86_RUNTIME
                .LINUX_TTY_FOREGROUND_GROUP
                .store(group as u32, Ordering::SeqCst);
            0
        }
        LINUX_TIOCNOTTY => {
            let Some(session) = linux_process::live_process_session(pid) else {
                return LINUX_ESRCH;
            };
            if X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst) != session {
                return LINUX_ENOTTY;
            }
            if session == pid {
                X86_RUNTIME.LINUX_TTY_SESSION.store(0, Ordering::SeqCst);
                X86_RUNTIME
                    .LINUX_TTY_FOREGROUND_GROUP
                    .store(0, Ordering::SeqCst);
            }
            0
        }
        LINUX_TIOCGSID => {
            let Some(session) = linux_process::live_process_session(pid) else {
                return LINUX_ESRCH;
            };
            if X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst) != session {
                return LINUX_ENOTTY;
            }
            if copy_to_linux_user(argument, &(session as i32).to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_TIOCGWINSZ => {
            let mut window = [0_u8; 8];
            window[..2].copy_from_slice(&24_u16.to_ne_bytes());
            window[2..4].copy_from_slice(&80_u16.to_ne_bytes());
            if copy_to_linux_user(argument, &window) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        LINUX_TIOCVHANGUP => {
            if current_linux_credentials()
                .is_some_and(|credentials| credentials.user.effective == 0)
            {
                X86_RUNTIME.LINUX_TTY_SESSION.store(0, Ordering::SeqCst);
                X86_RUNTIME
                    .LINUX_TTY_FOREGROUND_GROUP
                    .store(0, Ordering::SeqCst);
                0
            } else {
                LINUX_EPERM
            }
        }
        _ => LINUX_ENOTTY,
    }
}

fn linux_default_resource_limit(resource: u64, runtime: bool) -> Option<[u64; 2]> {
    let value = match resource {
        LINUX_RLIMIT_STACK if runtime => return Some([LINUX_STACK_DEFAULT_LIMIT, u64::MAX]),
        LINUX_RLIMIT_STACK => PAGE_SIZE as u64,
        // Linux's defaults (INR_OPEN_CUR, INR_OPEN_MAX): a process may raise
        // its soft limit to 4096 and, with CAP_SYS_RESOURCE, its hard limit
        // to /proc/sys/fs/nr_open; descriptors past the fixed table live in
        // `linux_fd_table`.
        LINUX_RLIMIT_NOFILE if runtime => return Some([LINUX_DESCRIPTOR_TABLE_LIMIT, 4096]),
        LINUX_RLIMIT_NOFILE => LINUX_AUX_DESCRIPTOR_LIMIT,
        // Linux counts every task; the process table and thread slots bound
        // the real capacity.
        LINUX_RLIMIT_NPROC => (linux_process::PROCESS_LIMIT + LINUX_THREAD_LIMIT) as u64,
        // RLIMIT_SIGPENDING: queued signals now count against it, so it is
        // Linux's order of magnitude (max_threads / 2), not one per signal.
        LINUX_RLIMIT_SIGPENDING => 16_384,
        13 | 14 => 0,
        resource if resource < LINUX_RLIMIT_NLIMITS => u64::MAX,
        _ => return None,
    };
    Some([value, value])
}

/// Writes a core file for the current process, ending by `signal`, a
/// core-dumping one, when its RLIMIT_CORE allows: named by the domain's
/// core_pattern (from its working directory; Linux's "core" unless set),
/// an ELF core with the process's NT_PRPSINFO note and a PT_LOAD segment
/// for each area of anonymous memory coredump_filter's default dumps, not
/// marked MADV_DONTDUMP, with the pages it has (the others read as zeros).
/// Whether one was written, which the wait status reports (WCOREDUMP,
/// CLD_DUMPED).
fn linux_write_core_file(signal: u64) -> bool {
    use crate::linux_areas::Backing;
    const RLIMIT_CORE: u64 = 4;
    const O_WRONLY: u64 = 1;
    const O_TRUNC: u64 = 0o1000;
    const NOTE_SIZE: usize = 20 + 136;
    const ELF_HEADER: usize = 64;
    const PROGRAM_HEADER: usize = 56;
    const PF_R: u32 = 4;
    const PF_W: u32 = 2;
    const PF_X: u32 = 1;
    let limit = linux_resource_limit_values(RLIMIT_CORE, true).map_or(0, |values| values[0]);
    let pid = current_linux_process_pid();
    let instance = linux_execution_instance();
    // The areas dumped: anonymous memory (the heap and stack too), private
    // and shared, which the default filter 0x33 names.
    let segments: Vec<crate::linux_areas::Area> = crate::linux_areas::snapshot(instance, pid)
        .map(|areas| {
            areas
                .iter()
                .filter(|area| {
                    !area.dont_dump
                        && matches!(
                            area.backing,
                            Backing::Anonymous
                                | Backing::Heap
                                | Backing::Stack
                                | Backing::Droppable
                        )
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let headers = 1 + segments.len();
    let note_offset = ELF_HEADER + headers * PROGRAM_HEADER;
    let data_offset = (note_offset + NOTE_SIZE).next_multiple_of(PAGE_SIZE);
    let size = segments
        .iter()
        .fold(data_offset as u64, |size, area| size + area.len());
    if limit < (note_offset + NOTE_SIZE) as u64 {
        return false;
    }
    let mut core = Vec::new();
    if core.try_reserve_exact(note_offset + NOTE_SIZE).is_err() {
        return false;
    }
    core.resize(note_offset + NOTE_SIZE, 0);
    // ELF header: 64-bit, little-endian, ET_CORE for x86-64, the program
    // headers (PT_NOTE, then the PT_LOADs) right after it.
    core[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    core[16..18].copy_from_slice(&4_u16.to_le_bytes());
    core[18..20].copy_from_slice(&62_u16.to_le_bytes());
    core[20..24].copy_from_slice(&1_u32.to_le_bytes());
    core[32..40].copy_from_slice(&(ELF_HEADER as u64).to_le_bytes());
    core[52..54].copy_from_slice(&(ELF_HEADER as u16).to_le_bytes());
    core[54..56].copy_from_slice(&(PROGRAM_HEADER as u16).to_le_bytes());
    core[56..58].copy_from_slice(&(headers as u16).to_le_bytes());
    let header = ELF_HEADER;
    core[header..header + 4].copy_from_slice(&4_u32.to_le_bytes());
    core[header + 8..header + 16].copy_from_slice(&(note_offset as u64).to_le_bytes());
    core[header + 32..header + 40].copy_from_slice(&(NOTE_SIZE as u64).to_le_bytes());
    core[header + 48..header + 56].copy_from_slice(&4_u64.to_le_bytes());
    let mut offset = data_offset as u64;
    for (index, area) in segments.iter().enumerate() {
        let at = ELF_HEADER + (index + 1) * PROGRAM_HEADER;
        let flags = if area.protection.readable() { PF_R } else { 0 }
            | if area.protection.writable() { PF_W } else { 0 }
            | if area.protection.executable() {
                PF_X
            } else {
                0
            };
        core[at..at + 4].copy_from_slice(&1_u32.to_le_bytes());
        core[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        core[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
        core[at + 16..at + 24].copy_from_slice(&area.start.to_le_bytes());
        core[at + 32..at + 40].copy_from_slice(&area.len().to_le_bytes());
        core[at + 40..at + 48].copy_from_slice(&area.len().to_le_bytes());
        core[at + 48..at + 56].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
        offset += area.len();
    }
    // NT_PRPSINFO: name "CORE", then elf_prpsinfo.
    let note = note_offset;
    core[note..note + 4].copy_from_slice(&5_u32.to_le_bytes());
    core[note + 4..note + 8].copy_from_slice(&136_u32.to_le_bytes());
    core[note + 8..note + 12].copy_from_slice(&3_u32.to_le_bytes());
    core[note + 12..note + 16].copy_from_slice(b"CORE");
    let info = note + 20;
    core[info] = b'R';
    core[info + 1] = b'R';
    if let Some(credentials) = current_linux_credentials() {
        core[info + 16..info + 20].copy_from_slice(&credentials.user.real.to_le_bytes());
        core[info + 20..info + 24].copy_from_slice(&credentials.group.real.to_le_bytes());
    }
    core[info + 24..info + 28].copy_from_slice(&pid.to_le_bytes());
    let parent = linux_process::live_process_parent_pid(pid).unwrap_or(0);
    core[info + 28..info + 32].copy_from_slice(&parent.to_le_bytes());
    let mut name = [0_u8; 16];
    let name = linux_process_name(pid, &mut name);
    let length = name.len().min(15);
    core[info + 40..info + 40 + length].copy_from_slice(&name[..length]);
    core[info + 56..info + 56 + length].copy_from_slice(&name[..length]);
    let (uid, gid) = current_linux_credentials().map_or((0, 0), |credentials| {
        (credentials.user.real, credentials.group.real)
    });
    let mut hostname = [0_u8; LINUX_UTS_NAME_CAPACITY];
    let hostname_length = linux_uts_name(LINUX_UTS_HOST, &mut hostname);
    let uses_pid =
        linux_proc_sysctl_value(b"sys/kernel/core_uses_pid").is_some_and(|value| value != 0);
    let Some(file_name) = crate::linux_core::file_name(
        &crate::linux_core::pattern(instance),
        uses_pid,
        &crate::linux_core::Process {
            pid,
            uid,
            gid,
            signal: signal as u32,
            seconds: linux_realtime_now().0.max(0) as u64,
            name,
            hostname: &hostname[..hostname_length],
        },
    ) else {
        return false;
    };
    let mut path = [0_u8; LINUX_PATH_MAX];
    let Some(target) = path
        .get_mut(..file_name.len())
        .filter(|_| !file_name.is_empty())
    else {
        return false;
    };
    target.copy_from_slice(&file_name);
    let descriptor = linux_openat_path(
        u64::from(LINUX_AT_FDCWD),
        path,
        file_name.len(),
        O_WRONLY | LINUX_O_CREAT | O_TRUNC | LINUX_O_NOFOLLOW,
        0o600,
    );
    if descriptor > u64::MAX - 4096 {
        return false;
    }
    let Some(handle) = linux_overlay_descriptor_handle(descriptor) else {
        let _ = linux_descriptor_close(descriptor);
        return false;
    };
    // The headers and note, then each segment's pages as far as
    // RLIMIT_CORE lets the file grow: a page the process never touched is
    // a hole, which reads as zeros.
    let mut written = crate::linux_overlay::write(handle, 0, &core) == Some(core.len());
    let mut offset = data_offset as u64;
    let mut page = [0_u8; PAGE_SIZE];
    for area in &segments {
        for address in (area.start..area.end).step_by(PAGE_SIZE) {
            let at = offset + (address - area.start);
            if !written || at + PAGE_SIZE as u64 > limit {
                break;
            }
            let state = address_space::current_linux_runtime_page(address);
            if state.frame.is_none() || !copy_from_linux_user(address, &mut page) {
                continue;
            }
            written = crate::linux_overlay::write(handle, at as usize, &page) == Some(PAGE_SIZE);
        }
        offset += area.len();
    }
    // The file is as long as its segments say, holes and all.
    if written && size <= limit {
        let _ = crate::linux_overlay::truncate(handle, size as usize);
    }
    let _ = linux_descriptor_close(descriptor);
    written
}

fn linux_resource_limit_values(resource: u64, runtime: bool) -> Option<[u64; 2]> {
    let defaults = linux_default_resource_limit(resource, runtime)?;
    if !X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst) {
        return Some(defaults);
    }
    let index = resource as usize * 2;
    Some([
        X86_RUNTIME.ELF_PROBE_RLIMITS[index].load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_RLIMITS[index + 1].load(Ordering::SeqCst),
    ])
}

fn linux_resource_limit(resource: u64, runtime: bool) -> Option<[u8; 16]> {
    let values = linux_resource_limit_values(resource, runtime)?;
    let mut limit = [0_u8; 16];
    limit[..8].copy_from_slice(&values[0].to_ne_bytes());
    limit[8..].copy_from_slice(&values[1].to_ne_bytes());
    Some(limit)
}

fn linux_process_resource_limit_values(pid: u32, resource: u64) -> Option<[u64; 2]> {
    linux_default_resource_limit(
        resource,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    )?;
    if pid == current_linux_process_pid() {
        return linux_resource_limit_values(
            resource,
            X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
        );
    }
    let state = linux_process_runtime_state(pid).filter(|state| state.valid)?;
    let index = resource as usize * 2;
    Some([state.rlimits[index], state.rlimits[index + 1]])
}

fn linux_set_process_resource_limit(pid: u32, resource: u64, requested: [u64; 2]) -> u64 {
    let Some(current) = linux_process_resource_limit_values(pid, resource) else {
        return LINUX_ESRCH;
    };
    if requested[0] > requested[1] {
        return LINUX_EINVAL;
    }
    // Raising a hard limit takes CAP_SYS_RESOURCE: root here. No one
    // raises RLIMIT_NOFILE past nr_open (setrlimit03).
    if requested[1] > current[1]
        && !current_linux_credentials().is_some_and(|credentials| credentials.privileged())
        || resource == LINUX_RLIMIT_NOFILE && requested[1] > linux_nr_open()
    {
        return LINUX_EPERM;
    }
    // RLIMIT_CPU (seconds of CPU time): SIGXCPU at the soft limit and
    // every second after, SIGKILL at the hard one, as timers on the
    // process's CPU clock (interval-timer slots 3 and 4).
    if resource == 0 {
        const SECOND: u64 = 1_000_000_000;
        const SIGXCPU: u8 = 24;
        let deadline = |limit: u64| {
            if limit == u64::MAX {
                0
            } else {
                limit.max(1).saturating_mul(SECOND)
            }
        };
        let _ = linux_process::set_live_process_interval_timer(
            pid,
            3,
            SIGXCPU,
            (SECOND, deadline(requested[0])),
        );
        let _ = linux_process::set_live_process_interval_timer(
            pid,
            4,
            LINUX_SIGKILL as u8,
            (0, deadline(requested[1])),
        );
        linux_refresh_posix_timer_cache(pid);
    }
    let index = resource as usize * 2;
    if pid == current_linux_process_pid() {
        X86_RUNTIME.ELF_PROBE_RLIMITS[index].store(requested[0], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_RLIMITS[index + 1].store(requested[1], Ordering::SeqCst);
        return 0;
    }
    let Some(state) = linux_process_runtime_state(pid).filter(|state| state.valid) else {
        return LINUX_ESRCH;
    };
    state.rlimits[index] = requested[0];
    state.rlimits[index + 1] = requested[1];
    0
}

fn linux_prlimit_target(pid: u64) -> Result<u32, u64> {
    let pid = pid as u32 as i32;
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

fn linux_prlimit_permitted(pid: u32) -> bool {
    if pid == current_linux_process_pid() {
        return true;
    }
    let (Some(caller), Some(target)) = (
        current_linux_credentials(),
        linux_process::live_process_credentials(pid),
    ) else {
        return false;
    };
    caller.privileged() || linux_ids_match(&caller, &target)
}

/// Every user and group id of `target` is `caller`'s real one: what ptrace
/// and prlimit require of a caller without the capability.
fn linux_ids_match(caller: &linux_user::Credentials, target: &linux_user::Credentials) -> bool {
    let all_are = |ids: linox_credentials::Ids, id: u32| {
        [ids.real, ids.effective, ids.saved]
            .into_iter()
            .all(|candidate| candidate == id)
    };
    all_are(target.user, caller.user.real) && all_are(target.group, caller.group.real)
}

fn linux_prlimit64(pid: u64, resource: u64, new_limit: u64, old_limit: u64) -> u64 {
    let resource = u64::from(resource as u32);
    if resource >= LINUX_RLIMIT_NLIMITS {
        return LINUX_EINVAL;
    }
    let requested = if new_limit == 0 {
        None
    } else {
        let mut bytes = [0_u8; 16];
        if !copy_from_linux_user(new_limit, &mut bytes) {
            return LINUX_EFAULT;
        }
        let values = [
            u64::from_ne_bytes(bytes[..8].try_into().unwrap()),
            u64::from_ne_bytes(bytes[8..].try_into().unwrap()),
        ];
        if values[0] > values[1] {
            return LINUX_EINVAL;
        }
        Some(values)
    };
    let pid = match linux_prlimit_target(pid) {
        Ok(pid) => pid,
        Err(error) => return error,
    };
    if !linux_prlimit_permitted(pid) {
        return LINUX_EPERM;
    }
    let Some(previous) = linux_process_resource_limit_values(pid, resource) else {
        return LINUX_ESRCH;
    };
    if let Some(requested) = requested {
        let result = linux_set_process_resource_limit(pid, resource, requested);
        if result != 0 {
            return result;
        }
    }
    if old_limit != 0 {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&previous[0].to_ne_bytes());
        bytes[8..].copy_from_slice(&previous[1].to_ne_bytes());
        if !copy_to_linux_user(old_limit, &bytes) {
            return LINUX_EFAULT;
        }
    }
    0
}

fn linux_file_size_limit() -> u64 {
    linux_resource_limit_values(
        LINUX_RLIMIT_FSIZE,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    )
    .map_or(0, |limit| limit[0])
}

fn linux_file_write_limit(start: usize, requested: usize) -> Result<usize, u64> {
    if requested == 0 {
        return Ok(0);
    }
    let limit = linux_file_size_limit();
    if limit == u64::MAX {
        return Ok(requested);
    }
    let start = start as u64;
    if start >= limit {
        X86_RUNTIME
            .LINUX_FSIZE_LIMIT_HIT
            .store(true, Ordering::SeqCst);
        return Err(LINUX_EFBIG);
    }
    Ok(requested.min((limit - start) as usize))
}

fn linux_file_extension_limit(size: usize) -> Result<(), u64> {
    if (size as u64) <= linux_file_size_limit() {
        Ok(())
    } else {
        X86_RUNTIME
            .LINUX_FSIZE_LIMIT_HIT
            .store(true, Ordering::SeqCst);
        Err(LINUX_EFBIG)
    }
}

fn linux_address_space_limit_allows(additional_pages: usize) -> bool {
    let Some(limit) = linux_resource_limit_values(
        LINUX_RLIMIT_AS,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    ) else {
        return false;
    };
    if limit[0] == u64::MAX {
        return true;
    }
    let Some(current_pages) = address_space::current_linux_user_page_count() else {
        return false;
    };
    current_pages
        .checked_add(additional_pages)
        .and_then(|pages| pages.checked_mul(PAGE_SIZE))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .is_some_and(|bytes| bytes <= limit[0])
}

fn linux_nproc_limit_reached() -> bool {
    let Some(limit) = linux_resource_limit_values(
        LINUX_RLIMIT_NPROC,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    ) else {
        return true;
    };
    if limit[0] == u64::MAX {
        return false;
    }
    let Some(processes) = linux_process::live_process_count() else {
        return true;
    };
    let threads = X86_RUNTIME
        .LINUX_THREAD_STATES
        .iter()
        .filter(|state| state.load(Ordering::SeqCst) != LINUX_THREAD_FREE)
        .count() as u64;
    u64::from(processes).saturating_add(threads.saturating_sub(1)) >= limit[0]
}

fn linux_getrlimit(
    resource: u64,
    address: u64,
    runtime: bool,
    copy: fn(u64, &[u8]) -> bool,
) -> u64 {
    let resource = u64::from(resource as u32);
    let Some(limit) = linux_resource_limit(resource, runtime) else {
        return LINUX_EINVAL;
    };
    if copy(address, &limit) {
        0
    } else {
        LINUX_EFAULT
    }
}

fn linux_setrlimit(resource: u64, address: u64) -> u64 {
    let resource = u64::from(resource as u32);
    if resource >= LINUX_RLIMIT_NLIMITS {
        return LINUX_EINVAL;
    }
    let mut requested = [0_u8; 16];
    if !copy_from_linux_user(address, &mut requested) {
        return LINUX_EFAULT;
    }
    let requested = [
        u64::from_ne_bytes(requested[..8].try_into().unwrap()),
        u64::from_ne_bytes(requested[8..].try_into().unwrap()),
    ];
    linux_set_process_resource_limit(current_linux_process_pid(), resource, requested)
}

fn linux_scheduler_priority_range(policy: u64, maximum: bool) -> u64 {
    let policy = u64::from(policy as u32);
    match policy {
        1 | 2 if maximum => 99,
        1 | 2 => 1,
        0 | 3 | 5 | 6 => 0,
        _ => LINUX_EINVAL,
    }
}

const LINUX_PRIO_PROCESS: u32 = 0;
const LINUX_PRIO_PGRP: u32 = 1;
const LINUX_PRIO_USER: u32 = 2;

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

fn linux_getpriority(which: u64, who: u64) -> u64 {
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

fn linux_setpriority(which: u64, who: u64, priority: u64) -> u64 {
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

fn linux_sched_getscheduler(pid: u64) -> u64 {
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

fn linux_sched_getparam(pid: u64, address: u64) -> u64 {
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

fn linux_sched_rr_get_interval(pid: u64, address: u64) -> u64 {
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

fn linux_sched_getaffinity(pid: u64, length: u64, address: u64) -> u64 {
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

fn linux_sched_setaffinity(pid: u64, length: u64, address: u64) -> u64 {
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
fn linux_sched_setaffinity_live_return(
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

fn linux_available_cpu_mask() -> u64 {
    let count = linux_available_cpu_count();
    if count == u64::BITS as usize {
        u64::MAX
    } else {
        (1_u64 << count).saturating_sub(1)
    }
}

fn linux_available_cpu_count() -> usize {
    let online = crate::arch::x86_64::smp::online_count().max(1);
    let domain_limit = current_container_slot()
        .map(|slot| usize::from(X86_RUNTIME.CONTAINER_CPU_COUNTS[slot].load(Ordering::Acquire)))
        .unwrap_or(online);
    online.min(domain_limit.max(1)).min(u64::BITS as usize)
}

fn linux_ioprio_get(which: u64, who: u64) -> u64 {
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

fn linux_ioprio_set(which: u64, who: u64, priority: u64) -> u64 {
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

const MEMBARRIER_CMD_QUERY: u32 = 0;
const MEMBARRIER_CMD_GLOBAL: u32 = 1 << 0;
const MEMBARRIER_CMD_GLOBAL_EXPEDITED: u32 = 1 << 1;
const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: u32 = 1 << 2;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED: u32 = 1 << 3;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: u32 = 1 << 4;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ: u32 = 1 << 7;
const MEMBARRIER_CMD_GET_REGISTRATIONS: u32 = 1 << 9;
const MEMBARRIER_CMD_FLAG_CPU: u32 = 1;
const MEMBARRIER_SUPPORTED_COMMANDS: u32 = MEMBARRIER_CMD_GLOBAL
    | MEMBARRIER_CMD_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_GET_REGISTRATIONS;

fn linux_membarrier(command: u64, flags: u64, _cpu_id: u64) -> u64 {
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

/// The character devices the kernel provides itself. Each has its own
/// inode and Linux's device number: programs compare them (GNU grep takes
/// output whose identity is /dev/null's as discarded and prints nothing).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxCharacterDevice {
    Null,
    Zero,
    Full,
    Random,
    Urandom,
    Console,
    Tty,
}

impl LinuxCharacterDevice {
    const ALL: [Self; 7] = [
        Self::Null,
        Self::Zero,
        Self::Full,
        Self::Random,
        Self::Urandom,
        Self::Console,
        Self::Tty,
    ];

    /// The device's name in /dev.
    fn name(self) -> &'static [u8] {
        match self {
            Self::Null => b"null",
            Self::Zero => b"zero",
            Self::Full => b"full",
            Self::Random => b"random",
            Self::Urandom => b"urandom",
            Self::Console => b"console",
            Self::Tty => b"tty",
        }
    }

    /// The device at `path`, `/dev/NAME`.
    fn from_path(path: &[u8]) -> Option<Self> {
        Self::from_name(path.strip_prefix(b"/dev/")?)
    }

    /// The device at canonical `path` (`dev/NAME`).
    fn from_canonical(path: &[u8]) -> Option<Self> {
        Self::from_name(path.strip_prefix(b"dev/")?)
    }

    fn from_name(name: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|device| device.name() == name)
    }

    /// The device an open descriptor's kind (`linux_device_descriptor`)
    /// names: /dev/null opens with no kind bits, only its access mode.
    fn from_kind(kind: u16) -> Self {
        match kind & !3 {
            LINUX_DEVICE_FULL => Self::Full,
            LINUX_DEVICE_RANDOM => Self::Urandom,
            _ if kind & LINUX_DEVICE_ZERO != 0 => Self::Zero,
            0 => Self::Null,
            _ => Self::Console,
        }
    }

    /// The kind bits a descriptor opened on the device carries.
    fn kind(self) -> u16 {
        match self {
            Self::Null => 0,
            Self::Zero => LINUX_DEVICE_ZERO,
            Self::Full => LINUX_DEVICE_FULL,
            Self::Random | Self::Urandom => LINUX_DEVICE_RANDOM,
            Self::Console | Self::Tty => LINUX_DEVICE_CONSOLE,
        }
    }

    /// Inode, major and minor number and permissions, as on Linux.
    fn identity(self) -> (u64, u32, u32, u32) {
        match self {
            Self::Null => (1, 1, 3, 0o666),
            Self::Zero => (2, 1, 5, 0o666),
            Self::Full => (6, 1, 7, 0o666),
            Self::Random => (7, 1, 8, 0o666),
            Self::Urandom => (8, 1, 9, 0o666),
            Self::Console => (3, 5, 1, 0o600),
            Self::Tty => (5, 5, 0, 0o666),
        }
    }

    fn stat(self) -> [u8; LINUX_STAT_SIZE] {
        let (inode, major, minor, permissions) = self.identity();
        let mut stat = linux_stat(0o020_000 | permissions, inode);
        let (major, minor) = (u64::from(major), u64::from(minor));
        let rdev = (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12);
        stat[40..48].copy_from_slice(&rdev.to_ne_bytes());
        stat
    }
}

fn linux_console_stat() -> [u8; LINUX_STAT_SIZE] {
    LinuxCharacterDevice::Console.stat()
}

/// Character devices for graphical sessions: the firmware framebuffer as
/// Linux fbdev (/dev/fb0) and evdev input devices (/dev/input/eventN).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxGraphicsDevice {
    Framebuffer,
    Input(usize),
}

fn linux_graphics_device(state: u16) -> Option<LinuxGraphicsDevice> {
    match state & !3 {
        LINUX_FILE_FRAMEBUFFER => Some(LinuxGraphicsDevice::Framebuffer),
        kind if kind & !LINUX_ROOT_NODE_MASK == LINUX_FILE_MASK => {
            let device = usize::from((kind >> 8).wrapping_sub(LINUX_INPUT_NODE_FIRST >> 8));
            (device < crate::linux_input::DEVICE_LIMIT)
                .then_some(LinuxGraphicsDevice::Input(device))
        }
        _ => None,
    }
}

fn linux_graphics_descriptor(descriptor: u64) -> Option<LinuxGraphicsDevice> {
    if linux_socket_slot(descriptor).is_some() {
        return None;
    }
    linux_graphics_device(linux_device_descriptor(descriptor))
}

fn linux_graphics_path_kind(path: &[u8]) -> Option<u16> {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return None;
    }
    if path == b"/dev/fb0" {
        return crate::framebuffer::display().map(|_| LINUX_FILE_FRAMEBUFFER);
    }
    let [digit] = path.strip_prefix(b"/dev/input/event")? else {
        return None;
    };
    let device = digit.checked_sub(b'0')?;
    crate::linux_input::device_kind(usize::from(device))?;
    Some(LINUX_FILE_MASK | (LINUX_INPUT_NODE_FIRST + (u16::from(device) << 8)))
}

fn linux_graphics_stat(device: LinuxGraphicsDevice) -> [u8; LINUX_STAT_SIZE] {
    // Linux numbers: fb0 is character device 29:0, eventN is 13:(64 + N).
    let (inode, major, minor) = match device {
        LinuxGraphicsDevice::Framebuffer => (60, 29_u64, 0_u64),
        LinuxGraphicsDevice::Input(device) => (61 + device as u64, 13, 64 + device as u64),
    };
    let mut stat = linux_stat(LINUX_STAT_CHARACTER_DEVICE_MODE | 0o060, inode);
    let rdev = (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12);
    stat[40..48].copy_from_slice(&rdev.to_ne_bytes());
    stat
}

fn linux_graphics_syscall(number: u64, descriptor: u64, buffer: u64, count: u64) -> u64 {
    let Some(device) = linux_graphics_descriptor(descriptor) else {
        return LINUX_EBADF;
    };
    let state = linux_device_descriptor(descriptor);
    match number {
        LINUX_IOCTL_SYSCALL => {
            if let Some(result) = linux_generic_ioctl(descriptor, buffer, count) {
                return result;
            }
            match device {
                LinuxGraphicsDevice::Framebuffer => linux_framebuffer_ioctl(buffer, count),
                LinuxGraphicsDevice::Input(device) => linux_evdev_ioctl(device, buffer, count),
            }
        }
        LINUX_READ_SYSCALL if state & LINUX_DESCRIPTOR_INPUT == 0 => LINUX_EBADF,
        LINUX_WRITE_SYSCALL if state & LINUX_DESCRIPTOR_OUTPUT == 0 => LINUX_EBADF,
        LINUX_READ_SYSCALL | LINUX_WRITE_SYSCALL => match device {
            LinuxGraphicsDevice::Input(device) if number == LINUX_READ_SYSCALL => {
                let mut events = [0_u8; crate::linux_input::EVENT_SIZE * 64];
                let wanted = usize::try_from(count)
                    .unwrap_or(usize::MAX)
                    .min(events.len());
                let wanted = wanted - wanted % crate::linux_input::EVENT_SIZE;
                if wanted == 0 {
                    return LINUX_EINVAL;
                }
                // Readers poll first; a read with nothing queued reports
                // EAGAIN rather than blocking.
                let length = crate::linux_input::read(device, &mut events[..wanted]);
                if length == 0 {
                    return LINUX_EAGAIN;
                }
                if !copy_to_linux_user(buffer, &events[..length]) {
                    return LINUX_EFAULT;
                }
                length as u64
            }
            // Injected events are accepted and dropped.
            LinuxGraphicsDevice::Input(_) => count,
            LinuxGraphicsDevice::Framebuffer => {
                linux_framebuffer_transfer(descriptor, buffer, count, number == LINUX_WRITE_SYSCALL)
            }
        },
        _ => LINUX_EINVAL,
    }
}

fn linux_framebuffer_transfer(descriptor: u64, buffer: u64, count: u64, write: bool) -> u64 {
    let offset = linux_descriptor_offset(descriptor);
    let mut position = usize::try_from(offset.load(Ordering::SeqCst)).unwrap_or(usize::MAX);
    let mut remaining = usize::try_from(count).unwrap_or(usize::MAX);
    let mut moved = 0_usize;
    let mut chunk = [0_u8; PAGE_SIZE];
    while remaining != 0 {
        let length = remaining.min(PAGE_SIZE);
        let user = buffer + moved as u64;
        if write && !copy_from_linux_user(user, &mut chunk[..length]) {
            return if moved == 0 {
                LINUX_EFAULT
            } else {
                moved as u64
            };
        }
        let done = crate::framebuffer::transfer(position, &mut chunk[..length], write);
        if !write && !copy_to_linux_user(user, &chunk[..done]) {
            return if moved == 0 {
                LINUX_EFAULT
            } else {
                moved as u64
            };
        }
        moved += done;
        position += done;
        remaining -= length;
        if done < length {
            break;
        }
    }
    offset.store(position as u64, Ordering::SeqCst);
    if write && moved == 0 && count != 0 {
        return LINUX_ENOSPC;
    }
    moved as u64
}

fn linux_framebuffer_ioctl(request: u64, argument: u64) -> u64 {
    const FBIOGET_VSCREENINFO: u64 = 0x4600;
    const FBIOPUT_VSCREENINFO: u64 = 0x4601;
    const FBIOGET_FSCREENINFO: u64 = 0x4602;
    const FBIOPAN_DISPLAY: u64 = 0x4606;
    const FBIOBLANK: u64 = 0x4611;
    const FBIO_WAITFORVSYNC: u64 = 0x4004_4620;
    let Some(display) = crate::framebuffer::display() else {
        return LINUX_ENODEV;
    };
    match request & 0xffff_ffff {
        // The mode is fixed by the firmware, so setting it reports it back.
        FBIOGET_VSCREENINFO | FBIOPUT_VSCREENINFO => {
            let mut info = [0_u32; 40];
            info[0] = display.width;
            info[1] = display.height;
            info[2] = display.width;
            info[3] = display.height;
            info[6] = 32;
            // red, green, blue and transparency bitfields: offset, length.
            let (red, blue) = if display.bgrx { (16, 0) } else { (0, 16) };
            info[8] = red;
            info[9] = 8;
            info[11] = 8;
            info[12] = 8;
            info[14] = blue;
            info[15] = 8;
            info[17] = 24;
            // height and width in millimetres are unknown.
            info[22] = u32::MAX;
            info[23] = u32::MAX;
            let mut bytes = [0_u8; 160];
            for (chunk, value) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(info) {
                chunk.copy_from_slice(&value.to_ne_bytes());
            }
            if copy_to_linux_user(argument, &bytes) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        FBIOGET_FSCREENINFO => {
            let mut info = [0_u8; 80];
            info[..7].copy_from_slice(b"linoxfb");
            info[16..24].copy_from_slice(&display.physical.to_ne_bytes());
            info[24..28].copy_from_slice(&(display.length as u32).to_ne_bytes());
            // FB_TYPE_PACKED_PIXELS, then FB_VISUAL_TRUECOLOR.
            info[36..40].copy_from_slice(&2_u32.to_ne_bytes());
            info[48..52].copy_from_slice(&display.line_length.to_ne_bytes());
            if copy_to_linux_user(argument, &info) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        FBIOPAN_DISPLAY | FBIOBLANK | FBIO_WAITFORVSYNC => 0,
        _ => LINUX_ENOTTY,
    }
}

/// Maps the framebuffer into the caller, after which the kernel console
/// stops drawing until the domain's descriptors are torn down.
fn linux_framebuffer_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    offset: u64,
) -> u64 {
    let Some(display) = crate::framebuffer::display() else {
        return LINUX_ENODEV;
    };
    let mapped = display.length.next_multiple_of(PAGE_SIZE) as u64;
    if flags & LINUX_MAP_SHARED == 0
        || protection & LINUX_PROT_READ == 0
        || length == 0
        || !offset.is_multiple_of(PAGE_SIZE as u64)
        || offset.checked_add(length).is_none_or(|end| end > mapped)
        || !display.physical.is_multiple_of(PAGE_SIZE as u64)
    {
        return LINUX_EINVAL;
    }
    let pages = length.div_ceil(PAGE_SIZE as u64) as usize;
    let fixed = flags & LINUX_MAP_FIXED != 0;
    let Some(mapping) = linux_runtime_select_mapping(address, pages, fixed, false) else {
        return LINUX_ENOMEM;
    };
    if !linux_runtime_range_available(mapping, pages)
        && (!fixed || linux_runtime_munmap(mapping, (pages * PAGE_SIZE) as u64) != 0)
    {
        return LINUX_ENOMEM;
    }
    for page in 0..pages {
        let installed = address_space::install_current_linux_device_page(
            mapping + (page * PAGE_SIZE) as u64,
            display.physical + offset + (page * PAGE_SIZE) as u64,
            protection & LINUX_PROT_WRITE != 0,
            address_space::DeviceCaching::WriteBack,
        );
        if !installed {
            let _ = rollback_linux_runtime_mapping(mapping, page);
            return LINUX_ENOMEM;
        }
    }
    crate::framebuffer::set_owned(true);
    mapping
}

fn linux_evdev_ioctl(device: usize, request: u64, argument: u64) -> u64 {
    const EVIOCGRAB: u64 = 0x4004_4590;
    const EVIOCSCLOCKID: u64 = 0x4004_45a0;
    let request = request & 0xffff_ffff;
    if matches!(request, EVIOCGRAB | EVIOCSCLOCKID) {
        return 0;
    }
    let Some(kind) = crate::linux_input::device_kind(device) else {
        return LINUX_ENODEV;
    };
    // _IOC(direction, 'E', number, size)
    let (direction, size, number) = (request >> 30, (request >> 16) & 0x3fff, request & 0xff);
    if (request >> 8) & 0xff != u64::from(b'E') || direction != 2 {
        return LINUX_ENOTTY;
    }
    let mut reply = [0_u8; 256];
    let length = match number {
        // EVIOCGVERSION
        0x01 => {
            reply[..4].copy_from_slice(&0x0001_0001_u32.to_ne_bytes());
            4
        }
        // EVIOCGID: bus type (USB), vendor, product, version
        0x02 => {
            reply[..2].copy_from_slice(&3_u16.to_ne_bytes());
            8
        }
        // EVIOCGNAME
        0x06 => {
            let name = crate::linux_input::device_name(device);
            let length = name.len().min(size as usize).min(reply.len() - 1);
            reply[..length].copy_from_slice(&name[..length]);
            length + 1
        }
        // EVIOCGPHYS, EVIOCGUNIQ: empty strings
        0x07 | 0x08 => 1,
        // EVIOCGPROP, and the key, LED, sound and switch states: all clear
        0x09 | 0x18..=0x1b => size as usize,
        // EVIOCGBIT(type): supported event types and codes
        0x20..=0x3f => {
            let mut set = |bit: u16| {
                if let Some(byte) = reply.get_mut(usize::from(bit / 8)) {
                    *byte |= 1 << (bit % 8);
                }
            };
            let pointer = !matches!(kind, crate::linux_input::DeviceKind::Keyboard);
            match (number - 0x20) as u16 {
                0 => {
                    set(crate::linux_input::EV_SYN);
                    set(crate::linux_input::EV_KEY);
                    match kind {
                        crate::linux_input::DeviceKind::Keyboard => {}
                        crate::linux_input::DeviceKind::Mouse => set(crate::linux_input::EV_REL),
                        crate::linux_input::DeviceKind::Tablet { .. } => {
                            set(crate::linux_input::EV_ABS);
                            set(crate::linux_input::EV_REL);
                        }
                    }
                }
                crate::linux_input::EV_KEY if pointer => {
                    set(crate::linux_input::BTN_LEFT);
                    set(crate::linux_input::BTN_RIGHT);
                    set(crate::linux_input::BTN_MIDDLE);
                }
                crate::linux_input::EV_KEY => (1..=248).for_each(&mut set),
                crate::linux_input::EV_REL if pointer => {
                    if matches!(kind, crate::linux_input::DeviceKind::Mouse) {
                        set(crate::linux_input::REL_X);
                        set(crate::linux_input::REL_Y);
                    }
                    set(crate::linux_input::REL_WHEEL);
                }
                crate::linux_input::EV_ABS
                    if matches!(kind, crate::linux_input::DeviceKind::Tablet { .. }) =>
                {
                    set(crate::linux_input::ABS_X);
                    set(crate::linux_input::ABS_Y);
                }
                _ => {}
            }
            size as usize
        }
        // EVIOCGABS(axis): value, minimum, maximum, fuzz, flat, resolution
        0x40..=0x7f => {
            let crate::linux_input::DeviceKind::Tablet { maximum } = kind else {
                return LINUX_EINVAL;
            };
            if !matches!(
                (number - 0x40) as u16,
                crate::linux_input::ABS_X | crate::linux_input::ABS_Y
            ) {
                return LINUX_EINVAL;
            }
            reply[8..12].copy_from_slice(&maximum.to_ne_bytes());
            24
        }
        _ => return LINUX_ENOTTY,
    };
    let length = length.min(size as usize).min(reply.len());
    if !copy_to_linux_user(argument, &reply[..length]) {
        return LINUX_EFAULT;
    }
    if matches!(number, 0x06..=0x08) {
        length as u64
    } else {
        0
    }
}

fn linux_key_error(error: crate::linux_keyring::Error) -> u64 {
    (-i64::from(error.errno())) as u64
}

/// Runs `operation` on the domain's keys for the calling thread: its
/// filesystem ids own and access keys, its real ids pick the user keyrings,
/// and it acts for other users (CAP_SYS_ADMIN) only where the domain lets
/// root switch users.
fn linux_with_keys<R>(
    operation: impl FnOnce(
        &mut crate::linux_keyring::Keyrings,
        &crate::linux_keyring::Caller,
    ) -> Result<R, crate::linux_keyring::Error>,
) -> Result<R, u64> {
    let pid = current_linux_process_pid();
    let tid = current_linux_tid().unwrap_or(pid);
    let credentials = current_linux_credentials().unwrap_or(linux_user::Credentials::ROOT);
    let privileged = current_linux_user_namespace().is_some_and(|namespace| {
        linux_user::identity_authority(namespace, &credentials).privileged
    });
    let groups = linux_process::with_live_process_groups(pid, |groups| {
        let mut copy = Vec::new();
        copy.try_reserve_exact(groups.len()).ok()?;
        copy.extend_from_slice(groups);
        Some(copy)
    })
    .flatten()
    .unwrap_or_default();
    let caller = crate::linux_keyring::Caller {
        uid: credentials.user.filesystem,
        gid: credentials.group.filesystem,
        groups: &groups,
        real_uid: credentials.user.real,
        real_gid: credentials.group.real,
        pid,
        tid,
        privileged,
    };
    let limits = linux_key_limits();
    let now = linux_key_clock();
    let gc_delay = linux_proc_sysctl_value(b"sys/kernel/keys/gc_delay")
        .and_then(|seconds| u64::try_from(seconds).ok())
        .unwrap_or(LINUX_KEY_GC_DELAY_SECONDS)
        .saturating_mul(NANOSECONDS_PER_SECOND);
    crate::linux_keyring::with(|keys| {
        keys.set_limits(limits)?;
        keys.collect_garbage(now, gc_delay);
        operation(keys, &caller)
    })
    .map_err(linux_key_error)
}

/// Linux's default /proc/sys/kernel/keys/gc_delay.
const LINUX_KEY_GC_DELAY_SECONDS: u64 = 300;

/// Process `pid` ended: its threads' and its own keyrings go, as Linux
/// drops them with the tasks' credentials, and keys only they kept leave
/// their owners' quotas. Skipped (left to the next fork that reuses the
/// id) when a lock ranked above the keys' is held.
fn release_linux_process_keys(pid: u32) {
    crate::linux_path_views::forget(linux_execution_instance(), pid);
    if crate::sync::rank_available(crate::sync::LockRank::KEYRINGS) {
        let _ = crate::linux_keyring::with(|keys| {
            keys.exit_process(pid);
            Ok(())
        });
    }
}

/// The domain's key quotas: /proc/sys/kernel/keys as written, else Linux's
/// defaults.
fn linux_key_limits() -> linox_keyrings::Limits {
    let defaults = linox_keyrings::Limits::LINUX;
    let value = |path: &[u8], default: u32| {
        linux_proc_sysctl_value(path)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(default)
    };
    linox_keyrings::Limits {
        root_max_keys: value(b"sys/kernel/keys/root_maxkeys", defaults.root_max_keys),
        root_max_bytes: value(b"sys/kernel/keys/root_maxbytes", defaults.root_max_bytes),
        max_keys: value(b"sys/kernel/keys/maxkeys", defaults.max_keys),
        max_bytes: value(b"sys/kernel/keys/maxbytes", defaults.max_bytes),
    }
}

/// The kernel clock the key service measures timeouts with.
fn linux_key_clock() -> u64 {
    linux_elapsed_nanoseconds().unwrap_or(0)
}

/// Copies a NUL-terminated key argument that fits in `limit` bytes with its
/// NUL; a longer one is EINVAL, as Linux's strndup_user makes it.
fn linux_key_string(address: u64, limit: usize) -> Result<Vec<u8>, u64> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(limit).map_err(|_| LINUX_ENOMEM)?;
    buffer.resize(limit, 0);
    match copy_linux_c_string(address, &mut buffer) {
        Ok(length) => {
            buffer.truncate(length);
            Ok(buffer)
        }
        Err(LINUX_ENAMETOOLONG) => Err(LINUX_EINVAL),
        Err(error) => Err(error),
    }
}

/// Copies a key type name, refusing reserved names (EPERM) before any later
/// argument is read, as Linux does.
fn linux_key_type(address: u64) -> Result<Vec<u8>, u64> {
    let name = linux_key_string(address, linox_keyrings::TYPE_LIMIT)?;
    linox_keyrings::check_type_name(&name).map_err(linux_key_error)?;
    Ok(name)
}

/// Copies `length` bytes of key payload from `address`.
fn linux_key_payload(address: u64, length: usize) -> Result<Vec<u8>, u64> {
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| LINUX_ENOMEM)?;
    payload.resize(length, 0);
    if length != 0 && !copy_from_linux_user(address, &mut payload) {
        return Err(LINUX_EFAULT);
    }
    Ok(payload)
}

/// Copies what `output` gives a buffer of `capacity` bytes at `address`
/// (nothing for a null buffer) and returns the output's full length.
fn linux_key_output(output: &crate::linux_keyring::Output, address: u64, capacity: u64) -> u64 {
    let bytes = if address == 0 {
        &[][..]
    } else {
        output.for_buffer(usize::try_from(capacity).unwrap_or(usize::MAX))
    };
    if !bytes.is_empty() && !copy_to_linux_user(address, bytes) {
        return LINUX_EFAULT;
    }
    output.len() as u64
}

fn linux_add_key(
    type_address: u64,
    description_address: u64,
    payload_address: u64,
    payload_length: u64,
    keyring: u64,
) -> u64 {
    let Some(payload_length) = usize::try_from(payload_length)
        .ok()
        .filter(|length| *length <= linox_keyrings::PAYLOAD_LIMIT)
    else {
        return LINUX_EINVAL;
    };
    let added = (|| {
        let key_type = linux_key_type(type_address)?;
        let description = if description_address == 0 {
            Vec::new()
        } else {
            linux_key_string(description_address, linox_keyrings::DESCRIPTION_LIMIT)?
        };
        if key_type == b"keyring" && description.first() == Some(&b'.') {
            return Err(LINUX_EPERM);
        }
        let payload = linux_key_payload(payload_address, payload_length)?;
        let now = linux_key_clock();
        linux_with_keys(|keys, caller| {
            keys.add_key(
                caller,
                &key_type,
                &description,
                &payload,
                keyring as i32,
                now,
            )
        })
    })();
    added.map_or_else(|error| error, |serial| serial as u64)
}

fn linux_request_key(
    type_address: u64,
    description_address: u64,
    callout_address: u64,
    destination: u64,
) -> u64 {
    let requested = (|| {
        let key_type = linux_key_type(type_address)?;
        let description = linux_key_string(description_address, linox_keyrings::DESCRIPTION_LIMIT)?;
        let callout = if callout_address == 0 {
            None
        } else {
            Some(linux_key_string(
                callout_address,
                linox_keyrings::CALLOUT_LIMIT,
            )?)
        };
        let now = linux_key_clock();
        linux_with_keys(|keys, caller| {
            keys.request_key(
                caller,
                &key_type,
                &description,
                callout.as_deref(),
                destination as i32,
                now,
            )
        })
    })();
    requested.map_or_else(|error| error, |serial| serial as u64)
}

fn linux_keyctl(command: u64, second: u64, third: u64, fourth: u64, fifth: u64) -> u64 {
    const GET_KEYRING_ID: u64 = 0;
    const JOIN_SESSION_KEYRING: u64 = 1;
    const UPDATE: u64 = 2;
    const REVOKE: u64 = 3;
    const CHOWN: u64 = 4;
    const SETPERM: u64 = 5;
    const DESCRIBE: u64 = 6;
    const CLEAR: u64 = 7;
    const LINK: u64 = 8;
    const UNLINK: u64 = 9;
    const SEARCH: u64 = 10;
    const READ: u64 = 11;
    const INSTANTIATE: u64 = 12;
    const NEGATE: u64 = 13;
    const SET_REQKEY_KEYRING: u64 = 14;
    const SET_TIMEOUT: u64 = 15;
    const ASSUME_AUTHORITY: u64 = 16;
    const GET_SECURITY: u64 = 17;
    const SESSION_TO_PARENT: u64 = 18;
    const REJECT: u64 = 19;
    const INSTANTIATE_IOV: u64 = 20;
    const INVALIDATE: u64 = 21;
    const DH_COMPUTE: u64 = 23;
    const PKEY_QUERY: u64 = 24;
    const RESTRICT_KEYRING: u64 = 29;
    const MOVE: u64 = 30;
    const CAPABILITIES: u64 = 31;
    let id = second as i32;
    let now = linux_key_clock();
    let unit = |result: Result<(), u64>| result.map_or_else(|error| error, |()| 0);
    let serial = |result: Result<i32, u64>| result.map_or_else(|error| error, |id| id as u64);
    let output = |result: Result<crate::linux_keyring::Output, u64>| {
        result.map_or_else(
            |error| error,
            |output| linux_key_output(&output, third, fourth),
        )
    };
    match command {
        GET_KEYRING_ID => serial(linux_with_keys(|keys, caller| {
            keys.get_keyring_id(caller, id, third as i32 != 0, now)
        })),
        JOIN_SESSION_KEYRING => serial((|| {
            let name = if second == 0 {
                None
            } else {
                Some(linux_key_string(second, linox_keyrings::DESCRIPTION_LIMIT)?)
            };
            linux_with_keys(|keys, caller| keys.join_session_keyring(caller, name.as_deref()))
        })()),
        UPDATE => unit((|| {
            let length = usize::try_from(fourth)
                .ok()
                .filter(|length| *length <= linox_keyrings::UPDATE_LIMIT)
                .ok_or(LINUX_EINVAL)?;
            let payload = linux_key_payload(third, length)?;
            linux_with_keys(|keys, caller| keys.update(caller, id, &payload, now))
        })()),
        REVOKE => unit(linux_with_keys(|keys, caller| keys.revoke(caller, id, now))),
        CHOWN => {
            let change = |raw: u64| (raw as u32 != u32::MAX).then_some(raw as u32);
            unit(linux_with_keys(|keys, caller| {
                keys.chown(caller, id, change(third), change(fourth), now)
            }))
        }
        SETPERM => unit(linux_with_keys(|keys, caller| {
            keys.set_permissions(caller, id, third as u32, now)
        })),
        DESCRIBE => output(linux_with_keys(|keys, caller| {
            keys.describe(caller, id, now)
        })),
        CLEAR => unit(linux_with_keys(|keys, caller| keys.clear(caller, id, now))),
        LINK => unit(linux_with_keys(|keys, caller| {
            keys.link(caller, id, third as i32, now)
        })),
        UNLINK => unit(linux_with_keys(|keys, caller| {
            keys.unlink(caller, id, third as i32, now)
        })),
        SEARCH => serial((|| {
            let key_type = linux_key_type(third)?;
            let description = linux_key_string(fourth, linox_keyrings::DESCRIPTION_LIMIT)?;
            linux_with_keys(|keys, caller| {
                keys.search(caller, id, &key_type, &description, fifth as i32, now)
            })
        })()),
        READ => {
            let capacity = if third == 0 {
                0
            } else {
                usize::try_from(fourth).unwrap_or(usize::MAX)
            };
            output(linux_with_keys(|keys, caller| {
                keys.read_into(caller, id, capacity, now)
            }))
        }
        INSTANTIATE | NEGATE | REJECT | INSTANTIATE_IOV => LINUX_EPERM,
        SET_REQKEY_KEYRING => serial(linux_with_keys(|keys, caller| {
            keys.set_request_default(caller, id)
        })),
        SET_TIMEOUT => unit(linux_with_keys(|keys, caller| {
            keys.set_timeout(caller, id, third as u32, now)
        })),
        // No upcalls, so there is never an authorization key to assume.
        ASSUME_AUTHORITY => match id {
            0 => 0,
            id if id < 0 => LINUX_EINVAL,
            _ => LINUX_ENOKEY,
        },
        GET_SECURITY => output(linux_with_keys(|keys, caller| {
            keys.get_security(caller, id, now)
        })),
        SESSION_TO_PARENT => unit(linux_keyctl_session_to_parent(now)),
        INVALIDATE => unit(linux_with_keys(|keys, caller| {
            keys.invalidate(caller, id, now)
        })),
        DH_COMPUTE => {
            linux_keyctl_dh_compute(second, third, fourth, fifth, now).unwrap_or_else(|error| error)
        }
        // The argument after the key id is reserved and must be 0.
        PKEY_QUERY if third != 0 => LINUX_EINVAL,
        PKEY_QUERY => unit((|| {
            let info = linux_key_string(fourth, 4096)?;
            let query = linux_with_keys(|keys, caller| keys.pkey_query(caller, id, &info, now))?;
            if !copy_to_linux_user(fifth, &query.to_bytes()) {
                return Err(LINUX_EFAULT);
            }
            Ok(())
        })()),
        RESTRICT_KEYRING => unit((|| {
            let key_type = if third == 0 {
                None
            } else {
                Some(linux_key_type(third)?)
            };
            let restriction = if fourth == 0 {
                None
            } else {
                Some(linux_key_string(fourth, linox_keyrings::DESCRIPTION_LIMIT)?)
            };
            linux_with_keys(|keys, caller| {
                keys.restrict_keyring(caller, id, key_type.as_deref(), restriction.as_deref(), now)
            })
        })()),
        MOVE => unit(linux_with_keys(|keys, caller| {
            keys.move_key(caller, id, third as i32, fourth as i32, fifth as u32, now)
        })),
        CAPABILITIES => crate::linux_keyring::Keyrings::capabilities()
            .map_err(linux_key_error)
            .map_or_else(
                |error| error,
                |output| linux_key_output(&output, second, third),
            ),
        _ => LINUX_EOPNOTSUPP,
    }
}

/// KEYCTL_DH_COMPUTE in Linux's order of checks: the KDF parameters
/// (`struct keyctl_kdf_params`) are copied first; then the parameters must
/// be given and a nonzero length needs a buffer (EINVAL); a KDF must have
/// zeroed spare words (EINVAL), ask for at most 1024 bytes with at most 64
/// of other information (EMSGSIZE) and name a known hash (ENOENT), all
/// before the keys are read. Without a KDF a zero length only asks for the
/// size and a buffer too small for the value is EOVERFLOW. Returns the
/// length written.
fn linux_keyctl_dh_compute(
    parameters: u64,
    buffer: u64,
    length: u64,
    kdf: u64,
    now: u64,
) -> Result<u64, u64> {
    use linox_keyrings::dh;
    const KDF_BYTES: usize = 56;
    let kdf = if kdf == 0 {
        None
    } else {
        let mut raw = [0_u8; KDF_BYTES];
        if !copy_from_linux_user(kdf, &mut raw) {
            return Err(LINUX_EFAULT);
        }
        Some(raw)
    };
    if parameters == 0 || (buffer == 0 && length != 0) {
        return Err(LINUX_EINVAL);
    }
    let mut ids = [0_u8; 12];
    if !copy_from_linux_user(parameters, &mut ids) {
        return Err(LINUX_EFAULT);
    }
    let id = |index: usize| {
        let bytes = ids.as_chunks::<4>().0[index];
        i32::from_ne_bytes(bytes)
    };
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    let derivation = match kdf {
        None => None,
        Some(raw) => {
            let address = |offset: usize| {
                u64::from_ne_bytes(raw[offset..offset + 8].try_into().unwrap_or_default())
            };
            let other_length =
                u32::from_ne_bytes(raw[16..20].try_into().unwrap_or_default()) as usize;
            if raw[20..52].iter().any(|byte| *byte != 0) {
                return Err(LINUX_EINVAL);
            }
            if length > dh::KDF_OUTPUT_LIMIT || other_length > dh::KDF_OTHER_INFO_LIMIT {
                return Err(LINUX_EMSGSIZE);
            }
            let hash = linux_key_string(address(0), dh::HASH_NAME_LIMIT)?;
            dh::check_hash(&hash).map_err(linux_key_error)?;
            Some((hash, address(8), other_length))
        }
    };
    let mut secret =
        linux_with_keys(|keys, caller| keys.dh_compute(caller, id(0), id(1), id(2), now))?;
    let Some((hash, other_address, other_length)) = derivation else {
        if length == 0 {
            return Ok(secret.len() as u64);
        }
        if secret.len() > length {
            return Err(LINUX_EOVERFLOW);
        }
        if !copy_to_linux_user(buffer, &secret) {
            return Err(LINUX_EFAULT);
        }
        return Ok(secret.len() as u64);
    };
    let other = linux_key_payload(other_address, other_length)?;
    secret
        .try_reserve_exact(other.len())
        .map_err(|_| LINUX_ENOMEM)?;
    secret.extend_from_slice(&other);
    let derived = dh::derive(&hash, &secret, length).map_err(linux_key_error)?;
    if !derived.is_empty() && !copy_to_linux_user(buffer, &derived) {
        return Err(LINUX_EFAULT);
    }
    Ok(derived.len() as u64)
}

/// KEYCTL_SESSION_TO_PARENT: the parent takes the caller's session keyring.
/// Like Linux, it refuses (EPERM) a parent that is init, has other threads,
/// or does not run with the caller's effective ids.
fn linux_keyctl_session_to_parent(now: u64) -> Result<(), u64> {
    let pid = current_linux_process_pid();
    let credentials = current_linux_credentials().ok_or(LINUX_ESRCH)?;
    let parent = linux_process::live_process_parent_pid(pid)
        .filter(|parent| *parent > 1)
        .ok_or(LINUX_EPERM)?;
    let parent_credentials = linux_process::live_process_credentials(parent).ok_or(LINUX_EPERM)?;
    let (user, group) = (credentials.user.effective, credentials.group.effective);
    let same_owner = [
        parent_credentials.user.real,
        parent_credentials.user.effective,
        parent_credentials.user.saved,
    ]
    .iter()
    .all(|id| *id == user)
        && [
            parent_credentials.group.real,
            parent_credentials.group.effective,
            parent_credentials.group.saved,
        ]
        .iter()
        .all(|id| *id == group);
    if !same_owner || linux_process_thread_count(parent) > 1 {
        return Err(LINUX_EPERM);
    }
    linux_with_keys(|keys, caller| keys.session_to_parent(caller, parent, now))
}

fn copy_linux_id_triple(first: u64, second: u64, third: u64, ids: (u32, u32, u32)) -> u64 {
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
fn linux_capget(header_address: u64, data_address: u64) -> u64 {
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
fn linux_capset(header_address: u64, data_address: u64) -> u64 {
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

/// sched_setscheduler(2): SCHED_OTHER, BATCH and IDLE take priority 0 from
/// anyone; FIFO and RR take 1..=99 from a privileged caller (CAP_SYS_NICE);
/// SCHED_DEADLINE needs sched_setattr. The policy and priority are kept
/// per process for sched_getscheduler and sched_getparam, with
/// SCHED_RESET_ON_FORK, which gives the process's children SCHED_OTHER.
fn linux_set_scheduler(pid: u64, policy: u64, parameter_address: u64) -> u64 {
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
fn linux_sched_setparam(pid: u64, parameter_address: u64) -> u64 {
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
fn linux_sched_setattr(pid: u64, attribute_address: u64, flags: u64) -> u64 {
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
fn linux_sched_getattr(pid: u64, attribute_address: u64, size: u64, flags: u64) -> u64 {
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

fn linux_personality(requested: u64) -> u64 {
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

fn linux_arch_prctl(option: u64, argument: u64) -> u64 {
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

/// Runs `change` on the calling process's credentials and keeps what it
/// leaves: its result, or EINVAL or EPERM for its error.
fn linux_current_credentials_result(
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

fn linux_prctl(option: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) -> u64 {
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

fn linux_modify_ldt(function: u64, address: u64, byte_count: u64) -> u64 {
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

pub(crate) fn force_next_control_discovery(domain_id: u64, discovery_word: u64) -> bool {
    if domain_id == 0
        || CONTROL_DISCOVERY_OVERRIDE_DOMAIN
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return false;
    }
    CONTROL_DISCOVERY_OVERRIDE_WORD.store(discovery_word, Ordering::Release);
    CONTROL_DISCOVERY_OVERRIDE_DOMAIN.store(domain_id, Ordering::Release);
    true
}

pub(crate) fn force_next_control_descriptor_reserved(domain_id: u64) -> bool {
    domain_id != 0
        && CONTROL_DESCRIPTOR_OVERRIDE_DOMAIN
            .compare_exchange(0, domain_id, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}

fn dispatch_charged_call(
    number: u64,
    capability: u64,
    caller_domain: u64,
    frame: *mut UserTrapFrame,
) -> u64 {
    match number {
        0 => {
            if CONTROL_DISCOVERY_OVERRIDE_DOMAIN
                .compare_exchange(caller_domain, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                CONTROL_DISCOVERY_OVERRIDE_WORD.load(Ordering::Acquire)
            } else {
                control_abi::DISCOVERY_WORD
            }
        }
        1 => {
            if domain::handle_permits(caller_domain, capability, 1, Rights::READ) {
                SYSCALL_STATE.fetch_or(2, Ordering::SeqCst);
                0x4758
            } else {
                SYSCALL_STATE.fetch_or(1, Ordering::SeqCst);
                u64::MAX - 1
            }
        }
        3 => runtime_result(frame),
        4 => {
            let Some(frame) = (unsafe { frame.as_ref() }) else {
                return u64::MAX;
            };
            let message = frame.first_argument();
            if domain::handle_permits(caller_domain, capability, 3, Rights::WRITE)
                && ipc::send_or_wake(caller_domain, message, |service_side, sequence| {
                    scheduler::wake_ipc_peer(caller_domain, 3, service_side, message, sequence)
                })
            {
                timer::mark_scheduler_preemption_ready();
                0
            } else {
                u64::MAX - 2
            }
        }
        5 => {
            if domain::handle_permits(caller_domain, capability, 3, Rights::READ) {
                match ipc::receive(caller_domain) {
                    ipc::Receive::Message(message) => message,
                    ipc::Receive::PeerClosed(_) => scheduler::IPC_PEER_CLOSED,
                    ipc::Receive::Empty => u64::MAX - 2,
                }
            } else {
                u64::MAX - 2
            }
        }
        6 => console_write(caller_domain, capability, frame),
        7 => {
            if domain::handle_permits(caller_domain, capability, 1, Rights::MANAGE) {
                domain::take_lifecycle_event().unwrap_or(u64::MAX - 2)
            } else {
                u64::MAX - 2
            }
        }
        8 => blocking_receive(caller_domain, capability, frame),
        9 => console_write_buffer(caller_domain, capability, frame),
        10 => write_abi_descriptor(caller_domain, frame),
        11 => write_fault_descriptor(caller_domain, capability, frame),
        12 => write_lifecycle_descriptor(caller_domain, capability, frame),
        13 => write_ipc_delivery_descriptor(caller_domain, capability, frame),
        14 => write_lifecycle_identity_descriptor(caller_domain, capability, frame),
        15 => create_auxiliary_service(caller_domain, capability, frame),
        16 => network_device_call(caller_domain, capability, frame),
        17 => root_device_call(caller_domain, capability, frame),
        18 => volume_device_call(caller_domain, capability, frame),
        19 => block_device_call(caller_domain, capability, frame),
        20 => network_wait_call(caller_domain, capability, frame),
        control_abi::CONSOLE_READ_LINE_OPERATION => {
            console_read_line(caller_domain, capability, frame)
        }
        linox_native_abi::NATIVE_CONSOLE_READ_BYTE_OPERATION => {
            console_read_byte(caller_domain, capability, frame)
        }
        control_abi::HOST_INSPECT_OPERATION => host_inspect(caller_domain, capability, frame),
        control_abi::DOMAIN_CONTROL_OPERATION => {
            container_control(caller_domain, capability, frame)
        }
        control_abi::LINUX_ABI_TEST_OPERATION => {
            linux_abi_test_results(caller_domain, capability, frame)
        }
        linox_native_abi::NATIVE_IMAGE_STORE_OPERATION => {
            image_store_call(caller_domain, capability, frame)
        }
        linox_native_abi::NATIVE_PROGRESS_OPERATION => {
            native_progress_call(caller_domain, capability, frame)
        }
        linox_native_abi::NATIVE_NETWORK_INVENTORY_OPERATION => {
            network_inventory_call(caller_domain, capability, frame)
        }
        // The frequency is the one the Linux clock profile already trusts; it
        // grants no authority, so no capability is required.
        linox_native_abi::NATIVE_TIMESTAMP_FREQUENCY_OPERATION => timer::monotonic_frequency()
            .unwrap_or(linox_native_abi::NATIVE_TIMESTAMP_FREQUENCY_UNAVAILABLE),
        control_abi::PACKET_PUBLISH_OPERATION => {
            packet_publish_call(caller_domain, capability, frame)
        }
        control_abi::PACKET_CONSUME_OPERATION => {
            packet_consume_call(caller_domain, capability, frame)
        }
        control_abi::PACKET_WAIT_OPERATION => {
            packet_wait_call(caller_domain, capability, frame, None)
        }
        control_abi::PACKET_WAIT_TIMEOUT_OPERATION => {
            let timeout_ms = unsafe { frame.as_ref() }.map(UserTrapFrame::second_argument);
            packet_wait_call(caller_domain, capability, frame, timeout_ms)
        }
        control_abi::PACKET_SPACE_WAIT_OPERATION => {
            packet_space_wait_call(caller_domain, capability, frame)
        }
        control_abi::PACKET_EGRESS_CLAIM_OPERATION => {
            packet_egress_claim_call(caller_domain, capability, frame)
        }
        control_abi::PACKET_EGRESS_ACK_OPERATION => {
            packet_egress_ack_call(caller_domain, capability, frame)
        }
        control_abi::PACKET_EGRESS_WAIT_OPERATION => packet_wait_call_for_object(
            caller_domain,
            capability,
            frame,
            None,
            control_abi::PACKET_EGRESS_OBJECT,
        ),
        control_abi::PACKET_EGRESS_SPACE_WAIT_OPERATION => packet_space_wait_call_for_object(
            caller_domain,
            capability,
            frame,
            control_abi::PACKET_EGRESS_OBJECT,
        ),
        control_abi::PACKET_EGRESS_DRAIN_WAIT_OPERATION => {
            packet_egress_drain_wait_call(caller_domain, capability, frame)
        }
        _ => u64::MAX,
    }
}

fn native_progress_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    if !domain::handle_permits(
        caller_domain,
        capability,
        linox_native_abi::NATIVE_IMAGE_STORE_OBJECT,
        Rights::WRITE,
    ) {
        return u64::MAX - 2;
    }
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let Ok(size) = usize::try_from(frame.second_argument()) else {
        return u64::MAX - 2;
    };
    if size == 0 || size > linox_native_abi::NATIVE_PROGRESS_MAX_SIZE {
        return u64::MAX - 2;
    }
    let mut bytes = [0; linox_native_abi::NATIVE_PROGRESS_MAX_SIZE];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut bytes[..size])
        || !bytes[..size]
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        return u64::MAX - 2;
    }
    if oci_progress_is_console_visible(&bytes[..size]) {
        serial_write("linox: OCI ");
        crate::serial_write_bytes(&bytes[..size]);
        serial_write("\r\n");
    }
    if domain::renew_auxiliary_call_epoch(caller_domain) {
        size as u64
    } else {
        u64::MAX - 2
    }
}

fn oci_progress_is_console_visible(message: &[u8]) -> bool {
    message == b"authenticating with registry"
        || message == b"pulling image manifest"
        || message == b"pulling image configuration"
        || message == b"image configuration verified"
        || message.starts_with(b"manifest selected for ")
        || message.starts_with(b"layer ")
        || contains_bytes(message, b"failed")
        || contains_bytes(message, b"rejected")
        || contains_bytes(message, b"unavailable")
        || contains_bytes(message, b"exceeded")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn image_store_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let failed = linox_native_abi::NATIVE_IMAGE_STORE_RESULT_FAILED;
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return failed;
    };
    if !domain::handle_permits(
        caller_domain,
        capability,
        linox_native_abi::NATIVE_IMAGE_STORE_OBJECT,
        Rights::WRITE,
    ) {
        return failed;
    }
    let mut request = [0_u8; linox_native_abi::NATIVE_IMAGE_STORE_REQUEST_SIZE as usize];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut request)
        || u32::from_le_bytes(request[0..4].try_into().unwrap())
            != linox_native_abi::NATIVE_IMAGE_STORE_REQUEST_SIZE
        || u16::from_le_bytes(request[4..6].try_into().unwrap())
            != linox_native_abi::NATIVE_IMAGE_STORE_REQUEST_VERSION
        || request[36..40] != [0; 4]
    {
        return failed;
    }
    let command = u16::from_le_bytes(request[6..8].try_into().unwrap());
    let raw_handle = u64::from_le_bytes(request[8..16].try_into().unwrap());
    let expected_length = u64::from_le_bytes(request[16..24].try_into().unwrap());
    let buffer_address = u64::from_le_bytes(request[24..32].try_into().unwrap());
    let buffer_size = u32::from_le_bytes(request[32..36].try_into().unwrap());
    let digest: [u8; 32] = request[40..72].try_into().unwrap();
    let result = match command {
        linox_native_abi::NATIVE_IMAGE_STORE_STAGE
            if raw_handle == 0
                && buffer_address == 0
                && buffer_size == 0
                && expected_length != 0
                && digest != [0; 32] =>
        {
            let Ok(expected_length) = usize::try_from(expected_length) else {
                return failed;
            };
            image_store::stage(digest, expected_length)
                .map(linox_image_store::StagingHandle::into_raw)
                .unwrap_or(failed)
        }
        linox_native_abi::NATIVE_IMAGE_STORE_APPEND
            if expected_length == 0
                && digest == [0; 32]
                && (1..=linox_native_abi::NATIVE_IMAGE_STORE_CHUNK_LIMIT)
                    .contains(&buffer_size) =>
        {
            let Some(handle) = linox_image_store::StagingHandle::from_raw(raw_handle) else {
                return failed;
            };
            let mut bytes = [0_u8; linox_native_abi::NATIVE_IMAGE_STORE_CHUNK_LIMIT as usize];
            let size = buffer_size as usize;
            if !address_space::copy_from_current_user(buffer_address, &mut bytes[..size]) {
                return failed;
            }
            image_store::append(handle, &bytes[..size])
                .map(|written| written as u64)
                .unwrap_or(failed)
        }
        linox_native_abi::NATIVE_IMAGE_STORE_PUBLISH
            if expected_length == 0
                && buffer_address == 0
                && buffer_size == 0
                && digest == [0; 32] =>
        {
            let Some(handle) = linox_image_store::StagingHandle::from_raw(raw_handle) else {
                return failed;
            };
            image_store::publish(handle).map_or(failed, |_| 0)
        }
        linox_native_abi::NATIVE_IMAGE_STORE_ABORT
            if expected_length == 0
                && buffer_address == 0
                && buffer_size == 0
                && digest == [0; 32] =>
        {
            let Some(handle) = linox_image_store::StagingHandle::from_raw(raw_handle) else {
                return failed;
            };
            image_store::abort(handle).map_or(failed, |()| 0)
        }
        _ => failed,
    };
    if result != failed && !domain::renew_auxiliary_call_epoch(caller_domain) {
        failed
    } else {
        result
    }
}

struct PacketRequest {
    buffer_address: u64,
    buffer_size: usize,
    expected_sequence: u64,
}

fn packet_request(address: u64) -> Option<PacketRequest> {
    let mut bytes = [0_u8; control_abi::PACKET_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut bytes)
        || u32::from_le_bytes(bytes[0..4].try_into().ok()?) as usize
            != control_abi::PACKET_REQUEST_SIZE
        || u16::from_le_bytes(bytes[4..6].try_into().ok()?) != control_abi::PACKET_REQUEST_VERSION
        || bytes[6..8] != [0, 0]
        || bytes[20..24] != [0, 0, 0, 0]
    {
        return None;
    }
    Some(PacketRequest {
        buffer_address: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
        buffer_size: usize::try_from(u32::from_le_bytes(bytes[16..20].try_into().ok()?)).ok()?,
        expected_sequence: u64::from_le_bytes(bytes[24..32].try_into().ok()?),
    })
}

fn packet_publish_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let Some(request) = packet_request(frame.first_argument()) else {
        return u64::MAX - 2;
    };
    let ingress = domain::handle_permits(
        caller_domain,
        capability,
        control_abi::PACKET_OBJECT,
        Rights::WRITE,
    );
    let egress = domain::handle_permits(
        caller_domain,
        capability,
        control_abi::PACKET_EGRESS_OBJECT,
        Rights::WRITE,
    );
    if request.expected_sequence != 0
        || !(1..=control_abi::PACKET_MAX_SIZE).contains(&request.buffer_size)
        || ingress == egress
    {
        return u64::MAX - 2;
    }
    let mut packet = [0_u8; control_abi::PACKET_MAX_SIZE];
    if !address_space::copy_from_current_user(
        request.buffer_address,
        &mut packet[..request.buffer_size],
    ) {
        return u64::MAX - 2;
    }
    let result = if egress {
        crate::packet::publish_egress(caller_domain, &packet[..request.buffer_size])
    } else {
        crate::packet::publish(caller_domain, &packet[..request.buffer_size])
    };
    match result {
        Ok(sequence) => {
            if ingress {
                if scheduler::wake_packet_waiter(caller_domain, sequence) {
                    let _ = timer::cancel_packet_wait_timer_for_sequence(sequence);
                }
            } else {
                let _ = scheduler::wake_egress_waiter(caller_domain, sequence);
            }
            timer::mark_scheduler_preemption_ready();
            sequence
        }
        Err(_) => u64::MAX - 2,
    }
}

fn packet_consume_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let Some(request) = packet_request(frame.first_argument()) else {
        return u64::MAX - 2;
    };
    let ingress = domain::handle_permits(
        caller_domain,
        capability,
        control_abi::PACKET_OBJECT,
        Rights::READ,
    );
    let egress = domain::handle_permits(
        caller_domain,
        capability,
        control_abi::PACKET_EGRESS_OBJECT,
        Rights::READ,
    );
    if request.expected_sequence == 0
        || !(1..=control_abi::PACKET_MAX_SIZE).contains(&request.buffer_size)
        || ingress == egress
    {
        return u64::MAX - 2;
    }
    let result = if egress {
        crate::packet::consume_egress_with(
            request.expected_sequence,
            request.buffer_size,
            |_, packet| address_space::copy_to_current_user(request.buffer_address, packet),
        )
    } else {
        crate::packet::consume_with(
            request.expected_sequence,
            request.buffer_size,
            |_, packet| address_space::copy_to_current_user(request.buffer_address, packet),
        )
    };
    match result {
        Ok(metadata) => {
            let woke = if ingress {
                scheduler::wake_packet_space_waiter(caller_domain)
            } else {
                scheduler::wake_egress_space_waiter(caller_domain)
            };
            if woke {
                timer::mark_scheduler_preemption_ready();
            }
            metadata.length as u64
        }
        Err(crate::packet::PacketError::Stale) => control_abi::PACKET_RESULT_STALE,
        Err(_) => u64::MAX - 2,
    }
}

fn packet_egress_claim_call(
    caller_domain: u64,
    capability: u64,
    frame: *const UserTrapFrame,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let Some(request) = packet_request(frame.first_argument()) else {
        return u64::MAX - 2;
    };
    if request.expected_sequence == 0
        || !(1..=control_abi::PACKET_MAX_SIZE).contains(&request.buffer_size)
        || !domain::handle_permits(
            caller_domain,
            capability,
            control_abi::PACKET_EGRESS_OBJECT,
            Rights::READ,
        )
    {
        return u64::MAX - 2;
    }
    match crate::packet::claim_egress_with(
        caller_domain,
        request.expected_sequence,
        request.buffer_size,
        |_, packet| address_space::copy_to_current_user(request.buffer_address, packet),
    ) {
        Ok(metadata) => metadata.length as u64,
        Err(crate::packet::PacketError::Stale) => control_abi::PACKET_RESULT_STALE,
        Err(_) => u64::MAX - 2,
    }
}

fn packet_egress_ack_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let Some(request) = packet_request(frame.first_argument()) else {
        return u64::MAX - 2;
    };
    if request.buffer_address != 0
        || request.buffer_size != 0
        || request.expected_sequence == 0
        || !domain::handle_permits(
            caller_domain,
            capability,
            control_abi::PACKET_EGRESS_OBJECT,
            Rights::READ,
        )
        || !address_space::auxiliary_network_egress_transmit_complete(caller_domain)
    {
        return u64::MAX - 2;
    }
    match crate::packet::acknowledge_egress(caller_domain, request.expected_sequence) {
        Ok(_) => {
            if !address_space::record_auxiliary_network_egress_ack(caller_domain) {
                return u64::MAX - 2;
            }
            if scheduler::wake_egress_space_waiter(caller_domain) {
                timer::mark_scheduler_preemption_ready();
            }
            if crate::packet::egress_is_empty()
                && scheduler::wake_egress_drain_waiter(caller_domain)
            {
                timer::mark_scheduler_preemption_ready();
            }
            0
        }
        Err(crate::packet::PacketError::Stale) => control_abi::PACKET_RESULT_STALE,
        Err(_) => u64::MAX - 2,
    }
}

fn packet_wait_call(
    caller_domain: u64,
    capability: u64,
    frame: *mut UserTrapFrame,
    timeout_ms: Option<u64>,
) -> u64 {
    packet_wait_call_for_object(
        caller_domain,
        capability,
        frame,
        timeout_ms,
        control_abi::PACKET_OBJECT,
    )
}

fn packet_wait_call_for_object(
    caller_domain: u64,
    capability: u64,
    frame: *mut UserTrapFrame,
    timeout_ms: Option<u64>,
    object: u64,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    let Some(request) = packet_request(frame.first_argument()) else {
        return u64::MAX - 2;
    };
    if request.buffer_address != 0
        || request.buffer_size != 0
        || timeout_ms.is_some_and(|timeout| timeout > control_abi::PACKET_WAIT_MAX_TIMEOUT_MS)
    {
        return u64::MAX - 2;
    }
    if request.expected_sequence == 0 {
        return u64::MAX - 2;
    }
    if !domain::handle_permits(caller_domain, capability, object, Rights::READ) {
        return u64::MAX - 2;
    }
    let state = if object == control_abi::PACKET_OBJECT {
        crate::packet::wait_state(request.expected_sequence)
    } else if object == control_abi::PACKET_EGRESS_OBJECT && timeout_ms.is_none() {
        crate::packet::egress_wait_state(request.expected_sequence)
    } else {
        return u64::MAX - 2;
    };
    match state {
        crate::packet::PacketWait::Ready => request.expected_sequence,
        crate::packet::PacketWait::Stale => control_abi::PACKET_RESULT_STALE,
        crate::packet::PacketWait::Empty => {
            if object == control_abi::PACKET_EGRESS_OBJECT
                && timeout_ms.is_none()
                && !crate::packet::egress_producer_is_bound()
                && domain::take_auxiliary_drain_request(caller_domain)
            {
                return control_abi::PACKET_RESULT_DRAINED;
            }
            if timeout_ms == Some(0) {
                return control_abi::PACKET_RESULT_TIMED_OUT;
            }
            let wait_available = if object == control_abi::PACKET_OBJECT {
                scheduler::packet_wait_is_available(request.expected_sequence)
            } else {
                scheduler::egress_wait_is_available(request.expected_sequence)
            };
            if !wait_available {
                return u64::MAX - 2;
            }
            if timeout_ms.is_some_and(|timeout| {
                !timer::arm_packet_wait_timer(caller_domain, request.expected_sequence, timeout)
            }) {
                return u64::MAX - 2;
            }
            let reason = scheduler::WaitReason::PacketAvailable {
                object,
                sequence: request.expected_sequence,
            };
            let action = scheduler::block_runtime(
                frame,
                USER_CODE_SELECTOR,
                USER_DATA_SELECTOR,
                reason,
                active_fs_base(),
            );
            if !matches!(action, RuntimeAction::Invalid) {
                return resume_action(action);
            }
            if timeout_ms.is_some()
                && scheduler::block_runtime_idle(
                    frame,
                    USER_CODE_SELECTOR,
                    USER_DATA_SELECTOR,
                    reason,
                    active_fs_base(),
                )
            {
                while !timer::packet_wait_timed_out(caller_domain, request.expected_sequence) {
                    linux_wait_for_interrupt();
                }
                return if timer::finish_packet_wait_timer(caller_domain, request.expected_sequence)
                    == Some(true)
                    && scheduler::current_domain() == Some(caller_domain)
                {
                    control_abi::PACKET_RESULT_TIMED_OUT
                } else {
                    u64::MAX - 2
                };
            }
            let _ = timer::cancel_packet_wait_timer_for_domain(caller_domain);
            u64::MAX - 2
        }
    }
}

fn packet_space_wait_call(caller_domain: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    packet_space_wait_call_for_object(caller_domain, capability, frame, control_abi::PACKET_OBJECT)
}

fn packet_space_wait_call_for_object(
    caller_domain: u64,
    capability: u64,
    frame: *mut UserTrapFrame,
    object: u64,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    if frame.first_argument() != 0
        || frame.second_argument() != 0
        || !domain::handle_permits(caller_domain, capability, object, Rights::WRITE)
    {
        return u64::MAX - 2;
    }
    let state = if object == control_abi::PACKET_OBJECT {
        crate::packet::space_state(caller_domain)
    } else if object == control_abi::PACKET_EGRESS_OBJECT {
        crate::packet::egress_space_state(caller_domain)
    } else {
        return u64::MAX - 2;
    };
    match state {
        crate::packet::PacketSpace::Ready => 0,
        crate::packet::PacketSpace::InvalidProducer
        | crate::packet::PacketSpace::SequenceExhausted => u64::MAX - 2,
        crate::packet::PacketSpace::Full => {
            let wait_available = if object == control_abi::PACKET_OBJECT {
                scheduler::packet_space_wait_is_available()
            } else {
                scheduler::egress_space_wait_is_available()
            };
            if !wait_available {
                return u64::MAX - 2;
            }
            let action = scheduler::block_runtime(
                frame,
                USER_CODE_SELECTOR,
                USER_DATA_SELECTOR,
                scheduler::WaitReason::PacketSpaceAvailable { object },
                active_fs_base(),
            );
            if matches!(action, RuntimeAction::Invalid) {
                u64::MAX - 2
            } else {
                resume_action(action)
            }
        }
    }
}

fn packet_egress_drain_wait_call(
    caller_domain: u64,
    capability: u64,
    frame: *mut UserTrapFrame,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    if frame.first_argument() != 0
        || frame.second_argument() != 0
        || !domain::handle_permits(
            caller_domain,
            capability,
            control_abi::PACKET_EGRESS_OBJECT,
            Rights::WRITE,
        )
    {
        return u64::MAX - 2;
    }
    if crate::packet::egress_is_empty() {
        return 0;
    }
    if !scheduler::egress_drain_wait_is_available() {
        return u64::MAX - 2;
    }
    let action = scheduler::block_runtime(
        frame,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        scheduler::WaitReason::PacketQueueDrained {
            object: control_abi::PACKET_EGRESS_OBJECT,
        },
        active_fs_base(),
    );
    if matches!(action, RuntimeAction::Invalid) {
        u64::MAX - 2
    } else {
        resume_action(action)
    }
}

fn network_wait_call(caller_domain: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    let command = frame.first_argument();
    let request = frame.second_argument();
    if !matches!(
        command,
        control_abi::NETWORK_DEVICE_WAIT_TX_NOTIFIED | control_abi::NETWORK_DEVICE_WAIT_RX_POSTED
    ) || request == 0
        || !domain::handle_permits(
            caller_domain,
            capability,
            control_abi::NETWORK_DEVICE_OBJECT,
            Rights::WRITE,
        )
        || !address_space::auxiliary_network_wait_ready(caller_domain, command, request)
    {
        return u64::MAX - 2;
    }
    let reason = scheduler::WaitReason::DeviceCompletion {
        object: control_abi::NETWORK_DEVICE_OBJECT,
        domain: caller_domain,
        request,
    };
    if !scheduler::block_runtime_idle(
        frame,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        reason,
        active_fs_base(),
    ) {
        return u64::MAX - 2;
    }
    match address_space::complete_auxiliary_network_wait(caller_domain, command, request) {
        address_space::AuxiliaryDeviceWaitCompletion::Completed => {
            if domain::renew_auxiliary_call_epoch(caller_domain) {
                0
            } else {
                u64::MAX - 2
            }
        }
        address_space::AuxiliaryDeviceWaitCompletion::Cancelled => {
            control_abi::NETWORK_DEVICE_RESULT_CANCELLED
        }
        address_space::AuxiliaryDeviceWaitCompletion::TimedOut
        | address_space::AuxiliaryDeviceWaitCompletion::Failed => {
            let _ = scheduler::wake_device_completion(
                caller_domain,
                control_abi::NETWORK_DEVICE_OBJECT,
                request,
                u64::MAX - 2,
            );
            u64::MAX - 2
        }
    }
}

fn block_device_call(caller_domain: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    let command = frame.first_argument();
    let request = frame.second_argument();
    let notified = match command {
        control_abi::BLOCK_DEVICE_WAIT => false,
        control_abi::BLOCK_DEVICE_WAIT_NOTIFIED => true,
        _ => return u64::MAX - 2,
    };
    if request == 0
        || !domain::handle_permits(
            caller_domain,
            capability,
            control_abi::BLOCK_DEVICE_OBJECT,
            Rights::WRITE,
        )
        || !address_space::auxiliary_device_wait_ready(caller_domain, request)
    {
        return u64::MAX - 2;
    }
    let reason = scheduler::WaitReason::DeviceCompletion {
        object: control_abi::BLOCK_DEVICE_OBJECT,
        domain: caller_domain,
        request,
    };
    if !scheduler::block_runtime_idle(
        frame,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        reason,
        active_fs_base(),
    ) {
        return u64::MAX - 2;
    }
    match address_space::complete_auxiliary_device_wait(caller_domain, request, notified) {
        address_space::AuxiliaryDeviceWaitCompletion::Completed => 0,
        address_space::AuxiliaryDeviceWaitCompletion::Cancelled => {
            control_abi::BLOCK_DEVICE_RESULT_CANCELLED
        }
        address_space::AuxiliaryDeviceWaitCompletion::TimedOut => u64::MAX - 2,
        address_space::AuxiliaryDeviceWaitCompletion::Failed => {
            let _ = scheduler::wake_device_completion(
                caller_domain,
                control_abi::BLOCK_DEVICE_OBJECT,
                request,
                u64::MAX - 2,
            );
            u64::MAX - 2
        }
    }
}

fn volume_device_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let command = frame.first_argument();
    let argument = frame.second_argument();
    match command {
        control_abi::VOLUME_PROBE
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::VOLUME_OBJECT,
                    Rights::READ,
                ) =>
        {
            control_abi::VOLUME_DESCRIPTOR_WORD
        }
        control_abi::VOLUME_QUERY_GENERATION
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::VOLUME_OBJECT,
                    Rights::READ,
                ) =>
        {
            volume::live_generation().unwrap_or(u64::MAX - 2)
        }
        control_abi::VOLUME_READ
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::VOLUME_OBJECT,
                Rights::READ,
            ) =>
        {
            volume_read(argument)
        }
        control_abi::VOLUME_COMMIT
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::VOLUME_OBJECT,
                Rights::WRITE,
            ) =>
        {
            volume_commit(argument)
        }
        _ => u64::MAX - 2,
    }
}

fn volume_read(address: u64) -> u64 {
    let Some(request) = volume_request(address) else {
        return u64::MAX - 2;
    };
    let Ok(capacity) = usize::try_from(request.size) else {
        return u64::MAX - 2;
    };
    if !(1..=control_abi::VOLUME_MAX_TRANSFER_SIZE).contains(&capacity) {
        return u64::MAX - 2;
    }
    let mut output = [0_u8; control_abi::VOLUME_MAX_TRANSFER_SIZE];
    match volume::read_live(request.expected_generation, &mut output[..capacity]) {
        Ok(size)
            if address_space::copy_to_current_user(request.buffer_address, &output[..size]) =>
        {
            size as u64
        }
        Ok(_) => u64::MAX - 2,
        Err(volume::LiveError::Stale) => control_abi::VOLUME_RESULT_STALE_GENERATION,
        Err(_) => u64::MAX - 2,
    }
}

fn volume_commit(address: u64) -> u64 {
    let Some(request) = volume_request(address) else {
        return u64::MAX - 2;
    };
    let Ok(size) = usize::try_from(request.size) else {
        return u64::MAX - 2;
    };
    if !(1..=control_abi::VOLUME_MAX_TRANSFER_SIZE).contains(&size) {
        return u64::MAX - 2;
    }
    let mut payload = [0_u8; control_abi::VOLUME_MAX_TRANSFER_SIZE];
    if !address_space::copy_from_current_user(request.buffer_address, &mut payload[..size]) {
        return u64::MAX - 2;
    }
    match volume::commit_live(request.expected_generation, &payload[..size]) {
        Ok(generation) => generation,
        Err(volume::LiveError::Stale) => control_abi::VOLUME_RESULT_STALE_GENERATION,
        Err(_) => u64::MAX - 2,
    }
}

struct VolumeRequest {
    expected_generation: u64,
    buffer_address: u64,
    size: u64,
}

fn volume_request(address: u64) -> Option<VolumeRequest> {
    let mut request = [0_u8; control_abi::VOLUME_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || u32::from_le_bytes(request[0..4].try_into().ok()?) as usize
            != control_abi::VOLUME_REQUEST_SIZE
        || u16::from_le_bytes(request[4..6].try_into().ok()?) != control_abi::VERSION
        || request[6..8] != [0, 0]
    {
        return None;
    }
    Some(VolumeRequest {
        expected_generation: u64::from_le_bytes(request[8..16].try_into().ok()?),
        buffer_address: u64::from_le_bytes(request[16..24].try_into().ok()?),
        size: u64::from_le_bytes(request[24..32].try_into().ok()?),
    })
}

fn root_device_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(
        caller_domain,
        capability,
        control_abi::ROOT_OBJECT,
        Rights::READ,
    ) || !initramfs::published_root_is_live()
    {
        return u64::MAX - 2;
    }
    let command = frame.first_argument();
    let argument = frame.second_argument();
    match command {
        control_abi::ROOT_PROBE if argument == 0 => control_abi::ROOT_DESCRIPTOR_WORD,
        control_abi::ROOT_LOOKUP => root_lookup(argument),
        control_abi::ROOT_READ => root_read(argument),
        control_abi::ROOT_READ_DIRECTORY => root_read_directory(argument),
        _ => u64::MAX - 2,
    }
}

fn root_lookup(address: u64) -> u64 {
    let mut request = [0_u8; control_abi::ROOT_LOOKUP_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || !root_request_header(&request, control_abi::ROOT_LOOKUP_REQUEST_SIZE)
    {
        return u64::MAX - 2;
    }
    let path_address = root_request_word(&request, 8);
    let path_size = root_request_word(&request, 16);
    let output_address = root_request_word(&request, 24);
    let output_size = root_request_word(&request, 32);
    let Some(path) = copy_root_path(path_address, path_size) else {
        return u64::MAX - 2;
    };
    if output_size != control_abi::ROOT_LOOKUP_DESCRIPTOR_SIZE as u64 {
        return u64::MAX - 2;
    }
    let Some((mode, data_size)) = initramfs::published_lookup(path.as_slice()) else {
        return u64::MAX - 2;
    };
    let Some(descriptor) = control_abi::root_lookup_descriptor(mode, data_size) else {
        return u64::MAX - 2;
    };
    if address_space::copy_to_current_user(output_address, &descriptor) {
        descriptor.len() as u64
    } else {
        u64::MAX - 2
    }
}

fn root_read(address: u64) -> u64 {
    let mut request = [0_u8; control_abi::ROOT_READ_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || !root_request_header(&request, control_abi::ROOT_READ_REQUEST_SIZE)
    {
        return u64::MAX - 2;
    }
    let path_address = root_request_word(&request, 8);
    let path_size = root_request_word(&request, 16);
    let offset = root_request_word(&request, 24);
    let output_address = root_request_word(&request, 32);
    let output_size = root_request_word(&request, 40);
    let (Some(path), Ok(offset), Ok(output_size)) = (
        copy_root_path(path_address, path_size),
        usize::try_from(offset),
        usize::try_from(output_size),
    ) else {
        return u64::MAX - 2;
    };
    if !(1..=control_abi::ROOT_MAX_READ_SIZE).contains(&output_size) {
        return u64::MAX - 2;
    }
    let mut output = [0_u8; control_abi::ROOT_MAX_READ_SIZE];
    let Some(size) = initramfs::published_read(path.as_slice(), offset, &mut output[..output_size])
    else {
        return u64::MAX - 2;
    };
    if size == 0 || address_space::copy_to_current_user(output_address, &output[..size]) {
        size as u64
    } else {
        u64::MAX - 2
    }
}

fn root_read_directory(address: u64) -> u64 {
    let mut request = [0_u8; control_abi::ROOT_DIRECTORY_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || !root_request_header(&request, control_abi::ROOT_DIRECTORY_REQUEST_SIZE)
    {
        return u64::MAX - 2;
    }
    let directory_address = root_request_word(&request, 8);
    let directory_size = root_request_word(&request, 16);
    let cursor = root_request_word(&request, 24);
    let output_address = root_request_word(&request, 32);
    let output_capacity = root_request_word(&request, 40);
    let directory = if directory_size == 0 {
        if directory_address != 0 {
            return u64::MAX - 2;
        }
        None
    } else {
        let Some(path) = copy_root_path(directory_address, directory_size) else {
            return u64::MAX - 2;
        };
        Some(path)
    };
    let (Ok(cursor), Ok(output_capacity)) =
        (usize::try_from(cursor), usize::try_from(output_capacity))
    else {
        return u64::MAX - 2;
    };
    if !(control_abi::ROOT_DIRECTORY_RECORD_HEADER_SIZE
        ..=control_abi::ROOT_MAX_DIRECTORY_RECORD_SIZE)
        .contains(&output_capacity)
    {
        return u64::MAX - 2;
    }
    let directory = directory.as_ref().map_or(&[][..], RootPath::as_slice);
    let Some(entry) = initramfs::published_next_child(directory, cursor) else {
        return u64::MAX - 2;
    };
    let Some(entry) = entry else {
        return 0;
    };
    let Some(record_size) =
        control_abi::ROOT_DIRECTORY_RECORD_HEADER_SIZE.checked_add(entry.name.len())
    else {
        return u64::MAX - 2;
    };
    if record_size > output_capacity {
        return u64::MAX - 2;
    }
    let mut output = [0_u8; control_abi::ROOT_MAX_DIRECTORY_RECORD_SIZE];
    output[0..4].copy_from_slice(&(record_size as u32).to_le_bytes());
    output[4..6].copy_from_slice(&control_abi::VERSION.to_le_bytes());
    output[8..16].copy_from_slice(&(entry.next_cursor as u64).to_le_bytes());
    output[16..20].copy_from_slice(&entry.mode.to_le_bytes());
    output[20..24].copy_from_slice(&(entry.name.len() as u32).to_le_bytes());
    output[24..32].copy_from_slice(&(entry.data_size as u64).to_le_bytes());
    output[32..record_size].copy_from_slice(entry.name);
    if address_space::copy_to_current_user(output_address, &output[..record_size]) {
        record_size as u64
    } else {
        u64::MAX - 2
    }
}

struct RootPath {
    bytes: [u8; control_abi::ROOT_MAX_PATH_SIZE],
    size: usize,
}

impl RootPath {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.size]
    }
}

fn copy_root_path(address: u64, size: u64) -> Option<RootPath> {
    let size = usize::try_from(size).ok()?;
    if !(1..=control_abi::ROOT_MAX_PATH_SIZE).contains(&size) {
        return None;
    }
    let mut path = RootPath {
        bytes: [0; control_abi::ROOT_MAX_PATH_SIZE],
        size,
    };
    address_space::copy_from_current_user(address, &mut path.bytes[..size]).then_some(path)
}

fn root_request_header(request: &[u8], expected_size: usize) -> bool {
    u32::from_le_bytes(request[0..4].try_into().unwrap()) as usize == expected_size
        && u16::from_le_bytes(request[4..6].try_into().unwrap()) == control_abi::VERSION
        && request[6..8] == [0, 0]
}

fn root_request_word(request: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(request[offset..offset + 8].try_into().unwrap())
}

fn network_device_call(caller_domain: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    let command = frame.first_argument();
    let argument = frame.second_argument();
    match command {
        control_abi::NETWORK_DEVICE_PROBE
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            control_abi::NETWORK_DEVICE_DESCRIPTOR_WORD
        }
        control_abi::NETWORK_DEVICE_QUERY_LINK
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            u64::from(network::link_is_up())
        }
        control_abi::NETWORK_DEVICE_SET_LINK
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            network_result(network::set_link(argument))
        }
        control_abi::NETWORK_DEVICE_SET_IPV4
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            network_result(network::set_ipv4(argument))
        }
        control_abi::NETWORK_DEVICE_QUERY_IPV4
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            network::ipv4_configuration()
        }
        control_abi::NETWORK_DEVICE_SET_GATEWAY
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            network_result(network::set_gateway(argument))
        }
        control_abi::NETWORK_DEVICE_QUERY_GATEWAY
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            network::ipv4_gateway()
        }
        control_abi::NETWORK_DEVICE_QUERY_GENERATION
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            network::generation()
        }
        control_abi::NETWORK_DEVICE_SET_ROUTE
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            set_network_route(argument)
        }
        control_abi::NETWORK_DEVICE_QUERY_ROUTE
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::READ,
            ) =>
        {
            query_network_route(argument)
        }
        control_abi::NETWORK_DEVICE_QUERY_SNAPSHOT
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::READ,
            ) =>
        {
            query_network_snapshot(argument)
        }
        control_abi::NETWORK_DEVICE_APPLY
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            apply_network_configuration(argument)
        }
        control_abi::NETWORK_DEVICE_ACTIVATE_EMPTY_QUEUES
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::WRITE,
                )
                && address_space::activate_auxiliary_network_empty_queues(caller_domain) =>
        {
            0
        }
        control_abi::NETWORK_DEVICE_PING
            if argument != 0
                && argument >> 32 == 0
                && network::link_is_up()
                && network::ipv4_configuration() as u32 == argument as u32
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            X86_RUNTIME.NETWORK_PING_RESULT.store(1, Ordering::Release);
            0
        }
        control_abi::NETWORK_DEVICE_PING
            if argument != 0
                && argument >> 32 == 0
                && network::link_is_up()
                && network::ipv4_configuration() != 0
                && network::ipv4_gateway() != 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                )
                && X86_RUNTIME
                    .NETWORK_PING_REQUESTED
                    .compare_exchange(0, argument, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok() =>
        {
            X86_RUNTIME.NETWORK_PING_RESULT.store(0, Ordering::Release);
            if !domain::renew_auxiliary_call_epoch(caller_domain)
                || !scheduler::suspend_container_lifecycle(
                    frame,
                    USER_CODE_SELECTOR,
                    USER_DATA_SELECTOR,
                    0,
                    active_fs_base(),
                )
            {
                X86_RUNTIME
                    .NETWORK_PING_REQUESTED
                    .store(0, Ordering::Release);
                return u64::MAX - 2;
            }
            u64::MAX
        }
        control_abi::NETWORK_DEVICE_QUERY_PING
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            u64::from(X86_RUNTIME.NETWORK_PING_RESULT.swap(0, Ordering::AcqRel))
        }
        linox_native_abi::NATIVE_NETWORK_DEVICE_DHCP
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::WRITE,
                )
                && X86_RUNTIME
                    .NETWORK_DHCP_REQUESTED
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok() =>
        {
            X86_RUNTIME.NETWORK_DHCP_RESULT.store(0, Ordering::Release);
            if !domain::renew_auxiliary_call_epoch(caller_domain)
                || !scheduler::suspend_container_lifecycle(
                    frame,
                    USER_CODE_SELECTOR,
                    USER_DATA_SELECTOR,
                    0,
                    active_fs_base(),
                )
            {
                X86_RUNTIME
                    .NETWORK_DHCP_REQUESTED
                    .store(false, Ordering::Release);
                return u64::MAX - 2;
            }
            u64::MAX
        }
        linox_native_abi::NATIVE_NETWORK_DEVICE_QUERY_DHCP
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            u64::from(X86_RUNTIME.NETWORK_DHCP_RESULT.swap(0, Ordering::AcqRel))
        }
        control_abi::NETWORK_DEVICE_QUERY_PING_TARGET
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            X86_RUNTIME.NETWORK_PING_ACTIVE.load(Ordering::Acquire)
        }
        control_abi::NETWORK_DEVICE_SET_DNS
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            network_result(network::set_dns(argument))
        }
        control_abi::NETWORK_DEVICE_QUERY_DNS
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            network::dns()
        }
        _ => u64::MAX - 2,
    }
}

pub(crate) fn take_network_ping_request() -> Option<u32> {
    let target = X86_RUNTIME.NETWORK_PING_REQUESTED.swap(0, Ordering::AcqRel);
    X86_RUNTIME
        .NETWORK_PING_ACTIVE
        .store(target, Ordering::Release);
    u32::try_from(target).ok().filter(|target| *target != 0)
}

pub(crate) fn complete_network_ping(success: bool) {
    X86_RUNTIME.NETWORK_PING_ACTIVE.store(0, Ordering::Release);
    X86_RUNTIME
        .NETWORK_PING_RESULT
        .store(if success { 1 } else { 2 }, Ordering::Release);
}

pub(crate) fn take_network_dhcp_request() -> bool {
    X86_RUNTIME
        .NETWORK_DHCP_REQUESTED
        .swap(false, Ordering::AcqRel)
}

pub(crate) fn complete_network_dhcp(success: bool) {
    if success {
        network::set_dhcp_configuration(true);
    }
    X86_RUNTIME
        .NETWORK_DHCP_RESULT
        .store(if success { 1 } else { 2 }, Ordering::Release);
}

fn apply_network_configuration(address: u64) -> u64 {
    let mut request = [0_u8; control_abi::NETWORK_APPLY_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request) {
        return u64::MAX - 2;
    }
    let version = network_request_word(&request, 0);
    let expected_generation = network_request_word(&request, 8);
    let link = network_request_word(&request, 16);
    let ipv4 = network_request_word(&request, 24);
    let gateway = network_request_word(&request, 32);
    let route_destination = network_request_word(&request, 40);
    let route_gateway = network_request_word(&request, 48);
    let reserved = network_request_word(&request, 56);
    if version != control_abi::NETWORK_APPLY_VERSION || reserved != 0 {
        return u64::MAX - 2;
    }
    match network::apply(
        expected_generation,
        network::Configuration {
            link,
            ipv4,
            gateway,
            route_destination,
            route_gateway,
        },
    ) {
        Ok(generation) => generation,
        Err(network::ApplyError::Stale) => control_abi::NETWORK_RESULT_STALE_GENERATION,
        Err(network::ApplyError::Invalid) => u64::MAX - 2,
    }
}

fn network_result(success: bool) -> u64 {
    if success {
        0
    } else {
        u64::MAX - 2
    }
}

fn network_request_word(
    request: &[u8; control_abi::NETWORK_APPLY_REQUEST_SIZE],
    offset: usize,
) -> u64 {
    u64::from_le_bytes([
        request[offset],
        request[offset + 1],
        request[offset + 2],
        request[offset + 3],
        request[offset + 4],
        request[offset + 5],
        request[offset + 6],
        request[offset + 7],
    ])
}

fn set_network_route(address: u64) -> u64 {
    let mut record = [0_u8; control_abi::NETWORK_ROUTE_RECORD_SIZE];
    if !address_space::copy_from_current_user(address, &mut record)
        || record[5..8].iter().any(|byte| *byte != 0)
        || record[12..].iter().any(|byte| *byte != 0)
    {
        return u64::MAX - 2;
    }
    let destination = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
    let prefix = record[4];
    let gateway = u32::from_le_bytes([record[8], record[9], record[10], record[11]]);
    network_result(network::set_route(destination, prefix, gateway))
}

fn query_network_route(address: u64) -> u64 {
    let (packed_destination, gateway) = network::route();
    let mut record = [0_u8; control_abi::NETWORK_ROUTE_RECORD_SIZE];
    record[0..4].copy_from_slice(&(packed_destination as u32).to_le_bytes());
    record[4] = (packed_destination >> 32) as u8;
    record[8..12].copy_from_slice(&(gateway as u32).to_le_bytes());
    if !address_space::copy_to_current_user(address, &record) {
        return u64::MAX - 2;
    }
    control_abi::NETWORK_ROUTE_RECORD_SIZE as u64
}

fn query_network_snapshot(address: u64) -> u64 {
    let state = network::snapshot();
    let words = [
        control_abi::NETWORK_SNAPSHOT_VERSION,
        state[0],
        state[1],
        state[2],
        state[3],
        state[4],
        state[5],
    ];
    let mut snapshot = [0_u8; control_abi::NETWORK_SNAPSHOT_SIZE];
    for (index, word) in words.iter().enumerate() {
        let offset = index * core::mem::size_of::<u64>();
        snapshot[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
    }
    if !address_space::copy_to_current_user(address, &snapshot) {
        return u64::MAX - 2;
    }
    control_abi::NETWORK_SNAPSHOT_SIZE as u64
}

fn create_auxiliary_service(
    caller_domain: u64,
    capability: u64,
    frame: *const UserTrapFrame,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(caller_domain, capability, 1, Rights::MANAGE)
        || frame.second_argument() != control_abi::MANAGEMENT_REQUEST_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let mut bytes = [0_u8; control_abi::MANAGEMENT_REQUEST_SIZE];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut bytes) {
        return u64::MAX - 2;
    }
    let Some(request) = control_abi::parse_management_request(&bytes) else {
        return u64::MAX - 2;
    };
    match request.action {
        control_abi::MANAGEMENT_CREATE_AUXILIARY => domain::create_auxiliary_service(
            caller_domain,
            capability,
            request.source,
            request.object,
            request.rights,
        )
        .unwrap_or(u64::MAX - 2),
        control_abi::MANAGEMENT_STOP_AUXILIARY
            if request.object == 0
                && request.rights == 0
                && address_space::stop_auxiliary_from_current_user(
                    caller_domain,
                    capability,
                    request.source,
                ) =>
        {
            0
        }
        control_abi::MANAGEMENT_LOAD_AUXILIARY
            if address_space::load_and_queue_auxiliary_from_current_user(
                request.source,
                request.object,
                request.rights,
            ) =>
        {
            0
        }
        control_abi::MANAGEMENT_INITIALIZE_AUXILIARY
            if address_space::initialize_staged_auxiliary_from_current_user(
                request.source,
                request.object,
                request.rights,
            ) =>
        {
            0
        }
        control_abi::MANAGEMENT_START_AUXILIARY
            if request.object == 0
                && request.rights == 0
                && scheduler::start_staged_auxiliary(request.source) =>
        {
            0
        }
        control_abi::MANAGEMENT_QUERY_AUXILIARY
            if request.object == 0
                && request.rights == 0
                && domain::auxiliary_service_is_ready(request.source) =>
        {
            scheduler::auxiliary_runtime_state(request.source).unwrap_or(u64::MAX - 2)
        }
        control_abi::MANAGEMENT_QUERY_AUXILIARY_FLAGS
            if request.object == 0
                && request.rights == 0
                && domain::auxiliary_service_is_ready(request.source) =>
        {
            scheduler::auxiliary_runtime_flags(request.source).unwrap_or(u64::MAX - 2)
        }
        control_abi::MANAGEMENT_DRAIN_AUXILIARY
            if request.object == 0
                && request.rights == 0
                && domain::request_auxiliary_drain(caller_domain, capability, request.source) =>
        {
            0
        }
        _ => u64::MAX - 2,
    }
}

fn blocking_receive(domain_id: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    if !domain::handle_permits(domain_id, capability, 3, Rights::READ) {
        return u64::MAX - 2;
    }
    match ipc::receive(domain_id) {
        ipc::Receive::Message(message) => return message,
        ipc::Receive::PeerClosed(_) => return scheduler::IPC_PEER_CLOSED,
        ipc::Receive::Empty => {}
    }
    let Some(service_side) = ipc::service_side(domain_id) else {
        return u64::MAX - 2;
    };
    let Some(peer_domain) = ipc::peer_domain(domain_id) else {
        return u64::MAX - 2;
    };
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX;
    };
    let action = scheduler::block_runtime(
        frame,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        scheduler::WaitReason::IpcReceive {
            object: 3,
            service_side,
            peer_domain,
        },
        active_fs_base(),
    );
    if matches!(action, RuntimeAction::Invalid) {
        u64::MAX - 2
    } else {
        if service_side
            && domain::service_failure_policy(domain_id)
                == Some(domain::ServiceFailurePolicy::RestartManaged)
            && !domain::record_service_ready(domain_id)
        {
            return u64::MAX;
        }
        resume_action(action)
    }
}

fn console_write(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 2, Rights::WRITE) {
        return u64::MAX - 2;
    }
    let Ok(length) = usize::try_from(frame.second_argument()) else {
        return u64::MAX - 2;
    };
    if !(1..=8).contains(&length) {
        return u64::MAX - 2;
    }
    let bytes = frame.first_argument().to_le_bytes();
    let message = &bytes[..length];
    if !message
        .iter()
        .all(|byte| matches!(*byte, 0x08 | b'\n' | b'\r' | 0x20..=0x7e))
    {
        return u64::MAX - 2;
    }
    let Ok(message) = core::str::from_utf8(message) else {
        return u64::MAX - 2;
    };
    serial_write(message);
    length as u64
}

fn console_write_buffer(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 2, Rights::WRITE) {
        return u64::MAX - 2;
    }
    let Ok(length) = usize::try_from(frame.second_argument()) else {
        return u64::MAX - 2;
    };
    if !(1..=control_abi::MAX_BUFFERED_CONSOLE_BYTES as usize).contains(&length) {
        return u64::MAX - 2;
    }
    let mut bytes = [0_u8; control_abi::MAX_BUFFERED_CONSOLE_BYTES as usize];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut bytes[..length])
        || !bytes[..length]
            .iter()
            .all(|byte| matches!(*byte, 0x08 | b'\n' | b'\r' | 0x20..=0x7e))
    {
        return u64::MAX - 2;
    }
    let Ok(message) = core::str::from_utf8(&bytes[..length]) else {
        return u64::MAX - 2;
    };
    serial_write(message);
    SYSCALL_STATE.fetch_or(8, Ordering::SeqCst);
    length as u64
}

fn console_read_line(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 2, Rights::READ) {
        return u64::MAX - 2;
    }
    let Ok(capacity) = usize::try_from(frame.second_argument()) else {
        return u64::MAX - 2;
    };
    if !(1..=control_abi::CONSOLE_MAX_LINE_BYTES).contains(&capacity) {
        return u64::MAX - 2;
    }
    let mut line = [0_u8; control_abi::CONSOLE_MAX_LINE_BYTES];
    let mut length = 0;
    loop {
        match crate::serial_read_byte_blocking() {
            b'\r' | b'\n' => {
                crate::serial_write_bytes(b"\r\n");
                break;
            }
            0x08 | 0x7f if length != 0 => {
                length -= 1;
                crate::serial_write_bytes(b"\x08 \x08");
            }
            byte @ 0x20..=0x7e if length < capacity => {
                line[length] = byte;
                length += 1;
                crate::serial_write_bytes(&[byte]);
            }
            _ => {}
        }
    }
    if length != 0 && !address_space::copy_to_current_user(frame.first_argument(), &line[..length])
        || !domain::renew_auxiliary_call_epoch(domain_id)
    {
        return u64::MAX - 2;
    }
    length as u64
}

fn console_read_byte(domain_id: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 2, Rights::READ)
        || frame.first_argument() != 0
        || frame.second_argument() != 0
        || !domain::renew_auxiliary_call_epoch(domain_id)
    {
        return u64::MAX - 2;
    }
    if !crate::serial_input_ready() && queue_background_container_work() {
        if !scheduler::suspend_container_lifecycle(
            frame,
            USER_CODE_SELECTOR,
            USER_DATA_SELECTOR,
            0,
            active_fs_base(),
        ) {
            return u64::MAX - 2;
        }
        return u64::MAX;
    }
    u64::from(crate::serial_read_byte_blocking())
}

fn host_inspect(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::READ)
        || frame.second_argument() != 0
    {
        return u64::MAX - 2;
    }
    let mut request = [0_u8; control_abi::HOST_INSPECT_REQUEST_SIZE];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut request)
        || u32::from_le_bytes(request[0..4].try_into().unwrap()) as usize != request.len()
        || u16::from_le_bytes(request[4..6].try_into().unwrap())
            != control_abi::HOST_INSPECT_VERSION
        || u64::from_le_bytes(request[24..32].try_into().unwrap())
            != control_abi::HOST_INSPECT_RECORD_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let command = u16::from_le_bytes(request[6..8].try_into().unwrap());
    let selector = u64::from_le_bytes(request[8..16].try_into().unwrap());
    let output_address = u64::from_le_bytes(request[16..24].try_into().unwrap());
    let record = match command {
        control_abi::HOST_PROC_ENUMERATE => {
            let Ok(cursor) = usize::try_from(selector) else {
                return u64::MAX - 2;
            };
            let container_cursor_base = domain::HOST_DOMAIN_CURSOR_END as usize + 1;
            let container_cursor_end = container_cursor_base + control_abi::DOMAIN_LIMIT;
            if cursor == container_cursor_end {
                return if domain::renew_auxiliary_call_epoch(domain_id) {
                    0
                } else {
                    u64::MAX - 2
                };
            }
            if cursor <= domain::HOST_DOMAIN_CURSOR_END as usize {
                let Some(record) = domain::inspect_live_domain(cursor) else {
                    return u64::MAX - 2;
                };
                if let Some(record) = record {
                    record
                } else if let Some(slot) = next_running_container_slot(0) {
                    domain::InspectionRecord {
                        pid: 100 + slot as u64,
                        parent_pid: 0,
                        kind: control_abi::HOST_PROCESS_KIND_DOMAIN_INIT,
                        state: control_abi::HOST_INSPECT_STATE_READY,
                        active_threads: 1,
                        next_cursor: (container_cursor_base + slot + 1) as u64,
                    }
                } else {
                    return if domain::renew_auxiliary_call_epoch(domain_id) {
                        0
                    } else {
                        u64::MAX - 2
                    };
                }
            } else {
                let Some(start) = cursor.checked_sub(container_cursor_base) else {
                    return u64::MAX - 2;
                };
                let Some(slot) = next_running_container_slot(start) else {
                    return if domain::renew_auxiliary_call_epoch(domain_id) {
                        0
                    } else {
                        u64::MAX - 2
                    };
                };
                domain::InspectionRecord {
                    pid: 100 + slot as u64,
                    parent_pid: 0,
                    kind: control_abi::HOST_PROCESS_KIND_DOMAIN_INIT,
                    state: control_abi::HOST_INSPECT_STATE_READY,
                    active_threads: 1,
                    next_cursor: (container_cursor_base + slot + 1) as u64,
                }
            }
        }
        control_abi::HOST_PROC_STATUS => {
            if let Some(slot) = selector
                .checked_sub(100)
                .and_then(|slot| usize::try_from(slot).ok())
                .filter(|slot| {
                    *slot < control_abi::DOMAIN_LIMIT
                        && container_state(*slot) == control_abi::DOMAIN_STATE_RUNNING
                })
            {
                domain::InspectionRecord {
                    pid: 100 + slot as u64,
                    parent_pid: 0,
                    kind: control_abi::HOST_PROCESS_KIND_DOMAIN_INIT,
                    state: control_abi::HOST_INSPECT_STATE_READY,
                    active_threads: 1,
                    next_cursor: 0,
                }
            } else {
                let Some(record) = domain::inspect_host_process(selector) else {
                    return u64::MAX - 2;
                };
                record
            }
        }
        _ => return u64::MAX - 2,
    };
    let mut output = [0_u8; control_abi::HOST_INSPECT_RECORD_SIZE];
    output[0..4].copy_from_slice(&(control_abi::HOST_INSPECT_RECORD_SIZE as u32).to_le_bytes());
    output[4..6].copy_from_slice(&control_abi::HOST_INSPECT_VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&record.kind.to_le_bytes());
    output[8..10].copy_from_slice(&record.state.to_le_bytes());
    output[12..16].copy_from_slice(&record.active_threads.to_le_bytes());
    output[16..24].copy_from_slice(&record.pid.to_le_bytes());
    output[24..32].copy_from_slice(&record.parent_pid.to_le_bytes());
    output[32..40].copy_from_slice(&record.next_cursor.to_le_bytes());
    if address_space::copy_to_current_user(output_address, &output)
        && domain::renew_auxiliary_call_epoch(domain_id)
    {
        output.len() as u64
    } else {
        u64::MAX - 2
    }
}

fn network_inventory_call(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::MANAGE)
        || frame.second_argument() != 0
    {
        return u64::MAX - 2;
    }
    let mut request = [0_u8; linox_native_abi::NATIVE_NETWORK_INVENTORY_REQUEST_SIZE as usize];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut request)
        || read_u32_at(&request, 0) != linox_native_abi::NATIVE_NETWORK_INVENTORY_REQUEST_SIZE
        || read_u16_at(&request, 4) != linox_native_abi::NATIVE_NETWORK_INVENTORY_VERSION
        || usize::from(read_u16_at(&request, 16)) > linox_native_abi::NATIVE_NETWORK_MAX_NAME_SIZE
        || usize::from(read_u16_at(&request, 20)) > linox_native_abi::NATIVE_NETWORK_MAX_NAME_SIZE
        || usize::from(read_u16_at(&request, 22)) > control_abi::DOMAIN_MAX_NAME_SIZE
    {
        return u64::MAX - 2;
    }
    let command = read_u16_at(&request, 6);
    let name_size = usize::from(read_u16_at(&request, 16));
    let uplink_size = usize::from(read_u16_at(&request, 20));
    let domain_size = usize::from(read_u16_at(&request, 22));
    let name = &request[24..24 + name_size];
    let uplink = &request[40..40 + uplink_size];
    let domain_name = &request[56..56 + domain_size];
    let result = match command {
        linox_native_abi::NATIVE_NETWORK_INVENTORY_QUERY => {
            let Ok(cursor) = usize::try_from(read_u64_at(&request, 8)) else {
                return u64::MAX - 2;
            };
            let Some(record) = network::inventory(cursor) else {
                return 0;
            };
            request.fill(0);
            request[0..4].copy_from_slice(
                &linox_native_abi::NATIVE_NETWORK_INVENTORY_REQUEST_SIZE.to_le_bytes(),
            );
            request[4..6]
                .copy_from_slice(&linox_native_abi::NATIVE_NETWORK_INVENTORY_VERSION.to_le_bytes());
            request[6..8].copy_from_slice(&command.to_le_bytes());
            request[8..16].copy_from_slice(&record.next_cursor.to_le_bytes());
            request[16..18].copy_from_slice(&(record.name_size as u16).to_le_bytes());
            request[18..20].copy_from_slice(&record.kind.to_le_bytes());
            request[20..22].copy_from_slice(&(record.uplink_size as u16).to_le_bytes());
            request[24..24 + record.name_size].copy_from_slice(&record.name[..record.name_size]);
            request[40..40 + record.uplink_size]
                .copy_from_slice(&record.uplink[..record.uplink_size]);
            1
        }
        linox_native_abi::NATIVE_NETWORK_INVENTORY_CREATE_VIRTUAL
            if network::create_virtual(name, uplink) =>
        {
            1
        }
        linox_native_abi::NATIVE_NETWORK_INVENTORY_ATTACH => {
            let Some(slot) = container_slot_by_name(domain_name) else {
                return u64::MAX - 2;
            };
            if !network::attach(slot, name)
                || !domain::configure_container_network_mode(
                    X86_RUNTIME.CONTAINER_DOMAIN_IDS[slot].load(Ordering::Acquire),
                    domain::ContainerNetworkMode::Isolated,
                )
            {
                return u64::MAX - 2;
            }
            1
        }
        linox_native_abi::NATIVE_NETWORK_INVENTORY_SET_LINK
            if read_u64_at(&request, 8) <= 1
                && network::set_virtual_link(name, read_u64_at(&request, 8) == 1) =>
        {
            1
        }
        linox_native_abi::NATIVE_NETWORK_INVENTORY_QUERY_ATTACHMENT => {
            let Some(slot) = container_slot_by_name(domain_name) else {
                return u64::MAX - 2;
            };
            let Ok(cursor) = usize::try_from(read_u64_at(&request, 8)) else {
                return u64::MAX - 2;
            };
            let Some((next, attached_name, attached_name_size)) = network::attachment(slot, cursor)
            else {
                return 0;
            };
            request.fill(0);
            request[0..4].copy_from_slice(
                &linox_native_abi::NATIVE_NETWORK_INVENTORY_REQUEST_SIZE.to_le_bytes(),
            );
            request[4..6]
                .copy_from_slice(&linox_native_abi::NATIVE_NETWORK_INVENTORY_VERSION.to_le_bytes());
            request[6..8].copy_from_slice(&command.to_le_bytes());
            request[8..16].copy_from_slice(&next.to_le_bytes());
            request[16..18].copy_from_slice(&(attached_name_size as u16).to_le_bytes());
            request[24..24 + attached_name_size]
                .copy_from_slice(&attached_name[..attached_name_size]);
            1
        }
        _ => return u64::MAX - 2,
    };
    if result != 0 && !address_space::copy_to_current_user(frame.first_argument(), &request) {
        return u64::MAX - 2;
    }
    if domain::renew_auxiliary_call_epoch(domain_id) {
        result
    } else {
        u64::MAX - 2
    }
}

fn container_control(domain_id: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::MANAGE) {
        return u64::MAX - 2;
    }
    let operation = frame.first_argument();
    if operation == control_abi::DOMAIN_HOST_SHUTDOWN && frame.second_argument() == 0 {
        X86_RUNTIME
            .CONTAINER_HOST_SHUTDOWN_REQUESTED
            .store(true, Ordering::SeqCst);
        return active_container_slot()
            .map(|slot| {
                u64::from(X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst))
            })
            .unwrap_or(0);
    }
    if operation == control_abi::DOMAIN_EXEC {
        let result = container_exec_control(frame.second_argument());
        if result == u64::MAX - 2 || !domain::renew_auxiliary_call_epoch(domain_id) {
            return u64::MAX - 2;
        }
        if !scheduler::suspend_container_lifecycle(
            frame,
            USER_CODE_SELECTOR,
            USER_DATA_SELECTOR,
            result,
            active_fs_base(),
        ) {
            return u64::MAX - 2;
        }
        return u64::MAX;
    }
    let Some(mut request) = read_container_request(frame.second_argument()) else {
        return u64::MAX - 2;
    };
    let name = container_request_name(&request);
    let requested_slot = container_slot_by_name(name);
    let result = match operation {
        control_abi::DOMAIN_QUERY if name.is_empty() => {
            let Ok(cursor) = usize::try_from(read_u64_at(&request, 24)) else {
                return u64::MAX - 2;
            };
            let Some(slot) = next_container_slot(cursor) else {
                return if domain::renew_auxiliary_call_epoch(domain_id) {
                    0
                } else {
                    u64::MAX - 2
                };
            };
            write_container_request(&mut request, slot, next_container_cursor(slot + 1));
            if !address_space::copy_to_current_user(frame.second_argument(), &request) {
                return u64::MAX - 2;
            }
            u64::from(X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst))
        }
        control_abi::DOMAIN_POLL_BACKGROUND => {
            u64::from(!crate::serial_input_ready() && queue_background_container_work())
        }
        control_abi::DOMAIN_QUERY if requested_slot.is_some() => {
            let slot = requested_slot.unwrap_or(0);
            write_container_request(&mut request, slot, control_abi::DOMAIN_CURSOR_END);
            if !address_space::copy_to_current_user(frame.second_argument(), &request) {
                return u64::MAX - 2;
            }
            u64::from(X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst))
        }
        control_abi::DOMAIN_CREATE if requested_slot.is_none() && valid_container_name(name) => {
            let Some(slot) = free_container_slot() else {
                return u64::MAX - 2;
            };
            let Some(container_domain) = domain::create_container_domain(domain_id, slot, 1, 128)
            else {
                return u64::MAX - 2;
            };
            X86_RUNTIME.CONTAINER_DOMAIN_IDS[slot].store(container_domain, Ordering::SeqCst);
            X86_RUNTIME.CONTAINER_CPU_COUNTS[slot].store(1, Ordering::SeqCst);
            X86_RUNTIME.CONTAINER_MEMORY_MIB[slot].store(128, Ordering::SeqCst);
            store_container_name(slot, name);
            store_container_value(
                b"/sbin/init",
                &X86_RUNTIME.CONTAINER_INITS[slot],
                &X86_RUNTIME.CONTAINER_INIT_SIZES[slot],
            );
            store_container_value(
                b"linux",
                &X86_RUNTIME.DOMAIN_PERSONALITIES[slot],
                &X86_RUNTIME.DOMAIN_PERSONALITY_SIZES[slot],
            );
            X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot].store(
                control_abi::DOMAIN_CONFIG_INIT
                    | control_abi::DOMAIN_CONFIG_CPU
                    | control_abi::DOMAIN_CONFIG_MEMORY
                    | control_abi::DOMAIN_CONFIG_PERSONALITY,
                Ordering::SeqCst,
            );
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_CREATED as u8, Ordering::SeqCst);
            control_abi::DOMAIN_STATE_CREATED
        }
        control_abi::DOMAIN_SET_INIT
            if configurable_container(requested_slot)
                && valid_container_init(container_request_init(&request)) =>
        {
            let slot = requested_slot.unwrap_or(0);
            store_container_value(
                container_request_init(&request),
                &X86_RUNTIME.CONTAINER_INITS[slot],
                &X86_RUNTIME.CONTAINER_INIT_SIZES[slot],
            );
            update_container_configuration(slot, control_abi::DOMAIN_CONFIG_INIT)
        }
        control_abi::DOMAIN_SET_CPU
            if configurable_container(requested_slot) && read_u16_at(&request, 70) != 0 =>
        {
            let slot = requested_slot.unwrap_or(0);
            let cpu_count = read_u16_at(&request, 70);
            let memory_mib = X86_RUNTIME.CONTAINER_MEMORY_MIB[slot].load(Ordering::Acquire);
            if !domain::configure_container_domain_limits(
                X86_RUNTIME.CONTAINER_DOMAIN_IDS[slot].load(Ordering::Acquire),
                cpu_count,
                memory_mib,
            ) {
                return u64::MAX - 2;
            }
            X86_RUNTIME.CONTAINER_CPU_COUNTS[slot].store(cpu_count, Ordering::Release);
            update_container_configuration(slot, control_abi::DOMAIN_CONFIG_CPU)
        }
        control_abi::DOMAIN_SET_MEMORY_MIB
            if configurable_container(requested_slot) && read_u64_at(&request, 200) != 0 =>
        {
            let slot = requested_slot.unwrap_or(0);
            let memory_mib = read_u64_at(&request, 200);
            let cpu_count = X86_RUNTIME.CONTAINER_CPU_COUNTS[slot].load(Ordering::Acquire);
            if !domain::configure_container_domain_limits(
                X86_RUNTIME.CONTAINER_DOMAIN_IDS[slot].load(Ordering::Acquire),
                cpu_count,
                memory_mib,
            ) {
                return u64::MAX - 2;
            }
            X86_RUNTIME.CONTAINER_MEMORY_MIB[slot].store(memory_mib, Ordering::Release);
            update_container_configuration(slot, control_abi::DOMAIN_CONFIG_MEMORY)
        }
        control_abi::DOMAIN_SET_AUTOSTART
            if configurable_container(requested_slot) && read_u64_at(&request, 24) <= 1 =>
        {
            update_container_flag(
                requested_slot.unwrap_or(0),
                control_abi::DOMAIN_CONFIG_AUTOSTART,
                read_u64_at(&request, 24) == 1,
            )
        }
        control_abi::DOMAIN_SET_USER_SWITCHING
            if configurable_container(requested_slot) && read_u64_at(&request, 24) <= 1 =>
        {
            update_container_flag(
                requested_slot.unwrap_or(0),
                control_abi::DOMAIN_CONFIG_USER_SWITCHING,
                read_u64_at(&request, 24) == 1,
            )
        }
        control_abi::DOMAIN_SET_WRITE_EXECUTE
            if configurable_container(requested_slot) && read_u64_at(&request, 24) <= 1 =>
        {
            update_container_flag(
                requested_slot.unwrap_or(0),
                control_abi::DOMAIN_CONFIG_WRITE_EXECUTE,
                read_u64_at(&request, 24) == 1,
            )
        }
        control_abi::DOMAIN_SET_PRIVILEGED
            if configurable_container(requested_slot) && read_u64_at(&request, 24) <= 1 =>
        {
            update_container_flag(
                requested_slot.unwrap_or(0),
                control_abi::DOMAIN_CONFIG_PRIVILEGED,
                read_u64_at(&request, 24) == 1,
            )
        }
        control_abi::DOMAIN_SET_IMAGE
            if configurable_container(requested_slot)
                && valid_container_image(container_request_image(&request)) =>
        {
            let slot = requested_slot.unwrap_or(0);
            let mut canonical = [0_u8; control_abi::DOMAIN_MAX_IMAGE_SIZE];
            let canonical_size =
                canonical_container_image(container_request_image(&request), &mut canonical)
                    .unwrap_or(0);
            let canonical = &canonical[..canonical_size];
            store_container_value(
                canonical,
                &X86_RUNTIME.CONTAINER_IMAGES[slot],
                &X86_RUNTIME.CONTAINER_IMAGE_SIZES[slot],
            );
            if crate::published_rootfs::is_installed(slot)
                && !crate::image_store::uninstall_rootfs(slot)
            {
                return u64::MAX - 2;
            }
            update_container_configuration(slot, control_abi::DOMAIN_CONFIG_IMAGE)
        }
        control_abi::DOMAIN_SET_PERSONALITY
            if configurable_container(requested_slot)
                && valid_domain_personality(domain_request_personality(&request)) =>
        {
            let slot = requested_slot.unwrap_or(0);
            store_container_value(
                domain_request_personality(&request),
                &X86_RUNTIME.DOMAIN_PERSONALITIES[slot],
                &X86_RUNTIME.DOMAIN_PERSONALITY_SIZES[slot],
            );
            update_container_configuration(slot, control_abi::DOMAIN_CONFIG_PERSONALITY)
        }
        control_abi::DOMAIN_STOP
            if requested_slot.is_some()
                && container_state(requested_slot.unwrap_or(0))
                    == control_abi::DOMAIN_STATE_RUNNING
                && (active_container_slot() == requested_slot
                    || address_space::linux_runtime_is_suspended(requested_slot.unwrap_or(0))) =>
        {
            let slot = requested_slot.unwrap_or(0);
            if address_space::linux_runtime_is_suspended(slot) {
                X86_RUNTIME
                    .CONTAINER_SELECTED_SLOT
                    .store(slot as u8, Ordering::Release);
                X86_RUNTIME.CONTAINER_STOP_REQUESTED[slot].store(true, Ordering::Release);
                X86_RUNTIME
                    .CONTAINER_RESTART_REQUESTED
                    .store(true, Ordering::Release);
            } else {
                X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                    .store(control_abi::DOMAIN_STATE_STOPPED as u8, Ordering::SeqCst);
            }
            control_abi::DOMAIN_STATE_STOPPED
        }
        control_abi::DOMAIN_RESTART | control_abi::DOMAIN_START_ATTACHED
            if requested_slot.is_some()
                && active_container_slot().is_none_or(|slot| Some(slot) == requested_slot)
                && X86_RUNTIME.CONTAINER_CONFIG_FLAGS[requested_slot.unwrap_or(0)]
                    .load(Ordering::SeqCst)
                    & control_abi::DOMAIN_CONFIG_COMPLETE
                    == control_abi::DOMAIN_CONFIG_COMPLETE
                && matches!(
                    container_state(requested_slot.unwrap_or(0)),
                    control_abi::DOMAIN_STATE_CONFIGURED
                        | control_abi::DOMAIN_STATE_RUNNING
                        | control_abi::DOMAIN_STATE_STOPPED
                        | control_abi::DOMAIN_STATE_FAILED
                ) =>
        {
            let slot = requested_slot.unwrap_or(0);
            let embedded = container_image_is_embedded(slot);
            // Another detached start still holds the lifecycle request until
            // the controller goes idle; queue this one behind it.
            if operation == control_abi::DOMAIN_RESTART
                && selected_container_slot().is_some_and(|selected| selected != slot)
                && (X86_RUNTIME.CONTAINER_PULL_REQUESTED.load(Ordering::Acquire)
                    || X86_RUNTIME
                        .CONTAINER_INSTALL_REQUESTED
                        .load(Ordering::Acquire)
                    || X86_RUNTIME
                        .CONTAINER_RESTART_REQUESTED
                        .load(Ordering::Acquire))
            {
                reset_container_console(slot, false);
                if !embedded {
                    X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                        .store(control_abi::DOMAIN_STATE_STARTING as u8, Ordering::Release);
                }
                X86_RUNTIME.CONTAINER_START_PENDING[slot].store(true, Ordering::Release);
                return if embedded {
                    control_abi::DOMAIN_STATE_STOPPED
                } else {
                    control_abi::DOMAIN_STATE_STARTING
                };
            }
            X86_RUNTIME.CONTAINER_START_PENDING[slot].store(false, Ordering::Release);
            X86_RUNTIME
                .CONTAINER_SELECTED_SLOT
                .store(slot as u8, Ordering::SeqCst);
            reset_container_console(slot, operation == control_abi::DOMAIN_START_ATTACHED);
            if !embedded {
                X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                    .store(control_abi::DOMAIN_STATE_STARTING as u8, Ordering::Release);
            }
            if embedded || crate::published_rootfs::is_installed(slot) {
                X86_RUNTIME
                    .CONTAINER_RESTART_REQUESTED
                    .store(true, Ordering::SeqCst);
            } else {
                X86_RUNTIME
                    .CONTAINER_PULL_REQUESTED
                    .store(true, Ordering::SeqCst);
            }
            if embedded {
                control_abi::DOMAIN_STATE_STOPPED
            } else {
                control_abi::DOMAIN_STATE_STARTING
            }
        }
        control_abi::DOMAIN_ATTACH
            if requested_slot.is_some()
                && container_state(requested_slot.unwrap_or(0))
                    == control_abi::DOMAIN_STATE_RUNNING
                && !X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[requested_slot.unwrap_or(0)]
                    .swap(true, Ordering::AcqRel) =>
        {
            let slot = requested_slot.unwrap_or(0);
            X86_RUNTIME
                .CONTAINER_SELECTED_SLOT
                .store(slot as u8, Ordering::Release);
            X86_RUNTIME
                .CONTAINER_RESTART_REQUESTED
                .store(true, Ordering::Release);
            redraw_container_console(slot);
            control_abi::DOMAIN_STATE_RUNNING
        }
        control_abi::DOMAIN_INJECT_FAILURE
            if requested_slot.is_some()
                && active_container_slot() == requested_slot
                && container_state(requested_slot.unwrap_or(0))
                    == control_abi::DOMAIN_STATE_RUNNING =>
        {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[requested_slot.unwrap_or(0)]
                .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::SeqCst);
            control_abi::DOMAIN_STATE_FAILED
        }
        _ => u64::MAX - 2,
    };
    if result != u64::MAX - 2 {
        if !domain::renew_auxiliary_call_epoch(domain_id) {
            return u64::MAX - 2;
        }
        if matches!(
            operation,
            control_abi::DOMAIN_STOP
                | control_abi::DOMAIN_START_ATTACHED
                | control_abi::DOMAIN_ATTACH
                | control_abi::DOMAIN_INJECT_FAILURE
        ) || operation == control_abi::DOMAIN_POLL_BACKGROUND && result == 1
            || operation == control_abi::DOMAIN_RESTART
                && result == control_abi::DOMAIN_STATE_STOPPED
        {
            if !scheduler::suspend_container_lifecycle(
                frame,
                USER_CODE_SELECTOR,
                USER_DATA_SELECTOR,
                result,
                active_fs_base(),
            ) {
                return u64::MAX - 2;
            }
            return u64::MAX;
        }
    }
    result
}

fn container_exec_control(address: u64) -> u64 {
    let mut request = [0_u8; control_abi::DOMAIN_EXEC_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || read_u32_at(&request, 0) != control_abi::DOMAIN_EXEC_REQUEST_SIZE as u32
        || read_u16_at(&request, 4) != control_abi::DOMAIN_EXEC_REQUEST_VERSION
        || read_u16_at(&request, 6) & !control_abi::DOMAIN_EXEC_INTERACTIVE != 0
        || usize::from(read_u16_at(&request, 8)) > control_abi::DOMAIN_MAX_NAME_SIZE
        || usize::from(read_u16_at(&request, 10)) == 0
        || usize::from(read_u16_at(&request, 10)) > control_abi::DOMAIN_EXEC_MAX_ARGUMENTS
        || read_u32_at(&request, 12) != 0
    {
        return u64::MAX - 2;
    }
    let name_size = usize::from(read_u16_at(&request, 8));
    let name = request.get(16..16 + name_size).unwrap_or_default();
    let Some(slot) = container_slot_by_name(name).filter(|slot| {
        matches!(
            container_state(*slot),
            control_abi::DOMAIN_STATE_BOOTING | control_abi::DOMAIN_STATE_RUNNING
        ) && address_space::linux_runtime_is_suspended(*slot)
    }) else {
        return u64::MAX - 2;
    };
    let count = usize::from(read_u16_at(&request, 10));
    let descriptors = read_u64_at(&request, 32);
    for index in 0..count {
        let Some(descriptor_address) = descriptors.checked_add((index * 16) as u64) else {
            return u64::MAX - 2;
        };
        let mut descriptor = [0_u8; 16];
        if !address_space::copy_from_current_user(descriptor_address, &mut descriptor) {
            return u64::MAX - 2;
        }
        let argument_address = read_u64_at(&descriptor, 0);
        let Ok(length) = usize::try_from(read_u64_at(&descriptor, 8)) else {
            return u64::MAX - 2;
        };
        if length == 0 || length >= DOMAIN_EXEC_ARGUMENT_CAPACITY {
            return u64::MAX - 2;
        }
        let mut value = [0_u8; DOMAIN_EXEC_ARGUMENT_CAPACITY];
        if !address_space::copy_from_current_user(argument_address, &mut value[..length]) {
            return u64::MAX - 2;
        }
        X86_RUNTIME.CONTAINER_EXEC_ARGUMENT_SIZES[slot][index]
            .store(length as u16, Ordering::Release);
        for (cell, byte) in X86_RUNTIME.CONTAINER_EXEC_ARGUMENTS[slot][index]
            .iter()
            .zip(value[..length].iter().copied())
        {
            cell.store(byte, Ordering::Release);
        }
    }
    X86_RUNTIME.CONTAINER_EXEC_ARGUMENT_COUNTS[slot].store(count as u8, Ordering::Release);
    X86_RUNTIME.CONTAINER_EXEC_INTERACTIVE[slot].store(
        read_u16_at(&request, 6) & control_abi::DOMAIN_EXEC_INTERACTIVE != 0,
        Ordering::Release,
    );
    X86_RUNTIME.CONTAINER_EXEC_REQUESTED[slot].store(true, Ordering::Release);
    X86_RUNTIME
        .CONTAINER_SELECTED_SLOT
        .store(slot as u8, Ordering::Release);
    X86_RUNTIME
        .CONTAINER_RESTART_REQUESTED
        .store(true, Ordering::Release);
    control_abi::DOMAIN_STATE_RUNNING
}

fn read_container_request(address: u64) -> Option<[u8; control_abi::DOMAIN_REQUEST_SIZE]> {
    let mut request = [0_u8; control_abi::DOMAIN_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || read_u32_at(&request, 0) != control_abi::DOMAIN_REQUEST_SIZE as u32
        || read_u16_at(&request, 4) != control_abi::DOMAIN_REQUEST_VERSION
        || usize::from(read_u16_at(&request, 6)) > control_abi::DOMAIN_MAX_NAME_SIZE
        || usize::from(read_u16_at(&request, 32)) > control_abi::DOMAIN_MAX_INIT_SIZE
        || usize::from(read_u16_at(&request, 68)) > control_abi::DOMAIN_MAX_IMAGE_SIZE
        || usize::from(read_u16_at(&request, 208)) > control_abi::DOMAIN_MAX_PERSONALITY_SIZE
        || request[210..216].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    Some(request)
}

fn container_request_name(request: &[u8; control_abi::DOMAIN_REQUEST_SIZE]) -> &[u8] {
    let size = usize::from(read_u16_at(request, 6));
    request.get(8..8 + size).unwrap_or_default()
}

fn container_request_init(request: &[u8; control_abi::DOMAIN_REQUEST_SIZE]) -> &[u8] {
    let size = usize::from(read_u16_at(request, 32));
    request.get(36..36 + size).unwrap_or_default()
}

fn container_request_image(request: &[u8; control_abi::DOMAIN_REQUEST_SIZE]) -> &[u8] {
    let size = usize::from(read_u16_at(request, 68));
    request.get(72..72 + size).unwrap_or_default()
}

fn domain_request_personality(request: &[u8; control_abi::DOMAIN_REQUEST_SIZE]) -> &[u8] {
    let size = usize::from(read_u16_at(request, 208));
    request.get(216..216 + size).unwrap_or_default()
}

fn valid_domain_personality(personality: &[u8]) -> bool {
    personality == b"linux"
}

fn valid_container_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= control_abi::DOMAIN_MAX_NAME_SIZE
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_container_init(init: &[u8]) -> bool {
    !init.is_empty()
        && init.len() <= control_abi::DOMAIN_MAX_INIT_SIZE
        && init[0] == b'/'
        && init.iter().all(u8::is_ascii_graphic)
}

fn valid_container_image(image: &[u8]) -> bool {
    let mut canonical = [0_u8; control_abi::DOMAIN_MAX_IMAGE_SIZE];
    canonical_container_image(image, &mut canonical).is_some()
}

fn canonical_container_image(image: &[u8], output: &mut [u8]) -> Option<usize> {
    if image == b"embedded://minimal-system-v0"
        || image == crate::image_store::BUILTIN_RUST_IMAGE
            && crate::image_store::builtin_rootfs_available()
    {
        output.get_mut(..image.len())?.copy_from_slice(image);
        return Some(image.len());
    }
    linox_oci::ImageReference::parse(image)
        .ok()?
        .write_canonical(output)
        .ok()
}

fn container_slot_by_name(name: &[u8]) -> Option<usize> {
    (!name.is_empty()).then_some(())?;
    (0..control_abi::DOMAIN_LIMIT).find(|slot| {
        let size = usize::from(X86_RUNTIME.CONTAINER_NAME_SIZES[*slot].load(Ordering::SeqCst));
        size == name.len()
            && X86_RUNTIME.CONTAINER_NAMES[*slot][..size]
                .iter()
                .zip(name)
                .all(|(stored, supplied)| stored.load(Ordering::SeqCst) == *supplied)
    })
}

fn free_container_slot() -> Option<usize> {
    (0..control_abi::DOMAIN_LIMIT)
        .find(|slot| X86_RUNTIME.CONTAINER_CONTROL_STATES[*slot].load(Ordering::SeqCst) == 0)
}

fn next_container_slot(cursor: usize) -> Option<usize> {
    (cursor..control_abi::DOMAIN_LIMIT)
        .find(|slot| X86_RUNTIME.CONTAINER_CONTROL_STATES[*slot].load(Ordering::SeqCst) != 0)
}

fn next_running_container_slot(cursor: usize) -> Option<usize> {
    (cursor..control_abi::DOMAIN_LIMIT)
        .find(|slot| container_state(*slot) == control_abi::DOMAIN_STATE_RUNNING)
}

fn queue_background_container_work() -> bool {
    if X86_RUNTIME.CONTAINER_PULL_REQUESTED.load(Ordering::Acquire)
        || X86_RUNTIME
            .CONTAINER_INSTALL_REQUESTED
            .load(Ordering::Acquire)
        || X86_RUNTIME
            .CONTAINER_RESTART_REQUESTED
            .load(Ordering::Acquire)
    {
        return true;
    }
    // Start the next queued detached domain.
    if let Some(slot) = (0..control_abi::DOMAIN_LIMIT)
        .find(|slot| X86_RUNTIME.CONTAINER_START_PENDING[*slot].swap(false, Ordering::AcqRel))
    {
        X86_RUNTIME
            .CONTAINER_SELECTED_SLOT
            .store(slot as u8, Ordering::Release);
        if container_image_is_embedded(slot) || crate::published_rootfs::is_installed(slot) {
            X86_RUNTIME
                .CONTAINER_RESTART_REQUESTED
                .store(true, Ordering::Release);
        } else {
            X86_RUNTIME
                .CONTAINER_PULL_REQUESTED
                .store(true, Ordering::Release);
        }
        return true;
    }
    // Otherwise resume the suspended background domains in turn.
    let start = usize::from(
        X86_RUNTIME
            .CONTAINER_LAST_RESUMED_SLOT
            .load(Ordering::Acquire),
    ) + 1;
    let Some(slot) = (start..start + control_abi::DOMAIN_LIMIT)
        .map(|slot| slot % control_abi::DOMAIN_LIMIT)
        .find(|slot| background_container_resumable(*slot))
    else {
        return false;
    };
    X86_RUNTIME
        .CONTAINER_LAST_RESUMED_SLOT
        .store(slot as u8, Ordering::Release);
    X86_RUNTIME
        .CONTAINER_SELECTED_SLOT
        .store(slot as u8, Ordering::Release);
    X86_RUNTIME
        .CONTAINER_RESTART_REQUESTED
        .store(true, Ordering::Release);
    true
}

fn background_container_resumable(slot: usize) -> bool {
    matches!(
        container_state(slot),
        control_abi::DOMAIN_STATE_BOOTING | control_abi::DOMAIN_STATE_RUNNING
    ) && X86_RUNTIME.CONTAINER_BACKGROUND_SUSPENDED[slot].load(Ordering::Acquire)
        && address_space::linux_runtime_is_suspended(slot)
}

/// Whether a domain other than `running` has background work waiting: a
/// queued start or a suspended domain to resume.
fn other_background_work_waiting(running: usize) -> bool {
    X86_RUNTIME
        .CONTAINER_START_PENDING
        .iter()
        .any(|pending| pending.load(Ordering::Acquire))
        || (0..control_abi::DOMAIN_LIMIT)
            .any(|slot| slot != running && background_container_resumable(slot))
}

fn next_container_cursor(cursor: usize) -> u64 {
    next_container_slot(cursor)
        .map(|slot| slot as u64)
        .unwrap_or(control_abi::DOMAIN_CURSOR_END)
}

fn selected_container_slot() -> Option<usize> {
    let slot = usize::from(X86_RUNTIME.CONTAINER_SELECTED_SLOT.load(Ordering::SeqCst));
    (slot < control_abi::DOMAIN_LIMIT).then_some(slot)
}

fn active_container_slot() -> Option<usize> {
    let slot = usize::from(X86_RUNTIME.CONTAINER_ACTIVE_SLOT.load(Ordering::SeqCst));
    (slot < control_abi::DOMAIN_LIMIT).then_some(slot)
}

fn selected_or_active_container_slot() -> Option<usize> {
    selected_container_slot().or_else(active_container_slot)
}

fn container_state(slot: usize) -> u64 {
    u64::from(X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst))
}

fn container_image_is_embedded(slot: usize) -> bool {
    let size = usize::from(X86_RUNTIME.CONTAINER_IMAGE_SIZES[slot].load(Ordering::SeqCst));
    let embedded = b"embedded://minimal-system-v0";
    size == embedded.len()
        && X86_RUNTIME.CONTAINER_IMAGES[slot][..size]
            .iter()
            .zip(embedded)
            .all(|(stored, expected)| stored.load(Ordering::SeqCst) == *expected)
}

pub(crate) fn configured_domain_uses_published_rootfs() -> bool {
    let Some(slot) = selected_container_slot() else {
        return false;
    };
    !container_image_is_embedded(slot) && crate::published_rootfs::is_installed(slot)
}

pub(crate) fn domain_uses_published_rootfs(slot: usize) -> bool {
    slot < control_abi::DOMAIN_LIMIT
        && !container_image_is_embedded(slot)
        && crate::published_rootfs::is_installed(slot)
}

pub(crate) fn configured_container_slot() -> Option<usize> {
    selected_container_slot()
}

pub(crate) fn current_container_slot() -> Option<usize> {
    active_container_slot()
}

pub(crate) fn container_domain_id(slot: usize) -> Option<u64> {
    crate::linux_profile::span(crate::linux_profile::Span::ContainerDomainId, || {
        container_domain_id_checked(slot)
    })
}

fn container_domain_id_checked(slot: usize) -> Option<u64> {
    let domain = X86_RUNTIME
        .CONTAINER_DOMAIN_IDS
        .get(slot)?
        .load(Ordering::Acquire);
    (domain != 0
        && domain::container_domain_for_slot(slot) == Some(domain)
        && domain::container_domain_limits(domain).is_some())
    .then_some(domain)
}

pub(crate) fn configured_container_init(output: &mut [u8]) -> Option<usize> {
    let slot = selected_container_slot()?;
    let size = usize::from(X86_RUNTIME.CONTAINER_INIT_SIZES[slot].load(Ordering::SeqCst));
    let output = output.get_mut(..size)?;
    for (destination, source) in output
        .iter_mut()
        .zip(&X86_RUNTIME.CONTAINER_INITS[slot][..size])
    {
        *destination = source.load(Ordering::SeqCst);
    }
    Some(size)
}

pub(crate) fn configured_container_image(output: &mut [u8]) -> Option<usize> {
    let slot = selected_container_slot()?;
    let size = usize::from(X86_RUNTIME.CONTAINER_IMAGE_SIZES[slot].load(Ordering::SeqCst));
    let output = output.get_mut(..size)?;
    for (destination, source) in output
        .iter_mut()
        .zip(&X86_RUNTIME.CONTAINER_IMAGES[slot][..size])
    {
        *destination = source.load(Ordering::SeqCst);
    }
    Some(size)
}

pub(crate) fn container_image_matches(slot: usize, image: &[u8]) -> bool {
    let Some(size) = X86_RUNTIME.CONTAINER_IMAGE_SIZES.get(slot) else {
        return false;
    };
    let size = usize::from(size.load(Ordering::Acquire));
    size == image.len()
        && X86_RUNTIME.CONTAINER_IMAGES[slot][..size]
            .iter()
            .zip(image)
            .all(|(stored, expected)| stored.load(Ordering::Acquire) == *expected)
}

pub(crate) fn take_container_pull_request() -> bool {
    X86_RUNTIME
        .CONTAINER_PULL_REQUESTED
        .swap(false, Ordering::AcqRel)
}

pub(crate) fn request_container_install() {
    X86_RUNTIME
        .CONTAINER_INSTALL_REQUESTED
        .store(true, Ordering::Release);
}

pub(crate) fn take_container_install_request() -> bool {
    X86_RUNTIME
        .CONTAINER_INSTALL_REQUESTED
        .swap(false, Ordering::AcqRel)
}

pub(crate) fn configured_container_console_attached() -> bool {
    selected_container_slot()
        .is_some_and(|slot| X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire))
}

pub(crate) fn detached_container_lifecycle_pending() -> bool {
    selected_container_slot().is_some_and(|slot| {
        !X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire)
            && (X86_RUNTIME.CONTAINER_PULL_REQUESTED.load(Ordering::Acquire)
                || X86_RUNTIME
                    .CONTAINER_INSTALL_REQUESTED
                    .load(Ordering::Acquire)
                || X86_RUNTIME
                    .CONTAINER_RESTART_REQUESTED
                    .load(Ordering::Acquire))
    })
}

pub(crate) fn complete_container_pull(success: bool) {
    let Some(slot) = selected_container_slot() else {
        return;
    };
    if success {
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
            .store(control_abi::DOMAIN_STATE_BOOTING as u8, Ordering::Release);
        X86_RUNTIME
            .CONTAINER_RESTART_REQUESTED
            .store(true, Ordering::Release);
    } else {
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
            .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::Release);
        X86_RUNTIME
            .CONTAINER_SELECTED_SLOT
            .store(CONTAINER_SLOT_NONE, Ordering::Release);
    }
}

fn store_container_name(slot: usize, name: &[u8]) {
    for (index, byte) in X86_RUNTIME.CONTAINER_NAMES[slot].iter().enumerate() {
        byte.store(name.get(index).copied().unwrap_or(0), Ordering::SeqCst);
    }
    X86_RUNTIME.CONTAINER_NAME_SIZES[slot].store(name.len() as u8, Ordering::SeqCst);
}

fn store_container_value<const N: usize>(value: &[u8], output: &[AtomicU8; N], size: &AtomicU8) {
    for (index, byte) in output.iter().enumerate() {
        byte.store(value.get(index).copied().unwrap_or(0), Ordering::SeqCst);
    }
    size.store(value.len() as u8, Ordering::SeqCst);
}

fn configurable_container(slot: Option<usize>) -> bool {
    slot.is_some_and(|slot| {
        matches!(
            container_state(slot),
            control_abi::DOMAIN_STATE_CREATED
                | control_abi::DOMAIN_STATE_CONFIGURED
                | control_abi::DOMAIN_STATE_STOPPED
                | control_abi::DOMAIN_STATE_FAILED
        )
    })
}

fn update_container_configuration(slot: usize, flag: u16) -> u64 {
    let flags = X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot].fetch_or(flag, Ordering::SeqCst) | flag;
    let state =
        if flags & control_abi::DOMAIN_CONFIG_COMPLETE == control_abi::DOMAIN_CONFIG_COMPLETE {
            control_abi::DOMAIN_STATE_CONFIGURED
        } else {
            control_abi::DOMAIN_STATE_CREATED
        };
    X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].store(state as u8, Ordering::SeqCst);
    state
}

/// Turns a yes-or-no domain setting (autostart, user switching) on or off.
fn update_container_flag(slot: usize, flag: u16, enabled: bool) -> u64 {
    if enabled {
        X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot].fetch_or(flag, Ordering::SeqCst);
    } else {
        X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot].fetch_and(!flag, Ordering::SeqCst);
    }
    update_container_configuration(slot, 0)
}

/// The domain in `slot` was configured with `privileged=true`; read only
/// by `linux_user::domain_privileged`.
pub(crate) fn container_privileged(slot: usize) -> bool {
    X86_RUNTIME
        .CONTAINER_CONFIG_FLAGS
        .get(slot)
        .is_some_and(|flags| {
            flags.load(Ordering::Acquire) & control_abi::DOMAIN_CONFIG_PRIVILEGED != 0
        })
}

/// The domain in `slot` was configured with `user-switching=true`; read
/// only by `linux_user::user_switching_allowed`.
pub(crate) fn container_user_switching(slot: usize) -> bool {
    X86_RUNTIME
        .CONTAINER_CONFIG_FLAGS
        .get(slot)
        .is_some_and(|flags| {
            flags.load(Ordering::Acquire) & control_abi::DOMAIN_CONFIG_USER_SWITCHING != 0
        })
}

fn write_container_request(
    request: &mut [u8; control_abi::DOMAIN_REQUEST_SIZE],
    slot: usize,
    next_cursor: u64,
) {
    request.fill(0);
    request[0..4].copy_from_slice(&(control_abi::DOMAIN_REQUEST_SIZE as u32).to_le_bytes());
    let size = usize::from(X86_RUNTIME.CONTAINER_NAME_SIZES[slot].load(Ordering::SeqCst));
    request[6..8].copy_from_slice(&(size as u16).to_le_bytes());
    for (output, stored) in request[8..8 + size]
        .iter_mut()
        .zip(&X86_RUNTIME.CONTAINER_NAMES[slot][..size])
    {
        *output = stored.load(Ordering::SeqCst);
    }
    request[4..6].copy_from_slice(&control_abi::DOMAIN_REQUEST_VERSION.to_le_bytes());
    let mut runtime_flags = 0;
    if X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire) {
        runtime_flags |= control_abi::DOMAIN_RUNTIME_CONSOLE_ATTACHED;
    }
    if crate::published_rootfs::is_installed(slot) {
        runtime_flags |= control_abi::DOMAIN_RUNTIME_ROOTFS_READY;
    }
    if address_space::linux_runtime_is_suspended(slot) {
        runtime_flags |= control_abi::DOMAIN_RUNTIME_SUSPENDED;
    }
    request[210] = runtime_flags;
    request[24..32].copy_from_slice(&next_cursor.to_le_bytes());
    let init_size = usize::from(X86_RUNTIME.CONTAINER_INIT_SIZES[slot].load(Ordering::SeqCst));
    request[32..34].copy_from_slice(&(init_size as u16).to_le_bytes());
    request[34..36].copy_from_slice(
        &X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot]
            .load(Ordering::SeqCst)
            .to_le_bytes(),
    );
    for (output, stored) in request[36..36 + init_size]
        .iter_mut()
        .zip(&X86_RUNTIME.CONTAINER_INITS[slot][..init_size])
    {
        *output = stored.load(Ordering::SeqCst);
    }
    let image_size = usize::from(X86_RUNTIME.CONTAINER_IMAGE_SIZES[slot].load(Ordering::SeqCst));
    request[68..70].copy_from_slice(&(image_size as u16).to_le_bytes());
    request[70..72].copy_from_slice(
        &X86_RUNTIME.CONTAINER_CPU_COUNTS[slot]
            .load(Ordering::Acquire)
            .to_le_bytes(),
    );
    for (output, stored) in request[72..72 + image_size]
        .iter_mut()
        .zip(&X86_RUNTIME.CONTAINER_IMAGES[slot][..image_size])
    {
        *output = stored.load(Ordering::SeqCst);
    }
    request[200..208].copy_from_slice(
        &X86_RUNTIME.CONTAINER_MEMORY_MIB[slot]
            .load(Ordering::Acquire)
            .to_le_bytes(),
    );
    let personality_size =
        usize::from(X86_RUNTIME.DOMAIN_PERSONALITY_SIZES[slot].load(Ordering::SeqCst));
    request[208..210].copy_from_slice(&(personality_size as u16).to_le_bytes());
    for (output, stored) in request[216..216 + personality_size]
        .iter_mut()
        .zip(&X86_RUNTIME.DOMAIN_PERSONALITIES[slot][..personality_size])
    {
        *output = stored.load(Ordering::SeqCst);
    }
}

fn read_u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn write_abi_descriptor(caller_domain: u64, frame: *const UserTrapFrame) -> u64 {
    let mut descriptor = control_abi::descriptor();
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if CONTROL_DESCRIPTOR_OVERRIDE_DOMAIN
        .compare_exchange(caller_domain, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        descriptor[12] = 1;
    }
    if frame.second_argument() != descriptor.len() as u64
        || !address_space::copy_to_current_user(frame.first_argument(), &descriptor)
    {
        return u64::MAX - 2;
    }
    SYSCALL_STATE.fetch_or(16, Ordering::SeqCst);
    descriptor.len() as u64
}

fn write_fault_descriptor(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::MANAGE)
        || frame.second_argument() != control_abi::FAULT_DESCRIPTOR_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let Some(descriptor) = domain::delivered_fault_descriptor() else {
        return u64::MAX - 2;
    };
    if !address_space::copy_to_current_user(frame.first_argument(), &descriptor) {
        return u64::MAX - 2;
    }
    descriptor.len() as u64
}

fn write_lifecycle_descriptor(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::MANAGE)
        || frame.second_argument() != control_abi::LIFECYCLE_DESCRIPTOR_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let Some(descriptor) = domain::delivered_lifecycle_event_descriptor() else {
        return u64::MAX - 2;
    };
    if !address_space::copy_to_current_user(frame.first_argument(), &descriptor) {
        return u64::MAX - 2;
    }
    descriptor.len() as u64
}

fn write_ipc_delivery_descriptor(
    domain_id: u64,
    capability: u64,
    frame: *const UserTrapFrame,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 3, Rights::READ)
        || frame.second_argument() != control_abi::IPC_DELIVERY_DESCRIPTOR_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let Some(descriptor) = ipc::delivery_descriptor(domain_id) else {
        return u64::MAX - 2;
    };
    if !address_space::copy_to_current_user(frame.first_argument(), &descriptor) {
        return u64::MAX - 2;
    }
    descriptor.len() as u64
}

fn write_lifecycle_identity_descriptor(
    domain_id: u64,
    capability: u64,
    frame: *const UserTrapFrame,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::MANAGE)
        || frame.second_argument() != control_abi::LIFECYCLE_IDENTITY_DESCRIPTOR_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let Some(descriptor) = domain::delivered_lifecycle_identity_descriptor() else {
        return u64::MAX - 2;
    };
    if !address_space::copy_to_current_user(frame.first_argument(), &descriptor) {
        return u64::MAX - 2;
    }
    descriptor.len() as u64
}

fn runtime_result(frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX;
    };
    let action = scheduler::yield_runtime(
        frame,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        active_fs_base(),
    );
    resume_action(action)
}

fn exit_result(caller_domain: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX;
    };
    let failure_policy = domain::service_failure_policy(caller_domain);
    let auxiliary_exit_status = if failure_policy == Some(domain::ServiceFailurePolicy::StopOnly) {
        let Ok(status) = u8::try_from(frame.first_argument()) else {
            return u64::MAX - 2;
        };
        Some(status)
    } else {
        None
    };
    let service_exit = failure_policy == Some(domain::ServiceFailurePolicy::RestartManaged);
    let close_wait = if failure_policy == Some(domain::ServiceFailurePolicy::StopOnly) {
        None
    } else {
        Some(scheduler::WaitReason::IpcReceive {
            object: 3,
            service_side: !service_exit,
            peer_domain: caller_domain,
        })
    };
    if failure_policy == Some(domain::ServiceFailurePolicy::StopOnly) {
        if !crate::packet::retire_egress_producer_if_bound(caller_domain) {
            serial_write("linox: auxiliary exit egress retirement failed\r\n");
            return u64::MAX;
        }
        if crate::packet::egress_is_empty() {
            if let Some((waiting_domain, sequence)) = scheduler::blocked_egress_waiter() {
                if domain::take_blocked_auxiliary_drain_request(waiting_domain)
                    && !scheduler::wake_egress_waiter_drained(caller_domain, sequence)
                {
                    serial_write("linox: auxiliary exit drain wake failed\r\n");
                    return u64::MAX;
                }
            }
        }
    }
    let action = scheduler::exit_runtime(frame, USER_CODE_SELECTOR, USER_DATA_SELECTOR, close_wait);
    if matches!(action, RuntimeAction::Invalid) {
        serial_write("linox: runtime exit scheduling failed\r\n");
        return u64::MAX;
    }
    if !domain::detach_thread(caller_domain) {
        serial_write("linox: runtime exit thread detach failed\r\n");
        return u64::MAX;
    }
    if service_exit
        && (!ipc::retire_service(caller_domain) || !domain::retire_clean_service(caller_domain))
    {
        return u64::MAX;
    }
    if failure_policy == Some(domain::ServiceFailurePolicy::StopOnly) {
        if !domain::begin_auxiliary_runtime_exit(caller_domain, auxiliary_exit_status.unwrap_or(0))
        {
            serial_write("linox: auxiliary exit transition failed\r\n");
            return u64::MAX;
        }
        if !address_space::quiesce_auxiliary_device(caller_domain) {
            serial_write("linox: auxiliary exit quiesce failed status: ");
            serial_write_u64(u64::from(auxiliary_exit_status.unwrap_or(0)));
            serial_write("\r\n");
            return u64::MAX;
        }
        if !address_space::activate_kernel_root_for_auxiliary(caller_domain) {
            serial_write("linox: auxiliary exit kernel-root restoration failed\r\n");
            return u64::MAX;
        }
        if !address_space::release_auxiliary_address_space(caller_domain) {
            serial_write("linox: auxiliary exit address-space release failed\r\n");
            return u64::MAX;
        }
        if !domain::retire_stopped_auxiliary_service(caller_domain) {
            serial_write("linox: auxiliary exit retirement failed\r\n");
            return u64::MAX;
        }
    }
    resume_action(action)
}

extern "sysv64" fn user_fault_handler(frame: *mut UserFaultFrame) -> u64 {
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

enum ServiceRestartSetup {
    Started,
    Unavailable,
    RollbackFailed,
}

fn setup_service_restart(fault_domain: u64) -> ServiceRestartSetup {
    let Some(replacement_domain) = domain::initialize_boot_service_restart() else {
        return ServiceRestartSetup::Unavailable;
    };
    let Some(replacement_handle) = domain::service_boot_handle() else {
        return if domain::discard_unstarted_service(replacement_domain) {
            ServiceRestartSetup::Unavailable
        } else {
            ServiceRestartSetup::RollbackFailed
        };
    };
    if !ipc::bind_service(replacement_domain) {
        return if domain::discard_unstarted_service(replacement_domain) {
            ServiceRestartSetup::Unavailable
        } else {
            ServiceRestartSetup::RollbackFailed
        };
    }
    let (Some(old_owner), Some(replacement_owner)) = (
        memory::FrameOwner::domain(fault_domain),
        memory::FrameOwner::domain(replacement_domain),
    ) else {
        return rollback_unstarted_replacement(replacement_domain, true);
    };
    if memory::transfer_frame_owner(old_owner, replacement_owner)
        != Some(address_space::USER_ADDRESS_SPACE_FRAMES)
    {
        return rollback_unstarted_replacement(replacement_domain, true);
    }
    if !domain::adopt_quarantined_service_frames(fault_domain, replacement_domain) {
        let _ = memory::transfer_frame_owner(replacement_owner, old_owner);
        return rollback_unstarted_replacement(replacement_domain, true);
    }
    if !scheduler::queue_service_restart(replacement_domain, replacement_handle) {
        return rollback_transferred_replacement(
            replacement_domain,
            fault_domain,
            old_owner,
            replacement_owner,
            false,
        );
    }
    if !timer::rearm_scheduler_preemption() {
        return rollback_transferred_replacement(
            replacement_domain,
            fault_domain,
            old_owner,
            replacement_owner,
            true,
        );
    }
    SERVICE_FRAMES_TRANSFERRED.store(true, Ordering::Release);
    ServiceRestartSetup::Started
}

fn rollback_unstarted_replacement(replacement_domain: u64, bound: bool) -> ServiceRestartSetup {
    if (!bound || ipc::rollback_service_binding(replacement_domain))
        && domain::discard_unstarted_service(replacement_domain)
    {
        ServiceRestartSetup::Unavailable
    } else {
        ServiceRestartSetup::RollbackFailed
    }
}

fn rollback_transferred_replacement(
    replacement_domain: u64,
    fault_domain: u64,
    old_owner: memory::FrameOwner,
    replacement_owner: memory::FrameOwner,
    queued: bool,
) -> ServiceRestartSetup {
    if (!queued || scheduler::rollback_service_restart(replacement_domain, fault_domain))
        && memory::transfer_frame_owner(replacement_owner, old_owner)
            == Some(address_space::USER_ADDRESS_SPACE_FRAMES)
        && domain::restore_quarantined_service_frames(fault_domain, replacement_domain)
        && ipc::rollback_service_binding(replacement_domain)
        && domain::discard_unstarted_service(replacement_domain)
    {
        ServiceRestartSetup::Unavailable
    } else {
        ServiceRestartSetup::RollbackFailed
    }
}

fn scrub_service_restart_stack() -> bool {
    const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
    let Some((root, stack_top)) = scheduler::service_restart_stack_mapping() else {
        return false;
    };
    let active_root: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) active_root, options(nomem, nostack, preserves_flags));
    }
    let Some(stack_base) = stack_top.checked_sub(PAGE_SIZE as u64) else {
        return false;
    };
    if active_root & ADDRESS_MASK != root || stack_top % PAGE_SIZE as u64 != 0 || stack_base == 0 {
        return false;
    }
    let zeroes = [0_u8; 128];
    let mut observed = [0xff_u8; 128];
    let mut scrubbed = true;
    for offset in (0..PAGE_SIZE).step_by(zeroes.len()) {
        scrubbed &= unsafe {
            raw_copy_to_user(
                (stack_base as usize + offset) as *mut u8,
                zeroes.as_ptr(),
                zeroes.len(),
            ) == 0
                && raw_copy_from_user(
                    observed.as_mut_ptr(),
                    (stack_base as usize + offset) as *const u8,
                    observed.len(),
                ) == 0
        } && observed == zeroes;
        if !scrubbed {
            break;
        }
    }
    if !scrubbed {
        return false;
    }
    SERVICE_STACK_SCRUBBED.store(true, Ordering::Release);
    true
}

pub(crate) fn service_restart_stack_was_scrubbed() -> bool {
    SERVICE_STACK_SCRUBBED.load(Ordering::Acquire)
}

pub(crate) fn service_address_space_frames_were_transferred() -> bool {
    SERVICE_FRAMES_TRANSFERRED.load(Ordering::Acquire)
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
    unsafe { read_msr(FS_BASE_MSR) }
}

pub(crate) fn verify_user_fs_base_installation() -> bool {
    let saved = active_fs_base();
    let first_installed = install_user_fs_base(0x1110);
    let second_installed = install_user_fs_base(0x2220);
    unsafe { write_msr(FS_BASE_MSR, saved) };
    first_installed && second_installed && active_fs_base() == saved
}

fn install_current_scheduler_fs_base() -> bool {
    scheduler::current_fs_base().is_some_and(install_user_fs_base)
}

fn install_user_fs_base(fs_base: u64) -> bool {
    if fs_base >= 1 << 47 {
        return false;
    }
    unsafe { write_msr(FS_BASE_MSR, fs_base) };
    active_fs_base() == fs_base
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
    let active: u64;
    super::smp::note_active_root(root);
    unsafe {
        asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    }
    super::smp::note_root_loaded();
    active & ADDRESS_MASK == root
}

unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
    (u64::from(high) << 32) | u64::from(low)
}

unsafe fn write_msr(msr: u32, value: u64) {
    asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nomem, nostack, preserves_flags));
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
extern "sysv64" fn fatal_exception_handler(
    vector: u64,
    error: u64,
    fault_address: u64,
    instruction: u64,
    frame: *const u64,
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
    // SAFETY: the entry stub pushed the 15 general registers, then the vector
    // and error code, and the CPU pushed rip, cs, rflags, rsp and ss.
    let saved = |index: usize| unsafe { frame.add(index).read_volatile() };
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
    let (cr0, cr3, cr4): (u64, u64, u64);
    // SAFETY: reading control registers has no side effects.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
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
            // SAFETY: the page holding `address` is mapped, checked above; this is a
            // kernel stack address, never a userspace one.
            let value = unsafe { core::ptr::read_volatile(address as *const u64) };
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
