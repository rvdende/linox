#![forbid(unsafe_code)]
//! This CPU core's descriptor tables, entry states and stacks, kept by
//! `trusted::cpu_tables`, and the checks the boot path makes of them.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

pub(super) use crate::trusted::cpu_tables::CpuEntryState;
use crate::trusted::cpu_tables::{self, CpuStackArray, CpuTables, Gate, KERNEL_GATE, USER_GATE};
use crate::trusted::entry::EntryStub;
use crate::trusted::{control, tsc};

use super::{
    BOOT_CPU_INDEX, CPU_ENTRY_STATE_LIMIT, CPU_KERNEL_STACK_STORAGE_SIZE,
    CPU_KERNEL_STACK_TOP_OFFSET, DOUBLE_FAULT_IST, EXCEPTION_STACK_STORAGE_SIZE,
    EXCEPTION_STACK_TOP_OFFSET, GS_BASE_MSR, IST_STACK_STORAGE_SIZE, IST_STACK_TOP_OFFSET,
    KERNEL_CODE_SELECTOR, KERNEL_DATA_SELECTOR, KERNEL_GS_BASE_MSR, MACHINE_CHECK_IST, NMI_IST,
    SYSCALL_VECTOR, TSS_SELECTOR,
};

type ExceptionStacks = CpuStackArray<EXCEPTION_STACK_STORAGE_SIZE, CPU_ENTRY_STATE_LIMIT>;
type KernelStacks = CpuStackArray<CPU_KERNEL_STACK_STORAGE_SIZE, CPU_ENTRY_STATE_LIMIT>;
type IstStacks = CpuStackArray<IST_STACK_STORAGE_SIZE, CPU_ENTRY_STATE_LIMIT>;

// The entry assembly in cpu.rs uses its own copies of the selectors, the
// stack indexes and the stack layout; they must be the trusted core's.
const _: () = {
    assert!(KERNEL_CODE_SELECTOR == cpu_tables::KERNEL_CODE_SELECTOR);
    assert!(KERNEL_DATA_SELECTOR == cpu_tables::KERNEL_DATA_SELECTOR);
    assert!(TSS_SELECTOR == cpu_tables::TSS_SELECTOR);
    assert!(DOUBLE_FAULT_IST == cpu_tables::DOUBLE_FAULT_IST);
    assert!(NMI_IST == cpu_tables::NMI_IST);
    assert!(MACHINE_CHECK_IST == cpu_tables::MACHINE_CHECK_IST);
    assert!(GS_BASE_MSR == cpu_tables::GS_BASE_MSR);
    assert!(KERNEL_GS_BASE_MSR == cpu_tables::KERNEL_GS_BASE_MSR);
    assert!(EXCEPTION_STACK_TOP_OFFSET == ExceptionStacks::top_offset());
    assert!(CPU_KERNEL_STACK_TOP_OFFSET == KernelStacks::top_offset());
    assert!(IST_STACK_TOP_OFFSET == IstStacks::top_offset());
};

pub(super) struct CpuArchitectureOwner {
    pub(super) extended_user_state_enabled: AtomicBool,
}

pub(super) static CPU_ARCHITECTURE: CpuArchitectureOwner = CpuArchitectureOwner {
    extended_user_state_enabled: AtomicBool::new(false),
};

/// Each CPU's entry state, GDT, TSS and IDT, and the exception stacks its
/// TSS names. All zero at first, so its stacks take no space in the kernel
/// image.
static CPU_TABLES: CpuTables<
    CPU_ENTRY_STATE_LIMIT,
    EXCEPTION_STACK_STORAGE_SIZE,
    IST_STACK_STORAGE_SIZE,
> = CpuTables::new();

/// Each CPU's own kernel stack (application processors start on theirs).
static KERNEL_STACKS: CpuStackArray<CPU_KERNEL_STACK_STORAGE_SIZE, CPU_ENTRY_STATE_LIMIT> =
    CpuStackArray::new();

pub(crate) fn install() -> bool {
    let installed = install_for_cpu(BOOT_CPU_INDEX);
    if installed {
        enable_fast_cpu_index();
    }
    installed
}

pub(crate) fn install_for_cpu(cpu: usize) -> bool {
    // Initialization runs once per CPU with interrupts disabled. The trusted
    // core writes this CPU's entry state and points GS_BASE at it (ring 3
    // begins with the architectural user GS base; Linux syscall and
    // user-fault entry use SWAPGS to recover this CPU's private entry state
    // without exposing it through ordinary userspace GS accesses), sets
    // IA32_TSC_AUX to the CPU number as Linux keeps it there (node 0), which
    // RDPID and RDTSCP read back far faster than GS_BASE (see
    // current_cpu_index_checked), and loads the GDT, TSS and IDT.
    CPU_TABLES.install(cpu) && entry_state_is_installed() && exception_gates_are_valid(cpu)
}

/// A copy of this CPU's entry state, for checks.
pub(super) fn current_entry_state_copy() -> Option<CpuEntryState> {
    CPU_TABLES.current_entry_state_copy()
}

/// Runs `body`, then puts this CPU's entry state back as it was.
pub(super) fn with_entry_state_restored<R>(body: impl FnOnce() -> R) -> R {
    CPU_TABLES.with_entry_state_restored(body)
}

fn entry_state_is_installed() -> bool {
    CPU_TABLES.current_index().is_some()
}

pub(crate) fn current_cpu_index() -> usize {
    current_cpu_index_checked().expect("CPU entry state is installed")
}

/// How this CPU's index is read: 0 from GS_BASE (an RDMSR, about a hundred
/// cycles, and the kernel reads the index for every banked runtime field),
/// 1 with RDPID, 2 with RDTSCP, both from IA32_TSC_AUX.
static CPU_INDEX_SOURCE: AtomicU8 = AtomicU8::new(0);

/// Reads CPU indexes from IA32_TSC_AUX from now on where the CPU can: every
/// CPU sets it as it installs its entry state, application processors before
/// anything else.
pub(crate) fn enable_fast_cpu_index() {
    let leaf_7 = core::arch::x86_64::__cpuid_count(7, 0);
    let extended = core::arch::x86_64::__cpuid(0x8000_0001);
    let source = if leaf_7.ecx & (1 << 22) != 0 {
        1
    } else if extended.edx & (1 << 27) != 0 {
        2
    } else {
        0
    };
    CPU_INDEX_SOURCE.store(source, Ordering::Release);
}

pub(crate) fn current_cpu_index_checked() -> Option<usize> {
    match CPU_INDEX_SOURCE.load(Ordering::Relaxed) {
        // Both read IA32_TSC_AUX, which install_for_cpu set; only a CPU
        // with the instruction gets here (enable_fast_cpu_index).
        1 => Some(tsc::processor_id() as usize & 0xfff),
        2 => Some(tsc::read_with_processor_id().1 as usize & 0xfff),
        _ => CPU_TABLES.current_index(),
    }
}

pub(crate) fn task_register_denies_user_io() -> bool {
    let selector = control::task_register();
    let cpu = current_cpu_index();
    let low = CPU_TABLES.gdt_entry(cpu, 3);
    let high = CPU_TABLES.gdt_entry(cpu, 4);
    let limit = (low & 0xffff) | ((low >> 32) & 0x000f_0000);
    let base =
        ((low >> 16) & 0x00ff_ffff) | ((low >> 32) & 0xff00_0000) | ((high & 0xffff_ffff) << 32);
    let Some((tss_address, io_map_base)) = CPU_TABLES.tss(cpu) else {
        return false;
    };
    selector == TSS_SELECTOR
        && low & (1 << 47) != 0
        && (low >> 40) & 0x0f == 0x0b
        && limit == CPU_TABLES.tss_limit()
        && base == tss_address
        && u64::from(io_map_base) > limit
}

pub(crate) fn user_interrupt_surface_is_minimal() -> bool {
    let cpu = current_cpu_index();
    for vector in 0..256 {
        let entry = CPU_TABLES.gate(cpu, vector);
        if vector == usize::from(SYSCALL_VECTOR) {
            if entry.selector != KERNEL_CODE_SELECTOR
                || entry.attributes != USER_GATE
                || entry.ist != 0
                || entry.reserved != 0
                || !entry.has_handler()
            {
                return false;
            }
        } else if vector <= 32 || vector == 255 || !entry.is_missing() {
            // Kernel interrupt sources may populate additional vectors, but
            // none may enlarge the user-callable surface beyond INT 0x80.
            if entry.selector != KERNEL_CODE_SELECTOR
                || entry.attributes != KERNEL_GATE
                || entry.ist != exception_ist(vector)
                || entry.reserved != 0
                || !entry.has_handler()
            {
                return false;
            }
        }
    }
    true
}

pub(crate) fn double_fault_guard_page() -> usize {
    CPU_TABLES.double_fault_stacks.guard_page(BOOT_CPU_INDEX)
}

pub(crate) fn double_fault_stack_top() -> usize {
    CPU_TABLES.double_fault_stacks.top(BOOT_CPU_INDEX)
}

pub(crate) fn nmi_guard_page() -> usize {
    CPU_TABLES.nmi_stacks.guard_page(BOOT_CPU_INDEX)
}

#[allow(dead_code)]
pub(crate) fn nmi_upper_guard_page() -> usize {
    nmi_guard_page() + IST_STACK_TOP_OFFSET
}

pub(crate) fn nmi_stack_top() -> usize {
    CPU_TABLES.nmi_stacks.top(BOOT_CPU_INDEX)
}

pub(crate) fn machine_check_guard_page() -> usize {
    CPU_TABLES.machine_check_stacks.guard_page(BOOT_CPU_INDEX)
}

#[allow(dead_code)]
pub(crate) fn machine_check_upper_guard_page() -> usize {
    machine_check_guard_page() + IST_STACK_TOP_OFFSET
}

pub(crate) fn machine_check_stack_top() -> usize {
    CPU_TABLES.machine_check_stacks.top(BOOT_CPU_INDEX)
}

pub(crate) fn privilege_stack_guard_page() -> usize {
    CPU_TABLES.privilege_stacks.guard_page(BOOT_CPU_INDEX)
}

pub(crate) fn privilege_stack_top() -> usize {
    CPU_TABLES.privilege_stacks.top(BOOT_CPU_INDEX)
}

pub(crate) fn kernel_stack_top_for_cpu(cpu: usize) -> Option<usize> {
    (cpu < CPU_ENTRY_STATE_LIMIT).then(|| KERNEL_STACKS.top(cpu))
}

pub(crate) fn stack_guard_pages() -> [usize; CPU_ENTRY_STATE_LIMIT * 10] {
    let mut pages = [0; CPU_ENTRY_STATE_LIMIT * 10];
    for cpu in 0..CPU_ENTRY_STATE_LIMIT {
        let bounds = [
            (
                CPU_TABLES.privilege_stacks.guard_page(cpu),
                CPU_TABLES.privilege_stacks.top(cpu),
            ),
            (KERNEL_STACKS.guard_page(cpu), KERNEL_STACKS.top(cpu)),
            (
                CPU_TABLES.double_fault_stacks.guard_page(cpu),
                CPU_TABLES.double_fault_stacks.top(cpu),
            ),
            (
                CPU_TABLES.nmi_stacks.guard_page(cpu),
                CPU_TABLES.nmi_stacks.top(cpu),
            ),
            (
                CPU_TABLES.machine_check_stacks.guard_page(cpu),
                CPU_TABLES.machine_check_stacks.top(cpu),
            ),
        ];
        for (stack, (lower, upper)) in bounds.into_iter().enumerate() {
            pages[cpu * 10 + stack * 2] = lower;
            pages[cpu * 10 + stack * 2 + 1] = upper;
        }
    }
    pages
}

/// Installs a non-exception interrupt gate while interrupts are disabled.
pub(crate) fn install_interrupt_gate(vector: u8, stub: EntryStub) -> bool {
    if vector < 32 {
        return false;
    }
    // Bootstrap remains single-threaded with interrupts disabled, and the
    // vector is outside the exception range.
    if !CPU_TABLES.set_gate_on_every_cpu(vector, Some(stub), KERNEL_GATE) {
        return false;
    }
    let entry = CPU_TABLES.gate(current_cpu_index(), usize::from(vector));
    entry.selector == KERNEL_CODE_SELECTOR && entry.attributes == KERNEL_GATE && entry.ist == 0
}

/// Removes a temporary kernel interrupt gate while interrupts are disabled.
pub(crate) fn clear_interrupt_gate(vector: u8) -> bool {
    if vector <= 32 || vector == SYSCALL_VECTOR || vector == u8::MAX {
        return false;
    }
    // The caller has quiesced the interrupt source and keeps interrupts
    // disabled while replacing this non-reserved gate.
    CPU_TABLES.set_gate_on_every_cpu(vector, None, KERNEL_GATE)
        && CPU_TABLES
            .gate(current_cpu_index(), usize::from(vector))
            .is_missing()
}

pub(super) fn install_user_interrupt_gate(vector: u8, stub: EntryStub) -> bool {
    if vector < 32 {
        return false;
    }
    CPU_TABLES.set_gate_on_every_cpu(vector, Some(stub), USER_GATE)
        && CPU_TABLES
            .gate(current_cpu_index(), usize::from(vector))
            .attributes
            == USER_GATE
}

fn exception_gates_are_valid(cpu: usize) -> bool {
    (0..32).all(|vector| {
        let entry: Gate = CPU_TABLES.gate(cpu, vector);
        entry.selector == KERNEL_CODE_SELECTOR
            && entry.attributes == KERNEL_GATE
            && entry.ist == exception_ist(vector)
            && entry.has_handler()
    })
}

/// The interrupt-stack-table index of exception `vector`'s gate, as the
/// trusted core installs it.
const fn exception_ist(vector: usize) -> u8 {
    const {
        assert!(cpu_tables::exception_ist(2) == NMI_IST);
        assert!(cpu_tables::exception_ist(8) == DOUBLE_FAULT_IST);
        assert!(cpu_tables::exception_ist(18) == MACHINE_CHECK_IST);
    }
    cpu_tables::exception_ist(vector)
}
