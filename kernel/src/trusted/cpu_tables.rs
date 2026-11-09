//! Each CPU's descriptor tables (GDT, TSS, IDT), its entry-state record,
//! and the stacks its TSS names.
//!
//! [`CpuTables`] holds, per CPU index, the record the system-call and
//! user-fault stubs in `cpu.rs` reach through GS ([`CpuEntryState`]), a
//! GDT with the kernel's fixed segments and a TSS descriptor, the TSS
//! itself, an IDT, and the four stacks the TSS names (where an interrupt
//! from ring 3 switches to, and the NMI, double-fault and machine-check
//! stacks). [`CpuTables::install`] fills them for one CPU and loads them on
//! the CPU that calls it: GS_BASE names the CPU's entry state, the GDT and
//! TSS are loaded with the kernel's segments and the CPU's own stacks, and
//! the 32 exception gates point at `cpu.rs`'s exception stubs
//! (`linox_exception_entries`), the NMI, double-fault and machine-check
//! ones on their stacks. The tables are atomics the processor reads in
//! place, so reading them for the boot checks and writing a gate need no
//! `unsafe`. Everything starts zeroed, so the tables and their tens of
//! megabytes of stacks take no space in the kernel image.
//!
//! [`CpuStackArray`] is an array of stacks, one per CPU, each with a guard
//! page below and above (which `lib.rs` unmaps). Rust never reads or
//! writes them; the processor switches to them (the TSS's stacks) or code
//! runs on them (each CPU's kernel stack, a `CpuStackArray` of the CPU
//! core's own).
//!
//! The invariants the `unsafe` blocks rely on:
//! - each CPU index is installed once, by the CPU it names
//!   ([`CpuTables::install`] refuses an index already installed), so no
//!   two CPUs share an entry state, a TSS or the stacks it names;
//! - the GDT and the TSS are written only by `install`, before they are
//!   loaded, so what the CPU loads is the kernel's segments and its own
//!   stacks;
//! - an exception gate (vectors 0-31) is written only by `install`, with
//!   `cpu.rs`'s stub for that vector.
//!
//! Known gap, as before this module: the gates above vector 31 take the
//! handler address their caller names (`arch/x86_64/cpu/architecture.rs`'s
//! `install_interrupt_gate` and `install_user_interrupt_gate`, whose
//! callers pass `trusted::entry`'s stubs and `cpu.rs`'s system-call
//! entry). An address that is not an entry stub would be jumped to in ring
//! 0 by the next such interrupt. A typed stub handle closes this once
//! `cpu.rs`'s stubs move into `trusted::entry`.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

pub(crate) const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub(crate) const KERNEL_DATA_SELECTOR: u16 = 0x10;
pub(crate) const TSS_SELECTOR: u16 = 0x18;
pub(crate) const DOUBLE_FAULT_IST: u8 = 1;
pub(crate) const NMI_IST: u8 = 2;
pub(crate) const MACHINE_CHECK_IST: u8 = 3;
/// Interrupt gate, present, callable from ring 0 only.
pub(crate) const KERNEL_GATE: u8 = 0x8e;
/// Interrupt gate, present, callable from ring 3 (`int`).
pub(crate) const USER_GATE: u8 = 0xee;

const PAGE_SIZE: usize = 4096;
const EXCEPTION_VECTORS: usize = 32;
const VECTORS: usize = 256;
const GDT_ENTRIES: usize = 7;
const TSS_SIZE: usize = 104;
const TSS_WORDS: usize = TSS_SIZE / 4;
pub(crate) const GS_BASE_MSR: u32 = 0xc000_0101;
pub(crate) const KERNEL_GS_BASE_MSR: u32 = 0xc000_0102;
const TSC_AUX_MSR: u32 = 0xc000_0103;

/// The kernel's segments: null, kernel code and data, the TSS (two
/// entries, filled per CPU), user data and user code.
const KERNEL_CODE_DESCRIPTOR: u64 = 0x00af_9a00_0000_ffff;
const KERNEL_DATA_DESCRIPTOR: u64 = 0x00af_9200_0000_ffff;
const USER_DATA_DESCRIPTOR: u64 = 0x00cf_f200_0000_ffff;
const USER_CODE_DESCRIPTOR: u64 = 0x00af_fa00_0000_ffff;

extern "C" {
    /// The 32 exception stubs' addresses, in `cpu.rs`'s entry assembly.
    static linox_exception_entries: [usize; EXCEPTION_VECTORS];
}

/// The address of the exception stubs' table, for the CPU core to check
/// against its own declaration.
pub(crate) fn exception_entries() -> *const usize {
    core::ptr::addr_of!(linox_exception_entries).cast()
}

/// What `cpu.rs`'s entry stubs keep per CPU, at GS while in the kernel:
/// the kernel stack to return to, the user context of a system call and
/// what the signal return path restores. The stubs use these fields at
/// fixed offsets (asserted below).
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub(crate) struct CpuEntryState {
    pub(crate) return_stack: u64,
    pub(crate) user_rsp: u64,
    pub(crate) user_rip: u64,
    pub(crate) user_rflags: u64,
    pub(crate) kernel_frame: u64,
    pub(crate) syscall_result: u64,
    pub(crate) signal_rax: u64,
    pub(crate) signal_rcx: u64,
    pub(crate) signal_r11: u64,
}

const _: () = {
    assert!(core::mem::offset_of!(CpuEntryState, return_stack) == 0);
    assert!(core::mem::offset_of!(CpuEntryState, user_rsp) == 8);
    assert!(core::mem::offset_of!(CpuEntryState, user_rip) == 16);
    assert!(core::mem::offset_of!(CpuEntryState, user_rflags) == 24);
    assert!(core::mem::offset_of!(CpuEntryState, kernel_frame) == 32);
    assert!(core::mem::offset_of!(CpuEntryState, syscall_result) == 40);
    assert!(core::mem::offset_of!(CpuEntryState, signal_rax) == 48);
    assert!(core::mem::offset_of!(CpuEntryState, signal_rcx) == 56);
    assert!(core::mem::offset_of!(CpuEntryState, signal_r11) == 64);
};

impl CpuEntryState {
    pub(crate) const EMPTY: Self = Self {
        return_stack: 0,
        user_rsp: 0,
        user_rip: 0,
        user_rflags: 0,
        kernel_frame: 0,
        syscall_result: 0,
        signal_rax: 0,
        signal_rcx: 0,
        signal_r11: 0,
    };
}

/// One interrupt gate as the IDT holds it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Gate {
    pub(crate) handler: u64,
    pub(crate) selector: u16,
    pub(crate) ist: u8,
    pub(crate) attributes: u8,
    pub(crate) reserved: u32,
}

impl Gate {
    pub(crate) const MISSING: Self = Self {
        handler: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        reserved: 0,
    };

    fn interrupt(handler: usize, ist: u8, attributes: u8) -> Self {
        Self {
            handler: handler as u64,
            selector: KERNEL_CODE_SELECTOR,
            ist,
            attributes,
            reserved: 0,
        }
    }

    fn encode(self) -> [u64; 2] {
        let low = (self.handler & 0xffff)
            | (u64::from(self.selector) << 16)
            | (u64::from(self.ist) << 32)
            | (u64::from(self.attributes) << 40)
            | (((self.handler >> 16) & 0xffff) << 48);
        let high = (self.handler >> 32) | (u64::from(self.reserved) << 32);
        [low, high]
    }

    fn decode([low, high]: [u64; 2]) -> Self {
        Self {
            handler: (low & 0xffff) | (((low >> 48) & 0xffff) << 16) | ((high & 0xffff_ffff) << 32),
            selector: (low >> 16) as u16,
            ist: (low >> 32) as u8,
            attributes: (low >> 40) as u8,
            reserved: (high >> 32) as u32,
        }
    }

    pub(crate) fn is_missing(self) -> bool {
        self == Self::MISSING
    }

    pub(crate) fn has_handler(self) -> bool {
        self.handler != 0
    }
}

/// The interrupt-stack-table index of exception `vector`'s gate.
pub(crate) const fn exception_ist(vector: usize) -> u8 {
    match vector {
        2 => NMI_IST,
        8 => DOUBLE_FAULT_IST,
        18 => MACHINE_CHECK_IST,
        _ => 0,
    }
}

#[repr(C, align(4096))]
struct Idt([AtomicU64; VECTORS * 2]);

#[repr(C, align(64))]
struct Gdt([AtomicU64; GDT_ENTRIES]);

/// The 64-bit TSS as 32-bit words: its 64-bit fields sit at offsets that
/// are multiples of 4 only.
#[repr(C, align(128))]
struct Tss([AtomicU32; TSS_WORDS]);

impl Tss {
    fn set_u64(&self, offset: usize, value: u64) {
        self.0[offset / 4].store(value as u32, Ordering::Relaxed);
        self.0[offset / 4 + 1].store((value >> 32) as u32, Ordering::Relaxed);
    }
}

#[repr(transparent)]
struct EntryStateCell(UnsafeCell<CpuEntryState>);

/// The tables and TSS stacks of `CPUS` CPUs, with privilege stacks of
/// `PRIVILEGE_STACK` bytes and interrupt-stack-table stacks of
/// `IST_STACK` bytes (each with its guard pages).
pub(crate) struct CpuTables<const CPUS: usize, const PRIVILEGE_STACK: usize, const IST_STACK: usize>
{
    installed: [AtomicBool; CPUS],
    entry_states: [EntryStateCell; CPUS],
    gdt: [Gdt; CPUS],
    tss: [Tss; CPUS],
    idt: [Idt; CPUS],
    /// Where the processor switches on an interrupt from ring 3 (RSP0).
    pub(crate) privilege_stacks: CpuStackArray<PRIVILEGE_STACK, CPUS>,
    pub(crate) double_fault_stacks: CpuStackArray<IST_STACK, CPUS>,
    pub(crate) nmi_stacks: CpuStackArray<IST_STACK, CPUS>,
    pub(crate) machine_check_stacks: CpuStackArray<IST_STACK, CPUS>,
}

// SAFETY: everything but the entry states is atomic. Each entry state is
// written by Rust only in `install` (before its CPU's GS names it) and in
// `with_entry_state_restored` (on the CPU whose GS names it); otherwise it
// is reached through the raw pointer `current_entry_state` hands out, by
// the CPU it belongs to (the module invariant), as `cpu.rs`'s stubs reach
// it through GS.
unsafe impl<const CPUS: usize, const PRIVILEGE_STACK: usize, const IST_STACK: usize> Sync
    for CpuTables<CPUS, PRIVILEGE_STACK, IST_STACK>
{
}

impl<const CPUS: usize, const PRIVILEGE_STACK: usize, const IST_STACK: usize>
    CpuTables<CPUS, PRIVILEGE_STACK, IST_STACK>
{
    pub(crate) const fn new() -> Self {
        Self {
            installed: [const { AtomicBool::new(false) }; CPUS],
            entry_states: [const { EntryStateCell(UnsafeCell::new(CpuEntryState::EMPTY)) }; CPUS],
            gdt: [const { Gdt([const { AtomicU64::new(0) }; GDT_ENTRIES]) }; CPUS],
            tss: [const { Tss([const { AtomicU32::new(0) }; TSS_WORDS]) }; CPUS],
            idt: [const { Idt([const { AtomicU64::new(0) }; VECTORS * 2]) }; CPUS],
            privilege_stacks: CpuStackArray::new(),
            double_fault_stacks: CpuStackArray::new(),
            nmi_stacks: CpuStackArray::new(),
            machine_check_stacks: CpuStackArray::new(),
        }
    }

    /// Fills CPU `cpu`'s entry state, GDT, TSS (with its own stacks) and
    /// exception gates and loads them on the calling CPU, which must be
    /// the CPU `cpu` names; false if `cpu` is out of range or was
    /// installed already.
    pub(crate) fn install(&'static self, cpu: usize) -> bool {
        let Some(claimed) = self.installed.get(cpu) else {
            return false;
        };
        if claimed.swap(true, Ordering::AcqRel) {
            return false;
        }
        let entry_state = self.entry_states[cpu].0.get();
        // SAFETY: the index is claimed by this call alone (the module
        // invariant), and no GS base names this slot yet, so nothing else
        // reaches it while it is written.
        unsafe { entry_state.write_volatile(CpuEntryState::EMPTY) };
        // SAFETY: GS_BASE names this CPU's own entry state, which lives in
        // a `static` and which the stubs expect there; ring 3 starts with a
        // GS base of 0 (system-call entry swaps it in with SWAPGS); and
        // IA32_TSC_AUX holds the CPU index RDPID and RDTSCP read back. None
        // of the three reaches memory.
        unsafe {
            write_msr(GS_BASE_MSR, entry_state as u64);
            write_msr(KERNEL_GS_BASE_MSR, 0);
            write_msr(TSC_AUX_MSR, cpu as u64);
        }
        self.load_gdt_and_tss(cpu);
        self.load_idt(cpu);
        true
    }

    fn load_gdt_and_tss(&'static self, cpu: usize) {
        let tss = &self.tss[cpu];
        tss.0
            .iter()
            .for_each(|word| word.store(0, Ordering::Relaxed));
        tss.set_u64(4, self.privilege_stacks.top(cpu) as u64);
        for (ist, stacks) in [
            (DOUBLE_FAULT_IST, &self.double_fault_stacks),
            (NMI_IST, &self.nmi_stacks),
            (MACHINE_CHECK_IST, &self.machine_check_stacks),
        ] {
            tss.set_u64(36 + 8 * usize::from(ist - 1), stacks.top(cpu) as u64);
        }
        // No I/O permission bitmap: the map base lies past the limit.
        tss.0[TSS_WORDS - 1].store((TSS_SIZE as u32) << 16, Ordering::Relaxed);

        let tss_address = core::ptr::from_ref(tss) as u64;
        let limit = (TSS_SIZE - 1) as u64;
        let gdt = &self.gdt[cpu];
        for (index, value) in [
            0,
            KERNEL_CODE_DESCRIPTOR,
            KERNEL_DATA_DESCRIPTOR,
            limit
                | ((tss_address & 0x00ff_ffff) << 16)
                | (0x89_u64 << 40)
                | (((limit >> 16) & 0x0f) << 48)
                | (((tss_address >> 24) & 0xff) << 56),
            tss_address >> 32,
            USER_DATA_DESCRIPTOR,
            USER_CODE_DESCRIPTOR,
        ]
        .into_iter()
        .enumerate()
        {
            gdt.0[index].store(value, Ordering::Release);
        }

        let pointer = DescriptorTablePointer {
            limit: (GDT_ENTRIES * 8 - 1) as u16,
            base: core::ptr::from_ref(gdt) as u64,
        };
        // SAFETY: the GDT is this CPU's, in a `static`, holding the
        // kernel's segments (written above, before the load), and the TSS
        // descriptor names this CPU's TSS, which names this CPU index's own
        // stacks (the module invariant). The segment registers are
        // reloaded with the kernel's code and data selectors, which those
        // entries describe as before; LTR marks the TSS descriptor busy.
        unsafe {
            asm!(
                "lgdt [{}]",
                "mov ax, {data}",
                "mov ds, ax",
                "mov es, ax",
                "mov ss, ax",
                "push {code}",
                "lea rax, [rip + 2f]",
                "push rax",
                "retfq",
                "2:",
                "mov ax, {tss}",
                "ltr ax",
                in(reg) &pointer,
                data = const KERNEL_DATA_SELECTOR,
                code = const KERNEL_CODE_SELECTOR as u64,
                tss = const TSS_SELECTOR,
                out("rax") _,
            );
        }
    }

    fn load_idt(&'static self, cpu: usize) {
        // SAFETY: `linox_exception_entries` is a read-only table of 32
        // addresses in the kernel image (`cpu.rs`'s entry assembly).
        let entries = unsafe { &*core::ptr::addr_of!(linox_exception_entries) };
        for (vector, handler) in entries.iter().enumerate() {
            write_gate(
                &self.idt[cpu],
                vector,
                Gate::interrupt(*handler, exception_ist(vector), KERNEL_GATE),
            );
        }
        let pointer = DescriptorTablePointer {
            limit: (VECTORS * 16 - 1) as u16,
            base: core::ptr::from_ref(&self.idt[cpu]) as u64,
        };
        // SAFETY: the IDT is this CPU's, in a `static`; its exception gates
        // name `cpu.rs`'s stubs (written above) and the stacks of its TSS,
        // and every other gate is missing or was written by
        // `set_gate_on_every_cpu` (see the known gap above).
        unsafe {
            asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
        }
    }

    /// CPU `cpu`'s gate for `vector`, missing for an index out of range.
    pub(crate) fn gate(&self, cpu: usize, vector: usize) -> Gate {
        self.idt
            .get(cpu)
            .filter(|_| vector < VECTORS)
            .map_or(Gate::MISSING, |idt| {
                Gate::decode([
                    idt.0[vector * 2].load(Ordering::Acquire),
                    idt.0[vector * 2 + 1].load(Ordering::Acquire),
                ])
            })
    }

    /// Points `vector` (32 or above) at `handler` with `attributes`
    /// ([`KERNEL_GATE`] or [`USER_GATE`]) on every CPU, or clears it with
    /// `handler` 0. The caller keeps the vector's interrupt source quiet
    /// meanwhile. False for an exception vector or other attributes.
    pub(crate) fn set_gate_on_every_cpu(&self, vector: u8, handler: usize, attributes: u8) -> bool {
        if usize::from(vector) < EXCEPTION_VECTORS || !matches!(attributes, KERNEL_GATE | USER_GATE)
        {
            return false;
        }
        let gate = if handler == 0 {
            Gate::MISSING
        } else {
            Gate::interrupt(handler, 0, attributes)
        };
        for idt in &self.idt {
            write_gate(idt, usize::from(vector), gate);
        }
        true
    }

    /// Entry `index` of CPU `cpu`'s GDT (0 out of range).
    pub(crate) fn gdt_entry(&self, cpu: usize, index: usize) -> u64 {
        self.gdt
            .get(cpu)
            .and_then(|gdt| gdt.0.get(index))
            .map_or(0, |entry| entry.load(Ordering::Acquire))
    }

    /// The address of CPU `cpu`'s TSS and its I/O map base.
    pub(crate) fn tss(&self, cpu: usize) -> Option<(u64, u16)> {
        let tss = self.tss.get(cpu)?;
        let io_map_base = (tss.0[TSS_WORDS - 1].load(Ordering::Acquire) >> 16) as u16;
        Some((core::ptr::from_ref(tss) as u64, io_map_base))
    }

    pub(crate) const fn tss_limit(&self) -> u64 {
        (TSS_SIZE - 1) as u64
    }

    /// The entry state GS_BASE names on this CPU. The record belongs to
    /// this CPU (the module invariant); `cpu.rs`'s entry code reads and
    /// writes it through this pointer, as its stubs do through GS.
    pub(crate) fn current_entry_state(&self) -> *mut CpuEntryState {
        read_msr(GS_BASE_MSR) as *mut CpuEntryState
    }

    /// The CPU index whose entry state GS_BASE names, if it names one of
    /// these.
    pub(crate) fn current_index(&self) -> Option<usize> {
        let base = read_msr(GS_BASE_MSR) as usize;
        let first = self.entry_states.as_ptr() as usize;
        let offset = base.checked_sub(first)?;
        let index = offset / size_of::<EntryStateCell>();
        (offset.is_multiple_of(size_of::<EntryStateCell>()) && index < CPUS).then_some(index)
    }

    /// A copy of this CPU's entry state, if GS names one of these.
    pub(crate) fn current_entry_state_copy(&self) -> Option<CpuEntryState> {
        let cpu = self.current_index()?;
        // SAFETY: the record is this CPU's (`current_index` checked GS
        // names it); a volatile copy of plain words, which only this CPU
        // writes, races with nothing.
        Some(unsafe { self.entry_states[cpu].0.get().read_volatile() })
    }

    /// Runs `body`, then puts this CPU's entry state back as it was, for
    /// boot checks that run the entry paths' Rust half and must not leave
    /// what they wrote behind. The record is put back only on the CPU it
    /// was taken from.
    pub(crate) fn with_entry_state_restored<R>(&self, body: impl FnOnce() -> R) -> R {
        let saved = self
            .current_index()
            .map(|cpu| (cpu, self.current_entry_state_copy()));
        let result = body();
        if let Some((cpu, Some(state))) = saved {
            if self.current_index() == Some(cpu) {
                // SAFETY: the record is this CPU's (checked again above)
                // and `state` is the value it held when `body` started:
                // the stack it names for a return to the kernel is this
                // call's caller's, which is still live.
                unsafe { self.entry_states[cpu].0.get().write_volatile(state) };
            }
        }
        result
    }
}

fn write_gate(idt: &Idt, vector: usize, gate: Gate) {
    let [low, high] = gate.encode();
    // A gate is present only once its low word is: take it out, write the
    // high word, then the low one, so no half-written gate is taken.
    idt.0[vector * 2].store(0, Ordering::Release);
    idt.0[vector * 2 + 1].store(high, Ordering::Release);
    idt.0[vector * 2].store(low, Ordering::Release);
}

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: callers read GS_BASE, which the processor implements in long
    // mode; reading it changes no state.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// # Safety
///
/// `msr` is GS_BASE, KERNEL_GS_BASE or IA32_TSC_AUX, written as `install`
/// says.
unsafe fn write_msr(msr: u32, value: u64) {
    // SAFETY: the caller's contract.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}

#[repr(C, align(4096))]
struct Stack<const SIZE: usize>([u8; SIZE]);

/// One stack of `SIZE` bytes per CPU, each a guard page, the stack, and a
/// guard page, page-aligned, in a `static` (or a [`CpuTables`] in one).
pub(crate) struct CpuStackArray<const SIZE: usize, const CPUS: usize>(
    UnsafeCell<[Stack<SIZE>; CPUS]>,
);

// SAFETY: Rust never reads or writes the stacks; only their addresses are
// taken. The processor and the code running on a stack use it, one CPU per
// stack (the module invariant).
unsafe impl<const SIZE: usize, const CPUS: usize> Sync for CpuStackArray<SIZE, CPUS> {}

impl<const SIZE: usize, const CPUS: usize> CpuStackArray<SIZE, CPUS> {
    const STACK_TOP_OFFSET: usize = {
        assert!(SIZE >= 3 * PAGE_SIZE && SIZE.is_multiple_of(PAGE_SIZE));
        SIZE - PAGE_SIZE
    };

    pub(crate) const fn new() -> Self {
        Self(UnsafeCell::new([const { Stack([0; SIZE]) }; CPUS]))
    }

    /// The lower guard page of CPU `cpu`'s stack (the start of its
    /// storage). Panics for a CPU index out of range.
    pub(crate) fn guard_page(&self, cpu: usize) -> usize {
        assert!(cpu < CPUS, "CPU index out of range");
        self.0.get() as usize + cpu * SIZE
    }

    /// The top of CPU `cpu`'s stack, which is also its upper guard page.
    /// Panics for a CPU index out of range.
    pub(crate) fn top(&self, cpu: usize) -> usize {
        self.guard_page(cpu) + Self::STACK_TOP_OFFSET
    }

    /// The offset of a stack's top from its storage's start.
    pub(crate) const fn top_offset() -> usize {
        Self::STACK_TOP_OFFSET
    }
}
