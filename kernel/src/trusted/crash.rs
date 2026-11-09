//! What crash reporting needs from the machine: the bring-up exception
//! table and its stubs, a walk of the live page tables, the stage text a
//! report names, and the words on a crashed stack.
//!
//! `bringup/trap.rs` writes the reports; everything here is the part that
//! cannot be safe Rust on its own:
//! - [`install_exception_table`] loads an interrupt descriptor table whose
//!   32 exception gates point at the stubs below, which push a common frame
//!   ([`ExceptionFrame`]) and call `trap::exception_handler` with a
//!   reference to it. The stubs never return to the faulting code.
//! - [`maps`] walks the page tables CR3 names, reading each level at its
//!   physical address, which is valid where the tables are identity mapped:
//!   the firmware's (bring-up, early boot) and the kernel's static tables
//!   in its identity-mapped image. On a CPU whose tables are not, the walk
//!   faults inside the report, and the report's reentrancy latch stops it.
//! - [`stack_word`] reads one word of a stack the walk says is mapped, and
//!   [`recover_console`] takes the console back from whatever was drawing,
//!   for a report that halts afterwards ([`StageText`] keeps the stage).

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::control;

/// Vectors the processor raises for exceptions (Intel SDM vol. 3A table 6-1;
/// AMD APM vol. 2 table 8-1).
const EXCEPTION_VECTORS: usize = 32;
/// Interrupt gate, present, ring 0 (SDM vol. 3A section 6.14.1).
const INTERRUPT_GATE: u64 = 0x8e << 40;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const LARGE_PAGE: u64 = 1 << 7;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const CR4_LA57: u64 = 1 << 12;

/// The registers as the stubs and the processor left them, lowest address
/// first.
#[repr(C)]
pub(crate) struct ExceptionFrame {
    pub(crate) r15: u64,
    pub(crate) r14: u64,
    pub(crate) r13: u64,
    pub(crate) r12: u64,
    pub(crate) r11: u64,
    pub(crate) r10: u64,
    pub(crate) r9: u64,
    pub(crate) r8: u64,
    pub(crate) rbp: u64,
    pub(crate) rdi: u64,
    pub(crate) rsi: u64,
    pub(crate) rdx: u64,
    pub(crate) rcx: u64,
    pub(crate) rbx: u64,
    pub(crate) rax: u64,
    pub(crate) vector: u64,
    pub(crate) error: u64,
    pub(crate) rip: u64,
    pub(crate) cs: u64,
    pub(crate) rflags: u64,
    pub(crate) rsp: u64,
    pub(crate) ss: u64,
}

/// Two words per gate. AtomicU64 has u64's layout, so the processor reads
/// the table directly.
static IDT: [AtomicU64; EXCEPTION_VECTORS * 2] =
    [const { AtomicU64::new(0) }; EXCEPTION_VECTORS * 2];

// Each stub pushes a zero error code when the processor pushes none, then
// the vector, so every exception reaches the common path with one layout.
// Vectors 8, 10-14, 17, 21, 29 and 30 push an error code. The common path
// passes the stack pointer, under which it pushed exactly an
// `ExceptionFrame`, as the handler's `&ExceptionFrame`: valid, aligned and
// unchanged until the handler, which never returns, is done with it.
global_asm!(
    ".macro linox_stub vector, error",
    ".global linox_bringup_exception_\\vector",
    "linox_bringup_exception_\\vector:",
    ".if \\error == 0",
    "push 0",
    ".endif",
    "push \\vector",
    "jmp linox_bringup_exception_common",
    ".endm",
    "linox_stub 0, 0", "linox_stub 1, 0", "linox_stub 2, 0", "linox_stub 3, 0",
    "linox_stub 4, 0", "linox_stub 5, 0", "linox_stub 6, 0", "linox_stub 7, 0",
    "linox_stub 8, 1", "linox_stub 9, 0", "linox_stub 10, 1", "linox_stub 11, 1",
    "linox_stub 12, 1", "linox_stub 13, 1", "linox_stub 14, 1", "linox_stub 15, 0",
    "linox_stub 16, 0", "linox_stub 17, 1", "linox_stub 18, 0", "linox_stub 19, 0",
    "linox_stub 20, 0", "linox_stub 21, 1", "linox_stub 22, 0", "linox_stub 23, 0",
    "linox_stub 24, 0", "linox_stub 25, 0", "linox_stub 26, 0", "linox_stub 27, 0",
    "linox_stub 28, 0", "linox_stub 29, 1", "linox_stub 30, 1", "linox_stub 31, 0",
    ".purgem linox_stub",
    "linox_bringup_exception_common:",
    "push rax", "push rbx", "push rcx", "push rdx", "push rsi", "push rdi", "push rbp",
    "push r8", "push r9", "push r10", "push r11", "push r12", "push r13", "push r14",
    "push r15",
    "mov rdi, rsp",
    "and rsp, -16",
    "call {handler}",
    "ud2",
    // A table of the stubs' addresses, in vector order.
    ".pushsection .rodata",
    ".balign 8",
    ".global linox_bringup_exception_stubs",
    "linox_bringup_exception_stubs:",
    ".irp vector, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
    ".quad linox_bringup_exception_\\vector",
    ".endr",
    ".popsection",
    handler = sym crate::bringup::exception_handler,
);

extern "C" {
    static linox_bringup_exception_stubs: [u64; EXCEPTION_VECTORS];
}

/// Loads the bring-up exception table, with gates in the code segment the
/// firmware left loaded (bring-up keeps the firmware's GDT).
pub(crate) fn install_exception_table() {
    let selector = control::code_segment();
    // SAFETY: the table is read-only data the assembly above defines.
    let stubs = unsafe { &*core::ptr::addr_of!(linox_bringup_exception_stubs) };
    for (vector, stub) in stubs.iter().copied().enumerate() {
        let low = (stub & 0xffff)
            | u64::from(selector) << 16
            | INTERRUPT_GATE
            | (stub >> 16 & 0xffff) << 48;
        IDT[vector * 2].store(low, Ordering::Relaxed);
        IDT[vector * 2 + 1].store(stub >> 32, Ordering::Relaxed);
    }
    #[repr(C, packed)]
    struct Pointer {
        limit: u16,
        base: u64,
    }
    let pointer = Pointer {
        limit: (core::mem::size_of_val(&IDT) - 1) as u16,
        base: IDT.as_ptr() as u64,
    };
    // SAFETY: the table holds a present interrupt gate for each exception
    // vector, pointing at the stubs above in the current code segment, and
    // it is static. Interrupts stay disabled in bring-up, so no external
    // vector beyond the table's limit can arrive.
    unsafe {
        asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
    }
}

/// Whether the live page tables map `address` (writable, if asked). The
/// firmware's tables, which bring-up runs on, identity map their own pages,
/// so each level is read at its physical address.
pub(crate) fn maps(address: u64, writable: bool) -> bool {
    let [_, _, cr3, cr4] = control::registers();
    let levels = if cr4 & CR4_LA57 != 0 { 5 } else { 4 };
    let width = 12 + 9 * levels;
    // The address must be canonical for the paging mode.
    let shift = 64 - width;
    if ((address << shift) as i64 >> shift) as u64 != address {
        return false;
    }
    let mut table = cr3 & ADDRESS_MASK;
    for level in (0..levels).rev() {
        let index = (address >> (12 + 9 * level)) & 0x1ff;
        // SAFETY: page-table pages are identity mapped by the firmware that
        // built them (and the kernel's static tables lie in its identity-
        // mapped image), a table entry is an aligned word inside its page,
        // and reading one has no side effects.
        let entry = unsafe { ((table + index * 8) as *const u64).read_volatile() };
        if entry & PRESENT == 0 || writable && entry & WRITABLE == 0 {
            return false;
        }
        // A large page ends the walk at 1 GiB (level 2) or 2 MiB (level 1).
        if level == 0 || (level <= 2 && entry & LARGE_PAGE != 0) {
            return true;
        }
        table = entry & ADDRESS_MASK;
    }
    true
}

/// The word at `address` on a stack a crash report lists, if it is aligned
/// and the live tables map it. Only the crash reports call this
/// (`bringup/trap.rs`), and they halt afterwards: the code whose stack this
/// is never runs again, so no reference it held into the stack is used
/// after the read.
pub(crate) fn stack_word(address: u64) -> Option<u64> {
    if !address.is_multiple_of(8) || !maps(address, false) {
        return None;
    }
    // SAFETY: the page holding the word is mapped (checked), the read is a
    // volatile copy of an aligned word, and the stack's owner never resumes
    // (see above).
    Some(unsafe { (address as *const u64).read_volatile() })
}

/// The standing of a crash report that halts when it is done, on the only
/// CPU running: what it interrupted never resumes. Only
/// [`recover_console`] makes one, to take back state that code was using
/// (`ClaimCell::release_abandoned`).
pub(crate) struct FatalReport(());

/// Releases the console after a fatal exception or panic that may have
/// struck while it was drawing, so the crash report reaches the screen.
/// Only the crash reports call this (`bringup/trap.rs`), and they halt
/// afterwards, as `stack_word`'s callers do.
pub(crate) fn recover_console() {
    crate::framebuffer::recover(&FatalReport(()));
}

/// A `&'static str` read and written atomically (a sequence lock over its
/// pointer and length): the bring-up stage, which a crash report reads in
/// an exception that may interrupt the write.
pub(crate) struct StageText {
    /// Even when stable, odd while a write is in progress.
    sequence: AtomicUsize,
    text: AtomicUsize,
    length: AtomicUsize,
}

impl StageText {
    pub(crate) const fn new() -> Self {
        Self {
            sequence: AtomicUsize::new(0),
            text: AtomicUsize::new(0),
            length: AtomicUsize::new(0),
        }
    }

    pub(crate) fn store(&self, text: &'static str) {
        // Writers take the sequence from even to odd one at a time.
        let mut sequence = self.sequence.load(Ordering::Relaxed);
        loop {
            if sequence % 2 == 1 {
                core::hint::spin_loop();
                sequence = self.sequence.load(Ordering::Relaxed);
                continue;
            }
            match self.sequence.compare_exchange_weak(
                sequence,
                sequence + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => sequence = current,
            }
        }
        self.text.store(text.as_ptr() as usize, Ordering::Release);
        self.length.store(text.len(), Ordering::Release);
        self.sequence.store(sequence + 2, Ordering::Release);
    }

    /// The text stored last, or `None` if none was, or a write is under way
    /// (an exception that interrupted it).
    pub(crate) fn load(&self) -> Option<&'static str> {
        for _ in 0..4 {
            let before = self.sequence.load(Ordering::Acquire);
            if before == 0 || before % 2 == 1 {
                return None;
            }
            let text = self.text.load(Ordering::Acquire);
            let length = self.length.load(Ordering::Acquire);
            if self.sequence.load(Ordering::Acquire) != before {
                continue;
            }
            // SAFETY: the sequence was even and unchanged across both loads,
            // so they are the pointer and length one `store` wrote together,
            // of a `&'static str`.
            let bytes = unsafe { core::slice::from_raw_parts(text as *const u8, length) };
            return core::str::from_utf8(bytes).ok();
        }
        None
    }
}
