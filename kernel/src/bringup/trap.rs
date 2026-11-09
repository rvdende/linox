//! Crash reporting for hardware bring-up, where the screen is often the only
//! output: a physical PC seldom has a serial port, and a photo of the screen
//! is what comes back from a failed boot.
//!
//! - [`install`] loads an interrupt descriptor table of our own for the 32
//!   processor exceptions. Until then the firmware's table is live, and its
//!   handlers write (if anywhere) to a serial port and spin. Ours prints the
//!   exception, the registers, kernel addresses on the stack, and the
//!   bring-up stage that was running, on the framebuffer and serial.
//! - [`set_stage`] records what bring-up is doing, so a fault, a panic or a
//!   long wait can name it.
//! - [`report_panic`] is the whole kernel's panic report after boot
//!   services end; the EFI loader's panic handler calls it.
//! - [`firmware_maps`] walks the live page tables, so the kernel can check
//!   that firmware identity-mapped the framebuffer before drawing on it.

use core::arch::{asm, global_asm};
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::drivers::Console;

/// Vectors the processor raises for exceptions (Intel SDM vol. 3A table 6-1;
/// AMD APM vol. 2 table 8-1).
const EXCEPTION_VECTORS: usize = 32;
const EXCEPTION_NAMES: [&str; EXCEPTION_VECTORS] = [
    "divide error (#DE)",
    "debug (#DB)",
    "non-maskable interrupt (NMI)",
    "breakpoint (#BP)",
    "overflow (#OF)",
    "bound range (#BR)",
    "invalid opcode (#UD)",
    "device not available (#NM)",
    "double fault (#DF)",
    "coprocessor segment overrun",
    "invalid TSS (#TS)",
    "segment not present (#NP)",
    "stack fault (#SS)",
    "general protection (#GP)",
    "page fault (#PF)",
    "reserved 15",
    "x87 floating point (#MF)",
    "alignment check (#AC)",
    "machine check (#MC)",
    "SIMD floating point (#XM)",
    "virtualization (#VE)",
    "control protection (#CP)",
    "reserved 22",
    "reserved 23",
    "reserved 24",
    "reserved 25",
    "reserved 26",
    "reserved 27",
    "hypervisor injection (#HV)",
    "VMM communication (#VC)",
    "security (#SX)",
    "reserved 31",
];
/// Interrupt gate, present, ring 0 (SDM vol. 3A section 6.14.1).
const INTERRUPT_GATE: u64 = 0x8e << 40;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const LARGE_PAGE: u64 = 1 << 7;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const CR4_LA57: u64 = 1 << 12;

/// Two words per gate. AtomicU64 has u64's layout, so the processor reads
/// the table directly.
static IDT: [AtomicU64; EXCEPTION_VECTORS * 2] =
    [const { AtomicU64::new(0) }; EXCEPTION_VECTORS * 2];
/// Set while a fatal report is being written; a fault inside the report
/// itself then stops at once instead of recursing.
static REPORTING: AtomicBool = AtomicBool::new(false);
/// The current stage's text, as a pointer and length into static data.
static STAGE_TEXT: AtomicUsize = AtomicUsize::new(0);
static STAGE_LENGTH: AtomicUsize = AtomicUsize::new(0);

/// Records what bring-up is doing now, for crash and timeout reports.
pub(crate) fn set_stage(stage: &'static str) {
    STAGE_LENGTH.store(0, Ordering::Release);
    STAGE_TEXT.store(stage.as_ptr() as usize, Ordering::Release);
    STAGE_LENGTH.store(stage.len(), Ordering::Release);
}

/// The stage [`set_stage`] recorded last.
pub(crate) fn stage() -> &'static str {
    let length = STAGE_LENGTH.load(Ordering::Acquire);
    let text = STAGE_TEXT.load(Ordering::Acquire);
    if length == 0 || text == 0 {
        return "kernel entry";
    }
    // SAFETY: set_stage stored the pointer and length of a &'static str,
    // and the length is published after the pointer.
    let bytes = unsafe { core::slice::from_raw_parts(text as *const u8, length) };
    core::str::from_utf8(bytes).unwrap_or("?")
}

// Each stub pushes a zero error code when the processor pushes none, then
// the vector, so every exception reaches the common path with one layout.
// Vectors 8, 10-14, 17, 21, 29 and 30 push an error code.
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
    handler = sym exception_handler,
);

extern "C" {
    static linox_bringup_exception_stubs: [u64; EXCEPTION_VECTORS];
}

/// The registers as the stubs and the processor left them, lowest address
/// first.
#[repr(C)]
struct Frame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    vector: u64,
    error: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

/// Loads the bring-up exception table, with gates in the code segment the
/// firmware left loaded (bring-up keeps the firmware's GDT).
pub(crate) fn install() {
    let selector: u16;
    // SAFETY: reading CS has no side effects.
    unsafe { asm!("mov {0:x}, cs", out(reg) selector, options(nomem, nostack, preserves_flags)) };
    // SAFETY: the table is static data the assembly above defines.
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

extern "sysv64" fn exception_handler(frame: *const Frame) -> ! {
    // SAFETY: the common stub passes its stack pointer, under which it
    // pushed exactly a Frame.
    let frame = unsafe { &*frame };
    if REPORTING.swap(true, Ordering::AcqRel) {
        // The report itself faulted, most likely while drawing: stop the
        // framebuffer and say what little we can on serial.
        crate::framebuffer::abandon();
        let _ = write!(
            Console,
            "\nlinox: nested exception {} at {:#x} while reporting\nLINOX_KERNEL_PANIC\n",
            frame.vector, frame.rip
        );
        halt();
    }
    // The fault may have struck while the console was drawing.
    // SAFETY: this handler reports and halts, on the only CPU bring-up
    // runs, so the code it interrupted never resumes.
    unsafe { crate::framebuffer::recover() };
    let vector = frame.vector as usize;
    let mut out = Console;
    let _ = write!(
        out,
        "\n\nlinox: FATAL: {} (vector {}) during bring-up stage: {}\n",
        EXCEPTION_NAMES.get(vector).copied().unwrap_or("unknown"),
        vector,
        stage()
    );
    let [cr0, cr2, cr3, cr4] = control_registers();
    let _ = writeln!(
        out,
        "linox:   rip {:#x} error {:#x} cr2 {:#x} rflags {:#x} cs {:#x}",
        frame.rip, frame.error, cr2, frame.rflags, frame.cs
    );
    let registers = [
        ("rax", frame.rax),
        ("rbx", frame.rbx),
        ("rcx", frame.rcx),
        ("rdx", frame.rdx),
        ("rsi", frame.rsi),
        ("rdi", frame.rdi),
        ("rbp", frame.rbp),
        ("rsp", frame.rsp),
        ("r8", frame.r8),
        ("r9", frame.r9),
        ("r10", frame.r10),
        ("r11", frame.r11),
        ("r12", frame.r12),
        ("r13", frame.r13),
        ("r14", frame.r14),
        ("r15", frame.r15),
    ];
    for row in registers.chunks(3) {
        let _ = write!(out, "linox:  ");
        for (name, value) in row {
            let _ = write!(out, " {name:>3}={value:016x}");
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(
        out,
        "linox:   cr0 {cr0:#x} cr3 {cr3:#x} cr4 {cr4:#x} ss {:#x}",
        frame.ss
    );
    write_stack_addresses(frame.rsp);
    let _ = write!(
        out,
        "linox: photograph this screen; symbolize with tools/debug/symbolize.sh IMAGE_BASE ADDRESS...\n\
         LINOX_KERNEL_PANIC\n"
    );
    halt()
}

/// Prints the kernel image base and the values on the interrupted stack
/// that point into the image, which include the return addresses.
fn write_stack_addresses(stack: u64) {
    let (image_base, image_size) = crate::kernel_image_range();
    let _ = write!(
        Console,
        "linox:   kernel image base {image_base:#x} size {image_size:#x}\nlinox:   kernel addresses on stack:"
    );
    let mut found = 0;
    for slot in 0..1024_u64 {
        let address = stack.wrapping_add(slot * 8);
        if !address.is_multiple_of(8) || !firmware_maps(address, false) {
            break;
        }
        // SAFETY: the page holding the slot is mapped, checked above, and
        // the interrupted code was running on this stack.
        let value = unsafe { (address as *const u64).read_volatile() };
        // Values near the stack pointer point into the stack (which lies in
        // the image), not at code.
        if value > image_base && value < image_base + image_size && value.abs_diff(stack) > 1 << 22
        {
            let _ = write!(Console, " {value:#x}");
            found += 1;
            if found == 24 {
                break;
            }
        }
    }
    let _ = writeln!(Console);
}

/// Reports a Rust panic on the framebuffer and serial, then halts. The EFI
/// loader's panic handler calls this once boot services have ended.
pub fn report_panic(info: &core::panic::PanicInfo<'_>) -> ! {
    if REPORTING.swap(true, Ordering::AcqRel) {
        crate::framebuffer::abandon();
        crate::serial_write_raw(
            b"\r\nlinox: panic while reporting a crash\r\nLINOX_BOOT_PANIC\r\n",
        );
        halt();
    }
    // SAFETY: this report halts, on the only CPU bring-up runs, so the
    // code that panicked never resumes.
    unsafe { crate::framebuffer::recover() };
    // Tests look for the marker at the start of a line.
    crate::serial_write_raw(b"\r\nLINOX_BOOT_PANIC\r\n");
    let mut out = Console;
    let _ = write!(
        out,
        "linox: PANIC during stage: {}\nlinox:   {}\n",
        stage(),
        info.message()
    );
    if let Some(location) = info.location() {
        let _ = writeln!(
            out,
            "linox:   at {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }
    let stack: u64;
    // SAFETY: reading the stack pointer has no side effects.
    unsafe { asm!("mov {}, rsp", out(reg) stack, options(nomem, nostack, preserves_flags)) };
    write_stack_addresses(stack);
    let _ = writeln!(out, "linox: photograph this screen");
    halt()
}

/// CR0, CR2, CR3 and CR4.
fn control_registers() -> [u64; 4] {
    let (cr0, cr2, cr3, cr4): (u64, u64, u64, u64);
    // SAFETY: reading control registers has no side effects.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    [cr0, cr2, cr3, cr4]
}

fn halt() -> ! {
    loop {
        // SAFETY: nothing runs after a fatal report; NMIs wake the halt and
        // loop back into it.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Whether the live page tables map `address` (writable, if asked). The
/// firmware's tables, which bring-up runs on, identity map their own pages,
/// so each level is read at its physical address.
pub(crate) fn firmware_maps(address: u64, writable: bool) -> bool {
    let [_, _, cr3, cr4] = control_registers();
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
        // built them, and reading one has no side effects.
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
