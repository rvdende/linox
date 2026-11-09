#![forbid(unsafe_code)]

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

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::drivers::Console;
use crate::trusted::control;
use crate::trusted::crash::{self, ExceptionFrame as Frame, StageText};

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
/// Set while a fatal report is being written; a fault inside the report
/// itself then stops at once instead of recursing.
static REPORTING: AtomicBool = AtomicBool::new(false);
/// The current stage's text.
static STAGE: StageText = StageText::new();

/// Records what bring-up is doing now, for crash and timeout reports.
pub(crate) fn set_stage(stage: &'static str) {
    STAGE.store(stage);
}

/// The stage [`set_stage`] recorded last.
pub(crate) fn stage() -> &'static str {
    STAGE.load().unwrap_or("kernel entry")
}

/// Loads the bring-up exception table (`trusted::crash`), whose stubs call
/// [`exception_handler`].
pub(crate) fn install() {
    crash::install_exception_table();
}

/// Reports a processor exception in bring-up and halts; the exception
/// stubs (`trusted::crash`) call it with the frame they pushed.
pub(crate) extern "sysv64" fn exception_handler(frame: &Frame) -> ! {
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
    // This handler reports and halts, on the only CPU bring-up runs, so
    // the code it interrupted never resumes.
    crash::recover_console();
    let vector = frame.vector as usize;
    let mut out = Console;
    let _ = write!(
        out,
        "\n\nlinox: FATAL: {} (vector {}) during bring-up stage: {}\n",
        EXCEPTION_NAMES.get(vector).copied().unwrap_or("unknown"),
        vector,
        stage()
    );
    let [cr0, cr2, cr3, cr4] = control::registers();
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
        let Some(value) = crash::stack_word(address) else {
            break;
        };
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
    // This report halts, on the only CPU bring-up runs, so the code that
    // panicked never resumes.
    crash::recover_console();
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
    write_stack_addresses(control::stack_pointer());
    let _ = writeln!(out, "linox: photograph this screen");
    halt()
}

fn halt() -> ! {
    // Nothing runs after a fatal report; NMIs wake the halt and loop back
    // into it.
    crate::trusted::interrupts::park()
}

/// Whether the live page tables map `address` (writable, if asked): see
/// `trusted::crash::maps`.
pub(crate) fn firmware_maps(address: u64, writable: bool) -> bool {
    crash::maps(address, writable)
}
