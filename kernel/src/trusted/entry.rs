//! Interrupt entry stubs for the device, timer and inter-processor vectors
//! the kernel installs outside the CPU core (`arch/x86_64/cpu`, which keeps
//! the system-call, exception and NMI entries).
//!
//! Each register-saving stub does what the handlers' own files did before
//! this module existed, instruction for instruction: switch to the kernel GS
//! base if the interrupt came from user mode, clear AC and DF, push the
//! fifteen general registers, call the handler on a 16-byte aligned stack
//! with RDI pointing at the saved registers and the interrupt frame above
//! them, pop them, switch GS back for user mode and `iretq`.
//!
//! The one audited fact the handlers rely on: RDI points at a
//! `scheduler::UserInterruptFrame` (`repr(C)`, the fifteen pushes from R15 at
//! the lowest address to RAX, then the hardware's RIP, CS, RFLAGS, RSP, SS),
//! on this CPU's stack, used by nothing else until the handler returns. So
//! each handler is declared as an `extern "sysv64" fn` taking
//! `&mut UserInterruptFrame`: the reference is valid, aligned (the pushes
//! keep RSP 8-byte aligned) and exclusive for the call, and the handler
//! itself is safe code. A handler may rewrite the frame (the timer's
//! preemption does) and the stub restores what it holds.
//!
//! The handlers are the functions named in the `sym` operands below; each
//! stub's address is what `cpu::install_interrupt_gate` gets for its vector.

use core::arch::global_asm;

use crate::arch::x86_64::{pci, smp, timer};

/// The register-saving entry stub `$name`, calling `$handler` with RDI set
/// to the saved frame (`frame`) or left as the interrupted code had it
/// (`no_frame`, for a handler that takes no argument).
macro_rules! entry_stub {
    ($name:literal, $handler:path, frame) => {
        entry_stub!(@emit $name, $handler, "    mov rdi, r12\n");
    };
    ($name:literal, $handler:path, no_frame) => {
        entry_stub!(@emit $name, $handler, "");
    };
    (@emit $name:literal, $handler:path, $pass_frame:literal) => {
        global_asm!(
            concat!(
                "    .text\n",
                "    .global ", $name, "\n",
                $name, ":\n",
                r#"    test qword ptr [rsp + 8], 3
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
"#,
                $pass_frame,
                r#"    and rsp, -16
    call {handler}
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
"#
            ),
            handler = sym $handler,
        );
    };
}

entry_stub!(
    "linox_virtio_interrupt_entry",
    pci::virtio_interrupt_handler,
    frame
);
entry_stub!(
    "linox_apic_timer_entry",
    timer::timer_interrupt_handler,
    frame
);
entry_stub!(
    "linox_ipi_entry",
    smp::interprocessor_interrupt_handler,
    no_frame
);

// The local APIC's spurious vector needs no end of interrupt and no
// handler.
global_asm!(
    r#"
    .text
    .global linox_apic_spurious_entry
linox_apic_spurious_entry:
    clac
    iretq
"#
);

extern "C" {
    fn linox_virtio_interrupt_entry();
    fn linox_apic_timer_entry();
    fn linox_apic_spurious_entry();
    fn linox_ipi_entry();
}

/// The entry stub of the virtio interrupt vectors.
pub(crate) fn virtio_interrupt_entry() -> usize {
    linox_virtio_interrupt_entry as *const () as usize
}

/// The entry stub of the local APIC timer vector.
pub(crate) fn timer_interrupt_entry() -> usize {
    linox_apic_timer_entry as *const () as usize
}

/// The entry stub of the local APIC spurious vector.
pub(crate) fn spurious_interrupt_entry() -> usize {
    linox_apic_spurious_entry as *const () as usize
}

/// The entry stub of the inter-processor interrupt vector.
pub(crate) fn interprocessor_interrupt_entry() -> usize {
    linox_ipi_entry as *const () as usize
}
