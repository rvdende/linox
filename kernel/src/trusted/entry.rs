//! Every way into and out of the kernel: the entry stubs of the system-call,
//! exception, NMI, device, timer and inter-processor vectors, the stubs that
//! enter user mode, and the frames they hand the kernel's handlers.
//!
//! # The handlers' frames
//!
//! Each register-saving stub switches to the kernel GS base if it came from
//! user mode, clears AC and DF, pushes the general registers, and calls its
//! handler on a 16-byte aligned stack with a pointer to what it pushed
//! (and, for an interrupt or exception, what the processor pushed above
//! it). Each frame type is `repr(C)` in the order of those pushes, R15 at
//! the lowest address, and its size is asserted below against the stub:
//!
//! | stub | handler | frame |
//! |---|---|---|
//! | `linox_syscall_entry` (native `int`) | `cpu::syscall_handler` | `scheduler::UserTrapFrame` |
//! | user-mode exception | `cpu::user_fault_handler` | `scheduler::UserFaultFrame` |
//! | kernel-mode exception | `cpu::fatal_exception_handler` | [`FatalFrame`] |
//! | virtio, APIC timer | their handlers | `scheduler::UserInterruptFrame` |
//! | `linox_linux_syscall_entry` (`syscall`) | `cpu::linux_syscall_handler` | [`LinuxSyscallFrameHandle`] |
//!
//! The frame lies on this CPU's stack and nothing else uses it until the
//! handler returns, so each handler is declared as an `extern "sysv64" fn`
//! taking `&mut Frame` (or `&FatalFrame`): the reference is valid, aligned
//! (the pushes keep RSP 8-byte aligned) and exclusive for the call, and the
//! handler is safe code. A handler may rewrite its frame (the timer's
//! preemption does) and the stub restores what it holds.
//!
//! The Linux `syscall` frame is the exception: a system call may park its
//! activation and be resumed, and code below the handler reaches the frame
//! through many layers. It gets a [`LinuxSyscallFrameHandle`], an address
//! that reads and writes the frame only while it is the live frame the
//! CPU's entry state names (see below), so a handle kept past its call, or
//! made up, reaches nothing.
//!
//! # The entry state and the return stack
//!
//! Each CPU's `CpuEntryState` (`trusted::cpu_tables`, at GS while in the
//! kernel) holds the stack to return to when user mode comes back to the
//! kernel (`return_stack`), the user context of the running Linux system
//! call, and the frame the `syscall` stub pushed (`kernel_frame`). The
//! invariants the stubs keep:
//!
//! - `return_stack` names the callee-saved registers an `enter_*` stub
//!   pushed, on the stack of a context that is waiting in that stub. Each
//!   entry pushes the `return_stack` and `kernel_frame` it found and puts
//!   them back when it returns to the kernel, so entries nest: an entry
//!   made during a system call (a native service's auxiliary run) returns
//!   with the outer call's state as it was. A system call that parks on its
//!   own stack takes its state with it (`trusted::switch`).
//! - `kernel_frame` is the `syscall` frame of the system call running on
//!   this CPU, and 0 when none is: the stub sets it on entry and clears it
//!   on every way out, and a parked call's is cleared when it parks.
//! - The user context the kernel returns to is user mode: the stubs push
//!   the user code and data selectors, return through SYSRET/IRETQ only to
//!   canonical addresses, and clear IOPL, VM and the virtual-interrupt
//!   flags (and set IF) in the flags they load, so no context Rust code
//!   writes can enter ring 3 with I/O privilege or return to ring 0.
//!
//! The exception stubs' table is [`linox_exception_entries`], which
//! `trusted::cpu_tables` points the 32 exception gates at; the gates above
//! vector 31 take an [`EntryStub`], which only this module makes.

use core::arch::global_asm;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, AtomicU8};

use crate::arch::x86_64::cpu::{self, LinuxSyscallFrame};
use crate::arch::x86_64::{pci, smp, timer};
use crate::scheduler::{UserFaultFrame, UserInterruptFrame, UserTrapFrame};

use super::cpu_tables::{self, USER_CODE_SELECTOR, USER_DATA_SELECTOR};

/// The flags a return to user mode may carry over from the context it is
/// given: CF, PF, AF, ZF, SF, TF, DF, OF, NT, AC, ID and the always-one
/// bit 1. IF is forced on; IOPL, RF, VM, VIF and VIP are cleared.
const USER_FLAGS_KEPT: u64 = 0x0024_4fd7;
/// Bit 1 (always one) and IF.
const USER_FLAGS_SET: u64 = 0x202;

/// The value a Linux system-call handler returns to have the stub return to
/// the kernel (the context that entered user mode) instead of the process.
pub(crate) const RETURN_TO_KERNEL: u64 = (-4096_i64) as u64;
/// The value a Linux system-call handler returns to have the stub return to
/// the process through IRETQ, with RAX, RCX and R11 from the entry state's
/// `signal_*` fields.
pub(crate) const RETURN_FROM_IRET: u64 = (-4095_i64) as u64;

/// Set by boot checks to raise an NMI at each of the six transitions of the
/// `syscall` entry and exit, proving each stack the NMI can arrive on.
pub(crate) static PRIVILEGE_ENTRY_NMI_PROBE_MASK: AtomicU64 = AtomicU64::new(0);
/// NMIs taken; the NMI stub counts them.
pub(crate) static PRIVILEGE_ENTRY_NMI_PROBE_HITS: AtomicU8 = AtomicU8::new(0);
/// How many transitions the probe covers.
pub(crate) const PRIVILEGE_ENTRY_NMI_STAGE_COUNT: u8 = 6;

/// What a kernel-mode exception stub pushed: the fifteen general registers
/// (R15 first), the vector and error code, then the processor's RIP, CS,
/// RFLAGS, RSP and SS.
#[repr(transparent)]
pub(crate) struct FatalFrame(pub(crate) [u64; 22]);

const _: () = {
    assert!(size_of::<UserTrapFrame>() == 19 * 8);
    assert!(size_of::<UserFaultFrame>() == 22 * 8);
    assert!(size_of::<UserInterruptFrame>() == 20 * 8);
    assert!(size_of::<FatalFrame>() == 22 * 8);
    assert!(size_of::<LinuxSyscallFrame>() == 12 * 8);
    // The stub's offsets into the entry state.
    assert!(core::mem::offset_of!(cpu_tables::CpuEntryState, return_stack) == 0);
    assert!(core::mem::offset_of!(cpu_tables::CpuEntryState, kernel_frame) == 32);
};

/// The frame the `syscall` stub pushed for a Linux system call (twelve
/// registers, `LinuxSyscallFrame`), as an address. It reads and writes the
/// frame only while the frame is live: while this CPU's entry state names
/// it as the running call's (`kernel_frame`, set by the stub on entry and
/// cleared on every way out and when the call parks). Otherwise — a handle
/// kept after its call returned, one of a parked call, or [`Self::NONE`] —
/// reads give `None` and writes do nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct LinuxSyscallFrameHandle(usize);

impl LinuxSyscallFrameHandle {
    /// No frame: for calls made from the kernel itself (boot checks).
    pub(crate) const NONE: Self = Self(0);

    pub(crate) fn is_null(self) -> bool {
        self.0 == 0
    }

    fn is_live(self) -> bool {
        self.0 != 0 && cpu_tables::live_kernel_frame() == Some(self.0 as u64)
    }

    /// The registers in the frame, if it is the live one.
    pub(crate) fn read(self) -> Option<LinuxSyscallFrame> {
        if !self.is_live() {
            return None;
        }
        // SAFETY: the live frame is the twelve registers the `syscall` stub
        // pushed on this CPU's stack for the running call (module
        // invariant), aligned, and no Rust reference covers it: the stub
        // pops it only after the handler returns.
        Some(unsafe { (self.0 as *const LinuxSyscallFrame).read_volatile() })
    }

    /// Replaces the registers the call returns with, if the frame is the
    /// live one; false otherwise.
    pub(crate) fn write(self, registers: LinuxSyscallFrame) -> bool {
        if !self.is_live() {
            return false;
        }
        // SAFETY: as in `read`; the stub pops these registers into user
        // mode, so any values are memory-safe.
        unsafe { (self.0 as *mut LinuxSyscallFrame).write_volatile(registers) };
        true
    }
}

/// Runs `body` with `frame`, a frame of the caller's, standing in for the
/// live system-call frame, for boot checks of code that writes a call's
/// return through a [`LinuxSyscallFrameHandle`]; the CPU's live frame is
/// put back after. `frame` is borrowed for the whole call, so the handle
/// reaches nothing else while it stands in.
pub(crate) fn with_stand_in_frame<R>(
    frame: &mut LinuxSyscallFrame,
    body: impl FnOnce(LinuxSyscallFrameHandle) -> R,
) -> R {
    let address = core::ptr::from_mut(frame) as usize;
    let Some(previous) = cpu_tables::replace_kernel_frame(address as u64) else {
        return body(LinuxSyscallFrameHandle::NONE);
    };
    let result = body(LinuxSyscallFrameHandle(address));
    let _ = cpu_tables::replace_kernel_frame(previous);
    result
}

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

// The exception, NMI, breakpoint, system-call and user-entry stubs. The
// user-copy loops whose faults the page-fault path recovers from are in
// `trusted::user_copy`.
global_asm!(
    r#"
    .text
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
    call {kernel_cow_fault_handler}
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
// linox_user_enter(entry: rdi, stack: rsi, host: rdx, console: rcx,
// ipc: r8, identity: r9, service domain, service identity, root handle on
// the stack): enters a native domain's ring-3 code with those values in
// rbx/rdx, rcx, r8, r9, r10, r11 and r14, returning when one of its system
// calls or faults returns to the kernel. The entry state's return stack and
// kernel frame are kept below the callee-saved registers and put back on
// the way out.
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
    push qword ptr gs:[{entry_return_stack}]
    push qword ptr gs:[{entry_kernel_frame}]
    mov gs:[{entry_return_stack}], rsp
    mov qword ptr gs:[{entry_kernel_frame}], 0
    mov r14, [rsp + 88]
    mov rbx, rdx
    push {user_data}
    push rsi
    push {user_flags_set}
    push {user_code}
    push rdi
    swapgs
    iretq

// linox_process_user_enter(entry: rdi, stack: rsi, general: rdx (fifteen
// registers, rax first), rflags: rcx): enters a Linux process's user mode
// with that context, returning when one of its system calls returns to the
// kernel.
    .global linox_process_user_enter
linox_process_user_enter:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push qword ptr gs:[{entry_return_stack}]
    push qword ptr gs:[{entry_kernel_frame}]
    mov gs:[{entry_return_stack}], rsp
    mov qword ptr gs:[{entry_kernel_frame}], 0
    and rcx, {user_flags_kept}
    or rcx, {user_flags_set}
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
    mov qword ptr gs:[{entry_kernel_frame}], 0
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
    jne linox_user_return_kernel
    mov rcx, gs:[{entry_user_rsp}]
    shr rcx, 47
    jne linox_user_return_kernel
    mov rcx, gs:[{entry_user_rip}]
    mov r11, gs:[{entry_user_rflags}]
    and r11, {user_flags_kept}
    or r11, {user_flags_set}
    lock btr qword ptr [rip + {entry_nmi_probe_mask}], 5
    jnc 6f
    int 2
6:
    mov rsp, gs:[{entry_user_rsp}]
    swapgs
    sysretq
linox_linux_iret_return:
    mov rax, gs:[{entry_user_rip}]
    shr rax, 47
    jne linox_user_return_kernel
    mov rax, gs:[{entry_user_rsp}]
    shr rax, 47
    jne linox_user_return_kernel
    mov rsp, gs:[{entry_kernel_frame}]
    mov qword ptr gs:[{entry_kernel_frame}], 0
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
    mov r11, gs:[{entry_user_rflags}]
    and r11, {user_flags_kept}
    or r11, {user_flags_set}
    push r11
    push {user_code}
    push gs:[{entry_user_rip}]
    mov rax, gs:[{entry_signal_rax}]
    mov rcx, gs:[{entry_signal_rcx}]
    mov r11, gs:[{entry_signal_r11}]
    swapgs
    iretq
// Back to the context that entered user mode: the stack its enter stub
// recorded, with the entry state it found put back.
linox_user_return_kernel:
    mov rsp, gs:[{entry_return_stack}]
    pop qword ptr gs:[{entry_kernel_frame}]
    pop qword ptr gs:[{entry_return_stack}]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
"#,
    breakpoint_handler = sym cpu::breakpoint_handler,
    fatal_exception_handler = sym cpu::fatal_exception_handler,
    kernel_cow_fault_handler = sym cpu::kernel_cow_fault_handler,
    user_fault_handler = sym cpu::user_fault_handler,
    syscall_handler = sym cpu::syscall_handler,
    linux_syscall_handler = sym cpu::linux_syscall_handler,
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
    tlb_shootdown_address = sym smp::TLB_SHOOTDOWN_ADDRESS,
    tlb_shootdown_acknowledged = sym smp::TLB_SHOOTDOWN_ACKNOWLEDGED,
    linux_return_to_kernel = const RETURN_TO_KERNEL as i64,
    linux_return_from_iret = const RETURN_FROM_IRET as i64,
    user_data = const USER_DATA_SELECTOR as u64,
    user_code = const USER_CODE_SELECTOR as u64,
    user_flags_kept = const USER_FLAGS_KEPT,
    user_flags_set = const USER_FLAGS_SET,
);

extern "C" {
    fn linox_virtio_interrupt_entry();
    fn linox_apic_timer_entry();
    fn linox_apic_spurious_entry();
    fn linox_ipi_entry();
    fn linox_syscall_entry();
    fn linox_linux_syscall_entry();
}

extern "sysv64" {
    #[allow(clippy::too_many_arguments)]
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

/// An entry stub a gate above the exception vectors may point at. Only
/// this module makes one, so `trusted::cpu_tables` never points a gate at
/// anything else.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EntryStub(usize);

impl EntryStub {
    /// The virtio interrupt vectors' stub.
    pub(crate) fn virtio_interrupt() -> Self {
        Self(linox_virtio_interrupt_entry as *const () as usize)
    }

    /// The local APIC timer vector's stub.
    pub(crate) fn timer_interrupt() -> Self {
        Self(linox_apic_timer_entry as *const () as usize)
    }

    /// The local APIC spurious vector's stub.
    pub(crate) fn spurious_interrupt() -> Self {
        Self(linox_apic_spurious_entry as *const () as usize)
    }

    /// The inter-processor interrupt vector's stub.
    pub(crate) fn interprocessor_interrupt() -> Self {
        Self(linox_ipi_entry as *const () as usize)
    }

    /// The native system-call gate's stub (`int`, from ring 3).
    pub(crate) fn native_system_call() -> Self {
        Self(linox_syscall_entry as *const () as usize)
    }

    pub(crate) fn address(self) -> usize {
        self.0
    }
}

/// The `syscall` instruction's entry stub, for IA32_LSTAR
/// (`trusted::msr::configure_linux_syscall`).
pub(super) fn linux_system_call_entry() -> u64 {
    linox_linux_syscall_entry as *const () as u64
}

/// Whether `address` is in the canonical lower half, where user mode runs.
fn user_address(address: usize) -> bool {
    address < 1 << 47
}

/// The values a native domain's code gets in its registers when it is
/// entered (`enter_native_user`).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativeEntryValues {
    pub(crate) host_handle: u64,
    pub(crate) console_handle: u64,
    pub(crate) ipc_handle: u64,
    pub(crate) identity: u64,
    pub(crate) service_domain: u64,
    pub(crate) service_identity: u64,
    pub(crate) root_handle: u64,
}

/// Enters ring 3 at `entry` with stack `stack` and `values` in its
/// registers, with interrupts enabled there, and returns once one of its
/// system calls or faults returns to the kernel. False, without entering,
/// for an address outside the user half. The caller has loaded the address
/// space the code runs in; what that code may do is the page tables' and
/// the gates' business, as for any user code.
pub(crate) fn enter_native_user(entry: usize, stack: usize, values: NativeEntryValues) -> bool {
    if !user_address(entry) || !user_address(stack) {
        return false;
    }
    // SAFETY: the stub records this stack as the return stack (pushing the
    // entry state's previous return stack and kernel frame, which the
    // return path restores), enters ring 3 through IRETQ with the user
    // selectors and IF set, and comes back here through
    // `linox_user_return_kernel` with the callee-saved registers restored,
    // as a call returning. Ring 3 reaches only user pages.
    unsafe {
        linox_user_enter(
            entry,
            stack,
            values.host_handle,
            values.console_handle,
            values.ipc_handle,
            values.identity,
            values.service_domain,
            values.service_identity,
            values.root_handle,
        );
    }
    true
}

/// Enters a Linux process's user mode at `entry` with stack `stack`, the
/// fifteen general registers `general` (RAX, RBX, RCX, RDX, RSI, RDI, RBP,
/// R8-R15) and `rflags` (IOPL, VM, RF and the virtual-interrupt flags
/// cleared, IF set), and returns once one of its system calls returns to
/// the kernel. False, without entering, for an address outside the user
/// half.
pub(crate) fn enter_process_user(
    entry: usize,
    stack: usize,
    general: &[u64; 15],
    rflags: u64,
) -> bool {
    if !user_address(entry) || !user_address(stack) {
        return false;
    }
    // SAFETY: as in `enter_native_user`; the stub reads the fifteen
    // registers from `general` before it leaves, and sanitizes `rflags`.
    unsafe { linox_process_user_enter(entry, stack, general.as_ptr(), rflags) };
    true
}
