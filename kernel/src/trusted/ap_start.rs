//! Starting the application processors: the real-mode trampoline they begin
//! in, its copy at [`TRAMPOLINE_PHYSICAL`], and the mailbox that tells each
//! one its CPU number, page-table root, stack and entry function.
//!
//! A processor woken by INIT-SIPI-SIPI with vector `TRAMPOLINE_PHYSICAL >>
//! 12` runs the trampoline in real mode; it loads its own GDT, enters
//! protected mode, turns on PAE, loads CR3 from the mailbox, turns on long
//! mode and NX in EFER, enables paging, and in 64-bit mode loads its stack
//! from the mailbox and calls the mailbox's entry with its CPU number in EDI.
//!
//! What makes this sound:
//! - [`prepare`] writes the trampoline page at `TRAMPOLINE_PHYSICAL`
//!   through the firmware's identity map, before the kernel installs its own
//!   page tables (it checks the firmware maps the page writable). The frame
//!   allocator never hands out memory below 1 MiB (`memory.rs`,
//!   `LOW_MEMORY_LIMIT`), and the kernel keeps nothing else there, so no
//!   Rust object lives in the page; `paging.rs` maps it into the kernel's
//!   identity map for the processors that run it.
//! - [`post`] is the only writer of the mailbox, and it fills it only with
//!   what an application processor may start from: the kernel's own root
//!   (`paging::kernel_root_address`, which maps the kernel image and the
//!   trampoline), the processor's own kernel stack from the CPU core
//!   (`cpu::kernel_stack_top_for_cpu`) and a safe Rust function that takes
//!   the CPU number and never returns. Processors are started one at a time
//!   (`smp::start_application_processors` waits for each to come online
//!   before posting the next).

use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::x86_64::{cpu, paging};

/// Where the trampoline is copied: a page below 1 MiB, as start-up IPIs
/// require. The assembly below has it built in.
pub(crate) const TRAMPOLINE_PHYSICAL: usize = 0x8000;
const PAGE_SIZE: usize = 4096;

static MAILBOX_CR3: AtomicU64 = AtomicU64::new(0);
static MAILBOX_STACK: AtomicU64 = AtomicU64::new(0);
static MAILBOX_ENTRY: AtomicU64 = AtomicU64::new(0);
static MAILBOX_CPU: AtomicU32 = AtomicU32::new(0);

global_asm!(
    r#"
    .pushsection .text.linox_ap_trampoline,"ax"
    .set linox_ap_gdt_pointer_physical, linox_ap_trampoline_gdt_pointer - linox_ap_trampoline_start + 0x8000
    .set linox_ap_cr3_pointer_physical, linox_ap_trampoline_cr3_pointer - linox_ap_trampoline_start + 0x8000
    .balign 16
    .global linox_ap_trampoline_start
linox_ap_trampoline_start:
    .code16
    cli
    cld
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov si, offset linox_ap_gdt_pointer_physical
    lgdt [si]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    .byte 0x66, 0xea
    .long linox_ap_trampoline_protected - linox_ap_trampoline_start + 0x8000
    .word 0x08

linox_ap_trampoline_protected:
    .code32
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax
    mov esi, linox_ap_cr3_pointer_physical
    mov eax, dword ptr [esi]
    mov cr3, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, (1 << 8) | (1 << 11)
    wrmsr
    mov eax, cr0
    or eax, 0x80000001
    mov cr0, eax
    .byte 0xea
    .long linox_ap_trampoline_long - linox_ap_trampoline_start + 0x8000
    .word 0x18

linox_ap_trampoline_long:
    .code64
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov rbx, qword ptr [rip + linox_ap_trampoline_stack_pointer]
    mov rsp, qword ptr [rbx]
    and rsp, -16
    mov rbx, qword ptr [rip + linox_ap_trampoline_cpu_pointer]
    mov edi, dword ptr [rbx]
    mov rbx, qword ptr [rip + linox_ap_trampoline_entry_pointer]
    mov rax, qword ptr [rbx]
    call rax
    ud2

    .balign 8
linox_ap_trampoline_cr3_pointer:
    .quad {mailbox_cr3}
linox_ap_trampoline_stack_pointer:
    .quad {mailbox_stack}
linox_ap_trampoline_entry_pointer:
    .quad {mailbox_entry}
linox_ap_trampoline_cpu_pointer:
    .quad {mailbox_cpu}

    .balign 8
linox_ap_trampoline_gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00af9a000000ffff
linox_ap_trampoline_gdt_end:
linox_ap_trampoline_gdt_pointer:
    .word linox_ap_trampoline_gdt_end - linox_ap_trampoline_gdt - 1
    .long linox_ap_trampoline_gdt - linox_ap_trampoline_start + 0x8000
    .global linox_ap_trampoline_end
linox_ap_trampoline_end:
    .code64
    .popsection
"#,
    mailbox_cr3 = sym MAILBOX_CR3,
    mailbox_stack = sym MAILBOX_STACK,
    mailbox_entry = sym MAILBOX_ENTRY,
    mailbox_cpu = sym MAILBOX_CPU,
);

extern "C" {
    static linox_ap_trampoline_start: u8;
    static linox_ap_trampoline_end: u8;
}

/// Copies the trampoline to [`TRAMPOLINE_PHYSICAL`], zeroing the rest of
/// the page. Runs at boot on the firmware's page tables.
pub(crate) fn prepare() -> bool {
    let start = core::ptr::addr_of!(linox_ap_trampoline_start) as usize;
    let end = core::ptr::addr_of!(linox_ap_trampoline_end) as usize;
    let size = end.saturating_sub(start);
    if size == 0
        || size > PAGE_SIZE
        || !crate::bringup::firmware_maps(TRAMPOLINE_PHYSICAL as u64, true)
    {
        return false;
    }
    // SAFETY: the firmware's identity map maps the page writable (checked)
    // and no Rust object lives in it (see the module comment); `size` bytes
    // from `start` are the trampoline's code and data in the kernel image,
    // which no one writes, and lie apart from the page.
    unsafe {
        core::ptr::write_bytes(TRAMPOLINE_PHYSICAL as *mut u8, 0, PAGE_SIZE);
        core::ptr::copy_nonoverlapping(start as *const u8, TRAMPOLINE_PHYSICAL as *mut u8, size);
    }
    true
}

/// Fills the mailbox for application processor `cpu`, to start in `entry`
/// on its kernel stack; false if the CPU core has no stack for it.
pub(crate) fn post(cpu: usize, entry: extern "sysv64" fn(u32) -> !) -> bool {
    let Some(stack) = cpu::kernel_stack_top_for_cpu(cpu) else {
        return false;
    };
    MAILBOX_CR3.store(paging::kernel_root_address(), Ordering::Release);
    MAILBOX_STACK.store(stack as u64, Ordering::Release);
    MAILBOX_ENTRY.store(entry as *const () as u64, Ordering::Release);
    MAILBOX_CPU.store(cpu as u32, Ordering::Release);
    true
}
