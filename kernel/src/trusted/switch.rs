//! Kernel stacks of their own for Linux thread activations, and switching
//! between them: the context-switch core under `cpu/activation.rs`.
//!
//! Entering a thread of a Linux process starts an activation: a kernel
//! context on a [`KernelStack`] of its own that enters user mode
//! (`cpu::process_user_enter`) and runs the process's system calls until
//! one of them returns to the kernel. A call that must wait parks its
//! activation ([`park`]): it switches back to the context that entered or
//! last resumed the activation, and continues when that context, or
//! another, resumes it ([`resume`]). Each thread waits on its own
//! activation, keyed by its [`Owner`] (docs/SCHEDULER.md, steps 2 and 5).
//!
//! # Stacks
//!
//! A [`KernelStack`] is a stack in the kernel stack window
//! (`paging::KERNEL_STACK_WINDOW_BASE`), one per 512 KiB slot: its pages at
//! the top of its slot, mapped from fresh frames by [`KernelStack::new`],
//! and the rest of the slot unmapped, so an overflow faults on a guard page
//! (reported as a double fault) instead of overwriting the memory below.
//! Only `new` makes one and it is not `Clone`: the value is the one handle
//! to its stack, so whoever holds it (an activation, or the pool in
//! `cpu/activation.rs`) uses the stack alone.
//!
//! # Switching
//!
//! `linox_switch_stack(save, load)` pushes the callee-saved registers,
//! stores the stack pointer at `save`, loads `load` and pops that context's
//! registers, returning into wherever it switched away (a new context
//! starts in `linox_context_start`, which calls its function). The
//! invariants this module keeps:
//!
//! - **Records.** Each activation's record is boxed in [`ACTIVATIONS`] and
//!   its address stays fixed until it is removed. A record is removed only
//!   by the context that switched into it, once it has finished (in `run`),
//!   or, while parked, by [`discard`] and [`discard_parked`] (its context
//!   then never runs again). The record's fields are read and written
//!   through the raw pointer, without the lock, only by the context running
//!   on its stack and by the context that switched into it while the other
//!   one is switched away: exactly one of the two runs at a time.
//! - **State.** A record is `Running` while one context has switched into
//!   it and not yet back; [`resume`] marks a `Parked` record `Running` under
//!   the lock before switching into it, so no two contexts resume one
//!   record; a `Finished` record is never switched into again.
//! - **Entry state.** A parked call's CPU entry state (its return stack and
//!   frame, `trusted::entry`) is taken off the CPU when it parks
//!   (`cpu_tables::take_for_park`, which clears the CPU's live frame) and
//!   put back when it is resumed, on whichever CPU; the resumer's own is put
//!   back after. So the stacks an entry state names are always those of a
//!   context that is running or parked, never freed: a parked activation's
//!   stack is freed only by `discard`, after which its entry state is
//!   dropped with its record.
//! - **Kernel-entry depth.** A parked call takes its entries of the
//!   kernel-entry lock off its CPU and the resumer adds them to its own
//!   (`sync::kernel_entry_detach`/`attach`), so the lock is accounted to
//!   whichever CPU runs the call.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::ffi::c_void;
use core::mem::size_of;

use super::cpu_tables::{self, CpuEntryState};
use crate::arch::x86_64::paging;
use crate::memory::{self, FrameOwner};
use crate::sync::{LockRank, SpinLock};

/// Usable bytes of a kernel stack.
pub(crate) const STACK_SIZE: usize = 256 * 1024;
/// Window space per stack; everything below the stack in its slot is guard.
const SLOT_SIZE: usize = 512 * 1024;
const PAGE_SIZE: usize = 4096;

/// A kernel stack mapped in its own window slot (see the module comment).
pub(crate) struct KernelStack {
    /// The initial stack pointer: the end of the stack, 16-byte aligned.
    top: usize,
}

impl KernelStack {
    /// The window slot the stack is in.
    pub(crate) fn slot(&self) -> usize {
        (self.top - paging::KERNEL_STACK_WINDOW_BASE) / SLOT_SIZE - 1
    }

    /// Whether `address` lies on this stack.
    fn contains(&self, address: usize) -> bool {
        (self.top - STACK_SIZE..self.top).contains(&address)
    }

    /// Unmaps the stack and gives its frames back.
    pub(crate) fn release(self) {
        for page in 1..=STACK_SIZE / PAGE_SIZE {
            let address = self.top - page * PAGE_SIZE;
            if let Some(frame) = paging::unmap_kernel_stack_page(address)
                .and_then(|physical| memory::live_frame_lease(FrameOwner::KERNEL, physical))
            {
                let _ = memory::release_frames(FrameOwner::KERNEL, [frame]);
            }
        }
    }

    /// Maps a new stack into window slot `slot` from fresh frames. The
    /// caller never maps one slot twice while its stack lives (the pool in
    /// `cpu/activation.rs` hands out each slot once until it is released,
    /// and maps a released slot again only once every CPU has dropped its
    /// translations of it).
    pub(crate) fn new(slot: usize) -> Option<Self> {
        let end = slot.checked_add(1)?.checked_mul(SLOT_SIZE)?;
        if end > paging::KERNEL_STACK_WINDOW_SIZE {
            return None;
        }
        let top = paging::KERNEL_STACK_WINDOW_BASE + end;
        for page in 1..=STACK_SIZE / PAGE_SIZE {
            let address = top - page * PAGE_SIZE;
            let [frame] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
            let mut table = None;
            if !paging::map_kernel_stack_page(address, frame.address(), &mut table) {
                // The first page in a 2 MiB region also needs its page table.
                let [table_frame] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
                table = Some(table_frame.address());
                if !paging::map_kernel_stack_page(address, frame.address(), &mut table) {
                    return None;
                }
            }
        }
        Some(Self { top })
    }
}

global_asm!(
    r#"
    .text
    .global linox_switch_stack
// linox_switch_stack(save: rdi, load: rsi) saves the callee-saved registers
// on the current stack, stores its stack pointer at [rdi], loads the stack
// pointer in rsi, restores that context's callee-saved registers and
// returns into wherever it switched away.
linox_switch_stack:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    .global linox_context_start
// A new context's first switch returns here with its function in r12 and
// the function's argument in r13. The function never returns.
linox_context_start:
    mov rdi, r13
    call r12
    ud2
"#
);

extern "sysv64" {
    fn linox_switch_stack(save: *mut usize, load: usize);
    fn linox_context_start();
}

/// Whose an activation is: thread `tid` of process `pid` in domain instance
/// `instance` (pids repeat across domains). An activation runs whichever
/// thread of its process is current on its CPU; it is keyed by the thread
/// whose system call parks on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Owner {
    pub(crate) instance: u32,
    pub(crate) pid: u32,
    pub(crate) tid: u32,
}

impl Owner {
    /// Whether the activation is of process `pid` in domain instance
    /// `instance`, whichever thread.
    const fn of_process(self, instance: u32, pid: u32) -> bool {
        self.instance == instance && self.pid == pid
    }
}

/// How a parked system call goes on when resumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Wake {
    /// Its wait may be over: it looks again.
    Continue,
    /// Its thread is ending (exit_group, exec, a fatal signal): the call
    /// unwinds at once, returning to the kernel, so the activation
    /// finishes and its stack is freed.
    Unwind,
}

/// What had become of an activation when control came back to the context
/// that entered or resumed it.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// One of the process's system calls returned to the kernel: the
    /// activation is over, and its stack is handed back with the number
    /// of activations still live.
    Finished(KernelStack, usize),
    /// A system call parked: it waits on the activation's stack until
    /// `resume`.
    Parked,
}

impl core::fmt::Debug for KernelStack {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KernelStack")
            .field("top", &self.top)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Running,
    Parked,
    Finished,
}

/// What an activation's context runs: enters the process's user mode with
/// the entry, stack, fifteen registers and flags given, returning when one
/// of its system calls returns to the kernel (`cpu::process_user_enter`).
pub(crate) type Body = fn(usize, usize, &[u64; 15], u64);

/// One entry into a process: a kernel context on a stack of its own that
/// enters user mode and runs the process's system calls, and the context
/// that entered (or last resumed) it.
struct Activation {
    owner: Owner,
    /// Resumed to unwind (see [`Wake::Unwind`]).
    unwind: bool,
    /// None once the record is removed for good.
    stack: Option<KernelStack>,
    body: Body,
    entry: usize,
    user_stack: usize,
    general: [u64; 15],
    rflags: u64,
    /// The entering or resuming context's stack pointer while this runs.
    caller: usize,
    /// This activation's stack pointer while it does not run.
    context: usize,
    state: State,
    /// A parked system call's CPU entry state, which other activations
    /// overwrite while it waits.
    entry_state: CpuEntryState,
    /// The kernel-entry depth of the context running this activation, when
    /// it switched here.
    base_depth: u32,
    /// The kernel-entry entries a parked system call holds on its stack,
    /// taken off its CPU while it waits and given to the CPU that resumes
    /// it.
    parked_depth: u32,
}

/// Every live activation, running or parked, in the order they were
/// entered (see the module comment). The lock ranks below the heap and the
/// frame allocator, both used while it is held.
#[allow(clippy::vec_box)] // the boxes keep each record's address fixed
static ACTIVATIONS: SpinLock<Vec<Box<Activation>>> =
    SpinLock::new(LockRank::KERNEL_STACKS, Vec::new());

/// An activation's context: runs the process until one of its system calls
/// returns to the kernel, then switches back for good.
extern "sysv64" fn run_activation(argument: *mut c_void) -> ! {
    let activation = argument.cast::<Activation>();
    // SAFETY: the record stays in ACTIVATIONS, at this address, until the
    // context that switched here sees it finished, which this context
    // reports last; meanwhile only this context touches it (module
    // comment). The fields are copied out before the body runs, since the
    // body parks and resumes through `park`, which uses the record too.
    let (body, entry, user_stack, general, rflags) = unsafe {
        (
            (*activation).body,
            (*activation).entry,
            (*activation).user_stack,
            (*activation).general,
            (*activation).rflags,
        )
    };
    body(entry, user_stack, &general, rflags);
    // SAFETY: as above; switching to the caller hands the record back to
    // it, and this context never runs again.
    unsafe {
        (*activation).state = State::Finished;
        linox_switch_stack(&raw mut (*activation).context, (*activation).caller);
    }
    unreachable!("a finished activation is never resumed")
}

/// Switches to `activation` until it parks or finishes, and removes it once
/// finished.
///
/// # Safety
///
/// `activation` is a record in ACTIVATIONS this context just made, or
/// marked `Running` itself (`resume`), so no other context runs it.
unsafe fn run(activation: *mut Activation) -> Outcome {
    // SAFETY: as the caller promises; the record outlives the switch, and
    // the activation's context touches it only while this one is switched
    // away.
    let state = unsafe {
        (*activation).base_depth = crate::sync::kernel_entry_depth();
        crate::sync::kernel_entry_attach(core::mem::take(&mut (*activation).parked_depth));
        linox_switch_stack(&raw mut (*activation).caller, (*activation).context);
        (*activation).state
    };
    match state {
        State::Parked => Outcome::Parked,
        State::Finished => {
            let (finished, live) = {
                let mut activations = ACTIVATIONS.lock();
                let finished = activations
                    .iter()
                    .position(|candidate| core::ptr::eq(&raw const **candidate, activation))
                    .map(|index| activations.remove(index));
                (finished, activations.len())
            };
            match finished.and_then(|mut record| record.stack.take()) {
                Some(stack) => Outcome::Finished(stack, live),
                None => crate::kernel_fail("linox: finished activation without its record\r\n"),
            }
        }
        State::Running => crate::kernel_fail("linox: activation switched away while running\r\n"),
    }
}

/// Enters a process's user mode through `body` on `stack`, its own, and
/// returns when one of its system calls returns to the kernel or parks.
/// The caller checked stack switching works first ([`verify_stack_switching`]).
pub(crate) fn enter_on_own_stack(
    owner: Owner,
    stack: KernelStack,
    body: Body,
    entry: usize,
    user_stack: usize,
    general: &[u64; 15],
    rflags: u64,
) -> Outcome {
    let top = stack.top;
    let mut record = Box::new(Activation {
        owner,
        unwind: false,
        stack: Some(stack),
        body,
        entry,
        user_stack,
        general: *general,
        rflags,
        caller: 0,
        context: 0,
        state: State::Running,
        entry_state: CpuEntryState::EMPTY,
        base_depth: 0,
        parked_depth: 0,
    });
    let activation: *mut Activation = &raw mut *record;
    // SAFETY: the stack is this activation's alone (it owns the
    // `KernelStack`) until it finishes.
    record.context = unsafe { new_context(top, run_activation, activation.cast()) };
    {
        let mut activations = ACTIVATIONS.lock();
        if activations.iter().any(|candidate| {
            candidate.owner.of_process(owner.instance, owner.pid)
                && candidate.state == State::Running
        }) {
            report_reentry(owner, &activations);
        }
        activations.push(record);
    }
    // SAFETY: the record was just added and is running.
    unsafe { run(activation) }
}

/// Parks the running activation of `owner`'s process for thread
/// `owner.tid`, whose system call waits on the activation's stack while the
/// context that entered or resumed it runs; the call continues from here
/// when `resume` switches back, and is told how. Returns None, without
/// parking, when this is not that activation's stack (a process run below
/// another's frames cannot park) or the thread already waits on another.
pub(crate) fn park(owner: Owner) -> Option<Wake> {
    let here = 0_u8;
    let here = &raw const here as usize;
    let activation = {
        let mut activations = ACTIVATIONS.lock();
        if activations
            .iter()
            .any(|candidate| candidate.owner == owner && candidate.state == State::Parked)
        {
            return None;
        }
        activations
            .iter_mut()
            .rev()
            .find(|candidate| {
                candidate.owner.of_process(owner.instance, owner.pid)
                    && candidate.state == State::Running
                    && candidate
                        .stack
                        .as_ref()
                        .is_some_and(|stack| stack.contains(here))
            })
            .map(|candidate| {
                candidate.owner = owner;
                candidate.unwind = false;
                &raw mut **candidate
            })?
    };
    let entry_state = cpu_tables::take_for_park()?;
    // SAFETY: this is the running activation, on its own stack; its record
    // stays in ACTIVATIONS while it is parked, and its caller touches it
    // only once this context has switched away. The entry state taken
    // above is put back when this call continues, into the CPU that
    // resumed it.
    unsafe {
        (*activation).entry_state = entry_state;
        (*activation).state = State::Parked;
        let own = crate::sync::kernel_entry_depth().saturating_sub((*activation).base_depth);
        crate::sync::kernel_entry_detach(own);
        (*activation).parked_depth = own;
        linox_switch_stack(&raw mut (*activation).context, (*activation).caller);
        cpu_tables::restore((*activation).entry_state);
        Some(if (*activation).unwind {
            Wake::Unwind
        } else {
            Wake::Continue
        })
    }
}

/// Resumes the parked activation of thread `owner` until it parks again or
/// finishes; `None` when it has none. With `unwind`, its call is told to
/// unwind ([`Wake::Unwind`]) rather than look at its wait again. The
/// resumed call installs its own CPU entry state while it runs; the
/// resumer's is put back after. The caller has made the process current
/// again (its address space and per-process kernel state), as for entering
/// it; the resumed call puts back its own thread pointer and address space.
pub(crate) fn resume(owner: Owner, unwind: bool) -> Option<Outcome> {
    let activation = ACTIVATIONS
        .lock()
        .iter_mut()
        .find(|candidate| candidate.owner == owner && candidate.state == State::Parked)
        .map(|candidate| {
            candidate.state = State::Running;
            candidate.unwind = unwind;
            &raw mut **candidate
        })?;
    let saved = cpu_tables::entry_state()?;
    // SAFETY: a parked record stays in ACTIVATIONS until its context runs
    // again and finishes (or is discarded, which only parked records are);
    // it was marked running above, under the lock, so nobody else resumes
    // it.
    let outcome = unsafe { run(activation) };
    cpu_tables::restore(saved);
    Some(outcome)
}

/// Drops thread `owner`'s parked activation without running it again and
/// hands back its stack; its frames are abandoned (anything they own
/// leaks). For a thread that ends when its call cannot be unwound.
pub(crate) fn discard(owner: Owner) -> Option<KernelStack> {
    let mut activations = ACTIVATIONS.lock();
    let index = activations
        .iter()
        .position(|candidate| candidate.owner == owner && candidate.state == State::Parked)?;
    activations.remove(index).stack.take()
}

/// Process `pid` of domain instance `instance` has an activation running
/// on some CPU: a system call of it is in progress there (or it runs user
/// code), so no other CPU may enter or resume it.
pub(crate) fn is_running(instance: u32, pid: u32) -> bool {
    ACTIVATIONS.lock().iter().any(|candidate| {
        candidate.owner.of_process(instance, pid) && candidate.state == State::Running
    })
}

/// How many activations are live, running or parked.
pub(crate) fn live_count() -> usize {
    ACTIVATIONS.lock().len()
}

/// The threads of process `pid` of domain instance `instance` parked in a
/// system call, in the order they were entered.
pub(crate) fn parked_threads(instance: u32, pid: u32) -> Vec<u32> {
    ACTIVATIONS
        .lock()
        .iter()
        .filter(|candidate| {
            candidate.owner.of_process(instance, pid) && candidate.state == State::Parked
        })
        .map(|candidate| candidate.owner.tid)
        .collect()
}

/// Drops the parked activations of domain instance `instance` when its
/// runtime stops (their system calls never continue) and hands back their
/// stacks.
pub(crate) fn discard_parked(instance: u32) -> Vec<KernelStack> {
    let mut activations = ACTIVATIONS.lock();
    let mut stacks = Vec::new();
    let mut index = 0;
    while index < activations.len() {
        let candidate = &activations[index];
        if candidate.state == State::Parked && candidate.owner.instance == instance {
            if let Some(stack) = activations.remove(index).stack.take() {
                stacks.push(stack);
            }
        } else {
            index += 1;
        }
    }
    stacks
}

/// Lays out a new context on the stack ending at `top` so that switching
/// to the returned stack pointer starts `function(argument)`.
///
/// # Safety
///
/// `top` must be the 16-byte aligned end of a mapped kernel stack that
/// nothing else uses while the context lives.
unsafe fn new_context(
    top: usize,
    function: extern "sysv64" fn(*mut c_void) -> !,
    argument: *mut c_void,
) -> usize {
    // Six callee-saved registers and the return address, placed so that
    // the stack is 16-byte aligned when linox_context_start calls function.
    let saved = top - 9 * size_of::<usize>();
    let frame = saved as *mut usize;
    let words = [
        0,                                         // r15
        0,                                         // r14
        argument as usize,                         // r13
        function as usize,                         // r12
        0,                                         // rbx
        0,                                         // rbp
        linox_context_start as *const () as usize, // return address
    ];
    for (index, word) in words.into_iter().enumerate() {
        // SAFETY: the caller hands over the stack below `top`, and these
        // seven words lie within its top page.
        unsafe { frame.add(index).write(word) };
    }
    saved
}

/// The state the switching self-test passes between its two contexts.
struct PingPong {
    boot: usize,
    context: usize,
    rounds: u32,
}

extern "sysv64" fn ping_pong(argument: *mut c_void) -> ! {
    let state = argument.cast::<PingPong>();
    loop {
        // SAFETY: verify_stack_switching keeps the state alive and only
        // touches it while this context is switched away.
        unsafe {
            (*state).rounds += 1;
            linox_switch_stack(&raw mut (*state).context, (*state).boot);
        }
    }
}

/// Starts a context on `stack`, switches into it and back three times, and
/// checks each round ran on that stack and came back here. The context
/// stays switched away for good; its frames on `stack` are abandoned, and
/// the stack may be used again once this returns.
pub(crate) fn verify_stack_switching(stack: &mut KernelStack) -> bool {
    let mut state = PingPong {
        boot: 0,
        context: 0,
        rounds: 0,
    };
    let state_pointer = &raw mut state;
    // SAFETY: the stack is this test's while `stack` is borrowed, and the
    // state outlives every switch into the context, which touches it only
    // while this function is switched away.
    unsafe {
        (*state_pointer).context = new_context(stack.top, ping_pong, state_pointer.cast());
        for round in 1..=3 {
            linox_switch_stack(&raw mut (*state_pointer).boot, (*state_pointer).context);
            let parked = (*state_pointer).context;
            if (*state_pointer).rounds != round || !stack.contains(parked) {
                return false;
            }
        }
    }
    true
}

/// A process entered while an earlier activation of it is still running
/// inside a system call: it now runs twice, which the scheduler rework
/// removes.
fn report_reentry(owner: Owner, activations: &[Box<Activation>]) {
    crate::serial_write_raw(b"linox: process re-entered during its own system call; pid ");
    crate::serial_write_u64(u64::from(owner.pid));
    crate::serial_write_raw(b" active");
    for activation in activations
        .iter()
        .filter(|activation| activation.state == State::Running)
    {
        crate::serial_write_raw(b" ");
        crate::serial_write_u64(u64::from(activation.owner.pid));
    }
    crate::serial_write_raw(b"\r\n");
}
