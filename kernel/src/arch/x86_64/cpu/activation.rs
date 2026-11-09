//! Kernel stacks for Linux thread activations.
//!
//! Entering a thread of a Linux process starts an activation: the thread
//! runs in ring 3 and makes its system calls, until one of them returns to
//! the kernel. Each activation gets a kernel stack of its own instead of
//! continuing below the frames of whoever entered it. A call that must
//! wait parks its activation, which then belongs to the thread whose call
//! waits there (its [`Owner`]); each thread of a process waits on its own
//! activation, so threads block and wake independently while a sibling
//! runs on another (docs/SCHEDULER.md, steps 2 and 5).
//!
//! Stacks live in the kernel stack window (`paging::KERNEL_STACK_WINDOW_BASE`),
//! one per 512 KiB slot: the stack's pages at the top of its slot and the
//! rest of the slot unmapped, so kernel work that overflows its stack faults
//! on a guard page (reported as a double fault) instead of overwriting the
//! memory below it. A finished activation's stack is kept for the next one,
//! as many as are live or [`SPARE_STACKS`]; past that (after a burst of
//! thousands of processes) its frames go back to the frame allocator, and
//! its slot is mapped again only once every other CPU has loaded CR3 since
//! (or sits halted idle, and reloads it before it runs anything), dropping
//! any translation it still held of the slot's pages; the CPU mapping it
//! drops its own.
//!
//! A kernel context parks on its stack by switching to another: the switch
//! saves the callee-saved registers and the stack pointer, loads another
//! context's, and returns into wherever that one switched away (or, for a
//! new context, into its function). This is how a blocked system call will
//! wait on its own stack while others run; `verify_stack_switching` proves
//! the mechanism at boot.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::ffi::c_void;
use core::mem::size_of;

use super::architecture::CpuEntryState;
use crate::arch::x86_64::paging;
use crate::memory::{self, FrameOwner};
use crate::sync::{LockRank, SpinLock};

/// Usable bytes of an activation stack.
const STACK_SIZE: usize = 256 * 1024;
/// Window space per stack; everything below the stack in its slot is guard.
const SLOT_SIZE: usize = 512 * 1024;
/// Finished activations' stacks kept mapped for the next ones.
const SPARE_STACKS: usize = 64;
const PAGE_SIZE: usize = 4096;

struct KernelStack {
    /// The initial stack pointer: the end of the stack, 16-byte aligned.
    top: usize,
}

impl KernelStack {
    /// The window slot the stack is in.
    fn slot(&self) -> usize {
        (self.top - paging::KERNEL_STACK_WINDOW_BASE) / SLOT_SIZE - 1
    }

    /// Unmaps the stack and gives its frames back.
    fn release(self) {
        for page in 1..=STACK_SIZE / PAGE_SIZE {
            let address = self.top - page * PAGE_SIZE;
            if let Some(frame) = paging::unmap_kernel_stack_page(address)
                .and_then(|physical| memory::live_frame_lease(FrameOwner::KERNEL, physical))
            {
                let _ = memory::release_frames(FrameOwner::KERNEL, [frame]);
            }
        }
    }

    /// Maps a new stack into window slot `slot` from fresh frames.
    fn new(slot: usize) -> Option<Self> {
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

/// Stacks of finished activations, kept for reuse because activations start
/// and end on every process switch, and the next unused window slot. The
/// lock serializes mapping new stacks; it ranks below the heap and the frame
/// allocator, both used while it is held.
struct StackPool {
    free: Vec<KernelStack>,
    /// Slots whose stacks went back to the frame allocator, with each CPU's
    /// CR3 loads when they did (`smp::flushed_since`).
    retired: Vec<(usize, [u64; crate::arch::x86_64::smp::CPU_LIMIT])>,
    next_slot: usize,
}

static STACK_POOL: SpinLock<StackPool> = SpinLock::new(
    LockRank::KERNEL_STACKS,
    StackPool {
        free: Vec::new(),
        retired: Vec::new(),
        next_slot: 0,
    },
);

/// Gives a finished activation's stack back, `live` activations being left:
/// stacks are kept for the next ones while no more of them wait than
/// `SPARE_STACKS` or as many as are live (which may finish and start again
/// any moment), and the rest are unmapped with their frames freed.
fn return_stack(stack: KernelStack, live: usize) {
    let mut pool = STACK_POOL.lock();
    pool.free.push(stack);
    let keep = SPARE_STACKS.max(live);
    while pool.free.len() > keep && pool.retired.try_reserve(1).is_ok() {
        let Some(stack) = pool.free.pop() else {
            break;
        };
        let slot = stack.slot();
        stack.release();
        let loads = crate::arch::x86_64::smp::root_loads();
        pool.retired.push((slot, loads));
    }
}

/// The memory kernel stacks hold, in bytes: the live activations' and the
/// spare ones kept mapped (/proc/meminfo's KernelStack).
pub(super) fn kernel_stack_bytes() -> usize {
    let live = ACTIVATIONS.lock().len();
    let spare = STACK_POOL.lock().free.len();
    (live + spare) * STACK_SIZE
}

/// Whether the first activation has checked stack switching yet.
static SWITCHING_VERIFIED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Every live activation, running or parked, in the order they were
/// entered. Each is boxed so its address stays fixed while its context and
/// the context that entered it use it through raw pointers, without the
/// lock, across a switch; only the context that entered or resumed an
/// activation removes it, once it has finished.
#[allow(clippy::vec_box)] // the boxes keep each record's address fixed
static ACTIVATIONS: SpinLock<Vec<Box<Activation>>> =
    SpinLock::new(LockRank::KERNEL_STACKS, Vec::new());

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
pub(super) struct Owner {
    pub(super) instance: u32,
    pub(super) pid: u32,
    pub(super) tid: u32,
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
pub(super) enum Wake {
    /// Its wait may be over: it looks again.
    Continue,
    /// Its thread is ending (exit_group, exec, a fatal signal): the call
    /// unwinds at once, returning to the kernel, so the activation
    /// finishes and its stack is freed.
    Unwind,
}

/// What had become of an activation when control came back to the context
/// that entered or resumed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Outcome {
    /// One of the process's system calls returned to the kernel: the
    /// activation is over.
    Finished,
    /// A system call parked: it waits on the activation's stack until
    /// `resume`.
    Parked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Running,
    Parked,
    Finished,
}

/// One entry into a process: a kernel context on a stack of its own that
/// enters user mode and runs the process's system calls, and the context
/// that entered (or last resumed) it.
struct Activation {
    owner: Owner,
    /// Resumed to unwind (see [`Wake::Unwind`]).
    unwind: bool,
    stack: KernelStack,
    entry: usize,
    user_stack: usize,
    general: [u64; 15],
    rflags: u64,
    /// The entering or resuming context's stack pointer while this runs.
    caller: usize,
    /// This activation's stack pointer while it does not run.
    context: usize,
    state: State,
    /// A parked system call's CPU entry state (its return stack, kernel
    /// frame and user return context), which other activations overwrite
    /// while it waits.
    entry_state: CpuEntryState,
    /// The kernel-entry depth of the context running this activation, when
    /// it switched here.
    base_depth: u32,
    /// The kernel-entry entries a parked system call holds on its stack,
    /// taken off its CPU while it waits and given to the CPU that resumes
    /// it.
    parked_depth: u32,
}

/// An activation's context: runs the process until one of its system calls
/// returns to the kernel, then switches back for good.
extern "sysv64" fn run_activation(argument: *mut c_void) -> ! {
    let activation = argument.cast::<Activation>();
    // SAFETY: the activation stays in ACTIVATIONS until the context that
    // switched here sees it finished, which this context reports last. The
    // entry stub records this stack as the return stack, so the process's
    // system calls run here too.
    unsafe {
        super::process_user_enter(
            (*activation).entry,
            (*activation).user_stack,
            (*activation).general.as_ptr(),
            (*activation).rflags,
        );
        (*activation).state = State::Finished;
        linox_switch_stack(&raw mut (*activation).context, (*activation).caller);
    }
    unreachable!("a finished activation is never resumed")
}

/// Switches to `activation` until it parks or finishes, and frees it once
/// finished.
///
/// # Safety
///
/// `activation` is a live, running record in ACTIVATIONS.
unsafe fn run(activation: *mut Activation) -> Outcome {
    // SAFETY: as the caller promises; the record outlives the switch.
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
            if let Some(finished) = finished {
                return_stack(finished.stack, live);
            }
            Outcome::Finished
        }
        State::Running => crate::kernel_fail("linox: activation switched away while running\r\n"),
    }
}

/// Enters process `pid`'s user mode on an activation stack of its own and
/// returns when one of its system calls returns to the kernel or parks.
/// Returns `None` without entering when no stack could be allocated.
///
/// # Safety
///
/// As for `linox_process_user_enter`: the caller activated the process's
/// address space and validated the complete user context in `general`
/// (fifteen registers).
pub(super) unsafe fn enter_on_own_stack(
    owner: Owner,
    entry: usize,
    stack: usize,
    general: *const u64,
    rflags: u64,
) -> Option<Outcome> {
    // The first activation proves stack switching on the stack window it
    // is about to use (the self-test cannot run earlier in boot, before
    // the runtime owns its frames).
    if !SWITCHING_VERIFIED.swap(true, core::sync::atomic::Ordering::AcqRel) {
        if !verify_stack_switching() {
            crate::kernel_fail("linox: kernel stack switching invalid\r\n");
        }
        crate::serial_write_raw(b"linox: kernel stack switching validated\r\n");
    }
    let kernel_stack = take_stack()?;
    let mut registers = [0_u64; 15];
    for (index, register) in registers.iter_mut().enumerate() {
        // SAFETY: the caller passes fifteen readable registers.
        *register = unsafe { general.add(index).read() };
    }
    let top = kernel_stack.top;
    let mut record = Box::new(Activation {
        owner,
        unwind: false,
        stack: kernel_stack,
        entry,
        user_stack: stack,
        general: registers,
        rflags,
        caller: 0,
        context: 0,
        state: State::Running,
        entry_state: CpuEntryState::EMPTY,
        base_depth: 0,
        parked_depth: 0,
    });
    let activation: *mut Activation = &raw mut *record;
    // SAFETY: the stack is this activation's alone until it finishes.
    unsafe { (*activation).context = new_context(top, run_activation, activation.cast()) };
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
    Some(unsafe { run(activation) })
}

/// Parks the running activation of `owner`'s process for thread
/// `owner.tid`, whose system call waits on the activation's stack while the
/// context that entered or resumed it runs; the call continues from here
/// when `resume` switches back, and is told how. Returns None, without
/// parking, when this is not that activation's stack (a process run below
/// another's frames cannot park) or the thread already waits on another.
pub(super) fn park(owner: Owner) -> Option<Wake> {
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
                    && (candidate.stack.top - STACK_SIZE..candidate.stack.top).contains(&here)
            })
            .map(|candidate| {
                candidate.owner = owner;
                candidate.unwind = false;
                &raw mut **candidate
            })?
    };
    // SAFETY: this is the running activation, on its own stack; its record
    // stays in ACTIVATIONS while it is parked. The CPU's entry state belongs
    // to this system call and is put back before it continues, into the
    // entry state of the CPU that resumed it.
    unsafe {
        (*activation).entry_state = *super::current_entry_state();
        (*activation).state = State::Parked;
        let own = crate::sync::kernel_entry_depth().saturating_sub((*activation).base_depth);
        crate::sync::kernel_entry_detach(own);
        (*activation).parked_depth = own;
        linox_switch_stack(&raw mut (*activation).context, (*activation).caller);
        *super::current_entry_state() = (*activation).entry_state;
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
/// resumer's is put back after.
///
/// # Safety
///
/// The caller made the process current again (its address space and
/// per-process kernel state), as for entering it; the resumed call puts
/// back its own thread pointer and address space.
pub(super) unsafe fn resume(owner: Owner, unwind: bool) -> Option<Outcome> {
    let activation = ACTIVATIONS
        .lock()
        .iter_mut()
        .find(|candidate| candidate.owner == owner && candidate.state == State::Parked)
        .map(|candidate| {
            candidate.state = State::Running;
            candidate.unwind = unwind;
            &raw mut **candidate
        })?;
    // SAFETY: a parked record stays in ACTIVATIONS until its context runs
    // again and finishes; it is marked running, so nobody else resumes it.
    // The entry state is this CPU's, used with interrupts off under the
    // kernel-entry lock.
    unsafe {
        let saved = *super::current_entry_state();
        let outcome = run(activation);
        *super::current_entry_state() = saved;
        Some(outcome)
    }
}

/// Resumes parked thread `owner`'s call to unwind (see [`Wake::Unwind`])
/// until its activation finishes, from the scheduler or from inside
/// another system call of its process (an exec): the CPU's entry state,
/// which the resumed call replaces with its own, is kept across. False
/// when it has no parked activation or did not finish.
pub(super) fn unwind(owner: Owner) -> bool {
    // SAFETY: the caller's process is current on this CPU (its address
    // space and kernel state); the unwinding call only returns to the
    // kernel, and `resume` puts back the entry state it replaces.
    let outcome = unsafe { resume(owner, true) };
    outcome == Some(Outcome::Finished)
}

/// Drops thread `owner`'s parked activation without running it again: its
/// stack goes back to the pool and its frames are abandoned (anything they
/// own leaks). For a thread that ends when its call cannot be unwound.
pub(super) fn discard(owner: Owner) {
    let discarded = {
        let mut activations = ACTIVATIONS.lock();
        activations
            .iter()
            .position(|candidate| candidate.owner == owner && candidate.state == State::Parked)
            .map(|index| activations.remove(index))
    };
    if let Some(activation) = discarded {
        STACK_POOL.lock().free.push(activation.stack);
    }
}

/// Process `pid` of domain instance `instance` has an activation running
/// on some CPU: a system call of it is in progress there (or it runs user
/// code), so no other CPU may enter or resume it.
pub(super) fn is_running(instance: u32, pid: u32) -> bool {
    ACTIVATIONS.lock().iter().any(|candidate| {
        candidate.owner.of_process(instance, pid) && candidate.state == State::Running
    })
}

/// The threads of process `pid` of domain instance `instance` parked in a
/// system call, in the order they were entered.
pub(super) fn parked_threads(instance: u32, pid: u32) -> Vec<u32> {
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
/// runtime stops: their system calls never continue, and their stacks are
/// reused.
pub(super) fn discard_parked(instance: u32) {
    let discarded = {
        let mut activations = ACTIVATIONS.lock();
        let mut discarded = Vec::new();
        let mut index = 0;
        while index < activations.len() {
            let candidate = &activations[index];
            if candidate.state == State::Parked && candidate.owner.instance == instance {
                discarded.push(activations.remove(index));
            } else {
                index += 1;
            }
        }
        discarded
    };
    let mut pool = STACK_POOL.lock();
    for activation in discarded {
        pool.free.push(activation.stack);
    }
}

/// Takes a kernel stack from the pool, or maps a new one.
fn take_stack() -> Option<KernelStack> {
    let mut pool = STACK_POOL.lock();
    if let Some(stack) = pool.free.pop() {
        return Some(stack);
    }
    // A retired slot every CPU has flushed is mapped anew; else a slot not
    // used yet.
    if let Some(index) = pool
        .retired
        .iter()
        .position(|(_, loads)| crate::arch::x86_64::smp::flushed_since(loads))
    {
        let (slot, _) = pool.retired.swap_remove(index);
        return KernelStack::new(slot);
    }
    let slot = pool.next_slot;
    let stack = KernelStack::new(slot)?;
    pool.next_slot = slot + 1;
    Some(stack)
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
        // touches it while this context is parked.
        unsafe {
            (*state).rounds += 1;
            linox_switch_stack(&raw mut (*state).context, (*state).boot);
        }
    }
}

/// Starts a context on a stack of its own, switches into it and back three
/// times, and checks each round ran on that stack and came back here.
pub(super) fn verify_stack_switching() -> bool {
    let Some(stack) = take_stack() else {
        return false;
    };
    let mut state = PingPong {
        boot: 0,
        context: 0,
        rounds: 0,
    };
    let state_pointer = &raw mut state;
    // SAFETY: the stack is this test's until it goes back to the pool, and
    // the state outlives every switch into the context.
    unsafe {
        (*state_pointer).context = new_context(stack.top, ping_pong, state_pointer.cast());
        for round in 1..=3 {
            linox_switch_stack(&raw mut (*state_pointer).boot, (*state_pointer).context);
            let parked = (*state_pointer).context;
            if (*state_pointer).rounds != round
                || !(stack.top - STACK_SIZE..stack.top).contains(&parked)
            {
                return false;
            }
        }
    }
    // The context stays parked; its stack is reused like any other.
    STACK_POOL.lock().free.push(stack);
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
