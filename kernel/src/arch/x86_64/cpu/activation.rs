//! Kernel stacks for Linux thread activations: the pool of stacks and the
//! scheduler's view of activations. The activations themselves, their
//! stacks and the switching between them are the trusted core's
//! (`trusted::switch`, whose module comment says how they work).
//!
//! A finished activation's stack is kept for the next one, as many as are
//! live or [`SPARE_STACKS`]; past that (after a burst of thousands of
//! processes) its frames go back to the frame allocator, and its slot is
//! mapped again only once every other CPU has loaded CR3 since (or sits
//! halted idle, and reloads it before it runs anything), dropping any
//! translation it still held of the slot's pages; the CPU mapping it drops
//! its own.
#![forbid(unsafe_code)]

use alloc::vec::Vec;

use crate::sync::{LockRank, SpinLock};
use crate::trusted::switch::{self, KernelStack};
pub(super) use crate::trusted::switch::{Owner, Wake};

/// What had become of an activation when control came back to the context
/// that entered or resumed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Outcome {
    /// One of the process's system calls returned to the kernel: the
    /// activation is over (its stack is back in the pool).
    Finished,
    /// A system call parked: it waits on the activation's stack until
    /// `resume`.
    Parked,
}

/// Finished activations' stacks kept mapped for the next ones.
const SPARE_STACKS: usize = 64;

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

/// Hands a finished activation's stack back to the pool and says what had
/// become of it.
fn settle(outcome: switch::Outcome) -> Outcome {
    match outcome {
        switch::Outcome::Finished(stack, live) => {
            return_stack(stack, live);
            Outcome::Finished
        }
        switch::Outcome::Parked => Outcome::Parked,
    }
}

/// The memory kernel stacks hold, in bytes: the live activations' and the
/// spare ones kept mapped (/proc/meminfo's KernelStack).
pub(super) fn kernel_stack_bytes() -> usize {
    let live = switch::live_count();
    let spare = STACK_POOL.lock().free.len();
    (live + spare) * switch::STACK_SIZE
}

/// Whether the first activation has checked stack switching yet.
static SWITCHING_VERIFIED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Enters process `pid`'s user mode on an activation stack of its own and
/// returns when one of its system calls returns to the kernel or parks.
/// Returns `None` without entering when no stack could be allocated. The
/// caller activated the process's address space and validated the user
/// context in `general` (fifteen registers).
pub(super) fn enter_on_own_stack(
    owner: Owner,
    entry: usize,
    stack: usize,
    general: &[u64; 15],
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
    Some(settle(switch::enter_on_own_stack(
        owner,
        kernel_stack,
        super::process_user_enter,
        entry,
        stack,
        general,
        rflags,
    )))
}

/// Parks the running activation of `owner`'s process for thread
/// `owner.tid` (`trusted::switch::park`).
pub(super) fn park(owner: Owner) -> Option<Wake> {
    switch::park(owner)
}

/// Resumes the parked activation of thread `owner` until it parks again or
/// finishes (`trusted::switch::resume`); `None` when it has none.
pub(super) fn resume(owner: Owner, unwind: bool) -> Option<Outcome> {
    switch::resume(owner, unwind).map(settle)
}

/// Resumes parked thread `owner`'s call to unwind (see [`Wake::Unwind`])
/// until its activation finishes, from the scheduler or from inside
/// another system call of its process (an exec): the CPU's entry state,
/// which the resumed call replaces with its own, is kept across. False
/// when it has no parked activation or did not finish.
pub(super) fn unwind(owner: Owner) -> bool {
    resume(owner, true) == Some(Outcome::Finished)
}

/// Drops thread `owner`'s parked activation without running it again: its
/// stack goes back to the pool and its frames are abandoned (anything they
/// own leaks). For a thread that ends when its call cannot be unwound.
pub(super) fn discard(owner: Owner) {
    if let Some(stack) = switch::discard(owner) {
        STACK_POOL.lock().free.push(stack);
    }
}

/// Process `pid` of domain instance `instance` has an activation running
/// on some CPU: a system call of it is in progress there (or it runs user
/// code), so no other CPU may enter or resume it.
pub(super) fn is_running(instance: u32, pid: u32) -> bool {
    switch::is_running(instance, pid)
}

/// The threads of process `pid` of domain instance `instance` parked in a
/// system call, in the order they were entered.
pub(super) fn parked_threads(instance: u32, pid: u32) -> Vec<u32> {
    switch::parked_threads(instance, pid)
}

/// Drops the parked activations of domain instance `instance` when its
/// runtime stops: their system calls never continue, and their stacks are
/// reused.
pub(super) fn discard_parked(instance: u32) {
    let stacks = switch::discard_parked(instance);
    let mut pool = STACK_POOL.lock();
    pool.free.extend(stacks);
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

/// Proves stack switching on a stack from the pool, which goes back after.
pub(super) fn verify_stack_switching() -> bool {
    let Some(mut stack) = take_stack() else {
        return false;
    };
    let verified = switch::verify_stack_switching(&mut stack);
    STACK_POOL.lock().free.push(stack);
    verified
}
