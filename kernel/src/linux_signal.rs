//! The Linux signal queues: each domain's queued signals, one queue per
//! process slot and one per thread slot of each process.
//!
//! Standard signals (`realtime` false) coalesce: a second one of a number
//! already queued is dropped. Real-time signals queue every instance. A
//! dequeue takes the lowest-numbered requested signal, and among queued
//! signals of the same number the oldest. The counts of queued signals are
//! atomics, so `pending_count` and `any_pending` take no lock.
//!
//! The tables grow as slots are first used: process queues by process
//! slot, and thread queues by process slot and then thread slot, so a
//! process that uses only its first threads has queues for those alone.
//!
//! Each domain instance's queues are under one leaf lock
//! (`LockRank::SIGNAL_QUEUES`, above the heap: a memory cgroup's OOM kill
//! sends SIGKILL from a page fault taken under whatever lock a system call
//! holds; docs/feedback-hardening/SYNCHRONIZATION.md, "Signal queues"). So
//! nothing is allocated or freed while it is held: an operation that has
//! to grow a table gets storage reserved with the lock released (`Spare`)
//! and tries again, and storage a table lets go of leaves the critical
//! section with the operation's result and is freed after the lock is.
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;

use crate::sync::{IrqSpinLock, LockRank};
use crate::{control_abi, linux_process};

/// Thread slots a process has: `LINUX_THREAD_LIMIT` (cpu.rs, whose signal
/// code checks they agree).
pub(crate) const THREAD_LIMIT: usize = 128;
const INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scope {
    Process,
    Thread,
}

/// The queue a signal is sent to: its process's, or one thread's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Target {
    Process(usize),
    Thread { process: usize, thread: usize },
}

impl Target {
    fn check(self) -> Result<(), Error> {
        let within = match self {
            Self::Process(process) => process < linux_process::PROCESS_LIMIT,
            Self::Thread { process, thread } => {
                process < linux_process::PROCESS_LIMIT && thread < THREAD_LIMIT
            }
        };
        within.then_some(()).ok_or(Error::Invalid)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Invalid,
    NoMemory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pending {
    pub(crate) signal: u8,
    pub(crate) code: i32,
    pub(crate) value: u64,
    pub(crate) sender_pid: u32,
    pub(crate) sender_uid: u32,
}

/// One queue: its signals in the order they were queued, so the first of
/// a number is the oldest of that number. An empty queue holds no storage.
type Queue = Vec<Pending>;

/// The room an operation found missing under the lock: the table and the
/// capacity to reserve for it.
#[derive(Clone, Copy)]
enum Need {
    Processes(usize),
    Threads(usize),
    Row(usize),
    Queue(usize),
}

/// Storage reserved with the lock released for the tables an operation
/// may have to grow, one empty `Vec` each. Under the lock a table that is
/// too small moves its entries into the spare and the two are swapped, so
/// the spare then holds the old, empty storage, which is freed when the
/// spare drops, after the lock is released.
#[derive(Default)]
struct Spare {
    processes: Vec<Queue>,
    threads: Vec<Vec<Queue>>,
    row: Vec<Queue>,
    queue: Queue,
}

impl Spare {
    /// Reserves `need`, the lock released; what the spare held before is
    /// freed here.
    fn reserve(&mut self, need: Need) -> Result<(), Error> {
        fn empty<T>(capacity: usize) -> Result<Vec<T>, Error> {
            let mut storage = Vec::new();
            storage
                .try_reserve_exact(capacity)
                .map_err(|_| Error::NoMemory)?;
            Ok(storage)
        }
        match need {
            Need::Processes(capacity) => self.processes = empty(capacity)?,
            Need::Threads(capacity) => self.threads = empty(capacity)?,
            Need::Row(capacity) => self.row = empty(capacity)?,
            Need::Queue(capacity) => self.queue = empty(capacity)?,
        }
        Ok(())
    }
}

/// Makes `table` able to hold `needed` entries without allocating, from
/// `spare` if it must grow; Err with the room to reserve when the spare is
/// too small. Tables grow by doubling, up to `limit` entries.
fn ensure<T>(
    table: &mut Vec<T>,
    needed: usize,
    spare: &mut Vec<T>,
    limit: usize,
    need: fn(usize) -> Need,
) -> Result<(), Need> {
    if table.capacity() >= needed {
        return Ok(());
    }
    if spare.capacity() < needed || !spare.is_empty() {
        let doubled = table.capacity().saturating_mul(2).max(4).min(limit);
        return Err(need(needed.max(doubled)));
    }
    // Neither allocates: the spare has room for every entry.
    spare.append(table);
    core::mem::swap(table, spare);
    Ok(())
}

/// The entry of `slot` in `table`, the table grown to it first.
fn grown<'a, T: Default>(
    table: &'a mut Vec<T>,
    slot: usize,
    spare: &mut Vec<T>,
    limit: usize,
    need: fn(usize) -> Need,
) -> Result<&'a mut T, Need> {
    ensure(table, slot + 1, spare, limit, need)?;
    if table.len() <= slot {
        // Within the capacity, and an empty `Vec` holds no storage.
        table.resize_with(slot + 1, T::default);
    }
    Ok(&mut table[slot])
}

/// Drops the empty entries at the end of `table` that hold no storage,
/// which frees nothing.
fn trim<T>(table: &mut Vec<Vec<T>>) {
    while table
        .last()
        .is_some_and(|entry| entry.is_empty() && entry.capacity() == 0)
    {
        table.pop();
    }
}

/// One instance's queues. Nothing here allocates or frees: the critical
/// sections are only the methods below and reads of their results.
struct Tables {
    /// Process queues by process slot: as long as the highest slot used
    /// so far.
    processes: Vec<Queue>,
    /// Thread queues by process slot, then thread slot (a row per process):
    /// each as long as the highest slot used so far.
    threads: Vec<Vec<Queue>>,
}

impl Tables {
    const fn new() -> Self {
        Self {
            processes: Vec::new(),
            threads: Vec::new(),
        }
    }

    /// The queue of `target` (checked), the tables grown to reach it from
    /// `spare`.
    fn queue(&mut self, target: Target, spare: &mut Spare) -> Result<&mut Queue, Need> {
        match target {
            Target::Process(process) => grown(
                &mut self.processes,
                process,
                &mut spare.processes,
                linux_process::PROCESS_LIMIT,
                Need::Processes,
            ),
            Target::Thread { process, thread } => {
                let row = grown(
                    &mut self.threads,
                    process,
                    &mut spare.threads,
                    linux_process::PROCESS_LIMIT,
                    Need::Threads,
                )?;
                grown(row, thread, &mut spare.row, THREAD_LIMIT, Need::Row)
            }
        }
    }

    /// The queue of `target` if the tables reach it, without growing them:
    /// a slot past the end has an empty queue.
    fn existing(&mut self, target: Target) -> Result<Option<&mut Queue>, Error> {
        target.check()?;
        Ok(match target {
            Target::Process(process) => self.processes.get_mut(process),
            Target::Thread { process, thread } => self
                .threads
                .get_mut(process)
                .and_then(|row| row.get_mut(thread)),
        })
    }

    /// Queues `pending` on `target`: Ok(false) when a standard signal of
    /// its number is already queued there.
    fn enqueue(
        &mut self,
        target: Target,
        pending: Pending,
        realtime: bool,
        spare: &mut Spare,
    ) -> Result<bool, Need> {
        let queue = self.queue(target, spare)?;
        if !realtime && queue.iter().any(|queued| queued.signal == pending.signal) {
            return Ok(false);
        }
        let needed = queue.len() + 1;
        ensure(queue, needed, &mut spare.queue, usize::MAX, Need::Queue)?;
        queue.push(pending);
        Ok(true)
    }

    /// Gives up the empty queues at the ends of the tables `target` is in.
    fn trim(&mut self, target: Target) {
        match target {
            Target::Process(_) => trim(&mut self.processes),
            Target::Thread { process, .. } => {
                if let Some(row) = self.threads.get_mut(process) {
                    trim(row);
                }
                trim(&mut self.threads);
            }
        }
    }
}

struct SignalRuntimeOwner {
    /// Signals queued in each instance, for RLIMIT_SIGPENDING and the
    /// lock-free `any_pending`; changed only with the instance's lock held.
    pending_counts: [AtomicU64; INSTANCE_LIMIT],
    instances: [IrqSpinLock<Tables>; INSTANCE_LIMIT],
}

static SIGNAL_RUNTIME: SignalRuntimeOwner = SignalRuntimeOwner {
    pending_counts: [const { AtomicU64::new(0) }; INSTANCE_LIMIT],
    instances: [const { IrqSpinLock::new(LockRank::SIGNAL_QUEUES, Tables::new()) }; INSTANCE_LIMIT],
};

fn tables(instance: usize) -> Result<&'static IrqSpinLock<Tables>, Error> {
    SIGNAL_RUNTIME.instances.get(instance).ok_or(Error::Invalid)
}

fn signal_bit(signal: u8) -> u64 {
    1_u64 << (signal - 1)
}

/// The index in `queue` of the signal a dequeue of `requested` takes: the
/// lowest-numbered, the oldest of that number.
fn select(queue: &Queue, requested: u64) -> Option<usize> {
    queue
        .iter()
        .enumerate()
        .filter(|(_, pending)| requested & signal_bit(pending.signal) != 0)
        .min_by_key(|(index, pending)| (pending.signal, *index))
        .map(|(index, _)| index)
}

pub(crate) fn enqueue(
    instance: usize,
    target: Target,
    pending: Pending,
    realtime: bool,
) -> Result<bool, Error> {
    if !(1..=64).contains(&pending.signal) {
        return Err(Error::Invalid);
    }
    target.check()?;
    let lock = tables(instance)?;
    // Dropped after the lock is released, with any storage it took over.
    let mut spare = Spare::default();
    loop {
        let need = match lock.lock().enqueue(target, pending, realtime, &mut spare) {
            Ok(queued) => {
                if queued {
                    SIGNAL_RUNTIME.pending_counts[instance].fetch_add(1, Ordering::Release);
                }
                return Ok(queued);
            }
            Err(need) => need,
        };
        spare.reserve(need)?;
    }
}

/// The signals queued in `instance`, for RLIMIT_SIGPENDING.
pub(crate) fn pending_count(instance: usize) -> u64 {
    SIGNAL_RUNTIME
        .pending_counts
        .get(instance)
        .map_or(0, |count| count.load(Ordering::Acquire))
}

pub(crate) fn any_pending(instance: usize) -> bool {
    SIGNAL_RUNTIME
        .pending_counts
        .get(instance)
        .is_some_and(|count| count.load(Ordering::Acquire) != 0)
}

/// Whether the queue of `target` holds a signal, blocked or not. Cheap
/// when the instance has nothing queued anywhere; otherwise one lock and a
/// look at the queue's length (a slot never used has no queue and holds
/// none).
pub(crate) fn queued(instance: usize, target: Target) -> bool {
    if !any_pending(instance) {
        return false;
    }
    let Ok(lock) = tables(instance) else {
        return false;
    };
    let mut tables = lock.lock();
    tables
        .existing(target)
        .ok()
        .flatten()
        .is_some_and(|queue| !queue.is_empty())
}

pub(crate) fn pending_mask(instance: usize, target: Target) -> Result<u64, Error> {
    let mut tables = tables(instance)?.lock();
    Ok(tables.existing(target)?.map_or(0, |queue| {
        queue
            .iter()
            .fold(0, |mask, pending| mask | signal_bit(pending.signal))
    }))
}

pub(crate) fn peek(
    instance: usize,
    target: Target,
    requested: u64,
) -> Result<Option<Pending>, Error> {
    let mut tables = tables(instance)?.lock();
    Ok(tables
        .existing(target)?
        .and_then(|queue| select(queue, requested).map(|index| queue[index])))
}

pub(crate) fn dequeue(
    instance: usize,
    target: Target,
    requested: u64,
) -> Result<Option<Pending>, Error> {
    let lock = tables(instance)?;
    let (pending, released) = {
        let mut tables = lock.lock();
        let Some(queue) = tables.existing(target)? else {
            return Ok(None);
        };
        let Some(index) = select(queue, requested) else {
            return Ok(None);
        };
        // `remove` keeps the order the rest were queued in.
        let pending = queue.remove(index);
        SIGNAL_RUNTIME.pending_counts[instance].fetch_sub(1, Ordering::AcqRel);
        // A drained queue gives its storage back, freed below.
        let released = if queue.is_empty() {
            core::mem::take(queue)
        } else {
            Vec::new()
        };
        (pending, released)
    };
    drop(released);
    Ok(Some(pending))
}

/// Drops every signal queued for `target`.
pub(crate) fn clear(instance: usize, target: Target) -> Result<(), Error> {
    let lock = tables(instance)?;
    // Freed after the lock is released.
    let _released = {
        let mut tables = lock.lock();
        let released = tables.existing(target)?.map(core::mem::take);
        tables.trim(target);
        let dropped = released.as_ref().map_or(0, Vec::len);
        if dropped != 0 {
            SIGNAL_RUNTIME.pending_counts[instance].fetch_sub(dropped as u64, Ordering::AcqRel);
        }
        released
    };
    Ok(())
}

/// Drops every signal queued for process slot `process` and each of its
/// thread slots, and the thread queues themselves: for a process slot that
/// is freed or given to a new process.
pub(crate) fn clear_process(instance: usize, process: usize) -> Result<(), Error> {
    let target = Target::Process(process);
    let lock = tables(instance)?;
    // Freed after the lock is released.
    let _released = {
        let mut tables = lock.lock();
        let queue = tables.existing(target)?.map(core::mem::take);
        let row = tables.threads.get_mut(process).map(core::mem::take);
        tables.trim(target);
        tables.trim(Target::Thread { process, thread: 0 });
        let dropped = queue.as_ref().map_or(0, Vec::len)
            + row
                .as_ref()
                .map_or(0, |row| row.iter().map(Vec::len).sum::<usize>());
        if dropped != 0 {
            SIGNAL_RUNTIME.pending_counts[instance].fetch_sub(dropped as u64, Ordering::AcqRel);
        }
        (queue, row)
    };
    Ok(())
}

/// The boot self-test of the queues: coalescing, real-time order, queues
/// of one process and thread slot kept apart from every other's, and the
/// storage given back once they drain.
pub(crate) fn verify_dynamic_fifo(instance: usize) -> bool {
    let process = linux_process::PROCESS_LIMIT - 2;
    let next = process + 1;
    let thread = Target::Thread {
        process,
        thread: THREAD_LIMIT - 1,
    };
    let process_target = Target::Process(process);
    if clear_process(instance, process).is_err() || clear_process(instance, next).is_err() {
        return false;
    }
    let base = pending_count(instance);
    let standard = Pending {
        signal: 10,
        code: 0,
        value: 1,
        sender_pid: 1,
        sender_uid: 0,
    };
    let realtime = |code: i32, value: u64| Pending {
        signal: 34,
        code,
        value,
        sender_pid: 1,
        sender_uid: 0,
    };
    let standard_coalesced = enqueue(instance, process_target, standard, false) == Ok(true)
        && enqueue(
            instance,
            process_target,
            Pending {
                value: 2,
                ..standard
            },
            false,
        ) == Ok(false)
        && pending_count(instance) == base + 1
        && dequeue(instance, process_target, u64::MAX) == Ok(Some(standard))
        && pending_count(instance) == base;
    let isolated = enqueue(instance, process_target, realtime(-1, 3), true) == Ok(true)
        && enqueue(instance, thread, realtime(-6, 4), true) == Ok(true)
        && pending_count(instance) == base + 2
        && pending_mask(instance, process_target) == Ok(1 << 33)
        && pending_mask(instance, thread) == Ok(1 << 33)
        && dequeue(instance, thread, u64::MAX) == Ok(Some(realtime(-6, 4)))
        && dequeue(instance, process_target, u64::MAX) == Ok(Some(realtime(-1, 3)))
        && pending_count(instance) == base;
    // Thread slot 20 of one process and thread slot 4 of the next: a
    // flattened index of 16 thread slots per process made them one queue.
    let high = Target::Thread {
        process,
        thread: 20,
    };
    let other = Target::Thread {
        process: next,
        thread: 4,
    };
    let threads_apart = enqueue(instance, high, realtime(-6, 20), true) == Ok(true)
        && pending_mask(instance, other) == Ok(0)
        && !queued(instance, other)
        && queued(instance, high)
        && dequeue(instance, other, u64::MAX) == Ok(None)
        && enqueue(instance, other, realtime(-6, 4), true) == Ok(true)
        && dequeue(instance, high, u64::MAX) == Ok(Some(realtime(-6, 20)))
        && dequeue(instance, other, u64::MAX) == Ok(Some(realtime(-6, 4)))
        && enqueue(
            instance,
            Target::Thread {
                process,
                thread: THREAD_LIMIT,
            },
            standard,
            false,
        ) == Err(Error::Invalid);
    // A process slot's clear drops its thread queues, the last too.
    let process_cleared = enqueue(instance, thread, standard, false) == Ok(true)
        && enqueue(instance, high, standard, false) == Ok(true)
        && enqueue(instance, other, standard, false) == Ok(true)
        && clear_process(instance, process).is_ok()
        && pending_count(instance) == base + 1
        && pending_mask(instance, thread) == Ok(0)
        && pending_mask(instance, high) == Ok(0)
        && pending_mask(instance, other) == Ok(1 << 9)
        && clear(instance, other).is_ok()
        && pending_count(instance) == base;
    // Many real-time signals of one number come out in the order sent,
    // after a lower-numbered one sent last.
    const MANY: u64 = 300;
    let mut filled = true;
    for value in 0..MANY {
        filled &= enqueue(instance, process_target, realtime(-1, value), true) == Ok(true);
    }
    let lower = Pending {
        signal: 33,
        ..realtime(-1, MANY)
    };
    filled &= enqueue(instance, process_target, lower, true) == Ok(true);
    let mut ordered = peek(instance, process_target, u64::MAX) == Ok(Some(lower))
        && dequeue(instance, process_target, 1 << 32) == Ok(Some(lower));
    for value in 0..MANY {
        ordered &= dequeue(instance, process_target, 1 << 33) == Ok(Some(realtime(-1, value)));
    }
    let released = pending_count(instance) == base
        && tables(instance).is_ok_and(|lock| {
            lock.lock()
                .existing(process_target)
                .is_ok_and(|queue| queue.is_none_or(|queue| queue.capacity() == 0))
        });
    let clean = clear_process(instance, process).is_ok() && clear_process(instance, next).is_ok();
    standard_coalesced
        && isolated
        && threads_apart
        && process_cleared
        && filled
        && ordered
        && released
        && clean
}
