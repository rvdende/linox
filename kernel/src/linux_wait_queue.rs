//! Wait queues for blocked Linux system calls (docs/SCHEDULER.md, step 5).
//!
//! A process whose system call must wait parks on its kernel stack and is
//! *blocked*: it records what it waits for (a [`WaitOn`]) in the process
//! registry and leaves the run queue until a waker marks it ready, a
//! signal reaches it or its deadline passes. Woken, it looks at its wait
//! once more, in its own call, and either returns or blocks again.
//!
//! What a call can wait for is a set of [`events`], some of them narrowed
//! to keys (the futex word's physical address, a socket's slot):
//!
//! - Wakers that run in system call context with the registry at hand wake
//!   the waiters at once: FUTEX_WAKE (`events::FUTEX`), a child's change of
//!   state (`events::CHILD`), a signal (every wait).
//! - Wakers deep inside a subsystem, under that subsystem's lock, queue the
//!   event here instead ([`notify`]); the scheduler hands the queued events
//!   to the registry before it picks the next process ([`take`]), so a
//!   waiter is ready by the time anything could run it.
//! - Two coarse events cover what has no waker of its own: `STATE` comes
//!   after any system call that may change what another process waits for
//!   ([`note_state_change`]), and `TICK` with every tick of the boot CPU
//!   ([`note_tick`]): devices that are polled rather than interrupt-driven
//!   (the serial console, the network interface) and the few waits that
//!   look at the clock themselves.
//!
//! Deadlines are kept by the registry in a min-heap that the scheduler and
//! the tick consult, so a timed wait needs no event at all.
//!
//! Waking happens on the CPU that runs the scheduler; a later per-CPU
//! scheduler (step 6) delivers a wake for a process another CPU owns by
//! interrupt instead, and this queue is where it would find it.
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::{LockRank, SpinLock};

/// What a blocked call waits for besides a signal and its deadline.
pub(crate) mod events {
    /// A child (or tracee) changed state: it stopped, continued, exited or
    /// executed (a vfork parent's wait).
    pub(crate) const CHILD: u16 = 1 << 0;
    /// FUTEX_WAKE on a futex word: the key is the word's physical address.
    pub(crate) const FUTEX: u16 = 1 << 1;
    /// Data, room, a connection or a hangup on a local socket or pipe: the
    /// key is the socket's slot.
    pub(crate) const SOCKET: u16 = 1 << 2;
    /// Any system call that may change what another process waits for.
    pub(crate) const STATE: u16 = 1 << 3;
    /// Every Linux tick of the boot CPU.
    pub(crate) const TICK: u16 = 1 << 4;
}

/// How many keys a wait names before it waits for any key of its events.
pub(crate) const WAIT_KEYS: usize = 4;

/// The events queued with a key; the others carry none.
const KEYED_EVENTS: u16 = events::SOCKET;

/// What a blocked call waits for: `events`, narrowed to `keys` when it
/// names any (a wait with none takes any key of its events), until
/// `deadline` (nanoseconds since boot, 0 for none). A signal always wakes
/// it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WaitOn {
    events: u16,
    keys: [u64; WAIT_KEYS],
    key_count: u8,
    deadline: u64,
}

impl WaitOn {
    /// Only a signal or the deadline ends the wait (a sleep, pause).
    pub(crate) const NOTHING: Self = Self::of(0);
    /// Anything may end the wait: every state change and every tick. The
    /// wait of a call that cannot say better.
    pub(crate) const ANYTHING: Self = Self::of(events::STATE | events::TICK);

    /// Events `events`, any key, no deadline.
    pub(crate) const fn of(events: u16) -> Self {
        Self {
            events,
            keys: [0; WAIT_KEYS],
            key_count: 0,
            deadline: 0,
        }
    }

    /// Event `event` on `key` only.
    pub(crate) fn keyed(event: u16, key: u64) -> Self {
        Self::NOTHING.with_key(event, key)
    }

    /// Also waits for `event` on `key`. Keys are only ever queued with
    /// keyed events (sockets); the coarse events and those woken directly
    /// carry none, so the wait's keys narrow only those. Past
    /// [`WAIT_KEYS`] keys the wait takes any key instead.
    pub(crate) fn with_key(mut self, event: u16, key: u64) -> Self {
        let any_key = self.events & event != 0 && self.key_count == 0;
        self.events |= event;
        if any_key || self.key_count == u8::MAX {
            return self;
        }
        let count = usize::from(self.key_count);
        if self.keys[..count].contains(&key) {
            return self;
        }
        if count < WAIT_KEYS {
            self.keys[count] = key;
            self.key_count += 1;
        } else {
            self.key_count = u8::MAX;
        }
        self
    }

    /// Also waits for `events`, any key of them.
    pub(crate) const fn with_events(mut self, events: u16) -> Self {
        // A keyed event added without a key takes any key.
        if events & KEYED_EVENTS != 0 && self.key_count != 0 {
            self.key_count = u8::MAX;
        }
        self.events |= events;
        self
    }

    /// The wait ends by `deadline` at the latest (0: no change).
    pub(crate) fn until(mut self, deadline: u64) -> Self {
        if deadline != 0 && (self.deadline == 0 || deadline < self.deadline) {
            self.deadline = deadline;
        }
        self
    }

    /// `until` an optional deadline.
    pub(crate) fn until_some(self, deadline: Option<u64>) -> Self {
        self.until(deadline.unwrap_or(0))
    }

    /// Both waits: their events, keys and the earlier deadline.
    pub(crate) fn and(mut self, other: Self) -> Self {
        let keyed = other.events & KEYED_EVENTS;
        self = self.with_events(other.events & !KEYED_EVENTS);
        if keyed != 0 {
            match other.key_count {
                0 | u8::MAX => self = self.with_events(keyed),
                count => {
                    for key in &other.keys[..usize::from(count)] {
                        self = self.with_key(keyed, *key);
                    }
                }
            }
        }
        self.until(other.deadline)
    }

    pub(crate) const fn events(&self) -> u16 {
        self.events
    }

    pub(crate) const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Whether event `events` on `key` ends this wait; an event queued
    /// without a key (an overflow) ends every wait for it.
    pub(crate) fn woken_by(&self, events: u16, key: Option<u64>) -> bool {
        self.events & events != 0
            && match key {
                None => true,
                Some(_) if self.key_count == 0 || self.key_count == u8::MAX => true,
                Some(key) => self.keys[..usize::from(self.key_count)].contains(&key),
            }
    }
}

/// Events queued by wakers that cannot reach the registry, until the
/// scheduler takes them.
const PENDING_LIMIT: usize = 64;

struct Pending {
    entries: [(u16, u64); PENDING_LIMIT],
    count: usize,
    /// Events queued past the limit: every waiter for them is woken.
    overflowed: u16,
    /// The state changes and ticks counted when the scheduler last took
    /// the events.
    state_changes: u64,
    ticks: u64,
}

/// The queued events. A leaf: nothing is taken while it is held, and it
/// ranks above every subsystem lock a waker may hold.
static PENDING: SpinLock<Pending> = SpinLock::new(
    LockRank::WAKEUPS,
    Pending {
        entries: [(0, 0); PENDING_LIMIT],
        count: 0,
        overflowed: 0,
        state_changes: 0,
        ticks: 0,
    },
);

/// System calls that may have changed what another process waits for
/// (`events::STATE`), and the boot CPU's Linux ticks
/// (`events::TICK`), counted since boot.
static STATE_CHANGES: AtomicU64 = AtomicU64::new(0);
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Queues event `event` on `key` for the scheduler to wake its waiters.
pub(crate) fn notify(event: u16, key: u64) {
    let mut pending = PENDING.lock();
    let count = pending.count;
    if pending.entries[..count].contains(&(event, key)) {
        return;
    }
    if count == PENDING_LIMIT {
        pending.overflowed |= event;
    } else {
        pending.entries[count] = (event, key);
        pending.count = count + 1;
    }
}

/// A system call that may change what another process waits for ended.
pub(crate) fn note_state_change() {
    STATE_CHANGES.fetch_add(1, Ordering::Relaxed);
}

/// A Linux tick came. Safe from interrupt handlers: it takes no lock.
pub(crate) fn note_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

/// What the scheduler has to wake since it last looked: the queued events,
/// and the coarse events that came since.
pub(crate) struct Wakeups {
    entries: [(u16, u64); PENDING_LIMIT],
    count: usize,
    /// Events every waiter of which wakes.
    pub(crate) all: u16,
}

impl Wakeups {
    /// The keyed events to wake.
    pub(crate) fn keyed(&self) -> &[(u16, u64)] {
        &self.entries[..self.count]
    }

    /// Whether there is nothing to wake.
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0 && self.all == 0
    }
}

/// Takes the queued events and the coarse ones since the last take.
pub(crate) fn take() -> Wakeups {
    let state_changes = STATE_CHANGES.load(Ordering::Relaxed);
    let ticks = TICKS.load(Ordering::Relaxed);
    let mut pending = PENDING.lock();
    let mut all = pending.overflowed;
    if state_changes != pending.state_changes {
        pending.state_changes = state_changes;
        all |= events::STATE;
    }
    if ticks != pending.ticks {
        pending.ticks = ticks;
        all |= events::TICK;
    }
    let wakeups = Wakeups {
        entries: pending.entries,
        count: pending.count,
        all,
    };
    pending.count = 0;
    pending.overflowed = 0;
    wakeups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_narrow_and_widen() {
        let wait = WaitOn::keyed(events::SOCKET, 7).with_key(events::SOCKET, 9);
        assert!(wait.woken_by(events::SOCKET, Some(7)));
        assert!(wait.woken_by(events::SOCKET, Some(9)));
        assert!(!wait.woken_by(events::SOCKET, Some(8)));
        assert!(wait.woken_by(events::SOCKET, None));
        assert!(!wait.woken_by(events::FUTEX, Some(7)));
        let wide = (0..8).fold(WaitOn::NOTHING, |wait, key| {
            wait.with_key(events::SOCKET, key + 1)
        });
        assert!(wide.woken_by(events::SOCKET, Some(100)));
        let mixed = WaitOn::ANYTHING.and(wait);
        assert!(mixed.woken_by(events::TICK, None));
        assert!(!mixed.woken_by(events::SOCKET, Some(8)));
        assert!(WaitOn::keyed(events::SOCKET, 3)
            .with_events(events::SOCKET)
            .woken_by(events::SOCKET, Some(8)));
        assert_eq!(WaitOn::NOTHING.until(5).until(9).deadline(), 5);
    }
}
