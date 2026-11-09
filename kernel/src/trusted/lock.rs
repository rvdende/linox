//! The kernel's spin locks: a ticket lock that hands out the protected
//! value through a guard, and the same lock taken with interrupts off.
//!
//! `crate::sync` re-exports these types and keeps what is not unsafe about
//! them: the lock ranks (each acquire checks this CPU holds no lock ranked at
//! or above the new one, and fails closed on an order violation), the
//! kernel-entry lock and the verification at boot.
//!
//! The invariant the `unsafe` code relies on: a [`SpinLockGuard`] exists for
//! a lock only while its holder owns the lock's current ticket. `lock` waits
//! for its ticket and `try_lock` takes the next ticket only when it is the
//! one being served, and the guard hands the ticket on when it drops, so at
//! most one guard per lock is alive at a time. The guard is the only path to
//! the value, and a `&mut` from it lives no longer than the guard. Taking a
//! lock again on the CPU that holds it does not alias the value: `lock`'s
//! rank check refuses it (`kernel_fail`) before a ticket is drawn, and
//! `try_lock` finds the lock taken.

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

use super::interrupts::{self, InterruptState};
use crate::sync::{enter_rank, leave_rank, LockRank};

/// A ranked ticket spin lock around a `T`.
pub(crate) struct SpinLock<T> {
    next: AtomicU32,
    owner: AtomicU32,
    rank: LockRank,
    value: UnsafeCell<T>,
}

// SAFETY: the lock hands the value to one guard at a time (the module
// invariant), so sharing the lock between CPUs only ever moves exclusive
// access to the `T` from one CPU to another, which `T: Send` permits; a
// `&T` handed out by a guard is exclusive too, so `T` need not be `Sync`.
// This is the bound `std::sync::Mutex` has.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub(crate) const fn new(rank: LockRank, value: T) -> Self {
        Self {
            next: AtomicU32::new(0),
            owner: AtomicU32::new(0),
            rank,
            value: UnsafeCell::new(value),
        }
    }

    pub(crate) fn lock(&self) -> SpinLockGuard<'_, T> {
        let previous_rank = enter_rank(self.rank);
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        while self.owner.load(Ordering::Acquire) != ticket {
            spin_loop();
        }
        SpinLockGuard {
            lock: self,
            previous_rank,
            _not_send: PhantomData,
        }
    }

    pub(crate) fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let owner = self.owner.load(Ordering::Acquire);
        if self
            .next
            .compare_exchange(
                owner,
                owner.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        let previous_rank = enter_rank(self.rank);
        Some(SpinLockGuard {
            lock: self,
            previous_rank,
            _not_send: PhantomData,
        })
    }
}

/// Exclusive access to a [`SpinLock`]'s value. Not `Send`: the rank it
/// entered belongs to the CPU that took the lock.
pub(crate) struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    previous_rank: u16,
    _not_send: PhantomData<*mut ()>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: this guard owns the lock's current ticket (the module
        // invariant), so no other reference to the value exists, and the
        // borrow ends before the guard drops and hands the ticket on.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as for `deref`; `&mut self` makes this the only borrow
        // through the guard.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        leave_rank(self.lock.rank, self.previous_rank);
        self.lock.owner.fetch_add(1, Ordering::Release);
    }
}

/// A [`SpinLock`] held with this CPU's interrupts off, for data interrupt
/// handlers also take.
pub(crate) struct IrqSpinLock<T>(SpinLock<T>);

impl<T> IrqSpinLock<T> {
    pub(crate) const fn new(rank: LockRank, value: T) -> Self {
        Self(SpinLock::new(rank, value))
    }

    pub(crate) fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let interrupts = InterruptsOff(interrupts::save_and_disable());
        let guard = self.0.lock();
        IrqSpinLockGuard {
            guard,
            _interrupts: interrupts,
        }
    }

    pub(crate) fn try_lock(&self) -> Option<IrqSpinLockGuard<'_, T>> {
        // Dropped on failure, which restores the interrupts.
        let interrupts = InterruptsOff(interrupts::save_and_disable());
        let guard = self.0.try_lock()?;
        Some(IrqSpinLockGuard {
            guard,
            _interrupts: interrupts,
        })
    }
}

/// Puts this CPU's interrupt flag back as it was when it drops.
struct InterruptsOff(InterruptState);

impl Drop for InterruptsOff {
    fn drop(&mut self) {
        interrupts::restore(self.0);
    }
}

/// Exclusive access to an [`IrqSpinLock`]'s value, with interrupts off.
pub(crate) struct IrqSpinLockGuard<'a, T> {
    // Fields drop in declaration order: the lock is released before the
    // interrupt flag is restored.
    guard: SpinLockGuard<'a, T>,
    _interrupts: InterruptsOff,
}

impl<T> Deref for IrqSpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for IrqSpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}
