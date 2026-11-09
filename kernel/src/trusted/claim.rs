//! A value one context at a time may claim, and that a busy claim makes
//! the others skip rather than wait for.
//!
//! [`ClaimCell`] is for state that code reaches from contexts which must
//! never spin on each other: the framebuffer console, written from any
//! context (an exception report included), drops output while it is busy;
//! the virtio-gpu scanout, flushed from the timer tick, skips a tick. It
//! is a try-lock without a lock rank, since such code is entered under
//! whatever locks the interrupted code holds.
//!
//! The invariant the `unsafe` blocks rely on: a [`Claim`] exists only
//! while `held` is set by the `try_claim` that made it, so it is the only
//! path to the value.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) struct ClaimCell<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: `held` admits one Claim at a time on any CPU (acquire on taking
// it, release on dropping it), and a Claim is the only access to `value`.
unsafe impl<T: Send> Sync for ClaimCell<T> {}

impl<T> ClaimCell<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// The value, unless another context holds it.
    pub(crate) fn try_claim(&self) -> Option<Claim<'_, T>> {
        if self.held.swap(true, Ordering::Acquire) {
            return None;
        }
        Some(Claim {
            cell: self,
            _not_send: PhantomData,
        })
    }

    /// Releases a claim whose holder was interrupted by a fatal error, so
    /// the error's report can still use the value (which may be
    /// mid-update).
    ///
    /// # Safety
    ///
    /// No claim on this cell that exists now may be used again: its holder
    /// never resumes (the caller reports a fatal error and halts, on the
    /// only CPU running), and the caller holds none itself.
    pub(crate) unsafe fn release_abandoned(&self) {
        self.held.store(false, Ordering::Release);
    }
}

/// Exclusive access to a [`ClaimCell`]'s value until it drops.
pub(crate) struct Claim<'a, T> {
    cell: &'a ClaimCell<T>,
    _not_send: PhantomData<*mut ()>,
}

impl<T> Deref for Claim<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the module invariant: this claim holds the cell.
        unsafe { &*self.cell.value.get() }
    }
}

impl<T> DerefMut for Claim<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as for deref; `&mut self` keeps the borrow unique.
        unsafe { &mut *self.cell.value.get() }
    }
}

impl<T> Drop for Claim<'_, T> {
    fn drop(&mut self) {
        self.cell.held.store(false, Ordering::Release);
    }
}
