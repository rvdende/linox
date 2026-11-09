//! Lifecycle owner for one long-lived kernel object: a set-once slot whose
//! readiness flag cannot be published apart from the value it guards.
//!
//! States: EMPTY (no value), CLAIMED (one [`OwnedStateClaim`] is writing
//! the value) and READY (initialized). Only a
//! claim moves EMPTY to READY, with a release store after the value is
//! written, and [`OwnedState::get`] reads the value only after an acquire
//! load sees READY, so a reader always sees the complete value.
//!
//! After publication the value is only ever shared ([`OwnedState::get`]):
//! a set-once owner never hands out `&mut`, and never drops its value
//! (owners that change their value after publication hold a lock or
//! atomics inside it).

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

const EMPTY: u8 = 0;
const CLAIMED: u8 = 1;
const READY: u8 = 2;

pub(crate) struct OwnedState<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: sharing the owner between CPUs lets any CPU read the published
// value through `get` (needs `T: Sync`), and lets the CPU that claims it
// write the value, which may differ from the CPU that made the owner
// (needs `T: Send`). The state machine in the module comment orders
// initialization before every read, and nothing writes the value after
// publication.
unsafe impl<T: Send + Sync> Sync for OwnedState<T> {}

impl<T> OwnedState<T> {
    pub(crate) const fn empty() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub(crate) fn try_claim(&self) -> Option<OwnedStateClaim<'_, T>> {
        self.state
            .compare_exchange(EMPTY, CLAIMED, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| OwnedStateClaim {
                owner: self,
                published: false,
            })
    }

    pub(crate) fn try_install(&self, value: T) -> Result<(), T> {
        let Some(claim) = self.try_claim() else {
            return Err(value);
        };
        claim.publish(value);
        Ok(())
    }

    pub(crate) fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) != READY {
            return None;
        }
        // SAFETY: READY is stored with release ordering only after the value
        // was completely written (`publish`), and the
        // acquire load above saw it, so the value is initialized and its
        // writes are visible here.
        Some(unsafe { (&*self.value.get()).assume_init_ref() })
    }
}

/// The right to initialize an [`OwnedState`] (it is CLAIMED while this
/// lives); dropping it unpublished returns the owner to EMPTY.
pub(crate) struct OwnedStateClaim<'a, T> {
    owner: &'a OwnedState<T>,
    published: bool,
}

impl<T> OwnedStateClaim<'_, T> {
    fn as_mut_ptr(&self) -> *mut T {
        self.owner.value.get().cast::<T>()
    }

    pub(crate) fn publish(mut self, value: T) {
        // SAFETY: the claim is the only path to the slot while the owner is
        // CLAIMED (`try_claim`'s exchange admitted only this one, and `get`
        // reads nothing before READY), so this write races with nothing;
        // `write` drops nothing, and the slot holds no value to leak (EMPTY
        // means none, and a partial init through `as_mut_ptr` is overwritten).
        unsafe { self.as_mut_ptr().write(value) };
        self.owner.state.store(READY, Ordering::Release);
        self.published = true;
    }
}

impl<T> Drop for OwnedStateClaim<'_, T> {
    fn drop(&mut self) {
        if !self.published {
            self.owner.state.store(EMPTY, Ordering::Release);
        }
    }
}
