//! Lifecycle owner for one long-lived kernel object: a set-once slot whose
//! readiness flag cannot be published apart from the value it guards.
//!
//! States: EMPTY (no value), CLAIMED (one [`OwnedStateClaim`] is writing
//! the value, or `reset` is dropping it) and READY (initialized). Only a
//! claim moves EMPTY to READY, with a release store after the value is
//! written, and [`OwnedState::get`] reads the value only after an acquire
//! load sees READY, so a reader always sees the complete value.
//!
//! What this type does not do is lock. After publication:
//! - [`OwnedState::get`] hands out shared references;
//! - [`OwnedState::get_mut_ptr`] hands out the raw pointer to the value;
//!   writing through it is `unsafe` at the caller (`domain.rs`,
//!   `scheduler.rs`, `ipc.rs`), whose SAFETY comments name the
//!   serialization rule they rely on (the kernel-entry lock and the
//!   bootstrap CPU); docs/FRAMEKERNEL.md §4.3 A replaces those callers with
//!   locks.
//!
//! Known gaps, kept for the callers above (outside this module's owner's
//! files; each closes when its caller moves to a lock):
//! - [`OwnedState::reset`] drops the value while a reference from an
//!   earlier `get` could still be live. Its one caller (the scheduler's
//!   per-process workspace) never holds `get` references, only
//!   `get_mut_ptr` ones scoped to a call.

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
// write the value and the one that resets it drop it, either of which may
// differ from the CPU that made it (needs `T: Send`). The state machine in
// the module comment orders initialization before every read; mutation
// after publication is the `unsafe` callers' of `get_mut_ptr` to
// serialize.
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

    pub(crate) fn get_mut_ptr(&self) -> Option<*mut T> {
        if self.state.load(Ordering::Acquire) != READY {
            return None;
        }
        Some(self.value.get().cast::<T>())
    }

    pub(crate) fn reset(&self) -> bool {
        if self
            .state
            .compare_exchange(READY, CLAIMED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        // SAFETY: the READY -> CLAIMED exchange succeeded on this call alone,
        // so the value is initialized, no claim writes it, and new `get` and
        // `get_mut_ptr` calls see no value until EMPTY is stored below; for
        // references taken before, see the module comment's known gaps.
        unsafe { (&mut *self.value.get()).assume_init_drop() };
        self.state.store(EMPTY, Ordering::Release);
        true
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
