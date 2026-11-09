//! A `static` value handed out as `&'static mut` exactly once, for a large
//! buffer the kernel keeps off its stack and gives to one owner for good.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) struct TakeOnce<T> {
    taken: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the value is reached only through `take`, which hands out one
// `&'static mut` in the program's lifetime (the swap below admits one
// caller), so sharing the `TakeOnce` between CPUs only moves that exclusive
// access to whichever CPU takes it, which `T: Send` permits.
unsafe impl<T: Send> Sync for TakeOnce<T> {}

impl<T> TakeOnce<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            taken: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// The value, the first time this is called; `None` after.
    // A `&mut` from `&self` is the point: the flag makes it unique.
    #[allow(clippy::mut_from_ref)]
    pub(crate) fn take(&'static self) -> Option<&'static mut T> {
        if self.taken.swap(true, Ordering::AcqRel) {
            return None;
        }
        // SAFETY: only the first `take` gets here (the swap above), so this
        // is the one reference to the value there will ever be, and the
        // value lives in a `static`.
        Some(unsafe { &mut *self.value.get() })
    }
}
