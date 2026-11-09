//! A `static` buffer the kernel rewrites on every use and hands out as a
//! `&'static` view until the next: the generated /proc files whose
//! contents `linux_regular_file` returns as `&'static [u8]` (/proc/uptime,
//! /proc/meminfo, /proc/self/cgroup).
//!
//! This replaces their `static mut`s; it does not make them safe. The view
//! stays valid only until the next rewrite, which the callers rule out by
//! serialization: they run under the kernel-entry lock, and every reader of
//! such a file copies the bytes before it gives the lock up. The way out is
//! a file that owns its bytes (a guard or a buffer per open file, as
//! Linux's seq_file keeps), which needs `linux_regular_file`'s callers
//! (`linux_mmap.rs`, `linux_syscall.rs`) to take one.

use core::cell::UnsafeCell;

pub(crate) struct ScratchBuffer<T>(UnsafeCell<T>);

// SAFETY: the value is reached only through `rewrite`, whose callers
// serialize every use and every view it hands out (its contract), so
// sharing the buffer between CPUs only moves that one access between them,
// which `T: Send` permits.
unsafe impl<T: Send> Sync for ScratchBuffer<T> {}

impl<T> ScratchBuffer<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// The buffer, to rewrite and then hand out until the next call.
    ///
    /// # Safety
    ///
    /// The caller holds the kernel-entry lock, and no reference an earlier
    /// call returned is still in use: everything that read the buffer
    /// copied what it needed before giving the lock up.
    // A `&mut` from `&self` is the point: the caller's serialization makes
    // it unique.
    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn rewrite(&'static self) -> &'static mut T {
        // SAFETY: the caller's contract: no other reference to the value
        // is in use.
        unsafe { &mut *self.0.get() }
    }
}
