//! The start of the trusted core (docs/FRAMEKERNEL.md §4): small safe
//! abstractions whose few `unsafe` blocks carry the invariant they rely on,
//! so the code above them reaches physical memory without `unsafe`.
//!
//! - [`frame`]: a physical frame of RAM, read and written by copying
//!   through the direct map.
//!
//! Each module says who may construct its types; the constructors from a
//! bare physical address are confined to the memory layer by
//! `tools/architecture/check-kernel-unsafe.sh`.

pub(crate) mod frame;
