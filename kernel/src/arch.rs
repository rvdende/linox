//! The architecture layer. Safe Rust throughout: what it needs of the
//! hardware it reaches through the trusted core (`crate::trusted`).
#![forbid(unsafe_code)]

#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;
