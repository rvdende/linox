//! Set-once lifecycle owners for long-lived kernel objects; the type and its
//! `unsafe` live in the trusted core (`trusted::owned_state`).
#![forbid(unsafe_code)]

pub(crate) use crate::trusted::owned_state::OwnedState;
