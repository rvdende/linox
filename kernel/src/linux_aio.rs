//! Linux AIO contexts (io_setup, io_submit, io_getevents): each domain's
//! and IPC namespace's contexts with the completion events queued on
//! them, kept on the kernel heap under one lock per instance.
#![forbid(unsafe_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::sync::{LockRank, SpinLock, SpinLockGuard};
use crate::{control_abi, linux_process};

const INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;

/// Each instance's contexts, newest last.
static AIO_RUNTIME: [SpinLock<Vec<Context>>; INSTANCE_LIMIT] =
    [const { SpinLock::new(LockRank::AIO_CONTEXTS, Vec::new()) }; INSTANCE_LIMIT];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Invalid,
    NoMemory,
    Full,
}

#[derive(Clone, Copy)]
pub(crate) struct Event {
    pub(crate) data: u64,
    pub(crate) object: u64,
    pub(crate) result: i64,
    pub(crate) result2: i64,
}

struct Context {
    /// The process whose io_setup made it: contexts are a process's (its
    /// ring is in that process's memory), so another process with a ring
    /// at the same address has a context of its own.
    owner: u32,
    id: u64,
    maximum: u64,
    ring_pages: u64,
    events: VecDeque<Event>,
}

impl Context {
    fn pending(&self) -> u64 {
        self.events.len() as u64
    }
}

/// The calling process's instance's contexts, locked.
fn contexts() -> Option<SpinLockGuard<'static, Vec<Context>>> {
    AIO_RUNTIME
        .get(linux_process::current_ipc_instance())
        .map(SpinLock::lock)
}

fn find(contexts: &[Context], owner: u32, id: u64) -> Option<usize> {
    contexts
        .iter()
        .position(|item| item.owner == owner && item.id == id)
}

fn find_mut(contexts: &mut [Context], owner: u32, id: u64) -> Result<&mut Context, Error> {
    let index = find(contexts, owner, id).ok_or(Error::Invalid)?;
    Ok(&mut contexts[index])
}

pub(crate) fn create(owner: u32, id: u64, maximum: u64, ring_pages: u64) -> Result<(), Error> {
    if id == 0 || maximum == 0 || ring_pages == 0 {
        return Err(Error::Invalid);
    }
    let mut contexts = contexts().ok_or(Error::Invalid)?;
    // The contexts of processes gone (their memory with them) go now.
    contexts.retain(|item| linux_process::live_process_status(item.owner).is_some());
    if find(&contexts, owner, id).is_some() {
        return Err(Error::Invalid);
    }
    contexts.try_reserve(1).map_err(|_| Error::NoMemory)?;
    contexts.push(Context {
        owner,
        id,
        // Linux sizes a context for at least four requests per CPU, doubled.
        maximum: maximum.max(16) * 2,
        ring_pages,
        events: VecDeque::new(),
    });
    Ok(())
}

pub(crate) fn push(owner: u32, id: u64, value: Event) -> Result<(), Error> {
    let mut contexts = contexts().ok_or(Error::Invalid)?;
    let item = find_mut(&mut contexts, owner, id)?;
    if item.pending() >= item.maximum {
        return Err(Error::Full);
    }
    item.events.try_reserve(1).map_err(|_| Error::NoMemory)?;
    item.events.push_back(value);
    Ok(())
}

pub(crate) fn pop(owner: u32, id: u64) -> Result<Option<Event>, Error> {
    let mut contexts = contexts().ok_or(Error::Invalid)?;
    Ok(find_mut(&mut contexts, owner, id)?.events.pop_front())
}

pub(crate) fn info(owner: u32, id: u64) -> Result<(u64, u64), Error> {
    let mut contexts = contexts().ok_or(Error::Invalid)?;
    let item = find_mut(&mut contexts, owner, id)?;
    Ok((item.pending(), item.ring_pages))
}

pub(crate) fn can_submit(owner: u32, id: u64) -> Result<bool, Error> {
    let mut contexts = contexts().ok_or(Error::Invalid)?;
    let item = find_mut(&mut contexts, owner, id)?;
    Ok(item.pending() < item.maximum)
}

/// Frees a context and its queued events; its ring's page count, for the
/// caller to unmap.
pub(crate) fn destroy(owner: u32, id: u64) -> Result<u64, Error> {
    let mut contexts = contexts().ok_or(Error::Invalid)?;
    let index = find(&contexts, owner, id).ok_or(Error::Invalid)?;
    Ok(contexts.swap_remove(index).ring_pages)
}

/// Frees the instance's contexts when its runtime ends.
pub(crate) fn teardown() -> bool {
    let Some(mut contexts) = contexts() else {
        return false;
    };
    *contexts = Vec::new();
    true
}
