//! The file cache: per domain, the frames that hold pages of the immutable
//! root filesystem's files, keyed by the file's bytes (`source_base`) and
//! the page's offset, so private read-only mappings of the same page share
//! one frame. Its frames belong to the kernel and are released with the
//! domain (`reset_current`); a mapping never frees one (`contains`).
//!
//! The index is a pair of open-addressed hash tables on the heap: sources
//! to frames, and the set of frames. Copy-on-write faults ask `contains`
//! while their caller may hold any lock a system call takes (a fault during
//! a copy to user memory), so each domain's table sits behind a leaf lock
//! (`LockRank::FILE_CACHE`) that is held only to probe or fill a table
//! that already has room: the heap is never entered with it held. Growing
//! allocates the larger table first, then rehashes into it under the lock;
//! the old table and released frames are freed after the lock is dropped.

#![forbid(unsafe_code)]

use crate::{
    arch::x86_64::cpu,
    control_abi, memory,
    sync::{LockRank, SpinLock},
};
use alloc::vec::Vec;

const INITIAL_CAPACITY: usize = 64;

#[derive(Clone, Copy)]
struct SourceEntry {
    source_base: u64,
    source_offset: u64,
    frame: memory::FrameLease,
}

/// One domain's cache. Both tables have `capacity` slots (a power of two,
/// or zero before the first insert); entries are never removed one by one,
/// only all at once.
struct CacheTable {
    sources: Vec<Option<SourceEntry>>,
    frames: Vec<Option<memory::FrameLease>>,
    entries: usize,
}

impl CacheTable {
    const fn new() -> Self {
        Self {
            sources: Vec::new(),
            frames: Vec::new(),
            entries: 0,
        }
    }

    /// A table with `capacity` empty slots in each half.
    fn with_capacity(capacity: usize) -> Option<Self> {
        let mut sources = Vec::new();
        let mut frames = Vec::new();
        sources.try_reserve_exact(capacity).ok()?;
        frames.try_reserve_exact(capacity).ok()?;
        sources.resize(capacity, None);
        frames.resize(capacity, None);
        Some(Self {
            sources,
            frames,
            entries: 0,
        })
    }

    fn capacity(&self) -> usize {
        self.sources.len()
    }

    /// Whether one more entry fits under the load factor (7/10).
    fn has_room(&self) -> bool {
        self.capacity() != 0
            && self
                .entries
                .checked_add(1)
                .is_some_and(|entries| entries * 10 < self.capacity() * 7)
    }

    fn lookup(&self, source_base: u64, source_offset: u64) -> Option<memory::FrameLease> {
        let capacity = self.capacity();
        if capacity == 0 {
            return None;
        }
        let mut index = source_slot(source_base, source_offset, capacity);
        for _ in 0..capacity {
            let entry = self.sources[index]?;
            if entry.source_base == source_base && entry.source_offset == source_offset {
                return Some(entry.frame);
            }
            index = (index + 1) & (capacity - 1);
        }
        None
    }

    fn contains(&self, frame: memory::FrameLease) -> bool {
        let capacity = self.capacity();
        if capacity == 0 {
            return false;
        }
        let mut index = frame_slot(frame, capacity);
        for _ in 0..capacity {
            match self.frames[index] {
                Some(entry) if same_lease(entry, frame) => return true,
                Some(_) => index = (index + 1) & (capacity - 1),
                None => return false,
            }
        }
        false
    }

    /// Adds an entry in place, never growing the table; false if the source
    /// or the frame is already there or there is no free slot.
    fn insert(&mut self, source_base: u64, source_offset: u64, frame: memory::FrameLease) -> bool {
        let capacity = self.capacity();
        if capacity == 0 {
            return false;
        }
        let mut source_index = source_slot(source_base, source_offset, capacity);
        let mut source_free = None;
        for _ in 0..capacity {
            match self.sources[source_index] {
                None => {
                    source_free = Some(source_index);
                    break;
                }
                Some(entry)
                    if entry.source_base == source_base && entry.source_offset == source_offset =>
                {
                    return false;
                }
                Some(_) => source_index = (source_index + 1) & (capacity - 1),
            }
        }
        let mut frame_index = frame_slot(frame, capacity);
        let mut frame_free = None;
        for _ in 0..capacity {
            match self.frames[frame_index] {
                None => {
                    frame_free = Some(frame_index);
                    break;
                }
                Some(entry) if same_lease(entry, frame) => return false,
                Some(_) => frame_index = (frame_index + 1) & (capacity - 1),
            }
        }
        let (Some(source_index), Some(frame_index)) = (source_free, frame_free) else {
            return false;
        };
        self.sources[source_index] = Some(SourceEntry {
            source_base,
            source_offset,
            frame,
        });
        self.frames[frame_index] = Some(frame);
        self.entries += 1;
        true
    }

    /// Moves every entry of `old` into this (larger, empty) table.
    fn rehash_from(&mut self, old: &Self) -> bool {
        old.sources
            .iter()
            .flatten()
            .all(|entry| self.insert(entry.source_base, entry.source_offset, entry.frame))
    }
}

/// Each domain's cache, by container slot.
static FILE_CACHES: [SpinLock<CacheTable>; control_abi::DOMAIN_LIMIT] =
    [const { SpinLock::new(LockRank::FILE_CACHE, CacheTable::new()) }; control_abi::DOMAIN_LIMIT];

fn current_cache() -> Option<&'static SpinLock<CacheTable>> {
    FILE_CACHES.get(cpu::current_container_slot()?)
}

fn same_lease(first: memory::FrameLease, second: memory::FrameLease) -> bool {
    first.address() == second.address() && first.generation() == second.generation()
}

fn source_slot(source_base: u64, source_offset: u64, capacity: usize) -> usize {
    (source_base ^ source_offset.rotate_left(23)).wrapping_mul(0x9e37_79b9_7f4a_7c15) as usize
        & (capacity - 1)
}

fn frame_slot(frame: memory::FrameLease, capacity: usize) -> usize {
    ((frame.address() >> 12) ^ u64::from(frame.generation()).rotate_left(19))
        .wrapping_mul(0x9e37_79b9_7f4a_7c15) as usize
        & (capacity - 1)
}

/// The cached frame holding page `source_offset` of the file at
/// `source_base` in the current domain.
pub(crate) fn lookup(source_base: u64, source_offset: u64) -> Option<memory::FrameLease> {
    if source_base == 0 {
        return None;
    }
    current_cache()?.lock().lookup(source_base, source_offset)
}

/// Records `frame` as page `source_offset` of the file at `source_base` in
/// the current domain's cache, which then owns it; false if either is
/// already cached or the table cannot grow.
pub(crate) fn insert(source_base: u64, source_offset: u64, frame: memory::FrameLease) -> bool {
    if source_base == 0 {
        return false;
    }
    let Some(cache) = current_cache() else {
        return false;
    };
    loop {
        let wanted = {
            let mut table = cache.lock();
            if table.lookup(source_base, source_offset).is_some() {
                return false;
            }
            if table.has_room() {
                return table.insert(source_base, source_offset, frame);
            }
            match table.capacity() {
                0 => INITIAL_CAPACITY,
                capacity => match capacity.checked_mul(2) {
                    Some(capacity) => capacity,
                    None => return false,
                },
            }
        };
        // Allocate the larger table with the lock released, then move the
        // entries over under it, unless another CPU grew the table first.
        let Some(mut grown) = CacheTable::with_capacity(wanted) else {
            return false;
        };
        let mut table = cache.lock();
        if table.capacity() >= wanted {
            drop(table);
            drop(grown);
            continue;
        }
        if !grown.rehash_from(&table) {
            drop(table);
            drop(grown);
            return false;
        }
        core::mem::swap(&mut *table, &mut grown);
        drop(table);
        // `grown` now holds the old table, freed here with no lock held.
        drop(grown);
    }
}

/// Whether `frame` belongs to the current domain's cache.
pub(crate) fn contains(frame: memory::FrameLease) -> bool {
    current_cache().is_some_and(|cache| cache.lock().contains(frame))
}

/// Empties the current domain's cache and releases its frames.
pub(crate) fn reset_current() -> bool {
    let Some(cache) = current_cache() else {
        return true;
    };
    let current = core::mem::replace(&mut *cache.lock(), CacheTable::new());
    let mut batch = [memory::FrameLease::EMPTY; 64];
    let mut count = 0;
    for entry in current.sources.iter().flatten() {
        let frame = entry.frame;
        // Teardown may already have retired an aliased mapping lease. The
        // cache table is authoritative only for leases that remain live.
        if !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[frame])
            || batch[..count].contains(&frame)
        {
            continue;
        }
        batch[count] = frame;
        count += 1;
        if count == batch.len() {
            if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &batch) {
                return false;
            }
            count = 0;
        }
    }
    count == 0 || memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &batch[..count])
}
