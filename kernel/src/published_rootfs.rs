#![forbid(unsafe_code)]

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
pub(crate) use linox_oci::{Entry, EntryKind};
use linox_oci::{Rootfs, RootfsMetadata};

use crate::sync::{LockRank, SpinLock};

// This module is the source-neutral, immutable root-filesystem boundary used
// by Linux VFS and ELF execution. OCI ingestion may publish an artifact here,
// but no registry, manifest, layer, or transport state crosses this boundary.

pub(crate) const ROOT_HANDLE: u16 = 1;
const ENTRY_HANDLE_BASE: usize = 2;
const PATH_CAPACITY: usize = 256;
const ENTRY_CACHE_SLOTS: usize = 64;
const INDEX_EMPTY: u64 = 0;
const INDEX_TOMBSTONE: u64 = u64::MAX;

#[derive(Clone, Copy)]
#[repr(C)]
struct PathIndexEntry {
    hash: u64,
    offset: usize,
    index: usize,
}

pub(crate) struct Child {
    pub(crate) next_cursor: usize,
    pub(crate) handle: u16,
    pub(crate) entry: Entry<'static>,
    pub(crate) name: &'static [u8],
}

pub(crate) struct LaunchArguments<'a> {
    pub(crate) values: [&'a [u8]; 3],
    pub(crate) count: usize,
    pub(crate) execfn: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessPlanFailure<'a> {
    RootfsUnavailable,
    ExecutableNotFound,
    NotRegularFile,
    NotExecutable,
    ScriptInterpreterNotFound(&'a [u8]),
    ScriptInterpreterNotExecutable(&'a [u8]),
    UnsupportedExecutable,
    DynamicLoaderNotFound(&'a [u8]),
    DynamicLoaderNotExecutable(&'a [u8]),
    UnsupportedLoadLayout,
}

/// A domain slot's published root filesystem: the image (published for
/// the kernel's lifetime as far as this module is concerned; see
/// `trusted::image::PublishedImage`) and its path index on the heap.
struct Published {
    bytes: &'static [u8],
    metadata: RootfsMetadata,
    /// The visible paths, open-addressed by hash.
    index: Vec<PathIndexEntry>,
    /// Each entry's offset in the image, by entry index.
    entry_offsets: Vec<usize>,
    /// Each directory's first child (and, at `entry_count`, the root's).
    child_heads: Vec<usize>,
    /// Each entry's next sibling.
    child_next: Vec<usize>,
}

impl Published {
    fn rootfs(&self) -> Option<Rootfs<'static>> {
        Rootfs::from_metadata(self.bytes, self.metadata)
    }
}

struct PublishedRootfsOwner {
    /// Each slot's root filesystem. A leaf held only to clone, take or
    /// put the reference: path walks ask under the mount, overlay and
    /// volume tables, so it ranks above them, and nothing is allocated or
    /// freed while it is held.
    slots: [SpinLock<Option<Arc<Published>>>; crate::control_abi::DOMAIN_LIMIT],
    entry_cache_handles: [[AtomicU16; ENTRY_CACHE_SLOTS]; crate::control_abi::DOMAIN_LIMIT],
    entry_cache_offsets: [[AtomicUsize; ENTRY_CACHE_SLOTS]; crate::control_abi::DOMAIN_LIMIT],
}

static PUBLISHED_ROOTFS: PublishedRootfsOwner = PublishedRootfsOwner {
    slots: [const { SpinLock::new(LockRank::PUBLISHED_ROOTFS, None) };
        crate::control_abi::DOMAIN_LIMIT],
    entry_cache_handles: [const { [const { AtomicU16::new(0) }; ENTRY_CACHE_SLOTS] };
        crate::control_abi::DOMAIN_LIMIT],
    entry_cache_offsets: [const { [const { AtomicUsize::new(0) }; ENTRY_CACHE_SLOTS] };
        crate::control_abi::DOMAIN_LIMIT],
};

/// Slot `slot`'s published root filesystem, if one is installed. The
/// reference keeps its index alive however long the caller uses it.
fn published(slot: usize) -> Option<Arc<Published>> {
    PUBLISHED_ROOTFS.slots.get(slot)?.lock().clone()
}

pub(crate) fn is_installed(slot: usize) -> bool {
    PUBLISHED_ROOTFS
        .slots
        .get(slot)
        .is_some_and(|published| published.lock().is_some())
}

pub(crate) fn install_published_rootfs(slot: usize, bytes: &'static [u8]) -> bool {
    if slot >= crate::control_abi::DOMAIN_LIMIT || is_installed(slot) {
        return false;
    }
    let Some(rootfs) = Rootfs::parse(bytes) else {
        crate::serial_write_bytes(b"linox: published rootfs validation failed\r\n");
        return false;
    };
    let metadata = rootfs.metadata();
    let Some(published) =
        build_path_index(&rootfs).map(|(index, entry_offsets, child_heads, child_next)| {
            Arc::new(Published {
                bytes,
                metadata,
                index,
                entry_offsets,
                child_heads,
                child_next,
            })
        })
    else {
        crate::serial_write_bytes(b"linox: published rootfs pathname index allocation failed\r\n");
        return false;
    };
    let mut installed = PUBLISHED_ROOTFS.slots[slot].lock();
    if installed.is_some() {
        drop(installed);
        drop(published);
        return false;
    }
    clear_entry_cache(slot);
    *installed = Some(published);
    true
}

pub(crate) fn uninstall_published_rootfs(slot: usize) -> bool {
    let Some(installed) = PUBLISHED_ROOTFS.slots.get(slot) else {
        return false;
    };
    // Freed (once no caller still holds it) after the lock is released.
    let removed = installed.lock().take();
    if removed.is_some() {
        clear_entry_cache(slot);
    }
    drop(removed);
    true
}

/// The path index of `rootfs`: the hashed visible paths, the entries'
/// offsets and the directory tree (first children and next siblings).
#[allow(clippy::type_complexity)]
fn build_path_index(
    rootfs: &Rootfs<'_>,
) -> Option<(Vec<PathIndexEntry>, Vec<usize>, Vec<usize>, Vec<usize>)> {
    let capacity = rootfs
        .entry_count()
        .checked_mul(2)
        .and_then(usize::checked_next_power_of_two)?;
    let entry_count = rootfs.entry_count();
    let mut table = Vec::new();
    let mut offsets = Vec::new();
    let mut child_heads = Vec::new();
    let mut child_next = Vec::new();
    table.try_reserve_exact(capacity).ok()?;
    offsets.try_reserve_exact(entry_count).ok()?;
    child_heads
        .try_reserve_exact(entry_count.checked_add(1)?)
        .ok()?;
    child_next.try_reserve_exact(entry_count).ok()?;
    table.resize(
        capacity,
        PathIndexEntry {
            hash: INDEX_EMPTY,
            offset: 0,
            index: 0,
        },
    );
    offsets.resize(entry_count, 0);
    child_heads.resize(entry_count + 1, usize::MAX);
    child_next.resize(entry_count, usize::MAX);
    let mut path = [0_u8; PATH_CAPACITY];
    let mut offset = 0_usize;
    for (index, stored_offset) in offsets.iter_mut().enumerate().take(entry_count) {
        let entry_offset = offset;
        *stored_offset = entry_offset;
        let (entry, next) = rootfs.entry_and_next_at_offset(entry_offset)?;
        offset = next;
        let length = entry.prefix.len() + usize::from(!entry.prefix.is_empty()) + entry.path.len();
        if length > path.len() {
            return None;
        }
        let mut used = 0;
        if !entry.prefix.is_empty() {
            path[..entry.prefix.len()].copy_from_slice(entry.prefix);
            used = entry.prefix.len();
            path[used] = b'/';
            used += 1;
        }
        path[used..length].copy_from_slice(entry.path);
        let visible = &path[..length];
        let name_start = visible
            .iter()
            .rposition(|byte| *byte == b'/')
            .map_or(0, |at| at + 1);
        let name = &visible[name_start..];
        if let Some(removed) = name.strip_prefix(b".wh.") {
            if removed == b".wh..opq" {
                remove_index_children(rootfs, &mut table, &visible[..name_start.saturating_sub(1)]);
            } else {
                if removed.is_empty() {
                    continue;
                }
                let mut target = [0_u8; PATH_CAPACITY];
                let target_length = name_start
                    .checked_add(removed.len())
                    .unwrap_or(PATH_CAPACITY + 1);
                if target_length > PATH_CAPACITY {
                    return None;
                }
                target[..name_start].copy_from_slice(&visible[..name_start]);
                target[name_start..target_length].copy_from_slice(removed);
                let target = &target[..target_length];
                remove_index_path(rootfs, &mut table, target);
                remove_index_children(rootfs, &mut table, target);
            }
            continue;
        }
        if !insert_index_path(rootfs, &mut table, visible, entry_offset, index) {
            return None;
        }
    }
    for index in (0..rootfs.entry_count()).rev() {
        let entry = rootfs.entry_at_offset(offsets[index])?;
        let Some(length) = copy_entry_path(entry, &mut path) else {
            continue;
        };
        let visible = &path[..length];
        if find_indexed_in(rootfs, &table, visible)
            .is_none_or(|(visible_index, _)| visible_index != index)
        {
            continue;
        }
        let parent = if let Some(separator) = visible.iter().rposition(|byte| *byte == b'/') {
            let Some((parent, entry)) = find_indexed_in(rootfs, &table, &visible[..separator])
            else {
                continue;
            };
            if entry.kind != EntryKind::Directory {
                continue;
            }
            parent
        } else {
            rootfs.entry_count()
        };
        child_next[index] = child_heads[parent];
        child_heads[parent] = index;
    }
    Some((table, offsets, child_heads, child_next))
}

fn path_hash(path: &[u8]) -> u64 {
    let hash = path.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3)
    });
    match hash {
        INDEX_EMPTY | INDEX_TOMBSTONE => hash ^ 0x8000_0000_0000_0000,
        _ => hash,
    }
}

fn entry_path_matches(entry: Entry<'_>, path: &[u8]) -> bool {
    if entry.prefix.is_empty() {
        entry.path == path
    } else {
        path.len() == entry.prefix.len() + 1 + entry.path.len()
            && path.starts_with(entry.prefix)
            && path[entry.prefix.len()] == b'/'
            && &path[entry.prefix.len() + 1..] == entry.path
    }
}

fn entry_offset(slot: usize, index: usize) -> Option<usize> {
    published(slot)?.entry_offsets.get(index).copied()
}

fn find_indexed_in<'a>(
    rootfs: &Rootfs<'a>,
    table: &[PathIndexEntry],
    path: &[u8],
) -> Option<(usize, Entry<'a>)> {
    let hash = path_hash(path);
    for probe in 0..table.len() {
        let indexed = table[(hash as usize + probe) & (table.len() - 1)];
        if indexed.hash == INDEX_EMPTY {
            return None;
        }
        if indexed.hash == hash {
            let entry = rootfs.entry_at_offset(indexed.offset)?;
            if entry_path_matches(entry, path) {
                return Some((indexed.index, entry));
            }
        }
    }
    None
}

fn find_visible<'a>(rootfs: &Rootfs<'a>, path: &[u8]) -> Option<(usize, Entry<'a>)> {
    if let Some(published) = crate::arch::x86_64::cpu::current_container_slot().and_then(published)
    {
        if !published.index.is_empty() {
            return find_indexed_in(rootfs, &published.index, path);
        }
    }
    rootfs.find_index(path)
}

fn insert_index_path(
    rootfs: &Rootfs<'_>,
    table: &mut [PathIndexEntry],
    path: &[u8],
    offset: usize,
    index: usize,
) -> bool {
    let hash = path_hash(path);
    let mut available = None;
    for probe in 0..table.len() {
        let slot = (hash as usize + probe) & (table.len() - 1);
        let indexed = table[slot];
        if indexed.hash == INDEX_TOMBSTONE {
            available.get_or_insert(slot);
        } else if indexed.hash == INDEX_EMPTY {
            table[available.unwrap_or(slot)] = PathIndexEntry {
                hash,
                offset,
                index,
            };
            return true;
        } else if indexed.hash == hash
            && rootfs
                .entry_at_offset(indexed.offset)
                .is_some_and(|entry| entry_path_matches(entry, path))
        {
            table[slot] = PathIndexEntry {
                hash,
                offset,
                index,
            };
            return true;
        }
    }
    false
}

fn remove_index_path(rootfs: &Rootfs<'_>, table: &mut [PathIndexEntry], path: &[u8]) {
    let hash = path_hash(path);
    for probe in 0..table.len() {
        let slot = (hash as usize + probe) & (table.len() - 1);
        let indexed = table[slot];
        if indexed.hash == INDEX_EMPTY {
            return;
        }
        if indexed.hash == hash
            && rootfs
                .entry_at_offset(indexed.offset)
                .is_some_and(|entry| entry_path_matches(entry, path))
        {
            table[slot].hash = INDEX_TOMBSTONE;
            return;
        }
    }
}

fn remove_index_children(rootfs: &Rootfs<'_>, table: &mut [PathIndexEntry], parent: &[u8]) {
    for indexed in table {
        if matches!(indexed.hash, INDEX_EMPTY | INDEX_TOMBSTONE) {
            continue;
        }
        let Some(entry) = rootfs.entry_at_offset(indexed.offset) else {
            continue;
        };
        let descendant = if parent.is_empty() {
            true
        } else if entry.prefix.is_empty() {
            entry.path.starts_with(parent) && entry.path.get(parent.len()) == Some(&b'/')
        } else {
            entry.prefix.starts_with(parent)
                && (entry.prefix.len() == parent.len()
                    || entry.prefix.get(parent.len()) == Some(&b'/'))
        };
        if descendant {
            indexed.hash = INDEX_TOMBSTONE;
        }
    }
}

fn rootfs() -> Option<Rootfs<'static>> {
    rootfs_for(crate::arch::x86_64::cpu::current_container_slot()?)
}

fn rootfs_for(slot: usize) -> Option<Rootfs<'static>> {
    published(slot)?.rootfs()
}

pub(crate) fn lookup_at(directory: u16, path: &[u8]) -> Option<(u16, Option<Entry<'static>>)> {
    let rootfs = rootfs()?;
    let (resolved, length) = resolve_at_in(&rootfs, directory, path)?;
    if length == 0 {
        return Some((ROOT_HANDLE, None));
    }
    let (index, entry) = lookup_in(&rootfs, &resolved[..length])?;
    let handle = u16::try_from(index.checked_add(ENTRY_HANDLE_BASE)?).ok()?;
    Some((handle, Some(entry)))
}

/// The image's entry at exactly the canonical `path`, links not followed:
/// what the path walk meets at each step.
pub(crate) fn exact_entry(path: &[u8]) -> Option<Entry<'static>> {
    let path = path.strip_prefix(b"/").unwrap_or(path);
    if path.is_empty() {
        return None;
    }
    let rootfs = rootfs()?;
    find_visible(&rootfs, path).map(|(_, entry)| entry)
}

pub(crate) fn lookup_metadata_at(
    directory: u16,
    path: &[u8],
) -> Option<(u16, Option<Entry<'static>>)> {
    let rootfs = rootfs()?;
    let (resolved, length) = resolve_at_in(&rootfs, directory, path)?;
    if length == 0 {
        return Some((ROOT_HANDLE, None));
    }
    let (index, entry) = lookup_metadata_in(&rootfs, &resolved[..length])?;
    if entry.kind == EntryKind::Hardlink {
        let target = entry.link.strip_prefix(b"/").unwrap_or(entry.link);
        let (index, entry) = lookup_in(&rootfs, target)?;
        let handle = u16::try_from(index.checked_add(ENTRY_HANDLE_BASE)?).ok()?;
        return Some((handle, Some(entry)));
    }
    let handle = u16::try_from(index.checked_add(ENTRY_HANDLE_BASE)?).ok()?;
    Some((handle, Some(entry)))
}

fn lookup_metadata_in<'a>(rootfs: &Rootfs<'a>, path: &[u8]) -> Option<(usize, Entry<'a>)> {
    let path = path.strip_prefix(b"/").unwrap_or(path);
    let path = path.strip_suffix(b"/").unwrap_or(path);
    if path.is_empty() {
        return None;
    }
    let mut current = [0_u8; PATH_CAPACITY];
    current.get_mut(..path.len())?.copy_from_slice(path);
    let mut length = path.len();
    for _ in 0..16 {
        if let Some(entry) = find_visible(rootfs, &current[..length]) {
            return Some(entry);
        }
        let mut source = [0_u8; PATH_CAPACITY];
        source[..length].copy_from_slice(&current[..length]);
        let mut replaced = false;
        for prefix_end in source[..length]
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| (*byte == b'/').then_some(index))
        {
            let Some((_, entry)) = find_visible(rootfs, &source[..prefix_end]) else {
                continue;
            };
            if !matches!(entry.kind, EntryKind::Symlink | EntryKind::Hardlink) {
                continue;
            }
            length = replace_link_path(
                &source[..prefix_end],
                entry.kind,
                entry.link,
                &source[prefix_end + 1..length],
                &mut current,
            )?;
            replaced = true;
            break;
        }
        if !replaced {
            return None;
        }
    }
    None
}

fn resolve_at_in(
    rootfs: &Rootfs<'_>,
    directory: u16,
    path: &[u8],
) -> Option<([u8; PATH_CAPACITY], usize)> {
    let absolute = path.starts_with(b"/");
    let mut resolved = [0_u8; PATH_CAPACITY];
    let mut length = if absolute || directory == ROOT_HANDLE {
        0
    } else {
        let index = usize::from(directory).checked_sub(ENTRY_HANDLE_BASE)?;
        let slot = crate::arch::x86_64::cpu::current_container_slot()?;
        let entry = rootfs.entry_at_offset(entry_offset(slot, index)?)?;
        if entry.kind != EntryKind::Directory {
            return None;
        }
        copy_entry_path(entry, &mut resolved)?
    };
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            length = resolved[..length]
                .iter()
                .rposition(|byte| *byte == b'/')
                .unwrap_or(0);
            continue;
        }
        if length != 0 {
            *resolved.get_mut(length)? = b'/';
            length += 1;
        }
        resolved
            .get_mut(length..length.checked_add(component.len())?)?
            .copy_from_slice(component);
        length += component.len();
    }
    Some((resolved, length))
}

pub(crate) fn copy_path(handle: u16, output: &mut [u8]) -> Option<usize> {
    if handle == ROOT_HANDLE {
        return Some(0);
    }
    let index = usize::from(handle).checked_sub(ENTRY_HANDLE_BASE)?;
    let slot = crate::arch::x86_64::cpu::current_container_slot()?;
    let entry = rootfs_for(slot)?.entry_at_offset(entry_offset(slot, index)?)?;
    copy_entry_path(entry, output)
}

fn lookup_in<'a>(rootfs: &Rootfs<'a>, path: &[u8]) -> Option<(usize, Entry<'a>)> {
    let path = path.strip_prefix(b"/").unwrap_or(path);
    let path = path.strip_suffix(b"/").unwrap_or(path);
    if path.is_empty() {
        return None;
    }
    let mut current = [0_u8; PATH_CAPACITY];
    current.get_mut(..path.len())?.copy_from_slice(path);
    let mut length = path.len();
    for _ in 0..16 {
        if let Some((index, entry)) = find_visible(rootfs, &current[..length]) {
            match entry.kind {
                EntryKind::Symlink | EntryKind::Hardlink => {
                    let mut source = [0_u8; PATH_CAPACITY];
                    source[..length].copy_from_slice(&current[..length]);
                    length = replace_link_path(
                        &source[..length],
                        entry.kind,
                        entry.link,
                        b"",
                        &mut current,
                    )?;
                }
                _ => return Some((index, entry)),
            }
            continue;
        }
        let mut source = [0_u8; PATH_CAPACITY];
        source[..length].copy_from_slice(&current[..length]);
        let mut replaced = false;
        for prefix_end in source[..length]
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| (*byte == b'/').then_some(index))
        {
            let Some((_, entry)) = find_visible(rootfs, &source[..prefix_end]) else {
                continue;
            };
            if !matches!(entry.kind, EntryKind::Symlink | EntryKind::Hardlink) {
                continue;
            }
            length = replace_link_path(
                &source[..prefix_end],
                entry.kind,
                entry.link,
                &source[prefix_end + 1..length],
                &mut current,
            )?;
            replaced = true;
            break;
        }
        if !replaced {
            return None;
        }
    }
    None
}

fn replace_link_path(
    source: &[u8],
    kind: EntryKind,
    link: &[u8],
    remainder: &[u8],
    output: &mut [u8; PATH_CAPACITY],
) -> Option<usize> {
    let mut length = if kind == EntryKind::Hardlink {
        let target = link.strip_prefix(b"/").unwrap_or(link);
        output.get_mut(..target.len())?.copy_from_slice(target);
        target.len()
    } else {
        resolve_link(source, link, output)?
    };
    if !remainder.is_empty() {
        *output.get_mut(length)? = b'/';
        length += 1;
        output
            .get_mut(length..length.checked_add(remainder.len())?)?
            .copy_from_slice(remainder);
        length += remainder.len();
    }
    Some(length)
}

pub(crate) fn entry(handle: u16) -> Option<Entry<'static>> {
    let index = usize::from(handle).checked_sub(ENTRY_HANDLE_BASE)?;
    let slot = crate::arch::x86_64::cpu::current_container_slot()?;
    let cache = usize::from(handle) % ENTRY_CACHE_SLOTS;
    let rootfs = rootfs_for(slot)?;
    if PUBLISHED_ROOTFS.entry_cache_handles[slot][cache].load(Ordering::Acquire) == handle {
        let offset = PUBLISHED_ROOTFS.entry_cache_offsets[slot][cache].load(Ordering::Relaxed);
        return rootfs.entry_at_offset(offset);
    }
    let offset = entry_offset(slot, index)?;
    let entry = rootfs.entry_at_offset(offset)?;
    PUBLISHED_ROOTFS.entry_cache_offsets[slot][cache].store(offset, Ordering::Relaxed);
    PUBLISHED_ROOTFS.entry_cache_handles[slot][cache].store(handle, Ordering::Release);
    Some(entry)
}

fn clear_entry_cache(slot: usize) {
    for handle in &PUBLISHED_ROOTFS.entry_cache_handles[slot] {
        handle.store(0, Ordering::Release);
    }
}

pub(crate) fn next_child(directory: u16, cursor: usize) -> Option<Option<Child>> {
    let slot = crate::arch::x86_64::cpu::current_container_slot()?;
    let rootfs = rootfs()?;
    let parent_index = if directory == ROOT_HANDLE {
        rootfs.entry_count()
    } else {
        let index = usize::from(directory).checked_sub(ENTRY_HANDLE_BASE)?;
        let entry = rootfs.entry_at_offset(entry_offset(slot, index)?)?;
        if entry.kind != EntryKind::Directory {
            return None;
        }
        index
    };
    let published = published(slot)?;
    let offsets = &published.entry_offsets;
    let (heads, next) = (&published.child_heads, &published.child_next);
    let end_cursor = offsets.len().checked_add(1)?;
    if cursor == end_cursor {
        return Some(None);
    }
    let index = if cursor == 0 {
        *heads.get(parent_index)?
    } else {
        cursor.checked_sub(1)?
    };
    if index == usize::MAX {
        return Some(None);
    }
    let entry = rootfs.entry_at_offset(*offsets.get(index)?)?;
    let handle = u16::try_from(index.checked_add(ENTRY_HANDLE_BASE)?).ok()?;
    let name = entry.path.rsplit(|byte| *byte == b'/').next()?;
    Some(Some(Child {
        next_cursor: next.get(index)?.checked_add(1).unwrap_or(end_cursor),
        handle,
        entry,
        name,
    }))
}

fn copy_entry_path(entry: Entry<'_>, output: &mut [u8]) -> Option<usize> {
    let length = entry.prefix.len() + usize::from(!entry.prefix.is_empty()) + entry.path.len();
    if length > output.len() {
        return None;
    }
    let mut used = 0;
    if !entry.prefix.is_empty() {
        output[..entry.prefix.len()].copy_from_slice(entry.prefix);
        used = entry.prefix.len();
        output[used] = b'/';
        used += 1;
    }
    output[used..length].copy_from_slice(entry.path);
    Some(length)
}

fn resolve_link(path: &[u8], link: &[u8], output: &mut [u8]) -> Option<usize> {
    let mut length = if link.starts_with(b"/") {
        0
    } else {
        path.iter().rposition(|byte| *byte == b'/').unwrap_or(0)
    };
    if length != 0 {
        output.get_mut(..length)?.copy_from_slice(&path[..length]);
    }
    for component in link.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            length = output[..length]
                .iter()
                .rposition(|byte| *byte == b'/')
                .unwrap_or(0);
            continue;
        }
        if length != 0 {
            *output.get_mut(length)? = b'/';
            length += 1;
        }
        output
            .get_mut(length..length.checked_add(component.len())?)?
            .copy_from_slice(component);
        length += component.len();
    }
    (length != 0).then_some(length)
}

/// The load address of a position-independent main executable, unless a
/// caller asks for another.
pub(crate) const LOW_LOAD_BASE: u64 = 0x40_0000;

pub(crate) fn process_plan(
    init: &[u8],
) -> Option<crate::linux_elf::RelocatableExecutablePlan<'static, 'static>> {
    process_plan_at(init, LOW_LOAD_BASE)
}

/// Plans `init` with a position-independent main executable loaded at
/// `main_base`; a fixed-address executable keeps its own addresses.
pub(crate) fn process_plan_at(
    init: &[u8],
    main_base: u64,
) -> Option<crate::linux_elf::RelocatableExecutablePlan<'static, 'static>> {
    process_plan_in(&rootfs()?, init, main_base)
}

pub(crate) fn process_plan_failure(init: &[u8]) -> ProcessPlanFailure<'static> {
    let Some(rootfs) = rootfs() else {
        return ProcessPlanFailure::RootfsUnavailable;
    };
    let Some((_, mut executable)) = lookup_in(&rootfs, init) else {
        return ProcessPlanFailure::ExecutableNotFound;
    };
    if executable.kind != EntryKind::File {
        return ProcessPlanFailure::NotRegularFile;
    }
    if executable.mode & 0o111 == 0 {
        return ProcessPlanFailure::NotExecutable;
    }
    if let Some((interpreter, _)) = shebang_command(executable.data) {
        let Some((_, script_interpreter)) = lookup_in(&rootfs, interpreter) else {
            return ProcessPlanFailure::ScriptInterpreterNotFound(interpreter);
        };
        if script_interpreter.kind != EntryKind::File || script_interpreter.mode & 0o111 == 0 {
            return ProcessPlanFailure::ScriptInterpreterNotExecutable(interpreter);
        }
        executable = script_interpreter;
    }
    let Some(interpreter_path) = crate::linux_elf::relocatable_interpreter(executable.data) else {
        return ProcessPlanFailure::UnsupportedExecutable;
    };
    let Some((_, interpreter)) = lookup_in(&rootfs, interpreter_path) else {
        return ProcessPlanFailure::DynamicLoaderNotFound(interpreter_path);
    };
    if interpreter.kind != EntryKind::File || interpreter.mode & 0o111 == 0 {
        return ProcessPlanFailure::DynamicLoaderNotExecutable(interpreter_path);
    }
    ProcessPlanFailure::UnsupportedLoadLayout
}

pub(crate) fn executable_diagnostic(init: &[u8]) -> Option<(usize, u64, u16, u16)> {
    let rootfs = rootfs()?;
    let (_, executable) = lookup_in(&rootfs, init)?;
    let head = u64::from_le_bytes(executable.data.get(..8)?.try_into().ok()?);
    let kind = u16::from_le_bytes(executable.data.get(16..18)?.try_into().ok()?);
    let headers = u16::from_le_bytes(executable.data.get(56..58)?.try_into().ok()?);
    Some((executable.data.len(), head, kind, headers))
}

pub(crate) fn executable_program_headers(init: &[u8]) -> Option<([u64; 16], usize)> {
    let rootfs = rootfs()?;
    let (_, executable) = lookup_in(&rootfs, init)?;
    let count = usize::from(u16::from_le_bytes(
        executable.data.get(56..58)?.try_into().ok()?,
    ));
    if count > 16 {
        return None;
    }
    let mut headers = [0_u64; 16];
    for (index, output) in headers[..count].iter_mut().enumerate() {
        let offset = 64 + index * 56;
        let kind = u32::from_le_bytes(executable.data.get(offset..offset + 4)?.try_into().ok()?);
        let flags = u32::from_le_bytes(
            executable
                .data
                .get(offset + 4..offset + 8)?
                .try_into()
                .ok()?,
        );
        *output = u64::from(kind) | (u64::from(flags) << 32);
    }
    Some((headers, count))
}

pub(crate) fn launch_arguments<'a>(init: &'a [u8]) -> Option<LaunchArguments<'a>> {
    let rootfs = rootfs()?;
    let (_, executable) = lookup_in(&rootfs, init)?;
    Some(launch_arguments_for_image(init, executable.data))
}

/// Returns the leading arguments for executing `image` as `init`, which
/// name the interpreter first when `image` is a script.
pub(crate) fn launch_arguments_for_image<'a>(
    init: &'a [u8],
    image: &'a [u8],
) -> LaunchArguments<'a> {
    if let Some((interpreter, argument)) = shebang_command(image) {
        let mut values = [b"" as &[u8]; 3];
        values[0] = interpreter;
        let count = if let Some(argument) = argument {
            values[1] = argument;
            values[2] = init;
            3
        } else {
            values[1] = init;
            2
        };
        LaunchArguments {
            values,
            count,
            execfn: count - 1,
        }
    } else {
        LaunchArguments {
            values: [init, b"", b""],
            count: 1,
            execfn: 0,
        }
    }
}

/// Plans a process for an executable that lives outside the published root,
/// such as a file written at runtime. Script and dynamic-loader interpreters
/// still come from the published root.
pub(crate) fn process_plan_for_image(
    image: &[u8],
    main_base: u64,
) -> Option<crate::linux_elf::RelocatableExecutablePlan<'_, '_>> {
    let rootfs = rootfs()?;
    let executable = if let Some((interpreter, _)) = shebang_command(image) {
        let (_, script_interpreter) = lookup_in(&rootfs, interpreter)?;
        if script_interpreter.kind != EntryKind::File || script_interpreter.mode & 0o111 == 0 {
            return None;
        }
        script_interpreter.data
    } else {
        image
    };
    plan_executable_in(&rootfs, executable, main_base)
}

fn process_plan_in<'a>(
    rootfs: &Rootfs<'a>,
    init: &[u8],
    main_base: u64,
) -> Option<crate::linux_elf::RelocatableExecutablePlan<'a, 'a>> {
    let (_, mut executable) = lookup_in(rootfs, init)?;
    if executable.kind != EntryKind::File || executable.mode & 0o111 == 0 {
        return None;
    }
    if let Some((interpreter, _)) = shebang_command(executable.data) {
        let (_, script_interpreter) = lookup_in(rootfs, interpreter)?;
        if script_interpreter.kind != EntryKind::File || script_interpreter.mode & 0o111 == 0 {
            return None;
        }
        executable = script_interpreter;
    }
    plan_executable_in(rootfs, executable.data, main_base)
}

fn plan_executable_in<'a>(
    rootfs: &Rootfs<'a>,
    executable: &'a [u8],
    main_base: u64,
) -> Option<crate::linux_elf::RelocatableExecutablePlan<'a, 'a>> {
    let Some(interpreter_path) = crate::linux_elf::relocatable_interpreter(executable) else {
        return crate::linux_elf::plan_relocatable_static(executable, main_base)
            .map(crate::linux_elf::RelocatableExecutablePlan::Static)
            .or_else(|| {
                crate::linux_elf::plan_static_exec(executable)
                    .map(crate::linux_elf::RelocatableExecutablePlan::Fixed)
            });
    };
    let (_, interpreter) = lookup_in(rootfs, interpreter_path)?;
    if interpreter.kind != EntryKind::File || interpreter.mode & 0o111 == 0 {
        return None;
    }
    crate::linux_elf::plan_relocatable_process_auto(
        executable,
        main_base,
        interpreter_path,
        interpreter.data,
    )
    .map(crate::linux_elf::RelocatableExecutablePlan::Interpreted)
}

fn shebang_command(bytes: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    let line = bytes.strip_prefix(b"#!")?;
    let end = line.iter().position(|byte| *byte == b'\n')?;
    let line = &line[..end];
    let start = line.iter().position(|byte| !byte.is_ascii_whitespace())?;
    let path = &line[start..];
    let end = path
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(path.len());
    let interpreter = &path[..end];
    if interpreter.is_empty() || !interpreter.starts_with(b"/") {
        return None;
    }
    let argument = path[end..]
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map(|start| &path[end + start..])
        .filter(|argument| !argument.is_empty());
    Some((interpreter, argument))
}
