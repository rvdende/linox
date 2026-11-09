//! Each domain's in-memory files: what it created over its root
//! filesystem's image (and whiteouts hiding the image's files), its tmpfs
//! and ramfs files, memfds, anonymous shared memory and the page caches of
//! its volumes' files.
//!
//! # Locking
//!
//! Each instance's overlay is behind a spin lock of its own,
//! `LockRank::OVERLAY_NODES` (191): a leaf above the kernel heap. The
//! overlay is called under the volumes (a loop device's backing file, a
//! volume's page cache), the overlay mounts (overlayfs copy-up), the
//! pseudo-terminals, the loop devices, the swap areas and the unlinked-file
//! list, and an operation's work reaches the volumes, the socket table, the
//! tmpfs limits, the unlinked-file list, the swap areas, the heap and the
//! frame allocator; so the lock is held only to read and write node fields,
//! the hint tables and file data (through `Frame` copies), and never across
//! any of those calls.
//!
//! An operation that needs something from outside (heap memory: a chunk of
//! node slots, room in a list or a hint table; zeroed frames; a page back
//! from swap) says so by returning a [`Need`]: [`locked_with`] releases the
//! lock, gets it, and runs the operation again from the start, which looks
//! its node up again by handle and so sees whatever changed meanwhile.
//! Operations check what they need before they change anything. What an
//! operation takes out (a node's old path, a removed attribute, a forgotten
//! node, a file's frames and swap entries) goes into its [`Spares`], which
//! are released, charged and freed after the lock is. Work done with the
//! lock released on a copy (moving a file's data into whole frames,
//! renaming a directory's tree) checks the file's `version`, or the moved
//! nodes' handles and paths, before it is put in place, and starts again if
//! they changed. The kernel-entry lock still serializes system calls; this
//! lock does not rely on it. Interrupt handlers never take it.
#![forbid(unsafe_code)]

use crate::{
    arch::x86_64::cpu,
    control_abi, linux_blockfs as blockfs, linux_overlayfs as overlayfs,
    linux_tmpfs_quota as tmpfs_quota,
    memory::{self, FrameLease, FrameOwner},
    sync::{LockRank, SpinLock},
    trusted::frame::Frame,
};
use alloc::{boxed::Box, vec::Vec};
use core::ops::Range;

const PAGE_SIZE: usize = 4096;
/// Room for a canonical path: Linux's PATH_MAX, so every path a single
/// argument can name fits (shorter by the terminating NUL), however deep.
pub(crate) const PATH_CAPACITY: usize = 4096;
/// NAME_MAX: the longest name a directory entry can have.
pub(crate) const NAME_MAX: usize = 255;
/// Nodes are allocated this many at a time, in a chunk that never moves.
const NODE_COUNT: usize = 9;
/// A frame lease as a data or index page stores it: the address and the
/// generation, little-endian, with nothing between.
const LEASE_SIZE: usize = core::mem::size_of::<FrameLease>();
/// The file bytes a data page holds after its next-page lease.
const DATA_CAPACITY: usize = PAGE_SIZE - LEASE_SIZE;
/// The frame leases an index page holds after its next-page lease.
const FRAME_INDEX_CAPACITY: usize = PAGE_SIZE / LEASE_SIZE - 1;
const XATTR_NAME_CAPACITY: usize = 255;
const HOST_INSTANCE: usize = control_abi::DOMAIN_LIMIT;
const INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;
/// How often an operation may ask for the same kind of thing, or start
/// again because what it worked on changed, before it gives up.
const RETRY_LIMIT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeKind {
    File,
    Directory,
    Symlink,
    Fifo,
    /// A UNIX socket's name in the filesystem (bind(2) on a pathname).
    Socket,
    /// A device file (mknod S_IFCHR or S_IFBLK); `Metadata::device` says
    /// which device.
    CharacterDevice,
    BlockDevice,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Handle {
    generation: u32,
    inode: u64,
}

impl Handle {
    pub(crate) const fn inode(self) -> u64 {
        self.inode
    }

    /// The handle of a file on a mounted volume ([`crate::linux_blockfs`]).
    pub(crate) const fn volume(generation: u32, inode: u64) -> Self {
        Self { generation, inode }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Metadata {
    pub(crate) handle: Handle,
    pub(crate) kind: NodeKind,
    pub(crate) mode: u32,
    pub(crate) owner: u32,
    pub(crate) group: u32,
    /// How many names the file has (its hard links).
    pub(crate) links: u32,
    /// A device file's device number, as mknod(2) and stat(2) encode it.
    pub(crate) device: u32,
    /// FS_*_FL attributes (see [`set_attributes`]).
    pub(crate) attributes: u32,
    pub(crate) size: usize,
    pub(crate) atime: (i64, i64),
    pub(crate) mtime: (i64, i64),
    pub(crate) ctime: (i64, i64),
    /// The device of the filesystem the file is on (stat's st_dev): the
    /// root filesystem's (0:1) for the overlay's own files.
    pub(crate) filesystem: u32,
    /// Space used, in 512-byte sectors (stat's st_blocks).
    pub(crate) sectors: u64,
    /// The preferred I/O size (stat's st_blksize): the filesystem's block.
    pub(crate) block_size: u32,
    /// When the file was made (statx's stx_btime), where the filesystem
    /// keeps it.
    pub(crate) btime: Option<(i64, i64)>,
}

pub(crate) struct Child {
    pub(crate) next_cursor: usize,
    pub(crate) metadata: Metadata,
    name_length: usize,
    name: [u8; NAME_MAX],
}

impl Child {
    pub(crate) fn new(next_cursor: usize, metadata: Metadata, name: &[u8]) -> Self {
        let name_length = name.len().min(NAME_MAX);
        let mut stored = [0; NAME_MAX];
        stored[..name_length].copy_from_slice(&name[..name_length]);
        Self {
            next_cursor,
            metadata,
            name_length,
            name: stored,
        }
    }

    pub(crate) fn name(&self) -> &[u8] {
        &self.name[..self.name_length]
    }
}

// A file's data lives in frames, which carry memory cgroup charges and
// which shared mappings map, so they stay frames and are only ever copied
// through `Frame`. A chain file's data pages each start with the lease of
// the next page, then DATA_CAPACITY bytes of the file. memfd contents (and
// every paged file's) are kept one file page per frame, listed in a chain
// of index pages that starts at the node's first_page, so MAP_SHARED can
// map the frames themselves into every process instead of copying them in
// at mmap time: an index page is the next index page's lease, then
// FRAME_INDEX_CAPACITY frame leases (EMPTY for a hole). A zeroed frame is
// an empty data or index page.

/// The frame of data or index page `page`, if it is one.
fn page_frame(page: FrameLease) -> Option<Frame> {
    (page != FrameLease::EMPTY).then_some(())?;
    Frame::leased(page)
}

/// The lease stored at byte `offset` of `frame`.
fn read_lease(frame: Frame, offset: usize) -> FrameLease {
    let mut bytes = [0_u8; LEASE_SIZE];
    frame.read_bytes(offset, &mut bytes);
    let mut address = [0_u8; 8];
    let mut generation = [0_u8; 4];
    address.copy_from_slice(&bytes[..8]);
    generation.copy_from_slice(&bytes[8..]);
    let (address, generation) = (u64::from_le_bytes(address), u32::from_le_bytes(generation));
    if address == 0 && generation == 0 {
        return FrameLease::EMPTY;
    }
    FrameLease::from_parts(address, generation).unwrap_or(FrameLease::EMPTY)
}

/// Stores `lease` at byte `offset` of `frame`.
fn write_lease(frame: Frame, offset: usize, lease: FrameLease) {
    let mut bytes = [0_u8; LEASE_SIZE];
    bytes[..8].copy_from_slice(&lease.address().to_le_bytes());
    bytes[8..].copy_from_slice(&lease.generation().to_le_bytes());
    frame.write_bytes(offset, &bytes);
}

/// The page after data or index page `page`.
fn next_page(page: FrameLease) -> Option<FrameLease> {
    Some(read_lease(page_frame(page)?, 0))
}

fn set_next_page(page: FrameLease, next: FrameLease) -> Option<()> {
    write_lease(page_frame(page)?, 0, next);
    Some(())
}

/// Entry `slot` of index page `page`.
fn index_entry(page: Frame, slot: usize) -> FrameLease {
    read_lease(page, LEASE_SIZE * (slot + 1))
}

fn set_index_entry(page: Frame, slot: usize, lease: FrameLease) {
    write_lease(page, LEASE_SIZE * (slot + 1), lease);
}

/// The entries of index page `page`.
fn index_entries(page: Frame) -> impl Iterator<Item = (usize, FrameLease)> {
    (0..FRAME_INDEX_CAPACITY).map(move |slot| (slot, index_entry(page, slot)))
}

/// An extended attribute of a file: its name and value, on the kernel
/// heap.
struct Xattr {
    name: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Clone, Copy)]
struct SharedMapping {
    active: bool,
    pid: u32,
    address: u64,
    handle: Handle,
    offset: usize,
}

impl SharedMapping {
    const EMPTY: Self = Self {
        active: false,
        pid: 0,
        address: 0,
        handle: Handle {
            generation: 0,
            inode: 0,
        },
        offset: 0,
    };
}

/// How a file holds its data.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Data {
    /// A chain of data pages.
    Chain,
    /// Whole frames indexed by page (`first_page` roots the index), which
    /// shared mappings map directly: a file becomes paged when it is first
    /// mapped shared.
    Paged,
    /// A memfd, always paged.
    Memfd,
    /// Anonymous shared memory (MAP_SHARED | MAP_ANONYMOUS), paged and
    /// unnamed, as Linux backs it with a shmem file. Each process mapping
    /// it registers its pages, and it is freed once none maps it.
    Shmem,
}

/// Where a file came from, which decides its link count once it has no
/// name and whether it may be given one.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Origin {
    /// Created by name: once unlinked (deleted while open) it has no links.
    Named,
    /// A memfd, secret memory or anonymous shared memory: a file of an
    /// internal filesystem with one link, which no directory can name
    /// (EXDEV).
    Pseudo,
    /// An O_TMPFILE file: no links until linkat(2) names it, which O_EXCL
    /// forbids (`linkable` false).
    Temporary { linkable: bool },
}

struct Node {
    active: bool,
    linked: bool,
    whiteout: bool,
    origin: Origin,
    data: Data,
    kind: NodeKind,
    mode: u32,
    owner: u32,
    group: u32,
    /// A hard link: this node is only a name for the file `alias_of`
    /// holds, and has no data of its own.
    alias_of: Option<Handle>,
    /// How many names the file has: this node's and its aliases'.
    links: u16,
    /// A device file's device number.
    device: u32,
    /// A memfd's seals (F_SEAL_*, which all fit a byte).
    seals: u8,
    /// The file's attributes (FS_IOC_GETFLAGS: FS_IMMUTABLE_FL,
    /// FS_APPEND_FL, FS_NODUMP_FL and FS_NOATIME_FL, which fit a byte).
    attributes: u8,
    /// The pipe socket behind a FIFO, plus one; 0 before one opens it.
    fifo_socket: u16,
    /// The tmpfs blocks the file's size is charged for (`linux_tmpfs_quota`).
    charged: u32,
    /// A frame of the paged file was handed out to be mapped: it may be in
    /// page tables, so the data stays until the overlay goes.
    frames_lent: bool,
    /// A file of huge pages: a hugetlbfs file or an MFD_HUGETLB memfd.
    huge: bool,
    /// The huge pages its shared mappings have taken from the huge page
    /// pool, which it holds until it goes.
    huge_pages: u32,
    handle: Handle,
    size: usize,
    /// Counts the changes of the file's data (writes, truncation, holes
    /// punched, a new layout), so work done on a copy of it with the lock
    /// released (`make_own_paged`) can tell whether it changed meanwhile.
    version: u64,
    first_page: FrameLease,
    last_page: FrameLease,
    page_count: usize,
    cached_page: FrameLease,
    cached_page_index: usize,
    /// Extended attributes, the most recently set last.
    xattrs: Vec<Xattr>,
    atime: (i64, i64),
    mtime: (i64, i64),
    ctime: (i64, i64),
    /// The node's canonical path, on the kernel heap at its own length
    /// (most are short; a deep one may be up to `PATH_CAPACITY - 1`).
    path: Vec<u8>,
}

impl Node {
    fn paged(&self) -> bool {
        self.data != Data::Chain
    }

    const EMPTY: Self = Self {
        active: false,
        linked: false,
        whiteout: false,
        origin: Origin::Named,
        data: Data::Chain,
        kind: NodeKind::File,
        mode: 0,
        owner: 0,
        group: 0,
        alias_of: None,
        links: 0,
        device: 0,
        seals: 0,
        attributes: 0,
        fifo_socket: 0,
        charged: 0,
        frames_lent: false,
        huge: false,
        huge_pages: 0,
        handle: Handle {
            generation: 0,
            inode: 0,
        },
        size: 0,
        version: 0,
        first_page: FrameLease::EMPTY,
        last_page: FrameLease::EMPTY,
        page_count: 0,
        cached_page: FrameLease::EMPTY,
        cached_page_index: 0,
        xattrs: Vec::new(),
        atime: (0, 0),
        mtime: (0, 0),
        ctime: (0, 0),
        path: Vec::new(),
    };

    fn path(&self) -> &[u8] {
        &self.path
    }

    /// A free slot that still holds heap memory of the node it held
    /// (`Overlay::forget` keeps it when it has nowhere else to put it), for
    /// `sweep` to free.
    fn husk(&self) -> bool {
        !self.active && (self.path.capacity() != 0 || self.xattrs.capacity() != 0)
    }

    fn metadata(&self) -> Metadata {
        Metadata {
            handle: self.handle,
            kind: self.kind,
            mode: self.mode,
            owner: self.owner,
            group: self.group,
            // Linux counts the names a file has: none for a deleted or
            // O_TMPFILE file still open, one for a memfd.
            links: if self.linked || self.origin == Origin::Pseudo {
                u32::from(self.links.max(1))
            } else {
                u32::from(self.links.saturating_sub(1))
            },
            device: self.device,
            attributes: u32::from(self.attributes),
            size: self.size,
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
            // A tmpfs's files show its device, the root's files the
            // root's.
            filesystem: crate::linux_mount_paths::device_of(&self.path),
            // A paged file has holes: only its pages count.
            sectors: if self.paged() {
                (paged_frames(self, self.size.div_ceil(PAGE_SIZE)) * (PAGE_SIZE / 512)) as u64
            } else {
                (self.size as u64).div_ceil(512)
            },
            block_size: PAGE_SIZE as u32,
            btime: None,
        }
    }

    /// The extended attribute `name`, if set.
    fn xattr(&self, name: &[u8]) -> Option<&Xattr> {
        self.xattrs.iter().find(|record| record.name == name)
    }
}

const _: () = assert!(LEASE_SIZE == 12);
const _: () = assert!(LEASE_SIZE * (FRAME_INDEX_CAPACITY + 1) <= PAGE_SIZE);

/// A table from keys to node places by open addressing (linear probing),
/// which never allocates or frees while the overlay's lock is held: its
/// storage is made with the lock released ([`PlaceMap::storage_for`]) and
/// put in place under it, and probing, inserting and removing only use the
/// room it has. It is kept at most half full.
struct PlaceMap {
    /// A power of two of slots (none before the first use).
    slots: Vec<Option<(u64, usize)>>,
    len: usize,
}

impl PlaceMap {
    const EMPTY: Self = Self {
        slots: Vec::new(),
        len: 0,
    };

    /// Storage for a table of `entries` keys, made with the lock released.
    fn storage_for(entries: usize) -> Option<Vec<Option<(u64, usize)>>> {
        let capacity = entries
            .checked_mul(2)?
            .max(16)
            .checked_next_power_of_two()?;
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity).ok()?;
        slots.resize(capacity, None);
        Some(slots)
    }

    /// Whether `storage` keeps a table of `entries` keys at most half full.
    fn holds(storage: &[Option<(u64, usize)>], entries: usize) -> bool {
        entries.saturating_mul(2) <= storage.len()
    }

    fn len(&self) -> usize {
        self.len
    }

    /// Whether `more` new keys fit, keeping the table at most half full.
    fn has_room(&self, more: usize) -> bool {
        self.len.saturating_add(more).saturating_mul(2) <= self.slots.len()
    }

    /// The slot `key` starts probing from (Fibonacci hashing; the table
    /// has at least 16 slots).
    fn home(&self, key: u64) -> usize {
        let bits = self.slots.len().trailing_zeros();
        (key.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - bits)) as usize
    }

    fn position(&self, key: u64) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut index = self.home(key);
        loop {
            match self.slots[index] {
                None => return None,
                Some((stored, _)) if stored == key => return Some(index),
                Some(_) => index = (index + 1) & mask,
            }
        }
    }

    fn get(&self, key: u64) -> Option<usize> {
        let index = self.position(key)?;
        self.slots[index].map(|(_, value)| value)
    }

    /// Sets `key` to `value`; false (nothing changed) for a new key with
    /// no room for it.
    fn insert(&mut self, key: u64, value: usize) -> bool {
        if let Some(index) = self.position(key) {
            self.slots[index] = Some((key, value));
            return true;
        }
        if !self.has_room(1) {
            return false;
        }
        let mask = self.slots.len() - 1;
        let mut index = self.home(key);
        while self.slots[index].is_some() {
            index = (index + 1) & mask;
        }
        self.slots[index] = Some((key, value));
        self.len += 1;
        true
    }

    /// Removes `key`, moving back the keys probed past it so every key
    /// stays reachable from its home slot.
    fn remove(&mut self, key: u64) {
        let Some(mut hole) = self.position(key) else {
            return;
        };
        self.slots[hole] = None;
        self.len -= 1;
        let mask = self.slots.len() - 1;
        let mut index = hole;
        loop {
            index = (index + 1) & mask;
            let Some((stored, value)) = self.slots[index] else {
                return;
            };
            let home = self.home(stored);
            // A key whose home lies cyclically in (hole, index] is still
            // reachable; any other moves into the hole.
            let reachable = if hole <= index {
                hole < home && home <= index
            } else {
                hole < home || home <= index
            };
            if !reachable {
                self.slots[hole] = Some((stored, value));
                self.slots[index] = None;
                hole = index;
            }
        }
    }

    /// Puts `storage` (empty, from `storage_for`) in place of the table's,
    /// emptying the table, and hands back the old storage to be dropped
    /// with the lock released.
    fn replace_storage(&mut self, storage: Vec<Option<(u64, usize)>>) -> Vec<Option<(u64, usize)>> {
        self.len = 0;
        core::mem::replace(&mut self.slots, storage)
    }
}

struct Overlay {
    /// The nodes, in chunks of NODE_COUNT on the kernel heap that are only
    /// appended and never move, so a node's place (its index among all
    /// slots) and address stay put until `teardown`.
    nodes: Vec<Box<[Node]>>,
    /// The shared mappings processes registered; a removed one leaves its
    /// slot for the next.
    mappings: Vec<SharedMapping>,
    next_generation: u32,
    next_inode: u64,
    /// Linked symlinks, so path walks skip looking for them when there are
    /// none.
    symlinks: usize,
    /// How many path hints there may be before they are made again from
    /// the names the nodes have.
    path_hint_limit: usize,
    /// Where nodes were last found, by inode: the node's place, checked on
    /// every use (the slot must still hold that handle), so a stale entry
    /// only costs the scan it would have saved. Without it every read,
    /// write and page fault of a file scanned all nodes: rustc mapping its
    /// 150 MB driver library from a domain with tens of thousands of files
    /// took minutes.
    node_hints: PlaceMap,
    /// Every path the nodes were given, by `path_key`, with where that node
    /// was last found (its place plus one; 0 when not yet looked up). A
    /// path missing here names no node (while `path_hints_complete`), which
    /// spares path lookups of files that do not exist (the dynamic
    /// loader's, cargo's while it unpacks crates) a scan of every node; a
    /// present one is checked like a node hint. Every place that gives a
    /// node a path notes it (`note_path`).
    path_hints: PlaceMap,
    /// False once a name could not be noted for want of room (operations
    /// make room first, so it should not happen): a name missing from the
    /// path hints may then still name a node, until they are made again.
    path_hints_complete: bool,
    /// Free slots still holding a forgotten node's heap memory.
    husks: usize,
}

impl Overlay {
    const EMPTY: Self = Self {
        nodes: Vec::new(),
        mappings: Vec::new(),
        next_generation: 0x8000_0000,
        next_inode: 0x10_000,
        symlinks: 0,
        path_hint_limit: PATH_HINT_FLOOR,
        node_hints: PlaceMap::EMPTY,
        path_hints: PlaceMap::EMPTY,
        path_hints_complete: true,
        husks: 0,
    };

    /// Every node slot, in place order.
    fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().flat_map(|chunk| chunk.iter())
    }

    fn slot_count(&self) -> usize {
        self.nodes.len() * NODE_COUNT
    }

    fn active_count(&self) -> usize {
        self.nodes().filter(|node| node.active).count()
    }

    fn node_at(&self, place: usize) -> Option<&Node> {
        self.nodes.get(place / NODE_COUNT)?.get(place % NODE_COUNT)
    }

    fn node_at_mut(&mut self, place: usize) -> Option<&mut Node> {
        self.nodes
            .get_mut(place / NODE_COUNT)?
            .get_mut(place % NODE_COUNT)
    }

    /// The place of the node `handle`, found by its node hint first.
    fn find(&mut self, handle: Handle) -> Option<usize> {
        let wanted = |node: &Node| node.active && node.handle == handle;
        if let Some(place) = self.node_hints.get(handle.inode) {
            if self.node_at(place).is_some_and(wanted) {
                return Some(place);
            }
        }
        let place = self.nodes().position(wanted)?;
        // Without room the hint waits for the next node made, which makes
        // room (`node_room`).
        let _ = self.node_hints.insert(handle.inode, place);
        Some(place)
    }

    fn get(&mut self, handle: Handle) -> Option<&mut Node> {
        let place = self.find(handle)?;
        self.node_at_mut(place)
    }

    /// The place of the node linked at `path` (a whiteout too when
    /// `whiteouts`), found by the path hints first.
    fn linked_place(&mut self, path: &[u8], whiteouts: bool) -> Option<usize> {
        let wanted = |node: &Node| {
            node.active && node.linked && (whiteouts || !node.whiteout) && node.path() == path
        };
        let key = path_key(path);
        let hint = match self.path_hints.get(key) {
            Some(hint) => hint,
            None if self.path_hints_complete => return None,
            None => 0,
        };
        if let Some(place) = hint.checked_sub(1) {
            if self.node_at(place).is_some_and(wanted) {
                return Some(place);
            }
        }
        let place = self.nodes().position(wanted)?;
        let _ = self.path_hints.insert(key, place + 1);
        Some(place)
    }

    /// Whether the path hints must be made again (from the names the nodes
    /// have) before `names` more are noted.
    fn path_rebuild(&self, names: usize) -> bool {
        !self.path_hints_complete
            || self.path_hints.len().saturating_add(names) > self.path_hint_limit
    }

    /// The keys the path hints must have room for to note `names` more.
    fn path_entries(&self, names: usize) -> usize {
        let kept = if self.path_rebuild(names) {
            self.active_count()
        } else {
            self.path_hints.len()
        };
        kept.saturating_add(names)
    }

    /// Room to note `names` new paths, or the need for it.
    fn path_room(&self, names: usize) -> Result<(), Need> {
        if !self.path_rebuild(names) && self.path_hints.has_room(names) {
            Ok(())
        } else {
            Err(Need::PathHints(names))
        }
    }

    /// Room for a new node's hint, or the need for it. Asked by everything
    /// that makes a node, so the node hints grow with the nodes.
    fn node_room(&self) -> Result<(), Need> {
        if self.node_hints.has_room(1) {
            Ok(())
        } else {
            Err(Need::NodeHints(1))
        }
    }

    /// Records that a node now has the path whose key is `key` (room was
    /// made with `path_room`).
    fn note_key(&mut self, key: u64) {
        if self.path_hints.get(key).is_none() && !self.path_hints.insert(key, 0) {
            self.path_hints_complete = false;
        }
    }

    fn note_path(&mut self, path: &[u8]) {
        self.note_key(path_key(path));
    }

    /// A free node slot's place, adding the chunk in `spares` when there is
    /// none.
    fn free_place(&mut self, spares: &mut Spares) -> Result<usize, Need> {
        if let Some(place) = self.nodes().position(|node| !node.active) {
            return Ok(place);
        }
        if self.nodes.len() == self.nodes.capacity() {
            return Err(Need::NodeList);
        }
        let Some(chunk) = spares.chunk.take() else {
            return Err(Need::Chunk);
        };
        self.nodes.push(chunk);
        Ok(self.slot_count() - NODE_COUNT)
    }

    /// Puts `node` in slot `place`; what the slot held goes to `spares`.
    fn fill(&mut self, place: usize, node: Node, spares: &mut Spares) {
        let Some(slot) = self.node_at_mut(place) else {
            spares.discard(Discard::Node(node));
            return;
        };
        let old = core::mem::replace(slot, node);
        if old.husk() {
            self.husks = self.husks.saturating_sub(1);
        }
        if holds_heap(&old) {
            spares.discard(Discard::Node(old));
        }
    }

    /// Frees node slot `place`, and its node hint: a hint per file ever
    /// made grew the heap for good (linkat02's 65,000 links, 2.6 MB a run).
    /// The node's heap memory goes to `spares`, or stays in the slot as a
    /// husk for `sweep` when they are full.
    fn forget(&mut self, place: usize, spares: &mut Spares) {
        let Some(slot) = self.node_at_mut(place) else {
            return;
        };
        let old = core::mem::replace(slot, Node::EMPTY);
        let inode = old.handle.inode;
        if holds_heap(&old) {
            match spares.try_discard(Discard::Node(old)) {
                None => {}
                Some(Discard::Node(mut kept)) => {
                    kept.path.clear();
                    if let Some(slot) = self.node_at_mut(place) {
                        // The empty slot's vectors hold nothing to free.
                        slot.path = core::mem::take(&mut kept.path);
                        slot.xattrs = core::mem::take(&mut kept.xattrs);
                    }
                    self.husks += 1;
                    spares.husked = true;
                    // Its vectors were moved into the slot.
                    core::mem::forget(kept);
                }
                Some(other) => core::mem::forget(other),
            }
        }
        self.node_hints.remove(inode);
    }
}

/// Whether `node` holds heap memory, which must not be freed under the
/// lock.
fn holds_heap(node: &Node) -> bool {
    node.path.capacity() != 0 || node.xattrs.capacity() != 0
}

/// The fewest path hints that may build up before they are made again.
const PATH_HINT_FLOOR: usize = 4096;

/// Each instance's overlay, behind its own leaf lock (the module comment).
static OVERLAYS: [SpinLock<Overlay>; INSTANCE_LIMIT] =
    [const { SpinLock::new(LockRank::OVERLAY_NODES, Overlay::EMPTY) }; INSTANCE_LIMIT];

fn current_instance() -> usize {
    cpu::current_container_slot().unwrap_or(HOST_INSTANCE)
}

/// The current instance's overlay lock.
fn overlay_lock() -> &'static SpinLock<Overlay> {
    &OVERLAYS[current_instance().min(HOST_INSTANCE)]
}

/// Runs `operation` on the current instance's overlay under its lock. It
/// must not allocate, free or call out (the module comment); what it
/// returns is dropped after the lock is released.
fn locked<R>(operation: impl FnOnce(&mut Overlay) -> R) -> R {
    let mut overlay = overlay_lock().lock();
    operation(&mut overlay)
}

/// What an operation found missing under the lock; [`locked_with`] gets
/// it with the lock released and runs the operation again.
#[derive(Clone, Copy)]
enum Need {
    /// This many more zeroed frames in the spares.
    Frames(usize),
    /// A chunk of node slots in the spares.
    Chunk,
    /// Room for another chunk in the node list.
    NodeList,
    /// Room in the path hints for this many more names.
    PathHints(usize),
    /// Room in the node hints for this many more.
    NodeHints(usize),
    /// Room for this many more shared mappings.
    Mappings(usize),
    /// Room for another extended attribute of this file.
    Xattr(Handle),
    /// Page `index` of this file back from swap.
    SwapIn(Handle, usize),
    /// Room in the spares for this many frames to release and swap
    /// entries to free.
    Room(usize),
}

/// Data taken off a node, released with the lock released.
#[derive(Clone, Copy)]
struct Detached {
    first: FrameLease,
    paged: bool,
}

/// Heap memory an operation took out, dropped with the lock released.
enum Discard {
    Node(Node),
    Path(Vec<u8>),
    Xattr(Xattr),
    Xattrs(Vec<Xattr>),
}

/// What an operation under the lock may take (frames and a node chunk got
/// beforehand) and what it gives back (heap memory, frames, swap entries,
/// data and memory cgroup charges), dealt with after the lock is released
/// ([`Spares::settle`]). Nothing here allocates: an operation checks the
/// room first ([`Spares::room`]), and the frames each come with room for
/// their charge.
struct Spares {
    /// Zeroed frames the operation may take.
    frames: Vec<FrameLease>,
    /// Frames it made file pages, charged after (shmem when true).
    charges: Vec<(FrameLease, bool)>,
    /// Frames it took out of files, released after.
    releases: Vec<FrameLease>,
    /// Swap entries of pages it dropped, freed after.
    swaps: Vec<u64>,
    detached: [Option<Detached>; 2],
    chunk: Option<Box<[Node]>>,
    discards: [Option<Discard>; 4],
    /// A forgotten node was left as a husk.
    husked: bool,
}

impl Spares {
    const fn new() -> Self {
        Self {
            frames: Vec::new(),
            charges: Vec::new(),
            releases: Vec::new(),
            swaps: Vec::new(),
            detached: [None, None],
            chunk: None,
            discards: [None, None, None, None],
            husked: false,
        }
    }

    fn take_frame(&mut self) -> Option<FrameLease> {
        self.frames.pop()
    }

    /// Asks for frames until there are `count`.
    fn frames_for(&self, count: usize) -> Result<(), Need> {
        match count.checked_sub(self.frames.len()) {
            Some(missing) if missing != 0 => Err(Need::Frames(missing)),
            _ => Ok(()),
        }
    }

    /// Records `frame`, just made a file page, to be charged after. Room
    /// came with the frame.
    fn charge(&mut self, frame: FrameLease, shmem: bool) {
        if self.charges.len() < self.charges.capacity() {
            self.charges.push((frame, shmem));
        }
    }

    /// Room to take `count` frames and swap entries out of a file.
    fn room(&self, count: usize) -> Result<(), Need> {
        if self.releases.capacity() - self.releases.len() >= count
            && self.swaps.capacity() - self.swaps.len() >= count
        {
            Ok(())
        } else {
            Err(Need::Room(count))
        }
    }

    fn release(&mut self, frame: FrameLease) {
        if self.releases.len() < self.releases.capacity() {
            self.releases.push(frame);
        }
    }

    fn free_swap(&mut self, entry: u64) {
        if self.swaps.len() < self.swaps.capacity() {
            self.swaps.push(entry);
        }
    }

    fn detach(&mut self, data: Detached) {
        if data.first == FrameLease::EMPTY {
            return;
        }
        if let Some(slot) = self.detached.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(data);
        }
    }

    /// Keeps `item` to drop after the lock; hands it back when there is
    /// no room.
    fn try_discard(&mut self, item: Discard) -> Option<Discard> {
        match self.discards.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(item);
                None
            }
            None => Some(item),
        }
    }

    /// Keeps `item` to drop after the lock. An operation discards at most
    /// a few; were there no room, the item is leaked rather than freed
    /// under the lock.
    fn discard(&mut self, item: Discard) {
        if let Some(item) = self.try_discard(item) {
            core::mem::forget(item);
        }
    }

    /// Deals with what the operation gave back, with the lock released.
    fn settle(self) {
        let Self {
            frames,
            charges,
            releases,
            swaps,
            detached,
            chunk,
            discards,
            husked,
        } = self;
        for (frame, shmem) in charges {
            memory::charge_cache_frame(frame, shmem);
        }
        for frame in frames.into_iter().chain(releases) {
            let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[frame]);
        }
        for data in detached.into_iter().flatten() {
            let _ = release_detached(data);
        }
        for entry in swaps {
            crate::linux_swap::free(entry);
        }
        drop(chunk);
        for item in discards.into_iter().flatten() {
            match item {
                Discard::Node(node) => drop(node),
                Discard::Path(path) => drop(path),
                Discard::Xattr(xattr) => drop(xattr),
                Discard::Xattrs(xattrs) => drop(xattrs),
            }
        }
        if husked {
            sweep();
        }
    }
}

/// Runs `operation` on the current instance's overlay under its lock,
/// getting what it says it needs with the lock released and running it
/// again, until it finishes; `None` when what it needs cannot be had.
/// What it gave back is dealt with after ([`Spares::settle`]).
fn locked_with<R>(
    mut operation: impl FnMut(&mut Overlay, &mut Spares) -> Result<R, Need>,
) -> Option<R> {
    let lock = overlay_lock();
    let mut spares = Spares::new();
    let mut stalls = 0;
    let result = loop {
        let attempt = {
            let mut overlay = lock.lock();
            operation(&mut overlay, &mut spares)
        };
        match attempt {
            Ok(value) => break Some(value),
            Err(need) => {
                // Each page back from swap is progress; anything else an
                // operation should need about once.
                stalls = if matches!(need, Need::SwapIn(..)) {
                    0
                } else {
                    stalls + 1
                };
                if stalls > RETRY_LIMIT || !supply(need, &mut spares) {
                    break None;
                }
            }
        }
    };
    spares.settle();
    result
}

/// Gets `need`, with the lock released.
fn supply(need: Need, spares: &mut Spares) -> bool {
    match need {
        Need::Frames(count) => {
            let charges = spares.charges.len() + spares.frames.len() + count;
            if spares.frames.try_reserve(count).is_err()
                || spares
                    .charges
                    .try_reserve(charges - spares.charges.len())
                    .is_err()
            {
                return false;
            }
            for _ in 0..count {
                let Some(frame) = allocate_zeroed_frame() else {
                    return false;
                };
                spares.frames.push(frame);
            }
            true
        }
        Need::Chunk => {
            if spares.chunk.is_none() {
                spares.chunk = new_chunk();
            }
            spares.chunk.is_some()
        }
        Need::NodeList => grow_node_list(),
        Need::PathHints(names) => grow_path_hints(names),
        Need::NodeHints(count) => grow_node_hints(count),
        Need::Mappings(count) => grow_mappings(count),
        Need::Xattr(handle) => grow_xattrs(handle),
        Need::SwapIn(handle, index) => swap_in(handle, index),
        Need::Room(count) => {
            spares.releases.try_reserve(count).is_ok() && spares.swaps.try_reserve(count).is_ok()
        }
    }
}

/// A chunk of empty node slots.
fn new_chunk() -> Option<Box<[Node]>> {
    let mut chunk = Vec::new();
    chunk.try_reserve_exact(NODE_COUNT).ok()?;
    chunk.extend((0..NODE_COUNT).map(|_| Node::EMPTY));
    Some(chunk.into_boxed_slice())
}

/// Makes room for another chunk in the node list: a list twice as long is
/// made with the lock released, and the chunks (pointers to slots that
/// stay put) are moved into it under the lock.
fn grow_node_list() -> bool {
    let wanted = locked(|overlay| {
        (overlay.nodes.len() == overlay.nodes.capacity())
            .then(|| overlay.nodes.capacity().saturating_mul(2).max(16))
    });
    let Some(capacity) = wanted else {
        return true;
    };
    let mut list = Vec::new();
    if list.try_reserve_exact(capacity).is_err() {
        return false;
    }
    let unused = locked(move |overlay| {
        if overlay.nodes.len() == overlay.nodes.capacity() && overlay.nodes.len() < list.capacity()
        {
            list.append(&mut overlay.nodes);
            core::mem::swap(&mut overlay.nodes, &mut list);
        }
        list
    });
    drop(unused);
    true
}

/// Makes room for `count` more shared mappings, as `grow_node_list` does.
fn grow_mappings(count: usize) -> bool {
    let wanted = locked(|overlay| {
        let mappings = &overlay.mappings;
        let required = mappings.len().saturating_add(count);
        (mappings.capacity() < required)
            .then(|| required.max(mappings.capacity().saturating_mul(2)).max(16))
    });
    let Some(capacity) = wanted else {
        return true;
    };
    let mut list = Vec::new();
    if list.try_reserve_exact(capacity).is_err() {
        return false;
    }
    let unused = locked(move |overlay| {
        let required = overlay.mappings.len().saturating_add(count);
        if overlay.mappings.capacity() < required && required <= list.capacity() {
            list.append(&mut overlay.mappings);
            core::mem::swap(&mut overlay.mappings, &mut list);
        }
        list
    });
    drop(unused);
    true
}

/// Makes room for another extended attribute of `handle`'s file.
fn grow_xattrs(handle: Handle) -> bool {
    let wanted = locked(|overlay| {
        let node = overlay.get(handle)?;
        (node.xattrs.len() == node.xattrs.capacity())
            .then(|| node.xattrs.capacity().saturating_mul(2).max(4))
    });
    let Some(capacity) = wanted else {
        return true;
    };
    let mut list = Vec::new();
    if list.try_reserve_exact(capacity).is_err() {
        return false;
    }
    let unused = locked(move |overlay| {
        if let Some(node) = overlay.get(handle) {
            if node.xattrs.len() == node.xattrs.capacity() && node.xattrs.len() < list.capacity() {
                list.append(&mut node.xattrs);
                core::mem::swap(&mut node.xattrs, &mut list);
            }
        }
        list
    });
    drop(unused);
    true
}

/// Makes room for `count` more node hints: the hints are made again, from
/// the nodes, in a table made with the lock released.
fn grow_node_hints(count: usize) -> bool {
    for _ in 0..RETRY_LIMIT {
        let wanted = locked(|overlay| {
            (!overlay.node_hints.has_room(count))
                .then(|| overlay.active_count().saturating_add(count))
        });
        let Some(entries) = wanted else {
            return true;
        };
        let Some(storage) = PlaceMap::storage_for(entries) else {
            return false;
        };
        let unused = locked(move |overlay| {
            let entries = overlay.active_count().saturating_add(count);
            if overlay.node_hints.has_room(count) || !PlaceMap::holds(&storage, entries) {
                return storage;
            }
            let Overlay {
                nodes, node_hints, ..
            } = overlay;
            let old = node_hints.replace_storage(storage);
            for (place, node) in nodes.iter().flat_map(|chunk| chunk.iter()).enumerate() {
                if node.active {
                    let _ = node_hints.insert(node.handle.inode, place);
                }
            }
            old
        });
        drop(unused);
    }
    false
}

/// Makes room to note `names` more paths: a table made with the lock
/// released, into which the hints are moved, or, once they have grown past
/// their limit (names no node has any more: a run of tests in fresh
/// temporary directories gave them a key per file ever made, for good),
/// made again from the names the nodes have.
fn grow_path_hints(names: usize) -> bool {
    for _ in 0..RETRY_LIMIT {
        let wanted = locked(|overlay| {
            overlay
                .path_room(names)
                .is_err()
                .then(|| overlay.path_entries(names))
        });
        let Some(entries) = wanted else {
            return true;
        };
        let Some(storage) = PlaceMap::storage_for(entries) else {
            return false;
        };
        let unused = locked(move |overlay| {
            if overlay.path_room(names).is_ok()
                || !PlaceMap::holds(&storage, overlay.path_entries(names))
            {
                return storage;
            }
            let rebuild = overlay.path_rebuild(names);
            let Overlay {
                nodes,
                path_hints,
                path_hint_limit,
                path_hints_complete,
                ..
            } = overlay;
            let old = path_hints.replace_storage(storage);
            if rebuild {
                for (place, node) in nodes.iter().flat_map(|chunk| chunk.iter()).enumerate() {
                    if node.active {
                        let _ = path_hints.insert(path_key(node.path()), place + 1);
                    }
                }
                let kept = path_hints.len();
                *path_hint_limit = kept
                    .saturating_mul(2)
                    .max(kept.saturating_add(names))
                    .max(PATH_HINT_FLOOR);
                *path_hints_complete = true;
            } else {
                for (key, value) in old.iter().flatten() {
                    let _ = path_hints.insert(*key, *value);
                }
            }
            old
        });
        drop(unused);
    }
    false
}

/// Brings page `index` of paged file `handle` back from swap: a frame is
/// allocated and read into with the lock released, and put in the page's
/// place if the page is still out in swap at that entry. False only when
/// that could not be done.
fn swap_in(handle: Handle, index: usize) -> bool {
    let state = locked(|overlay| {
        let node = overlay.get(handle).filter(|node| node.paged())?;
        let (entries, slot) = paged_slot(node, index)?;
        Some((index_entry(entries, slot), page_is_shmem(node)))
    });
    // Gone, or back already: the operation sees which when it runs again.
    let Some((mark, shmem)) = state else {
        return true;
    };
    let Some(swap) = swapped_entry(mark) else {
        return true;
    };
    let Some(frame) = allocate_zeroed_frame() else {
        return false;
    };
    memory::charge_cache_frame(frame, shmem);
    if !cpu::linux_swap_read_page(swap, frame) {
        let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[frame]);
        return false;
    }
    let installed = locked(|overlay| {
        let Some((entries, slot)) = overlay
            .get(handle)
            .filter(|node| node.paged())
            .and_then(|node| paged_slot(node, index))
        else {
            return false;
        };
        if index_entry(entries, slot) != mark {
            return false;
        }
        set_index_entry(entries, slot, frame);
        true
    });
    if installed {
        crate::linux_swap::free(swap);
    } else {
        let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[frame]);
    }
    true
}

/// Frees the heap memory husks hold (`Overlay::forget`), a batch of slots
/// at a time under the lock, the memory after it.
fn sweep() {
    const BATCH: usize = 32;
    let mut place = 0;
    loop {
        let (taken, more) = locked(|overlay| {
            let mut taken: [(Vec<u8>, Vec<Xattr>); BATCH] =
                core::array::from_fn(|_| (Vec::new(), Vec::new()));
            let mut count = 0;
            let total = overlay.slot_count();
            while place < total && count < BATCH && overlay.husks != 0 {
                let Some(node) = overlay.node_at_mut(place) else {
                    break;
                };
                if node.husk() {
                    taken[count] = (
                        core::mem::take(&mut node.path),
                        core::mem::take(&mut node.xattrs),
                    );
                    count += 1;
                    overlay.husks -= 1;
                }
                place += 1;
            }
            (taken, place < total && overlay.husks != 0)
        });
        drop(taken);
        if !more {
            return;
        }
    }
}

/// A copy of a node's path made under the lock, for what needs it after
/// (the tmpfs limits).
struct PathCopy {
    bytes: [u8; PATH_CAPACITY],
    length: usize,
}

impl PathCopy {
    const fn new() -> Self {
        Self {
            bytes: [0; PATH_CAPACITY],
            length: 0,
        }
    }

    fn set(&mut self, path: &[u8]) {
        let length = path.len().min(PATH_CAPACITY);
        self.bytes[..length].copy_from_slice(&path[..length]);
        self.length = length;
    }

    fn get(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// Takes `node`'s data off it, to be released with the lock released.
fn detach_data(node: &mut Node) -> Detached {
    let data = Detached {
        first: node.first_page,
        paged: node.paged(),
    };
    node.first_page = FrameLease::EMPTY;
    node.last_page = FrameLease::EMPTY;
    node.page_count = 0;
    node.cached_page = FrameLease::EMPTY;
    node.cached_page_index = 0;
    node.version = node.version.wrapping_add(1);
    data
}

fn release_detached(data: Detached) -> bool {
    if data.paged {
        release_frame_index(data.first)
    } else {
        release_data_pages(data.first)
    }
}

/// Whether paged `node`'s pages are shared memory (tmpfs, memfd and shmem)
/// rather than file memory (a volume's page cache), as memory.stat counts
/// them.
fn page_is_shmem(node: &Node) -> bool {
    !(node.origin == Origin::Pseudo && matches!(node.data, Data::Paged))
}

/// What page `index` of a paged file holds.
enum PageState {
    /// A frame in memory.
    Present(FrameLease),
    /// Its entry out in swap.
    Swapped,
    /// Nothing (a hole): filling it takes this many frames (the index
    /// pages missing on the way, and the page's own).
    Missing(usize),
}

fn page_state(node: &Node, index: usize) -> PageState {
    let depth = index / FRAME_INDEX_CAPACITY;
    let mut page = node.first_page;
    let mut level = 0;
    while page != FrameLease::EMPTY {
        if level == depth {
            let Some(entries) = page_frame(page) else {
                return PageState::Missing(1);
            };
            let entry = index_entry(entries, index % FRAME_INDEX_CAPACITY);
            return if entry == FrameLease::EMPTY {
                PageState::Missing(1)
            } else if swapped_entry(entry).is_some() {
                PageState::Swapped
            } else {
                PageState::Present(entry)
            };
        }
        page = next_page(page).unwrap_or(FrameLease::EMPTY);
        level += 1;
    }
    PageState::Missing(depth - level + 2)
}

/// What filling every page of `pages` of paged `node` takes: the frames
/// (index pages and data pages missing), or the first page out in swap to
/// bring back.
fn range_state(node: &Node, pages: Range<usize>) -> Result<usize, Need> {
    if pages.is_empty() {
        return Ok(0);
    }
    let last_depth = (pages.end - 1) / FRAME_INDEX_CAPACITY;
    let mut needed = 0;
    let mut page = node.first_page;
    for depth in 0..=last_depth {
        let entries = page_frame(page);
        if entries.is_none() {
            needed += 1;
        }
        let low = pages.start.max(depth * FRAME_INDEX_CAPACITY);
        let high = pages.end.min((depth + 1) * FRAME_INDEX_CAPACITY);
        for index in low..high {
            let Some(entries) = entries else {
                needed += 1;
                continue;
            };
            let entry = index_entry(entries, index % FRAME_INDEX_CAPACITY);
            if entry == FrameLease::EMPTY {
                needed += 1;
            } else if swapped_entry(entry).is_some() {
                return Err(Need::SwapIn(node.handle, index));
            }
        }
        page = match entries {
            Some(entries) => read_lease(entries, 0),
            None => FrameLease::EMPTY,
        };
    }
    Ok(needed)
}

/// Page `index` of paged `node` in memory, under the lock: `None` for a
/// hole unless `allocate`, which fills it (and the index pages on the way)
/// with zeroed frames from `spares`, asking for them first. A page out in
/// swap is asked back.
fn locked_page(
    node: &mut Node,
    index: usize,
    allocate: bool,
    spares: &mut Spares,
) -> Result<Option<FrameLease>, Need> {
    match page_state(node, index) {
        PageState::Present(frame) => return Ok(Some(frame)),
        PageState::Swapped => return Err(Need::SwapIn(node.handle, index)),
        PageState::Missing(_) if !allocate => return Ok(None),
        PageState::Missing(frames) => spares.frames_for(frames)?,
    }
    if node.first_page == FrameLease::EMPTY {
        let Some(frame) = spares.take_frame() else {
            return Ok(None);
        };
        node.first_page = frame;
    }
    let mut page = node.first_page;
    for _ in 0..index / FRAME_INDEX_CAPACITY {
        let Some(mut next) = next_page(page) else {
            return Ok(None);
        };
        if next == FrameLease::EMPTY {
            let Some(frame) = spares.take_frame() else {
                return Ok(None);
            };
            next = frame;
            if set_next_page(page, next).is_none() {
                return Ok(None);
            }
        }
        page = next;
    }
    let Some(entries) = page_frame(page) else {
        return Ok(None);
    };
    let slot = index % FRAME_INDEX_CAPACITY;
    let mut entry = index_entry(entries, slot);
    if entry == FrameLease::EMPTY {
        let Some(frame) = spares.take_frame() else {
            return Ok(None);
        };
        entry = frame;
        set_index_entry(entries, slot, entry);
        spares.charge(entry, page_is_shmem(node));
    }
    Ok(Some(entry))
}

/// Page `index` of a frame index no node has yet (`make_own_paged` builds
/// it with the lock released), allocated with the index pages on the way
/// and charged as shared memory.
fn detached_page(root: &mut FrameLease, index: usize) -> Option<Frame> {
    if *root == FrameLease::EMPTY {
        *root = allocate_zeroed_frame()?;
    }
    let mut page = *root;
    for _ in 0..index / FRAME_INDEX_CAPACITY {
        let mut next = next_page(page)?;
        if next == FrameLease::EMPTY {
            next = allocate_zeroed_frame()?;
            set_next_page(page, next)?;
        }
        page = next;
    }
    let entries = page_frame(page)?;
    let slot = index % FRAME_INDEX_CAPACITY;
    let mut entry = index_entry(entries, slot);
    if entry == FrameLease::EMPTY {
        entry = allocate_zeroed_frame()?;
        set_index_entry(entries, slot, entry);
        memory::charge_cache_frame(entry, true);
    }
    Frame::leased(entry)
}

/// The overlay has a symlink a path walk may need to follow.
pub(crate) fn has_symlinks() -> bool {
    locked(|overlay| overlay.symlinks != 0) || blockfs::any_mounted() || overlayfs::active()
}

pub(crate) fn register_shared_mapping(
    pid: u32,
    address: u64,
    handle: Handle,
    offset: usize,
) -> bool {
    if pid == 0 || !address.is_multiple_of(PAGE_SIZE as u64) || metadata(handle).is_none() {
        return false;
    }
    let registered = SharedMapping {
        active: true,
        pid,
        address,
        handle,
        offset,
    };
    locked_with(|overlay, _| {
        let mappings = &mut overlay.mappings;
        if mappings
            .iter()
            .any(|mapping| mapping.active && mapping.pid == pid && mapping.address == address)
        {
            return Ok(false);
        }
        if let Some(mapping) = mappings.iter_mut().find(|mapping| !mapping.active) {
            *mapping = registered;
            return Ok(true);
        }
        if mappings.len() == mappings.capacity() {
            return Err(Need::Mappings(1));
        }
        mappings.push(registered);
        Ok(true)
    })
    .unwrap_or(false)
}

/// `pid`'s registered shared mappings.
fn process_mappings(mappings: &[SharedMapping], pid: u32) -> impl Iterator<Item = &SharedMapping> {
    mappings
        .iter()
        .filter(move |mapping| mapping.active && mapping.pid == pid)
}

pub(crate) fn shared_mapping(pid: u32, address: u64) -> Option<(Handle, usize)> {
    locked(|overlay| {
        process_mappings(&overlay.mappings, pid)
            .find(|mapping| mapping.address == address)
            .map(|mapping| (mapping.handle, mapping.offset))
    })
}

pub(crate) fn next_shared_mapping(pid: u32, after: Option<u64>) -> Option<(u64, Handle, usize)> {
    locked(|overlay| {
        process_mappings(&overlay.mappings, pid)
            .filter(|mapping| after.is_none_or(|after| mapping.address > after))
            .min_by_key(|mapping| mapping.address)
            .map(|mapping| (mapping.address, mapping.handle, mapping.offset))
    })
}

/// Drops the shared mappings `pid` has registered from `start` up to
/// `end`, in one pass over the registrations, and returns them (address,
/// file, offset). munmap and MAP_FIXED looked each page up instead, so a
/// gigabyte took 262,144 passes over a list long since grown by thousands
/// of processes' mappings (fork14 after msgstress01: minutes).
pub(crate) fn take_shared_mappings(pid: u32, start: u64, end: u64) -> Vec<(u64, Handle, usize)> {
    collect_shared_mappings(pid, start, end, true)
}

/// The shared mappings `pid` has registered from `start` up to `end`
/// (address, file, offset), in address order, found in one pass.
pub(crate) fn shared_mappings_in(pid: u32, start: u64, end: u64) -> Vec<(u64, Handle, usize)> {
    collect_shared_mappings(pid, start, end, false)
}

/// The registrations `collect_shared_mappings` selects, counted under the
/// lock; the list for them is made after it is released.
fn collect_shared_mappings(
    pid: u32,
    start: u64,
    end: u64,
    remove: bool,
) -> Vec<(u64, Handle, usize)> {
    let selected = move |mapping: &SharedMapping| {
        mapping.active && mapping.pid == pid && (start..end).contains(&mapping.address)
    };
    for _ in 0..RETRY_LIMIT {
        let count = locked(|overlay| overlay.mappings.iter().filter(|m| selected(m)).count());
        let mut taken = Vec::new();
        if taken.try_reserve_exact(count).is_err() {
            return taken;
        }
        let (mut taken, filled) = locked(move |overlay| {
            if overlay.mappings.iter().filter(|m| selected(m)).count() > taken.capacity() {
                return (taken, false);
            }
            for mapping in overlay.mappings.iter_mut().filter(|m| selected(m)) {
                taken.push((mapping.address, mapping.handle, mapping.offset));
                if remove {
                    *mapping = SharedMapping::EMPTY;
                }
            }
            (taken, true)
        });
        if filled {
            taken.sort_unstable_by_key(|(address, _, _)| *address);
            return taken;
        }
    }
    Vec::new()
}

pub(crate) fn remove_shared_mapping(pid: u32, address: u64) -> bool {
    locked(|overlay| {
        overlay
            .mappings
            .iter_mut()
            .find(|mapping| mapping.active && mapping.pid == pid && mapping.address == address)
            .map(|mapping| *mapping = SharedMapping::EMPTY)
            .is_some()
    })
}

pub(crate) fn clone_shared_mappings(parent: u32, child: u32) -> bool {
    locked_with(|overlay, _| {
        let mappings = &mut overlay.mappings;
        let inherited = process_mappings(mappings, parent).count();
        let free = mappings.iter().filter(|mapping| !mapping.active).count();
        let room = mappings.capacity() - mappings.len() + free;
        if room < inherited {
            return Err(Need::Mappings(inherited - room));
        }
        let length = mappings.len();
        for index in 0..length {
            let mapping = mappings[index];
            if !mapping.active || mapping.pid != parent {
                continue;
            }
            // A second registration at an address is refused, as
            // `register_shared_mapping` refuses it: the child gets none.
            if mappings
                .iter()
                .any(|other| other.active && other.pid == child && other.address == mapping.address)
            {
                for other in mappings
                    .iter_mut()
                    .filter(|other| other.active && other.pid == child)
                {
                    *other = SharedMapping::EMPTY;
                }
                return Ok(false);
            }
            let inherited = SharedMapping {
                pid: child,
                ..mapping
            };
            match mappings.iter_mut().find(|other| !other.active) {
                Some(slot) => *slot = inherited,
                None => mappings.push(inherited),
            }
        }
        Ok(true)
    })
    .unwrap_or(false)
}

pub(crate) fn remove_process_shared_mappings(pid: u32) {
    locked(|overlay| {
        for mapping in overlay
            .mappings
            .iter_mut()
            .filter(|mapping| mapping.active && mapping.pid == pid)
        {
            *mapping = SharedMapping::EMPTY;
        }
    });
}

pub(crate) fn lookup_stored(path: &[u8]) -> Option<Metadata> {
    if let Some(found) = overlayfs::lookup(path) {
        return found;
    }
    if let Some(found) = blockfs::lookup(path) {
        return found;
    }
    valid_path(path)?;
    locked(|overlay| {
        let place = overlay.linked_place(path, false)?;
        match overlay.node_at(place)?.alias_of {
            Some(file) => overlay.get(file).map(|node| node.metadata()),
            None => overlay.node_at(place).map(Node::metadata),
        }
    })
}

pub(crate) fn hidden_stored(path: &[u8]) -> bool {
    // A volume's files are its own: nothing of the image shows through.
    if blockfs::covers(path) || overlayfs::covers(path) || valid_path(path).is_none() {
        return false;
    }
    locked(|overlay| {
        // Only a path or ancestor some node was ever given can be hidden.
        let named = !overlay.path_hints_complete
            || (0..=path.len())
                .filter(|end| *end == path.len() || path.get(*end) == Some(&b'/'))
                .any(|end| overlay.path_hints.get(path_key(&path[..end])).is_some());
        named
            && overlay.nodes().any(|node| {
                node.active
                    && node.linked
                    && node.whiteout
                    && (node.path() == path
                        || path.starts_with(node.path())
                            && path.get(node.path().len()) == Some(&b'/'))
            })
    })
}

pub(crate) fn from_generation(generation: u32) -> Option<Handle> {
    if overlayfs::owns(Handle::volume(generation, 0)) {
        return overlayfs::from_generation(generation);
    }
    if blockfs::owns(Handle::volume(generation, 0)) {
        return blockfs::from_generation(generation);
    }
    locked(|overlay| {
        overlay
            .nodes()
            .find(|node| node.active && node.handle.generation == generation)
            .map(|node| node.handle)
    })
}

pub(crate) fn generation(handle: Handle) -> u32 {
    handle.generation
}

pub(crate) fn metadata(handle: Handle) -> Option<Metadata> {
    if overlayfs::owns(handle) {
        return overlayfs::metadata(handle);
    }
    if blockfs::owns(handle) {
        return blockfs::metadata(handle);
    }
    locked(|overlay| overlay.get(handle).map(|node| node.metadata()))
}

/// Whether the overlay has a node `handle`.
fn exists(handle: Handle) -> bool {
    locked(|overlay| overlay.find(handle).is_some())
}

/// Sets fields of node `handle` with `change`; false if there is none.
fn change_node(handle: Handle, change: impl FnOnce(&mut Node)) -> bool {
    locked(|overlay| overlay.get(handle).map(change).is_some())
}

/// What `look` reads of node `handle`, if there is one.
fn read_node_field<T>(handle: Handle, look: impl FnOnce(&Node) -> T) -> Option<T> {
    locked(|overlay| overlay.get(handle).map(|node| look(node)))
}

pub(crate) fn configure_memfd(handle: Handle, allow_sealing: bool) -> bool {
    if read_node_field(handle, |node| node.kind) != Some(NodeKind::File) || !make_own_paged(handle)
    {
        return false;
    }
    locked(|overlay| {
        let Some(node) = overlay
            .get(handle)
            .filter(|node| node.kind == NodeKind::File && node.paged())
        else {
            return false;
        };
        node.data = Data::Memfd;
        node.origin = Origin::Pseudo;
        node.seals = if allow_sealing { 0 } else { 1 };
        true
    })
}

/// Makes `handle` a file of huge pages (hugetlbfs, MFD_HUGETLB).
pub(crate) fn set_huge(handle: Handle) -> bool {
    change_node(handle, |node| node.huge = true)
}

/// Whether `handle` is a file of huge pages.
pub(crate) fn is_huge(handle: Handle) -> bool {
    read_node_field(handle, |node| node.huge).unwrap_or(false)
}

/// The huge pages `handle`'s shared mappings hold.
pub(crate) fn huge_pages(handle: Handle) -> u32 {
    read_node_field(handle, |node| node.huge_pages).unwrap_or(0)
}

/// Records that `handle`'s shared mappings now hold `pages` huge pages,
/// when that is more than before.
pub(crate) fn hold_huge_pages(handle: Handle, pages: u32) -> bool {
    change_node(handle, |node| {
        node.huge = true;
        node.huge_pages = node.huge_pages.max(pages);
    })
}

/// The huge pages every file of huge pages holds, for the pool's count.
pub(crate) fn huge_pages_in_use() -> u64 {
    locked(|overlay| {
        overlay
            .nodes()
            .filter(|node| node.active && node.huge)
            .map(|node| u64::from(node.huge_pages))
            .sum()
    })
}

/// Marks `handle` a file of an internal filesystem (secret memory): one
/// link, and no directory can name it.
pub(crate) fn mark_pseudo(handle: Handle) -> bool {
    change_node(handle, |node| node.origin = Origin::Pseudo)
}

/// The name an O_TMPFILE file is created under in its directory, for the
/// moment before it is unlinked.
const TEMPORARY_NAME: &[u8] = b".linox-o-tmpfile";

/// Creates an O_TMPFILE file: a regular file with no name, made as if in
/// `directory` (owner, group and set-group-ID inheritance from it), that
/// linkat(2) may later name unless `linkable` is false (O_EXCL).
pub(crate) fn create_temporary_stored(
    directory: &[u8],
    mode: u32,
    linkable: bool,
) -> Option<Handle> {
    // On an overlay, the file is made in the upper layer's directory.
    if let Some(upper) = overlayfs::prepare_upper(directory) {
        return create_temporary_stored(&upper?, mode, linkable);
    }
    if blockfs::covers(directory) {
        let mut probe = Vec::new();
        probe.try_reserve_exact(directory.len() + 2).ok()?;
        probe.extend_from_slice(directory);
        probe.extend_from_slice(b"/x");
        let (owner, group, mode) = cpu::linux_new_file_identity(&probe, false, mode);
        return blockfs::create_temporary(directory, mode, owner, group, linkable).flatten();
    }
    let mut path = [0_u8; PATH_CAPACITY];
    let separator = usize::from(!directory.is_empty());
    let length = directory.len() + separator + TEMPORARY_NAME.len();
    let path = path.get_mut(..length)?;
    path[..directory.len()].copy_from_slice(directory);
    if separator == 1 {
        path[directory.len()] = b'/';
    }
    path[directory.len() + separator..].copy_from_slice(TEMPORARY_NAME);
    let handle = create_file_stored(path, mode, &[])?;
    if !unlink(handle) {
        return None;
    }
    change_node(handle, |node| node.origin = Origin::Temporary { linkable }).then_some(handle)
}

/// Why [`link_unnamed`] could not name a file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinkError {
    /// The file was deleted, or is an O_TMPFILE file opened with O_EXCL
    /// (ENOENT).
    Gone,
    /// The file belongs to an internal filesystem (EXDEV).
    CrossDevice,
    /// Something already has that name (EEXIST).
    Exists,
    /// The name is invalid or the node table is full.
    Failed,
}

/// Whether node `node` (an O_TMPFILE file) may be given a name.
fn nameable(node: &Node) -> Result<(), LinkError> {
    match node.origin {
        Origin::Pseudo => Err(LinkError::CrossDevice),
        Origin::Temporary { linkable: true } if !node.linked => Ok(()),
        _ => Err(LinkError::Gone),
    }
}

/// Gives the file `handle`, which has no name, the name `path`: the
/// linkat(2) of an O_TMPFILE file. A named file gets a hard link from
/// [`create_link`] instead.
pub(crate) fn link_unnamed_stored(path: &[u8], handle: Handle) -> Result<(), LinkError> {
    if lookup_stored(path).is_some() {
        return Err(LinkError::Exists);
    }
    if let Some(upper) = overlayfs::prepare_upper(path) {
        return link_unnamed_stored(&upper.ok_or(LinkError::Failed)?, handle);
    }
    if blockfs::owns(handle) {
        if lookup_stored(path).is_some() {
            return Err(LinkError::Exists);
        }
        return blockfs::link_unnamed(path, handle).unwrap_or(Err(LinkError::Gone));
    }
    if blockfs::covers(path) {
        return Err(LinkError::CrossDevice);
    }
    valid_path(path).ok_or(LinkError::Failed)?;
    if lookup_stored(path).is_some() {
        return Err(LinkError::Exists);
    }
    read_node_field(handle, nameable).ok_or(LinkError::Gone)??;
    let mut stored = Some(stored_path(path).ok_or(LinkError::Failed)?);
    // A whiteout of the same name hides the image's entry; the file takes
    // its place by taking over the name.
    let hidden = hidden_stored(path);
    locked_with(|overlay, spares| {
        overlay.path_room(1)?;
        let Some(place) = overlay.find(handle) else {
            return Ok(Err(LinkError::Gone));
        };
        if let Some(Err(error)) = overlay.node_at(place).map(nameable) {
            return Ok(Err(error));
        }
        if let Some(named) = overlay.linked_place(path, true) {
            if !hidden || !overlay.node_at(named).is_some_and(|node| node.whiteout) {
                return Ok(Err(LinkError::Exists));
            }
            overlay.forget(named, spares);
        } else if hidden {
            return Ok(Err(LinkError::Failed));
        }
        let Some(node) = overlay.node_at_mut(place) else {
            return Ok(Err(LinkError::Gone));
        };
        let old = core::mem::replace(&mut node.path, stored.take().unwrap_or_default());
        node.linked = true;
        node.links = 1;
        // Named once, it is an ordinary file (Linux clears I_LINKABLE).
        node.origin = Origin::Named;
        spares.discard(Discard::Path(old));
        overlay.note_path(path);
        Ok(Ok(()))
    })
    .unwrap_or(Err(LinkError::Failed))
}

/// Whether the file `handle` still has a name.
pub(crate) fn linked(handle: Handle) -> bool {
    if overlayfs::owns(handle) {
        return overlayfs::linked(handle);
    }
    if blockfs::owns(handle) {
        return blockfs::linked(handle);
    }
    read_node_field(handle, |node| node.linked).unwrap_or(false)
}

/// Page `index` of paged file `handle`, which is handed out to be mapped:
/// allocated zeroed when `allocate` and it has never been written.
fn lend_page(handle: Handle, index: usize, allocate: bool) -> Option<FrameLease> {
    locked_with(|overlay, spares| {
        let Some(node) = overlay.get(handle).filter(|node| node.paged()) else {
            return Ok(None);
        };
        node.frames_lent = true;
        locked_page(node, index, allocate, spares)
    })
    .flatten()
}

/// Returns the frame that holds page `index` of a paged file (a memfd, or a
/// file mapped shared), allocating a zeroed one if the page has never been
/// written. Shared mappings map this frame directly; it lives until the
/// overlay is torn down with its domain.
pub(crate) fn memfd_frame(handle: Handle, index: usize) -> Option<FrameLease> {
    if blockfs::owns(handle) {
        return blockfs::cached_frame(handle, index, true);
    }
    lend_page(handle, index, true)
}

/// The frame holding page `index` of a paged file, if the page has one:
/// what a shared mapping of that page maps. Nothing is allocated.
pub(crate) fn paged_frame(handle: Handle, index: usize) -> Option<FrameLease> {
    if blockfs::owns(handle) {
        return blockfs::cached_frame(handle, index, false);
    }
    lend_page(handle, index, false)
}

/// Puts `replacement` in place of `expected` as the frame holding page
/// `index` of a paged file, as page migration does; false (and nothing
/// changed) if `expected` does not hold it. The caller keeps `expected`.
pub(crate) fn replace_paged_frame(
    handle: Handle,
    index: usize,
    expected: FrameLease,
    replacement: FrameLease,
) -> bool {
    // A volume's cached pages stay where they are.
    if blockfs::owns(handle) {
        return false;
    }
    locked(|overlay| {
        let Some(node) = overlay.get(handle).filter(|node| node.paged()) else {
            return false;
        };
        if node.first_page == FrameLease::EMPTY {
            return false;
        }
        let mut page = node.first_page;
        for _ in 0..index / FRAME_INDEX_CAPACITY {
            match next_page(page) {
                Some(next) if next != FrameLease::EMPTY => page = next,
                _ => return false,
            }
        }
        let Some(entries) = page_frame(page) else {
            return false;
        };
        let slot = index % FRAME_INDEX_CAPACITY;
        if index_entry(entries, slot) != expected {
            return false;
        }
        set_index_entry(entries, slot, replacement);
        true
    })
}

/// Whether process `pid` at `address` is the only shared mapping of the
/// page at `offset` of `handle` registered.
pub(crate) fn sole_shared_mapping(handle: Handle, offset: usize, pid: u32, address: u64) -> bool {
    locked(|overlay| {
        let mut found = false;
        for mapping in &overlay.mappings {
            if !mapping.active
                || mapping.handle != handle
                || mapping.offset / PAGE_SIZE != offset / PAGE_SIZE
            {
                continue;
            }
            if mapping.pid != pid || mapping.address != address {
                return false;
            }
            found = true;
        }
        found
    })
}

/// The paged file whose inode is `inode` (not a hard link's name for it):
/// the file a shared mapping recorded by inode maps.
pub(crate) fn paged_file(device: u64, inode: u64) -> Option<Handle> {
    // A file on a disk is a volume's, mapped through its page cache.
    if let Some(handle) = blockfs::cached_file(device, inode) {
        return Some(handle);
    }
    // Else an overlay file with that identity: the root filesystem's, or
    // a tmpfs's or ramfs's (each with its own device).
    locked(|overlay| {
        overlay
            .nodes()
            .find(|node| {
                node.active
                    && node.handle.inode == inode
                    && node.alias_of.is_none()
                    && node.kind == NodeKind::File
                    && node.paged()
                    && u64::from(crate::linux_mount_paths::device_of(&node.path)) == device
            })
            .map(|node| node.handle)
    })
}

/// Makes the unnamed node behind an anonymous shared mapping. Its pages are
/// allocated zeroed as they are first mapped (`memfd_frame`).
pub(crate) fn create_shmem() -> Option<Handle> {
    let handle = create_file_stored(b"tmp/.linox-shmem", 0o600, &[])?;
    let made = make_own_paged(handle)
        && change_node(handle, |node| {
            node.data = Data::Shmem;
            node.origin = Origin::Pseudo;
        });
    (unlink(handle) && made).then_some(handle)
}

/// Frees the anonymous shared memory that no process maps any more. Call
/// it once the pages of the mappings just unregistered are out of every
/// page table.
pub(crate) fn release_unmapped_shmem() {
    release_orphan_caches();
    // One node a lock hold, its data released after; the scan goes on
    // from where it was.
    let mut cursor = 0;
    loop {
        let next = locked_with(|overlay, spares| {
            let found = (cursor..overlay.slot_count()).find(|place| {
                overlay.node_at(*place).is_some_and(|node| {
                    node.active
                        && node.data == Data::Shmem
                        && !mapped_in(&overlay.mappings, node.handle)
                })
            });
            let Some(place) = found else {
                return Ok(None);
            };
            if let Some(node) = overlay.node_at_mut(place) {
                spares.detach(detach_data(node));
            }
            overlay.forget(place, spares);
            Ok(Some(place + 1))
        })
        .flatten();
        match next {
            Some(next) => cursor = next,
            None => return,
        }
    }
}

fn mapped_in(mappings: &[SharedMapping], handle: Handle) -> bool {
    mappings
        .iter()
        .any(|mapping| mapping.active && mapping.handle == handle)
}

/// Moves a file's data into whole frames, so every process that maps it
/// shared maps the same pages (as Linux maps the page cache), instead of a
/// copy written back at munmap. Already paged files stay as they are.
pub(crate) fn make_paged(handle: Handle) -> bool {
    if blockfs::owns(handle) {
        return blockfs::map_shared(handle);
    }
    read_node_field(handle, |node| node.kind) == Some(NodeKind::File) && make_own_paged(handle)
}

/// Moves overlay file `handle`'s data from its chain of data pages into a
/// frame index (see `make_paged`). The index is built with the lock
/// released, from copies of the chain's pages each taken under it, and put
/// in place of the chain if the file did not change meanwhile (its
/// `version`); else it is built again.
fn make_own_paged(handle: Handle) -> bool {
    for _ in 0..RETRY_LIMIT {
        let Some((paged, size, version)) =
            read_node_field(handle, |node| (node.paged(), node.size, node.version))
        else {
            return false;
        };
        if paged {
            return true;
        }
        let mut root = FrameLease::EMPTY;
        let mut buffer = [0_u8; PAGE_SIZE];
        let mut built = Some(true);
        for index in 0..size.div_ceil(PAGE_SIZE) {
            // The page's bytes, or Err when the file changed meanwhile.
            let copied = locked(|overlay| {
                let node = overlay.get(handle)?;
                if node.paged() || node.version != version {
                    return Some(Err(()));
                }
                read_chain(node, index * PAGE_SIZE, &mut buffer).map(Ok)
            });
            let length = match copied {
                Some(Ok(length)) => length,
                // Changed meanwhile: built again.
                Some(Err(())) => {
                    built = Some(false);
                    break;
                }
                None => {
                    built = None;
                    break;
                }
            };
            let Some(page) = detached_page(&mut root, index) else {
                built = None;
                break;
            };
            page.write_bytes(0, &buffer[..length]);
        }
        let chain = match built {
            Some(true) => locked(|overlay| {
                let node = overlay.get(handle)?;
                if node.paged() || node.version != version {
                    return Some(None);
                }
                let chain = node.first_page;
                node.first_page = root;
                node.last_page = FrameLease::EMPTY;
                node.page_count = 0;
                node.cached_page = FrameLease::EMPTY;
                node.cached_page_index = 0;
                node.data = Data::Paged;
                node.version = node.version.wrapping_add(1);
                Some(Some(chain))
            }),
            Some(false) => Some(None),
            None => None,
        };
        match chain {
            Some(Some(chain)) => {
                let _ = release_data_pages(chain);
                return true;
            }
            Some(None) => {
                let _ = release_frame_index(root);
            }
            None => {
                let _ = release_frame_index(root);
                return false;
            }
        }
    }
    false
}

pub(crate) fn file_seals(handle: Handle) -> Option<u32> {
    read_node_field(handle, |node| {
        (node.data == Data::Memfd).then_some(u32::from(node.seals))
    })
    .flatten()
}

pub(crate) fn add_file_seals(handle: Handle, seals: u32) -> Option<bool> {
    let seals = u8::try_from(seals).ok()?;
    locked(|overlay| {
        let node = overlay.get(handle)?;
        if node.data != Data::Memfd {
            return None;
        }
        // F_SEAL_SEAL forbids any further F_ADD_SEALS, even of nothing.
        if node.seals & 1 != 0 {
            return Some(false);
        }
        node.seals |= seals;
        Some(true)
    })
}

pub(crate) fn copy_path_stored(handle: Handle, output: &mut [u8]) -> Option<usize> {
    if overlayfs::owns(handle) {
        return overlayfs::copy_path(handle, output);
    }
    if blockfs::owns(handle) {
        return blockfs::copy_path(handle, output);
    }
    locked(|overlay| {
        let node = overlay.get(handle)?;
        output
            .get_mut(..node.path().len())?
            .copy_from_slice(node.path());
        Some(node.path().len())
    })
}

/// The overlay's entry after `cursor` directly below the canonical
/// directory path `directory` ("" for the root), whether or not the overlay
/// has a node for the directory itself: files created in a directory of the
/// image are overlay nodes below the image's directory.
pub(crate) fn next_child_at_stored(directory: &[u8], cursor: usize) -> Option<Option<Child>> {
    if let Some(next) = overlayfs::next_child_at(directory, cursor) {
        return next;
    }
    if let Some(next) = blockfs::next_child_at(directory, cursor) {
        return next;
    }
    // A child's path is the directory's, a slash (none below the root),
    // then its name.
    let name_below = |path: &[u8]| -> Option<(usize, usize)> {
        let rest = path.strip_prefix(directory)?;
        let rest = if directory.is_empty() {
            rest
        } else {
            rest.strip_prefix(b"/")?
        };
        Some((path.len() - rest.len(), rest.len()))
    };
    // The cursor is a node slot's place among all slots, which stays put
    // while nodes come and go (chunks are only appended): unlinking the
    // entries already read, as `rm -r` does between reads, moves none of
    // the rest past the cursor.
    locked(|overlay| {
        let mut found = None;
        let mut ordinal = 0_usize;
        'scan: for nodes in &overlay.nodes {
            if ordinal + nodes.len() <= cursor {
                ordinal += nodes.len();
                continue;
            }
            for (index, node) in nodes.iter().enumerate() {
                let place = ordinal + index;
                if place < cursor || !node.active || !node.linked || node.whiteout {
                    continue;
                }
                let Some((start, length)) = name_below(node.path()) else {
                    continue;
                };
                let remainder = &node.path()[start..start + length];
                // Storage roots are no directory's entries.
                if remainder.is_empty()
                    || remainder.contains(&b'/')
                    || remainder.first() == Some(&0)
                {
                    continue;
                }
                found = Some(place);
                break 'scan;
            }
            ordinal += nodes.len();
        }
        let Some(place) = found else {
            return Some(None);
        };
        let node = overlay.node_at(place)?;
        let (start, length) = name_below(node.path())?;
        let mut name = [0_u8; NAME_MAX];
        name.get_mut(..length)?
            .copy_from_slice(&node.path()[start..start + length]);
        let metadata = match node.alias_of {
            Some(file) => overlay.get(file)?.metadata(),
            None => node.metadata(),
        };
        Some(Some(Child {
            next_cursor: place + 1,
            metadata,
            name_length: length,
            name,
        }))
    })
}

pub(crate) fn create_file_stored(path: &[u8], mode: u32, initial: &[u8]) -> Option<Handle> {
    create(path, NodeKind::File, mode, initial, 0)
}

pub(crate) fn create_directory_stored(path: &[u8], mode: u32) -> Option<Handle> {
    create(path, NodeKind::Directory, mode, &[], 0)
}

pub(crate) fn create_symlink_stored(path: &[u8], target: &[u8]) -> Option<Handle> {
    create(path, NodeKind::Symlink, 0o777, target, 0)
}

pub(crate) fn create_fifo_stored(path: &[u8], mode: u32) -> Option<Handle> {
    create(path, NodeKind::Fifo, mode, &[], 0)
}

/// Creates the socket file a UNIX socket is bound to at `path`.
pub(crate) fn create_socket_stored(path: &[u8], mode: u32) -> Option<Handle> {
    create(path, NodeKind::Socket, mode, &[], 0)
}

/// Creates a device file at `path` for `device` (mknod S_IFCHR or S_IFBLK).
pub(crate) fn create_device_stored(
    path: &[u8],
    kind: NodeKind,
    mode: u32,
    device: u32,
) -> Option<Handle> {
    if !matches!(kind, NodeKind::CharacterDevice | NodeKind::BlockDevice) {
        return None;
    }
    create(path, kind, mode, &[], device)
}

pub(crate) fn fifo_socket(handle: Handle) -> Option<crate::linux_socket::SlotId> {
    if overlayfs::owns(handle) {
        return fifo_socket(overlayfs::real(handle)?);
    }
    if blockfs::owns(handle) {
        return blockfs::fifo_socket(handle).flatten();
    }
    read_node_field(handle, |node| {
        (node.kind == NodeKind::Fifo && node.fifo_socket != 0).then(|| node.fifo_socket - 1)
    })
    .flatten()
}

pub(crate) fn set_fifo_socket(handle: Handle, slot: crate::linux_socket::SlotId) -> bool {
    if overlayfs::owns(handle) {
        return overlayfs::real(handle).is_some_and(|real| set_fifo_socket(real, slot));
    }
    if blockfs::owns(handle) {
        return blockfs::set_fifo_socket(handle, slot).unwrap_or(false);
    }
    let Some(encoded) = slot.checked_add(1) else {
        return false;
    };
    locked(|overlay| {
        let Some(node) = overlay
            .get(handle)
            .filter(|node| node.kind == NodeKind::Fifo)
        else {
            return false;
        };
        node.fifo_socket = encoded;
        true
    })
}

/// Creates `new` at `path` on the volume it lies on, owned as the overlay's
/// files are.
fn create_on_volume(path: &[u8], new: blockfs::New, mode: u32) -> Option<Handle> {
    let directory = matches!(new, blockfs::New::Directory);
    let (owner, group, mode) = cpu::linux_new_file_identity(path, directory, mode);
    blockfs::create(path, new, mode, owner, group).flatten()
}

/// Creates a `kind` node at `path` (a device file's for `device`), holding
/// `initial`.
fn create(path: &[u8], kind: NodeKind, mode: u32, initial: &[u8], device: u32) -> Option<Handle> {
    if let Some(made) = overlayfs::create(path, kind == NodeKind::Directory, |upper| {
        create(upper, kind, mode, initial, device)
    }) {
        return made;
    }
    if blockfs::covers(path) {
        let new = match kind {
            NodeKind::File => blockfs::New::File(initial),
            NodeKind::Directory => blockfs::New::Directory,
            NodeKind::Symlink => blockfs::New::Symlink(initial),
            NodeKind::Fifo => blockfs::New::Fifo,
            NodeKind::Socket => blockfs::New::Socket,
            NodeKind::CharacterDevice | NodeKind::BlockDevice => blockfs::New::Device(kind, device),
        };
        return create_on_volume(path, new, mode);
    }
    // A new file's times are when it was made.
    let created = cpu::linux_realtime_now();
    valid_path(path)?;
    if lookup_stored(path).is_some() {
        return None;
    }
    let replace_whiteout = hidden_stored(path);
    let mut stored = Some(stored_path(path)?);
    // A new file belongs to its creator, or to a set-group-ID directory's
    // group.
    let (owner, group, mode) =
        cpu::linux_new_file_identity(path, kind == NodeKind::Directory, mode);
    // A tmpfs with nr_inodes= has room for so many files (ENOSPC).
    let instance = cpu::current_linux_execution_instance();
    if !tmpfs_quota::charge(instance, path, 0, 1) {
        return None;
    }
    let made = locked_with(|overlay, spares| {
        let (Some(generation), Some(inode)) = (
            overlay.next_generation.checked_add(1),
            overlay.next_inode.checked_add(1),
        ) else {
            return Ok(None);
        };
        overlay.path_room(1)?;
        overlay.node_room()?;
        // Over a whiteout of that name the node takes the whiteout's slot.
        let place = match overlay.linked_place(path, true) {
            Some(place)
                if replace_whiteout && overlay.node_at(place).is_some_and(|n| n.whiteout) =>
            {
                place
            }
            Some(_) => return Ok(None),
            None if replace_whiteout => return Ok(None),
            None => overlay.free_place(spares)?,
        };
        let handle = Handle { generation, inode };
        let node = Node {
            active: true,
            linked: true,
            whiteout: false,
            origin: Origin::Named,
            data: Data::Chain,
            kind,
            mode: mode & 0o7777,
            owner,
            group,
            alias_of: None,
            links: 1,
            device,
            seals: 0,
            attributes: 0,
            fifo_socket: 0,
            charged: 0,
            frames_lent: false,
            huge: false,
            huge_pages: 0,
            handle,
            size: 0,
            version: 0,
            first_page: FrameLease::EMPTY,
            last_page: FrameLease::EMPTY,
            page_count: 0,
            cached_page: FrameLease::EMPTY,
            cached_page_index: 0,
            xattrs: Vec::new(),
            atime: created,
            mtime: created,
            ctime: created,
            path: stored.take().unwrap_or_default(),
        };
        overlay.fill(place, node, spares);
        overlay.note_path(path);
        let _ = overlay.node_hints.insert(inode, place);
        overlay.next_generation = generation;
        overlay.next_inode = inode;
        if kind == NodeKind::Symlink {
            overlay.symlinks += 1;
        }
        Ok(Some(handle))
    })
    .flatten();
    let Some(handle) = made else {
        tmpfs_quota::release(instance, path, 0, 1);
        return None;
    };
    if !initial.is_empty() && write(handle, 0, initial) != Some(initial.len()) {
        let _ = unlink(handle);
        return None;
    }
    Some(handle)
}

pub(crate) fn whiteout_stored(path: &[u8]) -> bool {
    if valid_path(path).is_none() || blockfs::covers(path) || overlayfs::covers(path) {
        return false;
    }
    let has_node = lookup_stored(path).is_some() || hidden_stored(path);
    let mut stored = if has_node {
        None
    } else {
        match stored_path(path) {
            Some(stored) => Some(stored),
            None => return false,
        }
    };
    locked_with(|overlay, spares| {
        if has_node {
            let Some(place) = overlay.linked_place(path, true) else {
                return Ok(false);
            };
            let Some(node) = overlay.node_at_mut(place) else {
                return Ok(false);
            };
            spares.detach(detach_data(node));
            let xattrs = core::mem::take(&mut node.xattrs);
            node.size = 0;
            node.linked = true;
            node.whiteout = true;
            spares.discard(Discard::Xattrs(xattrs));
            return Ok(true);
        }
        let (Some(generation), Some(inode)) = (
            overlay.next_generation.checked_add(1),
            overlay.next_inode.checked_add(1),
        ) else {
            return Ok(false);
        };
        overlay.path_room(1)?;
        overlay.node_room()?;
        if overlay.linked_place(path, true).is_some() {
            return Ok(false);
        }
        let place = overlay.free_place(spares)?;
        let node = Node {
            active: true,
            linked: true,
            whiteout: true,
            handle: Handle { generation, inode },
            path: stored.take().unwrap_or_default(),
            ..Node::EMPTY
        };
        overlay.fill(place, node, spares);
        overlay.note_path(path);
        let _ = overlay.node_hints.insert(inode, place);
        overlay.next_generation = generation;
        overlay.next_inode = inode;
        Ok(true)
    })
    .unwrap_or(false)
}

/// Whether nodes of `kind` hold no data to read or write.
fn holds_no_data(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::Directory
            | NodeKind::Fifo
            | NodeKind::Socket
            | NodeKind::CharacterDevice
            | NodeKind::BlockDevice
    )
}

pub(crate) fn read(handle: Handle, offset: usize, output: &mut [u8]) -> Option<usize> {
    if overlayfs::owns(handle) {
        return read(overlayfs::real(handle)?, offset, output);
    }
    if blockfs::owns(handle) {
        return blockfs::read(handle, offset, output);
    }
    locked_with(|overlay, _| {
        let Some(node) = overlay.get(handle) else {
            return Ok(None);
        };
        if holds_no_data(node.kind) {
            return Ok(None);
        }
        read_node(node, offset, output)
    })
    .flatten()
}

/// Reads `node`'s data at `offset` into `output`, under the lock: a page
/// of a paged file out in swap is asked back.
fn read_node(node: &mut Node, offset: usize, output: &mut [u8]) -> Result<Option<usize>, Need> {
    let start = offset.min(node.size);
    let end = start.saturating_add(output.len()).min(node.size);
    if node.paged() {
        let mut position = start;
        while position < end {
            let within = position % PAGE_SIZE;
            let length = (end - position).min(PAGE_SIZE - within);
            let target = &mut output[position - start..position - start + length];
            match page_state(node, position / PAGE_SIZE) {
                PageState::Present(frame) => match Frame::leased(frame) {
                    Some(page) => page.read_bytes(within, target),
                    None => target.fill(0),
                },
                PageState::Swapped => return Err(Need::SwapIn(node.handle, position / PAGE_SIZE)),
                PageState::Missing(_) => target.fill(0),
            }
            position += length;
        }
        return Ok(Some(end - start));
    }
    Ok(read_chain(node, offset, output))
}

/// Reads chain file `node`'s data at `offset` into `output`.
fn read_chain(node: &mut Node, offset: usize, output: &mut [u8]) -> Option<usize> {
    let start = offset.min(node.size);
    let end = start.saturating_add(output.len()).min(node.size);
    let target_page = start / DATA_CAPACITY;
    let (mut page, mut page_index) =
        if node.cached_page != FrameLease::EMPTY && node.cached_page_index <= target_page {
            (node.cached_page, node.cached_page_index)
        } else {
            (node.first_page, 0)
        };
    while page_index < target_page {
        page = next_page(page)?;
        page_index += 1;
    }
    node.cached_page = page;
    node.cached_page_index = page_index;
    let mut skipped = page_index * DATA_CAPACITY;
    let mut copied = 0;
    while start + copied < end {
        let data = page_frame(page)?;
        let page_offset = start + copied - skipped;
        let length = (end - start - copied).min(DATA_CAPACITY - page_offset);
        data.read_bytes(
            LEASE_SIZE + page_offset,
            &mut output[copied..copied + length],
        );
        copied += length;
        skipped += DATA_CAPACITY;
        page = read_lease(data, 0);
    }
    Some(copied)
}

/// Writes `input` at `offset` of the file at `handle`, which marks it
/// modified now (its mtime and ctime), as a Linux write does.
pub(crate) fn write(handle: Handle, offset: usize, input: &[u8]) -> Option<usize> {
    if overlayfs::owns(handle) {
        return write(overlayfs::copy_up(handle)?, offset, input);
    }
    if blockfs::owns(handle) {
        return blockfs::write(handle, offset, input);
    }
    let end = offset.checked_add(input.len())?;
    if input.is_empty() {
        return Some(0);
    }
    if !charge_size(handle, offset, end) {
        return None;
    }
    let now = cpu::linux_realtime_now();
    locked_with(|overlay, spares| {
        let Some(node) = overlay.get(handle) else {
            return Ok(None);
        };
        if holds_no_data(node.kind) {
            return Ok(None);
        }
        let written = write_node(node, offset, input, spares)?;
        if written.is_some() {
            node.mtime = now;
            node.ctime = now;
        }
        Ok(written)
    })
    .flatten()
}

/// Writes `input` at `offset` of `node`'s data, under the lock, with frames
/// from `spares` (asked for first, as are pages out in swap).
fn write_node(
    node: &mut Node,
    offset: usize,
    input: &[u8],
    spares: &mut Spares,
) -> Result<Option<usize>, Need> {
    let end = offset + input.len();
    if node.paged() {
        let needed = range_state(node, offset / PAGE_SIZE..end.div_ceil(PAGE_SIZE))?;
        spares.frames_for(needed)?;
        node.version = node.version.wrapping_add(1);
        let mut position = offset;
        while position < end {
            let within = position % PAGE_SIZE;
            let length = (end - position).min(PAGE_SIZE - within);
            let Some(page) =
                locked_page(node, position / PAGE_SIZE, true, spares)?.and_then(Frame::leased)
            else {
                return Ok(None);
            };
            page.write_bytes(
                within,
                &input[position - offset..position - offset + length],
            );
            position += length;
        }
        node.size = node.size.max(end);
        return Ok(Some(input.len()));
    }
    let required = end.div_ceil(DATA_CAPACITY);
    spares.frames_for(required.saturating_sub(node.page_count))?;
    node.version = node.version.wrapping_add(1);
    if ensure_data_pages(node, required, spares).is_none() {
        return Ok(None);
    }
    let target_page = offset / DATA_CAPACITY;
    let (mut page, mut page_index) =
        if node.cached_page != FrameLease::EMPTY && node.cached_page_index <= target_page {
            (node.cached_page, node.cached_page_index)
        } else {
            (node.first_page, 0)
        };
    while page_index < target_page {
        let Some(next) = next_page(page) else {
            return Ok(None);
        };
        page = next;
        page_index += 1;
    }
    node.cached_page = page;
    node.cached_page_index = page_index;
    let mut skipped = page_index * DATA_CAPACITY;
    let mut copied = 0;
    while copied < input.len() {
        let Some(data) = page_frame(page) else {
            return Ok(None);
        };
        let page_offset = offset + copied - skipped;
        let length = (input.len() - copied).min(DATA_CAPACITY - page_offset);
        data.write_bytes(LEASE_SIZE + page_offset, &input[copied..copied + length]);
        copied += length;
        skipped += DATA_CAPACITY;
        page = read_lease(data, 0);
    }
    node.size = node.size.max(end);
    Ok(Some(input.len()))
}

pub(crate) fn truncate(handle: Handle, size: usize) -> bool {
    if overlayfs::owns(handle) {
        return overlayfs::copy_up(handle).is_some_and(|real| truncate(real, size));
    }
    if blockfs::owns(handle) {
        return blockfs::truncate(handle, size).unwrap_or(false);
    }
    let mut path = PathCopy::new();
    let outcome = locked_with(|overlay, spares| {
        let Some(node) = overlay.get(handle) else {
            return Ok(None);
        };
        if node.kind != NodeKind::File {
            return Ok(None);
        }
        // What it takes, before anything changes: the pages whose cut-off
        // bytes are zeroed back from swap, or frames to grow the chain.
        if node.paged() {
            range_state(node, size / PAGE_SIZE..node.size.div_ceil(PAGE_SIZE))?;
        } else if size > node.size {
            spares.frames_for(size.div_ceil(DATA_CAPACITY).saturating_sub(node.page_count))?;
        }
        node.version = node.version.wrapping_add(1);
        // A tmpfs file that shrinks gives its blocks back (growing leaves a
        // hole, which uses none).
        let kept = size.div_ceil(tmpfs_quota::BLOCK_SIZE as usize) as u32;
        let mut released = 0;
        if kept < node.charged {
            released = node.charged - kept;
            node.charged = kept;
            path.set(node.path());
        }
        if node.paged() {
            // Frames stay allocated when a paged file shrinks, since
            // processes may still map them; the cut-off bytes are zeroed so
            // the file reads back as zeros if it grows again.
            let mut position = size;
            while position < node.size {
                let within = position % PAGE_SIZE;
                let length = (node.size - position).min(PAGE_SIZE - within);
                if let PageState::Present(frame) = page_state(node, position / PAGE_SIZE) {
                    if let Some(page) = Frame::leased(frame) {
                        page.fill_bytes(within, length, 0);
                    }
                }
                position += length;
            }
            node.size = size;
            return Ok(Some((true, released)));
        }
        if size > node.size {
            if ensure_data_pages(node, size.div_ceil(DATA_CAPACITY), spares).is_none() {
                return Ok(Some((false, released)));
            }
        } else if size == 0 {
            spares.detach(detach_data(node));
        } else if size < node.size {
            // The cut-off bytes are zeroed so the file reads back as zeros
            // if it grows again (ftruncate01).
            let mut page = node.first_page;
            let mut page_index = 0;
            let mut position = size;
            while position < node.size {
                while page_index < position / DATA_CAPACITY {
                    let Some(next) = next_page(page) else {
                        return Ok(Some((false, released)));
                    };
                    page = next;
                    page_index += 1;
                }
                let Some(data) = page_frame(page) else {
                    return Ok(Some((false, released)));
                };
                let within = position % DATA_CAPACITY;
                let length = (node.size - position).min(DATA_CAPACITY - within);
                data.fill_bytes(LEASE_SIZE + within, length, 0);
                position += length;
            }
        }
        node.size = size;
        Ok(Some((true, released)))
    })
    .flatten();
    let Some((done, released)) = outcome else {
        return false;
    };
    if released != 0 {
        tmpfs_quota::release(
            cpu::current_linux_execution_instance(),
            path.get(),
            u64::from(released),
            0,
        );
    }
    done
}

pub(crate) fn set_mode(handle: Handle, mode: u32) -> bool {
    if overlayfs::owns(handle) {
        return overlayfs::copy_up(handle).is_some_and(|real| set_mode(real, mode));
    }
    if blockfs::owns(handle) {
        return blockfs::set_mode(handle, mode).unwrap_or(false);
    }
    change_node(handle, |node| node.mode = mode & 0o7777)
}

/// Sets a file's attributes (FS_IOC_SETFLAGS): FS_*_FL bits, of which
/// the file keeps those that fit a byte.
pub(crate) fn set_attributes(handle: Handle, attributes: u32) -> bool {
    if overlayfs::owns(handle) {
        return overlayfs::copy_up(handle).is_some_and(|real| set_attributes(real, attributes));
    }
    if blockfs::owns(handle) {
        return blockfs::set_attributes(handle, attributes).unwrap_or(false);
    }
    change_node(handle, |node| node.attributes = attributes as u8)
}

pub(crate) fn set_owner(handle: Handle, owner: u32, group: u32) -> bool {
    if overlayfs::owns(handle) {
        return overlayfs::copy_up(handle).is_some_and(|real| set_owner(real, owner, group));
    }
    if blockfs::owns(handle) {
        return blockfs::set_owner(handle, owner, group).unwrap_or(false);
    }
    change_node(handle, |node| {
        node.owner = owner;
        node.group = group;
    })
}

/// Marks the file at `handle` modified at `time` (its mtime and ctime).
pub(crate) fn touch_modified(handle: Handle, time: (i64, i64)) -> bool {
    if overlayfs::owns(handle) {
        return overlayfs::copy_up(handle).is_some_and(|real| touch_modified(real, time));
    }
    if blockfs::owns(handle) {
        return blockfs::touch_modified(handle, time).unwrap_or(false);
    }
    change_node(handle, |node| {
        node.mtime = time;
        node.ctime = time;
    })
}

/// Sets `handle`'s access time alone, as a read does: an overlay file's
/// in the layer it reads from, with no copy-up.
pub(crate) fn touch_accessed(handle: Handle, time: (i64, i64)) -> bool {
    if overlayfs::owns(handle) {
        return overlayfs::real(handle).is_some_and(|real| touch_accessed(real, time));
    }
    if blockfs::owns(handle) {
        return blockfs::touch_accessed(handle, time).unwrap_or(false);
    }
    change_node(handle, |node| node.atime = time)
}

pub(crate) fn set_times(handle: Handle, atime: (i64, i64), mtime: (i64, i64)) -> bool {
    if overlayfs::owns(handle) {
        return overlayfs::copy_up(handle).is_some_and(|real| set_times(real, atime, mtime));
    }
    if blockfs::owns(handle) {
        return blockfs::set_times(handle, atime, mtime).unwrap_or(false);
    }
    change_node(handle, |node| {
        node.atime = atime;
        node.mtime = mtime;
        node.ctime = mtime;
    })
}

pub(crate) fn set_xattr_from<F>(
    handle: Handle,
    name: &[u8],
    value_size: usize,
    create_only: bool,
    replace_only: bool,
    mut fill: F,
) -> bool
where
    F: FnMut(usize, &mut [u8]) -> bool,
{
    if overlayfs::owns(handle) {
        return overlayfs::copy_up(handle).is_some_and(|real| {
            set_xattr_from(real, name, value_size, create_only, replace_only, fill)
        });
    }
    if blockfs::owns(handle) {
        return blockfs::set_xattr_from(handle, name, value_size, create_only, replace_only, fill)
            .unwrap_or(false);
    }
    if name.is_empty()
        || name.len() > XATTR_NAME_CAPACITY
        || name.contains(&0)
        || u32::try_from(value_size).is_err()
    {
        return false;
    }
    let exists = read_node_field(handle, |node| node.xattr(name).is_some()).unwrap_or(false);
    if create_only && exists || replace_only && !exists {
        return false;
    }
    let mut value = Vec::new();
    if value.try_reserve_exact(value_size).is_err() {
        return false;
    }
    value.resize(value_size, 0);
    if value_size != 0 && !fill(0, &mut value) {
        return false;
    }
    set_xattr(handle, name, value)
}

/// Sets extended attribute `name` of `handle` to `value`, as the most
/// recently set one.
fn set_xattr(handle: Handle, name: &[u8], value: Vec<u8>) -> bool {
    let mut stored_name = Vec::new();
    if stored_name.try_reserve_exact(name.len()).is_err() {
        return false;
    }
    stored_name.extend_from_slice(name);
    let mut record = Some(Xattr {
        name: stored_name,
        value,
    });
    locked_with(|overlay, spares| {
        let Some(node) = overlay.get(handle) else {
            return Ok(false);
        };
        match node.xattrs.iter().position(|record| record.name == name) {
            Some(index) => {
                let old = node.xattrs.remove(index);
                spares.discard(Discard::Xattr(old));
            }
            None if node.xattrs.len() == node.xattrs.capacity() => {
                return Err(Need::Xattr(handle));
            }
            None => {}
        }
        if let Some(record) = record.take() {
            node.xattrs.push(record);
        }
        Ok(true)
    })
    .unwrap_or(false)
}

pub(crate) fn get_xattr_chunk(
    handle: Handle,
    name: &[u8],
    offset: usize,
    output: &mut [u8],
) -> Option<(usize, usize)> {
    if overlayfs::owns(handle) {
        return get_xattr_chunk(overlayfs::real(handle)?, name, offset, output);
    }
    if blockfs::owns(handle) {
        return blockfs::get_xattr_chunk(handle, name, offset, output).flatten();
    }
    locked(|overlay| {
        let value = &overlay.get(handle)?.xattr(name)?.value;
        let size = value.len();
        if offset >= size || output.is_empty() {
            return Some((size, 0));
        }
        let copied = output.len().min(size - offset);
        output[..copied].copy_from_slice(&value[offset..offset + copied]);
        Some((size, copied))
    })
}

pub(crate) fn list_xattrs_chunk(
    handle: Handle,
    offset: usize,
    output: &mut [u8],
) -> Option<(usize, usize)> {
    if overlayfs::owns(handle) {
        return list_xattrs_chunk(overlayfs::real(handle)?, offset, output);
    }
    if blockfs::owns(handle) {
        return blockfs::list_xattrs_chunk(handle, offset, output).flatten();
    }
    locked(|overlay| {
        let node = overlay.get(handle)?;
        let mut used: usize = 0;
        let mut copied: usize = 0;
        // Most recently set first, each name NUL-terminated.
        for record in node.xattrs.iter().rev() {
            let length = record.name.len().checked_add(1)?;
            let end = used.checked_add(length)?;
            let copy_start = offset.max(used);
            let copy_end = end.min(offset.saturating_add(output.len()));
            if copy_start < copy_end {
                for source_index in copy_start - used..copy_end - used {
                    output[copied] = record.name.get(source_index).copied().unwrap_or(0);
                    copied += 1;
                }
            }
            used = end;
        }
        Some((used, copied))
    })
}

pub(crate) fn remove_xattr(handle: Handle, name: &[u8]) -> bool {
    if overlayfs::owns(handle) {
        return overlayfs::copy_up(handle).is_some_and(|real| remove_xattr(real, name));
    }
    if blockfs::owns(handle) {
        return blockfs::remove_xattr(handle, name).unwrap_or(false);
    }
    locked_with(|overlay, spares| {
        let Some(node) = overlay.get(handle) else {
            return Ok(false);
        };
        let Some(index) = node.xattrs.iter().position(|record| record.name == name) else {
            return Ok(false);
        };
        let old = node.xattrs.remove(index);
        spares.discard(Discard::Xattr(old));
        Ok(true)
    })
    .unwrap_or(false)
}

pub(crate) fn rename_stored(handle: Handle, path: &[u8]) -> bool {
    if overlayfs::owns(handle) {
        let mut from = [0_u8; PATH_CAPACITY];
        return copy_path_stored(handle, &mut from).is_some_and(|length| {
            overlayfs::rename(&from[..length], path, overlayfs::RenameMode::Replace)
                .is_some_and(|result| result.is_ok())
        });
    }
    if blockfs::owns(handle) {
        let done = blockfs::rename(handle, path).unwrap_or(false);
        cpu::linux_reclaim_unlinked_files();
        return done;
    }
    if blockfs::covers(path) {
        return false;
    }
    if valid_path(path).is_none() || lookup_stored(path).is_some() {
        return false;
    }
    for _ in 0..RETRY_LIMIT {
        if let Some(done) = rename_once(handle, path) {
            return done;
        }
    }
    false
}

/// A node a rename moves: where it is, which it is, and how long the rest
/// of its path after the renamed node's is.
struct Moved {
    place: usize,
    handle: Handle,
    suffix: usize,
}

/// Renames node `handle` to `path`, with everything below it when it is a
/// directory: what moves is copied out under the lock, the new paths are
/// made (and checked free) with it released, and they are put in place
/// under it if the same nodes are still at the same paths. `None` when
/// they were not: the caller starts again.
fn rename_once(handle: Handle, path: &[u8]) -> Option<bool> {
    let sizes = locked(|overlay| {
        let place = overlay.find(handle)?;
        let source = overlay.node_at(place).filter(|node| node.linked)?;
        let directory = source.kind == NodeKind::Directory;
        let (mut count, mut bytes) = (0, 0);
        for candidate in overlay.nodes() {
            if let Some(suffix) = renamed_suffix(candidate, handle, source.path(), directory) {
                count += 1;
                bytes += suffix.len();
            }
        }
        Some((source.path().len(), count, bytes))
    });
    let Some((old_length, count, bytes)) = sizes else {
        return Some(false);
    };
    let mut old_path = Vec::new();
    let mut suffixes = Vec::new();
    let mut moved = Vec::new();
    if old_path.try_reserve_exact(old_length).is_err()
        || suffixes.try_reserve_exact(bytes).is_err()
        || moved.try_reserve_exact(count).is_err()
    {
        return Some(false);
    }
    let (old_path, suffixes, moved, copied) = locked(move |overlay| {
        let copied = copy_moved(overlay, handle, &mut old_path, &mut suffixes, &mut moved);
        (old_path, suffixes, moved, copied)
    });
    match copied {
        None => return Some(false),
        Some(false) => return None,
        Some(true) => {}
    }
    // Every new path is made, and checked free, before any node moves, so
    // a taken name or a short heap leaves everything as it was.
    let mut new_paths = Vec::new();
    let mut old_paths = Vec::new();
    if new_paths.try_reserve_exact(moved.len()).is_err()
        || old_paths.try_reserve_exact(moved.len()).is_err()
    {
        return Some(false);
    }
    let mut start = 0;
    for entry in &moved {
        let suffix = &suffixes[start..start + entry.suffix];
        start += entry.suffix;
        let new_path = stored_joined(&[path, suffix])
            .filter(|new_path| new_path.len() < PATH_CAPACITY)
            .filter(|new_path| suffix.is_empty() || lookup_stored(new_path).is_none());
        let Some(new_path) = new_path else {
            return Some(false);
        };
        new_paths.push(new_path);
    }
    let outcome = locked_with(|overlay, _| {
        overlay.path_room(moved.len())?;
        let Some(place) = overlay.find(handle) else {
            return Ok(Some(false));
        };
        let Some(source) = overlay
            .node_at(place)
            .filter(|node| node.linked && node.path() == old_path.as_slice())
        else {
            return Ok(None);
        };
        let directory = source.kind == NodeKind::Directory;
        let current = overlay
            .nodes()
            .filter(|candidate| renamed_suffix(candidate, handle, &old_path, directory).is_some())
            .count();
        if current != moved.len() {
            return Ok(None);
        }
        let mut start = 0;
        for entry in &moved {
            let suffix = &suffixes[start..start + entry.suffix];
            start += entry.suffix;
            let same = overlay.node_at(entry.place).is_some_and(|node| {
                node.active
                    && node.linked
                    && node.handle == entry.handle
                    && node.path().strip_prefix(old_path.as_slice()) == Some(suffix)
            });
            if !same {
                return Ok(None);
            }
        }
        for (entry, new_path) in moved.iter().zip(new_paths.drain(..)) {
            let key = path_key(&new_path);
            match overlay.node_at_mut(entry.place) {
                Some(node) => old_paths.push(core::mem::replace(&mut node.path, new_path)),
                None => old_paths.push(new_path),
            }
            overlay.note_key(key);
        }
        Ok(Some(true))
    });
    match outcome {
        None => Some(false),
        Some(outcome) => outcome,
    }
}

/// Copies what renaming node `handle` moves (see `rename_once`) into
/// `old_path`, `suffixes` and `moved`, within the room they have: `None`
/// if the node is gone or unlinked, `Some(false)` if the room fell short.
fn copy_moved(
    overlay: &mut Overlay,
    handle: Handle,
    old_path: &mut Vec<u8>,
    suffixes: &mut Vec<u8>,
    moved: &mut Vec<Moved>,
) -> Option<bool> {
    let place = overlay.find(handle)?;
    let source = overlay.node_at(place).filter(|node| node.linked)?;
    let directory = source.kind == NodeKind::Directory;
    if source.path().len() > old_path.capacity() {
        return Some(false);
    }
    old_path.extend_from_slice(source.path());
    for (candidate_place, candidate) in overlay.nodes().enumerate() {
        let Some(suffix) = renamed_suffix(candidate, handle, source.path(), directory) else {
            continue;
        };
        if moved.len() == moved.capacity() || suffixes.capacity() - suffixes.len() < suffix.len() {
            return Some(false);
        }
        suffixes.extend_from_slice(suffix);
        moved.push(Moved {
            place: candidate_place,
            handle: candidate.handle,
            suffix: suffix.len(),
        });
    }
    Some(true)
}

/// What follows `old_path` in the path of `candidate` when renaming the
/// node `handle` (at `old_path`) moves it: empty for that node itself, the
/// rest of the path for everything below it when it is a directory.
fn renamed_suffix<'a>(
    candidate: &'a Node,
    handle: Handle,
    old_path: &[u8],
    directory: bool,
) -> Option<&'a [u8]> {
    if !candidate.active || !candidate.linked {
        return None;
    }
    if candidate.handle == handle {
        return Some(&[]);
    }
    let suffix = candidate.path().strip_prefix(old_path)?;
    (directory && suffix.starts_with(b"/")).then_some(suffix)
}

/// Gives the file `target` (not a directory) another name, `path`: a hard
/// link. Both names then reach the same data, owner and mode.
pub(crate) fn create_link_stored(path: &[u8], target: Handle) -> bool {
    if let Some(linked) = overlayfs::create_link(path, target) {
        return linked;
    }
    if overlayfs::covers(path) {
        return false;
    }
    if blockfs::owns(target) {
        return blockfs::create_link(path, target).unwrap_or(false);
    }
    if blockfs::covers(path) {
        return false;
    }
    if valid_path(path).is_none() || lookup_stored(path).is_some() {
        return false;
    }
    let linkable =
        |file: &Node| file.kind != NodeKind::Directory && file.linked && file.alias_of.is_none();
    if read_node_field(target, linkable) != Some(true) {
        return false;
    }
    let replace_whiteout = hidden_stored(path);
    let Some(stored) = stored_path(path) else {
        return false;
    };
    let mut stored = Some(stored);
    locked_with(|overlay, spares| {
        let Some(generation) = overlay.next_generation.checked_add(1) else {
            return Ok(false);
        };
        overlay.path_room(1)?;
        overlay.node_room()?;
        let place = match overlay.linked_place(path, true) {
            Some(place)
                if replace_whiteout && overlay.node_at(place).is_some_and(|n| n.whiteout) =>
            {
                place
            }
            Some(_) => return Ok(false),
            None if replace_whiteout => return Ok(false),
            None => overlay.free_place(spares)?,
        };
        let Some(kind) = overlay
            .get(target)
            .filter(|file| linkable(file))
            .map(|file| file.kind)
        else {
            return Ok(false);
        };
        let alias = Node {
            active: true,
            linked: true,
            kind,
            alias_of: Some(target),
            handle: Handle {
                generation,
                inode: target.inode,
            },
            path: stored.take().unwrap_or_default(),
            ..Node::EMPTY
        };
        overlay.fill(place, alias, spares);
        overlay.note_path(path);
        overlay.next_generation = generation;
        if let Some(file) = overlay.get(target) {
            file.links = file.links.saturating_add(1);
        }
        Ok(true)
    })
    .unwrap_or(false)
}

/// What `unlink_path_stored` found to do under the lock.
enum Unlinked {
    Done(bool),
    /// The file's last name: unlinked as `unlink` does.
    File(Handle),
}

/// Removes the name `path`. A file with other names keeps its data under
/// them: removing an alias drops just that name, and removing the file's
/// own node moves one alias's name onto it. Directories and files with one
/// name go as `unlink` does.
pub(crate) fn unlink_path_stored(path: &[u8]) -> bool {
    if let Some(removed) = overlayfs::remove(path) {
        cpu::linux_reclaim_unlinked_files();
        return removed;
    }
    if let Some(removed) = blockfs::unlink_path(path) {
        cpu::linux_reclaim_unlinked_files();
        return removed;
    }
    let outcome = locked_with(|overlay, spares| {
        let Some(place) = overlay.linked_place(path, false) else {
            return Ok(Unlinked::Done(false));
        };
        let Some((handle, alias_of)) = overlay
            .node_at(place)
            .map(|node| (node.handle, node.alias_of))
        else {
            return Ok(Unlinked::Done(false));
        };
        // An alias: that name goes, and one name of the file.
        if let Some(file) = alias_of {
            overlay.forget(place, spares);
            if let Some(file) = overlay.get(file) {
                file.links = file.links.saturating_sub(1).max(1);
            }
            return Ok(Unlinked::Done(true));
        }
        let alias = overlay
            .nodes()
            .position(|node| node.active && node.linked && node.alias_of == Some(handle));
        let Some(alias) = alias else {
            return Ok(Unlinked::File(handle));
        };
        overlay.path_room(1)?;
        // The file moves into the alias's slot under the alias's name, and
        // its own slot goes. The name stays where it was among the slots,
        // which is a directory listing's cursor (`next_child_at`): `rm -r`,
        // removing what it has read, still meets the names after it.
        let Some(alias_path) = overlay
            .node_at_mut(alias)
            .map(|node| core::mem::take(&mut node.path))
        else {
            return Ok(Unlinked::Done(false));
        };
        let Some(file_slot) = overlay.node_at_mut(place) else {
            if let Some(node) = overlay.node_at_mut(alias) {
                node.path = alias_path;
            }
            return Ok(Unlinked::Done(false));
        };
        let mut moved = core::mem::replace(file_slot, Node::EMPTY);
        let key = path_key(&alias_path);
        let file_path = core::mem::replace(&mut moved.path, alias_path);
        moved.links = moved.links.saturating_sub(1).max(1);
        spares.discard(Discard::Path(file_path));
        overlay.fill(alias, moved, spares);
        overlay.note_key(key);
        let _ = overlay.node_hints.insert(handle.inode, alias);
        Ok(Unlinked::Done(true))
    });
    match outcome {
        Some(Unlinked::Done(done)) => done,
        Some(Unlinked::File(file)) => unlink_own(file),
        None => false,
    }
}

/// Renames the name `from` to `to`: an alias moves alone; a file's own node
/// (or a directory, with everything under it) as `rename` does.
pub(crate) fn rename_path_stored(from: &[u8], to: &[u8]) -> bool {
    if let Some(renamed) = overlayfs::rename(from, to, overlayfs::RenameMode::Replace) {
        cpu::linux_reclaim_unlinked_files();
        return renamed.is_ok();
    }
    if overlayfs::covers(to) {
        return false;
    }
    if let Some(renamed) = blockfs::rename_path(from, to) {
        cpu::linux_reclaim_unlinked_files();
        return renamed;
    }
    if blockfs::covers(to) {
        return false;
    }
    if valid_path(to).is_none() || lookup_stored(to).is_some() {
        return false;
    }
    let named = locked(|overlay| {
        let place = overlay.linked_place(from, false)?;
        overlay
            .node_at(place)
            .map(|node| (node.handle, node.alias_of))
    });
    let Some((handle, alias_of)) = named else {
        return false;
    };
    if alias_of.is_none() {
        return rename_stored(handle, to);
    }
    let Some(stored) = stored_path(to) else {
        return false;
    };
    let mut stored = Some(stored);
    locked_with(|overlay, spares| {
        overlay.path_room(1)?;
        let Some(node) = overlay
            .get(handle)
            .filter(|node| node.linked && node.path() == from)
        else {
            return Ok(false);
        };
        let old = core::mem::replace(&mut node.path, stored.take().unwrap_or_default());
        spares.discard(Discard::Path(old));
        overlay.note_path(to);
        Ok(true)
    })
    .unwrap_or(false)
}

/// Removes everything below the directory `path`, as unmounting a tmpfs
/// from it drops what was created there. Open files stay readable until
/// closed, as after unlink.
pub(crate) fn unlink_below_stored(path: &[u8]) {
    let below = |node: &Node| {
        node.active
            && node.linked
            && node
                .path()
                .strip_prefix(path)
                .is_some_and(|rest| rest.starts_with(b"/"))
    };
    for _ in 0..RETRY_LIMIT {
        let files = locked(|overlay| {
            overlay
                .nodes()
                .filter(|node| below(node) && node.alias_of.is_none())
                .count()
        });
        let mut unlinked = Vec::new();
        if unlinked.try_reserve_exact(files).is_err() {
            return;
        }
        let done = locked_with(|overlay, spares| {
            let files = overlay
                .nodes()
                .filter(|node| below(node) && node.alias_of.is_none())
                .count();
            if files > unlinked.capacity() - unlinked.len() {
                return Ok(false);
            }
            let mut symlinks_removed = 0;
            for place in 0..overlay.slot_count() {
                let Some((alias, symlink)) =
                    overlay
                        .node_at(place)
                        .filter(|node| below(node))
                        .map(|node| {
                            (
                                node.alias_of.is_some(),
                                node.kind == NodeKind::Symlink && !node.whiteout,
                            )
                        })
                else {
                    continue;
                };
                if alias {
                    overlay.forget(place, spares);
                    continue;
                }
                if symlink {
                    symlinks_removed += 1;
                }
                if let Some(node) = overlay.node_at_mut(place) {
                    node.linked = false;
                    unlinked.push(node.handle);
                }
            }
            overlay.symlinks = overlay.symlinks.saturating_sub(symlinks_removed);
            Ok(true)
        })
        .unwrap_or(false);
        for handle in &unlinked {
            note_unlinked(*handle);
        }
        if done {
            return;
        }
    }
}

pub(crate) fn unlink(handle: Handle) -> bool {
    if let Some(removed) = overlayfs::unlink(handle) {
        cpu::linux_reclaim_unlinked_files();
        return removed;
    }
    if blockfs::owns(handle) {
        let done = blockfs::unlink(handle).unwrap_or(false);
        cpu::linux_reclaim_unlinked_files();
        return done;
    }
    unlink_own(handle)
}

/// Takes the name of overlay node `handle` (a directory only when nothing
/// is linked below it); the file's data goes at its last close
/// (`reclaim_unlinked`).
fn unlink_own(handle: Handle) -> bool {
    let unlinked = locked(|overlay| {
        let place = overlay.find(handle)?;
        let node = overlay.node_at(place)?;
        if node.kind == NodeKind::Directory {
            let prefix = node.path();
            let occupied = overlay.nodes().any(|candidate| {
                candidate.active
                    && candidate.linked
                    && !candidate.whiteout
                    && candidate.path().len() > prefix.len()
                    && candidate.path().starts_with(prefix)
                    && candidate.path()[prefix.len()] == b'/'
            });
            if occupied {
                return Some(false);
            }
        }
        let node = overlay.node_at_mut(place)?;
        node.linked = false;
        let symlink = node.kind == NodeKind::Symlink;
        if symlink {
            overlay.symlinks = overlay.symlinks.saturating_sub(1);
        }
        Some(true)
    });
    if unlinked != Some(true) {
        return false;
    }
    note_unlinked(handle);
    true
}

/// Reserves the blocks of `handle`'s file up to `end` (fallocate) in its
/// tmpfs; false (ENOSPC) past the tmpfs's size.
pub(crate) fn reserve(handle: Handle, end: usize) -> bool {
    let size = read_node_field(handle, |node| node.size).unwrap_or(0);
    charge_size(handle, size, end)
}

/// Charges to its tmpfs, if one with a limit holds `handle`'s file, the
/// blocks a write from `offset` to `end` adds past the file's end (what
/// lies between stays a hole, which uses none); false (ENOSPC) past the
/// limit.
fn charge_size(handle: Handle, offset: usize, end: usize) -> bool {
    let block = tmpfs_quota::BLOCK_SIZE as usize;
    let mut path = PathCopy::new();
    let added = locked(|overlay| {
        let node = overlay.get(handle)?;
        // The block the end of the file lies in is charged already.
        let first = if offset <= node.size {
            node.size.div_ceil(block)
        } else {
            offset / block
        };
        let mut added = end.div_ceil(block).saturating_sub(first);
        // A paged file's holes (pages never written, or punched) are free
        // until written.
        if node.paged() && offset < node.size {
            let pages = offset / PAGE_SIZE..end.min(node.size).div_ceil(PAGE_SIZE);
            added += pages
                .filter(|index| matches!(page_state(node, *index), PageState::Missing(_)))
                .count();
        }
        if added != 0 {
            path.set(node.path());
        }
        Some(added)
    });
    let Some(added) = added.filter(|added| *added != 0) else {
        return true;
    };
    let instance = cpu::current_linux_execution_instance();
    if !tmpfs_quota::charge(instance, path.get(), added as u64, 0) {
        return false;
    }
    let blocks = added.min(u32::MAX as usize) as u32;
    if !change_node(handle, |node| {
        node.charged = node.charged.saturating_add(blocks)
    }) {
        tmpfs_quota::release(instance, path.get(), added as u64, 0);
    }
    true
}

/// Punches a hole in `handle`'s file (tmpfs) from `offset` to `end`
/// (FALLOC_FL_PUNCH_HOLE): its whole pages go, and their tmpfs blocks with
/// them, so SEEK_HOLE finds the hole; the rest of the range is zeroed. The
/// file becomes paged to keep its holes. A file whose frames were lent to
/// shared mappings keeps them, zeroed.
pub(crate) fn punch_hole(handle: Handle, offset: usize, end: usize) -> bool {
    let Some((kind, size)) = read_node_field(handle, |node| (node.kind, node.size)) else {
        return false;
    };
    if kind != NodeKind::File {
        return false;
    }
    if offset >= end.min(size) {
        return true;
    }
    if !make_own_paged(handle) {
        return false;
    }
    let mut path = PathCopy::new();
    let released = locked_with(|overlay, spares| {
        let Some(node) = overlay.get(handle).filter(|node| node.paged()) else {
            return Ok(None);
        };
        let end = end.min(node.size);
        if offset >= end {
            return Ok(Some(0));
        }
        // What it takes: room for the frames and swap entries of the whole
        // pages that go, and the partly zeroed pages back from swap.
        let mut whole = 0;
        let mut position = offset;
        while position < end {
            let index = position / PAGE_SIZE;
            let length = (end - position).min(PAGE_SIZE - position % PAGE_SIZE);
            if length == PAGE_SIZE && !node.frames_lent {
                whole += 1;
            } else if matches!(page_state(node, index), PageState::Swapped) {
                return Err(Need::SwapIn(handle, index));
            }
            position += length;
        }
        spares.room(whole)?;
        node.version = node.version.wrapping_add(1);
        let mut freed = 0_u32;
        let mut position = offset;
        while position < end {
            let index = position / PAGE_SIZE;
            let within = position % PAGE_SIZE;
            let length = (end - position).min(PAGE_SIZE - within);
            if length == PAGE_SIZE && !node.frames_lent {
                if take_paged_frame(node, index, spares) {
                    freed += 1;
                }
            } else if let PageState::Present(frame) = page_state(node, index) {
                if let Some(page) = Frame::leased(frame) {
                    page.fill_bytes(within, length, 0);
                }
            }
            position += length;
        }
        let released = freed.min(node.charged);
        if released != 0 {
            node.charged -= released;
            path.set(node.path());
        }
        Ok(Some(released))
    })
    .flatten();
    let Some(released) = released else {
        return false;
    };
    if released != 0 {
        tmpfs_quota::release(
            cpu::current_linux_execution_instance(),
            path.get(),
            u64::from(released),
            0,
        );
    }
    true
}

/// Where the next data (`data`) or hole of `handle`'s file at or after
/// `offset` starts, for a paged file (whose holes are pages it lacks):
/// `Some(None)` for ENXIO, `None` for a file whose holes are not kept. A
/// page out in swap is data.
pub(crate) fn seek(handle: Handle, offset: usize, data: bool) -> Option<Option<usize>> {
    if blockfs::owns(handle) {
        return None;
    }
    locked(|overlay| {
        let node = overlay.get(handle)?;
        if !node.paged() {
            return None;
        }
        let size = node.size;
        if offset >= size {
            return Some(None);
        }
        let mut index = offset / PAGE_SIZE;
        let pages = size.div_ceil(PAGE_SIZE);
        while index < pages && !matches!(page_state(node, index), PageState::Missing(_)) != data {
            index += 1;
        }
        let found = (index * PAGE_SIZE).max(offset);
        Some(if found < size {
            Some(found)
        } else if data {
            None
        } else {
            Some(size)
        })
    })
}

/// Takes page `index` out of paged `node`, its frame or swap entry into
/// `spares` (which have room): whether it had one.
fn take_paged_frame(node: &mut Node, index: usize, spares: &mut Spares) -> bool {
    let Some((entries, slot)) = paged_slot(node, index) else {
        return false;
    };
    let entry = index_entry(entries, slot);
    if entry == FrameLease::EMPTY {
        return false;
    }
    match swapped_entry(entry) {
        Some(swap) => spares.free_swap(swap),
        None => spares.release(entry),
    }
    set_index_entry(entries, slot, FrameLease::EMPTY);
    true
}

/// The frames paged `node` has among its first `pages` pages.
fn paged_frames(node: &Node, pages: usize) -> usize {
    let mut count = 0;
    let mut page = node.first_page;
    let mut first = 0;
    while page != FrameLease::EMPTY && first < pages {
        let Some(entries) = page_frame(page) else {
            break;
        };
        count += index_entries(entries)
            .take(pages - first)
            .filter(|(_, frame)| *frame != FrameLease::EMPTY)
            .count();
        first += FRAME_INDEX_CAPACITY;
        page = read_lease(entries, 0);
    }
    count
}

/// A page cache for a file of a volume (`linux_blockfs`): an unnamed paged
/// file whose frames hold the pages read from the disk, which shared
/// mappings of the volume's file map. No path leads to it.
pub(crate) fn create_page_cache(size: usize) -> Option<Handle> {
    let created = cpu::linux_realtime_now();
    locked_with(|overlay, spares| {
        let (Some(generation), Some(inode)) = (
            overlay.next_generation.checked_add(1),
            overlay.next_inode.checked_add(1),
        ) else {
            return Ok(None);
        };
        overlay.node_room()?;
        let place = overlay.free_place(spares)?;
        let handle = Handle { generation, inode };
        let node = Node {
            active: true,
            linked: false,
            origin: Origin::Pseudo,
            data: Data::Paged,
            kind: NodeKind::File,
            mode: 0o600,
            links: 1,
            handle,
            size,
            atime: created,
            mtime: created,
            ctime: created,
            ..Node::EMPTY
        };
        overlay.fill(place, node, spares);
        let _ = overlay.node_hints.insert(inode, place);
        overlay.next_generation = generation;
        overlay.next_inode = inode;
        Ok(Some(handle))
    })
    .flatten()
}

/// Sets a page cache's size: the file's, which bounds what reads of it
/// return. Pages past it read as zeros.
pub(crate) fn resize_page_cache(handle: Handle, size: usize) -> bool {
    locked(|overlay| {
        let Some(node) = overlay.get(handle).filter(|node| node.paged()) else {
            return false;
        };
        node.size = size;
        true
    })
}

/// Page `index` of page cache `handle` into `output`, if it holds that page.
pub(crate) fn read_cached_page(handle: Handle, index: usize, output: &mut [u8; PAGE_SIZE]) -> bool {
    locked_with(|overlay, spares| {
        let Some(node) = overlay.get(handle).filter(|node| node.paged()) else {
            return Ok(false);
        };
        // A paged node's frames are whole pages it owns.
        let Some(page) = locked_page(node, index, false, spares)?.and_then(Frame::leased) else {
            return Ok(false);
        };
        page.read_bytes(0, output);
        Ok(true)
    })
    .unwrap_or(false)
}

/// Puts `page` in page cache `handle` as page `index`, allocating its frame.
pub(crate) fn fill_cached_page(handle: Handle, index: usize, page: &[u8; PAGE_SIZE]) -> bool {
    locked_with(|overlay, spares| {
        let Some(node) = overlay.get(handle).filter(|node| node.paged()) else {
            return Ok(false);
        };
        // The frame may be mapped into processes, which then see the page
        // as the file now holds it.
        let Some(frame) = locked_page(node, index, true, spares)?.and_then(Frame::leased) else {
            return Ok(false);
        };
        frame.write_bytes(0, page);
        node.version = node.version.wrapping_add(1);
        Ok(true)
    })
    .unwrap_or(false)
}

/// Whether page cache `handle` holds page `index`.
pub(crate) fn page_cached(handle: Handle, index: usize) -> bool {
    locked_with(|overlay, spares| {
        let Some(node) = overlay.get(handle).filter(|node| node.paged()) else {
            return Ok(false);
        };
        Ok(locked_page(node, index, false, spares)?.is_some())
    })
    .unwrap_or(false)
}

/// Frees page cache `handle` of `file`, unless a process maps the file
/// shared or a page table still maps one of the cache's frames (false).
pub(crate) fn release_page_cache(handle: Handle, file: Handle) -> bool {
    if mapped_shared(file) {
        return false;
    }
    if lent_frames(handle).is_some_and(|frames| cpu::linux_frames_mapped(&frames)) {
        return false;
    }
    locked_with(|overlay, spares| {
        let Some(place) = overlay.find(handle) else {
            return Ok(false);
        };
        let Some(node) = overlay
            .node_at_mut(place)
            .filter(|node| node.origin == Origin::Pseudo)
        else {
            return Ok(false);
        };
        spares.detach(detach_data(node));
        overlay.forget(place, spares);
        Ok(true)
    })
    .unwrap_or(false)
}

/// Page caches whose volume forgot them while a mapping still held their
/// frames: (instance, cache, file), freed once nothing maps them
/// ([`release_orphan_caches`]).
static ORPHAN_CACHES: SpinLock<Vec<(usize, Handle, Handle)>> =
    SpinLock::new(LockRank::UNLINKED_FILES, Vec::new());

/// Frees page cache `handle` of `file`, which its volume no longer
/// keeps: now, or once nothing maps it any more.
pub(crate) fn release_or_orphan_page_cache(handle: Handle, file: Handle) {
    if release_page_cache(handle, file) {
        return;
    }
    let mut orphans = ORPHAN_CACHES.lock();
    if orphans.try_reserve(1).is_ok() {
        orphans.push((current_instance(), handle, file));
    }
}

/// Frees the orphaned page caches of this domain that nothing maps any
/// more.
fn release_orphan_caches() {
    let instance = current_instance();
    let candidates: Vec<(Handle, Handle)> = ORPHAN_CACHES
        .lock()
        .iter()
        .filter(|(owner, _, _)| *owner == instance)
        .map(|(_, cache, file)| (*cache, *file))
        .collect();
    for (cache, file) in candidates {
        if !exists(cache) || release_page_cache(cache, file) {
            ORPHAN_CACHES
                .lock()
                .retain(|(owner, orphan, _)| *owner != instance || *orphan != cache);
        }
    }
}

/// The frames of index page `number` of paged file `handle`, copied under
/// the lock into `entries`; false past the end of its index.
fn copy_index_page(
    handle: Handle,
    number: usize,
    entries: &mut [FrameLease; FRAME_INDEX_CAPACITY],
) -> bool {
    locked(|overlay| {
        let Some(page) = overlay
            .get(handle)
            .filter(|node| node.paged())
            .and_then(|node| nth_index_page(node, number))
        else {
            return false;
        };
        for (slot, entry) in index_entries(page) {
            entries[slot] = entry;
        }
        true
    })
}

/// Takes out of index page `number` of paged file `handle` the entries
/// `chosen` marks, where they still hold what `entries` copied; unmarks
/// the others.
fn take_index_entries(
    handle: Handle,
    number: usize,
    entries: &[FrameLease; FRAME_INDEX_CAPACITY],
    chosen: &mut [bool; FRAME_INDEX_CAPACITY],
) {
    locked(|overlay| {
        let page = overlay
            .get(handle)
            .filter(|node| node.paged())
            .and_then(|node| nth_index_page(node, number));
        for slot in 0..FRAME_INDEX_CAPACITY {
            if !chosen[slot] {
                continue;
            }
            match page {
                Some(page) if index_entry(page, slot) == entries[slot] => {
                    set_index_entry(page, slot, FrameLease::EMPTY);
                }
                _ => chosen[slot] = false,
            }
        }
    });
}

/// Index page `number` of paged `node`.
fn nth_index_page(node: &Node, number: usize) -> Option<Frame> {
    let mut page = node.first_page;
    for _ in 0..number {
        page = next_page(page)?;
    }
    page_frame(page)
}

/// Drops the frames of page cache `handle` that `wanted` picks (asked with
/// the lock released, of each frame in memory), up to `budget`: each index
/// page's entries are copied under the lock, picked, then taken out under
/// it where they did not change, and released after. The count dropped.
fn drop_cached_frames(handle: Handle, budget: u64, wanted: impl Fn(FrameLease) -> bool) -> u64 {
    let mut dropped = 0;
    let mut number = 0;
    let mut entries = [FrameLease::EMPTY; FRAME_INDEX_CAPACITY];
    let mut chosen = [false; FRAME_INDEX_CAPACITY];
    while dropped < budget && copy_index_page(handle, number, &mut entries) {
        let mut picked = 0;
        for slot in 0..FRAME_INDEX_CAPACITY {
            let entry = entries[slot];
            chosen[slot] = dropped + picked < budget
                && entry != FrameLease::EMPTY
                && swapped_entry(entry).is_none()
                && wanted(entry);
            picked += u64::from(chosen[slot]);
        }
        if picked != 0 {
            take_index_entries(handle, number, &entries, &mut chosen);
            for slot in 0..FRAME_INDEX_CAPACITY {
                if chosen[slot]
                    && memory::scrub_and_release_frames(FrameOwner::KERNEL, &[entries[slot]])
                {
                    dropped += 1;
                }
            }
        }
        number += 1;
    }
    dropped
}

/// Drops the pages of page cache `handle` (of file `file`) that no
/// address space maps any more, as Linux's drop_caches drops clean
/// unmapped pages: a cache whose frames were handed out to mappings stays
/// otherwise ([`release_page_cache`]). Returns how many went; none while
/// a shared mapping of the file is registered. The caller has written
/// back what mappings changed.
pub(crate) fn release_unmapped_cached_pages(handle: Handle, file: Handle) -> usize {
    if mapped_shared(file) {
        return 0;
    }
    drop_cached_frames(handle, u64::MAX, |entry| !memory::frame_is_shared(entry)) as usize
}

/// Drops up to `budget` frames of page cache `handle` that no mapping maps
/// and whose memory cgroup charge `wanted` takes; the count dropped. The
/// caller knows they are clean (no shared mapping of the file).
pub(crate) fn release_charged_cached_pages(
    handle: Handle,
    budget: u64,
    wanted: &impl Fn(u16) -> bool,
) -> u64 {
    drop_cached_frames(handle, budget, |entry| {
        !memory::frame_is_shared(entry) && wanted(memory::frame_charge(entry))
    })
}

/// Whether a process maps `handle`'s file shared.
pub(crate) fn mapped_shared(handle: Handle) -> bool {
    locked(|overlay| mapped_in(&overlay.mappings, handle))
}

/// The frames paged `node` has in its index (its frames handed out to be
/// mapped, which page tables may still hold).
fn lent_count(node: &Node) -> Option<usize> {
    let mut count = 0;
    let mut page = node.first_page;
    while page != FrameLease::EMPTY {
        let entries = page_frame(page)?;
        count += index_entries(entries)
            .filter(|(_, frame)| *frame != FrameLease::EMPTY)
            .count();
        page = read_lease(entries, 0);
    }
    Some(count)
}

/// Copies paged `node`'s frames (their addresses) into `frames`, which has
/// room for `count`: false if it no longer has that many.
fn copy_lent(node: &Node, count: usize, frames: &mut Vec<u64>) -> Option<bool> {
    if lent_count(node)? != count || frames.capacity() < count {
        return Some(false);
    }
    let mut page = node.first_page;
    while page != FrameLease::EMPTY {
        let entries = page_frame(page)?;
        for (_, frame) in index_entries(entries).filter(|(_, frame)| *frame != FrameLease::EMPTY) {
            frames.push(frame.address());
        }
        page = read_lease(entries, 0);
    }
    Some(true)
}

/// The frames (physical addresses, sorted) of a paged file whose frames
/// were handed out to be mapped, which page tables may still hold; None
/// for any other file.
pub(crate) fn lent_frames(handle: Handle) -> Option<Vec<u64>> {
    let lent = |node: &Node| node.paged() && node.frames_lent;
    for _ in 0..RETRY_LIMIT {
        let count = locked(|overlay| lent_count(overlay.get(handle).filter(|node| lent(node))?))?;
        let mut frames = Vec::new();
        frames.try_reserve_exact(count).ok()?;
        let (mut frames, copied) = locked(move |overlay| {
            let copied = overlay
                .get(handle)
                .filter(|node| lent(node))
                .and_then(|node| copy_lent(node, count, &mut frames));
            (frames, copied)
        });
        match copied {
            None => return None,
            Some(false) => continue,
            Some(true) => {
                frames.sort_unstable();
                return Some(frames);
            }
        }
    }
    None
}

/// The unlinked files of the domain that wait for page tables to let go
/// of their frames (see [`lent_frames`]).
pub(crate) fn unlinked_lent() -> Vec<Handle> {
    let mut handles = unlinked_of(current_instance());
    handles.retain(|handle| {
        read_node_field(*handle, |node| node.paged() && node.frames_lent).unwrap_or(false)
    });
    handles
}

/// Files that lost their last name, whose data [`reclaim_unlinked`] frees
/// once nothing has them open: per domain instance.
static UNLINKED: SpinLock<Vec<(usize, Handle)>> =
    SpinLock::new(LockRank::UNLINKED_FILES, Vec::new());

fn note_unlinked(handle: Handle) {
    let mut unlinked = UNLINKED.lock();
    if unlinked.try_reserve(1).is_ok() {
        unlinked.push((current_instance(), handle));
    }
}

/// The files of `instance` that lost their last name.
fn unlinked_of(instance: usize) -> Vec<Handle> {
    UNLINKED
        .lock()
        .iter()
        .filter(|(owner, _)| *owner == instance)
        .map(|(_, handle)| *handle)
        .collect()
}

/// What `reclaim_unlinked` finds of an unlinked file.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Unlinking {
    /// Nothing more to do: gone, named again, or not a file it frees.
    Settled,
    /// Its data may go once nothing holds it.
    Reclaimable,
}

fn unlinking(node: Option<&Node>) -> Unlinking {
    let Some(node) = node else {
        // Gone already (the overlay was torn down).
        return Unlinking::Settled;
    };
    // Named again (linkat of an O_TMPFILE file), or not a file whose data
    // goes with its last name.
    let reclaimable = !node.linked
        && node.active
        && !node.whiteout
        && node.alias_of.is_none()
        && matches!(node.origin, Origin::Named | Origin::Temporary { .. })
        && matches!(
            node.kind,
            NodeKind::File | NodeKind::Directory | NodeKind::Symlink
        );
    if reclaimable {
        Unlinking::Reclaimable
    } else {
        Unlinking::Settled
    }
}

/// Frees the files of this domain that lost their last name and that
/// nothing has open any more, as Linux frees an inode at its last close:
/// `in_use` says whether a descriptor, a working directory or a loop device
/// still holds one, or a page table still maps a frame of one whose
/// frames were handed out.
pub(crate) fn reclaim_unlinked(in_use: impl Fn(Handle) -> bool) {
    let instance = current_instance();
    let candidates = unlinked_of(instance);
    if candidates.is_empty() {
        return;
    }
    let quota_instance = cpu::current_linux_execution_instance();
    let mut settled = Vec::new();
    for handle in candidates {
        let state = locked(|overlay| {
            let place = overlay.find(handle);
            unlinking(place.and_then(|place| overlay.node_at(place)))
        });
        if state == Unlinking::Settled {
            settled.push(handle);
            continue;
        }
        // A paged file's frames, once handed out, may be mapped (shared, or
        // copy-on-write into private mappings) where no registration says
        // so: `in_use` looks for them in page tables (`lent_frames`).
        if in_use(handle) {
            continue;
        }
        let mut path = PathCopy::new();
        let freed = locked_with(|overlay, spares| {
            let Some(place) = overlay.find(handle) else {
                return Ok(None);
            };
            let Some(node) = overlay.node_at_mut(place) else {
                return Ok(None);
            };
            if unlinking(Some(node)) != Unlinking::Reclaimable {
                return Ok(None);
            }
            path.set(node.path());
            let charged = node.charged;
            spares.detach(detach_data(node));
            overlay.forget(place, spares);
            Ok(Some(charged))
        })
        .flatten();
        if let Some(charged) = freed {
            tmpfs_quota::release(quota_instance, path.get(), u64::from(charged), 1);
            settled.push(handle);
        }
    }
    UNLINKED
        .lock()
        .retain(|(owner, handle)| *owner != instance || !settled.contains(handle));
}

pub(crate) fn teardown() -> bool {
    // The domain's loop devices are backed by its files, and its RAM disks
    // go with them.
    overlayfs::forget_instance();
    blockfs::forget_instance();
    let instance = current_instance();
    UNLINKED.lock().retain(|(owner, _)| *owner != instance);
    ORPHAN_CACHES
        .lock()
        .retain(|(owner, _, _)| *owner != instance);
    crate::linux_loop::forget_domain();
    crate::linux_ramdisk::forget_domain();
    // Everything is taken out under the lock and released after it.
    let old = locked(|overlay| core::mem::replace(overlay, Overlay::EMPTY));
    let mut released = true;
    for node in old.nodes().filter(|node| node.active) {
        released &= release_detached(Detached {
            first: node.first_page,
            paged: node.paged(),
        });
    }
    drop(old);
    released
}

fn valid_path(path: &[u8]) -> Option<()> {
    (!path.is_empty()
        && path.len() < PATH_CAPACITY
        && !path.starts_with(b"/")
        && !path.ends_with(b"/")
        && path
            .split(|byte| *byte == b'/')
            .enumerate()
            .all(|(index, component)| {
                // A storage root (`crate::linux_mount_paths`) is the one
                // name with a NUL, first and at the start.
                let storage_root = index == 0 && component.first() == Some(&0);
                !component.is_empty()
                    && component.len() <= NAME_MAX
                    && component != b"."
                    && component != b".."
                    && (!component.contains(&0) || storage_root && !component[1..].contains(&0))
            }))
    .then_some(())
}

/// `path` copied to the kernel heap for a node to keep; None when the heap
/// is out of memory.
fn stored_path(path: &[u8]) -> Option<Vec<u8>> {
    stored_joined(&[path])
}

/// `parts` joined into one path on the kernel heap, as `stored_path`.
fn stored_joined(parts: &[&[u8]]) -> Option<Vec<u8>> {
    let mut stored = Vec::new();
    stored
        .try_reserve_exact(parts.iter().map(|part| part.len()).sum())
        .ok()?;
    for part in parts {
        stored.extend_from_slice(part);
    }
    Some(stored)
}

/// A zeroed frame (the frame allocator zeroes what it hands out).
fn allocate_zeroed_frame() -> Option<FrameLease> {
    let [page] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
    Some(page)
}

/// Marks a paged file's page out in swap: the index holds this in place of
/// its frame, the swap entry in the address bits above any frame's.
const SWAPPED_TAG: u64 = 1 << 51;
const SWAPPED_GENERATION: u32 = u32::MAX;

fn swapped_entry(lease: FrameLease) -> Option<u64> {
    (lease.generation() == SWAPPED_GENERATION && lease.address() & SWAPPED_TAG != 0)
        .then_some((lease.address() & !SWAPPED_TAG) >> 12)
}

/// The index page and slot of page `index` of paged `node`, if its index
/// reaches it.
fn paged_slot(node: &Node, index: usize) -> Option<(Frame, usize)> {
    let mut page = node.first_page;
    for _ in 0..index / FRAME_INDEX_CAPACITY {
        page = next_page(page)?;
    }
    Some((page_frame(page)?, index % FRAME_INDEX_CAPACITY))
}

/// The frame holding page `index` of shared memory `handle` (an unnamed
/// shmem or memfd node of the overlay, not a volume's), for paging it out:
/// None if it has none in memory.
pub(crate) fn paged_frame_for_swap(handle: Handle, index: usize) -> Option<FrameLease> {
    if blockfs::owns(handle) {
        return None;
    }
    locked(|overlay| {
        let node = overlay.get(handle).filter(|node| node.paged())?;
        let (entries, slot) = paged_slot(node, index)?;
        let frame = index_entry(entries, slot);
        (frame != FrameLease::EMPTY && swapped_entry(frame).is_none()).then_some(frame)
    })
}

/// Records page `index` of `handle`, whose `frame` was written to swap
/// entry `entry`, as out in swap; false (nothing changed) if the page no
/// longer has that frame. The caller frees the frame.
pub(crate) fn mark_paged_page_swapped(
    handle: Handle,
    index: usize,
    frame: FrameLease,
    entry: u64,
) -> bool {
    let Some(mark) = FrameLease::from_parts(SWAPPED_TAG | entry << 12, SWAPPED_GENERATION) else {
        return false;
    };
    locked(|overlay| {
        let Some((entries, slot)) = overlay
            .get(handle)
            .filter(|node| node.paged())
            .and_then(|node| paged_slot(node, index))
        else {
            return false;
        };
        if index_entry(entries, slot) != frame {
            return false;
        }
        set_index_entry(entries, slot, mark);
        true
    })
}

/// Whether page `index` of paged file `handle` is out in swap.
pub(crate) fn paged_page_swapped(handle: Handle, index: usize) -> bool {
    !blockfs::owns(handle)
        && locked(|overlay| {
            overlay
                .get(handle)
                .filter(|node| node.paged())
                .and_then(|node| paged_slot(node, index))
                .is_some_and(|(entries, slot)| swapped_entry(index_entry(entries, slot)).is_some())
        })
}

/// Frees a frame index no node holds any more (taken off one, or never
/// given to one), and the frames and swap entries it lists.
fn release_frame_index(mut page: FrameLease) -> bool {
    while page != FrameLease::EMPTY {
        let Some(entries) = page_frame(page) else {
            return false;
        };
        let next = read_lease(entries, 0);
        for (_, frame) in index_entries(entries).filter(|(_, frame)| *frame != FrameLease::EMPTY) {
            if let Some(swap) = swapped_entry(frame) {
                crate::linux_swap::free(swap);
                continue;
            }
            if !memory::scrub_and_release_frames(FrameOwner::KERNEL, &[frame]) {
                return false;
            }
        }
        if !memory::scrub_and_release_frames(FrameOwner::KERNEL, core::slice::from_ref(&page)) {
            return false;
        }
        page = next;
    }
    true
}

/// Grows chain file `node` to `required` data pages with frames from
/// `spares` (which has them), each charged as shared memory, as a tmpfs
/// file's data is, to its writer.
fn ensure_data_pages(node: &mut Node, required: usize, spares: &mut Spares) -> Option<()> {
    while node.page_count < required {
        let next = spares.take_frame()?;
        spares.charge(next, true);
        if node.first_page == FrameLease::EMPTY {
            node.first_page = next;
            node.cached_page = next;
            node.cached_page_index = 0;
        } else {
            set_next_page(node.last_page, next)?;
        }
        node.last_page = next;
        node.page_count += 1;
    }
    Some(())
}

/// Frees a chain of data pages no node holds any more.
fn release_data_pages(mut page: FrameLease) -> bool {
    while page != FrameLease::EMPTY {
        let Some(next) = next_page(page) else {
            return false;
        };
        if !memory::scrub_and_release_frames(FrameOwner::KERNEL, core::slice::from_ref(&page)) {
            return false;
        }
        page = next;
    }
    true
}

/// FNV-1a of `path`; two paths may share a key, which costs a scan.
fn path_key(path: &[u8]) -> u64 {
    path.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

// ---- The paths processes see ----
//
// The functions above take storage paths (`crate::linux_mount_paths`):
// the root filesystem's files are stored at their own paths, a mounted
// filesystem's below its storage root. These take and give the paths
// processes see, which the mounts lead to storage paths.

use crate::linux_mount_paths as mount_paths;

pub(crate) fn lookup(path: &[u8]) -> Option<Metadata> {
    lookup_stored(&mount_paths::storage(path))
}

/// Whether the image's file at canonical `path` is hidden: by a whiteout,
/// or because a mount leads the path elsewhere.
pub(crate) fn hidden(path: &[u8]) -> bool {
    match mount_paths::storage(path) {
        alloc::borrow::Cow::Owned(_) => true,
        alloc::borrow::Cow::Borrowed(path) => hidden_stored(path),
    }
}

/// The path of the image's file that canonical `path` shows, if it shows
/// one: `path` itself, or the image path a bind mount of a root filesystem
/// directory leads it to (a bind of /usr on /mnt shows /usr's files at
/// /mnt). None where the overlay hides the image (a whiteout, or a mount
/// of another filesystem over it).
pub(crate) fn image_path(path: &[u8]) -> Option<alloc::borrow::Cow<'_, [u8]>> {
    match mount_paths::storage(path) {
        alloc::borrow::Cow::Borrowed(path) => {
            (!hidden_stored(path)).then_some(alloc::borrow::Cow::Borrowed(path))
        }
        alloc::borrow::Cow::Owned(stored) => (!mount_paths::is_storage(&stored)
            && !hidden_stored(&stored))
        .then_some(alloc::borrow::Cow::Owned(stored)),
    }
}

/// Where the image would have canonical `path`'s file, hidden or not: the
/// root filesystem path a bind mount leads it to, else `path` itself.
pub(crate) fn image_location(path: &[u8]) -> alloc::borrow::Cow<'_, [u8]> {
    match mount_paths::storage(path) {
        alloc::borrow::Cow::Owned(stored) if !mount_paths::is_storage(&stored) => {
            alloc::borrow::Cow::Owned(stored)
        }
        _ => alloc::borrow::Cow::Borrowed(path),
    }
}

pub(crate) fn create_temporary(directory: &[u8], mode: u32, linkable: bool) -> Option<Handle> {
    create_temporary_stored(&mount_paths::storage(directory), mode, linkable)
}

pub(crate) fn link_unnamed(path: &[u8], handle: Handle) -> Result<(), LinkError> {
    link_unnamed_stored(&mount_paths::storage(path), handle)
}

/// The path that leads to `handle`'s file, into `output`.
pub(crate) fn copy_path(handle: Handle, output: &mut [u8]) -> Option<usize> {
    let length = copy_path_stored(handle, output)?;
    let shown = match mount_paths::visible(&output[..length]) {
        alloc::borrow::Cow::Borrowed(_) => return Some(length),
        alloc::borrow::Cow::Owned(path) => path,
    };
    output.get_mut(..shown.len())?.copy_from_slice(&shown);
    Some(shown.len())
}

pub(crate) fn next_child_at(directory: &[u8], cursor: usize) -> Option<Option<Child>> {
    next_child_at_stored(&mount_paths::storage(directory), cursor)
}

pub(crate) fn create_file(path: &[u8], mode: u32, initial: &[u8]) -> Option<Handle> {
    create_file_stored(&mount_paths::storage(path), mode, initial)
}

pub(crate) fn create_directory(path: &[u8], mode: u32) -> Option<Handle> {
    create_directory_stored(&mount_paths::storage(path), mode)
}

pub(crate) fn create_symlink(path: &[u8], target: &[u8]) -> Option<Handle> {
    create_symlink_stored(&mount_paths::storage(path), target)
}

pub(crate) fn create_fifo(path: &[u8], mode: u32) -> Option<Handle> {
    create_fifo_stored(&mount_paths::storage(path), mode)
}

pub(crate) fn create_socket(path: &[u8], mode: u32) -> Option<Handle> {
    create_socket_stored(&mount_paths::storage(path), mode)
}

pub(crate) fn create_device(path: &[u8], kind: NodeKind, mode: u32, device: u32) -> Option<Handle> {
    create_device_stored(&mount_paths::storage(path), kind, mode, device)
}

pub(crate) fn whiteout(path: &[u8]) -> bool {
    match mount_paths::storage(path) {
        alloc::borrow::Cow::Owned(_) => false,
        alloc::borrow::Cow::Borrowed(path) => whiteout_stored(path),
    }
}

pub(crate) fn rename(handle: Handle, path: &[u8]) -> bool {
    rename_stored(handle, &mount_paths::storage(path))
}

pub(crate) fn create_link(path: &[u8], target: Handle) -> bool {
    create_link_stored(&mount_paths::storage(path), target)
}

pub(crate) fn unlink_path(path: &[u8]) -> bool {
    unlink_path_stored(&mount_paths::storage(path))
}

pub(crate) fn rename_path(from: &[u8], to: &[u8]) -> bool {
    rename_path_stored(&mount_paths::storage(from), &mount_paths::storage(to))
}
