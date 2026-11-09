//! Each domain's small in-kernel file store: the `linox-ready` file and
//! the image objects staged and published through it. Files and their
//! data live on the kernel heap, one lock per instance.
#![forbid(unsafe_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{
    arch::x86_64::cpu,
    control_abi, heap,
    sync::{LockRank, SpinLock, SpinLockGuard},
};

pub(crate) const FILE_CAPACITY: usize = 64;
const PAGE_SIZE: usize = 4096;
const NAME_CAPACITY: usize = 64;
/// The bytes of each data page.
const DATA_CAPACITY: usize = PAGE_SIZE;
const FILE_NAME: &[u8] = b"linox-ready";
const FIRST_FILE_INODE: u64 = 18;
const HOST_INSTANCE: usize = control_abi::DOMAIN_LIMIT;
const INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;

struct TmpfsRuntimeOwner {
    installed: AtomicBool,
    instances: [SpinLock<Tmpfs>; INSTANCE_LIMIT],
}

static TMPFS_RUNTIME: TmpfsRuntimeOwner = TmpfsRuntimeOwner {
    installed: AtomicBool::new(false),
    instances: [const { SpinLock::new(LockRank::TMPFS_FILES, Tmpfs::new()) }; INSTANCE_LIMIT],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileHandle {
    generation: u32,
    inode: u64,
}

struct File {
    handle: FileHandle,
    name_length: u8,
    name: [u8; NAME_CAPACITY],
    length: usize,
    /// The file's data, page by page; every page up to its length exists.
    pages: Vec<Box<[u8; DATA_CAPACITY]>>,
    published: bool,
}

struct Tmpfs {
    generation: u32,
    used: usize,
    files: Vec<File>,
}

impl Tmpfs {
    const fn new() -> Self {
        Self {
            generation: 0,
            used: 0,
            files: Vec::new(),
        }
    }

    fn valid_name(name: &[u8]) -> bool {
        !name.is_empty()
            && name.len() <= NAME_CAPACITY
            && name
                .iter()
                .all(|byte| byte.is_ascii_graphic() && *byte != b'/')
    }

    fn create(&mut self, name: &[u8], published: bool) -> Option<FileHandle> {
        if !Self::valid_name(name) || self.find(name, false).is_some() {
            return None;
        }
        self.files.try_reserve(1).ok()?;
        let generation = self.generation.checked_add(1)?;
        let mut stored_name = [0_u8; NAME_CAPACITY];
        stored_name[..name.len()].copy_from_slice(name);
        let handle = FileHandle {
            generation,
            inode: FIRST_FILE_INODE.checked_add(u64::from(generation) - 1)?,
        };
        self.generation = generation;
        self.files.push(File {
            handle,
            name_length: name.len() as u8,
            name: stored_name,
            length: 0,
            pages: Vec::new(),
            published,
        });
        Some(handle)
    }

    fn find(&self, name: &[u8], published_only: bool) -> Option<FileHandle> {
        self.files
            .iter()
            .find(|file| (!published_only || file.published) && file.name() == name)
            .map(|file| file.handle)
    }

    fn file(&self, handle: FileHandle) -> Option<&File> {
        self.files.iter().find(|file| file.handle == handle)
    }

    fn file_mut(&mut self, handle: FileHandle) -> Option<&mut File> {
        self.files.iter_mut().find(|file| file.handle == handle)
    }

    fn read(&self, handle: FileHandle, offset: usize, output: &mut [u8]) -> Option<usize> {
        let file = self.file(handle)?;
        let start = offset.min(file.length);
        let end = start.saturating_add(output.len()).min(file.length);
        let mut copied = 0;
        while start + copied < end {
            let position = start + copied;
            let page_offset = position % DATA_CAPACITY;
            let length = (end - position).min(DATA_CAPACITY - page_offset);
            let page = file.pages.get(position / DATA_CAPACITY)?;
            output[copied..copied + length]
                .copy_from_slice(&page[page_offset..page_offset + length]);
            copied += length;
        }
        Some(copied)
    }

    fn write(&mut self, handle: FileHandle, offset: usize, input: &[u8]) -> Option<usize> {
        let file = self.file_mut(handle)?;
        if input.is_empty() {
            return Some(0);
        }
        let end = offset.checked_add(input.len())?;
        if file.published && file.name() != FILE_NAME {
            return None;
        }
        let required_page_count = end.div_ceil(DATA_CAPACITY);
        let additional_page_count = required_page_count.saturating_sub(file.pages.len());
        file.pages.try_reserve(additional_page_count).ok()?;
        let mut additions = Vec::new();
        additions.try_reserve_exact(additional_page_count).ok()?;
        for _ in 0..additional_page_count {
            additions.push(heap::zeroed_page()?);
        }
        file.pages.append(&mut additions);

        let mut copied = 0;
        while copied < input.len() {
            let position = offset + copied;
            let page_offset = position % DATA_CAPACITY;
            let length = (input.len() - copied).min(DATA_CAPACITY - page_offset);
            let page = file.pages.get_mut(position / DATA_CAPACITY)?;
            page[page_offset..page_offset + length]
                .copy_from_slice(&input[copied..copied + length]);
            copied += length;
        }

        let old_length = file.length;
        file.length = old_length.max(end);
        self.used += end.saturating_sub(old_length);
        Some(input.len())
    }

    fn publish(&mut self, handle: FileHandle) -> bool {
        let Some(file) = self.file_mut(handle) else {
            return false;
        };
        if file.published {
            return false;
        }
        file.published = true;
        true
    }

    /// Removes a file; its pages go back to the frame allocator, scrubbed.
    fn unlink(&mut self, handle: FileHandle) -> bool {
        let Some(index) = self.files.iter().position(|file| file.handle == handle) else {
            return false;
        };
        let file = self.files.remove(index);
        self.used -= file.length;
        true
    }

    fn allocated_pages(&self) -> usize {
        self.files.iter().map(|file| file.pages.len()).sum()
    }

    fn clean(&self) -> bool {
        self.used == 0 && self.files.is_empty()
    }
}

impl File {
    fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_length)]
    }
}

pub(crate) fn verify_contract() -> bool {
    let Some(frames_before) = heap::kernel_frames_outside_heap() else {
        return false;
    };
    let mut tmpfs = Tmpfs::new();
    let Some(first) = tmpfs.create(FILE_NAME, true) else {
        return false;
    };
    let mut output = [0_u8; FILE_CAPACITY];
    if tmpfs.write(first, 0, b"ready\n") != Some(6)
        || tmpfs.read(first, 0, &mut output[..6]) != Some(6)
        || &output[..6] != b"ready\n"
        || tmpfs.create(FILE_NAME, true).is_some()
        || tmpfs.create(b"bad/name", true).is_some()
    {
        return false;
    }

    let staged_name = b"sha256:aaaaaaaa";
    let Some(staged) = tmpfs.create(staged_name, false) else {
        return false;
    };
    if tmpfs.find(staged_name, true).is_some()
        || tmpfs.write(staged, DATA_CAPACITY - 2, b"abcd") != Some(4)
        || tmpfs.read(staged, DATA_CAPACITY - 2, &mut output[..4]) != Some(4)
        || &output[..4] != b"abcd"
        || !tmpfs.publish(staged)
        || tmpfs.publish(staged)
        || tmpfs.find(staged_name, true) != Some(staged)
        || tmpfs.write(staged, 0, b"x").is_some()
    {
        return false;
    }

    let aborted_name = b"sha256:bbbbbbbb";
    let Some(aborted) = tmpfs.create(aborted_name, false) else {
        return false;
    };
    let beyond_old_quota = 8 * PAGE_SIZE + 17;
    if tmpfs.write(aborted, beyond_old_quota, b"z") != Some(1)
        || tmpfs.read(aborted, beyond_old_quota, &mut output[..1]) != Some(1)
        || output[0] != b'z'
        || tmpfs.read(aborted, PAGE_SIZE, &mut output[..1]) != Some(1)
        || output[0] != 0
    {
        return false;
    }
    let second_name = b"sha256:cccccccc";
    let Some(second) = tmpfs.create(second_name, false) else {
        return false;
    };
    if tmpfs.write(second, beyond_old_quota, b"q") != Some(1)
        || tmpfs.allocated_pages() != 1 + 2 + 2 * (beyond_old_quota + 1).div_ceil(DATA_CAPACITY)
        || tmpfs.find(aborted_name, true).is_some()
        || !tmpfs.unlink(second)
        || !tmpfs.unlink(aborted)
        || tmpfs.find(aborted_name, false).is_some()
    {
        return false;
    }

    let stale = first;
    if !tmpfs.unlink(first) || tmpfs.read(stale, 0, &mut output[..1]).is_some() {
        return false;
    }
    let Some(replacement) = tmpfs.create(FILE_NAME, true) else {
        return false;
    };
    if replacement.generation <= stale.generation
        || replacement.inode <= stale.inode
        || tmpfs.read(replacement, 0, &mut output) != Some(0)
        || tmpfs.unlink(stale)
        || !tmpfs.unlink(replacement)
        || !tmpfs.unlink(staged)
    {
        return false;
    }
    let many = |index: usize| {
        [
            b'm',
            b'a' + u8::try_from(index / 26).unwrap_or(25),
            b'a' + u8::try_from(index % 26).unwrap_or(25),
        ]
    };
    const MANY: usize = 100;
    if (0..MANY).any(|index| tmpfs.create(&many(index), false).is_none())
        || tmpfs.files.len() != MANY
    {
        return false;
    }
    for index in 0..MANY {
        let Some(handle) = tmpfs.find(&many(index), false) else {
            return false;
        };
        if !tmpfs.unlink(handle) {
            return false;
        }
    }
    let clean = tmpfs.clean() && tmpfs.allocated_pages() == 0;
    drop(tmpfs);
    clean && heap::kernel_frames_outside_heap() == Some(frames_before)
}

pub(crate) fn install() -> bool {
    if TMPFS_RUNTIME.installed.load(Ordering::Acquire) {
        return false;
    }
    for instance in &TMPFS_RUNTIME.instances {
        *instance.lock() = Tmpfs::new();
    }
    TMPFS_RUNTIME.installed.store(true, Ordering::Release);
    TMPFS_RUNTIME
        .instances
        .iter()
        .all(|instance| instance.lock().clean())
}

pub(crate) fn create(name: &[u8]) -> Option<FileHandle> {
    (name == FILE_NAME).then_some(())?;
    live()?.create(name, true)
}

pub(crate) fn open(name: &[u8]) -> Option<FileHandle> {
    live()?.find(name, true)
}

pub(crate) fn stage_object(name: &[u8]) -> Option<FileHandle> {
    (name != FILE_NAME).then_some(())?;
    live()?.create(name, false)
}

pub(crate) fn publish_object(handle: FileHandle) -> bool {
    live().is_some_and(|mut tmpfs| tmpfs.publish(handle))
}

pub(crate) fn abort_object(handle: FileHandle) -> bool {
    live().is_some_and(|mut tmpfs| {
        tmpfs.file(handle).is_some_and(|file| !file.published) && tmpfs.unlink(handle)
    })
}

pub(crate) fn usage() -> usize {
    live().map_or(0, |tmpfs| tmpfs.used)
}

pub(crate) fn verify_live_object_contract() -> bool {
    let Some(frames_before) = heap::kernel_frames_outside_heap() else {
        return false;
    };
    let first_name = b"sha256:live-a";
    let second_name = b"sha256:live-b";
    let overflow_name = b"sha256:overflow";
    if usage() != 0 {
        return false;
    }
    let Some(first) = stage_object(first_name) else {
        return false;
    };
    if open(first_name).is_some()
        || write(first, DATA_CAPACITY - 2, b"abcd") != Some(4)
        || !publish_object(first)
        || open(first_name) != Some(first)
        || abort_object(first)
        || write(first, 0, b"x").is_some()
    {
        return false;
    }
    let Some(second) = stage_object(second_name) else {
        return false;
    };
    let Some(overflow) = stage_object(overflow_name) else {
        return false;
    };
    let beyond_old_quota = 8 * PAGE_SIZE + 17;
    if write(second, beyond_old_quota, b"s") != Some(1)
        || write(overflow, beyond_old_quota, b"o") != Some(1)
        || !abort_object(overflow)
        || !abort_object(second)
        || !unlink(first_name, first)
    {
        return false;
    }
    usage() == 0
        && open(first_name).is_none()
        && open(second_name).is_none()
        && open(overflow_name).is_none()
        && heap::kernel_frames_outside_heap() == Some(frames_before)
}

pub(crate) fn from_generation(generation: u32) -> Option<FileHandle> {
    live()?
        .files
        .iter()
        .find(|file| file.published && file.handle.generation == generation)
        .map(|file| file.handle)
}

pub(crate) fn generation(handle: FileHandle) -> u32 {
    handle.generation
}

pub(crate) fn inode(handle: FileHandle) -> u64 {
    handle.inode
}

pub(crate) fn entry() -> Option<(FileHandle, &'static [u8])> {
    open(FILE_NAME).map(|handle| (handle, FILE_NAME))
}

pub(crate) fn size(handle: FileHandle) -> Option<usize> {
    live()?.file(handle).map(|file| file.length)
}

pub(crate) fn read(handle: FileHandle, offset: usize, output: &mut [u8]) -> Option<usize> {
    live()?.read(handle, offset, output)
}

pub(crate) fn write(handle: FileHandle, offset: usize, input: &[u8]) -> Option<usize> {
    live()?.write(handle, offset, input)
}

pub(crate) fn unlink(name: &[u8], handle: FileHandle) -> bool {
    live().is_some_and(|mut tmpfs| {
        tmpfs
            .file(handle)
            .is_some_and(|file| file.published && file.name() == name)
            && tmpfs.unlink(handle)
    })
}

pub(crate) fn teardown() -> bool {
    let Some(mut tmpfs) = live() else {
        return false;
    };
    tmpfs.files = Vec::new();
    tmpfs.used = 0;
    tmpfs.clean()
}

/// The calling domain's file store, locked, once installed.
fn live() -> Option<SpinLockGuard<'static, Tmpfs>> {
    if !TMPFS_RUNTIME.installed.load(Ordering::Acquire) {
        return None;
    }
    let instance = cpu::current_container_slot().unwrap_or(HOST_INSTANCE);
    TMPFS_RUNTIME.instances.get(instance).map(SpinLock::lock)
}
