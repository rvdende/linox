use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use linox_image_store::{Digest, ImageStore, ObjectBackend, StagingHandle, StoreError};

use crate::{
    memory::{self, FrameLease, FrameOwner},
    sync::{LockRank, SpinLock},
};

const PAGE_SIZE: usize = 4096;
const OBJECT_LIMIT: usize = linox_oci::OCI_LAYER_LIMIT;
pub(crate) const CACHE_QUOTA: usize = usize::MAX;
/// The most a root filesystem may expand to, checked against the layers'
/// untrusted size fields before anything is allocated for it. Upstream's
/// 512 MiB is too small for toolchain images (rust:alpine expands past it).
pub(crate) const DEFAULT_ROOTFS_UNPACK_LIMIT_BYTES: usize = 4 * 1024 * 1024 * 1024;

/// The object store and the layers published to it for the next root
/// filesystem, once installed.
struct Store {
    objects: ImageStore<RamBackend, OBJECT_LIMIT>,
    published_layers: [Digest; linox_oci::OCI_LAYER_LIMIT],
    published_layer_count: usize,
}

struct ImageStoreOwner {
    /// Image pulls and root filesystem installs run at system-call or
    /// boot level and hold it while they unpack, so it ranks just above
    /// system-call level.
    store: SpinLock<Option<Store>>,
    rootfs_frame_starts: [AtomicU64; crate::control_abi::DOMAIN_LIMIT],
    rootfs_frame_counts: [AtomicUsize; crate::control_abi::DOMAIN_LIMIT],
    rootfs_lengths: [AtomicUsize; crate::control_abi::DOMAIN_LIMIT],
    rootfs_owner_slots: [AtomicUsize; crate::control_abi::DOMAIN_LIMIT],
    rootfs_refcounts: [AtomicUsize; crate::control_abi::DOMAIN_LIMIT],
    /// The all-Rust root filesystem carried in the boot image (a gzip'd
    /// POSIX tar) for `image=builtin://rust`: its physical address and length.
    builtin_rootfs_address: AtomicU64,
    builtin_rootfs_length: AtomicUsize,
}

static IMAGE_STORE: ImageStoreOwner = ImageStoreOwner {
    store: SpinLock::new(LockRank::IMAGE_STORE, None),
    rootfs_frame_starts: [const { AtomicU64::new(0) }; crate::control_abi::DOMAIN_LIMIT],
    rootfs_frame_counts: [const { AtomicUsize::new(0) }; crate::control_abi::DOMAIN_LIMIT],
    rootfs_lengths: [const { AtomicUsize::new(0) }; crate::control_abi::DOMAIN_LIMIT],
    rootfs_owner_slots: [const { AtomicUsize::new(0) }; crate::control_abi::DOMAIN_LIMIT],
    rootfs_refcounts: [const { AtomicUsize::new(0) }; crate::control_abi::DOMAIN_LIMIT],
    builtin_rootfs_address: AtomicU64::new(0),
    builtin_rootfs_length: AtomicUsize::new(0),
};

/// The image reference that selects the boot image's Rust root filesystem.
pub(crate) const BUILTIN_RUST_IMAGE: &[u8] = b"builtin://rust";

/// Objects (compressed layers) in kernel heap memory: each a buffer of
/// its expected length, filled by appends.
struct RamBackend {
    objects: [Option<Box<[u8]>>; OBJECT_LIMIT],
}

impl RamBackend {
    const fn new() -> Self {
        Self {
            objects: [const { None }; OBJECT_LIMIT],
        }
    }

    fn object(&self, object: u8) -> Option<&[u8]> {
        self.objects.get(usize::from(object))?.as_deref()
    }
}

impl ObjectBackend for RamBackend {
    type Object = u8;

    fn create(&mut self, expected_length: usize) -> Option<Self::Object> {
        if expected_length == 0 {
            return None;
        }
        let slot = self.objects.iter().position(Option::is_none)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(expected_length).ok()?;
        bytes.resize(expected_length, 0);
        self.objects[slot] = Some(bytes.into_boxed_slice());
        Some(slot as u8)
    }

    fn append(&mut self, object: Self::Object, offset: usize, bytes: &[u8]) -> bool {
        let Some(Some(object)) = self.objects.get_mut(usize::from(object)) else {
            return false;
        };
        let Some(target) = offset
            .checked_add(bytes.len())
            .and_then(|end| object.get_mut(offset..end))
        else {
            return false;
        };
        target.copy_from_slice(bytes);
        true
    }

    fn read(&self, object: Self::Object, offset: usize, output: &mut [u8]) -> bool {
        let Some(source) = self.object(object).and_then(|object| {
            offset
                .checked_add(output.len())
                .and_then(|end| object.get(offset..end))
        }) else {
            return false;
        };
        output.copy_from_slice(source);
        true
    }

    fn destroy(&mut self, object: Self::Object) -> bool {
        self.objects
            .get_mut(usize::from(object))
            .and_then(Option::take)
            .is_some()
    }
}

pub(crate) fn install() -> bool {
    let mut store = IMAGE_STORE.store.lock();
    if store.is_some() {
        return false;
    }
    *store = Some(Store {
        objects: ImageStore::new(RamBackend::new(), CACHE_QUOTA),
        published_layers: [Digest([0; 32]); linox_oci::OCI_LAYER_LIMIT],
        published_layer_count: 0,
    });
    true
}

/// Records the boot image's Rust root filesystem; called once during boot.
pub(crate) fn set_builtin_rootfs(physical: u64, length: usize) {
    IMAGE_STORE
        .builtin_rootfs_address
        .store(physical, Ordering::Release);
    IMAGE_STORE
        .builtin_rootfs_length
        .store(length, Ordering::Release);
}

pub(crate) fn builtin_rootfs_available() -> bool {
    IMAGE_STORE.builtin_rootfs_length.load(Ordering::Acquire) != 0
}

/// Stages the boot image's Rust root filesystem as the image's only layer,
/// as a registry pull would, so installation unpacks and checks it with the
/// same code. Its digest is computed here: the bytes come from the boot
/// image, whose integrity is the boot chain's to establish.
pub(crate) fn stage_builtin_layer() -> bool {
    let length = IMAGE_STORE.builtin_rootfs_length.load(Ordering::Acquire);
    let Some(address) = crate::arch::x86_64::paging::direct_map_range_address(
        IMAGE_STORE.builtin_rootfs_address.load(Ordering::Acquire),
        length,
    ) else {
        return false;
    };
    // SAFETY: set_builtin_rootfs recorded read-only boot-image data that
    // stays mapped for the kernel's lifetime.
    let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, length) };
    let Ok(handle) = stage(crate::crypto::sha256(bytes), length) else {
        return false;
    };
    if append(handle, bytes) != Ok(length) {
        let _ = abort(handle);
        return false;
    }
    publish(handle).is_ok()
}

pub(crate) fn stage(digest: [u8; 32], length: usize) -> Result<StagingHandle, StoreError> {
    with_store(|store| store.objects.stage(Digest(digest), length))
        .unwrap_or(Err(StoreError::Backend))
}

pub(crate) fn append(handle: StagingHandle, bytes: &[u8]) -> Result<usize, StoreError> {
    with_store(|store| store.objects.append(handle, bytes)).unwrap_or(Err(StoreError::Backend))
}

pub(crate) fn publish(handle: StagingHandle) -> Result<Digest, StoreError> {
    with_store(|store| {
        let digest = store.objects.publish(handle)?;
        let index = store.published_layer_count;
        if index >= linox_oci::OCI_LAYER_LIMIT {
            return Err(StoreError::QuotaExceeded);
        }
        store.published_layers[index] = digest;
        store.published_layer_count += 1;
        Ok(digest)
    })
    .unwrap_or(Err(StoreError::Backend))
}

pub(crate) fn abort(handle: StagingHandle) -> Result<(), StoreError> {
    with_store(|store| store.objects.abort(handle)).unwrap_or(Err(StoreError::Backend))
}

pub(crate) fn published_layer_count() -> usize {
    with_store(|store| store.published_layer_count).unwrap_or(0)
}

/// Published layer `index`: its digest and object, if it is there.
fn published_layer(store: &Store, index: usize) -> Option<(Digest, u8, usize)> {
    if index >= store.published_layer_count {
        return None;
    }
    let digest = store.published_layers[index];
    let (object, length) = store.objects.published_object(digest)?;
    Some((digest, object, length))
}

pub(crate) fn published_layer_info(index: usize) -> Option<([u8; 32], usize)> {
    with_store(|store| published_layer(store, index).map(|(digest, _, length)| (digest.0, length)))?
}

pub(crate) fn read_published_layer(index: usize, offset: usize, output: &mut [u8]) -> bool {
    with_store(|store| {
        published_layer(store, index).is_some_and(|(_, object, length)| {
            offset
                .checked_add(output.len())
                .is_some_and(|end| end <= length)
                && store.objects.backend().read(object, offset, output)
        })
    })
    .unwrap_or(false)
}

/// Runs `operation` on the store, once installed, under its lock.
fn with_store<T>(operation: impl FnOnce(&mut Store) -> T) -> Option<T> {
    IMAGE_STORE.store.lock().as_mut().map(operation)
}

pub(crate) fn begin_layer_pull() -> bool {
    discard_published_layers()
}

pub(crate) fn discard_published_layers() -> bool {
    with_store(|store| {
        let count = core::mem::take(&mut store.published_layer_count);
        if count > linox_oci::OCI_LAYER_LIMIT {
            return false;
        }
        let mut valid = true;
        for digest in &mut store.published_layers[..count] {
            valid &= *digest != Digest([0; 32]) && store.objects.remove(*digest).is_ok();
            *digest = Digest([0; 32]);
        }
        valid
    })
    .unwrap_or(false)
}

pub(crate) fn install_published_layers(slot: usize, unpack_limit_bytes: usize) -> bool {
    if slot >= crate::control_abi::DOMAIN_LIMIT || crate::published_rootfs::is_installed(slot) {
        return false;
    }
    with_store(|store| {
        let layer_count = store.published_layer_count;
        if layer_count == 0 || layer_count > linox_oci::OCI_LAYER_LIMIT {
            return false;
        }
        let mut digests = [Digest([0; 32]); linox_oci::OCI_LAYER_LIMIT];
        let mut objects = [0_u8; linox_oci::OCI_LAYER_LIMIT];
        let mut compressed_lengths = [0_usize; linox_oci::OCI_LAYER_LIMIT];
        let mut headers = [0_usize; linox_oci::OCI_LAYER_LIMIT];
        let mut expected_lengths = [0_usize; linox_oci::OCI_LAYER_LIMIT];
        for index in 0..layer_count {
            let digest = store.published_layers[index];
            let Some((object, compressed_length)) = store.objects.published_object(digest) else {
                return false;
            };
            let Some(header) =
                gzip_header_length(store.objects.backend(), object, compressed_length)
            else {
                return false;
            };
            if compressed_length < header + 8 {
                return false;
            }
            let mut trailer = [0; 4];
            if !store
                .objects
                .backend()
                .read(object, compressed_length - 4, &mut trailer)
            {
                return false;
            }
            let expected_length = u32::from_le_bytes(trailer) as usize;
            if expected_length == 0 {
                return false;
            }
            digests[index] = digest;
            objects[index] = object;
            compressed_lengths[index] = compressed_length;
            headers[index] = header;
            expected_lengths[index] = expected_length;
        }
        let Some((allocation_length, page_count)) =
            rootfs_unpack_allocation(&expected_lengths[..layer_count], unpack_limit_bytes)
        else {
            crate::serial_write_bytes(b"linox: OCI rootfs expansion exceeds unpack limit\r\n");
            return false;
        };
        let Some((first_frame, _)) =
            memory::allocate_contiguous_extent(FrameOwner::KERNEL, page_count)
        else {
            crate::serial_write_bytes(b"linox: OCI rootfs memory allocation failed: ");
            crate::serial_write_u64(allocation_length as u64);
            crate::serial_write_bytes(b" bytes\r\n");
            return false;
        };
        let Some(address) = first_frame.direct_map_address() else {
            let _ = memory::scrub_and_release_contiguous_extent(
                FrameOwner::KERNEL,
                first_frame,
                page_count,
            );
            return false;
        };
        // SAFETY: the extent was just allocated to the kernel, page_count
        // frames long and direct-mapped; nothing else reaches it until
        // register_rootfs_backing records it.
        let output =
            unsafe { core::slice::from_raw_parts_mut(address as *mut u8, page_count * PAGE_SIZE) };
        output.fill(0);
        let mut rootfs_length = 0_usize;
        for index in 0..layer_count {
            let expected_length = expected_lengths[index];
            let Some(layer_end) = rootfs_length.checked_add(expected_length) else {
                let _ = memory::scrub_and_release_contiguous_extent(
                    FrameOwner::KERNEL,
                    first_frame,
                    page_count,
                );
                return false;
            };
            let input = ObjectSlices::new(
                store.objects.backend(),
                objects[index],
                headers[index],
                compressed_lengths[index] - headers[index] - 8,
            );
            let Ok(written) = miniz_oxide::inflate::decompress_slice_iter_to_slice(
                &mut output[rootfs_length..layer_end],
                input,
                false,
                true,
            ) else {
                let _ = memory::scrub_and_release_contiguous_extent(
                    FrameOwner::KERNEL,
                    first_frame,
                    page_count,
                );
                return false;
            };
            if written != expected_length {
                let _ = memory::scrub_and_release_contiguous_extent(
                    FrameOwner::KERNEL,
                    first_frame,
                    page_count,
                );
                return false;
            }
            let Some(layer) = linox_oci::Rootfs::parse(&output[rootfs_length..layer_end]) else {
                let _ = memory::scrub_and_release_contiguous_extent(
                    FrameOwner::KERNEL,
                    first_frame,
                    page_count,
                );
                return false;
            };
            rootfs_length += layer.content_length();
        }
        let Some(rootfs_end) = rootfs_length.checked_add(1024) else {
            let _ = memory::scrub_and_release_contiguous_extent(
                FrameOwner::KERNEL,
                first_frame,
                page_count,
            );
            return false;
        };
        if rootfs_end > output.len() {
            let _ = memory::scrub_and_release_contiguous_extent(
                FrameOwner::KERNEL,
                first_frame,
                page_count,
            );
            return false;
        }
        output[rootfs_length..rootfs_end].fill(0);
        // SAFETY: the same extent, no longer written; it stays allocated
        // while a domain's published rootfs uses it (uninstall_rootfs).
        let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, rootfs_end) };
        if !crate::published_rootfs::install_published_rootfs(slot, bytes) {
            crate::serial_write_bytes(b"linox: OCI rootfs publication failed\r\n");
            let _ = memory::scrub_and_release_contiguous_extent(
                FrameOwner::KERNEL,
                first_frame,
                page_count,
            );
            return false;
        }
        for digest in &digests[..layer_count] {
            if store.objects.remove(*digest).is_err() {
                let _ = crate::published_rootfs::uninstall_published_rootfs(slot);
                let _ = memory::scrub_and_release_contiguous_extent(
                    FrameOwner::KERNEL,
                    first_frame,
                    page_count,
                );
                return false;
            }
        }
        if !register_rootfs_backing(slot, first_frame, page_count, rootfs_end) {
            let _ = crate::published_rootfs::uninstall_published_rootfs(slot);
            let _ = memory::scrub_and_release_contiguous_extent(
                FrameOwner::KERNEL,
                first_frame,
                page_count,
            );
            return false;
        }
        store.published_layers[..layer_count].fill(Digest([0; 32]));
        store.published_layer_count = 0;
        true
    })
    .unwrap_or(false)
}

fn rootfs_unpack_allocation(
    expected_lengths: &[usize],
    unpack_limit_bytes: usize,
) -> Option<(usize, usize)> {
    if expected_lengths.is_empty() || unpack_limit_bytes == 0 {
        return None;
    }
    let mut allocation_length = 0_usize;
    for expected_length in expected_lengths {
        if *expected_length == 0 {
            return None;
        }
        allocation_length = allocation_length.checked_add(*expected_length)?;
        if allocation_length > unpack_limit_bytes {
            return None;
        }
    }
    Some((allocation_length, allocation_length.div_ceil(PAGE_SIZE)))
}

pub(crate) fn verify_rootfs_unpack_policy() -> bool {
    DEFAULT_ROOTFS_UNPACK_LIMIT_BYTES == 4 * 1024 * 1024 * 1024
        && rootfs_unpack_allocation(
            &[u32::MAX as usize, u32::MAX as usize],
            DEFAULT_ROOTFS_UNPACK_LIMIT_BYTES,
        )
        .is_none()
        && rootfs_unpack_allocation(
            &[DEFAULT_ROOTFS_UNPACK_LIMIT_BYTES, 1],
            DEFAULT_ROOTFS_UNPACK_LIMIT_BYTES,
        )
        .is_none()
        && rootfs_unpack_allocation(&[0], DEFAULT_ROOTFS_UNPACK_LIMIT_BYTES).is_none()
        && rootfs_unpack_allocation(&[4096, 8192], DEFAULT_ROOTFS_UNPACK_LIMIT_BYTES)
            == Some((12_288, 3))
}

pub(crate) fn install_cached_rootfs(
    slot: usize,
    first_frame: FrameLease,
    page_count: usize,
    length: usize,
) -> bool {
    if slot >= crate::control_abi::DOMAIN_LIMIT
        || page_count == 0
        || length == 0
        || length > page_count.saturating_mul(PAGE_SIZE)
        || crate::published_rootfs::is_installed(slot)
    {
        return false;
    }
    let Some(address) = first_frame.direct_map_address() else {
        return false;
    };
    // SAFETY: the caller hands over a kernel extent of page_count frames
    // that holds the rootfs and is no longer written; it stays allocated
    // while a domain's published rootfs uses it (uninstall_rootfs).
    let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, length) };
    if !crate::published_rootfs::install_published_rootfs(slot, bytes) {
        return false;
    }
    if register_rootfs_backing(slot, first_frame, page_count, length) {
        true
    } else {
        let _ = crate::published_rootfs::uninstall_published_rootfs(slot);
        false
    }
}

fn register_rootfs_backing(
    slot: usize,
    first_frame: FrameLease,
    page_count: usize,
    length: usize,
) -> bool {
    let Some(backing) = IMAGE_STORE.rootfs_refcounts.iter().position(|references| {
        references
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        return false;
    };
    IMAGE_STORE.rootfs_frame_starts[backing].store(first_frame.address(), Ordering::Release);
    IMAGE_STORE.rootfs_frame_counts[backing].store(page_count, Ordering::Release);
    IMAGE_STORE.rootfs_lengths[backing].store(length, Ordering::Release);
    IMAGE_STORE.rootfs_owner_slots[slot].store(backing + 1, Ordering::Release);
    true
}

pub(crate) fn share_installed_rootfs(source: usize, target: usize) -> bool {
    if source >= crate::control_abi::DOMAIN_LIMIT
        || target >= crate::control_abi::DOMAIN_LIMIT
        || source == target
        || crate::published_rootfs::is_installed(target)
    {
        return false;
    }
    let backing = IMAGE_STORE.rootfs_owner_slots[source]
        .load(Ordering::Acquire)
        .checked_sub(1);
    let Some(backing) = backing.filter(|backing| *backing < crate::control_abi::DOMAIN_LIMIT)
    else {
        return false;
    };
    let Some(bytes) = installed_rootfs(source) else {
        return false;
    };
    if !crate::published_rootfs::install_published_rootfs(target, bytes) {
        return false;
    }
    let previous = IMAGE_STORE.rootfs_refcounts[backing].fetch_add(1, Ordering::AcqRel);
    if previous == 0 {
        IMAGE_STORE.rootfs_refcounts[backing].store(0, Ordering::Release);
        let _ = crate::published_rootfs::uninstall_published_rootfs(target);
        return false;
    }
    IMAGE_STORE.rootfs_owner_slots[target].store(backing + 1, Ordering::Release);
    true
}

pub(crate) fn installed_rootfs(slot: usize) -> Option<&'static [u8]> {
    let backing = IMAGE_STORE
        .rootfs_owner_slots
        .get(slot)?
        .load(Ordering::Acquire)
        .checked_sub(1)?;
    let start = IMAGE_STORE
        .rootfs_frame_starts
        .get(backing)?
        .load(Ordering::Acquire);
    let length = IMAGE_STORE
        .rootfs_lengths
        .get(backing)?
        .load(Ordering::Acquire);
    let frame = FrameLease::from_parts(start, 1)?;
    let address = frame.direct_map_address()?;
    // SAFETY: a registered backing extent, read-only once registered and
    // freed only when its last domain uninstalls it.
    (length != 0).then(|| unsafe { core::slice::from_raw_parts(address as *const u8, length) })
}

pub(crate) fn uninstall_rootfs(slot: usize) -> bool {
    if slot >= crate::control_abi::DOMAIN_LIMIT
        || !crate::published_rootfs::uninstall_published_rootfs(slot)
    {
        return false;
    }
    let Some(backing) = IMAGE_STORE.rootfs_owner_slots[slot]
        .swap(0, Ordering::AcqRel)
        .checked_sub(1)
        .filter(|backing| *backing < crate::control_abi::DOMAIN_LIMIT)
    else {
        return true;
    };
    let references = IMAGE_STORE.rootfs_refcounts[backing].load(Ordering::Acquire);
    if references == 0 {
        return false;
    }
    let references = IMAGE_STORE.rootfs_refcounts[backing].fetch_sub(1, Ordering::AcqRel);
    if references > 1 {
        return true;
    }
    let start = IMAGE_STORE.rootfs_frame_starts[backing].load(Ordering::Acquire);
    let count = IMAGE_STORE.rootfs_frame_counts[backing].load(Ordering::Acquire);
    if count == 0 || start == 0 {
        return false;
    }
    let Some(first_frame) = FrameLease::from_parts(start, 1) else {
        return false;
    };
    let released =
        memory::scrub_and_release_contiguous_extent(FrameOwner::KERNEL, first_frame, count);
    if released {
        IMAGE_STORE.rootfs_frame_starts[backing].store(0, Ordering::Release);
        IMAGE_STORE.rootfs_frame_counts[backing].store(0, Ordering::Release);
        IMAGE_STORE.rootfs_lengths[backing].store(0, Ordering::Release);
        IMAGE_STORE.rootfs_refcounts[backing].store(0, Ordering::Release);
    }
    released
}

fn gzip_header_length(backend: &RamBackend, object: u8, length: usize) -> Option<usize> {
    let mut header = [0; PAGE_SIZE];
    let read = length.min(header.len());
    if !backend.read(object, 0, &mut header[..read]) || read < 10 || header[..3] != [0x1f, 0x8b, 8]
    {
        return None;
    }
    let flags = header[3];
    if flags & 0xe0 != 0 {
        return None;
    }
    let mut offset = 10;
    if flags & 4 != 0 {
        let extra = u16::from_le_bytes([*header.get(offset)?, *header.get(offset + 1)?]) as usize;
        offset = offset.checked_add(2 + extra)?;
    }
    for flag in [8, 16] {
        if flags & flag != 0 {
            offset = header.get(offset..)?.iter().position(|byte| *byte == 0)? + offset + 1;
        }
    }
    if flags & 2 != 0 {
        offset = offset.checked_add(2)?;
    }
    (offset < read).then_some(offset)
}

struct ObjectSlices<'a> {
    backend: &'a RamBackend,
    object: u8,
    offset: usize,
    remaining: usize,
}

impl<'a> ObjectSlices<'a> {
    fn new(backend: &'a RamBackend, object: u8, offset: usize, remaining: usize) -> Self {
        Self {
            backend,
            object,
            offset,
            remaining,
        }
    }
}

/// An object's bytes a page at a time, as the inflater takes them.
impl<'a> Iterator for ObjectSlices<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let length = self.remaining.min(PAGE_SIZE - self.offset % PAGE_SIZE);
        let bytes = self
            .backend
            .object(self.object)?
            .get(self.offset..self.offset.checked_add(length)?)?;
        self.offset += length;
        self.remaining -= length;
        Some(bytes)
    }
}
