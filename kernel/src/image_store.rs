use alloc::boxed::Box;
use alloc::vec::Vec;

use linox_image_store::{Digest, ImageStore, ObjectBackend, StagingHandle, StoreError};

use crate::{
    owned_state::OwnedState,
    sync::{LockRank, SpinLock},
    trusted::image::{BootImage, PublishedImage},
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
    /// The unpacked root filesystem images domains have installed, and
    /// which image each domain slot uses. A leaf: images are freed after it
    /// is released.
    rootfs_images: SpinLock<RootfsImages>,
    /// The all-Rust root filesystem carried in the boot image (a gzip'd
    /// POSIX tar) for `image=builtin://rust`.
    builtin_rootfs: OwnedState<BootImage>,
}

/// A published root filesystem image and how many domain slots use it.
struct Backing {
    image: PublishedImage,
    references: usize,
}

struct RootfsImages {
    backings: [Option<Backing>; crate::control_abi::DOMAIN_LIMIT],
    /// Each domain slot's backing, by index.
    owners: [Option<usize>; crate::control_abi::DOMAIN_LIMIT],
}

static IMAGE_STORE: ImageStoreOwner = ImageStoreOwner {
    store: SpinLock::new(LockRank::IMAGE_STORE, None),
    rootfs_images: SpinLock::new(
        LockRank::ROOTFS_IMAGES,
        RootfsImages {
            backings: [const { None }; crate::control_abi::DOMAIN_LIMIT],
            owners: [None; crate::control_abi::DOMAIN_LIMIT],
        },
    ),
    builtin_rootfs: OwnedState::empty(),
};

/// Frees a root filesystem image no domain uses.
fn retire(image: PublishedImage) {
    // SAFETY: every caller hands over an image that no published root
    // filesystem refers to: either its publication failed before any view
    // of it was handed out, or it was uninstalled from the last domain
    // slot that used it, which happens when that domain is torn down,
    // after its processes (the holders of entries borrowed from it) are
    // gone.
    unsafe { image.retire() }
}

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
pub(crate) fn set_builtin_rootfs(image: BootImage) {
    let _ = IMAGE_STORE.builtin_rootfs.try_install(image);
}

pub(crate) fn builtin_rootfs_available() -> bool {
    IMAGE_STORE.builtin_rootfs.get().is_some()
}

/// Stages the boot image's Rust root filesystem as the image's only layer,
/// as a registry pull would, so installation unpacks and checks it with the
/// same code. Its digest is computed here: the bytes come from the boot
/// image, whose integrity is the boot chain's to establish.
pub(crate) fn stage_builtin_layer() -> bool {
    // Read through the direct map: a process's page tables may be loaded.
    let Some(image) = IMAGE_STORE
        .builtin_rootfs
        .get()
        .and_then(|image| image.direct_mapped())
    else {
        return false;
    };
    let bytes = image.bytes();
    let length = bytes.len();
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
        let Some(mut output) = zeroed_image(page_count * PAGE_SIZE) else {
            crate::serial_write_bytes(b"linox: OCI rootfs memory allocation failed: ");
            crate::serial_write_u64(allocation_length as u64);
            crate::serial_write_bytes(b" bytes\r\n");
            return false;
        };
        let mut rootfs_length = 0_usize;
        for index in 0..layer_count {
            let expected_length = expected_lengths[index];
            let Some(layer_end) = rootfs_length.checked_add(expected_length) else {
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
                return false;
            };
            if written != expected_length {
                return false;
            }
            let Some(layer) = linox_oci::Rootfs::parse(&output[rootfs_length..layer_end]) else {
                return false;
            };
            rootfs_length += layer.content_length();
        }
        let Some(rootfs_end) = rootfs_length.checked_add(1024) else {
            return false;
        };
        if rootfs_end > output.len() {
            return false;
        }
        output[rootfs_length..rootfs_end].fill(0);
        output.truncate(rootfs_end);
        let image = PublishedImage::publish(output);
        if !crate::published_rootfs::install_published_rootfs(slot, image.bytes()) {
            crate::serial_write_bytes(b"linox: OCI rootfs publication failed\r\n");
            retire(image);
            return false;
        }
        for digest in &digests[..layer_count] {
            if store.objects.remove(*digest).is_err() {
                let _ = crate::published_rootfs::uninstall_published_rootfs(slot);
                retire(image);
                return false;
            }
        }
        if let Err(image) = register_rootfs_backing(slot, image) {
            let _ = crate::published_rootfs::uninstall_published_rootfs(slot);
            retire(image);
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

/// A zeroed buffer of `length` bytes on the kernel heap, if there is room.
pub(crate) fn zeroed_image(length: usize) -> Option<Vec<u8>> {
    let mut image = Vec::new();
    image.try_reserve_exact(length).ok()?;
    image.resize(length, 0);
    Some(image)
}

/// Installs `image`, a root filesystem image read back from the image
/// cache, as domain slot `slot`'s root filesystem.
pub(crate) fn install_cached_rootfs(slot: usize, image: Vec<u8>) -> bool {
    if slot >= crate::control_abi::DOMAIN_LIMIT
        || image.is_empty()
        || crate::published_rootfs::is_installed(slot)
    {
        return false;
    }
    let image = PublishedImage::publish(image);
    if !crate::published_rootfs::install_published_rootfs(slot, image.bytes()) {
        retire(image);
        return false;
    }
    match register_rootfs_backing(slot, image) {
        Ok(()) => true,
        Err(image) => {
            let _ = crate::published_rootfs::uninstall_published_rootfs(slot);
            retire(image);
            false
        }
    }
}

/// Records `image` as the backing of slot `slot`'s root filesystem, or
/// hands it back if there is no free backing.
fn register_rootfs_backing(slot: usize, image: PublishedImage) -> Result<(), PublishedImage> {
    let mut images = IMAGE_STORE.rootfs_images.lock();
    let Some(backing) = images.backings.iter().position(Option::is_none) else {
        return Err(image);
    };
    if slot >= images.owners.len() || images.owners[slot].is_some() {
        return Err(image);
    }
    images.backings[backing] = Some(Backing {
        image,
        references: 1,
    });
    images.owners[slot] = Some(backing);
    Ok(())
}

pub(crate) fn share_installed_rootfs(source: usize, target: usize) -> bool {
    if source >= crate::control_abi::DOMAIN_LIMIT
        || target >= crate::control_abi::DOMAIN_LIMIT
        || source == target
        || crate::published_rootfs::is_installed(target)
    {
        return false;
    }
    let Some((backing, bytes)) = ({
        let images = IMAGE_STORE.rootfs_images.lock();
        images.owners[source].and_then(|backing| {
            let image = images.backings[backing].as_ref()?;
            Some((backing, image.image.bytes()))
        })
    }) else {
        return false;
    };
    if !crate::published_rootfs::install_published_rootfs(target, bytes) {
        return false;
    }
    let shared = {
        let mut images = IMAGE_STORE.rootfs_images.lock();
        // The source may have let go of the image meanwhile.
        let still_held = images.owners[source] == Some(backing) && images.owners[target].is_none();
        match images.backings[backing].as_mut() {
            Some(held) if still_held => {
                held.references += 1;
                images.owners[target] = Some(backing);
                true
            }
            _ => false,
        }
    };
    if !shared {
        let _ = crate::published_rootfs::uninstall_published_rootfs(target);
    }
    shared
}

pub(crate) fn installed_rootfs(slot: usize) -> Option<&'static [u8]> {
    let images = IMAGE_STORE.rootfs_images.lock();
    let backing = (*images.owners.get(slot)?)?;
    Some(images.backings[backing].as_ref()?.image.bytes())
}

pub(crate) fn uninstall_rootfs(slot: usize) -> bool {
    if slot >= crate::control_abi::DOMAIN_LIMIT
        || !crate::published_rootfs::uninstall_published_rootfs(slot)
    {
        return false;
    }
    let released = {
        let mut images = IMAGE_STORE.rootfs_images.lock();
        let Some(backing) = images.owners[slot].take() else {
            return true;
        };
        let Some(held) = images.backings[backing].as_mut() else {
            return false;
        };
        held.references -= 1;
        if held.references != 0 {
            return true;
        }
        images.backings[backing].take()
    };
    if let Some(released) = released {
        retire(released.image);
    }
    true
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
