use super::*;

/// x86 pages that can be written or executed can be read: Linux accepts
/// PROT_WRITE or PROT_EXEC alone and maps them readable too. Linox keeps no
/// page both writable and executable.
pub(super) fn linux_implied_protection(protection: u64) -> u64 {
    if protection & (LINUX_PROT_WRITE | LINUX_PROT_EXEC) != 0 {
        protection | LINUX_PROT_READ
    } else {
        protection
    }
}

/// The page protection for a mapping's `protection`: writable and
/// executable, allowed only in a `write-execute=true` domain, starts out
/// writable (`linux_flip_write_execute_page`); otherwise it is refused
/// as before, by staying a combination the callers reject.
pub(super) fn linux_runtime_page_protection(protection: u64) -> u64 {
    let write_execute = LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC;
    if protection == write_execute && linux_write_execute_allowed() {
        LINUX_PROT_READ | LINUX_PROT_WRITE
    } else {
        protection
    }
}

pub(super) fn linux_runtime_mprotect(address: u64, length: u64, protection: u64) -> u64 {
    let protection = linux_runtime_page_protection(linux_implied_protection(protection));
    if ![
        0,
        LINUX_PROT_READ,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_PROT_READ | LINUX_PROT_EXEC,
    ]
    .contains(&protection)
    {
        return LINUX_EINVAL;
    }
    let Some((_, pages)) = linux_runtime_mapping_range(address, length) else {
        return LINUX_EINVAL;
    };
    if (0..pages).any(|page| {
        let state = address_space::current_linux_runtime_page(address + (page * PAGE_SIZE) as u64);
        !state.occupied || state.sealed
    }) {
        return if (0..pages).any(|page| {
            address_space::current_linux_runtime_page(address + (page * PAGE_SIZE) as u64).sealed
        }) {
            LINUX_EPERM
        } else {
            LINUX_ENOMEM
        };
    }
    // A private page that the file cache or another address space also
    // holds gets its own copy before it becomes writable.
    if protection & LINUX_PROT_WRITE != 0 {
        for page in 0..pages {
            let page_address = address + (page * PAGE_SIZE) as u64;
            let state = address_space::current_linux_runtime_page(page_address);
            let Some(source) = state.frame.filter(|frame| {
                crate::linux_file_cache::contains(*frame)
                    || !state.shared && memory::frame_is_shared(*frame)
            }) else {
                continue;
            };
            let Some([replacement]) = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL)
            else {
                return LINUX_ENOMEM;
            };
            if !address_space::copy_linux_frame(source, replacement)
                || address_space::replace_current_linux_runtime_page(
                    page_address,
                    replacement,
                    protection as u8,
                ) != Some(source)
            {
                let _ =
                    memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[replacement]);
                return LINUX_ENOMEM;
            }
            if !address_space::release_linux_private_page(source) {
                return LINUX_ENOMEM;
            }
        }
    }
    if (0..pages).all(|page| {
        address_space::protect_current_linux_runtime_page(
            address + (page * PAGE_SIZE) as u64,
            protection as u8,
        )
    }) {
        0
    } else {
        LINUX_EINVAL
    }
}

fn linux_runtime_madvise(address: u64, length: u64, advice: u64) -> u64 {
    if matches!(
        advice,
        LINUX_MADV_NORMAL
            | LINUX_MADV_RANDOM
            | LINUX_MADV_SEQUENTIAL
            | LINUX_MADV_WILLNEED
            | LINUX_MADV_MERGEABLE
            | LINUX_MADV_UNMERGEABLE
            | LINUX_MADV_HUGEPAGE
            | LINUX_MADV_NOHUGEPAGE
            | LINUX_MADV_DONTDUMP
            | LINUX_MADV_DODUMP
    ) {
        if length == 0 || !address.is_multiple_of(PAGE_SIZE as u64) {
            return LINUX_EINVAL;
        }
        let Some(pages) = length
            .checked_add(PAGE_SIZE as u64 - 1)
            .and_then(|rounded| usize::try_from(rounded / PAGE_SIZE as u64).ok())
        else {
            return LINUX_ENOMEM;
        };
        let Some(bytes) = pages.checked_mul(PAGE_SIZE) else {
            return LINUX_ENOMEM;
        };
        if address
            .checked_add(bytes as u64)
            .is_none_or(|end| end > 1 << 47)
        {
            return LINUX_ENOMEM;
        }
        let valid = (0..pages).all(|page| {
            let state =
                address_space::current_linux_runtime_page(address + (page * PAGE_SIZE) as u64);
            state.occupied
                && (!matches!(advice, LINUX_MADV_MERGEABLE | LINUX_MADV_UNMERGEABLE)
                    || !state.file && !state.shared && !state.secret)
        });
        if !valid {
            return LINUX_ENOMEM;
        }
        // Core dumps leave MADV_DONTDUMP's areas out.
        if matches!(advice, LINUX_MADV_DONTDUMP | LINUX_MADV_DODUMP) {
            crate::linux_areas::set_dont_dump(
                linux_execution_instance(),
                current_linux_process_pid(),
                address,
                length,
                advice == LINUX_MADV_DONTDUMP,
            );
        }
        if advice == LINUX_MADV_WILLNEED {
            // Pages out in swap are read into the swap cache.
            linux_swapon::linux_swap_willneed(address, pages);
        }
        return 0;
    }
    let Some((_, pages)) = linux_runtime_mapping_range(address, length) else {
        return LINUX_EINVAL;
    };
    if !matches!(
        advice,
        LINUX_MADV_DONTNEED | LINUX_MADV_FREE | LINUX_MADV_DONTNEED_LOCKED
    ) {
        return LINUX_EINVAL;
    }
    let free = advice == LINUX_MADV_FREE;
    for page in 0..pages {
        let page_address = address + (page * PAGE_SIZE) as u64;
        let state = address_space::current_linux_runtime_page(page_address);
        if !state.occupied
            || free && (state.file || state.shared || state.secret)
            || !free && (state.file || state.protection == 0)
        {
            return LINUX_EINVAL;
        }
        if state.sealed {
            return LINUX_EPERM;
        }
        // A shared mapping's page keeps its contents for the other mappings
        // and is read back unchanged, as Linux rereads it from the object.
        // One a userfaultfd watches for minor faults is unmapped, so its
        // next touch maps it again through that fault.
        if state.shared {
            if linux_userfaultfd_minor_page(page_address) {
                let removed = address_space::remove_current_linux_runtime_page(page_address);
                if !release_linux_runtime_page(removed)
                    || address_space::reserve_current_linux_past_eof_page(
                        page_address,
                        state.protection,
                        false,
                    )
                    .is_none()
                {
                    return LINUX_EINVAL;
                }
            }
            continue;
        }
        // MADV_FREE keeps the page until memory runs short; written first,
        // it stays (`linux_memcg_reclaim` drops it otherwise).
        if free && state.frame.is_some() {
            if !address_space::mark_current_linux_page_lazyfree(page_address) {
                return LINUX_EINVAL;
            }
            crate::linux_cgroup::note_reclaimable();
            continue;
        }
        // A page out in swap goes as one in memory does: its swap is freed
        // and it reads as zeros next.
        if state.frame.is_some() || state.swap.is_some() {
            let removed = address_space::remove_current_linux_runtime_page(page_address);
            if removed.frame != state.frame
                || address_space::reserve_current_linux_runtime_page(
                    page_address,
                    state.protection,
                    false,
                    false,
                ) != Some(None)
                || state.dontfork
                    && !address_space::set_current_linux_runtime_page_dontfork(page_address, true)
                || state.wipeonfork
                    && !address_space::set_current_linux_runtime_page_wipeonfork(page_address, true)
            {
                return LINUX_EINVAL;
            }
            if removed
                .frame
                .is_some_and(|frame| !release_linux_runtime_frame(frame))
            {
                return LINUX_EINVAL;
            }
        } else if !address_space::current_linux_runtime_page(page_address).occupied {
            return LINUX_EINVAL;
        }
    }
    0
}

fn linux_madvise_inheritance(address: u64, length: u64, enabled: bool) -> u64 {
    if length == 0 || !address.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let Some(pages) = length
        .checked_add(PAGE_SIZE as u64 - 1)
        .and_then(|rounded| usize::try_from(rounded / PAGE_SIZE as u64).ok())
    else {
        return LINUX_EINVAL;
    };
    let Some(last) = pages
        .checked_sub(1)
        .and_then(|page| page.checked_mul(PAGE_SIZE))
        .and_then(|offset| address.checked_add(offset as u64))
    else {
        return LINUX_ENOMEM;
    };
    if last >= 1 << 47
        || (0..pages).any(|page| {
            !address_space::current_linux_runtime_page(address + (page * PAGE_SIZE) as u64).occupied
        })
    {
        return LINUX_ENOMEM;
    }
    if enabled
        && (0..pages).any(|page| {
            address_space::current_linux_runtime_page(address + (page * PAGE_SIZE) as u64).sealed
        })
    {
        return LINUX_EPERM;
    }
    if (0..pages).all(|page| {
        address_space::set_current_linux_runtime_page_dontfork(
            address + (page * PAGE_SIZE) as u64,
            enabled,
        )
    }) {
        0
    } else {
        LINUX_EINVAL
    }
}

fn linux_madvise_wipeonfork(address: u64, length: u64, enabled: bool) -> u64 {
    if length == 0 || !address.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let Some(pages) = length
        .checked_add(PAGE_SIZE as u64 - 1)
        .and_then(|rounded| usize::try_from(rounded / PAGE_SIZE as u64).ok())
    else {
        return LINUX_EINVAL;
    };
    if (0..pages).any(|page| {
        let Some(page_address) = (page * PAGE_SIZE)
            .try_into()
            .ok()
            .and_then(|offset: u64| address.checked_add(offset))
        else {
            return true;
        };
        let state = address_space::current_linux_runtime_page(page_address);
        !state.occupied || state.file || state.shared
    }) {
        return LINUX_EINVAL;
    }
    if enabled
        && (0..pages).any(|page| {
            address_space::current_linux_runtime_page(address + (page * PAGE_SIZE) as u64).sealed
        })
    {
        return LINUX_EPERM;
    }
    if (0..pages).all(|page| {
        address_space::set_current_linux_runtime_page_wipeonfork(
            address + (page * PAGE_SIZE) as u64,
            enabled,
        )
    }) {
        0
    } else {
        LINUX_EINVAL
    }
}

fn linux_madvise_populate(address: u64, length: u64, writable: bool) -> u64 {
    if length == 0 || !address.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let Some(pages) = length
        .checked_add(PAGE_SIZE as u64 - 1)
        .and_then(|rounded| usize::try_from(rounded / PAGE_SIZE as u64).ok())
    else {
        return LINUX_ENOMEM;
    };
    let Some(mapped_length) = pages.checked_mul(PAGE_SIZE) else {
        return LINUX_ENOMEM;
    };
    let required = if writable {
        LINUX_PROT_WRITE
    } else {
        LINUX_PROT_READ
    } as u8;
    for page in 0..pages {
        let Some(page_address) = page
            .checked_mul(PAGE_SIZE)
            .and_then(|offset| address.checked_add(offset as u64))
        else {
            return LINUX_ENOMEM;
        };
        let state = address_space::current_linux_runtime_page(page_address);
        if !state.occupied {
            return LINUX_ENOMEM;
        }
        if state.secret || state.protection & required == 0 {
            return LINUX_EINVAL;
        }
    }
    if materialize_linux_runtime_user_range(address, mapped_length, writable) {
        0
    } else {
        LINUX_ENOMEM
    }
}

fn linux_madvise_reclaim_hint(address: u64, length: u64, pageout: bool) -> u64 {
    if length == 0 || !address.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let Some(pages) = length
        .checked_add(PAGE_SIZE as u64 - 1)
        .and_then(|rounded| usize::try_from(rounded / PAGE_SIZE as u64).ok())
    else {
        return LINUX_ENOMEM;
    };
    for page in 0..pages {
        let Some(page_address) = page
            .checked_mul(PAGE_SIZE)
            .and_then(|offset| address.checked_add(offset as u64))
        else {
            return LINUX_ENOMEM;
        };
        let state = address_space::current_linux_runtime_page(page_address);
        if !state.occupied {
            return LINUX_ENOMEM;
        }
        if state.secret {
            return LINUX_EINVAL;
        }
    }
    // MADV_PAGEOUT pages the range's private anonymous pages out to swap
    // now, if there is swap; both are advice, so what stays is no error.
    // MADV_COLD only makes the pages the first reclaim takes, which its
    // scan does as it finds them (there is no LRU to move them in).
    if pageout {
        linux_swapon::linux_swap_pageout(current_linux_process_pid(), address, pages);
    }
    0
}

/// MADV_SOFT_OFFLINE (CONFIG_MEMORY_FAILURE): soft-offlines each page of
/// the range, as Linux does memory that reports correctable errors. The
/// page is faulted in if need be, its contents move to a fresh frame that
/// its mapping then maps, and the frame it left is taken out of service
/// (`memory_failure`); each is logged as Linux logs it. The frames are the
/// machine's, so only root of a domain set `privileged=true` may: EPERM
/// otherwise, as for a caller without CAP_SYS_ADMIN. EFAULT for a page
/// nothing maps; EBUSY for one that cannot move (memory another process
/// shares, file cache, System V or secret memory).
/// madvise(MADV_HWPOISON), Linux's memory-failure injection for testing:
/// each page's memory is taken away as a failed page's would be, and
/// touching the page again is SIGBUS. Needs CAP_SYS_ADMIN.
fn linux_madvise_hwpoison(address: u64, length: u64) -> u64 {
    if !address.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let Some(end) = length
        .checked_next_multiple_of(PAGE_SIZE as u64)
        .and_then(|length| address.checked_add(length))
    else {
        return LINUX_EINVAL;
    };
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ManageKernel)
        || !linux_has_capability(linox_credentials::capability::SYS_ADMIN)
    {
        return LINUX_EPERM;
    }
    for page in (address..end).step_by(PAGE_SIZE) {
        let state = address_space::current_linux_runtime_page(page);
        if !state.occupied {
            return LINUX_EFAULT;
        }
        crate::serial_write_bytes(
            alloc::format!("Injecting memory failure at process virtual address {page:#x}\n")
                .as_bytes(),
        );
        // The page stays in the mapping without memory, as a page past a
        // mapped file's end does: its next touch is SIGBUS.
        if !release_linux_runtime_page(address_space::remove_current_linux_runtime_page(page))
            || address_space::reserve_current_linux_past_eof_page(page, state.protection, false)
                .is_none()
        {
            return LINUX_EFAULT;
        }
    }
    0
}

fn linux_madvise_soft_offline(address: u64, length: u64) -> u64 {
    if !address.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let Some(end) = length
        .checked_next_multiple_of(PAGE_SIZE as u64)
        .and_then(|length| address.checked_add(length))
    else {
        return LINUX_EINVAL;
    };
    if end == address {
        return 0;
    }
    if !linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ManageKernel)
        || !linux_has_capability(linox_credentials::capability::SYS_ADMIN)
    {
        return LINUX_EPERM;
    }
    for page in (address..end).step_by(PAGE_SIZE) {
        let mut state = address_space::current_linux_runtime_page(page);
        if !state.occupied || state.protection == 0 {
            return LINUX_EFAULT;
        }
        if state.frame.is_none() {
            if !materialize_linux_runtime_user_range(page, PAGE_SIZE, false) {
                return LINUX_EFAULT;
            }
            state = address_space::current_linux_runtime_page(page);
        }
        let Some(frame) = state.frame else {
            return LINUX_EFAULT;
        };
        crate::serial_write_bytes(
            alloc::format!(
                "Soft offlining pfn {:#x} at process virtual address {page:#x}\n",
                frame.address() / PAGE_SIZE as u64
            )
            .as_bytes(),
        );
        if let Err(error) = linux_soft_offline_page(page, state, frame) {
            return error;
        }
    }
    0
}

/// Moves page `page` of the current process, `state` in its page table and
/// held in `frame`, to a fresh frame and retires `frame`.
fn linux_soft_offline_page(
    page: u64,
    state: address_space::LinuxRuntimePage,
    frame: memory::FrameLease,
) -> Result<(), u64> {
    if state.secret || crate::linux_file_cache::contains(frame) {
        return Err(LINUX_EBUSY);
    }
    // A shared page is a paged file's (anonymous shared memory's, a
    // memfd's, a file's): its frame index moves with it, which only this
    // mapping may map, as no other address space can be changed from here.
    let file_page = if state.shared {
        let pid = current_linux_process_pid();
        let (handle, offset) =
            crate::linux_overlay::shared_mapping(pid, page).ok_or(LINUX_EBUSY)?;
        if crate::linux_overlay::paged_frame(handle, offset / PAGE_SIZE) != Some(frame)
            || !crate::linux_overlay::sole_shared_mapping(handle, offset, pid, page)
        {
            return Err(LINUX_EBUSY);
        }
        Some((handle, offset / PAGE_SIZE))
    } else {
        // A private page another address space still maps copy-on-write.
        if memory::frame_is_shared(frame) {
            return Err(LINUX_EBUSY);
        }
        None
    };
    let [replacement] = memory::allocate_user_frames::<1>().ok_or(LINUX_ENOMEM)?;
    if address_space::migrate_current_linux_runtime_page(page, replacement) != Some(frame) {
        let _ = release_linux_runtime_frame(replacement);
        return Err(LINUX_EBUSY);
    }
    if let Some((handle, index)) = file_page {
        // Checked above, with the kernel held since: it cannot fail.
        let _ = crate::linux_overlay::replace_paged_frame(handle, index, frame, replacement);
    }
    crate::memory_failure::retire(frame);
    Ok(())
}

fn linux_runtime_mincore(address: u64, length: u64, vector: u64) -> u64 {
    if length == 0 || !address.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let Some(pages) = length
        .checked_add(PAGE_SIZE as u64 - 1)
        .and_then(|rounded| usize::try_from(rounded / PAGE_SIZE as u64).ok())
    else {
        return LINUX_ENOMEM;
    };
    if pages.checked_mul(PAGE_SIZE).is_none()
        || address
            .checked_add((pages * PAGE_SIZE) as u64)
            .is_none_or(|end| end > 1 << 47)
    {
        return LINUX_ENOMEM;
    }
    for page in 0..pages {
        let state = address_space::current_linux_runtime_page(address + (page * PAGE_SIZE) as u64);
        if !state.occupied {
            return LINUX_ENOMEM;
        }
    }
    let mut area: Option<crate::linux_areas::Area> = None;
    for page in 0..pages {
        let page_address = address + (page * PAGE_SIZE) as u64;
        let state = address_space::current_linux_runtime_page(page_address);
        if area
            .as_ref()
            .is_none_or(|area| !(area.start..area.end).contains(&page_address))
        {
            area = crate::linux_areas::area_at(
                linux_execution_instance(),
                current_linux_process_pid(),
                page_address,
            );
        }
        // A volume file's page is resident while the page cache holds it,
        // mapped or not, as Linux's mincore reports a file's pages.
        let cached = area.as_ref().and_then(|area| match &area.backing {
            crate::linux_areas::Backing::File {
                device,
                inode,
                offset,
                ..
            } => {
                let index = (offset + (page_address - area.start)) / PAGE_SIZE as u64;
                crate::linux_blockfs::page_cached_at(*device, *inode, usize::try_from(index).ok()?)
            }
            _ => None,
        });
        // Anonymous shared memory has its pages from the start; one counts
        // as resident once touched, as Linux allocates it then.
        let resident = u8::from(cached.unwrap_or_else(|| {
            state.frame.is_some()
                && (!state.shared
                    || !linux_anonymous_shared_area(page_address)
                    || address_space::current_linux_page_accessed(page_address))
        }));
        if !copy_to_linux_user(vector + page as u64, &[resident]) {
            return LINUX_EFAULT;
        }
    }
    0
}

/// Whether the current process's area covering `address` is anonymous
/// shared memory (MAP_SHARED | MAP_ANONYMOUS).
pub(super) fn linux_anonymous_shared_area(address: u64) -> bool {
    crate::linux_areas::area_at(
        linux_execution_instance(),
        current_linux_process_pid(),
        address,
    )
    .is_some_and(|area| area.shared && area.backing == crate::linux_areas::Backing::Anonymous)
}

pub(super) fn linux_mprotect(address: u64, length: u64, protection: u64) -> u64 {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        // Linux's order: a bad address or protection, then an empty range
        // (nothing to do), then a range with unmapped pages.
        const PROT_SEM: u64 = 0x8;
        const PROT_GROWSDOWN: u64 = 0x0100_0000;
        const PROT_GROWSUP: u64 = 0x0200_0000;
        let known = LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC | PROT_SEM;
        if !address.is_multiple_of(PAGE_SIZE as u64)
            || protection & !(known | PROT_GROWSDOWN | PROT_GROWSUP) != 0
            || protection & (PROT_GROWSDOWN | PROT_GROWSUP) == PROT_GROWSDOWN | PROT_GROWSUP
        {
            return LINUX_EINVAL;
        }
        if length == 0 {
            return 0;
        }
        let Some(end) = address
            .checked_add(length)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE as u64))
            .filter(|end| *end <= 1 << 47)
        else {
            return LINUX_ENOMEM;
        };
        if (address..end)
            .step_by(PAGE_SIZE)
            .any(|page| !address_space::current_linux_runtime_page(page).occupied)
        {
            return LINUX_ENOMEM;
        }
    }
    if !address.is_multiple_of(PAGE_SIZE as u64) || length == 0 {
        return LINUX_EINVAL;
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && (address >= LINUX_FIXED_LOW_BASE || linux_runtime_heap_contains(address))
    {
        return linux_runtime_mprotect(address, length, protection);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        if let Some(result) = linux_mprotect_image(address, length, protection) {
            return result;
        }
    }
    let relro = X86_RUNTIME.ELF_PROBE_RELRO.load(Ordering::SeqCst);
    let relro_size = X86_RUNTIME.ELF_PROBE_RELRO_SIZE.load(Ordering::SeqCst);
    let relro_active_index = linux_active_image_writable_index(address);
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && protection == LINUX_PROT_READ
        && length.is_multiple_of(PAGE_SIZE as u64)
        && address_space::protect_current_linux_range_read_only(address, length)
    {
        let end = address.saturating_add(length);
        let active_count = usize::from(
            X86_RUNTIME
                .ELF_PROBE_ACTIVE_IMAGE_COUNT
                .load(Ordering::SeqCst),
        );
        for index in 0..active_count {
            let image_address =
                X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[index].load(Ordering::SeqCst);
            if (address..end).contains(&image_address) {
                X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].fetch_and(!1, Ordering::SeqCst);
            }
        }
        return 0;
    }
    if protection == LINUX_PROT_READ
        && address == relro
        && length == PAGE_SIZE as u64
        && relro_size != 0
        && relro_size <= PAGE_SIZE as u64
        && X86_RUNTIME
            .ELF_PROBE_READ_ONLY_DATA_PAGE
            .load(Ordering::SeqCst)
            == 0
    {
        if let Some(relro_active_index) = relro_active_index {
            if address_space::protect_current_user_page_read_only(address) {
                X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[relro_active_index]
                    .store(0, Ordering::SeqCst);
                X86_RUNTIME
                    .ELF_PROBE_READ_ONLY_DATA_PAGE
                    .store(address, Ordering::SeqCst);
                return 0;
            }
        }
    }
    linux_mprotect_mmap(address, length, protection)
}

/// mprotect of program-image pages (the data and bss of the program a
/// process runs, below the runtime's mappings) between read-only and
/// read-write (signal06 makes a static array read-only and writable again).
/// The page tables, the process's image records and its registered mappings
/// change together, so fork and exit, which check each against the others,
/// see one protection. None when the range is not all such pages (code
/// pages among them) or the protection is another, for the other paths.
fn linux_mprotect_image(address: u64, length: u64, protection: u64) -> Option<u64> {
    let writable = match protection {
        LINUX_PROT_READ => false,
        _ if protection == LINUX_PROT_READ | LINUX_PROT_WRITE => true,
        _ => return None,
    };
    let count = usize::from(
        X86_RUNTIME
            .ELF_PROBE_ACTIVE_IMAGE_COUNT
            .load(Ordering::SeqCst),
    )
    .min(LINUX_ACTIVE_IMAGE_MAPPING_LIMIT);
    let end = address
        .checked_add(length)?
        .checked_next_multiple_of(PAGE_SIZE as u64)?;
    let record = |page: u64| -> Option<(usize, memory::FrameLease)> {
        let index = X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[..count]
            .iter()
            .position(|candidate| candidate.load(Ordering::SeqCst) == page)?;
        if X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].load(Ordering::SeqCst) & 2 != 0 {
            return None;
        }
        let frame = memory::FrameLease::from_parts(
            X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index].load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index].load(Ordering::SeqCst),
        )?;
        (address_space::current_linux_mapping_frame_address(page) == Some(frame.address())
            && address_space::current_linux_active_mapping(page)
                .is_some_and(|mapping| !mapping.executable))
        .then_some((index, frame))
    };
    if !(address..end)
        .step_by(PAGE_SIZE)
        .all(|page| record(page).is_some())
    {
        return None;
    }
    let pid = current_linux_process_pid();
    for page in (address..end).step_by(PAGE_SIZE) {
        let Some((index, frame)) = record(page) else {
            return Some(LINUX_EINVAL);
        };
        if !address_space::set_current_linux_image_page_writable(page, frame, writable) {
            return Some(LINUX_EINVAL);
        }
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].store(u8::from(writable), Ordering::SeqCst);
        // A registry without this page (or that cannot take the change)
        // is read from the page tables instead.
        if !linux_process::replace_live_process_mapping(
            pid,
            page as usize,
            frame,
            frame,
            writable,
            false,
        ) {
            let _ = linux_process::mark_live_process_address_space_stale(pid);
        }
    }
    Some(0)
}

pub(super) fn linux_mseal(address: u64, length: u64, flags: u64) -> u64 {
    if flags != 0 || !address.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    if length == 0 {
        return 0;
    }
    let Some(rounded) = length.checked_add(PAGE_SIZE as u64 - 1) else {
        return LINUX_EINVAL;
    };
    let rounded = rounded & !(PAGE_SIZE as u64 - 1);
    if rounded == 0 || address.checked_add(rounded).is_none() {
        return LINUX_EINVAL;
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && address >= LINUX_FIXED_LOW_BASE {
        let Some((_, pages)) = linux_runtime_mapping_range(address, rounded) else {
            return LINUX_ENOMEM;
        };
        if (0..pages).any(|page| {
            !address_space::current_linux_runtime_page(address + (page * PAGE_SIZE) as u64).occupied
        }) {
            return LINUX_ENOMEM;
        }
        return if (0..pages).all(|page| {
            address_space::seal_current_linux_runtime_page(address + (page * PAGE_SIZE) as u64)
        }) {
            0
        } else {
            LINUX_ENOMEM
        };
    }
    let Some((start_slot, pages)) = linux_mmap_range_slots(address, rounded) else {
        return LINUX_ENOMEM;
    };
    if (start_slot..start_slot + pages).any(|slot| !linux_mmap_slot_occupied(slot)) {
        return LINUX_ENOMEM;
    }
    for sealed in &X86_RUNTIME.ELF_PROBE_MMAP_SEALED[start_slot..start_slot + pages] {
        sealed.store(true, Ordering::SeqCst);
    }
    0
}

pub(super) fn linux_pkey_mprotect(address: u64, length: u64, protection: u64, key: u64) -> u64 {
    let key = key as i32;
    if key != 0 && key != -1 {
        return LINUX_EINVAL;
    }
    linux_mprotect(address, length, protection)
}

pub(super) fn linux_pkey_alloc(flags: u64, access_rights: u64) -> u64 {
    if flags != 0 || access_rights & !3 != 0 {
        return LINUX_EINVAL;
    }
    LINUX_ENOSPC
}

pub(super) const fn linux_pkey_free(key: u64) -> u64 {
    let _key = key as i32;
    LINUX_EINVAL
}

fn linux_mprotect_mmap(address: u64, length: u64, protection: u64) -> u64 {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && address >= LINUX_FIXED_LOW_BASE {
        return linux_runtime_mprotect(address, length, protection);
    }
    if protection != 0
        && protection != LINUX_PROT_READ
        && protection != (LINUX_PROT_READ | LINUX_PROT_WRITE)
    {
        return LINUX_EINVAL;
    }
    let Some((start_slot, pages)) = linux_mmap_range_slots(address, length) else {
        return LINUX_EINVAL;
    };
    let target = protection as u8;
    let mut slots = linux_mmap_slot_attributes();
    if (start_slot..start_slot + pages)
        .any(|slot| X86_RUNTIME.ELF_PROBE_MMAP_SEALED[slot].load(Ordering::SeqCst))
    {
        return LINUX_EPERM;
    }
    if slots[start_slot..start_slot + pages]
        .iter()
        .any(|slot| slot.is_none())
    {
        return LINUX_EINVAL;
    }
    if slots[start_slot..start_slot + pages]
        .iter()
        .all(|slot| slot.is_some_and(|(current, _)| current == target))
    {
        for offset in 0..pages {
            let slot = start_slot + offset;
            let Some((current, _)) = slots[slot] else {
                return LINUX_EINVAL;
            };
            let page = address + (offset * PAGE_SIZE) as u64;
            if current == 0 {
                if linux_mmap_slot_frame(slot) != 0
                    || X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].load(Ordering::SeqCst) != 0
                    || !address_space::current_linux_page_absent(page)
                {
                    return LINUX_EINVAL;
                }
            } else {
                let Some(lease) = linux_mmap_slot_lease(slot) else {
                    return LINUX_EINVAL;
                };
                if !address_space::current_linux_mapping_matches(
                    page,
                    lease,
                    u64::from(current) & LINUX_PROT_WRITE != 0,
                    false,
                ) {
                    return LINUX_EINVAL;
                }
            }
        }
        return 0;
    }
    let all_reserved = slots[start_slot..start_slot + pages]
        .iter()
        .all(|slot| slot == &Some((0, 0)));
    if all_reserved {
        for offset in 0..pages {
            let slot = start_slot + offset;
            if linux_mmap_slot_frame(slot) != 0
                || X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].load(Ordering::SeqCst) != 0
                || !address_space::current_linux_page_absent(address + (offset * PAGE_SIZE) as u64)
            {
                return LINUX_EINVAL;
            }
        }
        let Some(leases) = linux_allocate_mmap_leases(pages) else {
            return LINUX_ENOMEM;
        };
        for lease in &leases[..pages] {
            if !address_space::prepare_linux_frame(lease.address(), &[]) {
                let _ =
                    memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &leases[..pages]);
                return LINUX_ENOMEM;
            }
        }
        if !address_space::map_current_linux_pages(
            address,
            &leases[..pages],
            protection & LINUX_PROT_WRITE != 0,
        ) {
            let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &leases[..pages]);
            return LINUX_ENOMEM;
        }
        for (offset, lease) in leases[..pages].iter().copied().enumerate() {
            linux_mmap_store_slot_lease(start_slot + offset, lease);
            slots[start_slot + offset] = Some((target, 0));
        }
        linux_mmap_rebuild_areas(slots);
        return 0;
    }
    if protection == LINUX_PROT_READ
        && slots[start_slot..start_slot + pages]
            .iter()
            .all(|slot| slot == &Some(((LINUX_PROT_READ | LINUX_PROT_WRITE) as u8, 0)))
    {
        let mut frames = [0_u64; LINUX_RUNTIME_MMAP_SLOT_COUNT];
        for (offset, frame) in frames.iter_mut().enumerate().take(pages) {
            *frame = linux_mmap_slot_frame(start_slot + offset);
        }
        if address_space::protect_current_linux_pages_read_only(address, &frames[..pages]) {
            for slot in &mut slots[start_slot..start_slot + pages] {
                *slot = Some((LINUX_PROT_READ as u8, 0));
            }
            linux_mmap_rebuild_areas(slots);
            return 0;
        }
    }
    LINUX_EINVAL
}

pub(super) fn linux_madvise(address: u64, length: u64, advice: u64) -> u64 {
    let advice = u64::from(advice as u32);
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        // Linox has no same-page merging: Linux built without CONFIG_KSM
        // refuses the advice (madvise02).
        if matches!(advice, LINUX_MADV_MERGEABLE | LINUX_MADV_UNMERGEABLE) {
            return LINUX_EINVAL;
        }
        if length == 0
            && address.is_multiple_of(PAGE_SIZE as u64)
            && matches!(advice, LINUX_MADV_WIPEONFORK | LINUX_MADV_KEEPONFORK)
        {
            return 0;
        }
        // Locked pages may not be dropped.
        if matches!(advice, LINUX_MADV_DONTNEED | LINUX_MADV_FREE)
            && crate::linux_areas::locked_in(
                linux_execution_instance(),
                current_linux_process_pid(),
                address & !(PAGE_SIZE as u64 - 1),
                length,
            )
        {
            return LINUX_EINVAL;
        }
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && matches!(
            advice,
            LINUX_MADV_NORMAL
                | LINUX_MADV_RANDOM
                | LINUX_MADV_SEQUENTIAL
                | LINUX_MADV_WILLNEED
                | LINUX_MADV_MERGEABLE
                | LINUX_MADV_UNMERGEABLE
                | LINUX_MADV_HUGEPAGE
                | LINUX_MADV_NOHUGEPAGE
                | LINUX_MADV_DONTDUMP
                | LINUX_MADV_DODUMP
        )
    {
        return linux_runtime_madvise(address, length, advice);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && matches!(advice, LINUX_MADV_DONTFORK | LINUX_MADV_DOFORK)
    {
        return linux_madvise_inheritance(address, length, advice == LINUX_MADV_DONTFORK);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && matches!(advice, LINUX_MADV_WIPEONFORK | LINUX_MADV_KEEPONFORK)
    {
        return linux_madvise_wipeonfork(address, length, advice == LINUX_MADV_WIPEONFORK);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && matches!(advice, LINUX_MADV_POPULATE_READ | LINUX_MADV_POPULATE_WRITE)
    {
        return linux_madvise_populate(address, length, advice == LINUX_MADV_POPULATE_WRITE);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && matches!(advice, LINUX_MADV_COLD | LINUX_MADV_PAGEOUT)
    {
        return linux_madvise_reclaim_hint(address, length, advice == LINUX_MADV_PAGEOUT);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && advice == LINUX_MADV_SOFT_OFFLINE {
        return linux_madvise_soft_offline(address, length);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && advice == LINUX_MADV_HWPOISON {
        return linux_madvise_hwpoison(address, length);
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && address >= LINUX_FIXED_LOW_BASE {
        return linux_runtime_madvise(address, length, advice);
    }
    let Some((start_slot, range_pages)) = linux_mmap_range_slots(address, length) else {
        return LINUX_EINVAL;
    };
    let areas: [Option<usize>; LINUX_RUNTIME_MMAP_SLOT_COUNT] = core::array::from_fn(|offset| {
        (offset < range_pages)
            .then(|| linux_mmap_slot_area_index(start_slot + offset))
            .flatten()
    });
    if matches!(
        advice,
        LINUX_MADV_NORMAL
            | LINUX_MADV_RANDOM
            | LINUX_MADV_SEQUENTIAL
            | LINUX_MADV_WILLNEED
            | LINUX_MADV_MERGEABLE
            | LINUX_MADV_UNMERGEABLE
            | LINUX_MADV_HUGEPAGE
            | LINUX_MADV_NOHUGEPAGE
            | LINUX_MADV_DONTDUMP
            | LINUX_MADV_DODUMP
    ) {
        return if areas[..range_pages].iter().all(Option::is_some) {
            0
        } else {
            LINUX_ENOMEM
        };
    }
    if matches!(advice, LINUX_MADV_DONTNEED | LINUX_MADV_DONTNEED_LOCKED)
        && (0..range_pages).any(|offset| {
            let slot = start_slot + offset;
            areas[offset].is_some()
                && X86_RUNTIME.ELF_PROBE_MMAP_SEALED[slot].load(Ordering::SeqCst)
        })
    {
        return LINUX_EPERM;
    }
    if !matches!(advice, LINUX_MADV_DONTNEED | LINUX_MADV_DONTNEED_LOCKED)
        || areas[..range_pages].iter().any(|area| {
            area.is_none_or(|index| {
                X86_RUNTIME.ELF_PROBE_MMAP_FILE[index].load(Ordering::SeqCst) != 0
                    || X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[index].load(Ordering::SeqCst) == 0
            })
        })
    {
        return LINUX_EINVAL;
    }
    for offset in 0..range_pages {
        if !address_space::zero_current_linux_page(
            address + (offset * PAGE_SIZE) as u64,
            linux_mmap_slot_frame(start_slot + offset),
        ) {
            return LINUX_EINVAL;
        }
    }
    0
}

pub(super) fn linux_process_madvise(
    pid_descriptor: u64,
    vectors: u64,
    vector_count: u64,
    advice: u64,
    flags: u64,
) -> u64 {
    const IOV_MAX: u64 = 1024;
    let pid_descriptor = u64::from(pid_descriptor as u32);
    let advice = u64::from(advice as u32);
    if flags != 0
        || vector_count > IOV_MAX
        || !matches!(
            advice,
            LINUX_MADV_NORMAL
                | LINUX_MADV_RANDOM
                | LINUX_MADV_SEQUENTIAL
                | LINUX_MADV_WILLNEED
                | LINUX_MADV_DONTNEED
                | LINUX_MADV_COLD
                | LINUX_MADV_PAGEOUT
                | LINUX_MADV_DONTNEED_LOCKED
        )
    {
        return LINUX_EINVAL;
    }
    if !linux_pidfd_descriptor(pid_descriptor) {
        return LINUX_EBADF;
    }
    let Some(process) = linux_pidfd_process(pid_descriptor) else {
        return LINUX_ESRCH;
    };
    if process != current_linux_process_pid() {
        return linux_remote_process_madvise(process, vectors, vector_count, advice);
    }
    let mut advised = 0_u64;
    for index in 0..vector_count {
        let Some(entry_address) = index
            .checked_mul(16)
            .and_then(|offset| vectors.checked_add(offset))
        else {
            return if advised == 0 { LINUX_EFAULT } else { advised };
        };
        let mut entry = [0_u8; 16];
        if !copy_from_linux_user(entry_address, &mut entry) {
            return if advised == 0 { LINUX_EFAULT } else { advised };
        }
        let address = u64::from_ne_bytes(entry[..8].try_into().unwrap());
        let length = u64::from_ne_bytes(entry[8..].try_into().unwrap());
        if length == 0 {
            continue;
        }
        let result = linux_madvise(address, length, advice);
        if result != 0 {
            return if advised == 0 { result } else { advised };
        }
        let Some(total) = advised.checked_add(length) else {
            return if advised == 0 { LINUX_EINVAL } else { advised };
        };
        if total > i64::MAX as u64 {
            return if advised == 0 { LINUX_EINVAL } else { advised };
        }
        advised = total;
    }
    advised
}

/// process_madvise on another process: only the advice Linux takes from
/// outside (MADV_COLD, MADV_PAGEOUT, MADV_WILLNEED; EINVAL otherwise),
/// from a caller that may read the process as ptrace would and has
/// CAP_SYS_NICE (EPERM). MADV_PAGEOUT pages its pages out when it is not
/// running on a CPU; the rest is advice nothing acts on. The bytes
/// advised.
fn linux_remote_process_madvise(process: u32, vectors: u64, vector_count: u64, advice: u64) -> u64 {
    if !matches!(
        advice,
        LINUX_MADV_COLD | LINUX_MADV_PAGEOUT | LINUX_MADV_WILLNEED
    ) {
        return LINUX_EINVAL;
    }
    if !linux_ptrace_access_permitted(process)
        || !linux_has_capability(linox_credentials::capability::SYS_NICE)
    {
        return LINUX_EPERM;
    }
    let instance = linux_execution_instance();
    let mut advised = 0_u64;
    for index in 0..vector_count {
        let mut entry = [0_u8; 16];
        if !index
            .checked_mul(16)
            .and_then(|offset| vectors.checked_add(offset))
            .is_some_and(|address| copy_from_linux_user(address, &mut entry))
        {
            return if advised == 0 { LINUX_EFAULT } else { advised };
        }
        let address = u64::from_ne_bytes(entry[..8].try_into().unwrap());
        let length = u64::from_ne_bytes(entry[8..].try_into().unwrap());
        if length == 0 {
            continue;
        }
        if !address.is_multiple_of(PAGE_SIZE as u64)
            || address.checked_add(length).is_none_or(|end| end > 1 << 47)
        {
            return if advised == 0 { LINUX_EINVAL } else { advised };
        }
        let pages = length.div_ceil(PAGE_SIZE as u64) as usize;
        if advice == LINUX_MADV_PAGEOUT && linux_live_process_bank(process, instance).is_none() {
            if let Some(root) = linux_process::live_process_root(process) {
                let _ = address_space::with_live_linux_process_root(root, || {
                    linux_swapon::linux_swap_pageout(process, address, pages)
                });
            }
        }
        advised = advised.saturating_add(length);
    }
    advised
}

pub(super) fn linux_process_mrelease(pid_descriptor: u64, flags: u64) -> u64 {
    let pid_descriptor = u64::from(pid_descriptor as u32);
    let flags = u64::from(flags as u32);
    if flags != 0 {
        return LINUX_EINVAL;
    }
    if !linux_pidfd_descriptor(pid_descriptor) {
        return LINUX_EBADF;
    }
    let Some(process) = linux_pidfd_process(pid_descriptor) else {
        return LINUX_ESRCH;
    };
    if process != current_linux_process_pid() {
        return LINUX_EPERM;
    }
    // Linux permits release only after the target has entered exit; the live
    // caller therefore cannot be released through its own pidfd.
    LINUX_EINVAL
}

pub(super) fn linux_mincore(address: u64, length: u64, vector: u64) -> u64 {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return linux_runtime_mincore(address, length, vector);
    }
    let Some((start_slot, range_pages)) = linux_mmap_range_slots(address, length) else {
        return LINUX_EINVAL;
    };
    let mut residency = [0_u8; LINUX_RUNTIME_MMAP_SLOT_COUNT];
    for (offset, resident) in residency.iter_mut().enumerate().take(range_pages) {
        let slot = start_slot + offset;
        let Some(area) = linux_mmap_slot_area_index(slot) else {
            return LINUX_ENOMEM;
        };
        let protection =
            u64::from(X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[area].load(Ordering::SeqCst));
        if protection == 0 {
            if linux_mmap_slot_frame(slot) != 0
                || X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].load(Ordering::SeqCst) != 0
                || !address_space::current_linux_page_absent(address + (offset * PAGE_SIZE) as u64)
            {
                return LINUX_EINVAL;
            }
        } else {
            let Some(lease) = linux_mmap_slot_lease(slot) else {
                return LINUX_EINVAL;
            };
            if !address_space::current_linux_mapping_matches(
                address + (offset * PAGE_SIZE) as u64,
                lease,
                protection & LINUX_PROT_WRITE != 0,
                false,
            ) {
                return LINUX_EINVAL;
            }
            *resident = 1;
        }
    }
    if !copy_to_linux_user(vector, &residency[..range_pages]) {
        return LINUX_EFAULT;
    }
    0
}

/// mlock, mlock2 (`lock`) and munlock. The range must be mapped (ENOMEM
/// past the areas and present pages). An unprivileged caller (no
/// CAP_IPC_LOCK) is bound by RLIMIT_MEMLOCK: a zero limit forbids locking
/// (EPERM), a smaller one refuses the range (ENOMEM); Linox keeps no count
/// of locked pages, so each call is measured alone.
pub(super) fn linux_memory_lock(address: u64, length: u64, flags: u64, lock: bool) -> u64 {
    let flags = flags as u32;
    if flags & !1 != 0 {
        return LINUX_EINVAL;
    }
    if length == 0 {
        return 0;
    }
    let Ok(length) = usize::try_from(length) else {
        return LINUX_ENOMEM;
    };
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return if address_space::current_linux_range_mapped(address, length, false) {
            0
        } else {
            LINUX_ENOMEM
        };
    }
    let page_mask = !(PAGE_SIZE as u64 - 1);
    let start = address & page_mask;
    let Some(end) = address
        .checked_add(length as u64)
        .and_then(|end| end.checked_add(PAGE_SIZE as u64 - 1))
        .map(|end| end & page_mask)
    else {
        return LINUX_ENOMEM;
    };
    let pid = current_linux_process_pid();
    let mapped = crate::linux_areas::snapshot(linux_execution_instance(), pid)
        .is_some_and(|areas| areas.covers(start, end))
        || (start..end)
            .step_by(PAGE_SIZE)
            .all(|page| address_space::current_linux_runtime_page(page).occupied);
    if !mapped {
        return LINUX_ENOMEM;
    }
    if lock && current_linux_credentials().is_none_or(|credentials| !credentials.privileged()) {
        let limit = linux_resource_limit_values(LINUX_RLIMIT_MEMLOCK, true)
            .map_or(u64::MAX, |values| values[0]);
        if limit == 0 {
            return LINUX_EPERM;
        }
        if end - start > limit {
            return LINUX_ENOMEM;
        }
    }
    // MLOCK_ONFAULT locks pages as they are touched instead of now; Linox
    // has no reclaim, so a touched page stays resident either way.
    const MLOCK_ONFAULT: u32 = 1;
    if lock
        && flags & MLOCK_ONFAULT == 0
        && !materialize_linux_runtime_user_range(address, length, false)
    {
        return LINUX_ENOMEM;
    }
    if lock && flags & MLOCK_ONFAULT == 0 {
        for page in (start..end).step_by(PAGE_SIZE) {
            address_space::mark_current_linux_page_accessed(page);
        }
    }
    crate::linux_areas::lock(linux_execution_instance(), pid, start, end - start, lock);
    0
}

pub(super) fn linux_mlockall(flags: u64) -> u64 {
    const MCL_CURRENT: u32 = 1;
    const MCL_FUTURE: u32 = 2;
    const MCL_ONFAULT: u32 = 4;
    let flags = flags as u32;
    if flags == 0 || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 || flags == MCL_ONFAULT
    {
        return LINUX_EINVAL;
    }
    // An unprivileged caller (no CAP_IPC_LOCK) is bound by RLIMIT_MEMLOCK: a
    // zero limit forbids locking (EPERM), and MCL_CURRENT refuses when what
    // is mapped exceeds it (ENOMEM) (mlockall02, mlockall03).
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && current_linux_credentials().is_none_or(|credentials| !credentials.privileged())
    {
        let limit = linux_resource_limit_values(LINUX_RLIMIT_MEMLOCK, true)
            .map_or(u64::MAX, |values| values[0]);
        if limit == 0 {
            return LINUX_EPERM;
        }
        if flags & MCL_CURRENT != 0 {
            let mapped = crate::linux_areas::snapshot(
                linux_execution_instance(),
                current_linux_process_pid(),
            )
            .map_or(0, |areas| {
                areas.iter().map(|area| area.end - area.start).sum::<u64>()
            });
            if mapped > limit {
                return LINUX_ENOMEM;
            }
        }
    }
    // Every present and future Linox userspace mapping is resident because the
    // kernel has no swap or page-reclaim path; the areas record the locks
    // (VmLck) and whether later mappings are locked.
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        crate::linux_areas::lock_all(
            linux_execution_instance(),
            current_linux_process_pid(),
            (flags & MCL_CURRENT != 0).then_some(true),
            flags & MCL_FUTURE != 0,
        );
    }
    0
}

pub(super) fn linux_munlockall() -> u64 {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        crate::linux_areas::lock_all(
            linux_execution_instance(),
            current_linux_process_pid(),
            Some(false),
            false,
        );
    }
    0
}

/// The single gate on memory both writable and executable: the current
/// process's domain was configured with `write-execute=true`. mmap and
/// mprotect ask here and nowhere else. Even then no page is writable and
/// executable at once (`linux_flip_write_execute_page`).
fn linux_write_execute_allowed() -> bool {
    current_container_slot().is_some_and(|slot| {
        X86_RUNTIME
            .CONTAINER_CONFIG_FLAGS
            .get(slot)
            .is_some_and(|flags| {
                flags.load(Ordering::Acquire) & control_abi::DOMAIN_CONFIG_WRITE_EXECUTE != 0
            })
    })
}

/// Whether the current process's memory area at `address` is both
/// writable and executable (mapped so in a `write-execute=true` domain).
pub(super) fn linux_write_execute_area(address: u64) -> bool {
    crate::sync::rank_available(crate::sync::LockRank::MEMORY_AREAS)
        && crate::linux_areas::protection_at(
            linux_execution_instance(),
            current_linux_process_pid(),
            address,
        )
        .is_some_and(|protection| protection.bits() & 6 == 6)
}

/// A fault on a page of a writable and executable area: the page is
/// writable or executable, never both, and flips to whichever the
/// faulting access needs (a JIT writes code, then runs it). Making it
/// writable copies a page another process shares, as mprotect does.
pub(super) fn linux_flip_write_execute_page(fault: domain::FaultMetadata) -> bool {
    let (write, fetch) = (fault.error & 2 != 0, fault.error & 16 != 0);
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || fault.vector != 14
        || fault.address >= 1 << 47
        || write == fetch
    {
        return false;
    }
    let page_address = fault.address & !(PAGE_SIZE as u64 - 1);
    let page = address_space::current_linux_runtime_page(page_address);
    let wanted = if fetch {
        LINUX_PROT_READ | LINUX_PROT_EXEC
    } else {
        LINUX_PROT_READ | LINUX_PROT_WRITE
    };
    page.occupied
        && u64::from(page.protection) != wanted
        && linux_write_execute_area(page_address)
        && linux_runtime_mprotect(page_address, PAGE_SIZE as u64, wanted) == 0
}
