#![forbid(unsafe_code)]
use super::*;

pub(super) fn linux_user_stack_pointer_valid(user_stack: u64) -> bool {
    let Some(slot) = current_linux_thread_slot() else {
        return false;
    };
    let base = X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].load(Ordering::SeqCst);
    let size = X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].load(Ordering::SeqCst);
    let primary = base != 0
        && size != 0
        && base
            .checked_add(size)
            .is_some_and(|end| user_stack >= base && user_stack <= end);
    if primary {
        return true;
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && current_linux_tid() == Some(current_linux_process_pid())
        && linux_runtime_primary_stack_contains(user_stack & !(PAGE_SIZE as u64 - 1))
    {
        return true;
    }
    if !X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    // Active signal delivery owns this context until the serialized
    // rt_sigreturn or abort path clears active and the record.
    let signal = current_linux_signal_context();
    let alt_base = signal.alt_stack_pointer;
    let alt_size = signal.alt_stack_size;
    let frame_uses_alt_stack = alt_base != 0
        && alt_size != 0
        && alt_base
            .checked_add(alt_size)
            .is_some_and(|end| signal.signal_stack >= alt_base && signal.signal_stack < end);
    frame_uses_alt_stack
        && alt_base
            .checked_add(alt_size)
            .is_some_and(|end| user_stack >= alt_base && user_stack <= end)
}

pub(super) fn linux_mmap_slot_frame(slot: usize) -> u64 {
    X86_RUNTIME
        .ELF_PROBE_MMAP_FRAMES
        .get(slot)
        .map_or(0, |frame| frame.load(Ordering::SeqCst))
}

pub(super) fn linux_mmap_slot_lease(slot: usize) -> Option<memory::FrameLease> {
    memory::FrameLease::from_parts(
        linux_mmap_slot_frame(slot),
        X86_RUNTIME
            .ELF_PROBE_MMAP_GENERATIONS
            .get(slot)?
            .load(Ordering::SeqCst),
    )
}

pub(super) fn linux_mmap_store_slot_lease(slot: usize, lease: memory::FrameLease) {
    let Some(frame) = X86_RUNTIME.ELF_PROBE_MMAP_FRAMES.get(slot) else {
        return;
    };
    frame.store(lease.address(), Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].store(lease.generation(), Ordering::SeqCst);
}

fn linux_mmap_clear_slot_lease(slot: usize) {
    let Some(frame) = X86_RUNTIME.ELF_PROBE_MMAP_FRAMES.get(slot) else {
        return;
    };
    frame.store(0, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].store(0, Ordering::SeqCst);
}

pub(super) fn linux_allocate_mmap_leases(
    pages: usize,
) -> Option<[memory::FrameLease; LINUX_RUNTIME_MMAP_SLOT_COUNT]> {
    if !(1..=LINUX_RUNTIME_MMAP_SLOT_COUNT).contains(&pages) {
        return None;
    }
    let mut leases = [memory::FrameLease::EMPTY; LINUX_RUNTIME_MMAP_SLOT_COUNT];
    for index in 0..pages {
        let Some([lease]) = memory::allocate_user_frames::<1>() else {
            if index != 0 {
                let _ =
                    memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &leases[..index]);
            }
            return None;
        };
        leases[index] = lease;
    }
    Some(leases)
}

fn linux_mmap_unmap_and_release_slots(start_slot: usize, pages: usize) -> bool {
    let base = X86_RUNTIME.ELF_PROBE_MMAP.load(Ordering::SeqCst);
    let mut leases = [None; LINUX_RUNTIME_MMAP_SLOT_COUNT];
    for slot in start_slot..start_slot + pages {
        let Some(area) = linux_mmap_slot_area_index(slot) else {
            continue;
        };
        let address = base + (slot * PAGE_SIZE) as u64;
        let protection =
            u64::from(X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[area].load(Ordering::SeqCst));
        if protection == 0 {
            if linux_mmap_slot_frame(slot) != 0
                || X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].load(Ordering::SeqCst) != 0
                || !address_space::current_linux_page_absent(address)
            {
                return false;
            }
        } else {
            let Some(lease) = linux_mmap_slot_lease(slot) else {
                return false;
            };
            if !memory::frame_leases_releasable(memory::FrameOwner::KERNEL, &[lease])
                || !address_space::current_linux_mapping_matches(
                    address,
                    lease,
                    protection & LINUX_PROT_WRITE != 0,
                    false,
                )
            {
                return false;
            }
            leases[slot - start_slot] = Some(lease);
        }
    }
    for (offset, lease) in leases[..pages].iter().copied().enumerate() {
        let Some(lease) = lease else {
            continue;
        };
        let slot = start_slot + offset;
        let address = base + (slot * PAGE_SIZE) as u64;
        if !address_space::unmap_current_linux_page(address, lease.address()) {
            return false;
        }
        if !crate::linux_file_cache::contains(lease)
            && (!address_space::prepare_linux_frame(lease.address(), &[])
                || !memory::release_frames(memory::FrameOwner::KERNEL, [lease]))
        {
            return false;
        }
        linux_mmap_clear_slot_lease(slot);
    }
    true
}

pub(super) fn release_linux_sealed_mmaps_at_exit() -> bool {
    let mut slots = linux_mmap_slot_attributes();
    let mut start_slot = 0;
    while start_slot < LINUX_RUNTIME_MMAP_SLOT_COUNT {
        let pages =
            usize::from(X86_RUNTIME.ELF_PROBE_MMAP_PAGES[start_slot].load(Ordering::SeqCst));
        if pages == 0 {
            start_slot += 1;
            continue;
        }
        if pages > LINUX_RUNTIME_MMAP_SLOT_COUNT - start_slot {
            return false;
        }
        let end_slot = start_slot + pages;
        if X86_RUNTIME.ELF_PROBE_MMAP_SEALED[start_slot..end_slot]
            .iter()
            .any(|sealed| sealed.load(Ordering::SeqCst))
        {
            if !linux_mmap_unmap_and_release_slots(start_slot, pages) {
                return false;
            }
            for (slot, entry) in slots.iter_mut().enumerate().take(end_slot).skip(start_slot) {
                *entry = None;
                X86_RUNTIME.ELF_PROBE_MMAP_SEALED[slot].store(false, Ordering::SeqCst);
            }
        }
        start_slot = end_slot;
    }
    linux_mmap_rebuild_areas(slots);
    true
}

pub(super) fn release_linux_runtime_mmaps(expected_base: u64) -> bool {
    let pid = current_linux_process_pid();
    let shared_flushed = linux_flush_process_shared_mappings(pid);
    let dynamic_released = !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || address_space::release_current_linux_runtime_mappings(LINUX_RUNTIME_DYNAMIC_MMAP_BASE);
    let next_expected = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        LINUX_RUNTIME_DYNAMIC_MMAP_BASE
    } else {
        expected_base
    };
    let next_valid = X86_RUNTIME.ELF_PROBE_MMAP_NEXT.swap(0, Ordering::SeqCst) >= next_expected;
    let address_valid = X86_RUNTIME.ELF_PROBE_MMAP.load(Ordering::SeqCst) == expected_base;
    let mut areas_released = true;
    for (start_slot, pages) in X86_RUNTIME.ELF_PROBE_MMAP_PAGES.iter().enumerate() {
        let pages = usize::from(pages.load(Ordering::SeqCst));
        if pages == 0 {
            continue;
        }
        areas_released &= pages <= LINUX_RUNTIME_MMAP_SLOT_COUNT - start_slot
            && linux_mmap_unmap_and_release_slots(start_slot, pages);
    }

    let mut leases_released = true;
    for (slot, pages) in X86_RUNTIME.ELF_PROBE_MMAP_PAGES.iter().enumerate() {
        pages.store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_FILE[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_SEALED[slot].store(false, Ordering::SeqCst);
        leases_released &= X86_RUNTIME.ELF_PROBE_MMAP_FRAMES[slot].load(Ordering::SeqCst) == 0
            && X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].load(Ordering::SeqCst) == 0;
    }
    let address_cleared = X86_RUNTIME.ELF_PROBE_MMAP.swap(0, Ordering::SeqCst) == expected_base;
    release_linux_process_shared_mappings(pid);
    release_linux_process_keys(pid);
    linux_fanotify_exit(pid);
    shared_flushed
        && address_valid
        && address_cleared
        && areas_released
        && leases_released
        && dynamic_released
        && next_valid
}

pub(super) fn linux_mmap_slot_occupied(slot: usize) -> bool {
    linux_mmap_slot_area_index(slot).is_some()
}

pub(super) fn linux_mmap_slot_area_index(slot: usize) -> Option<usize> {
    if slot >= LINUX_RUNTIME_MMAP_SLOT_COUNT {
        return None;
    }
    (0..LINUX_RUNTIME_MMAP_SLOT_COUNT).find(|start| {
        let pages = usize::from(X86_RUNTIME.ELF_PROBE_MMAP_PAGES[*start].load(Ordering::SeqCst));
        pages != 0
            && pages <= LINUX_RUNTIME_MMAP_SLOT_COUNT - *start
            && (*start..*start + pages).contains(&slot)
    })
}

pub(super) fn linux_mmap_slot_attributes() -> [Option<(u8, u8)>; LINUX_RUNTIME_MMAP_SLOT_COUNT] {
    core::array::from_fn(|slot| {
        let area = linux_mmap_slot_area_index(slot)?;
        Some((
            X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[area].load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_MMAP_FILE[area].load(Ordering::SeqCst),
        ))
    })
}

pub(super) fn capture_linux_mmap_runtime_state() -> LinuxMmapRuntimeState {
    LinuxMmapRuntimeState {
        base: X86_RUNTIME.ELF_PROBE_MMAP.load(Ordering::SeqCst),
        next: X86_RUNTIME.ELF_PROBE_MMAP_NEXT.load(Ordering::SeqCst),
        pages: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_MMAP_PAGES[index].load(Ordering::SeqCst)
        }),
        protection: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[index].load(Ordering::SeqCst)
        }),
        file: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_MMAP_FILE[index].load(Ordering::SeqCst)
        }),
        sealed: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_MMAP_SEALED[index].load(Ordering::SeqCst)
        }),
        frames: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_MMAP_FRAMES[index].load(Ordering::SeqCst)
        }),
        generations: core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[index].load(Ordering::SeqCst)
        }),
    }
}

pub(super) fn restore_linux_mmap_runtime_state(state: LinuxMmapRuntimeState) {
    X86_RUNTIME
        .ELF_PROBE_MMAP
        .store(state.base, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_MMAP_NEXT
        .store(state.next, Ordering::SeqCst);
    for index in 0..LINUX_RUNTIME_MMAP_SLOT_COUNT {
        X86_RUNTIME.ELF_PROBE_MMAP_PAGES[index].store(state.pages[index], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[index]
            .store(state.protection[index], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_FILE[index].store(state.file[index], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_SEALED[index].store(state.sealed[index], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_FRAMES[index].store(state.frames[index], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[index]
            .store(state.generations[index], Ordering::SeqCst);
    }
}

pub(super) fn linux_mmap_rebuild_areas(slots: [Option<(u8, u8)>; LINUX_RUNTIME_MMAP_SLOT_COUNT]) {
    for index in 0..LINUX_RUNTIME_MMAP_SLOT_COUNT {
        X86_RUNTIME.ELF_PROBE_MMAP_PAGES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_FILE[index].store(0, Ordering::SeqCst);
    }
    let mut start = 0;
    while start < LINUX_RUNTIME_MMAP_SLOT_COUNT {
        let Some((protection, file)) = slots[start] else {
            start += 1;
            continue;
        };
        let mut end = start + 1;
        while end < LINUX_RUNTIME_MMAP_SLOT_COUNT && slots[end] == Some((protection, file)) {
            end += 1;
        }
        X86_RUNTIME.ELF_PROBE_MMAP_PAGES[start].store((end - start) as u8, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[start].store(protection, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_FILE[start].store(file, Ordering::SeqCst);
        start = end;
    }
}

pub(super) fn linux_mmap_range_slots(address: u64, length: u64) -> Option<(usize, usize)> {
    let base = X86_RUNTIME.ELF_PROBE_MMAP.load(Ordering::SeqCst);
    if !address.is_multiple_of(PAGE_SIZE as u64) || address < base || length == 0 {
        return None;
    }
    let start = usize::try_from((address - base) / PAGE_SIZE as u64).ok()?;
    let pages = usize::try_from(length.div_ceil(PAGE_SIZE as u64)).ok()?;
    let limit = linux_mmap_slot_limit();
    (start < limit && start.checked_add(pages).is_some_and(|end| end <= limit))
        .then_some((start, pages))
}

fn linux_mmap_slot_limit() -> usize {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        LINUX_RUNTIME_MMAP_SLOT_COUNT
    } else {
        LINUX_MMAP_SLOT_COUNT
    }
}

pub(super) fn linux_runtime_mmap_end() -> Option<u64> {
    LINUX_RUNTIME_DYNAMIC_MMAP_BASE.checked_add(1 << 39)
}

pub(super) fn linux_runtime_mapping_range(address: u64, length: u64) -> Option<(u64, usize)> {
    let end = linux_runtime_mmap_end()?;
    let in_low_window = (LINUX_FIXED_LOW_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE).contains(&address);
    if length == 0
        || !address.is_multiple_of(PAGE_SIZE as u64)
        || address < LINUX_RUNTIME_DYNAMIC_MMAP_BASE
            && !in_low_window
            && !linux_runtime_heap_contains(address)
    {
        return None;
    }
    let pages = usize::try_from(length.div_ceil(PAGE_SIZE as u64)).ok()?;
    let mapped_end = address.checked_add((pages as u64).checked_mul(PAGE_SIZE as u64)?)?;
    // Programs too large for the low window load in their own region above
    // the mmap area; their pages are managed the same way. MAP_32BIT
    // mappings lie in the second gigabyte.
    let in_high_image = address >= LINUX_EXEC_HIGH_LOAD_BASE && mapped_end <= LINUX_EXEC_HIGH_LIMIT;
    let in_low_window = in_low_window && linux_in_fixed_low_window(address, mapped_end);
    // The heap up to the break may be protected and unmapped too (brk02).
    let in_heap =
        linux_runtime_heap_contains(address) && linux_runtime_heap_contains(mapped_end - 1);
    (pages != 0 && (mapped_end <= end || in_high_image || in_low_window || in_heap))
        .then_some((mapped_end, pages))
}

/// Whether a page of the program image the kernel keeps for the process
/// (its active image mappings) lies in `[start, end)`: those are the
/// kernel's to place and release, never a mapping call's.
pub(super) fn linux_range_holds_image_page(start: u64, end: u64) -> bool {
    let count = usize::from(
        X86_RUNTIME
            .ELF_PROBE_ACTIVE_IMAGE_COUNT
            .load(Ordering::SeqCst),
    )
    .min(LINUX_ACTIVE_IMAGE_MAPPING_LIMIT);
    (0..count).any(|index| {
        (start..end)
            .contains(&X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[index].load(Ordering::SeqCst))
    })
}

fn linux_page_ceil(address: u64) -> Option<u64> {
    address
        .checked_add(PAGE_SIZE as u64 - 1)
        .map(|value| value & !(PAGE_SIZE as u64 - 1))
}

pub(super) fn linux_runtime_brk(requested: u64) -> u64 {
    let current = X86_RUNTIME.ELF_PROBE_BRK.load(Ordering::SeqCst);
    if requested == 0 {
        return current;
    }
    let initial_limit = X86_RUNTIME.ELF_PROBE_BRK_LIMIT.load(Ordering::SeqCst);
    let base = initial_limit.saturating_sub((LINUX_RUNTIME_HEAP_PAGES * PAGE_SIZE) as u64);
    // The main thread's stack grows down to just above the initial limit,
    // into pages it has not touched yet. A break beyond the limit reserved
    // those pages for the heap, and the stack later grew over them, so malloc
    // metadata and stack frames shared memory. Allocators fall back to mmap
    // when the break cannot grow.
    if requested < base || requested > initial_limit {
        return current;
    }
    let (Some(old_end), Some(new_end)) = (linux_page_ceil(current), linux_page_ceil(requested))
    else {
        return current;
    };
    // Pages below the initial limit are reserved at exec, so a break that
    // stays inside them maps or releases nothing.
    if new_end > old_end {
        let start = old_end.max(initial_limit);
        let pages = (new_end.saturating_sub(start) / PAGE_SIZE as u64) as usize;
        let additional_pages = (0..pages)
            .filter(|page| {
                !address_space::current_linux_runtime_page(start + (*page * PAGE_SIZE) as u64)
                    .occupied
            })
            .count();
        if !linux_address_space_limit_allows(additional_pages) {
            return current;
        }
        for page in 0..pages {
            let address = start + (page * PAGE_SIZE) as u64;
            if address_space::reserve_current_linux_runtime_page(address, 3, false, false)
                != Some(None)
            {
                let _ = rollback_linux_runtime_mapping(start, page);
                return current;
            }
        }
    } else if new_end < old_end {
        // Pages below the initial limit stay reserved, but a later break
        // must find them read-write again even if mprotect changed them.
        for page in (new_end..old_end.min(initial_limit)).step_by(PAGE_SIZE) {
            let state = address_space::current_linux_runtime_page(page);
            if state.occupied && state.protection != 3 {
                let _ = address_space::protect_current_linux_runtime_page(page, 3);
            }
        }
        let start = new_end.max(initial_limit);
        let pages = (old_end.saturating_sub(start) / PAGE_SIZE as u64) as usize;
        for page in 0..pages {
            if !release_linux_runtime_page(address_space::remove_current_linux_runtime_page(
                start + (page * PAGE_SIZE) as u64,
            )) {
                return current;
            }
        }
    }
    X86_RUNTIME.ELF_PROBE_BRK.store(requested, Ordering::SeqCst);
    requested
}

/// The extent (base, size) of a clone child's stack whose top is `top`,
/// for the stack-pointer check of its system calls: the memory area or
/// heap of `pid` holding the top, else the mapped pages below the top
/// page (up to 8 MiB). clone02 gives a top 56 bytes into a page with the
/// buffer below it untouched, so the top page alone is not enough.
pub(super) fn linux_clone_stack_extent(pid: u32, top: u64) -> (u64, u64) {
    const SCAN_LIMIT: u64 = 8 << 20;
    let page_mask = !(PAGE_SIZE as u64 - 1);
    let top_page = (top - 1) & page_mask;
    let end = top_page + PAGE_SIZE as u64;
    if let Some(start) = crate::linux_areas::snapshot(linux_execution_instance(), pid)
        .and_then(|areas| areas.find(top - 1).map(|area| area.start))
    {
        return (start, end - start);
    }
    let heap_limit = X86_RUNTIME.ELF_PROBE_BRK_LIMIT.load(Ordering::SeqCst);
    let heap_base = heap_limit.saturating_sub((LINUX_RUNTIME_HEAP_PAGES * PAGE_SIZE) as u64);
    if linux_runtime_heap_contains(top - 1) && heap_base < end {
        return (heap_base, end - heap_base);
    }
    let mut base = top_page;
    while top_page - base < SCAN_LIMIT
        && base
            .checked_sub(PAGE_SIZE as u64)
            .is_some_and(|below| address_space::current_linux_range_mapped(below, PAGE_SIZE, false))
    {
        base -= PAGE_SIZE as u64;
    }
    (base, end - base)
}

pub(super) fn linux_runtime_heap_contains(address: u64) -> bool {
    let initial_limit = X86_RUNTIME.ELF_PROBE_BRK_LIMIT.load(Ordering::SeqCst);
    let base = initial_limit.saturating_sub((LINUX_RUNTIME_HEAP_PAGES * PAGE_SIZE) as u64);
    let end = linux_page_ceil(X86_RUNTIME.ELF_PROBE_BRK.load(Ordering::SeqCst)).unwrap_or(0);
    (base..end).contains(&address)
}

pub(super) fn linux_runtime_range_available(address: u64, pages: usize) -> bool {
    address_space::current_linux_range_unoccupied(address, pages)
        && !(X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
            && crate::linux_areas::overlaps(
                linux_execution_instance(),
                current_linux_process_pid(),
                address,
                (pages as u64).saturating_mul(PAGE_SIZE as u64),
            ))
}

/// Mappings at least this large (private, anonymous, placed by the kernel,
/// neither populated nor locked) are reserved lazily: only the memory
/// areas record them, and a page is made when first touched. Reserving
/// each page in the page tables, which fork copies, made fork's cost grow
/// with every untouched gigabyte (fork14).
const LINUX_LAZY_MAPPING_PAGES: usize = (64 << 20) / PAGE_SIZE;

/// The page protection (0, R, RW or RX as page entries hold it) of the
/// current process's private anonymous memory area covering `address`,
/// for a page the page tables do not hold yet.
pub(crate) fn linux_lazy_area_protection(address: u64) -> Option<u8> {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Relaxed)
        || address < LINUX_RUNTIME_DYNAMIC_MMAP_BASE
        || address >= linux_runtime_mmap_end()?
        || !crate::sync::rank_available(crate::sync::LockRank::MEMORY_AREAS)
    {
        return None;
    }
    let protection = crate::linux_areas::anonymous_protection(
        linux_execution_instance(),
        current_linux_process_pid(),
        address,
    )?;
    match protection.bits() {
        0 => Some(0),
        1 => Some(1),
        2 | 3 | 6 | 7 => Some(3),
        4 | 5 => Some(5),
        _ => None,
    }
}

/// `low` for MAP_32BIT: the first free range in the second gigabyte, or
/// none (ENOMEM) when nothing that size fits there (mmap23's 2 GiB).
pub(super) fn linux_runtime_select_mapping(
    address: u64,
    pages: usize,
    fixed: bool,
    low: bool,
) -> Option<u64> {
    let base = LINUX_RUNTIME_DYNAMIC_MMAP_BASE;
    let end = linux_runtime_mmap_end()?;
    let size = (pages as u64).checked_mul(PAGE_SIZE as u64)?;
    if low && !fixed {
        let mut candidate = LINUX_LOW_MMAP_BASE;
        while candidate
            .checked_add(size)
            .is_some_and(|mapped_end| mapped_end <= LINUX_LOW_MMAP_LIMIT)
        {
            if linux_runtime_range_available(candidate, pages) {
                return Some(candidate);
            }
            candidate = candidate.checked_add(PAGE_SIZE as u64)?;
        }
        return None;
    }
    if fixed {
        let mapped_end = address.checked_add(size)?;
        let in_low_window = linux_in_fixed_low_window(address, mapped_end);
        return (address.is_multiple_of(PAGE_SIZE as u64)
            && (address >= base && mapped_end <= end || in_low_window))
            .then_some(address);
    }
    if address >= base
        && address.is_multiple_of(PAGE_SIZE as u64)
        && address
            .checked_add(size)
            .is_some_and(|mapped_end| mapped_end <= end)
        && linux_runtime_range_available(address, pages)
    {
        return Some(address);
    }
    let mut candidate = X86_RUNTIME
        .ELF_PROBE_MMAP_NEXT
        .load(Ordering::SeqCst)
        .max(base);
    while candidate
        .checked_add(size)
        .is_some_and(|mapped_end| mapped_end <= end)
    {
        if linux_runtime_range_available(candidate, pages) {
            X86_RUNTIME
                .ELF_PROBE_MMAP_NEXT
                .store(candidate + size, Ordering::SeqCst);
            return Some(candidate);
        }
        candidate = candidate.checked_add(PAGE_SIZE as u64)?;
    }
    None
}

pub(super) fn release_linux_runtime_page(page: address_space::LinuxRuntimePage) -> bool {
    page.shared || page.frame.is_none_or(release_linux_runtime_frame)
}

pub(super) fn release_linux_runtime_frame(frame: memory::FrameLease) -> bool {
    crate::linux_file_cache::contains(frame)
        || memory::scrub_and_release_frames(
            memory::FrameOwner::KERNEL,
            core::slice::from_ref(&frame),
        )
}

pub(super) fn rollback_linux_runtime_mapping(address: u64, pages: usize) -> bool {
    (0..pages).all(|page| {
        let page =
            address_space::remove_current_linux_runtime_page(address + (page * PAGE_SIZE) as u64);
        release_linux_runtime_page(page)
    })
}

/// IPC_STAT without the read-permission check, for the *_STAT_ANY
/// commands (shmctl04, msgctl06, semctl09); never a command of Linux's.
pub(super) const LINUX_IPC_STAT_UNCHECKED: u64 = 0xfe;

/// remap_file_pages(2), as Linux now emulates it: the pages of a shared
/// file mapping from `start` are mapped again, to the file's pages from
/// page `page` on, keeping the mapping's protection. The start and length
/// are rounded down to pages; the range must lie in shared mappings of
/// one file (EINVAL otherwise).
pub(super) fn linux_remap_file_pages(
    start: u64,
    length: u64,
    protection: u64,
    page: u64,
    _flags: u64,
) -> u64 {
    use crate::linux_areas::{Area, Backing};
    let start = start & !(PAGE_SIZE as u64 - 1);
    let length = length & !(PAGE_SIZE as u64 - 1);
    let pages = length / PAGE_SIZE as u64;
    let Some(end) = start
        .checked_add(length)
        .filter(|end| protection == 0 && *end > start && *end <= 1 << 47)
    else {
        return LINUX_EINVAL;
    };
    let Some(file_offset) = page
        .checked_add(pages)
        .and_then(|_| page.checked_mul(PAGE_SIZE as u64))
        .and_then(|offset| usize::try_from(offset).ok())
    else {
        return LINUX_EINVAL;
    };
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return LINUX_EINVAL;
    }
    let (instance, pid) = (linux_execution_instance(), current_linux_process_pid());
    let Some(first) = crate::linux_areas::area_at(instance, pid, start) else {
        return LINUX_EINVAL;
    };
    let Backing::File {
        device,
        inode,
        ref path,
        ..
    } = first.backing
    else {
        return LINUX_EINVAL;
    };
    let Some((handle, _)) = linux_shared_file_page(start) else {
        return LINUX_EINVAL;
    };
    // The areas the range covers must follow each other without a hole,
    // all mapping the same file with the same flags.
    let mut cursor = first.end;
    while cursor < end {
        let next = crate::linux_areas::area_at(instance, pid, cursor).filter(|area| {
            area.start == cursor
                && area.shared
                && area.protection == first.protection
                && area.may_write == first.may_write
                && area.locked == first.locked
                && matches!(
                    area.backing,
                    Backing::File {
                        device: next_device,
                        inode: next_inode,
                        ..
                    } if next_device == device && next_inode == inode
                )
        });
        let Some(area) = next else {
            return LINUX_EINVAL;
        };
        cursor = area.end;
    }
    if (start..end)
        .step_by(PAGE_SIZE)
        .any(|address| address_space::current_linux_runtime_page(address).sealed)
    {
        return LINUX_EPERM;
    }
    for (index, address) in (start..end).step_by(PAGE_SIZE).enumerate() {
        let protection = address_space::current_linux_runtime_page(address).protection;
        if !linux_map_shared_file_page(address, handle, file_offset + index * PAGE_SIZE, protection)
        {
            return LINUX_ENOMEM;
        }
    }
    crate::linux_areas::map(
        instance,
        pid,
        Area {
            start,
            end,
            backing: Backing::File {
                device,
                inode,
                offset: file_offset as u64,
                path: path.clone(),
            },
            ..first
        },
    );
    0
}

pub(super) fn linux_map_shadow_stack(_address: u64, _length: u64, _flags: u64) -> u64 {
    // Linux x86 checks whether userspace CET shadow stacks are enabled before
    // interpreting mapping arguments. Linox does not enable that CPU/process
    // facility yet, so the Linux-visible result is EOPNOTSUPP.
    LINUX_EOPNOTSUPP
}

pub(super) fn linux_runtime_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    fd: u64,
    offset: u64,
) -> u64 {
    // A file mapping looks its descriptor up first: a closed one is EBADF
    // whatever else is wrong (mmap08).
    if flags & LINUX_MAP_ANONYMOUS == 0
        && offset.is_multiple_of(PAGE_SIZE as u64)
        && !linux_descriptor_open(u64::from(fd as u32))
    {
        return LINUX_EBADF;
    }
    // A mapping of /dev/zero is anonymous memory, private or shared.
    let flags = if flags & LINUX_MAP_ANONYMOUS == 0 && linux_dev_zero_descriptor(fd) {
        flags | LINUX_MAP_ANONYMOUS
    } else {
        flags
    };
    // MAP_DROPPABLE is private anonymous memory the kernel may drop under
    // memory pressure, after which it reads as zeros (Linux 6.11): never a
    // file's, never locked, and not inherited by a child (VM_WIPEONFORK).
    // Its pages are reserved as it is made (not lazily), so they carry
    // their wipe-on-fork mark.
    let droppable = flags & LINUX_MAP_TYPE == LINUX_MAP_DROPPABLE;
    if droppable && (flags & LINUX_MAP_ANONYMOUS == 0 || flags & LINUX_MAP_LOCKED != 0) {
        return LINUX_EINVAL;
    }
    let flags = if droppable {
        flags & !LINUX_MAP_TYPE | LINUX_MAP_PRIVATE
    } else {
        flags
    };
    let protection = linux_runtime_page_protection(linux_implied_protection(protection));
    if length == 0
        || ![
            0,
            LINUX_PROT_READ,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_PROT_READ | LINUX_PROT_EXEC,
        ]
        .contains(&protection)
    {
        return LINUX_EINVAL;
    }
    let Ok(pages) = usize::try_from(length.div_ceil(PAGE_SIZE as u64)) else {
        return LINUX_ENOMEM;
    };
    let anonymous = flags & LINUX_MAP_ANONYMOUS != 0;
    let fixed = flags & LINUX_MAP_FIXED != 0;
    let no_replace = flags & LINUX_MAP_FIXED_NOREPLACE != 0;
    // MAP_STACK is currently a Linux compatibility hint.  Runtime mappings
    // already have page-granular backing and teardown, so neither it nor
    // MAP_NORESERVE needs a distinct mapping mechanism.
    // MAP_SHARED_VALIDATE is MAP_SHARED that refuses flags it does not
    // know with EOPNOTSUPP instead of ignoring them (mmap20); MAP_32BIT
    // places the mapping below 2 GiB (mmap23, mmap24). MAP_GROWSDOWN is
    // kept in the memory areas, which a fault below the mapping grows
    // (`grow_linux_growsdown_area`, mmap18).
    let shared_validate = flags & LINUX_MAP_SHARED_VALIDATE == LINUX_MAP_SHARED_VALIDATE;
    let flags = if shared_validate {
        flags & !LINUX_MAP_SHARED_VALIDATE | LINUX_MAP_SHARED
    } else {
        flags
    };
    let low = flags & LINUX_MAP_32BIT != 0;
    let ignored = flags
        & (LINUX_MAP_DENYWRITE
            | LINUX_MAP_EXECUTABLE
            | LINUX_MAP_LOCKED
            | LINUX_MAP_NORESERVE
            | LINUX_MAP_STACK
            | LINUX_MAP_GROWSDOWN
            | LINUX_MAP_32BIT);
    let normalized = flags & !ignored;
    let sharing = normalized & (LINUX_MAP_SHARED | LINUX_MAP_PRIVATE);
    if !matches!(sharing, LINUX_MAP_SHARED | LINUX_MAP_PRIVATE) {
        return LINUX_EINVAL;
    }
    let valid_flags = if anonymous {
        sharing
            | LINUX_MAP_ANONYMOUS
            | flags & (LINUX_MAP_POPULATE | LINUX_MAP_NONBLOCK)
            | if fixed { LINUX_MAP_FIXED } else { 0 }
            | if no_replace {
                LINUX_MAP_FIXED_NOREPLACE
            } else {
                0
            }
    } else {
        sharing
            | flags & (LINUX_MAP_POPULATE | LINUX_MAP_NONBLOCK)
            | if fixed { LINUX_MAP_FIXED } else { 0 }
            | if no_replace {
                LINUX_MAP_FIXED_NOREPLACE
            } else {
                0
            }
    };
    // Linux ignores the descriptor of an anonymous mapping (LTP passes 0)
    // and only wants its offset page-aligned.
    if normalized != valid_flags {
        return if shared_validate {
            LINUX_EOPNOTSUPP
        } else {
            LINUX_EINVAL
        };
    }
    if fixed && no_replace || anonymous && !offset.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let Some(mapping) = linux_runtime_select_mapping(address, pages, fixed || no_replace, low)
    else {
        return LINUX_ENOMEM;
    };
    if no_replace && !linux_runtime_range_available(mapping, pages) {
        return LINUX_EEXIST;
    }
    // Sealed pages cannot be mapped over (mseal01).
    if fixed
        && (0..pages).any(|page| {
            address_space::current_linux_runtime_page(mapping + (page * PAGE_SIZE) as u64).sealed
        })
    {
        return LINUX_EPERM;
    }
    // A large private anonymous mapping the kernel places in the mmap
    // area, neither populated nor locked, is reserved lazily
    // (LINUX_LAZY_MAPPING_PAGES): the dispatcher records its memory area,
    // and its pages are made as they are touched.
    let lazy = anonymous
        && sharing == LINUX_MAP_PRIVATE
        && !droppable
        && !fixed
        && !no_replace
        && !low
        && flags & (LINUX_MAP_POPULATE | LINUX_MAP_LOCKED) == 0
        && matches!(protection, 0 | 1 | 3)
        && pages >= LINUX_LAZY_MAPPING_PAGES
        && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    if lazy {
        return if linux_address_space_limit_allows(pages) {
            mapping
        } else {
            LINUX_ENOMEM
        };
    }
    let additional_pages = (0..pages)
        .filter(|page| {
            !address_space::current_linux_runtime_page(mapping + (*page * PAGE_SIZE) as u64)
                .occupied
        })
        .count();
    if !linux_address_space_limit_allows(additional_pages) {
        return LINUX_ENOMEM;
    }
    let mut overlay_file = None;
    let mut immutable_rootfs_file = None;
    let mut secret = false;
    // A file mapping's pages past the file's last page are SIGBUS to touch
    // (mmap13), not zero-filled.
    let mut file_size = None;
    let file = if anonymous {
        None
    } else {
        let state = linux_device_descriptor(fd);
        if linux_path_descriptor(fd) {
            return LINUX_EBADF;
        }
        if let Some(handle) = linux_overlay_descriptor_handle(fd) {
            secret = linux_secret_descriptor(fd);
            if secret && (sharing != LINUX_MAP_SHARED || protection & LINUX_PROT_EXEC != 0) {
                return LINUX_EINVAL;
            }
            let Some(metadata) = crate::linux_overlay::metadata(handle) else {
                return LINUX_EBADF;
            };
            // A writable shared mapping needs a descriptor open for reading
            // and writing, checked before the seals (mm/mmap.c do_mmap: no
            // FMODE_WRITE is EACCES); otherwise any reader could change the
            // file through the mapping.
            if sharing == LINUX_MAP_SHARED && protection & LINUX_PROT_WRITE != 0 && state & 3 != 3 {
                return LINUX_EACCES;
            }
            if sharing == LINUX_MAP_SHARED
                && protection & LINUX_PROT_WRITE != 0
                && crate::linux_overlay::file_seals(handle).is_some_and(|seals| {
                    seals & (LINUX_F_SEAL_WRITE | LINUX_F_SEAL_FUTURE_WRITE) != 0
                })
            {
                return LINUX_EPERM;
            }
            if protection & LINUX_PROT_EXEC != 0
                && crate::linux_overlay::file_seals(handle)
                    .is_some_and(|seals| seals & LINUX_F_SEAL_EXEC != 0)
            {
                return LINUX_EPERM;
            }
            // A file of a noexec mount cannot be mapped executable.
            if protection & LINUX_PROT_EXEC != 0
                && linux_handle_mount_flags(handle) & crate::linux_mounts::NO_EXEC != 0
            {
                return LINUX_EPERM;
            }
            if metadata.kind != crate::linux_overlay::NodeKind::File
                || !matches!(state & 3, LINUX_DESCRIPTOR_INPUT | 3)
                || !offset.is_multiple_of(PAGE_SIZE as u64)
            {
                return LINUX_EACCES;
            }
            let Ok(start) = usize::try_from(offset) else {
                return LINUX_EINVAL;
            };
            // A mapping may start past the end of the file (mprotect05 maps
            // an empty one); its pages are then all past it.
            file_size = Some(metadata.size);
            overlay_file = Some((handle, start));
            None
        } else {
            let rootfs_entry = linux_rootfs_entry(fd);
            // An image file's address keys its pages in the file cache.
            let rootfs_file = rootfs_entry
                .as_ref()
                .map(|entry| entry.data().as_ptr() as u64);
            let Some(file) = rootfs_entry
                .map(RegularFile::Rootfs)
                .or_else(|| linux_regular_file_contents(state))
            else {
                return if linux_descriptor_open(fd) {
                    LINUX_ENODEV
                } else {
                    LINUX_EBADF
                };
            };
            // These descriptors are always read-only, so a writable shared
            // mapping is refused as Linux refuses one without FMODE_WRITE.
            if linux_proc_file(state)
                || state & 3 != LINUX_DESCRIPTOR_INPUT
                || sharing == LINUX_MAP_SHARED && protection & LINUX_PROT_WRITE != 0
                || !offset.is_multiple_of(PAGE_SIZE as u64)
            {
                return LINUX_EACCES;
            }
            let Ok(start) = usize::try_from(offset) else {
                return LINUX_EINVAL;
            };
            if start >= file.len() {
                if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                    serial_write("linox: file mmap rejected offset/file-length: ");
                    serial_write_u64(start as u64);
                    serial_write(" ");
                    serial_write_u64(file.len() as u64);
                    serial_write("\r\n");
                }
                return LINUX_EINVAL;
            }
            immutable_rootfs_file = rootfs_file;
            file_size = Some(file.len());
            Some((file, start))
        }
    };
    let file_backed = !anonymous;
    let replace = fixed;
    if anonymous && sharing == LINUX_MAP_SHARED && pages <= LINUX_SHMEM_PAGE_LIMIT {
        return linux_map_shared_anonymous(mapping, pages, protection as u8, replace);
    }
    if let Some((handle, start)) = overlay_file.filter(|(handle, _)| {
        // A shared mapping maps the file's own pages: a memfd's, or those of
        // a file moved to paged storage on its first shared mapping.
        sharing == LINUX_MAP_SHARED && !secret && crate::linux_overlay::make_paged(*handle)
    }) {
        let mapped = linux_map_shared_memfd(
            mapping,
            pages,
            handle,
            start,
            protection as u8,
            replace,
            file_size,
        );
        if replace {
            crate::linux_overlay::release_unmapped_shmem();
        }
        return mapped;
    }
    if replace {
        let _ = crate::linux_overlay::take_shared_mappings(
            current_linux_process_pid(),
            mapping,
            mapping + (pages * PAGE_SIZE) as u64,
        );
    }
    for (installed, page) in (0..pages).enumerate() {
        let page_address = mapping + (page * PAGE_SIZE) as u64;
        let past_eof = file_size.is_some_and(|size: usize| {
            usize::try_from(offset)
                .ok()
                .and_then(|offset| offset.checked_add(page * PAGE_SIZE))
                .is_none_or(|page_offset| page_offset >= size.next_multiple_of(PAGE_SIZE))
        });
        let old_frame = if past_eof {
            address_space::reserve_current_linux_past_eof_page(
                page_address,
                protection as u8,
                replace,
            )
        } else if anonymous {
            let install_started =
                cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
            let reserved = address_space::reserve_current_linux_runtime_page(
                page_address,
                protection as u8,
                false,
                replace,
            );
            linux_boot_profile_lifecycle_phase(14, install_started);
            reserved
        } else {
            let cache_source = immutable_rootfs_file
                .filter(|_| sharing == LINUX_MAP_PRIVATE && protection & LINUX_PROT_WRITE == 0)
                .and_then(|file| {
                    let page_offset = page.checked_mul(PAGE_SIZE)? as u64;
                    Some((file, offset.checked_add(page_offset)?))
                });
            let cached = cache_source.and_then(|(source_base, source_offset)| {
                crate::linux_file_cache::lookup(source_base, source_offset)
            });
            let (frame, cache_pinned) = if let Some(frame) = cached {
                (frame, true)
            } else {
                let allocate_started =
                    cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
                let Some([frame]) = memory::allocate_user_frames::<1>() else {
                    let _ = rollback_linux_runtime_mapping(mapping, installed);
                    return LINUX_ENOMEM;
                };
                linux_boot_profile_lifecycle_phase(12, allocate_started);
                (frame, false)
            };
            let mut overlay_bytes = [0_u8; PAGE_SIZE];
            let bytes = if let Some((handle, start)) = overlay_file {
                let page_start = start + page * PAGE_SIZE;
                let length =
                    crate::linux_overlay::read(handle, page_start, &mut overlay_bytes).unwrap_or(0);
                &overlay_bytes[..length]
            } else {
                file.as_ref().map_or(&[][..], |(file, start)| {
                    let page_start = *start + page * PAGE_SIZE;
                    file.get(page_start..file.len().min(page_start + PAGE_SIZE))
                        .unwrap_or(&[])
                })
            };
            let prepare_started =
                cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
            let prepared =
                cache_pinned || address_space::prepare_linux_frame(frame.address(), bytes);
            linux_boot_profile_lifecycle_phase(13, prepare_started);
            if !prepared {
                let _ = memory::scrub_and_release_frames(
                    memory::FrameOwner::KERNEL,
                    core::slice::from_ref(&frame),
                );
                let _ = rollback_linux_runtime_mapping(mapping, installed);
                return LINUX_ENOMEM;
            }
            let cache_pinned = cache_pinned
                || cache_source.is_some_and(|(source_base, source_offset)| {
                    crate::linux_file_cache::insert(source_base, source_offset, frame)
                });
            let install_started =
                cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
            // A PROT_NONE page is installed readable, then made inaccessible.
            let installed_page = address_space::install_current_linux_runtime_page(
                page_address,
                frame,
                (protection as u8).max(1),
                file_backed,
                replace,
            )
            .filter(|_| {
                protection != 0
                    || address_space::protect_current_linux_runtime_page(page_address, 0)
            });
            linux_boot_profile_lifecycle_phase(14, install_started);
            match installed_page {
                Some(old) => Some(old),
                None => {
                    if !cache_pinned {
                        let _ = memory::scrub_and_release_frames(
                            memory::FrameOwner::KERNEL,
                            core::slice::from_ref(&frame),
                        );
                    }
                    let _ = rollback_linux_runtime_mapping(mapping, installed);
                    return if no_replace {
                        LINUX_EEXIST
                    } else {
                        LINUX_ENOMEM
                    };
                }
            }
        };
        let Some(old_frame) = old_frame else {
            let _ = rollback_linux_runtime_mapping(mapping, installed);
            return if no_replace {
                LINUX_EEXIST
            } else {
                LINUX_ENOMEM
            };
        };
        if old_frame.is_some_and(|frame| !release_linux_runtime_frame(frame)) {
            let _ = rollback_linux_runtime_mapping(mapping, installed + 1);
            return LINUX_ENOMEM;
        }
        if secret && !address_space::mark_current_linux_runtime_page_secret(page_address) {
            let _ = rollback_linux_runtime_mapping(mapping, installed + 1);
            return LINUX_ENOMEM;
        }
    }
    if let Some((handle, start)) = overlay_file.filter(|_| sharing == LINUX_MAP_SHARED) {
        let pid = current_linux_process_pid();
        for page in 0..pages {
            let address = mapping + (page * PAGE_SIZE) as u64;
            let offset = start.saturating_add(page * PAGE_SIZE);
            if file_size.is_some_and(|size| offset >= size.next_multiple_of(PAGE_SIZE)) {
                continue;
            }
            if !crate::linux_overlay::register_shared_mapping(pid, address, handle, offset) {
                for rollback in 0..page {
                    let _ = crate::linux_overlay::remove_shared_mapping(
                        pid,
                        mapping + (rollback * PAGE_SIZE) as u64,
                    );
                }
                let _ = rollback_linux_runtime_mapping(mapping, pages);
                return LINUX_ENOMEM;
            }
        }
    }
    if replace {
        crate::linux_overlay::release_unmapped_shmem();
    }
    if anonymous
        && (flags & LINUX_MAP_LOCKED != 0
            || flags & LINUX_MAP_POPULATE != 0 && flags & LINUX_MAP_NONBLOCK == 0)
    {
        let _ = materialize_linux_runtime_user_range(
            mapping,
            pages.saturating_mul(PAGE_SIZE),
            protection & LINUX_PROT_WRITE != 0,
        );
    }
    if droppable
        && !(0..pages).all(|page| {
            address_space::set_current_linux_runtime_page_wipeonfork(
                mapping + (page * PAGE_SIZE) as u64,
                true,
            )
        })
    {
        let _ = rollback_linux_runtime_mapping(mapping, pages);
        return LINUX_ENOMEM;
    }
    if droppable {
        crate::linux_cgroup::note_reclaimable();
    }
    mapping
}

// Maps a memfd's own frames, so every process that maps the file shares
// its pages with the others and with read(2)/write(2) on the file, as
// Wayland shared-memory buffers require.
/// `size`, for a file's mapping, is the file's size: its pages past the
/// file's last page are reserved past its end (SIGBUS to touch); anonymous
/// shared memory (None) has every page.
fn linux_map_shared_memfd(
    mapping: u64,
    pages: usize,
    handle: crate::linux_overlay::Handle,
    start: usize,
    protection: u8,
    replace: bool,
    size: Option<usize>,
) -> u64 {
    if replace {
        let end = mapping + (pages * PAGE_SIZE) as u64;
        for (address, handle, offset) in
            crate::linux_overlay::take_shared_mappings(current_linux_process_pid(), mapping, end)
        {
            let _ = linux_flush_shared_file_page(address, handle, offset);
        }
    }
    for page in 0..pages {
        let address = mapping + (page * PAGE_SIZE) as u64;
        if replace
            && !release_linux_runtime_page(address_space::remove_current_linux_runtime_page(
                address,
            ))
        {
            let _ = rollback_linux_runtime_mapping(mapping, page);
            return LINUX_ENOMEM;
        }
        if size.is_some_and(|size| start + page * PAGE_SIZE >= size.next_multiple_of(PAGE_SIZE)) {
            if address_space::reserve_current_linux_past_eof_page(address, protection, false)
                .is_none()
            {
                let _ = rollback_linux_runtime_mapping(mapping, page);
                return LINUX_ENOMEM;
            }
            continue;
        }
        // A PROT_NONE page is installed readable, then made inaccessible.
        let installed = crate::linux_overlay::memfd_frame(handle, start / PAGE_SIZE + page)
            .is_some_and(|frame| {
                address_space::install_current_linux_shared_page(
                    address,
                    frame,
                    linux_shared_page_protection(handle, start + page * PAGE_SIZE, protection)
                        .max(1),
                )
            })
            && (protection != 0 || address_space::protect_current_linux_runtime_page(address, 0));
        if !installed {
            let _ = rollback_linux_runtime_mapping(mapping, page);
            return LINUX_ENOMEM;
        }
    }
    // The caller frees the shared memory the replaced pages held, once
    // what it maps here is registered (so it is not freed with them).
    mapping
}

/// The device and inode numbers (st_dev, st_ino) a mapping of overlay
/// file `handle` is recorded by in the memory areas.
fn linux_overlay_file_identity(handle: crate::linux_overlay::Handle) -> Option<(u64, u64)> {
    let stat = linux_overlay_stat(crate::linux_overlay::metadata(handle)?);
    Some((
        u64::from_ne_bytes(stat[..8].try_into().ok()?),
        u64::from_ne_bytes(stat[8..16].try_into().ok()?),
    ))
}

/// The paged file, and the offset in it, that the current process's
/// shared file mapping covering `address` maps there.
pub(super) fn linux_shared_file_page(
    address: u64,
) -> Option<(crate::linux_overlay::Handle, usize)> {
    let area = crate::linux_areas::area_at(
        linux_execution_instance(),
        current_linux_process_pid(),
        address,
    )?;
    let crate::linux_areas::Backing::File {
        device,
        inode,
        offset,
        ..
    } = area.backing
    else {
        return None;
    };
    if !area.shared {
        return None;
    }
    let handle = crate::linux_overlay::paged_file(device, inode)?;
    (linux_overlay_file_identity(handle)? == (device, inode)).then_some(())?;
    let offset = usize::try_from(offset.checked_add(address - area.start)?).ok()?;
    Some((handle, offset))
}

/// Maps page `address` of the current process to the page of paged file
/// `handle` at `offset` (shared with every other mapping of it and with
/// read(2) and write(2)), or, past the file's end, reserves it so that
/// touching it is SIGBUS, in place of what was there.
fn linux_map_shared_file_page(
    address: u64,
    handle: crate::linux_overlay::Handle,
    offset: usize,
    protection: u8,
) -> bool {
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return false;
    };
    if !release_linux_runtime_page(address_space::remove_current_linux_runtime_page(address)) {
        return false;
    }
    if offset >= metadata.size.next_multiple_of(PAGE_SIZE) {
        return address_space::reserve_current_linux_past_eof_page(address, protection, false)
            .is_some();
    }
    // A PROT_NONE page is installed readable, then made inaccessible.
    crate::linux_overlay::memfd_frame(handle, offset / PAGE_SIZE).is_some_and(|frame| {
        address_space::install_current_linux_shared_page(
            address,
            frame,
            linux_shared_page_protection(handle, offset, protection).max(1),
        )
    }) && (protection != 0 || address_space::protect_current_linux_runtime_page(address, 0))
}

/// The protection a page of a shared mapping of file `handle` at `offset`
/// is installed with: a volume's page whose blocks are not all allocated
/// yet is read-only first, so that the first write faults and allocates
/// them (`linux_volume_page_mkwrite`), as Linux's page_mkwrite does.
fn linux_shared_page_protection(
    handle: crate::linux_overlay::Handle,
    offset: usize,
    protection: u8,
) -> u8 {
    if protection & LINUX_PROT_WRITE as u8 != 0
        && crate::linux_blockfs::owns(handle)
        && !crate::linux_blockfs::page_backed(handle, offset / PAGE_SIZE)
    {
        protection & !(LINUX_PROT_WRITE as u8)
    } else {
        protection
    }
}

/// The first write to a page of a shared mapping of a volume's file that
/// was installed read-only for want of disk blocks: the blocks are
/// allocated and the page made writable. When the disk (or the quota) has
/// none, the page is noted so that the fault raises SIGBUS.
pub(super) fn linux_volume_page_mkwrite(fault: domain::FaultMetadata) -> bool {
    // The note is this fault's alone: every fault that gets this far
    // without being resolved clears what an earlier one left.
    LINUX_MKWRITE_FAILED_PAGE.store(0, Ordering::SeqCst);
    if fault.vector != 14 || fault.error & 3 != 3 || fault.address >= 1 << 47 {
        return false;
    }
    linux_volume_page_mkwrite_at(fault.address & !(PAGE_SIZE as u64 - 1))
}

/// `linux_volume_page_mkwrite` for page `address`, as a fault or the
/// kernel writing into the page would need it.
pub(super) fn linux_volume_page_mkwrite_at(address: u64) -> bool {
    let page = address_space::current_linux_runtime_page(address);
    if !page.occupied
        || !page.shared
        || page.frame.is_none()
        || page.protection != LINUX_PROT_READ as u8
    {
        return false;
    }
    let Some(area) = crate::linux_areas::area_at(
        linux_execution_instance(),
        current_linux_process_pid(),
        address,
    ) else {
        return false;
    };
    if !area.shared || !area.protection.writable() || area.protection.executable() {
        return false;
    }
    let Some((handle, offset)) = linux_shared_file_page(address) else {
        return false;
    };
    if !crate::linux_blockfs::owns(handle) {
        return false;
    }
    match crate::linux_blockfs::page_mkwrite(handle, offset / PAGE_SIZE) {
        Ok(()) => address_space::protect_current_linux_runtime_page(
            address,
            (LINUX_PROT_READ | LINUX_PROT_WRITE) as u8,
        ),
        Err(_) => {
            LINUX_MKWRITE_FAILED_PAGE.store(linux_mkwrite_note(address), Ordering::SeqCst);
            false
        }
    }
}

/// The page (with its process) whose page_mkwrite failed in the fault
/// being handled, so that the fault is SIGBUS, as Linux's VM_FAULT_SIGBUS.
static LINUX_MKWRITE_FAILED_PAGE: AtomicU64 = AtomicU64::new(0);

/// The note for page `address` of the current process: the page, bit 0,
/// and the pid above the address bits.
fn linux_mkwrite_note(address: u64) -> u64 {
    (address & !(PAGE_SIZE as u64 - 1)) | 1 | u64::from(current_linux_process_pid()) << 48
}

/// Whether user fault `fault` is the one whose page_mkwrite failed.
pub(in crate::arch::x86_64) fn linux_mkwrite_failed(fault: domain::FaultMetadata) -> bool {
    LINUX_MKWRITE_FAILED_PAGE.load(Ordering::SeqCst) == linux_mkwrite_note(fault.address)
}

/// Gives a page of a shared file mapping that was past the file's end
/// its file page, once the file has grown to reach it (Linux maps the
/// page then, where it raised SIGBUS before).
pub(super) fn linux_refill_shared_file_page(address: u64) -> bool {
    if !address_space::current_linux_page_past_eof(address) {
        return false;
    }
    let protection = address_space::current_linux_runtime_page(address).protection;
    // Anonymous shared memory's page, which reclaim unmapped to page it out:
    // its shmem node's (the registry has which), which has no end.
    if linux_anonymous_shared_area(address) {
        let Some((handle, offset)) =
            crate::linux_overlay::shared_mapping(current_linux_process_pid(), address)
        else {
            return false;
        };
        return release_linux_runtime_page(address_space::remove_current_linux_runtime_page(
            address,
        )) && crate::linux_overlay::memfd_frame(handle, offset / PAGE_SIZE).is_some_and(
            |frame| {
                address_space::install_current_linux_shared_page(address, frame, protection.max(1))
            },
        ) && (protection != 0
            || address_space::protect_current_linux_runtime_page(address, 0));
    }
    let Some((handle, offset)) = linux_shared_file_page(address) else {
        return false;
    };
    crate::linux_overlay::metadata(handle)
        .is_some_and(|metadata| offset < metadata.size.next_multiple_of(PAGE_SIZE))
        && linux_map_shared_file_page(address, handle, offset, protection)
}

/// After volume file `handle` grew from `old_size`, the current process's
/// shared mappings of the page that held the old end become read-only
/// again: the rest of that page now lies in the file and needs blocks
/// before a write through the mapping (Linux's pagecache_isize_extended).
fn linux_protect_grown_volume_page(handle: crate::linux_overlay::Handle, old_size: usize) {
    if old_size.is_multiple_of(PAGE_SIZE) || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
    {
        return;
    }
    let Some((device, inode)) = linux_overlay_file_identity(handle) else {
        return;
    };
    let page_offset = (old_size - old_size % PAGE_SIZE) as u64;
    for area in crate::linux_areas::shared_file_areas(
        linux_execution_instance(),
        current_linux_process_pid(),
        device,
        inode,
    ) {
        let crate::linux_areas::Backing::File { offset, .. } = area.backing else {
            continue;
        };
        let Some(address) = page_offset
            .checked_sub(offset)
            .map(|delta| area.start + delta)
            .filter(|address| *address < area.end)
        else {
            continue;
        };
        let page = address_space::current_linux_runtime_page(address);
        if page.shared
            && page.frame.is_some()
            && page.protection == (LINUX_PROT_READ | LINUX_PROT_WRITE) as u8
        {
            let _ =
                address_space::protect_current_linux_runtime_page(address, LINUX_PROT_READ as u8);
        }
    }
}

/// Truncates overlay file `handle` to `size`. The pages of the current
/// process's shared mappings of it that end up wholly past the new end
/// become SIGBUS to touch (and EFAULT to the kernel), as Linux unmaps
/// them. Other processes' mappings keep their pages until they map again.
pub(super) fn linux_truncate_overlay_file(
    handle: crate::linux_overlay::Handle,
    size: usize,
) -> bool {
    let old_size = crate::linux_overlay::metadata(handle).map_or(0, |metadata| metadata.size);
    if !crate::linux_overlay::truncate(handle, size) {
        return false;
    }
    if size > old_size && crate::linux_blockfs::owns(handle) {
        linux_protect_grown_volume_page(handle, old_size);
    }
    let end = size.next_multiple_of(PAGE_SIZE) as u64;
    if old_size as u64 <= end || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return true;
    }
    let Some((device, inode)) = linux_overlay_file_identity(handle) else {
        return true;
    };
    let areas = crate::linux_areas::shared_file_areas(
        linux_execution_instance(),
        current_linux_process_pid(),
        device,
        inode,
    );
    for area in areas {
        let crate::linux_areas::Backing::File { offset, .. } = area.backing else {
            continue;
        };
        let first = area.start + end.saturating_sub(offset);
        for address in (first..area.end).step_by(PAGE_SIZE) {
            let page = address_space::current_linux_runtime_page(address);
            let file_offset = (offset + (address - area.start)) as usize;
            if page.shared
                && !page.sealed
                && page.frame.is_some()
                && page.frame == crate::linux_overlay::paged_frame(handle, file_offset / PAGE_SIZE)
            {
                let _ = linux_map_shared_file_page(address, handle, file_offset, page.protection);
            }
        }
    }
    true
}

/// The largest anonymous shared mapping backed by shared pages (64 MiB).
/// Its pages are allocated when it is made and registered one by one, so a
/// larger one, often reserved and barely touched, stays a private mapping
/// that a fork copies, until mappings are tracked as ranges.
const LINUX_SHMEM_PAGE_LIMIT: usize = 16 * 1024;

/// Maps anonymous shared memory: the pages of an unnamed shmem node, which
/// a forked child shares rather than copies, as Linux backs MAP_SHARED |
/// MAP_ANONYMOUS with a shmem file. Each page is registered to this process,
/// and the node is freed once no process maps it.
fn linux_map_shared_anonymous(mapping: u64, pages: usize, protection: u8, replace: bool) -> u64 {
    let Some(handle) = crate::linux_overlay::create_shmem() else {
        return LINUX_ENOMEM;
    };
    let mapped = linux_map_shared_memfd(mapping, pages, handle, 0, protection, replace, None);
    if mapped != mapping {
        crate::linux_overlay::release_unmapped_shmem();
        return mapped;
    }
    let pid = current_linux_process_pid();
    for page in 0..pages {
        let address = mapping + (page * PAGE_SIZE) as u64;
        if !crate::linux_overlay::register_shared_mapping(pid, address, handle, page * PAGE_SIZE) {
            for rollback in 0..page {
                let _ = crate::linux_overlay::remove_shared_mapping(
                    pid,
                    mapping + (rollback * PAGE_SIZE) as u64,
                );
            }
            let _ = rollback_linux_runtime_mapping(mapping, pages);
            crate::linux_overlay::release_unmapped_shmem();
            return LINUX_ENOMEM;
        }
    }
    if replace {
        crate::linux_overlay::release_unmapped_shmem();
    }
    mapping
}

/// Drops the shared mappings registered to `pid`, whose pages its page
/// tables no longer hold, and frees anonymous shared memory that no process
/// maps any more.
pub(super) fn release_linux_process_shared_mappings(pid: u32) {
    crate::linux_overlay::remove_process_shared_mappings(pid);
    crate::linux_overlay::release_unmapped_shmem();
    crate::linux_areas::forget(linux_execution_instance(), pid);
    crate::linux_userfaultfd::forget(linux_execution_instance(), pid, 0, 1 << 47);
    linux_reclaim_unmapped_files();
}

/// Records the segments exec mapped for the new program: the executable's
/// at `path`, then its interpreter's at the path its PT_INTERP names.
pub(super) fn linux_record_exec_image(
    plan: &crate::linux_elf::RelocatableExecutablePlan<'_, '_>,
    path: &[u8],
) {
    use crate::linux_areas::{Area, Backing, Protection};
    use crate::linux_elf::RelocatableExecutablePlan;
    let main_count = match plan {
        RelocatableExecutablePlan::Interpreted(process) => process.main.segment_count,
        _ => plan.segment_count(),
    };
    let interpreter_path = match plan {
        RelocatableExecutablePlan::Interpreted(process) => process.interpreter_path,
        _ => path,
    };
    let (main_path, interpreter_path) = (
        alloc::sync::Arc::<[u8]>::from(path),
        alloc::sync::Arc::<[u8]>::from(interpreter_path),
    );
    for index in 0..plan.segment_count() {
        let Some(segment) = plan.segment(index) else {
            continue;
        };
        let protection =
            1 | if segment.writable { 2 } else { 0 } | if segment.executable { 4 } else { 0 };
        crate::linux_areas::map(
            linux_execution_instance(),
            current_linux_process_pid(),
            Area {
                start: segment.virtual_page,
                end: segment.virtual_page + (segment.page_count * PAGE_SIZE) as u64,
                protection: Protection::from_bits(protection),
                shared: false,
                may_write: true,
                locked: false,
                grows_down: false,
                huge: false,
                huge_reserved: false,
                dont_dump: false,
                policy: crate::linux_areas::Policy::DEFAULT,
                backing: Backing::File {
                    device: 0,
                    inode: 0,
                    offset: segment.file_page,
                    path: if index < main_count {
                        alloc::sync::Arc::clone(&main_path)
                    } else {
                        alloc::sync::Arc::clone(&interpreter_path)
                    },
                },
            },
        );
    }
    let stack = X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst)
        ..X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst);
    if !stack.is_empty() {
        crate::linux_areas::map(
            linux_execution_instance(),
            current_linux_process_pid(),
            Area {
                start: stack.start,
                end: stack.end,
                protection: Protection::from_bits(LINUX_PROT_READ | LINUX_PROT_WRITE),
                shared: false,
                may_write: true,
                locked: false,
                grows_down: false,
                huge: false,
                huge_reserved: false,
                dont_dump: false,
                policy: crate::linux_areas::Policy::DEFAULT,
                backing: Backing::Stack,
            },
        );
    }
}

/// Records the program break's heap, from its base up to `program_break`.
pub(super) fn linux_record_heap(program_break: u64) {
    use crate::linux_areas::{Area, Backing, Protection};
    let limit = X86_RUNTIME.ELF_PROBE_BRK_LIMIT.load(Ordering::SeqCst);
    let base = limit.saturating_sub((LINUX_RUNTIME_HEAP_PAGES * PAGE_SIZE) as u64);
    let (instance, pid) = (linux_execution_instance(), current_linux_process_pid());
    crate::linux_areas::unmap(instance, pid, base, limit - base);
    let Some(end) = program_break.checked_next_multiple_of(PAGE_SIZE as u64) else {
        return;
    };
    if end > base {
        crate::linux_areas::map(
            instance,
            pid,
            Area {
                start: base,
                end: end.min(limit),
                protection: Protection::from_bits(LINUX_PROT_READ | LINUX_PROT_WRITE),
                shared: false,
                may_write: true,
                locked: false,
                grows_down: false,
                huge: false,
                huge_reserved: false,
                dont_dump: false,
                policy: crate::linux_areas::Policy::DEFAULT,
                backing: Backing::Heap,
            },
        );
    }
}

/// Whether `descriptor` is open on /dev/zero, whose mappings are
/// anonymous memory.
fn linux_dev_zero_descriptor(descriptor: u64) -> bool {
    let descriptor = u64::from(descriptor as u32);
    linux_descriptor_open(descriptor)
        && linux_overlay_descriptor_handle(descriptor).is_none()
        && linux_rootfs_descriptor(descriptor) == 0
        && linux_socket_slot(descriptor).is_none()
        && linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_ZERO
}

/// Records a successful mmap of `length` bytes at `address` in the
/// process's memory areas, with the file it maps.
pub(super) fn linux_record_mapping(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    descriptor: u64,
    offset: u64,
) {
    use crate::linux_areas::{Area, Backing, Protection};
    let Some(end) = address
        .checked_add(length)
        .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE as u64))
    else {
        return;
    };
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || end > 1 << 47
        || !address.is_multiple_of(PAGE_SIZE as u64)
    {
        return;
    }
    // A shared file mapping may only become writable through a descriptor
    // with write access, of a file not sealed against writes.
    let may_write = flags & LINUX_MAP_SHARED == 0
        || flags & LINUX_MAP_ANONYMOUS != 0
        || linux_device_descriptor(descriptor) & LINUX_DESCRIPTOR_OUTPUT != 0
            && !linux_overlay_descriptor_handle(descriptor)
                .and_then(crate::linux_overlay::file_seals)
                .is_some_and(|seals| seals & (LINUX_F_SEAL_WRITE | LINUX_F_SEAL_FUTURE_WRITE) != 0);
    let backing = if flags & LINUX_MAP_TYPE == LINUX_MAP_DROPPABLE {
        Backing::Droppable
    } else if flags & LINUX_MAP_ANONYMOUS != 0 || linux_dev_zero_descriptor(descriptor) {
        Backing::Anonymous
    } else {
        let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        match (
            linux_descriptor_path(descriptor, &mut path),
            linux_descriptor_stat(descriptor),
        ) {
            (Some(length), Some(stat)) => Backing::File {
                device: u64::from_ne_bytes(stat[..8].try_into().unwrap_or([0; 8])),
                inode: u64::from_ne_bytes(stat[8..16].try_into().unwrap_or([0; 8])),
                offset,
                path: alloc::sync::Arc::from(&path[..length]),
            },
            _ => Backing::Anonymous,
        }
    };
    crate::linux_areas::map(
        linux_execution_instance(),
        current_linux_process_pid(),
        Area {
            start: address,
            end,
            protection: Protection::from_bits(protection),
            shared: flags & LINUX_MAP_SHARED != 0,
            may_write,
            locked: flags & LINUX_MAP_LOCKED != 0,
            grows_down: flags & LINUX_MAP_GROWSDOWN != 0,
            huge: false,
            huge_reserved: false,
            dont_dump: false,
            policy: crate::linux_areas::Policy::DEFAULT,
            backing,
        },
    );
}

pub(super) fn linux_runtime_munmap(address: u64, length: u64) -> u64 {
    crate::linux_profile::span(crate::linux_profile::Span::Munmap, || {
        linux_runtime_munmap_pages(address, length)
    })
}

/// Visits the pages of [start, end) that have a page-table entry slot (their
/// 2 MiB span has a leaf table), in order, until `visit` says false. The
/// other pages hold no entry: nothing to seal, map or release (a lazily
/// reserved anonymous page lives in its memory area only).
fn for_each_linux_tabled_page(start: u64, end: u64, mut visit: impl FnMut(u64) -> bool) -> bool {
    const SPAN: u64 = 1 << 21;
    let mut cursor = start;
    // The walk aligns down to the span: once the cursor has reached an end
    // inside a span, that span would be found again.
    while cursor < end {
        let Some(span) = address_space::next_current_linux_leaf_table(cursor, end) else {
            break;
        };
        let span_end = span.saturating_add(SPAN).min(end);
        let mut page = span.max(cursor);
        while page < span_end {
            if !visit(page) {
                return false;
            }
            page += PAGE_SIZE as u64;
        }
        cursor = span_end;
    }
    true
}

fn linux_runtime_munmap_pages(address: u64, length: u64) -> u64 {
    let Some((end, _)) = linux_runtime_mapping_range(address, length) else {
        return LINUX_EINVAL;
    };
    let pid = current_linux_process_pid();
    // Only pages with page tables can be sealed or hold frames: an unmap
    // walks those, not every page of the range. fork14's cleanup unmapped
    // hundreds of 1 GiB mappings no page of which was touched, a hundred
    // million pages walked one by one, each with four table walks and two
    // searches of the shared mappings.
    if !for_each_linux_tabled_page(address, end, |page| {
        !address_space::current_linux_runtime_page(page).sealed
    }) {
        return LINUX_EPERM;
    }
    // A shared mapping's page is written back to its file before it goes;
    // the process's shared mappings in the range are found once each.
    let mut unshared = false;
    let mut after = address.checked_sub(1);
    while let Some((page, _, _)) = crate::linux_overlay::next_shared_mapping(pid, after) {
        if page >= end {
            break;
        }
        let _ = linux_flush_shared_mapping_page(pid, page);
        unshared |= crate::linux_overlay::remove_shared_mapping(pid, page);
        after = Some(page);
    }
    if !for_each_linux_tabled_page(address, end, |page| {
        release_linux_runtime_page(address_space::remove_current_linux_runtime_page(page))
    }) {
        return LINUX_EINVAL;
    }
    // Shared memory can only have lost its last mapping here if a shared
    // mapping went: looking through every overlay node on each munmap made
    // munmap04's 65,000 unmaps take seconds once a long run had made
    // thousands of files.
    if unshared {
        crate::linux_overlay::release_unmapped_shmem();
    }
    if !address_space::prune_current_linux_page_tables(address, end) {
        return LINUX_EINVAL;
    }
    0
}

pub(super) fn linux_mremap(
    old_address: u64,
    old_length: u64,
    new_length: u64,
    flags: u64,
    fixed_address: u64,
) -> u64 {
    const MREMAP_MAYMOVE: u64 = 1;
    const MREMAP_FIXED: u64 = 2;
    const MREMAP_DONTUNMAP: u64 = 4;
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return LINUX_ENOSYS;
    }
    let dont_unmap = flags & MREMAP_DONTUNMAP != 0;
    if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
        || flags & MREMAP_FIXED != 0 && flags & MREMAP_MAYMOVE == 0
        || dont_unmap && flags & MREMAP_MAYMOVE == 0
    {
        return LINUX_EINVAL;
    }
    let Some((old_end, old_pages)) = linux_runtime_mapping_range(old_address, old_length) else {
        return LINUX_EINVAL;
    };
    let Ok(new_pages) = usize::try_from(new_length.div_ceil(PAGE_SIZE as u64)) else {
        return LINUX_ENOMEM;
    };
    // MREMAP_DONTUNMAP moves a mapping without resizing it.
    if new_length == 0 || dont_unmap && new_pages != old_pages {
        return LINUX_EINVAL;
    }
    let fixed = flags & MREMAP_FIXED != 0;
    let new_bytes = (new_pages as u64).saturating_mul(PAGE_SIZE as u64);
    // MREMAP_FIXED's destination is page aligned, in the user half of the
    // address space and apart from the source (mremap05).
    if fixed
        && (!fixed_address.is_multiple_of(PAGE_SIZE as u64)
            || fixed_address
                .checked_add(new_bytes)
                .is_none_or(|end| end > 1 << 47 || fixed_address < old_end && old_address < end))
    {
        return LINUX_EINVAL;
    }
    // A source that is not wholly mapped is EFAULT (mremap03).
    if (0..old_pages).any(|page| {
        !address_space::current_linux_runtime_page(old_address + (page * PAGE_SIZE) as u64).occupied
    }) {
        return LINUX_EFAULT;
    }
    if (0..old_pages).any(|page| {
        address_space::current_linux_runtime_page(old_address + (page * PAGE_SIZE) as u64).sealed
    }) {
        return LINUX_EPERM;
    }
    let template = address_space::current_linux_runtime_page(old_address);
    // A shared file mapping grows over the file's next pages.
    let shared_file = template
        .shared
        .then(|| linux_shared_file_page(old_address))
        .flatten();
    if dont_unmap {
        return linux_mremap_dont_unmap(
            (old_address, old_pages),
            fixed.then_some(fixed_address),
            &template,
            shared_file,
        );
    }
    if fixed {
        if template.file && new_pages > old_pages {
            return LINUX_ENOMEM;
        }
        // The destination is unmapped first, as Linux does (mremap08),
        // and a shrinking source loses its tail before it moves.
        let unmapped = linux_munmap(fixed_address, new_bytes);
        if unmapped != 0 {
            return unmapped;
        }
        crate::linux_areas::unmap(
            linux_execution_instance(),
            current_linux_process_pid(),
            fixed_address,
            new_bytes,
        );
        for page in new_pages..old_pages {
            if !release_linux_runtime_page(address_space::remove_current_linux_runtime_page(
                old_address + (page * PAGE_SIZE) as u64,
            )) {
                return LINUX_EINVAL;
            }
        }
        return linux_mremap_move(
            old_address,
            old_pages.min(new_pages),
            new_pages,
            fixed_address,
            &template,
            shared_file,
        );
    }
    if old_pages == new_pages {
        return old_address;
    }
    if new_pages < old_pages {
        for page in new_pages..old_pages {
            if !release_linux_runtime_page(address_space::remove_current_linux_runtime_page(
                old_address + (page * PAGE_SIZE) as u64,
            )) {
                return LINUX_EINVAL;
            }
        }
        return old_address;
    }

    let extension_pages = new_pages - old_pages;
    if !linux_address_space_limit_allows(extension_pages) {
        return LINUX_ENOMEM;
    }
    if template.file {
        return LINUX_ENOMEM;
    }
    if linux_runtime_range_available(old_end, extension_pages) {
        for page in 0..extension_pages {
            let address = old_end + (page * PAGE_SIZE) as u64;
            let extended = match shared_file {
                Some((handle, offset)) => linux_map_shared_file_page(
                    address,
                    handle,
                    offset + (old_pages + page) * PAGE_SIZE,
                    template.protection,
                ),
                None => {
                    address_space::reserve_current_linux_runtime_page(
                        address,
                        template.protection,
                        false,
                        false,
                    ) == Some(None)
                }
            };
            if !extended {
                let _ = rollback_linux_runtime_mapping(old_end, page);
                return LINUX_ENOMEM;
            }
            if template.dontfork
                && !address_space::set_current_linux_runtime_page_dontfork(address, true)
            {
                let _ = rollback_linux_runtime_mapping(old_end, page + 1);
                return LINUX_ENOMEM;
            }
            if template.wipeonfork
                && !address_space::set_current_linux_runtime_page_wipeonfork(address, true)
            {
                let _ = rollback_linux_runtime_mapping(old_end, page + 1);
                return LINUX_ENOMEM;
            }
        }
        return old_address;
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return LINUX_ENOMEM;
    }
    let Some(destination) = linux_runtime_select_mapping(0, new_pages, false, false) else {
        return LINUX_ENOMEM;
    };
    if !linux_runtime_range_available(destination, new_pages) {
        return LINUX_ENOMEM;
    }
    linux_mremap_move(
        old_address,
        old_pages,
        new_pages,
        destination,
        &template,
        shared_file,
    )
}

/// mremap with MREMAP_DONTUNMAP: the `pages` pages at `old_address` move
/// to `fixed` (or a place chosen for them), and the old range stays mapped
/// as it was, without pages: a private anonymous mapping's then fault in
/// as zeros (or reach a userfaultfd registered there), a shared file
/// mapping's map the file again. Other mappings (anonymous shared memory,
/// private file mappings) are not supported here (EINVAL).
fn linux_mremap_dont_unmap(
    (old_address, pages): (u64, usize),
    fixed: Option<u64>,
    template: &address_space::LinuxRuntimePage,
    shared_file: Option<(crate::linux_overlay::Handle, usize)>,
) -> u64 {
    if template.file && shared_file.is_none() || template.shared && shared_file.is_none() {
        return LINUX_EINVAL;
    }
    let bytes = (pages * PAGE_SIZE) as u64;
    let destination = match fixed {
        Some(destination) => {
            let unmapped = linux_munmap(destination, bytes);
            if unmapped != 0 {
                return unmapped;
            }
            crate::linux_areas::unmap(
                linux_execution_instance(),
                current_linux_process_pid(),
                destination,
                bytes,
            );
            destination
        }
        None => {
            if !linux_address_space_limit_allows(pages) {
                return LINUX_ENOMEM;
            }
            let Some(destination) = linux_runtime_select_mapping(0, pages, false, false)
                .filter(|destination| linux_runtime_range_available(*destination, pages))
            else {
                return LINUX_ENOMEM;
            };
            destination
        }
    };
    let moved = linux_mremap_move(
        old_address,
        pages,
        pages,
        destination,
        template,
        shared_file,
    );
    if moved >= LINUX_RETURN_TO_KERNEL {
        return moved;
    }
    for page in 0..pages {
        let address = old_address + (page * PAGE_SIZE) as u64;
        let remapped = match shared_file {
            Some((handle, offset)) => linux_map_shared_file_page(
                address,
                handle,
                offset + page * PAGE_SIZE,
                template.protection,
            ),
            None => {
                address_space::reserve_current_linux_runtime_page(
                    address,
                    template.protection,
                    false,
                    false,
                ) == Some(None)
            }
        };
        if !remapped {
            return LINUX_ENOMEM;
        }
    }
    destination
}

/// Moves the first `old_pages` pages at `old_address` to `destination`
/// and reserves the rest up to `new_pages` like `template`, or maps them
/// to the next pages of `shared_file` (its file and the offset of
/// `old_address` in it), undoing the move if a page cannot be placed.
fn linux_mremap_move(
    old_address: u64,
    old_pages: usize,
    new_pages: usize,
    destination: u64,
    template: &address_space::LinuxRuntimePage,
    shared_file: Option<(crate::linux_overlay::Handle, usize)>,
) -> u64 {
    for page_index in 0..old_pages {
        let source = old_address + (page_index * PAGE_SIZE) as u64;
        let target = destination + (page_index * PAGE_SIZE) as u64;
        if !address_space::move_current_linux_runtime_page(source, target) {
            for rollback in 0..page_index {
                let _ = address_space::move_current_linux_runtime_page(
                    destination + (rollback * PAGE_SIZE) as u64,
                    old_address + (rollback * PAGE_SIZE) as u64,
                );
            }
            return LINUX_ENOMEM;
        }
    }
    // A page of a shared file or shmem mapping keeps its place in the file
    // at its new address.
    let pid = current_linux_process_pid();
    for page_index in 0..old_pages {
        let source = old_address + (page_index * PAGE_SIZE) as u64;
        if let Some((handle, offset)) = crate::linux_overlay::shared_mapping(pid, source) {
            let _ = crate::linux_overlay::remove_shared_mapping(pid, source);
            let _ = crate::linux_overlay::register_shared_mapping(
                pid,
                destination + (page_index * PAGE_SIZE) as u64,
                handle,
                offset,
            );
        }
    }
    for page in old_pages..new_pages {
        let target = destination + (page * PAGE_SIZE) as u64;
        let extended = match shared_file {
            Some((handle, offset)) => linux_map_shared_file_page(
                target,
                handle,
                offset + page * PAGE_SIZE,
                template.protection,
            ),
            None => {
                address_space::reserve_current_linux_runtime_page(
                    target,
                    template.protection,
                    false,
                    false,
                ) == Some(None)
            }
        };
        if !extended {
            for extension in old_pages..page {
                let _ =
                    release_linux_runtime_page(address_space::remove_current_linux_runtime_page(
                        destination + (extension * PAGE_SIZE) as u64,
                    ));
            }
            for rollback in 0..old_pages {
                let _ = address_space::move_current_linux_runtime_page(
                    destination + (rollback * PAGE_SIZE) as u64,
                    old_address + (rollback * PAGE_SIZE) as u64,
                );
            }
            return LINUX_ENOMEM;
        }
        if template.dontfork
            && !address_space::set_current_linux_runtime_page_dontfork(target, true)
        {
            return LINUX_ENOMEM;
        }
        if template.wipeonfork
            && !address_space::set_current_linux_runtime_page_wipeonfork(target, true)
        {
            return LINUX_ENOMEM;
        }
    }
    destination
}

pub(super) fn linux_msync(address: u64, length: u64, flags: u64) -> u64 {
    const MS_ASYNC: u64 = 1;
    const MS_INVALIDATE: u64 = 2;
    const MS_SYNC: u64 = 4;
    let flags = u64::from(flags as u32);
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || flags & (MS_ASYNC | MS_SYNC) == (MS_ASYNC | MS_SYNC)
    {
        return LINUX_EINVAL;
    }
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return LINUX_ENOSYS;
    }
    if !address.is_multiple_of(PAGE_SIZE as u64) {
        return LINUX_EINVAL;
    }
    let Some((_, pages)) = linux_runtime_mapping_range(address, length) else {
        return LINUX_ENOMEM;
    };
    // Pages locked in memory cannot be invalidated.
    if flags & MS_INVALIDATE != 0
        && crate::linux_areas::locked_in(
            linux_execution_instance(),
            current_linux_process_pid(),
            address,
            length,
        )
    {
        return LINUX_EBUSY;
    }
    for page in 0..pages {
        let page_address = address + (page * PAGE_SIZE) as u64;
        if !address_space::current_linux_runtime_page(page_address).occupied {
            return LINUX_ENOMEM;
        }
    }
    let end = address + (pages * PAGE_SIZE) as u64;
    for (page_address, handle, offset) in
        crate::linux_overlay::shared_mappings_in(current_linux_process_pid(), address, end)
    {
        if !linux_flush_shared_file_page(page_address, handle, offset) {
            return LINUX_EIO;
        }
    }
    0
}

fn linux_flush_shared_mapping_page(pid: u32, address: u64) -> bool {
    let Some((handle, offset)) = crate::linux_overlay::shared_mapping(pid, address) else {
        return true;
    };
    linux_flush_shared_file_page(address, handle, offset)
}

/// Writes the page the current process maps at `address`, page `offset`
/// of `handle` shared, back to the file.
fn linux_flush_shared_file_page(
    address: u64,
    handle: crate::linux_overlay::Handle,
    offset: usize,
) -> bool {
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return false;
    };
    if offset >= metadata.size {
        return true;
    }
    let length = (metadata.size - offset).min(PAGE_SIZE);
    let mut bytes = [0_u8; PAGE_SIZE];
    copy_from_linux_user(address, &mut bytes[..length])
        && crate::linux_overlay::write(handle, offset, &bytes[..length]) == Some(length)
}

fn linux_flush_process_shared_mappings(pid: u32) -> bool {
    let mut after = None;
    while let Some((address, _, _)) = crate::linux_overlay::next_shared_mapping(pid, after) {
        if !linux_flush_shared_mapping_page(pid, address) {
            return false;
        }
        after = Some(address);
    }
    true
}

pub(super) fn linux_sync_file_range(descriptor: u64, offset: u64, length: u64, flags: u64) -> u64 {
    const SYNC_FILE_RANGE_VALID_FLAGS: u64 = 1 | 2 | 4;
    let descriptor = u64::from(descriptor as u32);
    let flags = u64::from(flags as u32);
    if flags & !SYNC_FILE_RANGE_VALID_FLAGS != 0
        || offset > i64::MAX as u64
        || length > i64::MAX as u64
        || offset
            .checked_add(length)
            .is_none_or(|end| end > i64::MAX as u64)
    {
        return LINUX_EINVAL;
    }
    // A closed descriptor is EBADF; one that is no regular file (a device,
    // pipe or socket) has no range to sync (ESPIPE), as in Linux.
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    if linux_overlay_descriptor_handle(descriptor).is_none()
        && linux_rootfs_descriptor(descriptor) == 0
    {
        return LINUX_ESPIPE;
    }
    0
}

pub(super) fn linux_fsync(descriptor: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    if !linux_descriptor_open(descriptor) || linux_path_descriptor(descriptor) {
        return LINUX_EBADF;
    }
    if let Some(handle) = linux_overlay_descriptor_handle(descriptor) {
        // A volume's pages that shared mappings changed go to its disk; the
        // overlay's files are their own backing store.
        if crate::linux_blockfs::owns(handle) {
            crate::linux_blockfs::write_back_all();
        }
        0
    } else if linux_rootfs_entry(descriptor).is_some() {
        // Immutable OCI objects have no dirty data.
        0
    } else {
        LINUX_EINVAL
    }
}

pub(super) fn linux_cachestat(
    descriptor: u64,
    range_address: u64,
    output_address: u64,
    flags: u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let flags = u64::from(flags as u32);
    if flags != 0 {
        return LINUX_EINVAL;
    }
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    if linux_overlay_descriptor_handle(descriptor).is_some_and(linux_overlay_huge) {
        return LINUX_EOPNOTSUPP;
    }
    let size = if let Some(metadata) =
        linux_overlay_descriptor_handle(descriptor).and_then(crate::linux_overlay::metadata)
    {
        metadata.size as u64
    } else if let Some(entry) = linux_rootfs_entry(descriptor) {
        entry.data().len() as u64
    } else {
        return LINUX_EBADF;
    };
    let mut range = [0_u8; 16];
    if !copy_from_linux_user(range_address, &mut range) {
        return LINUX_EFAULT;
    }
    let offset = u64::from_ne_bytes(range[..8].try_into().unwrap());
    let length = u64::from_ne_bytes(range[8..].try_into().unwrap());
    let start = offset.min(size);
    let end = if length == 0 {
        size
    } else {
        offset.saturating_add(length).min(size)
    };
    let cached = end.saturating_sub(start).div_ceil(PAGE_SIZE as u64);
    let mut result = [0_u8; 40];
    result[..8].copy_from_slice(&cached.to_ne_bytes());
    if copy_to_linux_user(output_address, &result) {
        0
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    fd: u64,
    offset: u64,
) -> u64 {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        if linux_io_uring_descriptor(fd) {
            return linux_io_uring_mmap(address, length, protection, flags, fd, offset);
        }
        return linux_runtime_mmap(address, length, protection, flags, fd, offset);
    }
    if length == 0 {
        return LINUX_EINVAL;
    }
    let Ok(pages) = u8::try_from(length.div_ceil(PAGE_SIZE as u64)) else {
        return LINUX_EINVAL;
    };
    let slot_limit = linux_mmap_slot_limit();
    if usize::from(pages) > slot_limit {
        return LINUX_EINVAL;
    }
    let anonymous_flags = LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS;
    let fixed_anonymous_flags = anonymous_flags | LINUX_MAP_FIXED_NOREPLACE;
    let replace_anonymous_flags = anonymous_flags | LINUX_MAP_FIXED;
    let fixed_anonymous = flags == fixed_anonymous_flags;
    let replace_anonymous = flags == replace_anonymous_flags;
    if address != 0 && !fixed_anonymous && !replace_anonymous {
        return linux_mmap_fixed_file(address, length, protection, flags, fd, offset);
    }
    if address == 0 && (fixed_anonymous || replace_anonymous) {
        return LINUX_EINVAL;
    }
    let start_slot = if fixed_anonymous || replace_anonymous {
        let Some((start, range_pages)) = linux_mmap_range_slots(address, length) else {
            return LINUX_EINVAL;
        };
        if range_pages != usize::from(pages) {
            return LINUX_EINVAL;
        }
        start
    } else {
        let Some(start) = (0..=slot_limit - usize::from(pages)).find(|start| {
            (*start..*start + usize::from(pages)).all(|slot| !linux_mmap_slot_occupied(slot))
        }) else {
            return LINUX_ENOMEM;
        };
        start
    };
    if !replace_anonymous
        && (start_slot..start_slot + usize::from(pages)).any(linux_mmap_slot_occupied)
    {
        return if fixed_anonymous {
            LINUX_EEXIST
        } else {
            LINUX_ENOMEM
        };
    }
    if replace_anonymous
        && (start_slot..start_slot + usize::from(pages))
            .any(|slot| X86_RUNTIME.ELF_PROBE_MMAP_SEALED[slot].load(Ordering::SeqCst))
    {
        return LINUX_EPERM;
    }
    let mapping =
        X86_RUNTIME.ELF_PROBE_MMAP.load(Ordering::SeqCst) + (start_slot * PAGE_SIZE) as u64;
    if mapping == 0
        || (fixed_anonymous || replace_anonymous) && mapping != address
        || !replace_anonymous
            && (start_slot..start_slot + usize::from(pages)).any(|slot| {
                linux_mmap_slot_frame(slot) != 0
                    || X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].load(Ordering::SeqCst) != 0
            })
    {
        return LINUX_ENOMEM;
    }

    let (file_kind, file_source) =
        if flags == anonymous_flags || fixed_anonymous || replace_anonymous {
            if protection != 0
                && protection != LINUX_PROT_READ
                && protection != (LINUX_PROT_READ | LINUX_PROT_WRITE)
                || fd != u64::MAX && fd != u64::from(u32::MAX)
                || offset != 0
            {
                return LINUX_EINVAL;
            }
            (0, None)
        } else {
            if protection != LINUX_PROT_READ || flags != LINUX_MAP_PRIVATE {
                return LINUX_EINVAL;
            }
            let state = linux_device_descriptor(fd);
            let Some(file) = linux_rootfs_entry(fd)
                .map(RegularFile::Rootfs)
                .or_else(|| linux_regular_file_contents(state))
            else {
                return if linux_descriptor_open(fd) {
                    LINUX_ENODEV
                } else {
                    LINUX_EBADF
                };
            };
            if linux_proc_file(state) {
                return LINUX_ENODEV;
            }
            if state & 3 != LINUX_DESCRIPTOR_INPUT || !offset.is_multiple_of(PAGE_SIZE as u64) {
                return LINUX_EINVAL;
            }
            let Ok(start) = usize::try_from(offset) else {
                return LINUX_EINVAL;
            };
            let mapped_length = usize::from(pages) * PAGE_SIZE;
            if start >= file.len()
                || start
                    .checked_add(mapped_length)
                    .is_none_or(|end| end > file.len().next_multiple_of(PAGE_SIZE))
            {
                return LINUX_EINVAL;
            }
            (state & LINUX_FILE_MASK, Some((file, start)))
        };

    if protection == 0 {
        if replace_anonymous {
            let mut slots = linux_mmap_slot_attributes();
            let mut old_leases = [None; LINUX_RUNTIME_MMAP_SLOT_COUNT];
            let mut old_writable = [false; LINUX_RUNTIME_MMAP_SLOT_COUNT];
            let mut released = [memory::FrameLease::EMPTY; LINUX_RUNTIME_MMAP_SLOT_COUNT];
            let mut released_count = 0;
            for offset in 0..usize::from(pages) {
                let slot = start_slot + offset;
                if let Some((old_protection, _)) = slots[slot] {
                    if old_protection != 0 {
                        let Some(lease) = linux_mmap_slot_lease(slot) else {
                            return LINUX_ENOMEM;
                        };
                        old_leases[offset] = Some(lease);
                        old_writable[offset] = u64::from(old_protection) & LINUX_PROT_WRITE != 0;
                        released[released_count] = lease;
                        released_count += 1;
                    } else if linux_mmap_slot_frame(slot) != 0
                        || X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].load(Ordering::SeqCst) != 0
                    {
                        return LINUX_ENOMEM;
                    }
                } else if linux_mmap_slot_frame(slot) != 0
                    || X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].load(Ordering::SeqCst) != 0
                {
                    return LINUX_ENOMEM;
                }
            }
            if released_count != 0
                && !memory::frame_leases_releasable(
                    memory::FrameOwner::KERNEL,
                    &released[..released_count],
                )
                || !address_space::reserve_current_linux_pages(
                    mapping,
                    &old_leases[..usize::from(pages)],
                    &old_writable[..usize::from(pages)],
                )
            {
                return LINUX_ENOMEM;
            }
            for offset in 0..usize::from(pages) {
                let slot = start_slot + offset;
                linux_mmap_clear_slot_lease(slot);
                slots[slot] = Some((0, 0));
            }
            linux_mmap_rebuild_areas(slots);
            if released_count != 0
                && !memory::scrub_and_release_frames(
                    memory::FrameOwner::KERNEL,
                    &released[..released_count],
                )
            {
                return LINUX_ENOMEM;
            }
            return mapping;
        }
        X86_RUNTIME.ELF_PROBE_MMAP_PAGES[start_slot].store(pages, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[start_slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_FILE[start_slot].store(0, Ordering::SeqCst);
        return mapping;
    }

    let Some(leases) = linux_allocate_mmap_leases(usize::from(pages)) else {
        return LINUX_ENOMEM;
    };
    for offset in 0..usize::from(pages) {
        let bytes = file_source.as_ref().map_or(&[][..], |(file, start)| {
            let page_start = *start + offset * PAGE_SIZE;
            &file[page_start..page_start.saturating_add(PAGE_SIZE).min(file.len())]
        });
        if !address_space::prepare_linux_frame(leases[offset].address(), bytes) {
            let _ = memory::scrub_and_release_frames(
                memory::FrameOwner::KERNEL,
                &leases[..usize::from(pages)],
            );
            return LINUX_ENOMEM;
        }
    }
    if replace_anonymous {
        let mut slots = linux_mmap_slot_attributes();
        let mut old_leases = [None; LINUX_RUNTIME_MMAP_SLOT_COUNT];
        let mut old_writable = [false; LINUX_RUNTIME_MMAP_SLOT_COUNT];
        let mut released = [memory::FrameLease::EMPTY; LINUX_RUNTIME_MMAP_SLOT_COUNT];
        let mut released_count = 0;
        for offset in 0..usize::from(pages) {
            let slot = start_slot + offset;
            match slots[slot] {
                Some((old_protection, _)) => {
                    if old_protection == 0 {
                        if linux_mmap_slot_frame(slot) != 0
                            || X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].load(Ordering::SeqCst)
                                != 0
                            || !address_space::current_linux_page_absent(
                                mapping + (offset * PAGE_SIZE) as u64,
                            )
                        {
                            let _ = memory::scrub_and_release_frames(
                                memory::FrameOwner::KERNEL,
                                &leases[..usize::from(pages)],
                            );
                            return LINUX_ENOMEM;
                        }
                    } else {
                        let Some(lease) = linux_mmap_slot_lease(slot) else {
                            let _ = memory::scrub_and_release_frames(
                                memory::FrameOwner::KERNEL,
                                &leases[..usize::from(pages)],
                            );
                            return LINUX_ENOMEM;
                        };
                        old_leases[offset] = Some(lease);
                        old_writable[offset] = u64::from(old_protection) & LINUX_PROT_WRITE != 0;
                        released[released_count] = lease;
                        released_count += 1;
                    }
                }
                None => {
                    if linux_mmap_slot_frame(slot) != 0
                        || X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[slot].load(Ordering::SeqCst) != 0
                    {
                        let _ = memory::scrub_and_release_frames(
                            memory::FrameOwner::KERNEL,
                            &leases[..usize::from(pages)],
                        );
                        return LINUX_ENOMEM;
                    }
                }
            }
        }
        if released_count != 0
            && !memory::frame_leases_releasable(
                memory::FrameOwner::KERNEL,
                &released[..released_count],
            )
            || !address_space::replace_current_linux_pages(
                mapping,
                &old_leases[..usize::from(pages)],
                &old_writable[..usize::from(pages)],
                &leases[..usize::from(pages)],
                protection & LINUX_PROT_WRITE != 0,
            )
        {
            let _ = memory::scrub_and_release_frames(
                memory::FrameOwner::KERNEL,
                &leases[..usize::from(pages)],
            );
            return LINUX_ENOMEM;
        }
        for (offset, lease) in leases[..usize::from(pages)].iter().copied().enumerate() {
            let slot = start_slot + offset;
            linux_mmap_store_slot_lease(slot, lease);
            slots[slot] = Some((protection as u8, 0));
        }
        linux_mmap_rebuild_areas(slots);
        if released_count != 0
            && !memory::scrub_and_release_frames(
                memory::FrameOwner::KERNEL,
                &released[..released_count],
            )
        {
            return LINUX_ENOMEM;
        }
        return mapping;
    }
    let writable = protection & LINUX_PROT_WRITE != 0;
    let map_page = |address, frame| {
        if writable {
            address_space::map_current_linux_page(address, frame)
        } else {
            address_space::map_current_linux_read_only_page(address, frame)
        }
    };
    let mut mapped = 0;
    while mapped < usize::from(pages) {
        if !map_page(
            mapping + (mapped * PAGE_SIZE) as u64,
            leases[mapped].address(),
        ) {
            for (rollback, lease) in leases.iter().enumerate().take(mapped) {
                let _ = address_space::unmap_current_linux_page(
                    mapping + (rollback * PAGE_SIZE) as u64,
                    lease.address(),
                );
            }
            let _ = memory::scrub_and_release_frames(
                memory::FrameOwner::KERNEL,
                &leases[..usize::from(pages)],
            );
            return LINUX_ENOMEM;
        }
        mapped += 1;
    }
    for (offset, lease) in leases[..usize::from(pages)].iter().copied().enumerate() {
        linux_mmap_store_slot_lease(start_slot + offset, lease);
    }
    X86_RUNTIME.ELF_PROBE_MMAP_PAGES[start_slot].store(pages, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[start_slot].store(protection as u8, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_MMAP_FILE[start_slot].store(file_kind as u8, Ordering::SeqCst);
    mapping
}

fn linux_mmap_fixed_file(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    fd: u64,
    offset: u64,
) -> u64 {
    if length != PAGE_SIZE as u64 || flags != (LINUX_MAP_PRIVATE | LINUX_MAP_FIXED_NOREPLACE) {
        return LINUX_EINVAL;
    }
    let state = linux_device_descriptor(fd);
    let Some(file) = linux_regular_file_contents(state) else {
        return if linux_descriptor_open(fd) {
            LINUX_ENODEV
        } else {
            LINUX_EBADF
        };
    };
    if linux_proc_file(state) {
        return LINUX_ENODEV;
    }
    if state & 3 != LINUX_DESCRIPTOR_INPUT {
        return LINUX_EACCES;
    }

    let file_kind = state & LINUX_FILE_MASK;
    let dependency = match file_kind {
        LINUX_FILE_DEPENDENCY => Some(0),
        LINUX_FILE_AUXILIARY_DEPENDENCY => Some(1),
        _ => None,
    };
    let (
        bit,
        expected_offset,
        file_size,
        expected_protection,
        mapping_state,
        relative_address,
        selectable_base,
        mapping_index,
    ) = if file_kind == LINUX_FILE_INIT {
        let Some(index) = X86_RUNTIME
            .ELF_PROBE_MAIN_ADDRESSES
            .iter()
            .position(|candidate| candidate.load(Ordering::SeqCst) == address)
        else {
            return LINUX_EINVAL;
        };
        (
            1_u8 << index,
            X86_RUNTIME.ELF_PROBE_MAIN_OFFSETS[index].load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_MAIN_FILE_SIZES[index].load(Ordering::SeqCst),
            u64::from(X86_RUNTIME.ELF_PROBE_MAIN_PROTECTIONS[index].load(Ordering::SeqCst)),
            X86_RUNTIME.ELF_PROBE_MAIN_MAPPINGS.0,
            0,
            false,
            index,
        )
    } else if let Some(dependency) = dependency {
        let state_start = dependency * LINUX_DEPENDENCY_MAPPING_COUNT;
        let Some(index) = (0..LINUX_DEPENDENCY_MAPPING_COUNT).position(|index| {
            let state = state_start + index;
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_FILE_SIZES[state].load(Ordering::SeqCst) != 0
                && X86_RUNTIME.ELF_PROBE_DEPENDENCY_OFFSETS[state].load(Ordering::SeqCst) == offset
                && u64::from(
                    X86_RUNTIME.ELF_PROBE_DEPENDENCY_PROTECTIONS[state].load(Ordering::SeqCst),
                ) == protection
        }) else {
            return LINUX_EINVAL;
        };
        let state = state_start + index;
        (
            1_u8 << index,
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_OFFSETS[state].load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_FILE_SIZES[state].load(Ordering::SeqCst),
            u64::from(X86_RUNTIME.ELF_PROBE_DEPENDENCY_PROTECTIONS[state].load(Ordering::SeqCst)),
            &X86_RUNTIME.ELF_PROBE_DEPENDENCY_MAPPINGS[dependency],
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_RELATIVES[state].load(Ordering::SeqCst),
            true,
            index,
        )
    } else {
        return LINUX_EACCES;
    };
    if address == 0
        || file_size == 0
        || file_size > PAGE_SIZE as u64
        || offset != expected_offset
        || protection != expected_protection
        || protection & (LINUX_PROT_WRITE | LINUX_PROT_EXEC) == (LINUX_PROT_WRITE | LINUX_PROT_EXEC)
    {
        return LINUX_EINVAL;
    }
    if selectable_base {
        let Some(candidate_base) = address.checked_sub(relative_address) else {
            return LINUX_EINVAL;
        };
        let dependency = dependency.unwrap_or(0);
        let base_min = X86_RUNTIME.ELF_PROBE_DEPENDENCY_BASE_MIN[dependency].load(Ordering::SeqCst);
        let base_end = X86_RUNTIME.ELF_PROBE_DEPENDENCY_BASE_END[dependency].load(Ordering::SeqCst);
        if candidate_base < base_min
            || candidate_base >= base_end
            || !candidate_base.is_multiple_of(PAGE_SIZE as u64)
        {
            return LINUX_EINVAL;
        }
        let selected_base = match X86_RUNTIME.ELF_PROBE_DEPENDENCY_SELECTED_BASE[dependency]
            .compare_exchange(0, candidate_base, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => candidate_base,
            Err(selected) => selected,
        };
        if selected_base != candidate_base {
            return LINUX_EINVAL;
        }
    }
    let Ok(start) = usize::try_from(offset) else {
        return LINUX_EINVAL;
    };
    let Ok(file_size) = usize::try_from(file_size) else {
        return LINUX_EINVAL;
    };
    if start >= file.len() {
        return LINUX_EINVAL;
    }
    let file_size = if dependency.is_some() {
        file_size.min(file.len() - start)
    } else {
        file_size
    };
    let Some(end) = start
        .checked_add(file_size)
        .filter(|end| *end <= file.len())
    else {
        return LINUX_EINVAL;
    };
    let Some([lease]) = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL) else {
        return LINUX_ENOMEM;
    };
    let frame = lease.address();
    if mapping_state.load(Ordering::SeqCst) & bit != 0 {
        let _ = memory::release_frames(memory::FrameOwner::KERNEL, [lease]);
        return LINUX_EEXIST;
    }
    if !address_space::prepare_linux_frame(frame, &file[start..end]) {
        let _ = memory::release_frames(memory::FrameOwner::KERNEL, [lease]);
        return LINUX_ENOMEM;
    }
    let writable = protection & LINUX_PROT_WRITE != 0;
    let executable = protection & LINUX_PROT_EXEC != 0;
    if !address_space::map_current_linux_file_page(address, frame, writable, executable) {
        let scrubbed = address_space::prepare_linux_frame(frame, &[]);
        if scrubbed {
            let _ = memory::release_frames(memory::FrameOwner::KERNEL, [lease]);
        }
        return LINUX_EEXIST;
    }
    if !append_linux_active_image_mapping(address, lease, writable, executable) {
        let unmapped = address_space::unmap_current_linux_page(address, frame);
        let scrubbed = unmapped && address_space::prepare_linux_frame(frame, &[]);
        if scrubbed {
            let _ = memory::release_frames(memory::FrameOwner::KERNEL, [lease]);
        }
        return LINUX_ENOMEM;
    }
    let (frame_state, generation_state) = if file_kind == LINUX_FILE_INIT {
        (
            &X86_RUNTIME.ELF_PROBE_MAIN_FRAMES[mapping_index],
            &X86_RUNTIME.ELF_PROBE_MAIN_GENERATIONS[mapping_index],
        )
    } else {
        let state = dependency.unwrap_or(0) * LINUX_DEPENDENCY_MAPPING_COUNT + mapping_index;
        (
            &X86_RUNTIME.ELF_PROBE_DEPENDENCY_FRAMES[state],
            &X86_RUNTIME.ELF_PROBE_DEPENDENCY_GENERATIONS[state],
        )
    };
    frame_state.store(lease.address(), Ordering::SeqCst);
    generation_state.store(lease.generation(), Ordering::SeqCst);
    mapping_state.fetch_or(bit, Ordering::SeqCst);
    address
}

pub(super) fn linux_munmap(address: u64, length: u64) -> u64 {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && address >= LINUX_FIXED_LOW_BASE {
        return linux_runtime_munmap(address, length);
    }
    let Some((start_slot, range_pages)) = linux_mmap_range_slots(address, length) else {
        return LINUX_EINVAL;
    };
    if (start_slot..start_slot + range_pages)
        .any(|slot| X86_RUNTIME.ELF_PROBE_MMAP_SEALED[slot].load(Ordering::SeqCst))
    {
        return LINUX_EPERM;
    }
    let mut slots = linux_mmap_slot_attributes();
    if !linux_mmap_unmap_and_release_slots(start_slot, range_pages) {
        return LINUX_EINVAL;
    }
    for slot in &mut slots[start_slot..start_slot + range_pages] {
        *slot = None;
    }
    for sealed in &X86_RUNTIME.ELF_PROBE_MMAP_SEALED[start_slot..start_slot + range_pages] {
        sealed.store(false, Ordering::SeqCst);
    }
    linux_mmap_rebuild_areas(slots);
    0
}
