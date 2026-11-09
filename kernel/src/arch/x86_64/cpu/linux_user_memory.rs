use super::*;

pub(super) fn copy_linux_cpu_location(cpu_address: u64, node_address: u64) -> bool {
    if (cpu_address != 0 && !linux_writable_user_range_contains(cpu_address, size_of::<u32>()))
        || (node_address != 0
            && !linux_writable_user_range_contains(node_address, size_of::<u32>()))
    {
        return false;
    }
    // The CPU this thread runs on right now (one NUMA node), on the owner's
    // path as on the light path: a thread pinned with sched_setaffinity sees
    // the CPU it was pinned to.
    let cpu = linux_cpu_slot() as u32;
    (cpu_address == 0 || copy_to_linux_user(cpu_address, &cpu.to_ne_bytes()))
        && (node_address == 0 || copy_to_linux_user(node_address, &0_u32.to_ne_bytes()))
}

pub(super) fn linux_writable_user_range_contains(address: u64, length: usize) -> bool {
    linux_user_range_covered(address, length, true)
}

pub(super) fn linux_ranges_overlap(
    first: u64,
    first_length: usize,
    second: u64,
    second_length: usize,
) -> bool {
    let Some(first_end) = first.checked_add(first_length as u64) else {
        return true;
    };
    let Some(second_end) = second.checked_add(second_length as u64) else {
        return true;
    };
    first < second_end && second < first_end
}

pub(super) fn linux_range_contains(base: u64, size: u64, address: u64, length: usize) -> bool {
    length != 0
        && address >= base
        && address
            .checked_add(length as u64)
            .is_some_and(|end| end <= base.saturating_add(size))
}

pub(super) fn linux_readable_user_range_contains(address: u64, length: usize) -> bool {
    linux_user_range_covered(address, length, false)
}

fn linux_user_area_end(base: u64, size: u64, address: u64) -> Option<u64> {
    let end = base.checked_add(size)?;
    (size != 0 && (base..end).contains(&address)).then_some(end)
}

fn extend_linux_user_area(next: &mut u64, base: u64, size: u64, address: u64) {
    if let Some(end) = linux_user_area_end(base, size, address) {
        *next = (*next).max(end);
    }
}

fn linux_user_range_covered(address: u64, length: usize, writable: bool) -> bool {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return materialize_linux_runtime_user_range(address, length, writable);
    }
    let Some(target) = address.checked_add(length as u64) else {
        return false;
    };
    if length == 0 {
        return false;
    }
    let data_base = X86_RUNTIME.ELF_PROBE_DATA.load(Ordering::SeqCst);
    let data_size = X86_RUNTIME.ELF_PROBE_DATA_SIZE.load(Ordering::SeqCst);
    let protected_page = X86_RUNTIME
        .ELF_PROBE_READ_ONLY_DATA_PAGE
        .load(Ordering::SeqCst);
    let tls_base = X86_RUNTIME.ELF_PROBE_TLS.load(Ordering::SeqCst);
    let tls_size = X86_RUNTIME.ELF_PROBE_TLS_SIZE.load(Ordering::SeqCst);
    let stack_base = X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1);
    let mmap_base = X86_RUNTIME.ELF_PROBE_MMAP.load(Ordering::SeqCst);
    let brk = X86_RUNTIME.ELF_PROBE_BRK.load(Ordering::SeqCst);
    let heap_base = X86_RUNTIME
        .ELF_PROBE_BRK_LIMIT
        .load(Ordering::SeqCst)
        .saturating_sub(PAGE_SIZE as u64);
    let mut current = address;
    while current < target {
        let mut next = current;
        if writable {
            if let Some(data_end) = linux_user_area_end(data_base, data_size, current) {
                let protected_end = protected_page.checked_add(PAGE_SIZE as u64);
                if protected_page == 0
                    || current < protected_page
                    || protected_end.is_some_and(|end| current >= end)
                {
                    next = next.max(if protected_page != 0 && current < protected_page {
                        data_end.min(protected_page)
                    } else {
                        data_end
                    });
                }
            }
        } else {
            extend_linux_user_area(&mut next, data_base, data_size, current);
            extend_linux_user_area(
                &mut next,
                X86_RUNTIME.ELF_PROBE_CODE_BASE.load(Ordering::SeqCst),
                X86_RUNTIME.ELF_PROBE_CODE_SIZE.load(Ordering::SeqCst),
                current,
            );
            extend_linux_user_area(
                &mut next,
                X86_RUNTIME
                    .ELF_PROBE_LOADER_CODE_BASE
                    .load(Ordering::SeqCst),
                X86_RUNTIME
                    .ELF_PROBE_LOADER_CODE_SIZE
                    .load(Ordering::SeqCst),
                current,
            );
        }
        extend_linux_user_area(&mut next, tls_base, tls_size, current);
        extend_linux_user_area(&mut next, stack_base, PAGE_SIZE as u64, current);
        for index in 0..LINUX_RUNTIME_MMAP_SLOT_COUNT {
            let pages = X86_RUNTIME.ELF_PROBE_MMAP_PAGES[index].load(Ordering::SeqCst);
            let protection =
                u64::from(X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[index].load(Ordering::SeqCst));
            let required = if writable {
                LINUX_PROT_WRITE
            } else {
                LINUX_PROT_READ
            };
            if pages != 0 && protection & required != 0 {
                extend_linux_user_area(
                    &mut next,
                    mmap_base + (index * PAGE_SIZE) as u64,
                    u64::from(pages) * PAGE_SIZE as u64,
                    current,
                );
            }
        }
        extend_linux_user_area(&mut next, heap_base, brk.saturating_sub(heap_base), current);
        if next == current {
            return false;
        }
        current = next.min(target);
    }
    true
}

pub(super) fn materialize_linux_runtime_user_range(
    address: u64,
    length: usize,
    writable: bool,
) -> bool {
    let Some(end) = address.checked_add(length as u64) else {
        return false;
    };
    if length == 0 || address >= 1 << 47 || end > 1 << 47 {
        return false;
    }
    let first = address & !(PAGE_SIZE as u64 - 1);
    let last = (end - 1) & !(PAGE_SIZE as u64 - 1);
    // Reclaim for the pages brought in may page out the process's other
    // pages, not these.
    let _reclaim =
        linux_swapon::LinuxUserFaultReclaim::enter_pinning(first, last + PAGE_SIZE as u64);
    let mut page_address = first;
    loop {
        if address_space::current_linux_runtime_page(page_address).secret {
            return false;
        }
        if writable
            && address_space::current_linux_cow_page(page_address).is_some()
            && !materialize_linux_cow_address(page_address)
        {
            return false;
        }
        if address_space::current_linux_range_mapped(page_address, PAGE_SIZE, writable) {
            if page_address == last {
                return true;
            }
            let Some(next) = page_address.checked_add(PAGE_SIZE as u64) else {
                return false;
            };
            page_address = next;
            continue;
        }
        let mut page = address_space::current_linux_runtime_page(page_address);
        // The main stack grows into a page the program has not touched for
        // a read as for a write (a write(2) from a large, untouched stack
        // buffer: memfd_create01), as a fault there would grow it.
        if !page.occupied && materialize_linux_primary_stack_page(page_address) {
            page = address_space::current_linux_runtime_page(page_address);
        }
        let required = if writable {
            LINUX_PROT_WRITE
        } else {
            LINUX_PROT_READ
        } as u8;
        // The kernel writing into a page of a writable and executable area
        // that is executable now flips it, as a user write would.
        if page.occupied
            && page.protection & required == 0
            && linux_write_execute_area(page_address)
            && linux_runtime_mprotect(
                page_address,
                PAGE_SIZE as u64,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
            ) == 0
        {
            page = address_space::current_linux_runtime_page(page_address);
        }
        // The kernel writing into a volume's page that waits for its
        // blocks allocates them, as a user write would.
        if writable && page.occupied && linux_volume_page_mkwrite_at(page_address) {
            page = address_space::current_linux_runtime_page(page_address);
        }
        if !page.occupied || page.protection & required == 0 {
            return false;
        }
        if page.frame.is_some() {
            if page_address == last {
                return true;
            }
            let Some(next) = page_address.checked_add(PAGE_SIZE as u64) else {
                return false;
            };
            page_address = next;
            continue;
        }
        if page.frame.is_none()
            && ((page_address >= LINUX_FIXED_LOW_BASE
                && page_address < linux_runtime_mmap_end().unwrap_or(0))
                || linux_runtime_heap_contains(page_address)
                || linux_runtime_primary_stack_contains(page_address))
        {
            if page.file {
                if !linux_refill_shared_file_page(page_address) {
                    return false;
                }
                if page_address == last {
                    return true;
                }
                page_address += PAGE_SIZE as u64;
                continue;
            }
            if linux_runtime_primary_stack_contains(page_address) {
                record_linux_primary_stack_growth(page_address);
            }
            let Some([frame]) = memory::allocate_user_frames::<1>() else {
                return false;
            };
            if !address_space::prepare_linux_frame(frame.address(), &[])
                || !address_space::materialize_current_linux_runtime_page(
                    page_address,
                    frame,
                    page.protection,
                    false,
                )
            {
                let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
                return false;
            }
        } else {
            return false;
        }
        if page_address == last {
            return true;
        }
        let Some(next) = page_address.checked_add(PAGE_SIZE as u64) else {
            return false;
        };
        page_address = next;
    }
}

fn materialize_linux_primary_stack_page(page_address: u64) -> bool {
    let low = X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst);
    let floor = linux_primary_stack_floor();
    let end = (X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1))
        .saturating_add(PAGE_SIZE as u64);
    if low == 0
        || page_address < floor
        || page_address >= end
        || page_address < low && linux_stack_guard_gap_taken(page_address)
    {
        return false;
    }
    let reserved = address_space::current_linux_runtime_page(page_address);
    if reserved.occupied
        && (reserved.frame.is_some()
            || reserved.file
            || reserved.protection & LINUX_PROT_WRITE as u8 == 0)
    {
        return false;
    }
    let Some([frame]) = memory::allocate_user_frames::<1>() else {
        return false;
    };
    if !address_space::prepare_linux_frame(frame.address(), &[])
        || address_space::install_current_linux_runtime_page(
            page_address,
            frame,
            LINUX_PROT_READ as u8 | LINUX_PROT_WRITE as u8,
            false,
            reserved.occupied,
        ) != Some(None)
    {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        return false;
    }
    record_linux_primary_stack_growth(page_address);
    true
}

pub(super) fn linux_runtime_primary_stack_contains(page_address: u64) -> bool {
    let floor = linux_primary_stack_floor();
    let end = (X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1))
        .saturating_add(PAGE_SIZE as u64);
    page_address >= floor && page_address < end
}

fn record_linux_primary_stack_growth(page_address: u64) {
    if page_address < X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst) {
        X86_RUNTIME
            .ELF_PROBE_STACK_LOW
            .store(page_address, Ordering::SeqCst);
    }
    if let Some(slot) = current_linux_thread_slot() {
        let end = (X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1))
            .saturating_add(PAGE_SIZE as u64);
        let low = X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].store(low, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].store(end.saturating_sub(low), Ordering::SeqCst);
    }
}

pub(super) fn copy_from_linux_user(address: u64, output: &mut [u8]) -> bool {
    if !linux_readable_user_range_contains(address, output.len()) {
        return false;
    }
    unsafe { raw_copy_from_user(output.as_mut_ptr(), address as *const u8, output.len()) == 0 }
}

pub(super) fn hardware_user_range_is_zero(address: u64, length: usize) -> bool {
    let mut bytes = [0_u8; 128];
    let mut offset = 0_usize;
    while offset < length {
        let count = core::cmp::min(bytes.len(), length - offset);
        if unsafe {
            raw_copy_from_user(
                bytes.as_mut_ptr(),
                (address + offset as u64) as *const u8,
                count,
            ) != 0
        } || bytes[..count].iter().any(|byte| *byte != 0)
        {
            return false;
        }
        offset += count;
    }
    true
}

pub(super) fn copy_linux_c_string(address: u64, output: &mut [u8]) -> Result<usize, u64> {
    for index in 0..output.len() {
        let Some(source) = address.checked_add(index as u64) else {
            return Err(LINUX_EFAULT);
        };
        if !copy_from_linux_user(source, &mut output[index..=index]) {
            return Err(LINUX_EFAULT);
        }
        if output[index] == 0 {
            return Ok(index);
        }
    }
    Err(LINUX_ENAMETOOLONG)
}

pub(super) fn copy_to_linux_user(address: u64, input: &[u8]) -> bool {
    if !linux_writable_user_range_contains(address, input.len())
        || !materialize_linux_cow_range(address, input.len())
    {
        return false;
    }
    unsafe { raw_copy_to_user(address as *mut u8, input.as_ptr(), input.len()) == 0 }
}

pub(super) fn handle_user_fault(frame: *mut UserFaultFrame) -> u64 {
    let _kernel_entry = crate::sync::kernel_entry_lock();
    // A refusal recorded before this fault is not this fault's.
    let _ = memory::take_user_frames_refused();
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX;
    };
    let fault_domain = scheduler::current_domain();
    let failure_policy = fault_domain.and_then(domain::service_failure_policy);
    let service_fault = failure_policy == Some(domain::ServiceFailurePolicy::RestartManaged);
    let fault_address = if frame.is_page_fault() {
        let address: u64;
        unsafe {
            asm!("mov {}, cr2", out(reg) address, options(nomem, nostack, preserves_flags));
        }
        address
    } else {
        0
    };
    let fault_metadata = frame.metadata(fault_address);
    let linux_page_fault = fault_domain.is_none()
        && frame.is_page_fault()
        && X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst);
    if linux_page_fault {
        crate::cpu_time::note(crate::cpu_time::TaskEvent::PageFault);
    }
    let resolved = |fault| {
        if linux_page_fault {
            crate::cpu_time::note(fault);
        }
        0
    };
    use crate::cpu_time::TaskEvent::{MajorFault, MinorFault};
    if fault_domain.is_none()
        && X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst)
        && refresh_linux_runtime_translation(fault_metadata)
    {
        return resolved(MinorFault);
    }
    // A page a userfaultfd context resolves: the thread waits for it.
    if fault_domain.is_none()
        && X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst)
        && linux_userfault(frame, fault_metadata)
    {
        return 0;
    }
    // Reclaim for the pages this fault allocates may page out the faulting
    // process's own pages.
    let reclaim = linux_swapon::LinuxUserFaultReclaim::enter();
    if fault_domain.is_none() && materialize_linux_cow_page(fault_metadata) {
        return resolved(MinorFault);
    }
    // A sibling thread on another CPU may have resolved this page's
    // copy-on-write (or otherwise made it writable) between the hardware
    // trap and now, having flushed only its own CPU's translation: the
    // page is writable again but this CPU still faults on a stale entry.
    // Flush it and let the instruction run again instead of killing the
    // process over a write the mapping now allows.
    if fault_domain.is_none() && linux_retry_resolved_write_fault(fault_metadata) {
        return resolved(MinorFault);
    }
    if fault_domain.is_none()
        && X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst)
        && (materialize_linux_runtime_mapping(fault_metadata)
            || materialize_linux_runtime_stack_page(fault_metadata)
            || grow_linux_runtime_stack(fault_metadata)
            || grow_linux_growsdown_area(fault_metadata)
            || linux_flip_write_execute_page(fault_metadata)
            || linux_volume_page_mkwrite(fault_metadata))
    {
        // A shared file page read back from its file is a major fault.
        let major = LINUX_FAULT_READ_FILE.swap(false, Ordering::Relaxed);
        return resolved(if major { MajorFault } else { MinorFault });
    }
    drop(reclaim);
    if fault_domain.is_some() && failure_policy.is_none() {
        serial_write("linox: unexpected control fault vector/rip: ");
        serial_write_u64(fault_metadata.vector);
        serial_write(" ");
        serial_write_u64(fault_metadata.instruction);
        serial_write("\r\n");
    }
    // The page was the process's to touch but no memory was left for it.
    if fault_domain.is_none()
        && X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst)
        && memory::take_user_frames_refused()
    {
        if linux_light_thread_here().is_some() {
            serial_write("linox: out of memory in a thread of process ");
            serial_write_u64(u64::from(current_linux_process_pid()));
            serial_write("\r\n");
            return fault_linux_light_thread(frame, fault_metadata, LINUX_SIGKILL);
        }
        if terminate_linux_process_out_of_memory() {
            return u64::MAX;
        }
    }
    // int3 and a debug trap raise SIGTRAP, which stops a traced process
    // for its tracer rather than ending it.
    if fault_domain.is_none()
        && X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst)
        && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && (fault_metadata.vector == 1 || linux_user_breakpoint(frame, fault_metadata))
    {
        if linux_light_thread_here().is_some() {
            return fault_linux_light_thread(frame, fault_metadata, LINUX_SIGTRAP);
        }
        if trap_linux_user_to_signal_entry(frame) {
            return 0;
        }
    }
    if fault_domain.is_none() && X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst) {
        serial_write("linox: Linux user fault vector/error/address/rip:");
        serial_write_u64(fault_metadata.vector);
        serial_write(" ");
        serial_write_u64(fault_metadata.error);
        serial_write(" ");
        serial_write_u64(fault_metadata.address);
        serial_write(" ");
        serial_write_u64(fault_metadata.instruction);
        serial_write("\r\n");
        if fault_metadata.vector == 14 {
            let page = fault_metadata.address & !(PAGE_SIZE as u64 - 1);
            let runtime_page = address_space::current_linux_runtime_page(page);
            let process_mapping =
                linux_process::live_process_mapping(current_linux_process_pid(), page as usize);
            serial_write("linox: Linux fault pid/page/stack-low/stack-top/brk-limit/occupied/frame/file/protection/registry-frame/cow-frame: ");
            for value in [
                u64::from(current_linux_process_pid()),
                page,
                X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst),
                X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst),
                X86_RUNTIME.ELF_PROBE_BRK_LIMIT.load(Ordering::SeqCst),
                u64::from(runtime_page.occupied),
                u64::from(runtime_page.frame.is_some()),
                u64::from(runtime_page.file),
                u64::from(runtime_page.protection),
                process_mapping.map_or(0, |mapping| mapping.frame.address()),
                address_space::current_linux_cow_page(page).map_or(0, |frame| frame.address()),
            ] {
                serial_write_u64(value);
                serial_write(" ");
            }
            serial_write("\r\n");
            if let Some(mapping) = process_mapping {
                serial_write("linox: Linux fault registry writable/executable/shared/dontfork: ");
                for value in [
                    mapping.writable,
                    mapping.executable,
                    mapping.shared,
                    mapping.dontfork,
                ] {
                    serial_write_u64(u64::from(value));
                    serial_write(" ");
                }
                serial_write("\r\n");
            }
        }
        let context = frame.context();
        serial_write("linox: Linux fault tid/fs: ");
        serial_write_u64(current_linux_tid().map_or(0, u64::from));
        serial_write(" ");
        serial_write_u64(active_fs_base());
        serial_write("\r\n");
        let current_thread = current_linux_thread_handle();
        serial_write(
            "linox: Linux fault cpu/slot/generation/state/saved-rip/saved-rsp/saved-rcx/saved-r11: ",
        );
        for value in [
            current_linux_runtime_cpu_index() as u64,
            current_thread.map_or(u64::MAX, |handle| u64::from(handle.slot)),
            current_thread.map_or(0, |handle| u64::from(handle.generation)),
            current_thread.map_or(0, |handle| {
                u64::from(
                    X86_RUNTIME.LINUX_THREAD_STATES[usize::from(handle.slot)]
                        .load(Ordering::SeqCst),
                )
            }),
            current_thread.map_or(0, |handle| {
                X86_RUNTIME.LINUX_THREAD_RIPS[usize::from(handle.slot)].load(Ordering::SeqCst)
            }),
            current_thread.map_or(0, |handle| {
                X86_RUNTIME.LINUX_THREAD_RSPS[usize::from(handle.slot)].load(Ordering::SeqCst)
            }),
            current_thread.map_or(0, |handle| {
                X86_RUNTIME.LINUX_THREAD_RCXS[usize::from(handle.slot)].load(Ordering::SeqCst)
            }),
            current_thread.map_or(0, |handle| {
                X86_RUNTIME.LINUX_THREAD_R11S[usize::from(handle.slot)].load(Ordering::SeqCst)
            }),
        ] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
        let mut instruction = [0_u8; 16];
        if copy_from_linux_user(context.rip, &mut instruction) {
            serial_write("linox: Linux fault instruction bytes:");
            for byte in instruction {
                serial_write(" ");
                serial_write_u64(u64::from(byte));
            }
            serial_write("\r\n");
        }
        serial_write("linox: Linux user fault rax/rbx/rcx/rdx/rdi/rsi/rsp/rbp/r12/r13/r14/r15:");
        for value in [
            context.rax,
            context.rbx,
            context.rcx,
            context.rdx,
            context.rdi,
            context.rsi,
            context.rsp,
            context.rbp,
            context.r12,
            context.r13,
            context.r14,
            context.r15,
        ] {
            serial_write(" ");
            serial_write_u64(value);
        }
        serial_write("\r\n");
        serial_write("linox: Linux user fault r8/r9/r10/r11:");
        for value in [context.r8, context.r9, context.r10, context.r11] {
            serial_write(" ");
            serial_write_u64(value);
        }
        serial_write("\r\n");
        let mut return_address = [0_u8; size_of::<u64>()];
        if copy_from_linux_user(context.rsp, &mut return_address) {
            serial_write("linox: Linux user fault stack return address: ");
            serial_write_u64(u64::from_ne_bytes(return_address));
            serial_write("\r\n");
        }
        // Which thread ran with which TLS, and the faulting instruction, so
        // a fault can be disassembled from the log.
        serial_write("linox: Linux user fault pid/tid/slot/fs:");
        for value in [
            u64::from(current_linux_process_pid()),
            current_linux_tid().map_or(0, u64::from),
            u64::from(X86_RUNTIME.LINUX_CURRENT_THREAD_SLOT.load(Ordering::SeqCst)),
            active_fs_base(),
        ] {
            serial_write(" ");
            serial_write_u64(value);
        }
        let mut code = [0_u8; 16];
        if copy_from_linux_user(fault_metadata.instruction, &mut code) {
            serial_write(" code:");
            for byte in code {
                let digits = [
                    b"0123456789abcdef"[usize::from(byte >> 4)],
                    b"0123456789abcdef"[usize::from(byte & 15)],
                ];
                serial_write(" ");
                serial_write(core::str::from_utf8(&digits).unwrap_or("??"));
            }
        }
        serial_write("\r\n");
        write_linux_runtime_syscall_trace();
        if linux_light_thread_here().is_some() {
            return fault_linux_light_thread(
                frame,
                fault_metadata,
                linux_user_fault_signal(fault_metadata),
            );
        }
        if deliver_linux_fault_signal(
            frame,
            fault_metadata,
            linux_user_fault_signal(fault_metadata),
        ) {
            return 0;
        }
        if terminate_linux_process_for_fault(fault_metadata) {
            return u64::MAX;
        }
        abort_linux_signal();
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return u64::MAX;
    }
    let action = scheduler::fault_runtime(
        frame,
        fault_address,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        fault_domain.and_then(|dead_domain| {
            (failure_policy != Some(domain::ServiceFailurePolicy::StopOnly)).then_some(
                scheduler::WaitReason::IpcReceive {
                    object: 3,
                    service_side: !service_fault,
                    peer_domain: dead_domain,
                },
            )
        }),
    );
    let Some(fault_domain) = fault_domain else {
        return u64::MAX;
    };
    if matches!(action, RuntimeAction::Invalid) || !domain::detach_thread(fault_domain) {
        return u64::MAX;
    }
    if service_fault && !scrub_service_restart_stack() {
        return u64::MAX;
    }
    if service_fault
        && (!domain::record_service_fault(fault_domain, fault_metadata)
            || !ipc::retire_service(fault_domain)
            || !domain::retire_service(fault_domain))
    {
        return u64::MAX;
    }
    if service_fault {
        match setup_service_restart(fault_domain) {
            ServiceRestartSetup::Started => {}
            ServiceRestartSetup::Unavailable => return resume_action(action),
            ServiceRestartSetup::RollbackFailed => return u64::MAX,
        }
    }
    if failure_policy == Some(domain::ServiceFailurePolicy::StopOnly) {
        serial_write("linox: auxiliary user fault vector/error/address/rip: ");
        for value in [
            fault_metadata.vector,
            fault_metadata.error,
            fault_metadata.address,
            fault_metadata.instruction,
        ] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
        if !domain::begin_auxiliary_runtime_fault(fault_domain, fault_metadata) {
            serial_write("linox: auxiliary fault transition failed\r\n");
            return u64::MAX;
        }
        if !crate::packet::retire_egress_producer_if_bound(fault_domain) {
            serial_write("linox: auxiliary fault egress retirement failed\r\n");
            return u64::MAX;
        }
        if !address_space::quiesce_faulted_auxiliary_device(fault_domain) {
            serial_write("linox: auxiliary device quiesce failed vector/error/address/rip:");
            serial_write_u64(fault_metadata.vector);
            serial_write(" ");
            serial_write_u64(fault_metadata.error);
            serial_write(" ");
            serial_write_u64(fault_metadata.address);
            serial_write(" ");
            serial_write_u64(fault_metadata.instruction);
            serial_write("\r\n");
            return u64::MAX;
        }
        if !address_space::activate_kernel_root_for_auxiliary(fault_domain) {
            serial_write("linox: auxiliary kernel-root restoration failed\r\n");
            return u64::MAX;
        }
        if !address_space::release_auxiliary_address_space(fault_domain) {
            serial_write("linox: auxiliary address-space release failed\r\n");
            return u64::MAX;
        }
        if !domain::retire_stopped_auxiliary_service(fault_domain) {
            serial_write("linox: auxiliary retirement failed\r\n");
            return u64::MAX;
        }
    }
    resume_action(action)
}

fn refresh_linux_runtime_translation(fault: domain::FaultMetadata) -> bool {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || fault.vector != 14
        || fault.error & 1 != 0
        || fault.address >= 1 << 47
    {
        return false;
    }
    address_space::refresh_current_linux_runtime_translation(
        fault.address & !(PAGE_SIZE as u64 - 1),
        fault.error & 2 != 0,
        fault.error & 16 != 0,
    )
}

fn materialize_linux_runtime_stack_page(fault: domain::FaultMetadata) -> bool {
    fault.vector == 14
        && fault.error & 1 == 0
        && fault.address < 1 << 47
        && materialize_linux_primary_stack_page(fault.address & !(PAGE_SIZE as u64 - 1))
}

fn grow_linux_runtime_stack(fault: domain::FaultMetadata) -> bool {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || fault.vector != 14
        || fault.error & 1 != 0
        || fault.address >= 1 << 47
    {
        return false;
    }
    let page = fault.address & !(PAGE_SIZE as u64 - 1);
    let low = X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst);
    let floor = linux_primary_stack_floor();
    let end = (X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1))
        .saturating_add(PAGE_SIZE as u64);
    if low == 0 || page < floor || page >= low || page >= end || linux_stack_guard_gap_taken(page) {
        return false;
    }
    let reserved = address_space::current_linux_runtime_page(page);
    if reserved.occupied
        && (reserved.frame.is_some()
            || reserved.file
            || reserved.protection & LINUX_PROT_WRITE as u8 == 0)
    {
        return false;
    }
    let Some([frame]) = memory::allocate_user_frames::<1>() else {
        return false;
    };
    if !address_space::prepare_linux_frame(frame.address(), &[])
        || address_space::install_current_linux_runtime_page(
            page,
            frame,
            LINUX_PROT_READ as u8 | LINUX_PROT_WRITE as u8,
            false,
            reserved.occupied,
        ) != Some(None)
    {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        return false;
    }
    X86_RUNTIME
        .ELF_PROBE_STACK_LOW
        .store(page, Ordering::SeqCst);
    if let Some(slot) = current_linux_thread_slot() {
        let end = (X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1))
            .saturating_add(PAGE_SIZE as u64);
        X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].store(page, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot]
            .store(end.saturating_sub(page), Ordering::SeqCst);
    }
    true
}

/// Linux's stack guard gap: a mapping that grows down stops this far
/// above the mapping below it (256 pages).
const LINUX_STACK_GUARD_GAP: u64 = 256 * PAGE_SIZE as u64;

/// Where an exec'd program's main stack ends: near the top of the user
/// address space, as on Linux, far above the mmap area and every region
/// the kernel places, so it can grow down to RLIMIT_STACK.
pub(super) const LINUX_STACK_END: u64 = 0x7fff_ffff_f000;
/// How far a stack with RLIMIT_STACK unlimited may grow (64 GiB).
const LINUX_STACK_UNLIMITED: u64 = 1 << 36;
/// RLIMIT_STACK's soft limit by default, as Linux's _STK_LIM (8 MiB).
pub(super) const LINUX_STACK_DEFAULT_LIMIT: u64 = 8 << 20;

/// The lowest page the current process's main stack may grow to. A stack at
/// the top of the address space (`LINUX_STACK_END`, every exec'd program's)
/// may span RLIMIT_STACK's soft limit from its end, as Linux's
/// acct_stack_growth allows, with the limit as it is when the stack grows;
/// the domain's first process keeps its stack above its heap, which bounds
/// it.
fn linux_primary_stack_floor() -> u64 {
    let end = (X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1))
        .saturating_add(PAGE_SIZE as u64);
    if end != LINUX_STACK_END {
        return X86_RUNTIME
            .ELF_PROBE_BRK_LIMIT
            .load(Ordering::SeqCst)
            .saturating_add(PAGE_SIZE as u64);
    }
    let limit = linux_resource_limit_values(LINUX_RLIMIT_STACK, true)
        .map_or(LINUX_STACK_DEFAULT_LIMIT, |values| values[0]);
    let size = if limit == u64::MAX {
        LINUX_STACK_UNLIMITED
    } else {
        limit.min(LINUX_STACK_UNLIMITED)
    };
    end.saturating_sub(size)
        .checked_next_multiple_of(PAGE_SIZE as u64)
        .unwrap_or(end)
}

/// Whether the main stack growing down to `page` would come within the
/// stack guard gap of a mapping below it (Linux's stack_guard_gap): the
/// growth is refused then, and the access is SIGSEGV. A stack the domain's
/// first process keeps above its heap has no mappings below to keep from.
fn linux_stack_guard_gap_taken(page: u64) -> bool {
    let end = (X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1))
        .saturating_add(PAGE_SIZE as u64);
    end == LINUX_STACK_END
        && crate::sync::rank_available(crate::sync::LockRank::MEMORY_AREAS)
        && crate::linux_areas::overlaps(
            linux_execution_instance(),
            current_linux_process_pid(),
            page.saturating_sub(LINUX_STACK_GUARD_GAP),
            LINUX_STACK_GUARD_GAP.min(page),
        )
}

/// Moves process `pid`'s main stack (the active address space's) to the top
/// of the address space for exec, if it is not there: the pages it grew
/// into are freed and its top page moves to just below `LINUX_STACK_END`,
/// which exec then fills. False if the move failed.
pub(super) fn linux_relocate_primary_stack(pid: u32) -> bool {
    let target = LINUX_STACK_END - PAGE_SIZE as u64;
    let stack = X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst);
    let page = stack & !(PAGE_SIZE as u64 - 1);
    if page == target {
        return true;
    }
    let low = X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst);
    if low == 0 || low > page {
        return false;
    }
    for address in (low..page).step_by(PAGE_SIZE) {
        let removed = address_space::remove_current_linux_runtime_page(address);
        if !removed.occupied {
            continue;
        }
        let _ = linux_process::remove_live_process_mapping(pid, address as usize);
        if let Some(frame) = removed.frame.filter(|_| !removed.shared) {
            if memory::frame_leases_releasable(memory::FrameOwner::KERNEL, &[frame])
                && !address_space::release_linux_private_page(frame)
            {
                return false;
            }
        }
    }
    if !address_space::move_current_linux_runtime_page(page, target)
        || !linux_process::move_live_process_mapping(pid, page as usize, target as usize)
    {
        return false;
    }
    X86_RUNTIME
        .ELF_PROBE_STACK
        .store(target | (stack & (PAGE_SIZE as u64 - 1)), Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_STACK_LOW
        .store(target, Ordering::SeqCst);
    true
}

/// A fault just below a mapping made with MAP_GROWSDOWN grows it down to
/// the faulting page (`linux_areas::grow_down`); the pages it gains are
/// reserved, and the access, run again, makes the one it touches. A
/// thread whose stack the mapping is gets the larger stack.
fn grow_linux_growsdown_area(fault: domain::FaultMetadata) -> bool {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || fault.vector != 14
        || fault.error & 1 != 0
        || fault.address < LINUX_FIXED_LOW_BASE
        || fault.address >= 1 << 47
        || !crate::sync::rank_available(crate::sync::LockRank::MEMORY_AREAS)
    {
        return false;
    }
    let page = fault.address & !(PAGE_SIZE as u64 - 1);
    if address_space::current_linux_runtime_page(page).occupied {
        return false;
    }
    let Some((old_start, protection)) = crate::linux_areas::grow_down(
        linux_execution_instance(),
        current_linux_process_pid(),
        page,
        LINUX_STACK_GUARD_GAP,
    ) else {
        return false;
    };
    let protection = linux_runtime_page_protection(u64::from(protection.bits())) as u8;
    for address in (page..old_start).step_by(PAGE_SIZE) {
        if !address_space::current_linux_runtime_page(address).occupied
            && address_space::reserve_current_linux_runtime_page(address, protection, false, false)
                .is_none()
        {
            return false;
        }
    }
    if let Some(slot) = current_linux_thread_slot() {
        if X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].load(Ordering::SeqCst) == old_start {
            X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].store(page, Ordering::SeqCst);
            X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot]
                .fetch_add(old_start - page, Ordering::SeqCst);
        }
    }
    true
}

/// Whether user fault `fault` is a breakpoint, int3 (or `int 3`), and if
/// so moves `frame` past it, where Linux reports the trap. Only INT 0x80
/// is a user gate here, so a user int3 reaches the kernel as a general
/// protection fault on IDT entry 3, at the instruction.
fn linux_user_breakpoint(frame: &mut UserFaultFrame, fault: domain::FaultMetadata) -> bool {
    /// A #GP error code naming IDT entry 3.
    const IDT_BREAKPOINT_ERROR: u64 = 3 << 3 | 2;
    if fault.vector == 3 {
        return true;
    }
    if fault.vector != 13 || fault.error != IDT_BREAKPOINT_ERROR {
        return false;
    }
    let mut first = [0_u8; 1];
    let mut second = [0_u8; 1];
    let length = match copy_from_linux_user(fault.instruction, &mut first).then_some(first[0]) {
        Some(0xcc) => 1,
        Some(0xcd)
            if copy_from_linux_user(fault.instruction.wrapping_add(1), &mut second)
                && second[0] == 3 =>
        {
            2
        }
        _ => return false,
    };
    frame.redirect(
        fault.instruction.wrapping_add(length),
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
    )
}

/// A user int3 or debug trap on the owner's path: SIGTRAP is queued for
/// the process and the thread goes to the vDSO's preemption entry, whose
/// system call delivers it with the trapping context (rip past the int3),
/// as a timer-delivered signal is: a traced process stops there for its
/// tracer, another runs its handler or ends. False when the signal cannot
/// be delivered that way (a handler is running), for the caller to end the
/// process as before.
fn trap_linux_user_to_signal_entry(frame: &mut UserFaultFrame) -> bool {
    let Some(entry) = crate::linux_elf::vdso_preempt_entry() else {
        return false;
    };
    if X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    let pid = current_linux_process_pid();
    let context = frame.context();
    if (entry..entry + 9).contains(&context.rip)
        || linux_queue_process_signal(pid, LINUX_SIGTRAP, LINUX_SI_KERNEL, None) != 0
        || !frame.redirect(entry, USER_CODE_SELECTOR, USER_DATA_SELECTOR)
    {
        return false;
    }
    *LINUX_PREEMPTED_CONTEXT[linux_cpu_slot()].lock() = Some(LinuxPreemptedContext {
        pid,
        general: [
            context.rax,
            context.rbx,
            context.rcx,
            context.rdx,
            context.rsi,
            context.rdi,
            context.rbp,
            context.r8,
            context.r9,
            context.r10,
            context.r11,
            context.r12,
            context.r13,
            context.r14,
            context.r15,
        ],
        rip: context.rip,
        rsp: context.rsp,
        rflags: context.rflags,
        signal: true,
    });
    true
}

fn materialize_linux_cow_page(fault: domain::FaultMetadata) -> bool {
    if fault.vector != 14 || fault.error & 3 != 3 || fault.address >= 1 << 47 {
        return false;
    }
    materialize_linux_cow_address(fault.address & !(PAGE_SIZE as u64 - 1))
}

/// A present-page write fault that the current mapping now allows: another
/// CPU made the page writable (it resolved the copy-on-write while this
/// thread was trapping) and invalidated only its own translation. This CPU
/// still holds a stale read-only entry, so flush it and retry rather than
/// treat the write as a protection violation. Returns false when the page
/// is genuinely not writable, leaving a real fault to be reported.
fn linux_retry_resolved_write_fault(fault: domain::FaultMetadata) -> bool {
    if fault.vector != 14 || fault.error & 3 != 3 || fault.address >= 1 << 47 {
        return false;
    }
    let page = fault.address & !(PAGE_SIZE as u64 - 1);
    if !address_space::current_linux_range_mapped(page, 1, true) {
        return false;
    }
    unsafe {
        asm!("invlpg [{}]", in(reg) page, options(nostack, preserves_flags));
    }
    true
}

pub(super) extern "sysv64" fn kernel_linux_cow_fault_handler(error: u64, address: u64) -> u64 {
    let page = address & !(PAGE_SIZE as u64 - 1);
    let eligible = error & 3 == 3 && address < 1 << 47;
    let cow = eligible && address_space::current_linux_cow_page(page).is_some();
    let materialized = cow && materialize_linux_cow_address(page);
    if eligible && !materialized {
        serial_write("linox: kernel Linux COW recovery failed address/cow/pid: ");
        serial_write_u64(address);
        serial_write(" ");
        serial_write_u64(u64::from(cow));
        serial_write(" ");
        serial_write_u64(u64::from(current_linux_process_pid()));
        serial_write("\r\n");
    }
    u64::from(materialized)
}

fn materialize_linux_cow_range(address: u64, length: usize) -> bool {
    let Some(end) = address.checked_add(length as u64) else {
        return false;
    };
    if length == 0 || address >= 1 << 47 || end > 1 << 47 {
        return false;
    }
    let mut page = address & !(PAGE_SIZE as u64 - 1);
    let last = (end - 1) & !(PAGE_SIZE as u64 - 1);
    loop {
        if address_space::current_linux_cow_page(page).is_some()
            && !materialize_linux_cow_address(page)
        {
            return false;
        }
        if page == last {
            return true;
        }
        page += PAGE_SIZE as u64;
    }
}

pub(super) fn materialize_linux_cow_address(address: u64) -> bool {
    let Some(source) = address_space::current_linux_cow_page(address) else {
        return false;
    };
    let pid = current_linux_process_pid();
    let failed = |step: u64| {
        serial_write("linox: copy-on-write fault failed address/pid/step: ");
        for value in [address, u64::from(pid), step] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
        false
    };
    let Some(mapping) = linux_process::live_process_mapping(pid, address as usize)
        .filter(|mapping| mapping.frame == source && mapping.writable && !mapping.shared)
    else {
        return failed(1);
    };
    // The last mapping of a page writes it in place, as Linux reuses a page
    // whose map count has dropped to one.
    if address_space::linux_private_page_counted(source) && !memory::frame_is_shared(source) {
        return address_space::promote_current_linux_cow_page(address, source, mapping.executable)
            || failed(2);
    }
    let Some([replacement]) = memory::allocate_user_frames::<1>() else {
        return failed(3);
    };
    let copied = address_space::copy_linux_frame(source, replacement);
    let mapping_replaced = copied
        && linux_process::replace_live_process_mapping(
            pid,
            address as usize,
            source,
            replacement,
            true,
            mapping.executable,
        );
    let page_replaced = mapping_replaced
        && address_space::replace_current_linux_cow_page(
            address,
            source,
            replacement,
            mapping.executable,
        );
    if !page_replaced {
        if mapping_replaced {
            let _ = linux_process::replace_live_process_mapping(
                pid,
                address as usize,
                replacement,
                source,
                true,
                mapping.executable,
            );
        }
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[replacement]);
        return failed(4 + u64::from(copied) + u64::from(mapping_replaced));
    }
    address_space::release_linux_private_page(source) || failed(7)
}

/// The fault `materialize_linux_runtime_mapping` just resolved read its
/// page from its file (a major fault, as perf counts it); faults are
/// handled under the kernel entry lock, one at a time.
static LINUX_FAULT_READ_FILE: AtomicBool = AtomicBool::new(false);

fn materialize_linux_runtime_mapping(fault: domain::FaultMetadata) -> bool {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || fault.vector != 14
        || fault.error & 1 != 0
        || !((fault.address >= LINUX_FIXED_LOW_BASE
            && fault.address < linux_runtime_mmap_end().unwrap_or(0))
            || linux_runtime_heap_contains(fault.address))
    {
        return false;
    }
    let page_address = fault.address & !(PAGE_SIZE as u64 - 1);
    if linux_refill_shared_file_page(page_address) {
        LINUX_FAULT_READ_FILE.store(true, Ordering::Relaxed);
        return true;
    }
    let page = address_space::current_linux_runtime_page(page_address);
    if !page.occupied
        || page.frame.is_some()
        || page.file
        || page.protection == 0
        || fault.error & 2 != 0 && page.protection & LINUX_PROT_WRITE as u8 == 0
        || fault.error & 16 != 0 && page.protection & LINUX_PROT_EXEC as u8 == 0
    {
        return false;
    }
    let Some([frame]) = memory::allocate_user_frames::<1>() else {
        return false;
    };
    if !address_space::prepare_linux_frame(frame.address(), &[])
        || !address_space::materialize_current_linux_runtime_page(
            page_address,
            frame,
            page.protection,
            false,
        )
    {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        return false;
    }
    true
}
