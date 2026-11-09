use super::*;

fn append_linux_process_snapshot_mapping(
    mappings: &mut [LinuxActiveImageMapping],
    count: &mut usize,
    mapping: LinuxActiveImageMapping,
) -> bool {
    if *count >= mappings.len()
        || mapping.address == 0
        || !mapping.address.is_multiple_of(PAGE_SIZE)
        || mapping.writable && mapping.executable
        || !(memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
            || memory::frame_lease_is_runtime(mapping.frame))
        || mappings[..*count].iter().any(|prior| {
            prior.address == mapping.address
                || prior.frame == mapping.frame && !(mapping.shared && prior.shared)
        })
        || !address_space::current_linux_mapping_matches(
            mapping.address as u64,
            mapping.frame,
            mapping.writable,
            mapping.executable,
        )
    {
        return false;
    }
    mappings[*count] = mapping;
    *count += 1;
    true
}

pub(super) fn live_runtime_linux_process_address_space_snapshot(
) -> Option<&'static LinuxProcessAddressSpaceSnapshot> {
    crate::linux_profile::span(
        crate::linux_profile::Span::Snapshot,
        take_runtime_linux_process_address_space_snapshot,
    )
}

fn take_runtime_linux_process_address_space_snapshot(
) -> Option<&'static LinuxProcessAddressSpaceSnapshot> {
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(1, Ordering::SeqCst);
    if !X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst)
        || current_linux_thread_handle().is_none()
    {
        return None;
    }
    let root_address = address_space::current_root_address();
    let root =
        memory::live_frame_lease(memory::FrameOwner::KERNEL, root_address).or_else(|| {
            memory::FrameLease::from_parts(root_address, 1)
                .filter(|frame| memory::frame_lease_is_runtime(*frame))
        })?;
    let snapshot = unsafe { &mut *X86_RUNTIME.LINUX_PROCESS_SNAPSHOT_SCRATCH.0 .0.get() };
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(8, Ordering::SeqCst);
    // Walk into lists sized for the last snapshot; when one fills, grow it
    // and walk again, so a process may map as much as there is memory for.
    let mut grow = (false, false);
    loop {
        if !snapshot.reset(grow) {
            serial_write("linox: runtime snapshot out of memory hierarchy/mappings: ");
            serial_write_u64(snapshot.hierarchy.len() as u64);
            serial_write(" ");
            serial_write_u64(snapshot.mappings.len() as u64);
            serial_write("\r\n");
            return None;
        }
        snapshot.hierarchy[0] = root;
        snapshot.hierarchy_count = 1;
        match address_space::complete_current_linux_process_snapshot(
            &mut snapshot.hierarchy,
            &mut snapshot.hierarchy_count,
            &mut snapshot.mappings,
            &mut snapshot.mapping_count,
        ) {
            address_space::SnapshotWalk::Complete => break,
            address_space::SnapshotWalk::Full => {
                grow = (
                    snapshot.hierarchy_count == snapshot.hierarchy.len(),
                    snapshot.mapping_count == snapshot.mappings.len(),
                );
            }
            address_space::SnapshotWalk::Invalid => {
                serial_write("linox: runtime snapshot walk rejected hierarchy/mappings: ");
                serial_write_u64(snapshot.hierarchy_count as u64);
                serial_write(" ");
                serial_write_u64(snapshot.mapping_count as u64);
                serial_write("\r\n");
                return None;
            }
        }
    }
    // The kernel just produced this snapshot by walking the active page
    // tables in monotonically increasing virtual-address order. Repeating the
    // adversarial slice validator here made every fork quadratic in the
    // number of resident pages. Keep the full validator for imported/test
    // snapshots and validate the trusted walk in one linear pass.
    let valid = snapshot.is_valid_runtime_walk();
    if !valid {
        serial_write("linox: runtime snapshot invalid hierarchy/mappings: ");
        serial_write_u64(snapshot.hierarchy_count as u64);
        serial_write(" ");
        serial_write_u64(snapshot.mapping_count as u64);
        if let Some((index, prior)) = snapshot.mappings[..snapshot.mapping_count]
            .iter()
            .enumerate()
            .find_map(|(index, mapping)| {
                snapshot.mappings[..index]
                    .iter()
                    .position(|candidate| {
                        candidate.address == mapping.address || candidate.frame == mapping.frame
                    })
                    .map(|prior| (index, prior))
            })
        {
            serial_write(" duplicate/index/prior ");
            serial_write_u64(index as u64);
            serial_write(" ");
            serial_write_u64(prior as u64);
        }
        serial_write("\r\n");
    }
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(if valid { 9 } else { 8 }, Ordering::SeqCst);
    valid.then_some(snapshot)
}

pub(crate) fn live_linux_process_address_space_snapshot(
) -> Option<&'static LinuxProcessAddressSpaceSnapshot> {
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(1, Ordering::SeqCst);
    if !X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst)
        || current_linux_thread_handle().is_none()
    {
        return None;
    }
    let snapshot = unsafe { &mut *X86_RUNTIME.LINUX_PROCESS_SNAPSHOT_SCRATCH.0 .0.get() };
    // The processes this path records are small: the lists' least lengths
    // hold them.
    if !snapshot.reset((false, false)) {
        return None;
    }
    let hierarchy = &mut snapshot.hierarchy;
    let mappings = &mut snapshot.mappings;
    let mut hierarchy_count = 0;
    let mut hierarchy_ended = false;
    for ((target, frame), generation) in hierarchy
        .iter_mut()
        .zip(X86_RUNTIME.ELF_PROBE_PAGE_TABLE_FRAMES.iter())
        .zip(X86_RUNTIME.ELF_PROBE_PAGE_TABLE_GENERATIONS.iter())
    {
        let address = frame.load(Ordering::SeqCst);
        let generation = generation.load(Ordering::SeqCst);
        match memory::FrameLease::from_parts(address, generation) {
            Some(frame) if !hierarchy_ended => {
                *target = frame;
                hierarchy_count += 1;
            }
            None if address == 0 && generation == 0 => hierarchy_ended = true,
            _ => return None,
        }
    }
    if !(5..=6).contains(&hierarchy_count)
        || hierarchy[0].address() != address_space::current_root_address()
    {
        if cfg!(feature = "verification-boot") {
            serial_write("linox: snapshot hierarchy count/root/current ");
            serial_write_u64(hierarchy_count as u64);
            serial_write(" ");
            serial_write_u64(hierarchy[0].address());
            serial_write(" ");
            serial_write_u64(address_space::current_root_address());
            serial_write("\r\n");
        }
        return None;
    }
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(2, Ordering::SeqCst);

    let (active, active_count) = linux_active_image_mappings()?;
    let mut mapping_count = 0;
    for (index, mapping) in active[..active_count].iter().copied().enumerate() {
        X86_RUNTIME
            .LINUX_PROCESS_SNAPSHOT_STAGE
            .store(30 + index as u8, Ordering::SeqCst);
        if !append_linux_process_snapshot_mapping(mappings, &mut mapping_count, mapping) {
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                serial_write("linox: snapshot rejected active mapping ");
                serial_write_u64(index as u64);
                serial_write(" address/frame/flags ");
                serial_write_u64(mapping.address as u64);
                serial_write(" ");
                serial_write_u64(mapping.frame.address());
                serial_write(" ");
                serial_write_u64(
                    u64::from(mapping.writable) | (u64::from(mapping.executable) << 1),
                );
                serial_write(" current ");
                serial_write_u64(
                    address_space::current_linux_mapping_frame_address(mapping.address as u64)
                        .unwrap_or(0),
                );
                serial_write("\r\n");
            }
            return None;
        }
    }
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(3, Ordering::SeqCst);

    let stack_address = usize::try_from(
        X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1),
    )
    .ok()?;
    let stack_frame = memory::FrameLease::from_parts(
        X86_RUNTIME.ELF_PROBE_STACK_FRAME.load(Ordering::SeqCst),
        X86_RUNTIME
            .ELF_PROBE_STACK_GENERATION
            .load(Ordering::SeqCst),
    )?;
    if !append_linux_process_snapshot_mapping(
        mappings,
        &mut mapping_count,
        LinuxActiveImageMapping {
            address: stack_address,
            frame: stack_frame,
            writable: true,
            executable: false,
            shared: false,
            dontfork: false,
        },
    ) {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            serial_write("linox: snapshot rejected stack address/frame/current/count ");
            serial_write_u64(stack_address as u64);
            serial_write(" ");
            serial_write_u64(stack_frame.address());
            serial_write(" ");
            serial_write_u64(
                address_space::current_linux_mapping_frame_address(stack_address as u64)
                    .unwrap_or(0),
            );
            serial_write(" ");
            serial_write_u64(mapping_count as u64);
            serial_write("\r\n");
        }
        return None;
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let stack_low =
            usize::try_from(X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst)).ok()?;
        if stack_low == 0 || stack_low > stack_address || !stack_low.is_multiple_of(PAGE_SIZE) {
            return None;
        }
        let stack_pages = (stack_address - stack_low) / PAGE_SIZE + 1;
        for page in 1..stack_pages {
            let address = stack_address.checked_sub(page * PAGE_SIZE)?;
            // A deep stack's pages need not all have been touched.
            let Some(frame_address) =
                address_space::current_linux_mapping_frame_address(address as u64)
            else {
                continue;
            };
            let frame = memory::live_frame_lease(memory::FrameOwner::KERNEL, frame_address)
                .or_else(|| {
                    memory::FrameLease::from_parts(frame_address, 1)
                        .filter(|frame| memory::frame_lease_is_runtime(*frame))
                })?;
            if !append_linux_process_snapshot_mapping(
                mappings,
                &mut mapping_count,
                LinuxActiveImageMapping {
                    address,
                    frame,
                    writable: true,
                    executable: false,
                    shared: false,
                    dontfork: false,
                },
            ) {
                return None;
            }
        }
    }
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(4, Ordering::SeqCst);

    let heap_address = usize::try_from(
        X86_RUNTIME
            .ELF_PROBE_BRK_LIMIT
            .load(Ordering::SeqCst)
            .checked_sub(
                (if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                    LINUX_RUNTIME_HEAP_PAGES
                } else {
                    1
                } * PAGE_SIZE) as u64,
            )?,
    )
    .ok()?;
    let heap_frame = memory::FrameLease::from_parts(
        X86_RUNTIME.ELF_PROBE_HEAP_FRAME.load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_HEAP_GENERATION.load(Ordering::SeqCst),
    )?;
    if !append_linux_process_snapshot_mapping(
        mappings,
        &mut mapping_count,
        LinuxActiveImageMapping {
            address: heap_address,
            frame: heap_frame,
            writable: true,
            executable: false,
            shared: false,
            dontfork: false,
        },
    ) {
        return None;
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        for page in 1..LINUX_RUNTIME_HEAP_PAGES {
            let address = heap_address.checked_add(page * PAGE_SIZE)?;
            let frame_address = address_space::current_linux_mapping_frame_address(address as u64)?;
            let frame = memory::live_frame_lease(memory::FrameOwner::KERNEL, frame_address)
                .or_else(|| {
                    memory::FrameLease::from_parts(frame_address, 1)
                        .filter(|frame| memory::frame_lease_is_runtime(*frame))
                })?;
            if !append_linux_process_snapshot_mapping(
                mappings,
                &mut mapping_count,
                LinuxActiveImageMapping {
                    address,
                    frame,
                    writable: true,
                    executable: false,
                    shared: false,
                    dontfork: false,
                },
            ) {
                return None;
            }
        }
    }
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(5, Ordering::SeqCst);

    let tls_addresses = [
        X86_RUNTIME.ELF_PROBE_TLS.load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_SIBLING_TLS.load(Ordering::SeqCst),
    ];
    for (index, address) in tls_addresses.into_iter().enumerate() {
        let frame_address = X86_RUNTIME.ELF_PROBE_TLS_FRAMES[index].load(Ordering::SeqCst);
        let generation = X86_RUNTIME.ELF_PROBE_TLS_GENERATIONS[index].load(Ordering::SeqCst);
        if address == 0 {
            if frame_address != 0 || generation != 0 {
                return None;
            }
            continue;
        }
        let page_address = usize::try_from(address & !(PAGE_SIZE as u64 - 1)).ok()?;
        if frame_address == 0 && generation == 0 {
            if mappings[..mapping_count]
                .iter()
                .any(|mapping| mapping.address == page_address)
            {
                continue;
            }
            return None;
        }
        let Some(frame) = memory::FrameLease::from_parts(frame_address, generation) else {
            serial_write("linox: snapshot missing TLS lease address/frame/generation/index ");
            serial_write_u64(address);
            serial_write(" ");
            serial_write_u64(frame_address);
            serial_write(" ");
            serial_write_u64(u64::from(generation));
            serial_write(" ");
            serial_write_u64(index as u64);
            serial_write("\r\n");
            return None;
        };
        if !append_linux_process_snapshot_mapping(
            mappings,
            &mut mapping_count,
            LinuxActiveImageMapping {
                address: page_address,
                frame,
                writable: true,
                executable: false,
                shared: false,
                dontfork: false,
            },
        ) {
            serial_write("linox: snapshot rejected TLS address/frame/current/index ");
            serial_write_u64(address);
            serial_write(" ");
            serial_write_u64(frame.address());
            serial_write(" ");
            serial_write_u64(
                address_space::current_linux_mapping_frame_address(
                    address & !(PAGE_SIZE as u64 - 1),
                )
                .unwrap_or(0),
            );
            serial_write(" ");
            serial_write_u64(index as u64);
            serial_write("\r\n");
            return None;
        }
    }
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(6, Ordering::SeqCst);

    let sibling_stack = X86_RUNTIME.ELF_PROBE_SIBLING_STACK.load(Ordering::SeqCst);
    let sibling_stack_frame = X86_RUNTIME
        .ELF_PROBE_SIBLING_STACK_FRAME
        .load(Ordering::SeqCst);
    let sibling_stack_generation = X86_RUNTIME
        .ELF_PROBE_SIBLING_STACK_GENERATION
        .load(Ordering::SeqCst);
    if sibling_stack == 0 {
        if sibling_stack_frame != 0 || sibling_stack_generation != 0 {
            return None;
        }
    } else if !append_linux_process_snapshot_mapping(
        mappings,
        &mut mapping_count,
        LinuxActiveImageMapping {
            address: usize::try_from(sibling_stack).ok()?,
            frame: memory::FrameLease::from_parts(sibling_stack_frame, sibling_stack_generation)?,
            writable: true,
            executable: false,
            shared: false,
            dontfork: false,
        },
    ) {
        return None;
    }
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(7, Ordering::SeqCst);

    let mmap_base = X86_RUNTIME.ELF_PROBE_MMAP.load(Ordering::SeqCst);
    for (slot, generation_cell) in X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS.iter().enumerate() {
        let area = linux_mmap_slot_area_index(slot);
        let frame_address = linux_mmap_slot_frame(slot);
        let generation = generation_cell.load(Ordering::SeqCst);
        let Some(area) = area else {
            if frame_address != 0 || generation != 0 {
                return None;
            }
            continue;
        };
        let protection =
            u64::from(X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[area].load(Ordering::SeqCst));
        let address = mmap_base.checked_add((slot * PAGE_SIZE) as u64)?;
        if protection == 0 {
            if frame_address != 0
                || generation != 0
                || !address_space::current_linux_page_absent(address)
            {
                return None;
            }
            continue;
        }
        if protection & !(LINUX_PROT_READ | LINUX_PROT_WRITE) != 0
            || !append_linux_process_snapshot_mapping(
                mappings,
                &mut mapping_count,
                LinuxActiveImageMapping {
                    address: usize::try_from(address).ok()?,
                    frame: memory::FrameLease::from_parts(frame_address, generation)?,
                    writable: protection & LINUX_PROT_WRITE != 0,
                    executable: false,
                    shared: false,
                    dontfork: false,
                },
            )
        {
            return None;
        }
    }
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(8, Ordering::SeqCst);

    if address_space::complete_current_linux_process_snapshot(
        hierarchy,
        &mut hierarchy_count,
        mappings,
        &mut mapping_count,
    ) != address_space::SnapshotWalk::Complete
    {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            serial_write("linox: runtime snapshot hierarchy/mappings before rejection: ");
            serial_write_u64(hierarchy_count as u64);
            serial_write(" ");
            serial_write_u64(mapping_count as u64);
            serial_write("\r\n");
        }
        return None;
    }

    snapshot.hierarchy_count = hierarchy_count;
    snapshot.mapping_count = mapping_count;
    let valid = snapshot.is_valid();
    if !valid {
        serial_write("linox: Linux process snapshot expected/observed hierarchy/leaves ");
        serial_write_u64(snapshot.hierarchy_count as u64);
        serial_write(" ");
        serial_write_u64(snapshot.mapping_count as u64);
        if let Some((hierarchy, leaves)) =
            address_space::current_linux_process_user_tree_counts(snapshot.hierarchy())
        {
            serial_write(" ");
            serial_write_u64(hierarchy as u64);
            serial_write(" ");
            serial_write_u64(leaves as u64);
        }
        serial_write("\r\n");
    }
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_STAGE
        .store(if valid { 9 } else { 8 }, Ordering::SeqCst);
    valid.then_some(snapshot)
}

#[inline(never)]
fn record_nonruntime_linux_process_snapshot() -> bool {
    live_linux_process_address_space_snapshot()
        .is_some_and(verify_live_linux_process_snapshot_contract)
}

pub(super) fn record_live_linux_process_snapshot() -> bool {
    let valid = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        live_runtime_linux_process_address_space_snapshot()
            .is_some_and(LinuxProcessAddressSpaceSnapshot::is_valid_runtime_walk)
    } else {
        record_nonruntime_linux_process_snapshot()
    };
    if !valid {
        serial_write("linox: Linux process snapshot failed at stage ");
        serial_write_u64(u64::from(
            X86_RUNTIME
                .LINUX_PROCESS_SNAPSHOT_STAGE
                .load(Ordering::SeqCst),
        ));
        serial_write("\r\n");
    }
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_VALIDATED
        .store(valid, Ordering::SeqCst);
    valid
}

#[inline(never)]
fn refresh_nonruntime_linux_process_registry(context: LinuxUserContext) -> bool {
    // A private page may have been materialized after fork by either a user
    // write fault or a kernel copy-to-user operation.  The process table is
    // authoritative for those COW replacements; refresh the legacy execution
    // cache before using it to construct the verification snapshot.
    if !sync_live_linux_process_address_space(current_linux_process_pid()) {
        serial_write("linox: live registry refresh address-space sync failed\r\n");
        return false;
    }
    let Some(snapshot) = live_linux_process_address_space_snapshot() else {
        serial_write("linox: live registry refresh snapshot failed at stage ");
        serial_write_u64(u64::from(
            X86_RUNTIME
                .LINUX_PROCESS_SNAPSHOT_STAGE
                .load(Ordering::SeqCst),
        ));
        serial_write("\r\n");
        return false;
    };
    linux_process::refresh_live_process_registry(
        current_linux_process_pid(),
        snapshot,
        context
            .registers
            .process_general(context.rax, context.rip, context.rflags),
        context.rip,
        context.rsp,
        context.rflags,
        context.fs_base,
    )
}

/// Records where a process waits, for the waits that let others run (a
/// yield, a parked blocking call): its execution context, without a
/// page-by-page snapshot of what it maps. A snapshot
/// walks every mapped page and checks each against the frame allocator,
/// which for a large process (a GPU application maps hundreds of thousands
/// of pages) cost milliseconds on every wait. The registry's mapping list is
/// marked stale instead, so the process's release frees what its live page
/// tables map; fork, exec and exit still take a full snapshot.
pub(super) fn refresh_linux_process_registry_for_wait(context: LinuxUserContext) -> bool {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return refresh_live_linux_process_registry(context);
    }
    // The page-table root does not change outside exec, and a stale
    // registry is released through the live tables, so neither its mapping
    // list nor its table list is walked here.
    let pid = current_linux_process_pid();
    let light = linux_process::refresh_live_process_context_for_wait(
        pid,
        context
            .registers
            .process_general(context.rax, context.rip, context.rflags),
        context.rip,
        context.rsp,
        context.rflags,
        context.fs_base,
    );
    light || refresh_live_linux_process_registry(context)
}

pub(super) fn refresh_live_linux_process_registry(context: LinuxUserContext) -> bool {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let Some(snapshot) = live_runtime_linux_process_address_space_snapshot() else {
            serial_write("linox: live registry refresh snapshot failed at stage ");
            serial_write_u64(u64::from(
                X86_RUNTIME
                    .LINUX_PROCESS_SNAPSHOT_STAGE
                    .load(Ordering::SeqCst),
            ));
            serial_write("\r\n");
            return false;
        };
        let refreshed = linux_process::refresh_validated_runtime_process_registry(
            current_linux_process_pid(),
            snapshot,
            context
                .registers
                .process_general(context.rax, context.rip, context.rflags),
            context.rip,
            context.rsp,
            context.rflags,
            context.fs_base,
        );
        return refreshed;
    }
    refresh_nonruntime_linux_process_registry(context)
}

#[inline(never)]
fn install_nonruntime_linux_process_registry(entry: usize, stack: usize, fs_base: u64) -> bool {
    let Some(snapshot) = live_linux_process_address_space_snapshot() else {
        serial_write("linox: live process registry install snapshot failed at stage ");
        serial_write_u64(u64::from(
            X86_RUNTIME
                .LINUX_PROCESS_SNAPSHOT_STAGE
                .load(Ordering::SeqCst),
        ));
        serial_write("\r\n");
        return false;
    };
    let installed = linux_process::install_live_process_registry(
        snapshot,
        [0; 15],
        entry as u64,
        stack as u64,
        0x202,
        fs_base,
    );
    if !installed {
        serial_write("linox: live process registry install rejected snapshot\r\n");
    }
    installed
}

pub(super) fn install_live_linux_process_registry(
    entry: usize,
    stack: usize,
    fs_base: u64,
) -> bool {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let Some(snapshot) = live_runtime_linux_process_address_space_snapshot() else {
            serial_write("linox: live process registry install snapshot failed at stage ");
            serial_write_u64(u64::from(
                X86_RUNTIME
                    .LINUX_PROCESS_SNAPSHOT_STAGE
                    .load(Ordering::SeqCst),
            ));
            serial_write("\r\n");
            return false;
        };
        return linux_process::install_live_process_registry(
            snapshot,
            [0; 15],
            entry as u64,
            stack as u64,
            0x202,
            fs_base,
        );
    }
    install_nonruntime_linux_process_registry(entry, stack, fs_base)
}

pub(super) fn sync_live_linux_process_address_space(pid: u32) -> bool {
    // The registry holds what the process mapped at its last snapshot; a
    // page mapped since (an interpreted program's image, mapped after the
    // registry was installed at the interpreter's entry) is read from the
    // live tables of the running process.
    let lookup = |address: usize| {
        linux_process::live_process_mapping(pid, address).or_else(|| {
            (pid == current_linux_process_pid())
                .then(|| address_space::current_linux_active_mapping(address as u64))
                .flatten()
        })
    };
    for index in 0..X86_RUNTIME.ELF_PROBE_PAGE_TABLE_FRAMES.len() {
        let Some(frame) = linux_process::live_process_hierarchy_frame(pid, index) else {
            if index < 5 {
                serial_write("linox: process address-space sync missing hierarchy frame\r\n");
                return false;
            }
            X86_RUNTIME.ELF_PROBE_PAGE_TABLE_FRAMES[index].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_PAGE_TABLE_GENERATIONS[index].store(0, Ordering::SeqCst);
            continue;
        };
        X86_RUNTIME.ELF_PROBE_PAGE_TABLE_FRAMES[index].store(frame.address(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PAGE_TABLE_GENERATIONS[index]
            .store(frame.generation(), Ordering::SeqCst);
    }
    let active_count = usize::from(
        X86_RUNTIME
            .ELF_PROBE_ACTIVE_IMAGE_COUNT
            .load(Ordering::SeqCst),
    );
    for index in 0..active_count {
        let address =
            X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[index].load(Ordering::SeqCst) as usize;
        let Some(mapping) = lookup(address) else {
            serial_write("linox: process address-space sync missing image mapping ");
            serial_write_u64(index as u64);
            serial_write("\r\n");
            return false;
        };
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index]
            .store(mapping.frame.address(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index]
            .store(mapping.frame.generation(), Ordering::SeqCst);
        // What the page allows, as this process mapped it: exec writes
        // these for the program it loads, so another process's exec must
        // not decide them.
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].store(
            u8::from(mapping.writable) | (u8::from(mapping.executable) << 1),
            Ordering::SeqCst,
        );
    }
    for index in 0..LINUX_EXEC_MAPPING_LIMIT {
        let address =
            X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_ADDRESSES[index].load(Ordering::SeqCst) as usize;
        if address == 0 {
            continue;
        }
        let Some(mapping) = lookup(address) else {
            serial_write("linox: process address-space sync missing exec mapping ");
            serial_write_u64(index as u64);
            serial_write("\r\n");
            return false;
        };
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_FRAMES[index]
            .store(mapping.frame.address(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_GENERATIONS[index]
            .store(mapping.frame.generation(), Ordering::SeqCst);
    }
    let stack_address =
        (X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) as usize) & !(PAGE_SIZE - 1);
    let heap_address = X86_RUNTIME.ELF_PROBE_BRK_LIMIT.load(Ordering::SeqCst) as usize
        - if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            LINUX_RUNTIME_HEAP_PAGES * PAGE_SIZE
        } else {
            PAGE_SIZE
        };
    let (Some(stack), Some(heap)) = (lookup(stack_address), lookup(heap_address)) else {
        serial_write("linox: process address-space sync missing stack or heap mapping\r\n");
        return false;
    };
    X86_RUNTIME
        .ELF_PROBE_STACK_FRAME
        .store(stack.frame.address(), Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_STACK_GENERATION
        .store(stack.frame.generation(), Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_HEAP_FRAME
        .store(heap.frame.address(), Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_HEAP_GENERATION
        .store(heap.frame.generation(), Ordering::SeqCst);
    true
}

/// The parent of a runtime fork that could not be carried out goes on with
/// `error` as the fork's result: the scheduler loop that ran it enters it
/// again.
fn resume_failed_linux_fork_parent(parent_pid: u32, error: u64) -> bool {
    linux_process::set_live_process_return_value(parent_pid, error)
        && restore_linux_process_extended_state(parent_pid)
}

/// Finishes a runtime fork, run parent first as Linux runs it: keeps the
/// child's prepared state for when a scheduler loop takes it from the run
/// queue, and makes the parent's state current again, with the child's pid
/// as its fork's result (written by `begin_live_fork`), for the loop that
/// ran it to go on with it. A vfork parent instead waits in its call until
/// the child executes or exits (`linux_vfork_wait_live`), as Linux's does;
/// a domain exec's child is first loaded with the command it runs. Kept out
/// of line so the process-state copies it makes do not enlarge the fork
/// executor's frame.
#[inline(never)]
fn finish_linux_fork_parent_first(
    parent_pid: u32,
    child: &linux_process::LiveProcessDispatch,
    parent_stack: Option<(usize, u64, u64)>,
    vfork: bool,
    domain_exec: bool,
) -> bool {
    if domain_exec && !load_linux_domain_exec(child) {
        return false;
    }
    save_current_linux_process_runtime_state(child.pid);
    if domain_exec && !save_linux_process_extended_state(child.pid) {
        return false;
    }
    X86_RUNTIME
        .LINUX_CURRENT_PROCESS_PID
        .store(parent_pid, Ordering::SeqCst);
    if !restore_saved_linux_process_runtime_state(parent_pid)
        || !restore_linux_process_extended_state(parent_pid)
    {
        return false;
    }
    if let Some((slot, base, size)) = parent_stack {
        X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].store(base, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].store(size, Ordering::SeqCst);
    }
    !vfork
        || linux_process::set_live_process_vfork_child(parent_pid, child.pid)
            && linux_process::restart_live_process_call(parent_pid, LINUX_VFORK_WAIT_SYSCALL)
}

/// Loads a domain exec's command (`domain exec NAME PATH`) into `child`,
/// the fork of the suspended process made for it, whose state is current,
/// with the domain's console as its standard streams; it becomes the
/// domain's exec child, whose exit detaches the console again.
fn load_linux_domain_exec(child: &linux_process::LiveProcessDispatch) -> bool {
    let Some(slot) = active_container_slot() else {
        return false;
    };
    let argument_size =
        usize::from(X86_RUNTIME.CONTAINER_EXEC_ARGUMENT_SIZES[slot][0].load(Ordering::Acquire));
    let mut path = [0_u8; DOMAIN_EXEC_ARGUMENT_CAPACITY];
    for (byte, cell) in path[..argument_size]
        .iter_mut()
        .zip(X86_RUNTIME.CONTAINER_EXEC_ARGUMENTS[slot][0].iter())
    {
        *byte = cell.load(Ordering::Acquire);
    }
    let prepared = sync_live_linux_process_address_space(child.pid)
        && restore_linux_process_extended_state(child.pid)
        && prepare_domain_exec_stdio();
    let loaded = prepared
        && address_space::with_live_linux_process_root(child.root, || {
            linux_rootfs_execve_domain(&path[..argument_size], slot)
        }) == Some(0);
    if !loaded {
        serial_write("linox: domain exec load failed\r\n");
        return false;
    }
    X86_RUNTIME.CONTAINER_EXEC_CHILD[slot].store(child.pid, Ordering::Release);
    true
}

#[inline(never)]
pub(super) fn execute_deferred_live_fork() -> bool {
    if !X86_RUNTIME
        .LINUX_FORK_REQUESTED
        .swap(false, Ordering::SeqCst)
    {
        return true;
    }
    // Fork execution is recursive: a child may fork before returning to its
    // parent. Preserve the outer transaction's vfork/CLONE_VM exec policy.
    let exec_flag_guard = LinuxForkExecFlagGuard::capture();
    let domain_exec = X86_RUNTIME
        .LINUX_DOMAIN_EXEC_INJECT
        .swap(false, Ordering::AcqRel);
    let profile_started = cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
    let new_mount_namespace = X86_RUNTIME
        .LINUX_FORK_NEW_MOUNT_NAMESPACE
        .swap(false, Ordering::SeqCst);
    let new_user_namespace = X86_RUNTIME
        .LINUX_FORK_NEW_USER_NAMESPACE
        .swap(false, Ordering::SeqCst);
    let parent_pid = current_linux_process_pid();
    // A clone's own requests (`linux_clone_process`): 0 for a plain fork.
    let clone_flags = X86_RUNTIME.LINUX_FORK_CLONE_FLAGS.swap(0, Ordering::SeqCst);
    let clone_tls = X86_RUNTIME.LINUX_FORK_TLS.swap(0, Ordering::SeqCst);
    let clear_tid_address = X86_RUNTIME
        .LINUX_FORK_CLEAR_TID_ADDRESS
        .swap(0, Ordering::SeqCst);
    let shares_descriptors = clone_flags & LINUX_CLONE_FILES != 0;
    let vfork = clone_flags & LINUX_CLONE_VFORK != 0;
    // The transaction switches back to the parent: no other CPU takes it.
    let _pin = LinuxProcessPin::new(parent_pid);
    let Some(parent_runtime) =
        stage_linux_fork_parent_runtime_state(parent_pid, shares_descriptors)
    else {
        return false;
    };
    if !save_linux_process_extended_state(parent_pid) {
        release_staged_linux_fork_descriptors(parent_pid, shares_descriptors);
        return false;
    }
    let child_stack = X86_RUNTIME.LINUX_FORK_CHILD_STACK.swap(0, Ordering::SeqCst);
    let share_vm = X86_RUNTIME
        .LINUX_FORK_SHARE_VM
        .swap(false, Ordering::SeqCst);
    let cgroup_generation = X86_RUNTIME
        .LINUX_FORK_CGROUP_GENERATION
        .swap(0, Ordering::SeqCst);
    // A child given its own stack (musl's posix_spawn, clone3 with a stack)
    // maps its parent's pages rather than copies of them even without
    // CLONE_VM: it only runs until exec or exit, and exec frees none of
    // them. Only a CLONE_VM child releases its parent at exec.
    // A runtime's forks run the parent first, as Linux does: the child waits
    // in the run queue for a scheduler loop, and a vfork parent waits in its
    // call for the child to execute or exit. Only the boot verification
    // probe, which has no scheduler loop, runs the child first, inside this
    // transaction.
    let parent_first = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    // vfork shares the parent's memory, and so does posix_spawn's
    // clone(CLONE_VM | CLONE_VFORK, stack) child, which exec's from it; a
    // stack with pages of the child's own (clone(SIGCHLD, stack), clone3
    // with a stack) is a fork whose child starts on that stack (clone01).
    let own_pages = X86_RUNTIME
        .LINUX_FORK_OWN_PAGES
        .swap(false, Ordering::SeqCst);
    let begin_started = crate::linux_profile::span_start();
    let begun = linux_process::begin_live_fork(
        parent_pid,
        false,
        share_vm || child_stack != 0 && !own_pages,
        (child_stack != 0).then_some(child_stack),
        !parent_first,
    );
    crate::linux_profile::span_since(crate::linux_profile::Span::ForkBegin, begin_started);
    let prepare_started = crate::linux_profile::span_start();
    let Some(mut child) = begun else {
        release_staged_linux_fork_descriptors(parent_pid, shares_descriptors);
        X86_RUNTIME
            .LINUX_FORK_CHILD_TID_ADDRESS
            .store(0, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_PARENT_TID_ADDRESS
            .store(0, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_PIDFD_ADDRESS
            .store(0, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_CLEAR_SIGHAND
            .store(false, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_OWN_PAGES
            .store(false, Ordering::SeqCst);
        let _ = linux_process::set_live_process_child_namespaces(parent_pid, None);
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            serial_write("linox: runtime fork preparation failed at stage ");
            serial_write_u64(u64::from(linux_process::live_fork_execution_stage()));
            serial_write("\r\n");
            // Linux fails fork with EAGAIN when it runs out of processes or
            // memory; the parent carries on.
            return resume_failed_linux_fork_parent(parent_pid, LINUX_EAGAIN);
        }
        return false;
    };
    if !clone_linux_process_extended_state(parent_pid, child.pid) {
        return false;
    }
    if clone_flags & LINUX_FORK_CLONE_REQUESTED != 0
        && !(linux_clone_shared_resources(clone_flags).all(|resource| {
            linux_process::share_live_process_resource(child.pid, resource, Some(parent_pid))
        }) && linux_process::set_live_process_exit_signal(child.pid, clone_flags as u8)
            && (clone_flags & LINUX_CLONE_PARENT == 0
                || linux_process::adopt_live_process_by_grandparent(child.pid)))
    {
        return false;
    }
    // The child's number in the parent's PID namespace, which fork returns
    // (begin_live_fork set it).
    let child_seen_by_parent = linux_pid_seen_by(parent_pid, child.pid);
    // A child in a time namespace reads its clocks through the system call,
    // which adds the namespace's offsets: its vDSO page says to fall back.
    if linux_process::live_process_namespaces(child.pid).is_some_and(|set| set.time != 0) {
        if let Some(vvar) =
            linux_process::live_process_mapping(child.pid, crate::linux_elf::VVAR_ADDRESS as usize)
        {
            let _ = address_space::update_linux_vvar(vvar.frame, [0; 6]);
        }
    }
    let pidfd_address = X86_RUNTIME
        .LINUX_FORK_PIDFD_ADDRESS
        .swap(0, Ordering::SeqCst);
    if new_user_namespace {
        let Some(parent_namespace) = linux_process::live_process_user_namespace(parent_pid) else {
            return false;
        };
        let Some(child_namespace) = linux_user::clone_namespace(parent_namespace) else {
            return false;
        };
        if !linux_process::set_live_process_user_namespace(child.pid, child_namespace) {
            let _ = linux_user::retire(child_namespace);
            return false;
        }
    }
    if pidfd_address != 0 {
        let pidfd = linux_pidfd_open(u64::from(child.pid), 0);
        if pidfd >= LINUX_RETURN_TO_KERNEL
            || !linux_process::write_live_process_u32(parent_pid, pidfd_address, pidfd as u32)
        {
            return false;
        }
        if !capture_linux_descriptors_for_process(parent_pid) {
            return false;
        }
    }
    let Some(child_process_slot) = linux_process::live_process_slot(child.pid) else {
        return false;
    };
    if !clear_linux_signal_queues_for_process(linux_signal_instance(), child_process_slot) {
        return false;
    }
    let Some(child_mount_namespace) =
        stage_linux_fork_child_runtime_state(parent_pid, child.pid, new_mount_namespace)
    else {
        return false;
    };
    if !crate::linux_overlay::clone_shared_mappings(parent_pid, child.pid) {
        return false;
    }
    crate::linux_areas::fork(linux_execution_instance(), parent_pid, child.pid);
    crate::linux_path_views::fork(linux_execution_instance(), parent_pid, child.pid);
    if !linux_landlock_fork(parent_pid, child.pid) {
        return false;
    }
    // The child shares the forking thread's session keyring; what an exited
    // process left under a reused id goes first.
    let _ = linux_with_keys(|keys, caller| {
        keys.exit_process(child.pid);
        keys.fork(caller, child.pid)
    });
    if !linux_assign_process_cgroup(child.pid, cgroup_generation) {
        return false;
    }
    let clear_sighand = X86_RUNTIME
        .LINUX_FORK_CLEAR_SIGHAND
        .swap(false, Ordering::SeqCst);
    if !linux_process::set_live_process_scheduler_nice(parent_pid, parent_runtime.nice)
        || !linux_process::set_live_process_scheduler_nice(child.pid, parent_runtime.nice)
    {
        return false;
    }
    if child.pid == 1 || child.general[0] != 0 {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            serial_write("linox: runtime fork produced invalid child pid/rax ");
            serial_write_u64(u64::from(child.pid));
            serial_write(" ");
            serial_write_u64(child.general[0]);
            serial_write("\r\n");
        }
        return false;
    }
    if cfg!(feature = "verification-boot")
        && !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && !X86_RUNTIME
            .LINUX_CROSS_PROCESS_PRLIMIT_VALIDATED
            .load(Ordering::SeqCst)
        && !verify_linux_running_child_wait_selectors(child.pid)
    {
        return false;
    }
    if !parent_first {
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXITED
            .store(false, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXECUTED
            .store(false, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_YIELDED
            .store(false, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXIT_PID
            .store(child.pid, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXEC_PID
            .store(child.pid, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_YIELD_PID
            .store(child.pid, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_RELEASE_PARENT_ON_EXEC
            .store(share_vm, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_STATUS
            .store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .LINUX_CURRENT_PROCESS_PID
        .store(child.pid, Ordering::SeqCst);
    if !restore_saved_linux_process_runtime_state(child.pid)
        || !linux_mount::switch_to(child_mount_namespace)
    {
        return false;
    }
    // CLONE_CHILD_CLEARTID: the child's exit clears and wakes the word;
    // CLONE_SETTLS: it starts with its own thread pointer.
    if clear_tid_address != 0 && !set_current_linux_clear_child_tid(clear_tid_address) {
        return false;
    }
    if clone_flags & LINUX_CLONE_SETTLS != 0 {
        let Some(slot) = current_linux_thread_slot() else {
            return false;
        };
        X86_RUNTIME.LINUX_THREAD_POINTERS[slot].store(clone_tls, Ordering::SeqCst);
        child.fs_base = clone_tls;
    }
    if clear_sighand {
        X86_RUNTIME
            .ELF_PROBE_SIGNAL_HANDLERS
            .iter()
            .for_each(|handler| handler.store(0, Ordering::SeqCst));
        X86_RUNTIME
            .ELF_PROBE_SIGNAL_FLAGS
            .iter()
            .for_each(|flags| flags.store(0, Ordering::SeqCst));
        X86_RUNTIME
            .ELF_PROBE_SIGNAL_RESTORERS
            .iter()
            .for_each(|restorer| restorer.store(0, Ordering::SeqCst));
        X86_RUNTIME
            .ELF_PROBE_SIGNAL_ACTION_MASKS
            .iter()
            .for_each(|mask| mask.store(0, Ordering::SeqCst));
    }
    if child_stack != 0 {
        // A child with pages of its own or sharing its parent's memory for
        // good (CLONE_VM without CLONE_VFORK) may use its whole stack
        // buffer; a vfork child (posix_spawn) exec's from the top page,
        // which is all that is registered for it, as before.
        let (base, size) = if own_pages || clone_flags & LINUX_CLONE_VM != 0 && !vfork {
            linux_clone_stack_extent(parent_pid, child_stack)
        } else {
            (
                (child_stack - 1) & !(PAGE_SIZE as u64 - 1),
                PAGE_SIZE as u64,
            )
        };
        if let Some(slot) = current_linux_thread_slot() {
            X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].store(base, Ordering::SeqCst);
            X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].store(size, Ordering::SeqCst);
        }
    }
    let child_tid_address = X86_RUNTIME
        .LINUX_FORK_CHILD_TID_ADDRESS
        .swap(0, Ordering::SeqCst);
    let parent_tid_address = X86_RUNTIME
        .LINUX_FORK_PARENT_TID_ADDRESS
        .swap(0, Ordering::SeqCst);
    let child_tid_ready = (child_tid_address == 0
        || linux_process::write_live_process_u32(
            child.pid,
            child_tid_address,
            linux_pid_seen_by(child.pid, child.pid),
        ))
        && (parent_tid_address == 0
            || linux_process::write_live_process_u32(
                parent_pid,
                parent_tid_address,
                child_seen_by_parent,
            ));
    if parent_first {
        return child_tid_ready
            && finish_linux_fork_parent_first(
                parent_pid,
                &child,
                parent_runtime.stack,
                vfork,
                domain_exec,
            );
    }
    linux_boot_profile_lifecycle_phase(0, profile_started);
    let profile_run_started = cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
    let mut child_executed = false;
    let mut child_resumed = child_tid_ready
        && (!X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
            || sync_live_linux_process_address_space(child.pid))
        && restore_linux_process_extended_state(child.pid)
        && {
            crate::linux_profile::span_since(
                crate::linux_profile::Span::ForkPrepare,
                prepare_started,
            );
            run_dispatched_linux_process(&child)
        };
    let finish_started = crate::linux_profile::span_start();
    while X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && !linux_child_exited(child.pid)
        && X86_RUNTIME.LINUX_FORK_REQUESTED.load(Ordering::SeqCst)
    {
        child_resumed = execute_deferred_live_fork();
    }
    while X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && !X86_RUNTIME
            .LINUX_PROCESS_RELEASE_PARENT_ON_EXEC
            .load(Ordering::SeqCst)
        && take_linux_child_exec(child.pid)
        && !linux_child_exited(child.pid)
    {
        child_executed = true;
        let Some(executed_child) = linux_process::dispatch_live_process(child.pid) else {
            return false;
        };
        child_resumed = run_dispatched_linux_process(&executed_child);
        while child_resumed
            && X86_RUNTIME.LINUX_FORK_REQUESTED.load(Ordering::SeqCst)
            && !linux_child_exited(child.pid)
        {
            child_resumed = execute_deferred_live_fork();
        }
        if !child_resumed {
            break;
        }
    }
    child_executed |= take_linux_child_exec(child.pid);
    let child_yielded = take_linux_child_yield(child.pid);
    let child_exit = take_linux_child_exit(child.pid);
    let child_exited = child_exit.is_some();
    let child_status = child_exit.unwrap_or(0);
    linux_boot_profile_lifecycle_phase(1, profile_run_started);
    let profile_state_started = cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
    // The child's threads on other CPUs leave before this CPU leaves its
    // bank for the parent's: the save cannot tell the child exited, its
    // exit was taken just above, and threads left running would go on in
    // its memory once the exit below frees it.
    if child_exited {
        wait_for_linux_process_threads_to_leave(child.pid);
    }
    save_current_linux_process_runtime_state(child.pid);
    if !save_linux_process_extended_state(child.pid) {
        return false;
    }
    if !restore_saved_linux_process_runtime_state(parent_pid) {
        return false;
    }
    if !restore_linux_process_extended_state(parent_pid) {
        return false;
    }
    // A child that left its new mount namespace (exited) took it along.
    if new_mount_namespace && !child_executed {
        linux_release_mount_namespace(child_mount_namespace);
    }
    if let Some((slot, base, size)) = parent_runtime.stack {
        X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].store(base, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].store(size, Ordering::SeqCst);
    }
    linux_boot_profile_lifecycle_phase(2, profile_state_started);
    if (child_executed || child_yielded) && !child_exited {
        let Some(mut parent) = linux_process::resume_live_parent_after_child_exec(child.pid) else {
            return false;
        };
        // A vfork parent stays suspended until its child executes or exits,
        // waiting in its vfork as the call it re-issues in place of
        // returning from it (`linux_vfork_wait_live`).
        if vfork && !child_executed {
            if !linux_process::set_live_process_vfork_child(parent_pid, child.pid) {
                return false;
            }
            parent.rip = parent.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
            parent.general[0] = LINUX_VFORK_WAIT_SYSCALL;
        }
        // The child runs on its own now; the parent resumes here, inside
        // this transaction, and its own exec or exit goes to the outer one.
        exec_flag_guard.resume_parent();
        X86_RUNTIME
            .LINUX_CURRENT_PROCESS_PID
            .store(parent_pid, Ordering::SeqCst);
        crate::linux_profile::span_since(crate::linux_profile::Span::ForkFinish, finish_started);
        let parent_resumed = sync_live_linux_process_address_space(parent_pid)
            && run_dispatched_linux_process(&parent);
        if parent_resumed {
            save_current_linux_process_runtime_state(parent_pid);
        }
        return parent_resumed;
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && !(child_resumed && child_exited) {
        serial_write("linox: runtime child return resumed/exited/status ");
        serial_write_u64(u64::from(child_resumed));
        serial_write(" ");
        serial_write_u64(u64::from(child_exited));
        serial_write(" ");
        serial_write_u64(u64::from(child_status));
        serial_write("\r\n");
    }
    if child_resumed
        && child_exited
        && !clear_linux_signal_queues_for_process(linux_signal_instance(), child_process_slot)
    {
        return false;
    }
    let profile_retire_started =
        cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
    let parent = (child_resumed && child_exited)
        .then(|| {
            // Its parent, which a CLONE_PARENT child does not share with
            // the transaction.
            let parent = linux_process::live_process_parent_pid(child.pid)
                .filter(|parent| *parent != 0)
                .unwrap_or(parent_pid);
            linux_signal_child_exit(parent, child.pid, child_status)
                .then(|| linux_process::complete_live_child_exit(child.pid, child_status))
                .flatten()
        })
        .flatten();
    let Some(parent) = parent else {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            serial_write("linox: runtime child completion failed at stage ");
            serial_write_u64(u64::from(linux_process::live_fork_execution_stage()));
            serial_write("\r\n");
        }
        return false;
    };
    linux_boot_profile_lifecycle_phase(3, profile_retire_started);
    let profile_cleanup_started =
        cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
    X86_RUNTIME
        .LINUX_CURRENT_PROCESS_PID
        .store(parent_pid, Ordering::SeqCst);
    if cfg!(feature = "verification-boot")
        && !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && !X86_RUNTIME
            .LINUX_CROSS_PROCESS_PRLIMIT_VALIDATED
            .load(Ordering::SeqCst)
        && !verify_linux_cross_process_prlimit(child.pid)
    {
        return false;
    }
    linux_release_process_cgroup(child.pid);
    release_linux_process_shared_mappings(child.pid);
    release_linux_process_keys(child.pid);
    linux_fanotify_exit(child.pid);
    let mut left_namespace = None;
    if let Some(child_state_slot) = linux_process_runtime_state(child.pid) {
        release_linux_process_descriptors(child.pid, child_state_slot);
        left_namespace = child_state_slot.mount_namespace;
        *child_state_slot = LinuxProcessRuntimeState::EMPTY;
    }
    if let Some(namespace) = left_namespace {
        linux_release_mount_namespace(namespace);
    }
    if let Some(threads) = linux_process_thread_runtime_state(child.pid) {
        threads.fill(LinuxThreadRuntimeState::EMPTY);
    }
    discard_linux_process_extended_state(child.pid);
    if !release_linux_process_runtime_slot(child.pid) {
        return false;
    }
    wake_linux_descriptor_waits();
    linux_boot_profile_lifecycle_phase(4, profile_cleanup_started);
    if parent.pid != parent_pid || parent.general[0] != u64::from(child_seen_by_parent) {
        return false;
    }
    X86_RUNTIME
        .LIVE_FORK_PUBLIC_DIAGNOSTIC
        .store(0x20, Ordering::SeqCst);
    let profile_parent_started =
        cfg!(feature = "linux-boot-profile").then(timer::timestamp_counter);
    let parent_synced = sync_live_linux_process_address_space(parent_pid);
    // The parent resumes inside this transaction: its own exec or exit goes
    // to the outer one.
    exec_flag_guard.resume_parent();
    let parent_resumed = parent_synced && run_dispatched_linux_process(&parent);
    let parent_resumed = if parent_resumed
        && !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && X86_RUNTIME.ELF_PROBE_SYSTEM_INIT.load(Ordering::SeqCst)
    {
        resume_linux_system_supervisor()
    } else {
        parent_resumed
    };
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        if parent_resumed {
            save_current_linux_process_runtime_state(parent_pid);
        }
        linux_boot_profile_lifecycle_phase(5, profile_parent_started);
        return parent_resumed;
    }
    let wait_count = X86_RUNTIME.LINUX_PROCESS_WAIT_COUNT.load(Ordering::SeqCst);
    let valid = parent_resumed
        && child_status == LINUX_PROBE_EXIT_STATUS as u8
        && wait_count == 1
        && !X86_RUNTIME.LINUX_FORK_REQUESTED.load(Ordering::SeqCst);
    X86_RUNTIME.LIVE_FORK_PUBLIC_DIAGNOSTIC.store(
        u8::from(parent_resumed)
            | (u8::from(child_status == LINUX_PROBE_EXIT_STATUS as u8) << 1)
            | (u8::from(wait_count == 1) << 2)
            | (u8::from(X86_RUNTIME.ELF_PROBE_COMPLETED.load(Ordering::SeqCst)) << 3)
            | (u8::from(!X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst)) << 4),
        Ordering::SeqCst,
    );
    if valid {
        serial_write("linox: Linux PID 1 fork and wait4 lifecycle completed\r\n");
        serial_write("linox: Linux fork inherited user namespace\r\n");
    }
    valid
}

pub(super) fn linux_setpgid(pid: u64, process_group: u64) -> u64 {
    let pid = pid as i32;
    let process_group = process_group as i32;
    if pid < 0 || process_group < 0 {
        return LINUX_EINVAL;
    }
    let caller = current_linux_process_pid();
    let target = if pid == 0 { caller } else { pid as u32 };
    match linux_process::set_live_process_group(caller, target, process_group as u32) {
        Ok(()) => 0,
        Err(linux_process::ProcessGroupError::Access) => LINUX_EACCES,
        Err(linux_process::ProcessGroupError::NoSuchProcess) => LINUX_ESRCH,
        Err(linux_process::ProcessGroupError::Permission) => LINUX_EPERM,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn linux_request_process_fork(
    runtime_mode: bool,
    caller: LinuxUserContext,
    clone_flags: u64,
    child_stack: u64,
    share_vm: bool,
    pidfd_address: u64,
    cgroup_generation: u32,
    clear_sighand: bool,
    own_pages: bool,
) -> u64 {
    crate::linux_profile::span(crate::linux_profile::Span::ForkRequest, || {
        linux_request_process_fork_now(
            runtime_mode,
            caller,
            clone_flags,
            child_stack,
            share_vm,
            pidfd_address,
            cgroup_generation,
            clear_sighand,
            own_pages,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn linux_request_process_fork_now(
    runtime_mode: bool,
    caller: LinuxUserContext,
    clone_flags: u64,
    child_stack: u64,
    share_vm: bool,
    pidfd_address: u64,
    cgroup_generation: u32,
    clear_sighand: bool,
    own_pages: bool,
) -> u64 {
    // The child's new UTS, IPC, PID and time namespaces are made now, in
    // the caller, so a failure is the call's; the fork takes them.
    if clone_flags & LINUX_CLONE_NEW_KEPT != 0 {
        let Some(owner) = current_linux_user_namespace() else {
            return LINUX_ESRCH;
        };
        let namespaces = match linux_create_namespaces(
            current_linux_namespaces().for_child(),
            clone_flags,
            owner,
            true,
        ) {
            Ok(namespaces) => namespaces,
            Err(error) => return error,
        };
        if !linux_process::set_live_process_child_namespaces(
            current_linux_process_pid(),
            Some(namespaces),
        ) {
            return LINUX_ESRCH;
        }
    }
    // vfork/CLONE_VM inherits the already-owned address space. Updating only
    // the execution context avoids manufacturing a page-per-leaf snapshot for
    // a child that will share the parent's mappings until exec or exit.
    // A child sharing the parent's memory takes the parent's mapping list
    // as its own, so a list a wait left stale is snapshotted first.
    let refreshed = if share_vm
        && !linux_process::live_process_address_space_stale(current_linux_process_pid())
    {
        let snapshot = unsafe { &mut *X86_RUNTIME.LINUX_PROCESS_SNAPSHOT_SCRATCH.0 .0.get() };
        let mut grow = false;
        let hierarchy_count = loop {
            if !snapshot.reset((grow, false)) {
                break None;
            }
            match address_space::current_linux_process_hierarchy(&mut snapshot.hierarchy) {
                Ok(count) => break Some(count),
                Err(full) if full => grow = true,
                Err(_) => break None,
            }
        };
        let hierarchy_refreshed = hierarchy_count.is_some_and(|count| {
            linux_process::refresh_live_process_hierarchy(
                current_linux_process_pid(),
                &snapshot.hierarchy[..count],
            )
        });
        // `caller` is the hardware-captured context already accepted by the
        // syscall return path. It is authoritative even when the optional
        // process-registry mapping snapshot predates a newly mapped page.
        let context_refreshed = hierarchy_refreshed
            && linux_process::refresh_live_process_context_from_syscall_entry(
                current_linux_process_pid(),
                caller
                    .registers
                    .process_general(caller.rax, caller.rip, caller.rflags),
                caller.rip,
                caller.rsp,
                caller.rflags,
                caller.fs_base,
            );
        // posix_spawn's child stack is fresh mmap memory nothing has touched
        // yet: its top page is brought in first, so the child (on the
        // parent's pages) and the parent's list agree on it.
        let child_stack_refreshed = child_stack == 0
            || child_stack.checked_sub(1).is_some_and(|address| {
                materialize_linux_runtime_user_range(address, 1, true)
                    && linux_process::import_live_process_mapping_from_hardware(
                        current_linux_process_pid(),
                        address,
                    )
            });
        context_refreshed && child_stack_refreshed
    } else {
        refresh_live_linux_process_registry(caller)
    };
    // A runtime process may fork from any thread (rustc spawns its linker
    // from its compiler thread). The child's thread table keeps only the
    // calling thread, with tid == pid.
    let leader = current_linux_tid() == Some(current_linux_process_pid())
        || X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    let nproc_reached = linux_nproc_limit_reached();
    let requested = X86_RUNTIME
        .LINUX_FORK_REQUESTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    if !leader || !refreshed || nproc_reached || !requested {
        if requested {
            X86_RUNTIME
                .LINUX_FORK_REQUESTED
                .store(false, Ordering::SeqCst);
        }
        if runtime_mode {
            serial_write("linox: fork rejected leader/refreshed/nproc/requested/share-vm: ");
            for value in [leader, refreshed, nproc_reached, requested, share_vm] {
                serial_write_u64(u64::from(value));
                serial_write(" ");
            }
            serial_write("\r\n");
        }
        let _ = linux_process::set_live_process_child_namespaces(current_linux_process_pid(), None);
        LINUX_EAGAIN
    } else {
        X86_RUNTIME
            .LINUX_FORK_NEW_MOUNT_NAMESPACE
            .store(clone_flags & LINUX_CLONE_NEWNS != 0, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_NEW_USER_NAMESPACE
            .store(clone_flags & LINUX_CLONE_NEWUSER != 0, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_CHILD_STACK
            .store(child_stack, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_SHARE_VM
            .store(share_vm, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_PIDFD_ADDRESS
            .store(pidfd_address, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_CGROUP_GENERATION
            .store(cgroup_generation, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_CLEAR_SIGHAND
            .store(clear_sighand, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_FORK_OWN_PAGES
            .store(own_pages, Ordering::SeqCst);
        LINUX_RETURN_TO_KERNEL
    }
}

/// A clone that makes a process rather than a thread: clone or clone3
/// without CLONE_THREAD.
#[derive(Clone, Copy)]
pub(super) struct LinuxProcessClone {
    pub(super) flags: u64,
    /// The signal the parent gets when the child ends (0 for none).
    pub(super) exit_signal: u64,
    /// The top of the child's stack, or 0 for the parent's.
    pub(super) stack: u64,
    pub(super) parent_tid: u64,
    pub(super) child_tid: u64,
    pub(super) tls: u64,
    /// Where the parent gets a pidfd of the child (CLONE_PIDFD), or 0.
    pub(super) pidfd: u64,
    /// CLONE_INTO_CGROUP's cgroup, by generation, or 0.
    pub(super) cgroup_generation: u32,
}

const LINUX_CLONE_PTRACE: u64 = 0x0000_2000;
const LINUX_CLONE_PARENT: u64 = 0x0000_8000;
const LINUX_CLONE_UNTRACED: u64 = 0x0080_0000;
const LINUX_CLONE_IO: u64 = 0x8000_0000;

/// What a process clone may ask for: the namespaces this kernel has, what
/// it shares with its parent, where it starts and which tid words it sets.
/// CLONE_PTRACE and CLONE_UNTRACED only matter to a tracer, which a clone
/// here never has.
const LINUX_PROCESS_CLONE_FLAGS: u64 = LINUX_CLONE_VM
    | LINUX_CLONE_FS
    | LINUX_CLONE_FILES
    | LINUX_CLONE_SIGHAND
    | LINUX_CLONE_PIDFD
    | LINUX_CLONE_PTRACE
    | LINUX_CLONE_VFORK
    | LINUX_CLONE_PARENT
    | LINUX_CLONE_NEWNS
    | LINUX_CLONE_SYSVSEM
    | LINUX_CLONE_SETTLS
    | LINUX_CLONE_PARENT_SETTID
    | LINUX_CLONE_CHILD_CLEARTID
    | LINUX_CLONE_DETACHED
    | LINUX_CLONE_UNTRACED
    | LINUX_CLONE_CHILD_SETTID
    | LINUX_CLONE_NEWUSER
    | LINUX_CLONE_NEW_KEPT
    | LINUX_CLONE_IO
    | LINUX_CLONE_CLEAR_SIGHAND
    | LINUX_CLONE_INTO_CGROUP;

/// Marks `LINUX_FORK_CLONE_FLAGS` as set by a clone (a plain fork leaves
/// it 0), so an exit signal of 0 means none rather than SIGCHLD.
pub(super) const LINUX_FORK_CLONE_REQUESTED: u64 = 1 << 63;

/// Starts process clone `clone` from the calling thread (`caller`): checks
/// it as Linux does, then asks the fork transaction for the child. From
/// clone(2) (`legacy`), CLONE_VM | CLONE_VFORK on a stack is musl's
/// posix_spawn, whose child maps its parent's pages and whose exec does not
/// let the parent go (see `execute_deferred_live_fork`).
#[inline(never)]
pub(super) fn linux_clone_process(
    clone: LinuxProcessClone,
    caller: LinuxUserContext,
    legacy: bool,
) -> u64 {
    let flags = clone.flags;
    if flags & LINUX_CLONE_FS != 0 && flags & (LINUX_CLONE_NEWNS | LINUX_CLONE_NEWUSER) != 0
        || flags & LINUX_CLONE_SIGHAND != 0 && flags & LINUX_CLONE_VM == 0
        || flags & LINUX_CLONE_SIGHAND != 0 && flags & LINUX_CLONE_CLEAR_SIGHAND != 0
        // init has no parent to give its child (Linux: an unkillable init).
        || flags & LINUX_CLONE_PARENT != 0 && current_linux_process_pid() == 1
        || flags & LINUX_CLONE_PIDFD != 0 && flags & LINUX_CLONE_DETACHED != 0
        || clone.exit_signal > LINUX_SIGNAL_COUNT as u64
        || flags & !LINUX_PROCESS_CLONE_FLAGS != 0
    {
        return LINUX_EINVAL;
    }
    if flags & LINUX_CLONE_PIDFD != 0 && !linux_writable_user_range_contains(clone.pidfd, 4)
        || flags & LINUX_CLONE_PARENT_SETTID != 0
            && !linux_writable_user_range_contains(clone.parent_tid, 4)
        || flags & LINUX_CLONE_CHILD_SETTID != 0
            && !linux_writable_user_range_contains(clone.child_tid, 4)
    {
        return LINUX_EFAULT;
    }
    if clone.stack != 0
        && !materialize_linux_runtime_user_range(
            (clone.stack - 1) & !(PAGE_SIZE as u64 - 1),
            PAGE_SIZE,
            true,
        )
    {
        return LINUX_EFAULT;
    }
    let share_vm = flags & LINUX_CLONE_VM != 0;
    let vfork = flags & LINUX_CLONE_VFORK != 0;
    // A child sharing its parent's memory maps the parent's pages. Pages
    // the parent shares copy-on-write with others (what an earlier fork
    // left) are made the parent's own first, so that what either writes
    // the other sees. A vfork child only runs until it executes or exits
    // while its parent waits, and goes without.
    // The registry's mapping list is brought up to date first: a wait
    // leaves it stale, and the copies are recorded in it.
    if share_vm && !vfork {
        if !refresh_live_linux_process_registry(caller) {
            return LINUX_EAGAIN;
        }
        if !linux_own_copy_on_write_pages() {
            return LINUX_ENOMEM;
        }
    }
    let result = linux_request_process_fork(
        true,
        caller,
        flags,
        clone.stack,
        share_vm && !(legacy && vfork && clone.stack != 0),
        clone.pidfd,
        clone.cgroup_generation,
        flags & LINUX_CLONE_CLEAR_SIGHAND != 0,
        !share_vm,
    );
    if result == LINUX_RETURN_TO_KERNEL {
        // The rest is done once the child exists: the tid words written
        // (the child's in it, the parent's in the parent), and what it
        // shares, its parent, exit signal and thread pointer set.
        let address_if = |flag: u64, address: u64| if flags & flag != 0 { address } else { 0 };
        X86_RUNTIME.LINUX_FORK_CHILD_TID_ADDRESS.store(
            address_if(LINUX_CLONE_CHILD_SETTID, clone.child_tid),
            Ordering::SeqCst,
        );
        X86_RUNTIME.LINUX_FORK_PARENT_TID_ADDRESS.store(
            address_if(LINUX_CLONE_PARENT_SETTID, clone.parent_tid),
            Ordering::SeqCst,
        );
        X86_RUNTIME.LINUX_FORK_CLEAR_TID_ADDRESS.store(
            address_if(LINUX_CLONE_CHILD_CLEARTID, clone.child_tid),
            Ordering::SeqCst,
        );
        X86_RUNTIME
            .LINUX_FORK_TLS
            .store(address_if(LINUX_CLONE_SETTLS, clone.tls), Ordering::SeqCst);
        X86_RUNTIME.LINUX_FORK_CLONE_FLAGS.store(
            LINUX_FORK_CLONE_REQUESTED | flags & !0xff | clone.exit_signal,
            Ordering::SeqCst,
        );
    }
    result
}

/// Makes every page the current process maps copy-on-write (shared with
/// another address space since a fork) a page of its own, as a write to
/// each would; false when memory runs out.
#[inline(never)]
fn linux_own_copy_on_write_pages() -> bool {
    let mut pages = Vec::new();
    if !address_space::current_linux_cow_addresses(&mut pages) {
        return false;
    }
    pages.into_iter().all(materialize_linux_cow_address)
}

/// The resources a process clone with `flags` shares with its parent.
fn linux_clone_shared_resources(flags: u64) -> impl Iterator<Item = linux_process::SharedResource> {
    use linux_process::SharedResource;
    [
        (LINUX_CLONE_VM, SharedResource::Memory),
        (LINUX_CLONE_FILES, SharedResource::Descriptors),
        (LINUX_CLONE_FS, SharedResource::Filesystem),
        (LINUX_CLONE_SIGHAND, SharedResource::SignalHandlers),
        (LINUX_CLONE_IO, SharedResource::Io),
        (LINUX_CLONE_SYSVSEM, SharedResource::SemaphoreUndo),
    ]
    .into_iter()
    .filter(move |(flag, _)| flags & flag != 0)
    .map(|(_, resource)| resource)
}

/// Tells process `child`'s parent that the child ended with `status`: its
/// exit signal (SIGCHLD unless clone named another; none for 0). Only a
/// SIGCHLD that cannot be queued fails.
pub(super) fn linux_signal_child_exit(parent: u32, child: u32, status: u8) -> bool {
    // A parent ignoring SIGCHLD now reaps this child; one that ended
    // before stays its zombie.
    if linux_parent_reaps_automatically(parent) {
        linux_process::set_live_process_reaped_by_parent(child);
    }
    let signal = linux_process::live_process_exit_signal(child).map_or(LINUX_SIGCHLD, u64::from);
    let queued = signal == 0
        || linux_queue_process_signal(parent, signal, LINUX_CLD_EXITED, Some(u64::from(status)))
            == 0;
    queued || signal != LINUX_SIGCHLD
}

pub(super) fn linux_clone3(
    arguments: u64,
    size: u64,
    caller: LinuxUserContext,
    parent_registers: LinuxSyscallFrame,
    user_rip: u64,
    user_rflags: u64,
) -> u64 {
    const CLONE_ARGS_MIN_SIZE: usize = 64;
    const CLONE_ARGS_SIZE: usize = 88;
    // The arguments as Linux takes them: up to a page, at least the first
    // version's 64 bytes, anything past the known struct zero (E2BIG) and
    // readable (EFAULT) (clone302).
    let Ok(size) = usize::try_from(size) else {
        return LINUX_E2BIG;
    };
    if size > PAGE_SIZE {
        return LINUX_E2BIG;
    }
    if size < CLONE_ARGS_MIN_SIZE {
        return LINUX_EINVAL;
    }
    let mut bytes = [0_u8; CLONE_ARGS_SIZE];
    let known = size.min(CLONE_ARGS_SIZE);
    if !copy_from_linux_user(arguments, &mut bytes[..known]) {
        return LINUX_EFAULT;
    }
    let mut extra_offset = known;
    while extra_offset < size {
        let mut extra = [0_u8; 64];
        let length = (size - extra_offset).min(extra.len());
        let Some(address) = arguments.checked_add(extra_offset as u64) else {
            return LINUX_EFAULT;
        };
        if !copy_from_linux_user(address, &mut extra[..length]) {
            return LINUX_EFAULT;
        }
        if extra[..length].iter().any(|byte| *byte != 0) {
            return LINUX_E2BIG;
        }
        extra_offset += length;
    }
    let word = |offset: usize| u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let flags = word(0);
    let _pidfd = word(8);
    let child_tid = word(16);
    let parent_tid = word(24);
    let exit_signal = word(32);
    let stack = word(40);
    let stack_size = word(48);
    let tls = word(56);
    let _set_tid = word(64);
    let set_tid_size = word(72);
    let cgroup = word(80);
    let Some(child_stack) = stack.checked_add(stack_size) else {
        return LINUX_EINVAL;
    };
    // Linux's checks of the flags and signal (clone302), before the
    // namespace and set_tid ones that need privilege (clone304).
    const CLONE_NEWTIME: u64 = 0x80;
    const CLONE_NEWCGROUP: u64 = 0x0200_0000;
    const CLONE_NEWUTS: u64 = 0x0400_0000;
    const CLONE_NEWIPC: u64 = 0x0800_0000;
    const CLONE_NEWPID: u64 = 0x2000_0000;
    const CLONE_NEWNET: u64 = 0x4000_0000;
    const NAMESPACE_FLAGS: u64 = CLONE_NEWTIME
        | LINUX_CLONE_NEWNS
        | CLONE_NEWCGROUP
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | LINUX_CLONE_NEWUSER
        | CLONE_NEWPID
        | CLONE_NEWNET;
    if flags & LINUX_CLONE_SIGHAND != 0 && flags & LINUX_CLONE_VM == 0
        || flags & LINUX_CLONE_THREAD != 0 && flags & LINUX_CLONE_SIGHAND == 0
        || flags & LINUX_CLONE_FS != 0 && flags & (LINUX_CLONE_NEWNS | LINUX_CLONE_NEWUSER) != 0
        || exit_signal & !0xff != 0
        || (stack == 0) != (stack_size == 0)
    {
        return LINUX_EINVAL;
    }
    let privileged = current_linux_credentials()
        .is_some_and(|credentials| credentials.has(linox_credentials::capability::SYS_ADMIN));
    // set_tid and the namespaces other than the user one need CAP_SYS_ADMIN
    // (or CAP_CHECKPOINT_RESTORE); root gets the ones this kernel has.
    if (set_tid_size != 0 || flags & NAMESPACE_FLAGS & !LINUX_CLONE_NEWUSER != 0) && !privileged {
        return LINUX_EPERM;
    }
    if set_tid_size != 0
        || flags
            & NAMESPACE_FLAGS
            & !(LINUX_CLONE_NEWNS | LINUX_CLONE_NEWUSER | LINUX_CLONE_NEW_KEPT)
            != 0
    {
        return LINUX_EINVAL;
    }
    if flags & LINUX_CLONE_THREAD == 0 {
        if flags & LINUX_CLONE_DETACHED != 0 {
            return LINUX_EINVAL;
        }
        let cgroup_generation = if flags & LINUX_CLONE_INTO_CGROUP != 0 {
            let Some(handle) = linux_overlay_descriptor_handle(cgroup) else {
                return LINUX_EBADF;
            };
            let Some(metadata) = crate::linux_overlay::metadata(handle) else {
                return LINUX_EBADF;
            };
            let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            let Some(length) = crate::linux_overlay::copy_path(handle, &mut path) else {
                return LINUX_EBADF;
            };
            if metadata.kind != crate::linux_overlay::NodeKind::Directory
                || !path[..length].starts_with(b"sys/fs/cgroup/")
            {
                return LINUX_EBADF;
            }
            crate::linux_overlay::generation(handle)
        } else {
            0
        };
        return linux_clone_process(
            LinuxProcessClone {
                flags,
                exit_signal,
                stack: child_stack,
                parent_tid,
                child_tid,
                tls,
                pidfd: if flags & LINUX_CLONE_PIDFD != 0 {
                    _pidfd
                } else {
                    0
                },
                cgroup_generation,
            },
            caller,
            false,
        );
    }
    // Linux permits unused clone3 output fields to alias the thread-id word.
    // Their values only carry meaning when the corresponding flag is set.
    if exit_signal != 0 || set_tid_size != 0 || stack == 0 || stack_size == 0 {
        return LINUX_EINVAL;
    }
    let request = LinuxCloneRequest {
        flags,
        child_stack,
        parent_tid,
        child_tid,
        tls,
    };
    let result = linux_clone_thread_request(request, parent_registers, user_rip, user_rflags);
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && result >= u64::MAX - 4095 {
        serial_write("linox: Linux clone3 flags/stack/size/parent-tid/child-tid/tls/result: ");
        for value in [flags, stack, stack_size, parent_tid, child_tid, tls, result] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
    }
    result
}

pub(super) fn linux_clone_thread(
    registers: LinuxSyscallFrame,
    user_rip: u64,
    user_rflags: u64,
) -> u64 {
    // x86-64 clone(flags, stack, parent_tid, child_tid, tls) passes its
    // arguments in rdi, rsi, rdx, r10, and r8.
    let request = LinuxCloneRequest {
        flags: registers.rdi,
        child_stack: registers.rsi,
        parent_tid: registers.rdx,
        child_tid: registers.r10,
        tls: registers.r8,
    };
    linux_clone_thread_request(request, registers, user_rip, user_rflags)
}

fn linux_clone_thread_request(
    mut request: LinuxCloneRequest,
    parent_registers: LinuxSyscallFrame,
    user_rip: u64,
    user_rflags: u64,
) -> u64 {
    let runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    // Any thread may create threads in the runtime (rustc's compiler thread
    // spawns the codegen coordinator); the boot probe keeps the stricter rule.
    if !runtime && current_linux_tid() != Some(current_linux_process_pid()) {
        return LINUX_EAGAIN;
    }
    if linux_nproc_limit_reached() {
        return LINUX_EAGAIN;
    }
    if !runtime && ready_linux_thread_handle().is_some() {
        X86_RUNTIME
            .LINUX_CLONE_BUSY_REJECTION_COUNT
            .fetch_add(1, Ordering::SeqCst);
        return LINUX_EAGAIN;
    }
    let sibling_fs = X86_RUNTIME.ELF_PROBE_SIBLING_FS_BASE.load(Ordering::SeqCst);
    let sibling_tls = X86_RUNTIME.ELF_PROBE_SIBLING_TLS.load(Ordering::SeqCst);
    let sibling_stack = X86_RUNTIME.ELF_PROBE_SIBLING_STACK.load(Ordering::SeqCst);
    let tls_size = X86_RUNTIME.ELF_PROBE_TLS_SIZE.load(Ordering::SeqCst);
    let (sibling_context, stack_base, stack_size) = if runtime {
        // Without CLONE_SETTLS the thread starts with its creator's thread
        // pointer; tid words no flag asks for are not looked at.
        if request.flags & LINUX_CLONE_SETTLS == 0 {
            request.tls = active_fs_base();
        }
        if request.flags & LINUX_CLONE_PARENT_SETTID == 0 {
            request.parent_tid = 0;
        }
        if request.flags & (LINUX_CLONE_CHILD_SETTID | LINUX_CLONE_CHILD_CLEARTID) == 0 {
            request.child_tid = 0;
        }
        let Ok(thread_pointer) = usize::try_from(request.tls) else {
            return LINUX_EINVAL;
        };
        let Ok(stack_top) = usize::try_from(request.child_stack) else {
            return LINUX_EINVAL;
        };
        // Linux does not require an aligned child stack; musl passes 16n - 8
        // because it pushes the thread argument before the system call.
        if !linux_thread_clone_flags_supported(request.flags)
            || stack_top == 0
            || stack_top & 7 != 0
            || !linux_readable_user_range_contains(request.tls, 16)
        {
            return LINUX_EINVAL;
        }
        let tls_base = thread_pointer & !(PAGE_SIZE - 1);
        let tls_extent_size = if thread_pointer
            .checked_add(16)
            .is_some_and(|end| end <= tls_base + PAGE_SIZE)
        {
            PAGE_SIZE
        } else {
            PAGE_SIZE * 2
        };
        let stack_page = (stack_top - 1) & !(PAGE_SIZE - 1);
        let Some(stack_end) = stack_page.checked_add(PAGE_SIZE) else {
            return LINUX_EINVAL;
        };
        if !materialize_linux_runtime_user_range(stack_page as u64, PAGE_SIZE, true) {
            return LINUX_EINVAL;
        }
        let mut stack_base = stack_page;
        while let Some(previous) = stack_base.checked_sub(PAGE_SIZE) {
            let page = address_space::current_linux_runtime_page(previous as u64);
            if !page.occupied || page.protection & LINUX_PROT_WRITE as u8 == 0 {
                break;
            }
            stack_base = previous;
        }
        (
            LinuxTlsContext {
                thread_pointer,
                extent: tls_base,
                extent_size: tls_extent_size,
            },
            stack_base,
            stack_end - stack_base,
        )
    } else {
        if sibling_fs == 0
            || sibling_tls == 0
            || sibling_stack == 0
            || tls_size == 0
            || request.child_stack != sibling_stack + PAGE_SIZE as u64
            || request.tls != sibling_fs
        {
            return LINUX_EINVAL;
        }
        (
            LinuxTlsContext {
                thread_pointer: sibling_fs as usize,
                extent: sibling_tls as usize,
                extent_size: tls_size as usize,
            },
            sibling_stack as usize,
            PAGE_SIZE,
        )
    };
    let prior_dispatch_count = X86_RUNTIME
        .LINUX_CLONE_DISPATCH_COUNT
        .load(Ordering::SeqCst);
    let reused_stack_scrubbed = !runtime
        && prior_dispatch_count == 1
        && hardware_user_range_is_zero(sibling_stack, PAGE_SIZE);
    let Some(child) = reserve_linux_thread(sibling_context, stack_base, stack_size) else {
        return LINUX_EAGAIN;
    };
    let data_base = X86_RUNTIME.ELF_PROBE_DATA.load(Ordering::SeqCst);
    let Ok(data_size) = usize::try_from(X86_RUNTIME.ELF_PROBE_DATA_SIZE.load(Ordering::SeqCst))
    else {
        let _ = retire_linux_thread(child);
        return LINUX_EFAULT;
    };
    let result = match publish_linux_clone(
        child,
        request,
        parent_registers,
        user_rip,
        user_rflags,
        data_base,
        data_size,
    ) {
        Ok(result) if initialize_linux_thread_extended_state(usize::from(child.slot)) => result,
        Ok(_) => {
            let _ = retire_linux_thread(child);
            return LINUX_EAGAIN;
        }
        Err(error) => {
            let _ = retire_linux_thread(child);
            return match error {
                LinuxClonePublishError::InvalidRequest => {
                    X86_RUNTIME
                        .LINUX_CLONE_INVALID_REJECTION_COUNT
                        .fetch_add(1, Ordering::SeqCst);
                    LINUX_EINVAL
                }
                LinuxClonePublishError::TidFault => {
                    X86_RUNTIME
                        .LINUX_CLONE_TID_FAULT_COUNT
                        .fetch_add(1, Ordering::SeqCst);
                    LINUX_EFAULT
                }
            };
        }
    };
    // The new thread shares its creator's session keyring; a failure here
    // does not fail the clone, as in Linux.
    let _ = linux_with_keys(|keys, caller| keys.spawn_thread(caller, child.tid));
    let dispatch_index = X86_RUNTIME
        .LINUX_CLONE_DISPATCH_COUNT
        .fetch_add(1, Ordering::SeqCst);
    if dispatch_index == 0 {
        X86_RUNTIME
            .LINUX_FIRST_CHILD_TID
            .store(child.tid, Ordering::SeqCst);
    } else if dispatch_index == 1
        && reused_stack_scrubbed
        && child.tid > X86_RUNTIME.LINUX_FIRST_CHILD_TID.load(Ordering::SeqCst)
    {
        X86_RUNTIME
            .LINUX_CLONE_REUSE_VALIDATED
            .store(true, Ordering::SeqCst);
    }
    result.parent_rax
}

pub(super) fn linux_schedule_new_thread(
    output: LinuxSyscallFrameHandle,
    registers: LinuxSyscallFrame,
    user_stack: u64,
    user_rip: u64,
    user_rflags: u64,
    parent_result: u64,
) -> u64 {
    if parent_result >= u64::MAX - 4095 {
        return parent_result;
    }
    let Some(parent) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let Some(parent_tls) = linux_thread_context(parent) else {
        return LINUX_ESRCH;
    };
    let parent_context = LinuxUserContext {
        registers,
        rip: user_rip,
        rsp: user_stack,
        rflags: user_rflags,
        rax: parent_result,
        fs_base: parent_tls.thread_pointer as u64,
    };
    if !save_linux_thread_return_context(parent, parent_context) {
        return LINUX_EINVAL;
    }
    let Some(child) = ready_linux_thread_handle() else {
        return parent_result;
    };
    let Some(child_context) = linux_thread_return_context(child) else {
        return LINUX_EINVAL;
    };
    // In a domain runtime with more than one CPU, the parent goes on and
    // an idle CPU of the runtime's loop takes the new thread (its owner
    // switches to it when none is idle and its own thread waits). A
    // single-CPU domain switches to the child here.
    if !cfg!(feature = "verification-boot") && linux_smp_runtime_active() {
        adopt_linux_process_bank(current_linux_process_pid());
        X86_RUNTIME
            .LINUX_LIVE_RETURN_VALIDATED
            .store(true, Ordering::SeqCst);
        return parent_result;
    }
    if !switch_linux_thread(child) || !write_linux_thread_live_return(output, child, child_context)
    {
        let _ = switch_linux_thread(parent);
        return LINUX_EINVAL;
    }
    X86_RUNTIME
        .LINUX_YIELD_SWITCH_COUNT
        .fetch_add(1, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_LIVE_RETURN_VALIDATED
        .store(true, Ordering::SeqCst);
    LINUX_RETURN_FROM_IRET
}

/// When a domain's init exits while other processes live, kills them as
/// Linux does when a PID namespace's init exits, and lets them run their
/// exits before init's exit runs again. Returns `None` once init is alone
/// (or the processes did not go away), so its exit proceeds.
pub(super) fn linux_init_exit_kill_others_live_return(
    output: LinuxSyscallFrameHandle,
    caller: LinuxUserContext,
    number: u64,
) -> Option<u64> {
    let living: (Vec<u32>, usize) = match linux_signal_targets(-1) {
        Ok((mut targets, _)) => {
            targets.retain(|pid| {
                linux_process::live_process_status(*pid)
                    .is_some_and(|status| status.state != linux_process::LiveProcessState::Zombie)
            });
            let found = targets.len();
            (targets, found)
        }
        Err(_) => (Vec::new(), 0),
    };
    let rounds = X86_RUNTIME
        .LINUX_INIT_EXIT_KILL_ROUNDS
        .fetch_add(1, Ordering::SeqCst);
    if living.1 == 0 || rounds >= LINUX_INIT_EXIT_KILL_ROUND_LIMIT {
        X86_RUNTIME
            .LINUX_INIT_EXIT_KILL_ROUNDS
            .store(0, Ordering::SeqCst);
        return None;
    }
    for pid in living.0[..living.1].iter().copied() {
        let _ = linux_queue_process_signal(pid, LINUX_SIGKILL, LINUX_SI_KERNEL, None);
    }
    // Blocked until the killed processes' exits change something.
    let ran = run_other_linux_processes(output, caller, number, WaitOn::of(wait_events::STATE));
    if ran.is_none() && rounds >= LINUX_INIT_EXIT_FORCE_ROUND {
        // The scheduler keeps failing to switch to the killed processes, so
        // they cannot run their own exits; end them from here.
        for pid in living.0[..living.1].iter().copied() {
            wait_for_linux_process_threads_to_leave(pid);
            if linux_process::force_exit_live_process(pid, 128 + LINUX_SIGKILL as u8) {
                retire_linux_process_record(pid);
                let _ = release_linux_process_runtime_slot(pid);
                release_linux_process_shared_mappings(pid);
                release_linux_process_keys(pid);
                linux_fanotify_exit(pid);
                linux_landlock_exit(pid);
            }
        }
    }
    Some(match ran {
        Some(LinuxBlockedWait::Return(result)) => result,
        _ => linux_restart_syscall_live_return(output, caller, number),
    })
}

/// Reaps exited child `pid` of `parent` (`linux_process::wait_live_child`),
/// and with it what an exited process keeps until then: its Landlock
/// domain, which signals to the zombie are still judged by.
pub(super) fn linux_reap_child(parent: u32, pid: u32) -> Option<(u32, u8)> {
    let reaped = linux_process::wait_live_child(parent, pid)?;
    linux_landlock_exit(reaped.0);
    Some(reaped)
}

/// Drops what the runtime saved for process `pid`, which will not run again:
/// its open descriptions, its thread table and its threads' register state.
fn retire_linux_process_record(pid: u32) {
    if let Some(state) = linux_process_runtime_state(pid) {
        if state.valid {
            release_linux_process_descriptors(pid, state);
        }
        *state = LinuxProcessRuntimeState::EMPTY;
    }
    if let Some(threads) = linux_process_thread_runtime_state(pid) {
        threads.fill(LinuxThreadRuntimeState::EMPTY);
    }
    discard_linux_process_extended_state(pid);
}

/// `caller` with a stack pointer on a mapped, writable page: its own, or a
/// sibling thread's saved one when its stack is already gone.
fn linux_exit_context_with_mapped_stack(caller: LinuxUserContext) -> LinuxUserContext {
    let writable = |rsp: u64| {
        rsp.checked_sub(1)
            .and_then(address_space::current_linux_active_mapping)
            .is_some_and(|page| page.writable)
    };
    if writable(caller.rsp) {
        return caller;
    }
    let current = current_linux_thread_slot();
    let replacement = (0..LINUX_THREAD_LIMIT)
        .filter(|slot| {
            Some(*slot) != current
                && X86_RUNTIME.LINUX_THREAD_STATES[*slot].load(Ordering::SeqCst)
                    != LINUX_THREAD_FREE
        })
        .map(|slot| X86_RUNTIME.LINUX_THREAD_RSPS[slot].load(Ordering::SeqCst))
        .find(|rsp| writable(*rsp));
    LinuxUserContext {
        rsp: replacement.unwrap_or(caller.rsp),
        ..caller
    }
}

pub(super) fn linux_exit_child_to_parent(
    output: LinuxSyscallFrameHandle,
    caller: LinuxUserContext,
) -> u64 {
    let clear_child_tid = current_linux_clear_child_tid().unwrap_or(0);
    let robust_list = current_linux_robust_list().unwrap_or(0);
    let tid = current_linux_tid().unwrap_or(0);
    if cfg!(feature = "linux-boot-profile") {
        serial_write("linox: profile child-exit pid/tid: ");
        serial_write_u64(u64::from(current_linux_process_pid()));
        serial_write("/");
        serial_write_u64(u64::from(tid));
        serial_write("\r\n");
        write_linux_futex_profile();
        write_linux_boot_profile();
        reset_linux_boot_profile();
    }
    if clear_child_tid != 0 {
        let _ = copy_to_linux_user(clear_child_tid, &0_u32.to_ne_bytes());
    }
    let woken = wake_linux_futex(clear_child_tid, 1);
    linux_trace_futex(7, clear_child_tid, u64::from(woken));
    exit_linux_robust_list(tid, robust_list);
    if !set_current_linux_clear_child_tid(0) || !set_current_linux_robust_list(0) {
        return LINUX_ESRCH;
    }
    // Where threads park in their calls, the thread just ends: its
    // activation finishes, and the scheduler runs its siblings, each on an
    // activation of its own, or blocks the process on what they wait for.
    // The last thread's exit ends the process, as exit_group would.
    if linux_threads_park_here() {
        return linux_exit_thread_live_return(caller, woken);
    }
    // Another thread of this process takes over the CPU. While all of them
    // wait, such as a main thread polling a child's pipes, this thread stays
    // current and other processes run. A yield restarts this exit, which has
    // nothing left to undo. A thread on an application processor just ends,
    // and so does one whose siblings run on other CPUs.
    // musl unmaps a detached thread's stack before this call, which then
    // uses no stack; the yields record a context the registry checks, so a
    // sibling's mapped stack pointer stands in for the unmapped one (the
    // refresh was refused every time and CPU 0 spun here: fcntl36_64).
    // A joinable thread's stack goes while this loop runs: the tid word's
    // wake above lets the joiner unmap it (futex_wait03), so the check is
    // made again on every pass.
    let mut caller = caller;
    while current_linux_runtime_cpu_index() == 0 && ready_linux_thread_handle().is_none() {
        caller = linux_exit_context_with_mapped_stack(caller);
        let _ = expire_linux_waits();
        // Its siblings all ended on other CPUs meanwhile: the process ends
        // with this thread, as exit_group would end it.
        if current_linux_thread_slot().is_some_and(|slot| {
            (0..LINUX_THREAD_LIMIT).all(|other| {
                other == slot
                    || X86_RUNTIME.LINUX_THREAD_STATES[other].load(Ordering::SeqCst)
                        == LINUX_THREAD_FREE
            })
        }) {
            if !clear_current_linux_process_signal_queues() {
                return LINUX_EIO;
            }
            X86_RUNTIME
                .LINUX_PROCESS_CHILD_STATUS
                .store(caller.registers.rdi as u8, Ordering::SeqCst);
            X86_RUNTIME
                .LINUX_PROCESS_CHILD_EXIT_PID
                .store(current_linux_process_pid(), Ordering::SeqCst);
            X86_RUNTIME
                .LINUX_PROCESS_CHILD_EXITED
                .store(true, Ordering::SeqCst);
            return LINUX_RETURN_TO_KERNEL;
        }
        if let Some(LinuxBlockedWait::Return(result)) =
            run_other_linux_processes(output, caller, LINUX_EXIT_SYSCALL, WaitOn::ANYTHING)
        {
            return result;
        }
        core::hint::spin_loop();
    }
    if !retire_current_linux_thread() {
        return LINUX_ESRCH;
    }
    if woken == 1 {
        X86_RUNTIME
            .LINUX_FUTEX_EXIT_WAKE_COUNT
            .fetch_add(1, Ordering::SeqCst);
    }
    X86_RUNTIME
        .LINUX_CHILD_EXIT_COUNT
        .fetch_add(1, Ordering::SeqCst);
    if current_linux_runtime_cpu_index() != 0 {
        return LINUX_RETURN_TO_KERNEL;
    }
    let Some(parent) = ready_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let mut registers = LinuxSyscallFrame::ZERO;
    let mut rip = 0;
    let mut rsp = 0;
    let mut rflags = 0;
    let mut rax = 0;
    if !install_linux_thread_return(
        parent,
        &mut registers,
        &mut rip,
        &mut rsp,
        &mut rflags,
        &mut rax,
    ) {
        return LINUX_ESRCH;
    }
    let context = LinuxUserContext {
        registers,
        rip,
        rsp,
        rflags,
        rax,
        fs_base: active_fs_base(),
    };
    if !write_linux_thread_live_return(output, parent, context) {
        return LINUX_EINVAL;
    }
    LINUX_RETURN_FROM_IRET
}

/// Thread exit (`linux_exit_child_to_parent`) where threads park in their
/// calls: the calling thread's slot is freed and the process's registry
/// context becomes a sibling's (an exited thread's stack may be gone), or
/// the process exits with it when it was the last.
fn linux_exit_thread_live_return(caller: LinuxUserContext, woken: u32) -> u64 {
    let Some(current) = current_linux_thread_slot() else {
        return LINUX_ESRCH;
    };
    let siblings = || {
        (0..LINUX_THREAD_LIMIT).filter(|slot| {
            *slot != current
                && X86_RUNTIME.LINUX_THREAD_STATES[*slot].load(Ordering::SeqCst)
                    != LINUX_THREAD_FREE
        })
    };
    let pid = current_linux_process_pid();
    if siblings().next().is_none() {
        // Its siblings all ended: the process ends with this thread.
        if !clear_current_linux_process_signal_queues() {
            return LINUX_EIO;
        }
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_STATUS
            .store(caller.registers.rdi as u8, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXIT_PID
            .store(pid, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXITED
            .store(true, Ordering::SeqCst);
        return LINUX_RETURN_TO_KERNEL;
    }
    if !retire_current_linux_thread() {
        return LINUX_ESRCH;
    }
    if let Some((general, rip, rsp, rflags, fs_base)) = siblings()
        .filter_map(linux_thread_handle)
        .find_map(linux_thread_entry_context)
    {
        let _ =
            linux_process::set_live_process_thread_context(pid, general, rip, rsp, rflags, fs_base);
    }
    if woken == 1 {
        X86_RUNTIME
            .LINUX_FUTEX_EXIT_WAKE_COUNT
            .fetch_add(1, Ordering::SeqCst);
    }
    X86_RUNTIME
        .LINUX_CHILD_EXIT_COUNT
        .fetch_add(1, Ordering::SeqCst);
    LINUX_RETURN_TO_KERNEL
}

pub(super) fn current_linux_process_pid() -> u32 {
    X86_RUNTIME.LINUX_CURRENT_PROCESS_PID.load(Ordering::SeqCst)
}

/// The process this CPU runs (0: none).
pub(crate) fn current_linux_process_id() -> u32 {
    current_linux_process_pid()
}

/// The mount namespace the process this CPU runs is in, as its runtime
/// record holds it (unshare and fork set it); None outside a process.
pub(crate) fn current_process_mount_namespace() -> Option<linux_mount::MountNamespaceHandle> {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Relaxed) {
        return None;
    }
    let pid = current_linux_process_pid();
    if pid == 0 {
        return None;
    }
    linux_process_runtime_state(pid)?.mount_namespace
}

pub(super) fn linux_child_exited(pid: u32) -> bool {
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_EXITED
        .load(Ordering::SeqCst)
        && X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXIT_PID
            .load(Ordering::SeqCst)
            == pid
}

fn linux_child_executed(pid: u32) -> bool {
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_EXECUTED
        .load(Ordering::SeqCst)
        && X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXEC_PID
            .load(Ordering::SeqCst)
            == pid
}

fn linux_child_yielded(pid: u32) -> bool {
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_YIELDED
        .load(Ordering::SeqCst)
        && X86_RUNTIME
            .LINUX_PROCESS_CHILD_YIELD_PID
            .load(Ordering::SeqCst)
            == pid
}

pub(super) fn take_linux_child_exit(pid: u32) -> Option<u8> {
    if !linux_child_exited(pid) {
        return None;
    }
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_EXITED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_EXIT_PID
        .store(0, Ordering::SeqCst);
    Some(
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_STATUS
            .swap(0, Ordering::SeqCst),
    )
}

fn take_linux_child_exec(pid: u32) -> bool {
    if !linux_child_executed(pid) {
        return false;
    }
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_EXECUTED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_EXEC_PID
        .store(0, Ordering::SeqCst);
    true
}

pub(super) fn take_linux_child_yield(pid: u32) -> bool {
    if !linux_child_yielded(pid) {
        return false;
    }
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_YIELDED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_YIELD_PID
        .store(0, Ordering::SeqCst);
    true
}

/// Lets interrupts in and halts until the next one (a timer tick or a
/// device), then turns them off again.
pub(in crate::arch::x86_64) fn linux_wait_for_interrupt() {
    let started = timer::timestamp_counter();
    // A process asleep in a wait of its own is not resumed to look at its
    // deadline (`linux_process_asleep`): the tick comes at it instead of up
    // to a tick later. The tick is the boot CPU's. One already due (its
    // deadline came after the look for work) is resumed now, not after a
    // whole tick (nanosleep01's 5 ms sleeps all ended 1.1 ms late): this
    // CPU looks again after a moment, with the lock let go meanwhile. The
    // sleeper may be one only another CPU may run (pinned there), which
    // can take it only with the lock: returning with the lock held, the
    // boot CPU looked and returned again for good, and the sleeper never
    // ran (`linox-threadtest pin`'s 1 ms sleeps marked to their end).
    let mut sleeper_due = false;
    if let Some((deadline, now)) = linux_elapsed_nanoseconds()
        .filter(|_| current_cpu_index_checked() == Some(0))
        .and_then(|now| Some((linux_process::next_live_block_deadline()?, now)))
    {
        if deadline <= now {
            sleeper_due = true;
        } else {
            timer::request_linux_tick_within(deadline - now);
        }
    }
    // Other CPUs enter the kernel while this one waits.
    crate::sync::kernel_entry_leave_to_user();
    if sleeper_due || current_cpu_index_checked().is_some_and(|cpu| cpu != 0) {
        let until = timer::timestamp_counter().wrapping_add(LINUX_SMP_IDLE_SPIN_TICKS);
        while timer::timestamp_counter() < until {
            core::hint::spin_loop();
        }
    } else {
        // SAFETY: interrupts are enabled only around the halt; their
        // handlers save and restore the state they touch, and `cli` ends the
        // window before this returns, so the caller's interrupt-off
        // invariants hold.
        crate::trusted::interrupts::wait();
    }
    crate::cpu_time::add_idle(timer::timestamp_counter().saturating_sub(started));
    crate::sync::kernel_entry_return_from_user();
    // Closed TCP connections finish sending while the domain waits.
    crate::linux_socket::poll_closing();
}

#[derive(Clone, Copy)]
enum LinuxChildWaitSelector {
    Any,
    Process(u32),
    ProcessGroup(u32),
}

fn linux_child_wait_state(
    parent: u32,
    selector: LinuxChildWaitSelector,
    events: linux_process::ChildWaitEvents,
) -> Option<linux_process::ChildWaitState> {
    match selector {
        LinuxChildWaitSelector::Any => linux_process::live_child_wait_state(parent, None, events),
        LinuxChildWaitSelector::Process(pid) => {
            linux_process::live_child_wait_state(parent, Some(pid), events)
        }
        LinuxChildWaitSelector::ProcessGroup(group) => {
            linux_process::live_child_group_wait_state(parent, group, events)
        }
    }
}

/// __WNOTHREAD, __WALL and __WCLONE: which children a wait looks at.
/// __WNOTHREAD changes nothing here: every thread waits for its process's
/// children.
const LINUX_WAIT_SCOPE_FLAGS: u64 = 0x2000_0000 | 0x4000_0000 | 0x8000_0000;

/// The children a wait with `options` reports: __WALL all of them, __WCLONE
/// those ending with a signal other than SIGCHLD, otherwise the others.
fn linux_wait_child_scope(options: u64) -> linux_process::ChildScope {
    const WALL: u64 = 0x4000_0000;
    const WCLONE: u64 = 0x8000_0000;
    if options & WALL != 0 {
        linux_process::ChildScope::All
    } else if options & WCLONE != 0 {
        linux_process::ChildScope::Clone
    } else {
        linux_process::ChildScope::Plain
    }
}

pub(super) fn linux_wait4(pid: u64, status_address: u64, options: u64, rusage: u64) -> u64 {
    let parent_pid = current_linux_process_pid();
    // Any thread may wait for the children of its process.
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && current_linux_tid() != Some(parent_pid)
    {
        return LINUX_ECHILD;
    }
    let pid = pid as u32 as i32;
    let options = u64::from(options as u32);
    let scope = linux_wait_child_scope(options);
    let options = options & !LINUX_WAIT_SCOPE_FLAGS;
    if options & !(LINUX_WNOHANG | LINUX_WUNTRACED | LINUX_WCONTINUED) != 0 {
        return LINUX_EINVAL;
    }
    if status_address != 0 && !linux_writable_user_range_contains(status_address, size_of::<u32>())
    {
        return LINUX_EFAULT;
    }
    if rusage != 0 && !linux_writable_user_range_contains(rusage, LINUX_RUSAGE_SIZE) {
        return LINUX_EFAULT;
    }
    let selector = match pid {
        -1 => LinuxChildWaitSelector::Any,
        0 => {
            let Some(group) = linux_process::live_process_group(parent_pid) else {
                return LINUX_ECHILD;
            };
            LinuxChildWaitSelector::ProcessGroup(group)
        }
        1..=i32::MAX => LinuxChildWaitSelector::Process(pid as u32),
        i32::MIN => return LINUX_ESRCH,
        _ => LinuxChildWaitSelector::ProcessGroup(pid.unsigned_abs()),
    };
    let Some(state) = linux_child_wait_state(
        parent_pid,
        selector,
        linux_process::ChildWaitEvents {
            exited: true,
            stopped: options & LINUX_WUNTRACED != 0,
            continued: options & LINUX_WCONTINUED != 0,
            scope,
        },
    ) else {
        return LINUX_ECHILD;
    };
    // Linux's wait status: the exit code in bits 8-15, or the terminating
    // signal in bits 0-6, or 0x7f with the stop signal above it.
    let (waited, encoded, exit_status, reaped) = match state {
        linux_process::ChildWaitState::Exited {
            pid: waited,
            status,
            signal,
        } => (
            waited,
            if signal != 0 {
                u32::from(signal)
            } else {
                u32::from(status) << 8
            },
            status,
            true,
        ),
        linux_process::ChildWaitState::Stopped { pid, signal } => {
            (pid, u32::from(signal) << 8 | 0x7f, 0, false)
        }
        linux_process::ChildWaitState::Continued { pid } => (pid, 0xffff, 0, false),
        linux_process::ChildWaitState::Running => {
            return if options & LINUX_WNOHANG != 0 {
                0
            } else {
                LINUX_ENOSYS
            };
        }
    };
    if status_address != 0 && !copy_to_linux_user(status_address, &encoded.to_ne_bytes()) {
        return LINUX_EFAULT;
    }
    if rusage != 0 && !copy_to_linux_user(rusage, &[0_u8; LINUX_RUSAGE_SIZE]) {
        return LINUX_EFAULT;
    }
    if reaped {
        let child_maxrss = linux_process::live_process_maxrss(waited);
        let identity = linux_pidfd_identity(waited);
        if linux_reap_child(parent_pid, waited) != Some((waited, exit_status)) {
            return LINUX_ECHILD;
        }
        linux_pidfd_record_exit(waited, identity, encoded);
        if let Some(child_maxrss) = child_maxrss {
            linux_process::add_waited_child_maxrss(parent_pid, child_maxrss);
        }
    } else if !linux_process::consume_live_child_wait_event(parent_pid, waited) {
        return LINUX_ECHILD;
    }
    X86_RUNTIME
        .LINUX_PROCESS_WAIT_COUNT
        .fetch_add(1, Ordering::SeqCst);
    u64::from(waited)
}

pub(super) fn linux_waitid(
    id_type: u64,
    id: u64,
    information: u64,
    options: u64,
    rusage: u64,
) -> u64 {
    const SIGNAL_INFORMATION_SIZE: usize = size_of::<LinuxSignalInformation>();

    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && current_linux_tid() != Some(current_linux_process_pid())
    {
        return LINUX_ECHILD;
    }
    let id_type = u64::from(id_type as u32);
    let id = u64::from(id as u32);
    let options = u64::from(options as u32);
    let scope = linux_wait_child_scope(options);
    if options
        & !(LINUX_WEXITED
            | LINUX_WUNTRACED
            | LINUX_WCONTINUED
            | LINUX_WNOHANG
            | LINUX_WNOWAIT
            | LINUX_WAIT_SCOPE_FLAGS)
        != 0
        || options & (LINUX_WEXITED | LINUX_WUNTRACED | LINUX_WCONTINUED) == 0
    {
        return LINUX_EINVAL;
    }
    let (selector, nonblocking_pidfd) = match id_type {
        LINUX_P_ALL => (LinuxChildWaitSelector::Any, false),
        LINUX_P_PID if (1..=i32::MAX as u64).contains(&id) => {
            (LinuxChildWaitSelector::Process(id as u32), false)
        }
        LINUX_P_PID => return LINUX_EINVAL,
        LINUX_P_PGID if id <= i32::MAX as u64 => {
            let group = if id == 0 {
                let Some(group) = linux_process::live_process_group(current_linux_process_pid())
                else {
                    return LINUX_ECHILD;
                };
                group
            } else {
                id as u32
            };
            (LinuxChildWaitSelector::ProcessGroup(group), false)
        }
        LINUX_P_PGID => return LINUX_EINVAL,
        LINUX_P_PIDFD if id <= i32::MAX as u64 => {
            if !linux_pidfd_descriptor(id) {
                return LINUX_EBADF;
            }
            let Some(process) = linux_pidfd_process(id) else {
                return LINUX_ECHILD;
            };
            (
                LinuxChildWaitSelector::Process(process),
                linux_socket_flags(id).is_some_and(|flags| flags & LINUX_O_NONBLOCK as u32 != 0),
            )
        }
        LINUX_P_PIDFD => return LINUX_EBADF,
        _ => return LINUX_EINVAL,
    };
    if information != 0 && !linux_writable_user_range_contains(information, SIGNAL_INFORMATION_SIZE)
    {
        return LINUX_EFAULT;
    }
    if rusage != 0 && !linux_writable_user_range_contains(rusage, LINUX_RUSAGE_SIZE) {
        return LINUX_EFAULT;
    }
    let parent = current_linux_process_pid();
    // Exited children are visible only when WEXITED is asked for; brush polls
    // for stopped children with waitid(WSTOPPED | WNOHANG) and must not reap
    // the children its runtime waits for.
    let Some(state) = linux_child_wait_state(
        parent,
        selector,
        linux_process::ChildWaitEvents {
            exited: options & LINUX_WEXITED != 0,
            stopped: options & LINUX_WUNTRACED != 0,
            continued: options & LINUX_WCONTINUED != 0,
            scope,
        },
    ) else {
        return LINUX_ECHILD;
    };
    if state == linux_process::ChildWaitState::Running {
        if options & LINUX_WNOHANG == 0 {
            return if nonblocking_pidfd {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            };
        }
        if information != 0 && !copy_to_linux_user(information, &[0_u8; SIGNAL_INFORMATION_SIZE]) {
            return LINUX_EFAULT;
        }
        if rusage != 0 && !copy_to_linux_user(rusage, &[0_u8; LINUX_RUSAGE_SIZE]) {
            return LINUX_EFAULT;
        }
        return 0;
    };
    // si_code CLD_EXITED (si_status the exit code) or CLD_KILLED (the signal).
    let (pid, status, exit_status, code, reaped) = match state {
        linux_process::ChildWaitState::Exited {
            pid,
            status,
            signal,
        } => {
            // Bit 7 of the signal marks a core dump (CLD_DUMPED).
            const LINUX_CLD_DUMPED: i32 = 3;
            if signal & 0x80 != 0 {
                (
                    pid,
                    u32::from(signal & 0x7f),
                    status,
                    LINUX_CLD_DUMPED,
                    true,
                )
            } else if signal != 0 {
                (pid, u32::from(signal), status, LINUX_CLD_KILLED, true)
            } else {
                (pid, u32::from(status), status, LINUX_CLD_EXITED, true)
            }
        }
        linux_process::ChildWaitState::Stopped { pid, signal } => {
            (pid, u32::from(signal), 0, 5, false)
        }
        linux_process::ChildWaitState::Continued { pid } => (pid, 18, 0, 6, false),
        linux_process::ChildWaitState::Running => unreachable!(),
    };
    let mut result = [0_u8; SIGNAL_INFORMATION_SIZE];
    result[..4].copy_from_slice(&(LINUX_SIGCHLD as i32).to_ne_bytes());
    result[8..12].copy_from_slice(&code.to_ne_bytes());
    result[16..20].copy_from_slice(&pid.to_ne_bytes());
    let uid =
        linux_process::live_process_credentials(pid).map_or(0, |credentials| credentials.user.real);
    result[20..24].copy_from_slice(&uid.to_ne_bytes());
    result[24..28].copy_from_slice(&status.to_ne_bytes());
    if information != 0 && !copy_to_linux_user(information, &result) {
        return LINUX_EFAULT;
    }
    if rusage != 0 && !copy_to_linux_user(rusage, &[0_u8; LINUX_RUSAGE_SIZE]) {
        return LINUX_EFAULT;
    }
    if options & LINUX_WNOWAIT == 0 {
        if reaped {
            let child_maxrss = linux_process::live_process_maxrss(pid);
            let identity = linux_pidfd_identity(pid);
            if linux_reap_child(parent, pid) != Some((pid, exit_status)) {
                return LINUX_ECHILD;
            }
            // The wait4 status of the exit siginfo reports.
            let encoded = match code {
                LINUX_CLD_EXITED => status << 8,
                LINUX_CLD_KILLED => status,
                _ => status | 0x80,
            };
            linux_pidfd_record_exit(pid, identity, encoded);
            if let Some(child_maxrss) = child_maxrss {
                linux_process::add_waited_child_maxrss(parent, child_maxrss);
            }
        } else if !linux_process::consume_live_child_wait_event(parent, pid) {
            return LINUX_ECHILD;
        }
        X86_RUNTIME
            .LINUX_PROCESS_WAIT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    }
    0
}

pub(super) fn linux_waitid_live(
    output: LinuxSyscallFrameHandle,
    id_type: u64,
    id: u64,
    information: u64,
    options: u64,
    rusage: u64,
    caller: LinuxUserContext,
) -> u64 {
    let result = linux_waitid(id_type, id, information, options, rusage);
    if options as u32 as u64 & LINUX_WNOHANG != 0 {
        return linux_wait_nohang_live_return(result, caller);
    }
    if result != LINUX_ENOSYS {
        return result;
    }
    let pid = current_linux_process_pid();
    if linux_process::live_running_child_pid(pid).is_none() {
        return LINUX_ECHILD;
    }
    loop {
        // Blocked until a child changes state or a signal comes (see
        // linux_wait4_live).
        let turn = run_other_linux_processes(
            output,
            caller,
            LINUX_WAITID_SYSCALL,
            WaitOn::of(wait_events::CHILD),
        );
        match turn {
            Some(LinuxBlockedWait::Recheck) => {}
            // Yielded to start again from user mode: still blocked until a
            // wake or the dispatch that restarts it.
            Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL)) => {
                return LINUX_RETURN_TO_KERNEL;
            }
            Some(LinuxBlockedWait::Return(result)) => return result,
            None => return LINUX_ECHILD,
        }
        let result = linux_waitid(id_type, id, information, options, rusage);
        if result != LINUX_ENOSYS {
            return result;
        }
    }
}

pub(super) fn linux_wait4_live(
    output: LinuxSyscallFrameHandle,
    pid: u64,
    status_address: u64,
    options: u64,
    rusage: u64,
    caller: LinuxUserContext,
) -> u64 {
    let Ok(pid) = linux_pid_argument(pid) else {
        return LINUX_ECHILD;
    };
    // The child's number as the waiting process sees it.
    let seen = |result: u64| {
        if (1..=u64::from(u32::MAX)).contains(&result) {
            u64::from(linux_pid_seen_by(
                current_linux_process_pid(),
                result as u32,
            ))
        } else {
            result
        }
    };
    loop {
        let result = linux_wait4(pid, status_address, options, rusage);
        if options as u32 as u64 & LINUX_WNOHANG != 0 {
            return seen(linux_wait_nohang_live_return(result, caller));
        }
        if result != LINUX_ENOSYS {
            return seen(result);
        }
        // Blocked until a child (or tracee) changes state, which clears
        // `waiting` (linux_process's child wakes), or a signal it takes:
        // resumed in every scheduling round to look again, an LTP harness
        // waiting for its test was dispatched some twenty times for each
        // of futex_cmp_requeue01's thousand forks, which then took longer
        // than the children's five-second waits.
        match run_other_linux_processes(
            output,
            caller,
            LINUX_WAIT4_SYSCALL,
            WaitOn::of(wait_events::CHILD),
        ) {
            Some(LinuxBlockedWait::Recheck) => {}
            // Yielded to start again from user mode: still waiting.
            Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL)) => {
                return LINUX_RETURN_TO_KERNEL;
            }
            Some(LinuxBlockedWait::Return(result)) => return result,
            None => return LINUX_ECHILD,
        }
    }
}

/// A `WNOHANG` wait that found no child to report while a child can run
/// gives the CPU to other processes before returning 0, as Linux's scheduler
/// would preempt a caller polling in a loop: without it the children it
/// polls for never run. Children all waiting in system calls gain nothing
/// from it.
fn linux_wait_nohang_live_return(result: u64, caller: LinuxUserContext) -> u64 {
    if result == 0
        && current_linux_runtime_cpu_index() == 0
        && linux_process::live_runnable_child_exists(current_linux_process_pid())
        && yield_current_linux_process(caller, 0)
    {
        return LINUX_RETURN_TO_KERNEL;
    }
    result
}
