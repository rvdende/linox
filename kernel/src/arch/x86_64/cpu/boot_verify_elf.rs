use super::*;

#[inline(never)]
pub(crate) fn verify_linux_elf_entry(execution: &LinuxElfExecution<'_>) -> LinuxElfResult {
    // The runtime's own kernel work (its loop, forks, teardown) holds the
    // kernel-entry lock; the processes it enters release it in user mode.
    let _kernel_entry = crate::sync::kernel_entry_lock();
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        serial_write("linox: Linux ELF verifier rejected active runtime mode\r\n");
        return LinuxElfResult::FAILED;
    }
    let Some(heap_limit) = execution.heap.checked_add(execution.heap_size) else {
        serial_write("linox: Linux ELF verifier heap overflow\r\n");
        return LinuxElfResult::FAILED;
    };
    let stack_page = execution.stack & !(PAGE_SIZE - 1);
    let stack_size = if execution.runtime {
        LINUX_RUNTIME_STACK_PAGES * PAGE_SIZE
    } else {
        PAGE_SIZE
    };
    let Some(stack_base) = stack_page.checked_sub(stack_size - PAGE_SIZE) else {
        serial_write("linox: Linux ELF verifier stack underflow\r\n");
        return LinuxElfResult::FAILED;
    };
    let page_table_contract_valid = (5..=execution.page_table_frames.len())
        .contains(&execution.page_table_frame_count)
        && execution.page_table_frames[execution.page_table_frame_count..]
            .iter()
            .all(|frame| *frame == memory::FrameLease::EMPTY)
        && execution.page_table_frames[..execution.page_table_frame_count]
            .iter()
            .enumerate()
            .all(|(index, frame)| {
                memory::frames_owned_by(memory::FrameOwner::KERNEL, &[*frame])
                    && execution.page_table_frames[..index]
                        .iter()
                        .all(|prior| prior != frame)
            })
        && execution.page_table_frames[0].address() == address_space::current_root_address()
        && [
            stack_base,
            execution.heap,
            execution.mmap,
            execution.tls & !(PAGE_SIZE - 1),
            execution.sibling_tls & !(PAGE_SIZE - 1),
            execution.sibling_stack,
            execution.code,
            execution.loader_code,
            execution.data,
            execution.relro,
        ]
        .into_iter()
        .filter(|address| *address != 0)
        .all(|address| {
            address_space::current_linux_hierarchy_matches(
                address as u64,
                &execution.page_table_frames[..execution.page_table_frame_count],
            )
        })
        && execution.initial_image_mappings.len() <= LINUX_ACTIVE_IMAGE_MAPPING_LIMIT
        && execution.initial_image_mappings.iter().all(|mapping| {
            address_space::current_linux_hierarchy_matches(
                mapping.address as u64,
                &execution.page_table_frames[..execution.page_table_frame_count],
            )
        })
        && X86_RUNTIME
            .ELF_PROBE_RECLAIM_PAGE_TABLE_FRAMES
            .iter()
            .all(|frame| frame.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .ELF_PROBE_RECLAIM_PAGE_TABLE_GENERATIONS
            .iter()
            .all(|generation| generation.load(Ordering::SeqCst) == 0);
    let stale_page_table_lease_rejected = execution.page_table_frames[0]
        .generation()
        .checked_add(1)
        .and_then(|generation| {
            memory::FrameLease::from_parts(execution.page_table_frames[0].address(), generation)
        })
        .is_some_and(|stale| {
            !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[stale])
                && memory::frames_owned_by(
                    memory::FrameOwner::KERNEL,
                    &[execution.page_table_frames[0]],
                )
        });
    let stack_contract_valid = execution.stack != 0
        && stack_base != 0
        && execution.stack < stack_base + stack_size
        && memory::frames_owned_by(memory::FrameOwner::KERNEL, &[execution.stack_frame])
        && address_space::current_linux_mapping_matches(
            stack_page as u64,
            execution.stack_frame,
            true,
            false,
        );
    let heap_contract_valid = execution.heap != 0
        && execution.heap.is_multiple_of(PAGE_SIZE)
        && execution.heap_size
            == if execution.runtime {
                LINUX_RUNTIME_HEAP_PAGES * PAGE_SIZE
            } else {
                PAGE_SIZE
            }
        && execution.heap_frame != execution.stack_frame
        && address_space::current_linux_mapping_matches(
            execution.heap as u64,
            execution.heap_frame,
            true,
            false,
        );
    let initial_image_valid = if execution.initial_image_mappings.is_empty() {
        true
    } else {
        (1..=LINUX_ACTIVE_IMAGE_MAPPING_LIMIT).contains(&execution.initial_image_mappings.len())
            && execution
                .initial_image_mappings
                .iter()
                .enumerate()
                .all(|(index, mapping)| {
                    mapping.address != 0
                        && mapping.address.is_multiple_of(PAGE_SIZE)
                        && !(mapping.writable && mapping.executable)
                        && (memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
                            || memory::frame_lease_is_runtime(mapping.frame))
                        && execution.initial_image_mappings[..index]
                            .iter()
                            .all(|prior| {
                                prior.address != mapping.address && prior.frame != mapping.frame
                            })
                })
    };
    let retired_image_state_clean = X86_RUNTIME
        .ELF_PROBE_RETIRED_IMAGE_COUNT
        .load(Ordering::SeqCst)
        == 0
        && (0..LINUX_ACTIVE_IMAGE_MAPPING_LIMIT).all(|index| {
            X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_ADDRESSES[index].load(Ordering::SeqCst) == 0
                && X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_FRAMES[index].load(Ordering::SeqCst) == 0
                && X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_GENERATIONS[index].load(Ordering::SeqCst)
                    == 0
                && X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_FLAGS[index].load(Ordering::SeqCst) == 0
        });
    let heap_reclaim_state_clean = X86_RUNTIME
        .ELF_PROBE_RECLAIM_HEAP_FRAME
        .load(Ordering::SeqCst)
        == 0
        && X86_RUNTIME
            .ELF_PROBE_RECLAIM_HEAP_GENERATION
            .load(Ordering::SeqCst)
            == 0;
    let mmap_contract_valid = execution.mmap != 0
        && execution.mmap.is_multiple_of(PAGE_SIZE)
        && X86_RUNTIME
            .ELF_PROBE_MMAP_FRAMES
            .iter()
            .all(|frame| frame.load(Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .ELF_PROBE_MMAP_GENERATIONS
            .iter()
            .all(|generation| generation.load(Ordering::SeqCst) == 0);
    if !page_table_contract_valid
        || !stale_page_table_lease_rejected
        || !stack_contract_valid
        || !heap_contract_valid
        || !initial_image_valid
        || !retired_image_state_clean
        || !heap_reclaim_state_clean
        || !mmap_contract_valid
        || execution.exec_expected && execution.initial_image_mappings.is_empty()
    {
        serial_write("linox: Linux ELF initial contract rejection:");
        for valid in [
            page_table_contract_valid,
            stale_page_table_lease_rejected,
            stack_contract_valid,
            heap_contract_valid,
            initial_image_valid,
            retired_image_state_clean,
            heap_reclaim_state_clean,
            mmap_contract_valid,
        ] {
            serial_write(" ");
            serial_write_u64(u64::from(valid));
        }
        serial_write("\r\n");
        return LinuxElfResult::FAILED;
    }
    let initial_tls = LinuxTlsContext {
        thread_pointer: execution.initial_fs_base,
        extent: execution.tls,
        extent_size: execution.tls_size,
    };
    let sibling_tls = LinuxTlsContext {
        thread_pointer: execution.sibling_fs_base,
        extent: execution.sibling_tls,
        extent_size: execution.tls_size,
    };
    let tls_contract_valid = initial_tls.is_valid()
        && sibling_tls.is_valid()
        && (execution.tls_size == 0 && execution.sibling_stack == 0
            || execution.tls_size != 0
                && execution.sibling_stack != 0
                && execution.sibling_stack.is_multiple_of(PAGE_SIZE)
                && execution
                    .sibling_stack
                    .checked_add(PAGE_SIZE)
                    .is_some_and(|end| end <= 1 << 47)
                && execution.sibling_stack != (execution.stack & !(PAGE_SIZE - 1)))
        && (execution.tls_size == 0
            || !linux_ranges_overlap(
                initial_tls.extent as u64,
                initial_tls.extent_size,
                sibling_tls.extent as u64,
                sibling_tls.extent_size,
            ));
    let tls_frame_contract_valid = if execution.tls_size == 0 {
        execution.tls_frames == [memory::FrameLease::EMPTY; 2]
            && execution.sibling_stack_frame == memory::FrameLease::EMPTY
    } else {
        execution.tls_frames[0] != execution.tls_frames[1]
            && execution
                .tls_frames
                .iter()
                .all(|frame| *frame != execution.stack_frame && *frame != execution.heap_frame)
            && address_space::current_linux_mapping_matches(
                (execution.tls & !(PAGE_SIZE - 1)) as u64,
                execution.tls_frames[0],
                true,
                false,
            )
            && address_space::current_linux_mapping_matches(
                (execution.sibling_tls & !(PAGE_SIZE - 1)) as u64,
                execution.tls_frames[1],
                true,
                false,
            )
            && execution.sibling_stack_frame != execution.stack_frame
            && execution.sibling_stack_frame != execution.heap_frame
            && !execution
                .tls_frames
                .contains(&execution.sibling_stack_frame)
            && address_space::current_linux_mapping_matches(
                execution.sibling_stack as u64,
                execution.sibling_stack_frame,
                true,
                false,
            )
    };
    let tls_reclaim_state_clean = (0..2).all(|index| {
        X86_RUNTIME.ELF_PROBE_RECLAIM_TLS_FRAMES[index].load(Ordering::SeqCst) == 0
            && X86_RUNTIME.ELF_PROBE_RECLAIM_TLS_GENERATIONS[index].load(Ordering::SeqCst) == 0
    });
    let sibling_stack_reclaim_state_clean = X86_RUNTIME
        .ELF_PROBE_RECLAIM_SIBLING_STACK_FRAME
        .load(Ordering::SeqCst)
        == 0
        && X86_RUNTIME
            .ELF_PROBE_RECLAIM_SIBLING_STACK_GENERATION
            .load(Ordering::SeqCst)
            == 0;
    if !tls_contract_valid
        || !tls_frame_contract_valid
        || !tls_reclaim_state_clean
        || !sibling_stack_reclaim_state_clean
    {
        serial_write("linox: Linux ELF TLS contract rejection:");
        for valid in [
            tls_contract_valid,
            tls_frame_contract_valid,
            tls_reclaim_state_clean,
            sibling_stack_reclaim_state_clean,
        ] {
            serial_write(" ");
            serial_write_u64(u64::from(valid));
        }
        serial_write("\r\n");
        return LinuxElfResult::FAILED;
    }
    if X86_RUNTIME.ELF_PROBE_ACTIVE.swap(true, Ordering::SeqCst) {
        serial_write("linox: Linux ELF verifier rejected stale active probe\r\n");
        return LinuxElfResult::FAILED;
    }
    let Some(clock_frequency) = timer::monotonic_frequency()
        .filter(|frequency| *frequency <= u64::MAX / NANOSECONDS_PER_SECOND)
    else {
        serial_write("linox: Linux clock setup failed\r\n");
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return LinuxElfResult::FAILED;
    };
    let Some(saved_msrs) = configure_linux_syscall() else {
        serial_write("linox: Linux syscall setup failed\r\n");
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return LinuxElfResult::FAILED;
    };
    let thread_table_finished = finish_linux_thread_table();
    let linux_thread_lifecycle_valid = thread_table_finished
        && (|| -> Option<bool> {
            let initial_stack = execution.stack & !(PAGE_SIZE - 1);
            let initial_thread = reserve_linux_thread(initial_tls, stack_base, stack_size)?;
            if initial_thread.tid != 1 || !switch_linux_thread(initial_thread) {
                return Some(false);
            }
            if execution.tls_size == 0 {
                return Some(true);
            }
            let sibling_thread =
                reserve_linux_thread(sibling_tls, execution.sibling_stack, PAGE_SIZE)?;
            let initial_clear_child_tid_set = set_current_linux_clear_child_tid(0x1110);
            let initial_robust_list_set = set_current_linux_robust_list(0x1120);
            let sibling_selected = switch_linux_thread(sibling_thread);
            let sibling_tid_valid = current_linux_tid() == Some(2);
            let sibling_clear_child_tid_clean = current_linux_clear_child_tid() == Some(0);
            let sibling_robust_list_clean = current_linux_robust_list() == Some(0);
            let sibling_clear_child_tid_set = set_current_linux_clear_child_tid(0x2210);
            let sibling_robust_list_set = set_current_linux_robust_list(0x2220);
            let initial_selected = switch_linux_thread(initial_thread);
            let initial_tid_valid = current_linux_tid() == Some(1);
            let initial_clear_child_tid_valid = current_linux_clear_child_tid() == Some(0x1110);
            let initial_robust_list_valid = current_linux_robust_list() == Some(0x1120);
            let sibling_robust_list_valid = linux_thread_robust_list(2) == Ok(0x2220);
            if !execution.runtime {
                serial_write("linox: sibling robust-list metadata read\r\n");
            }
            let initial_clear_child_tid_cleared = set_current_linux_clear_child_tid(0);
            let initial_robust_list_cleared = set_current_linux_robust_list(0);
            if sibling_thread.tid != 2
                || X86_RUNTIME.LINUX_THREAD_STACK_BASES[usize::from(sibling_thread.slot)]
                    .load(Ordering::SeqCst)
                    != execution.sibling_stack as u64
                || X86_RUNTIME.LINUX_THREAD_STACK_SIZES[usize::from(sibling_thread.slot)]
                    .load(Ordering::SeqCst)
                    != PAGE_SIZE as u64
                || !initial_clear_child_tid_set
                || !initial_robust_list_set
                || !sibling_selected
                || !sibling_tid_valid
                || !sibling_clear_child_tid_clean
                || !sibling_robust_list_clean
                || !sibling_clear_child_tid_set
                || !sibling_robust_list_set
                || !initial_selected
                || !initial_tid_valid
                || !initial_clear_child_tid_valid
                || !initial_robust_list_valid
                || !sibling_robust_list_valid
                || X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[usize::from(sibling_thread.slot)]
                    .load(Ordering::SeqCst)
                    != 0x2210
                || X86_RUNTIME.LINUX_THREAD_ROBUST_LISTS[usize::from(sibling_thread.slot)]
                    .load(Ordering::SeqCst)
                    != 0x2220
                || !initial_clear_child_tid_cleared
                || !initial_robust_list_cleared
            {
                if !execution.runtime {
                    serial_write("linox: Linux TLS lifecycle pre-clone validation failed\r\n");
                    for valid in [
                        sibling_thread.tid == 2,
                        X86_RUNTIME.LINUX_THREAD_STACK_BASES[usize::from(sibling_thread.slot)]
                            .load(Ordering::SeqCst)
                            == execution.sibling_stack as u64,
                        X86_RUNTIME.LINUX_THREAD_STACK_SIZES[usize::from(sibling_thread.slot)]
                            .load(Ordering::SeqCst)
                            == PAGE_SIZE as u64,
                        initial_clear_child_tid_set,
                        initial_robust_list_set,
                        sibling_selected,
                        sibling_tid_valid,
                        sibling_clear_child_tid_clean,
                        sibling_robust_list_clean,
                        sibling_clear_child_tid_set,
                        sibling_robust_list_set,
                        initial_selected,
                        initial_tid_valid,
                        initial_clear_child_tid_valid,
                        initial_robust_list_valid,
                        sibling_robust_list_valid,
                        initial_clear_child_tid_cleared,
                        initial_robust_list_cleared,
                    ] {
                        serial_write_u64(u64::from(valid));
                        serial_write(" ");
                    }
                    serial_write("\r\n");
                }
                return Some(false);
            }
            let clone_request = LinuxCloneRequest {
                flags: LINUX_BOUNDED_THREAD_CLONE_FLAGS,
                child_stack: execution.sibling_stack.checked_add(PAGE_SIZE)? as u64,
                parent_tid: initial_stack.checked_add(64)? as u64,
                child_tid: initial_stack.checked_add(68)? as u64,
                tls: execution.sibling_fs_base as u64,
            };
            let proof_registers = LinuxSyscallFrame::from_array([
                0x15,
                0x14,
                0x13,
                0x12,
                0xb0,
                0xb1,
                0x10,
                9,
                8,
                clone_request.parent_tid,
                clone_request.child_stack,
                clone_request.flags,
            ]);
            let invalid_flags_rejected = construct_linux_clone_context(
                sibling_thread,
                LinuxCloneRequest {
                    flags: clone_request.flags | (1 << 63),
                    ..clone_request
                },
                proof_registers,
                execution.entry as u64,
                0x202,
                initial_stack as u64,
                PAGE_SIZE,
            )
            .is_none();
            let invalid_stack_rejected = construct_linux_clone_context(
                sibling_thread,
                LinuxCloneRequest {
                    child_stack: execution.sibling_stack.saturating_sub(8) as u64,
                    ..clone_request
                },
                proof_registers,
                execution.entry as u64,
                0x202,
                initial_stack as u64,
                PAGE_SIZE,
            )
            .is_none();
            let clone = construct_linux_clone_context(
                sibling_thread,
                clone_request,
                proof_registers,
                execution.entry as u64,
                0x202,
                initial_stack as u64,
                PAGE_SIZE,
            )?;
            let selected = linux_thread_return_context(sibling_thread)?;
            let interrupt_resume_context_valid =
                verify_linux_thread_interrupt_resume_context(sibling_thread, selected);
            let mut installed_registers = LinuxSyscallFrame::ZERO;
            let mut installed_rip = 0;
            let mut installed_rsp = 0;
            let mut installed_rflags = 0;
            let mut installed_rax = u64::MAX;
            let return_installed = install_linux_thread_return(
                sibling_thread,
                &mut installed_registers,
                &mut installed_rip,
                &mut installed_rsp,
                &mut installed_rflags,
                &mut installed_rax,
            );
            let sibling_copy_state =
                linux_writable_user_range_contains(
                    execution.sibling_tls as u64,
                    execution.tls_size,
                ) && !linux_writable_user_range_contains(execution.tls as u64, execution.tls_size);
            let initial_restored = switch_linux_thread(initial_thread);
            let initial_copy_state =
                linux_writable_user_range_contains(execution.tls as u64, execution.tls_size)
                    && !linux_writable_user_range_contains(
                        execution.sibling_tls as u64,
                        execution.tls_size,
                    );
            let sibling_slot = usize::from(sibling_thread.slot);
            if !invalid_flags_rejected
                || !invalid_stack_rejected
                || clone.parent_rax != u64::from(sibling_thread.tid)
                || clone.child.rip != execution.entry as u64
                || clone.child.rsp != clone_request.child_stack
                || clone.child.rflags != 0x202
                || clone.child.rax != 0
                || clone.child.fs_base != execution.sibling_fs_base as u64
                || clone.child.registers != proof_registers
                || selected != clone.child
                || !interrupt_resume_context_valid
                || !return_installed
                || installed_registers != clone.child.registers
                || installed_rip != clone.child.rip
                || installed_rsp != clone.child.rsp
                || installed_rflags != clone.child.rflags
                || installed_rax != clone.child.rax
                || !sibling_copy_state
                || !initial_restored
                || !initial_copy_state
                || X86_RUNTIME.LINUX_THREAD_RIPS[sibling_slot].load(Ordering::SeqCst)
                    != clone.child.rip
                || X86_RUNTIME.LINUX_THREAD_RSPS[sibling_slot].load(Ordering::SeqCst)
                    != clone.child.rsp
                || X86_RUNTIME.LINUX_THREAD_RFLAGS[sibling_slot].load(Ordering::SeqCst)
                    != clone.child.rflags
                || X86_RUNTIME.LINUX_THREAD_RAXS[sibling_slot].load(Ordering::SeqCst) != 0
                || X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[sibling_slot].load(Ordering::SeqCst)
                    != clone_request.child_tid
                || !retire_linux_thread(sibling_thread)
            {
                if !execution.runtime {
                    serial_write("linox: Linux clone lifecycle validation failed\r\n");
                    for valid in [
                        invalid_flags_rejected,
                        invalid_stack_rejected,
                        clone.parent_rax == u64::from(sibling_thread.tid),
                        clone.child.rip == execution.entry as u64,
                        clone.child.rsp == clone_request.child_stack,
                        clone.child.rflags == 0x202,
                        clone.child.rax == 0,
                        clone.child.fs_base == execution.sibling_fs_base as u64,
                        clone.child.registers == proof_registers,
                        selected == clone.child,
                        interrupt_resume_context_valid,
                        return_installed,
                        installed_registers == clone.child.registers,
                        installed_rip == clone.child.rip,
                        installed_rsp == clone.child.rsp,
                        installed_rflags == clone.child.rflags,
                        installed_rax == clone.child.rax,
                        sibling_copy_state,
                        initial_restored,
                        initial_copy_state,
                        X86_RUNTIME.LINUX_THREAD_RIPS[sibling_slot].load(Ordering::SeqCst)
                            == clone.child.rip,
                        X86_RUNTIME.LINUX_THREAD_RSPS[sibling_slot].load(Ordering::SeqCst)
                            == clone.child.rsp,
                        X86_RUNTIME.LINUX_THREAD_RFLAGS[sibling_slot].load(Ordering::SeqCst)
                            == clone.child.rflags,
                        X86_RUNTIME.LINUX_THREAD_RAXS[sibling_slot].load(Ordering::SeqCst) == 0,
                        X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[sibling_slot]
                            .load(Ordering::SeqCst)
                            == clone_request.child_tid,
                    ] {
                        serial_write_u64(u64::from(valid));
                        serial_write(" ");
                    }
                    serial_write("\r\n");
                }
                return Some(false);
            }
            let mut stale_registers = proof_registers;
            let mut stale_rip = 0x1111;
            let mut stale_rsp = 0x2222;
            let mut stale_rflags = 0x3333;
            let mut stale_rax = 0x4444;
            let stale_install_rejected = !install_linux_thread_return(
                sibling_thread,
                &mut stale_registers,
                &mut stale_rip,
                &mut stale_rsp,
                &mut stale_rflags,
                &mut stale_rax,
            ) && stale_registers == proof_registers
                && stale_rip == 0x1111
                && stale_rsp == 0x2222
                && stale_rflags == 0x3333
                && stale_rax == 0x4444
                && current_linux_tid() == Some(1);
            let replacement =
                reserve_linux_thread(sibling_tls, execution.sibling_stack, PAGE_SIZE)?;
            Some(
                stale_install_rejected
                    && replacement.tid == 3
                    && replacement.slot == sibling_thread.slot
                    && replacement.generation != sibling_thread.generation
                    && X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[usize::from(replacement.slot)]
                        .load(Ordering::SeqCst)
                        == 0
                    && X86_RUNTIME.LINUX_THREAD_ROBUST_LISTS[usize::from(replacement.slot)]
                        .load(Ordering::SeqCst)
                        == 0
                    && X86_RUNTIME.LINUX_THREAD_STACK_BASES[usize::from(replacement.slot)]
                        .load(Ordering::SeqCst)
                        == execution.sibling_stack as u64
                    && X86_RUNTIME.LINUX_THREAD_RIPS[usize::from(replacement.slot)]
                        .load(Ordering::SeqCst)
                        == 0
                    && X86_RUNTIME.LINUX_THREAD_RSPS[usize::from(replacement.slot)]
                        .load(Ordering::SeqCst)
                        == 0
                    && X86_RUNTIME.LINUX_THREAD_RFLAGS[usize::from(replacement.slot)]
                        .load(Ordering::SeqCst)
                        == 0
                    && X86_RUNTIME.LINUX_THREAD_RAXS[usize::from(replacement.slot)]
                        .load(Ordering::SeqCst)
                        == 0
                    && linux_thread_return_context(sibling_thread).is_none()
                    && linux_thread_return_context(replacement).is_none()
                    && !switch_linux_thread(sibling_thread)
                    && retire_linux_thread(replacement),
            )
        })()
        .unwrap_or(false);
    if !linux_thread_lifecycle_valid {
        serial_write("linox: Linux initial thread rejection\r\n");
        let _ = restore_linux_syscall(saved_msrs);
        let _ = finish_linux_thread_table();
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return LinuxElfResult::FAILED;
    }
    X86_RUNTIME
        .ELF_PROBE_COMPLETED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_EXIT_STATUS.store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_TERMINATION_SIGNAL
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PARENT_DEATH_SIGNAL
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EXEC_REPLACED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_EXEC_NODE.store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_LIVE_RETURN_VALIDATED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CHILD_EXIT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PARENT_RESUMED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_REQUESTED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_NEW_MOUNT_NAMESPACE
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_NEW_USER_NAMESPACE
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_CHILD_TID_ADDRESS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_CHILD_STACK
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_SHARE_VM
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_PIDFD_ADDRESS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_PARENT_TID_ADDRESS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_CGROUP_GENERATION
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_CLEAR_SIGHAND
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FORK_OWN_PAGES
        .store(false, Ordering::SeqCst);
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
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_EXEC_PID
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_YIELD_PID
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PROCESS_CHILD_STATUS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CURRENT_PROCESS_PID
        .store(1, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PROCESS_WAIT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_TTY_SESSION.store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_TTY_FOREGROUND_GROUP
        .store(0, Ordering::SeqCst);
    for (flag, value) in X86_RUNTIME
        .LINUX_TTY_TERMIOS_FLAGS
        .iter()
        .zip([0x500, 0x5, 0xbf, 0x8a3b])
    {
        flag.store(value, Ordering::SeqCst);
    }
    X86_RUNTIME.LINUX_TTY_LINE.store(0, Ordering::SeqCst);
    for (character, value) in X86_RUNTIME
        .LINUX_TTY_CONTROL_CHARACTERS
        .iter()
        .zip(LINUX_TTY_DEFAULT_CONTROL_CHARACTERS)
    {
        character.store(value, Ordering::SeqCst);
    }
    X86_RUNTIME
        .LIVE_FORK_PUBLIC_DIAGNOSTIC
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_VALIDATED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CLONE_DISPATCH_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_FIRST_CHILD_TID.store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CLONE_REUSE_VALIDATED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CHILD_GETTID_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_YIELD_SWITCH_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_LAST_PREEMPTED_THREAD_SLOT
        .store(LINUX_THREAD_SLOT_NONE, Ordering::Release);
    X86_RUNTIME
        .LINUX_CLONE_BUSY_REJECTION_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CLONE_INVALID_REJECTION_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CLONE_TID_FAULT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FUTEX_WAIT_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FUTEX_EXPLICIT_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FUTEX_EXIT_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FUTEX_WAIT_TIMEOUT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SLEEP_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SLEEP_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SLEEP_INTERRUPT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_TIMER_WAIT_EXPIRY_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_TIMER_WAIT_PREEMPTION_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_RUNTIME_PREEMPT_TICKS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_POLL_WAIT_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_POLL_WAIT_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_POLL_WAIT_TIMEOUT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_POLL_WAIT_INTERRUPT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EPOLL_WAIT_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EPOLL_WAIT_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EPOLL_WAIT_TIMEOUT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EPOLL_WAIT_INTERRUPT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EVENTFD_READ_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EVENTFD_READ_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EVENTFD_READ_INTERRUPT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EVENTFD_WRITE_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EVENTFD_WRITE_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EVENTFD_WRITE_INTERRUPT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PIPE_READ_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PIPE_READ_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PIPE_READ_INTERRUPT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PIPE_WRITE_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PIPE_WRITE_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PIPE_WRITE_INTERRUPT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_TIMERFD_READ_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_TIMERFD_READ_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_TIMERFD_READ_INTERRUPT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PPOLL_WAIT_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PPOLL_WAIT_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_PPOLL_WAIT_TIMEOUT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EPOLL_PWAIT_BLOCK_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EPOLL_PWAIT_WAKE_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EPOLL_PWAIT_TIMEOUT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_MASKED_WAIT_INTERRUPT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_WAIT_INTERRUPT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SYSTEM_INIT
        .store(execution.system_init, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SIBLING_FS_BASE
        .store(execution.sibling_fs_base as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SIBLING_TLS
        .store(execution.sibling_tls as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SIBLING_STACK
        .store(execution.sibling_stack as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SIBLING_STACK_FRAME
        .store(execution.sibling_stack_frame.address(), Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SIBLING_STACK_GENERATION
        .store(execution.sibling_stack_frame.generation(), Ordering::SeqCst);
    for index in 0..X86_RUNTIME.ELF_PROBE_PAGE_TABLE_FRAMES.len() {
        let frame = execution.page_table_frames[index];
        X86_RUNTIME.ELF_PROBE_PAGE_TABLE_FRAMES[index].store(frame.address(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PAGE_TABLE_GENERATIONS[index]
            .store(frame.generation(), Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_STACK
        .store(execution.stack as u64, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_STACK_LOW.store(
        (execution.stack & !(PAGE_SIZE - 1))
            .saturating_sub((LINUX_RUNTIME_STACK_PAGES - 1) * PAGE_SIZE) as u64,
        Ordering::SeqCst,
    );
    X86_RUNTIME
        .ELF_PROBE_STACK_FRAME
        .store(execution.stack_frame.address(), Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_STACK_GENERATION
        .store(execution.stack_frame.generation(), Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_CODE_BASE
        .store(execution.code as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_CODE_SIZE
        .store(execution.code_size as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_LOADER_CODE_BASE
        .store(execution.loader_code as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_LOADER_CODE_SIZE
        .store(execution.loader_code_size as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_DATA
        .store(execution.data as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_DATA_SIZE
        .store(execution.data_size as u64, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_EXEC_ENTRY.store(0, Ordering::SeqCst);
    for index in 0..LINUX_EXEC_MAPPING_LIMIT {
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_ADDRESSES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_FRAMES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_GENERATIONS[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_FLAGS[index].store(0, Ordering::SeqCst);
    }
    for (index, mapping) in execution.initial_image_mappings.iter().copied().enumerate() {
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[index]
            .store(mapping.address as u64, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index]
            .store(mapping.frame.address(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index]
            .store(mapping.frame.generation(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].store(
            u8::from(mapping.writable) | (u8::from(mapping.executable) << 1),
            Ordering::SeqCst,
        );
    }
    X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_COUNT.store(
        execution.initial_image_mappings.len() as u16,
        Ordering::SeqCst,
    );
    X86_RUNTIME
        .ELF_PROBE_RELRO
        .store(execution.relro as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_RELRO_SIZE
        .store(execution.relro_size as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_BRK
        .store(execution.heap as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_BRK_LIMIT
        .store(heap_limit as u64, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_HEAP_FRAME
        .store(execution.heap_frame.address(), Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_HEAP_GENERATION
        .store(execution.heap_frame.generation(), Ordering::SeqCst);
    for (index, frame) in execution.tls_frames.iter().copied().enumerate() {
        X86_RUNTIME.ELF_PROBE_TLS_FRAMES[index].store(frame.address(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_TLS_GENERATIONS[index].store(frame.generation(), Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_MMAP
        .store(execution.mmap as u64, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_MMAP_NEXT.store(
        if execution.runtime {
            LINUX_RUNTIME_DYNAMIC_MMAP_BASE
        } else {
            execution.mmap as u64
        },
        Ordering::SeqCst,
    );
    for frame in &X86_RUNTIME.ELF_PROBE_MMAP_FRAMES {
        frame.store(0, Ordering::SeqCst);
    }
    for generation in &X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS {
        generation.store(0, Ordering::SeqCst);
    }
    for index in 0..LINUX_RUNTIME_MMAP_SLOT_COUNT {
        X86_RUNTIME.ELF_PROBE_MMAP_PAGES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_FILE[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MMAP_SEALED[index].store(false, Ordering::SeqCst);
    }
    for (index, mapping) in execution.main_mappings.iter().copied().enumerate() {
        let protection = LINUX_PROT_READ
            | if mapping.writable {
                LINUX_PROT_WRITE
            } else {
                0
            }
            | if mapping.executable {
                LINUX_PROT_EXEC
            } else {
                0
            };
        X86_RUNTIME.ELF_PROBE_MAIN_ADDRESSES[index].store(mapping.address as u64, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MAIN_FRAMES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MAIN_GENERATIONS[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MAIN_OFFSETS[index].store(mapping.offset, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MAIN_FILE_SIZES[index]
            .store(mapping.file_size as u64, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_MAIN_PROTECTIONS[index].store(protection as u8, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_MAIN_MAPPINGS
        .store(0, Ordering::SeqCst);
    for (dependency, mappings) in execution.dependency_mappings.iter().enumerate() {
        X86_RUNTIME.ELF_PROBE_DEPENDENCY_BASE_MIN[dependency].store(
            execution.dependency_base_min[dependency] as u64,
            Ordering::SeqCst,
        );
        X86_RUNTIME.ELF_PROBE_DEPENDENCY_BASE_END[dependency].store(
            execution.dependency_base_end[dependency] as u64,
            Ordering::SeqCst,
        );
        X86_RUNTIME.ELF_PROBE_DEPENDENCY_SELECTED_BASE[dependency].store(0, Ordering::SeqCst);
        for (index, mapping) in mappings.iter().copied().enumerate() {
            let state = dependency * LINUX_DEPENDENCY_MAPPING_COUNT + index;
            let protection = LINUX_PROT_READ
                | if mapping.writable {
                    LINUX_PROT_WRITE
                } else {
                    0
                }
                | if mapping.executable {
                    LINUX_PROT_EXEC
                } else {
                    0
                };
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_RELATIVES[state]
                .store(mapping.relative_address as u64, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_FRAMES[state].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_GENERATIONS[state].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_OFFSETS[state].store(mapping.offset, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_FILE_SIZES[state]
                .store(mapping.file_size as u64, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_PROTECTIONS[state]
                .store(protection as u8, Ordering::SeqCst);
        }
        X86_RUNTIME.ELF_PROBE_DEPENDENCY_MAPPINGS[dependency].store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_EXITED_CLEAR_CHILD_TID
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EXITED_ROBUST_LIST
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_READ_ONLY_DATA_PAGE
        .store(0, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_UMASK.store(0o022, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FSIZE_LIMIT_HIT
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_POSIX_MQ_BYTES
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_CROSS_PROCESS_PRLIMIT_VALIDATED
        .store(false, Ordering::SeqCst);
    for resource in 0..LINUX_RLIMIT_NLIMITS {
        let Some(limit) = linux_default_resource_limit(resource, execution.runtime) else {
            serial_write("linox: Linux resource-limit initialization failed\r\n");
            return LinuxElfResult::FAILED;
        };
        let index = resource as usize * 2;
        X86_RUNTIME.ELF_PROBE_RLIMITS[index].store(limit[0], Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_RLIMITS[index + 1].store(limit[1], Ordering::SeqCst);
    }
    X86_RUNTIME.ELF_PROBE_CONSOLE_DESCRIPTORS.store(
        (LINUX_DESCRIPTOR_INPUT | (LINUX_DESCRIPTOR_OUTPUT << 2)) as u8,
        Ordering::SeqCst,
    );
    X86_RUNTIME
        .ELF_PROBE_STDERR_OPEN
        .store(execution.runtime, Ordering::SeqCst);
    for word in &X86_RUNTIME.ELF_PROBE_CONSOLE_CLOEXEC {
        word.store(0, Ordering::SeqCst);
    }
    for table in [
        &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_CREATED,
        &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_READ_LEASES,
        &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_WRITE_LEASES,
    ] {
        for word in table.iter() {
            word.store(0, Ordering::SeqCst);
        }
    }
    for descriptor in &X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS {
        descriptor.store(0, Ordering::SeqCst);
    }
    for descriptor in &X86_RUNTIME.ELF_PROBE_ROOTFS_DESCRIPTORS {
        descriptor.store(0, Ordering::SeqCst);
    }
    for slot in &X86_RUNTIME.ELF_PROBE_SOCKET_SLOTS {
        slot.store(0, Ordering::SeqCst);
    }
    for flags in &X86_RUNTIME.ELF_PROBE_SOCKET_FLAGS {
        flags.store(0, Ordering::SeqCst);
    }
    for slot in &X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS {
        slot.store(0, Ordering::SeqCst);
    }
    for flags in &X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS {
        flags.store(0, Ordering::SeqCst);
    }
    for generation in &X86_RUNTIME.ELF_PROBE_TMP_FILE_GENERATIONS {
        generation.store(0, Ordering::SeqCst);
    }
    // A runtime starts with no inotify instances, fanotify groups or
    // io_uring rings of its domain.
    let domain = linux_execution_instance();
    crate::linux_inotify::release(domain, None, 0);
    crate::linux_fanotify::release(domain, None, 0);
    crate::linux_io_uring::release(domain, None, 0);
    for descriptor in &X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS {
        descriptor.store(0, Ordering::SeqCst);
    }
    for descriptor in &X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS {
        descriptor.store(0, Ordering::SeqCst);
    }
    for generation in &X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS {
        generation.store(0, Ordering::SeqCst);
    }
    for offset in &X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS {
        offset.store(0, Ordering::SeqCst);
    }
    for id in &X86_RUNTIME.ELF_PROBE_STDIO_OPEN_FILE_IDS {
        id.store(0, Ordering::SeqCst);
    }
    for id in &X86_RUNTIME.ELF_PROBE_OPEN_FILE_IDS {
        id.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .LINUX_NEXT_OPEN_FILE_ID
        .store(1, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_CWD
        .store(LINUX_ROOT_DIRECTORY, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ROOTFS_CWD
        .store(crate::published_rootfs::ROOT_HANDLE, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EPOLL_DESCRIPTOR
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_DESCRIPTOR_OVERFLOW
        .store(0, Ordering::SeqCst);
    for descriptor in 0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize {
        X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[descriptor].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EPOLL_DATA[descriptor].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[descriptor].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[descriptor].store(0, Ordering::SeqCst);
    }
    for active in &X86_RUNTIME.LINUX_RUNTIME_EPOLL_ACTIVE {
        active.store(0, Ordering::SeqCst);
    }
    for alias in &X86_RUNTIME.LINUX_RUNTIME_EPOLL_ALIASES {
        alias.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_EVENTFD_DESCRIPTOR
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EVENTFD_COUNTER
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EVENTFD_FLAGS
        .store(0, Ordering::SeqCst);
    for index in 0..LINUX_DEVICE_DESCRIPTOR_COUNT {
        X86_RUNTIME.LINUX_RUNTIME_EVENTFD_ACTIVE[index].store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_TIMERFD_DESCRIPTOR
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_TIMERFD_CLOCK
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_TIMERFD_FLAGS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_TIMERFD_INTERVAL
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_TIMERFD_DEADLINE
        .store(0, Ordering::SeqCst);
    for index in 0..LINUX_DEVICE_DESCRIPTOR_COUNT {
        X86_RUNTIME.LINUX_RUNTIME_TIMERFD_ACTIVE[index].store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_POSIX_TIMER_ACTIVE
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_POSIX_TIMER_INTERVAL
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_POSIX_TIMER_DEADLINE
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_INTERVAL
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_DEADLINE
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_READ_DESCRIPTOR
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_READ_FLAGS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PIPE_WRITE_FLAGS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.store(0, Ordering::SeqCst);
    for byte in &X86_RUNTIME.ELF_PROBE_PIPE_BUFFER {
        byte.store(0, Ordering::SeqCst);
    }
    if !crate::linux_file_cache::reset_current()
        || !linux_tmpfs::teardown()
        || !crate::linux_overlay::teardown()
        || execution.runtime && !prepare_configured_linux_system_domain()
    {
        serial_write("linox: Linux runtime filesystem preparation failed\r\n");
        return LinuxElfResult::FAILED;
    }
    for cursor in &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_OFFSETS {
        cursor.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_CLOCK_FREQUENCY
        .store(clock_frequency, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_CLOCK_EPOCH
        .store(timer::timestamp_counter(), Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_LOW
        .store(LINUX_INITIAL_PROCESS_NAME, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_HIGH
        .store(0, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_DUMPABLE.store(true, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_TSC_SIGSEGV
        .store(false, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_SECUREBITS.store(0, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_PERSONALITY.store(0, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_NICE.store(20, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_IOPRIO.store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_RUNTIME_EXIT_STATUS
        .store(u64::MAX, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_RUNTIME_FIRST_UNSUPPORTED_SYSCALL
        .store(u64::MAX, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_RUNTIME_SYSCALL_TRACE_COUNT
        .store(0, Ordering::SeqCst);
    if cfg!(feature = "linux-boot-profile") {
        for count in &X86_RUNTIME.LINUX_BOOT_PROFILE_SYSCALL_COUNTS {
            count.store(0, Ordering::Relaxed);
        }
        for ticks in &X86_RUNTIME.LINUX_BOOT_PROFILE_SYSCALL_TICKS {
            ticks.store(0, Ordering::Relaxed);
        }
        X86_RUNTIME
            .LINUX_BOOT_PROFILE_SAVE_COUNT
            .store(0, Ordering::Relaxed);
        X86_RUNTIME
            .LINUX_BOOT_PROFILE_SAVE_TICKS
            .store(0, Ordering::Relaxed);
        X86_RUNTIME
            .LINUX_BOOT_PROFILE_RESTORE_COUNT
            .store(0, Ordering::Relaxed);
        X86_RUNTIME
            .LINUX_BOOT_PROFILE_RESTORE_TICKS
            .store(0, Ordering::Relaxed);
        for count in &X86_RUNTIME.LINUX_BOOT_PROFILE_LIFECYCLE_COUNTS {
            count.store(0, Ordering::Relaxed);
        }
        for ticks in &X86_RUNTIME.LINUX_BOOT_PROFILE_LIFECYCLE_TICKS {
            ticks.store(0, Ordering::Relaxed);
        }
    }
    X86_RUNTIME
        .LINUX_RUNTIME_CONSOLE_TIMING_WRITTEN
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_TIMED_WAITS_ACTIVE
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_DESCRIPTOR_WAITS_ACTIVE
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_RUNTIME_SLOW_DIAGNOSTIC_WRITTEN
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_RUNTIME_LATE_DIAGNOSTIC_WRITTEN
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_RUNTIME_STALLED_DIAGNOSTIC_WRITTEN
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EPOLL_LAST_READY_DESCRIPTOR
        .store(u64::MAX, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EPOLL_LAST_READY_EVENTS
        .store(0, Ordering::SeqCst);
    for syscall in &X86_RUNTIME.LINUX_RUNTIME_SYSCALL_TRACE {
        syscall.store(u64::MAX, Ordering::SeqCst);
    }
    for result in &X86_RUNTIME.LINUX_RUNTIME_SYSCALL_RESULT_TRACE {
        result.store(0, Ordering::SeqCst);
    }
    for unsupported in &X86_RUNTIME.LINUX_RUNTIME_UNSUPPORTED_SYSCALLS {
        unsupported.store(0, Ordering::SeqCst);
    }
    for invalid in &X86_RUNTIME.LINUX_RUNTIME_EINVAL_SYSCALLS {
        invalid.store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_NO_NEW_PRIVS
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SECCOMP_STRICT
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SECCOMP_FILTERED
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_MEMBARRIER_REGISTRATIONS
        .store(0, Ordering::SeqCst);
    store_current_linux_signal_mask(0);
    X86_RUNTIME
        .ELF_PROBE_PENDING_SIGNALS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EXEC_IGNORED_SIGNALS
        .store(0, Ordering::SeqCst);
    for signal in 0..LINUX_SIGNAL_COUNT {
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[signal].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[signal].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[signal].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[signal].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[signal].store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_POINTER
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_SIZE
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_FLAGS
        .store(LINUX_SS_DISABLE, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_ACTIVE
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_DELIVERY_COUNT
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_RETURN_COUNT
        .store(0, Ordering::SeqCst);
    unsafe { linux_signal_context().get().write(LinuxSignalContext::ZERO) };
    let linux_clone_publication_valid = if execution.tls_size == 0 {
        true
    } else {
        (|| -> Option<bool> {
            let initial_stack = execution.stack & !(PAGE_SIZE - 1);
            let parent_tid = initial_stack.checked_add(128)? as u64;
            let child_tid = initial_stack.checked_add(132)? as u64;
            let child = reserve_linux_thread(sibling_tls, execution.sibling_stack, PAGE_SIZE)?;
            let request = LinuxCloneRequest {
                flags: LINUX_BOUNDED_THREAD_CLONE_FLAGS,
                child_stack: execution.sibling_stack.checked_add(PAGE_SIZE)? as u64,
                parent_tid,
                child_tid,
                tls: execution.sibling_fs_base as u64,
            };
            let rollback_request = LinuxCloneRequest {
                parent_tid: execution.sibling_stack as u64,
                child_tid: execution.sibling_stack.checked_add(4)? as u64,
                ..request
            };
            let rollback_rejected = matches!(
                publish_linux_clone(
                    child,
                    rollback_request,
                    LinuxSyscallFrame::ZERO,
                    execution.entry as u64,
                    0x202,
                    execution.sibling_stack as u64,
                    PAGE_SIZE,
                ),
                Err(LinuxClonePublishError::TidFault)
            );
            let slot = usize::from(child.slot);
            let rollback_clean = X86_RUNTIME.LINUX_THREAD_RIPS[slot].load(Ordering::SeqCst) == 0
                && X86_RUNTIME.LINUX_THREAD_RSPS[slot].load(Ordering::SeqCst) == 0
                && X86_RUNTIME.LINUX_THREAD_RFLAGS[slot].load(Ordering::SeqCst) == 0
                && X86_RUNTIME.LINUX_THREAD_RAXS[slot].load(Ordering::SeqCst) == 0
                && X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[slot].load(Ordering::SeqCst) == 0
                && X86_RUNTIME.LINUX_THREAD_REGISTERS[slot]
                    .iter()
                    .all(|register| register.load(Ordering::SeqCst) == 0);
            let mut saved_parent_tid = [0_u8; size_of::<u32>()];
            let mut saved_child_tid = [0_u8; size_of::<u32>()];
            if !copy_from_linux_user(parent_tid, &mut saved_parent_tid)
                || !copy_from_linux_user(child_tid, &mut saved_child_tid)
            {
                return None;
            }
            let published = publish_linux_clone(
                child,
                request,
                LinuxSyscallFrame::ZERO,
                execution.entry as u64,
                0x202,
                initial_stack as u64,
                PAGE_SIZE,
            )
            .ok()?;
            let selected = linux_thread_return_context(child)?;
            let mut published_parent_tid = [0_u8; size_of::<u32>()];
            let mut published_child_tid = [0_u8; size_of::<u32>()];
            let publication_visible = copy_from_linux_user(parent_tid, &mut published_parent_tid)
                && copy_from_linux_user(child_tid, &mut published_child_tid)
                && u32::from_ne_bytes(published_parent_tid) == child.tid
                && u32::from_ne_bytes(published_child_tid) == child.tid
                && copy_to_linux_user(parent_tid, &saved_parent_tid)
                && copy_to_linux_user(child_tid, &saved_child_tid);
            Some(
                rollback_rejected
                    && rollback_clean
                    && published.parent_rax == u64::from(child.tid)
                    && selected == published.child
                    && publication_visible
                    && X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[slot].load(Ordering::SeqCst)
                        == child_tid
                    && retire_linux_thread(child)
                    && X86_RUNTIME.LINUX_THREAD_RIPS[slot].load(Ordering::SeqCst) == 0
                    && X86_RUNTIME.LINUX_THREAD_CLEAR_CHILD_TIDS[slot].load(Ordering::SeqCst) == 0,
            )
        })()
        .unwrap_or(false)
    };
    let tls_copy_bounds_valid = execution.tls_size == 0
        || linux_writable_user_range_contains(execution.tls as u64, execution.tls_size)
            && !linux_writable_user_range_contains(
                execution.sibling_tls as u64,
                execution.tls_size,
            )
            && !linux_writable_user_range_contains(execution.sibling_stack as u64, PAGE_SIZE)
            && execution
                .tls
                .checked_sub(1)
                .is_some_and(|before| !linux_writable_user_range_contains(before as u64, 1))
            && execution
                .tls
                .checked_add(execution.tls_size - 1)
                .is_some_and(|last| !linux_writable_user_range_contains(last as u64, 2));
    let tls_context_switch_valid = if execution.tls_size == 0 {
        true
    } else {
        let sibling_installed = install_linux_tls_context(sibling_tls);
        let sibling_valid = sibling_installed
            && linux_writable_user_range_contains(execution.sibling_tls as u64, execution.tls_size)
            && !linux_writable_user_range_contains(execution.tls as u64, execution.tls_size)
            && {
                let mut value = [0_u8; size_of::<u64>()];
                copy_from_linux_user(execution.sibling_fs_base as u64, &mut value)
                    && u64::from_ne_bytes(value) == execution.sibling_fs_base as u64
            };
        let initial_restored = install_linux_tls_context(initial_tls);
        sibling_valid
            && initial_restored
            && linux_writable_user_range_contains(execution.tls as u64, execution.tls_size)
            && !linux_writable_user_range_contains(execution.sibling_tls as u64, execution.tls_size)
    };
    let linux_wait_timer_armed = timer::arm_linux_wait_timer();
    if !linux_wait_timer_armed {
        serial_write("linox: Linux wait timer setup failed\r\n");
        let _ = restore_linux_syscall(saved_msrs);
        let _ = finish_linux_thread_table();
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return LinuxElfResult::FAILED;
    }
    if !linux_mount::activate_initial() {
        serial_write("linox: Linux mount setup failed\r\n");
        let _ = timer::finish_linux_wait_timer();
        let _ = restore_linux_syscall(saved_msrs);
        let _ = finish_linux_thread_table();
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return LinuxElfResult::FAILED;
    }
    X86_RUNTIME
        .LINUX_RUNTIME_MODE
        .store(execution.runtime, Ordering::SeqCst);
    if execution.runtime {
        X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_REQUESTED
            .store(false, Ordering::Release);
        X86_RUNTIME
            .LINUX_RUNTIME_SUSPENDED
            .store(false, Ordering::Release);
        if let Some(slot) = active_container_slot() {
            X86_RUNTIME.CONTAINER_EXEC_CHILD[slot].store(0, Ordering::Release);
        }
    }
    if !install_live_linux_process_registry(execution.entry, execution.stack, active_fs_base()) {
        serial_write("linox: Linux process registry setup failed\r\n");
        X86_RUNTIME
            .LINUX_RUNTIME_MODE
            .store(false, Ordering::SeqCst);
        let _ = linux_mount::deactivate_initial();
        let _ = timer::finish_linux_wait_timer();
        let _ = restore_linux_syscall(saved_msrs);
        let _ = finish_linux_thread_table();
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return LinuxElfResult::FAILED;
    }
    if cfg!(feature = "verification-boot")
        && !execution.runtime
        && !verify_linux_sysv_shared_memory_syscalls()
    {
        serial_write("linox: Linux SysV verification failed\r\n");
        let _ = linux_process::finish_live_process_registry(0);
        let _ = linux_mount::deactivate_initial();
        let _ = timer::finish_linux_wait_timer();
        let _ = restore_linux_syscall(saved_msrs);
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return LinuxElfResult::FAILED;
    }
    if execution.runtime && !restore_container_extended_state() {
        let _ = linux_process::finish_runtime_process_registry();
        let _ = linux_mount::deactivate_initial();
        let _ = timer::finish_linux_wait_timer();
        let _ = restore_linux_syscall(saved_msrs);
        let _ = finish_linux_thread_table();
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return LinuxElfResult::FAILED;
    }
    let privilege_entry_nmi_probe = cfg!(feature = "verification-boot") && !execution.runtime;
    if privilege_entry_nmi_probe {
        PRIVILEGE_ENTRY_NMI_PROBE_HITS.store(0, Ordering::SeqCst);
        PRIVILEGE_ENTRY_NMI_PROBE_MASK.store(PRIVILEGE_ENTRY_NMI_STAGE_MASK, Ordering::SeqCst);
    }
    let user_entered = if execution.runtime {
        // A domain's init is ready in the run queue with the context its
        // registry entry holds (this entry point and stack); the runtime
        // loop enters it as it enters every process, on an activation stack
        // of its own. Its kernel state is saved first, as a process's is
        // whenever it leaves the CPU.
        let valid = address_space::current_user_entry_context_is_valid(
            execution.entry as u64,
            execution.stack as u64,
        ) && linux_process::start_runtime_scheduler();
        if valid {
            save_current_linux_process_runtime_state(1);
        }
        valid && save_linux_process_extended_state(1)
    } else {
        unsafe { enter_user(execution.entry, execution.stack, 0, 0, 0, 0, 0, 0, 0) }
    };
    if !user_entered {
        if execution.runtime {
            let _ = linux_process::finish_runtime_process_registry();
        } else {
            let _ = linux_process::finish_live_process_registry(0);
        }
        X86_RUNTIME
            .LINUX_RUNTIME_MODE
            .store(false, Ordering::Release);
        let _ = linux_mount::deactivate_initial();
        let _ = timer::finish_linux_wait_timer();
        let _ = restore_linux_syscall(saved_msrs);
        let _ = finish_linux_thread_table();
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        PRIVILEGE_ENTRY_NMI_PROBE_MASK.store(0, Ordering::SeqCst);
        return LinuxElfResult::FAILED;
    }
    let privilege_entry_nmi_valid = !privilege_entry_nmi_probe
        || PRIVILEGE_ENTRY_NMI_PROBE_MASK.swap(0, Ordering::SeqCst) == 0
            && PRIVILEGE_ENTRY_NMI_PROBE_HITS.swap(0, Ordering::SeqCst)
                == PRIVILEGE_ENTRY_NMI_STAGE_COUNT;
    if execution.runtime {
        if X86_RUNTIME.LINUX_RUNTIME_SUSPENDED.load(Ordering::Acquire) {
            let state_saved = save_container_extended_state();
            let registry_suspended =
                state_saved && linux_process::suspend_runtime_process_registry();
            let mount_deactivated = registry_suspended && linux_mount::deactivate_initial();
            let timer_finished = timer::finish_linux_wait_timer();
            let msrs_restored = restore_linux_syscall(saved_msrs);
            X86_RUNTIME
                .LINUX_RUNTIME_MODE
                .store(false, Ordering::Release);
            return LinuxElfResult {
                valid: mount_deactivated && timer_finished && msrs_restored,
                suspended: mount_deactivated && timer_finished && msrs_restored,
                ..LinuxElfResult::FAILED
            };
        }
        return run_linux_runtime(execution.mmap as u64, saved_msrs, None);
    }
    let live_fork_requested = X86_RUNTIME.LINUX_FORK_REQUESTED.load(Ordering::SeqCst);
    let live_fork_executed = execute_deferred_live_fork();
    let live_process_registry_finished = live_fork_executed
        && linux_process::finish_live_process_registry(if live_fork_requested { 2 } else { 0 });
    if !live_process_registry_finished {
        serial_write("linox: live Linux fork stages: ");
        serial_write_u64(u64::from(live_fork_executed));
        serial_write(" ");
        serial_write_u64(u64::from(linux_process::live_fork_execution_stage()));
        serial_write(" ");
        serial_write_u64(u64::from(linux_process::live_fork_child_diagnostic()));
        serial_write(" ");
        serial_write_u64(u64::from(
            X86_RUNTIME
                .PROCESS_CHILD_EXECUTION_DIAGNOSTIC
                .get(current_cpu_index())
                .expect("current processor index is bounded")
                .load(Ordering::SeqCst),
        ));
        serial_write(" ");
        serial_write_u64(u64::from(
            X86_RUNTIME
                .LIVE_FORK_PUBLIC_DIAGNOSTIC
                .load(Ordering::SeqCst),
        ));
        serial_write(" ");
        serial_write_u64(u64::from(
            X86_RUNTIME.LINUX_PROCESS_WAIT_COUNT.load(Ordering::SeqCst),
        ));
        serial_write("\r\n");
    }
    // Process exit closes every descriptor.  The deferred verification fork
    // restores the parent's saved table while it runs, so perform the final
    // close after that child has completed and the registry is quiescent.
    let linux_descriptors_closed = linux_close_all_descriptors();
    let linux_wait_timer_finished = timer::finish_linux_wait_timer();
    let msrs_restored = restore_linux_syscall(saved_msrs);
    let linux_thread_table_released = finish_linux_thread_table();
    let inactive = !X86_RUNTIME.ELF_PROBE_ACTIVE.swap(false, Ordering::SeqCst);
    let completed = X86_RUNTIME.ELF_PROBE_COMPLETED.load(Ordering::SeqCst);
    let exit_status = X86_RUNTIME.ELF_PROBE_EXIT_STATUS.swap(0, Ordering::SeqCst);
    let termination_signal = X86_RUNTIME
        .ELF_PROBE_TERMINATION_SIGNAL
        .swap(0, Ordering::SeqCst);
    let exec_replaced = X86_RUNTIME
        .ELF_PROBE_EXEC_REPLACED
        .swap(false, Ordering::SeqCst);
    let exec_node = X86_RUNTIME.ELF_PROBE_EXEC_NODE.swap(0, Ordering::SeqCst);
    let selected_static_exec_plan = if exec_replaced {
        initramfs::published_file_by_node(exec_node)
            .and_then(crate::linux_elf::measured_static_exec_plan)
    } else {
        None
    };
    let selected_interpreted_exec_plan = if exec_replaced
        && selected_static_exec_plan.is_none()
        && initramfs::published_file_name_by_node(exec_node) == Some(b"linux/init")
    {
        linux_measured_interpreted_exec_plan()
    } else {
        None
    };
    let selected_exec_plan = selected_static_exec_plan.as_ref().or_else(|| {
        selected_interpreted_exec_plan
            .as_ref()
            .map(|plan| &plan.process.interpreter)
    });
    let selected_runtime_plan = selected_static_exec_plan.as_ref().or_else(|| {
        selected_interpreted_exec_plan
            .as_ref()
            .map(|plan| &plan.process.main)
    });
    let selected_exec_mappings = selected_exec_plan
        .as_ref()
        .and_then(|plan| linux_exec_mapping_plan(plan));
    let interpreted_exec_replaced = selected_interpreted_exec_plan.is_some();
    let live_return_validated = X86_RUNTIME
        .LINUX_LIVE_RETURN_VALIDATED
        .swap(false, Ordering::SeqCst);
    let child_exit_count = X86_RUNTIME.LINUX_CHILD_EXIT_COUNT.swap(0, Ordering::SeqCst);
    let parent_resumed = X86_RUNTIME
        .LINUX_PARENT_RESUMED
        .swap(false, Ordering::SeqCst);
    let process_snapshot_validated = X86_RUNTIME
        .LINUX_PROCESS_SNAPSHOT_VALIDATED
        .swap(false, Ordering::SeqCst);
    let clone_dispatch_count = X86_RUNTIME
        .LINUX_CLONE_DISPATCH_COUNT
        .swap(0, Ordering::SeqCst);
    let first_child_tid = X86_RUNTIME.LINUX_FIRST_CHILD_TID.swap(0, Ordering::SeqCst);
    let clone_reuse_validated = X86_RUNTIME
        .LINUX_CLONE_REUSE_VALIDATED
        .swap(false, Ordering::SeqCst);
    let child_gettid_count = X86_RUNTIME
        .LINUX_CHILD_GETTID_COUNT
        .swap(0, Ordering::SeqCst);
    let yield_switch_count = X86_RUNTIME
        .LINUX_YIELD_SWITCH_COUNT
        .swap(0, Ordering::SeqCst);
    let clone_busy_rejection_count = X86_RUNTIME
        .LINUX_CLONE_BUSY_REJECTION_COUNT
        .swap(0, Ordering::SeqCst);
    let clone_invalid_rejection_count = X86_RUNTIME
        .LINUX_CLONE_INVALID_REJECTION_COUNT
        .swap(0, Ordering::SeqCst);
    let clone_tid_fault_count = X86_RUNTIME
        .LINUX_CLONE_TID_FAULT_COUNT
        .swap(0, Ordering::SeqCst);
    let futex_wait_block_count = X86_RUNTIME
        .LINUX_FUTEX_WAIT_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let futex_explicit_wake_count = X86_RUNTIME
        .LINUX_FUTEX_EXPLICIT_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let futex_exit_wake_count = X86_RUNTIME
        .LINUX_FUTEX_EXIT_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let futex_wait_timeout_count = X86_RUNTIME
        .LINUX_FUTEX_WAIT_TIMEOUT_COUNT
        .swap(0, Ordering::SeqCst);
    let sleep_block_count = X86_RUNTIME
        .LINUX_SLEEP_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let sleep_wake_count = X86_RUNTIME.LINUX_SLEEP_WAKE_COUNT.swap(0, Ordering::SeqCst);
    let sleep_interrupt_count = X86_RUNTIME
        .LINUX_SLEEP_INTERRUPT_COUNT
        .swap(0, Ordering::SeqCst);
    let timer_wait_expiry_count = X86_RUNTIME
        .LINUX_TIMER_WAIT_EXPIRY_COUNT
        .swap(0, Ordering::SeqCst);
    let timer_wait_preemption_count = X86_RUNTIME
        .LINUX_TIMER_WAIT_PREEMPTION_COUNT
        .swap(0, Ordering::SeqCst);
    let poll_wait_block_count = X86_RUNTIME
        .LINUX_POLL_WAIT_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let poll_wait_wake_count = X86_RUNTIME
        .LINUX_POLL_WAIT_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let poll_wait_timeout_count = X86_RUNTIME
        .LINUX_POLL_WAIT_TIMEOUT_COUNT
        .swap(0, Ordering::SeqCst);
    let poll_wait_interrupt_count = X86_RUNTIME
        .LINUX_POLL_WAIT_INTERRUPT_COUNT
        .swap(0, Ordering::SeqCst);
    let epoll_wait_block_count = X86_RUNTIME
        .LINUX_EPOLL_WAIT_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let epoll_wait_wake_count = X86_RUNTIME
        .LINUX_EPOLL_WAIT_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let epoll_wait_timeout_count = X86_RUNTIME
        .LINUX_EPOLL_WAIT_TIMEOUT_COUNT
        .swap(0, Ordering::SeqCst);
    let epoll_wait_interrupt_count = X86_RUNTIME
        .LINUX_EPOLL_WAIT_INTERRUPT_COUNT
        .swap(0, Ordering::SeqCst);
    let eventfd_read_block_count = X86_RUNTIME
        .LINUX_EVENTFD_READ_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let eventfd_read_wake_count = X86_RUNTIME
        .LINUX_EVENTFD_READ_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let eventfd_read_interrupt_count = X86_RUNTIME
        .LINUX_EVENTFD_READ_INTERRUPT_COUNT
        .swap(0, Ordering::SeqCst);
    let eventfd_write_block_count = X86_RUNTIME
        .LINUX_EVENTFD_WRITE_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let eventfd_write_wake_count = X86_RUNTIME
        .LINUX_EVENTFD_WRITE_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let eventfd_write_interrupt_count = X86_RUNTIME
        .LINUX_EVENTFD_WRITE_INTERRUPT_COUNT
        .swap(0, Ordering::SeqCst);
    let pipe_read_block_count = X86_RUNTIME
        .LINUX_PIPE_READ_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let pipe_read_wake_count = X86_RUNTIME
        .LINUX_PIPE_READ_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let pipe_read_interrupt_count = X86_RUNTIME
        .LINUX_PIPE_READ_INTERRUPT_COUNT
        .swap(0, Ordering::SeqCst);
    let pipe_write_block_count = X86_RUNTIME
        .LINUX_PIPE_WRITE_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let pipe_write_wake_count = X86_RUNTIME
        .LINUX_PIPE_WRITE_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let pipe_write_interrupt_count = X86_RUNTIME
        .LINUX_PIPE_WRITE_INTERRUPT_COUNT
        .swap(0, Ordering::SeqCst);
    let timerfd_read_block_count = X86_RUNTIME
        .LINUX_TIMERFD_READ_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let timerfd_read_wake_count = X86_RUNTIME
        .LINUX_TIMERFD_READ_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let timerfd_read_interrupt_count = X86_RUNTIME
        .LINUX_TIMERFD_READ_INTERRUPT_COUNT
        .swap(0, Ordering::SeqCst);
    let ppoll_wait_block_count = X86_RUNTIME
        .LINUX_PPOLL_WAIT_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let ppoll_wait_wake_count = X86_RUNTIME
        .LINUX_PPOLL_WAIT_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let ppoll_wait_timeout_count = X86_RUNTIME
        .LINUX_PPOLL_WAIT_TIMEOUT_COUNT
        .swap(0, Ordering::SeqCst);
    let epoll_pwait_block_count = X86_RUNTIME
        .LINUX_EPOLL_PWAIT_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let epoll_pwait_wake_count = X86_RUNTIME
        .LINUX_EPOLL_PWAIT_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let epoll_pwait_timeout_count = X86_RUNTIME
        .LINUX_EPOLL_PWAIT_TIMEOUT_COUNT
        .swap(0, Ordering::SeqCst);
    let masked_wait_interrupt_count = X86_RUNTIME
        .LINUX_MASKED_WAIT_INTERRUPT_COUNT
        .swap(0, Ordering::SeqCst);
    let signal_wait_interrupt_count = X86_RUNTIME
        .LINUX_SIGNAL_WAIT_INTERRUPT_COUNT
        .swap(0, Ordering::SeqCst);
    let signal_delivery_count = X86_RUNTIME
        .LINUX_SIGNAL_DELIVERY_COUNT
        .swap(0, Ordering::SeqCst);
    let signal_return_count = X86_RUNTIME
        .LINUX_SIGNAL_RETURN_COUNT
        .swap(0, Ordering::SeqCst);
    let signal_wait_block_count = X86_RUNTIME
        .LINUX_SIGNAL_WAIT_BLOCK_COUNT
        .swap(0, Ordering::SeqCst);
    let signal_wait_wake_count = X86_RUNTIME
        .LINUX_SIGNAL_WAIT_WAKE_COUNT
        .swap(0, Ordering::SeqCst);
    let signal_wait_timeout_count = X86_RUNTIME
        .LINUX_SIGNAL_WAIT_TIMEOUT_COUNT
        .swap(0, Ordering::SeqCst);
    let system_supervisor_wait_count = X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT
        .swap(0, Ordering::SeqCst);
    let system_supervisor_shutdown_count = X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
        .swap(0, Ordering::SeqCst);
    let system_init = X86_RUNTIME
        .ELF_PROBE_SYSTEM_INIT
        .swap(false, Ordering::SeqCst);
    let signal_probe_executed = exec_replaced
        && initramfs::published_file_name_by_node(exec_node) == Some(b"bin/signal-probe");
    let conformance_probe_executed = exec_replaced
        && initramfs::published_file_name_by_node(exec_node) == Some(b"bin/linux-conformance");
    let exit_status_valid = exit_status
        == if conformance_probe_executed || termination_signal != 0 {
            0
        } else {
            42
        };
    let termination_signal_valid = termination_signal
        == if signal_probe_executed {
            LINUX_SIGPIPE as u32
        } else {
            0
        };
    let expected_signal_count = if signal_probe_executed {
        11
    } else if execution.tls_size != 0 {
        16
    } else {
        2
    };
    let signal_lifecycle_valid = !X86_RUNTIME
        .LINUX_SIGNAL_ACTIVE
        .swap(false, Ordering::SeqCst)
        && signal_delivery_count == expected_signal_count
        && signal_return_count == expected_signal_count
        && unsafe { linux_signal_context().get().cast_const().read() == LinuxSignalContext::ZERO };
    let system_supervisor_valid = if system_init {
        system_supervisor_wait_count == 1 && system_supervisor_shutdown_count == 1
    } else {
        system_supervisor_wait_count == 0 && system_supervisor_shutdown_count == 0
    };
    if execution.tls_size != 0
        && !(child_exit_count == 2
            && parent_resumed
            && clone_dispatch_count == 2
            && first_child_tid != 0
            && clone_reuse_validated
            && child_gettid_count == 2
            && yield_switch_count == LINUX_VERIFICATION_YIELD_SWITCHES
            && clone_busy_rejection_count == 0
            && clone_invalid_rejection_count == 0
            && clone_tid_fault_count == 1
            && futex_wait_block_count == 4
            && futex_explicit_wake_count == 2
            && futex_exit_wake_count == 1
            && futex_wait_timeout_count == 1
            && sleep_block_count == 2
            && sleep_wake_count == 1
            && sleep_interrupt_count == 1
            && timer_wait_expiry_count == 8
            && timer_wait_preemption_count == 9
            && poll_wait_block_count == 4
            && poll_wait_wake_count == 1
            && poll_wait_timeout_count == 2
            && poll_wait_interrupt_count == 1
            && epoll_wait_block_count == 2
            && epoll_wait_wake_count == 1
            && epoll_wait_timeout_count == 0
            && epoll_wait_interrupt_count == 1
            && eventfd_read_block_count == 2
            && eventfd_read_wake_count == 1
            && eventfd_read_interrupt_count == 1
            && eventfd_write_block_count == 3
            && eventfd_write_wake_count == 2
            && eventfd_write_interrupt_count == 1
            && pipe_read_block_count == 3
            && pipe_read_wake_count == 2
            && pipe_read_interrupt_count == 1
            && pipe_write_block_count == 6
            && pipe_write_wake_count == 4
            && pipe_write_interrupt_count == 2
            && timerfd_read_block_count == 2
            && timerfd_read_wake_count == 1
            && timerfd_read_interrupt_count == 1
            && ppoll_wait_block_count == 3
            && ppoll_wait_wake_count == 0
            && ppoll_wait_timeout_count == 2
            && epoll_pwait_block_count == 2
            && epoll_pwait_wake_count == 0
            && epoll_pwait_timeout_count == 1
            && masked_wait_interrupt_count == 2
            && signal_wait_block_count == 3
            && signal_wait_wake_count == 1
            && signal_wait_timeout_count == 1
            && signal_wait_interrupt_count == 1)
    {
        serial_write("linox: Linux thread transition state:");
        for state in [
            child_exit_count == 2,
            parent_resumed,
            clone_dispatch_count == 2,
            first_child_tid != 0,
            clone_reuse_validated,
            child_gettid_count == 2,
            yield_switch_count == LINUX_VERIFICATION_YIELD_SWITCHES,
            clone_busy_rejection_count == 0,
            clone_invalid_rejection_count == 0,
            clone_tid_fault_count == 1,
            futex_wait_block_count == 4,
            futex_explicit_wake_count == 2,
            futex_exit_wake_count == 1,
            futex_wait_timeout_count == 1,
            sleep_block_count == 2,
            sleep_wake_count == 1,
            sleep_interrupt_count == 1,
            timer_wait_expiry_count == 8,
            timer_wait_preemption_count == 9,
            poll_wait_block_count == 4,
            poll_wait_wake_count == 1,
            poll_wait_timeout_count == 2,
            poll_wait_interrupt_count == 1,
            epoll_wait_block_count == 2,
            epoll_wait_wake_count == 1,
            epoll_wait_timeout_count == 0,
            epoll_wait_interrupt_count == 1,
            eventfd_read_block_count == 2,
            eventfd_read_wake_count == 1,
            eventfd_read_interrupt_count == 1,
            eventfd_write_block_count == 3,
            eventfd_write_wake_count == 2,
            eventfd_write_interrupt_count == 1,
            pipe_read_block_count == 3,
            pipe_read_wake_count == 2,
            pipe_read_interrupt_count == 1,
            pipe_write_block_count == 6,
            pipe_write_wake_count == 4,
            pipe_write_interrupt_count == 2,
            timerfd_read_block_count == 2,
            timerfd_read_wake_count == 1,
            timerfd_read_interrupt_count == 1,
            ppoll_wait_block_count == 3,
            ppoll_wait_wake_count == 0,
            ppoll_wait_timeout_count == 2,
            epoll_pwait_block_count == 2,
            epoll_pwait_wake_count == 0,
            epoll_pwait_timeout_count == 1,
            masked_wait_interrupt_count == 2,
            signal_wait_block_count == 3,
            signal_wait_wake_count == 1,
            signal_wait_timeout_count == 1,
            signal_wait_interrupt_count == 1,
        ] {
            serial_write(" ");
            serial_write_u64(u64::from(state));
        }
        serial_write("\r\n");
        serial_write("linox: Linux thread transition counts:");
        for count in [
            child_exit_count,
            clone_dispatch_count,
            first_child_tid,
            child_gettid_count,
            yield_switch_count,
            clone_busy_rejection_count,
            clone_invalid_rejection_count,
            clone_tid_fault_count,
            futex_wait_block_count,
            futex_explicit_wake_count,
            futex_exit_wake_count,
            futex_wait_timeout_count,
            sleep_block_count,
            sleep_wake_count,
            sleep_interrupt_count,
            timer_wait_expiry_count,
            timer_wait_preemption_count,
            poll_wait_block_count,
            poll_wait_wake_count,
            poll_wait_timeout_count,
            poll_wait_interrupt_count,
            epoll_wait_block_count,
            epoll_wait_wake_count,
            epoll_wait_timeout_count,
            epoll_wait_interrupt_count,
            eventfd_read_block_count,
            eventfd_read_wake_count,
            eventfd_read_interrupt_count,
            eventfd_write_block_count,
            eventfd_write_wake_count,
            eventfd_write_interrupt_count,
            pipe_read_block_count,
            pipe_read_wake_count,
            pipe_read_interrupt_count,
            pipe_write_block_count,
            pipe_write_wake_count,
            pipe_write_interrupt_count,
            timerfd_read_block_count,
            timerfd_read_wake_count,
            timerfd_read_interrupt_count,
            ppoll_wait_block_count,
            ppoll_wait_wake_count,
            ppoll_wait_timeout_count,
            epoll_pwait_block_count,
            epoll_pwait_wake_count,
            epoll_pwait_timeout_count,
            masked_wait_interrupt_count,
            signal_wait_block_count,
            signal_wait_wake_count,
            signal_wait_timeout_count,
            signal_wait_interrupt_count,
        ] {
            serial_write(" ");
            serial_write_u64(u64::from(count));
        }
        serial_write("\r\n");
    }
    let umask_restored = X86_RUNTIME.ELF_PROBE_UMASK.swap(0, Ordering::SeqCst) == 0o022;
    let descriptor_snapshot = [
        u64::from(
            X86_RUNTIME
                .ELF_PROBE_CONSOLE_DESCRIPTORS
                .load(Ordering::SeqCst),
        ),
        X86_RUNTIME.ELF_PROBE_CONSOLE_CLOEXEC[0].load(Ordering::SeqCst),
        u64::from(X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS[0].load(Ordering::SeqCst)),
        u64::from(X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS[1].load(Ordering::SeqCst)),
        u64::from(X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS[2].load(Ordering::SeqCst)),
        u64::from(X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS[3].load(Ordering::SeqCst)),
        u64::from(
            X86_RUNTIME
                .ELF_PROBE_EPOLL_DESCRIPTOR
                .load(Ordering::SeqCst),
        ),
        u64::from(X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[0].load(Ordering::SeqCst)),
        X86_RUNTIME.ELF_PROBE_EPOLL_DATA[0].load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_DESCRIPTOR_OFFSETS[0].load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_DESCRIPTOR_OFFSETS[1].load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_DESCRIPTOR_OFFSETS[2].load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_DESCRIPTOR_OFFSETS[3].load(Ordering::SeqCst),
        u64::from(
            X86_RUNTIME
                .ELF_PROBE_EVENTFD_DESCRIPTOR
                .load(Ordering::SeqCst),
        ),
        X86_RUNTIME.ELF_PROBE_EVENTFD_COUNTER.load(Ordering::SeqCst),
        u64::from(X86_RUNTIME.ELF_PROBE_EVENTFD_FLAGS.load(Ordering::SeqCst)),
        u64::from(
            X86_RUNTIME
                .ELF_PROBE_TIMERFD_DESCRIPTOR
                .load(Ordering::SeqCst),
        ),
        u64::from(X86_RUNTIME.ELF_PROBE_TIMERFD_CLOCK.load(Ordering::SeqCst)),
        u64::from(X86_RUNTIME.ELF_PROBE_TIMERFD_FLAGS.load(Ordering::SeqCst)),
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_INTERVAL
            .load(Ordering::SeqCst),
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_DEADLINE
            .load(Ordering::SeqCst),
        u64::from(
            X86_RUNTIME
                .ELF_PROBE_PIPE_READ_DESCRIPTOR
                .load(Ordering::SeqCst),
        ),
        u64::from(
            X86_RUNTIME
                .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
                .load(Ordering::SeqCst),
        ),
        u64::from(X86_RUNTIME.ELF_PROBE_PIPE_READ_FLAGS.load(Ordering::SeqCst)),
        u64::from(
            X86_RUNTIME
                .ELF_PROBE_PIPE_WRITE_FLAGS
                .load(Ordering::SeqCst),
        ),
        u64::from(X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst)),
    ];
    let mut devices_closed = true;
    for descriptor in &X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS {
        devices_closed &= descriptor.swap(0, Ordering::SeqCst) == 0;
    }
    let mut rootfs_descriptors_closed = true;
    for descriptor in &X86_RUNTIME.ELF_PROBE_ROOTFS_DESCRIPTORS {
        rootfs_descriptors_closed &= descriptor.swap(0, Ordering::SeqCst) == 0;
    }
    let mut sockets_closed = true;
    for slot in &X86_RUNTIME.ELF_PROBE_SOCKET_SLOTS {
        sockets_closed &= slot.swap(0, Ordering::SeqCst) == 0;
    }
    let mut offsets_reset = true;
    for offset in &X86_RUNTIME.ELF_PROBE_DESCRIPTOR_OFFSETS {
        offsets_reset &= offset.swap(0, Ordering::SeqCst) == 0;
    }
    let mut epoll_watches_reset = true;
    for descriptor in 0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize {
        epoll_watches_reset &=
            X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[descriptor].swap(0, Ordering::SeqCst) == 0;
        epoll_watches_reset &=
            X86_RUNTIME.ELF_PROBE_EPOLL_DATA[descriptor].swap(0, Ordering::SeqCst) == 0;
    }
    let descriptor_state_valid = X86_RUNTIME
        .ELF_PROBE_CONSOLE_DESCRIPTORS
        .swap(0, Ordering::SeqCst)
        == 0
        && clear_linux_descriptor_close_on_exec()
        && X86_RUNTIME
            .ELF_PROBE_CWD
            .swap(LINUX_ROOT_DIRECTORY, Ordering::SeqCst)
            == LINUX_ROOT_DIRECTORY
        && X86_RUNTIME
            .ELF_PROBE_ROOTFS_CWD
            .swap(crate::published_rootfs::ROOT_HANDLE, Ordering::SeqCst)
            == crate::published_rootfs::ROOT_HANDLE
        && X86_RUNTIME.ELF_PROBE_OVERLAY_CWD.swap(0, Ordering::SeqCst) == 0
        && devices_closed
        && rootfs_descriptors_closed
        && sockets_closed
        && X86_RUNTIME
            .ELF_PROBE_EPOLL_DESCRIPTOR
            .swap(0, Ordering::SeqCst)
            == 0
        && epoll_watches_reset
        && X86_RUNTIME
            .ELF_PROBE_EVENTFD_DESCRIPTOR
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_EVENTFD_COUNTER
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_EVENTFD_FLAGS
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_TIMERFD_DESCRIPTOR
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_TIMERFD_CLOCK
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_TIMERFD_FLAGS
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_TIMERFD_INTERVAL
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_TIMERFD_DEADLINE
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_PIPE_READ_DESCRIPTOR
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_PIPE_READ_FLAGS
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_FLAGS
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.swap(0, Ordering::SeqCst) == 0
        && offsets_reset;
    if !descriptor_state_valid {
        serial_write("linox: Linux descriptor state leak:");
        for value in descriptor_snapshot {
            serial_write(" ");
            serial_write_u64(value);
        }
        serial_write("\r\n");
    }
    let clock_state_valid = X86_RUNTIME.ELF_PROBE_CLOCK_EPOCH.swap(0, Ordering::SeqCst) != 0
        && X86_RUNTIME
            .ELF_PROBE_CLOCK_FREQUENCY
            .swap(0, Ordering::SeqCst)
            == clock_frequency;
    let sealed_mmaps_released = release_linux_sealed_mmaps_at_exit();
    let mmap_inactive = (0..LINUX_RUNTIME_MMAP_SLOT_COUNT)
        .all(|index| X86_RUNTIME.ELF_PROBE_MMAP_PAGES[index].swap(0, Ordering::SeqCst) == 0);
    let mmap_protection_cleared = (0..LINUX_RUNTIME_MMAP_SLOT_COUNT)
        .all(|index| X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[index].swap(0, Ordering::SeqCst) == 0);
    let mmap_file_released = (0..LINUX_RUNTIME_MMAP_SLOT_COUNT)
        .all(|index| X86_RUNTIME.ELF_PROBE_MMAP_FILE[index].swap(0, Ordering::SeqCst) == 0);
    let mmap_seals_released = (0..LINUX_RUNTIME_MMAP_SLOT_COUNT)
        .all(|index| !X86_RUNTIME.ELF_PROBE_MMAP_SEALED[index].swap(false, Ordering::SeqCst));
    let mmap_address_valid =
        X86_RUNTIME.ELF_PROBE_MMAP.swap(0, Ordering::SeqCst) == execution.mmap as u64;
    let mmap_next_valid =
        X86_RUNTIME.ELF_PROBE_MMAP_NEXT.swap(0, Ordering::SeqCst) >= execution.mmap as u64;
    let mmap_frames_valid = X86_RUNTIME
        .ELF_PROBE_MMAP_FRAMES
        .iter()
        .all(|frame| frame.swap(0, Ordering::SeqCst) == 0)
        && X86_RUNTIME
            .ELF_PROBE_MMAP_GENERATIONS
            .iter()
            .all(|generation| generation.swap(0, Ordering::SeqCst) == 0);
    let mmap_state_valid = sealed_mmaps_released
        && mmap_inactive
        && mmap_protection_cleared
        && mmap_file_released
        && mmap_seals_released
        && mmap_address_valid
        && mmap_next_valid
        && mmap_frames_valid;
    let expected_main_mappings = execution
        .main_mappings
        .iter()
        .enumerate()
        .fold(0_u8, |mask, (index, mapping)| {
            mask | if mapping.address == 0 { 0 } else { 1 << index }
        });
    let observed_main_mappings = X86_RUNTIME
        .ELF_PROBE_MAIN_MAPPINGS
        .swap(0, Ordering::SeqCst);
    let main_frames = core::array::from_fn(|index| {
        memory::FrameLease::from_parts(
            X86_RUNTIME.ELF_PROBE_MAIN_FRAMES[index].swap(0, Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_MAIN_GENERATIONS[index].swap(0, Ordering::SeqCst),
        )
    });
    let mut main_mapping_contract_valid = observed_main_mappings == expected_main_mappings;
    for (index, mapping) in execution.main_mappings.iter().enumerate() {
        let expected_protection = LINUX_PROT_READ
            | if mapping.writable {
                LINUX_PROT_WRITE
            } else {
                0
            }
            | if mapping.executable {
                LINUX_PROT_EXEC
            } else {
                0
            };
        main_mapping_contract_valid &= X86_RUNTIME.ELF_PROBE_MAIN_ADDRESSES[index]
            .swap(0, Ordering::SeqCst)
            == mapping.address as u64
            && X86_RUNTIME.ELF_PROBE_MAIN_OFFSETS[index].swap(0, Ordering::SeqCst)
                == mapping.offset
            && X86_RUNTIME.ELF_PROBE_MAIN_FILE_SIZES[index].swap(0, Ordering::SeqCst)
                == mapping.file_size as u64
            && u64::from(X86_RUNTIME.ELF_PROBE_MAIN_PROTECTIONS[index].swap(0, Ordering::SeqCst))
                == expected_protection
            && match (mapping.address, main_frames[index]) {
                (0, None) => true,
                (0, Some(_)) | (_, None) => false,
                (_, Some(frame)) => memory::frames_owned_by(memory::FrameOwner::KERNEL, &[frame]),
            };
    }
    let mut observed_dependency_bases = [0_u64; LINUX_DEPENDENCY_COUNT];
    let mut dependency_frames = [[None; LINUX_DEPENDENCY_MAPPING_COUNT]; LINUX_DEPENDENCY_COUNT];
    let mut dependency_mappings_valid = true;
    for dependency in 0..LINUX_DEPENDENCY_COUNT {
        let expected_mappings = execution.dependency_mappings[dependency]
            .iter()
            .enumerate()
            .fold(0_u8, |mask, (index, mapping)| {
                mask | if mapping.file_size == 0 {
                    0
                } else {
                    1 << index
                }
            });
        let observed_mappings =
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_MAPPINGS[dependency].swap(0, Ordering::SeqCst);
        let observed_base_min =
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_BASE_MIN[dependency].swap(0, Ordering::SeqCst);
        let observed_base_end =
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_BASE_END[dependency].swap(0, Ordering::SeqCst);
        let observed_base =
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_SELECTED_BASE[dependency].swap(0, Ordering::SeqCst);
        observed_dependency_bases[dependency] = observed_base;
        dependency_mappings_valid &= observed_mappings == expected_mappings
            && observed_base_min == execution.dependency_base_min[dependency] as u64
            && observed_base_end == execution.dependency_base_end[dependency] as u64
            && if expected_mappings == 0 {
                observed_base == 0
            } else {
                observed_base >= execution.dependency_base_min[dependency] as u64
                    && observed_base < execution.dependency_base_end[dependency] as u64
                    && observed_base.is_multiple_of(PAGE_SIZE as u64)
            };
        for (index, mapping) in execution.dependency_mappings[dependency].iter().enumerate() {
            let state = dependency * LINUX_DEPENDENCY_MAPPING_COUNT + index;
            let frame = memory::FrameLease::from_parts(
                X86_RUNTIME.ELF_PROBE_DEPENDENCY_FRAMES[state].swap(0, Ordering::SeqCst),
                X86_RUNTIME.ELF_PROBE_DEPENDENCY_GENERATIONS[state].swap(0, Ordering::SeqCst),
            );
            dependency_frames[dependency][index] = frame;
            let expected_protection = LINUX_PROT_READ
                | if mapping.writable {
                    LINUX_PROT_WRITE
                } else {
                    0
                }
                | if mapping.executable {
                    LINUX_PROT_EXEC
                } else {
                    0
                };
            dependency_mappings_valid &= X86_RUNTIME.ELF_PROBE_DEPENDENCY_RELATIVES[state]
                .swap(0, Ordering::SeqCst)
                == mapping.relative_address as u64
                && X86_RUNTIME.ELF_PROBE_DEPENDENCY_OFFSETS[state].swap(0, Ordering::SeqCst)
                    == mapping.offset
                && X86_RUNTIME.ELF_PROBE_DEPENDENCY_FILE_SIZES[state].swap(0, Ordering::SeqCst)
                    == mapping.file_size as u64
                && u64::from(
                    X86_RUNTIME.ELF_PROBE_DEPENDENCY_PROTECTIONS[state].swap(0, Ordering::SeqCst),
                ) == expected_protection
                && match (mapping.file_size, frame) {
                    (0, None) => true,
                    (0, Some(_)) | (_, None) => false,
                    (_, Some(frame)) => {
                        memory::frames_owned_by(memory::FrameOwner::KERNEL, &[frame])
                    }
                };
        }
        if observed_mappings != expected_mappings {
            serial_write("linox: Linux dependency mapping contract mismatch: ");
            serial_write_u64(dependency as u64);
            serial_write(" ");
            serial_write_u64(u64::from(observed_mappings));
            serial_write(" ");
            serial_write_u64(u64::from(expected_mappings));
            serial_write("\r\n");
        }
    }
    let expected_process_name = if exec_replaced {
        linux_exec_process_name(exec_node).unwrap_or([0; 2])
    } else {
        [LINUX_INITIAL_PROCESS_NAME, 0]
    };
    let process_name_restored = X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_LOW
        .swap(0, Ordering::SeqCst)
        == expected_process_name[0]
        && X86_RUNTIME
            .ELF_PROBE_PROCESS_NAME_HIGH
            .swap(0, Ordering::SeqCst)
            == expected_process_name[1];
    let executable_identity_restored = if exec_replaced {
        selected_exec_plan.is_some()
    } else {
        exec_node == 0
    };
    let no_new_privileges_enforced = X86_RUNTIME
        .ELF_PROBE_NO_NEW_PRIVS
        .swap(false, Ordering::SeqCst);
    let signal_mask_restored = X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.swap(0, Ordering::SeqCst) == 0;
    let pending_signals_cleared = X86_RUNTIME
        .ELF_PROBE_PENDING_SIGNALS
        .swap(0, Ordering::SeqCst)
        == 0;
    let pending_signal_codes_cleared = X86_RUNTIME
        .ELF_PROBE_PENDING_SIGNAL_CODES
        .iter()
        .all(|code| code.swap(0, Ordering::SeqCst) == 0);
    let pending_signal_values_cleared = X86_RUNTIME
        .ELF_PROBE_PENDING_SIGNAL_VALUES
        .iter()
        .all(|value| value.swap(0, Ordering::SeqCst) == 0);
    let ignored_signals = X86_RUNTIME
        .ELF_PROBE_EXEC_IGNORED_SIGNALS
        .swap(0, Ordering::SeqCst);
    let signal_actions_restored = (exec_replaced || ignored_signals == 0)
        && (0..LINUX_SIGNAL_COUNT).all(|signal| {
            let expected_handler = (ignored_signals >> signal) & 1;
            X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal].swap(0, Ordering::SeqCst)
                == expected_handler
                && X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[signal].swap(0, Ordering::SeqCst) == 0
                && X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[signal].swap(0, Ordering::SeqCst) == 0
                && X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[signal].swap(0, Ordering::SeqCst) == 0
        });
    let alt_stack_disabled = X86_RUNTIME
        .ELF_PROBE_ALT_STACK_POINTER
        .swap(0, Ordering::SeqCst)
        == 0
        && X86_RUNTIME
            .ELF_PROBE_ALT_STACK_SIZE
            .swap(0, Ordering::SeqCst)
            == 0
        && X86_RUNTIME
            .ELF_PROBE_ALT_STACK_FLAGS
            .swap(LINUX_SS_DISABLE, Ordering::SeqCst)
            == LINUX_SS_DISABLE;
    let expected_clear_child_tid = execution.data as u64 + LINUX_CLEAR_CHILD_TID_OFFSET;
    let expected_robust_list = execution.data as u64 + LINUX_ROBUST_LIST_OFFSET;
    let robust_list_cleared = X86_RUNTIME
        .ELF_PROBE_EXITED_ROBUST_LIST
        .swap(0, Ordering::SeqCst)
        == expected_robust_list;
    let protected_page = X86_RUNTIME
        .ELF_PROBE_READ_ONLY_DATA_PAGE
        .swap(0, Ordering::SeqCst);
    let clear_child_tid = X86_RUNTIME
        .ELF_PROBE_EXITED_CLEAR_CHILD_TID
        .swap(0, Ordering::SeqCst);
    let mut cleared_tid = [0xff_u8; size_of::<u32>()];
    let child_tid_cleared = clear_child_tid == expected_clear_child_tid
        && (exec_replaced
            || copy_from_linux_user(clear_child_tid, &mut cleared_tid)
                && cleared_tid == [0; size_of::<u32>()]);
    let heap_contents_valid = if exec_replaced {
        hardware_user_range_is_zero(execution.heap as u64, PAGE_SIZE)
    } else {
        let mut value = [0_u8; size_of::<u64>()];
        crate::trusted::user_copy::copy_from_user(execution.heap as u64, &mut value) == value.len()
            && u64::from_ne_bytes(value) == 0x4845_4150_4252_4b21
    };
    let observed_stack = X86_RUNTIME.ELF_PROBE_STACK.swap(0, Ordering::SeqCst);
    let observed_stack_low = X86_RUNTIME.ELF_PROBE_STACK_LOW.swap(0, Ordering::SeqCst);
    let current_stack_frame = memory::FrameLease::from_parts(
        X86_RUNTIME.ELF_PROBE_STACK_FRAME.swap(0, Ordering::SeqCst),
        X86_RUNTIME
            .ELF_PROBE_STACK_GENERATION
            .swap(0, Ordering::SeqCst),
    );
    let initial_stack_low = (execution.stack & !(PAGE_SIZE - 1))
        .saturating_sub((LINUX_RUNTIME_STACK_PAGES - 1) * PAGE_SIZE)
        as u64;
    let stack_frame_state_valid = observed_stack == execution.stack as u64
        && observed_stack_low != 0
        && observed_stack_low <= initial_stack_low
        && current_stack_frame.is_some_and(|frame| {
            address_space::current_linux_mapping_matches(
                (execution.stack & !(PAGE_SIZE - 1)) as u64,
                frame,
                true,
                false,
            ) && if exec_replaced {
                frame != execution.stack_frame
                    && !memory::frames_owned_by(
                        memory::FrameOwner::KERNEL,
                        &[execution.stack_frame],
                    )
            } else {
                frame == execution.stack_frame
            }
        });
    let exec_stack_frame = current_stack_frame.filter(|frame| *frame != execution.stack_frame);
    let heap_frame_state_valid =
        finalize_linux_exec_heap_frame(execution.heap, execution.heap_frame, exec_replaced);
    let expected_code = if exec_replaced {
        selected_runtime_plan
            .as_ref()
            .map_or(0, |plan| plan.executable.virtual_page as usize)
    } else {
        execution.code
    };
    let expected_code_size = if exec_replaced {
        selected_runtime_plan
            .as_ref()
            .map_or(0, |plan| plan.executable.page_count * PAGE_SIZE)
    } else {
        execution.code_size
    };
    let expected_data = if exec_replaced {
        selected_runtime_plan
            .as_ref()
            .map_or(0, |plan| plan.writable.virtual_page as usize)
    } else {
        execution.data
    };
    let expected_data_size = if exec_replaced {
        selected_runtime_plan
            .as_ref()
            .map_or(0, |plan| plan.writable.page_count * PAGE_SIZE)
    } else {
        execution.data_size
    };
    let runtime_image_state_valid = X86_RUNTIME.ELF_PROBE_CODE_BASE.swap(0, Ordering::SeqCst)
        == expected_code as u64
        && X86_RUNTIME.ELF_PROBE_CODE_SIZE.swap(0, Ordering::SeqCst) == expected_code_size as u64
        && X86_RUNTIME
            .ELF_PROBE_LOADER_CODE_BASE
            .swap(0, Ordering::SeqCst)
            == if exec_replaced {
                selected_interpreted_exec_plan
                    .as_ref()
                    .map_or(0, |plan| plan.process.interpreter.executable.virtual_page)
            } else {
                execution.loader_code as u64
            }
        && X86_RUNTIME
            .ELF_PROBE_LOADER_CODE_SIZE
            .swap(0, Ordering::SeqCst)
            == if exec_replaced {
                selected_interpreted_exec_plan.as_ref().map_or(0, |plan| {
                    (plan.process.interpreter.executable.page_count * PAGE_SIZE) as u64
                })
            } else {
                execution.loader_code_size as u64
            }
        && X86_RUNTIME.ELF_PROBE_DATA.swap(0, Ordering::SeqCst) == expected_data as u64
        && X86_RUNTIME.ELF_PROBE_DATA_SIZE.swap(0, Ordering::SeqCst) == expected_data_size as u64;
    let exec_frames = core::array::from_fn(|index| {
        memory::FrameLease::from_parts(
            X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_FRAMES[index].swap(0, Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_GENERATIONS[index].swap(0, Ordering::SeqCst),
        )
    });
    let exec_frame_state_valid = if exec_replaced {
        selected_exec_mappings.is_some_and(|(_, count)| {
            exec_frames[..count].iter().all(Option::is_some)
                && exec_frames[count..].iter().all(Option::is_none)
        }) && exec_frames
            .iter()
            .flatten()
            .all(|frame| memory::frames_owned_by(memory::FrameOwner::KERNEL, &[*frame]))
    } else {
        exec_frames.iter().all(Option::is_none)
    };
    let observed_exec_entry = X86_RUNTIME.ELF_PROBE_EXEC_ENTRY.swap(0, Ordering::SeqCst);
    let observed_exec_addresses: [u64; LINUX_EXEC_MAPPING_LIMIT] = core::array::from_fn(|index| {
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_ADDRESSES[index].swap(0, Ordering::SeqCst)
    });
    let observed_exec_flags: [u8; LINUX_EXEC_MAPPING_LIMIT] = core::array::from_fn(|index| {
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_FLAGS[index].swap(0, Ordering::SeqCst)
    });
    let exec_image_contract_valid = match selected_exec_mappings {
        Some((mappings, mapping_count)) => {
            selected_exec_plan
                .as_ref()
                .is_some_and(|plan| observed_exec_entry == plan.entry)
                && mappings[..mapping_count]
                    .iter()
                    .enumerate()
                    .all(|(index, mapping)| {
                        observed_exec_addresses[index] == mapping.address as u64
                            && observed_exec_flags[index]
                                == u8::from(mapping.writable) | (u8::from(mapping.executable) << 1)
                    })
                && observed_exec_addresses[mapping_count..]
                    .iter()
                    .all(|address| *address == 0)
                && observed_exec_flags[mapping_count..]
                    .iter()
                    .all(|flags| *flags == 0)
        }
        None => {
            observed_exec_entry == 0
                && observed_exec_addresses == [0; LINUX_EXEC_MAPPING_LIMIT]
                && observed_exec_flags == [0; LINUX_EXEC_MAPPING_LIMIT]
        }
    };
    let active_image_count = usize::from(
        X86_RUNTIME
            .ELF_PROBE_ACTIVE_IMAGE_COUNT
            .swap(0, Ordering::SeqCst),
    );
    let active_image_addresses: [u64; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
        core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[index].swap(0, Ordering::SeqCst)
        });
    let active_image_frames: [Option<memory::FrameLease>; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
        core::array::from_fn(|index| {
            memory::FrameLease::from_parts(
                X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index].swap(0, Ordering::SeqCst),
                X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index].swap(0, Ordering::SeqCst),
            )
        });
    let active_image_flags: [u8; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
        core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].swap(0, Ordering::SeqCst)
        });
    let retired_image_count = usize::from(
        X86_RUNTIME
            .ELF_PROBE_RETIRED_IMAGE_COUNT
            .swap(0, Ordering::SeqCst),
    );
    let retired_image_addresses: [u64; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
        core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_ADDRESSES[index].swap(0, Ordering::SeqCst)
        });
    let retired_image_frames: [Option<memory::FrameLease>; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
        core::array::from_fn(|index| {
            memory::FrameLease::from_parts(
                X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_FRAMES[index].swap(0, Ordering::SeqCst),
                X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_GENERATIONS[index].swap(0, Ordering::SeqCst),
            )
        });
    let retired_image_flags: [u8; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT] =
        core::array::from_fn(|index| {
            X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_FLAGS[index].swap(0, Ordering::SeqCst)
        });
    let mut expected_active = [LinuxActiveImageMapping::EMPTY; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
    let mut expected_active_count = 0;
    let active_seed_complete = if let Some((mappings, mapping_count)) = selected_exec_mappings {
        mappings[..mapping_count]
            .iter()
            .enumerate()
            .all(|(index, mapping)| {
                exec_frames[index].is_some_and(|frame| {
                    expected_active[index] = LinuxActiveImageMapping {
                        address: mapping.address,
                        frame,
                        writable: mapping.writable,
                        executable: mapping.executable,
                        shared: false,
                        dontfork: false,
                    };
                    expected_active_count += 1;
                    true
                })
            })
    } else {
        for mapping in execution.initial_image_mappings {
            expected_active[expected_active_count] = LinuxActiveImageMapping {
                writable: mapping.writable && mapping.address as u64 != protected_page,
                ..*mapping
            };
            expected_active_count += 1;
        }
        true
    };
    let mut append_active = |mapping: LinuxActiveImageMapping| {
        if mapping == LinuxActiveImageMapping::EMPTY
            || expected_active_count == expected_active.len()
            || expected_active[..expected_active_count]
                .iter()
                .any(|prior| prior.address == mapping.address || prior.frame == mapping.frame)
        {
            return false;
        }
        expected_active[expected_active_count] = mapping;
        expected_active_count += 1;
        true
    };
    let main_complete = execution
        .main_mappings
        .iter()
        .enumerate()
        .filter(|(_, mapping)| mapping.address != 0)
        .all(|(index, mapping)| {
            main_frames[index].is_some_and(|frame| {
                append_active(LinuxActiveImageMapping {
                    address: mapping.address,
                    frame,
                    writable: mapping.writable && mapping.address as u64 != protected_page,
                    executable: mapping.executable,
                    shared: false,
                    dontfork: false,
                })
            })
        });
    let dependencies_complete =
        execution
            .dependency_mappings
            .iter()
            .enumerate()
            .all(|(dependency, mappings)| {
                mappings
                    .iter()
                    .enumerate()
                    .filter(|(_, mapping)| mapping.file_size != 0)
                    .all(|(index, mapping)| {
                        observed_dependency_bases[dependency]
                            .checked_add(mapping.relative_address as u64)
                            .and_then(|address| usize::try_from(address).ok())
                            .zip(dependency_frames[dependency][index])
                            .is_some_and(|(address, frame)| {
                                append_active(LinuxActiveImageMapping {
                                    address,
                                    frame,
                                    writable: mapping.writable && address as u64 != protected_page,
                                    executable: mapping.executable,
                                    shared: false,
                                    dontfork: false,
                                })
                            })
                    })
            });
    let active_image_state_valid = active_seed_complete
        && main_complete
        && dependencies_complete
        && active_image_count == expected_active_count
        && (0..active_image_count).all(|index| {
            let flags = active_image_flags[index];
            flags & !3 == 0
                && flags != 3
                && active_image_frames[index].is_some_and(|frame| {
                    expected_active[..expected_active_count].contains(&LinuxActiveImageMapping {
                        address: active_image_addresses[index] as usize,
                        frame,
                        writable: flags & 1 != 0,
                        executable: flags & 2 != 0,
                        shared: false,
                        dontfork: false,
                    })
                })
        })
        && active_image_addresses[active_image_count..]
            .iter()
            .all(|address| *address == 0)
        && active_image_frames[active_image_count..]
            .iter()
            .all(Option::is_none)
        && active_image_flags[active_image_count..]
            .iter()
            .all(|flags| *flags == 0);
    let exec_contract_state_valid = exec_image_contract_valid && active_image_state_valid;
    let mut retired_image_leases = [memory::FrameLease::EMPTY; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
    for (output, frame) in retired_image_leases
        .iter_mut()
        .zip(retired_image_frames.iter().flatten())
    {
        *output = *frame;
    }
    let old_image_retirement_valid = if exec_replaced {
        (execution.initial_image_mappings.len()..=LINUX_ACTIVE_IMAGE_MAPPING_LIMIT)
            .contains(&retired_image_count)
            && (0..retired_image_count).all(|index| {
                let flags = retired_image_flags[index];
                retired_image_frames[index].is_some_and(|frame| {
                    retired_image_addresses[index] != 0
                        && retired_image_addresses[index].is_multiple_of(PAGE_SIZE as u64)
                        && flags & !3 == 0
                        && flags != 3
                        && !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[frame])
                        && (0..index).all(|prior| {
                            retired_image_addresses[prior] != retired_image_addresses[index]
                                && retired_image_frames[prior] != Some(frame)
                        })
                })
            })
            && execution.initial_image_mappings.iter().all(|mapping| {
                (0..retired_image_count).any(|index| {
                    retired_image_addresses[index] == mapping.address as u64
                        && retired_image_frames[index] == Some(mapping.frame)
                        && retired_image_flags[index]
                            == u8::from(
                                mapping.writable && mapping.address as u64 != protected_page,
                            ) | (u8::from(mapping.executable) << 1)
                })
            })
            && retired_image_addresses[retired_image_count..]
                .iter()
                .all(|address| *address == 0)
            && retired_image_frames[retired_image_count..]
                .iter()
                .all(Option::is_none)
            && retired_image_flags[retired_image_count..]
                .iter()
                .all(|flags| *flags == 0)
            && !memory::scrub_and_release_frames(
                memory::FrameOwner::KERNEL,
                &retired_image_leases[..retired_image_count],
            )
    } else {
        retired_image_count == 0
            && retired_image_addresses.iter().all(|address| *address == 0)
            && retired_image_frames.iter().all(Option::is_none)
            && retired_image_flags.iter().all(|flags| *flags == 0)
            && execution.initial_image_mappings.iter().all(|mapping| {
                memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
            })
    };
    let tls_state_valid = X86_RUNTIME.ELF_PROBE_TLS.swap(0, Ordering::SeqCst)
        == execution.tls as u64
        && X86_RUNTIME.ELF_PROBE_TLS_SIZE.swap(0, Ordering::SeqCst) == execution.tls_size as u64;
    let tls_frame_state_valid = finalize_linux_exec_tls_frames(
        [
            execution.tls & !(PAGE_SIZE - 1),
            execution.sibling_tls & !(PAGE_SIZE - 1),
        ],
        execution.tls_frames,
        interpreted_exec_replaced,
    );
    let sibling_stack_frame_state_valid = finalize_linux_exec_sibling_stack_frame(
        execution.sibling_stack,
        execution.sibling_stack_frame,
        interpreted_exec_replaced,
    );
    let sibling_thread_resources_cleared = X86_RUNTIME
        .ELF_PROBE_SIBLING_FS_BASE
        .swap(0, Ordering::SeqCst)
        == execution.sibling_fs_base as u64
        && X86_RUNTIME.ELF_PROBE_SIBLING_TLS.swap(0, Ordering::SeqCst)
            == execution.sibling_tls as u64
        && X86_RUNTIME
            .ELF_PROBE_SIBLING_STACK
            .swap(0, Ordering::SeqCst)
            == execution.sibling_stack as u64;
    X86_RUNTIME.ELF_PROBE_RELRO.store(0, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_RELRO_SIZE.store(0, Ordering::SeqCst);
    let heap_break_state_valid = X86_RUNTIME.ELF_PROBE_BRK.swap(0, Ordering::SeqCst)
        == execution.heap as u64
        && X86_RUNTIME.ELF_PROBE_BRK_LIMIT.swap(0, Ordering::SeqCst) == heap_limit as u64;
    let mount_namespace_valid =
        linux_mount::current_root_is_read_only() && linux_mount::deactivate_initial();
    let valid = inactive
        && completed
        && privilege_entry_nmi_valid
        && exit_status_valid
        && exec_replaced == execution.exec_expected
        && live_return_validated
        && process_snapshot_validated
        && mount_namespace_valid
        && (execution.tls_size == 0
            || child_exit_count == 2
                && parent_resumed
                && clone_dispatch_count == 2
                && first_child_tid != 0
                && clone_reuse_validated
                && child_gettid_count == 2
                && yield_switch_count == LINUX_VERIFICATION_YIELD_SWITCHES
                && clone_busy_rejection_count == 0
                && clone_invalid_rejection_count == 0
                && clone_tid_fault_count == 1
                && futex_wait_block_count == 4
                && futex_explicit_wake_count == 2
                && futex_exit_wake_count == 1
                && futex_wait_timeout_count == 1
                && sleep_block_count == 2
                && sleep_wake_count == 1
                && sleep_interrupt_count == 1
                && timer_wait_expiry_count == 8
                && timer_wait_preemption_count == 9
                && poll_wait_block_count == 4
                && poll_wait_wake_count == 1
                && poll_wait_timeout_count == 2
                && poll_wait_interrupt_count == 1
                && epoll_wait_block_count == 2
                && epoll_wait_wake_count == 1
                && epoll_wait_timeout_count == 0
                && epoll_wait_interrupt_count == 1
                && eventfd_read_block_count == 2
                && eventfd_read_wake_count == 1
                && eventfd_read_interrupt_count == 1
                && eventfd_write_block_count == 3
                && eventfd_write_wake_count == 2
                && eventfd_write_interrupt_count == 1
                && pipe_read_block_count == 3
                && pipe_read_wake_count == 2
                && pipe_read_interrupt_count == 1
                && pipe_write_block_count == 6
                && pipe_write_wake_count == 4
                && pipe_write_interrupt_count == 2
                && timerfd_read_block_count == 2
                && timerfd_read_wake_count == 1
                && timerfd_read_interrupt_count == 1
                && ppoll_wait_block_count == 3
                && ppoll_wait_wake_count == 0
                && ppoll_wait_timeout_count == 2
                && epoll_pwait_block_count == 2
                && epoll_pwait_wake_count == 0
                && epoll_pwait_timeout_count == 1
                && masked_wait_interrupt_count == 2
                && signal_wait_block_count == 3
                && signal_wait_wake_count == 1
                && signal_wait_timeout_count == 1
                && signal_wait_interrupt_count == 1)
        && child_tid_cleared
        && robust_list_cleared
        && protected_page == execution.relro as u64
        && heap_contents_valid
        && heap_frame_state_valid
        && heap_break_state_valid
        && umask_restored
        && linux_descriptors_closed
        && descriptor_state_valid
        && clock_state_valid
        && mmap_state_valid
        && main_mapping_contract_valid
        && dependency_mappings_valid
        && runtime_image_state_valid
        && exec_contract_state_valid
        && exec_frame_state_valid
        && stack_frame_state_valid
        && old_image_retirement_valid
        && tls_state_valid
        && tls_frame_state_valid
        && sibling_stack_frame_state_valid
        && sibling_thread_resources_cleared
        && tls_copy_bounds_valid
        && tls_context_switch_valid
        && linux_clone_publication_valid
        && linux_thread_table_released
        && linux_wait_timer_finished
        && process_name_restored
        && executable_identity_restored
        && no_new_privileges_enforced
        && signal_lifecycle_valid
        && system_supervisor_valid
        && termination_signal_valid
        && signal_mask_restored
        && pending_signals_cleared
        && pending_signal_codes_cleared
        && pending_signal_values_cleared
        && signal_actions_restored
        && alt_stack_disabled
        && live_process_registry_finished
        && msrs_restored;
    if !valid {
        serial_write("linox: Linux final state:");
        for state in [
            inactive,
            completed,
            privilege_entry_nmi_valid,
            exit_status_valid,
            exec_replaced == execution.exec_expected,
            live_return_validated,
            process_snapshot_validated,
            child_tid_cleared,
            robust_list_cleared,
            protected_page == execution.relro as u64,
            heap_contents_valid,
            heap_frame_state_valid,
            heap_break_state_valid,
            umask_restored,
            descriptor_state_valid,
            clock_state_valid,
            mmap_state_valid,
            main_mapping_contract_valid,
            dependency_mappings_valid,
            runtime_image_state_valid,
            exec_contract_state_valid,
            exec_frame_state_valid,
            stack_frame_state_valid,
            old_image_retirement_valid,
            tls_state_valid,
            tls_frame_state_valid,
            sibling_stack_frame_state_valid,
            sibling_thread_resources_cleared,
            tls_copy_bounds_valid,
            tls_context_switch_valid,
            linux_clone_publication_valid,
            linux_thread_table_released,
            linux_wait_timer_finished,
            process_name_restored,
            executable_identity_restored,
            no_new_privileges_enforced,
            signal_lifecycle_valid,
            system_supervisor_valid,
            termination_signal_valid,
            signal_mask_restored,
            pending_signals_cleared,
            pending_signal_codes_cleared,
            pending_signal_values_cleared,
            signal_actions_restored,
            alt_stack_disabled,
            live_process_registry_finished,
            mount_namespace_valid,
            msrs_restored,
        ] {
            serial_write(" ");
            serial_write_u64(u64::from(state));
        }
        serial_write("\r\n");
        serial_write("linox: Linux exit/deliveries/returns/termination: ");
        serial_write_u64(exit_status);
        serial_write(" ");
        serial_write_u64(signal_delivery_count);
        serial_write(" ");
        serial_write_u64(signal_return_count);
        serial_write(" ");
        serial_write_u64(u64::from(termination_signal));
        serial_write("\r\n");
        if system_init {
            serial_write("linox: Linux supervisor wait/shutdown: ");
            serial_write_u64(u64::from(system_supervisor_wait_count));
            serial_write(" ");
            serial_write_u64(u64::from(system_supervisor_shutdown_count));
            serial_write("\r\n");
            write_linux_runtime_syscall_trace();
        }
    }
    let exec_mapping_count = selected_exec_mappings.map_or(0, |(_, count)| count);
    let mut returned_exec_frames = exec_frames;
    if exec_replaced && exec_mapping_count < LINUX_EXEC_MAPPING_LIMIT {
        returned_exec_frames[exec_mapping_count] = exec_stack_frame;
    }
    LinuxElfResult {
        valid,
        suspended: false,
        exec_replaced,
        exec_node,
        active_image_mapping_count: active_image_count,
        dependency_bases: observed_dependency_bases,
        main_frames,
        dependency_frames,
        exec_mapping_count,
        exec_frames: returned_exec_frames,
        retired_image_count,
        retired_image_frames,
    }
}
