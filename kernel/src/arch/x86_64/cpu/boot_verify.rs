#![forbid(unsafe_code)]
use super::*;

pub(crate) fn verify_cross_cpu_linux_runtime_mechanisms() -> bool {
    if crate::arch::x86_64::smp::online_count() == 1 {
        return true;
    }
    let cpu = 1;
    let instance = linux_process::current_ipc_instance();
    let signal_slot = linux_process::PROCESS_LIMIT - 1;
    if crate::linux_signal::clear(instance, crate::linux_signal::Scope::Process, signal_slot)
        .is_err()
        || !crate::arch::x86_64::smp::execute_runtime_operation(cpu, CROSS_CPU_RUNTIME_SIGNAL)
    {
        return false;
    }
    let signal = crate::linux_signal::dequeue(
        instance,
        crate::linux_signal::Scope::Process,
        signal_slot,
        1 << 9,
    );
    if !signal.is_ok_and(|pending| {
        pending.is_some_and(|pending| {
            pending.signal == 10
                && pending.code == -1
                && pending.value == CROSS_CPU_RUNTIME_KEY
                && pending.sender_pid == 2
                && pending.sender_uid == 0
        })
    }) {
        return false;
    }

    let futex_slot = LINUX_THREAD_LIMIT - 1;
    if X86_RUNTIME.LINUX_THREAD_STATES[futex_slot].load(Ordering::Acquire) != 0
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[futex_slot].load(Ordering::Acquire)
            != LINUX_THREAD_WAIT_NONE
    {
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[futex_slot].store(CROSS_CPU_RUNTIME_KEY, Ordering::Release);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[futex_slot].store(u64::from(u32::MAX), Ordering::Release);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[futex_slot]
        .store(LINUX_THREAD_WAIT_FUTEX, Ordering::Release);
    X86_RUNTIME.LINUX_THREAD_STATES[futex_slot].store(LINUX_THREAD_BLOCKED, Ordering::Release);
    let futex_woke = crate::arch::x86_64::smp::execute_runtime_operation(
        cpu,
        CROSS_CPU_RUNTIME_FUTEX_WAKE | (linux_cpu_bank() as u64) << 8,
    ) && X86_RUNTIME.LINUX_THREAD_STATES[futex_slot].load(Ordering::Acquire)
        == LINUX_THREAD_READY
        && X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[futex_slot].load(Ordering::Acquire)
            == LINUX_THREAD_WAIT_NONE
        && X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[futex_slot].load(Ordering::Acquire) == 0;
    X86_RUNTIME.LINUX_THREAD_STATES[futex_slot].store(0, Ordering::Release);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[futex_slot]
        .store(LINUX_THREAD_WAIT_NONE, Ordering::Release);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[futex_slot].store(0, Ordering::Release);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[futex_slot].store(0, Ordering::Release);
    if !futex_woke {
        return false;
    }

    let Ok((socket_sender, socket_receiver)) = crate::linux_socket::open_pair(1) else {
        return false;
    };
    let socket_sent = crate::arch::x86_64::smp::execute_runtime_operation(
        cpu,
        CROSS_CPU_RUNTIME_SOCKET_SEND | (u64::from(socket_sender) << 8),
    );
    let mut socket_bytes = [0_u8; 10];
    let socket_received = crate::linux_socket::recv(socket_receiver, &mut socket_bytes).is_ok_and(
        |(length, endpoint)| {
            length == socket_bytes.len() && endpoint.is_none() && socket_bytes == *b"socket-smp"
        },
    );
    let socket_closed =
        crate::linux_socket::close(socket_sender) && crate::linux_socket::close(socket_receiver);
    if !socket_sent || !socket_received || !socket_closed {
        return false;
    }

    let mut pipe_descriptors = [0_u8; 8];
    if linux_socket_pipe(
        0,
        LINUX_O_NONBLOCK,
        LINUX_AUX_DESCRIPTOR_FIRST,
        |_, bytes| {
            if bytes.len() != pipe_descriptors.len() {
                return false;
            }
            pipe_descriptors.copy_from_slice(bytes);
            true
        },
    ) != 0
    {
        return false;
    }
    let pipe_reader = u64::from(u32::from_ne_bytes(
        pipe_descriptors[..4].try_into().unwrap(),
    ));
    let pipe_writer = u64::from(u32::from_ne_bytes(
        pipe_descriptors[4..].try_into().unwrap(),
    ));
    let Some(pipe_sender) = linux_socket_slot(pipe_writer) else {
        return false;
    };
    let Some(pipe_receiver) = linux_socket_slot(pipe_reader) else {
        return false;
    };
    let pipe_sent = crate::arch::x86_64::smp::execute_runtime_operation(
        cpu,
        CROSS_CPU_RUNTIME_PIPE_SEND | (u64::from(pipe_sender) << 8),
    );
    let mut pipe_bytes = [0_u8; 8];
    let pipe_received = crate::linux_socket::recv(pipe_receiver, &mut pipe_bytes).is_ok_and(
        |(length, endpoint)| {
            length == pipe_bytes.len() && endpoint.is_none() && pipe_bytes == *b"pipe-smp"
        },
    );
    let pipe_closed =
        linux_descriptor_close(pipe_reader) == 0 && linux_descriptor_close(pipe_writer) == 0;
    pipe_sent
        && pipe_received
        && pipe_closed
        && scheduler::verify_smp_process_scheduler(CROSS_CPU_RUNTIME_SCHEDULE)
}

pub(crate) fn verify_user_syscall(
    entry: usize,
    stack: usize,
    host_handle: u64,
    console_handle: u64,
    ipc_handle: u64,
    root_handle: u64,
    service_domain: u64,
) -> bool {
    if !install_user_interrupt_gate(SYSCALL_VECTOR, EntryStub::native_system_call())
        || !user_interrupt_surface_is_minimal()
    {
        return false;
    }
    SYSCALL_STATE.store(0, Ordering::SeqCst);
    let Some(service_identity) = domain::domain_service_identity(service_domain) else {
        return false;
    };
    if !install_current_scheduler_fs_base() {
        return false;
    }
    // The caller supplies mapped ring-3 code and stack addresses. The
    // syscall gate abandons the user frame and returns on the saved kernel
    // stack, with interrupts disabled throughout.
    if !enter_user(
        entry,
        stack,
        host_handle,
        console_handle,
        ipc_handle,
        1,
        service_domain,
        service_identity,
        root_handle,
    ) {
        return false;
    }
    SYSCALL_STATE.load(Ordering::SeqCst) == 31
}

pub(super) fn verify_live_linux_process_snapshot_contract(
    snapshot: &LinuxProcessAddressSpaceSnapshot,
) -> bool {
    if !snapshot.is_valid() {
        return false;
    }
    let truncated_count = snapshot.mapping_count.saturating_sub(1);
    if address_space::validate_linux_process_address_space(
        snapshot.hierarchy(),
        &snapshot.mappings[..truncated_count],
    ) {
        return false;
    }
    if snapshot.counts_are_in_bounds(snapshot.hierarchy_count, snapshot.mappings.len() + 1) {
        return false;
    }
    let first = snapshot.mappings[0];
    if address_space::current_linux_mapping_matches(
        first.address as u64,
        first.frame,
        !first.writable,
        first.executable,
    ) {
        return false;
    }
    let Some(stale_generation) = snapshot.hierarchy[0].generation().checked_add(1) else {
        return false;
    };
    let Some(stale_lease) =
        memory::FrameLease::from_parts(snapshot.hierarchy[0].address(), stale_generation)
    else {
        return false;
    };
    !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[stale_lease])
}

pub(crate) fn verify_linux_tls_context_contract() -> bool {
    LinuxTlsContext {
        thread_pointer: 0,
        extent: 0,
        extent_size: 0,
    }
    .is_valid()
        && LinuxTlsContext {
            thread_pointer: 0x1030,
            extent: 0x1000,
            extent_size: 0x40,
        }
        .is_valid()
        && LinuxTlsContext {
            thread_pointer: 0x1030,
            extent: 0,
            extent_size: 0,
        }
        .is_valid()
        && LinuxTlsContext {
            thread_pointer: 0,
            extent: 0x1000,
            extent_size: 0x40,
        }
        .is_valid()
        && LinuxTlsContext {
            thread_pointer: 0x0ff8,
            extent: 0x1000,
            extent_size: 0x40,
        }
        .is_valid()
        && LinuxTlsContext {
            thread_pointer: 0x1038,
            extent: 0x1000,
            extent_size: 0x40,
        }
        .is_valid()
        && !LinuxTlsContext {
            thread_pointer: (1 << 47) - 8,
            extent: (1 << 47) - 0x20,
            extent_size: 0x40,
        }
        .is_valid()
        && !LinuxTlsContext {
            thread_pointer: usize::MAX - 8,
            extent: usize::MAX - 0x20,
            extent_size: 0x40,
        }
        .is_valid()
}

pub(super) fn verify_linux_thread_interrupt_resume_context(
    handle: LinuxThreadHandle,
    original: LinuxUserContext,
) -> bool {
    let interrupted = UserFaultContext {
        r15: 0x1500_0000_0000_0015,
        r14: 0x1400_0000_0000_0014,
        r13: 0x1300_0000_0000_0013,
        r12: 0x1200_0000_0000_0012,
        r11: 0x1100_0000_0000_0011,
        r10: 0x1000_0000_0000_0010,
        r9: 0x0900_0000_0000_0009,
        r8: 0x0800_0000_0000_0008,
        rbp: 0xb000_0000_0000_000b,
        rdi: 0xd000_0000_0000_000d,
        rsi: 0x5000_0000_0000_0005,
        rdx: 0xd200_0000_0000_0002,
        rcx: 0xc000_0000_0000_000c,
        rbx: 0xb100_0000_0000_0001,
        rax: 0xa000_0000_0000_000a,
        rip: original.rip,
        rflags: original.rflags,
        rsp: original.rsp,
    };
    let expected = [
        interrupted.rax,
        interrupted.rbx,
        interrupted.rcx,
        interrupted.rdx,
        interrupted.rsi,
        interrupted.rdi,
        interrupted.rbp,
        interrupted.r8,
        interrupted.r9,
        interrupted.r10,
        interrupted.r11,
        interrupted.r12,
        interrupted.r13,
        interrupted.r14,
        interrupted.r15,
    ];
    let saved = save_linux_interrupt_context(handle, interrupted, original.fs_base);
    let interrupted_context = linux_thread_return_context(handle);
    // The live return writes this CPU's entry state; the record is put back
    // as it was once the check has read it.
    let mut exact_frame = LinuxSyscallFrame::ZERO;
    let exact_return_prepared = architecture::with_entry_state_restored(|| {
        interrupted_context.is_some_and(|context| {
            crate::trusted::entry::with_stand_in_frame(&mut exact_frame, |output| {
                write_linux_thread_live_return(output, handle, context)
            }) && exact_frame == context.registers
                && architecture::current_entry_state_copy().is_some_and(|entry_state| {
                    entry_state.user_rsp == context.rsp
                        && entry_state.user_rip == context.rip
                        && entry_state.user_rflags == context.rflags
                        && entry_state.signal_rax == expected[0]
                        && entry_state.signal_rcx == expected[2]
                        && entry_state.signal_r11 == expected[10]
                })
        })
    });
    let exact = saved
        && exact_return_prepared
        && interrupted_context.is_some_and(|context| {
            context.rip == original.rip
                && context.rsp == original.rsp
                && context.rflags == original.rflags
                && context.fs_base == original.fs_base
                && linux_thread_resume_general(handle, context) == Some(expected)
        });
    let restored = save_linux_interrupt_context(
        handle,
        UserFaultContext {
            r15: original.registers.r15,
            r14: original.registers.r14,
            r13: original.registers.r13,
            r12: original.registers.r12,
            r11: original.rflags,
            r10: original.registers.r10,
            r9: original.registers.r9,
            r8: original.registers.r8,
            rbp: original.registers.rbp,
            rdi: original.registers.rdi,
            rsi: original.registers.rsi,
            rdx: original.registers.rdx,
            rcx: original.rip,
            rbx: original.registers.rbx,
            rax: original.rax,
            rip: original.rip,
            rflags: original.rflags,
            rsp: original.rsp,
        },
        original.fs_base,
    ) && linux_thread_return_context(handle) == Some(original)
        && linux_thread_resume_general(handle, original)
            == Some(original.registers.process_general(
                original.rax,
                original.rip,
                original.rflags,
            ));
    exact && restored
}

pub(crate) fn verify_linux_mmap_process_restore() -> bool {
    let original = capture_linux_mmap_runtime_state();
    let mut parent = original;
    parent.base = 0x7f00_1000;
    parent.pages[0] = 2;
    parent.protection[0] = (LINUX_PROT_READ | LINUX_PROT_WRITE) as u8;
    parent.frames[0] = 0x20_0000;
    parent.generations[0] = 7;
    parent.frames[1] = 0x21_0000;
    parent.generations[1] = 8;
    restore_linux_mmap_runtime_state(parent);

    let mut child = parent;
    child.pages[0] = 0;
    child.protection[0] = 0;
    child.frames[0] = 0x30_0000;
    child.generations[0] = 11;
    restore_linux_mmap_runtime_state(child);
    restore_linux_mmap_runtime_state(parent);
    let restored = capture_linux_mmap_runtime_state() == parent;
    restore_linux_mmap_runtime_state(original);
    restored && capture_linux_mmap_runtime_state() == original
}

pub(super) fn verify_linux_sysv_shared_memory_syscalls() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let old_instance = X86_RUNTIME.LINUX_EXECUTION_INSTANCE.load(Ordering::SeqCst);
    let old_runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.swap(true, Ordering::SeqCst);
    let id = linux_shmget(
        UPPER_REGISTER_BITS,
        2 * PAGE_SIZE as u64,
        UPPER_REGISTER_BITS | 0o600,
    );
    let first = (id <= i32::MAX as u64)
        .then(|| linux_shmat(UPPER_REGISTER_BITS | id, 0, UPPER_REGISTER_BITS));
    let second = first
        .filter(|address| *address < LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .map(|_| linux_shmat(UPPER_REGISTER_BITS | id, 0, UPPER_REGISTER_BITS));
    let mapped = first.zip(second).filter(|(first, second)| {
        *first >= LINUX_RUNTIME_DYNAMIC_MMAP_BASE
            && *first < LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39)
            && *second >= LINUX_RUNTIME_DYNAMIC_MMAP_BASE
            && *second < LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39)
            && first != second
    });
    let shared = mapped.is_some_and(|(first, second)| {
        let value = 0x4749_4e55_5853_5956_u64.to_ne_bytes();
        let mut observed = [0_u8; size_of::<u64>()];
        copy_to_linux_user(first, &value)
            && copy_from_linux_user(second, &mut observed)
            && observed == value
    });
    let removed_while_attached = mapped.is_some()
        && linux_shmctl(UPPER_REGISTER_BITS | id, UPPER_REGISTER_BITS, 0) == 0
        && crate::linux_sysv_ipc::segment(id as u32).is_ok();
    let detached = mapped.is_some_and(|(first, second)| {
        linux_shmdt(first) == 0
            && crate::linux_sysv_ipc::segment(id as u32)
                .is_ok_and(|segment| segment.attachments == 1)
            && linux_shmdt(second) == 0
    });
    let destroyed = id <= i32::MAX as u64
        && matches!(
            crate::linux_sysv_ipc::segment(id as u32),
            Err(crate::linux_sysv_ipc::Error::Invalid)
        );
    let semaphores = verify_linux_sysv_semaphore_syscalls();
    let messages = verify_linux_sysv_message_queue_syscalls();
    let timer_argument_widths = verify_linux_timer_argument_widths();
    let signal_argument_widths = verify_linux_signal_argument_widths();
    let dynamic_signal_fifo = crate::linux_signal::verify_dynamic_fifo(linux_signal_instance());
    let descriptor_argument_widths = verify_linux_descriptor_argument_widths();
    let process_selector_widths = verify_linux_process_selector_widths();
    let filesystem_argument_widths = verify_linux_filesystem_argument_widths();
    let event_argument_widths = verify_linux_event_argument_widths();
    let process_advice = verify_linux_process_madvise_syscall();
    let posix_queues = verify_linux_posix_message_queue_syscalls();
    let unix_inflight_rights = verify_linux_unix_inflight_rights();
    let aio = verify_linux_aio_syscalls();
    let memfd_seals = verify_linux_memfd_seals();
    let secret_memory = verify_linux_memfd_secret_syscall();
    let mount_queries = verify_linux_mount_query_syscalls();
    let file_handles = verify_linux_file_handle_syscalls();
    let shadow_stack = linux_map_shadow_stack(0, PAGE_SIZE as u64, 0) == LINUX_EOPNOTSUPP
        && linux_map_shadow_stack(1, 0, u64::MAX) == LINUX_EOPNOTSUPP;
    let uretprobe = verify_linux_default_signal_dispositions();
    let seccomp = verify_linux_seccomp_syscall();
    let remap_file_pages = verify_linux_remap_file_pages_syscall();
    let keyrings = verify_linux_keyring_syscalls();
    let userfaultfd = verify_linux_userfaultfd_syscall();
    let fanotify = verify_linux_fanotify_syscalls();
    let landlock = verify_linux_landlock_syscalls();
    let numa = verify_linux_numa_syscalls();
    let perf = verify_linux_perf_event_open();
    let io_uring = verify_linux_io_uring_syscalls();
    let scheduler_priorities = verify_linux_scheduler_priority_ranges();
    let process_priorities = verify_linux_process_priorities();
    let modify_ldt = verify_linux_modify_ldt_syscall();
    let process_controls = verify_linux_prctl_syscall();
    let architecture_controls = verify_linux_arch_prctl_syscall();
    let personality = verify_linux_personality_syscall();
    let scheduler_queries = verify_linux_scheduler_queries();
    let scheduler_affinity = verify_linux_scheduler_affinity();
    let realtime_queries = verify_linux_realtime_queries();
    let resource_accounting = verify_linux_resource_accounting();
    let filesystem_statistics = verify_linux_filesystem_statistics();
    let filesystem_sync = linux_syncfs(1) == 0 && linux_syncfs(99) == LINUX_EBADF;
    let robust_list = verify_linux_robust_list_syscalls();
    let rseq = verify_linux_rseq_syscall();
    let membarrier = verify_linux_membarrier_syscall();
    let readahead = verify_linux_readahead_syscall();
    let memory_locking = verify_linux_memory_locking_syscalls();
    let address_space_limit = verify_linux_address_space_limit();
    let fadvise = verify_linux_fadvise64_syscall();
    let runtime_boot_contracts = verify_linux_runtime_boot_contracts();
    let mappings_released =
        address_space::release_current_linux_runtime_mappings(LINUX_RUNTIME_DYNAMIC_MMAP_BASE);
    X86_RUNTIME
        .ELF_PROBE_MMAP_NEXT
        .store(LINUX_RUNTIME_DYNAMIC_MMAP_BASE, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .store(old_instance, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_RUNTIME_MODE
        .store(old_runtime, Ordering::SeqCst);
    for (index, valid) in [
        shared,
        removed_while_attached,
        detached,
        destroyed,
        semaphores,
        messages,
        timer_argument_widths,
        signal_argument_widths,
        dynamic_signal_fifo,
        descriptor_argument_widths,
        process_selector_widths,
        filesystem_argument_widths,
        event_argument_widths,
        process_advice,
        posix_queues,
        unix_inflight_rights,
        aio,
        memfd_seals,
        secret_memory,
        mount_queries,
        file_handles,
        shadow_stack,
        uretprobe,
        seccomp,
        remap_file_pages,
        keyrings,
        userfaultfd,
        fanotify,
        landlock,
        io_uring,
        scheduler_priorities,
        process_priorities,
        modify_ldt,
        process_controls,
        architecture_controls,
        personality,
        scheduler_queries,
        scheduler_affinity,
        realtime_queries,
        resource_accounting,
        filesystem_statistics,
        filesystem_sync,
        robust_list,
        rseq,
        membarrier,
        readahead,
        memory_locking,
        address_space_limit,
        fadvise,
        runtime_boot_contracts,
        numa,
        perf,
        mappings_released,
    ]
    .into_iter()
    .enumerate()
    {
        if !valid {
            serial_write("linox: SysV suite failure index ");
            serial_write_u64(index as u64);
            serial_write("\r\n");
        }
    }
    shared
        && removed_while_attached
        && detached
        && destroyed
        && semaphores
        && messages
        && timer_argument_widths
        && signal_argument_widths
        && dynamic_signal_fifo
        && descriptor_argument_widths
        && process_selector_widths
        && filesystem_argument_widths
        && event_argument_widths
        && process_advice
        && posix_queues
        && unix_inflight_rights
        && aio
        && memfd_seals
        && secret_memory
        && mount_queries
        && file_handles
        && shadow_stack
        && uretprobe
        && seccomp
        && remap_file_pages
        && keyrings
        && userfaultfd
        && fanotify
        && landlock
        && numa
        && perf
        && io_uring
        && scheduler_priorities
        && process_priorities
        && modify_ldt
        && process_controls
        && architecture_controls
        && personality
        && scheduler_queries
        && scheduler_affinity
        && realtime_queries
        && resource_accounting
        && filesystem_statistics
        && filesystem_sync
        && robust_list
        && rseq
        && membarrier
        && readahead
        && memory_locking
        && address_space_limit
        && fadvise
        && runtime_boot_contracts
        && mappings_released
}

fn verify_linux_runtime_boot_contracts() -> bool {
    let procfs = linux_runtime_file_kind(b"/proc/1/cmdline")
        == Some(LINUX_FILE_PROC_PROCESS_CMDLINE)
        && linux_runtime_file_kind(b"/proc/1/environ") == Some(LINUX_FILE_PROC_PROCESS_ENVIRON)
        && linux_runtime_file_kind(b"/proc/sys/fs/file-max") == Some(LINUX_FILE_PROC_FILE_MAX)
        && linux_runtime_file_kind(b"/proc/sys/fs/nr_open") == Some(LINUX_FILE_PROC_NR_OPEN)
        && linux_runtime_file_kind(b"/proc/sys/kernel/random/boot_id")
            == Some(LINUX_FILE_PROC_BOOT_ID)
        && linux_regular_file(LINUX_FILE_PROC_PROCESS_CMDLINE) == Some(LINUX_PROC_PROCESS_CMDLINE)
        && linux_regular_file(LINUX_FILE_PROC_PROCESS_ENVIRON) == Some(LINUX_PROC_PROCESS_ENVIRON)
        && linux_regular_file(LINUX_FILE_PROC_FILE_MAX) == Some(LINUX_PROC_FILE_MAX)
        && linux_regular_file(LINUX_FILE_PROC_NR_OPEN) == Some(LINUX_PROC_NR_OPEN)
        && linux_regular_file(LINUX_FILE_PROC_BOOT_ID).is_some_and(|boot_id| {
            boot_id.len() == 37
                && boot_id[8] == b'-'
                && boot_id[13] == b'-'
                && boot_id[18] == b'-'
                && boot_id[23] == b'-'
                && boot_id[36] == b'\n'
        });

    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }

    let saved_flags = core::array::from_fn::<_, 4, _>(|index| {
        X86_RUNTIME.LINUX_TTY_TERMIOS_FLAGS[index].load(Ordering::SeqCst)
    });
    let saved_line = X86_RUNTIME.LINUX_TTY_LINE.load(Ordering::SeqCst);
    let saved_characters = core::array::from_fn::<_, 19, _>(|index| {
        X86_RUNTIME.LINUX_TTY_CONTROL_CHARACTERS[index].load(Ordering::SeqCst)
    });
    let saved_session = X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst);
    let saved_group = X86_RUNTIME
        .LINUX_TTY_FOREGROUND_GROUP
        .load(Ordering::SeqCst);

    let mut requested = [0_u8; 36];
    for (index, flag) in [0x500_u32, 0x5, 0xbf, 0x8a3b].into_iter().enumerate() {
        requested[index * 4..index * 4 + 4].copy_from_slice(&flag.to_ne_bytes());
    }
    requested[16] = 0;
    requested[17..].copy_from_slice(&[
        3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0,
    ]);
    let mut returned = [0_u8; 36];
    let termios = copy_to_linux_user(mapping, &requested)
        && linux_tty_ioctl(LINUX_TCSETS, mapping) == 0
        && linux_tty_ioctl(LINUX_TCGETS, mapping) == 0
        && copy_from_linux_user(mapping, &mut returned)
        && returned == requested;

    let mut window = [0_u8; 8];
    let window_size = linux_tty_ioctl(LINUX_TIOCGWINSZ, mapping) == 0
        && copy_from_linux_user(mapping, &mut window)
        && u16::from_ne_bytes(window[..2].try_into().unwrap()) == 24
        && u16::from_ne_bytes(window[2..4].try_into().unwrap()) == 80;

    let pid = current_linux_process_pid();
    let session = linux_process::live_process_session(pid);
    let process_group = linux_process::live_process_group(pid);
    let controlling_terminal = if session == Some(pid) && process_group == Some(pid) {
        let mut returned_group = [0_u8; 4];
        let mut returned_session = [0_u8; 4];
        linux_tty_ioctl(LINUX_TIOCSCTTY, 0) == 0
            && linux_tty_ioctl(LINUX_TIOCGPGRP, mapping) == 0
            && copy_from_linux_user(mapping, &mut returned_group)
            && u32::from_ne_bytes(returned_group) == pid
            && linux_tty_ioctl(LINUX_TIOCGSID, mapping) == 0
            && copy_from_linux_user(mapping, &mut returned_session)
            && u32::from_ne_bytes(returned_session) == pid
    } else {
        false
    };

    for (index, flag) in saved_flags.into_iter().enumerate() {
        X86_RUNTIME.LINUX_TTY_TERMIOS_FLAGS[index].store(flag, Ordering::SeqCst);
    }
    X86_RUNTIME
        .LINUX_TTY_LINE
        .store(saved_line, Ordering::SeqCst);
    for (index, character) in saved_characters.into_iter().enumerate() {
        X86_RUNTIME.LINUX_TTY_CONTROL_CHARACTERS[index].store(character, Ordering::SeqCst);
    }
    X86_RUNTIME
        .LINUX_TTY_SESSION
        .store(saved_session, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_TTY_FOREGROUND_GROUP
        .store(saved_group, Ordering::SeqCst);
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;

    procfs && termios && window_size && controlling_terminal && unmapped
}

fn verify_linux_scheduler_priority_ranges() -> bool {
    [
        (0, 0, 0),
        (1, 1, 99),
        (2, 1, 99),
        (3, 0, 0),
        (5, 0, 0),
        (6, 0, 0),
    ]
    .into_iter()
    .all(|(policy, minimum, maximum)| {
        linux_scheduler_priority_range(policy, false) == minimum
            && linux_scheduler_priority_range(policy, true) == maximum
    }) && linux_scheduler_priority_range(4, false) == LINUX_EINVAL
        && linux_scheduler_priority_range(1_u64 << 32, false) == 0
        && linux_scheduler_priority_range((1_u64 << 32) | 1, true) == 99
        && linux_scheduler_priority_range(u64::MAX, true) == LINUX_EINVAL
}

fn verify_linux_process_priorities() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let pid = u64::from(current_linux_process_pid());
    let saved = X86_RUNTIME.ELF_PROBE_NICE.load(Ordering::SeqCst);
    let initial = u64::from(40 - saved);
    let selectors = linux_getpriority(
        UPPER_REGISTER_BITS | u64::from(LINUX_PRIO_PROCESS),
        UPPER_REGISTER_BITS,
    ) == initial
        && linux_getpriority(LINUX_PRIO_PROCESS.into(), UPPER_REGISTER_BITS | pid) == initial
        && linux_getpriority(LINUX_PRIO_PGRP.into(), UPPER_REGISTER_BITS) == initial
        && linux_getpriority(LINUX_PRIO_USER.into(), UPPER_REGISTER_BITS) == initial
        && linux_getpriority(UPPER_REGISTER_BITS | 3, 0) == LINUX_EINVAL
        && linux_getpriority(LINUX_PRIO_PROCESS.into(), UPPER_REGISTER_BITS | 0xffff_fffe)
            == LINUX_ESRCH;
    let signed_and_clamped = selectors
        && linux_setpriority(
            UPPER_REGISTER_BITS | u64::from(LINUX_PRIO_PROCESS),
            UPPER_REGISTER_BITS,
            UPPER_REGISTER_BITS | u64::from(u32::MAX),
        ) == 0
        && linux_getpriority(LINUX_PRIO_PROCESS.into(), 0) == 21
        && linux_setpriority(LINUX_PRIO_PROCESS.into(), 0, UPPER_REGISTER_BITS | 100) == 0
        && linux_getpriority(LINUX_PRIO_PROCESS.into(), 0) == 1
        && linux_setpriority(
            LINUX_PRIO_PROCESS.into(),
            0,
            UPPER_REGISTER_BITS | u64::from((-100_i32) as u32),
        ) == 0
        && linux_getpriority(LINUX_PRIO_PROCESS.into(), 0) == 40
        && linux_setpriority(UPPER_REGISTER_BITS | 3, 0, 0) == LINUX_EINVAL
        && linux_setpriority(
            LINUX_PRIO_PROCESS.into(),
            UPPER_REGISTER_BITS | 0xffff_fffe,
            0,
        ) == LINUX_ESRCH;
    // setpriority sets the calling thread's nice as well as the process's:
    // put both back.
    let thread_restored = linux_setpriority(
        LINUX_PRIO_PROCESS.into(),
        0,
        u64::from((i32::from(saved) - 20) as u32),
    ) == 0
        && linux_getpriority(LINUX_PRIO_PROCESS.into(), 0) == initial;
    X86_RUNTIME.ELF_PROBE_NICE.store(saved, Ordering::SeqCst);
    signed_and_clamped
        && thread_restored
        && X86_RUNTIME.ELF_PROBE_NICE.load(Ordering::SeqCst) == saved
}

fn verify_linux_modify_ldt_syscall() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let mut bytes = [0xa5_u8; 160];
    let default = copy_to_linux_user(mapping, &bytes)
        && linux_modify_ldt(UPPER_REGISTER_BITS | 2, mapping, u64::MAX) == 128
        && copy_from_linux_user(mapping, &mut bytes)
        && bytes[..128] == [0; 128]
        && bytes[128..] == [0xa5; 32];
    let short = default
        && copy_to_linux_user(mapping, &[0xa5; 32])
        && linux_modify_ldt(2, mapping, 17) == 17
        && copy_from_linux_user(mapping, &mut bytes[..32])
        && bytes[..17] == [0; 17]
        && bytes[17..32] == [0xa5; 15];
    let errors = short
        && linux_modify_ldt(2, 1, 16) == LINUX_EFAULT
        && linux_modify_ldt(2, 1, 0) == 0
        && linux_modify_ldt(0, 1, u64::MAX) == 0
        && linux_modify_ldt(1, mapping, 16) == LINUX_ENOSYS
        && linux_modify_ldt(0x11, mapping, 16) == LINUX_ENOSYS
        && linux_modify_ldt(3, mapping, 16) == LINUX_ENOSYS;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    errors && unmapped
}

fn verify_linux_prctl_syscall() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let saved_name = [
        X86_RUNTIME
            .ELF_PROBE_PROCESS_NAME_LOW
            .load(Ordering::SeqCst),
        X86_RUNTIME
            .ELF_PROBE_PROCESS_NAME_HIGH
            .load(Ordering::SeqCst),
    ];
    let saved_dumpable = X86_RUNTIME.ELF_PROBE_DUMPABLE.load(Ordering::SeqCst);
    let saved_no_new_privileges = X86_RUNTIME.ELF_PROBE_NO_NEW_PRIVS.load(Ordering::SeqCst);
    let saved_seccomp_strict = X86_RUNTIME.ELF_PROBE_SECCOMP_STRICT.load(Ordering::SeqCst);
    let name = b"prctl-check\0";
    let mut returned_name = [0xa5_u8; LINUX_PROCESS_NAME_SIZE];
    let names = copy_to_linux_user(mapping, name)
        && linux_prctl(UPPER_REGISTER_BITS | LINUX_PR_SET_NAME, mapping, 1, 2, 3) == 0
        && linux_prctl(LINUX_PR_GET_NAME, mapping, 1, 2, 3) == 0
        && copy_from_linux_user(mapping, &mut returned_name)
        && returned_name[..name.len()] == name[..]
        && returned_name[name.len()..] == [0; 4]
        && linux_prctl(LINUX_PR_SET_NAME, 1, 0, 0, 0) == LINUX_EFAULT
        && linux_prctl(LINUX_PR_GET_NAME, 1, 0, 0, 0) == LINUX_EFAULT;
    let dumpable = names
        && linux_prctl(LINUX_PR_GET_DUMPABLE, 9, 8, 7, 6) == 1
        && linux_prctl(UPPER_REGISTER_BITS | LINUX_PR_SET_DUMPABLE, 0, 9, 8, 7) == 0
        && linux_prctl(LINUX_PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
        && linux_prctl(LINUX_PR_SET_DUMPABLE, 1, 0, 0, 0) == 0
        && linux_prctl(LINUX_PR_SET_DUMPABLE, 2, 0, 0, 0) == LINUX_EINVAL;
    let timing = dumpable
        && linux_prctl(LINUX_PR_GET_TIMING, 9, 8, 7, 6) == LINUX_PR_TIMING_STATISTICAL
        && linux_prctl(LINUX_PR_SET_TIMING, LINUX_PR_TIMING_STATISTICAL, 9, 8, 7) == 0
        && linux_prctl(LINUX_PR_SET_TIMING, 1, 0, 0, 0) == LINUX_EINVAL;
    let privileges = timing
        && linux_prctl(LINUX_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == u64::from(saved_no_new_privileges)
        && linux_prctl(LINUX_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
        && linux_prctl(LINUX_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1
        && linux_prctl(LINUX_PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) == LINUX_EINVAL
        && linux_prctl(LINUX_PR_GET_NO_NEW_PRIVS, 1, 0, 0, 0) == LINUX_EINVAL
        && linux_prctl(LINUX_PR_GET_SECCOMP, 9, 8, 7, 6) == u64::from(saved_seccomp_strict)
        && linux_prctl(LINUX_PR_SET_SECCOMP, 1, 0, 9, 8) == 0
        && linux_prctl(LINUX_PR_GET_SECCOMP, 0, 0, 0, 0) == 1
        && linux_prctl(LINUX_PR_SET_SECCOMP, 1, 0, 0, 0) == LINUX_EINVAL
        && linux_prctl(LINUX_PR_SET_SECCOMP, 2, 0, 0, 0) == LINUX_EFAULT
        && linux_prctl(0xffff_ffff, 0, 0, 0, 0) == LINUX_EINVAL;
    X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_LOW
        .store(saved_name[0], Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_HIGH
        .store(saved_name[1], Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_DUMPABLE
        .store(saved_dumpable, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_NO_NEW_PRIVS
        .store(saved_no_new_privileges, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_SECCOMP_STRICT
        .store(saved_seccomp_strict, Ordering::SeqCst);
    let restored = X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_LOW
        .load(Ordering::SeqCst)
        == saved_name[0]
        && X86_RUNTIME
            .ELF_PROBE_PROCESS_NAME_HIGH
            .load(Ordering::SeqCst)
            == saved_name[1]
        && X86_RUNTIME.ELF_PROBE_DUMPABLE.load(Ordering::SeqCst) == saved_dumpable
        && X86_RUNTIME.ELF_PROBE_NO_NEW_PRIVS.load(Ordering::SeqCst) == saved_no_new_privileges
        && X86_RUNTIME.ELF_PROBE_SECCOMP_STRICT.load(Ordering::SeqCst) == saved_seccomp_strict;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    privileges && restored && unmapped
}

fn verify_linux_arch_prctl_syscall() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let saved_fs_base = active_fs_base();
    let saved_extent = X86_RUNTIME.ELF_PROBE_TLS.load(Ordering::SeqCst);
    let saved_extent_size = X86_RUNTIME.ELF_PROBE_TLS_SIZE.load(Ordering::SeqCst);
    let arbitrary_unmapped = 0x1234_5678_u64;
    let mut returned = [0_u8; 8];
    let set_get = linux_arch_prctl(UPPER_REGISTER_BITS | LINUX_ARCH_SET_FS, arbitrary_unmapped)
        == 0
        && active_fs_base() == arbitrary_unmapped
        && X86_RUNTIME.ELF_PROBE_TLS.load(Ordering::SeqCst) == saved_extent
        && X86_RUNTIME.ELF_PROBE_TLS_SIZE.load(Ordering::SeqCst) == saved_extent_size
        && linux_arch_prctl(LINUX_ARCH_GET_FS, mapping) == 0
        && copy_from_linux_user(mapping, &mut returned)
        && u64::from_ne_bytes(returned) == arbitrary_unmapped;
    let boundaries = set_get
        && linux_arch_prctl(LINUX_ARCH_SET_FS, 0) == 0
        && linux_arch_prctl(LINUX_ARCH_GET_FS, mapping) == 0
        && copy_from_linux_user(mapping, &mut returned)
        && u64::from_ne_bytes(returned) == 0
        && linux_arch_prctl(LINUX_ARCH_SET_FS, (1 << 47) - 1) == 0
        && linux_arch_prctl(LINUX_ARCH_SET_FS, 1 << 47) == LINUX_EPERM
        && linux_arch_prctl(LINUX_ARCH_GET_FS, 1) == LINUX_EFAULT
        && linux_arch_prctl(0xffff_ffff, 0) == LINUX_EINVAL;
    let restored = update_current_linux_fs_base(saved_fs_base)
        && active_fs_base() == saved_fs_base
        && X86_RUNTIME.ELF_PROBE_TLS.load(Ordering::SeqCst) == saved_extent
        && X86_RUNTIME.ELF_PROBE_TLS_SIZE.load(Ordering::SeqCst) == saved_extent_size;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    boundaries && restored && unmapped
}

fn verify_linux_personality_syscall() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let saved = X86_RUNTIME.ELF_PROBE_PERSONALITY.load(Ordering::SeqCst);
    let initial = linux_personality(UPPER_REGISTER_BITS | u64::from(LINUX_PERSONALITY_QUERY))
        == u64::from(saved);
    let set = initial
        && linux_personality(UPPER_REGISTER_BITS | u64::from(LINUX_PERSONALITY_UNAME26))
            == u64::from(saved)
        && linux_personality(u64::from(LINUX_PERSONALITY_QUERY))
            == u64::from(LINUX_PERSONALITY_UNAME26)
        && linux_uname_with_copy(mapping, copy_to_linux_user) == 0;
    let mut name = [0_u8; LINUX_UTSNAME_SIZE];
    let uname26 = set
        && copy_from_linux_user(mapping, &mut name)
        && name[130..].starts_with(b"2.6.52.0-linox.0.1\0")
        && linux_personality(1) == u64::from(LINUX_PERSONALITY_UNAME26)
        && linux_personality(u64::from(LINUX_PERSONALITY_QUERY)) == 1;
    X86_RUNTIME
        .ELF_PROBE_PERSONALITY
        .store(saved, Ordering::SeqCst);
    let restored = X86_RUNTIME.ELF_PROBE_PERSONALITY.load(Ordering::SeqCst) == saved;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    uname26 && restored && unmapped
}

fn verify_linux_scheduler_queries() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let current = u64::from(current_linux_process_pid());
    let scheduler = linux_sched_getscheduler(0) == 0
        && linux_sched_getscheduler(current) == 0
        && linux_sched_getscheduler(2) == LINUX_ESRCH
        && linux_sched_getscheduler(u64::MAX) == LINUX_EINVAL;
    let parameter = scheduler
        && copy_to_linux_user(mapping, &u32::MAX.to_ne_bytes())
        && linux_sched_getparam(0, mapping) == 0
        && {
            let mut value = [0_u8; 4];
            copy_from_linux_user(mapping, &mut value) && u32::from_ne_bytes(value) == 0
        }
        && linux_sched_getparam(0, 0) == LINUX_EINVAL
        && linux_sched_getparam(u64::MAX, mapping) == LINUX_EINVAL
        && linux_sched_getparam(2, 0) == LINUX_EINVAL
        && linux_sched_getparam(2, 1) == LINUX_ESRCH
        && linux_sched_getparam(current, 1) == LINUX_EFAULT;
    let setters = parameter
        && copy_to_linux_user(mapping, &0_u32.to_ne_bytes())
        && linux_set_scheduler(0, 0, mapping) == 0
        && linux_set_scheduler(current, 0, mapping) == 0
        && linux_set_scheduler(0, 1_u64 << 32, mapping) == 0
        && linux_set_scheduler(2, 0, mapping) == LINUX_ESRCH
        && linux_set_scheduler(u64::MAX, 0, mapping) == LINUX_EINVAL
        && linux_set_scheduler(0, 4, mapping) == LINUX_EINVAL
        && linux_set_scheduler(0, 1, mapping) == LINUX_EINVAL
        && linux_set_scheduler(0, 0, 1) == LINUX_EFAULT
        && copy_to_linux_user(mapping, &1_u32.to_ne_bytes())
        && linux_set_scheduler(0, 0, mapping) == LINUX_EINVAL;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    setters && unmapped
}

fn verify_linux_scheduler_affinity() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let current = u64::from(current_linux_process_pid());
    let available = linux_available_cpu_mask();
    let topology = verify_linux_cpu_topology_files(mapping);
    let sentinel = [0xa5_u8; 16];
    let mut observed = [0_u8; 16];
    let get = copy_to_linux_user(mapping, &sentinel)
        && linux_sched_getaffinity(0, 8, mapping) == 8
        && copy_from_linux_user(mapping, &mut observed)
        && observed[..8] == available.to_ne_bytes()
        && observed[8..] == sentinel[8..]
        && linux_sched_getaffinity(current, 16, mapping) == 8
        && linux_sched_getaffinity(2, 7, mapping) == LINUX_EINVAL
        && linux_sched_getaffinity(current, 0x2000_0000, mapping) == 8
        && linux_sched_getaffinity(2, 8, mapping) == LINUX_ESRCH
        && linux_sched_getaffinity(u64::MAX, 8, mapping) == LINUX_ESRCH
        && linux_sched_getaffinity(current, 8, 1) == LINUX_EFAULT;
    let set = copy_to_linux_user(mapping, &1_u64.to_ne_bytes())
        && linux_sched_setaffinity(0, 8, mapping) == 0
        && linux_sched_setaffinity(current, 1, mapping) == 0
        && linux_sched_setaffinity(current, 1_u64 << 32, mapping) == 0
        && copy_to_linux_user(mapping, &(available | 1_u64 << 63).to_ne_bytes())
        && linux_sched_setaffinity(current, 8, mapping) == 0
        && copy_to_linux_user(mapping, &2_u64.to_ne_bytes())
        && linux_sched_setaffinity(current, 8, mapping)
            == if available & 2 != 0 { 0 } else { LINUX_EINVAL }
        && linux_sched_setaffinity(current, 8, 1) == LINUX_EFAULT
        && linux_sched_setaffinity(2, 8, 1) == LINUX_EFAULT
        && linux_sched_setaffinity(2, 8, mapping) == LINUX_ESRCH
        && linux_sched_setaffinity(2, 0, 0) == LINUX_ESRCH
        && linux_sched_setaffinity(current, 0, 0) == LINUX_EINVAL;
    let interval = linux_sched_rr_get_interval(current, mapping) == 0
        && linux_sched_rr_get_interval(2, 1) == LINUX_ESRCH
        && linux_sched_rr_get_interval(u64::MAX, mapping) == LINUX_EINVAL
        && linux_sched_rr_get_interval(current, 1) == LINUX_EFAULT;
    let restored = copy_to_linux_user(mapping, &available.to_ne_bytes())
        && linux_sched_setaffinity(current, 8, mapping) == 0;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    topology && get && set && interval && restored && unmapped
}

fn verify_linux_cpu_topology_files(mapping: u64) -> bool {
    let cpu_count = linux_available_cpu_count();
    let mut record = [0_u8; 768];
    let mut cpuinfo_size = 0_usize;
    let mut second_offset = 0_usize;
    for cpu in 0..cpu_count {
        let Some(size) = linux_cpuinfo_record(cpu, cpu_count, &mut record) else {
            return false;
        };
        if cpu == 0 {
            second_offset = size;
        }
        cpuinfo_size = cpuinfo_size.saturating_add(size);
    }
    let mut prefix = [0_u8; 16];
    let first = linux_proc_cpuinfo_read(mapping, prefix.len() as u64, 0) == prefix.len() as u64
        && copy_from_linux_user(mapping, &mut prefix)
        && prefix.starts_with(b"processor\t: 0\n");
    let second = cpu_count == 1
        || linux_proc_cpuinfo_read(mapping, prefix.len() as u64, second_offset as u64)
            == prefix.len() as u64
            && copy_from_linux_user(mapping, &mut prefix)
            && prefix.starts_with(b"processor\t: 1\n");
    // /proc/stat's CPU times advance with the clock (100 per second), so
    // a tick between building the expected text and reading the file
    // changes it: on a slow (emulated) machine that is likely, so the
    // comparison is tried again, each try still exact.
    let stat = (0..8).any(|_| {
        let mut expected_stat = [0_u8; 2048];
        let Some(stat_size) = linux_proc_stat_file(&mut expected_stat) else {
            return false;
        };
        let mut observed_stat = [0_u8; 2048];
        linux_proc_stat_read(mapping, stat_size as u64, 0) == stat_size as u64
            && copy_from_linux_user(mapping, &mut observed_stat[..stat_size])
            && observed_stat[..stat_size] == expected_stat[..stat_size]
            && linux_file_size(LINUX_FILE_PROC_STAT) == stat_size as u64
    });
    first && second && stat && linux_file_size(LINUX_FILE_PROC_CPUINFO) == cpuinfo_size as u64
}

fn verify_linux_realtime_queries() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let stored_time = linux_time(mapping);
    let mut word = [0_u8; 8];
    let time = stored_time <= i64::MAX as u64
        && copy_from_linux_user(mapping, &mut word)
        && u64::from_ne_bytes(word) == stored_time
        && linux_time(0) <= i64::MAX as u64
        && linux_time(1) == LINUX_EFAULT;
    let sentinel = [0xa5_u8; 16];
    let mut timeval = [0_u8; 16];
    let mut timezone = [0_u8; 8];
    let gettimeofday = time
        && copy_to_linux_user(mapping + 32, &sentinel)
        && copy_to_linux_user(mapping + 48, &sentinel[..8])
        && linux_gettimeofday(mapping + 32, mapping + 48) == 0
        && copy_from_linux_user(mapping + 32, &mut timeval)
        && u64::from_ne_bytes(timeval[..8].try_into().unwrap()) != 0
        && u64::from_ne_bytes(timeval[8..].try_into().unwrap()) < 1_000_000
        && copy_from_linux_user(mapping + 48, &mut timezone)
        && timezone == [0; 8]
        && linux_gettimeofday(0, 0) == 0;
    let ordered_faults = gettimeofday
        && copy_to_linux_user(mapping + PAGE_SIZE as u64 - 8, &u64::MAX.to_ne_bytes())
        && linux_gettimeofday(mapping + PAGE_SIZE as u64 - 8, 0) == LINUX_EFAULT
        && copy_from_linux_user(mapping + PAGE_SIZE as u64 - 8, &mut word)
        && u64::from_ne_bytes(word) != u64::MAX
        && copy_to_linux_user(mapping + 48, &sentinel[..8])
        && linux_gettimeofday(mapping + 32, 1) == LINUX_EFAULT
        && copy_from_linux_user(mapping + 32, &mut timeval)
        && u64::from_ne_bytes(timeval[..8].try_into().unwrap()) != 0
        && copy_to_linux_user(mapping + 48, &sentinel[..8])
        && linux_gettimeofday(1, mapping + 48) == LINUX_EFAULT
        && copy_from_linux_user(mapping + 48, &mut timezone)
        && timezone == sentinel[..8];
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    ordered_faults && unmapped
}

fn verify_linux_resource_accounting() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let self_usage = linux_getrusage(UPPER_REGISTER_BITS, mapping) == 0 && {
        let mut usage = [0_u8; 144];
        copy_from_linux_user(mapping, &mut usage)
            && u64::from_ne_bytes(usage[8..16].try_into().unwrap()) < 1_000_000
            && u64::from_ne_bytes(usage[32..40].try_into().unwrap()) != 0
    };
    let selectors = self_usage
        && linux_getrusage(UPPER_REGISTER_BITS | 1, mapping) == 0
        && linux_getrusage(UPPER_REGISTER_BITS | u64::from(u32::MAX), mapping) == 0
        && {
            let mut children = [1_u8; 144];
            copy_from_linux_user(mapping, &mut children) && children == [0; 144]
        }
        && linux_getrusage(UPPER_REGISTER_BITS | 2, mapping) == LINUX_EINVAL
        && linux_getrusage(0, 1) == LINUX_EFAULT;
    let elapsed = linux_times(mapping + 160);
    let times = selectors
        && elapsed < LINUX_RETURN_TO_KERNEL
        && {
            let mut accounting = [0_u8; 32];
            // The process's system time includes kernel work charged to
            // it; it has no children, so theirs is zero.
            copy_from_linux_user(mapping + 160, &mut accounting)
                && u64::from_ne_bytes(accounting[..8].try_into().unwrap()) <= elapsed
                && accounting[16..] == [0; 16]
        }
        && linux_times(0) >= elapsed
        && linux_times(1) == LINUX_EFAULT;
    let sysinfo = times
        && linux_sysinfo(mapping + 256) == 0
        && {
            let mut information = [0_u8; 112];
            copy_from_linux_user(mapping + 256, &mut information)
                && u64::from_ne_bytes(information[32..40].try_into().unwrap()) != 0
                && u64::from_ne_bytes(information[40..48].try_into().unwrap())
                    <= u64::from_ne_bytes(information[32..40].try_into().unwrap())
                && u16::from_ne_bytes(information[80..82].try_into().unwrap()) != 0
                && u32::from_ne_bytes(information[104..108].try_into().unwrap()) == 1
        }
        && linux_sysinfo(1) == LINUX_EFAULT;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    sysinfo && unmapped
}

fn verify_linux_filesystem_statistics() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    const RAMFS_MAGIC: u64 = 0x8584_58f6;
    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    const ANON_INODE_FS_MAGIC: u64 = 0x0904_1934;
    const ROOT_FLAGS: u64 = 32 | 2 | 4;
    const PROC_FLAGS: u64 = 32 | 2 | 4 | 8 | 4096;

    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let paths = copy_to_linux_user(mapping, b"/\0")
        && copy_to_linux_user(mapping + 16, b"/proc/cpuinfo\0")
        && copy_to_linux_user(mapping + 40, b"/linox-statfs-absent\0");
    let mut stat = [0_u8; 120];
    let root = paths
        && linux_statfs(mapping, mapping + 128) == 0
        && copy_from_linux_user(mapping + 128, &mut stat)
        && u64::from_ne_bytes(stat[..8].try_into().unwrap()) == RAMFS_MAGIC
        && u64::from_ne_bytes(stat[8..16].try_into().unwrap()) == PAGE_SIZE as u64
        && u64::from_ne_bytes(stat[16..24].try_into().unwrap()) != 0
        && u64::from_ne_bytes(stat[24..32].try_into().unwrap())
            <= u64::from_ne_bytes(stat[16..24].try_into().unwrap())
        && stat[24..32] == stat[32..40]
        && stat[40..56] == [0; 16]
        && u64::from_ne_bytes(stat[56..64].try_into().unwrap()) == 1
        && u64::from_ne_bytes(stat[64..72].try_into().unwrap()) == 255
        && u64::from_ne_bytes(stat[72..80].try_into().unwrap()) == PAGE_SIZE as u64
        && u64::from_ne_bytes(stat[80..88].try_into().unwrap()) == ROOT_FLAGS
        && stat[88..] == [0; 32];
    let procfs = root
        && linux_statfs(mapping + 16, mapping + 128) == 0
        && copy_from_linux_user(mapping + 128, &mut stat)
        && u64::from_ne_bytes(stat[..8].try_into().unwrap()) == PROC_SUPER_MAGIC
        && u64::from_ne_bytes(stat[56..64].try_into().unwrap()) == 2
        && u64::from_ne_bytes(stat[80..88].try_into().unwrap()) == PROC_FLAGS
        && copy_to_linux_user(mapping + 320, b"/proc/\0")
        && linux_statfs(mapping + 320, mapping + 128) == 0
        && copy_from_linux_user(mapping + 128, &mut stat)
        && u64::from_ne_bytes(stat[..8].try_into().unwrap()) == PROC_SUPER_MAGIC;
    let ordered_errors = procfs
        && linux_statfs(mapping + 40, 1) == LINUX_ENOENT
        && linux_statfs(mapping, 1) == LINUX_EFAULT
        && linux_fstatfs(UPPER_REGISTER_BITS | 2047, 1) == LINUX_EBADF;
    let mut legacy_output = [0xa5_u8; 32];
    let legacy_queries = ordered_errors
        && copy_to_linux_user(mapping + 64, b"proc\0")
        && copy_to_linux_user(mapping + 96, &[0xa5; 9])
        && copy_to_linux_user(mapping + 256, &legacy_output)
        && linux_ustat(UPPER_REGISTER_BITS | 1, mapping + 256) == 0
        && copy_from_linux_user(mapping + 256, &mut legacy_output)
        && legacy_output == [0; 32]
        && linux_ustat(UPPER_REGISTER_BITS | 2, 1) == LINUX_EINVAL
        && linux_ustat(1, 1) == LINUX_EFAULT
        && linux_sysfs(UPPER_REGISTER_BITS | 1, mapping + 64, 0) == 1
        && linux_sysfs(UPPER_REGISTER_BITS | 2, 1, mapping + 96) == 0
        && {
            let mut name = [0_u8; 9];
            copy_from_linux_user(mapping + 96, &mut name)
                && name[..5] == *b"proc\0"
                && name[5..] == [0xa5; 4]
        }
        && linux_sysfs(UPPER_REGISTER_BITS | 3, 0, 0) == 4
        && linux_sysfs(1, 1, 0) == LINUX_EFAULT
        && linux_sysfs(2, UPPER_REGISTER_BITS | 1, 1) == LINUX_EINVAL
        && linux_sysfs(2, 99, 1) == LINUX_EINVAL
        && linux_sysfs(4, 0, 0) == LINUX_EINVAL;
    let root_descriptor = if legacy_queries {
        linux_openat(u64::from(LINUX_AT_FDCWD), mapping, LINUX_O_DIRECTORY, 0)
    } else {
        LINUX_RETURN_TO_KERNEL
    };
    let proc_descriptor = if root_descriptor < LINUX_RETURN_TO_KERNEL {
        linux_openat(
            u64::from(LINUX_AT_FDCWD),
            mapping + 320,
            LINUX_O_PATH | LINUX_O_CLOEXEC,
            0,
        )
    } else {
        LINUX_RETURN_TO_KERNEL
    };
    let descriptors = proc_descriptor < LINUX_RETURN_TO_KERNEL
        && linux_fstatfs(UPPER_REGISTER_BITS | root_descriptor, mapping + 128) == 0
        && copy_from_linux_user(mapping + 128, &mut stat)
        && u64::from_ne_bytes(stat[..8].try_into().unwrap()) == RAMFS_MAGIC
        && linux_fstatfs(UPPER_REGISTER_BITS | proc_descriptor, mapping + 128) == 0
        && copy_from_linux_user(mapping + 128, &mut stat)
        && u64::from_ne_bytes(stat[..8].try_into().unwrap()) == PROC_SUPER_MAGIC;
    let event_descriptor = if descriptors {
        linux_eventfd(0, 0)
    } else {
        LINUX_RETURN_TO_KERNEL
    };
    let anonymous = event_descriptor < LINUX_RETURN_TO_KERNEL
        && linux_fstatfs(event_descriptor, mapping + 128) == 0
        && copy_from_linux_user(mapping + 128, &mut stat)
        && u64::from_ne_bytes(stat[..8].try_into().unwrap()) == ANON_INODE_FS_MAGIC;
    let closed_event =
        event_descriptor >= LINUX_RETURN_TO_KERNEL || linux_descriptor_close(event_descriptor) == 0;
    let closed_proc =
        proc_descriptor >= LINUX_RETURN_TO_KERNEL || linux_descriptor_close(proc_descriptor) == 0;
    let closed_root =
        root_descriptor >= LINUX_RETURN_TO_KERNEL || linux_descriptor_close(root_descriptor) == 0;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    let valid = anonymous && closed_event && closed_proc && closed_root && unmapped;
    if !valid {
        serial_write(
            "linox: statfs verifier paths/root/proc/legacy/descriptors/anonymous/cleanup ",
        );
        for value in [
            paths,
            root,
            procfs,
            legacy_queries,
            descriptors,
            anonymous,
            closed_event && closed_proc && closed_root && unmapped,
        ] {
            serial_write_u64(u64::from(value));
            serial_write(" ");
        }
        serial_write("fds ");
        serial_write_u64(root_descriptor);
        serial_write(" ");
        serial_write_u64(proc_descriptor);
        serial_write(" ");
        serial_write_u64(event_descriptor);
        serial_write("\r\n");
    }
    valid
}

fn verify_linux_robust_list_syscalls() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let saved = current_linux_robust_list().unwrap_or(0);
    let sentinel = u64::MAX.to_ne_bytes();
    let registered = set_current_linux_robust_list(1)
        && copy_to_linux_user(mapping, &sentinel)
        && copy_to_linux_user(mapping + 8, &sentinel);
    let mut head = [0_u8; 8];
    let mut size = [0_u8; 8];
    let current = registered
        && linux_get_robust_list(0, mapping, mapping + 8) == 0
        && copy_from_linux_user(mapping, &mut head)
        && u64::from_ne_bytes(head) == 1
        && copy_from_linux_user(mapping + 8, &mut size)
        && u64::from_ne_bytes(size) == LINUX_ROBUST_LIST_HEAD_SIZE as u64
        && linux_get_robust_list(1_u64 << 32, mapping, mapping + 8) == 0;
    let ordered_faults = current
        && copy_to_linux_user(mapping, &sentinel)
        && linux_get_robust_list(0, mapping, 1) == LINUX_EFAULT
        && copy_from_linux_user(mapping, &mut head)
        && head == sentinel
        && copy_to_linux_user(mapping + 8, &sentinel)
        && linux_get_robust_list(0, 1, mapping + 8) == LINUX_EFAULT
        && copy_from_linux_user(mapping + 8, &mut size)
        && u64::from_ne_bytes(size) == LINUX_ROBUST_LIST_HEAD_SIZE as u64
        && linux_get_robust_list(2, mapping, mapping + 8) == LINUX_ESRCH
        && linux_get_robust_list(u64::MAX, mapping, mapping + 8) == LINUX_ESRCH;
    let robust_head = mapping + 64;
    let robust_node = mapping + 96;
    let robust_futex = robust_node + 8;
    let tid = current_linux_tid().unwrap_or(0);
    let mut header = [0_u8; LINUX_ROBUST_LIST_HEAD_SIZE];
    header[..8].copy_from_slice(&robust_node.to_ne_bytes());
    header[8..16].copy_from_slice(&8_i64.to_ne_bytes());
    let listed = ordered_faults
        && copy_to_linux_user(robust_head, &header)
        && copy_to_linux_user(robust_node, &robust_head.to_ne_bytes())
        && copy_to_linux_user(robust_futex, &(tid | 0x8000_0000).to_ne_bytes());
    if listed {
        exit_linux_robust_list(tid, robust_head);
    }
    let mut futex = [0_u8; 4];
    let owner_died = listed
        && copy_from_linux_user(robust_futex, &mut futex)
        && u32::from_ne_bytes(futex) == 0xc000_0000;
    header[..8].copy_from_slice(&robust_head.to_ne_bytes());
    header[16..24].copy_from_slice(&robust_node.to_ne_bytes());
    let pending = owner_died
        && copy_to_linux_user(robust_head, &header)
        && copy_to_linux_user(robust_futex, &tid.to_ne_bytes());
    if pending {
        exit_linux_robust_list(tid, robust_head);
    }
    let pending_died = pending
        && copy_from_linux_user(robust_futex, &mut futex)
        && u32::from_ne_bytes(futex) == 0x4000_0000;
    let foreign = tid.saturating_add(1);
    let foreign_unchanged =
        pending_died && copy_to_linux_user(robust_futex, &foreign.to_ne_bytes());
    if foreign_unchanged {
        exit_linux_robust_list(tid, robust_head);
    }
    let cleanup = foreign_unchanged
        && copy_from_linux_user(robust_futex, &mut futex)
        && u32::from_ne_bytes(futex) == foreign;
    let restored = set_current_linux_robust_list(saved);
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    cleanup && restored && unmapped
}

fn verify_linux_rseq_syscall() -> bool {
    let Some(slot) = current_linux_thread_slot() else {
        return false;
    };
    if X86_RUNTIME.LINUX_THREAD_RSEQ_POINTERS[slot].load(Ordering::SeqCst) != 0 {
        return false;
    }
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let signature = 0x5305_3053_u64;
    let registered = copy_to_linux_user(mapping, &[0xa5_u8; 36])
        && linux_rseq(mapping, (1_u64 << 32) | 36, 1_u64 << 32, signature) == 0
        && linux_rseq(mapping, 36, 0, signature) == LINUX_EBUSY
        && linux_rseq(mapping, 36, 0, signature + 1) == LINUX_EPERM
        && linux_rseq(mapping + 4, 36, 0, signature) == LINUX_EINVAL
        && linux_rseq(mapping, 35, 1, signature) == LINUX_EINVAL
        && linux_rseq(mapping, 36, 1, signature + 1) == LINUX_EPERM;
    let mut area = [0xa5_u8; 32];
    let initialized = registered
        && copy_from_linux_user(mapping, &mut area)
        && area[..8] == [0; 8]
        && area[20..28] == [0; 8];
    let unregistered = initialized
        && linux_rseq(mapping, 36, 1, signature) == 0
        && copy_from_linux_user(mapping, &mut area)
        && area[..4] == [0; 4]
        && area[4..8] == u32::MAX.to_ne_bytes()
        && area[20..28] == [0; 8]
        && linux_rseq(mapping, 36, 1, signature) == LINUX_EINVAL
        && linux_rseq(mapping, 31, 0, signature) == LINUX_EINVAL
        && linux_rseq(mapping + 4, 32, 0, signature) == LINUX_EINVAL
        && linux_rseq(mapping + PAGE_SIZE as u64, 32, 0, signature) == LINUX_EFAULT;
    let clean = X86_RUNTIME.LINUX_THREAD_RSEQ_POINTERS[slot].load(Ordering::SeqCst) == 0
        && X86_RUNTIME.LINUX_THREAD_RSEQ_LENGTHS[slot].load(Ordering::SeqCst) == 0
        && X86_RUNTIME.LINUX_THREAD_RSEQ_SIGNATURES[slot].load(Ordering::SeqCst) == 0;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    unregistered && clean && unmapped
}

fn verify_linux_membarrier_syscall() -> bool {
    let saved = X86_RUNTIME
        .ELF_PROBE_MEMBARRIER_REGISTRATIONS
        .swap(0, Ordering::SeqCst);
    let query = linux_membarrier(1_u64 << 32, 1_u64 << 32, u64::MAX)
        == u64::from(MEMBARRIER_SUPPORTED_COMMANDS)
        && linux_membarrier(0, 1, 0) == LINUX_EINVAL
        && linux_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED.into(), 0, 0) == LINUX_EPERM
        && linux_membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS.into(), 0, 0) == 0;
    let private = query
        && linux_membarrier(
            MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED.into(),
            0,
            u64::MAX,
        ) == 0
        && linux_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED.into(), 0, 0) == 0
        && linux_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED.into(), 0, u64::MAX) == 0;
    let global = private
        && linux_membarrier(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED.into(), 0, 0) == 0
        && linux_membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS.into(), 0, 0)
            == u64::from(
                MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
                    | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
            )
        && linux_membarrier(MEMBARRIER_CMD_GLOBAL.into(), 0, u64::MAX) == 0
        && linux_membarrier(MEMBARRIER_CMD_GLOBAL_EXPEDITED.into(), 0, u64::MAX) == 0;
    let rejected = global
        && linux_membarrier(1 << 5, 0, 0) == LINUX_EINVAL
        && linux_membarrier(
            MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ.into(),
            MEMBARRIER_CMD_FLAG_CPU.into(),
            0,
        ) == LINUX_EINVAL
        && linux_membarrier(u64::from(u32::MAX), 0, 0) == LINUX_EINVAL;
    X86_RUNTIME
        .ELF_PROBE_MEMBARRIER_REGISTRATIONS
        .store(saved, Ordering::SeqCst);
    rejected
}

fn verify_linux_readahead_syscall() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let Some(node) = crate::linux_overlay::create_file(b"linox-readahead", 0o600, b"resident")
    else {
        let _ = linux_runtime_munmap(mapping, PAGE_SIZE as u64);
        return false;
    };
    let prepared = copy_to_linux_user(mapping, b"/linox-readahead\0");
    let input = if prepared {
        linux_openat(u64::from(LINUX_AT_FDCWD), mapping, 0, 0)
    } else {
        LINUX_EFAULT
    };
    let output = if input < LINUX_AUX_DESCRIPTOR_LIMIT {
        linux_openat(u64::from(LINUX_AT_FDCWD), mapping, 1, 0)
    } else {
        LINUX_EFAULT
    };
    let directory = if output < LINUX_AUX_DESCRIPTOR_LIMIT && copy_to_linux_user(mapping, b"/\0") {
        linux_openat(u64::from(LINUX_AT_FDCWD), mapping, LINUX_O_DIRECTORY, 0)
    } else {
        LINUX_EFAULT
    };
    let positive = input < LINUX_AUX_DESCRIPTOR_LIMIT
        && output < LINUX_AUX_DESCRIPTOR_LIMIT
        && directory < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_readahead(input, 0, 0) == 0
        && linux_readahead((1_u64 << 32) | input, 1, u64::MAX) == 0;
    let errors = positive
        && linux_readahead(input, u64::MAX, 1) == LINUX_EINVAL
        && linux_readahead(output, 0, 1) == LINUX_EBADF
        && linux_readahead(LINUX_AUX_DESCRIPTOR_LIMIT, 0, 1) == LINUX_EBADF
        && linux_readahead(directory, 0, 1) == LINUX_EINVAL;
    let closed = input < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(input) == 0
        && output < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(output) == 0
        && directory < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(directory) == 0;
    let removed = crate::linux_overlay::unlink(node);
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    errors && closed && removed && unmapped
}

fn verify_linux_memory_locking_syscalls() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64 * 2,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let ranges = [
        linux_memory_lock(u64::MAX, 0, 0, true),
        linux_memory_lock(mapping + 1, PAGE_SIZE as u64, 0, true),
        linux_memory_lock(mapping, PAGE_SIZE as u64 * 2, 1, true),
        linux_memory_lock(mapping, PAGE_SIZE as u64, 2, true),
        linux_memory_lock(mapping + PAGE_SIZE as u64 * 2, 1, 0, true),
    ] == [0, 0, 0, LINUX_EINVAL, LINUX_ENOMEM];
    let all = ranges
        && [1_u64, 2, 3, 5, 6, 7]
            .into_iter()
            .all(|flags| linux_mlockall(flags) == 0)
        && linux_mlockall(0) == LINUX_EINVAL
        && linux_mlockall(4) == LINUX_EINVAL
        && linux_mlockall(8) == LINUX_EINVAL
        && linux_mlockall(UPPER_REGISTER_BITS | 1) == 0
        && linux_msync(mapping, PAGE_SIZE as u64, UPPER_REGISTER_BITS | 4) == 0
        && linux_pkey_mprotect(
            mapping,
            PAGE_SIZE as u64,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            UPPER_REGISTER_BITS,
        ) == 0
        && linux_pkey_mprotect(
            mapping,
            PAGE_SIZE as u64,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            UPPER_REGISTER_BITS | u64::from(u32::MAX),
        ) == 0;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64 * 2) == 0;
    all && unmapped
}

fn verify_linux_address_space_limit() -> bool {
    let Some(original_limit) = linux_resource_limit_values(
        LINUX_RLIMIT_AS,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    ) else {
        return false;
    };
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let Some(current_bytes) = address_space::current_linux_user_page_count()
        .and_then(|pages| pages.checked_mul(PAGE_SIZE))
        .and_then(|bytes| u64::try_from(bytes).ok())
    else {
        let _ = linux_runtime_munmap(mapping, PAGE_SIZE as u64);
        return false;
    };
    let limited = linux_set_process_resource_limit(
        current_linux_process_pid(),
        LINUX_RLIMIT_AS,
        [current_bytes, original_limit[1]],
    ) == 0;
    let rejected = limited
        && linux_runtime_mmap(
            0,
            PAGE_SIZE as u64,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ) == LINUX_ENOMEM
        && linux_mremap(mapping, PAGE_SIZE as u64, PAGE_SIZE as u64 * 2, 1, 0) == LINUX_ENOMEM;
    let replaced = rejected
        && linux_runtime_mmap(
            mapping,
            PAGE_SIZE as u64,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
            u64::MAX,
            0,
        ) == mapping
        && address_space::current_linux_user_page_count()
            .and_then(|pages| pages.checked_mul(PAGE_SIZE))
            .and_then(|bytes| u64::try_from(bytes).ok())
            == Some(current_bytes);
    let restored = linux_set_process_resource_limit(
        current_linux_process_pid(),
        LINUX_RLIMIT_AS,
        original_limit,
    ) == 0;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    let valid = limited && rejected && replaced && restored && unmapped;
    if valid {
        serial_write("linox: Linux address-space resource limit enforced\r\n");
    }
    valid
}

fn verify_linux_fadvise64_syscall() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let Some(node) = crate::linux_overlay::create_file(b"linox-fadvise", 0o600, b"resident") else {
        let _ = linux_runtime_munmap(mapping, PAGE_SIZE as u64);
        return false;
    };
    let descriptor = if copy_to_linux_user(mapping, b"/linox-fadvise\0") {
        linux_openat(u64::from(LINUX_AT_FDCWD), mapping, 0, 0)
    } else {
        LINUX_EFAULT
    };
    let regular = descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && (0_u64..=5).all(|advice| linux_fadvise64(descriptor, 0, 0, advice) == 0)
        && linux_fadvise64(
            (1_u64 << 32) | descriptor,
            i64::MAX as u64,
            i64::MAX as u64,
            (1_u64 << 32) | 5,
        ) == 0
        && linux_fadvise64(descriptor, u64::MAX, 0, 0) == LINUX_EINVAL
        && linux_fadvise64(descriptor, 0, u64::MAX, 0) == LINUX_EINVAL
        && linux_fadvise64(descriptor, 0, 0, 6) == LINUX_EINVAL
        && linux_fadvise64(LINUX_AUX_DESCRIPTOR_LIMIT, 0, 0, 0) == LINUX_EBADF;
    let pipe_created = regular && linux_pipe(mapping + 128, (1_u64 << 32) | LINUX_O_CLOEXEC) == 0;
    let mut descriptors = [0_u8; 8];
    let pipe = if pipe_created && copy_from_linux_user(mapping + 128, &mut descriptors) {
        [
            u64::from(u32::from_ne_bytes(descriptors[..4].try_into().unwrap())),
            u64::from(u32::from_ne_bytes(descriptors[4..].try_into().unwrap())),
        ]
    } else {
        [LINUX_AUX_DESCRIPTOR_LIMIT; 2]
    };
    // Neither call here waits, so neither needs a caller to return to.
    let no_caller = LinuxUserContext {
        registers: LinuxSyscallFrame::ZERO,
        rip: 0,
        rsp: 0,
        rflags: 0,
        rax: 0,
        fs_base: 0,
    };
    let pipe_rejected = pipe[0] < LINUX_AUX_DESCRIPTOR_LIMIT
        && pipe[1] < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close_on_exec(pipe[0])
        && linux_descriptor_close_on_exec(pipe[1])
        && linux_vmsplice_live_return(
            LinuxSyscallFrameHandle::NONE,
            no_caller,
            (1_u64 << 32) | pipe[1],
            0,
            0,
            (1_u64 << 32) | LINUX_SPLICE_F_NONBLOCK,
        ) == 0
        && linux_tee(
            LinuxSyscallFrameHandle::NONE,
            no_caller,
            (1_u64 << 32) | pipe[0],
            (1_u64 << 32) | pipe[1],
            0,
            1_u64 << 32,
        ) == 0
        && linux_fadvise64(pipe[0], u64::MAX, u64::MAX, 6) == LINUX_ESPIPE;
    let closed = descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(descriptor) == 0
        && pipe[0] < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(pipe[0]) == 0
        && pipe[1] < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(pipe[1]) == 0;
    let removed = crate::linux_overlay::unlink(node);
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    pipe_rejected && closed && removed && unmapped
}

fn verify_linux_io_uring_syscalls() -> bool {
    let parameters = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&parameters)
    {
        return false;
    }
    let descriptor = if copy_to_linux_user(parameters, &[0_u8; 120]) {
        linux_io_uring_setup((1_u64 << 32) | 3, parameters)
    } else {
        LINUX_EBADF
    };
    let setup = descriptor < LINUX_AUX_DESCRIPTOR_LIMIT && {
        let mut output = [0_u8; 120];
        copy_from_linux_user(parameters, &mut output)
            && u32::from_ne_bytes(output[..4].try_into().unwrap()) == 4
            && u32::from_ne_bytes(output[4..8].try_into().unwrap()) == 8
            && u32::from_ne_bytes(output[64..68].try_into().unwrap()) == 24
            && u32::from_ne_bytes(output[100..104].try_into().unwrap()) == 32
    };
    let map = |offset| {
        linux_io_uring_mmap(
            0,
            PAGE_SIZE as u64,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_SHARED,
            descriptor,
            offset,
        )
    };
    let sq = if setup { map(0) } else { LINUX_EINVAL };
    let cq = if sq < LINUX_RETURN_TO_KERNEL {
        map(0x0800_0000)
    } else {
        LINUX_EINVAL
    };
    let sqes = if cq < LINUX_RETURN_TO_KERNEL {
        map(0x1000_0000)
    } else {
        LINUX_EINVAL
    };
    let rings = sqes < LINUX_RETURN_TO_KERNEL
        && copy_to_linux_user(sq + 24, &0_u32.to_ne_bytes())
        && copy_to_linux_user(sq + 4, &1_u32.to_ne_bytes())
        && copy_to_linux_user(sqes + 32, &0x4749_4e55_5852_494f_u64.to_ne_bytes());
    let submitted = rings
        && linux_io_uring_enter(
            (1_u64 << 32) | descriptor,
            (1_u64 << 32) | 1,
            (1_u64 << 32) | 1,
            (1_u64 << 32) | 1,
            0,
            0,
        ) == 1;
    let completed = submitted && {
        let mut tail = [0_u8; 4];
        let mut completion = [0_u8; 16];
        copy_from_linux_user(cq + 4, &mut tail)
            && u32::from_ne_bytes(tail) == 1
            && copy_from_linux_user(cq + 32, &mut completion)
            && u64::from_ne_bytes(completion[..8].try_into().unwrap()) == 0x4749_4e55_5852_494f
            && i32::from_ne_bytes(completion[8..12].try_into().unwrap()) == 0
    };
    let io_descriptor = if completed && copy_to_linux_user(parameters + 512, b"/dev/zero\0") {
        linux_openat(u64::from(LINUX_AT_FDCWD), parameters + 512, 2, 0)
    } else {
        LINUX_EBADF
    };
    let read_sqe = io_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT && {
        let mut sqe = [0_u8; 64];
        sqe[0] = 22;
        sqe[4..8].copy_from_slice(&(io_descriptor as u32).to_ne_bytes());
        sqe[8..16].copy_from_slice(&u64::MAX.to_ne_bytes());
        sqe[16..24].copy_from_slice(&(parameters + 1024).to_ne_bytes());
        sqe[24..28].copy_from_slice(&16_u32.to_ne_bytes());
        sqe[32..40].copy_from_slice(&0x5245_4144_u64.to_ne_bytes());
        copy_to_linux_user(sq + 28, &1_u32.to_ne_bytes())
            && copy_to_linux_user(sq + 4, &2_u32.to_ne_bytes())
            && copy_to_linux_user(sqes + 64, &sqe)
            && linux_io_uring_enter(descriptor, 1, 1, 1, 0, 0) == 1
    };
    let read_completed = read_sqe && {
        let mut completion = [0_u8; 16];
        let mut bytes = [1_u8; 16];
        copy_from_linux_user(cq + 48, &mut completion)
            && u64::from_ne_bytes(completion[..8].try_into().unwrap()) == 0x5245_4144
            && i32::from_ne_bytes(completion[8..12].try_into().unwrap()) == 16
            && copy_from_linux_user(parameters + 1024, &mut bytes)
            && bytes == [0_u8; 16]
    };
    let write_sqe = read_completed && {
        let mut sqe = [0_u8; 64];
        sqe[0] = 23;
        sqe[4..8].copy_from_slice(&(io_descriptor as u32).to_ne_bytes());
        sqe[8..16].copy_from_slice(&u64::MAX.to_ne_bytes());
        sqe[16..24].copy_from_slice(&(parameters + 1024).to_ne_bytes());
        sqe[24..28].copy_from_slice(&16_u32.to_ne_bytes());
        sqe[32..40].copy_from_slice(&0x0057_5249_5445_u64.to_ne_bytes());
        copy_to_linux_user(sq + 32, &2_u32.to_ne_bytes())
            && copy_to_linux_user(sq + 4, &3_u32.to_ne_bytes())
            && copy_to_linux_user(sqes + 128, &sqe)
            && linux_io_uring_enter(descriptor, 1, 1, 1, 0, 0) == 1
    };
    let io_completed = write_sqe && {
        let mut completion = [0_u8; 16];
        copy_from_linux_user(cq + 64, &mut completion)
            && u64::from_ne_bytes(completion[..8].try_into().unwrap()) == 0x0057_5249_5445
            && i32::from_ne_bytes(completion[8..12].try_into().unwrap()) == 16
            && linux_descriptor_close(io_descriptor) == 0
    };
    let probe = io_completed
        && linux_io_uring_register(
            (1_u64 << 32) | descriptor,
            (1_u64 << 32) | 8,
            parameters + 256,
            (1_u64 << 32) | 24,
        ) == 0
        && {
            let mut output = [0_u8; 16 + 24 * 8];
            copy_from_linux_user(parameters + 256, &mut output)
                && output[0] == LINUX_IORING_OP_LAST
                && output[1] == 24
                && u16::from_ne_bytes(output[2..4].try_into().unwrap()) == 0
                && output[16] == 0
                && u16::from_ne_bytes(output[18..20].try_into().unwrap()) == 1
                && output[24] == 1
                && u16::from_ne_bytes(output[26..28].try_into().unwrap()) == 1
                && output[40] == 3
                && u16::from_ne_bytes(output[42..44].try_into().unwrap()) == 1
                && output[192] == 22
                && u16::from_ne_bytes(output[194..196].try_into().unwrap()) == 1
                && output[200] == 23
                && u16::from_ne_bytes(output[202..204].try_into().unwrap()) == 1
        };
    let duplicate = if probe {
        linux_console_dup(descriptor)
    } else {
        LINUX_EBADF
    };
    let closed = duplicate < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(descriptor) == 0
        && linux_descriptor_close(duplicate) == 0;
    let unmapped = sq < LINUX_RETURN_TO_KERNEL
        && cq < LINUX_RETURN_TO_KERNEL
        && sqes < LINUX_RETURN_TO_KERNEL
        && linux_runtime_munmap(sq, PAGE_SIZE as u64) == 0
        && linux_runtime_munmap(cq, PAGE_SIZE as u64) == 0
        && linux_runtime_munmap(sqes, PAGE_SIZE as u64) == 0
        && linux_runtime_munmap(parameters, PAGE_SIZE as u64) == 0;
    closed && unmapped
}

fn verify_linux_fanotify_syscalls() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let Some(node) = crate::linux_overlay::create_file(b"linox-fanotify", 0o600, &[]) else {
        let _ = linux_runtime_munmap(mapping, PAGE_SIZE as u64);
        return false;
    };
    let prepared = copy_to_linux_user(mapping, b"/linox-fanotify\0")
        && copy_to_linux_user(mapping + 64, b"fan");
    let source = if prepared {
        linux_openat(u64::from(LINUX_AT_FDCWD), mapping, 2, 0)
    } else {
        LINUX_EBADF
    };
    let group = if source < LINUX_AUX_DESCRIPTOR_LIMIT {
        linux_fanotify_init(
            UPPER_REGISTER_BITS | 3,
            UPPER_REGISTER_BITS | LINUX_O_CLOEXEC,
        )
    } else {
        LINUX_EBADF
    };
    let marked = group < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_fanotify_mark(
            UPPER_REGISTER_BITS | group,
            UPPER_REGISTER_BITS | 1,
            2,
            UPPER_REGISTER_BITS | u64::from(LINUX_AT_FDCWD),
            mapping,
        ) == 0;
    // The write system call's hook reports the modification.
    let wrote = |source| {
        linux_descriptor_write(source, mapping + 64, 3) == 3 && {
            linux_fanotify_event(b"linox-fanotify", crate::linux_fanotify::FAN_MODIFY);
            true
        }
    };
    let notified =
        marked && wrote(source) && linux_fanotify_read(group, mapping + 128, 24) == Some(24);
    let mut event = [0_u8; 24];
    let event_descriptor = if notified && copy_from_linux_user(mapping + 128, &mut event) {
        u32::from_ne_bytes(event[16..20].try_into().unwrap()) as u64
    } else {
        u64::MAX
    };
    let event_valid = event_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && u32::from_ne_bytes(event[..4].try_into().unwrap()) == 24
        && event[4] == 3
        && u16::from_ne_bytes(event[6..8].try_into().unwrap()) == 24
        && u64::from_ne_bytes(event[8..16].try_into().unwrap()) == 2
        && linux_descriptor_open(event_descriptor);
    let removed = event_valid
        && linux_fanotify_mark(group, 2, 2, u64::from(LINUX_AT_FDCWD), mapping) == 0
        && wrote(source)
        && linux_fanotify_read(group, mapping + 128, 24) == Some(LINUX_EAGAIN);
    let closed = event_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(event_descriptor) == 0
        && linux_descriptor_close(source) == 0
        && linux_descriptor_close(group) == 0;
    let removed_file = crate::linux_overlay::unlink(node);
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    removed && closed && removed_file && unmapped
}

fn verify_linux_keyring_syscalls() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let prepared = copy_to_linux_user(mapping, b"user\0")
        && copy_to_linux_user(mapping + 64, b"linox-key\0")
        && copy_to_linux_user(mapping + 128, b"first")
        && copy_to_linux_user(mapping + 192, b"updated");
    let serial = if prepared {
        linux_add_key(mapping, mapping + 64, mapping + 128, 5, (-2_i64) as u64)
    } else {
        LINUX_EINVAL
    };
    let added = (1..i32::MAX as u64).contains(&serial)
        && linux_request_key(mapping, mapping + 64, 0, 0) == serial;
    let read = added && linux_keyctl(11, serial, mapping + 256, 16, 0) == 5 && {
        let mut payload = [0_u8; 5];
        copy_from_linux_user(mapping + 256, &mut payload) && payload == *b"first"
    };
    let updated = read
        && linux_keyctl(2, serial, mapping + 192, 7, 0) == 0
        && linux_keyctl(11, serial, mapping + 256, 16, 0) == 7
        && {
            let mut payload = [0_u8; 7];
            copy_from_linux_user(mapping + 256, &mut payload) && payload == *b"updated"
        };
    let described = updated && linux_keyctl(6, serial, mapping + 320, 64, 0) == 28 && {
        let mut description = [0_u8; 28];
        copy_from_linux_user(mapping + 320, &mut description)
            && description == *b"user;0;0;3f010000;linox-key\0"
    };
    let revoked = described
        && linux_keyctl(3, serial, 0, 0, 0) == 0
        && linux_keyctl(11, serial, mapping + 256, 16, 0) == LINUX_EKEYREVOKED;
    let rejected = revoked
        && linux_add_key(
            mapping,
            mapping + 64,
            mapping + 128,
            linox_keyrings::PAYLOAD_LIMIT as u64 + 1,
            (-2_i64) as u64,
        ) == LINUX_EINVAL
        && linux_request_key(mapping, mapping + 64, 0, 0) == LINUX_EKEYREVOKED;
    let cleared = crate::linux_keyring::teardown();
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    rejected && cleared && unmapped
}

fn verify_linux_remap_file_pages_syscall() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let private_rejected =
        linux_remap_file_pages(mapping, PAGE_SIZE as u64, 0, 0, 0) == LINUX_EINVAL;
    let invalid_rejected = linux_remap_file_pages(mapping + 1, PAGE_SIZE as u64, 0, 0, 0)
        == LINUX_EINVAL
        && linux_remap_file_pages(mapping, 0, 0, 0, 0) == LINUX_EINVAL
        && linux_remap_file_pages(mapping, PAGE_SIZE as u64, 1, 0, 0) == LINUX_EINVAL
        && linux_remap_file_pages(mapping, PAGE_SIZE as u64, 0, u64::MAX, 0) == LINUX_EINVAL;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    private_rejected && invalid_rejected && unmapped
}

fn verify_linux_seccomp_syscall() -> bool {
    const GET_ACTION_AVAIL: u64 = 2;
    const UNKNOWN_ACTION: u32 = 0x1234_0000;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let strict_contract = linux_seccomp_strict_syscall_allowed(LINUX_READ_SYSCALL)
        && linux_seccomp_strict_syscall_allowed(LINUX_WRITE_SYSCALL)
        && linux_seccomp_strict_syscall_allowed(LINUX_EXIT_SYSCALL)
        && linux_seccomp_strict_syscall_allowed(LINUX_RT_SIGRETURN_SYSCALL)
        && !linux_seccomp_strict_syscall_allowed(LINUX_EXIT_GROUP_SYSCALL)
        && !linux_seccomp_strict_syscall_allowed(LINUX_SECCOMP_SYSCALL);
    let kill_available = strict_contract
        && copy_to_linux_user(mapping, &0_u32.to_ne_bytes())
        && linux_seccomp(GET_ACTION_AVAIL, 0, mapping) == 0;
    let unknown_action_rejected = kill_available
        && copy_to_linux_user(mapping, &linox_seccomp::action::ALLOW.to_ne_bytes())
        && linux_seccomp(GET_ACTION_AVAIL, 0, mapping) == 0
        && copy_to_linux_user(mapping, &UNKNOWN_ACTION.to_ne_bytes())
        && linux_seccomp(GET_ACTION_AVAIL, 0, mapping) == LINUX_EOPNOTSUPP
        && linux_seccomp(GET_ACTION_AVAIL, 1, mapping) == LINUX_EINVAL
        && linux_seccomp(GET_ACTION_AVAIL, 0, 0) == LINUX_EFAULT;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    unknown_action_rejected && unmapped
}

fn verify_linux_file_handle_syscalls() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let Some(node) = crate::linux_overlay::create_file(b"linox-handle", 0o600, b"handle") else {
        let _ = linux_runtime_munmap(mapping, PAGE_SIZE as u64);
        return false;
    };
    let path = b"/linox-handle\0";
    let prepared =
        copy_to_linux_user(mapping, path) && copy_to_linux_user(mapping + 64, &0_u32.to_ne_bytes());
    let sized = prepared
        && linux_name_to_handle_at(
            u64::from(LINUX_AT_FDCWD),
            mapping,
            mapping + 64,
            mapping + 128,
            0,
        ) == LINUX_EOVERFLOW
        && {
            let mut size = [0_u8; 4];
            let mut mount = [0_u8; 4];
            copy_from_linux_user(mapping + 64, &mut size)
                && copy_from_linux_user(mapping + 128, &mut mount)
                && u32::from_ne_bytes(size) == 8
                && i32::from_ne_bytes(mount) == 1
        };
    let named = sized
        && linux_name_to_handle_at(
            u64::from(LINUX_AT_FDCWD),
            mapping,
            mapping + 64,
            mapping + 128,
            0,
        ) == 0;
    let renamed = named && crate::linux_overlay::rename(node, b"linox-handle-renamed");
    let descriptor = if renamed {
        linux_open_by_handle_at(u64::from(LINUX_AT_FDCWD), mapping + 64, 0)
    } else {
        LINUX_EBADF
    };
    let reopened = descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_read(descriptor, mapping + 256, 6) == 6
        && {
            let mut contents = [0_u8; 6];
            copy_from_linux_user(mapping + 256, &mut contents) && contents == *b"handle"
        };
    let path_descriptor = if named {
        linux_open_by_handle_at(
            u64::from(LINUX_AT_FDCWD),
            mapping + 64,
            LINUX_O_PATH | LINUX_O_CLOEXEC,
        )
    } else {
        LINUX_EBADF
    };
    let path_only = path_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close_on_exec(path_descriptor)
        && linux_descriptor_read(path_descriptor, mapping + 256, 1) == LINUX_EBADF;
    let closed = descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(descriptor) == 0
        && path_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(path_descriptor) == 0;
    let removed = crate::linux_overlay::unlink(node);
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    reopened && path_only && closed && removed && unmapped
}

fn verify_linux_mount_query_syscalls() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let namespace = linux_mount::current_namespace_id().unwrap_or(0);
    let mut request = [0_u8; 32];
    request[..4].copy_from_slice(&32_u32.to_ne_bytes());
    request[8..16].copy_from_slice(&u64::MAX.to_ne_bytes());
    request[24..].copy_from_slice(&namespace.to_ne_bytes());
    let listed =
        copy_to_linux_user(mapping, &request) && linux_listmount(mapping, mapping + 64, 2, 0) == 2;
    let mut identifiers = [0_u8; 16];
    let (root, proc_mount) = if listed && copy_from_linux_user(mapping + 64, &mut identifiers) {
        (
            u64::from_ne_bytes(identifiers[..8].try_into().unwrap()),
            u64::from_ne_bytes(identifiers[8..].try_into().unwrap()),
        )
    } else {
        (0, 0)
    };
    request[8..16].copy_from_slice(&root.to_ne_bytes());
    request[16..24].copy_from_slice(&0xff_u64.to_ne_bytes());
    let root_stat = root != 0
        && proc_mount != 0
        && copy_to_linux_user(mapping, &request)
        && linux_statmount(mapping, mapping + 512, 1024, 0) == 0;
    let mut stat = [0_u8; 608];
    let root_valid = root_stat
        && copy_from_linux_user(mapping + 512, &mut stat)
        && u32::from_ne_bytes(stat[..4].try_into().unwrap()) > 512
        && u64::from_ne_bytes(stat[8..16].try_into().unwrap()) == 0xff
        && u64::from_ne_bytes(stat[40..48].try_into().unwrap()) == root
        && u64::from_ne_bytes(stat[48..56].try_into().unwrap()) == root
        && u32::from_ne_bytes(stat[56..60].try_into().unwrap()) == 1;
    request[8..16].copy_from_slice(&proc_mount.to_ne_bytes());
    request[16..24].copy_from_slice(&2_u64.to_ne_bytes());
    let proc_valid = root_valid
        && copy_to_linux_user(mapping, &request)
        && linux_statmount(mapping, mapping + 512, 512, 0) == 0
        && {
            let mut basic = [0_u8; 64];
            copy_from_linux_user(mapping + 512, &mut basic)
                && u64::from_ne_bytes(basic[40..48].try_into().unwrap()) == proc_mount
                && u64::from_ne_bytes(basic[48..56].try_into().unwrap()) == root
                && u32::from_ne_bytes(basic[56..60].try_into().unwrap()) == 2
        };
    // As Linux: a mask bit statmount does not know is dropped, not
    // refused, and listmount with no room lists nothing. listmount reads
    // the request's `param` as the last id listed, which must be 0 or a
    // unique id (above 2^31): the mask left there is EINVAL.
    request[16..24].copy_from_slice(&0x102_u64.to_ne_bytes());
    let lenient = proc_valid
        && copy_to_linux_user(mapping, &request)
        && linux_statmount(mapping, mapping + 512, 1024, 0) == 0
        && {
            let mut mask = [0_u8; 8];
            copy_from_linux_user(mapping + 520, &mut mask) && u64::from_ne_bytes(mask) == 2
        }
        && linux_listmount(mapping, mapping + 64, 0, 0) == LINUX_EINVAL
        && {
            request[16..24].copy_from_slice(&0_u64.to_ne_bytes());
            copy_to_linux_user(mapping, &request)
        }
        && linux_listmount(mapping, mapping + 64, 0, 0) == 0;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    lenient && unmapped
}

fn verify_linux_memfd_seals() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
        || !copy_to_linux_user(mapping, b"linox-seals\0")
        || !copy_to_linux_user(mapping + 64, b"data")
    {
        return false;
    }
    let descriptor = linux_memfd_create(mapping, 2);
    let duplicated = if descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT {
        linux_device_dup_at_least(descriptor, LINUX_AUX_DESCRIPTOR_FIRST, false)
    } else {
        LINUX_EBADF
    };
    let initial = descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT
        && duplicated < LINUX_DESCRIPTOR_TABLE_LIMIT
        && linux_descriptor_fcntl(descriptor, LINUX_F_GET_SEALS, 0) == 0
        && linux_regular_file_write_at(descriptor, mapping + 64, 4, 0) == 4;
    let shared = initial
        && linux_descriptor_fcntl(duplicated, LINUX_F_ADD_SEALS, LINUX_F_SEAL_GROW.into()) == 0
        && linux_descriptor_fcntl(descriptor, LINUX_F_GET_SEALS, 0) == u64::from(LINUX_F_SEAL_GROW)
        && linux_regular_file_write_at(descriptor, mapping + 64, 4, 0) == 4
        && linux_regular_file_write_at(descriptor, mapping + 64, 1, 4) == LINUX_EPERM
        && linux_ftruncate(descriptor, 2) == 0
        && linux_ftruncate(descriptor, 5) == LINUX_EPERM;
    let immutable = shared
        && linux_descriptor_fcntl(
            descriptor,
            LINUX_F_ADD_SEALS,
            u64::from(LINUX_F_SEAL_SHRINK | LINUX_F_SEAL_WRITE | LINUX_F_SEAL_EXEC),
        ) == 0
        && linux_ftruncate(descriptor, 1) == LINUX_EPERM
        && linux_regular_file_write_at(descriptor, mapping + 64, 1, 0) == LINUX_EPERM
        && linux_fchmod(descriptor, 0o666) == LINUX_EPERM
        && linux_descriptor_fcntl(descriptor, LINUX_F_ADD_SEALS, u64::from(LINUX_F_SEAL_SEAL)) == 0
        && linux_descriptor_fcntl(
            descriptor,
            LINUX_F_ADD_SEALS,
            u64::from(LINUX_F_SEAL_FUTURE_WRITE),
        ) == LINUX_EPERM
        && linux_descriptor_fcntl(descriptor, LINUX_F_ADD_SEALS, 1 << 31) == LINUX_EINVAL;
    let closed = duplicated < LINUX_DESCRIPTOR_TABLE_LIMIT
        && linux_descriptor_close(duplicated) == 0
        && descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT
        && linux_descriptor_close(descriptor) == 0;
    let sealed_descriptor = linux_memfd_create(mapping, 0);
    let default_seal = sealed_descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT
        && linux_descriptor_fcntl(sealed_descriptor, LINUX_F_GET_SEALS, 0)
            == u64::from(LINUX_F_SEAL_SEAL)
        && linux_descriptor_fcntl(
            sealed_descriptor,
            LINUX_F_ADD_SEALS,
            u64::from(LINUX_F_SEAL_GROW),
        ) == LINUX_EPERM;
    let sealed_closed = sealed_descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT
        && linux_descriptor_close(sealed_descriptor) == 0;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    let valid =
        initial && shared && immutable && closed && default_seal && sealed_closed && unmapped;
    if valid {
        serial_write("linox: Linux memfd sealing enforced across descriptors\r\n");
    }
    valid
}

fn verify_linux_memfd_secret_syscall() -> bool {
    let descriptor = linux_memfd_secret(1);
    if descriptor >= LINUX_AUX_DESCRIPTOR_LIMIT {
        return false;
    }
    let duplicate = linux_console_dup(descriptor);
    let prepared = duplicate < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close_on_exec(descriptor)
        && linux_secret_descriptor(duplicate)
        && linux_ftruncate(descriptor, PAGE_SIZE as u64) == 0;
    let private_rejected = prepared
        && linux_runtime_mmap(
            0,
            PAGE_SIZE as u64,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE,
            descriptor,
            0,
        ) == LINUX_EINVAL;
    let executable_rejected = private_rejected
        && linux_runtime_mmap(
            0,
            PAGE_SIZE as u64,
            LINUX_PROT_READ | LINUX_PROT_EXEC,
            LINUX_MAP_SHARED,
            descriptor,
            0,
        ) == LINUX_EINVAL;
    let mapping = if executable_rejected {
        linux_runtime_mmap(
            0,
            PAGE_SIZE as u64,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_SHARED,
            descriptor,
            0,
        )
    } else {
        LINUX_EINVAL
    };
    let mapped = (LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
        && address_space::current_linux_runtime_page(mapping).secret;
    let secret_value = 0x5345_4352_4554_4d45_u64.to_ne_bytes();
    let mut secret_observed = [0_u8; size_of::<u64>()];
    let userspace_accessible = mapped
        && crate::trusted::user_copy::copy_to_user(mapping, &secret_value) == secret_value.len()
        && crate::trusted::user_copy::copy_from_user(mapping, &mut secret_observed)
            == secret_observed.len()
        && secret_observed == secret_value;
    let kernel_copy_denied = userspace_accessible
        && !copy_from_linux_user(mapping, &mut [0_u8; 8])
        && !copy_to_linux_user(mapping, &[0_u8; 8])
        && linux_descriptor_read(descriptor, mapping, 8) == LINUX_EINVAL
        && linux_descriptor_write(descriptor, mapping, 8) == LINUX_EINVAL;
    let protection_preserved = kernel_copy_denied
        && linux_mprotect(mapping, PAGE_SIZE as u64, LINUX_PROT_READ) == 0
        && address_space::current_linux_runtime_page(mapping).secret
        && !copy_from_linux_user(mapping, &mut [0_u8; 8]);
    let released = mapped && linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    let closed = linux_descriptor_close(duplicate) == 0 && linux_descriptor_close(descriptor) == 0;
    protection_preserved && released && closed && linux_memfd_secret(2) == LINUX_EINVAL
}

fn verify_linux_aio_syscalls() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let zero = 0_u64.to_ne_bytes();
    let setup = copy_to_linux_user(mapping, &zero) && linux_io_setup(4, mapping) == 0;
    let mut context_bytes = [0_u8; 8];
    let context = if setup && copy_from_linux_user(mapping, &mut context_bytes) {
        u64::from_ne_bytes(context_bytes)
    } else {
        0
    };
    let mut control = [0_u8; 64];
    control[..8].copy_from_slice(&0x4749_4e55_5841_494f_u64.to_ne_bytes());
    control[16..18].copy_from_slice(&2_u16.to_ne_bytes());
    control[20..24].copy_from_slice(&1_u32.to_ne_bytes());
    let submitted = context != 0
        && copy_to_linux_user(mapping + 64, &(mapping + 128).to_ne_bytes())
        && copy_to_linux_user(mapping + 128, &control)
        && linux_io_submit(context, 1, mapping + 64) == 1;
    let timeout = [0_u8; 16];
    let completed = submitted
        && copy_to_linux_user(mapping + 224, &timeout)
        && linux_io_getevents(context, 1, 1, mapping + 256, mapping + 224, 0) == 1
        && {
            let mut event = [0_u8; 32];
            copy_from_linux_user(mapping + 256, &mut event)
                && u64::from_ne_bytes(event[..8].try_into().unwrap()) == 0x4749_4e55_5841_494f
                && u64::from_ne_bytes(event[8..16].try_into().unwrap()) == mapping + 128
                && i64::from_ne_bytes(event[16..24].try_into().unwrap()) == 0
        };
    let empty =
        completed && linux_io_getevents(context, 0, 1, mapping + 256, mapping + 224, 0) == 0;
    let destroyed = context != 0
        && linux_io_cancel(context, mapping + 128, mapping + 256) == LINUX_EINVAL
        && linux_io_destroy(context) == 0;
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    // The capability module and Landlock, neither of which keeps process
    // attributes (lsm_get_self_attr and lsm_set_self_attr: EOPNOTSUPP).
    let lsm = copy_to_linux_user(mapping + 512, &16_u32.to_ne_bytes())
        && linux_lsm_list_modules(mapping + 544, mapping + 512, UPPER_REGISTER_BITS) == 2
        && {
            let mut size = [1_u8; 4];
            let mut identifiers = [0_u8; 16];
            copy_from_linux_user(mapping + 512, &mut size)
                && u32::from_ne_bytes(size) == 16
                && copy_from_linux_user(mapping + 544, &mut identifiers)
                && u64::from_ne_bytes(identifiers[..8].try_into().unwrap()) == 100
                && u64::from_ne_bytes(identifiers[8..].try_into().unwrap()) == 110
        }
        && copy_to_linux_user(mapping + 512, &8_u32.to_ne_bytes())
        && linux_lsm_list_modules(mapping + 544, mapping + 512, 0) == LINUX_E2BIG
        && (100..=105).all(|attribute| {
            copy_to_linux_user(mapping + 512, &16_u32.to_ne_bytes())
                && linux_lsm_get_self_attr(
                    UPPER_REGISTER_BITS | attribute,
                    0,
                    mapping + 512,
                    UPPER_REGISTER_BITS,
                ) == LINUX_EOPNOTSUPP
                && {
                    let mut size = [1_u8; 4];
                    copy_from_linux_user(mapping + 512, &mut size) && u32::from_ne_bytes(size) == 0
                }
                && linux_lsm_set_self_attr(
                    UPPER_REGISTER_BITS | attribute,
                    0,
                    UPPER_REGISTER_BITS,
                    UPPER_REGISTER_BITS,
                ) == LINUX_EINVAL
        })
        && copy_to_linux_user(mapping + 512, &16_u32.to_ne_bytes())
        && linux_lsm_get_self_attr(100, mapping + 544, mapping + 512, 1) == LINUX_EOPNOTSUPP
        && linux_lsm_get_self_attr(100, 0, mapping + 512, 1) == LINUX_EINVAL
        && linux_lsm_get_self_attr(0, 0, mapping + 512, 0) == LINUX_EINVAL
        && linux_lsm_get_self_attr(100, 0, 0, 0) == LINUX_EINVAL
        && linux_lsm_get_self_attr(100, 0, 1, 0) == LINUX_EFAULT
        && linux_lsm_set_self_attr(100, 0, 31, 0) == LINUX_EINVAL
        && linux_lsm_set_self_attr(100, 0, PAGE_SIZE as u64 + 1, 0) == LINUX_E2BIG
        && linux_lsm_set_self_attr(100, 1, 32, 0) == LINUX_EFAULT
        && linux_lsm_set_self_attr(100, 0, 0, 1) == LINUX_EINVAL
        && linux_lsm_list_modules(0, mapping + 512, 1) == LINUX_EINVAL
        && linux_lsm_list_modules(0, 1, 0) == LINUX_EFAULT;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    empty && destroyed && lsm && unmapped
}

fn verify_linux_posix_message_queue_syscalls() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let name = b"linox-abi\0";
    let mut attr = [0_u8; 64];
    attr[8..16].copy_from_slice(&4_u64.to_ne_bytes());
    attr[16..24].copy_from_slice(&32_u64.to_ne_bytes());
    let charge = 4 * 32 + 4 * LINUX_MSG_MSG_SIZE + 4 * LINUX_POSIX_MSG_TREE_NODE_SIZE;
    let mut limit = [0_u8; 16];
    limit[..8].copy_from_slice(&(charge - 1).to_ne_bytes());
    limit[8..].copy_from_slice(&u64::MAX.to_ne_bytes());
    let prepared = copy_to_linux_user(mapping, name)
        && copy_to_linux_user(mapping + 64, &attr)
        && copy_to_linux_user(mapping + 128, &limit);
    let rejected = prepared
        && linux_setrlimit(LINUX_RLIMIT_MSGQUEUE, mapping + 128) == 0
        && linux_mq_open(
            mapping,
            UPPER_REGISTER_BITS | LINUX_O_CREAT | 2,
            UPPER_REGISTER_BITS | 0o600,
            mapping + 64,
        ) == LINUX_EMFILE
        && X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::SeqCst) == 0;
    limit[..8].copy_from_slice(&charge.to_ne_bytes());
    let exact_limit = rejected
        && copy_to_linux_user(mapping + 128, &limit)
        && linux_setrlimit(LINUX_RLIMIT_MSGQUEUE, mapping + 128) == 0;
    let descriptor = if exact_limit {
        linux_mq_open(
            mapping,
            UPPER_REGISTER_BITS | LINUX_O_CREAT | 2,
            UPPER_REGISTER_BITS | 0o600,
            mapping + 64,
        )
    } else {
        LINUX_EFAULT
    };
    let opened = descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::SeqCst) == charge;
    let sent = opened
        && copy_to_linux_user(mapping + 256, b"low")
        && linux_mq_timedsend(
            UPPER_REGISTER_BITS | descriptor,
            mapping + 256,
            3,
            UPPER_REGISTER_BITS | 3,
            0,
        ) == 0
        && copy_to_linux_user(mapping + 256, b"high")
        && linux_mq_timedsend(descriptor, mapping + 256, 4, 9, 0) == 0;
    let received = sent
        && linux_mq_timedreceive(
            UPPER_REGISTER_BITS | descriptor,
            mapping + 512,
            32,
            mapping + 600,
            0,
        ) == 4
        && {
            let mut message = [0_u8; 4];
            let mut priority = [0_u8; 4];
            copy_from_linux_user(mapping + 512, &mut message)
                && copy_from_linux_user(mapping + 600, &mut priority)
                && message == *b"high"
                && u32::from_ne_bytes(priority) == 9
        };
    let mut event = [0_u8; 16];
    event[12..].copy_from_slice(&1_i32.to_ne_bytes());
    let queried = copy_to_linux_user(mapping + 640, &event)
        && linux_mq_notify(UPPER_REGISTER_BITS | descriptor, mapping + 640) == 0
        && linux_mq_getsetattr(UPPER_REGISTER_BITS | descriptor, 0, mapping + 704) == 0
        && {
            let mut current = [0_u8; 64];
            copy_from_linux_user(mapping + 704, &mut current)
                && u64::from_ne_bytes(current[8..16].try_into().unwrap()) == 4
                && u64::from_ne_bytes(current[16..24].try_into().unwrap()) == 32
                && u64::from_ne_bytes(current[24..32].try_into().unwrap()) == 1
        };
    let duplicate = if opened {
        linux_console_dup(descriptor)
    } else {
        LINUX_EBADF
    };
    let duplicated = duplicate < LINUX_AUX_DESCRIPTOR_LIMIT;
    let unlinked = linux_mq_unlink(mapping) == 0
        && X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::SeqCst) == charge;
    let reopen_missing = linux_mq_open(mapping, 2, 0, 0) == LINUX_ENOENT;
    let duplicate_closed = duplicated
        && linux_descriptor_close(duplicate) == 0
        && X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::SeqCst) == charge;
    let descriptor_closed = opened
        && linux_descriptor_close(descriptor) == 0
        && X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::SeqCst) == 0;
    let lifecycle =
        duplicated && unlinked && reopen_missing && duplicate_closed && descriptor_closed;
    let linked_descriptor = if lifecycle {
        linux_mq_open(mapping, LINUX_O_CREAT | 2, 0o600, mapping + 64)
    } else {
        LINUX_EFAULT
    };
    let linked_opened = linked_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::SeqCst) == charge;
    let linked_closed = linked_opened
        && linux_descriptor_close(linked_descriptor) == 0
        && X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::SeqCst) == charge;
    let linked_unlinked = linked_closed
        && linux_mq_unlink(mapping) == 0
        && X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::SeqCst) == 0;
    limit[..8].copy_from_slice(&u64::MAX.to_ne_bytes());
    let restored = copy_to_linux_user(mapping + 128, &limit)
        && linux_setrlimit(LINUX_RLIMIT_MSGQUEUE, mapping + 128) == 0;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    let valid = received && queried && lifecycle && linked_unlinked && restored && unmapped;
    if valid {
        serial_write("linox: Linux POSIX message queue resource limit enforced\r\n");
    }
    valid
}

fn verify_linux_unix_inflight_rights() -> bool {
    if crate::linux_socket::unix_inflight_rights() != 0 {
        return false;
    }
    let Some(original_limit) = linux_resource_limit_values(
        LINUX_RLIMIT_NOFILE,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    ) else {
        return false;
    };
    let Ok((sender, receiver)) = crate::linux_socket::open_pair(1) else {
        return false;
    };
    let first_retained = crate::linux_socket::duplicate(sender);
    let first_queued = if first_retained {
        if crate::linux_socket::queue_unix_rights(sender, &[(sender, 0)]).is_ok() {
            crate::linux_socket::unix_inflight_rights() == 1
        } else {
            let _ = crate::linux_socket::close(sender);
            false
        }
    } else {
        false
    };
    let limit_enforced = first_queued
        && linux_set_process_resource_limit(
            current_linux_process_pid(),
            LINUX_RLIMIT_NOFILE,
            [0, original_limit[1]],
        ) == 0
        && linux_unix_inflight_limit_exceeded();
    let limit_restored = linux_set_process_resource_limit(
        current_linux_process_pid(),
        LINUX_RLIMIT_NOFILE,
        original_limit,
    ) == 0;
    let mut received = [(0, 0_u32); crate::linux_socket::PASSED_RIGHT_LIMIT];
    let first_received = first_queued
        && crate::linux_socket::receive_unix_rights(receiver, &mut received, false) == Ok(1)
        && received[0].0 == sender
        && crate::linux_socket::unix_inflight_rights() == 0
        && crate::linux_socket::close(received[0].0);
    let second_retained = first_received && crate::linux_socket::duplicate(sender);
    let second_queued = if second_retained {
        if crate::linux_socket::queue_unix_rights(sender, &[(sender, 0)]).is_ok() {
            crate::linux_socket::unix_inflight_rights() == 1
        } else {
            let _ = crate::linux_socket::close(sender);
            false
        }
    } else {
        false
    };
    let receiver_closed = second_queued
        && crate::linux_socket::close(receiver)
        && crate::linux_socket::unix_inflight_rights() == 0;
    if !receiver_closed {
        let _ = crate::linux_socket::discard_unix_rights(receiver);
        let _ = crate::linux_socket::close(receiver);
    }
    let sender_closed = crate::linux_socket::close(sender);
    let valid = limit_enforced
        && limit_restored
        && first_received
        && second_queued
        && receiver_closed
        && sender_closed
        && crate::linux_socket::unix_inflight_rights() == 0;
    if valid {
        serial_write("linox: Linux UNIX in-flight descriptor limit enforced\r\n");
    }
    valid
}

fn verify_linux_process_madvise_syscall() -> bool {
    let mapping = linux_runtime_mmap(
        0,
        (3 * PAGE_SIZE) as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let first = mapping + PAGE_SIZE as u64;
    let second = first + PAGE_SIZE as u64;
    let hint_hole = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    let initialized = hint_hole < LINUX_RETURN_TO_KERNEL
        && linux_runtime_munmap(hint_hole, PAGE_SIZE as u64) == 0
        && copy_to_linux_user(first, &[0xa5])
        && copy_to_linux_user(second, &[0x5a]);
    let hints = initialized
        && [
            LINUX_MADV_NORMAL,
            LINUX_MADV_RANDOM,
            LINUX_MADV_SEQUENTIAL,
            LINUX_MADV_WILLNEED,
            LINUX_MADV_HUGEPAGE,
            LINUX_MADV_NOHUGEPAGE,
            LINUX_MADV_DONTDUMP,
            LINUX_MADV_DODUMP,
        ]
        .into_iter()
        .all(|advice| linux_madvise(first, PAGE_SIZE as u64, advice) == 0)
        && [LINUX_MADV_MERGEABLE, LINUX_MADV_UNMERGEABLE]
            .into_iter()
            .all(|advice| linux_madvise(first, PAGE_SIZE as u64, advice) == LINUX_EINVAL)
        && linux_madvise(first, PAGE_SIZE as u64, 1_u64 << 32) == 0
        && linux_madvise(first, PAGE_SIZE as u64, u64::from(u32::MAX)) == LINUX_EINVAL;
    let inheritance = hints
        && linux_madvise(first, PAGE_SIZE as u64, LINUX_MADV_DONTFORK) == 0
        && address_space::current_linux_runtime_page(first).dontfork
        && linux_madvise(first, PAGE_SIZE as u64, LINUX_MADV_DOFORK) == 0
        && !address_space::current_linux_runtime_page(first).dontfork
        && linux_madvise(first, PAGE_SIZE as u64, LINUX_MADV_WIPEONFORK) == 0
        && address_space::current_linux_runtime_page(first).wipeonfork
        && linux_madvise(first, PAGE_SIZE as u64, LINUX_MADV_KEEPONFORK) == 0
        && !address_space::current_linux_runtime_page(first).wipeonfork
        && linux_madvise(second, PAGE_SIZE as u64, LINUX_MADV_DONTFORK) == 0
        && address_space::current_linux_runtime_page(second).dontfork;
    let stack_page = X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1);
    let general_hints = inheritance
        && stack_page != 0
        && stack_page < LINUX_RUNTIME_DYNAMIC_MMAP_BASE
        && [
            LINUX_MADV_HUGEPAGE,
            LINUX_MADV_NOHUGEPAGE,
            LINUX_MADV_DONTDUMP,
            LINUX_MADV_DODUMP,
        ]
        .into_iter()
        .all(|advice| linux_madvise(stack_page, PAGE_SIZE as u64, advice) == 0)
        && linux_madvise(hint_hole, PAGE_SIZE as u64, LINUX_MADV_HUGEPAGE) == LINUX_ENOMEM;
    let general_inheritance = general_hints
        && linux_madvise(stack_page, PAGE_SIZE as u64, LINUX_MADV_DONTFORK) == 0
        && address_space::current_linux_runtime_page(stack_page).dontfork
        && linux_madvise(stack_page, PAGE_SIZE as u64, LINUX_MADV_DOFORK) == 0
        && !address_space::current_linux_runtime_page(stack_page).dontfork
        && linux_madvise(stack_page, PAGE_SIZE as u64, LINUX_MADV_WIPEONFORK) == 0
        && address_space::current_linux_runtime_page(stack_page).wipeonfork
        && linux_madvise(stack_page, PAGE_SIZE as u64, LINUX_MADV_KEEPONFORK) == 0
        && !address_space::current_linux_runtime_page(stack_page).wipeonfork;
    let mut vectors = [0_u8; 32];
    vectors[..8].copy_from_slice(&first.to_ne_bytes());
    vectors[8..16].copy_from_slice(&(PAGE_SIZE as u64).to_ne_bytes());
    vectors[16..24].copy_from_slice(&second.to_ne_bytes());
    vectors[24..].copy_from_slice(&(PAGE_SIZE as u64).to_ne_bytes());
    let descriptor = linux_pidfd_open(
        (1_u64 << 32) | u64::from(current_linux_process_pid()),
        1_u64 << 32,
    );
    let advised = general_inheritance
        && descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && copy_to_linux_user(mapping, &vectors)
        && linux_process_madvise(
            (1_u64 << 32) | descriptor,
            mapping,
            2,
            LINUX_MADV_DONTNEED,
            0,
        ) == (2 * PAGE_SIZE) as u64;
    let cleared = advised && {
        let mut bytes = [1_u8; 2];
        copy_from_linux_user(first, &mut bytes[..1])
            && copy_from_linux_user(second, &mut bytes[1..])
            && bytes == [0, 0]
            && !address_space::current_linux_runtime_page(first).dontfork
            && address_space::current_linux_runtime_page(second).dontfork
    };
    let populated = cleared
        && linux_madvise(first, (2 * PAGE_SIZE) as u64, LINUX_MADV_DONTNEED) == 0
        && address_space::current_linux_runtime_page(first)
            .frame
            .is_none()
        && address_space::current_linux_runtime_page(second)
            .frame
            .is_none()
        && linux_madvise(first, PAGE_SIZE as u64, LINUX_MADV_POPULATE_READ) == 0
        && address_space::current_linux_runtime_page(first)
            .frame
            .is_some()
        && linux_madvise(second, PAGE_SIZE as u64, LINUX_MADV_POPULATE_WRITE) == 0
        && address_space::current_linux_runtime_page(second)
            .frame
            .is_some()
        && linux_runtime_mprotect(first, PAGE_SIZE as u64, LINUX_PROT_READ) == 0
        && linux_madvise(first, PAGE_SIZE as u64, LINUX_MADV_POPULATE_WRITE) == LINUX_EINVAL
        && linux_runtime_mprotect(first, PAGE_SIZE as u64, LINUX_PROT_READ | LINUX_PROT_WRITE) == 0
        && linux_madvise(hint_hole, PAGE_SIZE as u64, LINUX_MADV_POPULATE_READ) == LINUX_ENOMEM;
    let freed = populated
        && copy_to_linux_user(first, &[0xa5])
        && linux_madvise(first, PAGE_SIZE as u64, LINUX_MADV_FREE) == 0
        // Lazily freed: the page and its contents stay until reclaim takes
        // them.
        && address_space::current_linux_runtime_page(first)
            .frame
            .is_some()
        && {
            let mut byte = [1_u8];
            copy_from_linux_user(first, &mut byte) && byte == [0xa5]
        }
        && linux_madvise(
            X86_RUNTIME.ELF_PROBE_CODE_BASE.load(Ordering::SeqCst),
            PAGE_SIZE as u64,
            LINUX_MADV_FREE,
        ) == LINUX_EINVAL;
    let reclaim_hints = freed
        && linux_madvise(first, PAGE_SIZE as u64, LINUX_MADV_COLD) == 0
        && linux_madvise(first, PAGE_SIZE as u64, LINUX_MADV_PAGEOUT) == 0
        && linux_process_madvise(descriptor, mapping, 2, LINUX_MADV_COLD, 0)
            == (2 * PAGE_SIZE) as u64
        && linux_process_madvise(descriptor, mapping, 2, LINUX_MADV_PAGEOUT, 0)
            == (2 * PAGE_SIZE) as u64
        && linux_madvise(hint_hole, PAGE_SIZE as u64, LINUX_MADV_COLD) == LINUX_ENOMEM;
    let locked_written = reclaim_hints && copy_to_linux_user(first, &[0x5a]);
    let locked_discarded = locked_written
        && linux_madvise(first, PAGE_SIZE as u64, LINUX_MADV_DONTNEED_LOCKED) == 0
        && address_space::current_linux_runtime_page(first)
            .frame
            .is_none();
    let locked_zeroed = locked_discarded && {
        let mut byte = [1_u8];
        copy_from_linux_user(first, &mut byte) && byte == [0]
    };
    let process_locked_discarded = locked_zeroed
        && linux_process_madvise(descriptor, mapping, 2, LINUX_MADV_DONTNEED_LOCKED, 0)
            == (2 * PAGE_SIZE) as u64;
    let discarded_locked = process_locked_discarded
        && address_space::current_linux_runtime_page(first)
            .frame
            .is_none()
        && address_space::current_linux_runtime_page(second)
            .frame
            .is_none();
    let errors = descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_pidfd_open(0, 0) == LINUX_EINVAL
        && linux_process_madvise(descriptor, mapping, 2, LINUX_MADV_DONTNEED, 1) == LINUX_EINVAL
        && linux_process_madvise(descriptor, mapping, 1025, LINUX_MADV_DONTNEED, 0) == LINUX_EINVAL
        && linux_process_mrelease((1_u64 << 32) | descriptor, 0) == LINUX_EINVAL
        && linux_process_mrelease(descriptor, 1) == LINUX_EINVAL
        && linux_process_mrelease(LINUX_DESCRIPTOR_TABLE_LIMIT, 0) == LINUX_EBADF;
    let closed = descriptor < LINUX_AUX_DESCRIPTOR_LIMIT && linux_descriptor_close(descriptor) == 0;
    let unmapped = linux_runtime_munmap(mapping, (3 * PAGE_SIZE) as u64) == 0;
    let populated_mapping = linux_runtime_mmap(
        0,
        (2 * PAGE_SIZE) as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_POPULATE,
        u64::MAX,
        0,
    );
    let map_populated = populated_mapping < LINUX_RETURN_TO_KERNEL
        && address_space::current_linux_runtime_page(populated_mapping)
            .frame
            .is_some()
        && address_space::current_linux_runtime_page(populated_mapping + PAGE_SIZE as u64)
            .frame
            .is_some();
    let nonblocking_mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_POPULATE | LINUX_MAP_NONBLOCK,
        u64::MAX,
        0,
    );
    let map_nonblocking = nonblocking_mapping < LINUX_RETURN_TO_KERNEL
        && address_space::current_linux_runtime_page(nonblocking_mapping)
            .frame
            .is_none();
    let mincore_runtime = map_populated
        && map_nonblocking
        && linux_mincore(nonblocking_mapping, PAGE_SIZE as u64, populated_mapping) == 0
        && {
            let mut resident = [1_u8];
            copy_from_linux_user(populated_mapping, &mut resident) && resident == [0]
        }
        && linux_mincore(stack_page, PAGE_SIZE as u64, populated_mapping) == 0
        && {
            let mut resident = [0_u8];
            copy_from_linux_user(populated_mapping, &mut resident) && resident == [1]
        }
        && linux_mincore(nonblocking_mapping + 1, PAGE_SIZE as u64, populated_mapping)
            == LINUX_EINVAL
        && linux_mincore(
            nonblocking_mapping + PAGE_SIZE as u64,
            PAGE_SIZE as u64,
            populated_mapping,
        ) == LINUX_ENOMEM;
    let population_unmapped = map_populated
        && map_nonblocking
        && mincore_runtime
        && linux_runtime_munmap(populated_mapping, (2 * PAGE_SIZE) as u64) == 0
        && linux_runtime_munmap(nonblocking_mapping, PAGE_SIZE as u64) == 0;
    let compatibility_mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_EXECUTABLE | LINUX_MAP_LOCKED,
        u64::MAX,
        0,
    );
    let compatibility_flags = compatibility_mapping < LINUX_RETURN_TO_KERNEL
        && address_space::current_linux_runtime_page(compatibility_mapping)
            .frame
            .is_some()
        && linux_runtime_munmap(compatibility_mapping, PAGE_SIZE as u64) == 0;
    let sealed_mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    let sealing = compatibility_flags
        && sealed_mapping < LINUX_RETURN_TO_KERNEL
        && linux_mseal(sealed_mapping, PAGE_SIZE as u64, 0) == 0
        && address_space::current_linux_runtime_page(sealed_mapping).sealed
        && linux_mprotect(sealed_mapping, PAGE_SIZE as u64, LINUX_PROT_READ) == LINUX_EPERM
        && linux_madvise(sealed_mapping, PAGE_SIZE as u64, LINUX_MADV_DONTNEED) == LINUX_EPERM
        && linux_madvise(sealed_mapping, PAGE_SIZE as u64, LINUX_MADV_FREE) == LINUX_EPERM
        && linux_madvise(sealed_mapping, PAGE_SIZE as u64, LINUX_MADV_DONTNEED_LOCKED)
            == LINUX_EPERM
        && linux_madvise(sealed_mapping, PAGE_SIZE as u64, LINUX_MADV_DONTFORK) == LINUX_EPERM
        && linux_madvise(sealed_mapping, PAGE_SIZE as u64, LINUX_MADV_WIPEONFORK) == LINUX_EPERM
        && linux_madvise(sealed_mapping, PAGE_SIZE as u64, LINUX_MADV_DOFORK) == 0
        && linux_madvise(sealed_mapping, PAGE_SIZE as u64, LINUX_MADV_KEEPONFORK) == 0
        && linux_munmap(sealed_mapping, PAGE_SIZE as u64) == LINUX_EPERM
        && linux_mseal(sealed_mapping, PAGE_SIZE as u64, 1) == LINUX_EINVAL;
    if !discarded_locked {
        serial_write("linox: Linux DONTNEED_LOCKED verification failed\r\n");
    }
    if !errors || !closed || !unmapped || !population_unmapped || !sealing {
        serial_write("linox: Linux process advice cleanup verification failed\r\n");
    }
    discarded_locked && errors && closed && unmapped && population_unmapped && sealing
}

fn verify_linux_timer_argument_widths() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    const SIGEV_NONE: u32 = 1;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let event_address = mapping + 64;
    let timer_address = mapping + 128;
    let mut event = [0_u8; 64];
    event[12..16].copy_from_slice(&SIGEV_NONE.to_ne_bytes());
    let prepared =
        copy_to_linux_user(mapping, &[0_u8; 32]) && copy_to_linux_user(event_address, &event);
    let mut real_timer = [0_u8; 32];
    real_timer[..8].copy_from_slice(&1_i64.to_ne_bytes());
    real_timer[8..16].copy_from_slice(&250_000_i64.to_ne_bytes());
    real_timer[16..24].copy_from_slice(&2_i64.to_ne_bytes());
    real_timer[24..].copy_from_slice(&500_000_i64.to_ne_bytes());
    let real_timer_state = prepared
        && copy_to_linux_user(mapping, &real_timer)
        && linux_setitimer(UPPER_REGISTER_BITS, mapping, timer_address) == 0
        && X86_RUNTIME
            .ELF_PROBE_REAL_TIMER_INTERVAL
            .load(Ordering::SeqCst)
            == NANOSECONDS_PER_SECOND + 250_000_000
        && X86_RUNTIME
            .ELF_PROBE_REAL_TIMER_DEADLINE
            .load(Ordering::SeqCst)
            != 0
        && linux_getitimer(UPPER_REGISTER_BITS, timer_address) == 0
        && {
            let mut current = [0_u8; 32];
            copy_from_linux_user(timer_address, &mut current)
                && i64::from_ne_bytes(current[..8].try_into().unwrap()) == 1
                && i64::from_ne_bytes(current[8..16].try_into().unwrap()) == 250_000
                && i64::from_ne_bytes(current[16..24].try_into().unwrap()) >= 0
                && (0..1_000_000).contains(&i64::from_ne_bytes(current[24..].try_into().unwrap()))
        }
        && linux_alarm(UPPER_REGISTER_BITS | 3) == 3
        && X86_RUNTIME
            .ELF_PROBE_REAL_TIMER_INTERVAL
            .load(Ordering::SeqCst)
            == 0
        && linux_alarm(UPPER_REGISTER_BITS) == 3
        && X86_RUNTIME
            .ELF_PROBE_REAL_TIMER_DEADLINE
            .load(Ordering::SeqCst)
            == 0;
    real_timer[24..].copy_from_slice(&1_000_000_i64.to_ne_bytes());
    let invalid_timeval = real_timer_state
        && copy_to_linux_user(mapping, &real_timer)
        && linux_setitimer(0, mapping, 0) == LINUX_EINVAL;
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_INTERVAL
        .store(NANOSECONDS_PER_SECOND, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_DEADLINE
        .store(1, Ordering::SeqCst);
    let interval_expiry = invalid_timeval
        && refresh_linux_real_timer()
        && X86_RUNTIME
            .ELF_PROBE_REAL_TIMER_DEADLINE
            .load(Ordering::SeqCst)
            > 1
        && X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst)
            & (1 << (LINUX_SIGALRM - 1))
            != 0;
    X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[LINUX_SIGALRM as usize - 1].store(1, Ordering::SeqCst);
    let expiration_delivered = interval_expiry
        && linux_real_timer_signal(
            LinuxSyscallFrameHandle::NONE,
            LinuxUserContext {
                registers: LinuxSyscallFrame::ZERO,
                rip: 0,
                rsp: 0,
                rflags: 0,
                rax: 0,
                fs_base: 0,
            },
            (0, 0),
            37,
        ) == 37
        && X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst)
            & (1 << (LINUX_SIGALRM - 1))
            == 0;
    X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[LINUX_SIGALRM as usize - 1].store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_INTERVAL
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_DEADLINE
        .store(0, Ordering::SeqCst);
    let interval_timers = expiration_delivered
        && copy_to_linux_user(mapping, &[0_u8; 32])
        && linux_getitimer(UPPER_REGISTER_BITS, mapping) == 0
        && linux_setitimer(UPPER_REGISTER_BITS, mapping, 0) == 0
        && linux_alarm(UPPER_REGISTER_BITS) == 0;
    let posix_timer = interval_timers
        && linux_timer_create(
            UPPER_REGISTER_BITS | LINUX_CLOCK_MONOTONIC,
            event_address,
            timer_address,
        ) == 0
        && linux_timer_settime(UPPER_REGISTER_BITS | 1, UPPER_REGISTER_BITS, mapping, 0) == 0
        && linux_timer_gettime(UPPER_REGISTER_BITS | 1, mapping) == 0
        && linux_timer_getoverrun(UPPER_REGISTER_BITS | 1) == 0
        && linux_timer_delete(UPPER_REGISTER_BITS | 1) == 0;
    let timerfd = linux_timerfd_create(
        UPPER_REGISTER_BITS | LINUX_CLOCK_MONOTONIC,
        UPPER_REGISTER_BITS | LINUX_TFD_NONBLOCK,
    );
    let timerfd_valid = posix_timer
        && timerfd < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_timerfd_settime(
            UPPER_REGISTER_BITS | timerfd,
            UPPER_REGISTER_BITS,
            mapping,
            0,
        ) == 0
        && linux_timerfd_gettime(UPPER_REGISTER_BITS | timerfd, mapping) == 0
        && linux_descriptor_close(timerfd) == 0;
    if X86_RUNTIME
        .ELF_PROBE_POSIX_TIMER_ACTIVE
        .load(Ordering::SeqCst)
    {
        let _ = linux_timer_delete(1);
    }
    if timerfd < LINUX_AUX_DESCRIPTOR_LIMIT && linux_timerfd_descriptor(timerfd) {
        let _ = linux_descriptor_close(timerfd);
    }
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    timerfd_valid && unmapped
}

fn verify_linux_signal_argument_widths() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let current_pid = u64::from(current_linux_process_pid());
    let current_tid = current_linux_tid().map(u64::from).unwrap_or(0);
    let interrupted = LinuxUserContext {
        registers: LinuxSyscallFrame::ZERO,
        rip: 0,
        rsp: 0,
        rflags: 0,
        rax: 0,
        fs_base: 0,
    };
    let valid = linux_rt_sigaction(UPPER_REGISTER_BITS | 1, 0, mapping, LINUX_SIGNAL_SET_SIZE) == 0
        && linux_rt_sigprocmask(
            UPPER_REGISTER_BITS | LINUX_SIG_BLOCK,
            0,
            mapping,
            LINUX_SIGNAL_SET_SIZE,
        ) == 0
        && linux_kill(
            UPPER_REGISTER_BITS | current_pid,
            (UPPER_REGISTER_BITS, LINUX_SI_USER, None),
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0
        && linux_tgkill_identity(
            UPPER_REGISTER_BITS | current_pid,
            UPPER_REGISTER_BITS | current_tid,
        )
        .is_ok()
        && linux_tkill_identity(UPPER_REGISTER_BITS | current_tid).is_ok()
        && linux_rt_sigqueueinfo(
            UPPER_REGISTER_BITS | current_pid,
            Some(UPPER_REGISTER_BITS | current_tid),
            UPPER_REGISTER_BITS,
            0,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0;
    let queued_self_signals =
        verify_linux_queued_self_signals(mapping, current_pid, current_tid, interrupted);
    let pidfd = linux_pidfd_open(UPPER_REGISTER_BITS | current_pid, UPPER_REGISTER_BITS);
    let duplicate = if pidfd < LINUX_AUX_DESCRIPTOR_LIMIT {
        linux_pidfd_getfd(pidfd, UPPER_REGISTER_BITS | 1, UPPER_REGISTER_BITS)
    } else {
        LINUX_EBADF
    };
    let mut queued_information = [0_u8; size_of::<LinuxSignalInformation>()];
    queued_information[8..12].copy_from_slice(&LINUX_SI_QUEUE.to_ne_bytes());
    queued_information[24..32].copy_from_slice(&0x5049_4446_4453_4947_u64.to_ne_bytes());
    let queued_information_valid = copy_to_linux_user(mapping, &queued_information)
        && linux_pidfd_send_signal(
            pidfd,
            0,
            mapping,
            0,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0;
    queued_information[8..12].copy_from_slice(&LINUX_SI_KERNEL.to_ne_bytes());
    let information_errors = copy_to_linux_user(mapping, &queued_information)
        && linux_pidfd_send_signal(
            pidfd,
            0,
            mapping,
            0,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0
        && linux_pidfd_send_signal(
            pidfd,
            0,
            1,
            0,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == LINUX_EFAULT;
    let pidfd_valid = valid
        && queued_self_signals
        && duplicate < LINUX_DESCRIPTOR_TABLE_LIMIT
        && queued_information_valid
        && information_errors
        && linux_pidfd_send_signal(
            pidfd,
            UPPER_REGISTER_BITS,
            0,
            UPPER_REGISTER_BITS,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0
        && linux_descriptor_close(duplicate) == 0
        && linux_descriptor_close(pidfd) == 0;
    if duplicate < LINUX_DESCRIPTOR_TABLE_LIMIT && linux_descriptor_open(duplicate) {
        let _ = linux_descriptor_close(duplicate);
    }
    if pidfd < LINUX_AUX_DESCRIPTOR_LIMIT && linux_pidfd_descriptor(pidfd) {
        let _ = linux_descriptor_close(pidfd);
    }
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    pidfd_valid && unmapped
}

fn verify_linux_queued_self_signals(
    mapping: u64,
    current_pid: u64,
    current_tid: u64,
    interrupted: LinuxUserContext,
) -> bool {
    const SIGNAL: u64 = 10;
    const SIGNAL_BIT: u64 = 1 << (SIGNAL - 1);
    const REALTIME_SIGNAL: u64 = 34;
    const REALTIME_SIGNAL_BIT: u64 = 1 << (REALTIME_SIGNAL - 1);
    const VALUE: u64 = 0x4749_4e55_5851_5545;
    const THREAD_VALUE: u64 = 0x5448_5245_4144_5349;
    let index = SIGNAL as usize - 1;
    let old_mask = X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst);
    let old_pending = X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst);
    let old_code = X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].load(Ordering::SeqCst);
    let old_value = X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].load(Ordering::SeqCst);
    let realtime_index = REALTIME_SIGNAL as usize - 1;
    let old_realtime_code =
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[realtime_index].load(Ordering::SeqCst);
    let old_realtime_value =
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[realtime_index].load(Ordering::SeqCst);
    store_current_linux_signal_mask(old_mask | SIGNAL_BIT | REALTIME_SIGNAL_BIT);
    X86_RUNTIME
        .ELF_PROBE_PENDING_SIGNALS
        .fetch_and(!(SIGNAL_BIT | REALTIME_SIGNAL_BIT), Ordering::SeqCst);

    let information = mapping;
    let pending_set = mapping + 128;
    let wait_set = mapping + 136;
    let returned_information = mapping + 144;
    let write_information = |supplied_signal: i32, code: i32, value: u64| {
        let mut bytes = [0_u8; size_of::<LinuxSignalInformation>()];
        bytes[..4].copy_from_slice(&supplied_signal.to_ne_bytes());
        bytes[8..12].copy_from_slice(&code.to_ne_bytes());
        bytes[24..32].copy_from_slice(&value.to_ne_bytes());
        copy_to_linux_user(information, &bytes)
    };
    let wait_for_signal = |signal: u64, expected_code: i32, expected_value: u64| {
        let mut returned = [0_u8; size_of::<LinuxSignalInformation>()];
        linux_rt_sigtimedwait(wait_set, returned_information, 0, LINUX_SIGNAL_SET_SIZE) == signal
            && copy_from_linux_user(returned_information, &mut returned)
            && i32::from_ne_bytes(returned[..4].try_into().unwrap()) == signal as i32
            && i32::from_ne_bytes(returned[8..12].try_into().unwrap()) == expected_code
            && u64::from_ne_bytes(returned[24..32].try_into().unwrap()) == expected_value
    };
    let queued = write_information(31, LINUX_SI_QUEUE, VALUE)
        && copy_to_linux_user(wait_set, &SIGNAL_BIT.to_ne_bytes())
        && linux_rt_sigqueueinfo(
            current_pid,
            None,
            SIGNAL,
            information,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0
        && linux_rt_sigpending(pending_set, LINUX_SIGNAL_SET_SIZE) == 0;
    let mut pending_bytes = [0_u8; LINUX_SIGNAL_SET_SIZE as usize];
    let process_signal = queued
        && copy_from_linux_user(pending_set, &mut pending_bytes)
        && u64::from_ne_bytes(pending_bytes) & SIGNAL_BIT != 0
        && wait_for_signal(SIGNAL, LINUX_SI_QUEUE, VALUE);
    let thread_signal = write_information(0, LINUX_SI_TKILL, THREAD_VALUE)
        && linux_rt_sigqueueinfo(
            current_pid,
            Some(current_tid),
            SIGNAL,
            information,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0
        && wait_for_signal(SIGNAL, LINUX_SI_TKILL, THREAD_VALUE);
    let realtime_signal = write_information(0, LINUX_SI_QUEUE, VALUE)
        && copy_to_linux_user(wait_set, &REALTIME_SIGNAL_BIT.to_ne_bytes())
        && linux_rt_sigqueueinfo(
            current_pid,
            None,
            REALTIME_SIGNAL,
            information,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0
        && write_information(0, LINUX_SI_QUEUE, THREAD_VALUE)
        && linux_rt_sigqueueinfo(
            current_pid,
            None,
            REALTIME_SIGNAL,
            information,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0
        && wait_for_signal(REALTIME_SIGNAL, LINUX_SI_QUEUE, VALUE)
        && wait_for_signal(REALTIME_SIGNAL, LINUX_SI_QUEUE, THREAD_VALUE);
    let separated_signals = copy_to_linux_user(wait_set, &SIGNAL_BIT.to_ne_bytes())
        && write_information(0, LINUX_SI_QUEUE, VALUE)
        && linux_rt_sigqueueinfo(
            current_pid,
            None,
            SIGNAL,
            information,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0
        && write_information(0, LINUX_SI_TKILL, THREAD_VALUE)
        && linux_rt_sigqueueinfo(
            current_pid,
            Some(current_tid),
            SIGNAL,
            information,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == 0
        && wait_for_signal(SIGNAL, LINUX_SI_TKILL, THREAD_VALUE)
        && wait_for_signal(SIGNAL, LINUX_SI_QUEUE, VALUE);
    let errors = write_information(0, LINUX_SI_KERNEL, VALUE)
        && linux_rt_sigqueueinfo(
            current_pid,
            None,
            SIGNAL,
            information,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == LINUX_EPERM
        && linux_rt_sigpending(pending_set, LINUX_SIGNAL_SET_SIZE - 1) == LINUX_EINVAL
        && linux_rt_sigpending(1, LINUX_SIGNAL_SET_SIZE) == LINUX_EFAULT
        && linux_rt_sigqueueinfo(
            current_pid,
            None,
            LINUX_SIGNAL_COUNT as u64 + 1,
            1,
            LinuxSyscallFrameHandle::NONE,
            interrupted,
            (0, 0),
        ) == LINUX_EINVAL;

    store_current_linux_signal_mask(old_mask);
    X86_RUNTIME
        .ELF_PROBE_PENDING_SIGNALS
        .store(old_pending, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].store(old_code, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].store(old_value, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[realtime_index]
        .store(old_realtime_code, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[realtime_index]
        .store(old_realtime_value, Ordering::SeqCst);
    process_signal && thread_signal && realtime_signal && separated_signals && errors
}

fn verify_linux_descriptor_argument_widths() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let control = linux_descriptor_fcntl(
        UPPER_REGISTER_BITS | 1,
        UPPER_REGISTER_BITS | LINUX_F_GETFD,
        0,
    ) == 0
        && linux_flock(UPPER_REGISTER_BITS | 1, UPPER_REGISTER_BITS | 1) == 0;
    let first = linux_console_dup(UPPER_REGISTER_BITS | 1);
    if first >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return false;
    }
    let pid = u64::from(current_linux_process_pid());
    let first_closed = linux_kcmp(pid, pid, 0, 1, first) == 0
        && linux_descriptor_close(UPPER_REGISTER_BITS | first) == 0
        && !linux_descriptor_open(first);
    let second = if first_closed {
        linux_console_dup2(UPPER_REGISTER_BITS | 1, UPPER_REGISTER_BITS | first)
    } else {
        LINUX_EBADF
    };
    let second_closed = second == first
        && linux_descriptor_close(UPPER_REGISTER_BITS | second) == 0
        && !linux_descriptor_open(second);
    let third = if second_closed {
        linux_dup3(
            UPPER_REGISTER_BITS | 1,
            UPPER_REGISTER_BITS | first,
            UPPER_REGISTER_BITS | LINUX_O_CLOEXEC,
        )
    } else {
        LINUX_EBADF
    };
    let third_valid = third == first && linux_descriptor_close_on_exec(third);
    let third_closed = third_valid
        && linux_descriptor_close(UPPER_REGISTER_BITS | third) == 0
        && !linux_descriptor_open(third);
    if first < LINUX_DESCRIPTOR_TABLE_LIMIT && linux_descriptor_open(first) {
        let _ = linux_descriptor_close(first);
    }
    control && first_closed && second_closed && third_closed
}

fn verify_linux_process_selector_widths() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let pid = u64::from(current_linux_process_pid());
    linux_process_vm_iov(UPPER_REGISTER_BITS | pid, 0, 0, 0, 0, 0, false) == 0
        && linux_kcmp(
            UPPER_REGISTER_BITS | pid,
            UPPER_REGISTER_BITS | pid,
            UPPER_REGISTER_BITS | 1,
            0,
            0,
        ) == 0
        && linux_move_pages(UPPER_REGISTER_BITS | pid, 0, 0, 0, 0, UPPER_REGISTER_BITS) == 0
}

fn verify_linux_event_argument_widths() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
        || !copy_to_linux_user(mapping, &[0_u8; 128])
    {
        return false;
    }
    let eventfd = linux_eventfd(1, UPPER_REGISTER_BITS | LINUX_EFD_NONBLOCK);
    let epoll = linux_epoll_create1(UPPER_REGISTER_BITS | LINUX_O_CLOEXEC);
    let mut event = [0_u8; 12];
    event[..4].copy_from_slice(&u32::from(LINUX_POLLIN).to_ne_bytes());
    let caller = LinuxUserContext {
        registers: LinuxSyscallFrame::ZERO,
        rip: 0,
        rsp: 0,
        rflags: 0,
        rax: 0,
        fs_base: 0,
    };
    let epoll_valid = eventfd < LINUX_AUX_DESCRIPTOR_LIMIT
        && epoll < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close_on_exec(epoll)
        && copy_to_linux_user(mapping + 128, &event)
        && linux_epoll_ctl(
            UPPER_REGISTER_BITS | epoll,
            UPPER_REGISTER_BITS | LINUX_EPOLL_CTL_ADD,
            UPPER_REGISTER_BITS | eventfd,
            mapping + 128,
        ) == 0
        && linux_epoll_wait_duration_live_return(
            LinuxSyscallFrameHandle::NONE,
            caller,
            LinuxEpollWaitInput {
                epoll: UPPER_REGISTER_BITS | epoll,
                address: mapping + 256,
                maximum: UPPER_REGISTER_BITS | 1,
            },
            Some(0),
            LINUX_EPOLL_WAIT_SYSCALL,
            None,
        ) == 1
        && linux_epoll_ctl(
            UPPER_REGISTER_BITS | epoll,
            UPPER_REGISTER_BITS | LINUX_EPOLL_CTL_DEL,
            UPPER_REGISTER_BITS | eventfd,
            0,
        ) == 0;
    let select_valid = linux_select_with_copy(
        LinuxSelectInput {
            descriptor_count: UPPER_REGISTER_BITS,
            read_address: 0,
            write_address: 0,
            exception_address: 0,
            timeout_address: mapping,
            signal_mask_address: 0,
        },
        false,
        copy_from_linux_user,
        copy_to_linux_user,
    ) == 0;
    let signalfd = linux_signalfd(
        UPPER_REGISTER_BITS | u64::from(u32::MAX),
        mapping,
        LINUX_SIGNAL_SET_SIZE,
        UPPER_REGISTER_BITS | LINUX_O_CLOEXEC,
    );
    let inotify = linux_inotify_init(UPPER_REGISTER_BITS | LINUX_O_CLOEXEC);
    let auxiliary_valid = signalfd < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close_on_exec(signalfd)
        && inotify < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close_on_exec(inotify);
    let mut closed = true;
    for descriptor in [inotify, signalfd, epoll, eventfd] {
        if descriptor < LINUX_AUX_DESCRIPTOR_LIMIT && linux_descriptor_open(descriptor) {
            closed &= linux_descriptor_close(descriptor) == 0;
        }
    }
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    epoll_valid && select_valid && auxiliary_valid && closed && unmapped
}

fn verify_linux_filesystem_argument_widths() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if mapping >= LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39)
        || !copy_to_linux_user(mapping, b"/dev/null\0")
    {
        return false;
    }
    let directory = UPPER_REGISTER_BITS | u64::from(LINUX_AT_FDCWD);
    let descriptor = linux_openat(
        directory,
        mapping,
        UPPER_REGISTER_BITS | LINUX_O_CLOEXEC,
        UPPER_REGISTER_BITS,
    );
    let valid = descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT
        && linux_descriptor_close_on_exec(descriptor)
        && linux_newfstatat(directory, mapping, mapping + 256, UPPER_REGISTER_BITS) == 0
        && linux_faccessat(directory, mapping, UPPER_REGISTER_BITS, UPPER_REGISTER_BITS) == 0
        && linux_statx(
            directory,
            mapping,
            UPPER_REGISTER_BITS,
            UPPER_REGISTER_BITS,
            mapping + 512,
        ) == 0;
    let closed =
        descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT && linux_descriptor_close(descriptor) == 0;
    let xattr_node = crate::linux_overlay::create_file(b"linox-xattr-width", 0o600, &[]);
    let xattr_prepared = xattr_node.is_some()
        && copy_to_linux_user(mapping + 768, b"/linox-xattr-width\0")
        && copy_to_linux_user(mapping + 832, b"user.linox\0")
        && copy_to_linux_user(mapping + 896, b"ok")
        && copy_to_linux_user(mapping + 960, b"/\0");
    let xattr_descriptor = if xattr_prepared {
        linux_openat(directory, mapping + 768, 2, 0)
    } else {
        LINUX_EFAULT
    };
    let xattrs = xattr_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_fsetxattr(
            UPPER_REGISTER_BITS | xattr_descriptor,
            mapping + 832,
            mapping + 896,
            2,
            UPPER_REGISTER_BITS,
        ) == 0
        && linux_fgetxattr(
            UPPER_REGISTER_BITS | xattr_descriptor,
            mapping + 832,
            mapping + 1024,
            2,
        ) == 2
        && linux_flistxattr(UPPER_REGISTER_BITS | xattr_descriptor, mapping + 1088, 64) == 11
        && linux_fremovexattr(UPPER_REGISTER_BITS | xattr_descriptor, mapping + 832) == 0;
    let xattr_closed = xattr_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(xattr_descriptor) == 0;
    let directory_descriptor = if xattr_closed {
        linux_openat(directory, mapping + 960, LINUX_O_DIRECTORY, 0)
    } else {
        LINUX_EFAULT
    };
    let enumerated = directory_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_getdents64(
            UPPER_REGISTER_BITS | directory_descriptor,
            mapping + 1536,
            512,
        ) > 0;
    let directory_closed = directory_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(directory_descriptor) == 0;
    let path_descriptor = if directory_closed {
        linux_openat(
            directory,
            mapping + 960,
            LINUX_O_PATH | LINUX_O_CLOEXEC | LINUX_O_DIRECTORY | LINUX_O_NOCTTY,
            0,
        )
    } else {
        LINUX_EFAULT
    };
    let path_only = path_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_path_descriptor(path_descriptor)
        && linux_descriptor_close_on_exec(path_descriptor)
        && linux_descriptor_read(path_descriptor, mapping + 1024, 1) == LINUX_EBADF;
    let path_closed = path_descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(path_descriptor) == 0;
    let xattr_removed = xattr_node.is_some_and(crate::linux_overlay::unlink);
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    valid
        && closed
        && xattrs
        && xattr_closed
        && enumerated
        && directory_closed
        && path_only
        && path_closed
        && xattr_removed
        && unmapped
}

fn verify_linux_sysv_semaphore_syscalls() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    const IPC_SET: u64 = 1;
    const IPC_STAT: u64 = 2;
    const GETVAL: u64 = 12;
    const GETALL: u64 = 13;
    const SETVAL: u64 = 16;
    const SETALL: u64 = 17;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let id = linux_semget(
        UPPER_REGISTER_BITS,
        UPPER_REGISTER_BITS | 2,
        UPPER_REGISTER_BITS | 0o600,
    );
    let valid_id = id <= i32::MAX as u64;
    let initialized = valid_id
        && linux_semctl(
            UPPER_REGISTER_BITS | id,
            UPPER_REGISTER_BITS,
            UPPER_REGISTER_BITS | SETVAL,
            2,
        ) == 0
        && linux_semctl(id, 1, SETVAL, 0) == 0;
    let operations = [0_u8, 0, 0xff, 0xff, 0, 0, 1, 0, 3, 0, 0, 0];
    let operations_written = copy_to_linux_user(mapping, &operations);
    let applied = initialized
        && operations_written
        && linux_semop(id, mapping, 2) == Ok(None)
        && linux_semctl(id, 0, GETVAL, 0) == 1
        && linux_semctl(id, 1, GETVAL, 0) == 3;
    let zero_operation = [0_u8, 0, 0, 0, 0, 0];
    let blocking_checked = copy_to_linux_user(mapping + 32, &zero_operation)
        && linux_semop(id, mapping + 32, 1)
            == Ok(Some(crate::linux_sysv_ipc::SemaphoreBlock {
                number: 0,
                zero: true,
            }));
    let stat_address = mapping + 128;
    let stat_valid = linux_semctl(id, 0, IPC_STAT, stat_address) == 0 && {
        let mut stat = [0_u8; 104];
        copy_from_linux_user(stat_address, &mut stat)
            && u16::from_ne_bytes(stat[20..22].try_into().unwrap()) == 0o600
            && u64::from_ne_bytes(stat[80..88].try_into().unwrap()) == 2
    };
    let mut changed = [0_u8; 104];
    changed[20..22].copy_from_slice(&0o640_u16.to_ne_bytes());
    let mode_changed = copy_to_linux_user(stat_address, &changed)
        && linux_semctl(id, 0, IPC_SET, stat_address) == 0
        && linux_semctl(id, 0, IPC_STAT, stat_address) == 0
        && {
            let mut mode = [0_u8; 2];
            copy_from_linux_user(stat_address + 20, &mut mode) && u16::from_ne_bytes(mode) == 0o640
        };
    let values_address = mapping + 256;
    let all_values = linux_semctl(id, 0, GETALL, values_address) == 0
        && {
            let mut values = [0_u8; 4];
            copy_from_linux_user(values_address, &mut values) && values == [1, 0, 3, 0]
        }
        && copy_to_linux_user(values_address, &[4, 0, 5, 0])
        && linux_semctl(id, 0, SETALL, values_address) == 0
        && linux_semctl(id, 0, GETVAL, 0) == 4
        && linux_semctl(id, 1, GETVAL, 0) == 5;
    let removed = linux_semctl(id, 0, 0, 0) == 0 && linux_semctl(id, 0, GETVAL, 0) == LINUX_EINVAL;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    applied && blocking_checked && stat_valid && mode_changed && all_values && removed && unmapped
}

fn verify_linux_sysv_message_queue_syscalls() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    const IPC_SET: u64 = 1;
    const IPC_STAT: u64 = 2;
    const IPC_NOWAIT: u64 = 0o4000;
    const MSG_NOERROR: u64 = 0o10_000;
    const MSG_COPY: u64 = 0o40_000;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let id = linux_msgget(UPPER_REGISTER_BITS, UPPER_REGISTER_BITS | 0o600);
    let mut first = [0_u8; 15];
    first[..8].copy_from_slice(&7_i64.to_ne_bytes());
    first[8..].copy_from_slice(b"message");
    let mut second = [0_u8; 11];
    second[..8].copy_from_slice(&2_i64.to_ne_bytes());
    second[8..].copy_from_slice(b"two");
    let sent = id <= i32::MAX as u64
        && copy_to_linux_user(mapping, &first)
        && linux_msgsnd(UPPER_REGISTER_BITS | id, mapping, 7, UPPER_REGISTER_BITS) == 0
        && copy_to_linux_user(mapping, &second)
        && linux_msgsnd(id, mapping, 3, 0) == 0;
    let stat_address = mapping + 256;
    let stat_valid = sent && linux_msgctl(id, IPC_STAT, stat_address) == 0 && {
        let mut stat = [0_u8; 120];
        copy_from_linux_user(stat_address, &mut stat)
            && u16::from_ne_bytes(stat[20..22].try_into().unwrap()) == 0o600
            && u64::from_ne_bytes(stat[72..80].try_into().unwrap()) == 10
            && u64::from_ne_bytes(stat[80..88].try_into().unwrap()) == 2
            && u64::from_ne_bytes(stat[88..96].try_into().unwrap()) == 16_384
    };
    let output = mapping + 512;
    let copied = linux_msgrcv(id, output, 8, 1, IPC_NOWAIT | MSG_COPY) == 3
        && {
            let mut bytes = [0_u8; 11];
            copy_from_linux_user(output, &mut bytes)
                && i64::from_ne_bytes(bytes[..8].try_into().unwrap()) == 2
                && &bytes[8..] == b"two"
        }
        && linux_msgctl(id, IPC_STAT, stat_address) == 0
        && {
            let mut count = [0_u8; 8];
            copy_from_linux_user(stat_address + 80, &mut count) && u64::from_ne_bytes(count) == 2
        };
    let selected = linux_msgrcv(id, output, 8, (-3_i64) as u64, IPC_NOWAIT) == 3 && {
        let mut bytes = [0_u8; 11];
        copy_from_linux_user(output, &mut bytes)
            && i64::from_ne_bytes(bytes[..8].try_into().unwrap()) == 2
            && &bytes[8..] == b"two"
    };
    let truncation = linux_msgrcv(id, output, 3, 7, IPC_NOWAIT) == LINUX_E2BIG
        && linux_msgrcv(id, output, 3, 7, IPC_NOWAIT | MSG_NOERROR) == 3
        && {
            let mut bytes = [0_u8; 11];
            copy_from_linux_user(output, &mut bytes)
                && i64::from_ne_bytes(bytes[..8].try_into().unwrap()) == 7
                && &bytes[8..] == b"mes"
        }
        && linux_msgrcv(id, output, 8, 0, IPC_NOWAIT) == LINUX_EAGAIN;
    let mut changed = [0_u8; 120];
    changed[20..22].copy_from_slice(&0o640_u16.to_ne_bytes());
    changed[88..96].copy_from_slice(&32_768_u64.to_ne_bytes());
    let changed = copy_to_linux_user(stat_address, &changed)
        && linux_msgctl(id, IPC_SET, stat_address) == 0
        && linux_msgctl(id, IPC_STAT, stat_address) == 0
        && {
            let mut stat = [0_u8; 120];
            copy_from_linux_user(stat_address, &mut stat)
                && u16::from_ne_bytes(stat[20..22].try_into().unwrap()) == 0o640
                && u64::from_ne_bytes(stat[88..96].try_into().unwrap()) == 32_768
        };
    let removed =
        linux_msgctl(id, 0, 0) == 0 && linux_msgctl(id, IPC_STAT, stat_address) == LINUX_EINVAL;
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    stat_valid && copied && selected && truncation && changed && removed && unmapped
}

pub(super) fn verify_linux_cross_process_prlimit(pid: u32) -> bool {
    let Some(original) = linux_process_resource_limit_values(pid, LINUX_RLIMIT_NOFILE) else {
        return false;
    };
    let lowered = [original[0].saturating_sub(1), original[1]];
    let changed = linux_prlimit_permitted(pid)
        && linux_set_process_resource_limit(pid, LINUX_RLIMIT_NOFILE, lowered) == 0
        && linux_process_resource_limit_values(pid, LINUX_RLIMIT_NOFILE) == Some(lowered)
        && lowered[0] < original[0];
    let restored = linux_set_process_resource_limit(pid, LINUX_RLIMIT_NOFILE, original) == 0
        && linux_process_resource_limit_values(pid, LINUX_RLIMIT_NOFILE) == Some(original);
    let errors = linux_process_resource_limit_values(u32::MAX, LINUX_RLIMIT_NOFILE).is_none()
        && linux_set_process_resource_limit(u32::MAX, LINUX_RLIMIT_NOFILE, original) == LINUX_ESRCH;
    let widths = linux_prlimit_target((1_u64 << 32) | u64::from(pid)) == Ok(pid)
        && linux_prlimit_target(u64::MAX) == Err(LINUX_ESRCH)
        && linux_prlimit64(
            (1_u64 << 32) | u64::from(pid),
            (1_u64 << 32) | LINUX_RLIMIT_NOFILE,
            0,
            0,
        ) == 0;
    let pidfd = linux_pidfd_open(u64::from(pid), 0x800);
    let pidfd_opened = pidfd < LINUX_AUX_DESCRIPTOR_LIMIT;
    let pidfd_identity = pidfd_opened && linux_pidfd_process(pidfd) == Some(pid);
    let pidfd_ready =
        pidfd_opened && linux_descriptor_poll_events(pidfd as i32, LINUX_POLLIN) == LINUX_POLLIN;
    let pidfd_signal = pidfd_opened
        && linux_pidfd_send_signal(
            pidfd,
            0,
            0,
            0,
            LinuxSyscallFrameHandle::NONE,
            LinuxUserContext {
                registers: LinuxSyscallFrame::ZERO,
                rip: 0,
                rsp: 0,
                rflags: 0,
                rax: 0,
                fs_base: 0,
            },
            (0, 0),
        ) == 0;
    let pidfd_wait = pidfd_opened
        && linux_waitid(
            (1_u64 << 32) | LINUX_P_PIDFD,
            (1_u64 << 32) | pidfd,
            0,
            (1_u64 << 32) | LINUX_WEXITED | LINUX_WNOWAIT,
            0,
        ) == 0
        && linux_waitid(LINUX_P_PIDFD, pidfd, 0, LINUX_WEXITED | LINUX_WNOWAIT, 0) == 0
        && linux_process::live_child_wait_state(
            current_linux_process_pid(),
            Some(pid),
            linux_process::ChildWaitEvents {
                exited: true,
                stopped: false,
                continued: false,
                scope: linux_process::ChildScope::All,
            },
        ) == Some(linux_process::ChildWaitState::Exited {
            pid,
            status: LINUX_PROBE_EXIT_STATUS as u8,
            signal: 0,
        });
    let parent_group = linux_process::live_process_group(current_linux_process_pid());
    let group_wait = parent_group.is_some_and(|group| {
        linux_waitid(
            (1_u64 << 32) | LINUX_P_PGID,
            (1_u64 << 32) | u64::from(group),
            0,
            (1_u64 << 32) | LINUX_WEXITED | LINUX_WNOWAIT,
            0,
        ) == 0
            && linux_waitid(LINUX_P_PGID, 0, 0, LINUX_WEXITED | LINUX_WNOWAIT, 0) == 0
    });
    let pidfd_getfd = pidfd_opened && linux_pidfd_getfd(pidfd, 1, 0) == LINUX_ESRCH;
    let process_vm_zombie =
        linux_process_vm_iov(u64::from(pid), 0, 0, 0, 0, 0, false) == LINUX_ESRCH;
    let pidfd_closed = !pidfd_opened || linux_descriptor_close(pidfd) == 0;
    let pidfd_valid = pidfd_opened
        && pidfd_identity
        && pidfd_ready
        && pidfd_signal
        && pidfd_wait
        && group_wait
        && pidfd_getfd
        && process_vm_zombie
        && pidfd_closed;
    let valid = changed && restored && errors && widths && pidfd_valid;
    if valid {
        X86_RUNTIME
            .LINUX_CROSS_PROCESS_PRLIMIT_VALIDATED
            .store(true, Ordering::SeqCst);
        serial_write("linox: Linux cross-process resource limits validated\r\n");
        serial_write("linox: Linux generation-bound pidfds validated\r\n");
    } else {
        serial_write("linox: Linux cross-process resource/pidfd validation failed:");
        for value in [
            changed,
            restored,
            errors,
            widths,
            pidfd_opened,
            pidfd_identity,
            pidfd_ready,
            pidfd_signal,
            pidfd_wait,
            group_wait,
            pidfd_getfd,
            process_vm_zombie,
            pidfd_closed,
        ] {
            serial_write(" ");
            serial_write_u64(u64::from(value));
        }
        serial_write("\r\n");
    }
    valid
}

pub(super) fn verify_linux_running_child_wait_selectors(pid: u32) -> bool {
    let parent = current_linux_process_pid();
    let Some(parent_group) = linux_process::live_process_group(parent) else {
        return false;
    };
    let isolated = linux_process::set_live_process_group(parent, pid, pid) == Ok(());
    let negative_group = u64::from((-(pid as i32)) as u32);
    let group_wait = isolated
        && linux_waitid(
            (1_u64 << 32) | LINUX_P_PGID,
            (1_u64 << 32) | u64::from(pid),
            0,
            (1_u64 << 32) | LINUX_WEXITED | LINUX_WNOHANG,
            0,
        ) == 0
        && linux_wait4(
            (1_u64 << 32) | negative_group,
            0,
            (1_u64 << 32) | LINUX_WNOHANG,
            0,
        ) == 0
        && linux_waitid(LINUX_P_PGID, 0, 0, LINUX_WEXITED | LINUX_WNOHANG, 0) == LINUX_ECHILD
        && linux_wait4(0, 0, LINUX_WNOHANG, 0) == LINUX_ECHILD;
    let group_restored =
        isolated && linux_process::set_live_process_group(parent, pid, parent_group) == Ok(());
    let child_pidfd = linux_pidfd_open(u64::from(pid), LINUX_O_NONBLOCK);
    let child_opened = child_pidfd < LINUX_AUX_DESCRIPTOR_LIMIT;
    let running = child_opened
        && linux_waitid(
            (1_u64 << 32) | LINUX_P_PIDFD,
            (1_u64 << 32) | child_pidfd,
            0,
            (1_u64 << 32) | LINUX_WEXITED,
            0,
        ) == LINUX_EAGAIN
        && linux_waitid(
            LINUX_P_PIDFD,
            child_pidfd,
            0,
            LINUX_WEXITED | LINUX_WNOHANG,
            0,
        ) == 0;
    let process_vm = running && verify_linux_cross_process_vm(pid);
    let kcmp = process_vm && verify_linux_cross_process_kcmp(parent, pid);
    let remote_descriptor = if kcmp {
        linux_pidfd_getfd(child_pidfd, 1, 0)
    } else {
        LINUX_EBADF
    };
    let remote_opened = remote_descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT
        && linux_descriptor_open(remote_descriptor)
        && linux_descriptor_close_on_exec(remote_descriptor)
        && linux_kcmp(u64::from(parent), u64::from(pid), 0, remote_descriptor, 1) == 0;
    let remote_errors = remote_opened
        && linux_pidfd_getfd(child_pidfd, 1, 1) == LINUX_EINVAL
        && linux_pidfd_getfd(child_pidfd, LINUX_DESCRIPTOR_TABLE_LIMIT, 0) == LINUX_EBADF;
    let remote_closed = !remote_opened || linux_descriptor_close(remote_descriptor) == 0;
    let parent_pidfd = linux_pidfd_open(u64::from(parent), 0);
    let parent_opened = parent_pidfd < LINUX_AUX_DESCRIPTOR_LIMIT;
    let errors = parent_opened
        && linux_waitid(LINUX_P_PIDFD, parent_pidfd, 0, LINUX_WEXITED, 0) == LINUX_ECHILD
        && linux_waitid(LINUX_P_PIDFD, 1, 0, LINUX_WEXITED, 0) == LINUX_EBADF
        && linux_waitid(LINUX_P_PIDFD, u64::from(u32::MAX), 0, LINUX_WEXITED, 0) == LINUX_EBADF;
    let parent_closed = !parent_opened || linux_descriptor_close(parent_pidfd) == 0;
    let child_closed = !child_opened || linux_descriptor_close(child_pidfd) == 0;
    let valid = group_wait
        && group_restored
        && child_opened
        && running
        && process_vm
        && kcmp
        && remote_opened
        && remote_errors
        && remote_closed
        && parent_opened
        && errors
        && parent_closed
        && child_closed;
    if valid {
        serial_write("linox: Linux process-group wait selectors validated\r\n");
        serial_write("linox: Linux nonblocking pidfd wait validated\r\n");
        serial_write("linox: Linux cross-process memory transfer validated\r\n");
        serial_write("linox: Linux cross-process resource comparison validated\r\n");
        serial_write("linox: Linux shared open-file position validated\r\n");
        serial_write("linox: Linux cross-process pidfd descriptor duplication validated\r\n");
    }
    valid
}

fn verify_linux_cross_process_kcmp(parent: u32, child: u32) -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let distinct = (1..=6).all(|kind| {
        linux_kcmp(
            UPPER_REGISTER_BITS | u64::from(parent),
            UPPER_REGISTER_BITS | u64::from(child),
            UPPER_REGISTER_BITS | kind,
            0,
            0,
        ) == 1
    });
    let same =
        (1..=6).all(|kind| linux_kcmp(u64::from(parent), u64::from(parent), kind, 0, 0) == 0);
    let files = linux_kcmp(u64::from(parent), u64::from(child), 0, 1, 1) == 0
        && linux_kcmp(
            u64::from(parent),
            u64::from(child),
            0,
            LINUX_DESCRIPTOR_TABLE_LIMIT,
            1,
        ) == LINUX_EBADF;
    let bounded = files
        && linux_kcmp(u64::from(u32::MAX), u64::from(child), 1, 0, 0) == LINUX_ESRCH
        && linux_kcmp(u64::from(parent), u64::from(child), 7, 0, 0) == LINUX_EINVAL;
    let permission = if let Some(dumpable) = linux_process_runtime_state(child)
        .filter(|state| state.valid)
        .map(|state| {
            let dumpable = state.dumpable;
            state.dumpable = false;
            dumpable
        }) {
        let denied = linux_kcmp(u64::from(parent), u64::from(child), 1, 0, 0) == LINUX_EPERM;
        linux_process_runtime_state(child)
            .filter(|state| state.valid)
            .is_some_and(|state| {
                state.dumpable = dumpable;
                denied
            })
    } else {
        false
    };
    distinct && same && bounded && permission && verify_linux_shared_open_file_offset(parent, child)
}

fn verify_linux_shared_open_file_offset(parent: u32, child: u32) -> bool {
    let descriptor = 1_u64;
    let Some(id) = linux_process_descriptor_open_file_id(parent, descriptor) else {
        return false;
    };
    if linux_process_descriptor_open_file_id(child, descriptor) != Some(id) {
        return false;
    }
    let original = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
    let marker = original.wrapping_add(0x0047_494e_5558);
    linux_descriptor_offset(descriptor).store(marker, Ordering::SeqCst);
    let child_updated = linux_process_runtime_state(child)
        .filter(|state| state.valid)
        .is_some_and(|state| state.descriptors.stdio_offsets[descriptor as usize] == marker);
    linux_descriptor_offset(descriptor).store(original, Ordering::SeqCst);
    child_updated
}

fn verify_linux_cross_process_vm(pid: u32) -> bool {
    const LENGTH: usize = 16;
    const INPUT_OFFSET: u64 = 128;
    const OUTPUT_OFFSET: u64 = 160;
    let mapping = X86_RUNTIME.ELF_PROBE_DATA.load(Ordering::SeqCst);
    let target = X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1);
    let mut workspace = [0_u8; 192];
    let mut original = [0_u8; LENGTH];
    let mut parent = [0_u8; LENGTH];
    let pattern = *b"LINOX-PROCESS-VM";
    let mut local_write = [0_u8; 16];
    local_write[..8].copy_from_slice(&(mapping + INPUT_OFFSET).to_ne_bytes());
    local_write[8..].copy_from_slice(&(LENGTH as u64).to_ne_bytes());
    let mut local_read = [0_u8; 16];
    local_read[..8].copy_from_slice(&(mapping + OUTPUT_OFFSET).to_ne_bytes());
    local_read[8..].copy_from_slice(&(LENGTH as u64).to_ne_bytes());
    let mut remote = [0_u8; 16];
    remote[..8].copy_from_slice(&target.to_ne_bytes());
    remote[8..].copy_from_slice(&(LENGTH as u64).to_ne_bytes());

    let workspace_saved = copy_from_linux_user(mapping, &mut workspace);
    let child_saved = linux_process::copy_from_live_process(pid, target, &mut original);
    let parent_saved = copy_from_linux_user(target, &mut parent);
    let local_write_ready = copy_to_linux_user(mapping, &local_write);
    let remote_ready = copy_to_linux_user(mapping + 16, &remote);
    let local_read_ready = copy_to_linux_user(mapping + 32, &local_read);
    let input_ready = copy_to_linux_user(mapping + INPUT_OFFSET, &pattern);
    let output_ready = copy_to_linux_user(mapping + OUTPUT_OFFSET, &[0_u8; LENGTH]);
    let prepared = workspace_saved
        && child_saved
        && parent_saved
        && local_write_ready
        && remote_ready
        && local_read_ready
        && input_ready
        && output_ready;
    let written = prepared
        && linux_process_vm_iov(u64::from(pid), mapping, 1, mapping + 16, 1, 0, true)
            == LENGTH as u64;
    let read = written
        && linux_process_vm_iov(u64::from(pid), mapping + 32, 1, mapping + 16, 1, 0, false)
            == LENGTH as u64;
    let mut observed = [0_u8; LENGTH];
    let isolated = read
        && copy_from_linux_user(mapping + OUTPUT_OFFSET, &mut observed)
        && observed == pattern
        && copy_from_linux_user(target, &mut parent)
        && parent == original;
    let mut partial_remote = [0_u8; 32];
    partial_remote[..8].copy_from_slice(&target.to_ne_bytes());
    partial_remote[8..16].copy_from_slice(&8_u64.to_ne_bytes());
    partial_remote[16..24].copy_from_slice(&1_u64.to_ne_bytes());
    partial_remote[24..].copy_from_slice(&8_u64.to_ne_bytes());
    let partial = isolated
        && copy_to_linux_user(mapping + 48, &partial_remote)
        && linux_process_vm_iov(u64::from(pid), mapping, 1, mapping + 48, 2, 0, true) == 8;

    let permission = if let Some(dumpable) = partial
        .then(|| linux_process_runtime_state(pid))
        .flatten()
        .filter(|state| state.valid)
        .map(|state| {
            let dumpable = state.dumpable;
            state.dumpable = false;
            dumpable
        }) {
        let denied =
            linux_process_vm_iov(u64::from(pid), mapping + 32, 1, mapping + 16, 1, 0, false)
                == LINUX_EPERM;
        linux_process_runtime_state(pid)
            .filter(|state| state.valid)
            .is_some_and(|state| {
                state.dumpable = dumpable;
                denied
            })
    } else {
        false
    };
    let errors = linux_process_vm_iov(
        u64::from(u32::MAX),
        mapping + 32,
        1,
        mapping + 16,
        1,
        0,
        false,
    ) == LINUX_ESRCH
        && linux_process_vm_iov(u64::from(pid), mapping + 32, 1, mapping + 16, 1, 1, false)
            == LINUX_EINVAL
        && {
            remote[..8].copy_from_slice(&1_u64.to_ne_bytes());
            copy_to_linux_user(mapping + 16, &remote)
                && linux_process_vm_iov(u64::from(pid), mapping + 32, 1, mapping + 16, 1, 0, false)
                    == LINUX_EFAULT
        };
    let restored = linux_process::copy_to_live_process(pid, target, &original);
    let workspace_restored = copy_to_linux_user(mapping, &workspace);
    let valid = partial && permission && errors && restored && workspace_restored;
    if !valid {
        serial_write("linox: Linux cross-process memory validation failed:");
        for value in [
            prepared,
            written,
            read,
            isolated,
            partial,
            permission,
            errors,
            restored,
            workspace_restored,
        ] {
            serial_write(" ");
            serial_write_u64(u64::from(value));
        }
        serial_write(" target/mapped/writable/access ");
        serial_write_u64(target);
        let target_mapping = usize::try_from(target)
            .ok()
            .and_then(|target| linux_process::live_process_mapping(pid, target));
        serial_write(" ");
        serial_write_u64(u64::from(target_mapping.is_some()));
        serial_write(" ");
        serial_write_u64(u64::from(
            target_mapping.is_some_and(|mapping| mapping.writable),
        ));
        serial_write(" ");
        serial_write_u64(u64::from(linux_ptrace_access_permitted(pid)));
        serial_write(" prepare ");
        for value in [
            child_saved,
            parent_saved,
            workspace_saved,
            local_write_ready,
            remote_ready,
            local_read_ready,
            input_ready,
            output_ready,
        ] {
            serial_write(" ");
            serial_write_u64(u64::from(value));
        }
        serial_write("\r\n");
    }
    valid
}

pub(crate) fn verify_linux_copy_bounds(base: u64, size: usize) -> bool {
    size >= LINUX_UTSNAME_SIZE
        && linux_range_contains(base, size as u64, base, LINUX_UTSNAME_SIZE)
        && linux_range_contains(
            base,
            size as u64,
            base + (size - LINUX_UTSNAME_SIZE) as u64,
            LINUX_UTSNAME_SIZE,
        )
        && !linux_range_contains(
            base,
            size as u64,
            base + (size - LINUX_UTSNAME_SIZE + 1) as u64,
            LINUX_UTSNAME_SIZE,
        )
        && !linux_range_contains(base, size as u64, base + size as u64, 1)
        && !linux_range_contains(base, size as u64, u64::MAX - 3, 8)
}

pub(crate) fn publish_linux_abi_test_results() -> bool {
    const VERIFIED_LINUX_PROFILE: u64 = ((1 << 16) - 1) | (1 << 18);

    if control_abi::LINUX_ABI_TEST_COUNT > u64::BITS as usize {
        return false;
    }
    LINUX_ABI_TEST_RESULTS
        .compare_exchange(
            0,
            VERIFIED_LINUX_PROFILE,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .is_ok()
}

pub(super) fn linux_abi_test_results(
    domain_id: u64,
    capability: u64,
    frame: Option<&UserTrapFrame>,
) -> u64 {
    let Some(frame) = frame else {
        return u64::MAX - 2;
    };
    let results = LINUX_ABI_TEST_RESULTS.load(Ordering::Acquire);
    if results == 0
        || !domain::handle_permits(domain_id, capability, 1, Rights::READ)
        || frame.first_argument() != 0
        || frame.second_argument() != 0
        || !domain::renew_auxiliary_call_epoch(domain_id)
    {
        u64::MAX - 2
    } else {
        results
    }
}
