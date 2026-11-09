#![forbid(unsafe_code)]
use super::*;

pub(crate) fn execute_auxiliary(
    entry: usize,
    stack: usize,
    console_handle: u64,
    domain_id: u64,
    service_identity: u64,
) {
    if !install_current_scheduler_fs_base() {
        return;
    }
    let _ = enter_user(
        entry,
        stack,
        0,
        console_handle,
        0,
        4,
        domain_id,
        service_identity,
        0,
    );
}

pub(crate) fn execute_packet_consumer(
    entry: usize,
    stack: usize,
    packet_handle: u64,
    expected_sequence: u64,
    more_pending: bool,
    domain_id: u64,
    service_identity: u64,
) {
    if !install_current_scheduler_fs_base() {
        return;
    }
    let _ = enter_user(
        entry,
        stack,
        expected_sequence,
        packet_handle,
        u64::from(more_pending),
        4,
        domain_id,
        service_identity,
        0,
    );
}

pub(crate) fn execute_native_auxiliary(
    entry: usize,
    stack: usize,
    boot_info: u64,
    capability: u64,
    domain_id: u64,
    service_identity: u64,
) {
    if !install_current_scheduler_fs_base() {
        return;
    }
    let _ = enter_user(
        entry,
        stack,
        boot_info,
        capability,
        0,
        4,
        domain_id,
        service_identity,
        0,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_native_controller(
    entry: usize,
    stack: usize,
    console_handle: u64,
    host_handle: u64,
    root_handle: u64,
    network_handle: u64,
    domain_id: u64,
    service_identity: u64,
) {
    if !install_current_scheduler_fs_base()
        || X86_RUNTIME
            .LINUX_CONTROLLER_DOMAIN
            .compare_exchange(0, domain_id, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return;
    }
    X86_RUNTIME
        .LINUX_CONTROLLER_CONSOLE
        .store(console_handle, Ordering::Release);
    X86_RUNTIME
        .LINUX_CONTROLLER_HOST
        .store(host_handle, Ordering::Release);
    X86_RUNTIME
        .LINUX_CONTROLLER_ROOT
        .store(root_handle, Ordering::Release);
    X86_RUNTIME
        .LINUX_CONTROLLER_NETWORK
        .store(network_handle, Ordering::Release);
    if configure_linux_syscall().is_none() {
        X86_RUNTIME
            .LINUX_CONTROLLER_DOMAIN
            .store(0, Ordering::Release);
        return;
    }
    let _ = enter_user(
        entry,
        stack,
        console_handle,
        host_handle,
        network_handle,
        4,
        domain_id,
        service_identity,
        root_handle,
    );
}

pub(crate) fn resume_native_controller(domain_id: u64) -> bool {
    let Some(context) = scheduler::resume_container_lifecycle(domain_id) else {
        return false;
    };
    let (Ok(entry), Ok(stack)) = (
        usize::try_from(context.instruction()),
        usize::try_from(context.stack()),
    ) else {
        return false;
    };
    if !activate_user_root(context.address_space_root()) || !install_user_fs_base(context.fs_base())
    {
        return false;
    }
    let general = context.general();
    // The scheduler retained the complete validated controller trap context
    // while its lifecycle request was serviced by the kernel.
    process_user_enter(entry, stack, &general, context.flags());
    true
}

pub(super) fn prepare_domain_exec_stdio() -> bool {
    for descriptor in 0..3 {
        if linux_descriptor_open(descriptor) && linux_descriptor_close(descriptor) != 0 {
            return false;
        }
        let index = descriptor as usize;
        X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_DEVICE_DESCRIPTORS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_ROOTFS_DESCRIPTORS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_TMP_FILE_GENERATIONS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_OFFSETS[index].store(0, Ordering::Release);
        X86_RUNTIME.ELF_PROBE_STDIO_OPEN_FILE_IDS[index].store(0, Ordering::Release);
        set_linux_descriptor_close_on_exec(descriptor, false);
    }
    X86_RUNTIME.ELF_PROBE_CONSOLE_DESCRIPTORS.store(
        (LINUX_DESCRIPTOR_INPUT | (LINUX_DESCRIPTOR_OUTPUT << 2)) as u8,
        Ordering::Release,
    );
    X86_RUNTIME
        .ELF_PROBE_STDERR_OPEN
        .store(true, Ordering::Release);
    true
}

pub(super) fn resume_linux_system_supervisor() -> bool {
    if X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT
        .load(Ordering::SeqCst)
        != 1
        || X86_RUNTIME
            .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
            .load(Ordering::SeqCst)
            != 0
        || current_linux_thread_handle().is_some()
        || linux_process::live_process_status(1)
            != Some(linux_process::LiveProcessStatus {
                pid: 1,
                parent_pid: 0,
                state: linux_process::LiveProcessState::Running,
            })
    {
        if cfg!(feature = "verification-boot") {
            serial_write(
                "linox: Linux supervisor resume preconditions wait/shutdown/thread/status: ",
            );
            serial_write_u64(u64::from(
                X86_RUNTIME
                    .LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT
                    .load(Ordering::SeqCst),
            ));
            serial_write(" ");
            serial_write_u64(u64::from(
                X86_RUNTIME
                    .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
                    .load(Ordering::SeqCst),
            ));
            serial_write(" ");
            serial_write_u64(u64::from(current_linux_thread_handle().is_some()));
            serial_write(" ");
            serial_write_u64(u64::from(linux_process::live_process_status(1).is_some()));
            serial_write("\r\n");
        }
        return false;
    }
    if !X86_RUNTIME
        .CONTAINER_MANAGEMENT_ENABLED
        .load(Ordering::SeqCst)
    {
        return resume_linux_system_supervisor_legacy();
    }
    let Some(slot) = selected_container_slot() else {
        return false;
    };
    X86_RUNTIME
        .CONTAINER_ACTIVE_SLOT
        .store(slot as u8, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .store(slot as u8, Ordering::SeqCst);
    X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
        .store(control_abi::DOMAIN_STATE_RUNNING as u8, Ordering::SeqCst);
    crate::serial_write("linox: configured runtime domain reached ready state\r\n");
    let controller_completed = address_space::run_installed_interactive_controller();
    let shutdown_requested = X86_RUNTIME
        .CONTAINER_HOST_SHUTDOWN_REQUESTED
        .load(Ordering::SeqCst);
    if !controller_completed && !shutdown_requested {
        return false;
    }
    if !controller_completed {
        crate::serial_write(
            "linox: authorized shutdown retained after controller teardown failure\r\n",
        );
    }
    if X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
        .load(Ordering::SeqCst)
        == 0
        && !shutdown_linux_system_supervisor(false)
    {
        return false;
    }
    X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
        .load(Ordering::SeqCst)
        == 1
}

fn resume_linux_system_supervisor_legacy() -> bool {
    if !wake_linux_signal_wait(LINUX_SIGTERM, LINUX_SI_KERNEL, None) {
        return false;
    }
    let Some(thread) = ready_linux_thread_handle() else {
        return false;
    };
    let Some(context) = linux_thread_return_context(thread) else {
        return false;
    };
    let Some(process) = linux_process::dispatch_live_init_with_return(LINUX_SIGTERM) else {
        return false;
    };
    if process.pid != 1
        || context.rax != LINUX_SIGTERM
        || process.general
            != context
                .registers
                .process_general(context.rax, context.rip, context.rflags)
        || process.rip != context.rip
        || process.rsp != context.rsp
        || process.rflags != context.rflags
        || process.fs_base != context.fs_base
        || !switch_linux_thread(thread)
    {
        return false;
    }
    X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
        .fetch_add(1, Ordering::SeqCst);
    run_dispatched_linux_process(&process)
}

fn shutdown_linux_system_supervisor(failed: bool) -> bool {
    if X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT
        .load(Ordering::SeqCst)
        != 1
        || X86_RUNTIME
            .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
            .load(Ordering::SeqCst)
            != 0
        || current_linux_thread_handle().is_some()
        || linux_process::live_process_status(1)
            != Some(linux_process::LiveProcessStatus {
                pid: 1,
                parent_pid: 0,
                state: linux_process::LiveProcessState::Running,
            })
        || !wake_linux_signal_wait(LINUX_SIGTERM, LINUX_SI_KERNEL, None)
    {
        return false;
    }
    let Some(thread) = ready_linux_thread_handle() else {
        return false;
    };
    let Some(context) = linux_thread_return_context(thread) else {
        return false;
    };
    let Some(process) = linux_process::dispatch_live_init_with_return(LINUX_SIGTERM) else {
        return false;
    };
    if process.pid != 1
        || context.rax != LINUX_SIGTERM
        || process.general
            != context
                .registers
                .process_general(context.rax, context.rip, context.rflags)
        || process.rip != context.rip
        || process.rsp != context.rsp
        || process.rflags != context.rflags
        || process.fs_base != context.fs_base
        || !switch_linux_thread(thread)
    {
        return false;
    }
    X86_RUNTIME
        .LINUX_SYSTEM_SUPERVISOR_SHUTDOWN_COUNT
        .fetch_add(1, Ordering::SeqCst);
    let resumed = run_dispatched_linux_process(&process);
    if resumed {
        let Some(slot) = active_container_slot() else {
            return false;
        };
        if X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst)
            != control_abi::DOMAIN_STATE_RUNNING as u8
        {
            return resumed;
        }
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].store(
            if failed {
                control_abi::DOMAIN_STATE_FAILED as u8
            } else {
                control_abi::DOMAIN_STATE_STOPPED as u8
            },
            Ordering::SeqCst,
        );
        X86_RUNTIME
            .CONTAINER_ACTIVE_SLOT
            .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
        X86_RUNTIME
            .CONTAINER_SELECTED_SLOT
            .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
    }
    resumed
}

pub(crate) fn take_container_restart_request() -> bool {
    X86_RUNTIME
        .CONTAINER_RESTART_REQUESTED
        .swap(false, Ordering::SeqCst)
}

pub(crate) fn take_container_host_shutdown_request() -> bool {
    X86_RUNTIME
        .CONTAINER_HOST_SHUTDOWN_REQUESTED
        .swap(false, Ordering::SeqCst)
}

pub(crate) fn fail_configured_container() {
    if let Some(slot) = selected_or_active_container_slot() {
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
            .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::SeqCst);
    }
    X86_RUNTIME
        .CONTAINER_ACTIVE_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
    X86_RUNTIME
        .CONTAINER_SELECTED_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .store(LINUX_RUNTIME_HOST_INSTANCE, Ordering::SeqCst);
}

pub(crate) fn begin_configured_container() {
    if let Some(slot) = selected_container_slot() {
        let Some(container_domain) = container_domain_id(slot) else {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::SeqCst);
            return;
        };
        if domain::container_domain_limits(container_domain).is_none() {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::SeqCst);
            return;
        }
        if domain::container_network_mode(container_domain).is_none() {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::SeqCst);
            return;
        }
        X86_RUNTIME
            .CONTAINER_ACTIVE_SLOT
            .store(slot as u8, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_EXECUTION_INSTANCE
            .store(slot as u8, Ordering::SeqCst);
        if container_state(slot) != control_abi::DOMAIN_STATE_BOOTING {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_RUNNING as u8, Ordering::SeqCst);
        }
    }
}

pub(crate) fn mark_configured_container_booting() {
    if let Some(slot) = selected_container_slot() {
        if container_state(slot) == control_abi::DOMAIN_STATE_STARTING
            && !container_image_is_embedded(slot)
            && crate::published_rootfs::is_installed(slot)
        {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_BOOTING as u8, Ordering::Release);
        }
    }
}

pub(crate) fn stop_configured_container() {
    activation::discard_parked(linux_execution_instance() as u32);
    crate::linux_exe::forget_instance(X86_RUNTIME.LINUX_EXECUTION_INSTANCE.load(Ordering::SeqCst));
    crate::linux_areas::forget_instance(linux_execution_instance());
    linux_perf_forget_instance(linux_execution_instance());
    crate::linux_mounts::forget_instance(linux_execution_instance());
    crate::linux_lease::forget_domain(linux_execution_instance());
    crate::linux_core::forget_domain(linux_execution_instance());
    crate::linux_fd_table::forget_domain(linux_execution_instance());
    crate::linux_wait_sets::forget_domain(linux_execution_instance());
    crate::linux_tmpfs_quota::forget_instance(linux_execution_instance());
    crate::linux_swap::forget_instance(linux_execution_instance());
    crate::linux_pidfs::forget_instance(linux_execution_instance());
    crate::linux_fscontext::forget_instance(linux_execution_instance());
    linux_namespace::forget_instance(
        linux_execution_instance(),
        crate::linux_sysv_ipc::release_instance,
    );
    if let Some(slot) = active_container_slot() {
        if matches!(
            u64::from(X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst)),
            control_abi::DOMAIN_STATE_BOOTING | control_abi::DOMAIN_STATE_RUNNING
        ) {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_STOPPED as u8, Ordering::SeqCst);
        }
    }
    X86_RUNTIME
        .CONTAINER_ACTIVE_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
    X86_RUNTIME
        .CONTAINER_SELECTED_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .store(LINUX_RUNTIME_HOST_INSTANCE, Ordering::SeqCst);
}

pub(crate) fn suspend_configured_container() {
    X86_RUNTIME
        .CONTAINER_ACTIVE_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::Release);
    X86_RUNTIME
        .CONTAINER_SELECTED_SLOT
        .store(CONTAINER_SLOT_NONE, Ordering::Release);
    X86_RUNTIME
        .LINUX_EXECUTION_INSTANCE
        .store(LINUX_RUNTIME_HOST_INSTANCE, Ordering::Release);
}

pub(crate) fn enable_container_management() -> bool {
    X86_RUNTIME
        .CONTAINER_MANAGEMENT_ENABLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

pub(crate) fn export_persistent_domain_configuration(
    output: &mut [u8; PERSISTENT_DOMAIN_CONFIG_SIZE],
) -> bool {
    if !X86_RUNTIME
        .CONTAINER_MANAGEMENT_ENABLED
        .load(Ordering::Acquire)
    {
        return false;
    }
    output.fill(0);
    output[..8].copy_from_slice(b"LINOXDC1");
    output[8..12].copy_from_slice(&1_u32.to_le_bytes());
    output[12..14].copy_from_slice(&(control_abi::DOMAIN_LIMIT as u16).to_le_bytes());
    for slot in 0..control_abi::DOMAIN_LIMIT {
        if container_state(slot) == 0 {
            continue;
        }
        let mut request = [0_u8; control_abi::DOMAIN_REQUEST_SIZE];
        write_container_request(&mut request, slot, control_abi::DOMAIN_CURSOR_END);
        let start = 16 + slot * control_abi::DOMAIN_REQUEST_SIZE;
        output[start..start + control_abi::DOMAIN_REQUEST_SIZE].copy_from_slice(&request);
    }
    true
}

pub(crate) fn import_persistent_domain_configuration(
    input: &[u8; PERSISTENT_DOMAIN_CONFIG_SIZE],
) -> bool {
    if !X86_RUNTIME
        .CONTAINER_MANAGEMENT_ENABLED
        .load(Ordering::Acquire)
        || &input[..8] != b"LINOXDC1"
        || u32::from_le_bytes(input[8..12].try_into().unwrap_or([0; 4])) != 1
        || usize::from(u16::from_le_bytes(
            input[12..14].try_into().unwrap_or([0; 2]),
        )) != control_abi::DOMAIN_LIMIT
        || input[14..16].iter().any(|byte| *byte != 0)
        || (0..control_abi::DOMAIN_LIMIT).any(|slot| container_state(slot) != 0)
    {
        return false;
    }
    let Some(supervisor) = domain::control_plane_id() else {
        return false;
    };
    for slot in 0..control_abi::DOMAIN_LIMIT {
        let start = 16 + slot * control_abi::DOMAIN_REQUEST_SIZE;
        let request: &[u8; control_abi::DOMAIN_REQUEST_SIZE] =
            match input[start..start + control_abi::DOMAIN_REQUEST_SIZE].try_into() {
                Ok(request) => request,
                Err(_) => return false,
            };
        if request.iter().all(|byte| *byte == 0) {
            continue;
        }
        let name = container_request_name(request);
        let init = container_request_init(request);
        let image = container_request_image(request);
        let personality = domain_request_personality(request);
        let flags = read_u16_at(request, 34);
        let cpu_count = read_u16_at(request, 70);
        let memory_mib = read_u64_at(request, 200);
        if read_u32_at(request, 0) != control_abi::DOMAIN_REQUEST_SIZE as u32
            || read_u16_at(request, 4) != control_abi::DOMAIN_REQUEST_VERSION
            || !valid_container_name(name)
            || container_slot_by_name(name).is_some()
            || !valid_container_init(init)
            || !valid_container_image(image)
            || !valid_domain_personality(personality)
            || cpu_count == 0
            || memory_mib == 0
            || flags
                & !(control_abi::DOMAIN_CONFIG_COMPLETE
                    | control_abi::DOMAIN_CONFIG_AUTOSTART
                    | control_abi::DOMAIN_CONFIG_USER_SWITCHING
                    | control_abi::DOMAIN_CONFIG_WRITE_EXECUTE
                    | control_abi::DOMAIN_CONFIG_PRIVILEGED)
                != 0
            || flags
                & (control_abi::DOMAIN_CONFIG_INIT
                    | control_abi::DOMAIN_CONFIG_CPU
                    | control_abi::DOMAIN_CONFIG_MEMORY
                    | control_abi::DOMAIN_CONFIG_PERSONALITY)
                != control_abi::DOMAIN_CONFIG_INIT
                    | control_abi::DOMAIN_CONFIG_CPU
                    | control_abi::DOMAIN_CONFIG_MEMORY
                    | control_abi::DOMAIN_CONFIG_PERSONALITY
        {
            return false;
        }
        let Some(container_domain) =
            domain::create_container_domain(supervisor, slot, cpu_count, memory_mib)
        else {
            return false;
        };
        X86_RUNTIME.CONTAINER_DOMAIN_IDS[slot].store(container_domain, Ordering::Release);
        X86_RUNTIME.CONTAINER_CPU_COUNTS[slot].store(cpu_count, Ordering::Release);
        X86_RUNTIME.CONTAINER_MEMORY_MIB[slot].store(memory_mib, Ordering::Release);
        store_container_name(slot, name);
        store_container_value(
            init,
            &X86_RUNTIME.CONTAINER_INITS[slot],
            &X86_RUNTIME.CONTAINER_INIT_SIZES[slot],
        );
        store_container_value(
            image,
            &X86_RUNTIME.CONTAINER_IMAGES[slot],
            &X86_RUNTIME.CONTAINER_IMAGE_SIZES[slot],
        );
        store_container_value(
            personality,
            &X86_RUNTIME.DOMAIN_PERSONALITIES[slot],
            &X86_RUNTIME.DOMAIN_PERSONALITY_SIZES[slot],
        );
        X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot].store(flags, Ordering::Release);
        let state =
            if flags & control_abi::DOMAIN_CONFIG_COMPLETE == control_abi::DOMAIN_CONFIG_COMPLETE {
                control_abi::DOMAIN_STATE_CONFIGURED
            } else {
                control_abi::DOMAIN_STATE_CREATED
            };
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].store(state as u8, Ordering::Release);
    }
    true
}

pub(crate) fn linux_runtime_diagnostics() -> (Option<u8>, Option<u64>) {
    let status = X86_RUNTIME.LINUX_RUNTIME_EXIT_STATUS.load(Ordering::SeqCst);
    let syscall = X86_RUNTIME
        .LINUX_RUNTIME_FIRST_UNSUPPORTED_SYSCALL
        .load(Ordering::SeqCst);
    (
        u8::try_from(status).ok(),
        (syscall != u64::MAX).then_some(syscall),
    )
}

pub(super) fn prepare_configured_linux_system_domain() -> bool {
    linux_prepare_securityfs();
    linux_prepare_hugetlbfs();
    linux_prepare_numa_sysfs();
    if !prepare_linux_package_platform() {
        return false;
    }
    let mut init = [0_u8; control_abi::DOMAIN_MAX_INIT_SIZE];
    let Some(init_size) = configured_container_init(&mut init) else {
        return false;
    };
    prepare_linux_system_domain(&init[..init_size])
}

fn prepare_linux_package_platform() -> bool {
    let rpm = b"usr/bin/rpm";
    let platform = b"etc/rpm/platform";
    let lower_has_rpm =
        crate::published_rootfs::lookup_metadata_at(crate::published_rootfs::ROOT_HANDLE, rpm)
            .and_then(|(_, entry)| entry)
            .is_some();
    let lower_has_platform =
        crate::published_rootfs::lookup_metadata_at(crate::published_rootfs::ROOT_HANDLE, platform)
            .and_then(|(_, entry)| entry)
            .is_some();
    !lower_has_rpm
        || lower_has_platform
        || crate::linux_overlay::lookup(platform).is_some()
        || crate::linux_overlay::create_file(platform, 0o644, b"x86_64-linux\n").is_some()
}

fn prepare_linux_system_domain(init: &[u8]) -> bool {
    if !matches!(
        init,
        b"/sbin/init" | b"sbin/init" | b"/usr/lib/systemd/systemd" | b"usr/lib/systemd/systemd"
    ) {
        return true;
    }
    for path in [
        &b"etc/systemd/system/console-getty.service"[..],
        &b"etc/systemd/system/getty.target"[..],
    ] {
        let masked =
            crate::published_rootfs::lookup_metadata_at(crate::published_rootfs::ROOT_HANDLE, path)
                .and_then(|(_, entry)| entry)
                .is_some_and(|entry| {
                    entry.kind == crate::published_rootfs::EntryKind::Symlink
                        && entry.link() == b"/dev/null"
                });
        if masked && !crate::linux_overlay::whiteout(path) {
            return false;
        }
    }
    // Domain attachment grants access to the console, not an authenticated
    // root session. Use the distribution's login stack so the console has the
    // same authentication boundary as a physical Linux console.
    let contents = b"[Unit]\nDescription=Linox Domain Console Login\nAfter=systemd-user-sessions.service\n\n[Service]\nExecStart=-/sbin/agetty --noclear --keep-baud 115200,57600,38400,9600 - linux\nType=idle\nRestart=always\nStandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTTYReset=yes\nTTYVHangup=yes\nEnvironment=TERM=linux\n\n[Install]\nWantedBy=getty.target\n";
    let vendor_console = &b"usr/lib/systemd/system/console-getty.service"[..];
    if crate::linux_overlay::lookup(vendor_console).is_none()
        && crate::linux_overlay::create_file(vendor_console, 0o644, contents).is_none()
    {
        return false;
    }
    let configured_console = &b"etc/systemd/system/console-getty.service"[..];
    if crate::linux_overlay::lookup(configured_console).is_none()
        && crate::linux_overlay::create_symlink(
            configured_console,
            b"/usr/lib/systemd/system/console-getty.service",
        )
        .is_none()
    {
        return false;
    }
    let configured_getty_target = &b"etc/systemd/system/getty.target"[..];
    if crate::linux_overlay::lookup(configured_getty_target).is_none()
        && crate::linux_overlay::create_symlink(
            configured_getty_target,
            b"/usr/lib/systemd/system/getty.target",
        )
        .is_none()
    {
        return false;
    }
    // The OCI root is ephemeral today, so journald must remain volatile; a
    // persistent flush has no valid destination. configfs is implemented by
    // the Linox kernel directly and does not require a domain-side module.
    for (unit, description) in [
        (
            &b"usr/lib/systemd/system/systemd-journal-flush.service"[..],
            &b"Linox Volatile Journal"[..],
        ),
        (
            &b"usr/lib/systemd/system/modprobe@.service"[..],
            &b"Linox Built-in Kernel Facility"[..],
        ),
    ] {
        let mut replacement = [0_u8; 192];
        let prefix = b"[Unit]\nDescription=";
        let suffix = b"\nDefaultDependencies=no\n\n[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n";
        let length = prefix.len() + description.len() + suffix.len();
        replacement[..prefix.len()].copy_from_slice(prefix);
        replacement[prefix.len()..prefix.len() + description.len()].copy_from_slice(description);
        replacement[prefix.len() + description.len()..length].copy_from_slice(suffix);
        if crate::linux_overlay::lookup(unit).is_none()
            && crate::linux_overlay::create_file(unit, 0o644, &replacement[..length]).is_none()
        {
            return false;
        }
    }
    true
}

pub(super) fn container_console_read_byte() -> Option<u8> {
    let slot = active_container_slot()?;
    // An init waiting for console input has finished booting, whether or not
    // the console stays attached.
    let _ = X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].compare_exchange(
        control_abi::DOMAIN_STATE_BOOTING as u8,
        control_abi::DOMAIN_STATE_RUNNING as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    if !X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire) {
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
            .store(control_abi::DOMAIN_STATE_RUNNING as u8, Ordering::Release);
        X86_RUNTIME.CONTAINER_BACKGROUND_SUSPENDED[slot].store(false, Ordering::Release);
        X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_REQUESTED
            .store(true, Ordering::Release);
        return None;
    }
    let byte = crate::serial_read_byte_blocking();
    if byte == CONTAINER_CONSOLE_DETACH {
        X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].store(false, Ordering::Release);
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
            .store(control_abi::DOMAIN_STATE_RUNNING as u8, Ordering::Release);
        X86_RUNTIME
            .LINUX_RUNTIME_SUSPEND_REQUESTED
            .store(true, Ordering::Release);
        crate::serial_write_bytes(
            b"\r\n[detached from domain; use 'domain attach NAME' to return]\r\n",
        );
        None
    } else {
        Some(byte)
    }
}

pub(super) fn container_console_write(bytes: &[u8]) {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire) {
        crate::serial_write_bytes(bytes);
        return;
    }
    let Some(slot) = active_container_slot() else {
        crate::serial_write_bytes(bytes);
        return;
    };
    let start = X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot].load(Ordering::Relaxed);
    for (offset, byte) in bytes.iter().copied().enumerate() {
        let index = start.wrapping_add(offset as u64) as usize % CONTAINER_CONSOLE_CAPACITY;
        X86_RUNTIME.CONTAINER_CONSOLE_BYTES[slot][index].store(byte, Ordering::Relaxed);
    }
    X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot]
        .store(start.wrapping_add(bytes.len() as u64), Ordering::Release);
    if X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire) {
        crate::serial_write_bytes(bytes);
    }
}

pub(crate) fn buffer_configured_container_console(bytes: &[u8]) -> bool {
    let Some(slot) = selected_or_active_container_slot() else {
        return false;
    };
    let start = X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot].load(Ordering::Relaxed);
    for (offset, byte) in bytes.iter().copied().enumerate() {
        let index = start.wrapping_add(offset as u64) as usize % CONTAINER_CONSOLE_CAPACITY;
        X86_RUNTIME.CONTAINER_CONSOLE_BYTES[slot][index].store(byte, Ordering::Relaxed);
    }
    X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot]
        .store(start.wrapping_add(bytes.len() as u64), Ordering::Release);
    true
}

fn reset_container_console(slot: usize, attached: bool) {
    X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot].store(0, Ordering::Release);
    X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].store(attached, Ordering::Release);
}

fn redraw_container_console(slot: usize) {
    crate::serial_write_bytes(b"\x1b[2J\x1b[H");
    let cursor = X86_RUNTIME.CONTAINER_CONSOLE_CURSOR[slot].load(Ordering::Acquire);
    let count = cursor.min(CONTAINER_CONSOLE_CAPACITY as u64);
    let start = cursor.wrapping_sub(count);
    for offset in 0..count {
        let index = start.wrapping_add(offset) as usize % CONTAINER_CONSOLE_CAPACITY;
        crate::serial_write_bytes(&[
            X86_RUNTIME.CONTAINER_CONSOLE_BYTES[slot][index].load(Ordering::Relaxed)
        ]);
    }
}

pub(super) fn container_control(
    domain_id: u64,
    capability: u64,
    frame: Option<&mut UserTrapFrame>,
) -> u64 {
    let Some(frame) = frame else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::MANAGE) {
        return u64::MAX - 2;
    }
    let operation = frame.first_argument();
    if operation == control_abi::DOMAIN_HOST_SHUTDOWN && frame.second_argument() == 0 {
        X86_RUNTIME
            .CONTAINER_HOST_SHUTDOWN_REQUESTED
            .store(true, Ordering::SeqCst);
        return active_container_slot()
            .map(|slot| {
                u64::from(X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst))
            })
            .unwrap_or(0);
    }
    if operation == control_abi::DOMAIN_EXEC {
        let result = container_exec_control(frame.second_argument());
        if result == u64::MAX - 2 || !domain::renew_auxiliary_call_epoch(domain_id) {
            return u64::MAX - 2;
        }
        if !scheduler::suspend_container_lifecycle(
            frame,
            USER_CODE_SELECTOR,
            USER_DATA_SELECTOR,
            result,
            active_fs_base(),
        ) {
            return u64::MAX - 2;
        }
        return u64::MAX;
    }
    let Some(mut request) = read_container_request(frame.second_argument()) else {
        return u64::MAX - 2;
    };
    let name = container_request_name(&request);
    let requested_slot = container_slot_by_name(name);
    let result = match operation {
        control_abi::DOMAIN_QUERY if name.is_empty() => {
            let Ok(cursor) = usize::try_from(read_u64_at(&request, 24)) else {
                return u64::MAX - 2;
            };
            let Some(slot) = next_container_slot(cursor) else {
                return if domain::renew_auxiliary_call_epoch(domain_id) {
                    0
                } else {
                    u64::MAX - 2
                };
            };
            write_container_request(&mut request, slot, next_container_cursor(slot + 1));
            if !address_space::copy_to_current_user(frame.second_argument(), &request) {
                return u64::MAX - 2;
            }
            u64::from(X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst))
        }
        control_abi::DOMAIN_POLL_BACKGROUND => {
            u64::from(!crate::serial_input_ready() && queue_background_container_work())
        }
        control_abi::DOMAIN_QUERY if requested_slot.is_some() => {
            let slot = requested_slot.unwrap_or(0);
            write_container_request(&mut request, slot, control_abi::DOMAIN_CURSOR_END);
            if !address_space::copy_to_current_user(frame.second_argument(), &request) {
                return u64::MAX - 2;
            }
            u64::from(X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst))
        }
        control_abi::DOMAIN_CREATE if requested_slot.is_none() && valid_container_name(name) => {
            let Some(slot) = free_container_slot() else {
                return u64::MAX - 2;
            };
            let Some(container_domain) = domain::create_container_domain(domain_id, slot, 1, 128)
            else {
                return u64::MAX - 2;
            };
            X86_RUNTIME.CONTAINER_DOMAIN_IDS[slot].store(container_domain, Ordering::SeqCst);
            X86_RUNTIME.CONTAINER_CPU_COUNTS[slot].store(1, Ordering::SeqCst);
            X86_RUNTIME.CONTAINER_MEMORY_MIB[slot].store(128, Ordering::SeqCst);
            store_container_name(slot, name);
            store_container_value(
                b"/sbin/init",
                &X86_RUNTIME.CONTAINER_INITS[slot],
                &X86_RUNTIME.CONTAINER_INIT_SIZES[slot],
            );
            store_container_value(
                b"linux",
                &X86_RUNTIME.DOMAIN_PERSONALITIES[slot],
                &X86_RUNTIME.DOMAIN_PERSONALITY_SIZES[slot],
            );
            X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot].store(
                control_abi::DOMAIN_CONFIG_INIT
                    | control_abi::DOMAIN_CONFIG_CPU
                    | control_abi::DOMAIN_CONFIG_MEMORY
                    | control_abi::DOMAIN_CONFIG_PERSONALITY,
                Ordering::SeqCst,
            );
            X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                .store(control_abi::DOMAIN_STATE_CREATED as u8, Ordering::SeqCst);
            control_abi::DOMAIN_STATE_CREATED
        }
        control_abi::DOMAIN_SET_INIT
            if configurable_container(requested_slot)
                && valid_container_init(container_request_init(&request)) =>
        {
            let slot = requested_slot.unwrap_or(0);
            store_container_value(
                container_request_init(&request),
                &X86_RUNTIME.CONTAINER_INITS[slot],
                &X86_RUNTIME.CONTAINER_INIT_SIZES[slot],
            );
            update_container_configuration(slot, control_abi::DOMAIN_CONFIG_INIT)
        }
        control_abi::DOMAIN_SET_CPU
            if configurable_container(requested_slot) && read_u16_at(&request, 70) != 0 =>
        {
            let slot = requested_slot.unwrap_or(0);
            let cpu_count = read_u16_at(&request, 70);
            let memory_mib = X86_RUNTIME.CONTAINER_MEMORY_MIB[slot].load(Ordering::Acquire);
            if !domain::configure_container_domain_limits(
                X86_RUNTIME.CONTAINER_DOMAIN_IDS[slot].load(Ordering::Acquire),
                cpu_count,
                memory_mib,
            ) {
                return u64::MAX - 2;
            }
            X86_RUNTIME.CONTAINER_CPU_COUNTS[slot].store(cpu_count, Ordering::Release);
            update_container_configuration(slot, control_abi::DOMAIN_CONFIG_CPU)
        }
        control_abi::DOMAIN_SET_MEMORY_MIB
            if configurable_container(requested_slot) && read_u64_at(&request, 200) != 0 =>
        {
            let slot = requested_slot.unwrap_or(0);
            let memory_mib = read_u64_at(&request, 200);
            let cpu_count = X86_RUNTIME.CONTAINER_CPU_COUNTS[slot].load(Ordering::Acquire);
            if !domain::configure_container_domain_limits(
                X86_RUNTIME.CONTAINER_DOMAIN_IDS[slot].load(Ordering::Acquire),
                cpu_count,
                memory_mib,
            ) {
                return u64::MAX - 2;
            }
            X86_RUNTIME.CONTAINER_MEMORY_MIB[slot].store(memory_mib, Ordering::Release);
            update_container_configuration(slot, control_abi::DOMAIN_CONFIG_MEMORY)
        }
        control_abi::DOMAIN_SET_AUTOSTART
            if configurable_container(requested_slot) && read_u64_at(&request, 24) <= 1 =>
        {
            update_container_flag(
                requested_slot.unwrap_or(0),
                control_abi::DOMAIN_CONFIG_AUTOSTART,
                read_u64_at(&request, 24) == 1,
            )
        }
        control_abi::DOMAIN_SET_USER_SWITCHING
            if configurable_container(requested_slot) && read_u64_at(&request, 24) <= 1 =>
        {
            update_container_flag(
                requested_slot.unwrap_or(0),
                control_abi::DOMAIN_CONFIG_USER_SWITCHING,
                read_u64_at(&request, 24) == 1,
            )
        }
        control_abi::DOMAIN_SET_WRITE_EXECUTE
            if configurable_container(requested_slot) && read_u64_at(&request, 24) <= 1 =>
        {
            update_container_flag(
                requested_slot.unwrap_or(0),
                control_abi::DOMAIN_CONFIG_WRITE_EXECUTE,
                read_u64_at(&request, 24) == 1,
            )
        }
        control_abi::DOMAIN_SET_PRIVILEGED
            if configurable_container(requested_slot) && read_u64_at(&request, 24) <= 1 =>
        {
            update_container_flag(
                requested_slot.unwrap_or(0),
                control_abi::DOMAIN_CONFIG_PRIVILEGED,
                read_u64_at(&request, 24) == 1,
            )
        }
        control_abi::DOMAIN_SET_IMAGE
            if configurable_container(requested_slot)
                && valid_container_image(container_request_image(&request)) =>
        {
            let slot = requested_slot.unwrap_or(0);
            let mut canonical = [0_u8; control_abi::DOMAIN_MAX_IMAGE_SIZE];
            let canonical_size =
                canonical_container_image(container_request_image(&request), &mut canonical)
                    .unwrap_or(0);
            let canonical = &canonical[..canonical_size];
            store_container_value(
                canonical,
                &X86_RUNTIME.CONTAINER_IMAGES[slot],
                &X86_RUNTIME.CONTAINER_IMAGE_SIZES[slot],
            );
            if crate::published_rootfs::is_installed(slot)
                && !crate::image_store::uninstall_rootfs(slot)
            {
                return u64::MAX - 2;
            }
            update_container_configuration(slot, control_abi::DOMAIN_CONFIG_IMAGE)
        }
        control_abi::DOMAIN_SET_PERSONALITY
            if configurable_container(requested_slot)
                && valid_domain_personality(domain_request_personality(&request)) =>
        {
            let slot = requested_slot.unwrap_or(0);
            store_container_value(
                domain_request_personality(&request),
                &X86_RUNTIME.DOMAIN_PERSONALITIES[slot],
                &X86_RUNTIME.DOMAIN_PERSONALITY_SIZES[slot],
            );
            update_container_configuration(slot, control_abi::DOMAIN_CONFIG_PERSONALITY)
        }
        control_abi::DOMAIN_STOP
            if requested_slot.is_some()
                && container_state(requested_slot.unwrap_or(0))
                    == control_abi::DOMAIN_STATE_RUNNING
                && (active_container_slot() == requested_slot
                    || address_space::linux_runtime_is_suspended(requested_slot.unwrap_or(0))) =>
        {
            let slot = requested_slot.unwrap_or(0);
            if address_space::linux_runtime_is_suspended(slot) {
                X86_RUNTIME
                    .CONTAINER_SELECTED_SLOT
                    .store(slot as u8, Ordering::Release);
                X86_RUNTIME.CONTAINER_STOP_REQUESTED[slot].store(true, Ordering::Release);
                X86_RUNTIME
                    .CONTAINER_RESTART_REQUESTED
                    .store(true, Ordering::Release);
            } else {
                X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                    .store(control_abi::DOMAIN_STATE_STOPPED as u8, Ordering::SeqCst);
            }
            control_abi::DOMAIN_STATE_STOPPED
        }
        control_abi::DOMAIN_RESTART | control_abi::DOMAIN_START_ATTACHED
            if requested_slot.is_some()
                && active_container_slot().is_none_or(|slot| Some(slot) == requested_slot)
                && X86_RUNTIME.CONTAINER_CONFIG_FLAGS[requested_slot.unwrap_or(0)]
                    .load(Ordering::SeqCst)
                    & control_abi::DOMAIN_CONFIG_COMPLETE
                    == control_abi::DOMAIN_CONFIG_COMPLETE
                && matches!(
                    container_state(requested_slot.unwrap_or(0)),
                    control_abi::DOMAIN_STATE_CONFIGURED
                        | control_abi::DOMAIN_STATE_RUNNING
                        | control_abi::DOMAIN_STATE_STOPPED
                        | control_abi::DOMAIN_STATE_FAILED
                ) =>
        {
            let slot = requested_slot.unwrap_or(0);
            let embedded = container_image_is_embedded(slot);
            // Another detached start still holds the lifecycle request until
            // the controller goes idle; queue this one behind it.
            if operation == control_abi::DOMAIN_RESTART
                && selected_container_slot().is_some_and(|selected| selected != slot)
                && (X86_RUNTIME.CONTAINER_PULL_REQUESTED.load(Ordering::Acquire)
                    || X86_RUNTIME
                        .CONTAINER_INSTALL_REQUESTED
                        .load(Ordering::Acquire)
                    || X86_RUNTIME
                        .CONTAINER_RESTART_REQUESTED
                        .load(Ordering::Acquire))
            {
                reset_container_console(slot, false);
                if !embedded {
                    X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                        .store(control_abi::DOMAIN_STATE_STARTING as u8, Ordering::Release);
                }
                X86_RUNTIME.CONTAINER_START_PENDING[slot].store(true, Ordering::Release);
                return if embedded {
                    control_abi::DOMAIN_STATE_STOPPED
                } else {
                    control_abi::DOMAIN_STATE_STARTING
                };
            }
            X86_RUNTIME.CONTAINER_START_PENDING[slot].store(false, Ordering::Release);
            X86_RUNTIME
                .CONTAINER_SELECTED_SLOT
                .store(slot as u8, Ordering::SeqCst);
            reset_container_console(slot, operation == control_abi::DOMAIN_START_ATTACHED);
            if !embedded {
                X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
                    .store(control_abi::DOMAIN_STATE_STARTING as u8, Ordering::Release);
            }
            if embedded || crate::published_rootfs::is_installed(slot) {
                X86_RUNTIME
                    .CONTAINER_RESTART_REQUESTED
                    .store(true, Ordering::SeqCst);
            } else {
                X86_RUNTIME
                    .CONTAINER_PULL_REQUESTED
                    .store(true, Ordering::SeqCst);
            }
            if embedded {
                control_abi::DOMAIN_STATE_STOPPED
            } else {
                control_abi::DOMAIN_STATE_STARTING
            }
        }
        control_abi::DOMAIN_ATTACH
            if requested_slot.is_some()
                && container_state(requested_slot.unwrap_or(0))
                    == control_abi::DOMAIN_STATE_RUNNING
                && !X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[requested_slot.unwrap_or(0)]
                    .swap(true, Ordering::AcqRel) =>
        {
            let slot = requested_slot.unwrap_or(0);
            X86_RUNTIME
                .CONTAINER_SELECTED_SLOT
                .store(slot as u8, Ordering::Release);
            X86_RUNTIME
                .CONTAINER_RESTART_REQUESTED
                .store(true, Ordering::Release);
            redraw_container_console(slot);
            control_abi::DOMAIN_STATE_RUNNING
        }
        control_abi::DOMAIN_INJECT_FAILURE
            if requested_slot.is_some()
                && active_container_slot() == requested_slot
                && container_state(requested_slot.unwrap_or(0))
                    == control_abi::DOMAIN_STATE_RUNNING =>
        {
            X86_RUNTIME.CONTAINER_CONTROL_STATES[requested_slot.unwrap_or(0)]
                .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::SeqCst);
            control_abi::DOMAIN_STATE_FAILED
        }
        _ => u64::MAX - 2,
    };
    if result != u64::MAX - 2 {
        if !domain::renew_auxiliary_call_epoch(domain_id) {
            return u64::MAX - 2;
        }
        if matches!(
            operation,
            control_abi::DOMAIN_STOP
                | control_abi::DOMAIN_START_ATTACHED
                | control_abi::DOMAIN_ATTACH
                | control_abi::DOMAIN_INJECT_FAILURE
        ) || operation == control_abi::DOMAIN_POLL_BACKGROUND && result == 1
            || operation == control_abi::DOMAIN_RESTART
                && result == control_abi::DOMAIN_STATE_STOPPED
        {
            if !scheduler::suspend_container_lifecycle(
                frame,
                USER_CODE_SELECTOR,
                USER_DATA_SELECTOR,
                result,
                active_fs_base(),
            ) {
                return u64::MAX - 2;
            }
            return u64::MAX;
        }
    }
    result
}

fn container_exec_control(address: u64) -> u64 {
    let mut request = [0_u8; control_abi::DOMAIN_EXEC_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || read_u32_at(&request, 0) != control_abi::DOMAIN_EXEC_REQUEST_SIZE as u32
        || read_u16_at(&request, 4) != control_abi::DOMAIN_EXEC_REQUEST_VERSION
        || read_u16_at(&request, 6) & !control_abi::DOMAIN_EXEC_INTERACTIVE != 0
        || usize::from(read_u16_at(&request, 8)) > control_abi::DOMAIN_MAX_NAME_SIZE
        || usize::from(read_u16_at(&request, 10)) == 0
        || usize::from(read_u16_at(&request, 10)) > control_abi::DOMAIN_EXEC_MAX_ARGUMENTS
        || read_u32_at(&request, 12) != 0
    {
        return u64::MAX - 2;
    }
    let name_size = usize::from(read_u16_at(&request, 8));
    let name = request.get(16..16 + name_size).unwrap_or_default();
    let Some(slot) = container_slot_by_name(name).filter(|slot| {
        matches!(
            container_state(*slot),
            control_abi::DOMAIN_STATE_BOOTING | control_abi::DOMAIN_STATE_RUNNING
        ) && address_space::linux_runtime_is_suspended(*slot)
    }) else {
        return u64::MAX - 2;
    };
    let count = usize::from(read_u16_at(&request, 10));
    let descriptors = read_u64_at(&request, 32);
    for index in 0..count {
        let Some(descriptor_address) = descriptors.checked_add((index * 16) as u64) else {
            return u64::MAX - 2;
        };
        let mut descriptor = [0_u8; 16];
        if !address_space::copy_from_current_user(descriptor_address, &mut descriptor) {
            return u64::MAX - 2;
        }
        let argument_address = read_u64_at(&descriptor, 0);
        let Ok(length) = usize::try_from(read_u64_at(&descriptor, 8)) else {
            return u64::MAX - 2;
        };
        if length == 0 || length >= DOMAIN_EXEC_ARGUMENT_CAPACITY {
            return u64::MAX - 2;
        }
        let mut value = [0_u8; DOMAIN_EXEC_ARGUMENT_CAPACITY];
        if !address_space::copy_from_current_user(argument_address, &mut value[..length]) {
            return u64::MAX - 2;
        }
        X86_RUNTIME.CONTAINER_EXEC_ARGUMENT_SIZES[slot][index]
            .store(length as u16, Ordering::Release);
        for (cell, byte) in X86_RUNTIME.CONTAINER_EXEC_ARGUMENTS[slot][index]
            .iter()
            .zip(value[..length].iter().copied())
        {
            cell.store(byte, Ordering::Release);
        }
    }
    X86_RUNTIME.CONTAINER_EXEC_ARGUMENT_COUNTS[slot].store(count as u8, Ordering::Release);
    X86_RUNTIME.CONTAINER_EXEC_INTERACTIVE[slot].store(
        read_u16_at(&request, 6) & control_abi::DOMAIN_EXEC_INTERACTIVE != 0,
        Ordering::Release,
    );
    X86_RUNTIME.CONTAINER_EXEC_REQUESTED[slot].store(true, Ordering::Release);
    X86_RUNTIME
        .CONTAINER_SELECTED_SLOT
        .store(slot as u8, Ordering::Release);
    X86_RUNTIME
        .CONTAINER_RESTART_REQUESTED
        .store(true, Ordering::Release);
    control_abi::DOMAIN_STATE_RUNNING
}

fn read_container_request(address: u64) -> Option<[u8; control_abi::DOMAIN_REQUEST_SIZE]> {
    let mut request = [0_u8; control_abi::DOMAIN_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || read_u32_at(&request, 0) != control_abi::DOMAIN_REQUEST_SIZE as u32
        || read_u16_at(&request, 4) != control_abi::DOMAIN_REQUEST_VERSION
        || usize::from(read_u16_at(&request, 6)) > control_abi::DOMAIN_MAX_NAME_SIZE
        || usize::from(read_u16_at(&request, 32)) > control_abi::DOMAIN_MAX_INIT_SIZE
        || usize::from(read_u16_at(&request, 68)) > control_abi::DOMAIN_MAX_IMAGE_SIZE
        || usize::from(read_u16_at(&request, 208)) > control_abi::DOMAIN_MAX_PERSONALITY_SIZE
        || request[210..216].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    Some(request)
}

fn container_request_name(request: &[u8; control_abi::DOMAIN_REQUEST_SIZE]) -> &[u8] {
    let size = usize::from(read_u16_at(request, 6));
    request.get(8..8 + size).unwrap_or_default()
}

fn container_request_init(request: &[u8; control_abi::DOMAIN_REQUEST_SIZE]) -> &[u8] {
    let size = usize::from(read_u16_at(request, 32));
    request.get(36..36 + size).unwrap_or_default()
}

fn container_request_image(request: &[u8; control_abi::DOMAIN_REQUEST_SIZE]) -> &[u8] {
    let size = usize::from(read_u16_at(request, 68));
    request.get(72..72 + size).unwrap_or_default()
}

fn domain_request_personality(request: &[u8; control_abi::DOMAIN_REQUEST_SIZE]) -> &[u8] {
    let size = usize::from(read_u16_at(request, 208));
    request.get(216..216 + size).unwrap_or_default()
}

fn valid_domain_personality(personality: &[u8]) -> bool {
    personality == b"linux"
}

fn valid_container_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= control_abi::DOMAIN_MAX_NAME_SIZE
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_container_init(init: &[u8]) -> bool {
    !init.is_empty()
        && init.len() <= control_abi::DOMAIN_MAX_INIT_SIZE
        && init[0] == b'/'
        && init.iter().all(u8::is_ascii_graphic)
}

fn valid_container_image(image: &[u8]) -> bool {
    let mut canonical = [0_u8; control_abi::DOMAIN_MAX_IMAGE_SIZE];
    canonical_container_image(image, &mut canonical).is_some()
}

fn canonical_container_image(image: &[u8], output: &mut [u8]) -> Option<usize> {
    if image == b"embedded://minimal-system-v0"
        || image == crate::image_store::BUILTIN_RUST_IMAGE
            && crate::image_store::builtin_rootfs_available()
    {
        output.get_mut(..image.len())?.copy_from_slice(image);
        return Some(image.len());
    }
    linox_oci::ImageReference::parse(image)
        .ok()?
        .write_canonical(output)
        .ok()
}

pub(super) fn container_slot_by_name(name: &[u8]) -> Option<usize> {
    (!name.is_empty()).then_some(())?;
    (0..control_abi::DOMAIN_LIMIT).find(|slot| {
        let size = usize::from(X86_RUNTIME.CONTAINER_NAME_SIZES[*slot].load(Ordering::SeqCst));
        size == name.len()
            && X86_RUNTIME.CONTAINER_NAMES[*slot][..size]
                .iter()
                .zip(name)
                .all(|(stored, supplied)| stored.load(Ordering::SeqCst) == *supplied)
    })
}

fn free_container_slot() -> Option<usize> {
    (0..control_abi::DOMAIN_LIMIT)
        .find(|slot| X86_RUNTIME.CONTAINER_CONTROL_STATES[*slot].load(Ordering::SeqCst) == 0)
}

fn next_container_slot(cursor: usize) -> Option<usize> {
    (cursor..control_abi::DOMAIN_LIMIT)
        .find(|slot| X86_RUNTIME.CONTAINER_CONTROL_STATES[*slot].load(Ordering::SeqCst) != 0)
}

pub(super) fn next_running_container_slot(cursor: usize) -> Option<usize> {
    (cursor..control_abi::DOMAIN_LIMIT)
        .find(|slot| container_state(*slot) == control_abi::DOMAIN_STATE_RUNNING)
}

pub(super) fn queue_background_container_work() -> bool {
    if X86_RUNTIME.CONTAINER_PULL_REQUESTED.load(Ordering::Acquire)
        || X86_RUNTIME
            .CONTAINER_INSTALL_REQUESTED
            .load(Ordering::Acquire)
        || X86_RUNTIME
            .CONTAINER_RESTART_REQUESTED
            .load(Ordering::Acquire)
    {
        return true;
    }
    // Start the next queued detached domain.
    if let Some(slot) = (0..control_abi::DOMAIN_LIMIT)
        .find(|slot| X86_RUNTIME.CONTAINER_START_PENDING[*slot].swap(false, Ordering::AcqRel))
    {
        X86_RUNTIME
            .CONTAINER_SELECTED_SLOT
            .store(slot as u8, Ordering::Release);
        if container_image_is_embedded(slot) || crate::published_rootfs::is_installed(slot) {
            X86_RUNTIME
                .CONTAINER_RESTART_REQUESTED
                .store(true, Ordering::Release);
        } else {
            X86_RUNTIME
                .CONTAINER_PULL_REQUESTED
                .store(true, Ordering::Release);
        }
        return true;
    }
    // Otherwise resume the suspended background domains in turn.
    let start = usize::from(
        X86_RUNTIME
            .CONTAINER_LAST_RESUMED_SLOT
            .load(Ordering::Acquire),
    ) + 1;
    let Some(slot) = (start..start + control_abi::DOMAIN_LIMIT)
        .map(|slot| slot % control_abi::DOMAIN_LIMIT)
        .find(|slot| background_container_resumable(*slot))
    else {
        return false;
    };
    X86_RUNTIME
        .CONTAINER_LAST_RESUMED_SLOT
        .store(slot as u8, Ordering::Release);
    X86_RUNTIME
        .CONTAINER_SELECTED_SLOT
        .store(slot as u8, Ordering::Release);
    X86_RUNTIME
        .CONTAINER_RESTART_REQUESTED
        .store(true, Ordering::Release);
    true
}

fn background_container_resumable(slot: usize) -> bool {
    matches!(
        container_state(slot),
        control_abi::DOMAIN_STATE_BOOTING | control_abi::DOMAIN_STATE_RUNNING
    ) && X86_RUNTIME.CONTAINER_BACKGROUND_SUSPENDED[slot].load(Ordering::Acquire)
        && address_space::linux_runtime_is_suspended(slot)
}

/// Whether a domain other than `running` has background work waiting: a
/// queued start or a suspended domain to resume.
pub(super) fn other_background_work_waiting(running: usize) -> bool {
    X86_RUNTIME
        .CONTAINER_START_PENDING
        .iter()
        .any(|pending| pending.load(Ordering::Acquire))
        || (0..control_abi::DOMAIN_LIMIT)
            .any(|slot| slot != running && background_container_resumable(slot))
}

fn next_container_cursor(cursor: usize) -> u64 {
    next_container_slot(cursor)
        .map(|slot| slot as u64)
        .unwrap_or(control_abi::DOMAIN_CURSOR_END)
}

fn selected_container_slot() -> Option<usize> {
    let slot = usize::from(X86_RUNTIME.CONTAINER_SELECTED_SLOT.load(Ordering::SeqCst));
    (slot < control_abi::DOMAIN_LIMIT).then_some(slot)
}

pub(super) fn active_container_slot() -> Option<usize> {
    let slot = usize::from(X86_RUNTIME.CONTAINER_ACTIVE_SLOT.load(Ordering::SeqCst));
    (slot < control_abi::DOMAIN_LIMIT).then_some(slot)
}

fn selected_or_active_container_slot() -> Option<usize> {
    selected_container_slot().or_else(active_container_slot)
}

pub(super) fn container_state(slot: usize) -> u64 {
    u64::from(X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].load(Ordering::SeqCst))
}

fn container_image_is_embedded(slot: usize) -> bool {
    let size = usize::from(X86_RUNTIME.CONTAINER_IMAGE_SIZES[slot].load(Ordering::SeqCst));
    let embedded = b"embedded://minimal-system-v0";
    size == embedded.len()
        && X86_RUNTIME.CONTAINER_IMAGES[slot][..size]
            .iter()
            .zip(embedded)
            .all(|(stored, expected)| stored.load(Ordering::SeqCst) == *expected)
}

pub(crate) fn configured_domain_uses_published_rootfs() -> bool {
    let Some(slot) = selected_container_slot() else {
        return false;
    };
    !container_image_is_embedded(slot) && crate::published_rootfs::is_installed(slot)
}

pub(crate) fn domain_uses_published_rootfs(slot: usize) -> bool {
    slot < control_abi::DOMAIN_LIMIT
        && !container_image_is_embedded(slot)
        && crate::published_rootfs::is_installed(slot)
}

pub(crate) fn configured_container_slot() -> Option<usize> {
    selected_container_slot()
}

pub(crate) fn current_container_slot() -> Option<usize> {
    active_container_slot()
}

pub(crate) fn container_domain_id(slot: usize) -> Option<u64> {
    crate::linux_profile::span(crate::linux_profile::Span::ContainerDomainId, || {
        container_domain_id_checked(slot)
    })
}

fn container_domain_id_checked(slot: usize) -> Option<u64> {
    let domain = X86_RUNTIME
        .CONTAINER_DOMAIN_IDS
        .get(slot)?
        .load(Ordering::Acquire);
    (domain != 0
        && domain::container_domain_for_slot(slot) == Some(domain)
        && domain::container_domain_limits(domain).is_some())
    .then_some(domain)
}

pub(crate) fn configured_container_init(output: &mut [u8]) -> Option<usize> {
    let slot = selected_container_slot()?;
    let size = usize::from(X86_RUNTIME.CONTAINER_INIT_SIZES[slot].load(Ordering::SeqCst));
    let output = output.get_mut(..size)?;
    for (destination, source) in output
        .iter_mut()
        .zip(&X86_RUNTIME.CONTAINER_INITS[slot][..size])
    {
        *destination = source.load(Ordering::SeqCst);
    }
    Some(size)
}

pub(crate) fn configured_container_image(output: &mut [u8]) -> Option<usize> {
    let slot = selected_container_slot()?;
    let size = usize::from(X86_RUNTIME.CONTAINER_IMAGE_SIZES[slot].load(Ordering::SeqCst));
    let output = output.get_mut(..size)?;
    for (destination, source) in output
        .iter_mut()
        .zip(&X86_RUNTIME.CONTAINER_IMAGES[slot][..size])
    {
        *destination = source.load(Ordering::SeqCst);
    }
    Some(size)
}

pub(crate) fn container_image_matches(slot: usize, image: &[u8]) -> bool {
    let Some(size) = X86_RUNTIME.CONTAINER_IMAGE_SIZES.get(slot) else {
        return false;
    };
    let size = usize::from(size.load(Ordering::Acquire));
    size == image.len()
        && X86_RUNTIME.CONTAINER_IMAGES[slot][..size]
            .iter()
            .zip(image)
            .all(|(stored, expected)| stored.load(Ordering::Acquire) == *expected)
}

pub(crate) fn take_container_pull_request() -> bool {
    X86_RUNTIME
        .CONTAINER_PULL_REQUESTED
        .swap(false, Ordering::AcqRel)
}

pub(crate) fn request_container_install() {
    X86_RUNTIME
        .CONTAINER_INSTALL_REQUESTED
        .store(true, Ordering::Release);
}

pub(crate) fn take_container_install_request() -> bool {
    X86_RUNTIME
        .CONTAINER_INSTALL_REQUESTED
        .swap(false, Ordering::AcqRel)
}

pub(crate) fn configured_container_console_attached() -> bool {
    selected_container_slot()
        .is_some_and(|slot| X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire))
}

pub(crate) fn detached_container_lifecycle_pending() -> bool {
    selected_container_slot().is_some_and(|slot| {
        !X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire)
            && (X86_RUNTIME.CONTAINER_PULL_REQUESTED.load(Ordering::Acquire)
                || X86_RUNTIME
                    .CONTAINER_INSTALL_REQUESTED
                    .load(Ordering::Acquire)
                || X86_RUNTIME
                    .CONTAINER_RESTART_REQUESTED
                    .load(Ordering::Acquire))
    })
}

pub(crate) fn complete_container_pull(success: bool) {
    let Some(slot) = selected_container_slot() else {
        return;
    };
    if success {
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
            .store(control_abi::DOMAIN_STATE_BOOTING as u8, Ordering::Release);
        X86_RUNTIME
            .CONTAINER_RESTART_REQUESTED
            .store(true, Ordering::Release);
    } else {
        X86_RUNTIME.CONTAINER_CONTROL_STATES[slot]
            .store(control_abi::DOMAIN_STATE_FAILED as u8, Ordering::Release);
        X86_RUNTIME
            .CONTAINER_SELECTED_SLOT
            .store(CONTAINER_SLOT_NONE, Ordering::Release);
    }
}

fn store_container_name(slot: usize, name: &[u8]) {
    for (index, byte) in X86_RUNTIME.CONTAINER_NAMES[slot].iter().enumerate() {
        byte.store(name.get(index).copied().unwrap_or(0), Ordering::SeqCst);
    }
    X86_RUNTIME.CONTAINER_NAME_SIZES[slot].store(name.len() as u8, Ordering::SeqCst);
}

fn store_container_value<const N: usize>(value: &[u8], output: &[AtomicU8; N], size: &AtomicU8) {
    for (index, byte) in output.iter().enumerate() {
        byte.store(value.get(index).copied().unwrap_or(0), Ordering::SeqCst);
    }
    size.store(value.len() as u8, Ordering::SeqCst);
}

fn configurable_container(slot: Option<usize>) -> bool {
    slot.is_some_and(|slot| {
        matches!(
            container_state(slot),
            control_abi::DOMAIN_STATE_CREATED
                | control_abi::DOMAIN_STATE_CONFIGURED
                | control_abi::DOMAIN_STATE_STOPPED
                | control_abi::DOMAIN_STATE_FAILED
        )
    })
}

fn update_container_configuration(slot: usize, flag: u16) -> u64 {
    let flags = X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot].fetch_or(flag, Ordering::SeqCst) | flag;
    let state =
        if flags & control_abi::DOMAIN_CONFIG_COMPLETE == control_abi::DOMAIN_CONFIG_COMPLETE {
            control_abi::DOMAIN_STATE_CONFIGURED
        } else {
            control_abi::DOMAIN_STATE_CREATED
        };
    X86_RUNTIME.CONTAINER_CONTROL_STATES[slot].store(state as u8, Ordering::SeqCst);
    state
}

/// Turns a yes-or-no domain setting (autostart, user switching) on or off.
fn update_container_flag(slot: usize, flag: u16, enabled: bool) -> u64 {
    if enabled {
        X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot].fetch_or(flag, Ordering::SeqCst);
    } else {
        X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot].fetch_and(!flag, Ordering::SeqCst);
    }
    update_container_configuration(slot, 0)
}

/// The domain in `slot` was configured with `privileged=true`; read only
/// by `linux_user::domain_privileged`.
pub(crate) fn container_privileged(slot: usize) -> bool {
    X86_RUNTIME
        .CONTAINER_CONFIG_FLAGS
        .get(slot)
        .is_some_and(|flags| {
            flags.load(Ordering::Acquire) & control_abi::DOMAIN_CONFIG_PRIVILEGED != 0
        })
}

/// The domain in `slot` was configured with `user-switching=true`; read
/// only by `linux_user::user_switching_allowed`.
pub(crate) fn container_user_switching(slot: usize) -> bool {
    X86_RUNTIME
        .CONTAINER_CONFIG_FLAGS
        .get(slot)
        .is_some_and(|flags| {
            flags.load(Ordering::Acquire) & control_abi::DOMAIN_CONFIG_USER_SWITCHING != 0
        })
}

fn write_container_request(
    request: &mut [u8; control_abi::DOMAIN_REQUEST_SIZE],
    slot: usize,
    next_cursor: u64,
) {
    request.fill(0);
    request[0..4].copy_from_slice(&(control_abi::DOMAIN_REQUEST_SIZE as u32).to_le_bytes());
    let size = usize::from(X86_RUNTIME.CONTAINER_NAME_SIZES[slot].load(Ordering::SeqCst));
    request[6..8].copy_from_slice(&(size as u16).to_le_bytes());
    for (output, stored) in request[8..8 + size]
        .iter_mut()
        .zip(&X86_RUNTIME.CONTAINER_NAMES[slot][..size])
    {
        *output = stored.load(Ordering::SeqCst);
    }
    request[4..6].copy_from_slice(&control_abi::DOMAIN_REQUEST_VERSION.to_le_bytes());
    let mut runtime_flags = 0;
    if X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire) {
        runtime_flags |= control_abi::DOMAIN_RUNTIME_CONSOLE_ATTACHED;
    }
    if crate::published_rootfs::is_installed(slot) {
        runtime_flags |= control_abi::DOMAIN_RUNTIME_ROOTFS_READY;
    }
    if address_space::linux_runtime_is_suspended(slot) {
        runtime_flags |= control_abi::DOMAIN_RUNTIME_SUSPENDED;
    }
    request[210] = runtime_flags;
    request[24..32].copy_from_slice(&next_cursor.to_le_bytes());
    let init_size = usize::from(X86_RUNTIME.CONTAINER_INIT_SIZES[slot].load(Ordering::SeqCst));
    request[32..34].copy_from_slice(&(init_size as u16).to_le_bytes());
    request[34..36].copy_from_slice(
        &X86_RUNTIME.CONTAINER_CONFIG_FLAGS[slot]
            .load(Ordering::SeqCst)
            .to_le_bytes(),
    );
    for (output, stored) in request[36..36 + init_size]
        .iter_mut()
        .zip(&X86_RUNTIME.CONTAINER_INITS[slot][..init_size])
    {
        *output = stored.load(Ordering::SeqCst);
    }
    let image_size = usize::from(X86_RUNTIME.CONTAINER_IMAGE_SIZES[slot].load(Ordering::SeqCst));
    request[68..70].copy_from_slice(&(image_size as u16).to_le_bytes());
    request[70..72].copy_from_slice(
        &X86_RUNTIME.CONTAINER_CPU_COUNTS[slot]
            .load(Ordering::Acquire)
            .to_le_bytes(),
    );
    for (output, stored) in request[72..72 + image_size]
        .iter_mut()
        .zip(&X86_RUNTIME.CONTAINER_IMAGES[slot][..image_size])
    {
        *output = stored.load(Ordering::SeqCst);
    }
    request[200..208].copy_from_slice(
        &X86_RUNTIME.CONTAINER_MEMORY_MIB[slot]
            .load(Ordering::Acquire)
            .to_le_bytes(),
    );
    let personality_size =
        usize::from(X86_RUNTIME.DOMAIN_PERSONALITY_SIZES[slot].load(Ordering::SeqCst));
    request[208..210].copy_from_slice(&(personality_size as u16).to_le_bytes());
    for (output, stored) in request[216..216 + personality_size]
        .iter_mut()
        .zip(&X86_RUNTIME.DOMAIN_PERSONALITIES[slot][..personality_size])
    {
        *output = stored.load(Ordering::SeqCst);
    }
}

pub(super) enum ServiceRestartSetup {
    Started,
    Unavailable,
    RollbackFailed,
}

pub(super) fn setup_service_restart(fault_domain: u64) -> ServiceRestartSetup {
    let Some(replacement_domain) = domain::initialize_boot_service_restart() else {
        return ServiceRestartSetup::Unavailable;
    };
    let Some(replacement_handle) = domain::service_boot_handle() else {
        return if domain::discard_unstarted_service(replacement_domain) {
            ServiceRestartSetup::Unavailable
        } else {
            ServiceRestartSetup::RollbackFailed
        };
    };
    if !ipc::bind_service(replacement_domain) {
        return if domain::discard_unstarted_service(replacement_domain) {
            ServiceRestartSetup::Unavailable
        } else {
            ServiceRestartSetup::RollbackFailed
        };
    }
    let (Some(old_owner), Some(replacement_owner)) = (
        memory::FrameOwner::domain(fault_domain),
        memory::FrameOwner::domain(replacement_domain),
    ) else {
        return rollback_unstarted_replacement(replacement_domain, true);
    };
    if memory::transfer_frame_owner(old_owner, replacement_owner)
        != Some(address_space::USER_ADDRESS_SPACE_FRAMES)
    {
        return rollback_unstarted_replacement(replacement_domain, true);
    }
    if !domain::adopt_quarantined_service_frames(fault_domain, replacement_domain) {
        let _ = memory::transfer_frame_owner(replacement_owner, old_owner);
        return rollback_unstarted_replacement(replacement_domain, true);
    }
    if !scheduler::queue_service_restart(replacement_domain, replacement_handle) {
        return rollback_transferred_replacement(
            replacement_domain,
            fault_domain,
            old_owner,
            replacement_owner,
            false,
        );
    }
    if !timer::rearm_scheduler_preemption() {
        return rollback_transferred_replacement(
            replacement_domain,
            fault_domain,
            old_owner,
            replacement_owner,
            true,
        );
    }
    SERVICE_FRAMES_TRANSFERRED.store(true, Ordering::Release);
    ServiceRestartSetup::Started
}

fn rollback_unstarted_replacement(replacement_domain: u64, bound: bool) -> ServiceRestartSetup {
    if (!bound || ipc::rollback_service_binding(replacement_domain))
        && domain::discard_unstarted_service(replacement_domain)
    {
        ServiceRestartSetup::Unavailable
    } else {
        ServiceRestartSetup::RollbackFailed
    }
}

fn rollback_transferred_replacement(
    replacement_domain: u64,
    fault_domain: u64,
    old_owner: memory::FrameOwner,
    replacement_owner: memory::FrameOwner,
    queued: bool,
) -> ServiceRestartSetup {
    if (!queued || scheduler::rollback_service_restart(replacement_domain, fault_domain))
        && memory::transfer_frame_owner(replacement_owner, old_owner)
            == Some(address_space::USER_ADDRESS_SPACE_FRAMES)
        && domain::restore_quarantined_service_frames(fault_domain, replacement_domain)
        && ipc::rollback_service_binding(replacement_domain)
        && domain::discard_unstarted_service(replacement_domain)
    {
        ServiceRestartSetup::Unavailable
    } else {
        ServiceRestartSetup::RollbackFailed
    }
}

pub(super) fn scrub_service_restart_stack() -> bool {
    const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
    let Some((root, stack_top)) = scheduler::service_restart_stack_mapping() else {
        return false;
    };
    let active_root = crate::trusted::root::current();
    let Some(stack_base) = stack_top.checked_sub(PAGE_SIZE as u64) else {
        return false;
    };
    if active_root & ADDRESS_MASK != root || stack_top % PAGE_SIZE as u64 != 0 || stack_base == 0 {
        return false;
    }
    let zeroes = [0_u8; 128];
    let mut observed = [0xff_u8; 128];
    let mut scrubbed = true;
    for offset in (0..PAGE_SIZE).step_by(zeroes.len()) {
        let address = stack_base + offset as u64;
        scrubbed &= crate::trusted::user_copy::copy_to_user(address, &zeroes) == zeroes.len()
            && crate::trusted::user_copy::copy_from_user(address, &mut observed) == observed.len()
            && observed == zeroes;
        if !scrubbed {
            break;
        }
    }
    if !scrubbed {
        return false;
    }
    SERVICE_STACK_SCRUBBED.store(true, Ordering::Release);
    true
}

pub(crate) fn service_restart_stack_was_scrubbed() -> bool {
    SERVICE_STACK_SCRUBBED.load(Ordering::Acquire)
}

pub(crate) fn service_address_space_frames_were_transferred() -> bool {
    SERVICE_FRAMES_TRANSFERRED.load(Ordering::Acquire)
}
