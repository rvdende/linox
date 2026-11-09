use super::*;

pub(crate) fn force_next_control_discovery(domain_id: u64, discovery_word: u64) -> bool {
    if domain_id == 0
        || CONTROL_DISCOVERY_OVERRIDE_DOMAIN
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return false;
    }
    CONTROL_DISCOVERY_OVERRIDE_WORD.store(discovery_word, Ordering::Release);
    CONTROL_DISCOVERY_OVERRIDE_DOMAIN.store(domain_id, Ordering::Release);
    true
}

pub(crate) fn force_next_control_descriptor_reserved(domain_id: u64) -> bool {
    domain_id != 0
        && CONTROL_DESCRIPTOR_OVERRIDE_DOMAIN
            .compare_exchange(0, domain_id, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}

pub(super) fn dispatch_charged_call(
    number: u64,
    capability: u64,
    caller_domain: u64,
    frame: *mut UserTrapFrame,
) -> u64 {
    match number {
        0 => {
            if CONTROL_DISCOVERY_OVERRIDE_DOMAIN
                .compare_exchange(caller_domain, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                CONTROL_DISCOVERY_OVERRIDE_WORD.load(Ordering::Acquire)
            } else {
                control_abi::DISCOVERY_WORD
            }
        }
        1 => {
            if domain::handle_permits(caller_domain, capability, 1, Rights::READ) {
                SYSCALL_STATE.fetch_or(2, Ordering::SeqCst);
                0x4758
            } else {
                SYSCALL_STATE.fetch_or(1, Ordering::SeqCst);
                u64::MAX - 1
            }
        }
        3 => runtime_result(frame),
        4 => {
            let Some(frame) = (unsafe { frame.as_ref() }) else {
                return u64::MAX;
            };
            let message = frame.first_argument();
            if domain::handle_permits(caller_domain, capability, 3, Rights::WRITE)
                && ipc::send_or_wake(caller_domain, message, |service_side, sequence| {
                    scheduler::wake_ipc_peer(caller_domain, 3, service_side, message, sequence)
                })
            {
                timer::mark_scheduler_preemption_ready();
                0
            } else {
                u64::MAX - 2
            }
        }
        5 => {
            if domain::handle_permits(caller_domain, capability, 3, Rights::READ) {
                match ipc::receive(caller_domain) {
                    ipc::Receive::Message(message) => message,
                    ipc::Receive::PeerClosed(_) => scheduler::IPC_PEER_CLOSED,
                    ipc::Receive::Empty => u64::MAX - 2,
                }
            } else {
                u64::MAX - 2
            }
        }
        6 => console_write(caller_domain, capability, frame),
        7 => {
            if domain::handle_permits(caller_domain, capability, 1, Rights::MANAGE) {
                domain::take_lifecycle_event().unwrap_or(u64::MAX - 2)
            } else {
                u64::MAX - 2
            }
        }
        8 => blocking_receive(caller_domain, capability, frame),
        9 => console_write_buffer(caller_domain, capability, frame),
        10 => write_abi_descriptor(caller_domain, frame),
        11 => write_fault_descriptor(caller_domain, capability, frame),
        12 => write_lifecycle_descriptor(caller_domain, capability, frame),
        13 => write_ipc_delivery_descriptor(caller_domain, capability, frame),
        14 => write_lifecycle_identity_descriptor(caller_domain, capability, frame),
        15 => create_auxiliary_service(caller_domain, capability, frame),
        16 => network_device_call(caller_domain, capability, frame),
        17 => root_device_call(caller_domain, capability, frame),
        18 => volume_device_call(caller_domain, capability, frame),
        19 => block_device_call(caller_domain, capability, frame),
        20 => network_wait_call(caller_domain, capability, frame),
        control_abi::CONSOLE_READ_LINE_OPERATION => {
            console_read_line(caller_domain, capability, frame)
        }
        linox_native_abi::NATIVE_CONSOLE_READ_BYTE_OPERATION => {
            console_read_byte(caller_domain, capability, frame)
        }
        control_abi::HOST_INSPECT_OPERATION => host_inspect(caller_domain, capability, frame),
        control_abi::DOMAIN_CONTROL_OPERATION => {
            container_control(caller_domain, capability, frame)
        }
        control_abi::LINUX_ABI_TEST_OPERATION => {
            linux_abi_test_results(caller_domain, capability, frame)
        }
        linox_native_abi::NATIVE_IMAGE_STORE_OPERATION => {
            image_store_call(caller_domain, capability, frame)
        }
        linox_native_abi::NATIVE_PROGRESS_OPERATION => {
            native_progress_call(caller_domain, capability, frame)
        }
        linox_native_abi::NATIVE_NETWORK_INVENTORY_OPERATION => {
            network_inventory_call(caller_domain, capability, frame)
        }
        // The frequency is the one the Linux clock profile already trusts; it
        // grants no authority, so no capability is required.
        linox_native_abi::NATIVE_TIMESTAMP_FREQUENCY_OPERATION => timer::monotonic_frequency()
            .unwrap_or(linox_native_abi::NATIVE_TIMESTAMP_FREQUENCY_UNAVAILABLE),
        control_abi::PACKET_PUBLISH_OPERATION => {
            packet_publish_call(caller_domain, capability, frame)
        }
        control_abi::PACKET_CONSUME_OPERATION => {
            packet_consume_call(caller_domain, capability, frame)
        }
        control_abi::PACKET_WAIT_OPERATION => {
            packet_wait_call(caller_domain, capability, frame, None)
        }
        control_abi::PACKET_WAIT_TIMEOUT_OPERATION => {
            let timeout_ms = unsafe { frame.as_ref() }.map(UserTrapFrame::second_argument);
            packet_wait_call(caller_domain, capability, frame, timeout_ms)
        }
        control_abi::PACKET_SPACE_WAIT_OPERATION => {
            packet_space_wait_call(caller_domain, capability, frame)
        }
        control_abi::PACKET_EGRESS_CLAIM_OPERATION => {
            packet_egress_claim_call(caller_domain, capability, frame)
        }
        control_abi::PACKET_EGRESS_ACK_OPERATION => {
            packet_egress_ack_call(caller_domain, capability, frame)
        }
        control_abi::PACKET_EGRESS_WAIT_OPERATION => packet_wait_call_for_object(
            caller_domain,
            capability,
            frame,
            None,
            control_abi::PACKET_EGRESS_OBJECT,
        ),
        control_abi::PACKET_EGRESS_SPACE_WAIT_OPERATION => packet_space_wait_call_for_object(
            caller_domain,
            capability,
            frame,
            control_abi::PACKET_EGRESS_OBJECT,
        ),
        control_abi::PACKET_EGRESS_DRAIN_WAIT_OPERATION => {
            packet_egress_drain_wait_call(caller_domain, capability, frame)
        }
        _ => u64::MAX,
    }
}

fn native_progress_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    if !domain::handle_permits(
        caller_domain,
        capability,
        linox_native_abi::NATIVE_IMAGE_STORE_OBJECT,
        Rights::WRITE,
    ) {
        return u64::MAX - 2;
    }
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let Ok(size) = usize::try_from(frame.second_argument()) else {
        return u64::MAX - 2;
    };
    if size == 0 || size > linox_native_abi::NATIVE_PROGRESS_MAX_SIZE {
        return u64::MAX - 2;
    }
    let mut bytes = [0; linox_native_abi::NATIVE_PROGRESS_MAX_SIZE];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut bytes[..size])
        || !bytes[..size]
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        return u64::MAX - 2;
    }
    if oci_progress_is_console_visible(&bytes[..size]) {
        serial_write("linox: OCI ");
        crate::serial_write_bytes(&bytes[..size]);
        serial_write("\r\n");
    }
    if domain::renew_auxiliary_call_epoch(caller_domain) {
        size as u64
    } else {
        u64::MAX - 2
    }
}

fn oci_progress_is_console_visible(message: &[u8]) -> bool {
    message == b"authenticating with registry"
        || message == b"pulling image manifest"
        || message == b"pulling image configuration"
        || message == b"image configuration verified"
        || message.starts_with(b"manifest selected for ")
        || message.starts_with(b"layer ")
        || contains_bytes(message, b"failed")
        || contains_bytes(message, b"rejected")
        || contains_bytes(message, b"unavailable")
        || contains_bytes(message, b"exceeded")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn image_store_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let failed = linox_native_abi::NATIVE_IMAGE_STORE_RESULT_FAILED;
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return failed;
    };
    if !domain::handle_permits(
        caller_domain,
        capability,
        linox_native_abi::NATIVE_IMAGE_STORE_OBJECT,
        Rights::WRITE,
    ) {
        return failed;
    }
    let mut request = [0_u8; linox_native_abi::NATIVE_IMAGE_STORE_REQUEST_SIZE as usize];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut request)
        || u32::from_le_bytes(request[0..4].try_into().unwrap())
            != linox_native_abi::NATIVE_IMAGE_STORE_REQUEST_SIZE
        || u16::from_le_bytes(request[4..6].try_into().unwrap())
            != linox_native_abi::NATIVE_IMAGE_STORE_REQUEST_VERSION
        || request[36..40] != [0; 4]
    {
        return failed;
    }
    let command = u16::from_le_bytes(request[6..8].try_into().unwrap());
    let raw_handle = u64::from_le_bytes(request[8..16].try_into().unwrap());
    let expected_length = u64::from_le_bytes(request[16..24].try_into().unwrap());
    let buffer_address = u64::from_le_bytes(request[24..32].try_into().unwrap());
    let buffer_size = u32::from_le_bytes(request[32..36].try_into().unwrap());
    let digest: [u8; 32] = request[40..72].try_into().unwrap();
    let result = match command {
        linox_native_abi::NATIVE_IMAGE_STORE_STAGE
            if raw_handle == 0
                && buffer_address == 0
                && buffer_size == 0
                && expected_length != 0
                && digest != [0; 32] =>
        {
            let Ok(expected_length) = usize::try_from(expected_length) else {
                return failed;
            };
            image_store::stage(digest, expected_length)
                .map(linox_image_store::StagingHandle::into_raw)
                .unwrap_or(failed)
        }
        linox_native_abi::NATIVE_IMAGE_STORE_APPEND
            if expected_length == 0
                && digest == [0; 32]
                && (1..=linox_native_abi::NATIVE_IMAGE_STORE_CHUNK_LIMIT)
                    .contains(&buffer_size) =>
        {
            let Some(handle) = linox_image_store::StagingHandle::from_raw(raw_handle) else {
                return failed;
            };
            let mut bytes = [0_u8; linox_native_abi::NATIVE_IMAGE_STORE_CHUNK_LIMIT as usize];
            let size = buffer_size as usize;
            if !address_space::copy_from_current_user(buffer_address, &mut bytes[..size]) {
                return failed;
            }
            image_store::append(handle, &bytes[..size])
                .map(|written| written as u64)
                .unwrap_or(failed)
        }
        linox_native_abi::NATIVE_IMAGE_STORE_PUBLISH
            if expected_length == 0
                && buffer_address == 0
                && buffer_size == 0
                && digest == [0; 32] =>
        {
            let Some(handle) = linox_image_store::StagingHandle::from_raw(raw_handle) else {
                return failed;
            };
            image_store::publish(handle).map_or(failed, |_| 0)
        }
        linox_native_abi::NATIVE_IMAGE_STORE_ABORT
            if expected_length == 0
                && buffer_address == 0
                && buffer_size == 0
                && digest == [0; 32] =>
        {
            let Some(handle) = linox_image_store::StagingHandle::from_raw(raw_handle) else {
                return failed;
            };
            image_store::abort(handle).map_or(failed, |()| 0)
        }
        _ => failed,
    };
    if result != failed && !domain::renew_auxiliary_call_epoch(caller_domain) {
        failed
    } else {
        result
    }
}

struct PacketRequest {
    buffer_address: u64,
    buffer_size: usize,
    expected_sequence: u64,
}

fn packet_request(address: u64) -> Option<PacketRequest> {
    let mut bytes = [0_u8; control_abi::PACKET_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut bytes)
        || u32::from_le_bytes(bytes[0..4].try_into().ok()?) as usize
            != control_abi::PACKET_REQUEST_SIZE
        || u16::from_le_bytes(bytes[4..6].try_into().ok()?) != control_abi::PACKET_REQUEST_VERSION
        || bytes[6..8] != [0, 0]
        || bytes[20..24] != [0, 0, 0, 0]
    {
        return None;
    }
    Some(PacketRequest {
        buffer_address: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
        buffer_size: usize::try_from(u32::from_le_bytes(bytes[16..20].try_into().ok()?)).ok()?,
        expected_sequence: u64::from_le_bytes(bytes[24..32].try_into().ok()?),
    })
}

fn packet_publish_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let Some(request) = packet_request(frame.first_argument()) else {
        return u64::MAX - 2;
    };
    let ingress = domain::handle_permits(
        caller_domain,
        capability,
        control_abi::PACKET_OBJECT,
        Rights::WRITE,
    );
    let egress = domain::handle_permits(
        caller_domain,
        capability,
        control_abi::PACKET_EGRESS_OBJECT,
        Rights::WRITE,
    );
    if request.expected_sequence != 0
        || !(1..=control_abi::PACKET_MAX_SIZE).contains(&request.buffer_size)
        || ingress == egress
    {
        return u64::MAX - 2;
    }
    let mut packet = [0_u8; control_abi::PACKET_MAX_SIZE];
    if !address_space::copy_from_current_user(
        request.buffer_address,
        &mut packet[..request.buffer_size],
    ) {
        return u64::MAX - 2;
    }
    let result = if egress {
        crate::packet::publish_egress(caller_domain, &packet[..request.buffer_size])
    } else {
        crate::packet::publish(caller_domain, &packet[..request.buffer_size])
    };
    match result {
        Ok(sequence) => {
            if ingress {
                if scheduler::wake_packet_waiter(caller_domain, sequence) {
                    let _ = timer::cancel_packet_wait_timer_for_sequence(sequence);
                }
            } else {
                let _ = scheduler::wake_egress_waiter(caller_domain, sequence);
            }
            timer::mark_scheduler_preemption_ready();
            sequence
        }
        Err(_) => u64::MAX - 2,
    }
}

fn packet_consume_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let Some(request) = packet_request(frame.first_argument()) else {
        return u64::MAX - 2;
    };
    let ingress = domain::handle_permits(
        caller_domain,
        capability,
        control_abi::PACKET_OBJECT,
        Rights::READ,
    );
    let egress = domain::handle_permits(
        caller_domain,
        capability,
        control_abi::PACKET_EGRESS_OBJECT,
        Rights::READ,
    );
    if request.expected_sequence == 0
        || !(1..=control_abi::PACKET_MAX_SIZE).contains(&request.buffer_size)
        || ingress == egress
    {
        return u64::MAX - 2;
    }
    let result = if egress {
        crate::packet::consume_egress_with(
            request.expected_sequence,
            request.buffer_size,
            |_, packet| address_space::copy_to_current_user(request.buffer_address, packet),
        )
    } else {
        crate::packet::consume_with(
            request.expected_sequence,
            request.buffer_size,
            |_, packet| address_space::copy_to_current_user(request.buffer_address, packet),
        )
    };
    match result {
        Ok(metadata) => {
            let woke = if ingress {
                scheduler::wake_packet_space_waiter(caller_domain)
            } else {
                scheduler::wake_egress_space_waiter(caller_domain)
            };
            if woke {
                timer::mark_scheduler_preemption_ready();
            }
            metadata.length as u64
        }
        Err(crate::packet::PacketError::Stale) => control_abi::PACKET_RESULT_STALE,
        Err(_) => u64::MAX - 2,
    }
}

fn packet_egress_claim_call(
    caller_domain: u64,
    capability: u64,
    frame: *const UserTrapFrame,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let Some(request) = packet_request(frame.first_argument()) else {
        return u64::MAX - 2;
    };
    if request.expected_sequence == 0
        || !(1..=control_abi::PACKET_MAX_SIZE).contains(&request.buffer_size)
        || !domain::handle_permits(
            caller_domain,
            capability,
            control_abi::PACKET_EGRESS_OBJECT,
            Rights::READ,
        )
    {
        return u64::MAX - 2;
    }
    match crate::packet::claim_egress_with(
        caller_domain,
        request.expected_sequence,
        request.buffer_size,
        |_, packet| address_space::copy_to_current_user(request.buffer_address, packet),
    ) {
        Ok(metadata) => metadata.length as u64,
        Err(crate::packet::PacketError::Stale) => control_abi::PACKET_RESULT_STALE,
        Err(_) => u64::MAX - 2,
    }
}

fn packet_egress_ack_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let Some(request) = packet_request(frame.first_argument()) else {
        return u64::MAX - 2;
    };
    if request.buffer_address != 0
        || request.buffer_size != 0
        || request.expected_sequence == 0
        || !domain::handle_permits(
            caller_domain,
            capability,
            control_abi::PACKET_EGRESS_OBJECT,
            Rights::READ,
        )
        || !address_space::auxiliary_network_egress_transmit_complete(caller_domain)
    {
        return u64::MAX - 2;
    }
    match crate::packet::acknowledge_egress(caller_domain, request.expected_sequence) {
        Ok(_) => {
            if !address_space::record_auxiliary_network_egress_ack(caller_domain) {
                return u64::MAX - 2;
            }
            if scheduler::wake_egress_space_waiter(caller_domain) {
                timer::mark_scheduler_preemption_ready();
            }
            if crate::packet::egress_is_empty()
                && scheduler::wake_egress_drain_waiter(caller_domain)
            {
                timer::mark_scheduler_preemption_ready();
            }
            0
        }
        Err(crate::packet::PacketError::Stale) => control_abi::PACKET_RESULT_STALE,
        Err(_) => u64::MAX - 2,
    }
}

fn packet_wait_call(
    caller_domain: u64,
    capability: u64,
    frame: *mut UserTrapFrame,
    timeout_ms: Option<u64>,
) -> u64 {
    packet_wait_call_for_object(
        caller_domain,
        capability,
        frame,
        timeout_ms,
        control_abi::PACKET_OBJECT,
    )
}

fn packet_wait_call_for_object(
    caller_domain: u64,
    capability: u64,
    frame: *mut UserTrapFrame,
    timeout_ms: Option<u64>,
    object: u64,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    let Some(request) = packet_request(frame.first_argument()) else {
        return u64::MAX - 2;
    };
    if request.buffer_address != 0
        || request.buffer_size != 0
        || timeout_ms.is_some_and(|timeout| timeout > control_abi::PACKET_WAIT_MAX_TIMEOUT_MS)
    {
        return u64::MAX - 2;
    }
    if request.expected_sequence == 0 {
        return u64::MAX - 2;
    }
    if !domain::handle_permits(caller_domain, capability, object, Rights::READ) {
        return u64::MAX - 2;
    }
    let state = if object == control_abi::PACKET_OBJECT {
        crate::packet::wait_state(request.expected_sequence)
    } else if object == control_abi::PACKET_EGRESS_OBJECT && timeout_ms.is_none() {
        crate::packet::egress_wait_state(request.expected_sequence)
    } else {
        return u64::MAX - 2;
    };
    match state {
        crate::packet::PacketWait::Ready => request.expected_sequence,
        crate::packet::PacketWait::Stale => control_abi::PACKET_RESULT_STALE,
        crate::packet::PacketWait::Empty => {
            if object == control_abi::PACKET_EGRESS_OBJECT
                && timeout_ms.is_none()
                && !crate::packet::egress_producer_is_bound()
                && domain::take_auxiliary_drain_request(caller_domain)
            {
                return control_abi::PACKET_RESULT_DRAINED;
            }
            if timeout_ms == Some(0) {
                return control_abi::PACKET_RESULT_TIMED_OUT;
            }
            let wait_available = if object == control_abi::PACKET_OBJECT {
                scheduler::packet_wait_is_available(request.expected_sequence)
            } else {
                scheduler::egress_wait_is_available(request.expected_sequence)
            };
            if !wait_available {
                return u64::MAX - 2;
            }
            if timeout_ms.is_some_and(|timeout| {
                !timer::arm_packet_wait_timer(caller_domain, request.expected_sequence, timeout)
            }) {
                return u64::MAX - 2;
            }
            let reason = scheduler::WaitReason::PacketAvailable {
                object,
                sequence: request.expected_sequence,
            };
            let action = scheduler::block_runtime(
                frame,
                USER_CODE_SELECTOR,
                USER_DATA_SELECTOR,
                reason,
                active_fs_base(),
            );
            if !matches!(action, RuntimeAction::Invalid) {
                return resume_action(action);
            }
            if timeout_ms.is_some()
                && scheduler::block_runtime_idle(
                    frame,
                    USER_CODE_SELECTOR,
                    USER_DATA_SELECTOR,
                    reason,
                    active_fs_base(),
                )
            {
                while !timer::packet_wait_timed_out(caller_domain, request.expected_sequence) {
                    linux_wait_for_interrupt();
                }
                return if timer::finish_packet_wait_timer(caller_domain, request.expected_sequence)
                    == Some(true)
                    && scheduler::current_domain() == Some(caller_domain)
                {
                    control_abi::PACKET_RESULT_TIMED_OUT
                } else {
                    u64::MAX - 2
                };
            }
            let _ = timer::cancel_packet_wait_timer_for_domain(caller_domain);
            u64::MAX - 2
        }
    }
}

fn packet_space_wait_call(caller_domain: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    packet_space_wait_call_for_object(caller_domain, capability, frame, control_abi::PACKET_OBJECT)
}

fn packet_space_wait_call_for_object(
    caller_domain: u64,
    capability: u64,
    frame: *mut UserTrapFrame,
    object: u64,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    if frame.first_argument() != 0
        || frame.second_argument() != 0
        || !domain::handle_permits(caller_domain, capability, object, Rights::WRITE)
    {
        return u64::MAX - 2;
    }
    let state = if object == control_abi::PACKET_OBJECT {
        crate::packet::space_state(caller_domain)
    } else if object == control_abi::PACKET_EGRESS_OBJECT {
        crate::packet::egress_space_state(caller_domain)
    } else {
        return u64::MAX - 2;
    };
    match state {
        crate::packet::PacketSpace::Ready => 0,
        crate::packet::PacketSpace::InvalidProducer
        | crate::packet::PacketSpace::SequenceExhausted => u64::MAX - 2,
        crate::packet::PacketSpace::Full => {
            let wait_available = if object == control_abi::PACKET_OBJECT {
                scheduler::packet_space_wait_is_available()
            } else {
                scheduler::egress_space_wait_is_available()
            };
            if !wait_available {
                return u64::MAX - 2;
            }
            let action = scheduler::block_runtime(
                frame,
                USER_CODE_SELECTOR,
                USER_DATA_SELECTOR,
                scheduler::WaitReason::PacketSpaceAvailable { object },
                active_fs_base(),
            );
            if matches!(action, RuntimeAction::Invalid) {
                u64::MAX - 2
            } else {
                resume_action(action)
            }
        }
    }
}

fn packet_egress_drain_wait_call(
    caller_domain: u64,
    capability: u64,
    frame: *mut UserTrapFrame,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    if frame.first_argument() != 0
        || frame.second_argument() != 0
        || !domain::handle_permits(
            caller_domain,
            capability,
            control_abi::PACKET_EGRESS_OBJECT,
            Rights::WRITE,
        )
    {
        return u64::MAX - 2;
    }
    if crate::packet::egress_is_empty() {
        return 0;
    }
    if !scheduler::egress_drain_wait_is_available() {
        return u64::MAX - 2;
    }
    let action = scheduler::block_runtime(
        frame,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        scheduler::WaitReason::PacketQueueDrained {
            object: control_abi::PACKET_EGRESS_OBJECT,
        },
        active_fs_base(),
    );
    if matches!(action, RuntimeAction::Invalid) {
        u64::MAX - 2
    } else {
        resume_action(action)
    }
}

fn network_wait_call(caller_domain: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    let command = frame.first_argument();
    let request = frame.second_argument();
    if !matches!(
        command,
        control_abi::NETWORK_DEVICE_WAIT_TX_NOTIFIED | control_abi::NETWORK_DEVICE_WAIT_RX_POSTED
    ) || request == 0
        || !domain::handle_permits(
            caller_domain,
            capability,
            control_abi::NETWORK_DEVICE_OBJECT,
            Rights::WRITE,
        )
        || !address_space::auxiliary_network_wait_ready(caller_domain, command, request)
    {
        return u64::MAX - 2;
    }
    let reason = scheduler::WaitReason::DeviceCompletion {
        object: control_abi::NETWORK_DEVICE_OBJECT,
        domain: caller_domain,
        request,
    };
    if !scheduler::block_runtime_idle(
        frame,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        reason,
        active_fs_base(),
    ) {
        return u64::MAX - 2;
    }
    match address_space::complete_auxiliary_network_wait(caller_domain, command, request) {
        address_space::AuxiliaryDeviceWaitCompletion::Completed => {
            if domain::renew_auxiliary_call_epoch(caller_domain) {
                0
            } else {
                u64::MAX - 2
            }
        }
        address_space::AuxiliaryDeviceWaitCompletion::Cancelled => {
            control_abi::NETWORK_DEVICE_RESULT_CANCELLED
        }
        address_space::AuxiliaryDeviceWaitCompletion::TimedOut
        | address_space::AuxiliaryDeviceWaitCompletion::Failed => {
            let _ = scheduler::wake_device_completion(
                caller_domain,
                control_abi::NETWORK_DEVICE_OBJECT,
                request,
                u64::MAX - 2,
            );
            u64::MAX - 2
        }
    }
}

fn block_device_call(caller_domain: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    let command = frame.first_argument();
    let request = frame.second_argument();
    let notified = match command {
        control_abi::BLOCK_DEVICE_WAIT => false,
        control_abi::BLOCK_DEVICE_WAIT_NOTIFIED => true,
        _ => return u64::MAX - 2,
    };
    if request == 0
        || !domain::handle_permits(
            caller_domain,
            capability,
            control_abi::BLOCK_DEVICE_OBJECT,
            Rights::WRITE,
        )
        || !address_space::auxiliary_device_wait_ready(caller_domain, request)
    {
        return u64::MAX - 2;
    }
    let reason = scheduler::WaitReason::DeviceCompletion {
        object: control_abi::BLOCK_DEVICE_OBJECT,
        domain: caller_domain,
        request,
    };
    if !scheduler::block_runtime_idle(
        frame,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        reason,
        active_fs_base(),
    ) {
        return u64::MAX - 2;
    }
    match address_space::complete_auxiliary_device_wait(caller_domain, request, notified) {
        address_space::AuxiliaryDeviceWaitCompletion::Completed => 0,
        address_space::AuxiliaryDeviceWaitCompletion::Cancelled => {
            control_abi::BLOCK_DEVICE_RESULT_CANCELLED
        }
        address_space::AuxiliaryDeviceWaitCompletion::TimedOut => u64::MAX - 2,
        address_space::AuxiliaryDeviceWaitCompletion::Failed => {
            let _ = scheduler::wake_device_completion(
                caller_domain,
                control_abi::BLOCK_DEVICE_OBJECT,
                request,
                u64::MAX - 2,
            );
            u64::MAX - 2
        }
    }
}

fn volume_device_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    let command = frame.first_argument();
    let argument = frame.second_argument();
    match command {
        control_abi::VOLUME_PROBE
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::VOLUME_OBJECT,
                    Rights::READ,
                ) =>
        {
            control_abi::VOLUME_DESCRIPTOR_WORD
        }
        control_abi::VOLUME_QUERY_GENERATION
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::VOLUME_OBJECT,
                    Rights::READ,
                ) =>
        {
            volume::live_generation().unwrap_or(u64::MAX - 2)
        }
        control_abi::VOLUME_READ
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::VOLUME_OBJECT,
                Rights::READ,
            ) =>
        {
            volume_read(argument)
        }
        control_abi::VOLUME_COMMIT
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::VOLUME_OBJECT,
                Rights::WRITE,
            ) =>
        {
            volume_commit(argument)
        }
        _ => u64::MAX - 2,
    }
}

fn volume_read(address: u64) -> u64 {
    let Some(request) = volume_request(address) else {
        return u64::MAX - 2;
    };
    let Ok(capacity) = usize::try_from(request.size) else {
        return u64::MAX - 2;
    };
    if !(1..=control_abi::VOLUME_MAX_TRANSFER_SIZE).contains(&capacity) {
        return u64::MAX - 2;
    }
    let mut output = [0_u8; control_abi::VOLUME_MAX_TRANSFER_SIZE];
    match volume::read_live(request.expected_generation, &mut output[..capacity]) {
        Ok(size)
            if address_space::copy_to_current_user(request.buffer_address, &output[..size]) =>
        {
            size as u64
        }
        Ok(_) => u64::MAX - 2,
        Err(volume::LiveError::Stale) => control_abi::VOLUME_RESULT_STALE_GENERATION,
        Err(_) => u64::MAX - 2,
    }
}

fn volume_commit(address: u64) -> u64 {
    let Some(request) = volume_request(address) else {
        return u64::MAX - 2;
    };
    let Ok(size) = usize::try_from(request.size) else {
        return u64::MAX - 2;
    };
    if !(1..=control_abi::VOLUME_MAX_TRANSFER_SIZE).contains(&size) {
        return u64::MAX - 2;
    }
    let mut payload = [0_u8; control_abi::VOLUME_MAX_TRANSFER_SIZE];
    if !address_space::copy_from_current_user(request.buffer_address, &mut payload[..size]) {
        return u64::MAX - 2;
    }
    match volume::commit_live(request.expected_generation, &payload[..size]) {
        Ok(generation) => generation,
        Err(volume::LiveError::Stale) => control_abi::VOLUME_RESULT_STALE_GENERATION,
        Err(_) => u64::MAX - 2,
    }
}

struct VolumeRequest {
    expected_generation: u64,
    buffer_address: u64,
    size: u64,
}

fn volume_request(address: u64) -> Option<VolumeRequest> {
    let mut request = [0_u8; control_abi::VOLUME_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || u32::from_le_bytes(request[0..4].try_into().ok()?) as usize
            != control_abi::VOLUME_REQUEST_SIZE
        || u16::from_le_bytes(request[4..6].try_into().ok()?) != control_abi::VERSION
        || request[6..8] != [0, 0]
    {
        return None;
    }
    Some(VolumeRequest {
        expected_generation: u64::from_le_bytes(request[8..16].try_into().ok()?),
        buffer_address: u64::from_le_bytes(request[16..24].try_into().ok()?),
        size: u64::from_le_bytes(request[24..32].try_into().ok()?),
    })
}

fn root_device_call(caller_domain: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(
        caller_domain,
        capability,
        control_abi::ROOT_OBJECT,
        Rights::READ,
    ) || !initramfs::published_root_is_live()
    {
        return u64::MAX - 2;
    }
    let command = frame.first_argument();
    let argument = frame.second_argument();
    match command {
        control_abi::ROOT_PROBE if argument == 0 => control_abi::ROOT_DESCRIPTOR_WORD,
        control_abi::ROOT_LOOKUP => root_lookup(argument),
        control_abi::ROOT_READ => root_read(argument),
        control_abi::ROOT_READ_DIRECTORY => root_read_directory(argument),
        _ => u64::MAX - 2,
    }
}

fn root_lookup(address: u64) -> u64 {
    let mut request = [0_u8; control_abi::ROOT_LOOKUP_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || !root_request_header(&request, control_abi::ROOT_LOOKUP_REQUEST_SIZE)
    {
        return u64::MAX - 2;
    }
    let path_address = root_request_word(&request, 8);
    let path_size = root_request_word(&request, 16);
    let output_address = root_request_word(&request, 24);
    let output_size = root_request_word(&request, 32);
    let Some(path) = copy_root_path(path_address, path_size) else {
        return u64::MAX - 2;
    };
    if output_size != control_abi::ROOT_LOOKUP_DESCRIPTOR_SIZE as u64 {
        return u64::MAX - 2;
    }
    let Some((mode, data_size)) = initramfs::published_lookup(path.as_slice()) else {
        return u64::MAX - 2;
    };
    let Some(descriptor) = control_abi::root_lookup_descriptor(mode, data_size) else {
        return u64::MAX - 2;
    };
    if address_space::copy_to_current_user(output_address, &descriptor) {
        descriptor.len() as u64
    } else {
        u64::MAX - 2
    }
}

fn root_read(address: u64) -> u64 {
    let mut request = [0_u8; control_abi::ROOT_READ_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || !root_request_header(&request, control_abi::ROOT_READ_REQUEST_SIZE)
    {
        return u64::MAX - 2;
    }
    let path_address = root_request_word(&request, 8);
    let path_size = root_request_word(&request, 16);
    let offset = root_request_word(&request, 24);
    let output_address = root_request_word(&request, 32);
    let output_size = root_request_word(&request, 40);
    let (Some(path), Ok(offset), Ok(output_size)) = (
        copy_root_path(path_address, path_size),
        usize::try_from(offset),
        usize::try_from(output_size),
    ) else {
        return u64::MAX - 2;
    };
    if !(1..=control_abi::ROOT_MAX_READ_SIZE).contains(&output_size) {
        return u64::MAX - 2;
    }
    let mut output = [0_u8; control_abi::ROOT_MAX_READ_SIZE];
    let Some(size) = initramfs::published_read(path.as_slice(), offset, &mut output[..output_size])
    else {
        return u64::MAX - 2;
    };
    if size == 0 || address_space::copy_to_current_user(output_address, &output[..size]) {
        size as u64
    } else {
        u64::MAX - 2
    }
}

fn root_read_directory(address: u64) -> u64 {
    let mut request = [0_u8; control_abi::ROOT_DIRECTORY_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request)
        || !root_request_header(&request, control_abi::ROOT_DIRECTORY_REQUEST_SIZE)
    {
        return u64::MAX - 2;
    }
    let directory_address = root_request_word(&request, 8);
    let directory_size = root_request_word(&request, 16);
    let cursor = root_request_word(&request, 24);
    let output_address = root_request_word(&request, 32);
    let output_capacity = root_request_word(&request, 40);
    let directory = if directory_size == 0 {
        if directory_address != 0 {
            return u64::MAX - 2;
        }
        None
    } else {
        let Some(path) = copy_root_path(directory_address, directory_size) else {
            return u64::MAX - 2;
        };
        Some(path)
    };
    let (Ok(cursor), Ok(output_capacity)) =
        (usize::try_from(cursor), usize::try_from(output_capacity))
    else {
        return u64::MAX - 2;
    };
    if !(control_abi::ROOT_DIRECTORY_RECORD_HEADER_SIZE
        ..=control_abi::ROOT_MAX_DIRECTORY_RECORD_SIZE)
        .contains(&output_capacity)
    {
        return u64::MAX - 2;
    }
    let directory = directory.as_ref().map_or(&[][..], RootPath::as_slice);
    let Some(entry) = initramfs::published_next_child(directory, cursor) else {
        return u64::MAX - 2;
    };
    let Some(entry) = entry else {
        return 0;
    };
    let Some(record_size) =
        control_abi::ROOT_DIRECTORY_RECORD_HEADER_SIZE.checked_add(entry.name.len())
    else {
        return u64::MAX - 2;
    };
    if record_size > output_capacity {
        return u64::MAX - 2;
    }
    let mut output = [0_u8; control_abi::ROOT_MAX_DIRECTORY_RECORD_SIZE];
    output[0..4].copy_from_slice(&(record_size as u32).to_le_bytes());
    output[4..6].copy_from_slice(&control_abi::VERSION.to_le_bytes());
    output[8..16].copy_from_slice(&(entry.next_cursor as u64).to_le_bytes());
    output[16..20].copy_from_slice(&entry.mode.to_le_bytes());
    output[20..24].copy_from_slice(&(entry.name.len() as u32).to_le_bytes());
    output[24..32].copy_from_slice(&(entry.data_size as u64).to_le_bytes());
    output[32..record_size].copy_from_slice(entry.name);
    if address_space::copy_to_current_user(output_address, &output[..record_size]) {
        record_size as u64
    } else {
        u64::MAX - 2
    }
}

struct RootPath {
    bytes: [u8; control_abi::ROOT_MAX_PATH_SIZE],
    size: usize,
}

impl RootPath {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.size]
    }
}

fn copy_root_path(address: u64, size: u64) -> Option<RootPath> {
    let size = usize::try_from(size).ok()?;
    if !(1..=control_abi::ROOT_MAX_PATH_SIZE).contains(&size) {
        return None;
    }
    let mut path = RootPath {
        bytes: [0; control_abi::ROOT_MAX_PATH_SIZE],
        size,
    };
    address_space::copy_from_current_user(address, &mut path.bytes[..size]).then_some(path)
}

fn root_request_header(request: &[u8], expected_size: usize) -> bool {
    u32::from_le_bytes(request[0..4].try_into().unwrap()) as usize == expected_size
        && u16::from_le_bytes(request[4..6].try_into().unwrap()) == control_abi::VERSION
        && request[6..8] == [0, 0]
}

fn root_request_word(request: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(request[offset..offset + 8].try_into().unwrap())
}

fn network_device_call(caller_domain: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    let command = frame.first_argument();
    let argument = frame.second_argument();
    match command {
        control_abi::NETWORK_DEVICE_PROBE
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            control_abi::NETWORK_DEVICE_DESCRIPTOR_WORD
        }
        control_abi::NETWORK_DEVICE_QUERY_LINK
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            u64::from(network::link_is_up())
        }
        control_abi::NETWORK_DEVICE_SET_LINK
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            network_result(network::set_link(argument))
        }
        control_abi::NETWORK_DEVICE_SET_IPV4
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            network_result(network::set_ipv4(argument))
        }
        control_abi::NETWORK_DEVICE_QUERY_IPV4
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            network::ipv4_configuration()
        }
        control_abi::NETWORK_DEVICE_SET_GATEWAY
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            network_result(network::set_gateway(argument))
        }
        control_abi::NETWORK_DEVICE_QUERY_GATEWAY
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            network::ipv4_gateway()
        }
        control_abi::NETWORK_DEVICE_QUERY_GENERATION
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            network::generation()
        }
        control_abi::NETWORK_DEVICE_SET_ROUTE
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            set_network_route(argument)
        }
        control_abi::NETWORK_DEVICE_QUERY_ROUTE
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::READ,
            ) =>
        {
            query_network_route(argument)
        }
        control_abi::NETWORK_DEVICE_QUERY_SNAPSHOT
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::READ,
            ) =>
        {
            query_network_snapshot(argument)
        }
        control_abi::NETWORK_DEVICE_APPLY
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            apply_network_configuration(argument)
        }
        control_abi::NETWORK_DEVICE_ACTIVATE_EMPTY_QUEUES
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::WRITE,
                )
                && address_space::activate_auxiliary_network_empty_queues(caller_domain) =>
        {
            0
        }
        control_abi::NETWORK_DEVICE_PING
            if argument != 0
                && argument >> 32 == 0
                && network::link_is_up()
                && network::ipv4_configuration() as u32 == argument as u32
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            X86_RUNTIME.NETWORK_PING_RESULT.store(1, Ordering::Release);
            0
        }
        control_abi::NETWORK_DEVICE_PING
            if argument != 0
                && argument >> 32 == 0
                && network::link_is_up()
                && network::ipv4_configuration() != 0
                && network::ipv4_gateway() != 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                )
                && X86_RUNTIME
                    .NETWORK_PING_REQUESTED
                    .compare_exchange(0, argument, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok() =>
        {
            X86_RUNTIME.NETWORK_PING_RESULT.store(0, Ordering::Release);
            if !domain::renew_auxiliary_call_epoch(caller_domain)
                || !scheduler::suspend_container_lifecycle(
                    frame,
                    USER_CODE_SELECTOR,
                    USER_DATA_SELECTOR,
                    0,
                    active_fs_base(),
                )
            {
                X86_RUNTIME
                    .NETWORK_PING_REQUESTED
                    .store(0, Ordering::Release);
                return u64::MAX - 2;
            }
            u64::MAX
        }
        control_abi::NETWORK_DEVICE_QUERY_PING
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            u64::from(X86_RUNTIME.NETWORK_PING_RESULT.swap(0, Ordering::AcqRel))
        }
        linox_native_abi::NATIVE_NETWORK_DEVICE_DHCP
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::WRITE,
                )
                && X86_RUNTIME
                    .NETWORK_DHCP_REQUESTED
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok() =>
        {
            X86_RUNTIME.NETWORK_DHCP_RESULT.store(0, Ordering::Release);
            if !domain::renew_auxiliary_call_epoch(caller_domain)
                || !scheduler::suspend_container_lifecycle(
                    frame,
                    USER_CODE_SELECTOR,
                    USER_DATA_SELECTOR,
                    0,
                    active_fs_base(),
                )
            {
                X86_RUNTIME
                    .NETWORK_DHCP_REQUESTED
                    .store(false, Ordering::Release);
                return u64::MAX - 2;
            }
            u64::MAX
        }
        linox_native_abi::NATIVE_NETWORK_DEVICE_QUERY_DHCP
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            u64::from(X86_RUNTIME.NETWORK_DHCP_RESULT.swap(0, Ordering::AcqRel))
        }
        control_abi::NETWORK_DEVICE_QUERY_PING_TARGET
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            X86_RUNTIME.NETWORK_PING_ACTIVE.load(Ordering::Acquire)
        }
        control_abi::NETWORK_DEVICE_SET_DNS
            if domain::handle_permits(
                caller_domain,
                capability,
                control_abi::NETWORK_DEVICE_OBJECT,
                Rights::WRITE,
            ) =>
        {
            network_result(network::set_dns(argument))
        }
        control_abi::NETWORK_DEVICE_QUERY_DNS
            if argument == 0
                && domain::handle_permits(
                    caller_domain,
                    capability,
                    control_abi::NETWORK_DEVICE_OBJECT,
                    Rights::READ,
                ) =>
        {
            network::dns()
        }
        _ => u64::MAX - 2,
    }
}

pub(crate) fn take_network_ping_request() -> Option<u32> {
    let target = X86_RUNTIME.NETWORK_PING_REQUESTED.swap(0, Ordering::AcqRel);
    X86_RUNTIME
        .NETWORK_PING_ACTIVE
        .store(target, Ordering::Release);
    u32::try_from(target).ok().filter(|target| *target != 0)
}

pub(crate) fn complete_network_ping(success: bool) {
    X86_RUNTIME.NETWORK_PING_ACTIVE.store(0, Ordering::Release);
    X86_RUNTIME
        .NETWORK_PING_RESULT
        .store(if success { 1 } else { 2 }, Ordering::Release);
}

pub(crate) fn take_network_dhcp_request() -> bool {
    X86_RUNTIME
        .NETWORK_DHCP_REQUESTED
        .swap(false, Ordering::AcqRel)
}

pub(crate) fn complete_network_dhcp(success: bool) {
    if success {
        network::set_dhcp_configuration(true);
    }
    X86_RUNTIME
        .NETWORK_DHCP_RESULT
        .store(if success { 1 } else { 2 }, Ordering::Release);
}

fn apply_network_configuration(address: u64) -> u64 {
    let mut request = [0_u8; control_abi::NETWORK_APPLY_REQUEST_SIZE];
    if !address_space::copy_from_current_user(address, &mut request) {
        return u64::MAX - 2;
    }
    let version = network_request_word(&request, 0);
    let expected_generation = network_request_word(&request, 8);
    let link = network_request_word(&request, 16);
    let ipv4 = network_request_word(&request, 24);
    let gateway = network_request_word(&request, 32);
    let route_destination = network_request_word(&request, 40);
    let route_gateway = network_request_word(&request, 48);
    let reserved = network_request_word(&request, 56);
    if version != control_abi::NETWORK_APPLY_VERSION || reserved != 0 {
        return u64::MAX - 2;
    }
    match network::apply(
        expected_generation,
        network::Configuration {
            link,
            ipv4,
            gateway,
            route_destination,
            route_gateway,
        },
    ) {
        Ok(generation) => generation,
        Err(network::ApplyError::Stale) => control_abi::NETWORK_RESULT_STALE_GENERATION,
        Err(network::ApplyError::Invalid) => u64::MAX - 2,
    }
}

fn network_result(success: bool) -> u64 {
    if success {
        0
    } else {
        u64::MAX - 2
    }
}

fn network_request_word(
    request: &[u8; control_abi::NETWORK_APPLY_REQUEST_SIZE],
    offset: usize,
) -> u64 {
    u64::from_le_bytes([
        request[offset],
        request[offset + 1],
        request[offset + 2],
        request[offset + 3],
        request[offset + 4],
        request[offset + 5],
        request[offset + 6],
        request[offset + 7],
    ])
}

fn set_network_route(address: u64) -> u64 {
    let mut record = [0_u8; control_abi::NETWORK_ROUTE_RECORD_SIZE];
    if !address_space::copy_from_current_user(address, &mut record)
        || record[5..8].iter().any(|byte| *byte != 0)
        || record[12..].iter().any(|byte| *byte != 0)
    {
        return u64::MAX - 2;
    }
    let destination = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
    let prefix = record[4];
    let gateway = u32::from_le_bytes([record[8], record[9], record[10], record[11]]);
    network_result(network::set_route(destination, prefix, gateway))
}

fn query_network_route(address: u64) -> u64 {
    let (packed_destination, gateway) = network::route();
    let mut record = [0_u8; control_abi::NETWORK_ROUTE_RECORD_SIZE];
    record[0..4].copy_from_slice(&(packed_destination as u32).to_le_bytes());
    record[4] = (packed_destination >> 32) as u8;
    record[8..12].copy_from_slice(&(gateway as u32).to_le_bytes());
    if !address_space::copy_to_current_user(address, &record) {
        return u64::MAX - 2;
    }
    control_abi::NETWORK_ROUTE_RECORD_SIZE as u64
}

fn query_network_snapshot(address: u64) -> u64 {
    let state = network::snapshot();
    let words = [
        control_abi::NETWORK_SNAPSHOT_VERSION,
        state[0],
        state[1],
        state[2],
        state[3],
        state[4],
        state[5],
    ];
    let mut snapshot = [0_u8; control_abi::NETWORK_SNAPSHOT_SIZE];
    for (index, word) in words.iter().enumerate() {
        let offset = index * core::mem::size_of::<u64>();
        snapshot[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
    }
    if !address_space::copy_to_current_user(address, &snapshot) {
        return u64::MAX - 2;
    }
    control_abi::NETWORK_SNAPSHOT_SIZE as u64
}

fn create_auxiliary_service(
    caller_domain: u64,
    capability: u64,
    frame: *const UserTrapFrame,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(caller_domain, capability, 1, Rights::MANAGE)
        || frame.second_argument() != control_abi::MANAGEMENT_REQUEST_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let mut bytes = [0_u8; control_abi::MANAGEMENT_REQUEST_SIZE];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut bytes) {
        return u64::MAX - 2;
    }
    let Some(request) = control_abi::parse_management_request(&bytes) else {
        return u64::MAX - 2;
    };
    match request.action {
        control_abi::MANAGEMENT_CREATE_AUXILIARY => domain::create_auxiliary_service(
            caller_domain,
            capability,
            request.source,
            request.object,
            request.rights,
        )
        .unwrap_or(u64::MAX - 2),
        control_abi::MANAGEMENT_STOP_AUXILIARY
            if request.object == 0
                && request.rights == 0
                && address_space::stop_auxiliary_from_current_user(
                    caller_domain,
                    capability,
                    request.source,
                ) =>
        {
            0
        }
        control_abi::MANAGEMENT_LOAD_AUXILIARY
            if address_space::load_and_queue_auxiliary_from_current_user(
                request.source,
                request.object,
                request.rights,
            ) =>
        {
            0
        }
        control_abi::MANAGEMENT_INITIALIZE_AUXILIARY
            if address_space::initialize_staged_auxiliary_from_current_user(
                request.source,
                request.object,
                request.rights,
            ) =>
        {
            0
        }
        control_abi::MANAGEMENT_START_AUXILIARY
            if request.object == 0
                && request.rights == 0
                && scheduler::start_staged_auxiliary(request.source) =>
        {
            0
        }
        control_abi::MANAGEMENT_QUERY_AUXILIARY
            if request.object == 0
                && request.rights == 0
                && domain::auxiliary_service_is_ready(request.source) =>
        {
            scheduler::auxiliary_runtime_state(request.source).unwrap_or(u64::MAX - 2)
        }
        control_abi::MANAGEMENT_QUERY_AUXILIARY_FLAGS
            if request.object == 0
                && request.rights == 0
                && domain::auxiliary_service_is_ready(request.source) =>
        {
            scheduler::auxiliary_runtime_flags(request.source).unwrap_or(u64::MAX - 2)
        }
        control_abi::MANAGEMENT_DRAIN_AUXILIARY
            if request.object == 0
                && request.rights == 0
                && domain::request_auxiliary_drain(caller_domain, capability, request.source) =>
        {
            0
        }
        _ => u64::MAX - 2,
    }
}

fn blocking_receive(domain_id: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    if !domain::handle_permits(domain_id, capability, 3, Rights::READ) {
        return u64::MAX - 2;
    }
    match ipc::receive(domain_id) {
        ipc::Receive::Message(message) => return message,
        ipc::Receive::PeerClosed(_) => return scheduler::IPC_PEER_CLOSED,
        ipc::Receive::Empty => {}
    }
    let Some(service_side) = ipc::service_side(domain_id) else {
        return u64::MAX - 2;
    };
    let Some(peer_domain) = ipc::peer_domain(domain_id) else {
        return u64::MAX - 2;
    };
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX;
    };
    let action = scheduler::block_runtime(
        frame,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        scheduler::WaitReason::IpcReceive {
            object: 3,
            service_side,
            peer_domain,
        },
        active_fs_base(),
    );
    if matches!(action, RuntimeAction::Invalid) {
        u64::MAX - 2
    } else {
        if service_side
            && domain::service_failure_policy(domain_id)
                == Some(domain::ServiceFailurePolicy::RestartManaged)
            && !domain::record_service_ready(domain_id)
        {
            return u64::MAX;
        }
        resume_action(action)
    }
}

fn console_write(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 2, Rights::WRITE) {
        return u64::MAX - 2;
    }
    let Ok(length) = usize::try_from(frame.second_argument()) else {
        return u64::MAX - 2;
    };
    if !(1..=8).contains(&length) {
        return u64::MAX - 2;
    }
    let bytes = frame.first_argument().to_le_bytes();
    let message = &bytes[..length];
    if !message
        .iter()
        .all(|byte| matches!(*byte, 0x08 | b'\n' | b'\r' | 0x20..=0x7e))
    {
        return u64::MAX - 2;
    }
    let Ok(message) = core::str::from_utf8(message) else {
        return u64::MAX - 2;
    };
    serial_write(message);
    length as u64
}

fn console_write_buffer(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 2, Rights::WRITE) {
        return u64::MAX - 2;
    }
    let Ok(length) = usize::try_from(frame.second_argument()) else {
        return u64::MAX - 2;
    };
    if !(1..=control_abi::MAX_BUFFERED_CONSOLE_BYTES as usize).contains(&length) {
        return u64::MAX - 2;
    }
    let mut bytes = [0_u8; control_abi::MAX_BUFFERED_CONSOLE_BYTES as usize];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut bytes[..length])
        || !bytes[..length]
            .iter()
            .all(|byte| matches!(*byte, 0x08 | b'\n' | b'\r' | 0x20..=0x7e))
    {
        return u64::MAX - 2;
    }
    let Ok(message) = core::str::from_utf8(&bytes[..length]) else {
        return u64::MAX - 2;
    };
    serial_write(message);
    SYSCALL_STATE.fetch_or(8, Ordering::SeqCst);
    length as u64
}

fn console_read_line(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 2, Rights::READ) {
        return u64::MAX - 2;
    }
    let Ok(capacity) = usize::try_from(frame.second_argument()) else {
        return u64::MAX - 2;
    };
    if !(1..=control_abi::CONSOLE_MAX_LINE_BYTES).contains(&capacity) {
        return u64::MAX - 2;
    }
    let mut line = [0_u8; control_abi::CONSOLE_MAX_LINE_BYTES];
    let mut length = 0;
    loop {
        match crate::serial_read_byte_blocking() {
            b'\r' | b'\n' => {
                crate::serial_write_bytes(b"\r\n");
                break;
            }
            0x08 | 0x7f if length != 0 => {
                length -= 1;
                crate::serial_write_bytes(b"\x08 \x08");
            }
            byte @ 0x20..=0x7e if length < capacity => {
                line[length] = byte;
                length += 1;
                crate::serial_write_bytes(&[byte]);
            }
            _ => {}
        }
    }
    if length != 0 && !address_space::copy_to_current_user(frame.first_argument(), &line[..length])
        || !domain::renew_auxiliary_call_epoch(domain_id)
    {
        return u64::MAX - 2;
    }
    length as u64
}

fn console_read_byte(domain_id: u64, capability: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 2, Rights::READ)
        || frame.first_argument() != 0
        || frame.second_argument() != 0
        || !domain::renew_auxiliary_call_epoch(domain_id)
    {
        return u64::MAX - 2;
    }
    if !crate::serial_input_ready() && queue_background_container_work() {
        if !scheduler::suspend_container_lifecycle(
            frame,
            USER_CODE_SELECTOR,
            USER_DATA_SELECTOR,
            0,
            active_fs_base(),
        ) {
            return u64::MAX - 2;
        }
        return u64::MAX;
    }
    u64::from(crate::serial_read_byte_blocking())
}

fn host_inspect(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::READ)
        || frame.second_argument() != 0
    {
        return u64::MAX - 2;
    }
    let mut request = [0_u8; control_abi::HOST_INSPECT_REQUEST_SIZE];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut request)
        || u32::from_le_bytes(request[0..4].try_into().unwrap()) as usize != request.len()
        || u16::from_le_bytes(request[4..6].try_into().unwrap())
            != control_abi::HOST_INSPECT_VERSION
        || u64::from_le_bytes(request[24..32].try_into().unwrap())
            != control_abi::HOST_INSPECT_RECORD_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let command = u16::from_le_bytes(request[6..8].try_into().unwrap());
    let selector = u64::from_le_bytes(request[8..16].try_into().unwrap());
    let output_address = u64::from_le_bytes(request[16..24].try_into().unwrap());
    let record = match command {
        control_abi::HOST_PROC_ENUMERATE => {
            let Ok(cursor) = usize::try_from(selector) else {
                return u64::MAX - 2;
            };
            let container_cursor_base = domain::HOST_DOMAIN_CURSOR_END as usize + 1;
            let container_cursor_end = container_cursor_base + control_abi::DOMAIN_LIMIT;
            if cursor == container_cursor_end {
                return if domain::renew_auxiliary_call_epoch(domain_id) {
                    0
                } else {
                    u64::MAX - 2
                };
            }
            if cursor <= domain::HOST_DOMAIN_CURSOR_END as usize {
                let Some(record) = domain::inspect_live_domain(cursor) else {
                    return u64::MAX - 2;
                };
                if let Some(record) = record {
                    record
                } else if let Some(slot) = next_running_container_slot(0) {
                    domain::InspectionRecord {
                        pid: 100 + slot as u64,
                        parent_pid: 0,
                        kind: control_abi::HOST_PROCESS_KIND_DOMAIN_INIT,
                        state: control_abi::HOST_INSPECT_STATE_READY,
                        active_threads: 1,
                        next_cursor: (container_cursor_base + slot + 1) as u64,
                    }
                } else {
                    return if domain::renew_auxiliary_call_epoch(domain_id) {
                        0
                    } else {
                        u64::MAX - 2
                    };
                }
            } else {
                let Some(start) = cursor.checked_sub(container_cursor_base) else {
                    return u64::MAX - 2;
                };
                let Some(slot) = next_running_container_slot(start) else {
                    return if domain::renew_auxiliary_call_epoch(domain_id) {
                        0
                    } else {
                        u64::MAX - 2
                    };
                };
                domain::InspectionRecord {
                    pid: 100 + slot as u64,
                    parent_pid: 0,
                    kind: control_abi::HOST_PROCESS_KIND_DOMAIN_INIT,
                    state: control_abi::HOST_INSPECT_STATE_READY,
                    active_threads: 1,
                    next_cursor: (container_cursor_base + slot + 1) as u64,
                }
            }
        }
        control_abi::HOST_PROC_STATUS => {
            if let Some(slot) = selector
                .checked_sub(100)
                .and_then(|slot| usize::try_from(slot).ok())
                .filter(|slot| {
                    *slot < control_abi::DOMAIN_LIMIT
                        && container_state(*slot) == control_abi::DOMAIN_STATE_RUNNING
                })
            {
                domain::InspectionRecord {
                    pid: 100 + slot as u64,
                    parent_pid: 0,
                    kind: control_abi::HOST_PROCESS_KIND_DOMAIN_INIT,
                    state: control_abi::HOST_INSPECT_STATE_READY,
                    active_threads: 1,
                    next_cursor: 0,
                }
            } else {
                let Some(record) = domain::inspect_host_process(selector) else {
                    return u64::MAX - 2;
                };
                record
            }
        }
        _ => return u64::MAX - 2,
    };
    let mut output = [0_u8; control_abi::HOST_INSPECT_RECORD_SIZE];
    output[0..4].copy_from_slice(&(control_abi::HOST_INSPECT_RECORD_SIZE as u32).to_le_bytes());
    output[4..6].copy_from_slice(&control_abi::HOST_INSPECT_VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&record.kind.to_le_bytes());
    output[8..10].copy_from_slice(&record.state.to_le_bytes());
    output[12..16].copy_from_slice(&record.active_threads.to_le_bytes());
    output[16..24].copy_from_slice(&record.pid.to_le_bytes());
    output[24..32].copy_from_slice(&record.parent_pid.to_le_bytes());
    output[32..40].copy_from_slice(&record.next_cursor.to_le_bytes());
    if address_space::copy_to_current_user(output_address, &output)
        && domain::renew_auxiliary_call_epoch(domain_id)
    {
        output.len() as u64
    } else {
        u64::MAX - 2
    }
}

fn network_inventory_call(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::MANAGE)
        || frame.second_argument() != 0
    {
        return u64::MAX - 2;
    }
    let mut request = [0_u8; linox_native_abi::NATIVE_NETWORK_INVENTORY_REQUEST_SIZE as usize];
    if !address_space::copy_from_current_user(frame.first_argument(), &mut request)
        || read_u32_at(&request, 0) != linox_native_abi::NATIVE_NETWORK_INVENTORY_REQUEST_SIZE
        || read_u16_at(&request, 4) != linox_native_abi::NATIVE_NETWORK_INVENTORY_VERSION
        || usize::from(read_u16_at(&request, 16)) > linox_native_abi::NATIVE_NETWORK_MAX_NAME_SIZE
        || usize::from(read_u16_at(&request, 20)) > linox_native_abi::NATIVE_NETWORK_MAX_NAME_SIZE
        || usize::from(read_u16_at(&request, 22)) > control_abi::DOMAIN_MAX_NAME_SIZE
    {
        return u64::MAX - 2;
    }
    let command = read_u16_at(&request, 6);
    let name_size = usize::from(read_u16_at(&request, 16));
    let uplink_size = usize::from(read_u16_at(&request, 20));
    let domain_size = usize::from(read_u16_at(&request, 22));
    let name = &request[24..24 + name_size];
    let uplink = &request[40..40 + uplink_size];
    let domain_name = &request[56..56 + domain_size];
    let result = match command {
        linox_native_abi::NATIVE_NETWORK_INVENTORY_QUERY => {
            let Ok(cursor) = usize::try_from(read_u64_at(&request, 8)) else {
                return u64::MAX - 2;
            };
            let Some(record) = network::inventory(cursor) else {
                return 0;
            };
            request.fill(0);
            request[0..4].copy_from_slice(
                &linox_native_abi::NATIVE_NETWORK_INVENTORY_REQUEST_SIZE.to_le_bytes(),
            );
            request[4..6]
                .copy_from_slice(&linox_native_abi::NATIVE_NETWORK_INVENTORY_VERSION.to_le_bytes());
            request[6..8].copy_from_slice(&command.to_le_bytes());
            request[8..16].copy_from_slice(&record.next_cursor.to_le_bytes());
            request[16..18].copy_from_slice(&(record.name_size as u16).to_le_bytes());
            request[18..20].copy_from_slice(&record.kind.to_le_bytes());
            request[20..22].copy_from_slice(&(record.uplink_size as u16).to_le_bytes());
            request[24..24 + record.name_size].copy_from_slice(&record.name[..record.name_size]);
            request[40..40 + record.uplink_size]
                .copy_from_slice(&record.uplink[..record.uplink_size]);
            1
        }
        linox_native_abi::NATIVE_NETWORK_INVENTORY_CREATE_VIRTUAL
            if network::create_virtual(name, uplink) =>
        {
            1
        }
        linox_native_abi::NATIVE_NETWORK_INVENTORY_ATTACH => {
            let Some(slot) = container_slot_by_name(domain_name) else {
                return u64::MAX - 2;
            };
            if !network::attach(slot, name)
                || !domain::configure_container_network_mode(
                    X86_RUNTIME.CONTAINER_DOMAIN_IDS[slot].load(Ordering::Acquire),
                    domain::ContainerNetworkMode::Isolated,
                )
            {
                return u64::MAX - 2;
            }
            1
        }
        linox_native_abi::NATIVE_NETWORK_INVENTORY_SET_LINK
            if read_u64_at(&request, 8) <= 1
                && network::set_virtual_link(name, read_u64_at(&request, 8) == 1) =>
        {
            1
        }
        linox_native_abi::NATIVE_NETWORK_INVENTORY_QUERY_ATTACHMENT => {
            let Some(slot) = container_slot_by_name(domain_name) else {
                return u64::MAX - 2;
            };
            let Ok(cursor) = usize::try_from(read_u64_at(&request, 8)) else {
                return u64::MAX - 2;
            };
            let Some((next, attached_name, attached_name_size)) = network::attachment(slot, cursor)
            else {
                return 0;
            };
            request.fill(0);
            request[0..4].copy_from_slice(
                &linox_native_abi::NATIVE_NETWORK_INVENTORY_REQUEST_SIZE.to_le_bytes(),
            );
            request[4..6]
                .copy_from_slice(&linox_native_abi::NATIVE_NETWORK_INVENTORY_VERSION.to_le_bytes());
            request[6..8].copy_from_slice(&command.to_le_bytes());
            request[8..16].copy_from_slice(&next.to_le_bytes());
            request[16..18].copy_from_slice(&(attached_name_size as u16).to_le_bytes());
            request[24..24 + attached_name_size]
                .copy_from_slice(&attached_name[..attached_name_size]);
            1
        }
        _ => return u64::MAX - 2,
    };
    if result != 0 && !address_space::copy_to_current_user(frame.first_argument(), &request) {
        return u64::MAX - 2;
    }
    if domain::renew_auxiliary_call_epoch(domain_id) {
        result
    } else {
        u64::MAX - 2
    }
}

pub(super) fn read_u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub(super) fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

pub(super) fn read_u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn write_abi_descriptor(caller_domain: u64, frame: *const UserTrapFrame) -> u64 {
    let mut descriptor = control_abi::descriptor();
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if CONTROL_DESCRIPTOR_OVERRIDE_DOMAIN
        .compare_exchange(caller_domain, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        descriptor[12] = 1;
    }
    if frame.second_argument() != descriptor.len() as u64
        || !address_space::copy_to_current_user(frame.first_argument(), &descriptor)
    {
        return u64::MAX - 2;
    }
    SYSCALL_STATE.fetch_or(16, Ordering::SeqCst);
    descriptor.len() as u64
}

fn write_fault_descriptor(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::MANAGE)
        || frame.second_argument() != control_abi::FAULT_DESCRIPTOR_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let Some(descriptor) = domain::delivered_fault_descriptor() else {
        return u64::MAX - 2;
    };
    if !address_space::copy_to_current_user(frame.first_argument(), &descriptor) {
        return u64::MAX - 2;
    }
    descriptor.len() as u64
}

fn write_lifecycle_descriptor(domain_id: u64, capability: u64, frame: *const UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::MANAGE)
        || frame.second_argument() != control_abi::LIFECYCLE_DESCRIPTOR_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let Some(descriptor) = domain::delivered_lifecycle_event_descriptor() else {
        return u64::MAX - 2;
    };
    if !address_space::copy_to_current_user(frame.first_argument(), &descriptor) {
        return u64::MAX - 2;
    }
    descriptor.len() as u64
}

fn write_ipc_delivery_descriptor(
    domain_id: u64,
    capability: u64,
    frame: *const UserTrapFrame,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 3, Rights::READ)
        || frame.second_argument() != control_abi::IPC_DELIVERY_DESCRIPTOR_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let Some(descriptor) = ipc::delivery_descriptor(domain_id) else {
        return u64::MAX - 2;
    };
    if !address_space::copy_to_current_user(frame.first_argument(), &descriptor) {
        return u64::MAX - 2;
    }
    descriptor.len() as u64
}

fn write_lifecycle_identity_descriptor(
    domain_id: u64,
    capability: u64,
    frame: *const UserTrapFrame,
) -> u64 {
    let Some(frame) = (unsafe { frame.as_ref() }) else {
        return u64::MAX - 2;
    };
    if !domain::handle_permits(domain_id, capability, 1, Rights::MANAGE)
        || frame.second_argument() != control_abi::LIFECYCLE_IDENTITY_DESCRIPTOR_SIZE as u64
    {
        return u64::MAX - 2;
    }
    let Some(descriptor) = domain::delivered_lifecycle_identity_descriptor() else {
        return u64::MAX - 2;
    };
    if !address_space::copy_to_current_user(frame.first_argument(), &descriptor) {
        return u64::MAX - 2;
    }
    descriptor.len() as u64
}

fn runtime_result(frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX;
    };
    let action = scheduler::yield_runtime(
        frame,
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
        active_fs_base(),
    );
    resume_action(action)
}

pub(super) fn exit_result(caller_domain: u64, frame: *mut UserTrapFrame) -> u64 {
    let Some(frame) = (unsafe { frame.as_mut() }) else {
        return u64::MAX;
    };
    let failure_policy = domain::service_failure_policy(caller_domain);
    let auxiliary_exit_status = if failure_policy == Some(domain::ServiceFailurePolicy::StopOnly) {
        let Ok(status) = u8::try_from(frame.first_argument()) else {
            return u64::MAX - 2;
        };
        Some(status)
    } else {
        None
    };
    let service_exit = failure_policy == Some(domain::ServiceFailurePolicy::RestartManaged);
    let close_wait = if failure_policy == Some(domain::ServiceFailurePolicy::StopOnly) {
        None
    } else {
        Some(scheduler::WaitReason::IpcReceive {
            object: 3,
            service_side: !service_exit,
            peer_domain: caller_domain,
        })
    };
    if failure_policy == Some(domain::ServiceFailurePolicy::StopOnly) {
        if !crate::packet::retire_egress_producer_if_bound(caller_domain) {
            serial_write("linox: auxiliary exit egress retirement failed\r\n");
            return u64::MAX;
        }
        if crate::packet::egress_is_empty() {
            if let Some((waiting_domain, sequence)) = scheduler::blocked_egress_waiter() {
                if domain::take_blocked_auxiliary_drain_request(waiting_domain)
                    && !scheduler::wake_egress_waiter_drained(caller_domain, sequence)
                {
                    serial_write("linox: auxiliary exit drain wake failed\r\n");
                    return u64::MAX;
                }
            }
        }
    }
    let action = scheduler::exit_runtime(frame, USER_CODE_SELECTOR, USER_DATA_SELECTOR, close_wait);
    if matches!(action, RuntimeAction::Invalid) {
        serial_write("linox: runtime exit scheduling failed\r\n");
        return u64::MAX;
    }
    if !domain::detach_thread(caller_domain) {
        serial_write("linox: runtime exit thread detach failed\r\n");
        return u64::MAX;
    }
    if service_exit
        && (!ipc::retire_service(caller_domain) || !domain::retire_clean_service(caller_domain))
    {
        return u64::MAX;
    }
    if failure_policy == Some(domain::ServiceFailurePolicy::StopOnly) {
        if !domain::begin_auxiliary_runtime_exit(caller_domain, auxiliary_exit_status.unwrap_or(0))
        {
            serial_write("linox: auxiliary exit transition failed\r\n");
            return u64::MAX;
        }
        if !address_space::quiesce_auxiliary_device(caller_domain) {
            serial_write("linox: auxiliary exit quiesce failed status: ");
            serial_write_u64(u64::from(auxiliary_exit_status.unwrap_or(0)));
            serial_write("\r\n");
            return u64::MAX;
        }
        if !address_space::activate_kernel_root_for_auxiliary(caller_domain) {
            serial_write("linox: auxiliary exit kernel-root restoration failed\r\n");
            return u64::MAX;
        }
        if !address_space::release_auxiliary_address_space(caller_domain) {
            serial_write("linox: auxiliary exit address-space release failed\r\n");
            return u64::MAX;
        }
        if !domain::retire_stopped_auxiliary_service(caller_domain) {
            serial_write("linox: auxiliary exit retirement failed\r\n");
            return u64::MAX;
        }
    }
    resume_action(action)
}
