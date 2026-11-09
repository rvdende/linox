use super::*;

pub(super) fn linux_controller_syscall(
    number: u64,
    registers: LinuxSyscallFrame,
    user_stack: u64,
    user_rip: u64,
    user_rflags: u64,
) -> Option<u64> {
    let domain_id = X86_RUNTIME.LINUX_CONTROLLER_DOMAIN.load(Ordering::Acquire);
    if domain_id == 0 || scheduler::current_domain() != Some(domain_id) {
        return None;
    }
    let first = registers.rdi;
    let second = registers.rsi;
    let third = registers.rdx;
    match number {
        LINUX_READ_SYSCALL if linux_socket_pipe_descriptor(first, LINUX_DESCRIPTOR_INPUT) => {
            Some(linux_controller_pipe_read(first, second, third))
        }
        LINUX_READ_SYSCALL if first == 0 && third != 0 => {
            let capability = X86_RUNTIME.LINUX_CONTROLLER_CONSOLE.load(Ordering::Acquire);
            if !domain::handle_permits(domain_id, capability, 2, Rights::READ) {
                return Some(LINUX_EBADF);
            }
            if !crate::serial_input_ready() && queue_background_container_work() {
                let mut frame = UserTrapFrame::from_linux_syscall(
                    registers.into_array(),
                    user_rip,
                    user_stack,
                    user_rflags,
                    second,
                    third,
                );
                if !scheduler::suspend_container_lifecycle(
                    &mut frame,
                    USER_CODE_SELECTOR,
                    USER_DATA_SELECTOR,
                    0,
                    active_fs_base(),
                ) {
                    return Some(LINUX_EIO);
                }
                return Some(LINUX_RETURN_TO_KERNEL);
            }
            let byte = crate::serial_read_byte_blocking();
            if !address_space::copy_to_current_user(second, &[byte]) {
                return Some(LINUX_EFAULT);
            }
            Some(1)
        }
        LINUX_READ_SYSCALL => Some(if first == 0 { 0 } else { LINUX_EBADF }),
        LINUX_WRITE_SYSCALL if linux_socket_pipe_descriptor(first, LINUX_DESCRIPTOR_OUTPUT) => {
            Some(linux_controller_pipe_write(first, second, third))
        }
        LINUX_WRITE_SYSCALL if matches!(first, 1 | 2) => {
            let Ok(length) = usize::try_from(third) else {
                return Some(LINUX_EINVAL);
            };
            if length == 0 {
                return Some(0);
            }
            if length > control_abi::MAX_BUFFERED_CONSOLE_BYTES as usize {
                return Some(LINUX_EINVAL);
            }
            let capability = X86_RUNTIME.LINUX_CONTROLLER_CONSOLE.load(Ordering::Acquire);
            let mut bytes = [0_u8; control_abi::MAX_BUFFERED_CONSOLE_BYTES as usize];
            if !domain::handle_permits(domain_id, capability, 2, Rights::WRITE)
                || !address_space::copy_from_current_user(second, &mut bytes[..length])
            {
                return Some(LINUX_EFAULT);
            }
            crate::serial_write_bytes(&bytes[..length]);
            Some(third)
        }
        LINUX_WRITE_SYSCALL => Some(LINUX_EBADF),
        LINUX_IOCTL_SYSCALL if second == linox_native_abi::LINOX_CONTROL_IOCTL => {
            let capability = match first {
                1 | 2 => X86_RUNTIME.LINUX_CONTROLLER_CONSOLE.load(Ordering::Acquire),
                3 => X86_RUNTIME.LINUX_CONTROLLER_HOST.load(Ordering::Acquire),
                4 => X86_RUNTIME.LINUX_CONTROLLER_ROOT.load(Ordering::Acquire),
                5 => X86_RUNTIME.LINUX_CONTROLLER_NETWORK.load(Ordering::Acquire),
                _ => return Some(LINUX_EBADF),
            };
            let mut request = [0_u8; linox_native_abi::LINOX_CONTROL_IOCTL_SIZE as usize];
            if !address_space::copy_from_current_user(third, &mut request)
                || u32::from_ne_bytes(request[0..4].try_into().unwrap())
                    != linox_native_abi::LINOX_CONTROL_IOCTL_SIZE
                || u16::from_ne_bytes(request[4..6].try_into().unwrap())
                    != linox_native_abi::LINOX_CONTROL_IOCTL_VERSION
                || request[6..8] != [0, 0]
            {
                return Some(LINUX_EFAULT);
            }
            let operation = u64::from_ne_bytes(request[8..16].try_into().unwrap());
            let operation_first = u64::from_ne_bytes(request[16..24].try_into().unwrap());
            let operation_second = u64::from_ne_bytes(request[24..32].try_into().unwrap());
            let mut frame = UserTrapFrame::from_linux_syscall(
                registers.into_array(),
                user_rip,
                user_stack,
                user_rflags,
                operation_first,
                operation_second,
            );
            let result = syscall_handler(operation, capability, &mut frame);
            Some(if scheduler::current_domain() == Some(domain_id) {
                result
            } else {
                LINUX_RETURN_TO_KERNEL
            })
        }
        LINUX_IOCTL_SYSCALL if linux_socket_pipe_descriptor(first, LINUX_DESCRIPTOR_INPUT) => {
            Some(linux_controller_pipe_ioctl(first, second, third))
        }
        LINUX_IOCTL_SYSCALL => Some(if linux_descriptor_open(first) {
            LINUX_ENOTTY
        } else {
            LINUX_EBADF
        }),
        LINUX_PIPE_SYSCALL => Some(linux_socket_pipe(
            first,
            0,
            6,
            address_space::copy_to_current_user,
        )),
        LINUX_PIPE2_SYSCALL => Some(linux_socket_pipe(
            first,
            second,
            6,
            address_space::copy_to_current_user,
        )),
        LINUX_POLL_SYSCALL => Some(linux_controller_poll(first, second, third)),
        LINUX_SELECT_SYSCALL | LINUX_PSELECT6_SYSCALL => Some(linux_select_with_copy(
            LinuxSelectInput {
                descriptor_count: first,
                read_address: second,
                write_address: third,
                exception_address: registers.r10,
                timeout_address: registers.r8,
                signal_mask_address: registers.r9,
            },
            number == LINUX_PSELECT6_SYSCALL,
            address_space::copy_from_current_user,
            address_space::copy_to_current_user,
        )),
        LINUX_DUP_SYSCALL => Some(linux_device_dup_at_least(first, 6, false)),
        LINUX_DUP2_SYSCALL => Some(linux_console_dup2(first, second)),
        LINUX_DUP3_SYSCALL => Some(linux_dup3(first, second, third)),
        LINUX_FCNTL_SYSCALL => Some(linux_descriptor_fcntl(first, second, third)),
        LINUX_CLOSE_SYSCALL => Some(linux_descriptor_close(first)),
        LINUX_SCHED_YIELD_SYSCALL => Some(0),
        LINUX_GETPID_SYSCALL | LINUX_GETTID_SYSCALL | LINUX_GETPGRP_SYSCALL => Some(1),
        LINUX_GETPPID_SYSCALL => Some(0),
        LINUX_GETUID_SYSCALL
        | LINUX_GETGID_SYSCALL
        | LINUX_GETEUID_SYSCALL
        | LINUX_GETEGID_SYSCALL => Some(0),
        LINUX_GETPGID_SYSCALL | LINUX_GETSID_SYSCALL => Some(if matches!(first as i32, 0 | 1) {
            1
        } else {
            LINUX_ESRCH
        }),
        LINUX_GETGROUPS_SYSCALL => Some(linux_controller_getgroups(first, second)),
        LINUX_UNAME_SYSCALL => Some(linux_uname_with_copy(
            first,
            address_space::copy_to_current_user,
        )),
        LINUX_CLOCK_GETTIME_SYSCALL => Some(linux_controller_clock_gettime(first, second)),
        LINUX_CLOCK_GETRES_SYSCALL => Some(linux_controller_clock_getres(first, second)),
        LINUX_GETTIMEOFDAY_SYSCALL => Some(linux_controller_gettimeofday(first, second)),
        LINUX_TIME_SYSCALL => Some(linux_controller_time(first)),
        LINUX_TIMES_SYSCALL => Some(linux_controller_times(first)),
        LINUX_GETRLIMIT_SYSCALL => Some(linux_getrlimit(
            first,
            second,
            true,
            address_space::copy_to_current_user,
        )),
        LINUX_SYSINFO_SYSCALL => {
            let Some(processes) =
                linux_process::host_live_process_count().and_then(|count| count.checked_add(1))
            else {
                return Some(LINUX_EOVERFLOW);
            };
            let Some(uptime) = linux_system_elapsed_time() else {
                return Some(LINUX_ENOSYS);
            };
            let information = match linux_sysinfo_information(processes, uptime) {
                Ok(information) => information,
                Err(error) => return Some(error),
            };
            Some(
                if address_space::copy_to_current_user(first, &information) {
                    0
                } else {
                    LINUX_EFAULT
                },
            )
        }
        LINUX_GETRANDOM_SYSCALL => Some(linux_getrandom_with_copy(
            first,
            second,
            third,
            address_space::copy_to_current_user,
        )),
        LINUX_EXIT_SYSCALL | LINUX_EXIT_GROUP_SYSCALL => {
            let mut frame = UserTrapFrame::from_linux_syscall(
                registers.into_array(),
                user_rip,
                user_stack,
                user_rflags,
                first,
                0,
            );
            let result = syscall_handler(2, 0, &mut frame);
            X86_RUNTIME
                .LINUX_CONTROLLER_DOMAIN
                .store(0, Ordering::Release);
            X86_RUNTIME
                .LINUX_CONTROLLER_CONSOLE
                .store(0, Ordering::Release);
            X86_RUNTIME
                .LINUX_CONTROLLER_HOST
                .store(0, Ordering::Release);
            X86_RUNTIME
                .LINUX_CONTROLLER_ROOT
                .store(0, Ordering::Release);
            X86_RUNTIME
                .LINUX_CONTROLLER_NETWORK
                .store(0, Ordering::Release);
            Some(if result == u64::MAX {
                LINUX_RETURN_TO_KERNEL
            } else {
                result
            })
        }
        _ => Some(LINUX_ENOSYS),
    }
}

fn linux_controller_getgroups(size: u64, output: u64) -> u64 {
    let size = size as i32;
    if size < 0 {
        return LINUX_EINVAL;
    }
    if size == 0 {
        return 1;
    }
    if !address_space::copy_to_current_user(output, &0_u32.to_ne_bytes()) {
        return LINUX_EFAULT;
    }
    1
}

fn linux_controller_poll(address: u64, count: u64, timeout: u64) -> u64 {
    let Ok(descriptor_count) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if descriptor_count > LINUX_POLLFD_LIMIT {
        return LINUX_EINVAL;
    }
    let timeout = timeout as u32 as i32;
    let duration = if timeout < 0 {
        None
    } else {
        Some((timeout as u64).saturating_mul(1_000_000))
    };
    let deadline = match duration {
        Some(0) | None => None,
        Some(duration) => {
            let Some(deadline) =
                linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
            else {
                return LINUX_EINVAL;
            };
            Some(deadline)
        }
    };
    let mut pollfds = [0_u8; LINUX_POLLFD_LIMIT * 8];
    let active = &mut pollfds[..descriptor_count * 8];
    if descriptor_count != 0 && !address_space::copy_from_current_user(address, active) {
        return LINUX_EFAULT;
    }
    loop {
        let mut ready = 0_u64;
        for pollfd in active.as_chunks_mut::<8>().0 {
            let descriptor = i32::from_ne_bytes(pollfd[..4].try_into().unwrap());
            let events = u16::from_ne_bytes(pollfd[4..6].try_into().unwrap());
            let returned = linux_descriptor_poll_events(descriptor, events);
            pollfd[6..8].copy_from_slice(&returned.to_ne_bytes());
            ready += u64::from(returned != 0);
        }
        let timed_out = duration == Some(0)
            || deadline.is_some_and(|deadline| {
                linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline)
            });
        if ready != 0 || timed_out {
            return if descriptor_count == 0 || address_space::copy_to_current_user(address, active)
            {
                ready
            } else {
                LINUX_EFAULT
            };
        }
        core::hint::spin_loop();
    }
}

fn linux_controller_clock_value(clock: u64) -> Option<(u64, u64)> {
    let clock = u64::from(clock as u32);
    let mut value = if matches!(
        clock,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_REALTIME_COARSE
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_TAI
    ) {
        linux_host_realtime_time()
    } else if matches!(
        clock,
        LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_PROCESS_CPUTIME_ID
            | LINUX_CLOCK_THREAD_CPUTIME_ID
            | LINUX_CLOCK_MONOTONIC_RAW
            | LINUX_CLOCK_MONOTONIC_COARSE
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_BOOTTIME_ALARM
    ) {
        linux_system_elapsed_time()
    } else {
        None
    }?;
    if matches!(
        clock,
        LINUX_CLOCK_REALTIME_COARSE | LINUX_CLOCK_MONOTONIC_COARSE
    ) {
        let resolution = NANOSECONDS_PER_SECOND / LINUX_CLOCK_TICKS_PER_SECOND;
        value.1 -= value.1 % resolution;
    }
    Some(value)
}

fn linux_controller_clock_gettime(clock: u64, output: u64) -> u64 {
    let Some((seconds, nanoseconds)) = linux_controller_clock_value(clock) else {
        return LINUX_EINVAL;
    };
    let mut timespec = [0_u8; 16];
    timespec[..8].copy_from_slice(&seconds.to_ne_bytes());
    timespec[8..].copy_from_slice(&nanoseconds.to_ne_bytes());
    if address_space::copy_to_current_user(output, &timespec) {
        0
    } else {
        LINUX_EFAULT
    }
}

fn linux_controller_clock_getres(clock: u64, output: u64) -> u64 {
    let clock = u64::from(clock as u32);
    if !linux_clock_supported(clock) {
        return LINUX_EINVAL;
    }
    if output == 0 {
        return 0;
    }
    let nanoseconds = if matches!(
        clock,
        LINUX_CLOCK_REALTIME_COARSE | LINUX_CLOCK_MONOTONIC_COARSE
    ) {
        NANOSECONDS_PER_SECOND / LINUX_CLOCK_TICKS_PER_SECOND
    } else {
        let Some(frequency) = timer::monotonic_frequency() else {
            return LINUX_ENOSYS;
        };
        NANOSECONDS_PER_SECOND.div_ceil(frequency).max(1)
    };
    let mut timespec = [0_u8; 16];
    timespec[8..].copy_from_slice(&nanoseconds.to_ne_bytes());
    if address_space::copy_to_current_user(output, &timespec) {
        0
    } else {
        LINUX_EFAULT
    }
}

fn linux_controller_gettimeofday(timeval: u64, timezone: u64) -> u64 {
    if timeval == 0 && timezone == 0 {
        return 0;
    }
    let Some((seconds, nanoseconds)) = linux_host_realtime_time() else {
        return LINUX_ENOSYS;
    };
    let mut output = [0_u8; 16];
    output[..8].copy_from_slice(&seconds.to_ne_bytes());
    output[8..].copy_from_slice(&(nanoseconds / 1_000).to_ne_bytes());
    if timeval != 0 && !address_space::copy_to_current_user(timeval, &output) {
        return LINUX_EFAULT;
    }
    if timezone != 0 && !address_space::copy_to_current_user(timezone, &[0; 8]) {
        return LINUX_EFAULT;
    }
    0
}

fn linux_controller_time(output: u64) -> u64 {
    let Some((seconds, _)) = linux_host_realtime_time() else {
        return LINUX_ENOSYS;
    };
    if output != 0 && !address_space::copy_to_current_user(output, &seconds.to_ne_bytes()) {
        return LINUX_EFAULT;
    }
    seconds
}

fn linux_controller_times(output: u64) -> u64 {
    let Some((seconds, nanoseconds)) = linux_system_elapsed_time() else {
        return LINUX_ENOSYS;
    };
    let ticks = seconds
        .saturating_mul(LINUX_CLOCK_TICKS_PER_SECOND)
        .saturating_add(
            nanoseconds.saturating_mul(LINUX_CLOCK_TICKS_PER_SECOND) / NANOSECONDS_PER_SECOND,
        );
    if output != 0 {
        let mut accounting = [0_u8; 32];
        accounting[..8].copy_from_slice(&ticks.to_ne_bytes());
        if !address_space::copy_to_current_user(output, &accounting) {
            return LINUX_EFAULT;
        }
    }
    ticks
}

fn linux_controller_pipe_read(descriptor: u64, address: u64, count: u64) -> u64 {
    let Some(slot) = linux_socket_slot(descriptor) else {
        return LINUX_EBADF;
    };
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if requested == 0 {
        return 0;
    }
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut total = 0_usize;
    while total < requested {
        let chunk = (requested - total).min(bytes.len());
        let result = if linux_socket_nonblocking(descriptor) {
            crate::linux_socket::recv(slot, &mut bytes[..chunk])
        } else {
            crate::linux_socket::recv_blocking(slot, &mut bytes[..chunk])
        };
        let received = match result {
            Ok((received, _)) => received,
            Err(error) => {
                return if total == 0 {
                    linux_socket_error(error)
                } else {
                    total as u64
                };
            }
        };
        if received != 0
            && !address_space::copy_to_current_user(address + total as u64, &bytes[..received])
        {
            return if total == 0 {
                LINUX_EFAULT
            } else {
                total as u64
            };
        }
        total += received;
        if received < chunk {
            break;
        }
    }
    total as u64
}

fn linux_controller_pipe_write(descriptor: u64, address: u64, count: u64) -> u64 {
    let Some(slot) = linux_socket_slot(descriptor) else {
        return LINUX_EBADF;
    };
    let Ok(requested) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if requested == 0 {
        return 0;
    }
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut total = 0_usize;
    while total < requested {
        let chunk = (requested - total).min(bytes.len());
        if !address_space::copy_from_current_user(address + total as u64, &mut bytes[..chunk]) {
            return if total == 0 {
                LINUX_EFAULT
            } else {
                total as u64
            };
        }
        let result = if linux_socket_nonblocking(descriptor) {
            crate::linux_socket::send(slot, &bytes[..chunk], None)
        } else {
            crate::linux_socket::send_blocking(slot, &bytes[..chunk], None)
        };
        let sent = match result {
            Ok(sent) => sent,
            Err(error) => {
                return if total == 0 {
                    linux_socket_error(error)
                } else {
                    total as u64
                };
            }
        };
        total += sent;
        if sent < chunk {
            break;
        }
    }
    total as u64
}

fn linux_controller_pipe_ioctl(descriptor: u64, request: u64, output: u64) -> u64 {
    if request != LINUX_FIONREAD {
        return LINUX_ENOTTY;
    }
    let Some(slot) = linux_socket_slot(descriptor) else {
        return LINUX_EBADF;
    };
    let available = match crate::linux_socket::local_queued_bytes(slot) {
        Ok(available) => available.min(i32::MAX as usize) as u32,
        Err(error) => return linux_socket_error(error),
    };
    if !address_space::copy_to_current_user(output, &available.to_ne_bytes()) {
        return LINUX_EFAULT;
    }
    0
}
