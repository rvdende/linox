use super::*;

/// The caller as System V IPC checks it.
fn linux_ipc_caller() -> crate::linux_sysv_ipc::Caller {
    current_linux_credentials().map_or(
        crate::linux_sysv_ipc::Caller {
            uid: 0,
            gid: 0,
            privileged: true,
        },
        |credentials| crate::linux_sysv_ipc::Caller {
            uid: credentials.user.effective,
            gid: credentials.group.effective,
            privileged: credentials.privileged(),
        },
    )
}

/// Wall-clock seconds for IPC times.
fn linux_ipc_now() -> i64 {
    linux_realtime_time().map_or(0, |(seconds, _)| seconds as i64)
}

/// After a get: the first get of a new object makes the caller its owner
/// and creator; a get of an existing key needs the access its mode bits
/// ask for (EACCES: msgget02, semget02, shmget04).
fn linux_ipc_got(
    kind: crate::linux_sysv_ipc::Kind,
    result: Result<u32, crate::linux_sysv_ipc::Error>,
    key: i32,
    flags: u64,
) -> u64 {
    let id = match result {
        Ok(id) => id,
        Err(error) => return linux_sysv_ipc_error(error),
    };
    let caller = linux_ipc_caller();
    match crate::linux_sysv_ipc::adopt(kind, id, caller, linux_ipc_now()) {
        Ok(false) if key != 0 => {
            crate::linux_sysv_ipc::check_access(kind, id, caller, flags as u16 & 0o777)
                .map_or_else(linux_sysv_ipc_error, |()| u64::from(id))
        }
        _ => u64::from(id),
    }
}

/// Fills an `ipc_perm`'s owner fields and an object's times into a
/// `*id_ds` (times at `time_offsets`, 0 to leave one out).
fn linux_ipc_fill_header(
    output: &mut [u8],
    kind: crate::linux_sysv_ipc::Kind,
    id: u32,
    time_offsets: [usize; 3],
) {
    let Ok((owner, times)) = crate::linux_sysv_ipc::header(kind, id) else {
        return;
    };
    output[4..8].copy_from_slice(&owner.uid.to_ne_bytes());
    output[8..12].copy_from_slice(&owner.gid.to_ne_bytes());
    output[12..16].copy_from_slice(&owner.cuid.to_ne_bytes());
    output[16..20].copy_from_slice(&owner.cgid.to_ne_bytes());
    for (offset, time) in time_offsets.into_iter().zip(times) {
        if offset != 0 {
            output[offset..offset + 8].copy_from_slice(&time.to_ne_bytes());
        }
    }
}

fn linux_sysv_ipc_error(error: crate::linux_sysv_ipc::Error) -> u64 {
    match error {
        crate::linux_sysv_ipc::Error::Access => LINUX_EACCES,
        crate::linux_sysv_ipc::Error::Permission => LINUX_EPERM,
        crate::linux_sysv_ipc::Error::Exists => LINUX_EEXIST,
        crate::linux_sysv_ipc::Error::Invalid => LINUX_EINVAL,
        crate::linux_sysv_ipc::Error::NoEntry => LINUX_ENOENT,
        crate::linux_sysv_ipc::Error::NoMemory => LINUX_ENOMEM,
        crate::linux_sysv_ipc::Error::NoSpace => LINUX_ENOSPC,
        crate::linux_sysv_ipc::Error::Range => LINUX_ERANGE,
        crate::linux_sysv_ipc::Error::WouldBlock => LINUX_EAGAIN,
        crate::linux_sysv_ipc::Error::TooBig => LINUX_E2BIG,
        crate::linux_sysv_ipc::Error::Fault => LINUX_EFAULT,
        crate::linux_sysv_ipc::Error::Busy => LINUX_EBUSY,
    }
}

pub(super) fn linux_shmget(key: u64, size: u64, flags: u64) -> u64 {
    const IPC_CREAT: u64 = 0o1000;
    const IPC_EXCL: u64 = 0o2000;
    let flags = u64::from(flags as u32);
    if flags & !(0o777 | IPC_CREAT | IPC_EXCL | LINUX_SHM_HUGE_FLAGS) != 0 {
        return LINUX_EINVAL;
    }
    let key = key as u32 as i32;
    // A new segment of huge pages needs the caller's right to them and the
    // pool's pages (hugetlb_file_setup); an existing one is only found.
    let huge = flags & LINUX_SHM_HUGETLB != 0;
    if huge
        && (key == 0 || flags & IPC_CREAT != 0)
        && (key == 0
            || crate::linux_sysv_ipc::segments()
                .iter()
                .all(|(_, segment)| segment.key != key))
        && size >= 1
        && linux_proc_sysctl_value(b"sys/kernel/shmmax")
            .and_then(|largest| u64::try_from(largest).ok())
            .is_none_or(|largest| size <= largest)
    {
        if let Err(error) = linux_shm_huge_allowed(size, flags) {
            return error;
        }
    }
    let requested =
        linux_proc_sysctl_value(b"sys/kernel/shm_next_id").and_then(|id| u32::try_from(id).ok());
    let limit = linux_proc_sysctl_value(b"sys/kernel/shmmni")
        .and_then(|limit| usize::try_from(limit).ok())
        .unwrap_or(4096);
    let result = crate::linux_sysv_ipc::get_or_create(
        key,
        size,
        flags as u16,
        key == 0 || flags & IPC_CREAT != 0,
        flags & IPC_EXCL != 0,
        current_linux_process_pid(),
        crate::linux_sysv_ipc::SegmentIds {
            requested,
            limit,
            largest: linux_proc_sysctl_value(b"sys/kernel/shmmax")
                .and_then(|largest| u64::try_from(largest).ok())
                .unwrap_or(u64::MAX),
            huge,
        },
    );
    // shm_next_id is used up by the segment it named.
    if requested.is_some_and(|id| result == Ok(id)) {
        linux_proc_sysctl_set(b"sys/kernel/shm_next_id", -1);
    }
    linux_ipc_got(crate::linux_sysv_ipc::Kind::Segment, result, key, flags)
}

pub(super) fn linux_shmat(id: u64, requested: u64, flags: u64) -> u64 {
    const SHM_RDONLY: u64 = 0o10_000;
    const SHM_RND: u64 = 0o20_000;
    const SHM_REMAP: u64 = 0o40_000;
    const SHM_EXEC: u64 = 0o100_000;
    const SHMLBA: u64 = PAGE_SIZE as u64;
    let id = id as i32;
    let flags = u64::from(flags as u32);
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return LINUX_ENOSYS;
    }
    if id < 0
        || flags & !(SHM_RDONLY | SHM_RND | SHM_REMAP | SHM_EXEC) != 0
        || flags & SHM_REMAP != 0
    {
        return LINUX_EINVAL;
    }
    if flags & SHM_EXEC != 0 && flags & SHM_RDONLY == 0 {
        return LINUX_EACCES;
    }
    let Ok(segment) = crate::linux_sysv_ipc::segment(id as u32) else {
        return LINUX_EINVAL;
    };
    // Reading needs read permission, and writing write (shmat02).
    let wanted = if flags & SHM_RDONLY != 0 {
        0o444
    } else {
        0o666
    };
    if let Err(error) = crate::linux_sysv_ipc::check_access(
        crate::linux_sysv_ipc::Kind::Segment,
        id as u32,
        linux_ipc_caller(),
        wanted,
    ) {
        return linux_sysv_ipc_error(error);
    }
    let _ = crate::linux_sysv_ipc::stamp(
        crate::linux_sysv_ipc::Kind::Segment,
        id as u32,
        crate::linux_sysv_ipc::TIME_OPERATION,
        linux_ipc_now(),
    );
    let Ok(pages) = usize::try_from(segment.size.div_ceil(PAGE_SIZE as u64)) else {
        return LINUX_ENOMEM;
    };
    let requested = if requested != 0 && flags & SHM_RND != 0 {
        requested & !(SHMLBA - 1)
    } else {
        requested
    };
    if requested != 0 && !requested.is_multiple_of(SHMLBA) {
        return LINUX_EINVAL;
    }
    let Some(address) = linux_runtime_select_mapping(requested, pages, requested != 0, false)
    else {
        return LINUX_ENOMEM;
    };
    if !linux_runtime_range_available(address, pages) {
        return LINUX_EINVAL;
    }
    let protection = if flags & SHM_EXEC != 0 {
        5
    } else if flags & SHM_RDONLY != 0 {
        1
    } else {
        3
    };
    for index in 0..pages {
        let Ok(frame) = crate::linux_sysv_ipc::frame(id as u32, index) else {
            let _ = rollback_linux_runtime_mapping(address, index);
            return LINUX_EINVAL;
        };
        if !address_space::install_current_linux_shared_page(
            address + (index * PAGE_SIZE) as u64,
            frame,
            protection,
        ) {
            let _ = rollback_linux_runtime_mapping(address, index);
            return LINUX_ENOMEM;
        }
    }
    if let Err(error) =
        crate::linux_sysv_ipc::attach(id as u32, address, current_linux_process_pid())
    {
        let _ = rollback_linux_runtime_mapping(address, pages);
        return linux_sysv_ipc_error(error);
    }
    address
}

pub(super) fn linux_shmdt(address: u64) -> u64 {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || !address.is_multiple_of(PAGE_SIZE as u64)
    {
        return LINUX_EINVAL;
    }
    let Ok((id, length)) =
        crate::linux_sysv_ipc::attachment_at(address, current_linux_process_pid())
    else {
        return LINUX_EINVAL;
    };
    let result = linux_runtime_munmap(address, length);
    if result != 0 {
        return result;
    }
    let _ = crate::linux_sysv_ipc::stamp(
        crate::linux_sysv_ipc::Kind::Segment,
        id,
        crate::linux_sysv_ipc::TIME_DETACH,
        linux_ipc_now(),
    );
    crate::linux_sysv_ipc::detach(address, current_linux_process_pid())
        .map_or_else(linux_sysv_ipc_error, |()| 0)
}

pub(super) fn linux_shmctl(id: u64, command: u64, address: u64) -> u64 {
    const IPC_RMID: u64 = 0;
    const IPC_SET: u64 = 1;
    const IPC_STAT: u64 = 2;
    const IPC_64: u64 = 0x100;
    let id = id as i32;
    let command = u64::from(command as u32);
    if id < 0 || command & !(IPC_64 | 0xff) != 0 {
        return LINUX_EINVAL;
    }
    let kind = crate::linux_sysv_ipc::Kind::Segment;
    let caller = linux_ipc_caller();
    const IPC_INFO: u64 = 3;
    const SHM_LOCK: u64 = 11;
    const SHM_UNLOCK: u64 = 12;
    const SHM_STAT: u64 = 13;
    const SHM_INFO: u64 = 14;
    const SHM_STAT_ANY: u64 = 15;
    const SHM_LOCKED: u16 = 0o2000;
    match command & !IPC_64 {
        // The limits (shmctl03), or the use (SHM_INFO); both return the
        // highest id in use, which is its index here.
        IPC_INFO | SHM_INFO => {
            let segments = crate::linux_sysv_ipc::segments();
            let highest = segments.iter().map(|(id, _)| *id).max().unwrap_or(0);
            let mut output = [0_u8; 48];
            if command & !IPC_64 == IPC_INFO {
                let sysctl = |path: &[u8], default: u64| {
                    linux_proc_sysctl_value(path).map_or(default, |value| value as u64)
                };
                let values = [
                    sysctl(b"sys/kernel/shmmax", 18_446_744_073_692_774_399),
                    1,
                    sysctl(b"sys/kernel/shmmni", 4096),
                    4096,
                    sysctl(b"sys/kernel/shmall", 18_446_744_073_692_774_399),
                ];
                for (index, value) in values.into_iter().enumerate() {
                    output[index * 8..index * 8 + 8].copy_from_slice(&value.to_ne_bytes());
                }
            } else {
                let pages: u64 = segments
                    .iter()
                    .map(|(_, segment)| segment.size.div_ceil(PAGE_SIZE as u64))
                    .sum();
                // Resident and swapped pages as /proc/sysvipc/shm lists
                // them: none counted (shmctl04 sums the listing).
                output[0..4].copy_from_slice(&(segments.len() as u32).to_ne_bytes());
                output[8..16].copy_from_slice(&pages.to_ne_bytes());
            }
            if copy_to_linux_user(address, &output) {
                u64::from(highest)
            } else {
                LINUX_EFAULT
            }
        }
        // By index (the id here): IPC_STAT's buffer, and the id.
        SHM_STAT | SHM_STAT_ANY => {
            let stat = if command & !IPC_64 == SHM_STAT_ANY {
                LINUX_IPC_STAT_UNCHECKED
            } else {
                IPC_STAT
            };
            let result = linux_shmctl(id as u64, stat | IPC_64, address);
            if result == 0 {
                id as u64
            } else {
                result
            }
        }
        // Locking needs the owner, the creator or root (shmctl02, shmctl07).
        SHM_LOCK | SHM_UNLOCK => {
            if let Err(error) = crate::linux_sysv_ipc::check_owner(kind, id as u32, caller) {
                return linux_sysv_ipc_error(error);
            }
            let (set, clear) = if command & !IPC_64 == SHM_LOCK {
                (SHM_LOCKED, 0)
            } else {
                (0, SHM_LOCKED)
            };
            crate::linux_sysv_ipc::update_mode(kind, id as u32, set, clear)
                .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        IPC_RMID => crate::linux_sysv_ipc::check_owner(kind, id as u32, caller)
            .and_then(|()| {
                crate::linux_sysv_ipc::mark_for_removal(id as u32, current_linux_process_pid())
            })
            .map_or_else(linux_sysv_ipc_error, |()| 0),
        IPC_SET => {
            let mut input = [0_u8; 112];
            if !copy_from_linux_user(address, &mut input) {
                return LINUX_EFAULT;
            }
            if let Err(error) = crate::linux_sysv_ipc::check_owner(kind, id as u32, caller) {
                return linux_sysv_ipc_error(error);
            }
            let _ = crate::linux_sysv_ipc::set_owner(
                kind,
                id as u32,
                u32::from_ne_bytes(input[4..8].try_into().unwrap()),
                u32::from_ne_bytes(input[8..12].try_into().unwrap()),
                linux_ipc_now(),
            );
            crate::linux_sysv_ipc::set_mode(
                id as u32,
                u16::from_ne_bytes(input[20..22].try_into().unwrap()),
                current_linux_process_pid(),
            )
            .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        IPC_STAT | LINUX_IPC_STAT_UNCHECKED => {
            let Ok(segment) = crate::linux_sysv_ipc::segment(id as u32) else {
                return LINUX_EINVAL;
            };
            if command & !IPC_64 == IPC_STAT {
                if let Err(error) =
                    crate::linux_sysv_ipc::check_access(kind, id as u32, caller, 0o444)
                {
                    return linux_sysv_ipc_error(error);
                }
            }
            let mut output = [0_u8; 112];
            linux_ipc_fill_header(&mut output, kind, id as u32, [56, 64, 72]);
            output[0..4].copy_from_slice(&segment.key.to_ne_bytes());
            output[20..22].copy_from_slice(&segment.mode.to_ne_bytes());
            output[48..56].copy_from_slice(&segment.size.to_ne_bytes());
            output[80..84].copy_from_slice(&segment.creator_pid.to_ne_bytes());
            output[84..88].copy_from_slice(&segment.last_pid.to_ne_bytes());
            output[88..96].copy_from_slice(&segment.attachments.to_ne_bytes());
            if !copy_to_linux_user(address, &output) {
                LINUX_EFAULT
            } else {
                0
            }
        }
        _ => LINUX_EINVAL,
    }
}

pub(super) fn linux_semget(key: u64, count: u64, flags: u64) -> u64 {
    const IPC_CREAT: u64 = 0o1000;
    const IPC_EXCL: u64 = 0o2000;
    const LINUX_SEMMSL: u64 = 32_000;
    let count = count as i32;
    let flags = u64::from(flags as u32);
    if count < 0 || flags & !(0o777 | IPC_CREAT | IPC_EXCL) != 0 || count as u64 > LINUX_SEMMSL {
        return LINUX_EINVAL;
    }
    let key = key as u32 as i32;
    let result = crate::linux_sysv_ipc::semaphore_get_or_create(
        key,
        count as u64,
        flags as u16,
        key == 0 || flags & IPC_CREAT != 0,
        flags & IPC_EXCL != 0,
        current_linux_process_pid(),
    );
    linux_ipc_got(crate::linux_sysv_ipc::Kind::Semaphores, result, key, flags)
}

fn linux_semaphore_operation(
    address: u64,
    index: usize,
) -> Option<crate::linux_sysv_ipc::SemaphoreOperation> {
    let address = address.checked_add((index as u64).checked_mul(6)?)?;
    let mut bytes = [0_u8; 6];
    copy_from_linux_user(address, &mut bytes).then_some(crate::linux_sysv_ipc::SemaphoreOperation {
        number: u16::from_ne_bytes(bytes[0..2].try_into().ok()?),
        operation: i16::from_ne_bytes(bytes[2..4].try_into().ok()?),
        flags: u16::from_ne_bytes(bytes[4..6].try_into().ok()?),
    })
}

/// `semop` and `semtimedop`: applies the operations, or waits until they
/// can be applied, the timeout passes, a signal arrives or the set is
/// removed (EIDRM). The wait outlives the call's restarts (a process other
/// than init yields by restarting the call), so `GETNCNT`/`GETZCNT` see it
/// and a timeout counts from the first attempt.
pub(super) fn linux_semop_live(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    (id, operations, count, timeout): (u64, u64, u64, u64),
) -> u64 {
    let timeout = if timeout == 0 {
        None
    } else {
        let mut bytes = [0_u8; 16];
        if !copy_from_linux_user(timeout, &mut bytes) {
            return LINUX_EFAULT;
        }
        let Some(timeout) = linux_timespec_nanoseconds(&bytes) else {
            return LINUX_EINVAL;
        };
        Some(timeout)
    };
    let pid = current_linux_process_pid();
    loop {
        let earlier = crate::linux_sysv_ipc::semaphore_wait(pid)
            .filter(|wait| u64::from(wait.id) == id as u32 as u64);
        let block = match linux_semop(id, operations, count) {
            Ok(None) => {
                crate::linux_sysv_ipc::end_semaphore_wait(pid);
                return 0;
            }
            Err(error) => {
                crate::linux_sysv_ipc::end_semaphore_wait(pid);
                return if error == LINUX_EINVAL && earlier.is_some() {
                    LINUX_EIDRM
                } else {
                    error
                };
            }
            Ok(Some(block)) => block,
        };
        let now = linux_elapsed_nanoseconds().unwrap_or(0);
        let deadline = earlier.map_or_else(
            || timeout.map(|timeout| now.saturating_add(timeout)),
            |wait| wait.deadline,
        );
        if deadline.is_some_and(|deadline| now >= deadline) {
            crate::linux_sysv_ipc::end_semaphore_wait(pid);
            return LINUX_EAGAIN;
        }
        let wait = crate::linux_sysv_ipc::SemaphoreWait {
            pid,
            id: id as u32,
            block,
            deadline,
        };
        if crate::linux_sysv_ipc::begin_semaphore_wait(wait).is_err() {
            return LINUX_ENOMEM;
        }
        // Only semop, semctl and the set's removal change it: system calls.
        let wait = WaitOn::of(wait_events::STATE).until_some(deadline);
        match run_other_linux_processes(output, caller, number, wait) {
            Some(LinuxBlockedWait::Recheck) => {}
            // Yielded: the call starts again and finds its wait.
            Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL)) => {
                return LINUX_RETURN_TO_KERNEL;
            }
            Some(LinuxBlockedWait::Return(result)) => {
                crate::linux_sysv_ipc::end_semaphore_wait(pid);
                return result;
            }
            None => {
                crate::linux_sysv_ipc::end_semaphore_wait(pid);
                return LINUX_EINTR;
            }
        }
    }
}

/// Applies `semop`'s operations once: `Ok(None)` when applied,
/// `Ok(Some(block))` when the call has to wait.
pub(super) fn linux_semop(
    id: u64,
    operations: u64,
    count: u64,
) -> Result<Option<crate::linux_sysv_ipc::SemaphoreBlock>, u64> {
    const LINUX_SEMOPM: usize = 500;
    let id = id as i32;
    if id < 0 {
        return Err(LINUX_EINVAL);
    }
    let Ok(count) = usize::try_from(count) else {
        return Err(LINUX_E2BIG);
    };
    if count == 0 || count > LINUX_SEMOPM {
        return Err(if count > LINUX_SEMOPM {
            LINUX_E2BIG
        } else {
            LINUX_EINVAL
        });
    }
    // Unreadable operations are EFAULT, a semaphore past the set's EFBIG
    // (semop02), before anything is applied.
    let Ok(set) = crate::linux_sysv_ipc::semaphore_set(id as u32) else {
        return Err(LINUX_EINVAL);
    };
    for index in 0..count {
        let Some(operation) = linux_semaphore_operation(operations, index) else {
            return Err(LINUX_EFAULT);
        };
        if u64::from(operation.number) >= set.count {
            return Err(LINUX_EFBIG);
        }
    }
    // Any operation that changes a value needs write permission, waiting
    // for zero read.
    let alters = (0..count).any(|index| {
        linux_semaphore_operation(operations, index)
            .is_some_and(|operation| operation.operation != 0)
    });
    crate::linux_sysv_ipc::check_access(
        crate::linux_sysv_ipc::Kind::Semaphores,
        id as u32,
        linux_ipc_caller(),
        if alters { 0o222 } else { 0o444 },
    )
    .map_err(linux_sysv_ipc_error)?;
    let applied = crate::linux_sysv_ipc::semaphore_apply(
        id as u32,
        count,
        current_linux_process_pid(),
        |index| linux_semaphore_operation(operations, index),
    )
    .map_err(linux_sysv_ipc_error)?;
    if applied.is_none() {
        let _ = crate::linux_sysv_ipc::stamp(
            crate::linux_sysv_ipc::Kind::Semaphores,
            id as u32,
            crate::linux_sysv_ipc::TIME_OPERATION,
            linux_ipc_now(),
        );
    }
    Ok(applied)
}

pub(super) fn linux_semctl(id: u64, number: u64, command: u64, argument: u64) -> u64 {
    const IPC_RMID: u64 = 0;
    const IPC_SET: u64 = 1;
    const IPC_STAT: u64 = 2;
    const IPC_64: u64 = 0x100;
    const GETPID: u64 = 11;
    const GETVAL: u64 = 12;
    const GETALL: u64 = 13;
    const GETNCNT: u64 = 14;
    const GETZCNT: u64 = 15;
    const SETVAL: u64 = 16;
    const SETALL: u64 = 17;
    let id = id as i32;
    let number = number as i32;
    let command = u64::from(command as u32);
    if id < 0 || number < 0 || command & !(IPC_64 | 0xff) != 0 {
        return LINUX_EINVAL;
    }
    let id = id as u32;
    let number = number as usize;
    let kind = crate::linux_sysv_ipc::Kind::Semaphores;
    let caller = linux_ipc_caller();
    // Reading values needs read permission, changing them write
    // (semctl02, semctl04).
    let wanted = match command & !IPC_64 {
        IPC_STAT | GETPID | GETVAL | GETALL | GETNCNT | GETZCNT => Some(0o444),
        SETVAL | SETALL => Some(0o222),
        _ => None,
    };
    if let Some(wanted) = wanted {
        if let Err(error) = crate::linux_sysv_ipc::check_access(kind, id, caller, wanted) {
            return linux_sysv_ipc_error(error);
        }
    }
    if matches!(command & !IPC_64, IPC_RMID | IPC_SET) {
        if let Err(error) = crate::linux_sysv_ipc::check_owner(kind, id, caller) {
            return linux_sysv_ipc_error(error);
        }
    }
    if matches!(command & !IPC_64, SETVAL | SETALL) {
        let _ = crate::linux_sysv_ipc::stamp(
            kind,
            id,
            crate::linux_sysv_ipc::TIME_CHANGE,
            linux_ipc_now(),
        );
    }
    const IPC_INFO: u64 = 3;
    const SEM_STAT: u64 = 18;
    const SEM_INFO: u64 = 19;
    const SEM_STAT_ANY: u64 = 20;
    match command & !IPC_64 {
        // struct seminfo: the limits, or with SEM_INFO the sets and
        // semaphores in use; the highest id in use (semctl01, semop02).
        IPC_INFO | SEM_INFO => {
            let sets = crate::linux_sysv_ipc::semaphore_sets();
            let highest = sets.iter().map(|(id, _)| *id).max().unwrap_or(0);
            let (usz, aem) = if command & !IPC_64 == IPC_INFO {
                (20, 32_767)
            } else {
                (
                    sets.len() as i32,
                    sets.iter().map(|(_, set)| set.count as i32).sum::<i32>(),
                )
            };
            let values = [
                32_000,
                crate::linux_sysv_ipc::SEMAPHORE_SET_LIMIT as i32,
                1_024_000_000,
                32_000,
                32_000,
                500,
                500,
                usz,
                32_767,
                aem,
            ];
            let mut output = [0_u8; 40];
            for (index, value) in values.into_iter().enumerate() {
                output[index * 4..index * 4 + 4].copy_from_slice(&value.to_ne_bytes());
            }
            if copy_to_linux_user(argument, &output) {
                u64::from(highest)
            } else {
                LINUX_EFAULT
            }
        }
        SEM_STAT | SEM_STAT_ANY => {
            let stat = if command & !IPC_64 == SEM_STAT_ANY {
                LINUX_IPC_STAT_UNCHECKED
            } else {
                IPC_STAT
            };
            let result = linux_semctl(u64::from(id), number as u64, stat | IPC_64, argument);
            if result == 0 {
                u64::from(id)
            } else {
                result
            }
        }
        IPC_RMID => {
            crate::linux_sysv_ipc::semaphore_remove(id).map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        IPC_SET => {
            let mut input = [0_u8; 104];
            if !copy_from_linux_user(argument, &mut input) {
                return LINUX_EFAULT;
            }
            let _ = crate::linux_sysv_ipc::set_owner(
                kind,
                id,
                u32::from_ne_bytes(input[4..8].try_into().unwrap()),
                u32::from_ne_bytes(input[8..12].try_into().unwrap()),
                linux_ipc_now(),
            );
            crate::linux_sysv_ipc::semaphore_set_mode(
                id,
                u16::from_ne_bytes(input[20..22].try_into().unwrap()),
                current_linux_process_pid(),
            )
            .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        IPC_STAT | LINUX_IPC_STAT_UNCHECKED => {
            let Ok(set) = crate::linux_sysv_ipc::semaphore_set(id) else {
                return LINUX_EINVAL;
            };
            let mut output = [0_u8; 104];
            linux_ipc_fill_header(&mut output, kind, id, [48, 0, 64]);
            output[0..4].copy_from_slice(&set.key.to_ne_bytes());
            output[20..22].copy_from_slice(&set.mode.to_ne_bytes());
            output[80..88].copy_from_slice(&set.count.to_ne_bytes());
            if copy_to_linux_user(argument, &output) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        GETPID | GETVAL | GETNCNT | GETZCNT => {
            let Ok((value, pid, waiting_increase, waiting_zero)) =
                crate::linux_sysv_ipc::semaphore_get(id, number)
            else {
                return LINUX_EINVAL;
            };
            match command & !IPC_64 {
                GETPID => u64::from(pid),
                GETVAL => u64::from(value),
                GETNCNT => u64::from(waiting_increase),
                GETZCNT => u64::from(waiting_zero),
                _ => unreachable!(),
            }
        }
        SETVAL => {
            // The value is the union semun's int: Linux reads the low 32
            // bits of the argument (musl passes the whole union, whose
            // upper half is whatever the caller's stack held).
            let value = argument as u32 as i32;
            if value < 0 || value > i32::from(crate::linux_sysv_ipc::SEM_VALUE_MAX) {
                return LINUX_ERANGE;
            }
            crate::linux_sysv_ipc::semaphore_set_value(
                id,
                number,
                value as u16,
                current_linux_process_pid(),
            )
            .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        GETALL => {
            let Ok(set) = crate::linux_sysv_ipc::semaphore_set(id) else {
                return LINUX_EINVAL;
            };
            let Ok(count) = usize::try_from(set.count) else {
                return LINUX_EINVAL;
            };
            for index in 0..count {
                let Ok((value, _, _, _)) = crate::linux_sysv_ipc::semaphore_get(id, index) else {
                    return LINUX_EINVAL;
                };
                let Some(address) = argument.checked_add((index * 2) as u64) else {
                    return LINUX_EFAULT;
                };
                if !copy_to_linux_user(address, &value.to_ne_bytes()) {
                    return LINUX_EFAULT;
                }
            }
            0
        }
        SETALL => {
            crate::linux_sysv_ipc::semaphore_set_all(id, current_linux_process_pid(), |index| {
                let address = argument.checked_add((index * 2) as u64)?;
                let mut bytes = [0_u8; 2];
                copy_from_linux_user(address, &mut bytes).then_some(u16::from_ne_bytes(bytes))
            })
            .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        _ => LINUX_EINVAL,
    }
}

pub(super) fn linux_msgget(key: u64, flags: u64) -> u64 {
    const IPC_CREAT: u64 = 0o1000;
    const IPC_EXCL: u64 = 0o2000;
    let flags = u64::from(flags as u32);
    if flags & !(0o777 | IPC_CREAT | IPC_EXCL) != 0 {
        return LINUX_EINVAL;
    }
    let key = key as u32 as i32;
    let requested =
        linux_proc_sysctl_value(b"sys/kernel/msg_next_id").and_then(|id| u32::try_from(id).ok());
    let limit = linux_proc_sysctl_value(b"sys/kernel/msgmni")
        .and_then(|limit| usize::try_from(limit).ok())
        .unwrap_or(32_000);
    let result = crate::linux_sysv_ipc::message_get_or_create(
        key,
        flags as u16,
        key == 0 || flags & IPC_CREAT != 0,
        flags & IPC_EXCL != 0,
        requested,
        limit,
    );
    // msg_next_id is used up by the queue it named.
    if requested.is_some_and(|id| result == Ok(id)) {
        linux_proc_sysctl_set(b"sys/kernel/msg_next_id", -1);
    }
    linux_ipc_got(crate::linux_sysv_ipc::Kind::Messages, result, key, flags)
}

/// msgsnd and msgrcv: `attempt` runs the call once. Without IPC_NOWAIT a
/// full queue or a missing message waits until the call completes, a signal
/// arrives (EINTR: neither call restarts after an SA_RESTART handler) or the
/// queue is removed (EIDRM); with it msgsnd fails with EAGAIN and msgrcv
/// with ENOMSG. The wait outlives the call's restarts, so a removal is seen
/// as one.
pub(super) fn linux_message_wait_live(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    (id, flags): (u64, u64),
    mut attempt: impl FnMut() -> u64,
) -> u64 {
    const IPC_NOWAIT: u64 = 0o4000;
    let pid = current_linux_process_pid();
    loop {
        let waited = crate::linux_sysv_ipc::message_wait(pid) == Some(id as u32);
        let result = attempt();
        if result != LINUX_EAGAIN {
            crate::linux_sysv_ipc::end_message_wait(pid);
            return if result == LINUX_EINVAL && waited {
                LINUX_EIDRM
            } else {
                result
            };
        }
        if flags & IPC_NOWAIT != 0 {
            crate::linux_sysv_ipc::end_message_wait(pid);
            return if number == LINUX_MSGRCV_SYSCALL {
                LINUX_ENOMSG
            } else {
                LINUX_EAGAIN
            };
        }
        if crate::linux_sysv_ipc::begin_message_wait(pid, id as u32).is_err() {
            return LINUX_ENOMEM;
        }
        let wait = WaitOn::of(wait_events::STATE);
        match run_other_linux_processes(output, caller, number, wait) {
            Some(LinuxBlockedWait::Recheck) => {}
            // Yielded: the call starts again and finds its wait.
            Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL)) => {
                return LINUX_RETURN_TO_KERNEL;
            }
            Some(LinuxBlockedWait::Return(result)) => {
                crate::linux_sysv_ipc::end_message_wait(pid);
                return result;
            }
            None => {
                crate::linux_sysv_ipc::end_message_wait(pid);
                return LINUX_EINTR;
            }
        }
    }
}

pub(super) fn linux_msgsnd(id: u64, message: u64, size: u64, flags: u64) -> u64 {
    const IPC_NOWAIT: u64 = 0o4000;
    const LINUX_MSGMAX: usize = 8192;
    let id = id as i32;
    let flags = u64::from(flags as u32);
    if id < 0 || flags & !IPC_NOWAIT != 0 {
        return LINUX_EINVAL;
    }
    let Ok(size) = usize::try_from(size) else {
        return LINUX_EINVAL;
    };
    if size > LINUX_MSGMAX {
        return LINUX_EINVAL;
    }
    if let Err(error) = crate::linux_sysv_ipc::check_access(
        crate::linux_sysv_ipc::Kind::Messages,
        id as u32,
        linux_ipc_caller(),
        0o222,
    ) {
        return linux_sysv_ipc_error(error);
    }
    let mut message_type = [0_u8; 8];
    if !copy_from_linux_user(message, &mut message_type) {
        return LINUX_EFAULT;
    }
    let sent = crate::linux_sysv_ipc::message_send(
        id as u32,
        i64::from_ne_bytes(message_type),
        size,
        current_linux_process_pid(),
        |offset, output| {
            message
                .checked_add(8)
                .and_then(|address| address.checked_add(offset as u64))
                .is_some_and(|address| copy_from_linux_user(address, output))
        },
    );
    if sent.is_ok() {
        let _ = crate::linux_sysv_ipc::stamp(
            crate::linux_sysv_ipc::Kind::Messages,
            id as u32,
            crate::linux_sysv_ipc::TIME_OPERATION,
            linux_ipc_now(),
        );
    }
    sent.map_or_else(linux_sysv_ipc_error, |()| 0)
}

pub(super) fn linux_msgrcv(id: u64, message: u64, size: u64, selector: u64, flags: u64) -> u64 {
    const IPC_NOWAIT: u64 = 0o4000;
    const MSG_NOERROR: u64 = 0o10_000;
    const MSG_EXCEPT: u64 = 0o20_000;
    const MSG_COPY: u64 = 0o40_000;
    let id = id as i32;
    let flags = u64::from(flags as u32);
    if id < 0
        || flags & !(IPC_NOWAIT | MSG_NOERROR | MSG_EXCEPT | MSG_COPY) != 0
        || flags & MSG_COPY != 0
            && (flags & IPC_NOWAIT == 0 || flags & MSG_EXCEPT != 0 || (selector as i64) < 0)
    {
        return LINUX_EINVAL;
    }
    // MSG_EXCEPT only changes a positive type's search, as in Linux: a
    // negative one still takes the lowest type up to it (msgrcv02).
    let except = flags & MSG_EXCEPT != 0 && (selector as i64) > 0;
    // A negative size (as a long) is EINVAL (msgrcv02).
    if (size as i64) < 0 {
        return LINUX_EINVAL;
    }
    let Ok(size) = usize::try_from(size) else {
        return LINUX_EINVAL;
    };
    if let Err(error) = crate::linux_sysv_ipc::check_access(
        crate::linux_sysv_ipc::Kind::Messages,
        id as u32,
        linux_ipc_caller(),
        0o444,
    ) {
        return linux_sysv_ipc_error(error);
    }
    let received = crate::linux_sysv_ipc::message_receive(
        id as u32,
        size,
        selector as i64,
        flags & MSG_NOERROR != 0,
        except,
        flags & MSG_COPY != 0,
        current_linux_process_pid(),
        |message_type, offset, bytes| {
            (offset != 0 || copy_to_linux_user(message, &message_type.to_ne_bytes()))
                && message
                    .checked_add(8)
                    .and_then(|address| address.checked_add(offset as u64))
                    .is_some_and(|address| copy_to_linux_user(address, bytes))
        },
    );
    if received.is_ok() && flags & MSG_COPY == 0 {
        let _ = crate::linux_sysv_ipc::stamp(
            crate::linux_sysv_ipc::Kind::Messages,
            id as u32,
            crate::linux_sysv_ipc::TIME_RECEIVE,
            linux_ipc_now(),
        );
    }
    received.map_or_else(linux_sysv_ipc_error, |size| size as u64)
}

pub(super) fn linux_msgctl(id: u64, command: u64, address: u64) -> u64 {
    const IPC_RMID: u64 = 0;
    const IPC_SET: u64 = 1;
    const IPC_STAT: u64 = 2;
    const IPC_64: u64 = 0x100;
    let id = id as i32;
    let command = u64::from(command as u32);
    if id < 0 || command & !(IPC_64 | 0xff) != 0 {
        return LINUX_EINVAL;
    }
    let id = id as u32;
    let kind = crate::linux_sysv_ipc::Kind::Messages;
    let caller = linux_ipc_caller();
    const IPC_INFO: u64 = 3;
    const MSG_STAT: u64 = 11;
    const MSG_INFO: u64 = 12;
    const MSG_STAT_ANY: u64 = 13;
    match command & !IPC_64 {
        // struct msginfo: the limits, or with MSG_INFO the queues, messages
        // and bytes in use; the highest id in use, its index (msgctl12).
        IPC_INFO | MSG_INFO => {
            let queues = crate::linux_sysv_ipc::message_queues();
            let highest = queues.iter().map(|(id, _)| *id).max().unwrap_or(0);
            let msgmni =
                linux_proc_sysctl_value(b"sys/kernel/msgmni").map_or(32_000, |value| value as i32);
            let (pool, map, tql) = if command & !IPC_64 == IPC_INFO {
                (msgmni.saturating_mul(16), 16_384, 16_384)
            } else {
                (
                    queues.len() as i32,
                    queues
                        .iter()
                        .map(|(_, queue)| queue.messages as i32)
                        .sum::<i32>(),
                    queues
                        .iter()
                        .map(|(_, queue)| queue.bytes as i32)
                        .sum::<i32>(),
                )
            };
            let mut output = [0_u8; 32];
            for (index, value) in [pool, map, 8192, 16_384, msgmni, 16, tql]
                .into_iter()
                .enumerate()
            {
                output[index * 4..index * 4 + 4].copy_from_slice(&value.to_ne_bytes());
            }
            output[28..30].copy_from_slice(&u16::MAX.to_ne_bytes());
            if copy_to_linux_user(address, &output) {
                u64::from(highest)
            } else {
                LINUX_EFAULT
            }
        }
        MSG_STAT | MSG_STAT_ANY => {
            let stat = if command & !IPC_64 == MSG_STAT_ANY {
                LINUX_IPC_STAT_UNCHECKED
            } else {
                IPC_STAT
            };
            let result = linux_msgctl(u64::from(id), stat | IPC_64, address);
            if result == 0 {
                u64::from(id)
            } else {
                result
            }
        }
        IPC_RMID => crate::linux_sysv_ipc::check_owner(kind, id, caller)
            .and_then(|()| crate::linux_sysv_ipc::message_queue_remove(id))
            .map_or_else(linux_sysv_ipc_error, |()| 0),
        IPC_SET => {
            let mut input = [0_u8; 120];
            if !copy_from_linux_user(address, &mut input) {
                return LINUX_EFAULT;
            }
            if let Err(error) = crate::linux_sysv_ipc::check_owner(kind, id, caller) {
                return linux_sysv_ipc_error(error);
            }
            let _ = crate::linux_sysv_ipc::set_owner(
                kind,
                id,
                u32::from_ne_bytes(input[4..8].try_into().unwrap()),
                u32::from_ne_bytes(input[8..12].try_into().unwrap()),
                linux_ipc_now(),
            );
            crate::linux_sysv_ipc::message_queue_set(
                id,
                u16::from_ne_bytes(input[20..22].try_into().unwrap()),
                u64::from_ne_bytes(input[88..96].try_into().unwrap()),
            )
            .map_or_else(linux_sysv_ipc_error, |()| 0)
        }
        IPC_STAT | LINUX_IPC_STAT_UNCHECKED => {
            let Ok(queue) = crate::linux_sysv_ipc::message_queue_info(id) else {
                return LINUX_EINVAL;
            };
            if command & !IPC_64 == IPC_STAT {
                if let Err(error) = crate::linux_sysv_ipc::check_access(kind, id, caller, 0o444) {
                    return linux_sysv_ipc_error(error);
                }
            }
            let mut output = [0_u8; 120];
            linux_ipc_fill_header(&mut output, kind, id, [48, 56, 64]);
            output[0..4].copy_from_slice(&queue.key.to_ne_bytes());
            output[20..22].copy_from_slice(&queue.mode.to_ne_bytes());
            output[72..80].copy_from_slice(&queue.bytes.to_ne_bytes());
            output[80..88].copy_from_slice(&queue.messages.to_ne_bytes());
            output[88..96].copy_from_slice(&queue.byte_limit.to_ne_bytes());
            output[96..100].copy_from_slice(&queue.last_sender.to_ne_bytes());
            output[100..104].copy_from_slice(&queue.last_receiver.to_ne_bytes());
            if copy_to_linux_user(address, &output) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        _ => LINUX_EINVAL,
    }
}

/// A message queue's name as the kernel receives it: the C library drops
/// the leading slash, so what remains is one path component of at most
/// NAME_MAX bytes (ENAMETOOLONG); a slash, ".", or ".." is EACCES, as a
/// lookup in Linux's mqueue filesystem answers.
fn linux_mq_name(address: u64, output: &mut [u8; 256]) -> Result<usize, u64> {
    let length = copy_linux_c_string(address, output)?;
    let name = &output[..length];
    // Linux finds no entry for an empty name (ENOENT); glibc reports EINVAL
    // before asking, and musl does not check, so programs see EINVAL here.
    if name.is_empty() {
        return Err(LINUX_EINVAL);
    }
    if name.contains(&b'/') || name == b"." || name == b".." {
        return Err(LINUX_EACCES);
    }
    Ok(length)
}

pub(super) fn linux_mq_descriptor_id(descriptor: u64) -> Option<u32> {
    (linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_POSIX_MQ)
        .then(|| u32::try_from(linux_descriptor_offset(descriptor).load(Ordering::SeqCst)).ok())
        .flatten()
}

const LINUX_MQ_PRIO_MAX: u64 = 32_768;
pub(super) const LINUX_MSG_MSG_SIZE: u64 = 48;
pub(super) const LINUX_POSIX_MSG_TREE_NODE_SIZE: u64 = 48;

fn linux_posix_queue_charge(info: crate::linux_sysv_ipc::PosixQueueInfo) -> Option<u64> {
    info.max_messages
        .checked_mul(info.max_message_size)?
        .checked_add(info.max_messages.checked_mul(LINUX_MSG_MSG_SIZE)?)?
        .checked_add(
            info.max_messages
                .min(LINUX_MQ_PRIO_MAX)
                .checked_mul(LINUX_POSIX_MSG_TREE_NODE_SIZE)?,
        )
}

fn linux_reserve_posix_queue_charge(info: crate::linux_sysv_ipc::PosixQueueInfo) -> bool {
    let Some(charge) = linux_posix_queue_charge(info) else {
        return false;
    };
    let limit = linux_resource_limit_values(
        LINUX_RLIMIT_MSGQUEUE,
        X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
    )
    .map_or(0, |values| values[0]);
    let mut used = X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::Acquire);
    loop {
        let Some(next) = used.checked_add(charge).filter(|next| *next <= limit) else {
            return false;
        };
        match X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.compare_exchange(
            used,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(current) => used = current,
        }
    }
}

pub(super) fn linux_release_posix_queue_charge(
    destroyed: Option<crate::linux_sysv_ipc::PosixQueueInfo>,
) -> bool {
    let Some(info) = destroyed else {
        return true;
    };
    let Some(charge) = linux_posix_queue_charge(info) else {
        return false;
    };
    let mut used = X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.load(Ordering::Acquire);
    loop {
        let Some(next) = used.checked_sub(charge) else {
            return false;
        };
        match X86_RUNTIME.ELF_PROBE_POSIX_MQ_BYTES.compare_exchange(
            used,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(current) => used = current,
        }
    }
}

pub(super) fn linux_mq_open(name_address: u64, flags: u64, mode: u64, attributes: u64) -> u64 {
    let flags = u64::from(flags as u32);
    let mode = u64::from(mode as u32);
    let valid = 3 | LINUX_O_CREAT | LINUX_O_EXCL | LINUX_O_NONBLOCK | LINUX_O_CLOEXEC;
    if flags & !valid != 0
        || flags & 3 == 3
        || flags & LINUX_O_EXCL != 0 && flags & LINUX_O_CREAT == 0
    {
        return LINUX_EINVAL;
    }
    let mut name = [0_u8; 256];
    let length = match linux_mq_name(name_address, &mut name) {
        Ok(length) => length,
        Err(error) => return error,
    };
    // Linux's hard ceilings (HARD_MSGMAX, HARD_MSGSIZEMAX); below them an
    // unprivileged creator is held to /proc/sys/fs/mqueue's msg_max and
    // msgsize_max, and to queues_max queues.
    const HARD_MESSAGES: i64 = 65_536;
    const HARD_MESSAGE_SIZE: i64 = 16 * 1024 * 1024;
    let resource_privileged = current_linux_credentials()
        .is_some_and(|credentials| credentials.has(linox_credentials::capability::SYS_RESOURCE));
    let (max_messages, max_message_size) = if flags & LINUX_O_CREAT != 0 && attributes != 0 {
        let mut attr = [0_u8; 64];
        if !copy_from_linux_user(attributes, &mut attr) {
            return LINUX_EFAULT;
        }
        let max_messages = i64::from_ne_bytes(attr[8..16].try_into().unwrap());
        let max_message_size = i64::from_ne_bytes(attr[16..24].try_into().unwrap());
        let over_soft = max_messages > linux_mq_limit(b"sys/fs/mqueue/msg_max") as i64
            || max_message_size > linux_mq_limit(b"sys/fs/mqueue/msgsize_max") as i64;
        if max_messages <= 0
            || max_message_size <= 0
            || max_messages > HARD_MESSAGES
            || max_message_size > HARD_MESSAGE_SIZE
            || over_soft && !resource_privileged
        {
            return LINUX_EINVAL;
        }
        (max_messages as u32, max_message_size as u32)
    } else {
        (
            linux_mq_limit(b"sys/fs/mqueue/msg_default") as u32,
            linux_mq_limit(b"sys/fs/mqueue/msgsize_default") as u32,
        )
    };
    let requested = match flags & 3 {
        0 => 0o444,
        1 => 0o222,
        _ => 0o666,
    };
    let queues_limit =
        (!resource_privileged).then(|| linux_mq_limit(b"sys/fs/mqueue/queues_max") as usize);
    let info = match crate::linux_sysv_ipc::posix_queue_open(
        &name[..length],
        flags & LINUX_O_CREAT != 0,
        flags & LINUX_O_EXCL != 0,
        mode as u16 & !(X86_RUNTIME.ELF_PROBE_UMASK.load(Ordering::SeqCst) as u16),
        (max_messages, max_message_size),
        linux_ipc_caller(),
        requested,
        queues_limit,
    ) {
        Ok(info) => info,
        Err(error) => return linux_sysv_ipc_error(error),
    };
    if info.created && !linux_reserve_posix_queue_charge(info) {
        let unlinked = matches!(
            crate::linux_sysv_ipc::posix_queue_unlink(&name[..length]),
            Ok(None)
        );
        let destroyed = matches!(
            crate::linux_sysv_ipc::posix_queue_close(info.id),
            Ok(Some(_))
        );
        return if unlinked && destroyed {
            LINUX_EMFILE
        } else {
            LINUX_EIO
        };
    }
    let Ok(descriptor) = linux_allocate_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        if info.created {
            let _ = crate::linux_sysv_ipc::posix_queue_unlink(&name[..length]);
        }
        let closed = crate::linux_sysv_ipc::posix_queue_close(info.id)
            .ok()
            .is_some_and(linux_release_posix_queue_charge);
        if info.created && !closed {
            return LINUX_EIO;
        }
        return LINUX_EMFILE;
    };
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device)
        .store(LINUX_DEVICE_POSIX_MQ | flags as u16 & 3, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags)
        .store((flags & LINUX_O_NONBLOCK) as u32, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(u64::from(info.id), Ordering::SeqCst);
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    descriptor
}

pub(super) fn linux_mq_unlink(name_address: u64) -> u64 {
    let mut name = [0_u8; 256];
    let length = match linux_mq_name(name_address, &mut name) {
        Ok(length) => length,
        Err(error) => return error,
    };
    match crate::linux_sysv_ipc::posix_queue_unlink_by(&name[..length], linux_ipc_caller()) {
        Ok(destroyed) if linux_release_posix_queue_charge(destroyed) => 0,
        Ok(_) => LINUX_EIO,
        Err(error) => linux_sysv_ipc_error(error),
    }
}

/// A /proc/sys/fs/mqueue value: as the domain wrote it, else the default.
fn linux_mq_limit(path: &[u8]) -> u64 {
    linux_proc_sysctl_value(path)
        .and_then(|value| u64::try_from(value).ok())
        .or_else(|| {
            let (_, _, contents) = LINUX_PROC_SYSCTLS
                .iter()
                .find(|(_, name, _)| *name == path)?;
            core::str::from_utf8(contents).ok()?.trim().parse().ok()
        })
        .unwrap_or(0)
}

/// An mq_timedsend or mq_timedreceive timeout: an absolute CLOCK_REALTIME
/// time, in nanoseconds; None waits for ever.
fn linux_mq_timeout(address: u64) -> Result<Option<u64>, u64> {
    if address == 0 {
        return Ok(None);
    }
    let mut timeout = [0_u8; 16];
    if !copy_from_linux_user(address, &mut timeout) {
        return Err(LINUX_EFAULT);
    }
    linux_timespec_nanoseconds(&timeout)
        .map(Some)
        .ok_or(LINUX_EINVAL)
}

/// The domain's CLOCK_REALTIME in nanoseconds.
fn linux_mq_now() -> u64 {
    linux_realtime_time().map_or(0, |(seconds, nanoseconds)| {
        seconds
            .saturating_mul(NANOSECONDS_PER_SECOND)
            .saturating_add(nanoseconds)
    })
}

/// mq_timedsend and mq_timedreceive: `attempt` once, then, while the
/// queue is full (or empty) and the descriptor blocks, let the rest of
/// the domain run and try again, until the absolute `timeout` passes
/// (ETIMEDOUT) or a signal comes (EINTR).
pub(super) fn linux_mq_wait_live(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    (descriptor, timeout): (u64, u64),
    mut attempt: impl FnMut() -> u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let Some(id) = linux_mq_descriptor_id(descriptor) else {
        return attempt();
    };
    let deadline = match linux_mq_timeout(timeout) {
        Ok(deadline) => deadline,
        Err(error) => return error,
    };
    let receiving = number == LINUX_MQ_TIMEDRECEIVE_SYSCALL;
    let waited = if receiving {
        id | crate::linux_sysv_ipc::RECEIVE_WAIT
    } else {
        id
    };
    let pid = current_linux_process_pid();
    loop {
        let result = attempt();
        let nonblocking =
            linux_socket_flags(descriptor).unwrap_or(0) & LINUX_O_NONBLOCK as u32 != 0;
        if result != LINUX_EAGAIN || nonblocking {
            crate::linux_sysv_ipc::end_message_wait(pid);
            return result;
        }
        if deadline.is_some_and(|deadline| linux_mq_now() >= deadline) {
            crate::linux_sysv_ipc::end_message_wait(pid);
            return LINUX_ETIMEDOUT;
        }
        if crate::linux_sysv_ipc::begin_message_wait(pid, waited).is_err() {
            return LINUX_ENOMEM;
        }
        // The timeout is on CLOCK_REALTIME: its deadline on the monotonic
        // clock is recomputed each time the call looks (setting the clock is
        // a state change, which wakes it).
        let wait = WaitOn::of(wait_events::STATE).until_some(deadline.and_then(|deadline| {
            let left = deadline.saturating_sub(linux_mq_now());
            linux_elapsed_nanoseconds().map(|now| now.saturating_add(left.max(1)))
        }));
        match run_other_linux_processes(output, caller, number, wait) {
            Some(LinuxBlockedWait::Recheck) => {}
            // Yielded: the call starts again and finds its wait.
            Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL)) => {
                return LINUX_RETURN_TO_KERNEL;
            }
            Some(LinuxBlockedWait::Return(result)) => {
                crate::linux_sysv_ipc::end_message_wait(pid);
                return result;
            }
            None => {
                crate::linux_sysv_ipc::end_message_wait(pid);
                return LINUX_EINTR;
            }
        }
    }
}

pub(super) fn linux_mq_timedsend(
    descriptor: u64,
    message: u64,
    length: u64,
    priority: u64,
    timeout: u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let priority = u64::from(priority as u32);
    let Some(id) = linux_mq_descriptor_id(descriptor) else {
        return LINUX_EBADF;
    };
    if linux_device_descriptor(descriptor) & 3 == 0 {
        return LINUX_EBADF;
    }
    if priority >= 32_768 {
        return LINUX_EINVAL;
    }
    let _ = timeout;
    let Ok(info) = crate::linux_sysv_ipc::posix_queue_info(id) else {
        return LINUX_EBADF;
    };
    if length > info.max_message_size || info.messages >= info.max_messages {
        return if length > info.max_message_size {
            LINUX_EMSGSIZE
        } else {
            LINUX_EAGAIN
        };
    }
    let Ok(length_usize) = usize::try_from(length) else {
        return LINUX_EMSGSIZE;
    };
    if let Err(error) = crate::linux_sysv_ipc::message_send(
        id,
        (32_768 - priority) as i64,
        length_usize,
        current_linux_process_pid(),
        |offset, output| {
            // An empty message reads nothing (mq_timedsend01).
            output.is_empty()
                || message
                    .checked_add(offset as u64)
                    .is_some_and(|address| copy_from_linux_user(address, output))
        },
    ) {
        return linux_sysv_ipc_error(error);
    }
    // A message reaching an empty queue that no receiver waits on tells the
    // process registered with mq_notify, once (SI_MESGQ, from the sender).
    let waiting = crate::linux_sysv_ipc::posix_queue_receiver_waiting(id);
    if let Some(registration) = crate::linux_sysv_ipc::posix_queue_take_notification(id, waiting) {
        linux_mq_finish_registration(registration, true);
    }
    0
}

/// Ends an mq_notify registration: notified (a message came) or removed.
/// SIGEV_SIGNAL sends its signal when notified (SI_MESGQ, from the
/// sender); SIGEV_THREAD sends its cookie on its netlink socket with the
/// last byte NOTIFY_WOKENUP or NOTIFY_REMOVED, as Linux does, and lets go
/// of the socket.
pub(super) fn linux_mq_finish_registration(
    registration: crate::linux_sysv_ipc::Registration,
    notified: bool,
) {
    const SI_MESGQ: i32 = -3;
    const NOTIFY_WOKENUP: u8 = 1;
    const NOTIFY_REMOVED: u8 = 2;
    match registration.notification {
        crate::linux_sysv_ipc::Notification::Signal { signal, value } if notified => {
            let _ = linux_queue_process_signal(
                registration.pid,
                u64::from(signal),
                SI_MESGQ,
                Some(value),
            );
        }
        crate::linux_sysv_ipc::Notification::Thread { socket, mut cookie } => {
            cookie[31] = if notified {
                NOTIFY_WOKENUP
            } else {
                NOTIFY_REMOVED
            };
            let _ = crate::linux_socket::deliver_netlink(socket, &cookie);
            let _ = crate::linux_socket::close(socket);
        }
        _ => {}
    }
}

pub(super) fn linux_mq_timedreceive(
    descriptor: u64,
    message: u64,
    length: u64,
    priority: u64,
    timeout: u64,
) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let Some(id) = linux_mq_descriptor_id(descriptor) else {
        return LINUX_EBADF;
    };
    if linux_device_descriptor(descriptor) & 3 == 1 {
        return LINUX_EBADF;
    }
    let _ = timeout;
    let Ok(info) = crate::linux_sysv_ipc::posix_queue_info(id) else {
        return LINUX_EBADF;
    };
    if length < info.max_message_size {
        return LINUX_EMSGSIZE;
    }
    let Ok(length) = usize::try_from(length) else {
        return LINUX_EMSGSIZE;
    };
    crate::linux_sysv_ipc::message_receive(
        id,
        length,
        -32_768,
        false,
        false,
        false,
        current_linux_process_pid(),
        |kind, offset, bytes| {
            let priority_written = priority == 0
                || offset != 0
                || copy_to_linux_user(priority, &((32_768 - kind) as u32).to_ne_bytes());
            priority_written
                && (bytes.is_empty()
                    || message
                        .checked_add(offset as u64)
                        .is_some_and(|address| copy_to_linux_user(address, bytes)))
        },
    )
    .map_or_else(linux_sysv_ipc_error, |size| size as u64)
}

/// mq_notify: SIGEV_NONE, SIGEV_SIGNAL or SIGEV_THREAD registers the
/// caller for the queue's next message to an empty queue (EBUSY while
/// another process holds it), a null event removes its registration. The
/// event is checked before the descriptor, as Linux does. SIGEV_THREAD
/// names a netlink socket (sigev_signo) and a 32-byte cookie (sigev_value
/// points at it), which the C library's helper thread reads back.
pub(super) fn linux_mq_notify(descriptor: u64, event: u64) -> u64 {
    const SIGEV_SIGNAL: i32 = 0;
    const SIGEV_NONE: i32 = 1;
    const SIGEV_THREAD: i32 = 2;
    let descriptor = u64::from(descriptor as u32);
    let notification = if event == 0 {
        None
    } else {
        let mut value = [0_u8; 16];
        if !copy_from_linux_user(event, &mut value) {
            return LINUX_EFAULT;
        }
        let signal = i32::from_ne_bytes(value[8..12].try_into().unwrap());
        match i32::from_ne_bytes(value[12..16].try_into().unwrap()) {
            SIGEV_NONE => Some(crate::linux_sysv_ipc::Notification::Quiet),
            SIGEV_SIGNAL if (1..=LINUX_SIGNAL_COUNT as i32).contains(&signal) => {
                Some(crate::linux_sysv_ipc::Notification::Signal {
                    signal: signal as u8,
                    value: u64::from_ne_bytes(value[..8].try_into().unwrap()),
                })
            }
            SIGEV_THREAD => {
                let mut cookie = [0_u8; 32];
                let cookie_address = u64::from_ne_bytes(value[..8].try_into().unwrap());
                if !copy_from_linux_user(cookie_address, &mut cookie) {
                    return LINUX_EFAULT;
                }
                let socket_descriptor = u64::from(signal as u32);
                let Some(socket) = linux_socket_slot(socket_descriptor) else {
                    return linux_not_socket_error(socket_descriptor);
                };
                if crate::linux_socket::kind(socket) != Some(crate::linux_socket::Kind::Netlink) {
                    return LINUX_ECONNREFUSED;
                }
                Some(crate::linux_sysv_ipc::Notification::Thread { socket, cookie })
            }
            _ => return LINUX_EINVAL,
        }
    };
    let Some(id) = linux_mq_descriptor_id(descriptor) else {
        return LINUX_EBADF;
    };
    // The registration holds a reference to its socket until it ends.
    if let Some(crate::linux_sysv_ipc::Notification::Thread { socket, .. }) = notification {
        if !crate::linux_socket::duplicate(socket) {
            return LINUX_ENOMEM;
        }
    }
    match crate::linux_sysv_ipc::posix_queue_set_notification(
        id,
        current_linux_process_pid(),
        notification,
    ) {
        Ok(removed) => {
            if let Some(removed) = removed {
                linux_mq_finish_registration(removed, false);
            }
            0
        }
        Err(error) => {
            if let Some(crate::linux_sysv_ipc::Notification::Thread { socket, .. }) = notification {
                let _ = crate::linux_socket::close(socket);
            }
            linux_sysv_ipc_error(error)
        }
    }
}

pub(super) fn linux_mq_getsetattr(descriptor: u64, new: u64, old: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    let Some(id) = linux_mq_descriptor_id(descriptor) else {
        return LINUX_EBADF;
    };
    let Ok(info) = crate::linux_sysv_ipc::posix_queue_info(id) else {
        return LINUX_EBADF;
    };
    let flags = linux_socket_flags(descriptor).unwrap_or(0) & LINUX_O_NONBLOCK as u32;
    if old != 0 {
        let mut attr = [0_u8; 64];
        attr[..8].copy_from_slice(&u64::from(flags).to_ne_bytes());
        attr[8..16].copy_from_slice(&info.max_messages.to_ne_bytes());
        attr[16..24].copy_from_slice(&info.max_message_size.to_ne_bytes());
        attr[24..32].copy_from_slice(&info.messages.to_ne_bytes());
        if !copy_to_linux_user(old, &attr) {
            return LINUX_EFAULT;
        }
    }
    if new != 0 {
        let mut attr = [0_u8; 64];
        if !copy_from_linux_user(new, &mut attr) {
            return LINUX_EFAULT;
        }
        let requested = u64::from_ne_bytes(attr[..8].try_into().unwrap());
        if requested & !LINUX_O_NONBLOCK != 0 {
            return LINUX_EINVAL;
        }
        linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags)
            .store(requested as u32, Ordering::SeqCst);
    }
    0
}
