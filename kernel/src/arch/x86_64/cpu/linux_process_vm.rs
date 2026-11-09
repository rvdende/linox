#![forbid(unsafe_code)]

use super::*;

pub(super) fn linux_process_vm_iov(
    pid: u64,
    local_vectors: u64,
    local_count: u64,
    remote_vectors: u64,
    remote_count: u64,
    flags: u64,
    write_remote: bool,
) -> u64 {
    let pid = pid as i32;
    if flags != 0 {
        return LINUX_EINVAL;
    }
    if pid <= 0 {
        return LINUX_ESRCH;
    }
    let pid = pid as u32;
    let current = pid == current_linux_process_pid();
    if !current {
        let Some(status) = linux_process::live_process_status(pid) else {
            return LINUX_ESRCH;
        };
        if !status.state.is_running() {
            return LINUX_ESRCH;
        }
        if !linux_ptrace_access_permitted(pid) {
            return LINUX_EPERM;
        }
    }
    // Linux checks the local vector, then the remote one; only the local
    // buffers (and a caller's own remote ones) must be accessible here.
    let local = match linux_process_vm_vectors(local_vectors, local_count, Some(!write_remote)) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let remote = match linux_process_vm_vectors(
        remote_vectors,
        remote_count,
        current.then_some(write_remote),
    ) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let (local_count, remote_count) = (local.len(), remote.len());
    let mut local_index = 0;
    let mut remote_index = 0;
    let mut local_offset = 0;
    let mut remote_offset = 0;
    let mut transferred = 0_u64;
    let mut bytes = [0_u8; 256];
    while local_index < local_count && remote_index < remote_count {
        let local_remaining = local[local_index].1 - local_offset;
        let remote_remaining = remote[remote_index].1 - remote_offset;
        if local_remaining == 0 {
            local_index += 1;
            local_offset = 0;
            continue;
        }
        if remote_remaining == 0 {
            remote_index += 1;
            remote_offset = 0;
            continue;
        }
        if !current
            && remote_offset == 0
            && !linux_process::live_process_range_mapped(
                pid,
                remote[remote_index].0,
                remote[remote_index].1,
                write_remote,
            )
        {
            return if transferred == 0 {
                LINUX_EFAULT
            } else {
                transferred
            };
        }
        let length = local_remaining.min(remote_remaining).min(bytes.len());
        let local_address = local[local_index].0 + local_offset as u64;
        let remote_address = remote[remote_index].0 + remote_offset as u64;
        let copied = if current {
            let (source, destination) = if write_remote {
                (local_address, remote_address)
            } else {
                (remote_address, local_address)
            };
            copy_from_linux_user(source, &mut bytes[..length])
                && copy_to_linux_user(destination, &bytes[..length])
        } else if write_remote {
            copy_from_linux_user(local_address, &mut bytes[..length])
                && linux_process::copy_to_live_process(pid, remote_address, &bytes[..length])
        } else {
            linux_process::copy_from_live_process(pid, remote_address, &mut bytes[..length])
                && copy_to_linux_user(local_address, &bytes[..length])
        };
        if !copied {
            return if transferred == 0 {
                LINUX_EFAULT
            } else {
                transferred
            };
        }
        local_offset += length;
        remote_offset += length;
        transferred += length as u64;
    }
    transferred
}

pub(super) fn linux_ptrace_access_permitted(pid: u32) -> bool {
    if pid == current_linux_process_pid() {
        return true;
    }
    let Some(target_state) = linux_process_runtime_state(pid).filter(|state| state.valid) else {
        return false;
    };
    let Some(caller_namespace) = current_linux_user_namespace() else {
        return false;
    };
    let Some(target_namespace) = linux_process::live_process_user_namespace(pid) else {
        return false;
    };
    let (Some(caller), Some(target)) = (
        current_linux_credentials(),
        linux_process::live_process_credentials(pid),
    ) else {
        return false;
    };
    target_state.dumpable
        && caller_namespace == target_namespace
        && (caller.privileged() || linux_ids_match(&caller, &target))
}

/// /proc/PID/mem: reads, or writes, `count` bytes of process `pid`'s
/// memory at `offset` (a virtual address) from or to `buffer`, page by
/// page through its page tables, as a tracer's forced access does. A page
/// the process may only read is still written, to a private copy put in
/// its place first when the page is shared (copy-on-write broken), so a
/// page of the file cache or of another process is never written; a shared
/// mapping the process may not write is not. The transfer stops at the
/// first page it cannot reach: EIO when that is the first.
pub(super) fn linux_proc_mem_transfer(
    pid: u32,
    buffer: u64,
    count: u64,
    offset: u64,
    write: bool,
) -> u64 {
    let own = pid == current_linux_process_pid();
    if !own
        && linux_process::live_process_status(pid).is_none_or(|status| !status.state.is_running())
    {
        return 0;
    }
    let count = usize::try_from(count).unwrap_or(usize::MAX);
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut done = 0_usize;
    while done < count {
        let Some(address) = offset
            .checked_add(done as u64)
            .filter(|address| *address < 1 << 47)
        else {
            break;
        };
        let start = (address % PAGE_SIZE as u64) as usize;
        let length = (count - done).min(PAGE_SIZE - start);
        let chunk = &mut bytes[..length];
        let user = buffer.wrapping_add(done as u64);
        if write && !copy_from_linux_user(user, chunk) {
            return if done == 0 { LINUX_EFAULT } else { done as u64 };
        }
        if !linux_proc_mem_page(pid, own, address - start as u64, start, chunk, write) {
            break;
        }
        if !write && !copy_to_linux_user(user, chunk) {
            return if done == 0 { LINUX_EFAULT } else { done as u64 };
        }
        done += length;
    }
    if done == 0 && count != 0 {
        LINUX_EIO
    } else {
        done as u64
    }
}

/// One page's part of a /proc/PID/mem transfer: `bytes` read from, or
/// written to, `page` + `start` in process `pid` (`own`: the caller).
fn linux_proc_mem_page(
    pid: u32,
    own: bool,
    page: u64,
    start: usize,
    bytes: &mut [u8],
    write: bool,
) -> bool {
    if own {
        let state = address_space::current_linux_runtime_page(page);
        if !state.occupied || state.secret {
            return false;
        }
        // A page never touched is brought in as a read would.
        if state.frame.is_none() && !materialize_linux_runtime_user_range(page, PAGE_SIZE, false) {
            return false;
        }
        // A writable page is written as the process would write it.
        if write && state.protection & LINUX_PROT_WRITE as u8 != 0 {
            return materialize_linux_runtime_user_range(page, PAGE_SIZE, true)
                && copy_to_linux_user(page + start as u64, bytes);
        }
    }
    // Another process's pages are reached through its own page tables.
    let root = if own {
        None
    } else {
        match linux_process::live_process_root(pid) {
            Some(root) => Some(root),
            None => return false,
        }
    };
    let Some(mapping) = root.map_or_else(
        || address_space::current_linux_active_mapping(page),
        |root| address_space::linux_active_mapping_in_root(root, page),
    ) else {
        return false;
    };
    if write && mapping.writable {
        return linux_process::copy_to_live_process(pid, page + start as u64, bytes);
    }
    if write && mapping.shared {
        return false;
    }
    let frame = if write {
        match linux_forced_write_frame(pid, root, mapping) {
            Some(frame) => frame,
            None => return false,
        }
    } else {
        mapping.frame
    };
    // The frame is mapped by the target's page tables (or is its private
    // copy just mapped there) and stays mapped while the kernel-entry lock
    // is held.
    let Some(target) = crate::trusted::frame::Frame::leased(frame) else {
        return false;
    };
    if start
        .checked_add(bytes.len())
        .is_none_or(|end| end > crate::trusted::frame::FRAME_SIZE)
    {
        return false;
    }
    if write {
        target.write_bytes(start, bytes);
    } else {
        target.read_bytes(start, bytes);
    }
    true
}

/// The frame a forced write to read-only private `mapping` of process
/// `pid` (page tables `root`, None for the current ones) may write: its own
/// frame when no other mapping or the file cache holds it, else a copy put
/// in its place.
fn linux_forced_write_frame(
    pid: u32,
    root: Option<memory::FrameLease>,
    mapping: LinuxActiveImageMapping,
) -> Option<memory::FrameLease> {
    let frame = mapping.frame;
    if address_space::linux_private_page_counted(frame) && !memory::frame_is_shared(frame) {
        return Some(frame);
    }
    let [replacement] = memory::allocate_user_frames::<1>()?;
    let page = mapping.address as u64;
    let replace = || address_space::replace_current_linux_read_only_page(page, frame, replacement);
    let replaced = address_space::copy_linux_frame(frame, replacement)
        && root.map_or_else(replace, |root| {
            address_space::with_live_linux_process_root(root, replace).unwrap_or(false)
        });
    if !replaced {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[replacement]);
        return None;
    }
    // A registered mapping list that does not have the page is stale: the
    // live tables are then the record.
    if !linux_process::replace_live_process_mapping(
        pid,
        mapping.address,
        frame,
        replacement,
        false,
        mapping.executable,
    ) {
        let _ = linux_process::mark_live_process_address_space_stale(pid);
    }
    let _ = address_space::release_linux_private_page(frame);
    Some(replacement)
}

/// Linux's UIO_MAXIOV: the most vectors process_vm_readv and
/// process_vm_writev take.
const LINUX_PROCESS_VM_IOV_LIMIT: usize = 1024;

/// The `count` vectors at `vectors` of process_vm_readv or
/// process_vm_writev: too many, or lengths whose sum overflows an ssize_t,
/// are EINVAL. With `accessible` (whether the buffers must be writable),
/// each buffer must lie in the caller's memory (EFAULT).
fn linux_process_vm_vectors(
    vectors: u64,
    count: u64,
    accessible: Option<bool>,
) -> Result<Vec<(u64, usize)>, u64> {
    let count = usize::try_from(count)
        .ok()
        .filter(|count| *count <= LINUX_PROCESS_VM_IOV_LIMIT)
        .ok_or(LINUX_EINVAL)?;
    let mut table = Vec::new();
    table
        .try_reserve_exact(count * 16)
        .map_err(|_| LINUX_ENOMEM)?;
    table.resize(count * 16, 0_u8);
    if count != 0 && !copy_from_linux_user(vectors, &mut table) {
        return Err(LINUX_EFAULT);
    }
    let mut ranges = Vec::new();
    ranges.try_reserve_exact(count).map_err(|_| LINUX_ENOMEM)?;
    let mut total = 0_usize;
    for vector in table.as_chunks::<16>().0 {
        let address = u64::from_ne_bytes(vector[..8].try_into().unwrap());
        let length = usize::from_ne_bytes(vector[8..].try_into().unwrap());
        total = total
            .checked_add(length)
            .filter(|total| *total <= isize::MAX as usize)
            .ok_or(LINUX_EINVAL)?;
        ranges.push((address, length));
    }
    if let Some(writable) = accessible {
        let reachable = |&(address, length): &(u64, usize)| {
            length == 0
                || if writable {
                    linux_writable_user_range_contains(address, length)
                } else {
                    linux_readable_user_range_contains(address, length)
                }
        };
        if !ranges.iter().all(reachable) {
            return Err(LINUX_EFAULT);
        }
    }
    Ok(ranges)
}

pub(super) fn linux_kcmp(
    first_pid: u64,
    second_pid: u64,
    kind: u64,
    first: u64,
    second: u64,
) -> u64 {
    const KCMP_FILE: u64 = 0;
    const KCMP_SYSVSEM: u64 = 6;
    let first_pid = first_pid as i32;
    let second_pid = second_pid as i32;
    let kind = u64::from(kind as u32);
    if first_pid <= 0 || second_pid <= 0 {
        return LINUX_ESRCH;
    }
    let first_pid = first_pid as u32;
    let second_pid = second_pid as u32;
    if linux_process::live_process_status(first_pid).is_none()
        || linux_process::live_process_status(second_pid).is_none()
    {
        return LINUX_ESRCH;
    }
    if !linux_ptrace_access_permitted(first_pid) || !linux_ptrace_access_permitted(second_pid) {
        return LINUX_EPERM;
    }
    if (1..=KCMP_SYSVSEM).contains(&kind) {
        use linux_process::SharedResource;
        // KCMP_VM, KCMP_FILES, KCMP_FS, KCMP_SIGHAND, KCMP_IO, KCMP_SYSVSEM:
        // the same object, or an order between the two (Linux orders them
        // by an obfuscated address; any consistent order will do).
        let resource = [
            SharedResource::Memory,
            SharedResource::Descriptors,
            SharedResource::Filesystem,
            SharedResource::SignalHandlers,
            SharedResource::Io,
            SharedResource::SemaphoreUndo,
        ][kind as usize - 1];
        let (Some(first), Some(second)) = (
            linux_process::live_process_shared_id(first_pid, resource),
            linux_process::live_process_shared_id(second_pid, resource),
        ) else {
            return LINUX_ESRCH;
        };
        return match first.cmp(&second) {
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Less => 1,
            core::cmp::Ordering::Greater => 2,
        };
    }
    if kind != KCMP_FILE {
        return LINUX_EINVAL;
    }
    let Some(first_id) = linux_process_descriptor_open_file_id(first_pid, first) else {
        return LINUX_EBADF;
    };
    let Some(second_id) = linux_process_descriptor_open_file_id(second_pid, second) else {
        return LINUX_EBADF;
    };
    u64::from(first_id != second_id)
}

pub(super) fn linux_process_descriptor_open_file_id(pid: u32, descriptor: u64) -> Option<u64> {
    let descriptor = u64::from(descriptor as u32);
    let id = if pid == current_linux_process_pid() {
        linux_descriptor_open_file_id(descriptor)?
    } else {
        let state = linux_process_runtime_state(pid).filter(|state| state.valid)?;
        if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
            crate::linux_fd_table::get(state.descriptors.overflow, descriptor)
                .filter(|entry| !entry.vacant())?
                .open_file_id
        } else if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
            state.descriptors.stdio_open_file_ids[descriptor as usize]
        } else {
            state.descriptors.open_file_ids[(descriptor - LINUX_AUX_DESCRIPTOR_FIRST) as usize]
        }
    };
    (id != 0).then_some(id)
}
