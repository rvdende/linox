use super::*;

pub(super) fn linux_epoll_ctl(
    epoll: u64,
    operation: u64,
    descriptor: u64,
    event_address: u64,
) -> u64 {
    let epoll = u64::from(epoll as u32);
    let operation = u64::from(operation as u32);
    let descriptor = u64::from(descriptor as u32);
    if !linux_epoll_descriptor(epoll) {
        return LINUX_EBADF;
    }
    if descriptor == epoll {
        return LINUX_EINVAL;
    }
    let epoll = linux_epoll_instance(epoll);
    // An O_PATH descriptor is no file to watch (EBADF, as in Linux), nor
    // a detached mount's, which is one.
    if !linux_descriptor_open(descriptor)
        || linux_path_descriptor(descriptor)
        || linux_detached_mount_descriptor(descriptor).is_some()
    {
        return LINUX_EBADF;
    }
    if !linux_descriptor_epollable(descriptor) {
        return LINUX_EPERM;
    }
    let runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    let existing = if runtime {
        (0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize).find(|slot| {
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[*slot].load(Ordering::SeqCst)
                == (epoll as u32).wrapping_add(1)
                && X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[*slot].load(Ordering::SeqCst)
                    == (descriptor as u32).wrapping_add(1)
        })
    } else {
        Some(descriptor as usize).filter(|target| {
            X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[*target].load(Ordering::SeqCst) != 0
        })
    };
    if operation == LINUX_EPOLL_CTL_DEL {
        let Some(slot) = existing else {
            return LINUX_ENOENT;
        };
        X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EPOLL_DATA[slot].store(0, Ordering::SeqCst);
        if runtime {
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].store(0, Ordering::SeqCst);
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].store(0, Ordering::SeqCst);
        }
        return 0;
    }
    if !matches!(operation, LINUX_EPOLL_CTL_ADD | LINUX_EPOLL_CTL_MOD) {
        return LINUX_EINVAL;
    }
    if operation == LINUX_EPOLL_CTL_ADD && existing.is_some() {
        return LINUX_EEXIST;
    }
    // An epoll instance watching another: a cycle back to this one is
    // ELOOP, and a chain deeper than Linux's EP_MAX_NESTS (4 below the
    // top) is EINVAL (epoll_ctl04, 05, 07).
    if runtime && operation == LINUX_EPOLL_CTL_ADD && linux_epoll_descriptor(descriptor) {
        let target = linux_epoll_instance(descriptor);
        if linux_epoll_reaches(target, epoll, 0) {
            return LINUX_ELOOP;
        }
        if linux_epoll_depth_below(target, 0) + linux_epoll_depth_above(epoll, 0) >= 4 {
            return LINUX_EINVAL;
        }
    }
    if operation == LINUX_EPOLL_CTL_MOD && existing.is_none() {
        return LINUX_ENOENT;
    }
    let mut event = [0_u8; 12];
    if !copy_from_linux_user(event_address, &mut event) {
        return LINUX_EFAULT;
    }
    let events = u32::from_ne_bytes(event[..4].try_into().unwrap());
    if events & !LINUX_EPOLL_SUPPORTED_EVENTS != 0 {
        return LINUX_EINVAL;
    }
    // EPOLLEXCLUSIVE is given at EPOLL_CTL_ADD only, never for an epoll
    // instance and with no events beyond LINUX_EPOLLEXCLUSIVE_OK_BITS; an
    // exclusive watch cannot be modified either.
    let exclusive_refused = events & LINUX_EPOLLEXCLUSIVE != 0
        && (operation == LINUX_EPOLL_CTL_MOD
            || linux_epoll_descriptor(descriptor)
            || events & !LINUX_EPOLLEXCLUSIVE_OK_BITS != 0);
    let exclusive_modified = operation == LINUX_EPOLL_CTL_MOD
        && existing.is_some_and(|slot| {
            X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].load(Ordering::SeqCst) & LINUX_EPOLLEXCLUSIVE
                != 0
        });
    if exclusive_refused || exclusive_modified {
        return LINUX_EINVAL;
    }
    let data = u64::from_ne_bytes(event[4..].try_into().unwrap());
    let slot = if let Some(slot) = existing {
        slot
    } else if runtime {
        let Some(slot) = (0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize).find(|slot| {
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[*slot].load(Ordering::SeqCst) == 0
        }) else {
            return LINUX_ENOSPC;
        };
        X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot]
            .store((epoll as u32).wrapping_add(1), Ordering::SeqCst);
        X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot]
            .store((descriptor as u32).wrapping_add(1), Ordering::SeqCst);
        slot
    } else {
        descriptor as usize
    };
    X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(events, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_EPOLL_DATA[slot].store(data, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    0
}

/// What kind of object a descriptor refers to, for diagnostics.
pub(in crate::arch::x86_64) fn linux_descriptor_kind_name(descriptor: u64) -> &'static str {
    if !linux_descriptor_open(descriptor) {
        "closed"
    } else if linux_pipe_descriptor(descriptor) {
        "pipe"
    } else if linux_socket_slot(descriptor).is_some() {
        "socket"
    } else if linux_eventfd_descriptor(descriptor) {
        "eventfd"
    } else if linux_pidfd_descriptor(descriptor) {
        "pidfd"
    } else if linux_signalfd_descriptor(descriptor) {
        "signalfd"
    } else if linux_timerfd_descriptor(descriptor) {
        "timerfd"
    } else if linux_epoll_descriptor(descriptor) {
        "epoll"
    } else if linux_console_descriptor_open(descriptor)
        || linux_device_descriptor(descriptor) & LINUX_DEVICE_CONSOLE != 0
    {
        "console"
    } else {
        "file"
    }
}

fn linux_descriptor_epollable(descriptor: u64) -> bool {
    let device = linux_device_descriptor(descriptor);
    linux_console_descriptor_open(descriptor)
        || descriptor == 2 && X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::SeqCst)
        || device & LINUX_DEVICE_CONSOLE != 0
        || linux_pidfd_descriptor(descriptor)
        || linux_signalfd_descriptor(descriptor)
        || linux_inotify_descriptor(descriptor)
        || linux_fanotify_descriptor(descriptor)
        // A filesystem context has no poll (EPERM, as in Linux).
        || linux_socket_slot(descriptor).is_some()
            && linux_fs_context_descriptor(descriptor).is_none()
        || linux_epoll_descriptor(descriptor)
        || linux_eventfd_descriptor(descriptor)
        || linux_timerfd_descriptor(descriptor)
        || linux_pipe_descriptor(descriptor)
        // io_uring (its completions), userfaultfd (its events) and
        // /proc/mounts (a mount table change) can be polled in Linux too.
        || linux_io_uring_descriptor(descriptor)
        || linux_userfaultfd_descriptor(descriptor)
        || device & !3 == LINUX_FILE_PROC_MOUNTS
}

/// Bits of a watch's stored events word that hold the readiness last reported
/// for an edge-triggered (EPOLLET) watch; Linux defines no epoll flags there.
const LINUX_EPOLL_REPORTED_SHIFT: u32 = 16;
const LINUX_EPOLL_REPORTED_MASK: u32 = 0x1f << LINUX_EPOLL_REPORTED_SHIFT;
/// Set in an edge-triggered watch's events word once
/// LINUX_RUNTIME_EPOLL_WATCH_SEEN holds the event counts it saw; clear after
/// EPOLL_CTL_ADD or MOD, which report readiness at once as Linux does.
const LINUX_EPOLL_SEEN_VALID: u32 = 1 << 21;
/// The events an input wakeup (new data, a hangup) concerns.
const LINUX_EPOLL_INPUT_EVENTS: u16 =
    LINUX_POLLIN | LINUX_POLLPRI | LINUX_POLLRDNORM | 0x80 | LINUX_POLLRDHUP;

/// The wakeup counts of the socket or pipe behind `descriptor`, input in
/// the low half and output in the high (see `linux_socket::event_counts`),
/// or None for a descriptor whose wakeups are not counted.
fn linux_epoll_event_counts(descriptor: u64) -> Option<u64> {
    let (input, output) = crate::linux_socket::event_counts(linux_socket_slot(descriptor)?)?;
    Some(u64::from(input) | u64::from(output) << 32)
}

/// Re-arms the edge-triggered watches on the descriptor a system call is
/// about to read, write, accept on or reap (a pidfd for waitid), so that
/// readiness after the call is reported again. Linux reports an edge for
/// each new event; consumers such as mio read until EAGAIN, so re-arming on
/// use reports every new event and at most adds a spurious one. Sockets and
/// pipes need none: their wakeups are counted (linux_epoll_event_counts).
pub(in crate::arch::x86_64) fn linux_epoll_rearm_for_syscall(number: u64, first: u64, second: u64) {
    let descriptor = match number {
        LINUX_READ_SYSCALL
        | LINUX_WRITE_SYSCALL
        | LINUX_PREAD64_SYSCALL
        | LINUX_PWRITE64_SYSCALL
        | LINUX_READV_SYSCALL
        | LINUX_WRITEV_SYSCALL
        | LINUX_PREADV_SYSCALL
        | LINUX_PWRITEV_SYSCALL
        | LINUX_PREADV2_SYSCALL
        | LINUX_PWRITEV2_SYSCALL
        | LINUX_SENDTO_SYSCALL
        | LINUX_RECVFROM_SYSCALL
        | LINUX_SENDMSG_SYSCALL
        | LINUX_RECVMSG_SYSCALL
        | LINUX_SENDMMSG_SYSCALL
        | LINUX_RECVMMSG_SYSCALL
        | LINUX_ACCEPT_SYSCALL
        | LINUX_ACCEPT4_SYSCALL => first,
        LINUX_WAITID_SYSCALL if first == LINUX_P_PIDFD => second,
        _ => return,
    };
    // Regular files, the bulk of a compiler's reads, cannot be watched.
    if !linux_descriptor_epollable(descriptor) {
        return;
    }
    let Some(target) = u32::try_from(descriptor)
        .ok()
        .and_then(|descriptor| descriptor.checked_add(1))
    else {
        return;
    };
    let mut counted = None;
    for slot in 0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize {
        if X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst) != target {
            continue;
        }
        let events = X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].load(Ordering::SeqCst);
        if events & LINUX_EPOLL_REPORTED_MASK != 0 {
            if *counted.get_or_insert_with(|| linux_epoll_event_counts(descriptor).is_some()) {
                return;
            }
            X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot]
                .store(events & !LINUX_EPOLL_REPORTED_MASK, Ordering::SeqCst);
        }
    }
}

/// The next event of an epoll instance. A caller that delivers the event
/// `consume`s it, so an edge-triggered watch waits for its next edge; a
/// readiness check leaves the watch armed. EPOLLONESHOT is accepted but not
/// yet honoured (the watch stays armed): some paths that take an event can
/// still drop it, which would leave a one-shot watch disarmed for good.
pub(super) fn linux_epoll_event(epoll: u64, consume: bool) -> Result<Option<[u8; 12]>, u64> {
    linux_epoll_event_from(epoll, consume, 0).map(|event| event.map(|(_, event)| event))
}

/// Per epoll descriptor, the watch slot the next epoll_wait starts its scan
/// at: ready descriptors are reported in turn when more are ready than
/// `maxevents` (epoll_wait14).
static LINUX_EPOLL_CURSORS: [AtomicU16; LINUX_DESCRIPTOR_TABLE_LIMIT as usize] =
    [const { AtomicU16::new(0) }; LINUX_DESCRIPTOR_TABLE_LIMIT as usize];

/// Collects up to `maximum` ready events of epoll descriptor `epoll` into
/// the user array at `address`, as epoll_wait does: each watch at most
/// once, starting where the last call stopped. The count, EFAULT when
/// nothing could be written, or the instance's error.
/// What a wait on epoll descriptor `epoll` waits on: what each watched
/// descriptor's readiness waits on (`linux_descriptor_wait`).
fn linux_epoll_wait_on(epoll: u64) -> WaitOn {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) || !linux_epoll_descriptor(epoll) {
        return WaitOn::ANYTHING;
    }
    let instance = (linux_epoll_instance(epoll) as u32).wrapping_add(1);
    (0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize)
        .filter(|slot| {
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[*slot].load(Ordering::SeqCst) == instance
        })
        .map(|slot| X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst))
        .filter(|target| *target != 0)
        .fold(WaitOn::NOTHING, |wait, target| {
            wait.and(linux_descriptor_wait(u64::from(target - 1)))
        })
}

fn linux_epoll_collect(epoll: u64, address: u64, maximum: u64) -> Result<u64, u64> {
    let limit = LINUX_DESCRIPTOR_TABLE_LIMIT as usize;
    let cursor = &LINUX_EPOLL_CURSORS[(epoll as usize) % limit];
    let start = usize::from(cursor.load(Ordering::Relaxed)) % limit;
    let mut next = start;
    let mut travelled = 0;
    let mut count = 0_u64;
    while count < maximum && travelled < limit {
        let Some((slot, event)) = linux_epoll_event_from(epoll, true, next)? else {
            break;
        };
        let distance = (slot + limit - next) % limit;
        travelled += distance + 1;
        if travelled > limit {
            break;
        }
        if !copy_to_linux_user(address + count * 12, &event) {
            return if count == 0 {
                Err(LINUX_EFAULT)
            } else {
                Ok(count)
            };
        }
        count += 1;
        next = (slot + 1) % limit;
    }
    cursor.store(next as u16, Ordering::Relaxed);
    Ok(count)
}

/// The first ready event of epoll descriptor `epoll` at or after watch slot
/// `start`, round the table, with its slot. An EPOLLONESHOT watch reports
/// once, then waits for EPOLL_CTL_MOD.
fn linux_epoll_event_from(
    epoll: u64,
    consume: bool,
    start: usize,
) -> Result<Option<(usize, [u8; 12])>, u64> {
    // A descriptor that is open but no epoll instance is EINVAL (epoll_wait03).
    if !linux_epoll_descriptor(epoll) {
        return Err(if linux_descriptor_open(epoll) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        });
    }
    let epoll = linux_epoll_instance(epoll);
    let runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    let limit = LINUX_DESCRIPTOR_TABLE_LIMIT as usize;
    for step in 0..limit {
        let slot = (start + step) % limit;
        let target = if runtime {
            if X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].load(Ordering::SeqCst)
                != (epoll as u32).wrapping_add(1)
            {
                continue;
            }
            let target = X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst);
            if target == 0 {
                continue;
            }
            (target - 1) as usize
        } else {
            slot
        };
        let stored = X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].load(Ordering::SeqCst);
        let requested = stored as u16;
        if requested == 0 {
            continue;
        }
        // Taken before the readiness, so that a wakeup in between is seen
        // again next time rather than lost.
        let counts = if stored & LINUX_EPOLLET != 0 {
            linux_epoll_event_counts(target as u64)
        } else {
            None
        };
        let ready = linux_descriptor_poll_events(target as i32, requested)
            & (LINUX_POLLIN
                | LINUX_POLLPRI
                | LINUX_POLLOUT
                | LINUX_POLLERR
                | LINUX_POLLHUP
                | LINUX_POLLRDHUP);
        if stored & LINUX_EPOLLET != 0 {
            // Edge-triggered: report readiness not reported since it was
            // last seen absent (the record keeps the low five event bits),
            // or since the descriptor was last used
            // (linux_epoll_rearm_for_syscall).
            let reported = (stored & LINUX_EPOLL_REPORTED_MASK) >> LINUX_EPOLL_REPORTED_SHIFT;
            let mut now = (stored & !LINUX_EPOLL_REPORTED_MASK)
                | (u32::from(ready & 0x1f) << LINUX_EPOLL_REPORTED_SHIFT);
            let mut edge = u32::from(ready) & !reported != 0;
            if let Some(counts) = counts {
                // A socket or pipe also has an edge on each wakeup since the
                // watch last looked, ready as it may have stayed: a write to
                // it, room a read made for its writer, a hangup. Linux queues
                // the watch on every such wakeup that concerns its events
                // (ep_poll_callback).
                now |= LINUX_EPOLL_SEEN_VALID;
                let seen = X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_SEEN[slot].load(Ordering::SeqCst);
                let added = stored & LINUX_EPOLL_SEEN_VALID == 0;
                let input =
                    counts as u32 != seen as u32 && requested & LINUX_EPOLL_INPUT_EVENTS != 0;
                let output = counts >> 32 != seen >> 32 && requested & LINUX_POLLOUT != 0;
                edge = if stored & LINUX_EPOLLEXCLUSIVE != 0 && input && !added {
                    // One exclusive watch takes each input wakeup: the
                    // first to look, which in a waiting instance is the
                    // first woken.
                    crate::linux_socket::claim_exclusive_event(
                        linux_socket_slot(target as u64).unwrap_or_default(),
                        counts as u32,
                        consume,
                    )
                } else {
                    edge || added || input || output
                };
                if consume && counts != seen {
                    X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_SEEN[slot]
                        .store(counts, Ordering::SeqCst);
                }
            }
            if consume && now != stored {
                X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(now, Ordering::SeqCst);
            }
            if !edge {
                continue;
            }
        }
        if ready != 0 {
            X86_RUNTIME
                .LINUX_EPOLL_LAST_READY_DESCRIPTOR
                .store(target as u64, Ordering::SeqCst);
            X86_RUNTIME
                .LINUX_EPOLL_LAST_READY_EVENTS
                .store(u64::from(ready), Ordering::SeqCst);
            let mut event = [0_u8; 12];
            event[..4].copy_from_slice(&u32::from(ready).to_ne_bytes());
            event[4..].copy_from_slice(
                &X86_RUNTIME.ELF_PROBE_EPOLL_DATA[slot]
                    .load(Ordering::SeqCst)
                    .to_ne_bytes(),
            );
            if consume && stored & LINUX_EPOLLONESHOT != 0 {
                // Disarmed: the flags stay, the events are gone.
                X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(stored & !0xffff, Ordering::SeqCst);
            }
            return Ok(Some((slot, event)));
        }
    }
    Ok(None)
}

/// The epoll instances epoll instance `epoll` watches directly.
fn linux_epoll_watched_instances(epoll: u64) -> impl Iterator<Item = u64> {
    (0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize).filter_map(move |slot| {
        if X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].load(Ordering::SeqCst)
            != (epoll as u32).wrapping_add(1)
        {
            return None;
        }
        let target = X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst);
        let target = u64::from(target.checked_sub(1)?);
        linux_epoll_descriptor(target).then(|| linux_epoll_instance(target))
    })
}

/// Whether epoll instance `from` reaches `to` through the instances it
/// watches (bounded, as Linux bounds its walk).
fn linux_epoll_reaches(from: u64, to: u64, depth: usize) -> bool {
    from == to
        || depth < 8
            && linux_epoll_watched_instances(from)
                .any(|next| linux_epoll_reaches(next, to, depth + 1))
}

/// How many epoll levels lie below instance `epoll` (0: it watches none).
fn linux_epoll_depth_below(epoll: u64, depth: usize) -> usize {
    if depth >= 8 {
        return depth;
    }
    linux_epoll_watched_instances(epoll)
        .map(|next| 1 + linux_epoll_depth_below(next, depth + 1))
        .max()
        .unwrap_or(0)
}

/// How many epoll instances watch instance `epoll`, level over level.
fn linux_epoll_depth_above(epoll: u64, depth: usize) -> usize {
    if depth >= 8 {
        return depth;
    }
    (0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize)
        .filter_map(|slot| {
            let target = X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst);
            let owner = X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].load(Ordering::SeqCst);
            let target = u64::from(target.checked_sub(1)?);
            let owner = u64::from(owner.checked_sub(1)?);
            (linux_epoll_descriptor(target) && linux_epoll_instance(target) == epoll)
                .then_some(owner)
        })
        .map(|owner| 1 + linux_epoll_depth_above(owner, depth + 1))
        .max()
        .unwrap_or(0)
}

/// The descriptor that owns an epoll instance's watches: the descriptor
/// itself, unless it was duplicated from another epoll descriptor.
fn linux_epoll_instance(descriptor: u64) -> u64 {
    if descriptor < LINUX_AUX_DESCRIPTOR_FIRST {
        return descriptor;
    }
    match linux_fd_cell::<u32>(descriptor, LinuxFdField::EpollAlias).load(Ordering::SeqCst) {
        0 => descriptor,
        alias => u64::from(alias - 1),
    }
}

/// Makes `target` another descriptor for the epoll instance `source` refers
/// to, as dup(2) does; tokio duplicates its epoll descriptor this way.
pub(super) fn linux_epoll_dup(source: u64, target: u64) -> u64 {
    if source == target {
        return target;
    }
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || target < LINUX_AUX_DESCRIPTOR_FIRST
        || target >= linux_nofile_soft_limit()
    {
        return LINUX_EBADF;
    }
    if linux_descriptor_open(target) && linux_descriptor_close(target) != 0 {
        return LINUX_EBADF;
    }
    let instance = linux_epoll_instance(source);
    linux_fd_cell::<u8>(target, LinuxFdField::Epoll).store(1, Ordering::SeqCst);
    linux_fd_cell::<u32>(target, LinuxFdField::EpollAlias)
        .store(instance as u32 + 1, Ordering::SeqCst);
    if !linux_epoll_descriptor(target) {
        return LINUX_ENOMEM;
    }
    set_linux_descriptor_close_on_exec(target, false);
    target
}

/// When the descriptor owning an epoll instance closes while duplicates
/// remain, moves the instance's watches to the first duplicate and points
/// the others at it. Returns false if there was no duplicate.
pub(super) fn linux_epoll_hand_over(owner: u64) -> bool {
    let owner_value = owner as u32 + 1;
    let alias = |descriptor: u64| linux_fd_cell::<u32>(descriptor, LinuxFdField::EpollAlias);
    let Some(heir) = linux_descriptor_numbers()
        .filter(|descriptor| *descriptor >= LINUX_AUX_DESCRIPTOR_FIRST)
        .find(|descriptor| alias(*descriptor).load(Ordering::SeqCst) == owner_value)
    else {
        return false;
    };
    let heir_value = heir as u32 + 1;
    alias(heir).store(0, Ordering::SeqCst);
    for descriptor in linux_descriptor_numbers().filter(|descriptor| {
        *descriptor >= LINUX_AUX_DESCRIPTOR_FIRST
            && alias(*descriptor).load(Ordering::SeqCst) == owner_value
    }) {
        alias(descriptor).store(heir_value, Ordering::SeqCst);
    }
    for watch in &X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL {
        let _ = watch.compare_exchange(owner_value, heir_value, Ordering::SeqCst, Ordering::SeqCst);
    }
    true
}

pub(super) fn linux_epoll_forget_descriptor(descriptor: u64) {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        for slot in 0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize {
            if X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].load(Ordering::SeqCst)
                == (descriptor as u32).wrapping_add(1)
            {
                X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].store(0, Ordering::SeqCst);
                X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].store(0, Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(0, Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_EPOLL_DATA[slot].store(0, Ordering::SeqCst);
            }
        }
    } else if descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT {
        X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[descriptor as usize].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EPOLL_DATA[descriptor as usize].store(0, Ordering::SeqCst);
    }
}

pub(super) fn linux_epoll_forget_owner(descriptor: u64) {
    for slot in 0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize {
        if X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].load(Ordering::SeqCst)
            == (descriptor as u32).wrapping_add(1)
        {
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_EPOLL[slot].store(0, Ordering::SeqCst);
            X86_RUNTIME.LINUX_RUNTIME_EPOLL_WATCH_TARGET[slot].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[slot].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_EPOLL_DATA[slot].store(0, Ordering::SeqCst);
        }
    }
}

pub(super) fn complete_linux_epoll_wait(slot: usize, timed_out: bool) -> bool {
    let kind = if slot < LINUX_THREAD_LIMIT {
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
    } else {
        LINUX_THREAD_WAIT_NONE
    };
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || !matches!(
            kind,
            LINUX_THREAD_WAIT_EPOLL | LINUX_THREAD_WAIT_EPOLL_PWAIT
        )
    {
        return false;
    }
    let output = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let (epoll, maximum) = (output & u64::from(u32::MAX), (output >> 32).max(1));
    if matches!(linux_epoll_event(epoll, false), Ok(None)) && !timed_out {
        return false;
    }
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = linux_epoll_collect(epoll, address, maximum).unwrap_or_else(|error| error);
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    if kind == LINUX_THREAD_WAIT_EPOLL_PWAIT {
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(
            X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].swap(0, Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    match (kind, timed_out) {
        (LINUX_THREAD_WAIT_EPOLL, true) => {
            X86_RUNTIME
                .LINUX_EPOLL_WAIT_TIMEOUT_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_EPOLL, false) => {
            X86_RUNTIME
                .LINUX_EPOLL_WAIT_WAKE_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_EPOLL_PWAIT, true) => {
            X86_RUNTIME
                .LINUX_EPOLL_PWAIT_TIMEOUT_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_EPOLL_PWAIT, false) => {
            X86_RUNTIME
                .LINUX_EPOLL_PWAIT_WAKE_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        _ => {}
    }
    true
}

fn wake_linux_epoll_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_epoll_wait(slot, false));
    }
    woken
}

pub(super) fn wake_linux_descriptor_waits() -> u32 {
    if !X86_RUNTIME
        .LINUX_DESCRIPTOR_WAITS_ACTIVE
        .load(Ordering::Acquire)
    {
        return 0;
    }
    // Completing a wait copies its result into the waiting thread's memory:
    // the live thread table's process, whose address space is not always
    // the active one (a fork transaction wakes the parent's waits once its
    // child has gone, and the child's exit is what made them ready).
    match linux_process::live_process_root(current_linux_process_pid()) {
        Some(root) if root.address() != address_space::current_root_address() => {
            address_space::with_live_linux_process_root(root, wake_linux_descriptor_waits_here)
                .unwrap_or(0)
        }
        _ => wake_linux_descriptor_waits_here(),
    }
}

/// `wake_linux_descriptor_waits` in the active address space.
fn wake_linux_descriptor_waits_here() -> u32 {
    let woken = wake_linux_poll_waits()
        + wake_linux_select_waits()
        + wake_linux_epoll_waits()
        + wake_linux_eventfd_read_waits()
        + wake_linux_eventfd_write_waits()
        + wake_linux_pipe_read_waits()
        + wake_linux_pipe_write_waits()
        + wake_linux_timerfd_read_waits();
    let active = (0..LINUX_THREAD_LIMIT).any(|slot| {
        X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::Relaxed) == LINUX_THREAD_BLOCKED
            && matches!(
                X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::Relaxed),
                LINUX_THREAD_WAIT_POLL
                    | LINUX_THREAD_WAIT_PPOLL
                    | LINUX_THREAD_WAIT_EPOLL
                    | LINUX_THREAD_WAIT_EPOLL_PWAIT
                    | LINUX_THREAD_WAIT_SELECT
                    | LINUX_THREAD_WAIT_PSELECT
                    | LINUX_THREAD_WAIT_EVENTFD_READ
                    | LINUX_THREAD_WAIT_EVENTFD_WRITE
                    | LINUX_THREAD_WAIT_PIPE_READ
                    | LINUX_THREAD_WAIT_PIPE_WRITE
                    | LINUX_THREAD_WAIT_TIMERFD_READ
            )
    });
    X86_RUNTIME
        .LINUX_DESCRIPTOR_WAITS_ACTIVE
        .store(active, Ordering::Release);
    woken
}

#[derive(Clone, Copy)]
pub(super) struct LinuxEpollWaitInput {
    pub(super) epoll: u64,
    pub(super) address: u64,
    pub(super) maximum: u64,
}

#[derive(Clone, Copy)]
pub(super) struct LinuxSignalMaskInput {
    pub(super) address: u64,
    pub(super) size: u64,
}

pub(super) fn linux_epoll_wait_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    input: LinuxEpollWaitInput,
    timeout: u64,
) -> u64 {
    let timeout = timeout as u32 as i32;
    let duration = if timeout < 0 {
        None
    } else {
        let Some(duration) = (timeout as u64).checked_mul(1_000_000) else {
            return LINUX_EINVAL;
        };
        Some(duration)
    };
    linux_epoll_wait_duration_live_return(
        output,
        caller,
        input,
        duration,
        LINUX_EPOLL_WAIT_SYSCALL,
        None,
    )
}

/// Waits in epoll_wait, epoll_pwait or epoll_pwait2 (system call `number`,
/// which a yield restarts). `temporary_signal_mask` is the mask an
/// epoll_pwait call gave; without one the call waits as epoll_wait does.
pub(super) fn linux_epoll_wait_duration_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    input: LinuxEpollWaitInput,
    duration: Option<u64>,
    number: u64,
    temporary_signal_mask: Option<u64>,
) -> u64 {
    let wait_kind = if temporary_signal_mask.is_some() {
        LINUX_THREAD_WAIT_EPOLL_PWAIT
    } else {
        LINUX_THREAD_WAIT_EPOLL
    };
    let maximum = input.maximum as u32 as i32;
    if maximum <= 0 {
        return LINUX_EINVAL;
    }
    let input = LinuxEpollWaitInput {
        epoll: u64::from(input.epoll as u32),
        maximum: maximum as u64,
        ..input
    };
    match linux_epoll_collect(input.epoll, input.address, input.maximum) {
        Ok(0) if duration == Some(0) => return 0,
        Ok(0) => {}
        Ok(count) => return count,
        Err(error) => return error,
    }
    if !linux_writable_user_range_contains(input.address, 12) {
        return LINUX_EFAULT;
    }
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    // The deadline of a wait that began below, if it goes on as a thread
    // wait because a sibling thread became ready meanwhile.
    let mut continued_deadline = None;
    let target = 'target: {
        if let Some(target) = ready_linux_thread_handle() {
            break 'target target;
        }
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            {
                // epoll_wait waits as poll does: other processes run, the
                // call restarts with its deadline, and a signal interrupts
                // it (EINTR). epoll_pwait waits under its temporary mask as
                // ppoll does: a signal it blocks stays pending, one it
                // unblocks ends the wait (epoll_pwait01), and a handler's
                // frame restores the caller's mask.
                let deadline = take_linux_restart_deadline(caller.rip).or_else(|| {
                    duration.and_then(|duration| {
                        linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
                    })
                });
                let slot = usize::from(current.slot);
                let prior = temporary_signal_mask.map(|mask| {
                    begin_linux_lone_masked_wait(slot, LINUX_THREAD_WAIT_SIGSUSPEND, mask)
                });
                // Resumed after a park with no signal, the call looks at
                // the instance and its deadline again. Once a sibling thread
                // is ready, this thread waits as a thread wait while it runs.
                let ended = loop {
                    if deadline.is_some_and(|deadline| {
                        linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline)
                    }) {
                        break Ok(0);
                    }
                    let wait = linux_epoll_wait_on(input.epoll).until_some(deadline);
                    let turn = linux_timed_wait_run_others(output, caller, number, wait);
                    if let LinuxWaitTurn::Done(result) = turn {
                        break Ok(result);
                    }
                    if let Some(target) = ready_linux_thread_handle() {
                        break Err((target, deadline));
                    }
                    match linux_epoll_collect(input.epoll, input.address, input.maximum) {
                        Ok(0) => {}
                        Ok(count) => break Ok(count),
                        Err(error) => break Ok(error),
                    }
                    // Nothing else can run: halt until an interrupt (the
                    // deadline's tick, or a waker on another CPU).
                    if let LinuxWaitTurn::Idle = turn {
                        if let Some((deadline, now)) = deadline.zip(linux_elapsed_nanoseconds()) {
                            timer::request_linux_tick_within(deadline.saturating_sub(now));
                        }
                        linux_wait_for_interrupt();
                    }
                };
                if let Some(prior) = prior {
                    end_linux_lone_masked_wait(slot, prior);
                }
                match ended {
                    Ok(result) => return result,
                    Err((target, deadline)) => {
                        continued_deadline = Some(deadline.unwrap_or(0));
                        break 'target target;
                    }
                }
            }
        }
        // The static verification executor has no peer thread to advance a
        // blocking wait. Report that harness limitation deterministically;
        // runtime domains continue through the scheduler-backed path above.
        return if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            0
        } else {
            LINUX_ENOSYS
        };
    };
    let Some(tls) = linux_thread_context(current) else {
        return LINUX_ESRCH;
    };
    let deadline = if let Some(deadline) = continued_deadline {
        deadline
    } else if let Some(duration) = duration {
        let Some(deadline) = linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
        else {
            return LINUX_EINVAL;
        };
        deadline
    } else {
        0
    };
    let slot = usize::from(current.slot);
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(
            wait_kind,
            input.address,
            input.epoll | input.maximum.min(u64::from(u32::MAX)) << 32,
            deadline,
        )
    {
        return LINUX_EINVAL;
    }
    let prior_signal_mask = X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst);
    if let Some(mask) = temporary_signal_mask {
        X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot]
            .store(prior_signal_mask, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(mask, Ordering::SeqCst);
    }
    let mut target_registers = LinuxSyscallFrame::ZERO;
    let mut target_rip = 0;
    let mut target_rsp = 0;
    let mut target_rflags = 0;
    let mut target_rax = 0;
    if !install_linux_thread_return(
        target,
        &mut target_registers,
        &mut target_rip,
        &mut target_rsp,
        &mut target_rflags,
        &mut target_rax,
    ) {
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_RUNNING, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_CURRENT_THREAD_SLOT
            .store(current.slot, Ordering::SeqCst);
        let _ = install_linux_tls_context(tls);
        if temporary_signal_mask.is_some() {
            store_current_linux_signal_mask(prior_signal_mask);
        }
        return LINUX_EINVAL;
    }
    let selected = LinuxUserContext {
        registers: target_registers,
        rip: target_rip,
        rsp: target_rsp,
        rflags: target_rflags,
        rax: target_rax,
        fs_base: active_fs_base(),
    };
    if !write_linux_thread_live_return(output, target, selected) {
        return LINUX_EINVAL;
    }
    X86_RUNTIME
        .LINUX_LIVE_RETURN_VALIDATED
        .store(true, Ordering::SeqCst);
    if wait_kind == LINUX_THREAD_WAIT_EPOLL_PWAIT {
        X86_RUNTIME
            .LINUX_EPOLL_PWAIT_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else {
        X86_RUNTIME
            .LINUX_EPOLL_WAIT_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
    }
    LINUX_RETURN_FROM_IRET
}

pub(super) fn linux_temporary_signal_mask(input: LinuxSignalMaskInput) -> Result<u64, u64> {
    if input.address == 0 {
        return Ok(X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst));
    }
    if input.size != LINUX_SIGNAL_SET_SIZE {
        return Err(LINUX_EINVAL);
    }
    let mut signal_mask = [0_u8; LINUX_SIGNAL_SET_SIZE as usize];
    if !copy_from_linux_user(input.address, &mut signal_mask) {
        return Err(LINUX_EFAULT);
    }
    Ok(u64::from_ne_bytes(signal_mask) & !LINUX_UNBLOCKABLE_SIGNALS)
}

pub(super) fn linux_epoll_pwait_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    input: LinuxEpollWaitInput,
    timeout: u64,
    signal_mask: LinuxSignalMaskInput,
) -> u64 {
    let signal_mask = match linux_epoll_signal_mask(signal_mask) {
        Ok(mask) => mask,
        Err(error) => return error,
    };
    let timeout = timeout as u32 as i32;
    let duration = if timeout < 0 {
        None
    } else {
        let Some(duration) = (timeout as u64).checked_mul(1_000_000) else {
            return LINUX_EINVAL;
        };
        Some(duration)
    };
    linux_epoll_wait_duration_live_return(
        output,
        caller,
        input,
        duration,
        LINUX_EPOLL_PWAIT_SYSCALL,
        signal_mask,
    )
}

/// The temporary mask an epoll_pwait or epoll_pwait2 call gives, or `None`
/// for a null mask (musl's epoll_wait passes one).
fn linux_epoll_signal_mask(input: LinuxSignalMaskInput) -> Result<Option<u64>, u64> {
    if input.address == 0 {
        return Ok(None);
    }
    linux_temporary_signal_mask(input).map(Some)
}

pub(super) fn linux_epoll_pwait2_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    input: LinuxEpollWaitInput,
    timeout_address: u64,
    signal_mask: LinuxSignalMaskInput,
) -> u64 {
    let duration = if timeout_address == 0 {
        None
    } else {
        let mut timeout = [0_u8; 16];
        if !copy_from_linux_user(timeout_address, &mut timeout) {
            return LINUX_EFAULT;
        }
        let seconds = i64::from_ne_bytes(timeout[..8].try_into().unwrap());
        let nanoseconds = i64::from_ne_bytes(timeout[8..].try_into().unwrap());
        if seconds < 0 || !(0..NANOSECONDS_PER_SECOND as i64).contains(&nanoseconds) {
            return LINUX_EINVAL;
        }
        let Some(duration) = (seconds as u64)
            .checked_mul(NANOSECONDS_PER_SECOND)
            .and_then(|seconds| seconds.checked_add(nanoseconds as u64))
        else {
            return LINUX_EINVAL;
        };
        Some(duration)
    };
    let signal_mask = match linux_epoll_signal_mask(signal_mask) {
        Ok(mask) => mask,
        Err(error) => return error,
    };
    linux_epoll_wait_duration_live_return(
        output,
        caller,
        input,
        duration,
        LINUX_EPOLL_PWAIT2_SYSCALL,
        signal_mask,
    )
}

pub(super) fn linux_epoll_descriptor(descriptor: u64) -> bool {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return descriptor >= LINUX_AUX_DESCRIPTOR_FIRST
            && linux_fd_cell::<u8>(descriptor, LinuxFdField::Epoll).load(Ordering::SeqCst) != 0;
    }
    u64::from(
        X86_RUNTIME
            .ELF_PROBE_EPOLL_DESCRIPTOR
            .load(Ordering::SeqCst),
    )
    .checked_sub(1)
        == Some(descriptor)
}
