use super::*;

pub(super) fn complete_linux_timerfd_read_wait(slot: usize) -> bool {
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            != LINUX_THREAD_WAIT_TIMERFD_READ
    {
        return false;
    }
    let descriptor = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = linux_timerfd_read(descriptor, address, 8).unwrap_or(LINUX_EBADF);
    if result == LINUX_ENOSYS {
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(
            linux_timerfd_state(descriptor)
                .map(|state| state.deadline.load(Ordering::SeqCst))
                .unwrap_or(0),
            Ordering::SeqCst,
        );
        if X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::SeqCst) != 0 {
            X86_RUNTIME
                .LINUX_TIMED_WAITS_ACTIVE
                .store(true, Ordering::Release);
        }
        return false;
    }
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_TIMERFD_READ_WAKE_COUNT
        .fetch_add(1, Ordering::SeqCst);
    true
}

pub(super) fn wake_linux_timerfd_read_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_timerfd_read_wait(slot));
    }
    woken
}

pub(super) fn linux_timerfd_create(clock: u64, flags: u64) -> u64 {
    let clock = u64::from(clock as u32);
    let flags = u64::from(flags as u32);
    if !matches!(
        clock,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_BOOTTIME_ALARM
    ) || flags & !(LINUX_TFD_NONBLOCK | LINUX_O_CLOEXEC) != 0
    {
        return LINUX_EINVAL;
    }
    let runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    if !runtime
        && X86_RUNTIME
            .ELF_PROBE_TIMERFD_DESCRIPTOR
            .load(Ordering::SeqCst)
            != 0
    {
        return LINUX_EMFILE;
    }
    let start = if runtime {
        LINUX_AUX_DESCRIPTOR_FIRST
    } else {
        2
    };
    let descriptor = if runtime {
        match linux_allocate_descriptor(start) {
            Ok(descriptor) => descriptor,
            Err(error) => return error,
        }
    } else {
        let Some(descriptor) = (start..LINUX_AUX_DESCRIPTOR_LIMIT)
            .find(|descriptor| linux_aux_descriptor_free(*descriptor))
        else {
            return LINUX_EMFILE;
        };
        descriptor
    };
    if runtime {
        let Some(id) = crate::linux_event_files::create_timerfd(clock as u8, flags as u32) else {
            return LINUX_ENFILE;
        };
        linux_legacy_descriptor_offset(descriptor).store(id, Ordering::SeqCst);
        linux_fd_cell::<u8>(descriptor, LinuxFdField::TimerFd).store(1, Ordering::SeqCst);
    } else {
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_CLOCK
            .store(clock as u8, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_FLAGS
            .store(flags as u32, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_INTERVAL
            .store(0, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_DEADLINE
            .store(0, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_TIMERFD_DESCRIPTOR
            .store(descriptor as u16, Ordering::SeqCst);
    }
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    descriptor
}

/// The clocks a POSIX timer may follow: wall-clock ones are converted to
/// the monotonic nanoseconds deadlines count in at timer_settime; the CPU
/// time clocks run as the monotonic clock here.
fn linux_posix_timer_clock_supported(clock: u64) -> bool {
    matches!(
        clock,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_PROCESS_CPUTIME_ID
            | LINUX_CLOCK_THREAD_CPUTIME_ID
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_BOOTTIME_ALARM
    )
}

/// Whether a timer's clock counts wall time, whose absolute values need
/// converting to the monotonic clock.
/// Timestamp-counter cycles in nanoseconds.
pub(super) fn linux_cycles_nanoseconds(cycles: u64) -> u64 {
    let frequency = X86_RUNTIME.ELF_PROBE_CLOCK_FREQUENCY.load(Ordering::SeqCst);
    if frequency == 0 {
        return 0;
    }
    cycles / frequency * NANOSECONDS_PER_SECOND
        + cycles % frequency * NANOSECONDS_PER_SECOND / frequency
}

/// The CPU time the current process's threads have used, the running one's
/// current interval included: each thread's charged time only grows, where
/// the process's running interval is marked once per runtime and moves
/// with every CPU that takes one of its threads up.
pub(super) fn linux_current_process_cpu_cycles() -> u64 {
    (0..LINUX_THREAD_LIMIT)
        .filter(|slot| {
            X86_RUNTIME.LINUX_THREAD_STATES[*slot].load(Ordering::Relaxed) != LINUX_THREAD_FREE
        })
        .map(linux_thread_cpu_cycles)
        .fold(0_u64, u64::saturating_add)
}

pub(super) fn linux_current_process_cpu_nanoseconds() -> u64 {
    linux_cycles_nanoseconds(linux_current_process_cpu_cycles())
}

fn linux_current_thread_cpu_nanoseconds() -> u64 {
    linux_cycles_nanoseconds(current_linux_thread_slot().map_or(0, linux_thread_cpu_cycles))
}

/// "Now" on a POSIX timer's clock: CPU nanoseconds for a CPU clock (the
/// thread's for a thread clock), else the monotonic clock.
fn linux_posix_timer_now(clock: u32) -> Option<u64> {
    if linux_process::posix_clock_is_thread_cpu(clock) {
        Some(linux_current_thread_cpu_nanoseconds())
    } else if linux_process::posix_clock_is_cpu(clock) {
        Some(linux_current_process_cpu_nanoseconds())
    } else {
        linux_elapsed_nanoseconds()
    }
}

fn linux_posix_timer_clock_is_wall(clock: u32) -> bool {
    matches!(
        u64::from(clock),
        LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_ALARM
    )
}

/// Keeps the banked earliest deadline, the check before the process table.
pub(super) fn linux_refresh_posix_timer_cache(pid: u32) {
    X86_RUNTIME.ELF_PROBE_POSIX_TIMER_DEADLINE.store(
        linux_process::earliest_posix_timer_deadline(pid),
        Ordering::SeqCst,
    );
}

/// timer_create(2): a timer of the calling process, numbered from 1. A
/// null sigevent means SIGALRM with the timer's id as the value, as Linux.
pub(super) fn linux_timer_create(clock: u64, event_address: u64, timer_address: u64) -> u64 {
    const SIGEV_SIGNAL: u32 = 0;
    const SIGEV_NONE: u32 = 1;
    const SIGEV_THREAD: u32 = 2;
    const SIGEV_THREAD_ID: u32 = 4;
    let clock = u64::from(clock as u32);
    if !linux_posix_timer_clock_supported(clock) {
        return LINUX_EINVAL;
    }
    if !linux_writable_user_range_contains(timer_address, size_of::<i32>()) {
        return LINUX_EFAULT;
    }
    let pid = current_linux_process_pid();
    let mut timer = linux_process::PosixTimer {
        clock: clock as u32,
        notify: SIGEV_SIGNAL,
        signal: LINUX_SIGALRM as u8,
        tid: 0,
        value: 0,
        deadline: 0,
        interval: 0,
        overrun: 0,
        delivered_overrun: 0,
    };
    if event_address != 0 {
        let mut event = [0_u8; 64];
        if !copy_from_linux_user(event_address, &mut event) {
            return LINUX_EFAULT;
        }
        let value = u64::from_ne_bytes(event[..8].try_into().unwrap());
        let signal = i32::from_ne_bytes(event[8..12].try_into().unwrap());
        let notify = u32::from_ne_bytes(event[12..16].try_into().unwrap());
        let tid = i32::from_ne_bytes(event[16..20].try_into().unwrap());
        // SIGEV_THREAD is the C library's own: it asks the kernel for a
        // signal to a thread of its (SIGEV_THREAD_ID) or for none.
        match notify {
            SIGEV_NONE => {}
            SIGEV_SIGNAL | SIGEV_THREAD => {
                if !(1..=64).contains(&signal) {
                    return LINUX_EINVAL;
                }
            }
            SIGEV_THREAD_ID => {
                if !(1..=64).contains(&signal)
                    || u32::try_from(tid)
                        .ok()
                        .and_then(linux_thread_state_by_tid)
                        .is_none_or(|(owner, _)| owner != pid)
                {
                    return LINUX_EINVAL;
                }
            }
            _ => return LINUX_EINVAL,
        }
        timer.notify = if notify == SIGEV_THREAD {
            SIGEV_SIGNAL
        } else {
            notify
        };
        timer.signal = if notify == SIGEV_NONE {
            0
        } else {
            signal as u8
        };
        timer.tid = if notify == SIGEV_THREAD_ID {
            tid as u32
        } else {
            0
        };
        timer.value = value;
    }
    let Some(id) = linux_process::create_posix_timer(pid, timer) else {
        return LINUX_EAGAIN;
    };
    if event_address == 0 {
        let _ = linux_process::update_posix_timer(pid, id, |timer| timer.value = u64::from(id));
    }
    if copy_to_linux_user(timer_address, &(id as i32).to_ne_bytes()) {
        0
    } else {
        let _ = linux_process::delete_posix_timer(pid, id);
        LINUX_EFAULT
    }
}

/// timer_settime(2): arms a timer, or disarms it with a zero value; the
/// time it had left and its interval go to `old_address`.
pub(super) fn linux_timer_settime(
    timer: u64,
    flags: u64,
    new_address: u64,
    old_address: u64,
) -> u64 {
    const TIMER_ABSTIME: u64 = 1;
    let id = timer as u32;
    let flags = u64::from(flags as u32);
    let pid = current_linux_process_pid();
    let Some(current) = linux_process::posix_timer(pid, id) else {
        return LINUX_EINVAL;
    };
    if flags & !TIMER_ABSTIME != 0 {
        return LINUX_EINVAL;
    }
    // No new value is EINVAL, as Linux; an unreadable one EFAULT.
    if new_address == 0 {
        return LINUX_EINVAL;
    }
    if old_address != 0 && !linux_writable_user_range_contains(old_address, 32) {
        return LINUX_EFAULT;
    }
    let mut specification = [0_u8; 32];
    if !copy_from_linux_user(new_address, &mut specification) {
        return LINUX_EFAULT;
    }
    let Some(interval) = linux_timespec_nanoseconds(&specification[..16]) else {
        return LINUX_EINVAL;
    };
    let Some(value) = linux_timespec_nanoseconds(&specification[16..]) else {
        return LINUX_EINVAL;
    };
    let Some(now) = linux_posix_timer_now(current.clock) else {
        return LINUX_ENOSYS;
    };
    let old = linux_timer_specification(current.interval, current.deadline, now);
    let deadline = if value == 0 {
        0
    } else if flags & TIMER_ABSTIME == 0 {
        let Some(deadline) = now.checked_add(value) else {
            return LINUX_EINVAL;
        };
        deadline
    } else if linux_posix_timer_clock_is_wall(current.clock) {
        // An absolute wall time: as far ahead of (or behind) the monotonic
        // clock as it is of the wall clock now. A past one fires at once,
        // and keeps its distance so its overrun counts the intervals since
        // (timer_settime03 expects that count saturated).
        let Some((seconds, nanoseconds)) = linux_realtime_time() else {
            return LINUX_ENOSYS;
        };
        let wall_now = seconds
            .saturating_mul(NANOSECONDS_PER_SECOND)
            .saturating_add(nanoseconds);
        if value >= wall_now {
            now.saturating_add(value - wall_now)
        } else {
            now.saturating_sub(wall_now - value).max(1)
        }
    } else {
        linux_time_namespace_host(u64::from(current.clock), value).max(1)
    };
    if old_address != 0 && !copy_to_linux_user(old_address, &old) {
        return LINUX_EFAULT;
    }
    if linux_process::update_posix_timer(pid, id, |timer| {
        timer.deadline = deadline;
        timer.interval = interval;
        timer.overrun = 0;
        timer.delivered_overrun = 0;
    })
    .is_none()
    {
        return LINUX_EINVAL;
    }
    linux_refresh_posix_timer_cache(pid);
    0
}

/// timer_gettime(2): the time a timer has left and its interval.
pub(super) fn linux_timer_gettime(timer: u64, address: u64) -> u64 {
    let pid = current_linux_process_pid();
    let Some(current) = linux_process::posix_timer(pid, timer as u32) else {
        return LINUX_EINVAL;
    };
    let Some(now) = linux_posix_timer_now(current.clock) else {
        return LINUX_ENOSYS;
    };
    let specification = linux_timer_specification(current.interval, current.deadline, now);
    if copy_to_linux_user(address, &specification) {
        0
    } else {
        LINUX_EFAULT
    }
}

/// timer_getoverrun(2): the expirations the last delivered signal stood
/// for beyond its own, at most DELAYTIMER_MAX.
pub(super) fn linux_timer_getoverrun(timer: u64) -> u64 {
    let pid = current_linux_process_pid();
    match linux_process::posix_timer(pid, timer as u32) {
        Some(current) => u64::from(current.delivered_overrun.min(i32::MAX as u32)),
        None => LINUX_EINVAL,
    }
}

/// timer_delete(2).
pub(super) fn linux_timer_delete(timer: u64) -> u64 {
    let pid = current_linux_process_pid();
    if !linux_process::delete_posix_timer(pid, timer as u32) {
        return LINUX_EINVAL;
    }
    linux_refresh_posix_timer_cache(pid);
    0
}

/// Fires the current process's POSIX timers whose deadline passed: queues
/// each one's signal (si_code SI_TIMER, si_value as created) and moves a
/// periodic timer on. Checked where the interval timer is; the banked
/// earliest deadline decides without the process table.
pub(in crate::arch::x86_64) fn refresh_linux_posix_timers() -> bool {
    const SIGEV_NONE: u32 = 1;
    const SIGEV_THREAD_ID: u32 = 4;
    let earliest = X86_RUNTIME
        .ELF_PROBE_POSIX_TIMER_DEADLINE
        .load(Ordering::SeqCst);
    if earliest == 0 {
        return false;
    }
    let Some(now) = linux_elapsed_nanoseconds() else {
        return false;
    };
    if now < earliest {
        return false;
    }
    let pid = current_linux_process_pid();
    // Called in a system call, where the signal queues may be consulted.
    let pending = X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst)
        | linux_dynamic_pending_masks().map_or(0, |(process, thread)| process | thread);
    let mut expiries = [linux_process::PosixTimerExpiry::NONE; linux_process::TIMER_EXPIRY_LIMIT];
    let cpu_now = linux_current_process_cpu_nanoseconds();
    let thread_now = linux_current_thread_cpu_nanoseconds();
    let count =
        linux_process::expire_posix_timers(pid, (now, cpu_now, thread_now), pending, &mut expiries);
    let mut queued = false;
    for expiry in &expiries[..count] {
        if expiry.notify == SIGEV_NONE || expiry.signal == 0 {
            continue;
        }
        // A thread-directed signal reaches the process until threads have
        // queues of their own a timer can reach; the thread is recorded.
        let _thread = (expiry.notify == SIGEV_THREAD_ID).then_some(expiry.tid);
        // Queued as kill queues a signal; its delivery freezes the overrun.
        // An interval timer's signal comes from the kernel (SI_KERNEL).
        let code = if expiry.interval_timer {
            0x80
        } else {
            LINUX_SI_TIMER
        };
        if linux_queue_process_signal(
            pid,
            u64::from(expiry.signal),
            code,
            (!expiry.interval_timer).then_some(expiry.value),
        ) == 0
        {
            queued = true;
        }
    }
    linux_refresh_posix_timer_cache(pid);
    queued
}

pub(super) fn linux_timerfd_settime(
    descriptor: u64,
    flags: u64,
    new_address: u64,
    old_address: u64,
) -> u64 {
    const TFD_TIMER_CANCEL_ON_SET: u64 = 2;
    let descriptor = u64::from(descriptor as u32);
    let flags = u64::from(flags as u32);
    // An open descriptor that is no timerfd is EINVAL, as in Linux.
    let Some(state) = linux_timerfd_state(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    };
    let clock = u64::from(state.clock.load(Ordering::SeqCst));
    if flags & !(LINUX_TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0
        || flags & TFD_TIMER_CANCEL_ON_SET != 0
            && (flags & LINUX_TFD_TIMER_ABSTIME == 0
                || !matches!(clock, LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_ALARM))
    {
        return LINUX_EINVAL;
    }
    if old_address != 0 && !linux_writable_user_range_contains(old_address, 32) {
        return LINUX_EFAULT;
    }
    let mut specification = [0_u8; 32];
    if !copy_from_linux_user(new_address, &mut specification) {
        return LINUX_EFAULT;
    }
    let Some(interval) = linux_timespec_nanoseconds_saturating(&specification[..16]) else {
        return LINUX_EINVAL;
    };
    let Some(value) = linux_timespec_nanoseconds_saturating(&specification[16..]) else {
        return LINUX_EINVAL;
    };
    let Some(now) = linux_elapsed_nanoseconds() else {
        return LINUX_ENOSYS;
    };
    let old = linux_timer_specification(
        state.interval.load(Ordering::SeqCst),
        state.deadline.load(Ordering::SeqCst),
        now,
    );
    let deadline = if value == 0 {
        0
    } else if flags & LINUX_TFD_TIMER_ABSTIME != 0
        && matches!(clock, LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_ALARM)
    {
        let Some((seconds, nanoseconds)) = linux_realtime_time() else {
            return LINUX_ENOSYS;
        };
        let Some(realtime_now) = seconds
            .checked_mul(NANOSECONDS_PER_SECOND)
            .and_then(|seconds| seconds.checked_add(nanoseconds))
        else {
            return LINUX_EINVAL;
        };
        now.saturating_add(value.saturating_sub(realtime_now))
    } else if flags & LINUX_TFD_TIMER_ABSTIME != 0 {
        linux_time_namespace_host(clock, value)
    } else {
        let Some(deadline) = now.checked_add(value) else {
            return LINUX_EINVAL;
        };
        deadline
    };
    if old_address != 0 && !copy_to_linux_user(old_address, &old) {
        return LINUX_EFAULT;
    }
    state.interval.store(interval, Ordering::SeqCst);
    state.deadline.store(deadline, Ordering::SeqCst);
    wake_linux_descriptor_waits();
    0
}

pub(super) fn linux_timerfd_gettime(descriptor: u64, address: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    // An open descriptor that is no timerfd is EINVAL, as in Linux.
    let Some(state) = linux_timerfd_state(descriptor) else {
        return if linux_descriptor_open(descriptor) {
            LINUX_EINVAL
        } else {
            LINUX_EBADF
        };
    };
    let Some(now) = linux_elapsed_nanoseconds() else {
        return LINUX_ENOSYS;
    };
    let specification = linux_timer_specification(
        state.interval.load(Ordering::SeqCst),
        state.deadline.load(Ordering::SeqCst),
        now,
    );
    if !copy_to_linux_user(address, &specification) {
        return LINUX_EFAULT;
    }
    0
}

pub(super) fn linux_timerfd_read(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    let state = linux_timerfd_state(descriptor)?;
    if count != 8 {
        return Some(LINUX_EINVAL);
    }
    let Some(now) = linux_elapsed_nanoseconds() else {
        return Some(LINUX_ENOSYS);
    };
    let deadline = state.deadline.load(Ordering::SeqCst);
    if deadline == 0 || now < deadline {
        return Some(
            if state.flags.load(Ordering::SeqCst) & LINUX_TFD_NONBLOCK as u32 != 0 {
                LINUX_EAGAIN
            } else {
                LINUX_ENOSYS
            },
        );
    }
    let interval = state.interval.load(Ordering::SeqCst);
    let expirations = now
        .saturating_sub(deadline)
        .checked_div(interval)
        .map_or(1, |elapsed| elapsed + 1);
    if !copy_to_linux_user(address, &expirations.to_ne_bytes()) {
        return Some(LINUX_EFAULT);
    }
    let next = if interval == 0 {
        0
    } else {
        deadline.saturating_add(expirations.saturating_mul(interval))
    };
    state.deadline.store(next, Ordering::SeqCst);
    Some(8)
}

pub(super) fn linux_timespec_nanoseconds(timespec: &[u8]) -> Option<u64> {
    let seconds = i64::from_ne_bytes(timespec[..8].try_into().ok()?);
    let nanoseconds = i64::from_ne_bytes(timespec[8..16].try_into().ok()?);
    if seconds < 0 || !(0..NANOSECONDS_PER_SECOND as i64).contains(&nanoseconds) {
        return None;
    }
    (seconds as u64)
        .checked_mul(NANOSECONDS_PER_SECOND)
        .and_then(|value| value.checked_add(nanoseconds as u64))
}

fn linux_timespec_nanoseconds_saturating(timespec: &[u8]) -> Option<u64> {
    let seconds = i64::from_ne_bytes(timespec.get(..8)?.try_into().ok()?);
    let nanoseconds = i64::from_ne_bytes(timespec.get(8..16)?.try_into().ok()?);
    if seconds < 0 || !(0..NANOSECONDS_PER_SECOND as i64).contains(&nanoseconds) {
        return None;
    }
    Some(
        (seconds as u64)
            .saturating_mul(NANOSECONDS_PER_SECOND)
            .saturating_add(nanoseconds as u64),
    )
}

fn linux_timer_specification(interval: u64, deadline: u64, now: u64) -> [u8; 32] {
    let remaining = if deadline == 0 {
        0
    } else if now < deadline {
        deadline - now
    } else if interval == 0 {
        0
    } else {
        interval - (now - deadline) % interval
    };
    let mut specification = [0_u8; 32];
    linux_store_timespec(&mut specification[..16], interval);
    linux_store_timespec(&mut specification[16..], remaining);
    specification
}

pub(super) fn linux_store_timespec(timespec: &mut [u8], nanoseconds: u64) {
    timespec[..8].copy_from_slice(&(nanoseconds / NANOSECONDS_PER_SECOND).to_ne_bytes());
    timespec[8..16].copy_from_slice(&(nanoseconds % NANOSECONDS_PER_SECOND).to_ne_bytes());
}

pub(super) struct LinuxTimerfdState {
    clock: &'static dyn LinuxFileCell<u8>,
    pub(super) flags: &'static dyn LinuxFileCell<u32>,
    interval: &'static dyn LinuxFileCell<u64>,
    pub(super) deadline: &'static dyn LinuxFileCell<u64>,
}

pub(super) fn linux_timerfd_state(descriptor: u64) -> Option<LinuxTimerfdState> {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let file = crate::linux_event_files::timerfd(linux_timerfd_file(descriptor)?)?;
        return Some(LinuxTimerfdState {
            clock: &file.clock,
            flags: &file.flags,
            interval: &file.interval,
            deadline: &file.deadline,
        });
    }
    (descriptor >= 2
        && u64::from(
            X86_RUNTIME
                .ELF_PROBE_TIMERFD_DESCRIPTOR
                .load(Ordering::SeqCst),
        ) == descriptor)
        .then_some(LinuxTimerfdState {
            clock: &X86_RUNTIME.ELF_PROBE_TIMERFD_CLOCK,
            flags: &X86_RUNTIME.ELF_PROBE_TIMERFD_FLAGS,
            interval: &X86_RUNTIME.ELF_PROBE_TIMERFD_INTERVAL,
            deadline: &X86_RUNTIME.ELF_PROBE_TIMERFD_DEADLINE,
        })
}

pub(super) fn linux_timerfd_descriptor(descriptor: u64) -> bool {
    linux_timerfd_state(descriptor).is_some()
}
