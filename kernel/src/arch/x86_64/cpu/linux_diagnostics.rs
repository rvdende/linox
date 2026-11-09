use super::*;

pub(super) fn linux_trace_futex(event: u8, address: u64, detail: u64) {
    let index =
        LINUX_FUTEX_TRACE_NEXT.fetch_add(1, Ordering::Relaxed) as usize % LINUX_FUTEX_TRACE_LIMIT;
    let cpu = linux_bank_cpu() as u64;
    let pid = u64::from(current_linux_process_pid());
    let tid = u64::from(current_linux_tid().unwrap_or(0));
    let entry = &LINUX_FUTEX_TRACE[index];
    entry[0].store(
        cpu << 56 | u64::from(event) << 48 | pid << 24 | tid,
        Ordering::Relaxed,
    );
    entry[1].store(address, Ordering::Relaxed);
    entry[2].store(detail, Ordering::Relaxed);
    entry[3].store(
        linux_elapsed_nanoseconds().unwrap_or(0) / 1000,
        Ordering::Relaxed,
    );
}

fn linux_report_futex_trace() {
    serial_write("linox: futex trace cpu/event/pid/tid/address/detail/us (oldest first):\r\n");
    let next = LINUX_FUTEX_TRACE_NEXT.load(Ordering::Relaxed) as usize;
    let count = next.min(LINUX_FUTEX_TRACE_LIMIT).min(48);
    for step in 0..count {
        let index = (next + LINUX_FUTEX_TRACE_LIMIT - count + step) % LINUX_FUTEX_TRACE_LIMIT;
        let entry = &LINUX_FUTEX_TRACE[index];
        let head = entry[0].load(Ordering::Relaxed);
        serial_write("linox: futex ");
        for value in [
            head >> 56,
            head >> 48 & 0xff,
            head >> 24 & 0xff_ffff,
            head & 0xff_ffff,
            entry[1].load(Ordering::Relaxed),
            entry[2].load(Ordering::Relaxed),
            entry[3].load(Ordering::Relaxed),
        ] {
            serial_write_u64(value);
            serial_write(" ");
        }
        serial_write("\r\n");
    }
}

/// The runtime loop's stall diagnostic: once the domain has run sixty
/// seconds, the futex trace, banks and task states, from the loop itself,
/// which runs while the boot CPU only halts between ticks (the timer's
/// snapshot needs a tick in user mode).
pub(super) fn linux_stall_diagnostic_from_loop() {
    if X86_RUNTIME
        .LINUX_RUNTIME_STALLED_DIAGNOSTIC_WRITTEN
        .load(Ordering::SeqCst)
        || !linux_elapsed_nanoseconds().is_some_and(|elapsed| elapsed >= 60_000_000_000)
        || X86_RUNTIME
            .LINUX_RUNTIME_STALLED_DIAGNOSTIC_WRITTEN
            .swap(true, Ordering::SeqCst)
    {
        return;
    }
    serial_write("linox: Linux runtime loop sixty-second diagnostic\r\n");
    linux_write_stall_diagnostic();
}

/// The futex trace, live bank threads, banks and task states: the most
/// telling first, in case the console is cut off.
pub(super) fn linux_write_stall_diagnostic() {
    linux_report_futex_trace();
    linux_report_live_bank_threads();
    linux_report_process_banks();
    linux_show_task_states();
}

pub(super) struct LinuxBootSyscallProfile {
    number: usize,
    started: u64,
}

impl LinuxBootSyscallProfile {
    pub(super) fn start(number: u64, runtime: bool) -> Option<Self> {
        (cfg!(feature = "linux-boot-profile") && runtime)
            .then(|| usize::try_from(number).ok())
            .flatten()
            .filter(|number| *number < LINUX_BOOT_PROFILE_SYSCALL_LIMIT)
            .map(|number| Self {
                number,
                started: timer::timestamp_counter(),
            })
    }
}

impl Drop for LinuxBootSyscallProfile {
    fn drop(&mut self) {
        let elapsed = timer::timestamp_counter().saturating_sub(self.started);
        X86_RUNTIME.LINUX_BOOT_PROFILE_SYSCALL_COUNTS[self.number].fetch_add(1, Ordering::Relaxed);
        X86_RUNTIME.LINUX_BOOT_PROFILE_SYSCALL_TICKS[self.number]
            .fetch_add(elapsed, Ordering::Relaxed);
    }
}

pub(crate) fn write_linux_runtime_syscall_trace() {
    let count = X86_RUNTIME
        .LINUX_RUNTIME_SYSCALL_TRACE_COUNT
        .load(Ordering::SeqCst) as usize;
    let retained = count.min(LINUX_RUNTIME_SYSCALL_TRACE_LIMIT);
    let start = count.saturating_sub(retained);
    crate::serial_write_bytes(b"linox: Linux init recent syscall/result pairs:");
    for offset in 0..retained {
        let index = (start + offset) % LINUX_RUNTIME_SYSCALL_TRACE_LIMIT;
        crate::serial_write_bytes(b" ");
        crate::serial_write_u64(
            X86_RUNTIME.LINUX_RUNTIME_SYSCALL_TRACE[index].load(Ordering::SeqCst),
        );
        crate::serial_write_bytes(b"/");
        crate::serial_write_u64(
            X86_RUNTIME.LINUX_RUNTIME_SYSCALL_RESULT_TRACE[index].load(Ordering::SeqCst),
        );
    }
    crate::serial_write_bytes(b"\r\n");
}

fn linux_profile_syscall_name(number: u64) -> &'static str {
    match number {
        LINUX_READ_SYSCALL => "read",
        LINUX_WRITE_SYSCALL => "write",
        LINUX_CLOSE_SYSCALL => "close",
        LINUX_STAT_SYSCALL => "stat",
        LINUX_FSTAT_SYSCALL => "fstat",
        LINUX_LSTAT_SYSCALL => "lstat",
        LINUX_POLL_SYSCALL => "poll",
        LINUX_LSEEK_SYSCALL => "lseek",
        LINUX_MMAP_SYSCALL => "mmap",
        LINUX_MPROTECT_SYSCALL => "mprotect",
        LINUX_MUNMAP_SYSCALL => "munmap",
        LINUX_BRK_SYSCALL => "brk",
        LINUX_RT_SIGACTION_SYSCALL => "rt_sigaction",
        LINUX_RT_SIGPROCMASK_SYSCALL => "rt_sigprocmask",
        LINUX_IOCTL_SYSCALL => "ioctl",
        LINUX_PREAD64_SYSCALL => "pread64",
        LINUX_READV_SYSCALL => "readv",
        LINUX_WRITEV_SYSCALL => "writev",
        LINUX_ACCESS_SYSCALL => "access",
        LINUX_PIPE2_SYSCALL => "pipe2",
        LINUX_SELECT_SYSCALL => "select",
        LINUX_SCHED_YIELD_SYSCALL => "sched_yield",
        LINUX_NANOSLEEP_SYSCALL => "nanosleep",
        LINUX_GETPID_SYSCALL => "getpid",
        LINUX_SOCKET_SYSCALL => "socket",
        LINUX_CONNECT_SYSCALL => "connect",
        LINUX_ACCEPT_SYSCALL => "accept",
        LINUX_SENDTO_SYSCALL => "sendto",
        LINUX_RECVFROM_SYSCALL => "recvfrom",
        LINUX_SENDMSG_SYSCALL => "sendmsg",
        LINUX_RECVMSG_SYSCALL => "recvmsg",
        LINUX_SHUTDOWN_SYSCALL => "shutdown",
        LINUX_BIND_SYSCALL => "bind",
        LINUX_LISTEN_SYSCALL => "listen",
        LINUX_GETSOCKNAME_SYSCALL => "getsockname",
        LINUX_GETPEERNAME_SYSCALL => "getpeername",
        LINUX_SOCKETPAIR_SYSCALL => "socketpair",
        LINUX_SETSOCKOPT_SYSCALL => "setsockopt",
        LINUX_GETSOCKOPT_SYSCALL => "getsockopt",
        LINUX_CLONE_SYSCALL => "clone",
        LINUX_FORK_SYSCALL => "fork",
        LINUX_VFORK_SYSCALL => "vfork",
        LINUX_EXECVE_SYSCALL => "execve",
        LINUX_EXIT_SYSCALL => "exit",
        LINUX_WAIT4_SYSCALL => "wait4",
        LINUX_KILL_SYSCALL => "kill",
        LINUX_UNAME_SYSCALL => "uname",
        LINUX_FCNTL_SYSCALL => "fcntl",
        LINUX_FSYNC_SYSCALL => "fsync",
        LINUX_GETCWD_SYSCALL => "getcwd",
        LINUX_CHDIR_SYSCALL => "chdir",
        LINUX_READLINK_SYSCALL => "readlink",
        LINUX_GETDENTS64_SYSCALL => "getdents64",
        LINUX_GETTID_SYSCALL => "gettid",
        LINUX_FUTEX_SYSCALL => "futex",
        LINUX_EPOLL_WAIT_SYSCALL => "epoll_wait",
        LINUX_EPOLL_CTL_SYSCALL => "epoll_ctl",
        LINUX_OPENAT_SYSCALL => "openat",
        LINUX_NEWFSTATAT_SYSCALL => "newfstatat",
        LINUX_UNLINKAT_SYSCALL => "unlinkat",
        LINUX_READLINKAT_SYSCALL => "readlinkat",
        LINUX_EPOLL_PWAIT_SYSCALL => "epoll_pwait",
        LINUX_ACCEPT4_SYSCALL => "accept4",
        LINUX_DUP3_SYSCALL => "dup3",
        LINUX_PIPE_SYSCALL => "pipe",
        LINUX_GETRANDOM_SYSCALL => "getrandom",
        LINUX_STATX_SYSCALL => "statx",
        LINUX_CLONE3_SYSCALL => "clone3",
        _ => "unknown",
    }
}

pub(super) fn write_linux_boot_profile() {
    if !cfg!(feature = "linux-boot-profile") {
        return;
    }
    let frequency = X86_RUNTIME
        .ELF_PROBE_CLOCK_FREQUENCY
        .load(Ordering::Relaxed)
        .max(1);
    let to_microseconds = |ticks: u64| ticks.saturating_mul(1_000_000) / frequency;
    let mut total_count = 0_u64;
    let mut total_ticks = 0_u64;
    for number in 0..LINUX_BOOT_PROFILE_SYSCALL_LIMIT {
        total_count = total_count.saturating_add(
            X86_RUNTIME.LINUX_BOOT_PROFILE_SYSCALL_COUNTS[number].load(Ordering::Relaxed),
        );
        total_ticks = total_ticks.saturating_add(
            X86_RUNTIME.LINUX_BOOT_PROFILE_SYSCALL_TICKS[number].load(Ordering::Relaxed),
        );
    }
    serial_write("linox: profile syscalls calls/total-us: ");
    serial_write_u64(total_count);
    serial_write("/");
    serial_write_u64(to_microseconds(total_ticks));
    serial_write("\r\n");
    serial_write("linox: profile syscall name/id calls total-us avg-us\r\n");
    let mut emitted = [0_u64; LINUX_BOOT_PROFILE_SYSCALL_LIMIT / 64];
    for _ in 0..24 {
        let mut selected = None;
        let mut selected_ticks = 0_u64;
        for number in 0..LINUX_BOOT_PROFILE_SYSCALL_LIMIT {
            if emitted[number / 64] & (1_u64 << (number % 64)) != 0 {
                continue;
            }
            let ticks =
                X86_RUNTIME.LINUX_BOOT_PROFILE_SYSCALL_TICKS[number].load(Ordering::Relaxed);
            if ticks > selected_ticks {
                selected = Some(number);
                selected_ticks = ticks;
            }
        }
        let Some(number) = selected else {
            break;
        };
        emitted[number / 64] |= 1_u64 << (number % 64);
        let count = X86_RUNTIME.LINUX_BOOT_PROFILE_SYSCALL_COUNTS[number].load(Ordering::Relaxed);
        let microseconds = to_microseconds(selected_ticks);
        serial_write("linox: profile syscall ");
        serial_write(linux_profile_syscall_name(number as u64));
        serial_write("/");
        serial_write_u64(number as u64);
        serial_write(" ");
        serial_write_u64(count);
        serial_write(" ");
        serial_write_u64(microseconds);
        serial_write(" ");
        serial_write_u64(microseconds / count.max(1));
        serial_write("\r\n");
    }
    for (name, count, ticks) in [
        (
            "state-save",
            X86_RUNTIME
                .LINUX_BOOT_PROFILE_SAVE_COUNT
                .load(Ordering::Relaxed),
            X86_RUNTIME
                .LINUX_BOOT_PROFILE_SAVE_TICKS
                .load(Ordering::Relaxed),
        ),
        (
            "state-restore",
            X86_RUNTIME
                .LINUX_BOOT_PROFILE_RESTORE_COUNT
                .load(Ordering::Relaxed),
            X86_RUNTIME
                .LINUX_BOOT_PROFILE_RESTORE_TICKS
                .load(Ordering::Relaxed),
        ),
    ] {
        let microseconds = to_microseconds(ticks);
        serial_write("linox: profile ");
        serial_write(name);
        serial_write(" calls/total-us/avg-us: ");
        serial_write_u64(count);
        serial_write("/");
        serial_write_u64(microseconds);
        serial_write("/");
        serial_write_u64(microseconds / count.max(1));
        serial_write("\r\n");
    }
    for (index, name) in [
        "fork-prepare",
        "child-run",
        "state-switch",
        "address-space-retire",
        "child-cleanup",
        "parent-resume",
        "scheduled-run",
        "page-table-retire",
        "frame-release",
        "frame-reference-check",
        "frame-ownership-check",
        "frame-scrub-release",
        "mmap-frame-allocate",
        "mmap-frame-prepare",
        "mmap-page-install",
    ]
    .into_iter()
    .enumerate()
    {
        let count = X86_RUNTIME.LINUX_BOOT_PROFILE_LIFECYCLE_COUNTS[index].load(Ordering::Relaxed);
        let microseconds = to_microseconds(
            X86_RUNTIME.LINUX_BOOT_PROFILE_LIFECYCLE_TICKS[index].load(Ordering::Relaxed),
        );
        serial_write("linox: profile ");
        serial_write(name);
        serial_write(" calls/total-us/avg-us: ");
        serial_write_u64(count);
        serial_write("/");
        serial_write_u64(microseconds);
        serial_write("/");
        serial_write_u64(microseconds / count.max(1));
        serial_write("\r\n");
    }
}

pub(super) fn reset_linux_boot_profile() {
    if !cfg!(feature = "linux-boot-profile") {
        return;
    }
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

pub(super) fn linux_boot_profile_lifecycle_phase(index: usize, started: Option<u64>) {
    if let Some(started) = started {
        X86_RUNTIME.LINUX_BOOT_PROFILE_LIFECYCLE_COUNTS[index].fetch_add(1, Ordering::Relaxed);
        X86_RUNTIME.LINUX_BOOT_PROFILE_LIFECYCLE_TICKS[index].fetch_add(
            timer::timestamp_counter().saturating_sub(started),
            Ordering::Relaxed,
        );
    }
}

pub(crate) fn linux_boot_profile_record_lifecycle_phase(index: usize, started: u64) {
    linux_boot_profile_lifecycle_phase(index, Some(started));
}

/// Writes `/proc/PID/oom_score_adj` as Linux does: at most 12 bytes are read,
/// surrounding whitespace is ignored and the value must lie in -1000..=1000.
/// A write to `/proc/sysrq-trigger`: its first byte names the request, as
/// on Linux. `t` (show task states) lists every task of the domain in the
/// kernel log, `l` profiles the runtime CPU (`crate::linux_profile`) and `u`
/// reports each CPU's user, kernel, idle and lock-wait time (`cpu_time`);
/// keys Linox has no handler for are accepted and ignored.
pub(super) fn linux_sysrq_trigger_write(address: u64, count: u64) -> u64 {
    if count == 0 {
        return 0;
    }
    let mut key = [0_u8; 1];
    if !copy_from_linux_user(address, &mut key) {
        return LINUX_EFAULT;
    }
    match key[0] {
        b't' => linux_show_task_states(),
        b'l' => crate::linux_profile::start(),
        b'u' => {
            crate::cpu_time::report();
            linux_report_process_banks();
            linux_report_live_bank_threads();
        }
        _ => {}
    }
    count
}

/// Lists each live process and its threads: the thread state (ready,
/// running, blocked), what a blocked thread waits for (wait kind and key:
/// a futex address, or the descriptors of a poll) and its saved user
/// context, which for a thread inside a system call holds the call number
/// and arguments.
fn linux_show_task_states() {
    serial_write("linox: sysrq: show task states\r\n");
    let current = current_linux_process_pid();
    let mut pid = 1;
    while let Some(next) = linux_process::next_live_pid(pid) {
        pid = next + 1;
        let mut name = [0_u8; 16];
        serial_write("linox: task ");
        serial_write_u64(u64::from(next));
        serial_write(" ");
        crate::serial_write_bytes(linux_process_name(next, &mut name));
        serial_write(
            match linux_process::live_process_status(next).map(|status| status.state) {
                Some(linux_process::LiveProcessState::Running) => " R",
                Some(linux_process::LiveProcessState::Sleeping) => " S",
                Some(linux_process::LiveProcessState::Stopped) => " T",
                Some(linux_process::LiveProcessState::Zombie) => " Z",
                None => " ?",
            },
        );
        if next == current {
            serial_write(" (current)");
        }
        // Blocked: what wakes it (`linux_wait_queue::events`) and when.
        if let Some(block) = linux_process::live_process_block(next) {
            serial_write(" blocked events/deadline ");
            serial_write_u64(u64::from(block.events()));
            serial_write("/");
            serial_write_u64(block.deadline());
        }
        serial_write("\r\n");
        for slot in 0..LINUX_THREAD_LIMIT {
            let thread = if next == current {
                capture_linux_thread_runtime_state(slot)
            } else {
                match with_linux_process_threads(next, |threads| threads[slot]) {
                    Some(thread) => thread,
                    None => break,
                }
            };
            if thread.state != LINUX_THREAD_FREE {
                linux_show_thread_state(&thread);
            }
        }
    }
}

fn linux_show_thread_state(thread: &LinuxThreadRuntimeState) {
    let frame = LinuxSyscallFrame::from_array(thread.registers);
    serial_write("linox:   tid ");
    serial_write_u64(u64::from(thread.tid));
    serial_write(match thread.state {
        LINUX_THREAD_READY => " ready",
        LINUX_THREAD_RUNNING => " running",
        LINUX_THREAD_BLOCKED => " blocked",
        _ => " ?",
    });
    if thread.owner_only != 0 {
        serial_write(" (for the owner)");
    }
    serial_write(" wait=");
    serial_write_u64(u64::from(thread.wait_kind));
    serial_write(" key=");
    serial_write_hex(thread.wait_key);
    serial_write(" rip=");
    serial_write_hex(thread.rip);
    serial_write(" rsp=");
    serial_write_hex(thread.rsp);
    serial_write(" rax=");
    serial_write_u64(thread.rax);
    serial_write(" args=");
    for value in [frame.rdi, frame.rsi, frame.rdx, frame.r10] {
        serial_write_hex(value);
        serial_write(",");
    }
    if matches!(
        thread.wait_kind,
        LINUX_THREAD_WAIT_POLL | LINUX_THREAD_WAIT_PPOLL
    ) {
        serial_write(" fds=");
        let count = usize::try_from(frame.rsi)
            .unwrap_or(0)
            .min(LINUX_POLLFD_LIMIT);
        for (descriptor, events) in thread.poll_descriptors[..count]
            .iter()
            .zip(&thread.poll_events[..count])
        {
            serial_write_u64(u64::from(*descriptor));
            serial_write(":");
            serial_write_u64(u64::from(*events));
            serial_write(" ");
        }
    }
    serial_write("\r\n");
}
