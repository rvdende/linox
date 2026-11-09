use super::*;

pub(super) fn wake_linux_poll_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_poll_wait(slot, false));
    }
    woken
}

#[derive(Clone, Copy)]
pub(super) struct LinuxSelectInput {
    pub(super) descriptor_count: u64,
    pub(super) read_address: u64,
    pub(super) write_address: u64,
    pub(super) exception_address: u64,
    pub(super) timeout_address: u64,
    pub(super) signal_mask_address: u64,
}

/// select's three descriptor sets (read, write, exception), `words` 64-bit
/// words each: inline up to FD_SETSIZE, on the heap past it.
pub(super) struct LinuxSelectSets {
    words: usize,
    inline: [u64; 3 * LINUX_SELECT_WORD_LIMIT],
    heap: Vec<u64>,
}

impl LinuxSelectSets {
    /// Empty sets of `words` words; None without memory.
    pub(super) fn new(words: usize) -> Option<Self> {
        let mut heap = Vec::new();
        if words > LINUX_SELECT_WORD_LIMIT {
            heap.try_reserve_exact(3 * words).ok()?;
            heap.resize(3 * words, 0);
        }
        Some(Self {
            words,
            inline: [0; 3 * LINUX_SELECT_WORD_LIMIT],
            heap,
        })
    }

    /// Whether the sets are too large for a thread's fixed wait snapshot.
    pub(super) fn large(&self) -> bool {
        self.words > LINUX_SELECT_WORD_LIMIT
    }

    pub(super) fn all(&self) -> &[u64] {
        if self.large() {
            &self.heap
        } else {
            &self.inline[..3 * self.words]
        }
    }

    fn all_mut(&mut self) -> &mut [u64] {
        if self.large() {
            &mut self.heap
        } else {
            &mut self.inline[..3 * self.words]
        }
    }

    /// Set `index`: 0 read, 1 write, 2 exception.
    pub(super) fn set(&self, index: usize) -> &[u64] {
        &self.all()[index * self.words..(index + 1) * self.words]
    }

    pub(super) fn set_mut(&mut self, index: usize) -> &mut [u64] {
        let words = self.words;
        &mut self.all_mut()[index * words..(index + 1) * words]
    }
}

pub(super) struct LinuxSelectSnapshot {
    pub(super) input: LinuxSelectInput,
    pub(super) requested: LinuxSelectSets,
}

pub(super) struct LinuxParsedSelect {
    pub(super) snapshot: LinuxSelectSnapshot,
    pub(super) duration: Option<u64>,
    pub(super) temporary_signal_mask: Option<u64>,
}

pub(super) fn linux_select_parse(
    mut input: LinuxSelectInput,
    pselect: bool,
    copy_from: fn(u64, &mut [u8]) -> bool,
) -> Result<LinuxParsedSelect, u64> {
    let descriptor_count = input.descriptor_count as i32;
    if descriptor_count < 0 {
        return Err(LINUX_EINVAL);
    }
    // Past the descriptor table's size, as Linux: its sets cover no more.
    input.descriptor_count = (descriptor_count as u64).min(linux_descriptor_table_size());
    let duration = if input.timeout_address == 0 {
        None
    } else {
        let mut timeout = [0_u8; 16];
        if !copy_from(input.timeout_address, &mut timeout) {
            return Err(LINUX_EFAULT);
        }
        let seconds = i64::from_ne_bytes(timeout[..8].try_into().unwrap());
        let fraction = i64::from_ne_bytes(timeout[8..].try_into().unwrap());
        let (fraction_limit, scale) = if pselect {
            (NANOSECONDS_PER_SECOND as i64, 1)
        } else {
            (MICROSECONDS_PER_SECOND as i64, 1_000)
        };
        if seconds < 0 || !(0..fraction_limit).contains(&fraction) {
            return Err(LINUX_EINVAL);
        }
        let Some(duration) = (seconds as u64)
            .checked_mul(NANOSECONDS_PER_SECOND)
            .and_then(|seconds| seconds.checked_add((fraction as u64) * scale))
        else {
            return Err(LINUX_EINVAL);
        };
        Some(duration)
    };
    let temporary_signal_mask = if pselect && input.signal_mask_address != 0 {
        let mut argument = [0_u8; 16];
        if !copy_from(input.signal_mask_address, &mut argument) {
            return Err(LINUX_EFAULT);
        }
        let mask_address = u64::from_ne_bytes(argument[..8].try_into().unwrap());
        let mask_size = u64::from_ne_bytes(argument[8..].try_into().unwrap());
        if mask_size != LINUX_SIGNAL_SET_SIZE {
            return Err(LINUX_EINVAL);
        }
        if mask_address == 0 {
            None
        } else {
            let mut mask = [0_u8; LINUX_SIGNAL_SET_SIZE as usize];
            if !copy_from(mask_address, &mut mask) {
                return Err(LINUX_EFAULT);
            }
            Some(u64::from_ne_bytes(mask) & !LINUX_UNBLOCKABLE_SIGNALS)
        }
    } else {
        None
    };
    let word_count = input.descriptor_count.div_ceil(u64::BITS as u64) as usize;
    let mut requested = LinuxSelectSets::new(word_count).ok_or(LINUX_ENOMEM)?;
    for (index, address) in [
        input.read_address,
        input.write_address,
        input.exception_address,
    ]
    .into_iter()
    .enumerate()
    {
        if address == 0 || word_count == 0 {
            continue;
        }
        // A page of words at a time.
        let set = requested.set_mut(index);
        let mut bytes = [0_u8; PAGE_SIZE];
        for (chunk_index, chunk) in set.chunks_mut(PAGE_SIZE / size_of::<u64>()).enumerate() {
            let length = core::mem::size_of_val(chunk);
            let offset = (chunk_index * PAGE_SIZE) as u64;
            if !copy_from(address + offset, &mut bytes[..length]) {
                return Err(LINUX_EFAULT);
            }
            for (word, bytes) in chunk.iter_mut().zip(bytes[..length].as_chunks::<8>().0) {
                *word = u64::from_ne_bytes(*bytes);
            }
        }
    }
    if word_count != 0 && !input.descriptor_count.is_multiple_of(u64::BITS as u64) {
        let valid_mask = (1_u64 << (input.descriptor_count % u64::BITS as u64)) - 1;
        for index in 0..3 {
            requested.set_mut(index)[word_count - 1] &= valid_mask;
        }
    }
    Ok(LinuxParsedSelect {
        snapshot: LinuxSelectSnapshot { input, requested },
        duration,
        temporary_signal_mask,
    })
}

/// Which descriptors of `snapshot`'s sets are ready: sets for read (0)
/// and write (1) and how many bits they hold, or EBADF for a requested
/// descriptor not open (ENOMEM without memory for the sets).
/// What a select on `snapshot`'s descriptors waits on
/// (`linux_descriptor_wait` for each).
fn linux_select_wait(snapshot: &LinuxSelectSnapshot) -> WaitOn {
    let (read, write, exception) = (
        snapshot.requested.set(0),
        snapshot.requested.set(1),
        snapshot.requested.set(2),
    );
    let mut wait = WaitOn::NOTHING;
    for word in 0..snapshot.requested.words {
        let mut any = read[word] | write[word] | exception[word];
        while any != 0 {
            let bit = any.trailing_zeros();
            any &= any - 1;
            wait = wait.and(linux_descriptor_wait(
                (word * u64::BITS as usize) as u64 + u64::from(bit),
            ));
        }
    }
    wait
}

/// What a poll on `pollfds` waits on (`linux_descriptor_wait` for each).
fn linux_pollfd_wait(pollfds: &[u8]) -> WaitOn {
    pollfds
        .as_chunks::<8>()
        .0
        .iter()
        .map(|pollfd| i32::from_ne_bytes(pollfd[..4].try_into().unwrap()))
        .filter(|descriptor| *descriptor >= 0)
        .fold(WaitOn::NOTHING, |wait, descriptor| {
            wait.and(linux_descriptor_wait(descriptor as u64))
        })
}

pub(super) fn linux_select_ready(
    snapshot: &LinuxSelectSnapshot,
) -> Result<(LinuxSelectSets, u64), u64> {
    let words = snapshot.requested.words;
    let mut ready = LinuxSelectSets::new(words).ok_or(LINUX_ENOMEM)?;
    let mut ready_count = 0_u64;
    let (read, write, exception) = (
        snapshot.requested.set(0),
        snapshot.requested.set(1),
        snapshot.requested.set(2),
    );
    for word in 0..words {
        let mut any = read[word] | write[word] | exception[word];
        while any != 0 {
            let bit = any.isolate_lowest_one();
            any &= any - 1;
            let descriptor = (word * u64::BITS as usize) as u64 + u64::from(bit.trailing_zeros());
            if !linux_descriptor_open(descriptor) {
                return Err(LINUX_EBADF);
            }
            // select returns the bits set in all its sets: a descriptor
            // both readable and writable counts twice, as in Linux
            // (select01).
            if read[word] & bit != 0
                && linux_descriptor_poll_events(descriptor as i32, LINUX_POLLIN) & LINUX_POLLIN != 0
            {
                ready.set_mut(0)[word] |= bit;
                ready_count += 1;
            }
            if write[word] & bit != 0
                && linux_descriptor_poll_events(descriptor as i32, LINUX_POLLOUT) & LINUX_POLLOUT
                    != 0
            {
                ready.set_mut(1)[word] |= bit;
                ready_count += 1;
            }
        }
    }
    Ok((ready, ready_count))
}

/// Writes the ready sets (`ready`, none on a timeout) back over the
/// caller's; the count of bits set, or EFAULT.
pub(super) fn linux_select_copy_result(
    snapshot: &LinuxSelectSnapshot,
    ready: Option<&LinuxSelectSets>,
    copy_to: fn(u64, &[u8]) -> bool,
) -> u64 {
    let word_count = snapshot.requested.words;
    let mut count = 0_u64;
    for (index, address) in [
        snapshot.input.read_address,
        snapshot.input.write_address,
        snapshot.input.exception_address,
    ]
    .into_iter()
    .enumerate()
    {
        let values = ready.filter(|_| index < 2).map(|ready| ready.set(index));
        if let Some(values) = values {
            count += values
                .iter()
                .map(|word| u64::from(word.count_ones()))
                .sum::<u64>();
        }
        if address == 0 || word_count == 0 {
            continue;
        }
        let mut bytes = [0_u8; PAGE_SIZE];
        let per_page = PAGE_SIZE / size_of::<u64>();
        let mut written = 0;
        while written < word_count {
            let chunk = (word_count - written).min(per_page);
            let length = chunk * size_of::<u64>();
            for (offset, bytes) in bytes[..length]
                .as_chunks_mut::<8>()
                .0
                .iter_mut()
                .enumerate()
            {
                let value = values.map_or(0, |values| values[written + offset]);
                bytes.copy_from_slice(&value.to_ne_bytes());
            }
            if !copy_to(
                address + (written * size_of::<u64>()) as u64,
                &bytes[..length],
            ) {
                return LINUX_EFAULT;
            }
            written += chunk;
        }
    }
    // The bits set in all the sets, as Linux counts (select01).
    count
}

pub(super) fn linux_select_with_copy(
    input: LinuxSelectInput,
    pselect: bool,
    copy_from: fn(u64, &mut [u8]) -> bool,
    copy_to: fn(u64, &[u8]) -> bool,
) -> u64 {
    let parsed = match linux_select_parse(input, pselect, copy_from) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let (ready, _) = match linux_select_ready(&parsed.snapshot) {
        Ok(ready) => ready,
        Err(error) => return error,
    };
    linux_select_copy_result(&parsed.snapshot, Some(&ready), copy_to)
}

/// Keeps `snapshot` as thread `slot`'s wait: in its fixed snapshot, or
/// past FD_SETSIZE in `linux_wait_sets`; false without memory.
pub(super) fn store_linux_select_snapshot(slot: usize, snapshot: &LinuxSelectSnapshot) -> bool {
    X86_RUNTIME.LINUX_THREAD_SELECT_READ_ADDRESSES[slot]
        .store(snapshot.input.read_address, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_ADDRESSES[slot]
        .store(snapshot.input.write_address, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES[slot]
        .store(snapshot.input.exception_address, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES[slot]
        .store(snapshot.input.timeout_address, Ordering::SeqCst);
    if snapshot.requested.large() {
        let mut words = Vec::new();
        if words
            .try_reserve_exact(snapshot.requested.all().len())
            .is_err()
        {
            return false;
        }
        words.extend_from_slice(snapshot.requested.all());
        crate::linux_wait_sets::store(linux_wait_set_key(slot), words);
        return true;
    }
    for index in 0..LINUX_SELECT_WORD_LIMIT {
        let word = |set: usize| snapshot.requested.set(set).get(index).copied().unwrap_or(0);
        X86_RUNTIME.LINUX_THREAD_SELECT_READ_SETS[slot][index].store(word(0), Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_SETS[slot][index].store(word(1), Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_SETS[slot][index]
            .store(word(2), Ordering::SeqCst);
    }
    true
}

/// Thread `slot`'s select wait over `descriptor_count` descriptors, as
/// `store_linux_select_snapshot` kept it; None without memory.
pub(super) fn load_linux_select_snapshot(
    slot: usize,
    descriptor_count: u64,
) -> Option<LinuxSelectSnapshot> {
    let words = descriptor_count.div_ceil(u64::BITS as u64) as usize;
    let mut requested = LinuxSelectSets::new(words)?;
    if requested.large() {
        let stored = crate::linux_wait_sets::load(linux_wait_set_key(slot))?;
        if stored.len() != requested.all().len() {
            return None;
        }
        requested.all_mut().copy_from_slice(&stored);
    } else {
        for index in 0..words {
            requested.set_mut(0)[index] =
                X86_RUNTIME.LINUX_THREAD_SELECT_READ_SETS[slot][index].load(Ordering::SeqCst);
            requested.set_mut(1)[index] =
                X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_SETS[slot][index].load(Ordering::SeqCst);
            requested.set_mut(2)[index] =
                X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_SETS[slot][index].load(Ordering::SeqCst);
        }
    }
    Some(LinuxSelectSnapshot {
        input: LinuxSelectInput {
            descriptor_count,
            read_address: X86_RUNTIME.LINUX_THREAD_SELECT_READ_ADDRESSES[slot]
                .load(Ordering::SeqCst),
            write_address: X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_ADDRESSES[slot]
                .load(Ordering::SeqCst),
            exception_address: X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES[slot]
                .load(Ordering::SeqCst),
            timeout_address: linux_select_timeout_address(slot),
            signal_mask_address: 0,
        },
        requested,
    })
}

/// The timeout address of thread `slot`'s select wait.
pub(super) fn linux_select_timeout_address(slot: usize) -> u64 {
    X86_RUNTIME.LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES[slot].load(Ordering::SeqCst)
}

pub(super) fn linux_select_write_remaining(snapshot: &LinuxSelectSnapshot, deadline: u64) -> bool {
    if snapshot.input.timeout_address == 0 {
        return true;
    }
    let Some(now) = linux_elapsed_nanoseconds() else {
        return false;
    };
    let remaining = deadline.saturating_sub(now);
    let mut timeval = [0_u8; 16];
    timeval[..8].copy_from_slice(&(remaining / NANOSECONDS_PER_SECOND).to_ne_bytes());
    timeval[8..].copy_from_slice(&(remaining % NANOSECONDS_PER_SECOND / 1_000).to_ne_bytes());
    copy_to_linux_user(snapshot.input.timeout_address, &timeval)
}

pub(super) fn complete_linux_select_wait(slot: usize, timed_out: bool) -> bool {
    let kind = if slot < LINUX_THREAD_LIMIT {
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
    } else {
        LINUX_THREAD_WAIT_NONE
    };
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || !matches!(kind, LINUX_THREAD_WAIT_SELECT | LINUX_THREAD_WAIT_PSELECT)
    {
        return false;
    }
    let descriptor_count = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
    let Some(snapshot) = load_linux_select_snapshot(slot, descriptor_count) else {
        return false;
    };
    let readiness = linux_select_ready(&snapshot);
    if readiness.as_ref().is_ok_and(|(_, count)| *count == 0) && !timed_out {
        return false;
    }
    if matches!(readiness, Err(error) if error == LINUX_ENOMEM) && !timed_out {
        return false;
    }
    let deadline = X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::SeqCst);
    let result = match readiness {
        Ok((ready, _)) => {
            let result = linux_select_copy_result(
                &snapshot,
                (!timed_out).then_some(&ready),
                copy_to_linux_user,
            );
            if result != LINUX_EFAULT
                && kind == LINUX_THREAD_WAIT_SELECT
                && !linux_select_write_remaining(&snapshot, deadline)
            {
                LINUX_EFAULT
            } else {
                result
            }
        }
        Err(error) => error,
    };
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    if kind == LINUX_THREAD_WAIT_PSELECT {
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(
            X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].swap(0, Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
    clear_linux_select_snapshot(slot);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    true
}

pub(super) fn wake_linux_select_waits() -> u32 {
    let mut woken = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        woken += u32::from(complete_linux_select_wait(slot, false));
    }
    woken
}

pub(super) fn linux_select_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    input: LinuxSelectInput,
    pselect: bool,
) -> u64 {
    let parsed = match linux_select_parse(input, pselect, copy_from_linux_user) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let set_size = parsed
        .snapshot
        .input
        .descriptor_count
        .div_ceil(u64::BITS as u64) as usize
        * size_of::<u64>();
    for address in [
        parsed.snapshot.input.read_address,
        parsed.snapshot.input.write_address,
        parsed.snapshot.input.exception_address,
    ] {
        if address != 0 && set_size != 0 && !linux_writable_user_range_contains(address, set_size) {
            return LINUX_EFAULT;
        }
    }
    if !pselect
        && parsed.snapshot.input.timeout_address != 0
        && !linux_writable_user_range_contains(parsed.snapshot.input.timeout_address, 16)
    {
        return LINUX_EFAULT;
    }
    let (ready_sets, ready) = match linux_select_ready(&parsed.snapshot) {
        Ok(ready) => ready,
        Err(error) => return error,
    };
    if ready != 0 || parsed.duration == Some(0) {
        let result =
            linux_select_copy_result(&parsed.snapshot, Some(&ready_sets), copy_to_linux_user);
        if result == LINUX_EFAULT || pselect || parsed.snapshot.input.timeout_address == 0 {
            return result;
        }
        let duration = parsed.duration.unwrap_or(0);
        let Some(deadline) = linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
        else {
            return LINUX_EINVAL;
        };
        return if linux_select_write_remaining(&parsed.snapshot, deadline) {
            result
        } else {
            LINUX_EFAULT
        };
    }
    // With no other thread of this process to switch to, wait here and let
    // other processes run; one of them, or the network, may make a
    // descriptor ready.
    if current_linux_runtime_cpu_index() == 0 && linux_thread_wait_handoff().is_none() {
        let deadline = parsed.duration.and_then(|duration| {
            linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
        });
        let number = if pselect {
            LINUX_PSELECT6_SYSCALL
        } else {
            LINUX_SELECT_SYSCALL
        };
        loop {
            let (ready_sets, ready) = match linux_select_ready(&parsed.snapshot) {
                Ok(ready) => ready,
                Err(error) => return error,
            };
            let timed_out = deadline.is_some_and(|deadline| {
                linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline)
            });
            if ready != 0 || timed_out {
                let result = linux_select_copy_result(
                    &parsed.snapshot,
                    Some(&ready_sets),
                    copy_to_linux_user,
                );
                return match deadline {
                    Some(deadline)
                        if result != LINUX_EFAULT
                            && !pselect
                            && !linux_select_write_remaining(&parsed.snapshot, deadline) =>
                    {
                        LINUX_EFAULT
                    }
                    _ => result,
                };
            }
            if linux_thread_wait_handoff().is_some() {
                break;
            }
            // A yield restarts the call; select restarts with the time it
            // has left.
            if !pselect
                && deadline.is_some_and(|deadline| {
                    !linux_select_write_remaining(&parsed.snapshot, deadline)
                })
            {
                return LINUX_EFAULT;
            }
            let wait = linux_select_wait(&parsed.snapshot).until_some(deadline);
            if let Some(LinuxBlockedWait::Return(result)) =
                run_other_linux_processes(output, caller, number, wait)
            {
                return result;
            }
            core::hint::spin_loop();
        }
    }
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let Some(target) = linux_thread_wait_handoff() else {
        return LINUX_ENOSYS;
    };
    let Some(tls) = linux_thread_context(current) else {
        return LINUX_ESRCH;
    };
    let deadline = if let Some(duration) = parsed.duration {
        let Some(deadline) = linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
        else {
            return LINUX_EINVAL;
        };
        deadline
    } else {
        0
    };
    let slot = usize::from(current.slot);
    if !store_linux_select_snapshot(slot, &parsed.snapshot) {
        clear_linux_select_snapshot(slot);
        return LINUX_ENOMEM;
    }
    let wait_kind = if pselect {
        LINUX_THREAD_WAIT_PSELECT
    } else {
        LINUX_THREAD_WAIT_SELECT
    };
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(
            wait_kind,
            1,
            parsed.snapshot.input.descriptor_count,
            deadline,
        )
    {
        clear_linux_select_snapshot(slot);
        return LINUX_EINVAL;
    }
    let prior_signal_mask = X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst);
    if pselect {
        X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot]
            .store(prior_signal_mask, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(
            parsed.temporary_signal_mask.unwrap_or(prior_signal_mask),
            Ordering::SeqCst,
        );
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
        clear_linux_select_snapshot(slot);
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_RUNNING, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_CURRENT_THREAD_SLOT
            .store(current.slot, Ordering::SeqCst);
        let _ = install_linux_tls_context(tls);
        if pselect {
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
    LINUX_RETURN_FROM_IRET
}

pub(super) fn linux_poll_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    address: u64,
    count: u64,
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
    linux_poll_wait_live_return(
        output,
        caller,
        address,
        count,
        duration,
        LINUX_THREAD_WAIT_POLL,
        None,
    )
}

pub(super) fn linux_signal_suspend_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    wait_kind: u8,
    temporary_signal_mask: Option<u64>,
) -> u64 {
    // The poll wait engine already provides the required atomic
    // save/block/schedule transition. A nonzero private key satisfies its
    // generation-safe wait record without exposing a descriptor or pointer.
    linux_poll_wait_live_return(output, caller, 1, 0, None, wait_kind, temporary_signal_mask)
}

pub(super) fn yield_current_linux_process(mut caller: LinuxUserContext, result: u64) -> bool {
    // A yield switches to the parent, which a thread of this process still
    // running on another CPU must not see; see linux_remote_thread_running.
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        return false;
    }
    caller.rax = result;
    // A thread on the light path leaves its CPU for the owner's path.
    if let Some((_, slot)) = linux_light_thread_here() {
        return linux_thread_handle(slot).is_some_and(|handle| {
            park_linux_light_thread(handle, caller, true) == LINUX_RETURN_TO_KERNEL
        });
    }
    // The registry holds where the process goes on: the loop that took the
    // yield enters it there (a call that parks never comes back this way).
    refresh_linux_process_registry_for_wait(caller)
}

/// Waits in poll(2) for a process with no other runnable thread: other
/// processes run until a descriptor is ready or the deadline passes, and
/// with nothing else to run the CPU halts until the next interrupt (or spins,
/// in the boot probe). Once a sibling thread is ready, the wait stops here
/// with that thread and the wait's deadline, to go on as a thread wait.
fn linux_poll_run_others_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    address: u64,
    active: &mut [u8],
    duration: Option<u64>,
    number: u64,
) -> Result<u64, (LinuxThreadHandle, Option<u64>)> {
    let deadline = take_linux_restart_deadline(caller.rip).or_else(|| {
        duration.and_then(|duration| {
            linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
        })
    });
    loop {
        let mut ready = 0_u64;
        for pollfd in active.as_chunks_mut::<8>().0 {
            let descriptor = i32::from_ne_bytes(pollfd[..4].try_into().unwrap());
            let events = u16::from_ne_bytes(pollfd[4..6].try_into().unwrap());
            let returned = linux_descriptor_poll_events(descriptor, events);
            pollfd[6..8].copy_from_slice(&returned.to_ne_bytes());
            ready += u64::from(returned != 0);
        }
        let expired = deadline
            .is_some_and(|deadline| linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline));
        if ready != 0 || expired {
            return Ok(
                if active.is_empty() || copy_to_linux_user(address, active) {
                    ready
                } else {
                    LINUX_EFAULT
                },
            );
        }
        let wait = linux_pollfd_wait(active).until_some(deadline);
        let turn = linux_timed_wait_run_others(output, caller, number, wait);
        if let LinuxWaitTurn::Done(result) = turn {
            return Ok(result);
        }
        if let Some(target) = linux_thread_wait_handoff() {
            return Err((target, deadline));
        }
        if let Some((deadline, now)) = deadline.zip(linux_elapsed_nanoseconds()) {
            timer::request_linux_tick_within(deadline.saturating_sub(now));
        }
        if !matches!(turn, LinuxWaitTurn::Idle) {
            continue;
        }
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
            linux_wait_for_interrupt();
        } else {
            core::hint::spin_loop();
        }
    }
}

pub(super) fn yield_current_linux_process_wait(caller: LinuxUserContext) -> bool {
    yield_current_linux_process(caller, LINUX_EINTR)
}

pub(super) fn linux_poll_wait_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    address: u64,
    count: u64,
    duration: Option<u64>,
    wait_kind: u8,
    temporary_signal_mask: Option<u64>,
) -> u64 {
    let Ok(descriptor_count) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    // As many pollfds as RLIMIT_NOFILE allows descriptors, as in Linux;
    // the boot probe's fixed snapshot only.
    let limit = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        linux_nofile_soft_limit()
    } else {
        LINUX_POLLFD_LIMIT as u64
    };
    if count > limit {
        return LINUX_EINVAL;
    }
    let mut pollfds = [0_u8; LINUX_POLLFD_LIMIT * 8];
    let mut large = Vec::new();
    let active: &mut [u8] = if descriptor_count <= LINUX_POLLFD_LIMIT {
        &mut pollfds[..descriptor_count * 8]
    } else {
        if large.try_reserve_exact(descriptor_count * 8).is_err() {
            return LINUX_ENOMEM;
        }
        large.resize(descriptor_count * 8, 0);
        &mut large[..]
    };
    if descriptor_count != 0
        && (!copy_from_linux_user(address, active)
            || !linux_writable_user_range_contains(address, active.len()))
    {
        return LINUX_EFAULT;
    }
    let mut ready = 0_u64;
    for pollfd in active.as_chunks_mut::<8>().0 {
        let descriptor = i32::from_ne_bytes(pollfd[..4].try_into().unwrap());
        let events = u16::from_ne_bytes(pollfd[4..6].try_into().unwrap());
        let returned = linux_descriptor_poll_events(descriptor, events);
        pollfd[6..8].copy_from_slice(&returned.to_ne_bytes());
        ready += u64::from(returned != 0);
    }
    if descriptor_count == 0 && duration == Some(0) {
        return 0;
    }
    if ready != 0 || duration == Some(0) {
        return if copy_to_linux_user(address, active) {
            ready
        } else {
            LINUX_EFAULT
        };
    }
    // The current nested executor suspends a parent while its child runs. If
    // that child blocks on the parent's Unix-socket endpoint, spinning until
    // timeout prevents the only process that can make the descriptor ready
    // from running. Yield this narrow dependency back to the parent.
    let current_pid = current_linux_process_pid();
    let parent_pid = linux_process::live_process_parent_pid(current_pid);
    let waits_for_parent_unix_peer = parent_pid.is_some_and(|parent_pid| {
        active.as_chunks::<8>().0.iter().any(|pollfd| {
            let descriptor = i32::from_ne_bytes(pollfd[..4].try_into().unwrap());
            let Some(peer) = (descriptor >= 0)
                .then(|| linux_socket_slot(descriptor as u64))
                .flatten()
                .filter(|slot| {
                    crate::linux_socket::kind(*slot) == Some(crate::linux_socket::Kind::Unix)
                })
                .and_then(crate::linux_socket::local_peer_slot)
            else {
                return false;
            };
            linux_process_runtime_state(parent_pid)
                .filter(|state| state.valid)
                .is_some_and(|state| {
                    state
                        .descriptors
                        .stdio_sockets
                        .iter()
                        .chain(&state.descriptors.sockets)
                        .any(|stored| *stored == peer + 1)
                        || linux_saved_overflow_entries(&state.descriptors)
                            .iter()
                            .any(|(_, entry)| entry.socket == peer + 1)
                })
        })
    });
    let polls_socket = active.as_chunks::<8>().0.iter().any(|pollfd| {
        let descriptor = i32::from_ne_bytes(pollfd[..4].try_into().unwrap());
        descriptor >= 0 && linux_socket_slot(descriptor as u64).is_some()
    });
    let poll_syscall = if wait_kind == LINUX_THREAD_WAIT_PPOLL {
        LINUX_PPOLL_SYSCALL
    } else {
        LINUX_POLL_SYSCALL
    };
    if !waits_for_parent_unix_peer && polls_socket {
        let deadline = take_linux_restart_deadline(caller.rip).or_else(|| {
            duration.and_then(|duration| {
                linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
            })
        });
        loop {
            ready = 0;
            for pollfd in active.as_chunks_mut::<8>().0 {
                let descriptor = i32::from_ne_bytes(pollfd[..4].try_into().unwrap());
                let events = u16::from_ne_bytes(pollfd[4..6].try_into().unwrap());
                let returned = linux_descriptor_poll_events(descriptor, events);
                pollfd[6..8].copy_from_slice(&returned.to_ne_bytes());
                ready += u64::from(returned != 0);
            }
            let expired = deadline.is_some_and(|deadline| {
                linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline)
            });
            if ready != 0 || expired {
                return if copy_to_linux_user(address, active) {
                    ready
                } else {
                    LINUX_EFAULT
                };
            }
            // Let another thread of this process run while this one
            // blocks below. Without one, another process, such as a spawned
            // child writing to a pipe, may be the only one that can make a
            // descriptor ready.
            if linux_thread_wait_handoff().is_some() {
                break;
            }
            let wait = linux_pollfd_wait(active).until_some(deadline);
            if let LinuxWaitTurn::Done(result) =
                linux_timed_wait_run_others(output, caller, poll_syscall, wait)
            {
                return result;
            }
            core::hint::spin_loop();
        }
    }
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    // The deadline of a wait that began below, if it goes on as a thread
    // wait because a sibling thread became ready meanwhile.
    let mut continued_deadline = None;
    let target = 'target: {
        if let Some(target) = linux_thread_wait_handoff() {
            break 'target target;
        }
        // pause and sigsuspend wait in the call, as a timed wait with no
        // deadline, until a signal ends it: resumed for anything else, it
        // waits again, as a thread wait once a sibling thread is ready.
        // sigsuspend waits under its temporary mask, which a handler's
        // frame and the call's end put back (sigsuspend01).
        if matches!(
            wait_kind,
            LINUX_THREAD_WAIT_PAUSE | LINUX_THREAD_WAIT_SIGSUSPEND
        ) && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        {
            let slot = usize::from(current.slot);
            let number = if wait_kind == LINUX_THREAD_WAIT_PAUSE {
                LINUX_PAUSE_SYSCALL
            } else {
                LINUX_RT_SIGSUSPEND_SYSCALL
            };
            let prior = temporary_signal_mask
                .map(|mask| begin_linux_lone_masked_wait(slot, LINUX_THREAD_WAIT_SIGSUSPEND, mask));
            let ended = loop {
                // Only a signal ends it.
                let turn = linux_timed_wait_run_others(output, caller, number, WaitOn::NOTHING);
                if let LinuxWaitTurn::Done(result) = turn {
                    break Ok(result);
                }
                if let Some(target) = linux_thread_wait_handoff() {
                    break Err(target);
                }
                if let LinuxWaitTurn::Idle = turn {
                    linux_wait_for_interrupt();
                }
            };
            if let Some(prior) = prior {
                end_linux_lone_masked_wait(slot, prior);
            }
            match ended {
                Ok(result) => return result,
                Err(target) => break 'target target,
            }
        }
        if matches!(
            wait_kind,
            LINUX_THREAD_WAIT_PAUSE | LINUX_THREAD_WAIT_SIGSUSPEND
        ) && yield_current_linux_process_wait(caller)
        {
            return LINUX_RETURN_TO_KERNEL;
        }
        // A lone Linux thread has no peer to schedule while it polls. Other
        // processes run, and descriptor readiness is driven until the
        // deadline, instead of leaking the scheduler's lack of a target as
        // ENOSYS to userspace.
        if matches!(wait_kind, LINUX_THREAD_WAIT_POLL | LINUX_THREAD_WAIT_PPOLL) {
            // ppoll waits under its temporary mask as sigsuspend does: a
            // signal it unblocks, pending already or arriving, ends the
            // wait (ppoll01's race case), and a handler's frame restores
            // the caller's mask.
            let slot = usize::from(current.slot);
            let prior = temporary_signal_mask
                .filter(|_| X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst))
                .map(|mask| begin_linux_lone_masked_wait(slot, LINUX_THREAD_WAIT_SIGSUSPEND, mask));
            let waited = linux_poll_run_others_live_return(
                output,
                caller,
                address,
                active,
                duration,
                poll_syscall,
            );
            if let Some(prior) = prior {
                end_linux_lone_masked_wait(slot, prior);
            }
            match waited {
                Ok(result) => return result,
                Err((target, deadline)) => {
                    continued_deadline = Some(deadline.unwrap_or(0));
                    break 'target target;
                }
            }
        }
        return LINUX_ENOSYS;
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
    if descriptor_count > LINUX_POLLFD_LIMIT {
        // Past the fixed snapshot: each pollfd's descriptor and events.
        let mut words = Vec::new();
        if words.try_reserve_exact(descriptor_count).is_err() {
            return LINUX_ENOMEM;
        }
        words.extend(active.as_chunks::<8>().0.iter().map(|pollfd| {
            u64::from(u32::from_ne_bytes(pollfd[..4].try_into().unwrap()))
                | u64::from(u16::from_ne_bytes(pollfd[4..6].try_into().unwrap())) << 32
        }));
        crate::linux_wait_sets::store(linux_wait_set_key(slot), words);
    }
    for (index, pollfd) in active
        .as_chunks::<8>()
        .0
        .iter()
        .take(LINUX_POLLFD_LIMIT)
        .enumerate()
    {
        X86_RUNTIME.LINUX_THREAD_POLL_DESCRIPTORS[slot][index].store(
            u32::from_ne_bytes(pollfd[..4].try_into().unwrap()),
            Ordering::SeqCst,
        );
        X86_RUNTIME.LINUX_THREAD_POLL_EVENTS[slot][index].store(
            u16::from_ne_bytes(pollfd[4..6].try_into().unwrap()),
            Ordering::SeqCst,
        );
    }
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(wait_kind, address, descriptor_count as u64, deadline)
    {
        clear_linux_poll_snapshot(slot);
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
        clear_linux_poll_snapshot(slot);
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
    match wait_kind {
        LINUX_THREAD_WAIT_PPOLL => {
            X86_RUNTIME
                .LINUX_PPOLL_WAIT_BLOCK_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        LINUX_THREAD_WAIT_PAUSE | LINUX_THREAD_WAIT_SIGSUSPEND => {}
        _ => {
            X86_RUNTIME
                .LINUX_POLL_WAIT_BLOCK_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
    }
    LINUX_RETURN_FROM_IRET
}

pub(super) fn linux_ppoll_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    address: u64,
    count: u64,
    timeout_address: u64,
    signal_mask_address: u64,
    signal_set_size: u64,
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
    let temporary_signal_mask = match linux_temporary_signal_mask(LinuxSignalMaskInput {
        address: signal_mask_address,
        size: signal_set_size,
    }) {
        Ok(mask) => mask,
        Err(error) => return error,
    };
    linux_poll_wait_live_return(
        output,
        caller,
        address,
        count,
        duration,
        LINUX_THREAD_WAIT_PPOLL,
        Some(temporary_signal_mask),
    )
}

pub(super) fn linux_epoll_create1(flags: u64) -> u64 {
    let flags = u64::from(flags as u32);
    if flags & !LINUX_O_CLOEXEC != 0 {
        return LINUX_EINVAL;
    }
    let runtime = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    if !runtime
        && X86_RUNTIME
            .ELF_PROBE_EPOLL_DESCRIPTOR
            .load(Ordering::SeqCst)
            != 0
    {
        return LINUX_EMFILE;
    }
    let descriptor_start = if runtime {
        LINUX_AUX_DESCRIPTOR_FIRST
    } else {
        0
    };
    let descriptor = if runtime {
        match linux_allocate_descriptor(descriptor_start) {
            Ok(descriptor) => descriptor,
            Err(error) => return error,
        }
    } else {
        let Some(descriptor) = (descriptor_start..LINUX_AUX_DESCRIPTOR_LIMIT)
            .find(|descriptor| !linux_descriptor_open(*descriptor))
        else {
            return LINUX_EMFILE;
        };
        descriptor
    };
    if runtime {
        linux_fd_cell::<u8>(descriptor, LinuxFdField::Epoll).store(1, Ordering::SeqCst);
        if !linux_epoll_descriptor(descriptor) {
            return LINUX_ENOMEM;
        }
        linux_epoll_forget_owner(descriptor);
    } else {
        X86_RUNTIME
            .ELF_PROBE_EPOLL_DESCRIPTOR
            .store(descriptor as u16 + 1, Ordering::SeqCst);
        for target in 0..LINUX_DESCRIPTOR_TABLE_LIMIT as usize {
            X86_RUNTIME.ELF_PROBE_EPOLL_EVENTS[target].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_EPOLL_DATA[target].store(0, Ordering::SeqCst);
        }
    }
    set_linux_descriptor_close_on_exec(descriptor, flags & LINUX_O_CLOEXEC != 0);
    descriptor
}

pub(super) fn clear_linux_poll_snapshot(slot: usize) {
    for descriptor in &X86_RUNTIME.LINUX_THREAD_POLL_DESCRIPTORS[slot] {
        descriptor.store(0, Ordering::SeqCst);
    }
    for events in &X86_RUNTIME.LINUX_THREAD_POLL_EVENTS[slot] {
        events.store(0, Ordering::SeqCst);
    }
    crate::linux_wait_sets::remove(linux_wait_set_key(slot));
}

/// The `linux_wait_sets` key of the current process's thread `slot`.
fn linux_wait_set_key(slot: usize) -> crate::linux_wait_sets::Key {
    (
        linux_execution_instance(),
        current_linux_process_pid(),
        slot as u16,
    )
}

/// How many descriptors the current process's table has room for, as
/// Linux's fdtable max_fds (what select looks at, at most): the fixed
/// table, or a size past it covering the highest descriptor open there,
/// grown as Linux grows its table (a power of two times 128).
fn linux_descriptor_table_size() -> u64 {
    let Some(&(highest, _)) = linux_overflow_descriptors().last() else {
        return LINUX_DESCRIPTOR_TABLE_LIMIT;
    };
    ((highest / 128 + 1).next_power_of_two() * 128)
        .min(linux_nr_open().max(highest + 1))
        .max(LINUX_DESCRIPTOR_TABLE_LIMIT)
}

pub(super) fn clear_linux_select_snapshot(slot: usize) {
    X86_RUNTIME.LINUX_THREAD_SELECT_READ_ADDRESSES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_ADDRESSES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_ADDRESSES[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_SELECT_TIMEOUT_ADDRESSES[slot].store(0, Ordering::SeqCst);
    for value in &X86_RUNTIME.LINUX_THREAD_SELECT_READ_SETS[slot] {
        value.store(0, Ordering::SeqCst);
    }
    for value in &X86_RUNTIME.LINUX_THREAD_SELECT_WRITE_SETS[slot] {
        value.store(0, Ordering::SeqCst);
    }
    for value in &X86_RUNTIME.LINUX_THREAD_SELECT_EXCEPTION_SETS[slot] {
        value.store(0, Ordering::SeqCst);
    }
    crate::linux_wait_sets::remove(linux_wait_set_key(slot));
}

pub(super) fn clear_linux_iov_snapshot(slot: usize) {
    for address in &X86_RUNTIME.LINUX_THREAD_IOV_ADDRESSES[slot] {
        address.store(0, Ordering::SeqCst);
    }
    for length in &X86_RUNTIME.LINUX_THREAD_IOV_LENGTHS[slot] {
        length.store(0, Ordering::SeqCst);
    }
}

pub(super) fn complete_linux_poll_wait(slot: usize, timed_out: bool) -> bool {
    let kind = if slot < LINUX_THREAD_LIMIT {
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
    } else {
        LINUX_THREAD_WAIT_NONE
    };
    if slot >= LINUX_THREAD_LIMIT
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || !matches!(kind, LINUX_THREAD_WAIT_POLL | LINUX_THREAD_WAIT_PPOLL)
    {
        return false;
    }
    let count = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst) as usize;
    // More pollfds than the fixed snapshot holds wait in linux_wait_sets.
    let stored = if count > LINUX_POLLFD_LIMIT {
        match crate::linux_wait_sets::load(linux_wait_set_key(slot)) {
            Some(words) if words.len() == count => Some(words),
            _ => return false,
        }
    } else {
        None
    };
    let mut small = [0_u8; LINUX_POLLFD_LIMIT * 8];
    let mut large = Vec::new();
    let pollfds: &mut [u8] = if stored.is_some() {
        if large.try_reserve_exact(count * 8).is_err() {
            return false;
        }
        large.resize(count * 8, 0);
        &mut large[..]
    } else {
        &mut small[..]
    };
    let mut ready = 0_u64;
    for index in 0..count {
        let (descriptor, events) = match &stored {
            Some(words) => (words[index] as u32, (words[index] >> 32) as u16),
            None => (
                X86_RUNTIME.LINUX_THREAD_POLL_DESCRIPTORS[slot][index].load(Ordering::SeqCst),
                X86_RUNTIME.LINUX_THREAD_POLL_EVENTS[slot][index].load(Ordering::SeqCst),
            ),
        };
        let returned = linux_descriptor_poll_events(descriptor as i32, events);
        let offset = index * 8;
        pollfds[offset..offset + 4].copy_from_slice(&descriptor.to_ne_bytes());
        pollfds[offset + 4..offset + 6].copy_from_slice(&events.to_ne_bytes());
        pollfds[offset + 6..offset + 8].copy_from_slice(&returned.to_ne_bytes());
        ready += u64::from(returned != 0);
    }
    if ready == 0 && !timed_out {
        return false;
    }
    let address = X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst);
    let result = if count == 0 || copy_to_linux_user(address, &pollfds[..count * 8]) {
        ready
    } else {
        LINUX_EFAULT
    };
    X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    if kind == LINUX_THREAD_WAIT_PPOLL {
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(
            X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].swap(0, Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
    clear_linux_poll_snapshot(slot);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    match (kind, timed_out) {
        (LINUX_THREAD_WAIT_POLL, true) => {
            X86_RUNTIME
                .LINUX_POLL_WAIT_TIMEOUT_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_POLL, false) => {
            X86_RUNTIME
                .LINUX_POLL_WAIT_WAKE_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_PPOLL, true) => {
            X86_RUNTIME
                .LINUX_PPOLL_WAIT_TIMEOUT_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        (LINUX_THREAD_WAIT_PPOLL, false) => {
            X86_RUNTIME
                .LINUX_PPOLL_WAIT_WAKE_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        _ => {}
    }
    true
}

pub(super) fn linux_descriptor_poll_events(descriptor: i32, requested: u16) -> u16 {
    let Ok(descriptor) = u64::try_from(descriptor) else {
        return 0;
    };
    match linux_graphics_descriptor(descriptor) {
        Some(LinuxGraphicsDevice::Input(device)) => {
            return if crate::linux_input::pending(device) {
                requested & LINUX_POLLIN
            } else {
                0
            };
        }
        Some(LinuxGraphicsDevice::Framebuffer) => {
            return requested & (LINUX_POLLIN | LINUX_POLLOUT);
        }
        None => {}
    }
    // /proc/mounts reads at once, and a mount table change since it was
    // last read is POLLPRI and POLLERR, as in Linux.
    if linux_device_descriptor(descriptor) & !3 == LINUX_FILE_PROC_MOUNTS {
        let readable = requested & (LINUX_POLLIN | LINUX_POLLRDNORM);
        return if linux_proc_mounts_changed(descriptor) {
            readable | LINUX_POLLPRI | LINUX_POLLERR
        } else {
            readable
        };
    }
    if linux_pidfd_descriptor(descriptor) {
        let Some(process) = linux_pidfd_process(descriptor) else {
            return LINUX_POLLHUP;
        };
        return if linux_process::live_process_status(process)
            .is_some_and(|status| status.state == linux_process::LiveProcessState::Zombie)
        {
            requested & LINUX_POLLIN
        } else {
            0
        };
    }
    if linux_signalfd_descriptor(descriptor) {
        let mask = linux_descriptor_offset(descriptor).load(Ordering::SeqCst);
        let dynamic = linux_dynamic_pending_masks().map_or(0, |(process, thread)| process | thread);
        return if (X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst) | dynamic) & mask
            != 0
        {
            requested & LINUX_POLLIN
        } else {
            0
        };
    }
    if linux_inotify_descriptor(descriptor) {
        return if linux_inotify_ready(descriptor) {
            requested & LINUX_POLLIN
        } else {
            0
        };
    }
    if linux_fanotify_descriptor(descriptor) {
        return if linux_fanotify_ready(descriptor) {
            requested & LINUX_POLLIN
        } else {
            0
        };
    }
    if let Some((end, index)) = linux_pty_descriptor(descriptor) {
        return linux_pty_poll_events(end, index, requested);
    }
    if let Some((crate::linux_userfaultfd::CLASS_CONTEXT, id)) = linux_object_descriptor(descriptor)
    {
        return linux_userfaultfd_poll_events(descriptor, id, requested);
    }
    if let Some(id) = linux_tun_file(descriptor) {
        return linux_tun_poll_events(id, requested);
    }
    if let Some(slot) = linux_socket_slot(descriptor) {
        if let Some((class, id)) = crate::linux_socket::object(slot) {
            return match class {
                // A sync file is readable once its fence has signalled.
                crate::linux_drm::CLASS_FENCE => {
                    if crate::drivers::virtio_gpu::fence_signaled(id) {
                        requested & LINUX_POLLIN
                    } else {
                        0
                    }
                }
                crate::linux_drm::CLASS_DMABUF => requested & (LINUX_POLLIN | LINUX_POLLOUT),
                // A render node has no DRM events to read.
                _ => 0,
            };
        }
        let Some((readable, writable, error)) = crate::linux_socket::readiness(slot) else {
            return LINUX_POLLNVAL;
        };
        let device = linux_device_descriptor(descriptor);
        let pipe = device & LINUX_DEVICE_PIPE != 0;
        // A pipe's other end is gone: its read end hangs up (POLLHUP) when
        // no writer is left, and its write end reports an error (POLLERR)
        // when no reader is.
        let peer_gone = pipe && crate::linux_socket::local_peer_write_closed(slot) == Some(true);
        let write_end = device & 3 == LINUX_DESCRIPTOR_OUTPUT;
        let hangup = peer_gone && !write_end;
        let error = error || peer_gone && write_end;
        // A pipe is readable only with data queued; end-of-file is POLLHUP
        // alone, where a socket also reports POLLIN.
        let readable = readable
            && (!pipe
                || crate::linux_socket::local_queued_bytes(slot).is_ok_and(|queued| queued != 0));
        let writable = writable && (!pipe || crate::linux_socket::pipe_writable(slot));
        return (if readable {
            requested & LINUX_POLLIN
        } else {
            0
        }) | (if writable {
            requested & LINUX_POLLOUT
        } else {
            0
        }) | if error { LINUX_POLLERR } else { 0 }
            | if hangup { LINUX_POLLHUP } else { 0 }
            | if requested & LINUX_POLLRDHUP != 0 && crate::linux_socket::read_hung_up(slot) {
                LINUX_POLLRDHUP
            } else {
                0
            };
    }
    let console = u16::from(linux_console_descriptor(descriptor));
    if console != 0 {
        let readable = if console & LINUX_DESCRIPTOR_INPUT != 0 {
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                if crate::serial_input_ready() {
                    requested & LINUX_POLLIN
                } else {
                    0
                }
            } else {
                LINUX_POLLHUP
            }
        } else {
            0
        };
        let writable = if console & LINUX_DESCRIPTOR_OUTPUT != 0 {
            requested & LINUX_POLLOUT
        } else {
            0
        };
        return readable | writable;
    }
    if linux_epoll_descriptor(descriptor) {
        return if linux_epoll_event(descriptor, false)
            .ok()
            .flatten()
            .is_some()
        {
            requested & LINUX_POLLIN
        } else {
            0
        };
    }
    if linux_eventfd_descriptor(descriptor) {
        let counter = linux_eventfd_state(descriptor)
            .map(|(counter, _)| counter.load(Ordering::SeqCst))
            .unwrap_or(0);
        let mut returned = 0;
        if counter != 0 {
            returned |= requested & LINUX_POLLIN;
        }
        if counter < u64::MAX - 1 {
            returned |= requested & LINUX_POLLOUT;
        }
        // The overflow state an AIO completion can reach (eventfd06).
        if counter == u64::MAX {
            returned |= LINUX_POLLERR;
        }
        return returned;
    }
    if let Some(state) = linux_timerfd_state(descriptor) {
        let deadline = state.deadline.load(Ordering::SeqCst);
        let ready = deadline != 0 && linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline);
        return if ready { requested & LINUX_POLLIN } else { 0 };
    }
    if linux_pipe_read_descriptor(descriptor) {
        let mut returned = 0;
        if X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst) != 0 {
            returned |= requested & LINUX_POLLIN;
        }
        if X86_RUNTIME
            .ELF_PROBE_PIPE_WRITE_DESCRIPTOR
            .load(Ordering::SeqCst)
            == 0
        {
            returned |= LINUX_POLLHUP;
        }
        return returned;
    }
    if linux_pipe_write_descriptor(descriptor) {
        if X86_RUNTIME
            .ELF_PROBE_PIPE_READ_DESCRIPTOR
            .load(Ordering::SeqCst)
            == 0
        {
            return LINUX_POLLERR;
        }
        return if X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst)
            < LINUX_PIPE_CAPACITY as u32
        {
            requested & LINUX_POLLOUT
        } else {
            0
        };
    }
    let device = linux_device_descriptor(descriptor);
    if device == 0 {
        return LINUX_POLLNVAL;
    }
    let access = device & 3;
    let mut returned = 0;
    if matches!(access, LINUX_DESCRIPTOR_INPUT | 3)
        && (device & LINUX_DEVICE_CONSOLE == 0 || crate::serial_input_ready())
    {
        returned |= requested & LINUX_POLLIN;
    }
    if matches!(access, LINUX_DESCRIPTOR_OUTPUT | 3) {
        returned |= requested & LINUX_POLLOUT;
    }
    returned
}
