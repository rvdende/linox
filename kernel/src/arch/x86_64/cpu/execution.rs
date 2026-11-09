//! The x87, SSE and AVX user state of domains and Linux threads, saved and
//! restored through the trusted core (`trusted::xstate`).
#![forbid(unsafe_code)]

use core::{
    arch::x86_64::{__cpuid, __cpuid_count},
    sync::atomic::Ordering,
};

use super::{
    active_container_slot, current_linux_thread_slot, with_linux_process_record,
    with_linux_process_record_pair, LinuxProcessRecord, CPUID_AVX, CPUID_EXTENDED_STATE, CPUID_SSE,
    CPUID_XSAVE, CPU_ARCHITECTURE, LINUX_THREAD_LIMIT, X86_MUTABLE_RUNTIME, X86_RUNTIME,
};
use crate::trusted::xstate;
pub(super) use crate::trusted::xstate::{ExtendedState, EXTENDED_STATE_SIZE};

pub(crate) fn enable_extended_user_state() -> bool {
    let features = __cpuid(1);
    if features.edx & CPUID_SSE == 0
        || features.ecx & (CPUID_XSAVE | CPUID_AVX) != CPUID_XSAVE | CPUID_AVX
        || __cpuid(0).eax < CPUID_EXTENDED_STATE
        || __cpuid_count(CPUID_EXTENDED_STATE, 0).eax & 7 != 7
    {
        return false;
    }
    let enabled = xstate::enable();
    CPU_ARCHITECTURE
        .extended_user_state_enabled
        .store(enabled, Ordering::Release);
    enabled
}

pub(super) fn reset_extended_user_state() -> bool {
    xstate::reset();
    true
}

pub(super) fn restore_container_extended_state() -> bool {
    if !CPU_ARCHITECTURE
        .extended_user_state_enabled
        .load(Ordering::Acquire)
    {
        return true;
    }
    let Some(slot) = active_container_slot() else {
        return false;
    };
    if !X86_RUNTIME.CONTAINER_EXTENDED_STATE_VALID[slot].load(Ordering::Acquire) {
        return reset_extended_user_state();
    }
    let Some(state) = X86_MUTABLE_RUNTIME.container_extended_states[slot].try_claim() else {
        return false;
    };
    xstate::restore(&state)
}

pub(super) fn save_container_extended_state() -> bool {
    if !CPU_ARCHITECTURE
        .extended_user_state_enabled
        .load(Ordering::Acquire)
    {
        return true;
    }
    let Some(slot) = active_container_slot() else {
        return false;
    };
    let Some(mut state) = X86_MUTABLE_RUNTIME.container_extended_states[slot].try_claim() else {
        return false;
    };
    if !xstate::save(&mut state) {
        return false;
    }
    drop(state);
    X86_RUNTIME.CONTAINER_EXTENDED_STATE_VALID[slot].store(true, Ordering::Release);
    reset_extended_user_state()
}

pub(super) fn discard_container_extended_state() -> bool {
    if !CPU_ARCHITECTURE
        .extended_user_state_enabled
        .load(Ordering::Acquire)
    {
        return true;
    }
    let Some(slot) = active_container_slot() else {
        return false;
    };
    X86_RUNTIME.CONTAINER_EXTENDED_STATE_VALID[slot].store(false, Ordering::Release);
    reset_extended_user_state()
}

/// Runs `f` on process `pid`'s record and thread slot `thread` of it,
/// under the record lock (`with_linux_process_record`): `f` only copies
/// extended state in and out of the record, or saves and restores it with
/// XSAVE and XRSTOR.
fn with_linux_thread_extended_record<R>(
    pid: u32,
    thread: usize,
    f: impl FnOnce(&mut LinuxProcessRecord, usize) -> R,
) -> Option<R> {
    if thread >= LINUX_THREAD_LIMIT {
        return None;
    }
    with_linux_process_record(pid, |record| f(record, thread))
}

/// Saves the live extended state as thread `thread` of process `pid`, which
/// stops running or blocks.
pub(super) fn save_linux_thread_extended_state(pid: u32, thread: usize) -> bool {
    if !CPU_ARCHITECTURE
        .extended_user_state_enabled
        .load(Ordering::Acquire)
    {
        return true;
    }
    with_linux_thread_extended_record(pid, thread, |record, thread| {
        if !xstate::save(&mut record.extended_states[thread]) {
            return false;
        }
        record.extended_state_valid[thread] = true;
        true
    })
    .unwrap_or(false)
}

/// The size of the XSAVE area the enabled features (x87, SSE, AVX) take,
/// in the standard format: CPUID.(EAX=0DH, ECX=0):EBX.
pub(super) fn linux_xstate_size() -> usize {
    (__cpuid_count(CPUID_EXTENDED_STATE, 0).ebx as usize).min(EXTENDED_STATE_SIZE)
}

/// The x87, SSE and AVX state of thread `thread` of process `pid` in
/// XSAVE's standard format, as PTRACE_GETREGSET's NT_X86_XSTATE shows it:
/// the saved state, or the state a thread starts with when it never saved
/// one. None when extended state is off or there is no such thread.
pub(super) fn linux_thread_xstate(pid: u32, thread: usize) -> Option<ExtendedState> {
    if !CPU_ARCHITECTURE
        .extended_user_state_enabled
        .load(Ordering::Acquire)
    {
        return None;
    }
    let saved = with_linux_thread_extended_record(pid, thread, |record, thread| {
        record.extended_state_valid[thread].then(|| record.extended_states[thread])
    })?;
    if saved.is_some() {
        return saved;
    }
    // The initial state: FCW 0x37f, MXCSR 0x1f80, nothing else in use.
    let mut state = ExtendedState([0; EXTENDED_STATE_SIZE]);
    state.0[..2].copy_from_slice(&0x37f_u16.to_le_bytes());
    state.0[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes());
    state.0[28..32].copy_from_slice(&0xffbf_u32.to_le_bytes());
    Some(state)
}

/// Replaces the saved x87, SSE and AVX state of thread `thread` of
/// process `pid` with `state` (XSAVE's standard format, already checked).
pub(super) fn set_linux_thread_xstate(pid: u32, thread: usize, state: &[u8]) -> bool {
    if !CPU_ARCHITECTURE
        .extended_user_state_enabled
        .load(Ordering::Acquire)
    {
        return false;
    }
    let length = state.len().min(EXTENDED_STATE_SIZE);
    with_linux_thread_extended_record(pid, thread, |record, thread| {
        record.extended_states[thread].0[..length].copy_from_slice(&state[..length]);
        record.extended_state_valid[thread] = true;
    })
    .is_some()
}

pub(super) fn restore_linux_thread_extended_state(pid: u32, thread: usize) -> bool {
    if !CPU_ARCHITECTURE
        .extended_user_state_enabled
        .load(Ordering::Acquire)
    {
        return true;
    }
    with_linux_thread_extended_record(pid, thread, |record, thread| {
        if !record.extended_state_valid[thread] {
            return reset_extended_user_state();
        }
        xstate::restore(&record.extended_states[thread])
    })
    .unwrap_or(false)
}

pub(super) fn save_linux_process_extended_state(pid: u32) -> bool {
    if !CPU_ARCHITECTURE
        .extended_user_state_enabled
        .load(Ordering::Acquire)
    {
        return true;
    }
    let Some(thread) = current_linux_thread_slot() else {
        // A process that has retired its final thread has no live architectural
        // state to preserve during terminal lifecycle cleanup.
        return true;
    };
    save_linux_thread_extended_state(pid, thread)
}

pub(super) fn restore_linux_process_extended_state(pid: u32) -> bool {
    if !CPU_ARCHITECTURE
        .extended_user_state_enabled
        .load(Ordering::Acquire)
    {
        return true;
    }
    let Some(thread) = current_linux_thread_slot() else {
        // No thread is current (they wait parked in calls, or are ready):
        // each gets its own state back as it is made current.
        return true;
    };
    restore_linux_thread_extended_state(pid, thread)
}

pub(super) fn switch_linux_thread_extended_state(from: usize, to: usize) -> bool {
    let pid = super::current_linux_process_pid();
    save_linux_thread_extended_state(pid, from) && restore_linux_thread_extended_state(pid, to)
}

pub(super) fn initialize_linux_thread_extended_state(thread: usize) -> bool {
    let Some(parent) = current_linux_thread_slot() else {
        return false;
    };
    let pid = super::current_linux_process_pid();
    if !save_linux_thread_extended_state(pid, parent) {
        return false;
    }
    if thread >= LINUX_THREAD_LIMIT {
        return false;
    }
    with_linux_thread_extended_record(pid, parent, |record, parent| {
        record.extended_states[thread] = record.extended_states[parent];
        record.extended_state_valid[thread] = record.extended_state_valid[parent];
    })
    .is_some()
}

pub(super) fn discard_linux_thread_extended_state(thread: usize) {
    let pid = super::current_linux_process_pid();
    let _ = with_linux_thread_extended_record(pid, thread, |record, thread| {
        record.extended_state_valid[thread] = false;
    });
}

pub(super) fn clone_linux_process_extended_state(parent: u32, child: u32) -> bool {
    // The child has one thread, the forking one, in the same slot (see
    // stage_linux_fork_child_runtime_state): its state is all that is
    // copied, not every slot's (128 KiB on each fork).
    let current = current_linux_thread_slot();
    // Parent and child are different processes (the pair is None for one
    // process), so different records; the copies go from one heap record
    // to the other.
    with_linux_process_record_pair(parent, child, |parent, child| {
        let Some(thread) = current else {
            child
                .extended_states
                .copy_from_slice(&*parent.extended_states);
            child.extended_state_valid = parent.extended_state_valid;
            return;
        };
        child.extended_state_valid = [false; LINUX_THREAD_LIMIT];
        child.extended_states[thread] = parent.extended_states[thread];
        child.extended_state_valid[thread] = parent.extended_state_valid[thread];
    })
    .is_some()
}

pub(super) fn discard_linux_process_extended_state(pid: u32) {
    let _ = with_linux_process_record(pid, |record| {
        record.extended_state_valid = [false; LINUX_THREAD_LIMIT];
    });
}
