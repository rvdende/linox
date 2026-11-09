//! The x87, SSE and AVX user state of domains and Linux threads, saved and
//! restored through the trusted core (`trusted::xstate`).
#![forbid(unsafe_code)]

use core::{
    arch::x86_64::{__cpuid, __cpuid_count},
    sync::atomic::Ordering,
};

use super::{
    active_container_slot, current_container_slot, current_linux_thread_slot, linux_process_record,
    LinuxProcessRecord, CPUID_AVX, CPUID_EXTENDED_STATE, CPUID_SSE, CPUID_XSAVE, CPU_ARCHITECTURE,
    LINUX_PROCESS_RUNTIME_INSTANCE_LIMIT, LINUX_THREAD_LIMIT, X86_MUTABLE_RUNTIME, X86_RUNTIME,
};
use crate::trusted::xstate;
pub(super) use crate::trusted::xstate::{ExtendedState, EXTENDED_STATE_SIZE};
use crate::{control_abi, linux_process};

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

fn linux_process_extended_state_index(pid: u32) -> Option<(usize, usize)> {
    let instance = current_container_slot().unwrap_or(control_abi::DOMAIN_LIMIT);
    let slot = linux_process::live_process_runtime_slot(pid)?;
    (instance < LINUX_PROCESS_RUNTIME_INSTANCE_LIMIT && slot < linux_process::PROCESS_RUNTIME_LIMIT)
        .then_some((instance, slot))
}

fn linux_thread_extended_state_index(pid: u32, thread: usize) -> Option<(usize, usize, usize)> {
    let (instance, process) = linux_process_extended_state_index(pid)?;
    (thread < LINUX_THREAD_LIMIT).then_some((instance, process, thread))
}

fn linux_thread_extended_record(
    pid: u32,
    thread: usize,
) -> Option<(&'static mut LinuxProcessRecord, usize)> {
    let (instance, process, thread) = linux_thread_extended_state_index(pid, thread)?;
    Some((linux_process_record(instance, process)?, thread))
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
    let Some((record, thread)) = linux_thread_extended_record(pid, thread) else {
        return false;
    };
    if !xstate::save(&mut record.extended_states[thread]) {
        return false;
    }
    record.extended_state_valid[thread] = true;
    true
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
    let (record, thread) = linux_thread_extended_record(pid, thread)?;
    if record.extended_state_valid[thread] {
        return Some(record.extended_states[thread]);
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
    let Some((record, thread)) = linux_thread_extended_record(pid, thread) else {
        return false;
    };
    let length = state.len().min(EXTENDED_STATE_SIZE);
    record.extended_states[thread].0[..length].copy_from_slice(&state[..length]);
    record.extended_state_valid[thread] = true;
    true
}

pub(super) fn restore_linux_thread_extended_state(pid: u32, thread: usize) -> bool {
    if !CPU_ARCHITECTURE
        .extended_user_state_enabled
        .load(Ordering::Acquire)
    {
        return true;
    }
    let Some((record, thread)) = linux_thread_extended_record(pid, thread) else {
        return false;
    };
    if !record.extended_state_valid[thread] {
        return reset_extended_user_state();
    }
    xstate::restore(&record.extended_states[thread])
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
    let (Some((record, parent)), Some((_, _, thread))) = (
        linux_thread_extended_record(pid, parent),
        linux_thread_extended_state_index(pid, thread),
    ) else {
        return false;
    };
    record.extended_states[thread] = record.extended_states[parent];
    record.extended_state_valid[thread] = record.extended_state_valid[parent];
    true
}

pub(super) fn discard_linux_thread_extended_state(thread: usize) {
    let pid = super::current_linux_process_pid();
    if let Some((record, thread)) = linux_thread_extended_record(pid, thread) {
        record.extended_state_valid[thread] = false;
    }
}

pub(super) fn clone_linux_process_extended_state(parent: u32, child: u32) -> bool {
    let (Some((parent_instance, parent_slot)), Some((child_instance, child_slot))) = (
        linux_process_extended_state_index(parent),
        linux_process_extended_state_index(child),
    ) else {
        return false;
    };
    if parent_instance != child_instance {
        return false;
    }
    if parent_slot == child_slot {
        return false;
    }
    let Some(parent) = linux_process_record(parent_instance, parent_slot) else {
        return false;
    };
    let Some(child) = linux_process_record(child_instance, child_slot) else {
        return false;
    };
    // The child has one thread, the forking one, in the same slot (see
    // stage_linux_fork_child_runtime_state): its state is all that is
    // copied, not every slot's (128 KiB on each fork).
    let Some(thread) = current_linux_thread_slot() else {
        // Parent and child are different slots, so different records; the
        // slices copy in place (no record-sized temporary on the stack).
        child
            .extended_states
            .copy_from_slice(&parent.extended_states);
        child.extended_state_valid = parent.extended_state_valid;
        return true;
    };
    child.extended_state_valid = [false; LINUX_THREAD_LIMIT];
    child.extended_states[thread] = parent.extended_states[thread];
    child.extended_state_valid[thread] = parent.extended_state_valid[thread];
    true
}

pub(super) fn discard_linux_process_extended_state(pid: u32) {
    if let Some(record) = linux_process_extended_state_index(pid)
        .and_then(|(instance, slot)| linux_process_record(instance, slot))
    {
        record.extended_state_valid = [false; LINUX_THREAD_LIMIT];
    }
}
