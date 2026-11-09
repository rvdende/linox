# x86-64 decomposition contract

Gate 7 decomposes `kernel/src/arch/x86_64/cpu.rs` without changing runtime
behavior. The pre-extraction file contains 48,510 lines. Extraction follows
the ownership boundaries established by Gates 4 through 6; line count is an
observation, not the acceptance target.

## Dependency direction

The intended dependency direction is:

```text
Linux personality policy
        |
        v
process/thread/signal/syscall mechanisms
        |
        v
x86 execution, entry, descriptor, and user-access mechanisms
        |
        v
paging, APIC, PCI, timer, and hardware primitives
```

Architecture mechanisms must not call into unrelated Linux filesystem,
network, IPC, or policy implementations. Linux-facing modules may use narrow
architecture operations, but architecture modules receive data and outcomes
rather than owning Linux policy.

## Planned boundaries

1. `cpu/architecture.rs`: per-CPU entry storage, GDT, TSS, IDT, IST and
   privilege stacks, descriptor installation, and interrupt-gate management.
2. `cpu/user_access.rs`: SMAP-scoped access and fault-recovering raw user-copy
   primitives. Assembly labels and exception-fixup ranges remain explicit.
3. `cpu/execution.rs`: ring transitions, saved register frames, extended user
   state, and architecture return paths.
4. `cpu/linux_abi.rs`: Linux syscall identifiers, ABI constants, and narrow
   argument/result types. This module contains no device ownership.
5. `cpu/linux_signal.rs`, `cpu/linux_thread.rs`, `cpu/linux_time.rs`,
   `cpu/linux_poll.rs`, and `cpu/linux_futex.rs`: cohesive Linux mechanisms
   extracted from dispatch while retaining domain/process-owned state.
6. `cpu/linux_syscall.rs`: syscall dispatch only; subsystem policy remains in
   the existing Linux filesystem, socket, mount, IPC, user, and process
   modules.
7. `cpu/diagnostics.rs`: verification-only probes, traces, and reporting.

## Unsafe and assembly invariants

- `SYSCALL` entry switches to the trusted per-CPU entry stack before Rust,
  compiler-generated code, calls, or pushes execute.
- GS base identifies a live `CpuEntryState` owned by the current processor.
- NMI, double fault, and machine check have distinct guarded IST stacks.
- IDT/GDT/TSS mutation occurs only during CPU initialization or through an
  interrupt-disabled gate update after the source is quiesced.
- User copies execute only inside the audited SMAP window and convert page
  faults inside registered copy ranges into bounded short-copy results.
- Extracted modules may not create new mutable owner roots or bypass the Gate 6
  ownership manifest.

## Verification rule

Every extraction runs formatting, architecture checks, the repository test
suite, Linux ABI coverage, and the deterministic QEMU verification boot before
the next boundary moves. The final gate reruns compatibility and performance
baselines and compares them with the Gate 1 record.

## Extraction record

- Architecture ownership moved first, establishing `CPU_ARCHITECTURE` as the
  single owner of per-CPU entry slots, descriptor tables, and guarded stacks.
- Linux syscall identifiers and ABI constants moved independently so policy
  definitions no longer obscure architecture mechanisms.
- Entry-state installation, GDT/TSS/IDT construction, interrupt-gate mutation,
  and guarded-stack accessors then moved beside their owner. The static
  privilege-entry check follows these mechanisms into `cpu/architecture.rs`
  while continuing to inspect entry assembly in `cpu.rs`.
- Extended-state enablement and container/process XSAVE lifecycle mechanisms
  moved to `cpu/execution.rs`, leaving Linux process policy outside the
  architecture mechanism while retaining explicit runtime ownership.
- The 1,480-line Linux syscall dispatcher moved to `cpu/linux_syscall.rs` as a
  policy-facing routing layer; the x86 `SYSCALL` entry and return assembly
  remains separate from that Linux decision surface.
- Linux clock, time accounting, sleep, interval-timer, rusage, and sysinfo
  mechanisms moved together to `cpu/linux_time.rs`.
- Linux futex wait, wake, wait-vector, and requeue mechanisms moved together to
  `cpu/linux_futex.rs`.
- Linux select, poll, ppoll, wait completion, and epoll creation mechanisms
  moved to `cpu/linux_poll.rs`.
- Linux signal actions, masks, pending queues, timed waits, delivery, frame
  construction, return, process-directed signaling, and default dispositions
  moved together to `cpu/linux_signal.rs`.

After these extractions, `cpu.rs` contains 41,166 lines,
`cpu/architecture.rs` contains 423 lines, `cpu/execution.rs` contains 238
lines, `cpu/linux_abi.rs` contains 868 lines, and `cpu/linux_syscall.rs`
contains 1,483 lines. `cpu/linux_time.rs` contains 630 lines. These
measurements record progress only; `cpu/linux_futex.rs` contains 359 lines.
`cpu/linux_poll.rs` contains 939 lines and `cpu/linux_signal.rs` contains 2,517
lines. Cohesive responsibility and dependency direction remain the gate
criteria.

## Subsystem split (2026-11-09)

A pure move split the remaining 69,325-line `cpu.rs` by subsystem: items
moved with their comments and attributes, private items used elsewhere
became `pub(super)`, and nothing else changed. `cpu.rs` keeps the shared
core: module declarations, the `X86RuntimeOwner` and
`X86MutableRuntimeOwner` runtime owners and their backings, the banked
per-CPU cells, the entry and user-copy assembly, the SMEP/SMAP/UMIP setup,
the syscall and fault entry handlers, and the process state structs. The
architecture checks that read `cpu.rs` (user access, runtime owner) also
cover `cpu/*.rs`.

- Scheduling: `linux_scheduler.rs` (process banks, light threads, the SMP
  and application-processor runtime, cross-CPU operations, timer
  preemption, thread switching) and `linux_runtime_loop.rs` (dispatch,
  parking, yield, live returns, the suspended runtime and the runtime loop).
- Processes: `linux_thread.rs`, `linux_process_state.rs`,
  `linux_process_lifecycle.rs` (snapshots, fork, clone, exit, wait),
  `linux_exec.rs`.
- Memory: `linux_mmap.rs`, `linux_memory_protection.rs`,
  `linux_process_vm.rs`, `linux_user_memory.rs` (user ranges, copies, user
  faults, stack growth, copy-on-write).
- Files: `linux_path_walk.rs`, `linux_directories.rs`, `linux_file_open.rs`,
  `linux_file_ops.rs`, `linux_descriptors.rs`, `linux_fcntl.rs`,
  `linux_read_write.rs`, `linux_procfs.rs`, `linux_mounts.rs`,
  `linux_inotify.rs`.
- I/O and IPC: `linux_sockets.rs`, `linux_pipes.rs`, `linux_epoll.rs`,
  `linux_event_fds.rs`, `linux_timers.rs`, `linux_ipc.rs`, `linux_aio.rs`,
  `linux_devices.rs`; poll waits joined `linux_poll.rs`, robust futex lists
  `linux_futex.rs`, seccomp `linux_security.rs`.
- System: `linux_domain_runtime.rs`, `native_services.rs`,
  `linux_controller.rs`, `linux_namespaces.rs`, `linux_system.rs`,
  `linux_credentials.rs`, `linux_keys.rs`, `linux_prctl.rs`,
  `linux_sched_syscalls.rs`, `linux_rlimit.rs`.
- Verification and diagnostics: `boot_verify.rs`, `boot_verify_elf.rs`,
  `linux_diagnostics.rs`.

Afterwards `cpu.rs` has 4,719 lines and no module exceeds 4,400.
