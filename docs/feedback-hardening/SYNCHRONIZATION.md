# Synchronization and lock order

Gate 8 replaces the single-processor assumption with explicit synchronization.
Disabling interrupts is only a local-CPU operation and is never treated as
cross-CPU exclusion.

## Primitives

- `SpinLock<T>` is a fair ticket lock for shared state that is never acquired
  by a local interrupt handler while interrupted code may hold it.
- `IrqSpinLock<T>` disables local interrupts, acquires the same ticket lock,
  releases it, and then restores the exact prior interrupt-enable state. It is
  used when process and interrupt contexts can reach the same state.
- Atomics remain appropriate for independent counters, flags, generation
  publication, and immutable-object publication. Multi-field invariants use a
  lock rather than a collection of unrelated atomics.

Both locks use acquire/release ordering. Every lock has a rank, and each CPU
tracks its currently held rank. Acquisition must proceed in strictly ascending
rank order and release in reverse order. Violations fail closed in all builds.

## Global order

1. Architecture and per-CPU state (`10`)
2. Physical memory (`20`)
3. Address spaces and page tables (`30`)
4. Scheduler (`40`)
5. Domains and processes (`50`)
6. Filesystems and file caches (`60`)
7. IPC and signals (`70`)
8. Devices and networking (`80`)
9. Diagnostics (`90`)

Code must not call into a lower-ranked owner while holding a higher-ranked
lock. Slow device waits, blocking scheduler operations, and userspace copies
must occur outside spinlock critical sections unless the gate evidence proves
the bounded operation is required and safe.

## Interrupt rules

- Interrupt handlers may take only locks documented as IRQ-safe.
- A local interrupt must not spin on a lock held by the code it interrupted.
- Restoring interrupts happens only after the final IRQ-safe guard releases.
- NMI and machine-check paths do not acquire ordinary locks.
- Cross-CPU wakeups and TLB invalidation use explicit IPI protocols in Gate 9.

## Migrated owners

- Kernel runtime entry: native and Linux syscalls, user faults, timer
  interrupts, and virtio interrupts enter through a rank-10 IRQ-safe boundary.
  This is the initial coarse serialization rule for owner roots not yet given a
  finer lock. The boundary is recursive only for the current CPU because a
  syscall may launch ring-3 auxiliary work whose fault returns through a nested
  entry before the outer frame unwinds; other CPUs still serialize through the
  ticket. Boot initialization remains single-CPU by construction.
- Physical frame allocator: all reservation, ownership, transfer, accounting,
  and release metadata is serialized by the rank-20 IRQ-safe lock. The
  allocator lock also covers contiguous-extent validation, security scrubbing,
  and metadata release so another CPU cannot recycle a frame during scrubbing.
  The `initialized` flag remains release/acquire publication for the fully
  constructed allocator.

## Leaf locks between the heap and the frame allocator

Some tables are consulted from page faults and path walks, under whatever
lock the calling system call holds. Every lock a system call may hold
across a copy to user memory ranks below the kernel heap (190), and the
frame allocator (200) is taken only inside `memory.rs`. So these tables
get leaf locks ranked 191-199: each critical section only reads or writes
the table's own records, never allocates or frees heap memory, and calls
nothing that takes a lock. Two such leaves are never held together.

- `OVERLAY_NODES` (191, `linux_overlay`): one lock per instance over
  each domain's in-memory files (nodes, their hint tables, shared-mapping
  registrations) and, through `Frame` copies, the file data frames they
  index. The overlay is called under VOLUMES (a loop device's backing
  file, a volume's page cache), OVERLAY_MOUNTS (overlayfs copy-up and its
  `create` callback), PTYS, LOOP, SWAPS and UNLINKED_FILES, and its work
  reaches VOLUMES, OVERLAY_MOUNTS, SOCKETS (FIFOs), TMPFS_LIMITS,
  UNLINKED_FILES, SWAPS (freeing and reading swap entries, which for a
  loop device comes back into the overlay), the heap and the frame
  allocator. No rank fits a lock held across that, so the lock is a leaf
  held only to read and write node fields, the hint tables and frame
  data: every other call is made with it released. An operation that
  needs heap memory (a chunk of node slots, room in the chunk list, the
  mapping list, a node's attribute list or a hint table), zeroed frames,
  or a page back from swap returns what it needs; `locked_with` gets it
  with the lock released and runs the operation again, which looks its
  node up again by handle (a chunk list and hint tables twice as large
  are built outside and moved into under the lock, as FILE_CACHE does).
  Operations check what they need before they change anything. What they
  take out (old paths, removed attributes, forgotten nodes, a file's
  frames, swap entries and detached data chains) is released after the
  lock, as are the tmpfs-limit charges, the unlinked-file list and memory
  cgroup charges. Work done on a copy with the lock released (moving a
  file's chain into a frame index for MAP_SHARED, a directory rename's
  new paths) checks the node's data `version`, or the moved nodes'
  handles and paths, before it is put in place, and starts again if they
  changed. Ranked just above the heap, it may be taken under any lock
  but the other leaves, none of which calls the overlay. Never taken in
  interrupt context.
- `MOUNT_NAMESPACES` (192, `linux_mount`): the mount namespace table.
  Records are copied out; the domain and published-root checks that
  `current_root_is_read_only` makes run after the lock is released.
- `USER_NAMESPACES` (194, `linux_user`): one lock per instance. A table's
  storage (64 namespaces) is reserved with the lock released
  (`reserve_table`), so `create` only fills reserved room; the domain
  lookup that picks the instance happens before the lock is taken.
- `FILE_CACHE` (196, `linux_file_cache`): one lock per domain. The cache
  is asked by `contains` from copy-on-write faults (mprotect, fork's
  sharing checks, private page releases) and by `lookup`/`insert` from
  the mmap fault path. A fault can happen during any copy to user memory,
  so the caller may hold SYSV_IPC, SOCKETS, the futex coordination lock,
  MEMORY_AREAS, VOLUMES, the tmpfs limits or the swap areas (all below
  the heap); the fault path itself then takes the frame allocator. The
  cache therefore sits above all of them and below the frame allocator,
  and is held only to probe or fill a table that already has room:
  `insert` allocates a twice-as-large table with the lock released,
  rehashes into it under the lock (an insert into reserved slots, no
  allocation), swaps it in and frees the old table after unlocking;
  `reset_current` takes the whole table out under the lock and releases
  the cached frames and the storage after. A lock-free table was not
  needed: the critical sections are a few probes long.
- `PUBLISHED_ROOTFS` (197, `published_rootfs`): one lock per domain slot,
  held to clone, take or put the `Arc` of the slot's image and path
  index. Readers keep the clone while they walk; the index is freed when
  the last clone drops, after the lock is released.
- `ROOTFS_IMAGES` (198, `image_store`): the unpacked images and which
  slots use them. Taken after the image store (102) and the published
  root filesystems; an image whose last user goes is freed after the lock
  is released.
- `SUSPENDED_INIT_FRAMES` (193, `address_space`): one lock per domain
  slot, holding the frame leases of the slot's suspended init (its
  page-table hierarchy and runtime extent). Held only to copy the leases
  in when init suspends and out when it resumes or ends.
- `ADDRESS_SPACE_SCRATCH` (199, `address_space`): the work lists an
  address-space clone or validation reuses. An operation takes its list
  out whole under the lock and puts it back when done
  (`address_space::take_scratch`), so the lock is never held across the
  work, which allocates and takes the frame allocator; a nested operation
  finds the slot empty and starts a list of its own, and a list displaced
  on the way back is freed after the lock is released.
- `SIGNAL_QUEUES` (199, `linux_signal`): each domain's signal queues;
  see "Signal queues" below.

## Other new ranks

- `AUXILIARY_ADDRESS_SPACES` (106, `address_space`): the native service
  domains' address spaces and their device bindings. Taken by native
  service calls and the user-fault path at system-call level, never under
  another lock, and held while a domain's virtio device is bound,
  checked or quiesced, so the domain manager (450), the frame allocator
  (200), the I/O MMU and the scheduler are taken under it; it ranks just
  above system-call level, below all of them. A staged service's payload
  is copied from user memory before the lock is taken (a user copy may
  fault into the memory layer), and a timed-out device wait releases it
  before quiescing the device, which takes it again.

- `CONTROL_CHANNEL` (103, `ipc`) and `PACKET_MAILBOXES` (104, `packet`):
  taken by native service calls at system-call level, never under another
  lock. The channel calls the scheduler's wakeup while held; a packet
  consume copies the packet to user memory while held, which is why both
  rank just above system-call level (as SYSV_IPC does), below everything
  a user copy or a wakeup may take.
- `DOMAINS` (450, `domain`): the domain manager, an `IrqSpinLock` in a
  set-once `OwnedState`. Capability and credential checks ask it under
  whatever lock a call holds, and the scheduler asks it for service
  classes and CPU limits while it chooses what to run, so it ranks above
  the scheduler's locks (400) and is a leaf: the checks that need frame
  counts (`memory::owner_live_frame_count`) read them before taking it.
  Interrupts stay off while it is held, so a timer interrupt's scheduler
  work on the same CPU cannot reach it while it is held.

## The Linux process tables

`PROCESS_TABLE` (189, `linux_process`): one `IrqSpinLock` per domain
instance (`PROCESS_TABLES`), around the instance's process table and its
processes' address-space lists (page-table frames and mapped pages by
runtime slot, which used to be raw pointers to leaked boxes). Every access
goes through `with_live_table` (or `with_live_process`), which holds the
lock for the closure only.

- What runs under it: the table's own updates, which grow and free its
  vectors (the heap, 190); frame ownership checks and the release of
  page-table frames (the frame allocator, 200); user-namespace lookups
  (`linux_user`, 194, and the domain manager, 450); the scheduler's run
  queue (its workspace has no lock yet; the preempted-context leaf is
  400); and the fork scratch leaf below. Nothing under it parks, copies to
  or from user memory, or calls back into `linux_process`.
- What it is taken under: whatever a system call holds while it looks a
  process up, including a copy-on-write fault taken during a copy to user
  memory, which reaches `live_process_mapping` and
  `replace_live_process_mapping` under the futex coordination lock (180),
  the socket table (140), System V IPC (101), the volumes (186) or the
  unlinked-file list (188); the executables (110) and AIO contexts (116)
  look processes up while held. So it ranks as high as the heap allows,
  sharing 189 with the tmpfs limits and the swap areas, which are leaves
  that neither call into the table nor are called under it.
- What moved out from under it, done between two holds that look the
  process up again by its handle (slot and generation): the namespace
  bookkeeping (`NAMESPACES`, 107: entering a new child's PID namespace,
  forgetting a reaped pid, collecting unused namespaces, owed as
  `DeferredWork` and run by `with_live_table` after the unlock); System V
  attachments a fork inherits or an exit drops (`SYSV_IPC`, 101);
  page-table teardown at exit and the page copy and page-table clone at
  fork, which drop and duplicate swap entries (`SWAPS`, 189) and walk
  page tables; the walk of a stale process's live page tables; and the
  callbacks callers pass (`ready_live_process_after`'s `accept`,
  `live_memcg_members`' `within`, `any_live_process_root`'s `visit`), which
  call into the table themselves. The callbacks that still run under it
  (`with_live_process_groups`, `with_live_process_root`,
  `account_live_process_io`, `update_posix_timer`) only read or set the
  values they are given; getgroups copies the groups out before its copy
  to user memory.
- Interrupts are off while it is held (it is an `IrqSpinLock`), so the
  timer's CPU-time accounting on the same CPU cannot reach it held.

The kernel-entry lock still serializes system calls, so a process's state
between two holds (out of the run queue, page tables retired, not yet a
zombie) is not yet seen by another CPU's call; splitting the kernel-entry
lock (M3) has to keep that in mind, as it has for the frames a lookup
hands out (`copy_from_live_process` copies a page after the lock is
released).

`PROCESS_SCRATCH` (195): the fork work areas (`FORK_SCRATCH`). A fork
takes them out and puts them back, each a swap of vectors that allocates
and frees nothing under the lock, so no lock is held across the fork's
copies; a fork that finds them taken works with empty ones.

## Signal queues

`SIGNAL_QUEUES` (199, `linux_signal`): one `IrqSpinLock` per domain
instance over that instance's queued signals, heap tables grown as
process and thread slots are first used (thread queues are keyed by
process slot and thread slot). The lock is held only inside
`linux_signal.rs` and nothing else is taken under it, so its rank is set
by what its callers hold. Audit of the callers:

- Senders (`linux_enqueue_signal`): kill, tkill, tgkill,
  rt_(tg)sigqueueinfo, a blocked real-time raise, SIGCONT's removal of
  stop signals, SIGCHLD, SIGPIPE and SIGXFSZ on the write return paths,
  SIGTRAP and fault signals, SIGIO and lease breaks (fcntl), dnotify, pty
  hangups and job control, mq_notify, cgroup.kill, PID namespace
  teardown and the POSIX and interval timers (expired from system calls,
  `refresh_linux_posix_timers`). Almost all run at system-call level
  under only the kernel-entry lock (100); subsystems that owe a signal
  collect it under their own lock and send it after releasing it
  (`linux_send_dnotify_notices`, `linux_pty_send_hangups`, the holders
  `linux_lease::break_for` returns, `linux_mq_finish_registration`).
  The exception is a memory cgroup's OOM kill: `allocate_user_frames`
  charges the cgroup (`charge_linux_user_pages`), which may pick a victim
  and queue SIGKILL (`linux_memcg_oom_kill`). That allocation happens in
  page faults, including copy-on-write and lazily reserved pages faulted
  during a copy to user memory, under whatever lock the system call holds:
  SYSV_IPC, SOCKETS, the futex coordination lock, MEMORY_AREAS, VOLUMES,
  the tmpfs limits or the swap areas (189), as `FILE_CACHE` above found.
- Readers and takers (`pending_mask`, `peek`, `queued`, `dequeue`): signal
  delivery, sigtimedwait, signalfd and sigpending at system-call level,
  the scheduler loop (`linux_thread_turn`, `linux_process_killed`) under
  the kernel-entry lock only, and the timer tick's
  `linux_signal_due_from_timer`, which runs only on a tick that
  interrupted user mode, after it takes the kernel-entry lock.
- Clears: fork, exec, exit and slot release (`clear_process`) and a
  thread's exit (`clear`), at system-call or scheduler-loop level.

Because senders may hold locks up to 189, a lock below the heap (which
would let the tables grow while held) cannot rank above them all, so the
queues use the leaf pattern: nothing is allocated or freed while the lock
is held. An operation that finds a table or queue too small returns what
it needs; the caller reserves it with the lock released (`Spare`) and
tries again, and under the lock the full table's entries move into the
reserved storage, which is swapped in (no allocation). Storage a table
lets go of (a drained or cleared queue, a process's thread queues, a
replaced table) leaves the critical section with the result and is freed
after the lock is released; trimming a table only drops trailing entries
that hold no storage, so the two slot tables keep their capacity (at most
4096 entries of 24 bytes each per domain), while a process's thread
queues go with its slot (`clear_process`). Out of memory while reserving is still
`Error::NoMemory`. The rank is 199 (shared with ADDRESS_SPACE_SCRATCH, a leaf that is
never held with it), above the heap, every lock below it
and the other leaves (none of which sends a signal or is held across
one), below the frame allocator, which it never reaches. It is
interrupt-safe so no tick can arrive on the CPU that holds it.
`pending_count` and `any_pending` read per-instance atomic counts,
changed only with the lock held, and take no lock. With every acquire
recording the rank its CPU already held, the verification boot (`make
test`), `make test-quick` and a full LTP run (the whole syscall list in
one boot) saw only 0 (boot, no lock) and 100 (the kernel-entry lock); no
memory cgroup ran out of memory in them, so the OOM path is what sets
the rank, not the measurement.

## Local interrupt audit

Direct `cli`, `sti`, and `sti; hlt; cli` sequences are limited to local CPU
semantics:

- synchronization guards save, clear, and restore the local IF state;
- APIC and virtio verification temporarily admit a local interrupt and then
  mask it while device state is retired;
- device waits use the x86 interrupt shadow around `sti; hlt` to avoid a lost
  wakeup; and
- timer calibration and timeout proofs temporarily admit their local vector.

None of these sequences protects cross-CPU shared state. The architecture
check rejects removal of the shared kernel-entry boundary, replacement of the
locked physical allocator, and stale single-processor serialization claims.
