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
