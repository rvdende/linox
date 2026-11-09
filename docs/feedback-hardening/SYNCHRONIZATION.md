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

## Other new ranks

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

## Owner cells still without a lock

The overlay (`linux_overlay`, each domain's in-memory files) keeps an
owner cell serialized by the kernel-entry lock. Its operations hold node
references while they call the volumes (VOLUMES, 186), the overlay mounts
(182), the socket table (140, FIFOs and socket names), the tmpfs limits
(189), the unlinked-file list (188) and the heap, and they are called
under several of those (a loop device's backing file under VOLUMES, a
pseudo-terminal's node under PTYS, overlayfs copy-up under
OVERLAY_MOUNTS). A lock held across an operation would have to rank both
below and above those, so the overlay needs leaf locking instead: node
fields read and written under a short lock, with the calls out made
between. Its nodes are now heap objects (chunks that never move) and its
file data frames are reached only through `Frame` copies, which that
refactor builds on.

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
