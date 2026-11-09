//! System V IPC (shared memory segments, semaphore sets, message queues)
//! and POSIX message queues, per domain and per IPC namespace. Each
//! instance's objects are heap records under one lock; a segment's pages
//! are frames, since they are mapped into the processes that attach it,
//! and are only ever copied through `trusted::frame::Frame` here.
#![forbid(unsafe_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::sync::{LockRank, SpinLock, SpinLockGuard};
use crate::{heap, linux_namespace, linux_process, memory, trusted::frame::Frame};

const PAGE_SIZE: usize = 4096;
/// One instance per domain, the host's, and one per IPC namespace made
/// inside a domain (`linux_namespace` hands those out).
const INSTANCE_LIMIT: usize =
    linux_namespace::IPC_INSTANCE_FIRST + linux_namespace::IPC_INSTANCE_LIMIT;
pub(crate) const SEM_VALUE_MAX: u16 = 32_767;

/// Each instance's objects. Lists keep the newest object first, the order
/// `/proc/sysvipc` lists them in.
struct Instance {
    segments: VecDeque<Segment>,
    attachments: VecDeque<Attachment>,
    semaphore_sets: VecDeque<SemaphoreSet>,
    queues: VecDeque<MessageQueue>,
    next_id: u32,
    next_semaphore_id: u32,
    next_message_id: u32,
    processes: SemaphoreProcesses,
}

impl Instance {
    const fn new() -> Self {
        Self {
            segments: VecDeque::new(),
            attachments: VecDeque::new(),
            semaphore_sets: VecDeque::new(),
            queues: VecDeque::new(),
            next_id: 1,
            next_semaphore_id: 1,
            next_message_id: 1,
            processes: SemaphoreProcesses::EMPTY,
        }
    }
}

/// The instances. System calls copy to and from user memory while holding
/// an instance (msgsnd, msgrcv, semctl), so the lock ranks just above
/// system-call level, below everything a user copy may take.
static SYSV_IPC_RUNTIME: [SpinLock<Instance>; INSTANCE_LIMIT] =
    [const { SpinLock::new(LockRank::SYSV_IPC, Instance::new()) }; INSTANCE_LIMIT];

/// Which semaphore value a blocked `semop` waits on: to rise far enough for
/// a decrement, or (`zero`) to reach zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SemaphoreBlock {
    pub(crate) number: u16,
    pub(crate) zero: bool,
}

/// A process waiting in `semop`. The record outlives the call's restarts and
/// goes when the call completes, fails, times out or is interrupted, or the
/// process exits.
#[derive(Clone, Copy)]
pub(crate) struct SemaphoreWait {
    pub(crate) pid: u32,
    pub(crate) id: u32,
    pub(crate) block: SemaphoreBlock,
    /// Elapsed nanoseconds after which `semtimedop` gives up.
    pub(crate) deadline: Option<u64>,
}

/// A process's `SEM_UNDO` adjustment of one value, applied when it exits.
#[derive(Clone, Copy)]
struct SemaphoreUndo {
    pid: u32,
    id: u32,
    number: u16,
    adjustment: i32,
}

struct SemaphoreProcesses {
    waits: Vec<SemaphoreWait>,
    undo: Vec<SemaphoreUndo>,
    /// Processes waiting in msgsnd or msgrcv, with the queue they wait on.
    message_waits: Vec<(u32, u32)>,
}

impl SemaphoreProcesses {
    const EMPTY: Self = Self {
        waits: Vec::new(),
        undo: Vec::new(),
        message_waits: Vec::new(),
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Exists,
    Invalid,
    NoEntry,
    NoMemory,
    /// The domain's segment limit (shmmni) is reached.
    NoSpace,
    Range,
    WouldBlock,
    TooBig,
    Fault,
    /// The caller may not use the object that way (EACCES).
    Access,
    /// Only the object's owner, creator or a privileged caller may (EPERM).
    Permission,
    /// Another process has registered for the queue's notification (EBUSY).
    Busy,
}

#[derive(Clone, Copy)]
pub(crate) struct SegmentInfo {
    pub(crate) key: i32,
    pub(crate) size: u64,
    pub(crate) mode: u16,
    pub(crate) creator_pid: u32,
    pub(crate) last_pid: u32,
    pub(crate) attachments: u64,
    /// Made with SHM_HUGETLB: its size is in huge pages.
    pub(crate) huge: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct SemaphoreSetInfo {
    pub(crate) key: i32,
    pub(crate) count: u64,
    pub(crate) mode: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct SemaphoreOperation {
    pub(crate) number: u16,
    pub(crate) operation: i16,
    pub(crate) flags: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct MessageQueueInfo {
    pub(crate) key: i32,
    pub(crate) mode: u16,
    pub(crate) bytes: u64,
    pub(crate) messages: u64,
    pub(crate) byte_limit: u64,
    pub(crate) last_sender: u32,
    pub(crate) last_receiver: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct PosixQueueInfo {
    pub(crate) id: u32,
    pub(crate) max_messages: u64,
    pub(crate) max_message_size: u64,
    pub(crate) messages: u64,
    pub(crate) created: bool,
}

struct MessageQueue {
    id: u32,
    key: i32,
    mode: u16,
    byte_limit: u64,
    bytes: u64,
    messages: VecDeque<Message>,
    last_sender: u32,
    last_receiver: u32,
    posix: bool,
    /// A POSIX queue still has its name (mq_unlink clears it).
    linked: bool,
    max_messages: u32,
    max_message_size: u32,
    open_references: u64,
    owner: Ownership,
    /// msg_stime, msg_rtime, msg_ctime.
    times: [i64; 3],
    /// A POSIX queue's mq_notify registration.
    registration: Option<Registration>,
    name: Vec<u8>,
}

impl MessageQueue {
    fn new(id: u32, key: i32, mode: u16, byte_limit: u64) -> Self {
        Self {
            id,
            key,
            mode: mode & 0o777,
            byte_limit,
            bytes: 0,
            messages: VecDeque::new(),
            last_sender: 0,
            last_receiver: 0,
            posix: false,
            linked: false,
            max_messages: 0,
            max_message_size: 0,
            open_references: 0,
            owner: Ownership::default(),
            times: [0; 3],
            registration: None,
            name: Vec::new(),
        }
    }

    fn named(&self, name: &[u8]) -> bool {
        self.posix && self.linked && self.name == name
    }

    fn message_count(&self) -> u64 {
        self.messages.len() as u64
    }
}

struct Message {
    message_type: i64,
    bytes: Vec<u8>,
}

/// What mq_notify asks for when a message reaches an empty queue.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Notification {
    /// SIGEV_NONE: registered, but told nothing.
    Quiet,
    /// SIGEV_SIGNAL: this signal, with this value.
    Signal { signal: u8, value: u64 },
    /// SIGEV_THREAD as the C library asks for it: this cookie, sent back
    /// on this netlink socket (whose reference the registration holds).
    Thread { socket: u16, cookie: [u8; 32] },
}

/// A registration taken for delivery: who registered, and for what.
#[derive(Clone, Copy)]
pub(crate) struct Registration {
    pub(crate) pid: u32,
    pub(crate) notification: Notification,
}

#[derive(Clone, Copy, Default)]
struct Semaphore {
    value: u16,
    last_pid: u32,
}

struct SemaphoreSet {
    id: u32,
    key: i32,
    mode: u16,
    last_pid: u32,
    owner: Ownership,
    /// sem_otime, unused, sem_ctime.
    times: [i64; 3],
    values: Vec<Semaphore>,
}

impl SemaphoreSet {
    fn count(&self) -> u64 {
        self.values.len() as u64
    }
}

struct Segment {
    id: u32,
    key: i32,
    size: u64,
    mode: u16,
    marked_for_removal: bool,
    /// A segment of huge pages (SHM_HUGETLB), which holds its pages from
    /// the huge page pool while it exists.
    huge: bool,
    creator_pid: u32,
    last_pid: u32,
    attachments: u64,
    owner: Ownership,
    /// shm_atime, shm_dtime, shm_ctime.
    times: [i64; 3],
    /// The segment's pages, which the processes attaching it map.
    frames: Vec<memory::FrameLease>,
}

impl Segment {
    fn info(&self) -> SegmentInfo {
        SegmentInfo {
            key: self.key,
            size: self.size,
            mode: self.mode,
            creator_pid: self.creator_pid,
            last_pid: self.last_pid,
            attachments: self.attachments,
            huge: self.huge,
        }
    }

    /// Gives the segment's pages back to the frame allocator, scrubbed.
    fn release(self) -> bool {
        self.frames
            .iter()
            .all(|frame| memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[*frame]))
    }
}

/// A process's attachment of a segment at an address.
struct Attachment {
    segment: u32,
    address: u64,
    length: u64,
    pid: u32,
}

/// An object's `ipc_perm` owner and creator, set by the first caller to
/// get it after it was made (`adopt`): its creator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Ownership {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) cuid: u32,
    pub(crate) cgid: u32,
    adopted: bool,
}

/// Who asks: effective user and group, and whether privileged (root).
#[derive(Clone, Copy)]
pub(crate) struct Caller {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) privileged: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Kind {
    Segment,
    Semaphores,
    Messages,
}

/// Indexes into an object's times.
pub(crate) const TIME_OPERATION: usize = 0;
pub(crate) const TIME_DETACH: usize = 1;
pub(crate) const TIME_RECEIVE: usize = 1;
pub(crate) const TIME_CHANGE: usize = 2;

/// Runs `body` on object `id`'s owner, times and mode under the lock.
fn with_header<R>(
    kind: Kind,
    id: u32,
    body: impl FnOnce(&mut Ownership, &mut [i64; 3], &mut u16) -> R,
) -> Result<R, Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let instance = &mut *guard;
    match kind {
        Kind::Segment => {
            let segment = find_segment(instance, id).ok_or(Error::Invalid)?;
            Ok(body(
                &mut segment.owner,
                &mut segment.times,
                &mut segment.mode,
            ))
        }
        Kind::Semaphores => {
            let set = find_semaphore_set(instance, id).ok_or(Error::Invalid)?;
            Ok(body(&mut set.owner, &mut set.times, &mut set.mode))
        }
        Kind::Messages => {
            let queue = find_message_queue(instance, id).ok_or(Error::Invalid)?;
            Ok(body(&mut queue.owner, &mut queue.times, &mut queue.mode))
        }
    }
}

/// The first get of a new object makes its caller owner and creator and
/// stamps its change time; true then (the caller created it).
pub(crate) fn adopt(kind: Kind, id: u32, caller: Caller, now: i64) -> Result<bool, Error> {
    with_header(kind, id, |owner, times, _| {
        if owner.adopted {
            return false;
        }
        *owner = Ownership {
            uid: caller.uid,
            gid: caller.gid,
            cuid: caller.uid,
            cgid: caller.gid,
            adopted: true,
        };
        times[TIME_CHANGE] = now;
        true
    })
}

/// Whether `caller` may use object `id` as `requested` asks (permission
/// bits, as in a mode: 0o444 to read, 0o222 to write), as Linux's
/// ipcperms decides: the owner's bits for its owner or creator, the
/// group's for its group, else the others'; root may always.
pub(crate) fn check_access(
    kind: Kind,
    id: u32,
    caller: Caller,
    requested: u16,
) -> Result<(), Error> {
    with_header(kind, id, |owner, _, mode| {
        let requested = (requested >> 6 | requested >> 3 | requested) & 7;
        let granted = if caller.uid == owner.uid || caller.uid == owner.cuid {
            *mode >> 6
        } else if caller.gid == owner.gid || caller.gid == owner.cgid {
            *mode >> 3
        } else {
            *mode
        } & 7;
        caller.privileged || requested & !granted == 0
    })?
    .then_some(())
    .ok_or(Error::Access)
}

/// Whether `caller` may change or remove object `id`: its owner, its
/// creator, or a privileged caller (EPERM otherwise).
pub(crate) fn check_owner(kind: Kind, id: u32, caller: Caller) -> Result<(), Error> {
    with_header(kind, id, |owner, _, _| {
        caller.privileged || caller.uid == owner.uid || caller.uid == owner.cuid
    })?
    .then_some(())
    .ok_or(Error::Permission)
}

/// Object `id`'s owner and times.
pub(crate) fn header(kind: Kind, id: u32) -> Result<(Ownership, [i64; 3]), Error> {
    with_header(kind, id, |owner, times, _| (*owner, *times))
}

/// IPC_SET's owner, stamped with its change time.
pub(crate) fn set_owner(kind: Kind, id: u32, uid: u32, gid: u32, now: i64) -> Result<(), Error> {
    with_header(kind, id, |owner, times, _| {
        owner.uid = uid;
        owner.gid = gid;
        times[TIME_CHANGE] = now;
    })
}

/// Sets and clears flag bits of object `id`'s mode (SHM_LOCKED).
pub(crate) fn update_mode(kind: Kind, id: u32, set: u16, clear: u16) -> Result<(), Error> {
    with_header(kind, id, |_, _, mode| *mode = *mode & !clear | set)
}

/// Stamps time `index` of object `id` with `now`.
pub(crate) fn stamp(kind: Kind, id: u32, index: usize, now: i64) -> Result<(), Error> {
    with_header(kind, id, |_, times, _| times[index] = now)
}

/// The calling process's instance, locked.
struct Guard;

impl Guard {
    fn acquire() -> Option<SpinLockGuard<'static, Instance>> {
        Self::acquire_at(linux_process::current_ipc_instance())
    }

    fn acquire_at(instance: usize) -> Option<SpinLockGuard<'static, Instance>> {
        SYSV_IPC_RUNTIME.get(instance).map(SpinLock::lock)
    }
}

/// A zeroed frame for a segment page.
fn allocate_zeroed() -> Option<memory::FrameLease> {
    let [frame] = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL)?;
    let Some(page) = Frame::leased(frame) else {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        return None;
    };
    page.fill(0);
    Some(frame)
}

fn segment_index(instance: &Instance, id: u32) -> Option<usize> {
    instance
        .segments
        .iter()
        .position(|segment| segment.id == id)
}

fn find_segment(instance: &mut Instance, id: u32) -> Option<&mut Segment> {
    instance
        .segments
        .iter_mut()
        .find(|segment| segment.id == id)
}

fn find_key(instance: &Instance, key: i32) -> Option<&Segment> {
    instance
        .segments
        .iter()
        .find(|segment| segment.key == key && !segment.marked_for_removal)
}

/// Removes segment `id` and gives its pages back.
fn unlink_and_release(instance: &mut Instance, id: u32) -> bool {
    segment_index(instance, id)
        .and_then(|index| instance.segments.remove(index))
        .is_some_and(Segment::release)
}

pub(crate) fn get_or_create(
    key: i32,
    size: u64,
    mode: u16,
    create: bool,
    exclusive: bool,
    pid: u32,
    ids: SegmentIds,
) -> Result<u32, Error> {
    let SegmentIds {
        requested,
        limit,
        largest,
        huge,
    } = ids;
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let instance = &mut *guard;
    if key != 0 {
        if let Some(segment) = find_key(instance, key) {
            if create && exclusive {
                return Err(Error::Exists);
            }
            if size > segment.size {
                return Err(Error::Invalid);
            }
            return Ok(segment.id);
        }
        if !create {
            return Err(Error::NoEntry);
        }
    }
    if size == 0 || size > largest {
        return Err(Error::Invalid);
    }
    let pages = usize::try_from(size.div_ceil(PAGE_SIZE as u64)).map_err(|_| Error::Invalid)?;
    // No more segments than /proc/sys/kernel/shmmni allows (ENOSPC).
    if instance.segments.len() >= limit.max(1) {
        return Err(Error::NoSpace);
    }
    instance
        .segments
        .try_reserve(1)
        .map_err(|_| Error::NoMemory)?;
    // A requested id (/proc/sys/kernel/shm_next_id) that is free is used, and
    // the counter moves past it; otherwise the next free id.
    let id = match requested
        .filter(|id| *id != 0 && *id <= i32::MAX as u32 && segment_index(instance, *id).is_none())
    {
        Some(id) => {
            if instance.next_id <= id {
                instance.next_id = id + 1;
            }
            id
        }
        None => {
            let id = instance.next_id;
            instance.next_id = id.wrapping_add(1);
            id
        }
    };
    if id == 0 {
        return Err(Error::NoMemory);
    }
    let mut segment = Segment {
        id,
        key,
        size,
        mode: mode & 0o777,
        marked_for_removal: false,
        huge,
        creator_pid: pid,
        last_pid: pid,
        attachments: 0,
        owner: Ownership::default(),
        times: [0; 3],
        frames: Vec::new(),
    };
    segment
        .frames
        .try_reserve_exact(pages)
        .map_err(|_| Error::NoMemory)?;
    for _ in 0..pages {
        let Some(frame) = allocate_zeroed() else {
            let _ = segment.release();
            return Err(Error::NoMemory);
        };
        segment.frames.push(frame);
    }
    instance.segments.push_front(segment);
    Ok(id)
}

/// How a new segment gets its id: the id `/proc/sys/kernel/shm_next_id`
/// asks for, if any, and how many segments `shmmni` allows in all.
#[derive(Clone, Copy)]
pub(crate) struct SegmentIds {
    pub(crate) requested: Option<u32>,
    pub(crate) limit: usize,
    /// The largest segment that may be made (shmmax).
    pub(crate) largest: u64,
    /// The segment is made of huge pages (SHM_HUGETLB).
    pub(crate) huge: bool,
}

/// Every segment of the current instance with its id, newest first, for
/// `/proc/sysvipc/shm`.
pub(crate) fn segments() -> Vec<(u32, SegmentInfo)> {
    let mut found = Vec::new();
    let Some(guard) = Guard::acquire() else {
        return found;
    };
    if found.try_reserve_exact(guard.segments.len()).is_ok() {
        found.extend(
            guard
                .segments
                .iter()
                .map(|segment| (segment.id, segment.info())),
        );
    }
    found
}

/// Every System V message queue of the current instance with its id,
/// newest first, for `/proc/sysvipc/msg` (POSIX queues share the list and
/// are left out).
pub(crate) fn message_queues() -> Vec<(u32, MessageQueueInfo)> {
    let mut found = Vec::new();
    let Some(guard) = Guard::acquire() else {
        return found;
    };
    let queues = guard.queues.iter().filter(|queue| !queue.posix);
    if found.try_reserve_exact(queues.clone().count()).is_ok() {
        found.extend(queues.map(|queue| (queue.id, message_queue_info_of(queue))));
    }
    found
}

/// Every semaphore set of the current instance with its id, newest first,
/// for `/proc/sysvipc/sem`.
pub(crate) fn semaphore_sets() -> Vec<(u32, SemaphoreSetInfo)> {
    let mut found = Vec::new();
    let Some(guard) = Guard::acquire() else {
        return found;
    };
    if found.try_reserve_exact(guard.semaphore_sets.len()).is_ok() {
        found.extend(
            guard
                .semaphore_sets
                .iter()
                .map(|set| (set.id, semaphore_set_info_of(set))),
        );
    }
    found
}

pub(crate) fn segment(id: u32) -> Result<SegmentInfo, Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    find_segment(&mut guard, id)
        .map(|segment| segment.info())
        .ok_or(Error::Invalid)
}

pub(crate) fn frame(id: u32, index: usize) -> Result<memory::FrameLease, Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let segment = find_segment(&mut guard, id).ok_or(Error::Invalid)?;
    segment.frames.get(index).copied().ok_or(Error::Invalid)
}

pub(crate) fn attach(id: u32, address: u64, pid: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let instance = &mut *guard;
    let segment = find_segment(instance, id).ok_or(Error::Invalid)?;
    let attachments = segment.attachments.checked_add(1).ok_or(Error::NoMemory)?;
    let length = segment.size;
    instance
        .attachments
        .try_reserve(1)
        .map_err(|_| Error::NoMemory)?;
    let segment = find_segment(instance, id).ok_or(Error::Invalid)?;
    segment.attachments = attachments;
    segment.last_pid = pid;
    instance.attachments.push_front(Attachment {
        segment: id,
        address,
        length,
        pid,
    });
    Ok(())
}

pub(crate) fn attachment_at(address: u64, pid: u32) -> Result<(u32, u64), Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    guard
        .attachments
        .iter()
        .find(|entry| entry.address == address && entry.pid == pid)
        .map(|entry| (entry.segment, entry.length))
        .ok_or(Error::Invalid)
}

/// Removes `pid`'s attachments (only the one at `address`, if given),
/// freeing segments marked for removal that lose their last attachment;
/// how many it removed.
fn detach_matching(
    instance: &mut Instance,
    pid: u32,
    address: Option<u64>,
) -> Result<usize, Error> {
    let mut removed = 0;
    let mut index = 0;
    while index < instance.attachments.len() {
        let entry = &instance.attachments[index];
        if entry.pid != pid || address.is_some_and(|address| entry.address != address) {
            index += 1;
            continue;
        }
        let Some(entry) = instance.attachments.remove(index) else {
            return Err(Error::Invalid);
        };
        let segment = find_segment(instance, entry.segment).ok_or(Error::Invalid)?;
        segment.attachments = segment.attachments.checked_sub(1).ok_or(Error::Invalid)?;
        segment.last_pid = pid;
        if segment.marked_for_removal
            && segment.attachments == 0
            && !unlink_and_release(instance, entry.segment)
        {
            return Err(Error::Invalid);
        }
        removed += 1;
        if address.is_some() {
            break;
        }
    }
    Ok(removed)
}

pub(crate) fn detach(address: u64, pid: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    (detach_matching(&mut guard, pid, Some(address))? == 1)
        .then_some(())
        .ok_or(Error::Invalid)
}

pub(crate) fn inherit_process_attachments(parent: u32, child: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let instance = &mut *guard;
    if parent == child {
        return Err(Error::Invalid);
    }
    if instance.attachments.iter().any(|entry| entry.pid == child) {
        let _ = detach_matching(instance, child, None);
        return Err(Error::Invalid);
    }
    let mut clones = Vec::new();
    clones
        .try_reserve_exact(
            instance
                .attachments
                .iter()
                .filter(|entry| entry.pid == parent)
                .count(),
        )
        .map_err(|_| Error::NoMemory)?;
    clones.extend(
        instance
            .attachments
            .iter()
            .filter(|entry| entry.pid == parent)
            .map(|entry| Attachment {
                segment: entry.segment,
                address: entry.address,
                length: entry.length,
                pid: child,
            }),
    );
    if instance.attachments.try_reserve(clones.len()).is_err() {
        return Err(Error::NoMemory);
    }
    // Each copy goes in front as it is met, as the parent's were made.
    for clone in clones {
        let Some(segment) = find_segment(instance, clone.segment) else {
            let _ = detach_matching(instance, child, None);
            return Err(Error::Invalid);
        };
        let Some(attachments) = segment.attachments.checked_add(1) else {
            let _ = detach_matching(instance, child, None);
            return Err(Error::NoMemory);
        };
        segment.attachments = attachments;
        segment.last_pid = child;
        instance.attachments.push_front(clone);
    }
    Ok(())
}

pub(crate) fn drop_process_attachments(pid: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    undo_process_semaphores(&mut guard, pid);
    detach_matching(&mut guard, pid, None).map(|_| ())
}

/// Ends an exiting process's semaphore wait and applies its `SEM_UNDO`
/// adjustments, clamped to the value's range as Linux does.
fn undo_process_semaphores(instance: &mut Instance, pid: u32) {
    let Instance {
        processes,
        semaphore_sets,
        ..
    } = instance;
    processes.waits.retain(|wait| wait.pid != pid);
    processes.message_waits.retain(|(waiter, _)| *waiter != pid);
    processes.undo.retain(|undo| {
        if undo.pid != pid {
            return true;
        }
        let value = semaphore_sets
            .iter_mut()
            .find(|set| set.id == undo.id)
            .and_then(|set| set.values.get_mut(usize::from(undo.number)));
        if let Some(value) = value {
            value.value = (i32::from(value.value) + undo.adjustment)
                .clamp(0, i32::from(SEM_VALUE_MAX)) as u16;
            value.last_pid = pid;
        }
        false
    });
}

/// The wait `pid` recorded in an earlier, restarted `semop`.
pub(crate) fn semaphore_wait(pid: u32) -> Option<SemaphoreWait> {
    let guard = Guard::acquire()?;
    guard
        .processes
        .waits
        .iter()
        .find(|wait| wait.pid == pid)
        .copied()
}

/// Records that a process waits in `semop`, replacing its earlier record.
pub(crate) fn begin_semaphore_wait(wait: SemaphoreWait) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let waits = &mut guard.processes.waits;
    if let Some(existing) = waits.iter_mut().find(|existing| existing.pid == wait.pid) {
        *existing = wait;
        return Ok(());
    }
    waits.try_reserve(1).map_err(|_| Error::NoMemory)?;
    waits.push(wait);
    Ok(())
}

/// The queue `pid` waited on in an earlier, restarted msgsnd or msgrcv.
pub(crate) fn message_wait(pid: u32) -> Option<u32> {
    let guard = Guard::acquire()?;
    guard
        .processes
        .message_waits
        .iter()
        .find(|(waiter, _)| *waiter == pid)
        .map(|(_, id)| *id)
}

/// Records that `pid` waits on queue `id` in msgsnd or msgrcv.
pub(crate) fn begin_message_wait(pid: u32, id: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let waits = &mut guard.processes.message_waits;
    if let Some(existing) = waits.iter_mut().find(|(waiter, _)| *waiter == pid) {
        existing.1 = id;
        return Ok(());
    }
    waits.try_reserve(1).map_err(|_| Error::NoMemory)?;
    waits.push((pid, id));
    Ok(())
}

pub(crate) fn end_message_wait(pid: u32) {
    if let Some(mut guard) = Guard::acquire() {
        guard
            .processes
            .message_waits
            .retain(|(waiter, _)| *waiter != pid);
    }
}

pub(crate) fn end_semaphore_wait(pid: u32) {
    if let Some(mut guard) = Guard::acquire() {
        guard.processes.waits.retain(|wait| wait.pid != pid);
    }
}

pub(crate) fn teardown() -> bool {
    Guard::acquire().is_some_and(|mut guard| teardown_held(&mut guard))
}

/// Releases every object of IPC namespace instance `instance`, which no
/// process uses any more: not while a process still has one of its
/// segments attached (it may have left the namespace with it).
pub(crate) fn release_instance(instance: usize) -> bool {
    let Some(mut guard) = Guard::acquire_at(instance) else {
        return false;
    };
    if !guard.attachments.is_empty() {
        return false;
    }
    let released = teardown_held(&mut guard);
    guard.next_id = 1;
    guard.next_semaphore_id = 1;
    guard.next_message_id = 1;
    released
}

/// Frees every object of `instance`; its id counters stay.
fn teardown_held(instance: &mut Instance) -> bool {
    instance.processes = SemaphoreProcesses::EMPTY;
    instance.attachments = VecDeque::new();
    instance.semaphore_sets = VecDeque::new();
    instance.queues = VecDeque::new();
    core::mem::take(&mut instance.segments)
        .into_iter()
        .all(Segment::release)
}

pub(crate) fn mark_for_removal(id: u32, pid: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let instance = &mut *guard;
    let segment = find_segment(instance, id).ok_or(Error::Invalid)?;
    segment.marked_for_removal = true;
    segment.last_pid = pid;
    if segment.attachments == 0 && !unlink_and_release(instance, id) {
        return Err(Error::Invalid);
    }
    Ok(())
}

pub(crate) fn set_mode(id: u32, mode: u16, pid: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let segment = find_segment(&mut guard, id).ok_or(Error::Invalid)?;
    segment.mode = mode & 0o777;
    segment.last_pid = pid;
    Ok(())
}

fn find_semaphore_set(instance: &mut Instance, id: u32) -> Option<&mut SemaphoreSet> {
    instance.semaphore_sets.iter_mut().find(|set| set.id == id)
}

fn semaphore_set_info_of(set: &SemaphoreSet) -> SemaphoreSetInfo {
    SemaphoreSetInfo {
        key: set.key,
        count: set.count(),
        mode: set.mode,
    }
}

/// SEMMNI (the last value of /proc/sys/kernel/sem): semaphore sets per
/// domain.
pub(crate) const SEMAPHORE_SET_LIMIT: usize = 1024;

pub(crate) fn semaphore_get_or_create(
    key: i32,
    count: u64,
    mode: u16,
    create: bool,
    exclusive: bool,
    pid: u32,
) -> Result<u32, Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let instance = &mut *guard;
    if key != 0 {
        if let Some(set) = instance.semaphore_sets.iter().find(|set| set.key == key) {
            if create && exclusive {
                return Err(Error::Exists);
            }
            if count > set.count() {
                return Err(Error::Invalid);
            }
            return Ok(set.id);
        }
        if !create {
            return Err(Error::NoEntry);
        }
    }
    let count = usize::try_from(count).map_err(|_| Error::Invalid)?;
    if count == 0 {
        return Err(Error::Invalid);
    }
    // SEMMNI (/proc/sys/kernel/sem): no more sets than that (semget05).
    if instance.semaphore_sets.len() >= SEMAPHORE_SET_LIMIT {
        return Err(Error::NoSpace);
    }
    let mut values = Vec::new();
    if values.try_reserve_exact(count).is_err() || instance.semaphore_sets.try_reserve(1).is_err() {
        return Err(Error::NoMemory);
    }
    values.resize(count, Semaphore::default());
    let id = instance.next_semaphore_id;
    instance.next_semaphore_id = id.wrapping_add(1);
    if id == 0 || id > i32::MAX as u32 {
        return Err(Error::NoMemory);
    }
    instance.semaphore_sets.push_front(SemaphoreSet {
        id,
        key,
        mode: mode & 0o777,
        last_pid: pid,
        owner: Ownership::default(),
        times: [0; 3],
        values,
    });
    Ok(id)
}

pub(crate) fn semaphore_set(id: u32) -> Result<SemaphoreSetInfo, Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    find_semaphore_set(&mut guard, id)
        .map(|set| semaphore_set_info_of(set))
        .ok_or(Error::Invalid)
}

pub(crate) fn semaphore_get(id: u32, number: usize) -> Result<(u16, u32, u32, u32), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let set = find_semaphore_set(&mut guard, id).ok_or(Error::Invalid)?;
    let value = *set.values.get(number).ok_or(Error::Range)?;
    let (waiting_increase, waiting_zero) = guard
        .processes
        .waits
        .iter()
        .filter(|wait| wait.id == id && usize::from(wait.block.number) == number)
        .fold((0, 0), |(increase, zero), wait| {
            if wait.block.zero {
                (increase, zero + 1)
            } else {
                (increase + 1, zero)
            }
        });
    Ok((value.value, value.last_pid, waiting_increase, waiting_zero))
}

pub(crate) fn semaphore_set_value(
    id: u32,
    number: usize,
    value: u16,
    pid: u32,
) -> Result<(), Error> {
    if value > SEM_VALUE_MAX {
        return Err(Error::Range);
    }
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let instance = &mut *guard;
    let set = find_semaphore_set(instance, id).ok_or(Error::Invalid)?;
    if number >= set.values.len() {
        return Err(Error::Range);
    }
    set.values[number] = Semaphore {
        value,
        last_pid: pid,
    };
    set.last_pid = pid;
    instance
        .processes
        .undo
        .retain(|undo| undo.id != id || usize::from(undo.number) != number);
    Ok(())
}

pub(crate) fn semaphore_apply<F>(
    id: u32,
    operation_count: usize,
    pid: u32,
    mut operation: F,
) -> Result<Option<SemaphoreBlock>, Error>
where
    F: FnMut(usize) -> Option<SemaphoreOperation>,
{
    const IPC_NOWAIT: u16 = 0o4000;
    const SEM_UNDO: u16 = 0x1000;
    if operation_count == 0 {
        return Err(Error::Invalid);
    }
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let Instance {
        semaphore_sets,
        processes,
        ..
    } = &mut *guard;
    let set = semaphore_sets
        .iter_mut()
        .find(|set| set.id == id)
        .ok_or(Error::Invalid)?;
    let set_count = set.values.len();
    for index in 0..operation_count {
        let current = operation(index).ok_or(Error::Invalid)?;
        if current.flags & !(IPC_NOWAIT | SEM_UNDO) != 0 || usize::from(current.number) >= set_count
        {
            return Err(Error::Invalid);
        }
        let mut simulated = i32::from(set.values[usize::from(current.number)].value);
        for prior_index in 0..index {
            let prior = operation(prior_index).ok_or(Error::Invalid)?;
            if prior.number == current.number {
                simulated = simulated
                    .checked_add(i32::from(prior.operation))
                    .ok_or(Error::Range)?;
            }
        }
        let blocks = match current.operation.cmp(&0) {
            core::cmp::Ordering::Greater => {
                if simulated
                    .checked_add(i32::from(current.operation))
                    .is_none_or(|value| value > i32::from(SEM_VALUE_MAX))
                {
                    return Err(Error::Range);
                }
                false
            }
            core::cmp::Ordering::Less => simulated < -i32::from(current.operation),
            core::cmp::Ordering::Equal => simulated != 0,
        };
        if !blocks {
            continue;
        }
        if current.flags & IPC_NOWAIT != 0 {
            return Err(Error::WouldBlock);
        }
        return Ok(Some(SemaphoreBlock {
            number: current.number,
            zero: current.operation == 0,
        }));
    }
    // SEM_UNDO keeps the opposite of each change, to apply at exit; an
    // adjustment out of the value's range fails the call (ERANGE).
    let undo = &mut processes.undo;
    let mut new_entries = 0;
    for index in 0..operation_count {
        let current = operation(index).ok_or(Error::Invalid)?;
        if current.flags & SEM_UNDO == 0 || current.operation == 0 {
            continue;
        }
        let existing = undo
            .iter()
            .find(|entry| entry.pid == pid && entry.id == id && entry.number == current.number)
            .map(|entry| entry.adjustment);
        let earlier: i32 = (0..index)
            .filter_map(&mut operation)
            .filter(|prior| prior.flags & SEM_UNDO != 0 && prior.number == current.number)
            .map(|prior| -i32::from(prior.operation))
            .sum();
        let adjustment = existing.unwrap_or(0) + earlier - i32::from(current.operation);
        if adjustment.abs() > i32::from(SEM_VALUE_MAX) {
            return Err(Error::Range);
        }
        new_entries += usize::from(existing.is_none());
    }
    undo.try_reserve(new_entries).map_err(|_| Error::NoMemory)?;
    for index in 0..operation_count {
        let current = operation(index).ok_or(Error::Invalid)?;
        if current.flags & SEM_UNDO == 0 || current.operation == 0 {
            continue;
        }
        match undo
            .iter_mut()
            .find(|entry| entry.pid == pid && entry.id == id && entry.number == current.number)
        {
            Some(entry) => entry.adjustment -= i32::from(current.operation),
            None => undo.push(SemaphoreUndo {
                pid,
                id,
                number: current.number,
                adjustment: -i32::from(current.operation),
            }),
        }
    }
    undo.retain(|entry| entry.adjustment != 0);
    for index in 0..operation_count {
        let current = operation(index).ok_or(Error::Invalid)?;
        let semaphore = set
            .values
            .get_mut(usize::from(current.number))
            .ok_or(Error::Invalid)?;
        if current.operation != 0 {
            semaphore.value =
                u16::try_from(i32::from(semaphore.value) + i32::from(current.operation))
                    .map_err(|_| Error::Range)?;
        }
        semaphore.last_pid = pid;
    }
    set.last_pid = pid;
    Ok(None)
}

pub(crate) fn semaphore_set_all<F>(id: u32, pid: u32, mut value: F) -> Result<(), Error>
where
    F: FnMut(usize) -> Option<u16>,
{
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let instance = &mut *guard;
    let count = find_semaphore_set(instance, id)
        .ok_or(Error::Invalid)?
        .values
        .len();
    // Setting values clears every process's adjustments to them.
    instance.processes.undo.retain(|undo| undo.id != id);
    for index in 0..count {
        if value(index)
            .filter(|value| *value <= SEM_VALUE_MAX)
            .is_none()
        {
            return Err(Error::Range);
        }
    }
    let set = find_semaphore_set(instance, id).ok_or(Error::Invalid)?;
    for (index, semaphore) in set.values.iter_mut().enumerate() {
        semaphore.value = value(index).ok_or(Error::Invalid)?;
        semaphore.last_pid = pid;
    }
    set.last_pid = pid;
    Ok(())
}

pub(crate) fn semaphore_set_mode(id: u32, mode: u16, pid: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let set = find_semaphore_set(&mut guard, id).ok_or(Error::Invalid)?;
    set.mode = mode & 0o777;
    set.last_pid = pid;
    Ok(())
}

pub(crate) fn semaphore_remove(id: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let index = guard
        .semaphore_sets
        .iter()
        .position(|set| set.id == id)
        .ok_or(Error::Invalid)?;
    guard.processes.undo.retain(|undo| undo.id != id);
    guard.semaphore_sets.remove(index);
    Ok(())
}

fn message_queue_index(instance: &Instance, id: u32) -> Option<usize> {
    instance.queues.iter().position(|queue| queue.id == id)
}

fn find_message_queue(instance: &mut Instance, id: u32) -> Option<&mut MessageQueue> {
    instance.queues.iter_mut().find(|queue| queue.id == id)
}

/// msgget: the queue `key` names, or a new one; no more queues in all
/// than `limit` (/proc/sys/kernel/msgmni, ENOSPC: msgget03).
pub(crate) fn message_get_or_create(
    key: i32,
    mode: u16,
    create: bool,
    exclusive: bool,
    requested: Option<u32>,
    limit: usize,
) -> Result<u32, Error> {
    const DEFAULT_BYTE_LIMIT: u64 = 16_384;
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let instance = &mut *guard;
    if key != 0 {
        if let Some(queue) = instance.queues.iter().find(|queue| queue.key == key) {
            if create && exclusive {
                return Err(Error::Exists);
            }
            return Ok(queue.id);
        }
        if !create {
            return Err(Error::NoEntry);
        }
    }
    if instance.queues.len() >= limit {
        return Err(Error::NoSpace);
    }
    instance
        .queues
        .try_reserve(1)
        .map_err(|_| Error::NoMemory)?;
    // A requested id (/proc/sys/kernel/msg_next_id) that is free is used, and
    // the counter moves past it; otherwise the next free id.
    let id = match requested.filter(|id| {
        *id != 0 && *id <= i32::MAX as u32 && message_queue_index(instance, *id).is_none()
    }) {
        Some(id) => {
            if instance.next_message_id <= id {
                instance.next_message_id = id + 1;
            }
            id
        }
        None => {
            let id = instance.next_message_id;
            instance.next_message_id = id.wrapping_add(1);
            id
        }
    };
    if id == 0 || id > i32::MAX as u32 {
        return Err(Error::NoMemory);
    }
    instance
        .queues
        .push_front(MessageQueue::new(id, key, mode, DEFAULT_BYTE_LIMIT));
    Ok(id)
}

fn posix_info(queue: &MessageQueue, created: bool) -> PosixQueueInfo {
    PosixQueueInfo {
        id: queue.id,
        max_messages: u64::from(queue.max_messages),
        max_message_size: u64::from(queue.max_message_size),
        messages: queue.message_count(),
        created,
    }
}

/// mq_open: queue `name`, created if `create` allows (EEXIST if
/// `exclusive`), owned by `caller` then; an existing queue's mode must
/// grant `caller` the `requested` access (EACCES). A new queue past
/// `queues_limit` POSIX queues in the domain is ENOSPC.
#[allow(clippy::too_many_arguments)]
pub(crate) fn posix_queue_open(
    name: &[u8],
    create: bool,
    exclusive: bool,
    mode: u16,
    (max_messages, max_message_size): (u32, u32),
    caller: Caller,
    requested: u16,
    queues_limit: Option<usize>,
) -> Result<PosixQueueInfo, Error> {
    if name.is_empty() || name.len() > 255 || max_messages == 0 || max_message_size == 0 {
        return Err(Error::Invalid);
    }
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let instance = &mut *guard;
    if let Some(queue) = instance.queues.iter_mut().find(|queue| queue.named(name)) {
        if create && exclusive {
            return Err(Error::Exists);
        }
        let wanted = (requested >> 6 | requested >> 3 | requested) & 7;
        let granted = if caller.uid == queue.owner.uid {
            queue.mode >> 6
        } else if caller.gid == queue.owner.gid {
            queue.mode >> 3
        } else {
            queue.mode
        } & 7;
        if !caller.privileged && wanted & !granted != 0 {
            return Err(Error::Access);
        }
        queue.open_references = queue
            .open_references
            .checked_add(1)
            .ok_or(Error::NoMemory)?;
        return Ok(posix_info(queue, false));
    }
    if !create {
        return Err(Error::NoEntry);
    }
    if queues_limit
        .is_some_and(|limit| instance.queues.iter().filter(|queue| queue.posix).count() >= limit)
    {
        return Err(Error::NoSpace);
    }
    let mut stored_name = Vec::new();
    if instance.queues.try_reserve(1).is_err() || stored_name.try_reserve_exact(name.len()).is_err()
    {
        return Err(Error::NoMemory);
    }
    stored_name.extend_from_slice(name);
    let id = instance.next_message_id;
    instance.next_message_id = id.wrapping_add(1);
    if id == 0 || id > i32::MAX as u32 {
        return Err(Error::NoMemory);
    }
    let queue = MessageQueue {
        posix: true,
        linked: true,
        max_messages,
        max_message_size,
        open_references: 1,
        owner: Ownership {
            uid: caller.uid,
            gid: caller.gid,
            cuid: caller.uid,
            cgid: caller.gid,
            adopted: true,
        },
        name: stored_name,
        ..MessageQueue::new(
            id,
            0,
            mode,
            u64::from(max_messages) * u64::from(max_message_size),
        )
    };
    let info = posix_info(&queue, true);
    instance.queues.push_front(queue);
    Ok(info)
}

pub(crate) fn posix_queue_info(id: u32) -> Result<PosixQueueInfo, Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let queue = find_message_queue(&mut guard, id).ok_or(Error::Invalid)?;
    queue
        .posix
        .then(|| posix_info(queue, false))
        .ok_or(Error::Invalid)
}

pub(crate) fn posix_queue_duplicate(id: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let queue = find_message_queue(&mut guard, id).ok_or(Error::Invalid)?;
    if !queue.posix {
        return Err(Error::Invalid);
    }
    queue.open_references = queue
        .open_references
        .checked_add(1)
        .ok_or(Error::NoMemory)?;
    Ok(())
}

/// Closes a descriptor of queue `id`: the closing process's registration
/// goes with it, as in Linux, and is returned for the caller to release;
/// the last close of an unlinked queue frees the queue.
pub(crate) fn posix_queue_close_by(
    id: u32,
    pid: u32,
) -> Result<(Option<PosixQueueInfo>, Option<Registration>), Error> {
    let removed = {
        let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
        let queue = find_message_queue(&mut guard, id).ok_or(Error::Invalid)?;
        take_registration(queue, Some(pid))
    };
    posix_queue_close(id).map(|destroyed| (destroyed, removed))
}

pub(crate) fn posix_queue_close(id: u32) -> Result<Option<PosixQueueInfo>, Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let index = message_queue_index(&guard, id).ok_or(Error::Invalid)?;
    let queue = &mut guard.queues[index];
    if !queue.posix || queue.open_references == 0 {
        return Err(Error::Invalid);
    }
    queue.open_references -= 1;
    if queue.open_references == 0 && !queue.linked {
        let info = posix_info(queue, false);
        guard.queues.remove(index);
        Ok(Some(info))
    } else {
        Ok(None)
    }
}

/// mq_notify for queue `id` by `pid`: registers `notification` (EBUSY
/// while another process holds the registration), or with None removes
/// `pid`'s own registration and returns it, for the caller to release.
pub(crate) fn posix_queue_set_notification(
    id: u32,
    pid: u32,
    notification: Option<Notification>,
) -> Result<Option<Registration>, Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let queue = find_message_queue(&mut guard, id).ok_or(Error::Invalid)?;
    if !queue.posix {
        return Err(Error::Invalid);
    }
    let Some(notification) = notification else {
        return Ok(take_registration(queue, Some(pid)));
    };
    if queue.registration.is_some() {
        return Err(Error::Busy);
    }
    queue.registration = Some(Registration { pid, notification });
    Ok(None)
}

/// Removes `queue`'s registration (only `pid`'s, if given) and returns it.
fn take_registration(queue: &mut MessageQueue, pid: Option<u32>) -> Option<Registration> {
    queue
        .registration
        .take_if(|registration| pid.is_none_or(|pid| pid == registration.pid))
}

/// After a send to queue `id`: when the message reached an empty queue
/// and no receiver waits, the registration, which this removes, as Linux
/// notifies once.
pub(crate) fn posix_queue_take_notification(
    id: u32,
    receiver_waiting: bool,
) -> Option<Registration> {
    let mut guard = Guard::acquire()?;
    let queue = find_message_queue(&mut guard, id)?;
    if !queue.posix || queue.message_count() != 1 || receiver_waiting {
        return None;
    }
    take_registration(queue, None)
}

/// Whether some process waits to receive from queue `id` (its wait is
/// recorded as `id | RECEIVE_WAIT`).
pub(crate) fn posix_queue_receiver_waiting(id: u32) -> bool {
    let Some(guard) = Guard::acquire() else {
        return false;
    };
    guard
        .processes
        .message_waits
        .iter()
        .any(|(_, waited)| *waited == id | RECEIVE_WAIT)
}

/// Marks a recorded message wait as a receiver's (`begin_message_wait`).
pub(crate) const RECEIVE_WAIT: u32 = 1 << 31;

/// mq_unlink by `caller`: the queue's owner, or a privileged caller
/// (EACCES otherwise).
pub(crate) fn posix_queue_unlink_by(
    name: &[u8],
    caller: Caller,
) -> Result<Option<PosixQueueInfo>, Error> {
    {
        let guard = Guard::acquire().ok_or(Error::Invalid)?;
        if let Some(queue) = guard.queues.iter().find(|queue| queue.named(name)) {
            if !caller.privileged && caller.uid != queue.owner.uid {
                return Err(Error::Access);
            }
        }
    }
    posix_queue_unlink(name)
}

pub(crate) fn posix_queue_unlink(name: &[u8]) -> Result<Option<PosixQueueInfo>, Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let index = guard
        .queues
        .iter()
        .position(|queue| queue.named(name))
        .ok_or(Error::NoEntry)?;
    let queue = &mut guard.queues[index];
    queue.linked = false;
    queue.name = Vec::new();
    if queue.open_references == 0 {
        let info = posix_info(queue, false);
        guard.queues.remove(index);
        Ok(Some(info))
    } else {
        Ok(None)
    }
}

fn message_queue_info_of(queue: &MessageQueue) -> MessageQueueInfo {
    MessageQueueInfo {
        key: queue.key,
        mode: queue.mode,
        bytes: queue.bytes,
        messages: queue.message_count(),
        byte_limit: queue.byte_limit,
        last_sender: queue.last_sender,
        last_receiver: queue.last_receiver,
    }
}

pub(crate) fn message_queue_info(id: u32) -> Result<MessageQueueInfo, Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    find_message_queue(&mut guard, id)
        .map(|queue| message_queue_info_of(queue))
        .ok_or(Error::Invalid)
}

pub(crate) fn message_send<F>(
    id: u32,
    message_type: i64,
    size: usize,
    pid: u32,
    mut read: F,
) -> Result<(), Error>
where
    F: FnMut(usize, &mut [u8]) -> bool,
{
    if message_type <= 0 {
        return Err(Error::Invalid);
    }
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let queue = find_message_queue(&mut guard, id).ok_or(Error::Invalid)?;
    if queue
        .bytes
        .checked_add(size as u64)
        .is_none_or(|bytes| bytes > queue.byte_limit)
    {
        return Err(Error::WouldBlock);
    }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(size).is_err() || queue.messages.try_reserve(1).is_err() {
        return Err(Error::NoMemory);
    }
    bytes.resize(size, 0);
    if !read(0, &mut bytes) {
        return Err(Error::Fault);
    }
    queue.messages.push_back(Message {
        message_type,
        bytes,
    });
    queue.bytes += size as u64;
    queue.last_sender = pid;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn message_receive<F>(
    id: u32,
    size: usize,
    selector: i64,
    no_error: bool,
    except: bool,
    copy: bool,
    pid: u32,
    mut write: F,
) -> Result<usize, Error>
where
    F: FnMut(i64, usize, &[u8]) -> bool,
{
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let queue = find_message_queue(&mut guard, id).ok_or(Error::Invalid)?;
    let mut selected: Option<usize> = None;
    for (ordinal, message) in queue.messages.iter().enumerate() {
        let matches = if copy {
            i64::try_from(ordinal).is_ok_and(|ordinal| ordinal == selector)
        } else if selector == 0 {
            true
        } else if selector > 0 && except {
            message.message_type != selector
        } else if selector > 0 {
            message.message_type == selector
        } else {
            message.message_type <= selector.checked_abs().ok_or(Error::Invalid)?
        };
        if matches
            && selected.is_none_or(|prior| {
                selector < 0 && message.message_type < queue.messages[prior].message_type
            })
        {
            selected = Some(ordinal);
            if selector >= 0 {
                break;
            }
        }
    }
    let selected = selected.ok_or(Error::WouldBlock)?;
    let message = &queue.messages[selected];
    let message_size = message.bytes.len();
    if message_size > size && !no_error {
        return Err(Error::TooBig);
    }
    let copied = message_size.min(size);
    if !write(message.message_type, 0, &message.bytes[..copied]) {
        return Err(Error::Fault);
    }
    if copy {
        return Ok(copied);
    }
    queue.messages.remove(selected);
    queue.bytes = queue
        .bytes
        .checked_sub(message_size as u64)
        .ok_or(Error::Invalid)?;
    queue.last_receiver = pid;
    Ok(copied)
}

pub(crate) fn message_queue_set(id: u32, mode: u16, byte_limit: u64) -> Result<(), Error> {
    if byte_limit == 0 {
        return Err(Error::Invalid);
    }
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let queue = find_message_queue(&mut guard, id).ok_or(Error::Invalid)?;
    if byte_limit < queue.bytes {
        return Err(Error::Invalid);
    }
    queue.mode = mode & 0o777;
    queue.byte_limit = byte_limit;
    Ok(())
}

pub(crate) fn message_queue_remove(id: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let index = message_queue_index(&guard, id).ok_or(Error::Invalid)?;
    guard.queues.remove(index);
    Ok(())
}

pub(crate) fn verify_message_queue_lifecycle() -> bool {
    let Some(before) = heap::kernel_frames_outside_heap() else {
        return false;
    };
    let Ok(id) = message_get_or_create(0x4d53_4751, 0o620, true, true, None, usize::MAX) else {
        return false;
    };
    let large_size = PAGE_SIZE + 37;
    let large_sent = message_send(id, 3, large_size, 1, |offset, bytes| {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = ((offset + index) % 251) as u8;
        }
        true
    });
    let small = b"second";
    let small_sent = message_send(id, 1, small.len(), 1, |offset, bytes| {
        let Some(source) = small.get(offset..offset + bytes.len()) else {
            return false;
        };
        bytes.copy_from_slice(source);
        true
    });
    let initial_info = message_queue_info(id)
        .is_ok_and(|queue| queue.messages == 2 && queue.bytes == (large_size + small.len()) as u64);
    let selected_small = message_receive(
        id,
        small.len(),
        -2,
        false,
        false,
        false,
        2,
        |message_type, offset, bytes| {
            message_type == 1 && small.get(offset..offset + bytes.len()) == Some(bytes)
        },
    );
    let mut copied = 0;
    let after_small = message_queue_info(id).is_ok_and(|queue| queue.messages == 1);
    let copied_large = message_receive(
        id,
        large_size,
        0,
        false,
        false,
        true,
        2,
        |message_type, offset, bytes| {
            let valid = message_type == 3
                && bytes
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| *byte == ((offset + index) % 251) as u8);
            copied += bytes.len();
            valid
        },
    );
    let after_copy = message_queue_info(id).is_ok_and(|queue| queue.messages == 1);
    let too_big = message_receive(id, 8, 3, false, false, false, 2, |_, _, _| true);
    let after_too_big = message_queue_info(id).is_ok_and(|queue| queue.messages == 1);
    let mut truncated = [0_u8; 8];
    let truncated_large = message_receive(
        id,
        truncated.len(),
        3,
        true,
        false,
        false,
        2,
        |message_type, offset, bytes| {
            if message_type != 3 || offset + bytes.len() > truncated.len() {
                return false;
            }
            truncated[offset..offset + bytes.len()].copy_from_slice(bytes);
            true
        },
    );
    let after_truncated = message_queue_info(id).is_ok_and(|queue| queue.messages == 0);
    let verified = large_sent.is_ok()
        && small_sent.is_ok()
        && initial_info
        && selected_small == Ok(small.len())
        && after_small
        && copied_large == Ok(large_size)
        && copied == large_size
        && after_copy
        && too_big == Err(Error::TooBig)
        && after_too_big
        && truncated_large == Ok(truncated.len())
        && after_truncated
        && truncated
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte == (index % 251) as u8)
        && message_queue_set(id, 0o600, 32_768).is_ok()
        && message_queue_info(id).is_ok_and(|queue| {
            queue.mode == 0o600 && queue.byte_limit == 32_768 && queue.messages == 0
        })
        && message_queue_remove(id).is_ok()
        && matches!(message_queue_info(id), Err(Error::Invalid));
    verified && heap::kernel_frames_outside_heap() == Some(before)
}

pub(crate) fn verify_semaphore_lifecycle() -> bool {
    const SEMAPHORE_SET_SIZE: usize = 240;
    let Some(before) = heap::kernel_frames_outside_heap() else {
        return false;
    };
    let Ok(id) = semaphore_get_or_create(
        0x5345_4d41,
        (SEMAPHORE_SET_SIZE + 7) as u64,
        0o640,
        true,
        true,
        1,
    ) else {
        return false;
    };
    let operations = [
        SemaphoreOperation {
            number: 0,
            operation: -2,
            flags: 0,
        },
        SemaphoreOperation {
            number: 1,
            operation: 3,
            flags: 0,
        },
    ];
    let blocked = [
        SemaphoreOperation {
            number: 0,
            operation: -1,
            flags: 0,
        },
        SemaphoreOperation {
            number: 1,
            operation: 4,
            flags: 0,
        },
    ];
    let verified = semaphore_set_value(id, 0, 2, 1).is_ok()
        && semaphore_apply(id, operations.len(), 1, |index| {
            operations.get(index).copied()
        }) == Ok(None)
        && semaphore_get(id, 0).is_ok_and(|value| value.0 == 0 && value.1 == 1)
        && semaphore_get(id, 1).is_ok_and(|value| value.0 == 3 && value.1 == 1)
        && semaphore_apply(id, blocked.len(), 2, |index| blocked.get(index).copied())
            == Ok(Some(SemaphoreBlock {
                number: 0,
                zero: false,
            }))
        && semaphore_get(id, 1).is_ok_and(|value| value.0 == 3)
        && semaphore_set_all(id, 3, |index| Some((index % 101) as u16)).is_ok()
        && semaphore_get(id, SEMAPHORE_SET_SIZE + 6)
            .is_ok_and(|value| value.0 == ((SEMAPHORE_SET_SIZE + 6) % 101) as u16)
        && semaphore_set_mode(id, 0o600, 3).is_ok()
        && semaphore_set(id)
            .is_ok_and(|set| set.count == (SEMAPHORE_SET_SIZE + 7) as u64 && set.mode == 0o600)
        && semaphore_remove(id).is_ok()
        && matches!(semaphore_set(id), Err(Error::Invalid));
    verified && heap::kernel_frames_outside_heap() == Some(before)
}

pub(crate) fn verify_shared_memory_lifecycle() -> bool {
    let Some(before) = heap::kernel_frames_outside_heap() else {
        return false;
    };
    let Ok(id) = get_or_create(
        0x4749_4e55,
        2 * PAGE_SIZE as u64,
        0o600,
        true,
        true,
        1,
        SegmentIds {
            requested: None,
            limit: 4096,
            largest: u64::MAX,
            huge: false,
        },
    ) else {
        return false;
    };
    let verified = (|| {
        let first = frame(id, 0).ok()?;
        let second = frame(id, 1).ok()?;
        let first_page = Frame::leased(first)?;
        let second_page = Frame::leased(second)?;
        first_page.write_u8(0, 0x47);
        second_page.write_u8(0, 0x58);
        attach(id, 0x4000_0000, 1).ok()?;
        inherit_process_attachments(1, 2).ok()?;
        let state = segment(id).ok()?;
        if state.size != 2 * PAGE_SIZE as u64
            || state.mode != 0o600
            || state.attachments != 2
            || attachment_at(0x4000_0000, 1).ok()? != (id, 2 * PAGE_SIZE as u64)
            || attachment_at(0x4000_0000, 2).ok()? != (id, 2 * PAGE_SIZE as u64)
            || first_page.read_u8(0) != 0x47
            || second_page.read_u8(0) != 0x58
        {
            return None;
        }
        mark_for_removal(id, 1).ok()?;
        if segment(id).ok()?.attachments != 2 {
            return None;
        }
        detach(0x4000_0000, 1).ok()?;
        if segment(id).ok()?.attachments != 1 {
            return None;
        }
        drop_process_attachments(2).ok()?;
        matches!(segment(id), Err(Error::Invalid)).then_some(())
    })()
    .is_some();
    verified
        && heap::kernel_frames_outside_heap() == Some(before)
        && get_or_create(
            0x4749_4e55,
            0,
            0,
            false,
            false,
            1,
            SegmentIds {
                requested: None,
                limit: 4096,
                largest: u64::MAX,
                huge: false,
            },
        ) == Err(Error::NoEntry)
}
