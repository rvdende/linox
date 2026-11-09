use super::*;

#[derive(Clone, Copy)]
pub(crate) struct LinuxFileMapping {
    pub(crate) address: usize,
    pub(crate) offset: u64,
    pub(crate) file_size: usize,
    pub(crate) writable: bool,
    pub(crate) executable: bool,
}

impl LinuxFileMapping {
    pub(crate) const EMPTY: Self = Self {
        address: 0,
        offset: 0,
        file_size: 0,
        writable: false,
        executable: false,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct LinuxRelativeFileMapping {
    pub(crate) relative_address: usize,
    pub(crate) offset: u64,
    pub(crate) file_size: usize,
    pub(crate) writable: bool,
    pub(crate) executable: bool,
}

impl LinuxRelativeFileMapping {
    pub(crate) const EMPTY: Self = Self {
        relative_address: 0,
        offset: 0,
        file_size: 0,
        writable: false,
        executable: false,
    };
}

pub(crate) struct LinuxElfExecution<'a> {
    pub(crate) runtime: bool,
    pub(crate) entry: usize,
    pub(crate) page_table_frames: [memory::FrameLease; 6],
    pub(crate) page_table_frame_count: usize,
    pub(crate) stack: usize,
    pub(crate) stack_frame: memory::FrameLease,
    pub(crate) heap_frame: memory::FrameLease,
    pub(crate) tls_frames: [memory::FrameLease; 2],
    pub(crate) initial_fs_base: usize,
    pub(crate) tls: usize,
    pub(crate) tls_size: usize,
    pub(crate) sibling_fs_base: usize,
    pub(crate) sibling_tls: usize,
    pub(crate) sibling_stack: usize,
    pub(crate) sibling_stack_frame: memory::FrameLease,
    pub(crate) code: usize,
    pub(crate) code_size: usize,
    pub(crate) loader_code: usize,
    pub(crate) loader_code_size: usize,
    pub(crate) data: usize,
    pub(crate) data_size: usize,
    pub(crate) relro: usize,
    pub(crate) relro_size: usize,
    pub(crate) heap: usize,
    pub(crate) heap_size: usize,
    pub(crate) mmap: usize,
    pub(crate) main_mappings: [LinuxFileMapping; LINUX_MAIN_MAPPING_COUNT],
    pub(crate) dependency_base_min: [usize; LINUX_DEPENDENCY_COUNT],
    pub(crate) dependency_base_end: [usize; LINUX_DEPENDENCY_COUNT],
    pub(crate) dependency_mappings:
        [[LinuxRelativeFileMapping; LINUX_DEPENDENCY_MAPPING_COUNT]; LINUX_DEPENDENCY_COUNT],
    pub(crate) exec_expected: bool,
    pub(crate) system_init: bool,
    pub(crate) initial_image_mappings: &'a [LinuxActiveImageMapping],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct LinuxActiveImageMapping {
    pub(crate) address: usize,
    pub(crate) frame: memory::FrameLease,
    pub(crate) writable: bool,
    pub(crate) executable: bool,
    pub(crate) shared: bool,
    pub(crate) dontfork: bool,
}

impl LinuxActiveImageMapping {
    pub(crate) const EMPTY: Self = Self {
        address: 0,
        frame: memory::FrameLease::EMPTY,
        writable: false,
        executable: false,
        shared: false,
        dontfork: false,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct LinuxExecMapping {
    pub(crate) address: usize,
    pub(crate) frame: u64,
    pub(crate) writable: bool,
    pub(crate) executable: bool,
}

impl LinuxExecMapping {
    pub(crate) const EMPTY: Self = Self {
        address: 0,
        frame: 0,
        writable: false,
        executable: false,
    };
}

pub(crate) fn linux_exec_mapping_plan(
    plan: &crate::linux_elf::LoadPlan<'_>,
) -> Option<([LinuxExecMapping; LINUX_EXEC_MAPPING_LIMIT], usize)> {
    let segments = [plan.read_only, Some(plan.executable), Some(plan.writable)];
    let mapping_count = segments
        .iter()
        .flatten()
        .try_fold(0_usize, |count, segment| {
            count.checked_add(segment.page_count)
        })?;
    if !(3..=LINUX_EXEC_MAPPING_LIMIT).contains(&mapping_count) {
        return None;
    }
    let mut mappings = [LinuxExecMapping::EMPTY; LINUX_EXEC_MAPPING_LIMIT];
    let mut index = 0;
    for segment in segments.into_iter().flatten() {
        for page in 0..segment.page_count {
            let address = segment
                .virtual_page
                .checked_add((page * PAGE_SIZE) as u64)
                .and_then(|address| usize::try_from(address).ok())?;
            if address == 0
                || mappings[..index]
                    .iter()
                    .any(|mapping| mapping.address == address)
            {
                return None;
            }
            mappings[index] = LinuxExecMapping {
                address,
                frame: 0,
                writable: segment.writable,
                executable: segment.executable,
            };
            index += 1;
        }
    }
    Some((mappings, mapping_count))
}

pub(super) fn append_linux_active_image_mapping(
    address: u64,
    frame: memory::FrameLease,
    writable: bool,
    executable: bool,
) -> bool {
    if address == 0
        || !address.is_multiple_of(PAGE_SIZE as u64)
        || writable && executable
        || !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[frame])
    {
        return false;
    }
    let count = usize::from(
        X86_RUNTIME
            .ELF_PROBE_ACTIVE_IMAGE_COUNT
            .load(Ordering::SeqCst),
    );
    if count >= LINUX_ACTIVE_IMAGE_MAPPING_LIMIT
        || X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[..count]
            .iter()
            .any(|candidate| candidate.load(Ordering::SeqCst) == address)
        || X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[..count]
            .iter()
            .any(|candidate| candidate.load(Ordering::SeqCst) == frame.address())
        || X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[count].load(Ordering::SeqCst) != 0
        || X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[count].load(Ordering::SeqCst) != 0
        || X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[count].load(Ordering::SeqCst) != 0
        || X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[count].load(Ordering::SeqCst) != 0
    {
        return false;
    }
    X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[count].store(address, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[count].store(frame.address(), Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[count]
        .store(frame.generation(), Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[count].store(
        u8::from(writable) | (u8::from(executable) << 1),
        Ordering::SeqCst,
    );
    X86_RUNTIME
        .ELF_PROBE_ACTIVE_IMAGE_COUNT
        .store((count + 1) as u16, Ordering::SeqCst);
    true
}

pub(super) fn linux_active_image_mappings() -> Option<(
    [LinuxActiveImageMapping; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT],
    usize,
)> {
    let count = usize::from(
        X86_RUNTIME
            .ELF_PROBE_ACTIVE_IMAGE_COUNT
            .load(Ordering::SeqCst),
    );
    if !(1..=LINUX_ACTIVE_IMAGE_MAPPING_LIMIT).contains(&count) {
        return None;
    }
    let mut mappings = [LinuxActiveImageMapping::EMPTY; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT];
    for index in 0..count {
        let address = X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[index].load(Ordering::SeqCst);
        let frame = memory::FrameLease::from_parts(
            X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index].load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index].load(Ordering::SeqCst),
        )?;
        let flags = X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].load(Ordering::SeqCst);
        let address = usize::try_from(address).ok()?;
        if address == 0
            || !address.is_multiple_of(PAGE_SIZE)
            || flags & !3 != 0
            || flags == 3
            || !(memory::frames_owned_by(memory::FrameOwner::KERNEL, &[frame])
                || memory::frame_lease_is_runtime(frame))
            || mappings[..index]
                .iter()
                .any(|prior| prior.address == address || prior.frame == frame)
        {
            return None;
        }
        mappings[index] = LinuxActiveImageMapping {
            address,
            frame,
            writable: flags & 1 != 0,
            executable: flags & 2 != 0,
            shared: false,
            dontfork: false,
        };
    }
    if (count..LINUX_ACTIVE_IMAGE_MAPPING_LIMIT).any(|index| {
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[index].load(Ordering::SeqCst) != 0
            || X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index].load(Ordering::SeqCst) != 0
            || X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index].load(Ordering::SeqCst) != 0
            || X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].load(Ordering::SeqCst) != 0
    }) {
        return None;
    }
    Some((mappings, count))
}

pub(super) fn linux_active_image_writable_index(address: u64) -> Option<usize> {
    let count = usize::from(
        X86_RUNTIME
            .ELF_PROBE_ACTIVE_IMAGE_COUNT
            .load(Ordering::SeqCst),
    );
    if !(1..=LINUX_ACTIVE_IMAGE_MAPPING_LIMIT).contains(&count)
        || address == 0
        || !address.is_multiple_of(PAGE_SIZE as u64)
    {
        return None;
    }
    let index = X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[..count]
        .iter()
        .position(|candidate| candidate.load(Ordering::SeqCst) == address)?;
    let frame = memory::FrameLease::from_parts(
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index].load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index].load(Ordering::SeqCst),
    )?;
    (X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].load(Ordering::SeqCst) == 1
        && memory::frames_owned_by(memory::FrameOwner::KERNEL, &[frame]))
    .then_some(index)
}

pub(crate) struct LinuxElfResult {
    pub(crate) valid: bool,
    pub(crate) suspended: bool,
    pub(crate) exec_replaced: bool,
    pub(crate) exec_node: u8,
    pub(crate) active_image_mapping_count: usize,
    pub(crate) dependency_bases: [u64; LINUX_DEPENDENCY_COUNT],
    pub(crate) main_frames: [Option<memory::FrameLease>; LINUX_MAIN_MAPPING_COUNT],
    pub(crate) dependency_frames:
        [[Option<memory::FrameLease>; LINUX_DEPENDENCY_MAPPING_COUNT]; LINUX_DEPENDENCY_COUNT],
    pub(crate) exec_mapping_count: usize,
    pub(crate) exec_frames: [Option<memory::FrameLease>; LINUX_EXEC_MAPPING_LIMIT],
    pub(crate) retired_image_count: usize,
    pub(crate) retired_image_frames: [Option<memory::FrameLease>; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT],
}

impl LinuxElfResult {
    pub(crate) const FAILED: Self = Self {
        valid: false,
        suspended: false,
        exec_replaced: false,
        exec_node: 0,
        active_image_mapping_count: 0,
        dependency_bases: [0; LINUX_DEPENDENCY_COUNT],
        main_frames: [None; LINUX_MAIN_MAPPING_COUNT],
        dependency_frames: [[None; LINUX_DEPENDENCY_MAPPING_COUNT]; LINUX_DEPENDENCY_COUNT],
        exec_mapping_count: 0,
        exec_frames: [None; LINUX_EXEC_MAPPING_LIMIT],
        retired_image_count: 0,
        retired_image_frames: [None; LINUX_ACTIVE_IMAGE_MAPPING_LIMIT],
    };
}

#[inline(never)]
pub(super) fn finalize_linux_exec_heap_frame(
    address: usize,
    initial: memory::FrameLease,
    replaced: bool,
) -> bool {
    let current = memory::FrameLease::from_parts(
        X86_RUNTIME.ELF_PROBE_HEAP_FRAME.swap(0, Ordering::SeqCst),
        X86_RUNTIME
            .ELF_PROBE_HEAP_GENERATION
            .swap(0, Ordering::SeqCst),
    );
    current.is_some_and(|frame| {
        let valid =
            address_space::current_linux_mapping_matches(address as u64, frame, true, false)
                && if replaced {
                    frame != initial
                        && !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[initial])
                        && X86_RUNTIME
                            .ELF_PROBE_RECLAIM_HEAP_FRAME
                            .load(Ordering::SeqCst)
                            == 0
                        && X86_RUNTIME
                            .ELF_PROBE_RECLAIM_HEAP_GENERATION
                            .load(Ordering::SeqCst)
                            == 0
                } else {
                    frame == initial
                };
        if valid && replaced {
            X86_RUNTIME
                .ELF_PROBE_RECLAIM_HEAP_FRAME
                .store(frame.address(), Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_RECLAIM_HEAP_GENERATION
                .store(frame.generation(), Ordering::SeqCst);
        }
        valid
    })
}

pub(crate) fn take_linux_exec_heap_frame() -> Option<memory::FrameLease> {
    memory::FrameLease::from_parts(
        X86_RUNTIME
            .ELF_PROBE_RECLAIM_HEAP_FRAME
            .swap(0, Ordering::SeqCst),
        X86_RUNTIME
            .ELF_PROBE_RECLAIM_HEAP_GENERATION
            .swap(0, Ordering::SeqCst),
    )
}

#[inline(never)]
pub(super) fn finalize_linux_exec_tls_frames(
    addresses: [usize; 2],
    initial: [memory::FrameLease; 2],
    replaced: bool,
) -> bool {
    let mut valid = true;
    for index in 0..2 {
        let current = memory::FrameLease::from_parts(
            X86_RUNTIME.ELF_PROBE_TLS_FRAMES[index].swap(0, Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_TLS_GENERATIONS[index].swap(0, Ordering::SeqCst),
        );
        if initial[index] == memory::FrameLease::EMPTY {
            valid &= !replaced && current.is_none();
            continue;
        }
        valid &= current.is_some_and(|frame| {
            let replacement_valid = frame != initial[index]
                && !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[initial[index]])
                && X86_RUNTIME.ELF_PROBE_RECLAIM_TLS_FRAMES[index].load(Ordering::SeqCst) == 0
                && X86_RUNTIME.ELF_PROBE_RECLAIM_TLS_GENERATIONS[index].load(Ordering::SeqCst) == 0;
            let mapping_valid = address_space::current_linux_mapping_matches(
                addresses[index] as u64,
                frame,
                true,
                false,
            );
            if replaced && replacement_valid {
                X86_RUNTIME.ELF_PROBE_RECLAIM_TLS_FRAMES[index]
                    .store(frame.address(), Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_RECLAIM_TLS_GENERATIONS[index]
                    .store(frame.generation(), Ordering::SeqCst);
            }
            mapping_valid
                && if replaced {
                    replacement_valid
                } else {
                    frame == initial[index]
                }
        });
    }
    valid
}

pub(crate) fn take_linux_exec_tls_frames() -> [Option<memory::FrameLease>; 2] {
    core::array::from_fn(|index| {
        memory::FrameLease::from_parts(
            X86_RUNTIME.ELF_PROBE_RECLAIM_TLS_FRAMES[index].swap(0, Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_RECLAIM_TLS_GENERATIONS[index].swap(0, Ordering::SeqCst),
        )
    })
}

#[inline(never)]
pub(super) fn finalize_linux_exec_sibling_stack_frame(
    address: usize,
    initial: memory::FrameLease,
    replaced: bool,
) -> bool {
    let current = memory::FrameLease::from_parts(
        X86_RUNTIME
            .ELF_PROBE_SIBLING_STACK_FRAME
            .swap(0, Ordering::SeqCst),
        X86_RUNTIME
            .ELF_PROBE_SIBLING_STACK_GENERATION
            .swap(0, Ordering::SeqCst),
    );
    if initial == memory::FrameLease::EMPTY {
        return !replaced && current.is_none();
    }
    current.is_some_and(|frame| {
        let replacement_valid = frame != initial
            && !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[initial])
            && X86_RUNTIME
                .ELF_PROBE_RECLAIM_SIBLING_STACK_FRAME
                .load(Ordering::SeqCst)
                == 0
            && X86_RUNTIME
                .ELF_PROBE_RECLAIM_SIBLING_STACK_GENERATION
                .load(Ordering::SeqCst)
                == 0;
        let mapping_valid =
            address_space::current_linux_mapping_matches(address as u64, frame, true, false);
        if replaced && replacement_valid {
            X86_RUNTIME
                .ELF_PROBE_RECLAIM_SIBLING_STACK_FRAME
                .store(frame.address(), Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_RECLAIM_SIBLING_STACK_GENERATION
                .store(frame.generation(), Ordering::SeqCst);
        }
        mapping_valid
            && if replaced {
                replacement_valid
            } else {
                frame == initial
            }
    })
}

pub(crate) fn take_linux_exec_sibling_stack_frame() -> Option<memory::FrameLease> {
    memory::FrameLease::from_parts(
        X86_RUNTIME
            .ELF_PROBE_RECLAIM_SIBLING_STACK_FRAME
            .swap(0, Ordering::SeqCst),
        X86_RUNTIME
            .ELF_PROBE_RECLAIM_SIBLING_STACK_GENERATION
            .swap(0, Ordering::SeqCst),
    )
}

#[inline(never)]
pub(crate) fn finalize_linux_exec_page_table_frames(
    initial: [memory::FrameLease; 6],
    count: usize,
    replaced: bool,
) -> bool {
    if !(5..=6).contains(&count) {
        return false;
    }
    let mut valid = true;
    for (index, initial_frame) in initial.iter().enumerate() {
        let current = memory::FrameLease::from_parts(
            X86_RUNTIME.ELF_PROBE_PAGE_TABLE_FRAMES[index].swap(0, Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_PAGE_TABLE_GENERATIONS[index].swap(0, Ordering::SeqCst),
        );
        if index >= count {
            valid &= current.is_none();
            continue;
        }
        valid &= current.is_some_and(|frame| {
            let replacement_valid = frame != *initial_frame
                && memory::frames_owned_by(memory::FrameOwner::KERNEL, &[frame])
                && !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[*initial_frame])
                && X86_RUNTIME.ELF_PROBE_RECLAIM_PAGE_TABLE_FRAMES[index].load(Ordering::SeqCst)
                    == 0
                && X86_RUNTIME.ELF_PROBE_RECLAIM_PAGE_TABLE_GENERATIONS[index]
                    .load(Ordering::SeqCst)
                    == 0;
            if replaced && replacement_valid {
                X86_RUNTIME.ELF_PROBE_RECLAIM_PAGE_TABLE_FRAMES[index]
                    .store(frame.address(), Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_RECLAIM_PAGE_TABLE_GENERATIONS[index]
                    .store(frame.generation(), Ordering::SeqCst);
            }
            if replaced {
                replacement_valid
                    && (index != 0 || address_space::current_root_address() == frame.address())
            } else {
                frame == initial[index]
            }
        });
    }
    valid
}

pub(crate) fn take_linux_exec_page_table_frames() -> [Option<memory::FrameLease>; 6] {
    core::array::from_fn(|index| {
        memory::FrameLease::from_parts(
            X86_RUNTIME.ELF_PROBE_RECLAIM_PAGE_TABLE_FRAMES[index].swap(0, Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_RECLAIM_PAGE_TABLE_GENERATIONS[index].swap(0, Ordering::SeqCst),
        )
    })
}

fn linux_exec_vector(
    address: u64,
    require_nonempty: bool,
) -> Result<([u64; LINUX_EXEC_VECTOR_LIMIT], usize), u64> {
    let mut pointers = [0_u64; LINUX_EXEC_VECTOR_LIMIT];
    for index in 0..=LINUX_EXEC_VECTOR_LIMIT {
        let Some(pointer_address) = address.checked_add((index * size_of::<u64>()) as u64) else {
            return Err(LINUX_EFAULT);
        };
        let mut bytes = [0_u8; size_of::<u64>()];
        if !copy_from_linux_user(pointer_address, &mut bytes) {
            return Err(LINUX_EFAULT);
        }
        let pointer = u64::from_ne_bytes(bytes);
        if pointer == 0 {
            if require_nonempty && index == 0 {
                return Err(LINUX_E2BIG);
            }
            return Ok((pointers, index));
        }
        if index == LINUX_EXEC_VECTOR_LIMIT {
            return Err(LINUX_E2BIG);
        }
        pointers[index] = pointer;
    }
    Err(LINUX_E2BIG)
}

fn linux_exec_root_node(directory: u64, path: &[u8]) -> Result<u8, u64> {
    if !linux_mount::current_root_is_read_only() {
        return Err(LINUX_ENOENT);
    }
    let mut root_name = [0_u8; 64];
    let root_name_length = if let Some(absolute) = path.strip_prefix(b"/") {
        if !linux_normalized_relative_path(absolute) {
            return Err(LINUX_ENOENT);
        }
        let Some(destination) = root_name.get_mut(..absolute.len()) else {
            return Err(LINUX_ENAMETOOLONG);
        };
        destination.copy_from_slice(absolute);
        absolute.len()
    } else {
        if !linux_normalized_relative_path(path) {
            return Err(LINUX_ENOENT);
        }
        let directory_state = if directory as u32 == LINUX_AT_FDCWD {
            X86_RUNTIME.ELF_PROBE_CWD.load(Ordering::SeqCst)
        } else {
            let state = linux_device_descriptor(directory);
            if state == 0 {
                return Err(LINUX_EBADF);
            }
            if state & LINUX_DEVICE_DIRECTORY == 0 {
                return Err(LINUX_ENOTDIR);
            }
            state & !3
        };
        let Some(directory) = linux_measured_directory_path(directory_state) else {
            return Err(LINUX_ENOENT);
        };
        let separator = usize::from(!directory.is_empty());
        let Some(length) = directory
            .len()
            .checked_add(separator)
            .and_then(|length| length.checked_add(path.len()))
        else {
            return Err(LINUX_ENAMETOOLONG);
        };
        let Some(destination) = root_name.get_mut(..length) else {
            return Err(LINUX_ENAMETOOLONG);
        };
        destination[..directory.len()].copy_from_slice(directory);
        if separator != 0 {
            destination[directory.len()] = b'/';
        }
        destination[directory.len() + separator..].copy_from_slice(path);
        length
    };
    let root_name = match &root_name[..root_name_length] {
        b"init" => b"linux/init" as &[u8],
        name => name,
    };
    let Some((mode, _)) = initramfs::published_lookup(root_name) else {
        return Err(LINUX_ENOENT);
    };
    if mode & 0o170000 != 0o100000 || mode & 0o111 == 0 {
        return Err(LINUX_EACCES);
    }
    initramfs::published_regular_file_node(root_name).ok_or(LINUX_ENOENT)
}

pub(super) fn linux_execve(
    path_address: u64,
    arguments_address: u64,
    environment_address: u64,
) -> u64 {
    linux_execve_at(
        u64::from(LINUX_AT_FDCWD),
        path_address,
        arguments_address,
        environment_address,
        false,
    )
}

fn linux_exec_descriptor_node(descriptor: u64) -> Result<u8, u64> {
    let state = linux_device_descriptor(descriptor);
    if state == 0 {
        return Err(LINUX_EBADF);
    }
    if state & LINUX_DEVICE_DIRECTORY != 0 {
        return Err(LINUX_EACCES);
    }
    let node = ((state & LINUX_ROOT_NODE_MASK) >> LINUX_ROOT_NODE_SHIFT) as u8;
    let Some(name) = initramfs::published_file_name_by_node(node) else {
        return Err(LINUX_EACCES);
    };
    let Some((mode, _)) = initramfs::published_lookup(name) else {
        return Err(LINUX_ENOENT);
    };
    if mode & 0o111 == 0 {
        return Err(LINUX_EACCES);
    }
    Ok(node)
}

pub(super) fn linux_exec_process_name(node: u8) -> Option<[u64; 2]> {
    let name = initramfs::published_file_name_by_node(node)?;
    let basename = name.rsplit(|byte| *byte == b'/').next()?;
    if basename.is_empty() {
        return None;
    }
    let mut bytes = [0_u8; 16];
    let length = basename.len().min(bytes.len() - 1);
    bytes[..length].copy_from_slice(&basename[..length]);
    Some([
        u64::from_ne_bytes(bytes[..8].try_into().ok()?),
        u64::from_ne_bytes(bytes[8..].try_into().ok()?),
    ])
}

pub(super) fn linux_measured_interpreted_exec_plan(
) -> Option<crate::linux_elf::DependencyGraphLoadPlan<'static, 'static, 'static>> {
    let file = |name: &[u8]| {
        initramfs::published_regular_file_node(name).and_then(initramfs::published_file_by_node)
    };
    crate::linux_elf::measured_interpreted_exec_plan(
        file(b"linux/init")?,
        file(b"linux/ld-linox.so")?,
        [file(b"linux/liblinox.so")?, file(b"linux/liblinox-aux.so")?],
    )
}

fn release_linux_exec_frames(
    frames: &mut [Option<memory::FrameLease>; LINUX_EXEC_MAPPING_LIMIT],
) -> bool {
    let mut scrubbed = true;
    let mut released = true;
    for slot in frames {
        if let Some(frame) = *slot {
            let frame_scrubbed = address_space::prepare_linux_frame(frame.address(), &[]);
            scrubbed &= frame_scrubbed;
            if frame_scrubbed {
                let frame_released = memory::release_frames(memory::FrameOwner::KERNEL, [frame]);
                released &= frame_released;
                if frame_released {
                    *slot = None;
                }
            } else {
                released = false;
            }
        }
    }
    scrubbed && released
}

#[inline(never)]
fn replace_current_linux_image_with_hierarchy(
    mappings: &[LinuxExecMapping],
    old_mappings: &[LinuxActiveImageMapping],
    hierarchy_count: usize,
) -> bool {
    let old: [Option<memory::FrameLease>; 6] = core::array::from_fn(|index| {
        memory::FrameLease::from_parts(
            X86_RUNTIME.ELF_PROBE_PAGE_TABLE_FRAMES[index].load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_PAGE_TABLE_GENERATIONS[index].load(Ordering::SeqCst),
        )
    });
    match (hierarchy_count, old) {
        (5, [Some(root), Some(pdpt), Some(directory), Some(main), Some(read_only), None]) => {
            replace_current_linux_image_hierarchy(
                mappings,
                old_mappings,
                [root, pdpt, directory, main, read_only],
            )
        }
        (
            6,
            [Some(root), Some(pdpt), Some(directory), Some(read_only), Some(main), Some(interpreter)],
        ) => replace_current_linux_image_hierarchy(
            mappings,
            old_mappings,
            [root, pdpt, directory, read_only, main, interpreter],
        ),
        _ => false,
    }
}

#[inline(never)]
fn replace_current_linux_image_hierarchy<const N: usize>(
    mappings: &[LinuxExecMapping],
    old_mappings: &[LinuxActiveImageMapping],
    old: [memory::FrameLease; N],
) -> bool {
    if address_space::current_root_address() != old[0].address()
        || !memory::frames_owned_by(memory::FrameOwner::KERNEL, &old)
        || old
            .iter()
            .enumerate()
            .any(|(index, frame)| old[..index].contains(frame))
    {
        return false;
    }
    let Some(new) = memory::allocate_frames::<N>(memory::FrameOwner::KERNEL) else {
        return false;
    };
    if !new
        .iter()
        .all(|frame| address_space::prepare_linux_frame(frame.address(), &[]))
        || !address_space::replace_current_linux_image_and_hierarchy(
            mappings,
            old_mappings,
            &old,
            &new,
        )
    {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &new);
        return false;
    }
    for (index, frame) in new.into_iter().enumerate() {
        X86_RUNTIME.ELF_PROBE_PAGE_TABLE_FRAMES[index].store(frame.address(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PAGE_TABLE_GENERATIONS[index]
            .store(frame.generation(), Ordering::SeqCst);
    }
    true
}

pub(super) fn linux_execveat(
    directory: u64,
    path_address: u64,
    arguments_address: u64,
    environment_address: u64,
    flags: u64,
) -> u64 {
    if flags & !(LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW) != 0 {
        return LINUX_EINVAL;
    }
    // A relative path needs a directory to start from (ENOTDIR).
    let directory_number = u64::from(directory as u32);
    if directory_number != u64::from(LINUX_AT_FDCWD) && flags & LINUX_AT_EMPTY_PATH == 0 {
        let mut first = [0_u8; 1];
        let relative =
            copy_from_linux_user(path_address, &mut first) && first[0] != b'/' && first[0] != 0;
        let not_directory = linux_overlay_descriptor_handle(directory_number)
            .and_then(crate::linux_overlay::metadata)
            .map_or(
                linux_descriptor_open(directory_number)
                    && linux_device_descriptor(directory_number) & LINUX_DEVICE_DIRECTORY == 0,
                |metadata| metadata.kind != crate::linux_overlay::NodeKind::Directory,
            );
        if relative && not_directory {
            return LINUX_ENOTDIR;
        }
    }
    // With AT_SYMLINK_NOFOLLOW a path naming a symlink is ELOOP.
    if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
        let mut path = [0_u8; LINUX_PATH_MAX];
        let length = match copy_linux_c_string(path_address, &mut path) {
            Ok(length) => length,
            Err(error) => return error,
        };
        let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        if length != 0 {
            if let Ok(canonical_length) =
                linux_canonical_path_at(directory, &path[..length], &mut canonical)
            {
                if crate::linux_overlay::lookup(&canonical[..canonical_length]).is_some_and(
                    |metadata| metadata.kind == crate::linux_overlay::NodeKind::Symlink,
                ) {
                    return LINUX_ELOOP;
                }
            }
        }
    }
    linux_execve_at(
        directory,
        path_address,
        arguments_address,
        environment_address,
        flags & LINUX_AT_EMPTY_PATH != 0,
    )
}

pub(super) fn linux_rootfs_execve_domain(path: &[u8], slot: usize) -> u64 {
    linux_rootfs_execve_source(path, 0, 0, Some(slot), None)
}

/// Runs the program at `path`, or, when `file` is given, the program in
/// that file, which `path` named before its name went (execveat of a
/// descriptor of an unlinked file).
fn linux_rootfs_execve_source(
    path: &[u8],
    arguments_address: u64,
    environment_address: u64,
    domain_exec_slot: Option<usize>,
    file: Option<crate::linux_overlay::Handle>,
) -> u64 {
    let unlinked = file.and_then(crate::linux_overlay::metadata);
    if cfg!(feature = "linux-boot-profile")
        && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Relaxed)
    {
        serial_write("linox: profile exec elapsed-ms/path: ");
        serial_write_u64(linux_elapsed_nanoseconds().unwrap_or(0) / 1_000_000);
        serial_write(" ");
        crate::serial_write_bytes(path);
        serial_write("\r\n");
    }
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && matches!(
            path,
            b"/bin/bash" | b"bin/bash" | b"/sbin/agetty" | b"sbin/agetty"
        )
        && !X86_RUNTIME
            .LINUX_RUNTIME_CONSOLE_TIMING_WRITTEN
            .swap(true, Ordering::SeqCst)
    {
        serial_write("linox: timing Linux-init-to-console: ");
        serial_write_u64(linux_elapsed_nanoseconds().unwrap_or(0) / 1_000_000);
        serial_write(" ms\r\n");
        write_linux_boot_profile();
    }
    // Resolve relative paths and `.` and `..` components, as a path walk
    // would, before looking in the overlay or the published root.
    let mut absolute = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    let path = match linux_absolute_exec_path(path, &mut absolute) {
        Ok(length) if domain_exec_slot.is_none() => &absolute[..length],
        Err(error @ (LINUX_ENAMETOOLONG | LINUX_ELOOP | LINUX_EACCES | LINUX_ENOTDIR))
            if domain_exec_slot.is_none() =>
        {
            return error
        }
        _ => path,
    };
    // The process is named for the path as given (`exe` for
    // /proc/self/exe), as Linux names it from the file name.
    let named_path = path;
    // /proc/PID/exe runs the program that process runs.
    let linked;
    let path = match linux_proc_exe_link(path) {
        Some(Ok(target)) if domain_exec_slot.is_none() => {
            linked = target;
            &linked[..]
        }
        Some(Err(error)) if domain_exec_slot.is_none() => return error,
        _ => path,
    };
    // A symlink written at runtime (dpkg installs clang-21 -> clang) leads
    // to the file that runs, in the overlay or the image.
    let mut followed = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    let path = match linux_exec_follow_overlay_links(path, &mut followed) {
        Ok(Some(length)) if domain_exec_slot.is_none() => &followed[..length],
        Err(error) if domain_exec_slot.is_none() => return error,
        _ => path,
    };
    let mut overlay_image = None;
    let mut exec_file = None;
    if domain_exec_slot.is_none() {
        exec_file = match unlinked {
            Some(metadata) => Some(linux_overlay_file_access(metadata)),
            None => linux_exec_file_access(path),
        };
        if let Err(error) = linux_check_access(exec_file, linox_credentials::access::EXECUTE, false)
            .and_then(|()| linux_landlock_check_execute(path.strip_prefix(b"/").unwrap_or(path)))
        {
            return error;
        }
        // Nothing on a noexec mount runs (EACCES, before ETXTBSY).
        if linux_mount_flags(path.strip_prefix(b"/").unwrap_or(path)) & crate::linux_mounts::NO_EXEC
            != 0
        {
            return LINUX_EACCES;
        }
        // A file some process has open for writing cannot be executed
        // (execve04).
        if unlinked
            .or_else(|| crate::linux_overlay::lookup(path.strip_prefix(b"/").unwrap_or(path)))
            .is_some_and(|metadata| {
                linux_overlay_file_open_for_write(crate::linux_overlay::generation(metadata.handle))
            })
        {
            return LINUX_ETXTBSY;
        }
        let image = match unlinked {
            Some(metadata) => linux_overlay_exec_image_of(metadata),
            None => linux_overlay_exec_image(path),
        };
        match image {
            Ok(image) => overlay_image = image,
            Err(error) => return error,
        }
        // The program's file is opened to run it.
        linux_fanotify_event(
            path.strip_prefix(b"/").unwrap_or(path),
            crate::linux_fanotify::FAN_OPEN | crate::linux_fanotify::FAN_OPEN_EXEC,
        );
    }
    let overlay_bytes = overlay_image
        .as_mut()
        .map(|(image, size)| &image.bytes_mut()[..*size]);
    // The image's program at the path: where a bind mount of a root
    // filesystem directory leads it, if one does.
    let mut bound = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    let image_path =
        match crate::linux_overlay::image_location(path.strip_prefix(b"/").unwrap_or(path)) {
            alloc::borrow::Cow::Owned(image)
                if domain_exec_slot.is_none() && image.len() < bound.len() =>
            {
                bound[0] = b'/';
                bound[1..=image.len()].copy_from_slice(&image);
                &bound[..=image.len()]
            }
            _ => path,
        };
    let plan_at = |base| match overlay_bytes {
        Some(image) => crate::published_rootfs::process_plan_for_image(image, base),
        None => crate::published_rootfs::process_plan_at(image_path, base),
    };
    // A program loads low, below the heap, when it fits there. Larger
    // position-independent programs such as cargo load high instead; a
    // fixed-address one that does not fit is refused before anything about
    // the process changes.
    let plan = match plan_at(crate::published_rootfs::LOW_LOAD_BASE) {
        Some(plan)
            if linux_exec_plan_bounds(&plan)
                .is_some_and(|(_, end)| end <= LINUX_EXEC_LOW_LIMIT) =>
        {
            Some(plan)
        }
        Some(_) => plan_at(LINUX_EXEC_HIGH_LOAD_BASE).filter(|plan| {
            linux_exec_plan_bounds(plan).is_some_and(|(start, end)| {
                start >= LINUX_EXEC_HIGH_LOAD_BASE && end <= LINUX_EXEC_HIGH_LIMIT
            })
        }),
        None => None,
    };
    let Some(plan) = plan else {
        if overlay_bytes.is_some() {
            serial_write("linox: Linux exec of runtime file rejected: ");
            crate::serial_write_bytes(path);
            serial_write("\r\n");
            return LINUX_ENOEXEC;
        }
        use crate::published_rootfs::ProcessPlanFailure;
        let failure = match crate::published_rootfs::process_plan_failure(image_path) {
            ProcessPlanFailure::RootfsUnavailable => 1,
            ProcessPlanFailure::ExecutableNotFound => 2,
            ProcessPlanFailure::NotRegularFile => 3,
            ProcessPlanFailure::NotExecutable => 4,
            ProcessPlanFailure::ScriptInterpreterNotFound(_) => 5,
            ProcessPlanFailure::ScriptInterpreterNotExecutable(_) => 6,
            ProcessPlanFailure::UnsupportedExecutable => 7,
            ProcessPlanFailure::DynamicLoaderNotFound(_) => 8,
            ProcessPlanFailure::DynamicLoaderNotExecutable(_) => 9,
            ProcessPlanFailure::UnsupportedLoadLayout => 10,
        };
        serial_write("linox: Linux exec plan rejection code: ");
        serial_write_u64(failure);
        if let Some((length, head, kind, headers)) =
            crate::published_rootfs::executable_diagnostic(image_path)
        {
            serial_write(" length/head/type/phnum: ");
            for value in [length as u64, head, u64::from(kind), u64::from(headers)] {
                serial_write_u64(value);
                serial_write(" ");
            }
        }
        serial_write("\r\n");
        if let Some((headers, count)) =
            crate::published_rootfs::executable_program_headers(image_path)
        {
            serial_write("linox: Linux exec program type/flags: ");
            for header in &headers[..count] {
                serial_write_u64(*header);
                serial_write(" ");
            }
            serial_write("\r\n");
        }
        // PATH searches in libc try the next directory only on ENOENT, so a
        // missing file must not be reported as ENOEXEC.
        return match crate::published_rootfs::process_plan_failure(image_path) {
            ProcessPlanFailure::ExecutableNotFound => {
                linux_missing_path_error(path.strip_prefix(b"/").unwrap_or(path))
            }
            ProcessPlanFailure::RootfsUnavailable
            | ProcessPlanFailure::ScriptInterpreterNotFound(_)
            | ProcessPlanFailure::DynamicLoaderNotFound(_) => LINUX_ENOENT,
            ProcessPlanFailure::NotRegularFile
            | ProcessPlanFailure::NotExecutable
            | ProcessPlanFailure::ScriptInterpreterNotExecutable(_)
            | ProcessPlanFailure::DynamicLoaderNotExecutable(_) => LINUX_EACCES,
            ProcessPlanFailure::UnsupportedExecutable
            | ProcessPlanFailure::UnsupportedLoadLayout => LINUX_ENOEXEC,
        };
    };
    let launch_arguments = match overlay_bytes {
        Some(image) => Some(crate::published_rootfs::launch_arguments_for_image(
            path, image,
        )),
        None => crate::published_rootfs::launch_arguments(image_path),
    };
    let Some(launch_arguments) = launch_arguments else {
        return LINUX_ENOEXEC;
    };
    let startup = plan.startup();
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && (current_linux_process_pid() == 1 || path.ends_with(b"/systemd"))
    {
        serial_write("linox: PID1 ELF segment ranges:");
        for index in 0..plan.segment_count() {
            if let Some(segment) = plan.segment(index) {
                serial_write(" [");
                serial_write_u64(segment.virtual_page);
                serial_write("+");
                serial_write_u64(segment.page_count as u64);
                serial_write("p/");
                serial_write_u64(segment.memory_size as u64);
                serial_write("]");
            }
        }
        serial_write("\r\n");
    }
    // The new program's stack is at the top of the address space, where it
    // may grow down to RLIMIT_STACK (`linux_primary_stack_floor`).
    let stack_page = LINUX_STACK_END - PAGE_SIZE as u64;
    let (mut stack_image, new_stack) = match build_linux_exec_stack_image(
        &launch_arguments,
        arguments_address,
        environment_address,
        domain_exec_slot,
        startup,
        stack_page + PAGE_SIZE as u64,
    ) {
        Ok(image) => image,
        Err(error) => return error,
    };
    if !linux_relocate_primary_stack(current_linux_process_pid()) {
        serial_write("linox: Linux exec stack relocation failed\r\n");
        return LINUX_ENOMEM;
    }

    let replacement_count = (0..plan.segment_count()).try_fold(0_usize, |count, index| {
        count.checked_add(plan.segment(index)?.page_count)
    });
    let Some(replacement_count) =
        replacement_count.filter(|count| (1..=LINUX_EXEC_IMAGE_PAGE_LIMIT).contains(count))
    else {
        serial_write("linox: Linux exec replacement page count invalid: ");
        serial_write_u64(replacement_count.unwrap_or(0) as u64);
        serial_write("\r\n");
        return LINUX_ENOEXEC;
    };
    let mut replacement_scratch =
        LinuxExecScratch::allocate(replacement_count * size_of::<memory::FrameLease>());
    let Some(replacements) = replacement_scratch
        .as_mut()
        .and_then(|scratch| scratch.frame_leases(replacement_count))
        .and_then(|replacements| {
            memory::allocate_frame_prefix_into(
                memory::FrameOwner::KERNEL,
                replacements,
                replacement_count,
            )
            .then_some(replacements)
        })
    else {
        serial_write("linox: Linux exec frame allocation failed count: ");
        serial_write_u64(replacement_count as u64);
        serial_write("\r\n");
        return LINUX_ENOMEM;
    };
    let mut replacement_index = 0;
    let pid = current_linux_process_pid();
    for segment_index in 0..plan.segment_count() {
        let Some(segment) = plan.segment(segment_index) else {
            return LINUX_ENOEXEC;
        };
        for page in 0..segment.page_count {
            let Some(address) = segment
                .virtual_page
                .checked_add((page * PAGE_SIZE) as u64)
                .and_then(|address| usize::try_from(address).ok())
            else {
                return LINUX_ENOEXEC;
            };
            let mapping = linux_process::live_process_mapping(pid, address);
            let replacement = replacements[replacement_index];
            replacement_index += 1;
            if !address_space::materialize_linux_exec_frame(replacement, segment, page) {
                let _ =
                    memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[replacement]);
                return LINUX_ENOEXEC;
            }
            let protection = if segment.executable {
                LINUX_PROT_READ | LINUX_PROT_EXEC
            } else if segment.writable {
                LINUX_PROT_READ | LINUX_PROT_WRITE
            } else {
                LINUX_PROT_READ
            } as u8;
            if mapping.is_some_and(|mapping| {
                !address_space::current_linux_mapping_matches(
                    address as u64,
                    mapping.frame,
                    mapping.writable,
                    mapping.executable,
                )
            }) {
                serial_write("linox: Linux exec current/registry mapping mismatch address/frame: ");
                serial_write_u64(address as u64);
                serial_write("/");
                serial_write_u64(mapping.map_or(0, |mapping| mapping.frame.address()));
                serial_write("\r\n");
                return LINUX_ENOEXEC;
            }
            let replaced = address_space::install_current_linux_runtime_page(
                address as u64,
                replacement,
                protection,
                true,
                mapping.is_some(),
            );
            let registry_updated = if let Some(mapping) = mapping {
                replaced.is_some()
                    && linux_process::replace_live_process_mapping_for_exec(
                        pid,
                        address,
                        mapping.frame,
                        replacement,
                        segment.writable,
                        segment.executable,
                    )
            } else {
                replaced == Some(None)
                    && linux_process::add_live_process_mapping(
                        pid,
                        LinuxActiveImageMapping {
                            address,
                            frame: replacement,
                            writable: segment.writable,
                            executable: segment.executable,
                            shared: false,
                            dontfork: false,
                        },
                    )
            };
            if !registry_updated {
                serial_write("linox: Linux exec mapping update failed address/prior/install: ");
                serial_write_u64(address as u64);
                serial_write(" ");
                serial_write_u64(u64::from(mapping.is_some()));
                serial_write(" ");
                serial_write_u64(match replaced {
                    Some(Some(_)) => 2,
                    Some(None) => 1,
                    None => 0,
                });
                serial_write("\r\n");
                return LINUX_ENOEXEC;
            }
            if let Some(index) = (0..usize::from(
                X86_RUNTIME
                    .ELF_PROBE_ACTIVE_IMAGE_COUNT
                    .load(Ordering::SeqCst),
            ))
                .find(|index| {
                    X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[*index].load(Ordering::SeqCst)
                        == address as u64
                })
            {
                X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index]
                    .store(replacement.address(), Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index]
                    .store(replacement.generation(), Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].store(
                    u8::from(segment.writable) | (u8::from(segment.executable) << 1),
                    Ordering::SeqCst,
                );
            }
            if let Some(mapping) = mapping {
                if memory::frame_leases_releasable(memory::FrameOwner::KERNEL, &[mapping.frame])
                    && !address_space::release_linux_private_page(mapping.frame)
                {
                    return LINUX_ENOMEM;
                }
            }
        }
    }
    if replacement_index != replacement_count {
        return LINUX_ENOEXEC;
    }
    let reset_exec_page = |address: usize| -> bool {
        let Some(mapping) = linux_process::live_process_mapping(pid, address) else {
            return false;
        };
        let Some([replacement]) = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL) else {
            return false;
        };
        let shared = address_space::current_linux_runtime_page(address as u64).shared;
        let mut old = None;
        let installed = address_space::prepare_linux_frame(replacement.address(), &[])
            && address_space::install_current_linux_runtime_page(
                address as u64,
                replacement,
                LINUX_PROT_READ as u8 | LINUX_PROT_WRITE as u8,
                false,
                true,
            )
            .inspect(|frame| old = *frame)
            .is_some()
            && linux_process::replace_live_process_mapping_for_exec(
                pid,
                address,
                mapping.frame,
                replacement,
                true,
                false,
            );
        if !installed {
            let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[replacement]);
            return false;
        }
        // The old program's private page loses this mapping, as a segment
        // page does above: freed unless a fork parent or child still maps
        // it. Dropping it here instead left one mapping count on it for
        // good, and the page with it (16 heap pages and the stack's, every
        // exec).
        old.filter(|frame| {
            !shared && memory::frame_leases_releasable(memory::FrameOwner::KERNEL, &[*frame])
        })
        .is_none_or(address_space::release_linux_private_page)
    };
    let heap_base = X86_RUNTIME.ELF_PROBE_BRK_LIMIT.load(Ordering::SeqCst) as usize
        - LINUX_RUNTIME_HEAP_PAGES * PAGE_SIZE;
    for page in 0..LINUX_RUNTIME_HEAP_PAGES {
        let address = heap_base + page * PAGE_SIZE;
        if !reset_exec_page(address) {
            serial_write("linox: Linux exec heap write preparation failed\r\n");
            return LINUX_ENOMEM;
        }
    }
    let stack_low = X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst) as usize;
    if stack_low == 0 || stack_low > stack_page as usize || !stack_low.is_multiple_of(PAGE_SIZE) {
        return LINUX_ENOEXEC;
    }
    let stack_pages = (stack_page as usize - stack_low) / PAGE_SIZE + 1;
    let mut reset_stack_top = false;
    for page in 0..stack_pages {
        let address = stack_page as usize - page * PAGE_SIZE;
        if linux_process::live_process_mapping(pid, address).is_none() {
            continue;
        }
        if !reset_exec_page(address) {
            serial_write("linox: Linux exec stack write preparation failed\r\n");
            return LINUX_ENOMEM;
        }
        if address == stack_page as usize {
            reset_stack_top = true;
        }
    }
    if !reset_stack_top {
        return LINUX_ENOEXEC;
    }
    let Some(stack_mapping) = linux_process::live_process_mapping(pid, stack_page as usize) else {
        return LINUX_ENOEXEC;
    };
    // The top page is written through its frame; any part of a larger image
    // below it goes through the user mapping, which grows the stack on demand.
    let image = stack_image.bytes();
    let (lower, top) = image.split_at(image.len().saturating_sub(PAGE_SIZE));
    if !address_space::materialize_linux_exec_stack_frame(
        stack_mapping.frame,
        PAGE_SIZE - top.len(),
        top,
    ) || !lower.is_empty() && !copy_to_linux_user(new_stack, lower)
    {
        serial_write("linox: Linux exec stack image failed\r\n");
        return LINUX_ENOMEM;
    }
    // The new image runs on the primary stack, whatever thread or vfork
    // stack the exec came from.
    if let Some(slot) = current_linux_thread_slot() {
        let low = X86_RUNTIME.ELF_PROBE_STACK_LOW.load(Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].store(low, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].store(
            (stack_page + PAGE_SIZE as u64).saturating_sub(low),
            Ordering::SeqCst,
        );
    }
    let process_name = named_path
        .rsplit(|byte| *byte == b'/')
        .next()
        .unwrap_or(named_path);
    if process_name.is_empty() {
        return LINUX_ENOEXEC;
    }
    let process_name = &process_name[..process_name.len().min(15)];
    let mut name = [0_u8; 16];
    name[..process_name.len()].copy_from_slice(process_name);
    X86_RUNTIME.ELF_PROBE_PROCESS_NAME_LOW.store(
        u64::from_ne_bytes(name[..8].try_into().unwrap_or([0; 8])),
        Ordering::SeqCst,
    );
    X86_RUNTIME.ELF_PROBE_PROCESS_NAME_HIGH.store(
        u64::from_ne_bytes(name[8..].try_into().unwrap_or([0; 8])),
        Ordering::SeqCst,
    );
    crate::linux_exe::record(
        X86_RUNTIME.LINUX_EXECUTION_INSTANCE.load(Ordering::SeqCst),
        pid,
        path,
    );
    X86_RUNTIME
        .ELF_PROBE_BRK
        .store(heap_base as u64, Ordering::SeqCst);
    let Some(main_code) = plan.main_executable() else {
        return LINUX_ENOEXEC;
    };
    X86_RUNTIME
        .ELF_PROBE_CODE_BASE
        .store(main_code.virtual_page, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_CODE_SIZE
        .store((main_code.page_count * PAGE_SIZE) as u64, Ordering::SeqCst);
    let Some(loader_code) = plan.loader_executable() else {
        return LINUX_ENOEXEC;
    };
    X86_RUNTIME
        .ELF_PROBE_LOADER_CODE_BASE
        .store(loader_code.virtual_page, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_LOADER_CODE_SIZE.store(
        (loader_code.page_count * PAGE_SIZE) as u64,
        Ordering::SeqCst,
    );
    unshare_linux_state_for_exec(current_linux_process_pid());
    for descriptor in 0..LINUX_AUX_DESCRIPTOR_LIMIT {
        if linux_descriptor_close_on_exec(descriptor) {
            let _ = linux_descriptor_close(descriptor);
        }
    }
    linux_close_overflow_on_exec();
    end_other_linux_threads_for_exec();
    reset_linux_signal_state_after_exec();
    let _ = set_current_linux_clear_child_tid(0);
    let _ = set_current_linux_robust_list(0);
    // Drop the old program's mmap area and its mappings below it (MAP_FIXED
    // and MAP_32BIT memory); the new image's own pages are kept.
    // The high image window is left alone: releasing it from a vfork child
    // of a high-loaded program unmapped that program's own code. Each
    // private page loses this mapping; a vfork child's pages, all its
    // parent's, stay with the parent.
    if !address_space::release_current_linux_runtime_mappings_preserving(
        LINUX_RUNTIME_DYNAMIC_MMAP_BASE,
        |frame| !address_space::linux_private_page_counted(frame),
        |frame| replacements[..replacement_count].contains(&frame),
    ) || !address_space::release_current_linux_low_mappings_preserving(
        LINUX_FIXED_LOW_BASE,
        |frame| !address_space::linux_private_page_counted(frame),
        |frame| replacements[..replacement_count].contains(&frame),
    ) {
        serial_write("linox: Linux exec mmap release failed\r\n");
        return LINUX_ENOMEM;
    }
    release_linux_process_shared_mappings(current_linux_process_pid());
    linux_record_exec_image(&plan, path);
    // A set-user-ID or set-group-ID program on a nosuid mount runs with the
    // caller's ids.
    let nosuid = linux_mount_flags(path.strip_prefix(b"/").unwrap_or(path))
        & crate::linux_mounts::NO_SUID
        != 0;
    linux_apply_exec_credentials(exec_file.filter(|_| !nosuid));
    // The new program has no rseq area yet: its C library registers its
    // own (Linux's rseq_execve), which the old image's would refuse.
    if let Some(slot) = current_linux_thread_slot() {
        X86_RUNTIME.LINUX_THREAD_RSEQ_POINTERS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RSEQ_LENGTHS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_RSEQ_SIGNATURES[slot].store(0, Ordering::SeqCst);
    }
    // The new program starts without thread and process keyrings.
    let (pid, tid) = (current_linux_process_pid(), current_linux_tid());
    let _ = linux_with_keys(|keys, _| {
        keys.exec(pid, tid.unwrap_or(pid));
        Ok(())
    });
    X86_RUNTIME
        .ELF_PROBE_MMAP_NEXT
        .store(LINUX_RUNTIME_DYNAMIC_MMAP_BASE, Ordering::SeqCst);
    if !update_current_linux_tls(0) {
        serial_write("linox: Linux exec TLS reset failed\r\n");
        return LINUX_ENOMEM;
    }
    let Some(thread) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let thread_slot = usize::from(thread.slot);
    let Some(stack_end) = stack_page.checked_add(PAGE_SIZE as u64) else {
        return LINUX_ENOMEM;
    };
    let Some(stack_size) = stack_end.checked_sub(stack_low as u64) else {
        return LINUX_ENOEXEC;
    };
    X86_RUNTIME.LINUX_THREAD_POINTERS[thread_slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_TLS_EXTENTS[thread_slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_TLS_SIZES[thread_slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STACK_BASES[thread_slot].store(stack_low as u64, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STACK_SIZES[thread_slot].store(stack_size, Ordering::SeqCst);
    if !save_linux_thread_return_context(
        thread,
        LinuxUserContext {
            registers: LinuxSyscallFrame::ZERO,
            rip: startup.initial_entry,
            rsp: new_stack,
            rflags: 0x202,
            rax: 0,
            fs_base: 0,
        },
    ) {
        serial_write("linox: Linux exec thread context reset failed\r\n");
        return LINUX_ENOEXEC;
    }
    if !reset_extended_user_state() {
        return LINUX_ENOMEM;
    }
    unsafe {
        let entry_state = &mut *current_entry_state();
        entry_state.user_rip = startup.initial_entry;
        entry_state.user_rsp = new_stack;
    }
    if !linux_process::set_live_process_exec_context(pid, startup.initial_entry, new_stack) {
        serial_write("linox: Linux exec process context rejected entry/stack: ");
        serial_write_u64(startup.initial_entry);
        serial_write("/");
        serial_write_u64(new_stack);
        serial_write("\r\n");
        return LINUX_ENOEXEC;
    }
    // Every tracked fork child must return to the kernel scheduler after a
    // successful exec so execution can resume from the replacement image.
    // CLONE_VM/vfork separately controls when the parent may resume; it does
    // not determine whether the exec transition is reported.
    if X86_RUNTIME
        .LINUX_PROCESS_CHILD_EXEC_PID
        .load(Ordering::SeqCst)
        == pid
    {
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXECUTED
            .store(true, Ordering::SeqCst);
    }
    if !refresh_linux_vvar() {
        return LINUX_ENOMEM;
    }
    let entry_page = startup.initial_entry & !(PAGE_SIZE as u64 - 1);
    let entry_mapping = address_space::current_linux_active_mapping(entry_page);
    let registered_entry = linux_process::live_process_mapping(pid, entry_page as usize);
    if entry_mapping.is_none()
        || registered_entry.is_none()
        || entry_mapping.map(|mapping| mapping.frame)
            != registered_entry.map(|mapping| mapping.frame)
        || entry_mapping.is_some_and(|mapping| !mapping.executable)
    {
        serial_write("linox: Linux exec entry mapping mismatch pid/page/hardware/registry: ");
        serial_write_u64(u64::from(pid));
        serial_write("/");
        serial_write_u64(entry_page);
        serial_write("/");
        serial_write_u64(entry_mapping.map_or(0, |mapping| mapping.frame.address()));
        serial_write("/");
        serial_write_u64(registered_entry.map_or(0, |mapping| mapping.frame.address()));
        serial_write("\r\n");
        return LINUX_ENOEXEC;
    }
    0
}

/// Returns the lowest and highest-plus-one addresses a plan maps.
fn linux_exec_plan_bounds(
    plan: &crate::linux_elf::RelocatableExecutablePlan<'_, '_>,
) -> Option<(u64, u64)> {
    (0..plan.segment_count()).try_fold((u64::MAX, 0_u64), |(start, end), index| {
        let segment = plan.segment(index)?;
        let segment_end = segment
            .virtual_page
            .checked_add((segment.page_count * PAGE_SIZE) as u64)?;
        Some((start.min(segment.virtual_page), end.max(segment_end)))
    })
}

/// Writes the absolute, normalized form of exec `path` to `output` and
/// returns its length.
fn linux_absolute_exec_path(
    path: &[u8],
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY + 1],
) -> Result<usize, u64> {
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), path, &mut canonical)?;
    output[0] = b'/';
    output[1..=length].copy_from_slice(&canonical[..length]);
    Ok(length + 1)
}

/// The absolute path the overlay's symlinks at absolute `path` lead to,
/// written to `output`, or `None` when the overlay has no symlink there.
fn linux_exec_follow_overlay_links(
    path: &[u8],
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY + 1],
) -> Result<Option<usize>, u64> {
    let Some(relative) = path.strip_prefix(b"/") else {
        return Ok(None);
    };
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let Some(start) = canonical.get_mut(..relative.len()) else {
        return Ok(None);
    };
    start.copy_from_slice(relative);
    let (length, followed, _) =
        linux_overlay_lookup_following(&mut canonical, relative.len(), true)?;
    if !followed {
        return Ok(None);
    }
    output[0] = b'/';
    output[1..=length].copy_from_slice(&canonical[..length]);
    Ok(Some(length + 1))
}

/// Reads an executable written at runtime into a kernel extent. Returns the
/// extent and the file size, or `None` when absolute `path` does not name a
/// file in the overlay.
/// The file execve runs at absolute `path`: the overlay's, or the image's
/// after following its symlinks.
fn linux_exec_file_access(path: &[u8]) -> Option<linox_credentials::FileAccess> {
    if let Some(metadata) = path
        .strip_prefix(b"/")
        .and_then(crate::linux_overlay::lookup)
        .filter(|metadata| metadata.kind != crate::linux_overlay::NodeKind::Symlink)
    {
        return Some(linux_overlay_file_access(metadata));
    }
    let (_, entry) = linux_rootfs_path_at(u64::from(LINUX_AT_FDCWD), path)?;
    entry.map(|entry| linox_credentials::FileAccess {
        owner: entry.owner,
        group: entry.group,
        mode: entry.mode & 0o7777,
        directory: entry.kind == crate::published_rootfs::EntryKind::Directory,
    })
}

/// execve's credential change: a set-user-ID program makes its owner the
/// effective user id, a set-group-ID (and group-executable) one its group
/// the effective group id, when the domain maps that id; the saved and
/// filesystem ids then follow the effective ones.
fn linux_apply_exec_credentials(file: Option<linox_credentials::FileAccess>) {
    let pid = current_linux_process_pid();
    let (Some(namespace), Some(mut credentials)) = (
        current_linux_user_namespace(),
        linux_process::live_process_credentials(pid),
    ) else {
        return;
    };
    let id_count = linux_user::identity_authority(namespace, &credentials).id_count;
    // With no_new_privs an exec grants nothing: the set-ID bits do not
    // count (PR_SET_NO_NEW_PRIVS).
    let file = file.filter(|_| !X86_RUNTIME.ELF_PROBE_NO_NEW_PRIVS.load(Ordering::SeqCst));
    let set_id = |bits: u32, id: fn(&linox_credentials::FileAccess) -> u32| {
        file.filter(|file| file.mode & bits == bits)
            .map(|file| id(&file))
            .filter(|id| *id < id_count)
    };
    credentials.user.exec(set_id(0o4000, |file| file.owner));
    credentials.group.exec(set_id(0o2010, |file| file.group));
    credentials.after_exec();
    linux_process::set_live_process_credentials(pid, credentials);
}

fn linux_overlay_exec_image(path: &[u8]) -> Result<Option<(LinuxExecScratch, usize)>, u64> {
    let Some(metadata) = path
        .strip_prefix(b"/")
        .and_then(crate::linux_overlay::lookup)
    else {
        return Ok(None);
    };
    linux_overlay_exec_image_of(metadata)
}

/// The program in the overlay file `metadata` describes, read whole.
fn linux_overlay_exec_image_of(
    metadata: crate::linux_overlay::Metadata,
) -> Result<Option<(LinuxExecScratch, usize)>, u64> {
    match metadata.kind {
        crate::linux_overlay::NodeKind::File => {}
        crate::linux_overlay::NodeKind::Symlink => return Ok(None),
        _ => return Err(LINUX_EACCES),
    }
    if metadata.mode & 0o111 == 0 {
        return Err(LINUX_EACCES);
    }
    if metadata.size == 0 || metadata.size > LINUX_EXEC_IMAGE_PAGE_LIMIT * PAGE_SIZE {
        return Err(LINUX_ENOEXEC);
    }
    let mut image = LinuxExecScratch::allocate(metadata.size).ok_or(LINUX_ENOMEM)?;
    if crate::linux_overlay::read(metadata.handle, 0, &mut image.bytes_mut()[..metadata.size])
        != Some(metadata.size)
    {
        return Err(LINUX_EIO);
    }
    Ok(Some((image, metadata.size)))
}

/// A zeroed, kernel-owned extent for exec data too large for the kernel
/// stack. It is scrubbed and released when dropped.
struct LinuxExecScratch {
    first: memory::FrameLease,
    pages: usize,
}

impl LinuxExecScratch {
    fn allocate(bytes: usize) -> Option<Self> {
        let pages = bytes.div_ceil(PAGE_SIZE).max(1);
        let (first, _) = memory::allocate_contiguous_extent(memory::FrameOwner::KERNEL, pages)?;
        Some(Self { first, pages })
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let length = self.pages * PAGE_SIZE;
        let Some(address) = paging::direct_map_range_address(self.first.address(), length) else {
            return &mut [];
        };
        // SAFETY: the extent is live, kernel-owned, contiguous, and only
        // reachable through this value.
        unsafe { core::slice::from_raw_parts_mut(address as *mut u8, length) }
    }

    /// Views the start of the extent as `count` frame leases, which are all
    /// empty while the extent is still zeroed.
    fn frame_leases(&mut self, count: usize) -> Option<&mut [memory::FrameLease]> {
        let bytes = self.bytes_mut();
        if count.checked_mul(size_of::<memory::FrameLease>())? > bytes.len() {
            return None;
        }
        // SAFETY: the page-aligned extent holds `count` leases, a lease is
        // plain integers, and the borrow of `self` keeps the view unique.
        Some(unsafe {
            core::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<memory::FrameLease>(), count)
        })
    }
}

impl Drop for LinuxExecScratch {
    fn drop(&mut self) {
        let _ = memory::scrub_and_release_contiguous_extent(
            memory::FrameOwner::KERNEL,
            self.first,
            self.pages,
        );
    }
}

/// The argument, environment and auxiliary-vector block that exec places at
/// the top of the new stack, staged in kernel frames because the strings are
/// read from the old image.
struct LinuxExecStackImage {
    scratch: LinuxExecScratch,
    length: usize,
}

impl LinuxExecStackImage {
    fn bytes(&mut self) -> &[u8] {
        let length = self.length;
        &self.scratch.bytes_mut()[..length]
    }
}

/// Builds the initial stack for an exec whose stack ends at `stack_top`, and
/// returns it with the new stack pointer. Pointer words hold offsets into the
/// image until its final size, and so its address, is known.
fn build_linux_exec_stack_image(
    launch_arguments: &crate::published_rootfs::LaunchArguments<'_>,
    arguments_address: u64,
    environment_address: u64,
    domain_exec_slot: Option<usize>,
    startup: crate::linux_elf::ProcessStartup,
    stack_top: u64,
) -> Result<(LinuxExecStackImage, u64), u64> {
    // An empty argv gets one empty argument, as Linux has done since 5.18,
    // so the new program's argv[0] is never NULL (execve06).
    let mut empty_arguments = false;
    let original_argument_count = if let Some(slot) = domain_exec_slot {
        usize::from(X86_RUNTIME.CONTAINER_EXEC_ARGUMENT_COUNTS[slot].load(Ordering::Acquire))
    } else {
        match linux_exec_vector_length(arguments_address)? {
            0 => {
                empty_arguments = true;
                1
            }
            count => count,
        }
    };
    // A program (not a script) gets the caller's argv[0], as in Linux:
    // rustup's proxies (cargo -> rustup) and clang++ -> clang tell what to
    // be from it. The path that runs is only AT_EXECFN then.
    let keep_argument_zero =
        launch_arguments.count == 1 && domain_exec_slot.is_none() && original_argument_count >= 1;
    let (launch_count, first_original) = if keep_argument_zero {
        (0, 0)
    } else {
        (launch_arguments.count, 1)
    };
    let argument_count = launch_count
        .checked_add(original_argument_count.saturating_sub(first_original))
        .filter(|count| *count <= LINUX_EXEC_ARGUMENT_LIMIT)
        .ok_or(LINUX_E2BIG)?;
    let environment_count = if domain_exec_slot.is_some() {
        0
    } else {
        linux_exec_vector_length(environment_address)?
    };
    let mut image = LinuxExecStackImage {
        scratch: LinuxExecScratch::allocate(LINUX_EXEC_ARGUMENT_PAGES * PAGE_SIZE)
            .ok_or(LINUX_ENOMEM)?,
        length: 0,
    };
    let buffer = image.scratch.bytes_mut();
    let environment_word = 1 + argument_count + 1;
    let auxiliary_word = environment_word + environment_count + 1;
    let table_words = auxiliary_word + crate::linux_elf::AUXILIARY_VECTOR_WORDS;
    let mut cursor = table_words
        .checked_mul(size_of::<u64>())
        .filter(|end| *end <= buffer.len())
        .ok_or(LINUX_E2BIG)?;
    let write_word = |buffer: &mut [u8], word: usize, value: u64| {
        buffer[word * 8..(word + 1) * 8].copy_from_slice(&value.to_ne_bytes());
    };
    let string_error = |error| {
        if error == LINUX_ENAMETOOLONG {
            LINUX_E2BIG
        } else {
            error
        }
    };
    write_word(buffer, 0, argument_count as u64);
    let mut execfn_offset = None;
    for index in 0..argument_count {
        let remaining = &mut buffer[cursor..];
        let length = if index < launch_count {
            let value = launch_arguments.values[index];
            let output = remaining.get_mut(..=value.len()).ok_or(LINUX_E2BIG)?;
            output[..value.len()].copy_from_slice(value);
            output[value.len()] = 0;
            value.len()
        } else if let Some(slot) = domain_exec_slot {
            let original_index = 1 + index - launch_arguments.count;
            let length = usize::from(
                X86_RUNTIME.CONTAINER_EXEC_ARGUMENT_SIZES[slot][original_index]
                    .load(Ordering::Acquire),
            );
            let output = remaining.get_mut(..=length).ok_or(LINUX_E2BIG)?;
            for (byte, cell) in output[..length]
                .iter_mut()
                .zip(X86_RUNTIME.CONTAINER_EXEC_ARGUMENTS[slot][original_index].iter())
            {
                *byte = cell.load(Ordering::Acquire);
            }
            output[length] = 0;
            length
        } else {
            let original_index = first_original + index - launch_count;
            if empty_arguments {
                *remaining.first_mut().ok_or(LINUX_E2BIG)? = 0;
                0
            } else {
                let pointer = linux_exec_vector_entry(arguments_address, original_index)?;
                copy_linux_c_string(pointer, remaining).map_err(string_error)?
            }
        };
        if index == launch_arguments.execfn && !keep_argument_zero {
            execfn_offset = Some(cursor);
        }
        write_word(buffer, 1 + index, cursor as u64);
        cursor += length + 1;
    }
    if keep_argument_zero {
        let value = launch_arguments.values[0];
        let output = buffer
            .get_mut(cursor..=cursor + value.len())
            .ok_or(LINUX_E2BIG)?;
        output[..value.len()].copy_from_slice(value);
        output[value.len()] = 0;
        execfn_offset = Some(cursor);
        cursor += value.len() + 1;
    }
    let execfn_offset = execfn_offset.ok_or(LINUX_ENOEXEC)?;
    for index in 0..environment_count {
        let pointer = linux_exec_vector_entry(environment_address, index)?;
        let length = copy_linux_c_string(pointer, &mut buffer[cursor..]).map_err(string_error)?;
        write_word(buffer, environment_word + index, cursor as u64);
        cursor += length + 1;
    }
    let platform_offset = cursor;
    buffer
        .get_mut(platform_offset..platform_offset + LINUX_PLATFORM.len())
        .ok_or(LINUX_E2BIG)?
        .copy_from_slice(LINUX_PLATFORM);
    let random = linux_startup_random().ok_or(LINUX_EIO)?;
    let random_offset = platform_offset + LINUX_PLATFORM.len();
    buffer
        .get_mut(random_offset..random_offset + random.len())
        .ok_or(LINUX_E2BIG)?
        .copy_from_slice(&random);
    let length = (random_offset + random.len())
        .max(LINUX_EXEC_STACK_SIZE)
        .next_multiple_of(16);
    if length > buffer.len() {
        return Err(LINUX_E2BIG);
    }
    let new_stack = stack_top - length as u64;
    for word in (1..=argument_count).chain(environment_word..environment_word + environment_count) {
        let offset = u64::from_ne_bytes(
            buffer[word * 8..(word + 1) * 8]
                .try_into()
                .map_err(|_| LINUX_EFAULT)?,
        );
        write_word(buffer, word, new_stack + offset);
    }
    for (index, value) in crate::linux_elf::auxiliary_vector(
        startup,
        new_stack + execfn_offset as u64,
        new_stack + platform_offset as u64,
        new_stack + random_offset as u64,
        crate::linux_elf::VDSO_ADDRESS,
    )
    .into_iter()
    .enumerate()
    {
        write_word(buffer, auxiliary_word + index, value);
    }
    image.length = length;
    Ok((image, new_stack))
}

/// Counts the entries of a NULL-terminated user pointer vector.
fn linux_exec_vector_length(address: u64) -> Result<usize, u64> {
    // A NULL argv or envp is an empty one, as in Linux.
    if address == 0 {
        return Ok(0);
    }
    for index in 0..=LINUX_EXEC_ARGUMENT_LIMIT {
        if linux_exec_vector_entry(address, index)? == 0 {
            return Ok(index);
        }
    }
    Err(LINUX_E2BIG)
}

fn linux_exec_vector_entry(address: u64, index: usize) -> Result<u64, u64> {
    let pointer_address = address
        .checked_add((index * size_of::<u64>()) as u64)
        .ok_or(LINUX_EFAULT)?;
    let mut bytes = [0_u8; size_of::<u64>()];
    if !copy_from_linux_user(pointer_address, &mut bytes) {
        return Err(LINUX_EFAULT);
    }
    Ok(u64::from_ne_bytes(bytes))
}

fn linux_execve_at(
    directory: u64,
    path_address: u64,
    arguments_address: u64,
    environment_address: u64,
    allow_empty_path: bool,
) -> u64 {
    // The main thread of a process with other threads may exec too (they
    // end at the point of no return, as Linux's de_thread does: rustup's
    // proxies exec the toolchain's rustc from a threaded process), unless
    // one of them is running on another CPU.
    let other_threads = X86_RUNTIME
        .LINUX_THREAD_STATES
        .iter()
        .filter(|state| state.load(Ordering::SeqCst) != LINUX_THREAD_FREE)
        .count()
        != 1;
    if current_linux_tid() != Some(current_linux_process_pid())
        || other_threads && !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
    {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && current_linux_process_pid() != 1
        {
            serial_write("linox: Linux child exec precondition rejected\r\n");
        }
        return LINUX_EAGAIN;
    }
    let mut path = [0_u8; LINUX_PATH_MAX];
    let path_length = match copy_linux_c_string(path_address, &mut path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && current_linux_process_pid() != 1 {
        let mut resolved = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        // A descriptor of a file whose last name went runs that file.
        let mut unlinked = None;
        let resolved_length = if path_length == 0 && allow_empty_path {
            unlinked = linux_overlay_descriptor_handle(u64::from(directory as u32))
                .filter(|handle| !crate::linux_overlay::linked(*handle));
            match linux_descriptor_path(directory, &mut resolved) {
                Some(length) => Some(length),
                None => return LINUX_EBADF,
            }
        } else if let Some(descriptor) =
            linux_descriptor_link_at(directory, &path[..path_length], true)
        {
            match linux_descriptor_path(descriptor, &mut resolved) {
                Some(length) => Some(length),
                None => return LINUX_ENOENT,
            }
        } else {
            None
        };
        let exec_path = resolved_length
            .map(|length| &resolved[..length])
            .unwrap_or(&path[..path_length]);
        let result = linux_rootfs_execve_source(
            exec_path,
            arguments_address,
            environment_address,
            None,
            unlinked,
        );
        if result == 0 {
            return LINUX_RETURN_TO_KERNEL;
        }
        if result != 0 {
            serial_write("linox: Linux child exec rejected path/error ");
            crate::serial_write_bytes(exec_path);
            serial_write(" ");
            serial_write_u64(result);
            serial_write("\r\n");
        }
        return result;
    }
    let exec_node = match if path_length == 0 {
        if allow_empty_path {
            linux_exec_descriptor_node(directory)
        } else {
            Err(LINUX_ENOENT)
        }
    } else {
        linux_exec_root_node(directory, &path[..path_length])
    } {
        Ok(node) => node,
        Err(error) => return error,
    };
    let Some(exec_bytes) = initramfs::published_file_by_node(exec_node) else {
        return LINUX_ENOENT;
    };
    let static_exec_plan = crate::linux_elf::measured_static_exec_plan(exec_bytes);
    let interpreted_exec_plan = if static_exec_plan.is_none()
        && initramfs::published_file_name_by_node(exec_node) == Some(b"linux/init")
    {
        linux_measured_interpreted_exec_plan()
    } else {
        None
    };
    let Some(exec_plan) = static_exec_plan.as_ref().or_else(|| {
        interpreted_exec_plan
            .as_ref()
            .map(|plan| &plan.process.interpreter)
    }) else {
        return LINUX_ENOEXEC;
    };
    let Some(process_name) = linux_exec_process_name(exec_node) else {
        return LINUX_ENOEXEC;
    };
    if interpreted_exec_plan.is_some() {
        serial_write("linox: measured-root interpreted Linux exec admitted\r\n");
    }
    let (argument_pointers, argument_count) = match linux_exec_vector(arguments_address, true) {
        Ok(vector) => vector,
        Err(error) => return error,
    };
    let (environment_pointers, environment_count) =
        match linux_exec_vector(environment_address, false) {
            Ok(vector) => vector,
            Err(error) => return error,
        };
    if linux_descriptor_numbers().any(|descriptor| {
        linux_descriptor_close_on_exec(descriptor) && !linux_descriptor_open(descriptor)
    }) {
        return LINUX_ESRCH;
    }
    let Some((mut active_image_mappings, active_image_count)) = linux_active_image_mappings()
    else {
        return LINUX_ENOEXEC;
    };
    let startup = interpreted_exec_plan.as_ref().map_or_else(
        || crate::linux_elf::static_startup(exec_plan),
        |plan| crate::linux_elf::interpreted_startup(&plan.process),
    );
    let entry = startup.initial_entry;
    let Some((mapping_templates, mapping_count)) = linux_exec_mapping_plan(exec_plan) else {
        return LINUX_ENOEXEC;
    };
    let interpreted = interpreted_exec_plan.is_some();
    let ancillary_mapping_count = 2 + 3 * usize::from(interpreted);
    if mapping_count > LINUX_EXEC_MAPPING_LIMIT - ancillary_mapping_count {
        return LINUX_E2BIG;
    }
    let stack_base = X86_RUNTIME.ELF_PROBE_STACK.load(Ordering::SeqCst) & !(PAGE_SIZE as u64 - 1);
    let heap_base = X86_RUNTIME
        .ELF_PROBE_BRK_LIMIT
        .load(Ordering::SeqCst)
        .saturating_sub(PAGE_SIZE as u64);
    let new_stack = stack_base + PAGE_SIZE as u64 - LINUX_EXEC_STACK_SIZE as u64;
    let mut stack_image = [0_u8; LINUX_EXEC_STACK_SIZE];
    if active_image_count > LINUX_ACTIVE_IMAGE_MAPPING_LIMIT - ancillary_mapping_count {
        return LINUX_E2BIG;
    }
    let Some(old_stack_frame) = memory::FrameLease::from_parts(
        X86_RUNTIME.ELF_PROBE_STACK_FRAME.load(Ordering::SeqCst),
        X86_RUNTIME
            .ELF_PROBE_STACK_GENERATION
            .load(Ordering::SeqCst),
    ) else {
        return LINUX_ENOEXEC;
    };
    if stack_base == 0
        || !address_space::current_linux_mapping_matches(stack_base, old_stack_frame, true, false)
    {
        return LINUX_ENOEXEC;
    }
    if (0..LINUX_RUNTIME_MMAP_SLOT_COUNT).any(|index| {
        X86_RUNTIME.ELF_PROBE_MMAP_PAGES[index].load(Ordering::SeqCst) != 0
            || X86_RUNTIME.ELF_PROBE_MMAP_PROTECTION[index].load(Ordering::SeqCst) != 0
            || X86_RUNTIME.ELF_PROBE_MMAP_FILE[index].load(Ordering::SeqCst) != 0
            || linux_mmap_slot_frame(index) != 0
            || X86_RUNTIME.ELF_PROBE_MMAP_GENERATIONS[index].load(Ordering::SeqCst) != 0
    }) {
        return LINUX_ENOEXEC;
    }
    let interpreted_tls = if let Some(plan) = interpreted_exec_plan.as_ref() {
        if current_linux_thread_handle()
            .and_then(linux_thread_context)
            .is_none()
        {
            serial_write("linox: exec current TLS context unavailable\r\n");
            return LINUX_ESRCH;
        }
        let sibling = X86_RUNTIME.ELF_PROBE_SIBLING_FS_BASE.load(Ordering::SeqCst);
        let initial_page = (sibling & !(PAGE_SIZE as u64 - 1)).checked_sub(PAGE_SIZE as u64);
        let Some((initial_thread_pointer, initial_extent, initial_extent_size)) =
            initial_page.and_then(|page| address_space::linux_exec_tls_context(plan, page))
        else {
            serial_write("linox: exec measured TLS layout unavailable\r\n");
            return LINUX_ENOEXEC;
        };
        let initial = LinuxTlsContext {
            thread_pointer: initial_thread_pointer,
            extent: initial_extent,
            extent_size: initial_extent_size,
        };
        let thread_pointers = [initial.thread_pointer as u64, sibling];
        if sibling == 0 {
            serial_write("linox: exec sibling TLS context unavailable\r\n");
            return LINUX_ENOEXEC;
        }
        if !address_space::current_linux_tls_rematerializable(plan, thread_pointers) {
            serial_write("linox: exec TLS rematerialization contract rejected\r\n");
            serial_write_u64(thread_pointers[0]);
            serial_write(" ");
            serial_write_u64(thread_pointers[1]);
            serial_write("\r\n");
            return LINUX_ENOEXEC;
        }
        Some((initial, thread_pointers))
    } else {
        None
    };
    let table_words =
        1 + argument_count + 1 + environment_count + 1 + crate::linux_elf::AUXILIARY_VECTOR_WORDS;
    let mut string_offset = table_words * size_of::<u64>();
    let string_limit = stack_image.len().saturating_sub(LINUX_PLATFORM.len() + 16);
    stack_image[..8].copy_from_slice(&(argument_count as u64).to_ne_bytes());
    let mut argument_zero_address = 0;
    for (index, pointer) in argument_pointers[..argument_count].iter().enumerate() {
        let Some(remaining) = stack_image.get_mut(string_offset..string_limit) else {
            return LINUX_E2BIG;
        };
        let length = match copy_linux_c_string(*pointer, remaining) {
            Ok(length) => length.saturating_add(1),
            Err(LINUX_ENAMETOOLONG) => return LINUX_E2BIG,
            Err(error) => return error,
        };
        let Some(end) = string_offset.checked_add(length) else {
            return LINUX_E2BIG;
        };
        if end > string_limit {
            return LINUX_E2BIG;
        }
        let word = 1 + index;
        stack_image[word * 8..word * 8 + 8]
            .copy_from_slice(&(new_stack + string_offset as u64).to_ne_bytes());
        if index == 0 {
            argument_zero_address = new_stack + string_offset as u64;
        }
        string_offset = end;
    }
    let environment_word = 1 + argument_count + 1;
    for (index, pointer) in environment_pointers[..environment_count].iter().enumerate() {
        let Some(remaining) = stack_image.get_mut(string_offset..string_limit) else {
            return LINUX_E2BIG;
        };
        let length = match copy_linux_c_string(*pointer, remaining) {
            Ok(length) => length.saturating_add(1),
            Err(LINUX_ENAMETOOLONG) => return LINUX_E2BIG,
            Err(error) => return error,
        };
        let Some(end) = string_offset.checked_add(length) else {
            return LINUX_E2BIG;
        };
        if end > string_limit {
            return LINUX_E2BIG;
        }
        let word = environment_word + index;
        stack_image[word * 8..word * 8 + 8]
            .copy_from_slice(&(new_stack + string_offset as u64).to_ne_bytes());
        string_offset = end;
    }
    let auxiliary_word = environment_word + environment_count + 1;
    let platform_offset = string_offset;
    let Some(platform_end) = platform_offset.checked_add(LINUX_PLATFORM.len()) else {
        return LINUX_E2BIG;
    };
    let Some(output) = stack_image.get_mut(platform_offset..platform_end) else {
        return LINUX_E2BIG;
    };
    output.copy_from_slice(LINUX_PLATFORM);
    let Some(random) = linux_startup_random() else {
        return LINUX_EIO;
    };
    let random_offset = platform_end;
    let Some(random_end) = random_offset.checked_add(random.len()) else {
        return LINUX_E2BIG;
    };
    let Some(output) = stack_image.get_mut(random_offset..random_end) else {
        return LINUX_E2BIG;
    };
    output.copy_from_slice(&random);
    let mut auxiliary = crate::linux_elf::auxiliary_vector(
        startup,
        argument_zero_address,
        new_stack + platform_offset as u64,
        new_stack + random_offset as u64,
        0,
    );
    if interpreted {
        auxiliary[33] = 1;
    }
    for (index, value) in auxiliary.into_iter().enumerate() {
        let word = auxiliary_word + index;
        stack_image[word * 8..word * 8 + 8].copy_from_slice(&value.to_ne_bytes());
    }
    let mut exec_frames = [None; LINUX_EXEC_MAPPING_LIMIT];
    let segments = [
        exec_plan.read_only,
        Some(exec_plan.executable),
        Some(exec_plan.writable),
    ];
    let mut mapping_index = 0;
    for segment in segments.into_iter().flatten() {
        for page in 0..segment.page_count {
            let Some([frame]) = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL) else {
                let _ = release_linux_exec_frames(&mut exec_frames);
                return LINUX_ENOMEM;
            };
            exec_frames[mapping_index] = Some(frame);
            if !address_space::materialize_linux_exec_frame(frame, segment, page) {
                let _ = release_linux_exec_frames(&mut exec_frames);
                return LINUX_ENOMEM;
            }
            mapping_index += 1;
        }
    }
    if mapping_index != mapping_count {
        let _ = release_linux_exec_frames(&mut exec_frames);
        return LINUX_ENOEXEC;
    }
    {
        let Some([frame]) = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL) else {
            let _ = release_linux_exec_frames(&mut exec_frames);
            return LINUX_ENOMEM;
        };
        exec_frames[mapping_count] = Some(frame);
        if !address_space::materialize_linux_exec_stack_frame(
            frame,
            PAGE_SIZE - LINUX_EXEC_STACK_SIZE,
            &stack_image,
        ) {
            let _ = release_linux_exec_frames(&mut exec_frames);
            return LINUX_ENOMEM;
        }
    }
    if interpreted {
        let Some([frame]) = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL) else {
            let _ = release_linux_exec_frames(&mut exec_frames);
            return LINUX_ENOMEM;
        };
        exec_frames[mapping_count + 4] = Some(frame);
        if !address_space::prepare_linux_frame(frame.address(), &[]) {
            let _ = release_linux_exec_frames(&mut exec_frames);
            return LINUX_ENOMEM;
        }
    }
    if let Some((_, thread_pointers)) = interpreted_tls {
        let Some(frames) = memory::allocate_frames::<2>(memory::FrameOwner::KERNEL) else {
            let _ = release_linux_exec_frames(&mut exec_frames);
            return LINUX_ENOMEM;
        };
        exec_frames[mapping_count + 2] = Some(frames[0]);
        exec_frames[mapping_count + 3] = Some(frames[1]);
        if !address_space::materialize_linux_exec_tls_frames(
            interpreted_exec_plan
                .as_ref()
                .unwrap_or_else(|| unreachable!()),
            thread_pointers,
            frames,
        ) {
            let _ = release_linux_exec_frames(&mut exec_frames);
            return LINUX_ENOMEM;
        }
    }
    {
        let Some([frame]) = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL) else {
            let _ = release_linux_exec_frames(&mut exec_frames);
            return LINUX_ENOMEM;
        };
        exec_frames[mapping_count + 1] = Some(frame);
        if !address_space::prepare_linux_frame(frame.address(), &[]) {
            let _ = release_linux_exec_frames(&mut exec_frames);
            return LINUX_ENOMEM;
        }
    }
    let mut mappings: [LinuxExecMapping; LINUX_EXEC_MAPPING_LIMIT] =
        core::array::from_fn(|index| LinuxExecMapping {
            frame: exec_frames[index].map_or(0, memory::FrameLease::address),
            ..mapping_templates[index]
        });
    let transaction_mapping_count = mapping_count + ancillary_mapping_count;
    if let Some(frame) = exec_frames[mapping_count] {
        mappings[mapping_count] = LinuxExecMapping {
            address: stack_base as usize,
            frame: frame.address(),
            writable: true,
            executable: false,
        };
    }
    if let Some(frame) = exec_frames[mapping_count + 1] {
        mappings[mapping_count + 1] = LinuxExecMapping {
            address: heap_base as usize,
            frame: frame.address(),
            writable: true,
            executable: false,
        };
    }
    if interpreted {
        if let Some((_, thread_pointers)) = interpreted_tls {
            for (offset, thread_pointer) in thread_pointers.into_iter().enumerate() {
                if let Some(frame) = exec_frames[mapping_count + 2 + offset] {
                    mappings[mapping_count + 2 + offset] = LinuxExecMapping {
                        address: (thread_pointer & !(PAGE_SIZE as u64 - 1)) as usize,
                        frame: frame.address(),
                        writable: true,
                        executable: false,
                    };
                }
            }
        }
        if let Some(frame) = exec_frames[mapping_count + 4] {
            mappings[mapping_count + 4] = LinuxExecMapping {
                address: X86_RUNTIME.ELF_PROBE_SIBLING_STACK.load(Ordering::SeqCst) as usize,
                frame: frame.address(),
                writable: true,
                executable: false,
            };
        }
    }
    let old_mapping_count = active_image_count + ancillary_mapping_count;
    let old_stack_page = address_space::current_linux_runtime_page(stack_base);
    active_image_mappings[active_image_count] = LinuxActiveImageMapping {
        address: stack_base as usize,
        frame: old_stack_frame,
        writable: true,
        executable: false,
        shared: old_stack_page.shared,
        dontfork: old_stack_page.dontfork,
    };
    let Some(old_heap_frame) = memory::FrameLease::from_parts(
        X86_RUNTIME.ELF_PROBE_HEAP_FRAME.load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_HEAP_GENERATION.load(Ordering::SeqCst),
    ) else {
        let _ = release_linux_exec_frames(&mut exec_frames);
        return LINUX_ENOEXEC;
    };
    if old_heap_frame == old_stack_frame
        || heap_base == 0
        || !address_space::current_linux_mapping_matches(heap_base, old_heap_frame, true, false)
    {
        let _ = release_linux_exec_frames(&mut exec_frames);
        return LINUX_ENOEXEC;
    }
    let old_heap_page = address_space::current_linux_runtime_page(heap_base);
    active_image_mappings[active_image_count + 1] = LinuxActiveImageMapping {
        address: heap_base as usize,
        frame: old_heap_frame,
        writable: true,
        executable: false,
        shared: old_heap_page.shared,
        dontfork: old_heap_page.dontfork,
    };
    if let Some((_, thread_pointers)) = interpreted_tls {
        for (index, thread_pointer) in thread_pointers.into_iter().enumerate() {
            let Some(frame) = memory::FrameLease::from_parts(
                X86_RUNTIME.ELF_PROBE_TLS_FRAMES[index].load(Ordering::SeqCst),
                X86_RUNTIME.ELF_PROBE_TLS_GENERATIONS[index].load(Ordering::SeqCst),
            ) else {
                let _ = release_linux_exec_frames(&mut exec_frames);
                return LINUX_ENOEXEC;
            };
            let address = thread_pointer & !(PAGE_SIZE as u64 - 1);
            let duplicate = active_image_mappings[..active_image_count + 2 + index]
                .iter()
                .any(|mapping| mapping.frame == frame || mapping.address == address as usize);
            let mapping_matches =
                address_space::current_linux_mapping_matches(address, frame, true, false);
            if duplicate || !mapping_matches {
                serial_write("linox: exec old TLS frame rejection: ");
                serial_write_u64(index as u64);
                serial_write(" ");
                serial_write_u64(address);
                serial_write(" ");
                serial_write_u64(frame.address());
                serial_write(" ");
                serial_write_u64(u64::from(duplicate));
                serial_write(" ");
                serial_write_u64(u64::from(mapping_matches));
                serial_write("\r\n");
                let _ = release_linux_exec_frames(&mut exec_frames);
                return LINUX_ENOEXEC;
            }
            let old_tls_page = address_space::current_linux_runtime_page(address);
            active_image_mappings[active_image_count + 2 + index] = LinuxActiveImageMapping {
                address: address as usize,
                frame,
                writable: true,
                executable: false,
                shared: old_tls_page.shared,
                dontfork: old_tls_page.dontfork,
            };
        }
    }
    if interpreted {
        let Some(frame) = memory::FrameLease::from_parts(
            X86_RUNTIME
                .ELF_PROBE_SIBLING_STACK_FRAME
                .load(Ordering::SeqCst),
            X86_RUNTIME
                .ELF_PROBE_SIBLING_STACK_GENERATION
                .load(Ordering::SeqCst),
        ) else {
            let _ = release_linux_exec_frames(&mut exec_frames);
            return LINUX_ENOEXEC;
        };
        let address = X86_RUNTIME.ELF_PROBE_SIBLING_STACK.load(Ordering::SeqCst);
        if address == 0
            || !(address as usize).is_multiple_of(PAGE_SIZE)
            || active_image_mappings[..active_image_count + 4]
                .iter()
                .any(|mapping| mapping.frame == frame || mapping.address == address as usize)
            || !address_space::current_linux_mapping_matches(address, frame, true, false)
        {
            let _ = release_linux_exec_frames(&mut exec_frames);
            return LINUX_ENOEXEC;
        }
        let old_sibling_stack_page = address_space::current_linux_runtime_page(address);
        active_image_mappings[active_image_count + 4] = LinuxActiveImageMapping {
            address: address as usize,
            frame,
            writable: true,
            executable: false,
            shared: old_sibling_stack_page.shared,
            dontfork: old_sibling_stack_page.dontfork,
        };
    }
    let clear_child_tid = current_linux_clear_child_tid().unwrap_or(0);
    let robust_list = current_linux_robust_list().unwrap_or(0);
    let mut previous_tid = [0_u8; size_of::<u32>()];
    if clear_child_tid != 0
        && (!copy_from_linux_user(clear_child_tid, &mut previous_tid)
            || !copy_to_linux_user(clear_child_tid, &0_u32.to_ne_bytes()))
    {
        let _ = release_linux_exec_frames(&mut exec_frames);
        return LINUX_EFAULT;
    }
    if !set_current_linux_clear_child_tid(0) || !set_current_linux_robust_list(0) {
        let _ = set_current_linux_clear_child_tid(clear_child_tid);
        let _ = set_current_linux_robust_list(robust_list);
        if clear_child_tid != 0 {
            let _ = copy_to_linux_user(clear_child_tid, &previous_tid);
        }
        let _ = release_linux_exec_frames(&mut exec_frames);
        return LINUX_ESRCH;
    }
    let image_replaced = if interpreted {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
            && current_linux_process_pid() >= 19
        {
            serial_write("linox: exec retained mappings pid/old/shared/stack/heap: ");
            serial_write_u64(u64::from(current_linux_process_pid()));
            serial_write("/");
            serial_write_u64(old_mapping_count as u64);
            serial_write("/");
            serial_write_u64(
                active_image_mappings[..old_mapping_count]
                    .iter()
                    .filter(|mapping| mapping.shared)
                    .count() as u64,
            );
            serial_write("/");
            serial_write_u64(u64::from(old_stack_page.shared));
            serial_write("/");
            serial_write_u64(u64::from(old_heap_page.shared));
            serial_write("\r\n");
        }
        replace_current_linux_image_with_hierarchy(
            &mappings[..transaction_mapping_count],
            &active_image_mappings[..old_mapping_count],
            6,
        )
    } else {
        replace_current_linux_image_with_hierarchy(
            &mappings[..transaction_mapping_count],
            &active_image_mappings[..old_mapping_count],
            5,
        )
    };
    if !image_replaced {
        let _ = set_current_linux_clear_child_tid(clear_child_tid);
        let _ = set_current_linux_robust_list(robust_list);
        if clear_child_tid != 0 {
            let _ = copy_to_linux_user(clear_child_tid, &previous_tid);
        }
        let _ = release_linux_exec_frames(&mut exec_frames);
        return LINUX_ENOMEM;
    }
    if let Some(frame) = exec_frames[mapping_count] {
        X86_RUNTIME
            .ELF_PROBE_STACK_FRAME
            .store(frame.address(), Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_STACK_GENERATION
            .store(frame.generation(), Ordering::SeqCst);
    }
    if let Some(frame) = exec_frames[mapping_count + 1] {
        X86_RUNTIME
            .ELF_PROBE_HEAP_FRAME
            .store(frame.address(), Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_HEAP_GENERATION
            .store(frame.generation(), Ordering::SeqCst);
    }
    if interpreted {
        for index in 0..2 {
            if let Some(frame) = exec_frames[mapping_count + 2 + index] {
                X86_RUNTIME.ELF_PROBE_TLS_FRAMES[index].store(frame.address(), Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_TLS_GENERATIONS[index]
                    .store(frame.generation(), Ordering::SeqCst);
            }
        }
        if let Some(frame) = exec_frames[mapping_count + 4] {
            X86_RUNTIME
                .ELF_PROBE_SIBLING_STACK_FRAME
                .store(frame.address(), Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_SIBLING_STACK_GENERATION
                .store(frame.generation(), Ordering::SeqCst);
        }
    }
    X86_RUNTIME.ELF_PROBE_BRK.store(heap_base, Ordering::SeqCst);
    let next_tls = interpreted_tls.map_or(
        LinuxTlsContext {
            thread_pointer: 0,
            extent: 0,
            extent_size: 0,
        },
        |(initial, _)| initial,
    );
    if !install_linux_tls_context(next_tls) {
        return LINUX_ENOMEM;
    }
    if let Some(slot) = current_linux_thread_slot() {
        X86_RUNTIME.LINUX_THREAD_POINTERS[slot]
            .store(next_tls.thread_pointer as u64, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_TLS_EXTENTS[slot].store(next_tls.extent as u64, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_TLS_SIZES[slot]
            .store(next_tls.extent_size as u64, Ordering::SeqCst);
    }
    if interpreted {
        serial_write("linox: interpreted Linux exec image committed\r\n");
    }
    for (index, mapping) in active_image_mappings[..active_image_count]
        .iter()
        .enumerate()
    {
        X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_ADDRESSES[index]
            .store(mapping.address as u64, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_FRAMES[index]
            .store(mapping.frame.address(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_GENERATIONS[index]
            .store(mapping.frame.generation(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_RETIRED_IMAGE_FLAGS[index].store(
            u8::from(mapping.writable) | (u8::from(mapping.executable) << 1),
            Ordering::SeqCst,
        );
    }
    X86_RUNTIME
        .ELF_PROBE_RETIRED_IMAGE_COUNT
        .store(active_image_count as u8, Ordering::SeqCst);
    if interpreted {
        X86_RUNTIME
            .ELF_PROBE_MAIN_MAPPINGS
            .store(0, Ordering::SeqCst);
        for index in 0..LINUX_MAIN_MAPPING_COUNT {
            X86_RUNTIME.ELF_PROBE_MAIN_FRAMES[index].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_MAIN_GENERATIONS[index].store(0, Ordering::SeqCst);
        }
        for dependency in 0..LINUX_DEPENDENCY_COUNT {
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_MAPPINGS[dependency].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_DEPENDENCY_SELECTED_BASE[dependency].store(0, Ordering::SeqCst);
            for index in 0..LINUX_DEPENDENCY_MAPPING_COUNT {
                let state = dependency * LINUX_DEPENDENCY_MAPPING_COUNT + index;
                X86_RUNTIME.ELF_PROBE_DEPENDENCY_FRAMES[state].store(0, Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_DEPENDENCY_GENERATIONS[state].store(0, Ordering::SeqCst);
            }
        }
        X86_RUNTIME
            .ELF_PROBE_READ_ONLY_DATA_PAGE
            .store(0, Ordering::SeqCst);
    }
    unshare_linux_state_for_exec(current_linux_process_pid());
    for descriptor in 0..LINUX_AUX_DESCRIPTOR_LIMIT {
        if linux_descriptor_close_on_exec(descriptor) {
            let _ = linux_descriptor_close(descriptor);
        }
    }
    linux_close_overflow_on_exec();
    end_other_linux_threads_for_exec();
    reset_linux_signal_state_after_exec();
    X86_RUNTIME
        .ELF_PROBE_MEMBARRIER_REGISTRATIONS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_LOW
        .store(process_name[0], Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PROCESS_NAME_HIGH
        .store(process_name[1], Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EXITED_CLEAR_CHILD_TID
        .store(clear_child_tid, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EXITED_ROBUST_LIST
        .store(robust_list, Ordering::SeqCst);
    let runtime_plan = interpreted_exec_plan
        .as_ref()
        .map_or(exec_plan, |plan| &plan.process.main);
    X86_RUNTIME
        .ELF_PROBE_CODE_BASE
        .store(runtime_plan.executable.virtual_page, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_CODE_SIZE.store(
        (runtime_plan.executable.page_count * PAGE_SIZE) as u64,
        Ordering::SeqCst,
    );
    X86_RUNTIME.ELF_PROBE_LOADER_CODE_BASE.store(
        if interpreted {
            exec_plan.executable.virtual_page
        } else {
            0
        },
        Ordering::SeqCst,
    );
    X86_RUNTIME.ELF_PROBE_LOADER_CODE_SIZE.store(
        if interpreted {
            (exec_plan.executable.page_count * PAGE_SIZE) as u64
        } else {
            0
        },
        Ordering::SeqCst,
    );
    X86_RUNTIME
        .ELF_PROBE_DATA
        .store(runtime_plan.writable.virtual_page, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_DATA_SIZE.store(
        (runtime_plan.writable.page_count * PAGE_SIZE) as u64,
        Ordering::SeqCst,
    );
    X86_RUNTIME.ELF_PROBE_RELRO.store(
        runtime_plan.relro.map_or(0, |relro| relro.virtual_address),
        Ordering::SeqCst,
    );
    X86_RUNTIME.ELF_PROBE_RELRO_SIZE.store(
        runtime_plan.relro.map_or(0, |relro| relro.memory_size),
        Ordering::SeqCst,
    );
    unsafe {
        let entry_state = &mut *current_entry_state();
        entry_state.user_rip = entry;
        entry_state.user_rsp = new_stack;
    }
    X86_RUNTIME
        .ELF_PROBE_EXEC_NODE
        .store(exec_node, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EXEC_ENTRY
        .store(entry, Ordering::SeqCst);
    for (index, (frame, mapping)) in exec_frames[..mapping_count]
        .iter()
        .flatten()
        .zip(&mappings[..mapping_count])
        .enumerate()
    {
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_ADDRESSES[index]
            .store(mapping.address as u64, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_FRAMES[index].store(frame.address(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_GENERATIONS[index]
            .store(frame.generation(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_EXEC_MAPPING_FLAGS[index].store(
            u8::from(mapping.writable) | (u8::from(mapping.executable) << 1),
            Ordering::SeqCst,
        );
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[index]
            .store(mapping.address as u64, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index].store(frame.address(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index]
            .store(frame.generation(), Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].store(
            u8::from(mapping.writable) | (u8::from(mapping.executable) << 1),
            Ordering::SeqCst,
        );
    }
    for index in mapping_count..LINUX_ACTIVE_IMAGE_MAPPING_LIMIT {
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FLAGS[index].store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_ACTIVE_IMAGE_COUNT
        .store(mapping_count as u16, Ordering::SeqCst);
    let Some(snapshot) = live_linux_process_address_space_snapshot() else {
        return LINUX_ENOMEM;
    };
    if !linux_process::refresh_live_process_registry(
        current_linux_process_pid(),
        snapshot,
        [0; 15],
        entry,
        new_stack,
        0x202,
        next_tls.thread_pointer as u64,
    ) {
        return LINUX_ESRCH;
    }
    X86_RUNTIME
        .ELF_PROBE_EXEC_REPLACED
        .store(true, Ordering::SeqCst);
    let _ = linux_process::mark_live_process_executed(current_linux_process_pid());
    serial_write("linox: measured Linux exec image replaced atomically\r\n");
    0
}

fn reset_linux_signal_state_after_exec() {
    let ignored_signals = (0..LINUX_SIGNAL_COUNT).fold(0_u64, |mask, signal| {
        mask | (u64::from(
            X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal].load(Ordering::SeqCst) == 1,
        ) << signal)
    });
    X86_RUNTIME
        .ELF_PROBE_EXEC_IGNORED_SIGNALS
        .store(ignored_signals, Ordering::SeqCst);
    for signal in 0..LINUX_SIGNAL_COUNT {
        if X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal].load(Ordering::SeqCst) != 1 {
            X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[signal].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[signal].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[signal].store(0, Ordering::SeqCst);
        }
    }
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_POINTER
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_SIZE
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_FLAGS
        .store(LINUX_SS_DISABLE, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_ACTIVE
        .store(false, Ordering::SeqCst);
    unsafe { linux_signal_context().get().write(LinuxSignalContext::ZERO) };
}
