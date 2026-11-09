//! Plain old data: types whose values are their bytes, viewed as byte
//! slices to copy them to and from user memory.
//!
//! A [`Pod`] type has no padding and every bit pattern of its size is a
//! valid value, so [`bytes_of`] (reading its bytes) never reads an
//! uninitialized byte and [`bytes_of_mut`] (writing any bytes into it)
//! never makes an invalid value. The integers and arrays of `Pod` are
//! `Pod`; a struct becomes `Pod` only through this module's `pod!`, which
//! checks at compile time that every field is listed, that each is `Pod`,
//! and that the field sizes add up to the struct's size (no padding).

/// Plain old data (see the module comment).
///
/// # Safety
///
/// No padding, and every bit pattern of `size_of::<Self>()` bytes is a
/// valid value. Implement it for a struct only through this module's
/// `pod!`.
pub(crate) unsafe trait Pod: Copy + 'static {}

// SAFETY: integers have no padding and accept every bit pattern.
unsafe impl Pod for u8 {}
// SAFETY: as for u8.
unsafe impl Pod for u16 {}
// SAFETY: as for u8.
unsafe impl Pod for u32 {}
// SAFETY: as for u8.
unsafe impl Pod for u64 {}
// SAFETY: as for u8.
unsafe impl Pod for i32 {}
// SAFETY: as for u8.
unsafe impl Pod for i64 {}
// SAFETY: an array of `Pod` elements has no padding between them (an
// element's size is a multiple of its alignment) and accepts every bit
// pattern its elements do.
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

/// The bytes of `value`.
pub(crate) fn bytes_of<T: Pod>(value: &T) -> &[u8] {
    // SAFETY: `T: Pod` has no padding, so all its bytes are initialized;
    // the slice covers exactly `value` and borrows it.
    unsafe { core::slice::from_raw_parts(core::ptr::from_ref(value).cast::<u8>(), size_of::<T>()) }
}

/// The bytes of `value`, to write any bytes into it.
pub(crate) fn bytes_of_mut<T: Pod>(value: &mut T) -> &mut [u8] {
    // SAFETY: as in `bytes_of`; every bit pattern is a valid `T`, so any
    // bytes written leave a valid value, and the slice borrows `value`
    // exclusively.
    unsafe {
        core::slice::from_raw_parts_mut(core::ptr::from_mut(value).cast::<u8>(), size_of::<T>())
    }
}

/// Makes a struct [`Pod`] after checking at compile time that the fields
/// listed are all of its fields (an exhaustive pattern), each of the type
/// given and itself `Pod`, and that their sizes add up to the struct's (so
/// it has no padding):
///
/// ```ignore
/// pod!(Point { x: u32, y: u32 });
/// ```
///
/// Local to this module: the kernel's `Pod` structs are all listed below,
/// so no module outside the trusted core implements it.
macro_rules! pod {
    ($type:ident { $($field:ident : $field_type:ty),+ $(,)? }) => {
        const _: () = {
            assert!(
                ::core::mem::size_of::<$type>() == 0 $(+ ::core::mem::size_of::<$field_type>())+,
                "a Pod struct has padding"
            );
            fn is_pod<T: Pod>() {}
            #[allow(dead_code)]
            fn fields_are_pod() {
                $(is_pod::<$field_type>();)+
            }
            #[allow(dead_code)]
            fn fields_are_listed(value: $type) {
                let $type { $($field),+ } = value;
                $(let _: $field_type = $field;)+
            }
        };
        // SAFETY: the checks above: every field is listed with its type,
        // each is `Pod`, and their sizes fill the struct, so it has no
        // padding and every bit pattern is a valid value.
        unsafe impl Pod for $type {}
    };
}

// The Linux signal frame's layouts (arch/x86_64/cpu.rs), which signal
// delivery and sigreturn copy to and from user memory as bytes.
use crate::arch::x86_64::cpu::{
    LinuxRtSignalFrame, LinuxSignalInformation, LinuxSignalMachineContext, LinuxSignalStack,
    LinuxSignalUserContext,
};

pod!(LinuxSignalStack {
    pointer: u64,
    flags: u32,
    padding: u32,
    size: u64,
});
pod!(LinuxSignalMachineContext {
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rax: u64,
    rcx: u64,
    rsp: u64,
    rip: u64,
    rflags: u64,
    cs: u16,
    gs: u16,
    fs: u16,
    ss: u16,
    error: u64,
    trap: u64,
    old_mask: u64,
    cr2: u64,
    fpstate: u64,
    reserved: [u64; 8],
});
pod!(LinuxSignalUserContext {
    flags: u64,
    link: u64,
    stack: LinuxSignalStack,
    machine: LinuxSignalMachineContext,
    signal_mask: u64,
});
pod!(LinuxSignalInformation {
    signal: i32,
    error: i32,
    code: i32,
    padding: i32,
    fields: [u8; 112],
});
pod!(LinuxRtSignalFrame {
    restorer: u64,
    context: LinuxSignalUserContext,
    information: LinuxSignalInformation,
});
