#![forbid(unsafe_code)]
//! The initial stack of a Linux process, laid out in a page image.
//!
//! From the top of the page down: the argument strings (each with a
//! terminating NUL, the first argument lowest), the environment strings
//! (likewise), the platform string, the random bytes `AT_RANDOM` points
//! at, and then, 16-byte aligned, the words the program starts with:
//! `argc`, the argument pointers and a null, the environment pointers and
//! a null, and the auxiliary vector (System V x86-64 ABI §3.4.1, as Linux's
//! `create_elf_tables` arranges it).
//!
//! This is pure layout arithmetic over a byte slice, so it can be tested on
//! the host; the kernel copies the finished image into the stack frame in
//! one piece.

#![no_std]

/// Where `build` put the strings the auxiliary vector points at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Addresses {
    /// The argument the program was executed as (`AT_EXECFN`).
    pub execfn: u64,
    /// The platform string (`AT_PLATFORM`).
    pub platform: u64,
    /// The random bytes (`AT_RANDOM`).
    pub random: u64,
}

/// What a process starts with on its stack.
#[derive(Clone, Copy, Debug)]
pub struct Contents<'a> {
    /// The arguments, without their NULs.
    pub arguments: &'a [&'a [u8]],
    /// The index in `arguments` of the one the program was executed as.
    pub execfn: usize,
    /// The environment strings, without their NULs.
    pub environment: &'a [&'a [u8]],
    /// The platform string, copied as given (with its NUL).
    pub platform: &'a [u8],
    /// The random bytes for `AT_RANDOM`.
    pub random: &'a [u8],
}

/// Lays out `contents` as an initial stack in `page`, which is mapped at
/// `base`, and returns the offset of `argc` in it, the stack pointer the
/// program starts with. `auxiliary` builds the auxiliary vector from the
/// strings' addresses. Bytes of `page` outside the layout are left as they
/// are. None when the layout does not fit the page or `execfn` names no
/// argument.
pub fn build<const A: usize>(
    page: &mut [u8],
    base: u64,
    contents: &Contents<'_>,
    auxiliary: impl FnOnce(Addresses) -> [u64; A],
) -> Option<usize> {
    let Contents {
        arguments,
        execfn,
        environment,
        platform,
        random,
    } = *contents;
    if execfn >= arguments.len() {
        return None;
    }
    let address = |offset: usize| base.checked_add(u64::try_from(offset).ok()?);
    // Strings from the top of the page down, the last one highest.
    let strings = |values: &[&[u8]], top: usize| -> Option<usize> {
        values.iter().try_fold(top, |top, value| {
            top.checked_sub(value.len().checked_add(1)?)
        })
    };
    let arguments_start = strings(arguments, page.len())?;
    let environment_start = strings(environment, arguments_start)?;
    let platform_offset = environment_start.checked_sub(platform.len())?;
    let random_offset = platform_offset.checked_sub(random.len())?;
    let words = arguments
        .len()
        .checked_add(environment.len())?
        .checked_add(3)?
        .checked_add(A)?;
    let stack_offset = random_offset.checked_sub(words.checked_mul(8)?)? & !15;

    let mut put_strings = |values: &[&[u8]], start: usize| -> Option<usize> {
        let mut offset = start;
        for value in values {
            page.get_mut(offset..offset + value.len())?
                .copy_from_slice(value);
            *page.get_mut(offset + value.len())? = 0;
            offset += value.len() + 1;
        }
        Some(offset)
    };
    put_strings(arguments, arguments_start)?;
    put_strings(environment, environment_start)?;
    page.get_mut(platform_offset..environment_start)?
        .copy_from_slice(platform);
    page.get_mut(random_offset..platform_offset)?
        .copy_from_slice(random);

    let execfn_offset = string_offsets(arguments, arguments_start).nth(execfn)?;
    let auxiliary = auxiliary(Addresses {
        execfn: address(execfn_offset)?,
        platform: address(platform_offset)?,
        random: address(random_offset)?,
    });
    let mut offset = stack_offset;
    let mut put_word = |value: Option<u64>| -> Option<()> {
        page.get_mut(offset..offset + 8)?
            .copy_from_slice(&value?.to_ne_bytes());
        offset += 8;
        Some(())
    };
    put_word(u64::try_from(arguments.len()).ok())?;
    for offset in string_offsets(arguments, arguments_start) {
        put_word(address(offset))?;
    }
    put_word(Some(0))?;
    for offset in string_offsets(environment, environment_start) {
        put_word(address(offset))?;
    }
    put_word(Some(0))?;
    for value in auxiliary {
        put_word(Some(value))?;
    }
    Some(stack_offset)
}

/// The offsets of `values` laid out one after another from `start`, each
/// followed by its NUL.
fn string_offsets<'a>(values: &'a [&'a [u8]], start: usize) -> impl Iterator<Item = usize> + 'a {
    values.iter().scan(start, |offset, value| {
        let at = *offset;
        *offset += value.len() + 1;
        Some(at)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 4096;
    const BASE: u64 = 0x88_0000;

    fn word(page: &[u8], offset: usize) -> u64 {
        u64::from_ne_bytes(page[offset..offset + 8].try_into().unwrap())
    }

    /// The layout the kernel used to write by hand for init: arguments in
    /// reverse from the top, then PWD, PATH, the platform and the random
    /// bytes, then the words.
    fn reference(arguments: &[&[u8]], execfn: usize) -> ([u8; PAGE], usize) {
        let path: &[u8] = b"PATH=/bin:/usr/bin:/sbin:/usr/sbin\0";
        let pwd: &[u8] = b"PWD=/\0";
        let platform: &[u8] = b"x86_64\0";
        let random = [7_u8; 16];
        let mut stack = [0x55_u8; PAGE];
        let mut offsets = [0; 3];
        let mut string_offset = PAGE;
        for index in (0..arguments.len()).rev() {
            let value = arguments[index];
            string_offset -= value.len() + 1;
            stack[string_offset..string_offset + value.len()].copy_from_slice(value);
            stack[string_offset + value.len()] = 0;
            offsets[index] = string_offset;
        }
        let pwd_offset = string_offset - pwd.len();
        let path_offset = pwd_offset - path.len();
        let platform_offset = path_offset - platform.len();
        let random_offset = platform_offset - random.len();
        let words = arguments.len() + 5 + 4;
        let stack_offset = (random_offset - words * 8) & !15;
        stack[path_offset..pwd_offset].copy_from_slice(path);
        stack[pwd_offset..string_offset].copy_from_slice(pwd);
        stack[platform_offset..platform_offset + platform.len()].copy_from_slice(platform);
        stack[random_offset..platform_offset].copy_from_slice(&random);
        let address = |offset: usize| BASE + offset as u64;
        let values = [arguments.len() as u64]
            .into_iter()
            .chain(
                offsets[..arguments.len()]
                    .iter()
                    .map(|offset| address(*offset)),
            )
            .chain([0, address(path_offset), address(pwd_offset), 0])
            .chain([
                31,
                address(offsets[execfn]),
                15,
                address(platform_offset) ^ address(random_offset),
            ]);
        for (index, value) in values.enumerate() {
            let offset = stack_offset + index * 8;
            stack[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
        (stack, stack_offset)
    }

    fn built(arguments: &[&[u8]], execfn: usize) -> ([u8; PAGE], usize) {
        let mut stack = [0x55_u8; PAGE];
        let offset = build(
            &mut stack,
            BASE,
            &Contents {
                arguments,
                execfn,
                environment: &[b"PATH=/bin:/usr/bin:/sbin:/usr/sbin", b"PWD=/"],
                platform: b"x86_64\0",
                random: &[7; 16],
            },
            |addresses| {
                [
                    31,
                    addresses.execfn,
                    15,
                    addresses.platform ^ addresses.random,
                ]
            },
        )
        .unwrap();
        (stack, offset)
    }

    #[test]
    fn matches_the_hand_written_layout() {
        for (arguments, execfn) in [
            (&[b"/sbin/init" as &[u8]][..], 0),
            (&[b"/bin/sh" as &[u8], b"/etc/rc"][..], 1),
            (&[b"/usr/bin/env" as &[u8], b"-S", b"/init"][..], 2),
        ] {
            assert_eq!(built(arguments, execfn), reference(arguments, execfn));
        }
    }

    #[test]
    fn words_are_aligned_and_counted() {
        let (stack, offset) = built(&[b"/a" as &[u8], b"bc"], 0);
        assert_eq!(offset % 16, 0);
        assert_eq!(word(&stack, offset), 2);
        assert_eq!(word(&stack, offset + 3 * 8), 0);
        assert_eq!(word(&stack, offset + 6 * 8), 0);
        assert_eq!(word(&stack, offset + 7 * 8), 31);
        let execfn = word(&stack, offset + 8 * 8) - BASE;
        assert_eq!(&stack[execfn as usize..execfn as usize + 3], b"/a\0");
    }

    #[test]
    fn refuses_what_does_not_fit() {
        fn contents<'a>(arguments: &'a [&'a [u8]], execfn: usize) -> Contents<'a> {
            Contents {
                arguments,
                execfn,
                environment: &[],
                platform: b"",
                random: &[],
            }
        }
        let long = [b'x'; 60];
        assert_eq!(
            build(&mut [0_u8; 64], BASE, &contents(&[&long], 0), |_| [0_u64;
                0]),
            None
        );
        assert_eq!(
            build(&mut [0_u8; PAGE], BASE, &contents(&[b"/a"], 1), |_| [0_u64;
                0]),
            None
        );
    }
}
