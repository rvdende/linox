//! The bring-up shell's `log` command: pages through everything the kernel
//! wrote since it started (the kernel log ring, `crate::kernel_log`), one
//! screen at a time, so lines that scrolled off can still be read and
//! photographed.

use core::fmt::Write;

use crate::drivers::Screen;
use crate::kernel_log;

/// Page starts remembered for paging backwards.
const HISTORY: usize = 512;
/// The longest line shown in full; longer ones are cut.
const LINE_LIMIT: usize = 1024;

/// Pages through the log. `key` blocks for the next key press. With
/// `from_end`, starts on the last page.
pub(crate) fn page(mut key: impl FnMut() -> u8, from_end: bool) {
    let (columns, rows) = crate::framebuffer::text_size().unwrap_or((100, 40));
    let columns = columns.max(20);
    // Each page starts on a cleared screen and leaves the last row for the
    // prompt, so nothing scrolls away while it is read.
    let page_rows = rows.saturating_sub(1).max(4);
    let (oldest, end) = kernel_log::extent();
    if oldest == end {
        let _ = writeln!(Screen, "the log is empty");
        return;
    }
    let first = line_start_at_or_after(oldest, end);
    let mut history = [0_u64; HISTORY];
    let mut pages = 0;
    let mut position = if from_end {
        last_page_start(first, end, columns, page_rows)
    } else {
        first
    };
    loop {
        if pages < HISTORY {
            history[pages] = position;
            pages += 1;
        }
        let next = show_page(position, end, columns, page_rows);
        let percent = (next - first) * 100 / (end - first).max(1);
        let _ = write!(
            Screen,
            "-- log {percent}% -- Enter/Space: next page, b: back, q: quit --"
        );
        let pressed = key();
        // Erase the prompt line before whatever comes next.
        let _ = write!(Screen, "\r\x1b[K");
        match pressed {
            b'q' | b'Q' | 0x03 | 0x1b => return,
            b'b' | b'B' => {
                // Back to the page before the one just shown.
                pages = pages.saturating_sub(2);
                position = history[pages];
            }
            _ if next >= end => {
                let _ = writeln!(Screen, "-- end of log --");
                return;
            }
            _ => position = next,
        }
    }
}

/// Shows the lines from `position` that fit in `page_rows` rows; returns
/// where the next page starts.
fn show_page(mut position: u64, end: u64, columns: usize, page_rows: usize) -> u64 {
    let _ = Screen.write_str("\x1b[2J\x1b[H");
    let mut used = 0;
    let mut line = [0_u8; LINE_LIMIT];
    while position < end {
        let (length, next) = read_line(position, end, &mut line);
        let needed = length.max(1).div_ceil(columns);
        if used + needed > page_rows && used > 0 {
            break;
        }
        let shown = length.min(LINE_LIMIT).min(page_rows * columns);
        let text = &line[..shown];
        // The log holds only what the kernel printed; show other bytes as dots.
        for chunk in text.split(|byte| !(0x20..0x7f).contains(byte)) {
            let _ = Screen.write_str(core::str::from_utf8(chunk).unwrap_or(""));
            if chunk.as_ptr_range().end != text.as_ptr_range().end {
                let _ = Screen.write_str(".");
            }
        }
        let _ = writeln!(Screen);
        used += needed;
        position = next;
    }
    position
}

/// Copies the line at `position` (without its newline) into `line` as far as
/// it fits; returns its full length and where the next line starts.
fn read_line(position: u64, end: u64, line: &mut [u8]) -> (usize, u64) {
    let mut at = position;
    while at < end {
        match kernel_log::byte(at) {
            Some(b'\n') | None => break,
            Some(byte) => {
                if let Some(slot) = line.get_mut((at - position) as usize) {
                    *slot = byte;
                }
            }
        }
        at += 1;
    }
    ((at - position) as usize, (at + 1).min(end))
}

/// The start of the first whole line at or after `position`.
fn line_start_at_or_after(position: u64, end: u64) -> u64 {
    if position == 0 || kernel_log::byte(position - 1) == Some(b'\n') {
        return position;
    }
    (position..end)
        .find(|at| kernel_log::byte(*at) == Some(b'\n'))
        .map_or(end, |newline| newline + 1)
}

/// The start of a page that ends with the log's last line.
fn last_page_start(first: u64, end: u64, columns: usize, page_rows: usize) -> u64 {
    let mut start = end;
    let mut used = 0;
    while start > first {
        // The line before `start` begins after the newline before it.
        let line_end = start - 1;
        let mut line_start = line_end;
        while line_start > first && kernel_log::byte(line_start - 1) != Some(b'\n') {
            line_start -= 1;
        }
        let needed = ((line_end - line_start) as usize).max(1).div_ceil(columns);
        if used + needed > page_rows {
            break;
        }
        used += needed;
        start = line_start;
    }
    start
}
