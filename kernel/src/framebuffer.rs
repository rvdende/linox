#![forbid(unsafe_code)]
//! Text console on the linear framebuffer left active by UEFI.
//!
//! Physical machines rarely expose a serial port, so every byte written to the
//! serial console is mirrored here. The console keeps a model of the text grid
//! and redraws only the cells that changed, so scrolling never reads from video
//! memory. It understands the subset of ANSI escape sequences that the
//! controller, BusyBox, and bash emit: SGR colours, cursor positioning, and
//! screen and line erasure.
//!
//! The same console and /dev/fb0 also run on a virtio-gpu surface, which
//! [`adopt`] moves them to during boot. Such a surface is guest memory the
//! host copies only when told, so the console reports each rectangle it
//! draws to the GPU driver, and the Linux timer tick calls [`refresh`] so
//! that the driver can flush what a domain draws through /dev/fb0.
//!
//! Pixels go through a `trusted::pixels::PixelBuffer`, which checks every
//! access against the surface. The console's state is claimed by one
//! context at a time (`trusted::claim::ClaimCell`): output arriving while
//! it is busy, for example from an exception handler, is dropped rather
//! than interleaved. Each surface is published once, with the display mode
//! /dev/fb0 reports, so that /dev/fb0 copies need no claim.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use font8x8::legacy::BASIC_LEGACY;
use linox_virtio_gpu::Rect;

use crate::owned_state::OwnedState;
use crate::trusted::claim::ClaimCell;
use crate::trusted::crash::FatalReport;
use crate::trusted::pixels::PixelBuffer;
use crate::{BootFramebuffer, FRAMEBUFFER_FORMAT_BGRX, FRAMEBUFFER_FORMAT_RGBX};

const GLYPH_SIZE: usize = 8;
const MAX_COLUMNS: usize = 320;
const MAX_ROWS: usize = 160;
const MAX_CSI_PARAMETERS: usize = 8;
const DEFAULT_FOREGROUND: u8 = 7;
const DEFAULT_BACKGROUND: u8 = 0;
const TARGET_ROWS: usize = 50;
/// Surfaces a boot publishes: the firmware's framebuffer, its kernel
/// mapping, and a virtio-gpu surface, with one to spare.
const SURFACE_LIMIT: usize = 4;

/// The sixteen VGA colours as 0xRRGGBB.
const PALETTE: [u32; 16] = [
    0x000000, 0xaa0000, 0x00aa00, 0xaa5500, 0x0000aa, 0xaa00aa, 0x00aaaa, 0xaaaaaa, 0x555555,
    0xff5555, 0x55ff55, 0xffff55, 0x5555ff, 0xff55ff, 0x55ffff, 0xffffff,
];

#[derive(Clone, Copy, Eq, PartialEq)]
struct Cell {
    glyph: u8,
    foreground: u8,
    background: u8,
}

const BLANK: Cell = Cell {
    glyph: b' ',
    foreground: DEFAULT_FOREGROUND,
    background: DEFAULT_BACKGROUND,
};

/// The bounding box of the pixels drawn since the console last presented.
#[derive(Clone, Copy)]
struct Bounds {
    left: usize,
    top: usize,
    right: usize,
    bottom: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Escape {
    None,
    Started,
    Charset,
    Csi,
}

struct Console {
    pixels: PixelBuffer,
    width: usize,
    height: usize,
    stride: usize,
    bgrx: bool,
    scale: usize,
    columns: usize,
    rows: usize,
    column: usize,
    row: usize,
    foreground: u8,
    background: u8,
    bold: bool,
    escape: Escape,
    parameters: [u16; MAX_CSI_PARAMETERS],
    parameter_count: usize,
    cells: [[Cell; MAX_COLUMNS]; MAX_ROWS],
    drawn: [[Cell; MAX_COLUMNS]; MAX_ROWS],
    damage: Option<Bounds>,
    /// Lines to scroll at once when output reaches the bottom: 1, or a
    /// quarter of the screen in jump-scroll mode.
    jump_scroll: bool,
}

static READY: AtomicBool = AtomicBool::new(false);
/// Set while a domain draws to the framebuffer through /dev/fb0; the console
/// keeps its text model but stops drawing until the screen is handed back.
static OWNED: AtomicBool = AtomicBool::new(false);

/// How pixels written to the framebuffer reach the screen.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Scanout {
    /// The firmware's framebuffer, which the display hardware reads by
    /// itself.
    Firmware,
    /// A virtio-gpu resource's backing, which the host copies to the
    /// screen only when the driver flushes it.
    VirtioGpu,
}

/// The framebuffer as /dev/fb0 describes it to Linux programs.
#[derive(Clone, Copy)]
pub(crate) struct Display {
    pub(crate) physical: u64,
    pub(crate) width: u32,
    pub(crate) height: u32,
    /// Bytes per scan line.
    pub(crate) line_length: u32,
    pub(crate) length: usize,
    pub(crate) bgrx: bool,
    pub(crate) scanout: Scanout,
}

/// A display mode and the pixels that show it.
#[derive(Clone, Copy)]
struct Surface {
    display: Display,
    pixels: PixelBuffer,
}

/// The surfaces published during boot (by [`init`], [`relocate`] and
/// [`adopt`]), each once; [`CURRENT_SURFACE`] names the one in use.
static SURFACES: [OwnedState<Surface>; SURFACE_LIMIT] =
    [const { OwnedState::empty() }; SURFACE_LIMIT];
/// One more than the index of the surface in use, or 0 for none.
static CURRENT_SURFACE: AtomicUsize = AtomicUsize::new(0);

static CONSOLE: ClaimCell<Console> = ClaimCell::new(Console {
    pixels: PixelBuffer::EMPTY,
    width: 0,
    height: 0,
    stride: 0,
    bgrx: true,
    scale: 1,
    columns: 0,
    rows: 0,
    column: 0,
    row: 0,
    foreground: DEFAULT_FOREGROUND,
    background: DEFAULT_BACKGROUND,
    bold: false,
    escape: Escape::None,
    parameters: [0; MAX_CSI_PARAMETERS],
    parameter_count: 0,
    cells: [[BLANK; MAX_COLUMNS]; MAX_ROWS],
    drawn: [[BLANK; MAX_COLUMNS]; MAX_ROWS],
    damage: None,
    jump_scroll: false,
});

/// Makes `surface` the one /dev/fb0 and [`display`] report. Whether a
/// slot was left for it.
fn publish(surface: Surface) -> bool {
    let Some(index) = SURFACES
        .iter()
        .position(|slot| slot.try_install(surface).is_ok())
    else {
        return false;
    };
    CURRENT_SURFACE.store(index + 1, Ordering::Release);
    true
}

/// The surface in use, if any.
fn surface() -> Option<Surface> {
    let index = CURRENT_SURFACE.load(Ordering::Acquire).checked_sub(1)?;
    SURFACES.get(index)?.get().copied()
}

/// Returns the byte length a framebuffer description covers, or `None` when
/// the description is absent, unsupported, or inconsistent.
pub(crate) fn mapped_length(info: &BootFramebuffer) -> Option<usize> {
    if !matches!(
        info.format,
        FRAMEBUFFER_FORMAT_RGBX | FRAMEBUFFER_FORMAT_BGRX
    ) || info.base == 0
        || info.width == 0
        || info.height == 0
        || info.stride < info.width
    {
        return None;
    }
    let length = (info.stride as usize)
        .checked_mul(info.height as usize)?
        .checked_mul(4)?;
    (length as u64 <= info.size).then_some(length)
}

/// Starts the console on the framebuffer `info` describes, which `pixels`
/// covers.
pub(crate) fn init(info: &BootFramebuffer, pixels: PixelBuffer) -> bool {
    let Some(length) = mapped_length(info) else {
        return false;
    };
    if pixels.len() < length {
        return false;
    }
    let Some(mut console) = CONSOLE.try_claim() else {
        return false;
    };
    let display = Display {
        physical: info.base,
        width: info.width,
        height: info.height,
        line_length: info.stride * 4,
        length,
        bgrx: info.format == FRAMEBUFFER_FORMAT_BGRX,
        scanout: Scanout::Firmware,
    };
    if !publish(Surface { display, pixels }) {
        return false;
    }
    console.attach(&display, pixels);
    console.column = 0;
    console.row = 0;
    console.reset_attributes();
    console.escape = Escape::None;
    console.clear_all();
    let (width, height) = (console.width, console.height);
    console.fill(0, 0, width, height, DEFAULT_BACKGROUND);
    for row in 0..console.rows {
        let columns = console.columns;
        console.drawn[row][..columns].fill(BLANK);
    }
    console.damage = None;
    drop(console);
    READY.store(true, Ordering::Release);
    true
}

/// Moves the console and /dev/fb0 to another surface, such as a virtio-gpu
/// resource's backing that `pixels` covers, and repaints the console's text
/// there. Called during boot, before Linux programs run, with or without a
/// firmware framebuffer in use before it.
pub(crate) fn adopt(display: Display, pixels: PixelBuffer) -> bool {
    let rows = display.height as usize;
    let valid = display.width as usize >= GLYPH_SIZE
        && rows >= GLYPH_SIZE
        && display.line_length >= display.width.saturating_mul(4)
        && (display.line_length as usize)
            .checked_mul(rows)
            .is_some_and(|needed| needed <= display.length)
        && display.physical.is_multiple_of(4096)
        && pixels.len() >= display.length;
    if !valid {
        return false;
    }
    let Some(mut console) = CONSOLE.try_claim() else {
        return false;
    };
    if !publish(Surface { display, pixels }) {
        return false;
    }
    console.attach(&display, pixels);
    console.repaint();
    let damage = console.damage.take();
    drop(console);
    READY.store(true, Ordering::Release);
    if let Some(damage) = damage {
        present(damage);
    }
    true
}

/// Moves the console to `pixels`, a new mapping of the framebuffer passed
/// to [`init`] (the kernel's own, once its page tables are live).
pub(crate) fn relocate(pixels: PixelBuffer) {
    let Some(mut console) = CONSOLE.try_claim() else {
        return;
    };
    if let Some(Surface { display, .. }) = surface() {
        if pixels.len() < display.length || !publish(Surface { display, pixels }) {
            return;
        }
    }
    console.pixels = pixels;
}

/// Mirrors console output. Output arriving while the console is busy, for
/// example from an exception handler, is dropped rather than interleaved.
pub(crate) fn write(bytes: &[u8]) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    // READY guarantees that init published the surface the console draws.
    let Some(mut console) = CONSOLE.try_claim() else {
        return;
    };
    let owned = OWNED.load(Ordering::Acquire);
    if !owned {
        console.hide_cursor();
    }
    for byte in bytes.iter().copied() {
        console.byte(byte);
    }
    if !owned {
        console.show_cursor();
    }
    let damage = console.damage.take();
    drop(console);
    if let Some(damage) = damage {
        present(damage);
    }
}

/// Releases the console after a fatal exception or panic that may have
/// struck while it was drawing, so the crash report still reaches the
/// screen. The text model may be mid-update; a report is worth more. Only
/// a crash report has a [`FatalReport`] (`trusted::crash::recover_console`).
pub(crate) fn recover(report: &FatalReport) {
    OWNED.store(false, Ordering::Release);
    CONSOLE.release_abandoned(report);
}

/// Scrolls a quarter of the screen at a time instead of one line. Each
/// scroll redraws most of the screen, and a large framebuffer in an
/// uncached PCI BAR (as firmware leaves it on a physical PC) takes a
/// noticeable fraction of a second per redraw; bring-up mode turns this on
/// so that its long report scrolls in a few redraws, not hundreds.
pub(crate) fn set_jump_scroll(enabled: bool) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    if let Some(mut console) = CONSOLE.try_claim() {
        console.jump_scroll = enabled;
    }
}

/// Stops drawing for good, after drawing itself faulted.
pub(crate) fn abandon() {
    READY.store(false, Ordering::Release);
}

/// The console's text grid as (columns, rows), once it is drawing.
pub(crate) fn text_size() -> Option<(usize, usize)> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    let console = CONSOLE.try_claim()?;
    Some((console.columns, console.rows))
}

/// Whether a Linux program currently draws to the screen through /dev/fb0.
pub(crate) fn owned() -> bool {
    OWNED.load(Ordering::Acquire)
}

/// The framebuffer /dev/fb0 exposes: the firmware's, a virtio-gpu
/// surface, or none.
pub(crate) fn display() -> Option<Display> {
    surface().map(|surface| surface.display)
}

/// Makes `damage` of the screen visible. The firmware framebuffer is on
/// screen as soon as it is written; a virtio-gpu surface is flushed.
fn present(damage: Bounds) {
    if let Some(Display {
        scanout: Scanout::VirtioGpu,
        ..
    }) = display()
    {
        crate::drivers::virtio_gpu::present(Rect {
            x: damage.left as u32,
            y: damage.top as u32,
            width: (damage.right - damage.left) as u32,
            height: (damage.bottom - damage.top) as u32,
        });
    }
}

/// Called by the Linux timer tick: lets a virtio-gpu flush what a domain
/// draws through its mapping of /dev/fb0, which the kernel never sees.
pub(crate) fn refresh() {
    if let Some(Display {
        scanout: Scanout::VirtioGpu,
        ..
    }) = display()
    {
        crate::drivers::virtio_gpu::refresh(owned());
    }
}

/// Hands the screen to a Linux program, or takes it back for the console,
/// which then repaints everything the program drew over.
pub(crate) fn set_owned(owned: bool) {
    if OWNED.swap(owned, Ordering::AcqRel) == owned || owned {
        return;
    }
    if !READY.load(Ordering::Acquire) {
        return;
    }
    let Some(mut console) = CONSOLE.try_claim() else {
        return;
    };
    console.repaint();
    let damage = console.damage.take();
    drop(console);
    if let Some(damage) = damage {
        present(damage);
    }
}

/// Copies between the framebuffer and `bytes` at a byte offset, for read(2)
/// and write(2) on /dev/fb0. Returns the bytes copied.
pub(crate) fn transfer(offset: usize, bytes: &mut [u8], write: bool) -> usize {
    let Some(Surface { display, pixels }) = surface() else {
        return 0;
    };
    if !READY.load(Ordering::Acquire) || offset >= display.length {
        return 0;
    }
    let length = bytes.len().min(display.length - offset);
    let length = if write {
        pixels.copy_from(offset, &bytes[..length])
    } else {
        pixels.copy_to(offset, &mut bytes[..length])
    };
    if write && length != 0 {
        let line = display.line_length as usize;
        present(Bounds {
            left: 0,
            top: offset / line,
            right: display.width as usize,
            bottom: (offset + length)
                .div_ceil(line)
                .min(display.height as usize),
        });
    }
    length
}

impl Console {
    /// Points the console at a surface and lays the text grid out for its
    /// size. The text is kept, scrolled if needed so the cursor's line
    /// stays in view.
    fn attach(&mut self, display: &Display, pixels: PixelBuffer) {
        self.pixels = pixels;
        self.width = display.width as usize;
        self.height = display.height as usize;
        self.stride = display.line_length as usize / 4;
        self.bgrx = display.bgrx;
        self.scale = (self.height / (GLYPH_SIZE * TARGET_ROWS)).max(1);
        let cell = GLYPH_SIZE * self.scale;
        self.columns = (self.width / cell).min(MAX_COLUMNS);
        self.rows = (self.height / cell).min(MAX_ROWS);
        if self.row >= self.rows {
            let shift = self.row + 1 - self.rows;
            self.cells.copy_within(shift..shift + self.rows, 0);
            self.row = self.rows - 1;
        }
        for row in self.rows..MAX_ROWS {
            self.cells[row].fill(BLANK);
        }
        self.column = self.column.min(self.columns);
        self.damage = None;
    }

    /// Clears the screen and draws every cell and the cursor again.
    fn repaint(&mut self) {
        self.fill(0, 0, self.width, self.height, DEFAULT_BACKGROUND);
        for row in 0..self.rows {
            for column in 0..self.columns {
                self.draw_cell(row, column);
            }
        }
        self.show_cursor();
    }

    /// Records that the pixels in the given box were drawn.
    fn touch(&mut self, x: usize, y: usize, width: usize, height: usize) {
        let right = (x + width).min(self.width);
        let bottom = (y + height).min(self.height);
        if x >= right || y >= bottom {
            return;
        }
        self.damage = Some(match self.damage {
            None => Bounds {
                left: x,
                top: y,
                right,
                bottom,
            },
            Some(bounds) => Bounds {
                left: bounds.left.min(x),
                top: bounds.top.min(y),
                right: bounds.right.max(right),
                bottom: bounds.bottom.max(bottom),
            },
        });
    }

    fn byte(&mut self, byte: u8) {
        match self.escape {
            Escape::Started => {
                self.escape = match byte {
                    b'[' => {
                        self.parameters = [0; MAX_CSI_PARAMETERS];
                        self.parameter_count = 0;
                        Escape::Csi
                    }
                    b'(' | b')' => Escape::Charset,
                    _ => Escape::None,
                };
                return;
            }
            Escape::Charset => {
                self.escape = Escape::None;
                return;
            }
            Escape::Csi => {
                self.csi(byte);
                return;
            }
            Escape::None => {}
        }
        match byte {
            0x1b => self.escape = Escape::Started,
            b'\r' => self.column = 0,
            b'\n' => {
                self.column = 0;
                self.line_feed();
            }
            0x08 => self.column = self.column.saturating_sub(1),
            b'\t' => {
                let next = (self.column / 8 + 1) * 8;
                while self.column < next.min(self.columns) {
                    self.put(b' ');
                }
            }
            // UTF-8 continuation bytes belong to a glyph already drawn.
            0x80..=0xbf => {}
            0xc0..=0xff => self.put(b'?'),
            0x20..=0x7e => self.put(byte),
            _ => {}
        }
    }

    fn csi(&mut self, byte: u8) {
        match byte {
            b'0'..=b'9' => {
                self.parameter_count = self.parameter_count.max(1);
                let value = &mut self.parameters[self.parameter_count - 1];
                *value = value
                    .saturating_mul(10)
                    .saturating_add(u16::from(byte - b'0'));
            }
            b';' => {
                self.parameter_count = (self.parameter_count.max(1) + 1).min(MAX_CSI_PARAMETERS);
            }
            b'?' | b'>' | b'=' | b' ' => {}
            0x40..=0x7e => {
                self.escape = Escape::None;
                self.csi_final(byte);
            }
            _ => self.escape = Escape::None,
        }
    }

    fn parameter(&self, index: usize, default: usize) -> usize {
        match self.parameters.get(index) {
            Some(&value) if index < self.parameter_count && value != 0 => usize::from(value),
            _ => default,
        }
    }

    fn csi_final(&mut self, byte: u8) {
        match byte {
            b'm' => self.select_graphic_rendition(),
            b'H' | b'f' => {
                self.row = self.parameter(0, 1).min(self.rows) - 1;
                self.column = self.parameter(1, 1).min(self.columns) - 1;
            }
            b'A' => self.row = self.row.saturating_sub(self.parameter(0, 1)),
            b'B' => self.row = (self.row + self.parameter(0, 1)).min(self.rows - 1),
            b'C' => self.column = (self.column + self.parameter(0, 1)).min(self.columns - 1),
            b'D' => self.column = self.column.saturating_sub(self.parameter(0, 1)),
            b'G' => self.column = self.parameter(0, 1).min(self.columns) - 1,
            b'J' => match self.parameter(0, 0) {
                0 => {
                    self.erase_line(self.row, self.column, self.columns);
                    for row in self.row + 1..self.rows {
                        self.erase_line(row, 0, self.columns);
                    }
                }
                1 => {
                    for row in 0..self.row {
                        self.erase_line(row, 0, self.columns);
                    }
                    self.erase_line(self.row, 0, self.column + 1);
                }
                _ => {
                    self.clear_all();
                    self.row = 0;
                    self.column = 0;
                }
            },
            b'K' => match self.parameter(0, 0) {
                0 => self.erase_line(self.row, self.column, self.columns),
                1 => self.erase_line(self.row, 0, self.column + 1),
                _ => self.erase_line(self.row, 0, self.columns),
            },
            _ => {}
        }
        self.flush();
    }

    fn select_graphic_rendition(&mut self) {
        if self.parameter_count == 0 {
            self.reset_attributes();
            return;
        }
        for index in 0..self.parameter_count {
            match self.parameters[index] {
                0 => self.reset_attributes(),
                1 => self.bold = true,
                22 => self.bold = false,
                7 => core::mem::swap(&mut self.foreground, &mut self.background),
                code @ 30..=37 => self.foreground = (code - 30) as u8,
                39 => self.foreground = DEFAULT_FOREGROUND,
                code @ 40..=47 => self.background = (code - 40) as u8,
                49 => self.background = DEFAULT_BACKGROUND,
                code @ 90..=97 => self.foreground = (code - 90) as u8 + 8,
                code @ 100..=107 => self.background = (code - 100) as u8 + 8,
                _ => {}
            }
        }
    }

    fn reset_attributes(&mut self) {
        self.foreground = DEFAULT_FOREGROUND;
        self.background = DEFAULT_BACKGROUND;
        self.bold = false;
    }

    fn put(&mut self, glyph: u8) {
        if self.column >= self.columns {
            self.column = 0;
            self.line_feed();
        }
        let foreground = if self.bold && self.foreground < 8 {
            self.foreground + 8
        } else {
            self.foreground
        };
        self.cells[self.row][self.column] = Cell {
            glyph,
            foreground,
            background: self.background,
        };
        self.draw_cell(self.row, self.column);
        self.column += 1;
    }

    fn line_feed(&mut self) {
        if self.row + 1 < self.rows {
            self.row += 1;
            return;
        }
        let lines = if self.jump_scroll {
            (self.rows / 4).max(1)
        } else {
            1
        };
        self.cells.copy_within(lines..self.rows, 0);
        for row in self.rows - lines..self.rows {
            self.cells[row][..self.columns].fill(BLANK);
        }
        self.row = self.rows - lines;
        self.flush();
    }

    fn erase_line(&mut self, row: usize, start: usize, end: usize) {
        if row < self.rows {
            let blank = Cell {
                background: self.background,
                ..BLANK
            };
            self.cells[row][start.min(self.columns)..end.min(self.columns)].fill(blank);
        }
    }

    fn clear_all(&mut self) {
        for row in 0..self.rows {
            self.cells[row][..self.columns].fill(BLANK);
        }
    }

    fn flush(&mut self) {
        for row in 0..self.rows {
            for column in 0..self.columns {
                if self.cells[row][column] != self.drawn[row][column] {
                    self.draw_cell(row, column);
                }
            }
        }
    }

    fn draw_cell(&mut self, row: usize, column: usize) {
        let cell = self.cells[row][column];
        if OWNED.load(Ordering::Acquire) {
            return;
        }
        self.drawn[row][column] = cell;
        let glyph = BASIC_LEGACY[usize::from(cell.glyph & 0x7f)];
        let foreground = self.pixel(cell.foreground);
        let background = self.pixel(cell.background);
        let size = GLYPH_SIZE * self.scale;
        let origin_x = column * size;
        let origin_y = row * size;
        self.touch(origin_x, origin_y, size, size);
        for y in 0..size {
            let bits = glyph[y / self.scale];
            let line = (origin_y + y) * self.stride + origin_x;
            for x in 0..size {
                let lit = bits & (1 << (x / self.scale)) != 0;
                // The cell lies inside the width-by-height area that init
                // validated against the framebuffer's length.
                self.pixels
                    .write_pixel(line + x, if lit { foreground } else { background });
            }
        }
    }

    fn show_cursor(&mut self) {
        if self.row >= self.rows || self.column >= self.columns {
            return;
        }
        let size = GLYPH_SIZE * self.scale;
        let colour = self.pixel(DEFAULT_FOREGROUND);
        let thickness = self.scale.max(2);
        let x = self.column * size;
        let y = self.row * size + size - thickness;
        self.fill_pixels(x, y, size, thickness, colour);
    }

    fn hide_cursor(&mut self) {
        if self.row < self.rows && self.column < self.columns {
            self.draw_cell(self.row, self.column);
        }
    }

    fn fill(&mut self, x: usize, y: usize, width: usize, height: usize, colour: u8) {
        let pixel = self.pixel(colour);
        self.fill_pixels(x, y, width, height, pixel);
    }

    fn fill_pixels(&mut self, x: usize, y: usize, width: usize, height: usize, pixel: u32) {
        if OWNED.load(Ordering::Acquire) {
            return;
        }
        self.touch(x, y, width, height);
        for row in y..(y + height).min(self.height) {
            let line = row * self.stride;
            for column in x..(x + width).min(self.width) {
                // Row and column are clamped to the validated area.
                self.pixels.write_pixel(line + column, pixel);
            }
        }
    }

    fn pixel(&self, colour: u8) -> u32 {
        let rgb = PALETTE[usize::from(colour & 0x0f)];
        if self.bgrx {
            rgb
        } else {
            ((rgb & 0xff) << 16) | (rgb & 0xff00) | (rgb >> 16)
        }
    }
}
