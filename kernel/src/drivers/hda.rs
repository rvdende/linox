//! Intel High Definition Audio controllers, which also cover the AMD HD
//! Audio and GPU HDMI/DP audio functions: controller reset, codec discovery
//! through the CORB/RIRB command rings, and a report of each codec's output
//! pins, and a test tone played through one output stream.
//!
//! AMD's GPU HDMI/DP audio functions (such as 1002:ab28 on Navi 21 and
//! 1002:1640 on Raphael) do not snoop the processor caches, and AMD's
//! chipset/SoC HD Audio snoops only once bit 1 of PCI config byte 0x42 is
//! set (Linux's "ATI" snoop type). This driver's rings and buffers are
//! ordinary write-back memory, so it writes back every line it hands the
//! controller and discards stale lines before reading what the controller
//! wrote; on a snooping controller that costs a few cache-line flushes.

use core::ptr::{addr_of, addr_of_mut};

use super::pci::{Function, Identity};
use super::{delay_ms, flush_cache, wait_until_ms, DmaPage, DmaRegion};
use crate::trusted::mmio::Mmio;

const CAPABILITIES: usize = 0x00;
const GLOBAL_CONTROL: usize = 0x08;
const STATE_CHANGE: usize = 0x0e;
const CORB_LOW: usize = 0x40;
const CORB_HIGH: usize = 0x44;
const CORB_WRITE: usize = 0x48;
const CORB_READ: usize = 0x4a;
const CORB_CONTROL: usize = 0x4c;
const CORB_SIZE: usize = 0x4e;
const RIRB_LOW: usize = 0x50;
const RIRB_HIGH: usize = 0x54;
const RIRB_WRITE: usize = 0x58;
const RESPONSE_COUNT: usize = 0x5a;
const RIRB_CONTROL: usize = 0x5c;
const RIRB_STATUS: usize = 0x5d;
const RIRB_SIZE: usize = 0x5e;
const CONTROL_RUN: u32 = 1 << 0;
const RING_RUN: u8 = 1 << 1;
const CORB_READ_RESET: u16 = 1 << 15;
const RIRB_WRITE_RESET: u16 = 1 << 15;
/// The response-interrupt and overrun bits, both write-one-to-clear.
const RIRB_STATUS_CLEAR: u8 = 0x05;
/// Size selector for 256-entry rings.
const RING_256: u8 = 2;
const RING_ENTRIES: usize = 256;
/// The first stream descriptor; input streams come before output streams.
/// The controller's memory BAR (HD Audio 1.0a section 3.3): 16 KiB.
const REGISTER_BYTES: usize = 0x4000;
const STREAMS: usize = 0x80;
const STREAM_STRIDE: usize = 0x20;
const STREAM_CONTROL: usize = 0x00;
const STREAM_POSITION: usize = 0x04;
const STREAM_LENGTH: usize = 0x08;
const STREAM_LAST_INDEX: usize = 0x0c;
const STREAM_FORMAT: usize = 0x12;
const STREAM_BDL_LOW: usize = 0x18;
const STREAM_BDL_HIGH: usize = 0x1c;
const STREAM_RESET: u32 = 1 << 0;
const STREAM_RUN: u32 = 1 << 1;
/// The stream tag codecs use to pick out this stream's samples.
const STREAM_TAG: u32 = 1;
/// 48 kHz, 16-bit samples, two channels.
const FORMAT_48K_16_STEREO: u16 = 0x0011;
const SAMPLE_RATE: u32 = 48_000;
const TONE_HZ: u32 = 440;
const TONE_AMPLITUDE: i16 = 6000;
const AUDIO_PAGES: usize = 8;
const VERB_SET_FORMAT: u32 = 0x2;
const VERB_SET_AMPLIFIER: u32 = 0x3;
const VERB_SET_CONNECTION: u32 = 0x701;
const VERB_SET_STREAM: u32 = 0x706;
const VERB_SET_PIN_CONTROL: u32 = 0x707;
const VERB_SET_EAPD: u32 = 0x70c;
const PIN_OUTPUT_ENABLE: u32 = 0x40;
const EAPD_ENABLE: u32 = 0x02;
const VERB_GET_AMPLIFIER: u32 = 0xb;
/// Get the left output amplifier's gain and mute state.
const AMPLIFIER_OUTPUT_LEFT: u32 = 0xa000;
/// Set the output amplifier of both channels, unmuted, to the low bits.
const AMPLIFIER_OUTPUT_BOTH: u32 = 0xb000;
const VERB_GET_PARAMETER: u32 = 0xf00;
const VERB_GET_CONFIGURATION: u32 = 0xf1c;
const PARAMETER_VENDOR: u32 = 0x00;
const PARAMETER_NODES: u32 = 0x04;
const PARAMETER_FUNCTION_TYPE: u32 = 0x05;
const PARAMETER_WIDGET: u32 = 0x09;
const FUNCTION_AUDIO: u32 = 1;
const WIDGET_OUTPUT: u32 = 0;
const WIDGET_PIN: u32 = 4;
const COMMAND_TIMEOUT_MS: u64 = 50;
const MAX_CODECS: usize = 15;
const VENDOR_AMD: u16 = 0x1022;
/// AMD/ATI HD Audio miscellaneous control: bits 2:0 select snooping, and
/// 0b010 turns it on.
const AMD_MISC_CONTROL: u8 = 0x40;
const AMD_MISC_CONTROL_SHIFT: u32 = 16;
const AMD_ENABLE_SNOOP: u32 = 0x02;

static mut CORB: DmaPage = DmaPage::ZERO;
static mut RIRB: DmaPage = DmaPage::ZERO;
static mut BUFFER_LIST: DmaPage = DmaPage::ZERO;
static mut SAMPLES: [DmaPage; AUDIO_PAGES] = [DmaPage::ZERO; AUDIO_PAGES];

/// Returns whether `device` is a High Definition Audio controller.
pub(crate) fn is_supported(device: &Identity) -> bool {
    (device.class, device.subclass) == (0x04, 0x03)
}

/// The memory HD Audio controllers may reach by DMA.
pub(crate) fn dma_regions() -> [DmaRegion; 4] {
    [
        DmaRegion::of(addr_of!(CORB)),
        DmaRegion::of(addr_of!(RIRB)),
        DmaRegion::of(addr_of!(BUFFER_LIST)),
        DmaRegion::of(addr_of!(SAMPLES)),
    ]
}

// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum Error {
    NoMemoryBar,
    ResetTimedOut,
    NoCodecs,
    CommandTimedOut,
    NoOutputStream,
    NoOutputPath,
    StreamResetTimedOut,
}

/// One output pin of a codec, as its default configuration describes it.
#[derive(Clone, Copy)]
pub(crate) struct Pin {
    pub(crate) node: u8,
    /// The configuration default register (verb F1Ch).
    pub(crate) configuration: u32,
}

impl Pin {
    /// What the pin is wired as, from the default-device field.
    pub(crate) fn device_name(&self) -> &'static str {
        match (self.configuration >> 20) & 0xf {
            0x0 => "line out",
            0x1 => "speaker",
            0x2 => "headphone",
            0x3 => "CD",
            0x4 => "S/PDIF out",
            0x5 => "digital out",
            0x6 => "modem line",
            0x7 => "modem handset",
            0x8 => "line in",
            0x9 => "aux",
            0xa => "microphone",
            0xb => "telephony",
            0xc => "S/PDIF in",
            0xd => "digital in",
            _ => "other",
        }
    }

    /// Whether anything is attached according to the port-connectivity
    /// field (bits 31:30 are 1 for "no physical connection").
    pub(crate) fn connected(&self) -> bool {
        self.configuration >> 30 != 1
    }

    pub(crate) fn is_output(&self) -> bool {
        matches!((self.configuration >> 20) & 0xf, 0x0..=0x2 | 0x4 | 0x5)
    }
}

/// What one codec reports.
pub(crate) struct Codec {
    pub(crate) address: u8,
    pub(crate) vendor: u16,
    pub(crate) device: u16,
    pub(crate) converters: usize,
    /// The first output converter, which playback uses.
    pub(crate) converter: Option<u8>,
    pub(crate) pins: [Option<Pin>; 16],
}

/// A reset controller with its command rings running.
pub(crate) struct Controller {
    registers: Mmio,
    corb_write: u16,
    rirb_read: u16,
    codecs: u16,
}

impl Controller {
    /// Resets `function` and starts its CORB and RIRB.
    ///
    /// # Safety
    ///
    /// `function` must be an HD Audio controller that nothing else drives,
    /// with its registers and this driver's DMA pages identity mapped. Only
    /// one controller may be open at a time.
    pub(crate) unsafe fn open(function: Function) -> Result<Self, Error> {
        let base = function
            .memory_bar(0)
            .and_then(|bar| Mmio::firmware(bar, REGISTER_BYTES))
            .ok_or(Error::NoMemoryBar)?;
        function.enable_memory_and_bus_master();
        let vendor = function.read_u32(0) as u16;
        if vendor == VENDOR_AMD {
            // Byte 0x42 sits in the dword at 0x40: ask the chipset/SoC
            // function for snooped DMA. The GPU (ATI) audio functions have
            // no such switch and are left alone.
            let value = function.read_u32(AMD_MISC_CONTROL);
            let value =
                value & !(7 << AMD_MISC_CONTROL_SHIFT) | AMD_ENABLE_SNOOP << AMD_MISC_CONTROL_SHIFT;
            function.write_u32(AMD_MISC_CONTROL, value);
        }
        base.write::<u8>(CORB_CONTROL, 0);
        base.write::<u8>(RIRB_CONTROL, 0);
        base.write::<u32>(
            GLOBAL_CONTROL,
            base.read::<u32>(GLOBAL_CONTROL) & !CONTROL_RUN,
        );
        if !wait_until_ms(100, || base.read::<u32>(GLOBAL_CONTROL) & CONTROL_RUN == 0) {
            return Err(Error::ResetTimedOut);
        }
        delay_ms(1);
        base.write::<u32>(
            GLOBAL_CONTROL,
            base.read::<u32>(GLOBAL_CONTROL) | CONTROL_RUN,
        );
        if !wait_until_ms(100, || base.read::<u32>(GLOBAL_CONTROL) & CONTROL_RUN != 0) {
            return Err(Error::ResetTimedOut);
        }
        // Codecs need 521 us after reset to request an address.
        delay_ms(2);
        let codecs = base.read::<u16>(STATE_CHANGE) & 0x7fff;
        if codecs == 0 {
            return Err(Error::NoCodecs);
        }

        (*addr_of_mut!(CORB)).0.fill(0);
        (*addr_of_mut!(RIRB)).0.fill(0);
        flush_cache(addr_of!(CORB) as usize, 4096);
        flush_cache(addr_of!(RIRB) as usize, 4096);
        let corb = addr_of!(CORB) as u64;
        let rirb = addr_of!(RIRB) as u64;
        base.write::<u32>(CORB_LOW, corb as u32);
        base.write::<u32>(CORB_HIGH, (corb >> 32) as u32);
        base.write::<u8>(CORB_SIZE, RING_256);
        base.write::<u16>(CORB_WRITE, 0);
        base.write::<u16>(CORB_READ, CORB_READ_RESET);
        let _ = wait_until_ms(10, || base.read::<u16>(CORB_READ) & CORB_READ_RESET != 0);
        base.write::<u16>(CORB_READ, 0);
        let _ = wait_until_ms(10, || base.read::<u16>(CORB_READ) & CORB_READ_RESET == 0);
        base.write::<u32>(RIRB_LOW, rirb as u32);
        base.write::<u32>(RIRB_HIGH, (rirb >> 32) as u32);
        base.write::<u8>(RIRB_SIZE, RING_256);
        base.write::<u16>(RIRB_WRITE, RIRB_WRITE_RESET);
        // Controllers may stop writing responses once this many are
        // unacknowledged, so allow the most and acknowledge each one.
        base.write::<u16>(RESPONSE_COUNT, 0xff);
        base.write::<u8>(RIRB_STATUS, RIRB_STATUS_CLEAR);
        base.write::<u8>(CORB_CONTROL, RING_RUN);
        base.write::<u8>(RIRB_CONTROL, RING_RUN);
        Ok(Self {
            registers: base,
            corb_write: 0,
            rirb_read: 0,
            codecs,
        })
    }

    /// Discovers each codec's audio function group and its pins.
    pub(crate) fn codecs(&mut self) -> impl Iterator<Item = Result<Codec, Error>> + '_ {
        let present = self.codecs;
        (0..MAX_CODECS as u8)
            .filter(|address| present & 1 << address != 0)
            .collect::<CodecAddresses>()
            .into_iter()
            .map(move |address| self.codec(address))
    }

    fn codec(&mut self, address: u8) -> Result<Codec, Error> {
        let identity = self.parameter(address, 0, PARAMETER_VENDOR)?;
        let mut codec = Codec {
            address,
            vendor: (identity >> 16) as u16,
            device: identity as u16,
            converters: 0,
            converter: None,
            pins: [None; 16],
        };
        let (first_group, groups) = node_range(self.parameter(address, 0, PARAMETER_NODES)?);
        for group in first_group..first_group + groups {
            if self.parameter(address, group, PARAMETER_FUNCTION_TYPE)? & 0xff != FUNCTION_AUDIO {
                continue;
            }
            let (first, count) = node_range(self.parameter(address, group, PARAMETER_NODES)?);
            let mut pins = 0;
            for node in first..first + count {
                let kind = (self.parameter(address, node, PARAMETER_WIDGET)? >> 20) & 0xf;
                if kind == WIDGET_OUTPUT {
                    codec.converters += 1;
                    codec.converter.get_or_insert(node);
                } else if kind == WIDGET_PIN && pins < codec.pins.len() {
                    let configuration = self.command(address, node, VERB_GET_CONFIGURATION, 0)?;
                    codec.pins[pins] = Some(Pin {
                        node,
                        configuration,
                    });
                    pins += 1;
                }
            }
        }
        Ok(codec)
    }

    /// Plays a 440 Hz tone for `milliseconds` from `codec`'s first output
    /// converter to its first connected output pin, and returns how far the
    /// controller's DMA position advanced.
    pub(crate) fn play_tone(&mut self, codec: &Codec, milliseconds: u64) -> Result<u32, Error> {
        let converter = codec.converter.ok_or(Error::NoOutputPath)?;
        let pin = codec
            .pins
            .iter()
            .flatten()
            .find(|pin| pin.is_output() && pin.connected())
            .ok_or(Error::NoOutputPath)?;
        let capabilities = self.registers.read::<u16>(CAPABILITIES);
        let inputs = usize::from(capabilities >> 8 & 0xf);
        if capabilities >> 12 & 0xf == 0 {
            return Err(Error::NoOutputStream);
        }
        let stream = self
            .registers
            .window(STREAMS + inputs * STREAM_STRIDE, STREAM_STRIDE)
            .ok_or(Error::NoOutputStream)?;

        let bytes = fill_tone();
        let half = (bytes / 2) as u32;
        let samples = addr_of!(SAMPLES) as u64;
        // SAFETY: the buffer list page belongs to this driver; its two
        // entries each cover half of the sample pages.
        unsafe {
            let list = addr_of_mut!(BUFFER_LIST).cast::<u32>();
            for (index, address) in [samples, samples + u64::from(half)].into_iter().enumerate() {
                let entry = list.add(index * 4);
                entry.write_volatile(address as u32);
                entry.add(1).write_volatile((address >> 32) as u32);
                entry.add(2).write_volatile(half);
                entry.add(3).write_volatile(0);
            }
        }
        flush_cache(addr_of!(BUFFER_LIST) as usize, 4096);
        flush_cache(samples as usize, bytes);

        stream.write::<u32>(STREAM_CONTROL, STREAM_RESET);
        if !wait_until_ms(100, || {
            stream.read::<u32>(STREAM_CONTROL) & STREAM_RESET != 0
        }) {
            return Err(Error::StreamResetTimedOut);
        }
        stream.write::<u32>(STREAM_CONTROL, 0);
        if !wait_until_ms(100, || {
            stream.read::<u32>(STREAM_CONTROL) & STREAM_RESET == 0
        }) {
            return Err(Error::StreamResetTimedOut);
        }
        let list = addr_of!(BUFFER_LIST) as u64;
        stream.write::<u32>(STREAM_BDL_LOW, list as u32);
        stream.write::<u32>(STREAM_BDL_HIGH, (list >> 32) as u32);
        stream.write::<u32>(STREAM_LENGTH, bytes as u32);
        stream.write::<u16>(STREAM_LAST_INDEX, 1);
        stream.write::<u16>(STREAM_FORMAT, FORMAT_48K_16_STEREO);
        stream.write::<u32>(STREAM_CONTROL, STREAM_TAG << 20);

        let address = codec.address;
        self.command_long(
            address,
            converter,
            VERB_SET_FORMAT,
            u32::from(FORMAT_48K_16_STEREO),
        )?;
        self.command(address, converter, VERB_SET_STREAM, STREAM_TAG << 4)?;
        for node in [converter, pin.node] {
            // Unmute the output amplifiers at their current gain: what
            // firmware or the codec chose is safer than guessing a level.
            let gain =
                self.command_long(address, node, VERB_GET_AMPLIFIER, AMPLIFIER_OUTPUT_LEFT)?;
            self.command_long(
                address,
                node,
                VERB_SET_AMPLIFIER,
                AMPLIFIER_OUTPUT_BOTH | gain & 0x7f,
            )?;
        }
        self.command(address, pin.node, VERB_SET_CONNECTION, 0)?;
        self.command(address, pin.node, VERB_SET_PIN_CONTROL, PIN_OUTPUT_ENABLE)?;
        // External amplifiers on laptops and boards hang off EAPD; codecs
        // without it ignore the verb.
        let _ = self.command(address, pin.node, VERB_SET_EAPD, EAPD_ENABLE);

        let start = stream.read::<u32>(STREAM_POSITION);
        stream.write::<u32>(STREAM_CONTROL, STREAM_TAG << 20 | STREAM_RUN);
        delay_ms(milliseconds);
        let end = stream.read::<u32>(STREAM_POSITION);
        stream.write::<u32>(STREAM_CONTROL, STREAM_TAG << 20);
        Ok(end.wrapping_sub(start) % bytes as u32)
    }

    fn parameter(&mut self, codec: u8, node: u8, parameter: u32) -> Result<u32, Error> {
        self.command(codec, node, VERB_GET_PARAMETER, parameter)
    }

    /// Sends one 12-bit verb with an 8-bit payload and returns the response.
    fn command(&mut self, codec: u8, node: u8, verb: u32, payload: u32) -> Result<u32, Error> {
        self.send(u32::from(codec) << 28 | u32::from(node) << 20 | verb << 8 | payload)
    }

    /// Sends one 4-bit verb with a 16-bit payload and returns the response.
    fn command_long(&mut self, codec: u8, node: u8, verb: u32, payload: u32) -> Result<u32, Error> {
        self.send(u32::from(codec) << 28 | u32::from(node) << 20 | verb << 16 | payload)
    }

    fn send(&mut self, command: u32) -> Result<u32, Error> {
        self.corb_write = (self.corb_write + 1) % RING_ENTRIES as u16;
        // SAFETY: the CORB page belongs to this driver, and the controller
        // only reads entries up to the write pointer.
        let entry = unsafe {
            let entry = addr_of_mut!(CORB)
                .cast::<u32>()
                .add(usize::from(self.corb_write));
            entry.write_volatile(command);
            entry
        };
        flush_cache(entry as usize, 4);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.registers.write::<u16>(CORB_WRITE, self.corb_write);
        let next = (self.rirb_read + 1) % RING_ENTRIES as u16;
        if !wait_until_ms(COMMAND_TIMEOUT_MS, || {
            self.registers.read::<u16>(RIRB_WRITE) & 0xff == next
        }) {
            return Err(Error::CommandTimedOut);
        }
        self.rirb_read = next;
        // SAFETY: the controller wrote the response before moving its
        // write pointer; each entry is a response and a codec tag.
        let entry = unsafe { addr_of!(RIRB).cast::<u32>().add(usize::from(next) * 2) };
        // Drop any stale cached copy of the entry the controller wrote.
        flush_cache(entry as usize, 8);
        // SAFETY: as above.
        let response = unsafe { entry.read_volatile() };
        self.registers.write::<u8>(RIRB_STATUS, RIRB_STATUS_CLEAR);
        Ok(response)
    }
}

/// The addresses of present codecs, collected so commands can borrow the
/// controller mutably while iterating.
struct CodecAddresses {
    addresses: [u8; MAX_CODECS],
    count: usize,
}

impl FromIterator<u8> for CodecAddresses {
    fn from_iter<T: IntoIterator<Item = u8>>(iterator: T) -> Self {
        let mut collected = Self {
            addresses: [0; MAX_CODECS],
            count: 0,
        };
        for address in iterator.into_iter().take(MAX_CODECS) {
            collected.addresses[collected.count] = address;
            collected.count += 1;
        }
        collected
    }
}

impl IntoIterator for CodecAddresses {
    type Item = u8;
    type IntoIter = core::iter::Take<core::array::IntoIter<u8, MAX_CODECS>>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.into_iter().take(self.count)
    }
}

/// Fills the sample pages with a 440 Hz square wave in 16-bit stereo and
/// returns their length in bytes.
fn fill_tone() -> usize {
    let frames = AUDIO_PAGES * 4096 / 4;
    let half_period = (SAMPLE_RATE / TONE_HZ / 2) as usize;
    // SAFETY: the sample pages belong to this driver and no stream is
    // running while they are written.
    let samples =
        unsafe { core::slice::from_raw_parts_mut(addr_of_mut!(SAMPLES).cast::<i16>(), frames * 2) };
    for (frame, pair) in samples.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        let level = if (frame / half_period).is_multiple_of(2) {
            TONE_AMPLITUDE
        } else {
            -TONE_AMPLITUDE
        };
        pair.fill(level);
    }
    frames * 4
}

/// Decodes a subordinate-node-count response into a first node and count.
fn node_range(response: u32) -> (u8, u8) {
    ((response >> 16) as u8, response as u8)
}
