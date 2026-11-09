//! The clock the polled drivers count their timeouts against.
//!
//! Every wait on hardware is bounded by a number of timestamp-counter ticks.
//! Until [`calibrate`] has measured the counter against a fixed-frequency
//! ACPI timer, the drivers assume a 5 GHz counter, which no x86-64 CPU
//! exceeds, so an uncalibrated wait is never shorter than asked (only
//! longer on a slower counter). After calibration the bounds are accurate,
//! and the bring-up report can say how long each step took.
//!
//! The references, in order of preference:
//!
//! - The ACPI power-management timer (ACPI 6.5 section 4.8.3.3): a free
//!   running 3.579545 MHz counter, 24 or 32 bits wide (FADT flag
//!   TMR_VAL_EXT), read from an I/O port or a generic address. Reading it
//!   changes nothing.
//! - The HPET main counter (IA-PC HPET specification 1.0a, section 2.3):
//!   its period in femtoseconds is in the capabilities register. If firmware
//!   left the counter halted it is started (ENABLE_CNF), with no timer
//!   interrupts routed.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::timer::timestamp_counter;
use crate::trusted::mmio::Mmio;
use crate::trusted::port::PmTimer;

/// Ticks per millisecond assumed before calibration: a 5 GHz counter.
const ASSUMED_TICKS_PER_MS: u64 = 5_000_000;
/// The ACPI PM timer's frequency in Hz.
const PM_TIMER_HZ: u64 = 3_579_545;
/// How long calibration measures, in milliseconds.
const CALIBRATION_MS: u64 = 50;
/// Counter frequencies outside this range are measurement errors.
const PLAUSIBLE_HZ: core::ops::RangeInclusive<u64> = 100_000_000..=10_000_000_000;
const HPET_CAPABILITIES: usize = 0x00;
const HPET_CONFIGURATION: usize = 0x10;
const HPET_MAIN_COUNTER: usize = 0xf0;
const HPET_ENABLE: u64 = 1 << 0;
/// An HPET block's registers (IA-PC HPET 1.0a section 2.3.1): 1 KiB.
const HPET_BYTES: usize = 0x400;

/// Timestamp-counter ticks per millisecond.
static TICKS_PER_MS: AtomicU64 = AtomicU64::new(ASSUMED_TICKS_PER_MS);

/// A fixed-frequency counter to measure the timestamp counter against.
#[derive(Clone, Copy)]
pub(crate) enum Reference {
    /// The ACPI PM timer at an I/O port, 32 bits wide or 24.
    PmTimerPort { port: u16, wide: bool },
    /// The ACPI PM timer in memory space.
    PmTimerMemory { address: u64, wide: bool },
    /// An HPET block at this identity-mapped address.
    Hpet { address: u64 },
}

impl Reference {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::PmTimerPort { .. } | Self::PmTimerMemory { .. } => "ACPI PM timer",
            Self::Hpet { .. } => "HPET",
        }
    }
}

/// A reference counter readied for reading: its tick rate, width mask, and
/// how to read it.
struct Counter {
    source: Source,
    hz: u64,
    mask: u64,
}

/// Where a counter is read.
enum Source {
    PmTimerPort(PmTimer),
    /// The PM timer's 32-bit register in memory space.
    PmTimerMemory(Mmio),
    /// An HPET block's registers.
    Hpet(Mmio),
}

impl Counter {
    /// Readies the timer the firmware described in ACPI. A memory-space
    /// timer must be mapped by the firmware's page tables.
    fn open(reference: Reference) -> Option<Self> {
        let (source, hz, mask) = match reference {
            Reference::PmTimerPort { port, wide } => (
                Source::PmTimerPort(PmTimer::new(port)),
                PM_TIMER_HZ,
                if wide { u64::from(u32::MAX) } else { 0xff_ffff },
            ),
            Reference::PmTimerMemory { address, wide } => (
                Source::PmTimerMemory(Mmio::firmware(address, size_of::<u32>())?),
                PM_TIMER_HZ,
                if wide { u64::from(u32::MAX) } else { 0xff_ffff },
            ),
            Reference::Hpet { address } => {
                let registers = Mmio::firmware(address, HPET_BYTES)?;
                let capabilities = registers.read::<u64>(HPET_CAPABILITIES);
                // The period is in femtoseconds; the specification caps it at
                // 100 ns (10 MHz is the slowest counter allowed).
                let period = capabilities >> 32;
                if period == 0 || period > 100_000_000 {
                    return None;
                }
                let value = registers.read::<u64>(HPET_CONFIGURATION);
                if value & HPET_ENABLE == 0 {
                    registers.write::<u64>(HPET_CONFIGURATION, value | HPET_ENABLE);
                }
                // COUNT_SIZE_CAP (bit 13) says whether the counter has 64 bits.
                let mask = if capabilities & (1 << 13) != 0 {
                    u64::MAX
                } else {
                    u64::from(u32::MAX)
                };
                (
                    Source::Hpet(registers),
                    1_000_000_000_000_000 / period,
                    mask,
                )
            }
        };
        Some(Self { source, hz, mask })
    }

    /// Reads the counter, which has no side effects.
    fn read(&self) -> u64 {
        let value = match &self.source {
            Source::PmTimerPort(timer) => u64::from(timer.read()),
            Source::PmTimerMemory(register) => u64::from(register.read::<u32>(0)),
            Source::Hpet(registers) => registers.read::<u64>(HPET_MAIN_COUNTER),
        };
        value & self.mask
    }
}

/// Measures the timestamp counter against `reference` and uses the result
/// for every later wait. Returns the counter's frequency in Hz, or `None`
/// when the reference does not count or the result is implausible (the
/// assumed rate stays in force). `reference` comes from the firmware's
/// ACPI tables (FADT or HPET); a memory-space timer must be mapped by the
/// firmware's page tables.
pub(crate) fn calibrate(reference: Reference) -> Option<u64> {
    let counter = Counter::open(reference)?;
    let wanted = counter.hz * CALIBRATION_MS / 1000;
    // Bound the measurement itself: if the reference never moves, give up
    // after what would be a second on the fastest counter.
    let give_up = ASSUMED_TICKS_PER_MS * 1000;
    let first = counter.read();
    // Start on a tick edge so the measurement does not include a partial tick.
    let started = timestamp_counter();
    let mut start = first;
    while start == first {
        if timestamp_counter().wrapping_sub(started) > give_up {
            return None;
        }
        start = counter.read();
    }
    let tsc_start = timestamp_counter();
    let mut elapsed = 0;
    let mut previous = start;
    while elapsed < wanted {
        let now = counter.read();
        // Accumulate differences so a 24-bit counter may wrap during the
        // measurement.
        elapsed += now.wrapping_sub(previous) & counter.mask;
        previous = now;
        if timestamp_counter().wrapping_sub(tsc_start) > give_up {
            return None;
        }
    }
    let ticks = timestamp_counter().wrapping_sub(tsc_start);
    let hz =
        u64::try_from(u128::from(ticks) * u128::from(counter.hz) / u128::from(elapsed)).ok()?;
    if !PLAUSIBLE_HZ.contains(&hz) {
        return None;
    }
    TICKS_PER_MS.store(hz / 1000, Ordering::Release);
    Some(hz)
}

/// Timestamp-counter ticks per millisecond: as [`calibrate`] measured it,
/// else as the main kernel's timer knows it, else the assumed 5 GHz.
pub(crate) fn ticks_per_ms() -> u64 {
    match TICKS_PER_MS.load(Ordering::Acquire) {
        ASSUMED_TICKS_PER_MS => crate::arch::x86_64::timer::monotonic_frequency()
            .filter(|hz| PLAUSIBLE_HZ.contains(hz))
            .map_or(ASSUMED_TICKS_PER_MS, |hz| hz / 1000),
        calibrated => calibrated,
    }
}

/// Milliseconds since the counter read `start`.
pub(crate) fn elapsed_ms(start: u64) -> u64 {
    timestamp_counter().wrapping_sub(start) / ticks_per_ms().max(1)
}
