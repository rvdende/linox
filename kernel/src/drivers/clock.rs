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

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::timer::timestamp_counter;
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
    reference: Reference,
    hz: u64,
    mask: u64,
}

impl Counter {
    /// # Safety
    ///
    /// The reference must name a timer the firmware described in ACPI,
    /// identity mapped when it is in memory space.
    unsafe fn open(reference: Reference) -> Option<Self> {
        let (hz, mask) = match reference {
            Reference::PmTimerPort { wide, .. } | Reference::PmTimerMemory { wide, .. } => (
                PM_TIMER_HZ,
                if wide { u64::from(u32::MAX) } else { 0xff_ffff },
            ),
            Reference::Hpet { address } => {
                let registers = address as *mut u64;
                let capabilities = registers.byte_add(HPET_CAPABILITIES).read_volatile();
                // The period is in femtoseconds; the specification caps it at
                // 100 ns (10 MHz is the slowest counter allowed).
                let period = capabilities >> 32;
                if period == 0 || period > 100_000_000 {
                    return None;
                }
                let configuration = registers.byte_add(HPET_CONFIGURATION);
                let value = configuration.read_volatile();
                if value & HPET_ENABLE == 0 {
                    configuration.write_volatile(value | HPET_ENABLE);
                }
                // COUNT_SIZE_CAP (bit 13) says whether the counter has 64 bits.
                let mask = if capabilities & (1 << 13) != 0 {
                    u64::MAX
                } else {
                    u64::from(u32::MAX)
                };
                (1_000_000_000_000_000 / period, mask)
            }
        };
        Some(Self {
            reference,
            hz,
            mask,
        })
    }

    fn read(&self) -> u64 {
        // SAFETY: open's contract: the timer exists where ACPI says, and
        // reading its counter has no side effects.
        let value = unsafe {
            match self.reference {
                Reference::PmTimerPort { port, .. } => u64::from(PmTimer::new(port).read()),
                Reference::PmTimerMemory { address, .. } => {
                    u64::from((address as *const u32).read_volatile())
                }
                Reference::Hpet { address } => (address as *const u64)
                    .byte_add(HPET_MAIN_COUNTER)
                    .read_volatile(),
            }
        };
        value & self.mask
    }
}

/// Measures the timestamp counter against `reference` and uses the result
/// for every later wait. Returns the counter's frequency in Hz, or `None`
/// when the reference does not count or the result is implausible (the
/// assumed rate stays in force).
///
/// # Safety
///
/// `reference` must come from the firmware's ACPI tables (FADT or HPET),
/// and a memory-space timer must be identity mapped.
pub(crate) unsafe fn calibrate(reference: Reference) -> Option<u64> {
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
