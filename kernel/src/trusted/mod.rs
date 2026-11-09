//! The start of the trusted core (docs/FRAMEKERNEL.md §4): small safe
//! abstractions whose few `unsafe` blocks carry the invariant they rely on,
//! so the code above them reaches physical memory without `unsafe`.
//!
//! - [`frame`]: a physical frame of RAM, read and written by copying
//!   through the direct map.
//! - [`frame_tables`]: the frame allocator's per-frame tables, carved out
//!   of RAM once at boot.
//! - [`boot`]: the loader's boot handoff (the firmware memory map).
//! - [`page_table`]: a page-table frame viewed as its 512 entries.
//! - [`port`]: the I/O ports the kernel uses, each a typed handle.
//! - [`root`]: reading and reloading the page-table root register.
//! - [`firmware`]: firmware (ACPI) tables viewed in place for parsing.
//! - [`dma`]: DMA memory the drivers' devices reach: static pages claimed
//!   by one driver instance at a time, a static pool sub-allocated by one
//!   instance at a time, and frame-allocator buffers.
//! - [`pixels`]: a display surface the console and /dev/fb0 draw into.
//! - [`claim`]: a value one context at a time may claim, the others
//!   skipping it while it is busy.
//! - [`pci_config`]: PCI configuration space.
//! - [`mmio`]: a window of one device's memory-mapped registers.
//! - [`msr`]: the model-specific registers the kernel uses outside the CPU
//!   core.
//! - [`image`]: the boot loader's handoff images and published root
//!   filesystem images, read in place as `'static` byte slices.
//! - [`interrupts`]: this CPU's interrupt flag, and halting.
//! - [`entry`]: the entry stubs of the device, timer and inter-processor
//!   interrupt vectors.
//! - [`ap_start`]: the application processors' start-up trampoline.
//! - [`tsc`]: the timestamp counter.
//! - [`boot`]: the kernel's entry from the loader and the boot information
//!   it hands over.
//! - [`control`]: control registers, the stack pointer, CR0.WP.
//! - [`take_once`]: a static handed out as `&'static mut` once.
//! - [`lock`]: the spin locks (`crate::sync` re-exports them with the lock
//!   ranks).
//! - [`owned_state`]: set-once owners for long-lived kernel objects.
//!
//! Each module says who may construct its types; the constructors from a
//! bare physical address are confined to the memory layer by
//! `tools/architecture/check-kernel-unsafe.sh`.

pub(crate) mod ap_start;
pub(crate) mod boot;
pub(crate) mod claim;
pub(crate) mod control;
pub(crate) mod crash;
pub(crate) mod dma;
pub(crate) mod entry;
pub(crate) mod firmware;
pub(crate) mod frame;
pub(crate) mod frame_tables;
pub(crate) mod image;
pub(crate) mod interrupts;
pub(crate) mod lock;
pub(crate) mod mmio;
pub(crate) mod msr;
pub(crate) mod owned_state;
pub(crate) mod page_table;
pub(crate) mod pci_config;
pub(crate) mod pixels;
pub(crate) mod port;
pub(crate) mod root;
pub(crate) mod take_once;
pub(crate) mod tsc;
