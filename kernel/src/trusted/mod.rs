//! The start of the trusted core (docs/FRAMEKERNEL.md §4): small safe
//! abstractions whose few `unsafe` blocks carry the invariant they rely on,
//! so the code above them reaches physical memory without `unsafe`.
//!
//! - [`frame`]: a physical frame of RAM, read and written by copying
//!   through the direct map.
//! - [`page_table`]: a page-table frame viewed as its 512 entries.
//! - [`port`]: the I/O ports the kernel uses, each a typed handle.
//! - [`firmware`]: firmware (ACPI) tables viewed in place for parsing.
//! - [`dma`]: static DMA pages the hardware drivers claim, one instance
//!   at a time.
//! - [`pci_config`]: PCI configuration space.
//! - [`mmio`]: a window of one device's memory-mapped registers.
//! - [`msr`]: the model-specific registers the kernel uses outside the CPU
//!   core.
//!
//! Each module says who may construct its types; the constructors from a
//! bare physical address are confined to the memory layer by
//! `tools/architecture/check-kernel-unsafe.sh`.

pub(crate) mod dma;
pub(crate) mod firmware;
pub(crate) mod frame;
pub(crate) mod mmio;
pub(crate) mod msr;
pub(crate) mod page_table;
pub(crate) mod pci_config;
pub(crate) mod port;
