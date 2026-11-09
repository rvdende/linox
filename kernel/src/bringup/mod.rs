//! Hardware bring-up mode.
//!
//! The main boot path requires the QEMU reference devices (virtio block and
//! network behind an Intel IOMMU). When they are absent, as on a physical PC,
//! the kernel enters this mode instead of failing. It runs on the firmware page
//! tables with interrupts disabled, reports the platform on the console, and
//! exercises the physical-hardware drivers in `crate::drivers`. Only the
//! shell's `disktest` writes to storage, and only inside partitions of the
//! Linox volume type, restoring what it wrote.
//!
//! On a physical PC the screen is usually the only output, so bring-up is
//! built to be photographed: each step is named as it starts (and a crash
//! or panic names the step it struck in, see [`trap`]), waits on hardware
//! are bounded by a calibrated clock, slow steps report how long they took,
//! and the report ends with a summary that fits on one screen. Everything
//! printed is kept in the kernel log, which the shell's `log` command pages
//! through.

mod log;
mod trap;

use crate::drivers::net::{self, Nic};
use crate::drivers::{
    ahci, amd_iommu, clock, e1000e, gpt, hda, keyboard, nvme, pci, realtek, say, xhci, BlockDevice,
};
use crate::trusted::{dma::StaticDma, firmware, mmio::Mmio};
use crate::{BootInfo, UefiMemoryDescriptor, EFI_BOOT_SERVICES_CODE, EFI_BOOT_SERVICES_DATA};

pub use trap::report_panic;
pub(crate) use trap::{firmware_maps, set_stage};

const EFI_LOADER_CODE: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_CONVENTIONAL_MEMORY: u32 = crate::EFI_CONVENTIONAL_MEMORY;
const FOUR_GIB: u64 = 1 << 32;
const MAX_CONTROLLERS: usize = 8;
const MAX_IOMMUS: usize = 8;
const LINE_CAPACITY: usize = 128;
const EFI_RESET_COLD: u32 = 0;
const EFI_RESET_SHUTDOWN: u32 = 2;
const MAX_LISTED_PARTITIONS: u32 = 128;

/// What the report found, repeated at its end so that one photo of the
/// screen shows the outcome of every step.
#[derive(Default)]
struct Summary {
    clock: Option<(&'static str, u64)>,
    iommus: usize,
    remapping: usize,
    nvme: (usize, usize),
    xhci: (usize, usize),
    keyboards: usize,
    pointers: usize,
}

/// Reports the platform and runs the hardware drivers, then halts.
pub(crate) fn run(boot_info: &BootInfo) -> ! {
    trap::install();
    set_stage("bring-up start");
    crate::framebuffer::set_jump_scroll(true);
    say!("\nlinox: QEMU reference devices not found; entering hardware bring-up mode\n");
    say!(
        "linox: serial console {}\n",
        if crate::SERIAL_PRESENT.load(core::sync::atomic::Ordering::Acquire) {
            "present"
        } else {
            "absent"
        }
    );
    let framebuffer = &boot_info.framebuffer;
    if crate::framebuffer::mapped_length(framebuffer).is_some() {
        say!(
            "linox: framebuffer {}x{} stride {} at {:#x}\n",
            framebuffer.width,
            framebuffer.height,
            framebuffer.stride,
            framebuffer.base
        );
    }
    let rsdp = boot_info.acpi_rsdp as u64;
    let mut summary = Summary::default();
    step("clock calibration", || {
        summary.clock = calibrate_clock(rsdp);
    });
    step("memory map", || report_memory(boot_info));
    let ivrs = step("ACPI tables", || report_acpi(rsdp));
    summary.iommus = ivrs
        .as_ref()
        .map_or(0, |ivrs| ivrs.units.iter().flatten().count());
    step("PCI enumeration", report_pci);
    let mut remapping = step("AMD-Vi DMA remapping", || match &ivrs {
        Some(ivrs) => enable_dma_remapping(ivrs),
        None => [const { None }; MAX_IOMMUS],
    });
    summary.remapping = remapping.iter().flatten().count();
    step("network", report_network);
    step("HD Audio", report_audio);
    summary.nvme = step("disks", || report_disks(&mut remapping));
    let keyboards = step("USB (xHCI)", open_keyboards);
    for controller in keyboards.iter().flatten() {
        summary.xhci.0 += 1;
        for input in controller.inputs() {
            match input.kind {
                xhci::InputKind::Keyboard => summary.keyboards += 1,
                _ => summary.pointers += 1,
            }
        }
    }
    summary.xhci.1 = functions(pci::Identity::is_xhci).1;
    report_faults(&mut remapping, false);
    set_stage("summary");
    report_summary(&summary);

    if keyboards
        .iter()
        .flatten()
        .all(|controller| controller.keyboards().next().is_none())
        && !crate::SERIAL_PRESENT.load(core::sync::atomic::Ordering::Acquire)
    {
        say!("linox: no keyboard or serial input; halted\n");
        halt();
    }
    shell(boot_info, keyboards, remapping)
}

/// Runs one bring-up step under its stage name, and reports how long it
/// took when that was long enough to notice.
fn step<T>(name: &'static str, body: impl FnOnce() -> T) -> T {
    set_stage(name);
    let started = crate::arch::x86_64::timer::timestamp_counter();
    let result = body();
    let elapsed = clock::elapsed_ms(started);
    if elapsed >= 1000 {
        say!("linox: {} took {} ms\n", name, elapsed);
    }
    result
}

fn report_summary(summary: &Summary) {
    say!("\nlinox: ---- bring-up summary ----\n");
    match summary.clock {
        Some((source, hz)) => say!(
            "linox: clock: TSC {}.{:03} MHz, calibrated against the {}\n",
            hz / 1_000_000,
            hz / 1000 % 1000,
            source
        ),
        None => say!("linox: clock: NOT calibrated; timeouts assume a 5 GHz TSC\n"),
    }
    say!(
        "linox: AMD-Vi: {} unit(s) in IVRS, remapping on {}\n",
        summary.iommus,
        summary.remapping
    );
    say!(
        "linox: NVMe: {} of {} controller(s) opened\n",
        summary.nvme.0,
        summary.nvme.1
    );
    say!(
        "linox: xHCI: {} of {} controller(s) running, {} keyboard(s), {} mouse/tablet(s)\n",
        summary.xhci.0,
        summary.xhci.1,
        summary.keyboards,
        summary.pointers
    );
    say!("linox: (type 'log' to page back through the whole report)\n");
}

/// Calibrates the timestamp counter against the ACPI PM timer or the HPET,
/// whichever the firmware describes first.
fn calibrate_clock(rsdp: u64) -> Option<(&'static str, u64)> {
    let mut references = [None; 2];
    for_each_table(rsdp, |signature, table| {
        let length = table.len();
        match signature {
            // FADT (ACPI 6.5 section 5.2.9): PM_TMR_BLK at 76, PM_TMR_LEN
            // at 91, flags at 112 (TMR_VAL_EXT is bit 8, HW_REDUCED_ACPI
            // bit 20), X_PM_TMR_BLK (a generic address) at 208.
            b"FACP" if length >= 116 => {
                let flags = u32_at(table, 112);
                let wide = flags & 1 << 8 != 0;
                if flags & 1 << 20 != 0 {
                    return;
                }
                let extended = if length >= 220 {
                    let space = table[208];
                    let address = u64_at(table, 212);
                    match (space, address) {
                        (_, 0) => None,
                        (0, address) => Some(clock::Reference::PmTimerMemory { address, wide }),
                        (1, port) if port <= 0xffff => Some(clock::Reference::PmTimerPort {
                            port: port as u16,
                            wide,
                        }),
                        _ => None,
                    }
                } else {
                    None
                };
                let port = u32_at(table, 76);
                let length = table[91];
                references[0] = extended.or_else(|| {
                    (port != 0 && port <= 0xffff && length == 4).then_some(
                        clock::Reference::PmTimerPort {
                            port: port as u16,
                            wide,
                        },
                    )
                });
            }
            // HPET description table: the block's generic address at 40.
            b"HPET" if length >= 56 => {
                let space = table[40];
                let address = u64_at(table, 44);
                if space == 0 && address != 0 {
                    references[1] = Some(clock::Reference::Hpet { address });
                }
            }
            _ => {}
        }
    });
    for reference in references.into_iter().flatten() {
        match clock::calibrate(reference) {
            Some(hz) => {
                say!(
                    "linox: TSC runs at {}.{:03} MHz (measured against the {})\n",
                    hz / 1_000_000,
                    hz / 1000 % 1000,
                    reference.name()
                );
                return Some((reference.name(), hz));
            }
            None => say!(
                "linox: the {} did not count; trying the next clock\n",
                reference.name()
            ),
        }
    }
    say!("linox: no ACPI timer to calibrate against; timeouts assume a 5 GHz TSC\n");
    None
}

/// Calls `visit` with the signature and bytes of every table the root
/// table lists: the whole table when the firmware maps the length its
/// header records, else only that 8-byte header.
fn for_each_table(rsdp: u64, mut visit: impl FnMut(&[u8; 4], &[u8])) {
    if rsdp == 0 {
        return;
    }
    let Some(revision) = firmware::with_identity_mapped(rsdp, 16, |prefix| {
        prefix.starts_with(b"RSD PTR ").then(|| prefix[15])
    })
    .flatten() else {
        return;
    };
    let root = if revision >= 2 {
        firmware::with_identity_mapped(rsdp, 32, |rsdp| (u64_at(rsdp, 24), 8))
    } else {
        firmware::with_identity_mapped(rsdp, 20, |rsdp| (u64::from(u32_at(rsdp, 16)), 4))
    };
    let Some((root, entry_size)) = root.filter(|(root, _)| *root != 0) else {
        return;
    };
    let Some(length) = firmware::with_identity_mapped(root, 8, |header| u32_at(header, 4)) else {
        return;
    };
    firmware::with_identity_mapped(root, length as usize, |root| {
        let entries = root.get(36..).unwrap_or_default();
        for entry in entries.chunks_exact(entry_size) {
            let table = if entry_size == 8 {
                u64_at(entry, 0)
            } else {
                u64::from(u32_at(entry, 0))
            };
            if table == 0 {
                continue;
            }
            let Some((signature, length)) = firmware::with_identity_mapped(table, 8, |header| {
                (bytes_at::<4>(header, 0), u32_at(header, 4) as usize)
            }) else {
                continue;
            };
            if firmware::with_identity_mapped(table, length, |table| visit(&signature, table))
                .is_none()
            {
                let _ =
                    firmware::with_identity_mapped(table, 8, |header| visit(&signature, header));
            }
        }
    });
}

/// The `N` bytes at `offset` of a table, zeros past its end.
fn bytes_at<const N: usize>(table: &[u8], offset: usize) -> [u8; N] {
    table
        .get(offset..offset.saturating_add(N))
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or([0; N])
}

fn u32_at(table: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes_at(table, offset))
}

fn u64_at(table: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes_at(table, offset))
}

fn halt() -> ! {
    loop {
        // SAFETY: bring-up runs with interrupts disabled and never resumes.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Collects the PCI functions that satisfy `wanted`.
fn functions(
    wanted: impl Fn(&pci::Identity) -> bool,
) -> ([Option<pci::Function>; MAX_CONTROLLERS], usize) {
    let mut found = [None; MAX_CONTROLLERS];
    let mut count = 0;
    pci::for_each_function(|device| {
        if wanted(&device) && count < MAX_CONTROLLERS {
            found[count] = Some(device.address);
            count += 1;
        }
    });
    (found, count)
}

fn report_pci() {
    say!("linox: PCI devices:\n");
    pci::for_each_function(|device| {
        say!(
            "  {:02x}:{:02x}.{} {:04x}:{:04x} {:02x}{:02x}{:02x} {}\n",
            device.address.bus,
            device.address.device,
            device.address.function,
            device.vendor,
            device.device,
            device.class,
            device.subclass,
            device.interface,
            device.class_name()
        );
    });
}

fn report_network() {
    // One probe per boot is enough to tell offers apart.
    static mut TRANSACTION: u32 = 0x6769_6e00;
    pci::for_each_function(|device| {
        if device.class != 0x02 {
            return;
        }
        let address = device.address;
        say!(
            "linox: network {:02x}:{:02x}.{}: ",
            address.bus,
            address.device,
            address.function
        );
        // SAFETY: bring-up runs on one CPU and only here uses the counter.
        let transaction = unsafe {
            TRANSACTION = TRANSACTION.wrapping_add(1);
            TRANSACTION
        };
        if e1000e::is_supported(&device) {
            // SAFETY: bring-up is the only driver of this controller, and the
            // firmware identity map covers its registers and DMA pages.
            set_stage("network: Intel 82574");
            let Some(mut nic) = e1000e::Controller::open(address) else {
                say!("Intel 82574 reset failed\n");
                return;
            };
            say!(
                "Intel 82574, MAC {}, {}\n",
                net::Mac(nic.mac()),
                if nic.link_up() { "link up" } else { "no link" }
            );
            report_dhcp(&mut nic, transaction);
            return;
        }
        if !realtek::is_supported(&device) {
            say!(
                "{:04x}:{:04x} has no driver yet\n",
                device.vendor,
                device.device
            );
            return;
        }
        let Some(report) = realtek::probe(address) else {
            say!("Realtek {:04x} registers unavailable\n", device.device);
            return;
        };
        say!(
            "Realtek {:04x} chip {:#x} ({}), MAC {}, ",
            device.device,
            report.chip,
            realtek::chip_name(report.chip).unwrap_or("unknown chip"),
            net::Mac(report.mac)
        );
        match report.speed {
            Some(speed) => say!(
                "link up at {} Mb/s {} duplex\n",
                speed,
                if report.full_duplex { "full" } else { "half" }
            ),
            None => say!("no link yet\n"),
        }
        if !realtek::can_transfer(&device) {
            return;
        }
        // The previous driver may have powered the PHY down, so open the
        // controller (which powers it up and renegotiates) with or without
        // a link now.
        set_stage("network: Realtek reset and link");
        match realtek::Controller::open(address) {
            Ok(mut nic) => match nic.link_speed() {
                Some(speed) => {
                    say!("linox:   link up at {} Mb/s after reset\n", speed);
                    set_stage("network: Realtek DHCP");
                    report_dhcp(&mut nic, transaction);
                }
                None => say!("linox:   no link after reset (is a cable plugged in?)\n"),
            },
            Err(error) => say!("linox:   bring-up failed: {:?}\n", error),
        }
    });
}

/// Resets each HD Audio controller and lists its codecs and output pins.
fn report_audio() {
    pci::for_each_function(|device| {
        if !hda::is_supported(&device) {
            return;
        }
        let address = device.address;
        say!(
            "linox: audio {:02x}:{:02x}.{}: {:04x}:{:04x} HD Audio",
            address.bus,
            address.device,
            address.function,
            device.vendor,
            device.device
        );
        let mut controller = match hda::Controller::open(address) {
            Ok(controller) => controller,
            Err(error) => {
                say!(", {:?}\n", error);
                return;
            }
        };
        say!("\n");
        for codec in controller.codecs() {
            let codec = match codec {
                Ok(codec) => codec,
                Err(error) => {
                    say!("linox:   codec: {:?}\n", error);
                    continue;
                }
            };
            say!(
                "linox:   codec {}: {:04x}:{:04x}, {} output converters, outputs:",
                codec.address,
                codec.vendor,
                codec.device,
                codec.converters
            );
            let mut outputs = codec
                .pins
                .iter()
                .flatten()
                .filter(|pin| pin.is_output() && pin.connected())
                .peekable();
            if outputs.peek().is_none() {
                say!(" none");
            }
            for pin in outputs {
                say!(" {} (node {})", pin.device_name(), pin.node);
            }
            say!("\n");
        }
    });
}

/// Plays a one-second tone on every HD Audio codec with a connected output.
fn play_test_tones() {
    pci::for_each_function(|device| {
        if !hda::is_supported(&device) {
            return;
        }
        let Ok(mut controller) = hda::Controller::open(device.address) else {
            return;
        };
        let mut codecs = [const { None }; 15];
        for (slot, codec) in codecs.iter_mut().zip(controller.codecs().flatten()) {
            *slot = Some(codec);
        }
        for codec in codecs.iter().flatten() {
            match controller.play_tone(codec, 1000) {
                Ok(advanced) => say!(
                    "linox: codec {} played a 440 Hz tone; DMA moved {} bytes\n",
                    codec.address,
                    advanced
                ),
                Err(error) => say!("linox: codec {}: {:?}\n", codec.address, error),
            }
        }
    });
}

/// Broadcasts a DHCP discover on `nic` and reports the offer, which shows
/// that the controller can send and receive.
fn report_dhcp(nic: &mut impl Nic, transaction: u32) {
    match net::dhcp_discover(nic, transaction) {
        Some(offer) => {
            say!(
                "linox:   DHCP offer {} from {}",
                net::Ipv4(offer.address),
                net::Ipv4(offer.server)
            );
            if let Some(subnet) = offer.subnet {
                say!(", netmask {}", net::Ipv4(subnet));
            }
            if let Some(router) = offer.router {
                say!(", router {}", net::Ipv4(router));
            }
            if let Some(dns) = offer.dns {
                say!(", DNS {}", net::Ipv4(dns));
            }
            say!("\n");
        }
        None => say!("linox:   no DHCP offer\n"),
    }
}

/// Reports every disk; returns how many NVMe controllers opened, of how many.
fn report_disks(remapping: &mut Remapping) -> (usize, usize) {
    let (controllers, nvme_count) = functions(pci::Identity::is_nvme);
    let mut nvme_opened = 0;
    for function in controllers.iter().flatten() {
        if probe_nvme(*function, remapping) {
            nvme_opened += 1;
        }
    }
    let (controllers, _) = functions(pci::Identity::is_ahci);
    let mut slot = 0;
    for function in controllers.iter().flatten() {
        let (base, ports, version) = match ahci::open_controller(*function) {
            Ok(opened) => opened,
            Err(error) => {
                say!(
                    "linox: AHCI {:02x}:{:02x}.{}: {:?}\n",
                    function.bus,
                    function.device,
                    function.function,
                    error
                );
                continue;
            }
        };
        say!(
            "linox: AHCI {:02x}:{:02x}.{}: version {}.{}, ports {:#x}\n",
            function.bus,
            function.device,
            function.function,
            version >> 16,
            (version >> 8) & 0xff,
            ports
        );
        for port in (0..32).filter(|port| ports & (1 << port) != 0) {
            if slot == ahci::MAX_PORTS {
                break;
            }
            match ahci::Disk::open(&base, port, slot) {
                Ok(mut disk) => {
                    slot += 1;
                    let bytes = disk.sectors.saturating_mul(u64::from(disk.sector_size));
                    say!(
                        "linox:   port {}: {} (serial {}), {} sectors of {} bytes ({} MiB)\n",
                        disk.port(),
                        trimmed(&disk.model),
                        trimmed(&disk.serial),
                        disk.sectors,
                        disk.sector_size,
                        bytes >> 20
                    );
                    list_partitions(&mut disk);
                }
                Err(ahci::Error::NoDevice) => {}
                Err(error) => say!("linox:   port {}: {:?}\n", port, error),
            }
        }
    }
    (nvme_opened, nvme_count)
}

/// Every USB controller with at least one input device or speaker.
type UsbKeyboards = [Option<xhci::Controller>; MAX_CONTROLLERS];

fn open_keyboards() -> UsbKeyboards {
    let mut opened = [const { None }; MAX_CONTROLLERS];
    let (controllers, count) = functions(pci::Identity::is_xhci);
    if count == 0 {
        say!("linox: no xHCI controller\n");
    }
    for (slot, function) in controllers.iter().flatten().enumerate() {
        say!(
            "linox: xHCI {:02x}:{:02x}.{}: looking for keyboards\n",
            function.bus,
            function.device,
            function.function
        );
        // The whole of BAR 0, as config space sizes it.
        let registers = function.memory_bar(0).and_then(|bar| {
            let length = function
                .memory_bar_size(0)
                .map_or(0x1_0000, |size| size as usize);
            Mmio::firmware(bar, length)
        });
        let result = registers.map_or(Err(xhci::Error::NoMemoryBar), |registers| {
            xhci::Controller::open(*function, registers, true)
        });
        match result {
            Ok(controller) => {
                for speaker in controller.speakers() {
                    say!(
                        "linox:   USB speaker {:04x}:{:04x} on port {}: {}, {} channels, {}-bit\n",
                        speaker.vendor,
                        speaker.product,
                        speaker.location,
                        speaker.name,
                        speaker.channels,
                        speaker.bits
                    );
                }
                for input in controller.inputs() {
                    say!(
                        "linox:   {} {:04x}:{:04x} on port {}\n",
                        match input.kind {
                            xhci::InputKind::Keyboard => "keyboard",
                            xhci::InputKind::Mouse => "mouse",
                            xhci::InputKind::Tablet => "tablet",
                        },
                        input.vendor,
                        input.product,
                        input.location
                    );
                }
                opened[slot] = Some(controller);
            }
            Err(error) => say!("linox:   {:?}\n", error),
        }
    }
    opened
}

/// The shell's keyboards: every USB keyboard, and serial when present.
struct Input {
    usb: UsbKeyboards,
    decoders: [[keyboard::Keyboard; xhci::MAX_INPUTS]; MAX_CONTROLLERS],
}

impl Input {
    /// Collects the bytes typed since the last call into `pressed`.
    fn poll(&mut self, pressed: &mut [u8; 16]) -> usize {
        let mut count = 0;
        for (controller, decoders) in self.usb.iter_mut().zip(self.decoders.iter_mut()) {
            let Some(report) = controller.as_mut().and_then(xhci::Controller::poll) else {
                continue;
            };
            if report.kind != xhci::InputKind::Keyboard {
                continue;
            }
            decoders[report.input].report(&report.bytes, |bytes| {
                for byte in bytes {
                    if count < pressed.len() {
                        pressed[count] = *byte;
                        count += 1;
                    }
                }
            });
        }
        if count < pressed.len() && crate::serial_input_ready() {
            pressed[count] = crate::serial_read_byte_blocking();
            count += 1;
        }
        count
    }

    /// Waits for one key.
    fn key(&mut self) -> u8 {
        let mut pressed = [0_u8; 16];
        loop {
            if self.poll(&mut pressed) > 0 {
                return pressed[0];
            }
            core::hint::spin_loop();
        }
    }
}

fn shell(boot_info: &BootInfo, usb: UsbKeyboards, mut remapping: Remapping) -> ! {
    set_stage("bring-up shell");
    say!("\nLinox bring-up shell. Type 'help' for commands.\n");
    let mut input = Input {
        usb,
        decoders: core::array::from_fn(|_| core::array::from_fn(|_| keyboard::Keyboard::new())),
    };
    let mut line = [0_u8; LINE_CAPACITY];
    let mut length = 0;
    say!("bring-up> ");
    loop {
        let mut pressed = [0_u8; 16];
        let count = input.poll(&mut pressed);
        for byte in pressed[..count].iter().copied() {
            match byte {
                b'\r' | b'\n' => {
                    // The prompt is in the log already; add what was typed.
                    crate::kernel_log::record(&line[..length]);
                    say!("\n");
                    run_command(boot_info, &mut input, &mut remapping, &line[..length]);
                    length = 0;
                    set_stage("bring-up shell");
                    say!("bring-up> ");
                }
                0x08 | 0x7f => {
                    if length > 0 {
                        length -= 1;
                        crate::serial_write_raw(b"\x08 \x08");
                    }
                }
                0x03 => {
                    length = 0;
                    say!("^C\nbring-up> ");
                }
                0x0c => {
                    crate::serial_write_raw(b"\x1b[2J\x1b[H");
                    say!("bring-up> ");
                    length = 0;
                }
                0x20..=0x7e if length < LINE_CAPACITY => {
                    line[length] = byte;
                    length += 1;
                    crate::serial_write_raw(&[byte]);
                }
                _ => {}
            }
        }
    }
}

const HELP: &str = "\
Commands:
  log [end]   page through everything printed since boot (Enter: next, b: back, q: quit)
  pci acpi mem disks net usb   repeat one report
  faults      AMD-Vi DMA faults logged since the last look
  disktest    write, verify and restore one block of each Linox volume partition
  beep        play a test tone on every HD Audio codec and USB speaker
  crash [panic]   test the crash report: an invalid-opcode fault, or a Rust panic
  clear  echo TEXT  reboot  poweroff
";

fn run_command(boot_info: &BootInfo, input: &mut Input, remapping: &mut Remapping, line: &[u8]) {
    let text = core::str::from_utf8(line).unwrap_or("").trim();
    let (command, argument) = text.split_once(' ').unwrap_or((text, ""));
    match command {
        "" => {}
        "help" => say!("{}", HELP),
        "beep" => {
            set_stage("shell: beep");
            play_test_tones();
            for controller in input.usb.iter_mut().flatten() {
                for index in 0..xhci::MAX_SPEAKERS {
                    let Some((vendor, product, name)) = controller
                        .speakers()
                        .nth(index)
                        .map(|speaker| (speaker.vendor, speaker.product, speaker.name))
                    else {
                        break;
                    };
                    if let Some(sent) = controller.play_tone(index, 1000) {
                        say!(
                            "linox: USB speaker {:04x}:{:04x} played a 500 Hz tone ({} packets) on its {}\n",
                            vendor,
                            product,
                            sent,
                            name
                        );
                    }
                }
            }
        }
        "log" => log::page(|| input.key(), argument.trim() == "end"),
        "pci" => report_pci(),
        "net" => {
            set_stage("shell: net");
            report_network();
        }
        "acpi" => {
            report_acpi(boot_info.acpi_rsdp as u64);
        }
        "mem" => report_memory(boot_info),
        "disks" => {
            set_stage("shell: disks");
            report_disks(&mut [const { None }; MAX_IOMMUS]);
        }
        "usb" => report_usb(&input.usb),
        "faults" => report_faults(remapping, true),
        "disktest" => {
            set_stage("shell: disktest");
            test_disk_writes();
        }
        "crash" => {
            set_stage("shell: crash test");
            if argument.trim() == "panic" {
                panic!("crash test requested in the bring-up shell");
            }
            // SAFETY: ud2 raises #UD, which the bring-up exception table
            // reports; the handler never returns.
            unsafe { core::arch::asm!("ud2", options(nomem, nostack, noreturn)) };
        }
        "clear" => crate::serial_write_raw(b"\x1b[2J\x1b[H"),
        "echo" => say!("{}\n", argument),
        "reboot" => reset(boot_info, EFI_RESET_COLD),
        "poweroff" => reset(boot_info, EFI_RESET_SHUTDOWN),
        _ => say!("unknown command: {} (try 'help')\n", command),
    }
}

/// Lists the USB input devices and speakers each running controller found.
fn report_usb(usb: &UsbKeyboards) {
    for controller in usb.iter().flatten() {
        for input in controller.inputs() {
            say!(
                "linox: {} {:04x}:{:04x} on port {}\n",
                match input.kind {
                    xhci::InputKind::Keyboard => "keyboard",
                    xhci::InputKind::Mouse => "mouse",
                    xhci::InputKind::Tablet => "tablet",
                },
                input.vendor,
                input.product,
                input.location
            );
        }
        for speaker in controller.speakers() {
            say!(
                "linox: USB speaker {:04x}:{:04x} on port {}: {}\n",
                speaker.vendor,
                speaker.product,
                speaker.location,
                speaker.name
            );
        }
    }
}

fn reset(boot_info: &BootInfo, kind: u32) {
    set_stage("shutting down NVMe before reset");
    let (controllers, _) = functions(pci::Identity::is_nvme);
    for function in controllers.iter().flatten() {
        if nvme::shutdown(*function) {
            say!(
                "linox: NVMe {:02x}:{:02x}.{} shut down\n",
                function.bus,
                function.device,
                function.function
            );
        }
    }
    set_stage("UEFI ResetSystem");
    say!("linox: resetting through UEFI runtime services\n");
    // SAFETY: bring-up never calls SetVirtualAddressMap, so the runtime
    // services remain callable through the firmware identity map.
    unsafe { (boot_info.reset_system)(kind, 0, 0, core::ptr::null()) };
}

fn report_memory(boot_info: &BootInfo) {
    let count = boot_info.memory_map_size / boot_info.memory_descriptor_size;
    let (mut usable, mut usable_low, mut highest) = (0_u64, 0_u64, 0_u64);
    for index in 0..count {
        // SAFETY: kernel_main validated the memory-map bounds and descriptor size.
        let descriptor = unsafe {
            core::ptr::read_unaligned(
                boot_info
                    .memory_map
                    .add(index * boot_info.memory_descriptor_size)
                    .cast::<UefiMemoryDescriptor>(),
            )
        };
        let start = descriptor.physical_start;
        let end = start.saturating_add(descriptor.page_count.saturating_mul(4096));
        highest = highest.max(end);
        if matches!(
            descriptor.memory_type,
            EFI_CONVENTIONAL_MEMORY
                | EFI_BOOT_SERVICES_CODE
                | EFI_BOOT_SERVICES_DATA
                | EFI_LOADER_CODE
                | EFI_LOADER_DATA
        ) {
            usable += end - start;
            usable_low += end.min(FOUR_GIB).saturating_sub(start.min(FOUR_GIB));
        }
    }
    say!(
        "linox: memory {} MiB usable, {} MiB below 4 GiB, map ends at {:#x}\n",
        usable >> 20,
        usable_low >> 20,
        highest
    );
}

/// Reports the ACPI tables and returns what IVRS says about AMD-Vi.
fn report_acpi(rsdp: u64) -> Option<amd_iommu::Ivrs> {
    if rsdp == 0 {
        say!("linox: ACPI root pointer missing\n");
        return None;
    }
    let mut ivrs = None;
    say!("linox: ACPI tables:");
    for_each_table(rsdp, |signature, table| {
        say!(" {}", core::str::from_utf8(signature).unwrap_or("????"));
        match signature {
            b"APIC" => report_madt(table),
            b"IVRS" => {
                ivrs = Some(amd_iommu::parse_ivrs(table));
                say!("[AMD-Vi]");
            }
            b"DMAR" => say!("[Intel VT-d]"),
            b"MCFG" => report_mcfg(table),
            b"HPET" => say!("[{:#x}]", u64_at(table, 44)),
            _ => {}
        }
    });
    say!("\n");
    if let Some(ivrs) = &ivrs {
        report_ivrs(ivrs);
    }
    ivrs
}

fn report_ivrs(ivrs: &amd_iommu::Ivrs) {
    say!(
        "linox: IVRS: IVinfo {:#x}{}\n",
        ivrs.info,
        if ivrs.preboot_dma_protection() {
            " (firmware enabled pre-boot DMA protection)"
        } else {
            ""
        }
    );
    for unit in ivrs.units.iter().flatten() {
        let report = amd_iommu::probe(unit.base);
        say!(
            "linox: AMD-Vi {:#x} (PCI {:02x}:{:02x}.{}, IVHD flags {:#04x}): {} by firmware, \
             control {:#x}, status {:#x}, features ",
            unit.base,
            unit.device >> 8,
            (unit.device >> 3) & 0x1f,
            unit.device & 7,
            unit.flags,
            if report.enabled() {
                "enabled"
            } else {
                "disabled"
            },
            report.control,
            report.status
        );
        let _ = report.write_features(&mut crate::drivers::Console);
        if unit.segment != 0 {
            // Linox enumerates only PCI segment 0.
            say!(", PCI segment {} (not enumerated)", unit.segment);
        }
        if report.exclusion & 1 != 0 {
            say!(", exclusion range at {:#x}", report.exclusion & !0xfff);
        }
        say!("\n");
    }
    for range in ivrs.unity.iter().flatten() {
        let (read, write) = range.access();
        say!(
            "linox: IVMD: devices {:04x}-{:04x} need {:#x}-{:#x} ({}{}{})\n",
            range.first_device,
            range.last_device,
            range.start,
            range.start.saturating_add(range.length),
            if range.is_exclusion() {
                "exclusion"
            } else {
                "unity"
            },
            if read { ", read" } else { "" },
            if write { ", write" } else { "" }
        );
    }
    let aliases = ivrs.aliases.iter().flatten().count();
    if aliases != 0 {
        say!("linox: IVRS: {} requester-ID alias(es)\n", aliases);
    }
    if ivrs.dropped != 0 {
        say!(
            "linox: IVRS: {} entries did not fit and were ignored\n",
            ivrs.dropped
        );
    }
}

/// The AMD-Vi units with remapping on.
type Remapping = [Option<amd_iommu::Remapping>; MAX_IOMMUS];

/// Turns on DMA remapping on every AMD-Vi unit. Devices Linox drives reach
/// only their driver's buffers, display controllers keep untranslated access
/// for the firmware framebuffer, devices with IVMD unity ranges reach those,
/// and every other device is blocked.
fn enable_dma_remapping(ivrs: &amd_iommu::Ivrs) -> Remapping {
    let mut units = [const { None }; MAX_IOMMUS];
    if ivrs.units.iter().all(Option::is_none) {
        return units;
    }
    let (xhci, nvme, ahci) = (
        xhci::dma_regions(),
        nvme::dma_regions(),
        ahci::dma_regions(),
    );
    let (intel, realtek, audio) = (
        e1000e::dma_regions(),
        realtek::dma_regions(),
        hda::dma_regions(),
    );
    // The tables are claimed for good: remapping is enabled once per boot.
    let Some(mut table) = amd_iommu::DeviceTableBuilder::new(&ivrs.unity) else {
        say!("linox: AMD-Vi remapping not enabled: its tables are in use\n");
        return units;
    };
    let (mut confined, mut passthrough, mut blocked) = (0, 0, 0);
    let mut failure = None;
    pci::for_each_function(|device| {
        let access = if device.is_xhci() {
            amd_iommu::Access::Regions(&xhci)
        } else if device.is_nvme() {
            amd_iommu::Access::Regions(&nvme)
        } else if device.is_ahci() {
            amd_iommu::Access::Regions(&ahci)
        } else if e1000e::is_supported(&device) {
            amd_iommu::Access::Regions(&intel)
        } else if realtek::can_transfer(&device) {
            amd_iommu::Access::Regions(&realtek)
        } else if hda::is_supported(&device) {
            amd_iommu::Access::Regions(&audio)
        } else if device.class == 0x03 {
            amd_iommu::Access::Passthrough
        } else {
            amd_iommu::Access::Blocked
        };
        match access {
            amd_iommu::Access::Regions(_) => confined += 1,
            amd_iommu::Access::Passthrough => passthrough += 1,
            amd_iommu::Access::Blocked => blocked += 1,
        }
        let id = device.address.requester_id();
        // A device whose DMA carries another requester ID (IVHD alias
        // entries) is translated under that ID.
        let alias = ivrs.alias_of(id);
        for target in core::iter::once(id).chain(alias) {
            if let Err(error) = table.assign(target, access) {
                failure = Some(error);
            }
        }
    });
    if let Some(error) = failure {
        say!("linox: AMD-Vi remapping not enabled: {:?}\n", error);
        return units;
    }
    for (slot, unit) in ivrs.units.iter().enumerate() {
        let Some(unit) = unit else {
            continue;
        };
        // The base comes from IVRS, the firmware identity map covers it,
        // and bring-up is the only code driving the unit.
        match amd_iommu::Remapping::enable(unit, &table) {
            Ok(remapping) => {
                say!(
                    "linox: AMD-Vi {:#x}: DMA remapping on; {} devices confined to their \
                     driver's buffers ({} domains), {} displays passed through, {} blocked\n",
                    unit.base,
                    confined,
                    table.domains(),
                    passthrough,
                    blocked
                );
                if let Some(free) = units.get_mut(slot) {
                    *free = Some(remapping);
                }
            }
            Err(error) => say!(
                "linox: AMD-Vi {:#x}: remapping failed: {:?}\n",
                unit.base,
                error
            ),
        }
    }
    units
}

/// Prints the DMA faults the units have logged since the last call: a
/// device Linox blocked that still tried to reach memory shows up here.
fn report_faults(remapping: &mut Remapping, always: bool) {
    let mut count = 0;
    for unit in remapping.iter_mut().flatten() {
        if unit.overflowed() {
            say!(
                "linox: AMD-Vi {:#x}: the event log overflowed; later faults were lost\n",
                unit.base()
            );
        }
        while let Some(fault) = unit.next_fault() {
            count += 1;
            if count <= 32 {
                say!(
                    "linox: AMD-Vi event {:#x} from {:02x}:{:02x}.{} at {:#x}{}\n",
                    fault.code,
                    fault.device >> 8,
                    (fault.device >> 3) & 0x1f,
                    fault.device & 7,
                    fault.address,
                    if fault.is_page_fault() {
                        " (I/O page fault: a blocked DMA)"
                    } else {
                        ""
                    }
                );
            }
        }
    }
    if count > 32 {
        say!("linox: ... and {} more AMD-Vi events\n", count - 32);
    }
    if always && count == 0 {
        say!(
            "linox: {}\n",
            if remapping.iter().any(Option::is_some) {
                "no new AMD-Vi events"
            } else {
                "AMD-Vi remapping is not on"
            }
        );
    }
}

/// Checks that remapping stops `controller` from writing outside its own
/// buffers, by asking it to read a block into a page it was not given.
fn verify_dma_confinement(
    controller: &mut nvme::Controller,
    function: pci::Function,
    remapping: &mut Remapping,
) {
    static PROBE: StaticDma<1> = StaticDma::new();
    // Only this check uses the probe page.
    let Some(page) = PROBE.claim() else {
        return;
    };
    let probe = page.device_address(0);
    page.fill(0, 4096, 0x5a);
    let result = controller.read_block_to(0, probe);
    // A successful stray DMA would have changed it.
    let untouched = (0..4096).all(|offset| page.read::<u8>(offset) == 0x5a);
    // Emulated units may log faults with nonstandard encodings, so any
    // event from the controller counts as evidence; the page is the test.
    let mut fault = None;
    for unit in remapping.iter_mut().flatten() {
        while let Some(event) = unit.next_fault() {
            if event.device == function.requester_id() {
                fault.get_or_insert(event);
            }
        }
    }
    if untouched {
        say!(
            "linox:   AMD-Vi blocked a stray DMA from this controller to {:#x}",
            probe
        );
        match fault {
            Some(fault) => say!(
                " (event {:#x} at {:#x}{})\n",
                fault.code,
                fault.address,
                if fault.is_page_fault() {
                    ", I/O page fault"
                } else {
                    ""
                }
            ),
            None => say!(" (no event logged)\n"),
        }
    } else {
        say!(
            "linox:   WARNING: AMD-Vi did not stop a stray DMA to {:#x} (command {})\n",
            probe,
            if result.is_ok() {
                "completed"
            } else {
                "failed"
            }
        );
    }
}

fn report_madt(table: &[u8]) {
    let length = table.len();
    let (mut enabled, mut capable) = (0, 0);
    let mut offset = 44;
    while offset + 2 <= length {
        let kind = table[offset];
        let size = usize::from(table[offset + 1]);
        if size < 2 {
            break;
        }
        let flags = match kind {
            0 => Some(u32_at(table, offset + 4)),
            9 => Some(u32_at(table, offset + 8)),
            _ => None,
        };
        match flags {
            Some(flags) if flags & 1 != 0 => enabled += 1,
            Some(flags) if flags & 2 != 0 => capable += 1,
            _ => {}
        }
        offset += size;
    }
    say!("[{} CPUs", enabled);
    if capable != 0 {
        say!(" +{} hotplug", capable);
    }
    say!("]");
}

fn report_mcfg(table: &[u8]) {
    let length = table.len();
    let mut offset = 44;
    while offset + 16 <= length {
        say!(
            "[{:#x} buses {}-{}]",
            u64_at(table, offset),
            table[offset + 10],
            table[offset + 11]
        );
        offset += 16;
    }
}

/// Checks NVMe writes on every Linox volume partition without changing it:
/// saves the partition's last block, writes a pattern, reads it back,
/// restores the block and reads that back, and checks that a write one block
/// past the partition is refused. Disks without such a partition are not
/// written at all.
fn test_disk_writes() {
    let (controllers, _) = functions(pci::Identity::is_nvme);
    for function in controllers.iter().flatten() {
        let mut controller = match nvme::Controller::open(*function) {
            Ok((controller, _)) => controller,
            Err(error) => {
                say!(
                    "linox: NVMe {:02x}:{:02x}.{}: {:?}\n",
                    function.bus,
                    function.device,
                    function.function,
                    error
                );
                continue;
            }
        };
        let extents = gpt::writable_extents(&mut controller);
        if extents.iter().all(Option::is_none) {
            say!(
                "linox: NVMe {:02x}:{:02x}.{}: no Linox volume partition; nothing written\n",
                function.bus,
                function.device,
                function.function
            );
        }
        for extent in extents.iter().flatten() {
            say!(
                "linox: NVMe {:02x}:{:02x}.{}: Linox volume blocks {}-{}: {}\n",
                function.bus,
                function.device,
                function.function,
                extent.first_lba(),
                extent.last_lba(),
                check_extent_writes(&mut controller, extent)
            );
        }
    }
}

fn check_extent_writes(
    controller: &mut nvme::Controller,
    extent: &gpt::WritableExtent,
) -> &'static str {
    let block = extent.last_lba();
    let size = controller.block_size as usize;
    if size > 4096 {
        return "block size unsupported";
    }
    let mut original = [0_u8; 4096];
    let mut pattern = [0_u8; 4096];
    match controller.read(block, 1) {
        Ok(data) => original[..size].copy_from_slice(data),
        Err(_) => return "reading the block failed",
    }
    for (index, byte) in pattern[..size].iter_mut().enumerate() {
        *byte = (index as u8) ^ 0x5a;
    }
    pattern[..8].copy_from_slice(b"LINOXWR1");
    if controller.write(extent, block, &pattern[..size]).is_err()
        || controller.read(block, 1).ok() != Some(&pattern[..size])
    {
        let _ = controller.write(extent, block, &original[..size]);
        return "write or read-back failed";
    }
    if controller.write(extent, block, &original[..size]).is_err()
        || controller.read(block, 1).ok() != Some(&original[..size])
    {
        return "restoring the block failed";
    }
    if controller
        .write(extent, block + 1, &pattern[..size])
        .is_ok()
    {
        return "a write past the partition was accepted";
    }
    "write verified, restored, and bounded"
}

fn probe_nvme(function: pci::Function, remapping: &mut Remapping) -> bool {
    say!(
        "linox: NVMe {:02x}:{:02x}.{}: ",
        function.bus,
        function.device,
        function.function
    );
    let (mut controller, identity) = match nvme::Controller::open(function) {
        Ok(opened) => opened,
        Err(error) => {
            say!("initialization failed: {:?}\n", error);
            return false;
        }
    };
    say!(
        "{} (serial {}, firmware {}, NVMe {}.{})\n",
        trimmed(&identity.model),
        trimmed(&identity.serial),
        trimmed(&identity.firmware),
        identity.version >> 16,
        (identity.version >> 8) & 0xff
    );
    let bytes = controller
        .block_count
        .saturating_mul(u64::from(controller.block_size));
    let (size, unit) = if bytes >= 1 << 30 {
        (bytes >> 30, "GiB")
    } else {
        (bytes >> 20, "MiB")
    };
    say!(
        "linox:   namespace {}: {} blocks of {} bytes ({} {})\n",
        controller.namespace,
        controller.block_count,
        controller.block_size,
        size,
        unit
    );
    list_partitions(&mut controller);
    if remapping.iter().any(Option::is_some) {
        verify_dma_confinement(&mut controller, function, remapping);
    }
    true
}

fn list_partitions(disk: &mut impl BlockDevice) {
    let header = match disk.read_blocks(gpt::HEADER_LBA, 1) {
        Some(block) => gpt::parse_header(block),
        None => {
            say!("linox:   reading the partition table failed\n");
            return;
        }
    };
    let Some(header) = header else {
        say!("linox:   no valid GPT\n");
        return;
    };
    say!("linox:   GPT disk {}\n", header.disk);
    let block_size = u64::from(disk.block_size());
    let entry_size = u64::from(header.entry_size);
    let mut cached_block = u64::MAX;
    let mut block = [0_u8; 4096];
    for index in 0..u64::from(header.entry_count.min(MAX_LISTED_PARTITIONS)) {
        let byte_offset = index * entry_size;
        let lba = header.entries_lba + byte_offset / block_size;
        if lba != cached_block {
            match disk.read_blocks(lba, 1) {
                Some(data) => block[..data.len()].copy_from_slice(data),
                None => {
                    say!("linox:   reading partition entries failed\n");
                    return;
                }
            }
            cached_block = lba;
        }
        let start = (byte_offset % block_size) as usize;
        let Some(entry) = block.get(start..start + entry_size as usize) else {
            break;
        };
        let Some(partition) = gpt::parse_entry(entry) else {
            continue;
        };
        let size = (partition.last_lba + 1).saturating_sub(partition.first_lba) * block_size;
        say!(
            "linox:   partition {}: {} MiB {} \"",
            index + 1,
            size >> 20,
            gpt::type_name(partition.kind)
        );
        let _ = partition.write_name(&mut crate::drivers::Console);
        say!("\"\n");
    }
}

fn trimmed(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes)
        .unwrap_or("?")
        .trim_matches(|character: char| character == ' ' || character == '\0')
}
