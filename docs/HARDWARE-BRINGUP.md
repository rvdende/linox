# Hardware bring-up: first boot on the development PC

This is the checklist for booting Linox from a USB stick on the machine it
is developed on, and the plan for getting from bring-up mode to the full
system there. Bring-up mode is described in the README ("Boot media and
physical machines"); its code is `kernel/src/bringup/` and
`kernel/src/drivers/`.

## The machine

MSI PRO X670-P WIFI (MS-7D67), BIOS 1.40 (2022-11-23), Ryzen 5 7600X
(Raphael). Secure Boot is **enabled** today (Ubuntu boots through shim).

| PCI | Device | IDs | Bring-up driver |
| --- | --- | --- | --- |
| 00:00.2 | AMD-Vi IOMMU | 1022:14d9 | `amd_iommu`: remapping, IVHD/IVMD/aliases |
| 03:00.0 | Radeon RX 6800 (Navi 21); 16 GiB BAR at 0xf8_0000_0000 (Resizable BAR on) | 1002:73bf | GOP framebuffer only; DMA passed through |
| 03:00.1, 18:00.1 | GPU HDMI/DP audio | 1002:ab28, 1002:1640 | `hda` (non-snooping: caches flushed) |
| 18:00.6 | Ryzen HD Audio | 1022:15e3 | `hda` (snoop enabled through config 0x42) |
| 07:00.0 | Realtek RTL8125B 2.5GbE, rev 05 | 10ec:8125 | `realtek`: reset, PHY power-up, DHCP probe |
| 0e:00.0 | MediaTek MT7922 Wi-Fi | 14c3:0616 | none (blocked by the IOMMU) |
| 12:00.0 | Crucial P3 4 TB NVMe (the Ubuntu disk) | c0a9:540a | `nvme`: read; writes only into Linox-type partitions |
| 08:00.0, 14:00.0, 16:00.0 | ASMedia ASM1061, AMD 600-series SATA | 1b21:0612, 1022:43f6 | `ahci` (read-only) |
| 13:00.0, 15:00.0 | AMD 600-series USB 3.2 xHCI (Promontory) | 1022:43f7 | `xhci` |
| 18:00.3, 18:00.4, 19:00.0 | Raphael USB 3.1 / USB 2.0 xHCI | 1022:15b6/7/8 | `xhci` |

USB devices that matter: the Corsair STRAFE RGB MK.2 keyboard (1b1c:1b48)
on 15:00.0 port 4, the Logitech Unifying receiver (046d:c543, keyboard and
mouse) on 13:00.0 port 6, and the board's USB audio (ALC4080, 0db0:3130,
UAC2) on 15:00.0 port 6.

## What changed for this boot (and why)

- **Screen first.** The loader prints each step on the firmware console
  (`linox loader: ...`), so a photo shows how far it got before the kernel
  took the screen. The kernel checks that the firmware's page tables map the
  framebuffer (it may sit in a 64-bit BAR near 1 TiB) before drawing.
  Bring-up installs its own exception table: a CPU fault prints the
  exception, registers, the kernel image base, return addresses and the
  bring-up stage on the screen. A Rust panic after ExitBootServices does the
  same (`report_panic`); before it, on the firmware console.
- **Bounded, calibrated waits.** The TSC is measured against the ACPI PM
  timer (or the HPET) before any driver runs; every hardware wait counts
  against it. Steps that take a second or more say so.
- **A log that can be read back.** Everything printed is kept in the
  128 KiB kernel log; `log` pages through it. A summary ends the report.
- **AMD-Vi**: takes the unit from firmware properly (stops command buffer,
  event/PPR/GA logs and their interrupts, waits for them to stop, clears
  the overflow latch), programs the control bits IVHD flags ask for plus
  coherent table walks; maps IVMD unity ranges for the devices they name;
  gives requester-ID aliases their device's policy; shares one domain per
  driver (all five xHCI controllers share one page table), so 13 confined
  devices fit the page-table pool. `faults` shows blocked DMA.
- **xHCI**: bounded BIOS handoff that takes ownership if firmware does not
  let go; waits for CNR; 10 s reset bound; USB 3 ports found from the
  Supported Protocol capabilities, warm reset for stuck links; every root
  port watched for 2 s with a 100 ms debounce; 10 ms SET_ADDRESS recovery;
  failed devices are disabled and retried (3 attempts); control transfers
  match their slot/endpoint, recover from every halting error and from
  timeouts (Stop Endpoint); stuck commands are aborted; halted keyboard
  endpoints are restarted; report slots consumed while waiting for other
  events are requeued (a keyboard typed on during `beep` used to lose
  them); Corsair keyboards get 200 ms between requests; a refused
  SET_PROTOCOL no longer drops the keyboard; failed controllers are reset
  and lose bus mastering before their DMA pages are reused.
- **RTL8125B**: drains and gates the receiver, takes the MAC from the
  out-of-band controller, waits for the link-list FIFO, resets, selects the
  classic descriptor format, powers up the PHY and restarts autonegotiation
  (with or without a link at probe), 6 s link bound, RX pause slot on the
  8125B, a TX timeout no longer corrupts the ring. Unknown chip IDs are
  refused. (QEMU has no RTL8125 model: this path is untested.)
- **NVMe**: CAP sanity (all-ones, MQES), CC written before enabling, LBA
  formats with metadata refused, completions matched by command ID, a
  timed-out controller is not used again, and `reboot`/`poweroff` shut the
  controller down cleanly (CC.SHN) so the P3 records a safe shutdown.
- **PCI**: functions left in D1-D3hot are brought to D0 (BARs restored).
- **HD Audio**: caches are flushed for the non-snooping GPU audio
  functions; AMD's chipset audio gets snooping enabled.

## 1. Before the boot (on Ubuntu, on this PC)

1. Optional but useful: `sudo tools/hardware/probe.sh` and keep the archive
   (ACPI tables including IVRS, `lspci -xxxx`, `lsusb -v`, dmesg AMD-Vi
   lines). Linox reads the same tables; a mismatch is then easy to explain.
   Without root, the IVRS table cannot be read here: if bring-up reports
   IVMD ranges or aliases, `sudo cat /sys/firmware/acpi/tables/IVRS | xxd`
   lets us check them.
2. `make boot-media` and write the stick:
   `tools/images/write-usb.sh /dev/sdX` (it refuses anything that is not a
   removable USB disk under 256 GB that is unmounted and not the system
   disk, shows model/serial/size, and asks you to type the device name;
   `--dry-run` checks only). Run it with the stick as the only USB disk you
   might confuse it with.
3. Leave a wired Ethernet cable in the RTL8125 port if you want the DHCP
   probe to say something.

## 2. Firmware settings (Del at power-on enters setup)

MSI's Click BIOS 5 menu names below are for this board's generation; they
move between versions, so search (F3 in Advanced mode) if not found.

| Setting | Where (Advanced mode, F7) | Value | Why |
| --- | --- | --- | --- |
| Secure Boot | Settings > Security > Secure Boot | **Disabled** | The Linox image is unsigned. Ubuntu still boots (shim works with Secure Boot off). |
| CSM / boot mode | Settings > Advanced > Windows OS Configuration > BIOS UEFI/CSM Mode | **UEFI** | Linox boots only through UEFI and needs GOP. |
| IOMMU | OC > CPU Features (or Settings > Advanced > AMD CBS > NBIO Common Options) > IOMMU | **Enabled** | Already on (Linux shows `ivhd0`). With it off there is no IVRS and no DMA remapping; bring-up still runs. |
| Above 4G decoding / Re-Size BAR | Settings > Advanced > PCI Subsystem Settings | Leave as is (both on today) | Linox handles a framebuffer above 4 GiB; if the screen stays black after the loader lines, try Re-Size BAR **off** (the BAR then lands lower). |
| Legacy USB support | Settings > Advanced > USB Configuration > Legacy USB Support | **Enabled** | Keyboard works in the boot menu; Linox takes the controllers over by the xHCI handoff. If the keyboard is dead in Linox, try **Disabled** once. |
| Fast Boot | Settings > Boot > Fast Boot | **Disabled** | Fast boot may skip USB initialisation, hiding the stick and the boot menu key. |
| Primary display | Settings > Advanced > Integrated Graphics Configuration > Initiate Graphic Adapter | PEG (the RX 6800) | Plug the monitor into the RX 6800. |

Note the current values before changing them, so they can be restored.

## 3. Booting the stick

- One-time boot menu: **F11** at the MSI logo on this board. (Other boards:
  ASUS F8, Gigabyte F12, ASRock F11, Dell/Lenovo F12, HP F9. The POST
  screen usually names the key; the board manual always does.) Pick the
  entry named `UEFI: <stick vendor> ...` (not a non-UEFI one).
- From Ubuntu instead: `systemctl reboot --firmware-setup` opens setup;
  from setup, the Boot Override list boots the stick once.
- If the stick is not listed: Fast Boot off, try a USB 2 port on the back
  panel, check the stick was written (`write-usb.sh` verifies it).

## 4. What the screen should show, stage by stage

| Stage | What you see | If it stops here |
| --- | --- | --- |
| Firmware | MSI logo, boot menu | Stick not bootable: see above |
| Loader | screen clears; `Linox booted`, `linox loader: started ...`, `ACPI root pointer at ...`, `display WxH ... framebuffer at 0x...`, `exiting UEFI boot services ...`, `if nothing follows this line ...` | Photo. A `linox loader PANIC` names file and line. If the last line is "if nothing follows", the kernel died before drawing: note the framebuffer address. |
| Kernel takes the screen | screen clears; `linox: booting`, `linox: firmware framebuffer console active` | If the screen keeps the loader text: the framebuffer is not mapped or the kernel faulted very early. |
| Bring-up report | `QEMU reference devices not found; entering hardware bring-up mode`, framebuffer size, `TSC runs at ... MHz (measured against ...)`, memory, ACPI tables, IVRS/AMD-Vi lines, the PCI list (~60 lines), `AMD-Vi ...: DMA remapping on ...`, network, audio codecs, NVMe identity and partitions, the DMA-blocking self-test, AHCI ports, each xHCI controller and its devices | Each step names itself; a crash prints `linox: FATAL: <exception> during bring-up stage: <step>` with registers. Photograph the whole screen. |
| Summary | `---- bring-up summary ----`: clock, AMD-Vi, NVMe, xHCI controllers and keyboards found | Photograph it: it is the outcome of every step on one screen. |
| Shell | `Linox bring-up shell. Type 'help' for commands.` and `bring-up>` | No keyboard was found: `no keyboard or serial input; halted`. `log` is unusable then, so photograph the xHCI lines on screen (scroll position permitting) and the summary. |

Slow steps report `linox: <step> took N ms`. The USB step takes a few
seconds (2 s of port watching per controller, plus Corsair delays).

## 5. What to photograph

1. Any screen with `FATAL`, `PANIC` or `LINOX_KERNEL_PANIC`: the whole
   screen, sharp enough to read hex digits.
2. The summary screen.
3. `log` from the start, one photo per page (Enter/Space for the next page,
   `b` back, `q` quit). On a 2560x1440 screen a page is about 60 lines.

## 6. Shell commands, in order

1. `log` — page through the full report; photograph each page.
2. `faults` — DMA the IOMMU blocked since boot (expect possibly the PSP
   18:00.2, the MT7922 or the GPU's own engines; each line names a device).
3. `usb` — the keyboards, mice and speakers found.
4. `net` — repeats the RTL8125 bring-up and DHCP probe (cable plugged in).
5. `beep` — HDA tone on each codec (HDMI audio plays on the monitor's
   speakers if it has any) and the 500 Hz tone on the ALC4080 USB outputs:
   listen on the rear jacks and front headphones.
6. `disks` — repeats the storage report.
7. `crash` (then `crash panic` after a reboot) — only if everything above
   worked: proves that a fault and a panic reach the screen.
8. `poweroff` (or `reboot`) — shuts the NVMe down cleanly first.

Do not run `disktest`: it writes only to partitions of the Linox volume
type (80769f29-5413-45a3-abab-5b44b6125922), and this NVMe has none, so it
would report "nothing written"; it is harmless but pointless.

## 7. Keeping the log

- Done: the kernel log ring (128 KiB, about 1500 lines) holds the whole
  report and every shell command; `log` and `log end` page it on screen.
- Not done: writing the log to the stick. The stick is lost to Linox the
  moment the xHCI controllers are reset, and Linox has no USB mass-storage
  driver. The plan: the boot image gains a 16 MiB partition of the Linox
  volume type after the ESP (the stick is ours to erase, and the NVMe
  write guard already allows exactly that type); the xHCI driver gains
  bulk endpoints and the Bulk-Only Transport with READ(10)/WRITE(10)
  (about 400 lines, testable in QEMU with `usb-storage`); a `savelog`
  command writes the log ring there, with a header and length, through
  the same `gpt::writable_extents` checks the NVMe path uses; the host
  reads it back with `dd if=/dev/sdX2 bs=1M count=1 | strings`.
  The same partition type on the NVMe would work too, but the NVMe holds
  Ubuntu and has no free space today.

## 8. Root commands that would tell us more (for the user to run)

| Command | Tells us |
| --- | --- |
| `sudo tools/hardware/probe.sh` | Everything below in one archive |
| `sudo xxd /sys/firmware/acpi/tables/IVRS` | IVHD types and flags, device entries (aliases, special IOAPIC/HPET IDs) and any IVMD unity ranges Linox must map |
| `sudo dmesg \| grep -i -e AMD-Vi -e iommu` | Features, whether firmware left it enabled, faults Linux sees |
| `sudo lspci -s 07:00.0 -vvv -xxxx` | RTL8125 capabilities and power state |
| `sudo lspci -s 13:00.0 -vvv` (and 15:00.0, 18:00.3/4, 19:00.0) | xHCI capabilities, MSI-X, power management |
| `sudo lsusb -v -d 1b1c:1b48` | The Corsair keyboard's interfaces and endpoint intervals |
| `sudo nvme id-ctrl /dev/nvme0` | RTD3E (shutdown time), MDTS, power states of the P3 |
| `sudo efibootmgr -v` | Boot entries (the stick appears while inserted) |

## Part 2: from bring-up mode to the full system on this PC

The full system (`kernel_main` after `discover_virtio_block`) needs four
things the QEMU reference machine supplies: virtio-blk for the persistent
volume, virtio-net for the network service, an Intel VT-d unit for DMA
isolation, and a console. On this PC they become the NVMe Linox partition,
the RTL8125, AMD-Vi, and the framebuffer with a USB keyboard. The order
below keeps the QEMU suites green at each step: every new backend is first
added alongside the virtio one and tested on the QEMU hardware profile
(which already has an AMD IOMMU, NVMe and xHCI, but no RTL8125).

### Step 1 — a platform probe instead of "virtio or bring-up"

`lib.rs` decides between the full system and bring-up with
`discover_virtio_block()`. Replace that with a `platform::Inventory`
(new module, safe code) built from one PCI scan and the ACPI tables: the
IOMMU kind (DMAR or IVRS), the storage candidates (virtio-blk, NVMe with a
Linox volume partition), the network candidates (virtio-net, RTL8125/6,
82574), the input controllers. The full system starts when one candidate of
each kind exists; bring-up stays the fallback and reports which one is
missing. This is pure refactoring on QEMU.

### Step 2 — AMD-Vi in the main kernel

`arch/x86_64/iommu.rs` drives VT-d through `MmioMapping` and
`FrameLease`s: root/context tables, per-device page tables
(`InactiveTranslation` → `DeviceTranslation`), standing devices
(`admit_standing_devices`) and fault recovery. AMD-Vi needs the same
operations with a different layout:

- `iommu::Unit` becomes an enum over `VtdUnit` and `AmdViUnit`; the
  callers (`probe`, `build_inactive_translation`, `activate_translation`,
  `admit_standing_devices`, `recover_expected_write_fault`) stay the same.
- `AmdViUnit` reuses the bring-up driver's IVRS parser and enable sequence
  (moved from `drivers/amd_iommu.rs` into `arch/x86_64/amd_vi.rs`), but
  takes its device table (2 MiB, 512 contiguous frames), command buffer,
  event log and page tables from the frame allocator through
  `device_memory::DmaBuffer`, and its registers through the device window
  instead of the identity map.
- Per-device translation: a domain ID per device (VT-d uses one context
  entry per source ID; AMD-Vi one DTE per requester ID plus aliases), a
  4-level page table built with the same `FrameLease` code,
  `INVALIDATE_DEVTAB_ENTRY` + `INVALIDATE_IOMMU_PAGES` + `COMPLETION_WAIT`
  where VT-d writes its invalidation registers.
- Faults come from the event log (I/O page fault events) instead of the
  fault recording registers; `recover_expected_write_fault` reads them.
- Interrupt remapping: the full system uses MSI-X; with remapping off in
  the DTE (IV=0) MSIs pass untranslated, which matches what Linox does
  with VT-d today. Turning it on later needs per-device interrupt tables.
- Test: QEMU's `amd-iommu` (already in the hardware profile), with a
  variant of `make test` that boots the full system on q35 + amd-iommu.

### Step 3 — the persistent volume on an NVMe partition

`volume.rs` works on `persistent_block` (a virtio-blk device behind
`VirtioBlockDevice`). Introduce a `BlockBackend` trait (read/write/flush
of 512-byte sectors, capacity) implemented by the virtio-blk driver and by
an NVMe backend:

- The NVMe backend reuses `drivers/nvme.rs` but with `DmaBuffer` queues
  from the frame allocator, the controller's BAR through the device window,
  and an `Extent` offset: sector 0 of the volume is the first LBA of the
  Linox volume partition, and every request is checked against
  `gpt::WritableExtent` (the guard that already keeps bring-up's writes
  inside the partition and on the right disk).
- 4 KiB LBA namespaces need read-modify-write for 512-byte volume sectors,
  or the volume format moves to 4 KiB sectors (simpler: the P3 uses 512-byte
  LBAs, so start there and refuse 4 KiB namespaces).
- Creating the partition is a one-time manual step from Ubuntu (shrink the
  root filesystem or use free space, then
  `sgdisk --new=3:0:+16G --typecode=3:80769f29-5413-45a3-abab-5b44b6125922 /dev/nvme0n1`).
  Linox never creates or resizes partitions itself.
- Test: the QEMU hardware profile's NVMe disk already has such a partition;
  `make test-storage` gains an NVMe variant.

### Step 4 — the network service on the RTL8125

The network service domain talks to the kernel's packet path
(`packet.rs`, `network.rs`) which drives virtio-net with MSI-X. Add a
`NetworkBackend` trait (transmit, receive into a ring, link state, MAC)
implemented by virtio-net and by the RTL8125 driver:

- The RTL8125 backend reuses `drivers/realtek.rs`, moved onto
  `DmaBuffer` rings and buffers, polled from the runtime loop at first (the
  bring-up driver is already polled) and on MSI-X later.
- Link changes and DHCP stay in the network service; the backend only
  moves frames.
- QEMU cannot test it (no RTL8125 model); the e1000e backend is written
  the same way and tests the trait in QEMU, while the RTL8125 is tested on
  this PC with the bring-up `net` command first.

### Step 5 — the console: framebuffer and USB keyboards

Already mostly there: the framebuffer console runs on the firmware
framebuffer, and `drivers/usb_input.rs` hands USB keyboards to the console
and domains. Two changes for this PC:

- `usb_input::MAX_CONTROLLERS` is 2 and discovery walks buses breadth-first,
  so the full system would take the two Raphael controllers (18:00.3/4)
  and miss the keyboards on the chipset controllers (13:00.0, 15:00.0).
  Raising it is not a one-line change: the controllers' registers live in
  the kernel's device window, which is one page table (512 pages, 2 MiB)
  with `paging::MAX_DEVICE_REGIONS` = 4 slots, and each Raphael controller
  has a 1 MiB BAR. Either the window grows to several page tables and six
  or more slots (paging.rs), or `usb_input` maps only the part of each BAR
  the driver uses (capability, operational, runtime and doorbell
  registers, plus the extended capabilities, all within the first 64 KiB
  on these controllers; `xhci::Controller::open` bounds its capability
  walk by the BAR size today and would take the mapped length instead). The second is smaller and keeps the window as
  it is; prefer controllers with a keyboard attached when slots run out.
- The framebuffer may lie in a 64-bit BAR above 1 TiB (Resizable BAR):
  the kernel's own page tables must map it (today `relocate` maps it in
  the device window; check the window covers 64-bit addresses).

### Step 6 — the remaining devices

MT7922 Wi-Fi and the Radeon GPU are out of scope for the first full boot
(blocked and passed through respectively). The GPU driver is roadmap item 5.
