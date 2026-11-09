# Linox

**A Rust-first x86-64 operating system built around native domains and Linux
userspace compatibility.**

Linox began on 2026-10-30 as a fork of
[Ginux](https://github.com/gmkurtzer/ginux) by Gregory M. Kurtzer and
continues its standalone bootable kernel; it is developed by Rouan van der
Ende with Claude Code agents. Upstream ended that line on 2026-11-04, froze
it as the `bootable-kernel-final` tag and moved on to a userspace kernel; its
fixes up to that tag are merged here, without its native controller desktop
(Linox's desktop runs in a Linux domain).

Linox is an independent kernel and operating-system prototype. It boots directly
through UEFI without a Linux host kernel, provides its own memory management,
scheduler, process model, VFS, networking, device support, and Linux ABI, and
runs an embedded administration controller in ring 3. Its primary workload is
an unmodified Linux userspace running inside a kernel-native **domain**.

The repository contains the complete bootable system, controller, native
services, Linux compatibility implementation, hardware paths, build tools,
architecture specifications, and QEMU test harnesses. The current development
target is an x86-64 Q35 virtual machine with OVMF, Intel IOMMU, and virtio
devices. It runs through KVM on an x86-64 Linux host and QEMU TCG on Apple
Silicon.

Today, Linox can:

- build as one bootable `LINOX.EFI` image;
- start its embedded controller as an ordinary ring-3 process;
- configure devices, networking, storage, and persistent domain definitions;
- pull, verify, cache, and assemble OCI images into domain-local roots;
- create and run multiple domains with separate process, address-space,
  filesystem, mount, capability, and lifecycle state;
- execute selected unmodified Alpine musl/BusyBox and Rocky Linux glibc
  programs; and
- boot Rocky Linux 10 systemd through `multi-user.target`.

Linox is experimental. Linux ABI coverage, device support, filesystems,
networking, resource enforcement, security validation, and real-hardware
coverage are incomplete. It is useful for research, architecture experiments,
and testing—not production workloads or as a replacement for Linux.

The name is Linux with the `u` oxidised to an `o`: Linux, in Rust.

## Design goals

- **Linux userspace without Linux underneath.** Linux is a personality exposed
  by Linox, not the host kernel.
- **Domains as the native system boundary.** Domains own processes, address
  spaces, filesystems, devices, resources, authority, and lifecycle.
- **A self-contained boot image.** The kernel, controller, and core boot
  requirements ship in one EFI release unit.
- **A small userspace control plane.** The embedded controller configures and
  observes the kernel without executing in ring 0.
- **Explicit, revocable authority.** Kernel capabilities grant access to named
  objects and are tied to domain generations for cleanup after failure.
- **OCI as transport, not runtime.** OCI delivers and assembles filesystems;
  Linox domains provide execution and isolation.
- **Compatibility as an observable contract.** Real Alpine and Rocky Linux
  workloads supplement synthetic ABI tests.

## System description

```text
+-----------------------------------------------------------------------+
| Embedded ring-3 controller: configuration, devices, domains, lifecycle |
+-----------------------------------------------------------------------+
| Linux-personality domains: Alpine, Rocky, and other Linux userspaces   |
+-----------------------------------------------------------------------+
| Native domains: ownership | capabilities | resources | failure policy  |
+-----------------------------------------------------------------------+
| Linox kernel: processes | VFS | networking | scheduling | memory | IPC |
+-----------------------------------------------------------------------+
| UEFI firmware and the validated x86-64 QEMU hardware profile           |
+-----------------------------------------------------------------------+
```

### Boot architecture and controller

UEFI loads one `LINOX.EFI` image containing the kernel, boot catalog, and
authenticated controller payload. Small assembly boundaries enter and leave
UEFI, install exception, interrupt, and syscall entries, and switch privilege
and address-space state; policy and most mechanisms are implemented in Rust.

The controller is part of the single EFI release unit rather than a service
installed in a host distribution. At boot, the kernel maps the statically
linked controller into ring 3. It configures the kernel and devices, discovers
host state, manages networking and persistent storage, maintains the OCI cache,
defines domains, and controls their resources, attachments, autostart, and
lifecycle. Ordinary process behavior uses the Linux ABI; protected management
operations use a versioned device/`ioctl` interface checked by the kernel.

This arrangement keeps the bootable system self-contained without running the
controller in ring 0. The controller can delegate or revoke authority granted
by the sealed boot envelope, but it cannot create new kernel authority.

### Domains and personalities

A **domain** is a native Linox kernel object and the outer unit of isolation,
ownership, accounting, scheduling, lifecycle, and failure containment. A
domain owns or is granted:

- processes, threads, and address spaces;
- a generation-tagged capability table;
- CPU and memory policy;
- IPC objects and shared-memory grants;
- filesystem roots and mount views;
- network endpoints and device grants; and
- lifecycle and failure policy.

Domains are stronger boundaries than OCI containers or Linux namespaces. OCI
supplies an initial filesystem; Linox supplies isolation and execution. A
single Linux-personality domain can look like a conventional computer, with
systemd as PID 1 and a distribution userspace above it. Multiple domains share
one Linox kernel while retaining separate kernel-owned state.

A **personality** is the userspace contract visible inside a domain: executable
format, syscalls, processes, signals, VFS behavior, devices, terminals, clocks,
networking, and namespace expectations. Linux x86-64 is the only implemented
personality. Other personalities, such as BSD, remain architectural
possibilities rather than tested features.

### Filesystems, devices, and persistence

The kernel VFS presents domain-local roots assembled from verified OCI layers,
a writable overlay, and selected `tmpfs`, `procfs`, and `devfs` behavior. A
persistent host-owned volume stores controller configuration and a
content-addressed OCI cache across reboots.

The validated QEMU profile includes virtio block and network paths, MSI-X, and
VT-d DMA confinement. Measured Rust driver and protocol services can run in
separate ring-3 domains with bounded MMIO, DMA, queue, and packet authority.
General driver support, production storage guarantees, broad filesystem
coverage, and a physical-hardware matrix remain future work.

## Current demonstrated state

| Area | Demonstrated | Important boundary |
|---|---|---|
| Boot | Unified x86-64 UEFI image under Q35/OVMF | No production signing, recovery, or physical-hardware profile |
| Controller | Embedded static ring-3 administration process | No production remote management plane |
| Domains | Multiple domain objects with distinct process, address-space, root, mount, capability, and lifecycle state | Resource and device isolation remain incomplete in several paths |
| LTP | The syscall tests of the [Linux Test Project](docs/LTP.md) in a 4-CPU Alpine domain: 1362 pass and none fail, break, hang or crash (162 report a feature Linox does not offer, 35 are skipped) | The `syscalls` suite only; the LTP domain runs with `user-switching`, `write-execute` and `privileged` on |
| Linux userspace | Selected Alpine and Rocky programs; Rocky systemd reaches `multi-user.target`; in the official `rust:alpine` image, cargo downloads crates from crates.io, builds a project using `serde` with derive (build scripts, proc macros, rustc linking through `cc`), and `cargo install`s the uutils (Rust coreutils) multicall binary, which then runs | No distribution-wide compatibility claim |
| Storage | Persistent configuration and verified OCI layer cache | Writable domain persistence and production recovery remain incomplete |
| Networking | Host DHCP/DNS, virtual-link configuration, loopback, and tested lifecycle | Independent per-domain packet paths and leases remain unfinished |
| Devices | QEMU virtio block/network, MSI-X, and VT-d paths; a polled virtio-gpu 2D display driver ([docs/GRAPHICS.md](docs/GRAPHICS.md)) | No GPU acceleration, NVMe, broad hardware, or stable third-party driver ABI |
| Desktop | A Rust Wayland compositor and terminal run in an Alpine domain on `/dev/fb0` (the firmware framebuffer, or a virtio-gpu in the mode the host asks for), with USB keyboard and tablet input through evdev | Software rendering at a fixed mode; no XKB keymap, pseudo-terminals, clipboard or popups |
| Performance | Matched 1/2/4-vCPU QEMU comparison using the same Rocky userspace and sysbench binary | Not a native-hardware or general kernel benchmark; four-thread scheduling remains weak |
| Security | Capability and generation mechanisms exercised by tests | No independent audit or production security claim |

The validated development target is QEMU's x86-64 Q35 machine with OVMF,
Intel IOMMU, and virtio devices. QEMU uses KVM on a suitable x86-64 Linux host
and TCG on Apple Silicon Macs.

### Linux compatibility status

The Linux 6.12 x86-64 ledger classifies all 375 syscall numbers: 82 complete,
245 partial, and 48 policy-denied. Classification means every syscall number has
an explicit disposition; it does not mean complete Linux conformance. Loader,
process, VFS, terminal, socket, IPC, namespace, cgroup, pseudo-filesystem, and
device behavior is implemented only to the extent recorded in the
[compatibility matrix](docs/LINUX-COMPATIBILITY.md). Behaviour is checked
against the Linux Test Project's syscall tests, which all pass
([docs/LTP.md](docs/LTP.md)).

The project uses real workloads as compound integration tests. Alpine exercises
the musl/BusyBox path. Rocky exercises glibc, dynamic linking, fork/exec, systemd,
services, procfs, terminals, and related kernel interfaces. The `rust:alpine`
image exercises a multithreaded toolchain: cargo's TLS downloads, rustc's
worker threads and dynamically loaded proc macros, and process trees six deep
(cargo, rustc, cc, collect2, ld) joined by pipes. A successful tested
workflow is evidence for that workflow only; it is not a guarantee that an
arbitrary Linux binary or distribution will run.

## Build and run

Requirements:

- Rust 1.99.0 through `rustup`;
- Clang with the `x86_64-none-elf` target;
- QEMU with x86-64 and OVMF support; and
- GNU Make.

Check the host, build Linox, and boot it:

```sh
make doctor
make run
```

`make run` creates a sparse development volume at `build/qemu/volume.raw`.
`make reset-storage` deletes it; the next boot recreates a clean volume.

At the `linox>` prompt, a minimal Alpine workflow is:

```text
domain new alpine
domain set alpine image=alpine:latest init=/bin/sh
domain start alpine --attach
```

Press Control-] to detach. Reattach or execute another process with:

```text
domain attach alpine
domain exec alpine /bin/echo hello
domain exec alpine --interactive /bin/sh
```

To exercise the tested Rocky systemd path:

```text
domain new rocky
domain set rocky image=rockylinux/rockylinux:10-ubi-init init=/sbin/init memory-mib=2048
domain start rocky --attach
```

The base `rockylinux/rockylinux:10` image does not contain systemd; the tested
init-bearing image is `rockylinux/rockylinux:10-ubi-init`.

`domain start NAME` queues startup and returns to the controller. Use
`domain list` for transitional state and `domain status NAME` for detailed
root, execution, console, resource, image, and network state. OCI is only the
transport and filesystem assembly format; it is not the runtime or security
boundary.

### Wayland desktop

[`userland`](userland) is a Wayland desktop written in Rust that runs inside a
domain: `linox-wm`, a compositor and stacking window manager built on the
pure-Rust `wayland-server` backend, and `linox-term`, a terminal client;
`linox-fetch` prints a neofetch-style system summary. They are static
`x86_64-unknown-linux-musl` binaries in their own Cargo workspace, so their
crates.io dependencies stay out of the kernel build. The compositor
draws in software onto `/dev/fb0`, the firmware framebuffer or a virtio-gpu
surface ([docs/GRAPHICS.md](docs/GRAPHICS.md)) exposed through Linux fbdev,
and reads keyboards and pointers from `/dev/input/eventN`, which
the kernel feeds from USB keyboards, boot mice and QEMU's USB tablet. Clients
share window buffers through memfd pools passed with `SCM_RIGHTS`; Linox maps
a memfd's own pages into every process that maps it.

```sh
just desktop            # build, boot in a QEMU window and start the desktop
make userland           # build linox-wm, linox-term, linox-fetch and linox-init
make userland-check     # format check, clippy and unit tests on the host
make test-desktop       # type into the terminal on USB, check a screendump
make test-desktop-virtio-gpu # the same on a virtio-gpu display, no VGA
make test-rust-userland # boot the all-Rust domain and run brush and uutils
```

### All-Rust userland

`make rust-rootfs` builds `build/rootfs-rust.tar.gz`, a root filesystem whose
programs are all Rust: `linox-init` as process 1, the bash-compatible
[brush](https://github.com/reubeno/brush) shell as `/bin/sh`, the
[uutils](https://github.com/uutils/coreutils) coreutils multicall binary with a
link per utility, and the desktop programs. When it exists, the boot image
embeds it, and a domain set to `image=builtin://rust init=/sbin/init` boots it
directly, with no registry pull; `just desktop` and the desktop test use it.
The programs are static musl binaries, so libc is still musl, a C library.

In the domain's shell, run `linox-wm --terminal linox-term --spawn
linox-term &` to start the desktop. Windows get server-side title bars with close and maximize
buttons; drag a window by its title bar or with Alt and the left button.
Alt+Enter opens a terminal, Alt+Tab cycles focus, Alt+Q closes and Alt+M
maximizes; Control+Alt+Backspace quits. To see and use it in a window, boot
with `LINOX_QEMU_DISPLAY=gtk LINOX_QEMU_USB_INPUT=1 make run`. The terminal has no
pseudo-terminal yet, so it runs the shell over pipes with its own line
editing, and keys reach clients as raw evdev codes unless `--keymap` supplies
an XKB keymap. There is no GPU acceleration, clipboard or popup placement.

### Boot media and physical machines

`make boot-media` packages the EFI image as removable media in `build/media`:

- `linox.iso` is a UEFI-bootable hybrid ISO. It can be burned to optical media
  or written directly to a USB stick.
- `linox-usb.img` is a raw GPT disk image with one EFI system partition, for
  firmware that does not boot hybrid ISOs from USB.

Write the USB image to a stick (this erases the stick) and boot it in UEFI
mode with Secure Boot disabled:

```sh
tools/images/write-usb.sh /dev/sdX
```

The helper refuses anything that is not an unmounted, removable USB disk
under 256 GB that does not hold the running system, shows the disk's model,
serial and size, asks for the device name to be typed back, writes with
`sudo dd` and verifies what it wrote (`--dry-run` only checks).
`docs/HARDWARE-BRINGUP.md` is the checklist for the first boot on the
development PC (firmware settings, what each screen shows, what to
photograph) and the plan from bring-up mode to the full system there.

`make test-boot-media` boots both images in QEMU as a CD-ROM and as a USB stick
on an xHCI controller, and requires each boot to reach the controller prompt.

To install Linox next to an existing Linux system on the target computer, run
`sudo tools/images/install-to-esp.sh --boot-next` there. It copies the image to
`EFI/linox/linox.efi` on the EFI system partition and registers a firmware boot
entry outside the default boot order, so `--boot-next` boots Linox once and the
following reboot returns to the existing system.

Physical hardware is not fully supported yet. The full system still requires
the QEMU virtio devices and an Intel VT-d IOMMU. On any other machine Linox
enters **hardware bring-up mode**: it shows its console on the UEFI framebuffer
(no serial port needed), reports memory, ACPI tables, CPUs, the IOMMU type, and
every PCI device, and runs the physical-hardware drivers in `kernel/src/drivers`:

- AMD-Vi DMA remapping: each device Linox drives can reach only its driver's
  buffers, display controllers keep untranslated access for the firmware
  framebuffer, and every other device is blocked. A self-test asks the NVMe
  controller to write outside its buffers and checks that the write is stopped.
- NVMe and AHCI (SATA) drivers that list GPT partitions. The NVMe driver
  writes only inside partitions of the Linox volume type
  (`80769f29-5413-45a3-abab-5b44b6125922`), and only on the disk whose
  partition table defines them; the table's header and entry array must pass
  their CRCs and the partition may overlap no other. AHCI is read-only.
- An xHCI driver that runs USB boot keyboards, boot mice and QEMU's USB
  tablet on every controller, including devices behind USB hubs (up to five
  tiers, with transaction translators for low- and full-speed devices behind
  high-speed hubs), and plays the
  `beep` test tone on every playback output of USB Audio Class 1 and 2
  devices (such as the speaker, headphone and S/PDIF outputs of a
  motherboard's USB audio chip) through isochronous endpoints, setting
  48 kHz on the endpoint or the class 2 clock source. Descriptor parsing
  lives in `crates/usb-audio` and is tested against a real class 2 device's
  descriptors; class 2 playback has not run on hardware yet. On the QEMU
  reference machine the same driver hands USB keyboards and pointers to
  domains as Linux evdev devices (`/dev/input/eventN`), with the report
  decoding in `crates/usb-hid`; `LINOX_QEMU_USB_INPUT=1 make run` adds a USB
  keyboard and tablet.
- An HD Audio driver for Intel-compatible controllers (including AMD HD Audio
  and GPU HDMI/DP audio) that resets each controller, lists its codecs and
  output pins, and plays a 440 Hz test tone on request (`beep`).
- Polled Ethernet for the Intel 82574 and the Realtek RTL8125/RTL8126, checked
  by broadcasting a DHCP discover and reporting the offer. The Realtek path
  takes the chip from its out-of-band controller, powers up its PHY and
  renegotiates, following the behaviour of Linux's r8169; QEMU has no model
  of it, and it has not run on hardware yet.

Bring-up is built to be read from a photo of the screen: the loader
reports its steps on the firmware console before the kernel takes over, the
kernel checks the firmware maps the framebuffer before drawing, every wait
on hardware is bounded by a clock calibrated against the ACPI PM timer or
HPET, each step names itself so that a CPU exception or a panic (both
reported on the framebuffer with registers and return addresses) says
where it struck, and the report ends with a one-screen summary.

With a keyboard or serial port it then offers a small bring-up shell (`help`,
`log` to page through everything printed since boot, `faults` for DMA the
IOMMU blocked, `usb`, `pci`, `acpi`, `mem`, `disks`, `disktest`, `net`,
`beep`, `crash` to test the crash report, `reboot` and `poweroff`, which
shut NVMe controllers down cleanly first). Only
`disktest` writes to storage: on each Linox volume partition it writes a block,
reads it back, restores it, and checks that a write past the partition is
refused; disks without one are not written. `make test-hardware-profile` boots a QEMU machine with an
AMD IOMMU, an e1000e on a DHCP network, an HD Audio codec, a USB audio device,
NVMe, AHCI, two xHCI controllers (one keyboard behind a hub), and a SATA disk
without virtio, types a command on an
emulated USB keyboard, records the test tones from HD Audio and USB audio through QEMU's WAV output,
runs `disktest` on the NVMe disk and checks the disk image is unchanged afterwards,
pages the log, checks that the crash test's report names the fault and the
bring-up stage, and checks the framebuffer console at 2560x1440 with no
serial port. Its AMD IOMMU has interrupt remapping and x2APIC support, as
Raphael's does.

Bringing up a specific machine starts with `sudo tools/hardware/probe.sh`, run
under an existing Linux installation on that machine, which archives the
firmware tables and device inventory that the remaining storage, network,
display, and IOMMU drivers will be written against.

## Verification

Useful gates include:

```sh
make build                 # build the unified EFI image
make test-linux-runtime    # ELF, loader, PIE, TLS, heap, and VM behavior
make test-alpine           # registry pull and Alpine shell
make test-rocky-shell      # Rocky glibc shell and process/file behavior
make test-multi-domain     # concurrent domain lifecycle
make test-rocky-systemd    # cold and cached Rocky systemd boot
make test-storage          # volume initialization, recovery, and reset
make test-rust-workloads   # rust:alpine compiles and runs stress programs, cargo builds serde
make check                 # architecture, ABI, format, lint, and unit checks
```

`make test-rust-workloads` compiles the programs in `tests/linux-workloads`
with the image's own rustc and runs them inside the domain: allocator, thread
churn, mmap/munmap/mremap, file I/O, and malloc-metadata stress, each checking
every byte it wrote. It needs an 8 GiB guest and takes about half an hour.

The Ginux checkpoint evaluated in the paper below did not pass the aggregate
`make test` (a post-`execve()` system-supervisor lifecycle probe failed); on
current `main` it passes, and CI runs it on every push.

The EFI image is written to `build/esp/EFI/BOOT/BOOTX64.EFI`. Run `make help`
for the full target and environment-variable list.

## Repository guide

- [`boot/efi`](boot/efi) builds the UEFI entry and unified image.
- [`kernel`](kernel) contains the kernel, Linux personality, executable
  loaders, and QEMU hardware paths.
- [`control-plane/runtime`](control-plane/runtime) contains the embedded
  ring-3 controller.
- [`services`](services) contains isolated native-service runtimes.
- [`crates`](crates) contains shared `no_std` contracts and state machines.
- [`userland`](userland) contains Linux programs for domains, built as static
  musl binaries: the Rust Wayland compositor (`linox-wm`), terminal
  (`linox-term`) and system summary (`linox-fetch`).
- [`specs`](specs) records versioned boot, kernel, ABI, domain, image, and
  service contracts.
- [`tests`](tests) contains ABI, lifecycle, and end-to-end QEMU gates.
- [`tools`](tools) contains image, manifest, architecture, and QEMU tooling.
- [`skills`](skills) contains portable HDAE development and scheduled PR/issue
  review Agent Skills shared by Codex and Claude Code.

## Using the agent skills

The canonical skills live under [`skills/`](skills). Git-tracked relative
symlinks expose the same files to Codex under `.agents/skills/` and to Claude
Code under `.claude/skills/`. Start a new agent session from this repository
after checking out the branch that contains those links so the agent discovers
them at startup.

### HDAE development

Use this skill when starting or restructuring substantial work. It begins with
focused Q&A, helps the human establish product intent and architecture, creates
milestones with executable gates, and gives the agent autonomy to iterate
inside each approved gate. It stops at gate boundaries for human direction.

In Codex, start with:

```text
Use $hdae-development to help me develop this project.
```

In Claude Code, use the same request with the Claude skill command:

```text
/hdae-development Help me develop this project.
```

The user may begin with only an idea. The agent is responsible for eliciting the
structured project brief through focused follow-up questions, confirming it,
and writing it into durable project state before implementation. The skill also
requires the agent to propose complete gates, ask what is missing, wait for
approval, and update the persisted status at every stopping point. After
approving a gate, tell the agent to implement that named gate using the same
skill.

### Recurring PR and issue review

Use this skill to establish read-only reviews of new or updated GitHub issues
and pull requests. The agent discovers the repository, checks for a connected
GitHub account or authenticated `gh` CLI, guides installation or interactive
login when needed, and asks for the frequency, time/day anchor, timezone,
scope, report destination, and notification preference. It validates access
with a review before creating the schedule.

In Codex, start with:

```text
Use $pr-issue-review to set up recurring, read-only reviews of new or updated
issues and pull requests for this repository. Discover and validate the GitHub
repository and authentication, then ask me how often and when the review should
run. Preview one review before creating the schedule. Do not post, label, close,
approve, merge, commit, or push anything.
```

In Claude Code, use:

```text
/pr-issue-review Set up recurring, read-only reviews of new or updated issues
and pull requests for this repository. Discover and validate the GitHub
repository and authentication, then ask me how often and when the review should
run. Preview one review before creating the schedule. Do not post, label, close,
approve, merge, commit, or push anything.
```

Codex can use its native recurring automation when available. Claude Code uses
an available native scheduler or proposes an explicit repository workflow or
host scheduler for approval. In either environment, the skill verifies that
the unattended runtime can access the repository before creating the task; it
never asks for a token to be pasted into the conversation.

## Design and evidence

- [Architecture](ARCHITECTURE.md)
- [Verification roadmap](docs/ROADMAP.md)
- [Feedback-driven hardening research](docs/FEEDBACK-HARDENING-RESEARCH.md)
- [Linux compatibility matrix](docs/LINUX-COMPATIBILITY.md)
- [Linux runtime compatibility](docs/LINUX-RUNTIME-COMPATIBILITY.md)
- [Runtime use cases](docs/USE-CASES.md)
- [Performance methodology](docs/PERFORMANCE.md)
- [Storage architecture](docs/STORAGE.md)
- [Stability audit](docs/STABILITY-AUDIT.md)
- [Native domains and authority](docs/decisions/0001-native-domains-and-authority.md)
- [Unified image and driver boundary](docs/decisions/0002-unified-image-and-driver-boundary.md)

## Research background

Ginux, the project Linox was forked from, was built to test whether a coding
agent, directed by someone with the relevant systems experience, could
construct an independent kernel that runs existing Linux userspace. Over
eleven days, one persistent OpenAI Codex task
using GPT-5.6 Sol produced approximately 139,000 retained lines of
implementation and test code.

The development method is called **Human-Directed Agentic Engineering (HDAE)**.
Human direction established the architecture, constraints, milestones,
acceptance criteria, and stopping point. The agent implemented, booted, tested,
diagnosed, and revised the system against executable gates. Architecture and
decision documents kept the work aligned; real userspaces exposed failures that
synthetic tests missed.

Linox continues that kernel with the same method, using Claude Code agents:
since the fork it has gained the Linux Test Project as its compatibility
gate, multi-CPU domains, kernel stacks per activation, the all-Rust userland
and the Wayland desktop.

The result demonstrates rapid construction of deep systems software, not a
production alternative to Linux. The project does not reproduce Linux's broad
compatibility, hardware enablement, review, vendor ecosystem, community, or
long-term maintenance.

The technical report on Ginux, the project Linox was forked from, documents
the method, architecture, evaluation, and limitations (it is published under
the Ginux name):

- [DOI: 10.5281/zenodo.23682548](https://doi.org/10.5281/zenodo.23682548)
- [LaTeX source](docs/paper/ginux-ai-systems-report.tex)
- [Steering chronology](docs/paper/STEERING-PROVENANCE.md)
- [Benchmark artifacts](docs/paper/artifact/benchmark-2026-10-23)

The paper evaluates commit
`d11c126a048a51fe7eb9c4105f31760add1027ea`, dated October 23, 2026. Later
repository changes are not silently treated as part of that experimental
checkpoint.

## Citation

Please cite the technical report using its Zenodo record:

```bibtex
@techreport{kurtzer2026ginux,
  author = {Gregory M. Kurtzer},
  title = {Ginux: Building an Independent Kernel That Runs Linux Userspace
           through Human-Directed Agentic Engineering},
  year = {2026},
  doi = {10.5281/zenodo.23682548},
  url = {https://doi.org/10.5281/zenodo.23682548}
}
```

## License

Linox is licensed under the [Apache License, Version 2.0](LICENSE). See
[`NOTICE`](NOTICE) for attribution information. The technical report is
published separately through Zenodo under its declared record license.
