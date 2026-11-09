use super::*;

pub(super) fn linux_socket_pipe_descriptor(descriptor: u64, access: u16) -> bool {
    let device = linux_device_descriptor(descriptor);
    linux_socket_slot(descriptor).is_some()
        && device & (LINUX_DEVICE_SOCKET | LINUX_DEVICE_PIPE)
            == LINUX_DEVICE_SOCKET | LINUX_DEVICE_PIPE
        && device & 3 & access == access
}

/// Handles the ioctls Linux applies to every descriptor before asking the
/// file's own driver, by way of the equivalent fcntl calls.
/// The socket ioctls of Linux's sock_ioctl and inet: SIOCATMARK on TCP
/// (no urgent data is ever pending), and the interface queries SIOCGIF*
/// over the domain's loopback and eth0 (`linux_socket::interfaces`).
/// None for a request this is not, or a descriptor that is no socket.
pub(super) fn linux_socket_ioctl(descriptor: u64, request: u64, argument: u64) -> Option<u64> {
    const SIOCATMARK: u64 = 0x8905;
    const SIOCGIFNAME: u64 = 0x8910;
    const SIOCGIFCONF: u64 = 0x8912;
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCSIFFLAGS: u64 = 0x8914;
    const SIOCGIFADDR: u64 = 0x8915;
    const SIOCGIFNETMASK: u64 = 0x891b;
    const SIOCGIFMTU: u64 = 0x8921;
    const SIOCSIFMTU: u64 = 0x8922;
    const SIOCGIFHWADDR: u64 = 0x8927;
    const SIOCGIFINDEX: u64 = 0x8933;
    const SIOCGIFTXQLEN: u64 = 0x8942;
    const IFREQ_SIZE: usize = 40;
    let request = u64::from(request as u32);
    if !matches!(
        request,
        SIOCATMARK
            | SIOCGIFNAME
            | SIOCGIFCONF
            | SIOCGIFFLAGS
            | SIOCSIFFLAGS
            | SIOCGIFADDR
            | SIOCGIFNETMASK
            | SIOCGIFMTU
            | SIOCSIFMTU
            | SIOCGIFHWADDR
            | SIOCGIFINDEX
            | SIOCGIFTXQLEN
    ) {
        return None;
    }
    let descriptor = u64::from(descriptor as u32);
    let slot = linux_socket_slot(descriptor).filter(|_| !linux_pipe_descriptor(descriptor))?;
    let kind = crate::linux_socket::kind(slot);
    if request == SIOCATMARK {
        if kind != Some(crate::linux_socket::Kind::Tcp) {
            return Some(LINUX_ENOTTY);
        }
        return Some(if copy_to_linux_user(argument, &0_i32.to_ne_bytes()) {
            0
        } else {
            LINUX_EFAULT
        });
    }
    let interfaces = linux_network_interfaces();
    let sockaddr_in = |address: u32| {
        let mut sockaddr = [0_u8; 16];
        sockaddr[..2].copy_from_slice(&2_u16.to_ne_bytes());
        sockaddr[4..8].copy_from_slice(&address.to_be_bytes());
        sockaddr
    };
    if request == SIOCGIFCONF {
        // struct ifconf: the buffer's length, then the buffer: one ifreq
        // (name and address) per interface, or the length needed when the
        // buffer is null.
        let mut ifconf = [0_u8; 16];
        if !copy_from_linux_user(argument, &mut ifconf) {
            return Some(LINUX_EFAULT);
        }
        let capacity = i32::from_ne_bytes(ifconf[..4].try_into().unwrap()).max(0) as usize;
        let buffer = u64::from_ne_bytes(ifconf[8..16].try_into().unwrap());
        let mut written = 0_usize;
        for interface in &interfaces {
            if buffer != 0 {
                if written + IFREQ_SIZE > capacity {
                    break;
                }
                let mut entry = [0_u8; IFREQ_SIZE];
                let name = interface.name.as_bytes();
                entry[..name.len()].copy_from_slice(name);
                entry[16..32].copy_from_slice(&sockaddr_in(interface.ipv4));
                if !copy_to_linux_user(buffer + written as u64, &entry) {
                    return Some(LINUX_EFAULT);
                }
            }
            written += IFREQ_SIZE;
        }
        return Some(
            if copy_to_linux_user(argument, &(written as i32).to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            },
        );
    }
    let mut ifreq = [0_u8; IFREQ_SIZE];
    if !copy_from_linux_user(argument, &mut ifreq) {
        return Some(LINUX_EFAULT);
    }
    let interface = if request == SIOCGIFNAME {
        let index = i32::from_ne_bytes(ifreq[16..20].try_into().unwrap());
        interfaces.iter().find(|interface| interface.index == index)
    } else {
        let name_length = ifreq[..16].iter().position(|byte| *byte == 0).unwrap_or(16);
        interfaces
            .iter()
            .find(|interface| interface.name.as_bytes() == &ifreq[..name_length])
    };
    let Some(interface) = interface else {
        return Some(LINUX_ENODEV);
    };
    match request {
        SIOCGIFNAME => {
            ifreq[..16].fill(0);
            let name = interface.name.as_bytes();
            ifreq[..name.len()].copy_from_slice(name);
        }
        SIOCGIFFLAGS => ifreq[16..18].copy_from_slice(&interface.flags.to_ne_bytes()),
        // Changing an interface takes CAP_NET_ADMIN. The domain's own stay
        // as the kernel set them up (EOPNOTSUPP for a change; setting what
        // they have is a success); a TUN or TAP device, and a network
        // namespace's loopback, go up and down and take another MTU.
        SIOCSIFFLAGS | SIOCSIFMTU => {
            if !current_linux_credentials().is_some_and(|credentials| {
                credentials.has(linox_credentials::capability::NET_ADMIN)
            }) {
                return Some(LINUX_EPERM);
            }
            let flags = u16::from_ne_bytes(ifreq[16..18].try_into().unwrap());
            let mtu = i32::from_ne_bytes(ifreq[16..20].try_into().unwrap());
            if request == SIOCSIFMTU && !(68..=65_536).contains(&mtu) {
                return Some(LINUX_EINVAL);
            }
            let network = current_linux_namespaces().net;
            let unchanged = if request == SIOCSIFMTU {
                mtu == interface.mtu
            } else {
                (flags ^ interface.flags) & LINUX_IFF_UP == 0
            };
            if interface.tun {
                let result = if request == SIOCSIFMTU {
                    crate::linux_socket::tun_set_link(
                        interface.index,
                        None,
                        u32::try_from(mtu).ok(),
                    )
                } else {
                    crate::linux_socket::tun_set_link(
                        interface.index,
                        Some(flags & LINUX_IFF_UP != 0),
                        None,
                    )
                };
                return Some(result.map_or_else(|errno| (-i64::from(errno)) as u64, |()| 0));
            }
            if network == 0 && !unchanged {
                return Some(LINUX_EOPNOTSUPP);
            }
            if network != 0 {
                let changed = linux_namespace::set_loopback(
                    linux_execution_instance(),
                    network,
                    |loopback| {
                        if request == SIOCSIFMTU {
                            loopback.mtu = mtu;
                        } else {
                            loopback.up = flags & LINUX_IFF_UP != 0;
                        }
                    },
                );
                if !changed {
                    return Some(LINUX_ENODEV);
                }
            }
            return Some(0);
        }
        SIOCGIFADDR => ifreq[16..32].copy_from_slice(&sockaddr_in(interface.ipv4)),
        SIOCGIFNETMASK => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(interface.prefix))
                .unwrap_or(0);
            ifreq[16..32].copy_from_slice(&sockaddr_in(mask));
        }
        SIOCGIFMTU => ifreq[16..20].copy_from_slice(&interface.mtu.to_ne_bytes()),
        // ifr_qlen: Linux's defaults, 500 for a TUN or TAP device's queue
        // and 1000 for the others.
        SIOCGIFTXQLEN => {
            let length: i32 = if interface.tun { 500 } else { 1000 };
            ifreq[16..20].copy_from_slice(&length.to_ne_bytes());
        }
        SIOCGIFHWADDR => {
            ifreq[16..18].copy_from_slice(&interface.hardware.0.to_ne_bytes());
            ifreq[18..24].copy_from_slice(&interface.hardware.1);
        }
        _ => ifreq[16..20].copy_from_slice(&interface.index.to_ne_bytes()),
    }
    Some(if copy_to_linux_user(argument, &ifreq) {
        0
    } else {
        LINUX_EFAULT
    })
}

/// Whether the current process's network namespace reaches `endpoint`
/// (INADDR_ANY is the local host, as connect takes it).
fn linux_endpoint_reachable(endpoint: smoltcp::wire::IpEndpoint) -> bool {
    match endpoint.addr {
        smoltcp::wire::IpAddress::Ipv4(address) if address.is_unspecified() => {
            linux_network_reaches(0x7f00_0001)
        }
        smoltcp::wire::IpAddress::Ipv4(address) => {
            linux_network_reaches(u32::from_be_bytes(address.octets()))
        }
        // IPv6 has loopback alone: no address or route on eth0.
        smoltcp::wire::IpAddress::Ipv6(address) => {
            (address.is_loopback() || address.is_unspecified())
                && linux_network_reaches(0x7f00_0001)
        }
    }
}

/// IFF_UP: an interface carries traffic.
pub(super) const LINUX_IFF_UP: u16 = 0x1;

/// The interfaces the current process's network namespace has: the
/// domain's (loopback and eth0), or a namespace's own loopback alone,
/// with 127.0.0.1 only while it is up.
pub(super) fn linux_network_interfaces() -> Vec<crate::linux_socket::InterfaceInfo> {
    const IFF_LOOPBACK: u16 = 0x8;
    const IFF_RUNNING: u16 = 0x40;
    const ARPHRD_LOOPBACK: u16 = 772;
    let network = current_linux_namespaces().net;
    if network == 0 {
        return crate::linux_socket::interfaces();
    }
    let loopback = linux_namespace::loopback(linux_execution_instance(), network).map(|loopback| {
        crate::linux_socket::InterfaceInfo {
            name: linox_tun::Name::new(b"lo").unwrap_or_else(|| unreachable!("a valid name")),
            index: 1,
            ipv4: if loopback.up { 0x7f00_0001 } else { 0 },
            prefix: if loopback.up { 8 } else { 0 },
            more_ipv4: Vec::new(),
            tun: false,
            flags: IFF_LOOPBACK
                | if loopback.up {
                    LINUX_IFF_UP | IFF_RUNNING
                } else {
                    0
                },
            mtu: loopback.mtu,
            hardware: (ARPHRD_LOOPBACK, [0; 6]),
        }
    });
    loopback.into_iter().collect()
}

/// Whether the current process's network namespace reaches IPv4 address
/// `address` (host order): the domain's reaches what its interfaces do; a
/// namespace made inside it only its loopback's 127.0.0.0/8, and only while
/// that is up.
fn linux_network_reaches(address: u32) -> bool {
    let network = current_linux_namespaces().net;
    network == 0
        || address >> 24 == 127
            && linux_namespace::loopback(linux_execution_instance(), network)
                .is_some_and(|loopback| loopback.up)
}

pub(super) fn linux_socket_slot(descriptor: u64) -> Option<crate::linux_socket::SlotId> {
    let descriptor = u64::from(descriptor as u32);
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_overflow_entry(descriptor).and_then(|entry| entry.socket.checked_sub(1));
    }
    if let Some(slot) = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_SLOTS.get(index))
        .map(|slot| slot.load(Ordering::SeqCst))
        .filter(|slot| *slot != 0)
    {
        return Some(slot - 1);
    }
    descriptor
        .checked_sub(LINUX_AUX_DESCRIPTOR_FIRST)
        .and_then(|index| X86_RUNTIME.ELF_PROBE_SOCKET_SLOTS.get(index as usize))
        .map(|slot| slot.load(Ordering::SeqCst))
        .filter(|slot| *slot != 0)
        .map(|slot| slot - 1)
}

pub(super) fn linux_socket_error(error: crate::linux_socket::Error) -> u64 {
    match error {
        crate::linux_socket::Error::WrongType => LINUX_EPROTOTYPE,
        crate::linux_socket::Error::Unavailable => LINUX_ENETUNREACH,
        crate::linux_socket::Error::Exhausted => LINUX_ENFILE,
        crate::linux_socket::Error::AddressInUse => LINUX_EADDRINUSE,
        crate::linux_socket::Error::AddressNotAvailable => LINUX_EADDRNOTAVAIL,
        crate::linux_socket::Error::Invalid => LINUX_EINVAL,
        crate::linux_socket::Error::InProgress => LINUX_EINPROGRESS,
        crate::linux_socket::Error::WouldBlock => LINUX_EAGAIN,
        crate::linux_socket::Error::NotConnected => LINUX_ENOTCONN,
        crate::linux_socket::Error::BrokenPipe => LINUX_EPIPE,
        crate::linux_socket::Error::Reset => LINUX_ECONNRESET,
        crate::linux_socket::Error::Refused => LINUX_ECONNREFUSED,
        crate::linux_socket::Error::IsConnected => LINUX_EISCONN,
        crate::linux_socket::Error::Already => LINUX_EALREADY,
        crate::linux_socket::Error::Errno(errno) => (-i64::from(errno)) as u64,
    }
}

fn linux_socket_descriptor_index(descriptor: u64) -> Option<usize> {
    let descriptor = u64::from(descriptor as u32);
    let index = descriptor.checked_sub(LINUX_AUX_DESCRIPTOR_FIRST)? as usize;
    (index < LINUX_DEVICE_DESCRIPTOR_COUNT).then_some(index)
}

pub(super) fn linux_socket_nonblocking(descriptor: u64) -> bool {
    if X86_RUNTIME
        .LINUX_SOCKET_SINGLE_ATTEMPT
        .load(Ordering::SeqCst)
    {
        return true;
    }
    let descriptor = u64::from(descriptor as u32);
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_overflow_entry(descriptor)
            .is_some_and(|entry| entry.socket_flags & LINUX_O_NONBLOCK as u32 != 0);
    }
    if let Some(flags) = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS.get(index))
    {
        return flags.load(Ordering::SeqCst) & LINUX_O_NONBLOCK as u32 != 0;
    }
    linux_socket_descriptor_index(descriptor).is_some_and(|index| {
        X86_RUNTIME.ELF_PROBE_SOCKET_FLAGS[index].load(Ordering::SeqCst) & LINUX_O_NONBLOCK as u32
            != 0
    })
}

pub(super) fn linux_socket_flags(descriptor: u64) -> Option<u32> {
    let descriptor = u64::from(descriptor as u32);
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return linux_overflow_entry(descriptor).map(|entry| entry.socket_flags);
    }
    if let Some(flags) = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS.get(index))
    {
        return Some(flags.load(Ordering::SeqCst));
    }
    linux_socket_descriptor_index(descriptor)
        .map(|index| X86_RUNTIME.ELF_PROBE_SOCKET_FLAGS[index].load(Ordering::SeqCst))
}

/// socket(AF_NETLINK, SOCK_RAW or SOCK_DGRAM, protocol): a netlink socket
/// that receives the kernel's messages to it (`linux_socket::Kind::Netlink`).
fn linux_netlink_socket_create(socket_type: u64, protocol: u64) -> u64 {
    const SOCK_DGRAM: u64 = 2;
    const SOCK_RAW: u64 = 3;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x8_0000;
    const NETLINK_PROTOCOLS: u64 = 32;
    if socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    if !matches!(socket_type & 0xf, SOCK_DGRAM | SOCK_RAW) {
        return LINUX_ESOCKTNOSUPPORT;
    }
    if protocol >= NETLINK_PROTOCOLS {
        return LINUX_EPROTONOSUPPORT;
    }
    let Some(descriptor) = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        return LINUX_EMFILE;
    };
    let slot = match crate::linux_socket::open_netlink(protocol as u8) {
        Ok(slot) => slot,
        Err(error) => return linux_socket_error(error),
    };
    linux_socket_descriptor_installed(
        descriptor,
        slot,
        LINUX_DEVICE_SOCKET | 3,
        (socket_type & SOCK_NONBLOCK) as u32,
        socket_type & SOCK_CLOEXEC != 0,
    )
}

/// `install_linux_socket_descriptor`, the descriptor (or ENOMEM, the
/// socket closed again) returned.
pub(super) fn linux_socket_descriptor_installed(
    descriptor: u64,
    slot: crate::linux_socket::SlotId,
    state: u16,
    flags: u32,
    close_on_exec: bool,
) -> u64 {
    if install_linux_socket_descriptor(descriptor, slot, state, flags, close_on_exec) {
        descriptor
    } else {
        let _ = crate::linux_socket::close(slot);
        LINUX_ENOMEM
    }
}

pub(super) fn linux_socket_create(family: u64, socket_type: u64, protocol: u64) -> u64 {
    const AF_UNIX: u64 = 1;
    const AF_INET: u64 = 2;
    const AF_INET6: u64 = 10;
    const SOCK_STREAM: u64 = 1;
    const SOCK_DGRAM: u64 = 2;
    const SOCK_RAW: u64 = 3;
    const SOCK_SEQPACKET: u64 = 5;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x8_0000;
    const IPPROTO_ICMP: u64 = 1;
    const IPPROTO_ICMPV6: u64 = 58;
    const IPPROTO_UDPLITE: u64 = 136;
    const AF_NETLINK: u64 = 16;
    const AF_PACKET: u64 = 17;
    let family = u64::from(family as u32);
    let socket_type = u64::from(socket_type as u32);
    let protocol = u64::from(protocol as u32);
    if family == AF_NETLINK {
        return linux_netlink_socket_create(socket_type, protocol);
    }
    if family == AF_PACKET {
        return linux_packet_socket_create(socket_type, protocol);
    }
    if !matches!(family, AF_UNIX | AF_INET | AF_INET6) {
        return LINUX_EAFNOSUPPORT;
    }
    let base = socket_type & 0xf;
    if socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    let kind = match (family, base) {
        (AF_UNIX, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) if protocol == 0 => {
            crate::linux_socket::Kind::Unix
        }
        (AF_UNIX, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) => {
            return LINUX_EPROTONOSUPPORT;
        }
        (AF_INET, SOCK_STREAM) if matches!(protocol, 0 | 6) => crate::linux_socket::Kind::Tcp,
        (AF_INET, SOCK_DGRAM) if matches!(protocol, 0 | 17) => crate::linux_socket::Kind::Udp,
        (AF_INET | AF_INET6, SOCK_DGRAM) if protocol == IPPROTO_UDPLITE => {
            crate::linux_socket::Kind::UdpLite
        }
        // Ping sockets, which Linux grants to the groups in ping_group_range
        // (every group on Ubuntu), and raw ICMP sockets.
        (AF_INET, SOCK_DGRAM | SOCK_RAW) if protocol == IPPROTO_ICMP => {
            crate::linux_socket::Kind::Icmp
        }
        (AF_INET, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW) => return LINUX_EPROTONOSUPPORT,
        // AF_INET6 TCP and UDP, and ICMPv6 ping and raw sockets; raw
        // sockets of other IPv6 protocols are not made here.
        (AF_INET6, SOCK_STREAM) if matches!(protocol, 0 | 6) => crate::linux_socket::Kind::Tcp,
        (AF_INET6, SOCK_DGRAM) if matches!(protocol, 0 | 17) => crate::linux_socket::Kind::Udp,
        (AF_INET6, SOCK_DGRAM | SOCK_RAW) if protocol == IPPROTO_ICMPV6 => {
            crate::linux_socket::Kind::Icmp
        }
        (AF_INET6, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW) => return LINUX_EPROTONOSUPPORT,
        _ => return LINUX_EINVAL,
    };
    // A raw socket needs CAP_NET_RAW, checked once the protocol is known,
    // as Linux's inet_create and inet6_create do; a ping socket a group in
    // ping_group_range (EACCES).
    if base == SOCK_RAW && !linux_has_capability(linox_credentials::capability::NET_RAW) {
        return LINUX_EPERM;
    }
    if base == SOCK_DGRAM && kind == crate::linux_socket::Kind::Icmp && !linux_ping_allowed() {
        return LINUX_EACCES;
    }
    let Some(descriptor) = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        return LINUX_EMFILE;
    };
    let slot = match if kind == crate::linux_socket::Kind::Unix {
        crate::linux_socket::open_unix(base as u8)
    } else if kind == crate::linux_socket::Kind::Icmp && family == AF_INET6 {
        crate::linux_socket::open_icmpv6(base == SOCK_RAW)
    } else if kind == crate::linux_socket::Kind::Icmp {
        crate::linux_socket::open_icmp(base == SOCK_RAW)
    } else if family == AF_INET6 {
        crate::linux_socket::open_ipv6(kind)
    } else {
        crate::linux_socket::open(kind)
    } {
        Ok(slot) => slot,
        Err(error) => {
            let result = linux_socket_error(error);
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                serial_write("linox: Linux IPv4 socket creation failed: ");
                serial_write_u64(result);
                serial_write(" socket/device/pipe/event/timer/stderr ");
                serial_write_u64(linux_socket_slot(descriptor).map_or(u64::MAX, u64::from));
                serial_write(" ");
                serial_write_u64(u64::from(linux_device_descriptor(descriptor)));
                serial_write(" ");
                serial_write_u64(u64::from(linux_pipe_descriptor(descriptor)));
                serial_write(" ");
                serial_write_u64(u64::from(linux_eventfd_descriptor(descriptor)));
                serial_write(" ");
                serial_write_u64(u64::from(linux_timerfd_descriptor(descriptor)));
                serial_write(" ");
                serial_write_u64(u64::from(
                    X86_RUNTIME.ELF_PROBE_STDERR_OPEN.load(Ordering::SeqCst),
                ));
                serial_write("\r\n");
            }
            return result;
        }
    };
    linux_socket_descriptor_installed(
        descriptor,
        slot,
        LINUX_DEVICE_SOCKET | 3,
        (socket_type & SOCK_NONBLOCK) as u32,
        socket_type & SOCK_CLOEXEC != 0,
    )
}

/// socket(AF_PACKET, ...): a packet socket of base type SOCK_RAW or
/// SOCK_DGRAM, which needs CAP_NET_RAW in the domain's user namespace. The
/// socket lives in the caller's network namespace; it carries the TPACKET
/// options its setsockopt validates but delivers no frames.
fn linux_packet_socket_create(socket_type: u64, protocol: u64) -> u64 {
    const SOCK_DGRAM: u64 = 2;
    const SOCK_RAW: u64 = 3;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x8_0000;
    let base = socket_type & 0xf;
    if socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    if !matches!(base, SOCK_DGRAM | SOCK_RAW) {
        return LINUX_ESOCKTNOSUPPORT;
    }
    if !linux_has_capability(linox_credentials::capability::NET_RAW) {
        return LINUX_EPERM;
    }
    let Some(descriptor) = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        return LINUX_EMFILE;
    };
    let slot = match crate::linux_socket::open_packet(base as u8, protocol as u16) {
        Ok(slot) => slot,
        Err(error) => return linux_socket_error(error),
    };
    linux_socket_descriptor_installed(
        descriptor,
        slot,
        LINUX_DEVICE_SOCKET | 3,
        (socket_type & SOCK_NONBLOCK) as u32,
        socket_type & SOCK_CLOEXEC != 0,
    )
}

pub(super) fn linux_socket_pair(family: u64, socket_type: u64, protocol: u64, output: u64) -> u64 {
    const AF_UNIX: u64 = 1;
    const SOCK_STREAM: u64 = 1;
    const SOCK_DGRAM: u64 = 2;
    const SOCK_SEQPACKET: u64 = 5;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x8_0000;
    const AF_INET: u64 = 2;
    const AF_INET6: u64 = 10;
    const SOCK_RAW: u64 = 3;
    let family = u64::from(family as u32);
    let socket_type = u64::from(socket_type as u32);
    let protocol = u64::from(protocol as u32);
    let base = socket_type & 0xf;
    // An inet socket is made first, as Linux makes it (a bad type EINVAL,
    // a protocol the type lacks EPROTONOSUPPORT), and then has no pairs
    // (EOPNOTSUPP: socketpair01).
    if matches!(family, AF_INET | AF_INET6) {
        if socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0
            || !matches!(base, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW)
        {
            return LINUX_EINVAL;
        }
        let made = matches!(
            (family, base, protocol),
            (_, SOCK_STREAM, 0 | 6)
                | (_, SOCK_DGRAM, 0 | 17 | 136)
                | (AF_INET, SOCK_DGRAM | SOCK_RAW, 1)
                | (AF_INET6, SOCK_DGRAM | SOCK_RAW, 58)
        );
        return if made {
            LINUX_EOPNOTSUPP
        } else {
            LINUX_EPROTONOSUPPORT
        };
    }
    if family != AF_UNIX {
        return LINUX_EAFNOSUPPORT;
    }
    if !matches!(base, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET)
        || socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0
        || protocol != 0
    {
        return LINUX_EPROTONOSUPPORT;
    }
    let Some(descriptors) = linux_free_descriptors::<2>(2) else {
        return LINUX_EMFILE;
    };
    let (first, second) = match crate::linux_socket::open_pair(base as u8) {
        Ok(pair) => pair,
        Err(error) => return linux_socket_error(error),
    };
    let Some(credentials) = current_linux_credentials() else {
        let _ = crate::linux_socket::close(first);
        let _ = crate::linux_socket::close(second);
        return LINUX_ESRCH;
    };
    if !crate::linux_socket::set_unix_pair_credentials(
        first,
        second,
        (
            current_linux_process_pid(),
            credentials.user.effective,
            credentials.group.effective,
        ),
    ) {
        let _ = crate::linux_socket::close(first);
        let _ = crate::linux_socket::close(second);
        return LINUX_EINVAL;
    }
    let mut bytes = [0_u8; 8];
    bytes[..4].copy_from_slice(&(descriptors[0] as u32).to_ne_bytes());
    bytes[4..].copy_from_slice(&(descriptors[1] as u32).to_ne_bytes());
    if !copy_to_linux_user(output, &bytes) {
        let _ = crate::linux_socket::close(first);
        let _ = crate::linux_socket::close(second);
        return LINUX_EFAULT;
    }
    let mut installed = [first, second].map(|slot| (slot, false));
    for (descriptor, (slot, done)) in descriptors.into_iter().zip(installed.iter_mut()) {
        *done = install_linux_socket_descriptor(
            descriptor,
            *slot,
            LINUX_DEVICE_SOCKET | 3,
            (socket_type & SOCK_NONBLOCK) as u32,
            socket_type & SOCK_CLOEXEC != 0,
        );
    }
    if installed.iter().any(|(_, done)| !done) {
        for (descriptor, (slot, done)) in descriptors.into_iter().zip(installed) {
            if done {
                let _ = linux_descriptor_close(descriptor);
            } else {
                let _ = crate::linux_socket::close(slot);
            }
        }
        return LINUX_ENOMEM;
    }
    0
}

/// The internet address user memory holds for socket `slot`: a
/// sockaddr_in, or for an AF_INET6 socket a sockaddr_in6 (at least the 24
/// bytes of RFC 2133's, without the scope id, as Linux takes). A shorter
/// one is EINVAL, another family EAFNOSUPPORT.
fn linux_inet_address(
    slot: crate::linux_socket::SlotId,
    address: u64,
    length: u64,
) -> Result<(IpAddress, u16), u64> {
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    let ipv6 = crate::linux_socket::is_ipv6(slot);
    let length = u64::from(length as u32);
    let size = if ipv6 { 24 } else { 16 };
    if length < size as u64 {
        return Err(LINUX_EINVAL);
    }
    let mut sockaddr = [0_u8; 24];
    if !copy_from_linux_user(address, &mut sockaddr[..size]) {
        return Err(LINUX_EFAULT);
    }
    let family = u16::from_ne_bytes([sockaddr[0], sockaddr[1]]);
    if family != if ipv6 { AF_INET6 } else { AF_INET } {
        return Err(LINUX_EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
    let ip = if ipv6 {
        let octets: [u8; 16] = sockaddr[8..24].try_into().unwrap_or([0; 16]);
        IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from_octets(octets))
    } else {
        IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(
            sockaddr[4],
            sockaddr[5],
            sockaddr[6],
            sockaddr[7],
        ))
    };
    Ok((ip, port))
}

/// A destination for socket `slot` (connect, sendto, sendmsg): port 0 is
/// EINVAL, except for ICMP sockets, which have none; an AF_INET6 socket reaches an IPv4-mapped address over IPv4,
/// which an IPV6_V6ONLY one cannot (ENETUNREACH). The unspecified address
/// stays: the socket table takes it as the local host, as Linux does.
fn linux_socket_address(
    slot: crate::linux_socket::SlotId,
    address: u64,
    length: u64,
) -> Result<smoltcp::wire::IpEndpoint, u64> {
    let (ip, port) = linux_inet_address(slot, address, length)?;
    if port == 0 && crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Icmp) {
        return Err(LINUX_EINVAL);
    }
    let ip = match crate::linux_socket::ipv4_of(ip) {
        Some(ipv4) if matches!(ip, IpAddress::Ipv6(_)) => {
            if crate::linux_socket::v6only(slot) == Some(true) {
                return Err(LINUX_ENETUNREACH);
            }
            IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_octets(ipv4.to_be_bytes()))
        }
        _ => ip,
    };
    Ok(smoltcp::wire::IpEndpoint::new(ip, port))
}

/// Whether user memory holds an AF_UNSPEC address (connect's
/// disconnect): the family alone, as Linux reads it.
fn linux_socket_unspecified_address(address: u64, length: u64) -> Result<bool, u64> {
    if u64::from(length as u32) < 2 {
        return Err(LINUX_EINVAL);
    }
    let mut family = [0_u8; 2];
    if !copy_from_linux_user(address, &mut family) {
        return Err(LINUX_EFAULT);
    }
    Ok(u16::from_ne_bytes(family) == 0)
}

/// The canonical path of the file Unix socket pathname `path` leads to,
/// from the caller's root and directory as Linux walks it: the walk's
/// error, or ENOENT when nothing is there.
fn linux_unix_socket_file(
    path: &[u8],
    canonical: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Result<usize, u64> {
    let length = linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), path, canonical)?;
    let file = &canonical[..length];
    if crate::linux_overlay::lookup(file).is_some() || linux_path_access(file).is_some() {
        Ok(length)
    } else {
        Err(LINUX_ENOENT)
    }
}

fn linux_unix_socket_path(address: u64, length: u64, output: &mut [u8; 108]) -> Result<usize, u64> {
    let length = usize::try_from(u64::from(length as u32)).map_err(|_| LINUX_EINVAL)?;
    if !(3..=110).contains(&length) {
        return Err(LINUX_EINVAL);
    }
    let mut sockaddr = [0_u8; 110];
    if !copy_from_linux_user(address, &mut sockaddr[..length]) {
        return Err(LINUX_EFAULT);
    }
    if u16::from_ne_bytes(sockaddr[..2].try_into().unwrap()) != 1 {
        return Err(LINUX_EAFNOSUPPORT);
    }
    let supplied = &sockaddr[2..length];
    let path_length = if supplied[0] == 0 {
        supplied.len()
    } else {
        supplied
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(supplied.len())
    };
    if path_length == 0 {
        return Err(LINUX_EINVAL);
    }
    output[..path_length].copy_from_slice(&supplied[..path_length]);
    Ok(path_length)
}

/// The socket-table slot behind `descriptor` for a call only sockets take
/// (bind, accept, setsockopt...): none for the table's other objects, such
/// as a userfaultfd or a pseudo-terminal, which are no sockets (accept03).
fn linux_socket_call_slot(descriptor: u64) -> Option<crate::linux_socket::SlotId> {
    linux_socket_slot(descriptor)
        .filter(|slot| crate::linux_socket::kind(*slot) != Some(crate::linux_socket::Kind::Object))
}

/// The error for a socket call on `descriptor` that is not a socket: ENOTSOCK
/// when it is an open descriptor of another kind, EBADF when it is not open.
/// A socket call's error for a descriptor that is no socket: EBADF when
/// it is closed or an O_PATH descriptor (which socket calls cannot use, as
/// in Linux), ENOTSOCK otherwise.
pub(super) fn linux_not_socket_error(descriptor: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    if linux_descriptor_open(descriptor) && !linux_path_descriptor(descriptor) {
        LINUX_ENOTSOCK
    } else {
        LINUX_EBADF
    }
}

pub(super) fn linux_socket_bind(descriptor: u64, address: u64, length: u64) -> u64 {
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Netlink) {
        // struct sockaddr_nl: family, padding, port id, multicast groups.
        let mut sockaddr = [0_u8; 12];
        if length < sockaddr.len() as u64 {
            return LINUX_EINVAL;
        }
        if !copy_from_linux_user(address, &mut sockaddr) {
            return LINUX_EFAULT;
        }
        if u16::from_ne_bytes([sockaddr[0], sockaddr[1]]) != 16 {
            return LINUX_EINVAL;
        }
        let port = u32::from_ne_bytes(sockaddr[4..8].try_into().unwrap());
        return match crate::linux_socket::bind_netlink(slot, port, current_linux_process_pid()) {
            Ok(_) => 0,
            Err(error) => linux_socket_error(error),
        };
    }
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Packet) {
        // struct sockaddr_ll: family, protocol, ifindex, hatype, pkttype,
        // halen, addr[8]. bind takes the family, the interface to bind to
        // (ifindex 0 unbinds) and the protocol; a frame ring is never mapped.
        let mut sockaddr = [0_u8; 20];
        if length < sockaddr.len() as u64 {
            return LINUX_EINVAL;
        }
        if !copy_from_linux_user(address, &mut sockaddr) {
            return LINUX_EFAULT;
        }
        if u16::from_ne_bytes([sockaddr[0], sockaddr[1]]) != 17 {
            return LINUX_EINVAL;
        }
        let protocol = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
        let ifindex = i32::from_ne_bytes(sockaddr[4..8].try_into().unwrap());
        // A non-zero index must name an interface of this network namespace.
        if ifindex != 0
            && !linux_network_interfaces()
                .iter()
                .any(|interface| interface.index == ifindex)
        {
            return LINUX_ENODEV;
        }
        return if crate::linux_socket::set_packet_bind(slot, ifindex, protocol) {
            0
        } else {
            linux_not_socket_error(descriptor)
        };
    }
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Unix) {
        let mut path = [0_u8; 108];
        let path_length = match linux_unix_socket_path(address, length, &mut path) {
            Ok(length) => length,
            Err(error) => return error,
        };
        // A pathname becomes a socket file where the path leads, as Linux
        // makes one (bind04 unlinks it after the test): a name already there
        // is EADDRINUSE, a missing parent ENOENT. An abstract name has none.
        let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        let node_length = if path[0] != 0 {
            let length = match linux_canonical_path_at(
                u64::from(LINUX_AT_FDCWD),
                &path[..path_length],
                &mut canonical,
            ) {
                Ok(length) => length,
                Err(error) => return error,
            };
            if crate::linux_overlay::lookup(&canonical[..length]).is_some()
                || linux_path_access(&canonical[..length]).is_some()
            {
                return LINUX_EADDRINUSE;
            }
            if !linux_overlay_parent_exists(&canonical[..length]) {
                return linux_missing_path_error(&canonical[..length]);
            }
            Some(length)
        } else {
            None
        };
        if let Err(error) = crate::linux_socket::bind_unix(slot, &path[..path_length]) {
            return linux_socket_error(error);
        }
        linux_landlock_bound_unix(slot, &path[..path_length]);
        if let Some(length) = node_length {
            let mode = 0o777 & !(X86_RUNTIME.ELF_PROBE_UMASK.load(Ordering::SeqCst) as u32);
            let _ = crate::linux_overlay::create_socket(&canonical[..length], mode);
        }
        return 0;
    }
    let (address, port) = match linux_inet_address(slot, address, length) {
        Ok(endpoint) => endpoint,
        Err(error) => return error,
    };
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Tcp) {
        if let Err(error) = linux_landlock_check_port(port, false) {
            return error;
        }
    }
    // Ports below 1024 need CAP_NET_BIND_SERVICE.
    if (1..1024).contains(&port)
        && !linux_has_capability(linox_credentials::capability::NET_BIND_SERVICE)
    {
        return LINUX_EACCES;
    }
    // A network namespace's sockets bind only to its own addresses (IPv6
    // loopback as its IPv4 loopback).
    let reaches = match address {
        _ if address.is_unspecified() => true,
        IpAddress::Ipv6(ipv6) if ipv6.is_loopback() => linux_network_reaches(0x7f00_0001),
        _ => crate::linux_socket::ipv4_of(address).is_none_or(linux_network_reaches),
    };
    if !reaches {
        return LINUX_EADDRNOTAVAIL;
    }
    crate::linux_socket::bind(slot, address, port).map_or_else(linux_socket_error, |_| 0)
}

pub(super) fn linux_socket_listen(descriptor: u64, backlog: u64) -> u64 {
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // Linux reads the backlog as an unsigned int capped at somaxconn, so a
    // negative backlog, which Rust's standard library passes, means the
    // largest one.
    let backlog = backlog as u32 as usize;
    if !matches!(
        crate::linux_socket::kind(slot),
        Some(crate::linux_socket::Kind::Tcp | crate::linux_socket::Kind::Unix)
    ) {
        return LINUX_EOPNOTSUPP;
    }
    crate::linux_socket::listen(slot, backlog).map_or_else(linux_socket_error, |()| 0)
}

fn linux_socket_accept_address_valid(address: u64, length: u64, size: u32) -> bool {
    if address == 0 {
        return true;
    }
    let mut supplied = [0_u8; 4];
    if length == 0 || !copy_from_linux_user(length, &mut supplied) {
        return false;
    }
    let address_length = usize::try_from(u32::from_ne_bytes(supplied).min(size)).unwrap_or(16);
    linux_writable_user_range_contains(length, 4)
        && linux_writable_user_range_contains(address, address_length)
}

fn linux_socket_accept(descriptor: u64, address: u64, length: u64, flags: u64) -> u64 {
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x8_0000;
    let flags = u64::from(flags as u32);
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    // A pipe end is no socket here, though pipes are socket pairs inside.
    let Some(listener_slot) = linux_socket_call_slot(descriptor)
        .filter(|_| !linux_pipe_descriptor(u64::from(descriptor as u32)))
    else {
        return linux_not_socket_error(descriptor);
    };
    // As Linux's order: a datagram socket cannot accept (EOPNOTSUPP), one
    // not listening has nothing to accept (EINVAL), before the address is
    // looked at (accept01).
    if matches!(
        crate::linux_socket::kind(listener_slot),
        Some(
            crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
                | crate::linux_socket::Kind::Icmp
        )
    ) || crate::linux_socket::socket_type(listener_slot) == Some(2)
    {
        return LINUX_EOPNOTSUPP;
    }
    if !crate::linux_socket::is_listening(listener_slot) {
        return LINUX_EINVAL;
    }
    let Some(accepted_descriptor) = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST) else {
        return LINUX_EMFILE;
    };
    let ipv6 = crate::linux_socket::is_ipv6(listener_slot);
    if !linux_socket_accept_address_valid(address, length, linux_inet_address_size(ipv6)) {
        return LINUX_EFAULT;
    }
    let accepted = if linux_socket_nonblocking(descriptor)
        || X86_RUNTIME
            .LINUX_SOCKET_SINGLE_ATTEMPT
            .load(Ordering::SeqCst)
    {
        crate::linux_socket::accept(listener_slot)
    } else {
        crate::linux_socket::accept_blocking(listener_slot)
    };
    let (accepted_slot, remote) = match accepted {
        Ok(accepted) => accepted,
        Err(error) => return linux_socket_error(error),
    };
    let written =
        if crate::linux_socket::kind(listener_slot) == Some(crate::linux_socket::Kind::Unix) {
            linux_write_unnamed_unix_address(address, length)
        } else {
            linux_write_socket_address(address, length, remote, ipv6)
        };
    if address != 0 && !written {
        let _ = crate::linux_socket::close(accepted_slot);
        return LINUX_EFAULT;
    }
    linux_socket_descriptor_installed(
        accepted_descriptor,
        accepted_slot,
        LINUX_DEVICE_SOCKET | 3,
        (flags & SOCK_NONBLOCK) as u32,
        flags & SOCK_CLOEXEC != 0,
    )
}

/// accept(2) (system call `number`) on a blocking listener waits as a
/// blocking read does: one attempt, then a ready sibling thread or the
/// other processes run and the call starts again, until SO_RCVTIMEO passes.
/// A listener that spun inside the kernel with the entry lock held kept the
/// peer that would connect, a thread or a child on another CPU, from ever
/// entering it (bind04, connect01, setsockopt10).
#[allow(clippy::too_many_arguments)]
pub(super) fn linux_socket_accept_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    descriptor: u64,
    address: u64,
    length: u64,
    flags: u64,
) -> u64 {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire)
        && linux_socket_slot(descriptor).is_some()
        && !linux_socket_nonblocking(descriptor)
    {
        return linux_local_socket_io_live_return(output, caller, number, descriptor, || {
            linux_socket_accept(descriptor, address, length, flags)
        });
    }
    linux_socket_accept(descriptor, address, length, flags)
}

pub(super) fn linux_socket_connect(descriptor: u64, address: u64, length: u64) -> u64 {
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Unix) {
        let mut path = [0_u8; 108];
        let path_length = match linux_unix_socket_path(address, length, &mut path) {
            Ok(length) => length,
            Err(error) => return error,
        };
        // A pathname names the socket file the caller's path walk reaches
        // (from its root: a chrooted process cannot reach sockets outside),
        // and connecting through it needs write permission on it.
        if path[0] != 0 {
            let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            let length = match linux_unix_socket_file(&path[..path_length], &mut canonical) {
                Ok(length) => length,
                Err(error) => return error,
            };
            if let Some(metadata) = crate::linux_overlay::lookup(&canonical[..length])
                .filter(|metadata| metadata.kind == crate::linux_overlay::NodeKind::Socket)
            {
                if let Err(error) = linux_check_access(
                    Some(linux_overlay_file_access(metadata)),
                    linox_credentials::access::WRITE,
                    false,
                ) {
                    return error;
                }
            }
        }
        let credentials = current_linux_credentials().map_or((0, 0), |credentials| {
            (credentials.user.effective, credentials.group.effective)
        });
        if let Some(peer) = crate::linux_socket::unix_connect_target(slot, &path[..path_length]) {
            if let Err(error) = linux_landlock_check_unix_peer(peer, &path[..path_length]) {
                return error;
            }
        }
        // No socket bound to the name: Linux fails a path that does not
        // exist with ENOENT and an abstract name with ECONNREFUSED (musl's
        // nscd lookup treats both as "no daemon").
        return match crate::linux_socket::connect_unix(
            slot,
            &path[..path_length],
            (current_linux_process_pid(), credentials.0, credentials.1),
        ) {
            Ok(()) => 0,
            Err(crate::linux_socket::Error::NotConnected) if path[0] == 0 => LINUX_ECONNREFUSED,
            // A socket file nothing is bound to any more refuses; a path
            // with no file is ENOENT.
            Err(crate::linux_socket::Error::NotConnected) => {
                let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
                match linux_canonical_path_at(
                    u64::from(LINUX_AT_FDCWD),
                    &path[..path_length],
                    &mut canonical,
                ) {
                    Ok(length)
                        if crate::linux_overlay::lookup(&canonical[..length]).is_some_and(
                            |metadata| metadata.kind == crate::linux_overlay::NodeKind::Socket,
                        ) =>
                    {
                        LINUX_ECONNREFUSED
                    }
                    _ => LINUX_ENOENT,
                }
            }
            Err(error) => linux_socket_error(error),
        };
    }
    // AF_UNSPEC ends a TCP connection or forgets a datagram socket's peer.
    if matches!(
        crate::linux_socket::kind(slot),
        Some(
            crate::linux_socket::Kind::Tcp
                | crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
                | crate::linux_socket::Kind::Icmp
        )
    ) {
        match linux_socket_unspecified_address(address, length) {
            Ok(true) => {
                return crate::linux_socket::disconnect(slot)
                    .map_or_else(linux_socket_error, |()| 0)
            }
            Ok(false) => {}
            Err(error) => return error,
        }
    }
    let endpoint = match linux_socket_address(slot, address, length) {
        Ok(endpoint) => endpoint,
        Err(error) => return error,
    };
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Tcp) {
        if let Err(error) = linux_landlock_check_port(endpoint.port, true) {
            return error;
        }
    }
    if !linux_endpoint_reachable(endpoint) {
        return LINUX_ENETUNREACH;
    }
    match crate::linux_socket::connect(slot, endpoint) {
        Ok(()) => 0,
        Err(crate::linux_socket::Error::InProgress) if !linux_socket_nonblocking(descriptor) => {
            crate::linux_socket::complete_connect(slot).map_or_else(linux_socket_error, |()| 0)
        }
        Err(error) => linux_socket_error(error),
    }
}

pub(super) fn linux_socket_sendto(
    descriptor: u64,
    address: u64,
    count: u64,
    flags: u64,
    destination: u64,
    destination_length: u64,
) -> u64 {
    const MSG_OOB: u64 = 1;
    const SUPPORTED_FLAGS: u64 = MSG_OOB | 0x40 | 0x4000 | LINUX_MSG_MORE;
    // The largest UDP payload over IPv4.
    const UDP_PAYLOAD_LIMIT: u64 = 65_507;
    let flags = u64::from(flags as u32);
    // Pipes are socket pairs inside, and write(2) on one comes here too.
    let Some(slot) = linux_socket_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    if flags & !SUPPORTED_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    let kind = crate::linux_socket::kind(slot);
    let tcp = kind == Some(crate::linux_socket::Kind::Tcp);
    // Only TCP has urgent data (MSG_OOB is EOPNOTSUPP elsewhere; sent as
    // ordinary data here).
    if flags & MSG_OOB != 0 && !tcp {
        return LINUX_EOPNOTSUPP;
    }
    // The address is read before anything else, as Linux copies it in: a
    // length past sockaddr_storage is EINVAL, an unreadable one EFAULT.
    if destination != 0 && (destination_length as u32 as i32) < 0
        || destination != 0 && u64::from(destination_length as u32) > 128
    {
        return LINUX_EINVAL;
    }
    if tcp && destination != 0 && !copy_from_linux_user(destination, &mut [0_u8; 16]) {
        return LINUX_EFAULT;
    }
    if matches!(
        kind,
        Some(crate::linux_socket::Kind::Udp | crate::linux_socket::Kind::UdpLite)
    ) && count > UDP_PAYLOAD_LIMIT
    {
        return LINUX_EMSGSIZE;
    }
    let netlink = kind == Some(crate::linux_socket::Kind::Netlink);
    let unix = kind == Some(crate::linux_socket::Kind::Unix);
    // A Unix datagram sent to a name goes to the socket bound to it.
    let _target = if unix && destination != 0 {
        match linux_unix_send_target(slot, destination, destination_length) {
            Ok(target) => target,
            Err(error) => return error,
        }
    } else {
        None
    };
    // A TCP socket sends to its peer, whatever address it is given.
    let remote = if destination == 0 || netlink || tcp || unix {
        None
    } else {
        match linux_socket_address(slot, destination, destination_length) {
            Ok(endpoint) => Some(endpoint),
            Err(error) => return error,
        }
    };
    // A stream (a pipe, a socketpair, TCP) takes as much of the write as it
    // has room for in one call; a UDP or ICMP datagram stays within a page.
    let limit = if matches!(
        crate::linux_socket::kind(slot),
        Some(
            crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
                | crate::linux_socket::Kind::Icmp
        )
    ) {
        PAGE_SIZE
    } else {
        1 << 20
    };
    let length = usize::try_from(count).unwrap_or(usize::MAX).min(limit);
    if length == 0 && limit != PAGE_SIZE {
        return 0;
    }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(length).is_err() {
        return LINUX_ENOMEM;
    }
    bytes.resize(length, 0);
    if !copy_from_linux_user(address, &mut bytes) {
        return LINUX_EFAULT;
    }
    let automatic_credentials = if crate::linux_socket::kind(slot)
        == Some(crate::linux_socket::Kind::Unix)
        && crate::linux_socket::unix_peer_passes_credentials(slot).unwrap_or(false)
    {
        let Some(credentials) = current_linux_credentials() else {
            return LINUX_ESRCH;
        };
        if let Err(error) = crate::linux_socket::unix_credentials_queue_available(slot) {
            return linux_socket_error(error);
        }
        Some((
            current_linux_process_pid(),
            credentials.user.effective,
            credentials.group.effective,
        ))
    } else {
        None
    };
    let result = linux_socket_send_corked(slot, descriptor, flags, &bytes[..length], remote);
    match result {
        Ok(written) => {
            if let Some(credentials) = automatic_credentials {
                if let Err(error) = crate::linux_socket::queue_unix_credentials(slot, credentials) {
                    return linux_socket_error(error);
                }
            }
            if written != 0 {
                linux_notify_async_io(slot);
            }
            written as u64
        }
        // A TCP socket never connected cannot send: EPIPE, as Linux's
        // stream send answers (with SIGPIPE).
        Err(crate::linux_socket::Error::NotConnected) if tcp => LINUX_EPIPE,
        Err(error) => linux_socket_error(error),
    }
}

pub(super) fn linux_socket_recvfrom(
    live: Option<(*mut LinuxSyscallFrame, LinuxUserContext, u64)>,
    descriptor: u64,
    address: u64,
    count: u64,
    flags: u64,
    source: u64,
    source_length: u64,
) -> u64 {
    const MSG_PEEK: u64 = 0x2;
    const MSG_TRUNC: u64 = 0x20;
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_WAITALL: u64 = 0x100;
    // MSG_NOSIGNAL means nothing to a receive; Linux accepts it.
    const MSG_NOSIGNAL: u64 = 0x4000;
    const SUPPORTED_FLAGS: u64 = MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT | MSG_WAITALL | MSG_NOSIGNAL;
    let flags = u64::from(flags as u32);
    let Some(slot) = linux_socket_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // A TLS record that is not application data needs recvmsg's control
    // buffer: here it is EIO.
    linux_tls_receive_control(slot, 0);
    // Linox keeps no socket error queues, so reading one finds it empty.
    if flags & LINUX_MSG_ERRQUEUE != 0 {
        return LINUX_EAGAIN;
    }
    if flags & !SUPPORTED_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    let length = usize::try_from(count).unwrap_or(usize::MAX).min(PAGE_SIZE);
    let mut bytes = [0_u8; PAGE_SIZE];
    let nonblocking = flags & MSG_DONTWAIT != 0 || linux_socket_nonblocking(descriptor);
    let peek_only = flags & MSG_PEEK != 0;
    let wait_all = flags & MSG_WAITALL != 0;
    let result = if nonblocking {
        crate::linux_socket::recv_message(slot, &mut bytes[..length], peek_only)
    } else if matches!(
        crate::linux_socket::kind(slot),
        Some(crate::linux_socket::Kind::Unix | crate::linux_socket::Kind::Netlink)
    ) && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && live.is_some()
    {
        let (output, caller, syscall) = live.unwrap();
        loop {
            match crate::linux_socket::recv_message(slot, &mut bytes[..length], peek_only) {
                // The peer, often a forked child on a socketpair, runs; the
                // receive is retried, or the call restarts later.
                Err(crate::linux_socket::Error::WouldBlock) => {
                    match run_other_linux_processes(output, caller, syscall) {
                        Some(LinuxBlockedWait::Recheck) => continue,
                        Some(LinuxBlockedWait::Return(result)) => return result,
                        // Nothing else can run now: the call waits parked
                        // and starts again, as a blocking receive never
                        // answers EAGAIN (mq_notify03's helper thread).
                        None => return linux_retry_later_live_return(output, caller, syscall),
                    }
                }
                result => break result,
            }
        }
    } else {
        crate::linux_socket::recv_message_blocking(slot, &mut bytes[..length], peek_only, wait_all)
    };
    let (received, message_length, endpoint) = match result {
        Ok(result) => result,
        Err(error) => return linux_socket_error(error),
    };
    if received != 0 && !copy_to_linux_user(address, &bytes[..received]) {
        return LINUX_EFAULT;
    }
    // A netlink message comes from the kernel: sockaddr_nl with port 0.
    if source != 0 && crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Netlink) {
        let mut sockaddr = [0_u8; 12];
        sockaddr[..2].copy_from_slice(&16_u16.to_ne_bytes());
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(source_length, &mut supplied) {
            return LINUX_EFAULT;
        }
        let output_length = (u32::from_ne_bytes(supplied) as usize).min(sockaddr.len());
        if !copy_to_linux_user(source, &sockaddr[..output_length])
            || !copy_to_linux_user(source_length, &(sockaddr.len() as u32).to_ne_bytes())
        {
            return LINUX_EFAULT;
        }
    } else if source != 0 && endpoint.is_none() && crate::linux_socket::unix_type(slot) == Some(2) {
        // A Unix datagram names its sender (bind05 answers it), an unbound
        // one with length 0.
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(source_length, &mut supplied) {
            return LINUX_EFAULT;
        }
        if i32::from_ne_bytes(supplied) < 0 {
            return LINUX_EINVAL;
        }
        if !linux_write_unix_address(
            source,
            source_length,
            &crate::linux_socket::unix_last_sender(slot),
        ) {
            return LINUX_EFAULT;
        }
    } else if source != 0 && endpoint.is_none() {
        // A connected stream names no sender: the length reads back 0 and
        // the address is left alone (recvfrom01's bad address); a negative
        // length is still EINVAL.
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(source_length, &mut supplied) {
            return LINUX_EFAULT;
        }
        if i32::from_ne_bytes(supplied) < 0 {
            return LINUX_EINVAL;
        }
        if !copy_to_linux_user(source_length, &0_u32.to_ne_bytes()) {
            return LINUX_EFAULT;
        }
    } else if source != 0 {
        let Some(endpoint) = endpoint else {
            return LINUX_EINVAL;
        };
        if !linux_write_socket_address(
            source,
            source_length,
            endpoint,
            crate::linux_socket::is_ipv6(slot),
        ) {
            return LINUX_EFAULT;
        }
    }
    if received != 0
        && !peek_only
        && crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Unix)
    {
        let _ = crate::linux_socket::discard_unix_ancillary(slot);
    }
    if flags & MSG_TRUNC != 0
        && matches!(
            crate::linux_socket::kind(slot),
            Some(
                crate::linux_socket::Kind::Udp
                    | crate::linux_socket::Kind::UdpLite
                    | crate::linux_socket::Kind::Icmp
                    | crate::linux_socket::Kind::Netlink
            )
        )
    {
        message_length as u64
    } else {
        received as u64
    }
}

pub(super) fn linux_socket_sendmsg(descriptor: u64, message: u64, flags: u64) -> u64 {
    const MSG_OOB: u64 = 1;
    const SUPPORTED_FLAGS: u64 = 0x40 | 0x4000 | LINUX_MSG_MORE;
    let flags = u64::from(flags as u32);
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // Only TCP has urgent data, as sendto answers (sendmsg01).
    if flags & MSG_OOB != 0
        && crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Tcp)
    {
        return LINUX_EOPNOTSUPP;
    }
    if flags & !SUPPORTED_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    let mut header = [0_u8; 56];
    if !copy_from_linux_user(message, &mut header) {
        return LINUX_EFAULT;
    }
    let name = u64::from_ne_bytes(header[0..8].try_into().unwrap());
    let name_length = u32::from_ne_bytes(header[8..12].try_into().unwrap()) as u64;
    let iov_address = u64::from_ne_bytes(header[16..24].try_into().unwrap());
    let iov_count = u64::from_ne_bytes(header[24..32].try_into().unwrap());
    let control = u64::from_ne_bytes(header[32..40].try_into().unwrap());
    let control_length = u64::from_ne_bytes(header[40..48].try_into().unwrap());
    let Ok(iov_count) = usize::try_from(iov_count) else {
        return LINUX_EINVAL;
    };
    if iov_count > LINUX_IOV_LIMIT {
        return LINUX_EINVAL;
    }
    let kind = crate::linux_socket::kind(slot);
    let tcp = kind == Some(crate::linux_socket::Kind::Tcp);
    let unix = kind == Some(crate::linux_socket::Kind::Unix);
    // A Unix datagram sent to a name goes to the socket bound to it, its
    // rights and credentials too.
    let _target = if unix && name != 0 {
        match linux_unix_send_target(slot, name, name_length) {
            Ok(target) => target,
            Err(error) => return error,
        }
    } else {
        None
    };
    // A TCP socket sends to its peer, whatever address it is given, as
    // sendto does (sendmsg01).
    let remote = if name == 0 || tcp || unix || kind == Some(crate::linux_socket::Kind::Netlink) {
        None
    } else {
        match linux_socket_address(slot, name, name_length) {
            Ok(endpoint) => Some(endpoint),
            Err(error) => return error,
        }
    };
    // A UDP datagram past the largest IPv4 payload is EMSGSIZE, however
    // its parts are laid out.
    if matches!(
        kind,
        Some(crate::linux_socket::Kind::Udp | crate::linux_socket::Kind::UdpLite)
    ) {
        const UDP_PAYLOAD_LIMIT: u64 = 65_507;
        let mut total = 0_u64;
        for index in 0..iov_count {
            let mut iov = [0_u8; 16];
            if !iov_address
                .checked_add((index * 16) as u64)
                .is_some_and(|entry| copy_from_linux_user(entry, &mut iov))
            {
                return LINUX_EFAULT;
            }
            total = total.saturating_add(u64::from_ne_bytes(iov[8..].try_into().unwrap()));
        }
        if total > UDP_PAYLOAD_LIMIT {
            return LINUX_EMSGSIZE;
        }
    }
    let mut passed_rights = [(0, 0_u32); crate::linux_socket::PASSED_RIGHT_LIMIT];
    let mut passed_files = [None; crate::linux_socket::PASSED_RIGHT_LIMIT];
    let mut passed_right_count = 0_usize;
    let mut passed_credentials = None;
    // A TLS socket's control messages say what record type it sends.
    let tls_sends = crate::linux_socket::tls_sends(slot);
    if control_length != 0 && tls_sends {
        if let Some(error) =
            linux_tls_send_control(slot, control, control_length, flags & LINUX_MSG_MORE != 0)
        {
            return error;
        }
    }
    if control_length != 0 && !tls_sends {
        if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Unix) {
            return LINUX_EINVAL;
        }
        let maximum_right_length = 16 + 4 * crate::linux_socket::PASSED_RIGHT_LIMIT as u64;
        if !(20..=maximum_right_length).contains(&control_length) {
            return LINUX_EINVAL;
        }
        let mut ancillary = [0_u8; 16 + 4 * crate::linux_socket::PASSED_RIGHT_LIMIT];
        let copied = usize::try_from(control_length)
            .unwrap_or(usize::MAX)
            .min(ancillary.len());
        if !copy_from_linux_user(control, &mut ancillary[..copied]) {
            return LINUX_EFAULT;
        }
        let ancillary_length = u64::from_ne_bytes(ancillary[..8].try_into().unwrap());
        let level = i32::from_ne_bytes(ancillary[8..12].try_into().unwrap());
        let kind = i32::from_ne_bytes(ancillary[12..16].try_into().unwrap());
        if level != 1 {
            return LINUX_EINVAL;
        }
        match kind {
            1 => {
                let Some(payload_length) = ancillary_length.checked_sub(16) else {
                    return LINUX_EINVAL;
                };
                if payload_length == 0
                    || payload_length % 4 != 0
                    || ancillary_length > maximum_right_length
                    || control_length < ancillary_length
                    || control_length > ((ancillary_length + 7) & !7)
                {
                    return LINUX_EINVAL;
                }
                passed_right_count = payload_length as usize / 4;
                let mut right_slots = [0; crate::linux_socket::PASSED_RIGHT_LIMIT];
                for index in 0..passed_right_count {
                    let start = 16 + index * 4;
                    let descriptor =
                        i32::from_ne_bytes(ancillary[start..start + 4].try_into().unwrap());
                    let Ok(descriptor) = u64::try_from(descriptor) else {
                        return LINUX_EBADF;
                    };
                    if let Some(right_slot) = linux_socket_slot(descriptor) {
                        let Some(right_flags) = linux_socket_flags(descriptor) else {
                            return LINUX_EBADF;
                        };
                        passed_rights[index] = (right_slot, right_flags);
                        right_slots[index] = right_slot;
                    } else {
                        let Some(file) = linux_file_right(descriptor) else {
                            return LINUX_EBADF;
                        };
                        passed_files[index] = Some(file);
                        right_slots[index] = crate::linux_socket::SlotId::MAX;
                    }
                }
                if let Err(error) = crate::linux_socket::unix_right_queue_available(
                    slot,
                    &right_slots[..passed_right_count],
                ) {
                    return linux_socket_error(error);
                }
                if linux_unix_inflight_limit_exceeded() {
                    return LINUX_ETOOMANYREFS;
                }
            }
            2 if ancillary_length == 28 && (28..=32).contains(&control_length) => {
                let pid = i32::from_ne_bytes(ancillary[16..20].try_into().unwrap());
                let uid = u32::from_ne_bytes(ancillary[20..24].try_into().unwrap());
                let gid = u32::from_ne_bytes(ancillary[24..28].try_into().unwrap());
                let Some(credentials) = current_linux_credentials() else {
                    return LINUX_ESRCH;
                };
                let held = |ids: linox_credentials::Ids, id: u32| {
                    credentials.privileged() || [ids.real, ids.effective, ids.saved].contains(&id)
                };
                if pid < 0
                    || pid as u32 != current_linux_process_pid()
                    || !held(credentials.user, uid)
                    || !held(credentials.group, gid)
                {
                    return LINUX_EPERM;
                }
                if let Err(error) = crate::linux_socket::unix_credentials_queue_available(slot) {
                    return linux_socket_error(error);
                }
                passed_credentials = Some((pid as u32, uid, gid));
            }
            _ => return LINUX_EINVAL,
        }
    }
    if passed_credentials.is_none()
        && crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Unix)
        && crate::linux_socket::unix_peer_passes_credentials(slot).unwrap_or(false)
    {
        let Some(credentials) = current_linux_credentials() else {
            return LINUX_ESRCH;
        };
        if let Err(error) = crate::linux_socket::unix_credentials_queue_available(slot) {
            return linux_socket_error(error);
        }
        passed_credentials = Some((
            current_linux_process_pid(),
            credentials.user.effective,
            credentials.group.effective,
        ));
    }
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut used = 0_usize;
    for index in 0..iov_count {
        let Some(entry) = iov_address.checked_add((index * 16) as u64) else {
            return LINUX_EFAULT;
        };
        let mut iov = [0_u8; 16];
        if !copy_from_linux_user(entry, &mut iov) {
            return LINUX_EFAULT;
        }
        let source = u64::from_ne_bytes(iov[..8].try_into().unwrap());
        let length = usize::try_from(u64::from_ne_bytes(iov[8..].try_into().unwrap()))
            .unwrap_or(usize::MAX)
            .min(PAGE_SIZE - used);
        if !copy_from_linux_user(source, &mut bytes[used..used + length]) {
            return LINUX_EFAULT;
        }
        used += length;
        if used == PAGE_SIZE {
            break;
        }
    }
    if (passed_right_count != 0 || passed_credentials.is_some()) && used == 0 {
        return LINUX_EINVAL;
    }
    for retained_rights in 0..passed_right_count {
        let retained = match passed_files[retained_rights] {
            Some(file) => crate::linux_socket::queue_file_right(file)
                .map(|right| passed_rights[retained_rights].0 = right)
                .is_some(),
            None => crate::linux_socket::duplicate(passed_rights[retained_rights].0),
        };
        if !retained {
            for (rollback, _) in passed_rights.iter().copied().take(retained_rights) {
                let _ = crate::linux_socket::close(rollback);
            }
            return LINUX_ENFILE;
        }
    }
    let result = linux_socket_send_corked(slot, descriptor, flags, &bytes[..used], remote);
    match result {
        Ok(written) => {
            if passed_right_count != 0 {
                if let Err(error) = crate::linux_socket::queue_unix_rights(
                    slot,
                    &passed_rights[..passed_right_count],
                ) {
                    for (passed_slot, _) in passed_rights.iter().copied().take(passed_right_count) {
                        let _ = crate::linux_socket::close(passed_slot);
                    }
                    return linux_socket_error(error);
                }
            }
            if let Some(credentials) = passed_credentials {
                if let Err(error) = crate::linux_socket::queue_unix_credentials(slot, credentials) {
                    let _ = crate::linux_socket::discard_unix_peer_ancillary(slot);
                    return linux_socket_error(error);
                }
            }
            written as u64
        }
        Err(error) => {
            for (passed_slot, _) in passed_rights.iter().copied().take(passed_right_count) {
                let _ = crate::linux_socket::close(passed_slot);
            }
            // A TCP socket never connected cannot send: EPIPE, as sendto.
            if tcp && error == crate::linux_socket::Error::NotConnected {
                return LINUX_EPIPE;
            }
            linux_socket_error(error)
        }
    }
}

fn linux_install_received_socket(
    slot: crate::linux_socket::SlotId,
    flags: u32,
    close_on_exec: bool,
) -> Option<u64> {
    let descriptor = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST)?;
    install_linux_socket_descriptor(
        descriptor,
        slot,
        LINUX_DEVICE_SOCKET | 3,
        flags,
        close_on_exec,
    )
    .then_some(descriptor)
}

// Describes a non-socket descriptor for SCM_RIGHTS with the same state a
// dup(2) copies, so Wayland clients can pass memfd pools and other files.
fn linux_file_right(descriptor: u64) -> Option<crate::linux_socket::FileRight> {
    let device = linux_device_descriptor(descriptor);
    if device == 0
        || device & LINUX_DEVICE_CONSOLE != 0
        || linux_mq_descriptor_id(descriptor).is_some()
        || linux_fanotify_descriptor(descriptor)
        || linux_io_uring_descriptor(descriptor)
    {
        return None;
    }
    let generation = linux_descriptor_tmp_generation(descriptor).unwrap_or(0);
    Some(crate::linux_socket::FileRight {
        device,
        rootfs: linux_rootfs_descriptor(descriptor),
        generation,
        flags: linux_socket_flags(descriptor).unwrap_or(0),
        offset: linux_descriptor_offset(descriptor).load(Ordering::SeqCst),
    })
}

fn linux_install_received_file(
    file: crate::linux_socket::FileRight,
    close_on_exec: bool,
) -> Option<u64> {
    let descriptor = linux_free_descriptor(LINUX_AUX_DESCRIPTOR_FIRST)?;
    if descriptor >= LINUX_DESCRIPTOR_TABLE_LIMIT {
        return install_linux_overflow_descriptor(
            descriptor,
            crate::linux_fd_table::Entry {
                state: file.device,
                rootfs: file.rootfs,
                generation: file.generation,
                socket_flags: file.flags,
                offset: file.offset,
                close_on_exec,
                ..Default::default()
            },
        )
        .then_some(descriptor);
    }
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Device).store(file.device, Ordering::SeqCst);
    linux_fd_cell::<u16>(descriptor, LinuxFdField::Rootfs).store(file.rootfs, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Generation)
        .store(file.generation, Ordering::SeqCst);
    linux_fd_cell::<u32>(descriptor, LinuxFdField::Flags).store(file.flags, Ordering::SeqCst);
    linux_legacy_descriptor_offset(descriptor).store(file.offset, Ordering::SeqCst);
    set_linux_descriptor_close_on_exec(descriptor, close_on_exec);
    Some(descriptor)
}

pub(super) fn linux_unix_inflight_limit_exceeded() -> bool {
    crate::linux_socket::unix_inflight_rights() > linux_nofile_soft_limit() as usize
}

pub(super) fn linux_socket_recvmsg(
    live: Option<(*mut LinuxSyscallFrame, LinuxUserContext, u64)>,
    descriptor: u64,
    message: u64,
    flags: u64,
) -> u64 {
    const MSG_PEEK: u64 = 0x2;
    const MSG_TRUNC: u64 = 0x20;
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_WAITALL: u64 = 0x100;
    const MSG_CTRUNC: u32 = 0x8;
    const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
    const MSG_NOSIGNAL: u64 = 0x4000;
    const SUPPORTED_FLAGS: u64 =
        MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT | MSG_WAITALL | MSG_CMSG_CLOEXEC | MSG_NOSIGNAL;
    let flags = u64::from(flags as u32);
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // Linux's order: MSG_CMSG_COMPAT is EINVAL, then the header is read
    // (EFAULT) and checked (a negative name length EINVAL, more vectors
    // than UIO_MAXIOV EMSGSIZE), then the flags (recvmsg01).
    const MSG_CMSG_COMPAT: u64 = 0x8000_0000;
    if flags & MSG_CMSG_COMPAT != 0 {
        return LINUX_EINVAL;
    }
    let mut header = [0_u8; 56];
    if !copy_from_linux_user(message, &mut header) {
        return LINUX_EFAULT;
    }
    let name = u64::from_ne_bytes(header[0..8].try_into().unwrap());
    let iov_address = u64::from_ne_bytes(header[16..24].try_into().unwrap());
    let iov_count = usize::try_from(u64::from_ne_bytes(header[24..32].try_into().unwrap()))
        .unwrap_or(usize::MAX);
    let control = u64::from_ne_bytes(header[32..40].try_into().unwrap());
    let control_capacity = u64::from_ne_bytes(header[40..48].try_into().unwrap());
    if i32::from_ne_bytes(header[8..12].try_into().unwrap()) < 0 {
        return LINUX_EINVAL;
    }
    if iov_count > LINUX_IOV_LIMIT {
        return LINUX_EMSGSIZE;
    }
    // Linox keeps no socket error queues, so reading one finds it empty.
    if flags & LINUX_MSG_ERRQUEUE != 0 {
        return LINUX_EAGAIN;
    }
    if flags & !SUPPORTED_FLAGS != 0 {
        return LINUX_EINVAL;
    }
    let right_count = crate::linux_socket::unix_right_count(slot);
    let credentials_pending = crate::linux_socket::unix_credentials_pending(slot);
    let mut right_output_count = right_count;
    while right_output_count != 0
        && ((16 + 4 * right_output_count as u64 + 7) & !7) > control_capacity
    {
        right_output_count -= 1;
    }
    let right_output_space = if right_output_count == 0 {
        0
    } else {
        (16 + 4 * right_output_count as u64 + 7) & !7
    };
    let credentials_output =
        credentials_pending && control_capacity.saturating_sub(right_output_space) >= 32;
    let writable_control =
        usize::try_from(right_output_space + if credentials_output { 32 } else { 0 })
            .unwrap_or(usize::MAX);
    if writable_control != 0
        && (control == 0 || !linux_writable_user_range_contains(control, writable_control))
    {
        return LINUX_EFAULT;
    }
    let mut capacity = 0_usize;
    let mut iovs = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
    for (index, output) in iovs.iter_mut().enumerate().take(iov_count) {
        let Some(entry) = iov_address.checked_add((index * 16) as u64) else {
            return LINUX_EFAULT;
        };
        let mut iov = [0_u8; 16];
        if !copy_from_linux_user(entry, &mut iov) {
            return LINUX_EFAULT;
        }
        output.0 = u64::from_ne_bytes(iov[..8].try_into().unwrap());
        output.1 = usize::try_from(u64::from_ne_bytes(iov[8..].try_into().unwrap()))
            .unwrap_or(usize::MAX)
            .min(PAGE_SIZE.saturating_sub(capacity));
        capacity += output.1;
    }
    let mut bytes = [0_u8; PAGE_SIZE];
    let nonblocking = flags & MSG_DONTWAIT != 0 || linux_socket_nonblocking(descriptor);
    let peek_only = flags & MSG_PEEK != 0;
    let wait_all = flags & MSG_WAITALL != 0;
    linux_tls_receive_control(slot, if control == 0 { 0 } else { control_capacity });
    let result = if nonblocking {
        crate::linux_socket::recv_message(slot, &mut bytes[..capacity], peek_only)
    } else if matches!(
        crate::linux_socket::kind(slot),
        Some(crate::linux_socket::Kind::Unix | crate::linux_socket::Kind::Netlink)
    ) && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && live.is_some()
    {
        let (output, caller, syscall) = live.unwrap();
        loop {
            match crate::linux_socket::recv_message(slot, &mut bytes[..capacity], peek_only) {
                // The peer, often a forked child on a socketpair, runs; the
                // receive is retried, or the call restarts later.
                Err(crate::linux_socket::Error::WouldBlock) => {
                    match run_other_linux_processes(output, caller, syscall) {
                        Some(LinuxBlockedWait::Recheck) => continue,
                        Some(LinuxBlockedWait::Return(result)) => return result,
                        // Nothing else can run now: the call waits parked
                        // and starts again, as a blocking receive never
                        // answers EAGAIN (mq_notify03's helper thread).
                        None => return linux_retry_later_live_return(output, caller, syscall),
                    }
                }
                result => break result,
            }
        }
    } else {
        crate::linux_socket::recv_message_blocking(
            slot,
            &mut bytes[..capacity],
            peek_only,
            wait_all,
        )
    };
    let (received, message_length, endpoint) = match result {
        Ok(result) => result,
        Err(error) => return linux_socket_error(error),
    };
    let mut copied = 0_usize;
    for (destination, length) in iovs.into_iter().take(iov_count) {
        let length = length.min(received - copied);
        if length != 0 && !copy_to_linux_user(destination, &bytes[copied..copied + length]) {
            return LINUX_EFAULT;
        }
        copied += length;
        if copied == received {
            break;
        }
    }
    if name != 0 {
        if let Some(endpoint) = endpoint {
            let name_length_address = message + 8;
            let ipv6 = crate::linux_socket::is_ipv6(slot);
            if !linux_write_socket_address(name, name_length_address, endpoint, ipv6) {
                return LINUX_EFAULT;
            }
            header[8..12].copy_from_slice(&linux_inet_address_size(ipv6).to_ne_bytes());
        } else if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Netlink) {
            // A netlink message comes from the kernel: sockaddr_nl, port 0.
            let mut sockaddr = [0_u8; 12];
            sockaddr[..2].copy_from_slice(&16_u16.to_ne_bytes());
            let supplied = u32::from_ne_bytes(header[8..12].try_into().unwrap());
            let length = (supplied as usize).min(sockaddr.len());
            if !copy_to_linux_user(name, &sockaddr[..length]) {
                return LINUX_EFAULT;
            }
            header[8..12].copy_from_slice(&(sockaddr.len() as u32).to_ne_bytes());
        } else if crate::linux_socket::unix_type(slot) == Some(2) {
            // A Unix datagram's sender, as recvfrom gives it.
            let name_length_address = message + 8;
            if !linux_write_unix_address(
                name,
                name_length_address,
                &crate::linux_socket::unix_last_sender(slot),
            ) {
                return LINUX_EFAULT;
            }
            let mut written = [0_u8; 4];
            if !copy_from_linux_user(name_length_address, &mut written) {
                return LINUX_EFAULT;
            }
            header[8..12].copy_from_slice(&written);
        }
    }
    let mut output_flags = if message_length > received {
        MSG_TRUNC as u32
    } else {
        0
    };
    let mut control_length = 0_u64;
    if right_count != 0 {
        if right_output_count == 0 {
            output_flags |= MSG_CTRUNC;
            if !peek_only {
                let _ = crate::linux_socket::discard_unix_rights(slot);
            }
        } else {
            let mut rights = [(0, 0_u32); crate::linux_socket::PASSED_RIGHT_LIMIT];
            let received_rights =
                match crate::linux_socket::receive_unix_rights(slot, &mut rights, peek_only) {
                    Ok(count) if count == right_count => count,
                    Ok(_) => return LINUX_EINVAL,
                    Err(error) => return linux_socket_error(error),
                };
            let mut ancillary = [0_u8; 16 + 4 * crate::linux_socket::PASSED_RIGHT_LIMIT];
            ancillary[8..12].copy_from_slice(&1_i32.to_ne_bytes());
            ancillary[12..16].copy_from_slice(&1_i32.to_ne_bytes());
            let mut installed = 0_usize;
            for (right_slot, right_flags) in rights
                .iter()
                .copied()
                .take(received_rights.min(right_output_count))
            {
                let close_on_exec = flags & MSG_CMSG_CLOEXEC != 0;
                let received_descriptor = match crate::linux_socket::file_right(right_slot) {
                    // The new descriptor copies the file's state, so the
                    // queued reference to the right is dropped either way.
                    Some(file) => {
                        let installed = linux_install_received_file(file, close_on_exec);
                        let _ = crate::linux_socket::close(right_slot);
                        installed
                    }
                    None => linux_install_received_socket(right_slot, right_flags, close_on_exec),
                };
                let Some(received_descriptor) = received_descriptor else {
                    break;
                };
                let start = 16 + installed * 4;
                ancillary[start..start + 4]
                    .copy_from_slice(&(received_descriptor as i32).to_ne_bytes());
                installed += 1;
            }
            for (right_slot, _) in rights
                .iter()
                .copied()
                .skip(installed)
                .take(received_rights - installed)
            {
                let _ = crate::linux_socket::close(right_slot);
            }
            if installed != received_rights {
                output_flags |= MSG_CTRUNC;
            }
            if installed != 0 {
                let ancillary_length = 16 + installed * 4;
                let ancillary_space = (ancillary_length + 7) & !7;
                ancillary[..8].copy_from_slice(&(ancillary_length as u64).to_ne_bytes());
                if !copy_to_linux_user(control, &ancillary[..ancillary_space]) {
                    for offset in 0..installed {
                        let start = 16 + offset * 4;
                        let descriptor =
                            i32::from_ne_bytes(ancillary[start..start + 4].try_into().unwrap());
                        let _ = linux_descriptor_close(descriptor as u64);
                    }
                    return LINUX_EFAULT;
                }
                control_length = ancillary_space as u64;
            }
        }
    }
    if credentials_pending {
        let remaining = control_capacity.saturating_sub(control_length);
        if remaining < 32 {
            output_flags |= MSG_CTRUNC;
            if !peek_only {
                let _ = crate::linux_socket::receive_unix_credentials(slot, false);
            }
        } else {
            let credentials = match crate::linux_socket::receive_unix_credentials(slot, peek_only) {
                Ok(Some(credentials)) => credentials,
                Ok(None) => return LINUX_EINVAL,
                Err(error) => return linux_socket_error(error),
            };
            let mut ancillary = [0_u8; 32];
            ancillary[..8].copy_from_slice(&28_u64.to_ne_bytes());
            ancillary[8..12].copy_from_slice(&1_i32.to_ne_bytes());
            ancillary[12..16].copy_from_slice(&2_i32.to_ne_bytes());
            ancillary[16..20].copy_from_slice(&(credentials.0 as i32).to_ne_bytes());
            ancillary[20..24].copy_from_slice(&credentials.1.to_ne_bytes());
            ancillary[24..28].copy_from_slice(&credentials.2.to_ne_bytes());
            if !copy_to_linux_user(control + control_length, &ancillary) {
                return LINUX_EFAULT;
            }
            control_length += 32;
        }
    }
    // TLS_GET_RECORD_TYPE: the type of the TLS records read.
    if let Some(written) = linux_tls_record_type_message(
        slot,
        control + control_length,
        if control == 0 {
            0
        } else {
            control_capacity.saturating_sub(control_length)
        },
    ) {
        match written {
            Ok(space) => control_length += space,
            Err(0) => output_flags |= MSG_CTRUNC,
            Err(error) => return error,
        }
    }
    // IP_RECVTTL: the datagram's TTL (SOL_IP, IP_TTL), which ping prints.
    if let Some(ttl) = crate::linux_socket::received_ttl(slot).filter(|_| {
        crate::linux_socket::boolean_option(slot, crate::linux_socket::BooleanOption::ReceiveTtl)
            .unwrap_or(false)
    }) {
        if control_capacity.saturating_sub(control_length) < 24 {
            output_flags |= MSG_CTRUNC;
        } else {
            let mut ancillary = [0_u8; 24];
            ancillary[..8].copy_from_slice(&20_u64.to_ne_bytes());
            ancillary[12..16].copy_from_slice(&2_i32.to_ne_bytes());
            ancillary[16..20].copy_from_slice(&i32::from(ttl).to_ne_bytes());
            if !copy_to_linux_user(control + control_length, &ancillary) {
                return LINUX_EFAULT;
            }
            control_length += 24;
        }
    }
    // IPV6_RECVHOPLIMIT and IPV6_2292HOPLIMIT: the hop limit an ICMPv6
    // datagram arrived with (SOL_IPV6, IPV6_HOPLIMIT, or the RFC 2292 type).
    for (option, kind) in [
        (crate::linux_socket::BooleanOption::ReceiveHopLimit, 52_i32),
        (
            crate::linux_socket::BooleanOption::ReceiveHopLimit2292,
            8_i32,
        ),
    ] {
        let Some(hop_limit) = crate::linux_socket::received_ttl(slot).filter(|_| {
            crate::linux_socket::is_ipv6(slot)
                && crate::linux_socket::boolean_option(slot, option).unwrap_or(false)
        }) else {
            continue;
        };
        if control_capacity.saturating_sub(control_length) < 24 {
            output_flags |= MSG_CTRUNC;
            continue;
        }
        let mut ancillary = [0_u8; 24];
        ancillary[..8].copy_from_slice(&20_u64.to_ne_bytes());
        ancillary[8..12].copy_from_slice(&41_i32.to_ne_bytes());
        ancillary[12..16].copy_from_slice(&kind.to_ne_bytes());
        ancillary[16..20].copy_from_slice(&i32::from(hop_limit).to_ne_bytes());
        if !copy_to_linux_user(control + control_length, &ancillary) {
            return LINUX_EFAULT;
        }
        control_length += 24;
    }
    header[40..48].copy_from_slice(&control_length.to_ne_bytes());
    header[48..52].copy_from_slice(&output_flags.to_ne_bytes());
    if !copy_to_linux_user(message, &header) {
        return LINUX_EFAULT;
    }
    if flags & MSG_TRUNC != 0
        && matches!(
            crate::linux_socket::kind(slot),
            Some(
                crate::linux_socket::Kind::Udp
                    | crate::linux_socket::Kind::UdpLite
                    | crate::linux_socket::Kind::Icmp
                    | crate::linux_socket::Kind::Netlink
            )
        )
    {
        message_length as u64
    } else {
        received as u64
    }
}

pub(super) fn linux_socket_sendmmsg(
    descriptor: u64,
    messages: u64,
    count: u64,
    flags: u64,
) -> (u64, bool) {
    const MMSGHDR_SIZE: u64 = 64;
    let flags = u64::from(flags as u32);
    let Ok(count) = usize::try_from(count) else {
        return (LINUX_EINVAL, false);
    };
    if count > LINUX_IOV_LIMIT {
        return (LINUX_EINVAL, false);
    }
    let mut completed = 0_u64;
    for index in 0..count {
        let Some(message) = messages.checked_add((index as u64) * MMSGHDR_SIZE) else {
            return (
                if completed == 0 {
                    LINUX_EFAULT
                } else {
                    completed
                },
                false,
            );
        };
        let result = linux_socket_sendmsg(descriptor, message, flags);
        if result >= u64::MAX - 4095 {
            return (
                if completed == 0 { result } else { completed },
                result == LINUX_EPIPE,
            );
        }
        let Some(length) = u32::try_from(result).ok() else {
            return (
                if completed == 0 {
                    LINUX_EINVAL
                } else {
                    completed
                },
                false,
            );
        };
        if !copy_to_linux_user(message + 56, &length.to_ne_bytes()) {
            return (
                if completed == 0 {
                    LINUX_EFAULT
                } else {
                    completed
                },
                false,
            );
        }
        completed += 1;
    }
    (completed, false)
}

pub(super) fn linux_socket_send_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    descriptor: u64,
    result: u64,
    flags: u64,
    broken_pipe: bool,
) -> u64 {
    const MSG_NOSIGNAL: u64 = 0x4000;
    if (result == LINUX_EPIPE || broken_pipe) && flags & MSG_NOSIGNAL == 0 {
        linux_broken_pipe_live_return(output, caller)
    } else if result < u64::MAX - 4095
        && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && crate::linux_socket::kind(
            linux_socket_slot(descriptor).unwrap_or(crate::linux_socket::SlotId::MAX),
        ) == Some(crate::linux_socket::Kind::Unix)
        && X86_RUNTIME
            .LINUX_PROCESS_SCHEDULER_NESTING
            .load(Ordering::SeqCst)
            != 0
        && yield_current_linux_process(caller, result)
    {
        LINUX_RETURN_TO_KERNEL
    } else {
        result
    }
}

pub(super) fn linux_socket_recvmmsg(
    descriptor: u64,
    messages: u64,
    count: u64,
    flags: u64,
    timeout: u64,
) -> u64 {
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_WAITFORONE: u64 = 0x1_0000;
    const MMSGHDR_SIZE: u64 = 64;
    let flags = u64::from(flags as u32);
    if flags & !(MSG_DONTWAIT | MSG_WAITFORONE) != 0 {
        return LINUX_EINVAL;
    }
    let Ok(count) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if count > LINUX_IOV_LIMIT {
        return LINUX_EINVAL;
    }
    if timeout != 0 {
        let mut value = [0_u8; 16];
        if !copy_from_linux_user(timeout, &mut value) {
            return LINUX_EFAULT;
        }
        if linux_timespec_nanoseconds(&value).is_none() {
            return LINUX_EINVAL;
        }
    }
    let mut completed = 0_u64;
    for index in 0..count {
        let Some(message) = messages.checked_add((index as u64) * MMSGHDR_SIZE) else {
            return if completed == 0 {
                LINUX_EFAULT
            } else {
                completed
            };
        };
        let receive_flags = (flags & MSG_DONTWAIT)
            | (u64::from(flags & MSG_WAITFORONE != 0 && completed != 0) * MSG_DONTWAIT);
        let result = linux_socket_recvmsg(None, descriptor, message, receive_flags);
        if result >= u64::MAX - 4095 {
            return if completed == 0 { result } else { completed };
        }
        let Some(length) = u32::try_from(result).ok() else {
            return if completed == 0 {
                LINUX_EINVAL
            } else {
                completed
            };
        };
        if !copy_to_linux_user(message + 56, &length.to_ne_bytes()) {
            return if completed == 0 {
                LINUX_EFAULT
            } else {
                completed
            };
        }
        completed += 1;
    }
    if timeout != 0 && !copy_to_linux_user(timeout, &[0_u8; 16]) {
        return if completed == 0 {
            LINUX_EFAULT
        } else {
            completed
        };
    }
    completed
}

/// Reports an AF_UNIX peer with no bound name: just the address family, as
/// Linux returns for the client end of a connection to a named listener.
fn linux_write_unnamed_unix_address(address: u64, length_address: u64) -> bool {
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length_address, &mut supplied) {
        return false;
    }
    let length = u32::from_ne_bytes(supplied).min(2) as usize;
    copy_to_linux_user(address, &1_u16.to_ne_bytes()[..length])
        && copy_to_linux_user(length_address, &2_u32.to_ne_bytes())
}

/// MSG_MORE: more data follows, so the send is held back.
const LINUX_MSG_MORE: u64 = 0x8000;

/// Sends `payload` on socket `slot` (descriptor `descriptor`), waiting
/// unless MSG_DONTWAIT or the descriptor says not to. On TCP and UDP,
/// MSG_MORE holds the data back, and the next send without it goes out
/// with what was held, as one datagram on UDP (send02); the count returned
/// is this call's.
fn linux_socket_send_corked(
    slot: crate::linux_socket::SlotId,
    descriptor: u64,
    flags: u64,
    payload: &[u8],
    remote: Option<smoltcp::wire::IpEndpoint>,
) -> Result<usize, crate::linux_socket::Error> {
    if remote.is_some_and(|remote| !linux_endpoint_reachable(remote)) {
        return Err(crate::linux_socket::Error::Unavailable);
    }
    if linux_rtnetlink_socket(slot) {
        return linux_rtnetlink_send(slot, payload);
    }
    let corks = matches!(
        crate::linux_socket::kind(slot),
        Some(
            crate::linux_socket::Kind::Tcp
                | crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
        )
    );
    if corks && flags & LINUX_MSG_MORE != 0 {
        return crate::linux_socket::cork(slot, payload);
    }
    let mut corked = if corks {
        crate::linux_socket::take_corked(slot)
    } else {
        Vec::new()
    };
    let held = corked.len();
    let combined = if held == 0 {
        payload
    } else {
        corked
            .try_reserve(payload.len())
            .map_err(|_| crate::linux_socket::Error::Exhausted)?;
        corked.extend_from_slice(payload);
        &corked
    };
    let sent = if flags & 0x40 != 0 || linux_socket_nonblocking(descriptor) {
        crate::linux_socket::send(slot, combined, remote)
    } else {
        crate::linux_socket::send_blocking(slot, combined, remote)
    };
    sent.map(|written| written.saturating_sub(held))
}

/// A Unix datagram socket's send to a name in progress: its sends go to the
/// socket bound to the name until this is dropped.
struct LinuxUnixSendTarget(crate::linux_socket::SlotId);

impl Drop for LinuxUnixSendTarget {
    fn drop(&mut self) {
        let _ = crate::linux_socket::set_unix_send_target(self.0, None);
    }
}

/// Points Unix socket `slot`'s sends at the datagram socket bound to the
/// sockaddr_un at `address`, as sendto and sendmsg with a name do. A
/// stream socket given a name is EISCONN when connected, else EOPNOTSUPP;
/// no socket at the name is ECONNREFUSED (an abstract name, or a socket
/// file nothing is bound to) or ENOENT.
fn linux_unix_send_target(
    slot: crate::linux_socket::SlotId,
    address: u64,
    length: u64,
) -> Result<Option<LinuxUnixSendTarget>, u64> {
    let mut path = [0_u8; 108];
    let path_length = linux_unix_socket_path(address, length, &mut path)?;
    if crate::linux_socket::unix_type(slot) != Some(2) {
        return Err(if crate::linux_socket::unix_peer_name(slot).is_some() {
            LINUX_EISCONN
        } else {
            LINUX_EOPNOTSUPP
        });
    }
    // A pathname must lead to a file from the sender's root.
    if path[0] != 0 {
        let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
        linux_unix_socket_file(&path[..path_length], &mut canonical)?;
    }
    let target = match crate::linux_socket::unix_datagram_target(slot, &path[..path_length]) {
        Ok(target) => {
            linux_landlock_check_unix_peer(target, &path[..path_length])?;
            target
        }
        Err(crate::linux_socket::Error::WrongType) => return Err(LINUX_EPROTOTYPE),
        Err(_) if path[0] == 0 => return Err(LINUX_ECONNREFUSED),
        Err(_) => {
            let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            let socket_file = linux_canonical_path_at(
                u64::from(LINUX_AT_FDCWD),
                &path[..path_length],
                &mut canonical,
            )
            .is_ok_and(|length| {
                crate::linux_overlay::lookup(&canonical[..length])
                    .is_some_and(|metadata| metadata.kind == crate::linux_overlay::NodeKind::Socket)
            });
            return Err(if socket_file {
                LINUX_ECONNREFUSED
            } else {
                LINUX_ENOENT
            });
        }
    };
    crate::linux_socket::set_unix_send_target(slot, Some(target)).map_err(linux_socket_error)?;
    Ok(Some(LinuxUnixSendTarget(slot)))
}

/// Writes Unix socket name `name` as a sockaddr_un at `address`, cut to the
/// length at `length_address`, which then holds the whole length: an
/// unbound socket's name is empty and its length 0.
fn linux_write_unix_address(address: u64, length_address: u64, name: &[u8]) -> bool {
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length_address, &mut supplied) {
        return false;
    }
    if name.is_empty() {
        return copy_to_linux_user(length_address, &0_u32.to_ne_bytes());
    }
    let mut sockaddr = [0_u8; 110];
    let name = &name[..name.len().min(108)];
    sockaddr[..2].copy_from_slice(&1_u16.to_ne_bytes());
    sockaddr[2..2 + name.len()].copy_from_slice(name);
    // A pathname's length takes in its terminating NUL; an abstract one's
    // does not.
    let actual = (2 + name.len() + usize::from(name[0] != 0)).min(sockaddr.len());
    let output_length = (u32::from_ne_bytes(supplied) as usize).min(actual);
    copy_to_linux_user(address, &sockaddr[..output_length])
        && copy_to_linux_user(length_address, &(actual as u32).to_ne_bytes())
}

/// The size of an internet socket's address: sockaddr_in6 for an AF_INET6
/// socket, else sockaddr_in.
fn linux_inet_address_size(ipv6: bool) -> u32 {
    if ipv6 {
        28
    } else {
        16
    }
}

/// Writes `endpoint` as a socket's address: a sockaddr_in, or for an
/// AF_INET6 socket (`ipv6`) a sockaddr_in6 with an IPv4 address mapped
/// (::ffff:a.b.c.d), as much as the length at `length_address` has room
/// for, and the full length there.
fn linux_write_socket_address(
    address: u64,
    length_address: u64,
    endpoint: smoltcp::wire::IpEndpoint,
    ipv6: bool,
) -> bool {
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length_address, &mut supplied) {
        return false;
    }
    let size = linux_inet_address_size(ipv6);
    let length = u32::from_ne_bytes(supplied).min(size);
    let mut sockaddr = [0_u8; 28];
    sockaddr[2..4].copy_from_slice(&endpoint.port.to_be_bytes());
    match endpoint.addr {
        IpAddress::Ipv6(address) => {
            sockaddr[..2].copy_from_slice(&10_u16.to_ne_bytes());
            sockaddr[8..24].copy_from_slice(&address.octets());
        }
        IpAddress::Ipv4(address) if ipv6 => {
            sockaddr[..2].copy_from_slice(&10_u16.to_ne_bytes());
            sockaddr[18..20].copy_from_slice(&[0xff, 0xff]);
            sockaddr[20..24].copy_from_slice(&address.octets());
        }
        IpAddress::Ipv4(address) => {
            sockaddr[..2].copy_from_slice(&2_u16.to_ne_bytes());
            sockaddr[4..8].copy_from_slice(&address.octets());
        }
    }
    copy_to_linux_user(address, &sockaddr[..length as usize])
        && copy_to_linux_user(length_address, &size.to_ne_bytes())
}

pub(super) fn linux_socket_shutdown(descriptor: u64, how: u64) -> u64 {
    let how = u64::from(how as u32);
    let Some(slot) = linux_socket_slot(descriptor) else {
        let descriptor = u64::from(descriptor as u32);
        return if linux_descriptor_open(descriptor) {
            LINUX_ENOTSOCK
        } else {
            LINUX_EBADF
        };
    };
    if how > 2 {
        return LINUX_EINVAL;
    }
    crate::linux_socket::shutdown_socket(slot, how as u8).map_or_else(linux_socket_error, |()| 0)
}

pub(super) fn linux_socket_name(descriptor: u64, address: u64, length: u64, peer: bool) -> u64 {
    let Some(slot) = linux_socket_slot(descriptor)
        .filter(|_| !linux_pipe_descriptor(u64::from(descriptor as u32)))
    else {
        return linux_not_socket_error(descriptor);
    };
    // The length is read first: unreadable is EFAULT, negative EINVAL
    // (getsockname01).
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    if i32::from_ne_bytes(supplied) < 0 {
        return LINUX_EINVAL;
    }
    if let Some((_, port)) = crate::linux_socket::netlink_address(slot) {
        // Its own port id; the peer is the kernel (port 0).
        let mut sockaddr = [0_u8; 12];
        sockaddr[..2].copy_from_slice(&16_u16.to_ne_bytes());
        if !peer {
            sockaddr[4..8].copy_from_slice(&port.to_ne_bytes());
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(length, &mut supplied) {
            return LINUX_EFAULT;
        }
        let output_length = (u32::from_ne_bytes(supplied) as usize).min(sockaddr.len());
        return if copy_to_linux_user(address, &sockaddr[..output_length])
            && copy_to_linux_user(length, &(sockaddr.len() as u32).to_ne_bytes())
        {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Unix) {
        let name = if peer {
            let Some(name) = crate::linux_socket::unix_peer_name(slot) else {
                return LINUX_ENOTCONN;
            };
            name
        } else {
            crate::linux_socket::unix_name(slot).unwrap_or_default()
        };
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(length, &mut supplied) {
            return LINUX_EFAULT;
        }
        let mut sockaddr = [0_u8; 110];
        sockaddr[..2].copy_from_slice(&1_u16.to_ne_bytes());
        sockaddr[2..2 + name.len()].copy_from_slice(&name);
        let actual = 2 + name.len() + usize::from(name.first().is_some_and(|byte| *byte != 0));
        let output_length = (u32::from_ne_bytes(supplied) as usize).min(actual);
        return if copy_to_linux_user(address, &sockaddr[..output_length])
            && copy_to_linux_user(length, &(actual as u32).to_ne_bytes())
        {
            0
        } else {
            LINUX_EFAULT
        };
    }
    let Some((local, remote)) = crate::linux_socket::names(slot) else {
        return LINUX_EBADF;
    };
    let endpoint = if peer {
        let Some(remote) = remote else {
            return LINUX_ENOTCONN;
        };
        remote
    } else {
        local
    };
    if linux_write_socket_address(
        address,
        length,
        endpoint,
        crate::linux_socket::is_ipv6(slot),
    ) {
        0
    } else {
        LINUX_EFAULT
    }
}

/// The TPACKET header length (bytes) for version `version` (0: V1, 1: V2,
/// 2: V3): the aligned per-frame header plus the sockaddr_ll a frame carries,
/// as Linux's TPACKET_HDRLEN macros compute. Used to reject a ring whose
/// frame is too small to hold a packet's header.
fn linux_tpacket_hdrlen(version: u8) -> u64 {
    match version {
        // TPACKET_ALIGN(sizeof(tpacket_hdr)) + sizeof(sockaddr_ll) = 32 + 20,
        // and the V2 header aligns to the same 32.
        0 | 1 => 52,
        // TPACKET_ALIGN(sizeof(tpacket3_hdr)) + sizeof(sockaddr_ll) = 48 + 20.
        _ => 68,
    }
}

/// `setsockopt(SOL_PACKET)` on AF_PACKET socket `slot`, validating options in
/// Linux's order and errno (the packet-ring CVE regression tests). No ring is
/// mapped: the geometry is validated and remembered, not allocated.
fn linux_packet_setsockopt(slot: u16, option: u64, value: u64, length: u64) -> u64 {
    const PACKET_RX_RING: u64 = 5;
    const PACKET_VERSION: u64 = 10;
    const PACKET_RESERVE: u64 = 12;
    const PACKET_TX_RING: u64 = 13;
    const PACKET_VNET_HDR: u64 = 15;
    const TPACKET_ALIGNMENT: u64 = 16;
    let Some(info) = crate::linux_socket::packet_info(slot) else {
        return LINUX_ENOTSOCK;
    };
    let read_int = || -> Result<u32, u64> {
        if length < 4 {
            return Err(LINUX_EINVAL);
        }
        let mut supplied = [0_u8; 4];
        if copy_from_linux_user(value, &mut supplied) {
            Ok(u32::from_ne_bytes(supplied))
        } else {
            Err(LINUX_EFAULT)
        }
    };
    match option {
        PACKET_VERSION => {
            // optlen must be exactly an int; the value is V1, V2 or V3.
            if length != 4 {
                return LINUX_EINVAL;
            }
            let version = match read_int() {
                Ok(version) => version,
                Err(error) => return error,
            };
            let version = match version {
                0..=2 => version as u8,
                _ => return LINUX_EINVAL,
            };
            if info.has_ring {
                return LINUX_EBUSY;
            }
            crate::linux_socket::set_packet_version(slot, version);
            0
        }
        PACKET_RESERVE => {
            if length != 4 {
                return LINUX_EINVAL;
            }
            let reserve = match read_int() {
                Ok(reserve) => reserve,
                Err(error) => return error,
            };
            // Capped at INT_MAX (CVE-2017-1000111 / bcc5364bdcfe).
            if reserve > i32::MAX as u32 {
                return LINUX_EINVAL;
            }
            if info.has_ring {
                return LINUX_EBUSY;
            }
            crate::linux_socket::set_packet_reserve(slot, reserve);
            0
        }
        PACKET_VNET_HDR => {
            // A virtio-net header is a SOCK_RAW option; it may not change
            // while a ring is set.
            if info.socket_type != 3 {
                return LINUX_EINVAL;
            }
            if length < 4 {
                return LINUX_EINVAL;
            }
            let enabled = match read_int() {
                Ok(value) => value != 0,
                Err(error) => return error,
            };
            if info.has_ring {
                return LINUX_EBUSY;
            }
            crate::linux_socket::set_packet_vnet_hdr(slot, enabled);
            0
        }
        PACKET_RX_RING | PACKET_TX_RING => {
            // struct tpacket_req is four u32s; the V3 request adds
            // tp_retire_blk_tov, tp_sizeof_priv and tp_feature_req_word.
            let minimum = if info.version == 2 { 28 } else { 16 };
            if length < minimum {
                return LINUX_EINVAL;
            }
            let mut request = [0_u8; 28];
            let wanted = minimum as usize;
            if !copy_from_linux_user(value, &mut request[..wanted]) {
                return LINUX_EFAULT;
            }
            let field = |index: usize| {
                u32::from_ne_bytes(request[index * 4..index * 4 + 4].try_into().unwrap())
            };
            let block_size = field(0);
            let block_nr = field(1);
            let frame_size = field(2);
            let frame_nr = field(3);
            // Tearing a ring down: block_nr 0 needs frame_nr 0, then frees it.
            if block_nr == 0 {
                if frame_nr != 0 {
                    return LINUX_EINVAL;
                }
                crate::linux_socket::set_packet_ring(slot, false);
                return 0;
            }
            // Creating one while another exists is EBUSY (CVE-2016-8655).
            if info.has_ring {
                return LINUX_EBUSY;
            }
            // A virtio-net header with a ring is not supported here.
            if info.vnet_hdr {
                return LINUX_EINVAL;
            }
            // tp_block_size must be a positive, page-aligned size.
            if block_size == 0
                || block_size & 0x8000_0000 != 0
                || !u64::from(block_size).is_multiple_of(PAGE_SIZE as u64)
            {
                return LINUX_EINVAL;
            }
            let min_frame_size = linux_tpacket_hdrlen(info.version) + u64::from(info.reserve);
            // V3 keeps per-block private space ahead of the frames: the block
            // must hold the aligned block descriptor, that space and a frame
            // (CVE-2017-7308, computed in u64 so a huge tp_sizeof_priv cannot
            // overflow into an acceptable value).
            if info.version == 2 {
                let sizeof_priv = u64::from(field(5));
                if u64::from(block_size) < 48 + sizeof_priv + min_frame_size {
                    return LINUX_EINVAL;
                }
            }
            if u64::from(frame_size) < min_frame_size {
                return LINUX_EINVAL;
            }
            if u64::from(frame_size) & (TPACKET_ALIGNMENT - 1) != 0 {
                return LINUX_EINVAL;
            }
            let frames_per_block = block_size / frame_size;
            if frames_per_block == 0 {
                return LINUX_EINVAL;
            }
            if frames_per_block > u32::MAX / block_nr {
                return LINUX_EINVAL;
            }
            if frames_per_block * block_nr != frame_nr {
                return LINUX_EINVAL;
            }
            crate::linux_socket::set_packet_ring(slot, true);
            0
        }
        _ => LINUX_ENOPROTOOPT,
    }
}

/// `getsockopt(SOL_PACKET)` on AF_PACKET socket `slot`: PACKET_VERSION and
/// PACKET_RESERVE return their stored int; other options are unsupported.
fn linux_packet_getsockopt(slot: u16, option: u64, value: u64, length: u64) -> u64 {
    const PACKET_VERSION: u64 = 10;
    const PACKET_RESERVE: u64 = 12;
    let Some(info) = crate::linux_socket::packet_info(slot) else {
        return LINUX_ENOTSOCK;
    };
    let result = match option {
        PACKET_VERSION => u32::from(info.version),
        PACKET_RESERVE => info.reserve,
        _ => return LINUX_ENOPROTOOPT,
    };
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    let Ok(wanted) = usize::try_from(i32::from_ne_bytes(supplied)) else {
        return LINUX_EINVAL;
    };
    let copied = wanted.min(4);
    if copied != 0 && !copy_to_linux_user(value, &result.to_ne_bytes()[..copied])
        || !copy_to_linux_user(length, &(copied as u32).to_ne_bytes())
    {
        return LINUX_EFAULT;
    }
    0
}

pub(super) fn linux_socket_setsockopt(
    descriptor: u64,
    level: u64,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    let level = u64::from(level as u32);
    let option = u64::from(option as u32);
    let length = u64::from(length as u32);
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // SOL_PACKET options on an AF_PACKET socket.
    if level == 263 {
        return linux_packet_setsockopt(slot, option, value, length);
    }
    if level == 41 {
        return linux_ipv6_setsockopt(slot, option, value, length);
    }
    if level == LINUX_SOL_ICMPV6 && crate::linux_socket::is_ipv6(slot) {
        return linux_icmpv6_setsockopt(slot, option, value, length);
    }
    if level == linox_ktls::SOL_TLS {
        return linux_tls_setsockopt(slot, option, value, length);
    }
    if let Some(coverage) = linux_udplite_coverage_option(level, option) {
        if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::UdpLite) {
            return LINUX_ENOPROTOOPT;
        }
        if length < 4 {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(value, &mut supplied) {
            return LINUX_EFAULT;
        }
        return crate::linux_socket::set_udplite_coverage(
            slot,
            coverage,
            i32::from_ne_bytes(supplied),
        )
        .map_or_else(linux_socket_error, |()| 0);
    }
    // SO_OOBINLINE: an int, read and checked as Linux does (a short length
    // EINVAL, an unreadable value EFAULT); urgent data is not kept apart.
    if level == 1 && option == 10 {
        if length < 4 {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 4];
        return if copy_from_linux_user(value, &mut supplied) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if level == 1 && matches!(option, 20 | 21) {
        if length < 16 {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 16];
        if !copy_from_linux_user(value, &mut supplied) {
            return LINUX_EFAULT;
        }
        let seconds = i64::from_ne_bytes(supplied[..8].try_into().unwrap());
        let microseconds = i64::from_ne_bytes(supplied[8..].try_into().unwrap());
        if seconds < 0 || !(0..1_000_000).contains(&microseconds) {
            return LINUX_EDOM;
        }
        let Some(timeout) = (seconds as u64)
            .checked_mul(1_000_000)
            .and_then(|seconds| seconds.checked_add(microseconds as u64))
        else {
            return LINUX_EDOM;
        };
        let timeout_option = if option == 20 {
            crate::linux_socket::TimeoutOption::Receive
        } else {
            crate::linux_socket::TimeoutOption::Send
        };
        return crate::linux_socket::set_timeout_option(slot, timeout_option, timeout)
            .map_or_else(linux_socket_error, |()| 0);
    }
    // Multicast membership: MCAST_JOIN_GROUP and MCAST_LEAVE_GROUP take a
    // group_req (interface, then a sockaddr_in at offset 8),
    // IP_ADD_MEMBERSHIP and IP_DROP_MEMBERSHIP an ip_mreq (group first).
    // Each socket keeps its own groups; an accepted one has none (accept02).
    if level == 0 && matches!(option, 35 | 36 | 42 | 45) {
        let group_request = matches!(option, 42 | 45);
        let minimum = if group_request { 136 } else { 8 };
        if length < minimum {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 136];
        if !copy_from_linux_user(value, &mut supplied[..minimum as usize]) {
            return LINUX_EFAULT;
        }
        let group = if group_request {
            if u16::from_ne_bytes([supplied[8], supplied[9]]) != 2 {
                return LINUX_EINVAL;
            }
            u32::from_be_bytes(supplied[12..16].try_into().unwrap())
        } else {
            u32::from_be_bytes(supplied[..4].try_into().unwrap())
        };
        if group >> 28 != 0xe {
            return LINUX_EINVAL;
        }
        return crate::linux_socket::change_group(slot, group, matches!(option, 35 | 42))
            .map_or_else(linux_socket_error, |()| 0);
    }
    // SOL_RAW IPV6_CHECKSUM of a raw ICMPv6 socket: an int offset.
    if (level, option) == (255, 7) && crate::linux_socket::is_ipv6(slot) {
        if !crate::linux_socket::is_raw(slot) {
            return LINUX_ENOPROTOOPT;
        }
        if length < 4 {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(value, &mut supplied) {
            return LINUX_EFAULT;
        }
        return crate::linux_socket::set_icmpv6_checksum(slot, i32::from_ne_bytes(supplied))
            .map_or_else(linux_socket_error, |()| 0);
    }
    if matches!((level, option), (0, 2) | (255, 1)) {
        if length < 4 {
            return LINUX_EINVAL;
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(value, &mut supplied) {
            return LINUX_EFAULT;
        }
        let value = i32::from_ne_bytes(supplied);
        if level == 255 {
            return crate::linux_socket::set_icmp_filter(slot, value as u32)
                .map_or(LINUX_EOPNOTSUPP, |()| 0);
        }
        // IP_TTL: 1 to 255, or -1 for the default.
        let ttl = match value {
            -1 => 0,
            1..=255 => value as u8,
            _ => return LINUX_EINVAL,
        };
        return crate::linux_socket::set_ttl(slot, ttl).map_or(LINUX_ENOPROTOOPT, |()| 0);
    }
    let boolean_option = match (level, option) {
        // IP_RETOPTS: received IP options; smoltcp keeps none to return.
        (0, 7) => None,
        (0, 11) => Some(crate::linux_socket::BooleanOption::ReceiveErrors),
        (0, 12) => Some(crate::linux_socket::BooleanOption::ReceiveTtl),
        // IP_HDRINCL: raw sockets only.
        (0, 3) => {
            if !crate::linux_socket::is_raw(slot) {
                return LINUX_ENOPROTOOPT;
            }
            Some(crate::linux_socket::BooleanOption::HeaderIncluded)
        }
        (1, 2) => Some(crate::linux_socket::BooleanOption::ReuseAddress),
        (1, 6) => Some(crate::linux_socket::BooleanOption::Broadcast),
        (1, 9) => Some(crate::linux_socket::BooleanOption::KeepAlive),
        (1, 11) => Some(crate::linux_socket::BooleanOption::NoCheck),
        (1, 16) => Some(crate::linux_socket::BooleanOption::PassCredentials),
        (1, 29) => Some(crate::linux_socket::BooleanOption::Timestamp),
        // These options are advisory for the current in-kernel socket
        // transport. Accept them so service managers can configure standard
        // Linux logging sockets without a compatibility warning.
        (1, 32..=34) => None,
        (6, 1) => {
            if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Tcp) {
                return LINUX_EOPNOTSUPP;
            }
            Some(crate::linux_socket::BooleanOption::NoDelay)
        }
        (1, 7 | 8) => None,
        // TCP_ULP: "tls" is the upper layer there is (kernel TLS).
        (6, LINUX_TCP_ULP) => return linux_set_ulp(slot, value, length),
        _ => return LINUX_ENOPROTOOPT,
    };
    if length < 4 {
        return LINUX_EINVAL;
    }
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(value, &mut supplied) {
        return LINUX_EFAULT;
    }
    let enabled = i32::from_ne_bytes(supplied) != 0;
    boolean_option.map_or(0, |option| {
        crate::linux_socket::set_boolean_option(slot, option, enabled)
            .map_or_else(linux_socket_error, |()| 0)
    })
}

/// UDPLITE_SEND_CSCOV (10) or UDPLITE_RECV_CSCOV (11), at SOL_UDP or
/// SOL_UDPLITE, as Linux takes either level for them.
fn linux_udplite_coverage_option(level: u64, option: u64) -> Option<crate::linux_socket::Coverage> {
    match (level, option) {
        (17 | 136, 10) => Some(crate::linux_socket::Coverage::Send),
        (17 | 136, 11) => Some(crate::linux_socket::Coverage::Receive),
        _ => None,
    }
}

/// SOL_ICMPV6 (IPPROTO_ICMPV6), the level of ICMPV6_FILTER.
const LINUX_SOL_ICMPV6: u64 = 58;
/// ICMPV6_FILTER: a raw ICMPv6 socket's struct icmp6_filter.
const LINUX_ICMPV6_FILTER: u64 = 1;

/// setsockopt(SOL_ICMPV6, ...) on AF_INET6 socket `slot`: ICMPV6_FILTER
/// on a raw ICMPv6 socket, as many bytes of the filter as are given (up to
/// its 32). Other sockets lack the level (ENOPROTOOPT, as ipv6_setsockopt
/// answers a ping, TCP or UDP socket).
fn linux_icmpv6_setsockopt(
    slot: crate::linux_socket::SlotId,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    if !crate::linux_socket::is_raw(slot) {
        return LINUX_ENOPROTOOPT;
    }
    if option != LINUX_ICMPV6_FILTER {
        return LINUX_ENOPROTOOPT;
    }
    let mut filter = [0_u8; 32];
    let length = usize::try_from(length)
        .unwrap_or(usize::MAX)
        .min(filter.len());
    if !copy_from_linux_user(value, &mut filter[..length]) {
        return LINUX_EFAULT;
    }
    crate::linux_socket::set_icmpv6_filter(slot, &filter[..length])
        .map_or_else(linux_socket_error, |()| 0)
}

/// getsockopt(SOL_ICMPV6, ICMPV6_FILTER) on a raw ICMPv6 socket: as much
/// of the filter as the length has room for (a negative one EINVAL).
fn linux_icmpv6_getsockopt(
    slot: crate::linux_socket::SlotId,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    if !crate::linux_socket::is_raw(slot) || option != LINUX_ICMPV6_FILTER {
        return LINUX_ENOPROTOOPT;
    }
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    let Ok(supplied) = usize::try_from(i32::from_ne_bytes(supplied)) else {
        return LINUX_EINVAL;
    };
    let filter = match crate::linux_socket::icmpv6_filter(slot) {
        Ok(filter) => filter,
        Err(error) => return linux_socket_error(error),
    };
    let copied = supplied.min(filter.len());
    if !copy_to_linux_user(length, &(copied as u32).to_ne_bytes())
        || copied != 0 && !copy_to_linux_user(value, &filter[..copied])
    {
        return LINUX_EFAULT;
    }
    0
}

/// IPV6_V6ONLY (an int).
const LINUX_IPV6_V6ONLY: u64 = 26;
/// IPV6_ADDRFORM: an int, the family to turn an AF_INET6 socket into.
const LINUX_IPV6_ADDRFORM: u64 = 1;
/// IPV6_MTU: the path MTU a socket sends with (an int, 0 for the route's).
const LINUX_IPV6_MTU: u64 = 24;

/// setsockopt(IPPROTO_IPV6, ...) on socket `slot`, which must be an AF_INET6
/// one (ENOPROTOOPT otherwise, as IPv4 sockets lack the level).
fn linux_ipv6_setsockopt(
    slot: crate::linux_socket::SlotId,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    if !crate::linux_socket::is_ipv6(slot) {
        return LINUX_ENOPROTOOPT;
    }
    // Every option here is an int; Linux reads it before acting.
    let read_int = || -> Result<i32, u64> {
        if length < 4 {
            return Err(LINUX_EINVAL);
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(value, &mut supplied) {
            return Err(LINUX_EFAULT);
        }
        Ok(i32::from_ne_bytes(supplied))
    };
    match option {
        LINUX_IPV6_V6ONLY => match read_int() {
            Ok(enabled) => crate::linux_socket::set_v6only(slot, enabled != 0)
                .map_or_else(linux_socket_error, |()| 0),
            Err(error) => error,
        },
        // Only AF_INET is a family to turn into.
        LINUX_IPV6_ADDRFORM => match read_int() {
            Ok(2) => {
                crate::linux_socket::address_form_ipv4(slot).map_or_else(linux_socket_error, |()| 0)
            }
            Ok(_) => LINUX_EINVAL,
            Err(error) => error,
        },
        // The largest fragment to send: 0 (the route's) or at least IPv6's
        // minimum link MTU, 1280. Datagrams here are not fragmented, so the
        // size is only checked.
        LINUX_IPV6_MTU => match read_int() {
            Ok(mtu) if mtu == 0 || mtu >= 1280 => 0,
            Ok(_) => LINUX_EINVAL,
            Err(error) => error,
        },
        // IPV6_RECVHOPLIMIT and IPV6_2292HOPLIMIT: an int, nonzero to
        // receive each datagram's hop limit.
        51 | 8 => match read_int() {
            Ok(enabled) => crate::linux_socket::set_boolean_option(
                slot,
                if option == 51 {
                    crate::linux_socket::BooleanOption::ReceiveHopLimit
                } else {
                    crate::linux_socket::BooleanOption::ReceiveHopLimit2292
                },
                enabled != 0,
            )
            .map_or_else(linux_socket_error, |()| 0),
            Err(error) => error,
        },
        // IPV6_RTHDR: routing headers are not sent here, so none is taken
        // (EINVAL, as Linux answers a type it does not build).
        57 => {
            if length == 0 {
                0
            } else {
                LINUX_EINVAL
            }
        }
        _ => LINUX_ENOPROTOOPT,
    }
}

/// getsockopt(IPPROTO_IPV6, ...) on AF_INET6 socket `slot`.
fn linux_ipv6_getsockopt(
    slot: crate::linux_socket::SlotId,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    if !crate::linux_socket::is_ipv6(slot) {
        return LINUX_EOPNOTSUPP;
    }
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    let Ok(supplied) = usize::try_from(i32::from_ne_bytes(supplied)) else {
        return LINUX_EINVAL;
    };
    let result = match option {
        LINUX_IPV6_V6ONLY => i32::from(crate::linux_socket::v6only(slot).unwrap_or(false)),
        51 | 8 => i32::from(
            crate::linux_socket::boolean_option(
                slot,
                if option == 51 {
                    crate::linux_socket::BooleanOption::ReceiveHopLimit
                } else {
                    crate::linux_socket::BooleanOption::ReceiveHopLimit2292
                },
            )
            .unwrap_or(false),
        ),
        // A connected socket's route MTU: loopback's 65536, eth0's 1500;
        // ENOTCONN with no route yet, as in Linux.
        LINUX_IPV6_MTU => match crate::linux_socket::names(slot).and_then(|(_, remote)| remote) {
            Some(remote)
                if match remote.addr {
                    IpAddress::Ipv4(address) => address.is_loopback(),
                    IpAddress::Ipv6(address) => address.is_loopback(),
                } =>
            {
                65_536
            }
            Some(_) => 1500,
            None => return LINUX_ENOTCONN,
        },
        _ => return LINUX_ENOPROTOOPT,
    };
    let copied = supplied.min(4);
    if copied != 0 && !copy_to_linux_user(value, &result.to_ne_bytes()[..copied])
        || !copy_to_linux_user(length, &(copied as u32).to_ne_bytes())
    {
        return LINUX_EFAULT;
    }
    0
}

pub(super) fn linux_socket_getsockopt(
    descriptor: u64,
    level: u64,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    let level = u64::from(level as u32);
    let option = u64::from(option as u32);
    let Some(slot) = linux_socket_call_slot(descriptor) else {
        return linux_not_socket_error(descriptor);
    };
    // SOL_PACKET options on an AF_PACKET socket.
    if level == 263 {
        return linux_packet_getsockopt(slot, option, value, length);
    }
    if level == 41 {
        return linux_ipv6_getsockopt(slot, option, value, length);
    }
    if level == LINUX_SOL_ICMPV6 && crate::linux_socket::is_ipv6(slot) {
        return linux_icmpv6_getsockopt(slot, option, value, length);
    }
    if level == linox_ktls::SOL_TLS {
        return linux_tls_getsockopt(slot, option, value, length);
    }
    if (level, option) == (6, LINUX_TCP_ULP)
        && crate::linux_socket::kind(slot) == Some(crate::linux_socket::Kind::Tcp)
    {
        return linux_get_ulp(slot, value, length);
    }
    if level == 1 && option == 17 {
        if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Unix) {
            return LINUX_ENOPROTOOPT;
        }
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(length, &mut supplied) {
            return LINUX_EFAULT;
        }
        if u32::from_ne_bytes(supplied) < 12 {
            return LINUX_EINVAL;
        }
        let Some(credentials) = crate::linux_socket::unix_peer_credentials(slot) else {
            return LINUX_ENOTCONN;
        };
        let mut output = [0_u8; 12];
        output[..4].copy_from_slice(&(credentials.0 as i32).to_ne_bytes());
        output[4..8].copy_from_slice(&credentials.1.to_ne_bytes());
        output[8..].copy_from_slice(&credentials.2.to_ne_bytes());
        return if copy_to_linux_user(value, &output)
            && copy_to_linux_user(length, &12_u32.to_ne_bytes())
        {
            0
        } else {
            LINUX_EFAULT
        };
    }
    if level == 1 && matches!(option, 20 | 21) {
        let mut supplied = [0_u8; 4];
        if !copy_from_linux_user(length, &mut supplied) {
            return LINUX_EFAULT;
        }
        if u32::from_ne_bytes(supplied) < 16 {
            return LINUX_EINVAL;
        }
        let timeout_option = if option == 20 {
            crate::linux_socket::TimeoutOption::Receive
        } else {
            crate::linux_socket::TimeoutOption::Send
        };
        let timeout = match crate::linux_socket::timeout_option(slot, timeout_option) {
            Ok(timeout) => timeout,
            Err(error) => return linux_socket_error(error),
        };
        let mut output = [0_u8; 16];
        output[..8].copy_from_slice(&(timeout / 1_000_000).to_ne_bytes());
        output[8..].copy_from_slice(&(timeout % 1_000_000).to_ne_bytes());
        return if copy_to_linux_user(value, &output)
            && copy_to_linux_user(length, &16_u32.to_ne_bytes())
        {
            0
        } else {
            LINUX_EFAULT
        };
    }
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    let Ok(supplied) = usize::try_from(i32::from_ne_bytes(supplied)) else {
        return LINUX_EINVAL;
    };
    // A level the socket's family does not have is EOPNOTSUPP, as Linux's
    // protocol handlers answer (getsockopt01): SOL_SOCKET everywhere, IP
    // on inet sockets, TCP or UDP on their own, ICMP's on a raw ICMP one.
    let kind = crate::linux_socket::kind(slot);
    let level_known = match level {
        1 => true,
        0 => matches!(
            kind,
            Some(
                crate::linux_socket::Kind::Tcp
                    | crate::linux_socket::Kind::Udp
                    | crate::linux_socket::Kind::UdpLite
                    | crate::linux_socket::Kind::Icmp
            )
        ),
        6 => kind == Some(crate::linux_socket::Kind::Tcp),
        17 => matches!(
            kind,
            Some(crate::linux_socket::Kind::Udp | crate::linux_socket::Kind::UdpLite)
        ),
        136 => kind == Some(crate::linux_socket::Kind::UdpLite),
        255 => kind == Some(crate::linux_socket::Kind::Icmp),
        _ => false,
    };
    if !level_known {
        return LINUX_EOPNOTSUPP;
    }
    let read_boolean = |option| match crate::linux_socket::boolean_option(slot, option) {
        Ok(value) => Ok(i32::from(value)),
        Err(error) => Err(linux_socket_error(error)),
    };
    let result = match (level, option) {
        (0, 2) => match crate::linux_socket::ttl(slot) {
            Ok(ttl) => i32::from(ttl),
            Err(_) => return LINUX_ENOPROTOOPT,
        },
        (0, 11) => match read_boolean(crate::linux_socket::BooleanOption::ReceiveErrors) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (0, 12) => match read_boolean(crate::linux_socket::BooleanOption::ReceiveTtl) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (0, 3) if crate::linux_socket::is_raw(slot) => {
            match read_boolean(crate::linux_socket::BooleanOption::HeaderIncluded) {
                Ok(value) => value,
                Err(error) => return error,
            }
        }
        // ICMP_FILTER of a raw ICMP socket.
        (255, 1) => match crate::linux_socket::icmp_filter(slot) {
            Ok(filter) => filter as i32,
            Err(_) => return LINUX_EOPNOTSUPP,
        },
        (1, 2) => match read_boolean(crate::linux_socket::BooleanOption::ReuseAddress) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (1, 6) => match read_boolean(crate::linux_socket::BooleanOption::Broadcast) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (255, 7) if crate::linux_socket::is_ipv6(slot) => {
            match crate::linux_socket::icmpv6_checksum(slot) {
                Ok(offset) => offset,
                Err(_) => return LINUX_ENOPROTOOPT,
            }
        }
        (1, 11) => match read_boolean(crate::linux_socket::BooleanOption::NoCheck) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (1, 3) => match crate::linux_socket::socket_type(slot) {
            Some(socket_type) => i32::from(socket_type),
            None => return LINUX_EBADF,
        },
        (1, 4) => {
            crate::linux_socket::readiness(slot).is_some_and(|(_, _, error)| error) as i32 * 111
        }
        (1, 7 | 8) => 64 * 1024,
        // SO_OOBINLINE: urgent data is not kept apart here.
        (1, 10) => 0,
        (1, 9) => match read_boolean(crate::linux_socket::BooleanOption::KeepAlive) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (1, 16) => match read_boolean(crate::linux_socket::BooleanOption::PassCredentials) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (1, 29) => match read_boolean(crate::linux_socket::BooleanOption::Timestamp) {
            Ok(value) => value,
            Err(error) => return error,
        },
        (1, 30) => i32::from(crate::linux_socket::is_listening(slot)),
        (1, 32 | 33) => 64 * 1024,
        (1, 34) => 0,
        (1, 38) => match crate::linux_socket::kind(slot) {
            Some(crate::linux_socket::Kind::Tcp) => 6,
            Some(crate::linux_socket::Kind::Udp) => 17,
            Some(crate::linux_socket::Kind::UdpLite) => 136,
            Some(crate::linux_socket::Kind::Icmp) if crate::linux_socket::is_ipv6(slot) => 58,
            Some(crate::linux_socket::Kind::Icmp) => 1,
            Some(crate::linux_socket::Kind::Unix) => 0,
            Some(crate::linux_socket::Kind::Netlink) => crate::linux_socket::netlink_address(slot)
                .map_or(0, |(protocol, _)| i32::from(protocol)),
            // SO_PROTOCOL on an AF_PACKET socket: no single IP protocol.
            Some(crate::linux_socket::Kind::Packet) => 0,
            Some(crate::linux_socket::Kind::Object) => return LINUX_ENOTSOCK,
            None => return LINUX_EBADF,
        },
        (1, 39) => match crate::linux_socket::kind(slot) {
            Some(
                crate::linux_socket::Kind::Tcp
                | crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
                | crate::linux_socket::Kind::Icmp,
            ) if crate::linux_socket::is_ipv6(slot) => 10,
            Some(
                crate::linux_socket::Kind::Tcp
                | crate::linux_socket::Kind::Udp
                | crate::linux_socket::Kind::UdpLite
                | crate::linux_socket::Kind::Icmp,
            ) => 2,
            Some(crate::linux_socket::Kind::Unix) => 1,
            Some(crate::linux_socket::Kind::Netlink) => 16,
            Some(crate::linux_socket::Kind::Packet) => 17,
            Some(crate::linux_socket::Kind::Object) => return LINUX_ENOTSOCK,
            None => return LINUX_EBADF,
        },
        (17 | 136, 10 | 11) => match crate::linux_socket::udplite_coverage(
            slot,
            if option == 10 {
                crate::linux_socket::Coverage::Send
            } else {
                crate::linux_socket::Coverage::Receive
            },
        ) {
            Ok(coverage) => i32::from(coverage),
            Err(_) => return LINUX_ENOPROTOOPT,
        },
        (6, 1) => {
            if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Tcp) {
                return LINUX_EOPNOTSUPP;
            }
            match read_boolean(crate::linux_socket::BooleanOption::NoDelay) {
                Ok(value) => value,
                Err(error) => return error,
            }
        }
        _ => return LINUX_ENOPROTOOPT,
    };
    // A shorter buffer gets the first bytes of the int, as in Linux.
    let copied = supplied.min(4);
    if copied != 0 && !copy_to_linux_user(value, &result.to_ne_bytes()[..copied])
        || !copy_to_linux_user(length, &(copied as u32).to_ne_bytes())
    {
        return LINUX_EFAULT;
    }
    0
}

pub(super) fn linux_socket_iov_ranges(
    vectors: u64,
    count: u64,
    writable: bool,
) -> Result<([(u64, usize); LINUX_IOV_LIMIT], usize), u64> {
    let Ok(vector_count) = usize::try_from(count) else {
        return Err(LINUX_EINVAL);
    };
    if vector_count > LINUX_IOV_LIMIT {
        return Err(LINUX_EINVAL);
    }
    let mut table = [0_u8; LINUX_IOV_LIMIT * 16];
    if vector_count != 0 && !copy_from_linux_user(vectors, &mut table[..vector_count * 16]) {
        return Err(LINUX_EFAULT);
    }
    let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
    for (range, vector) in ranges
        .iter_mut()
        .zip(table[..vector_count * 16].as_chunks::<16>().0)
    {
        *range = (
            u64::from_ne_bytes(vector[..8].try_into().unwrap()),
            usize::from_ne_bytes(vector[8..].try_into().unwrap()),
        );
    }
    // As Linux, every length is checked (each and their sum must fit an
    // ssize_t) before any buffer is.
    let total = ranges[..vector_count]
        .iter()
        .try_fold(0_usize, |total, (_, length)| total.checked_add(*length))
        .filter(|total| *total <= isize::MAX as usize);
    if total.is_none() {
        return Err(LINUX_EINVAL);
    }
    let accessible = |(address, length): &(u64, usize)| {
        *length == 0
            || if writable {
                linux_writable_user_range_contains(*address, *length)
            } else {
                linux_readable_user_range_contains(*address, *length)
            }
    };
    if !ranges[..vector_count].iter().all(accessible) {
        return Err(LINUX_EFAULT);
    }
    Ok((ranges, vector_count))
}

pub(super) fn linux_socket_writev(descriptor: u64, vectors: u64, count: u64) -> Option<u64> {
    let slot = linux_socket_slot(descriptor)?;
    let device = linux_device_descriptor(descriptor);
    if device & LINUX_DEVICE_PIPE != 0 && device & 3 & LINUX_DESCRIPTOR_OUTPUT == 0 {
        return Some(LINUX_EBADF);
    }
    let (ranges, vector_count) = match linux_socket_iov_ranges(vectors, count, false) {
        Ok(ranges) => ranges,
        Err(error) => return Some(error),
    };
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut written = 0_usize;
    for (address, length) in ranges[..vector_count].iter().copied() {
        let mut offset = 0_usize;
        while offset < length {
            let chunk = (length - offset).min(bytes.len());
            if !copy_from_linux_user(address + offset as u64, &mut bytes[..chunk]) {
                return Some(if written == 0 {
                    LINUX_EFAULT
                } else {
                    written as u64
                });
            }
            let result = if linux_socket_nonblocking(descriptor) {
                crate::linux_socket::send(slot, &bytes[..chunk], None)
            } else {
                crate::linux_socket::send_blocking(slot, &bytes[..chunk], None)
            };
            let sent = match result {
                Ok(sent) => sent,
                Err(error) => {
                    return Some(if written == 0 {
                        linux_socket_error(error)
                    } else {
                        written as u64
                    });
                }
            };
            written += sent;
            offset += sent;
            if sent < chunk {
                return Some(written as u64);
            }
        }
    }
    Some(written as u64)
}

pub(super) fn linux_socket_readv(descriptor: u64, vectors: u64, count: u64) -> Option<u64> {
    let slot = linux_socket_slot(descriptor)?;
    let device = linux_device_descriptor(descriptor);
    if device & LINUX_DEVICE_PIPE != 0 && device & 3 & LINUX_DESCRIPTOR_INPUT == 0 {
        return Some(LINUX_EBADF);
    }
    let (ranges, vector_count) = match linux_socket_iov_ranges(vectors, count, true) {
        Ok(ranges) => ranges,
        Err(error) => return Some(error),
    };
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut received_total = 0_usize;
    for (address, length) in ranges[..vector_count].iter().copied() {
        let mut offset = 0_usize;
        while offset < length {
            let chunk = (length - offset).min(bytes.len());
            let result = if linux_socket_nonblocking(descriptor) {
                crate::linux_socket::recv(slot, &mut bytes[..chunk])
            } else {
                crate::linux_socket::recv_blocking(slot, &mut bytes[..chunk])
            };
            let received = match result {
                Ok((received, _)) => received,
                Err(error) => {
                    return Some(if received_total == 0 {
                        linux_socket_error(error)
                    } else {
                        received_total as u64
                    });
                }
            };
            if received != 0 && !copy_to_linux_user(address + offset as u64, &bytes[..received]) {
                return Some(if received_total == 0 {
                    LINUX_EFAULT
                } else {
                    received_total as u64
                });
            }
            received_total += received;
            offset += received;
            if received < chunk {
                return Some(received_total as u64);
            }
        }
    }
    Some(received_total as u64)
}
