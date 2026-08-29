//! Network interface operations — mirrors libdnet's `intf.h` / `intf.c`.
//!
//! libdnet enumerates network interfaces and exposes each one as a
//! `struct intf_entry`. We provide a safe Rust equivalent carrying the
//! interface name, type, flags, MTU, address, link-layer address, and
//! aliases. Enumeration is backed by `GetAdaptersAddresses` on Windows and
//! `getifaddrs()` on Unix.

use crate::addr::Addr;

/// Maximum length of an interface name string, mirroring `INTF_NAME_LEN`.
pub const INTF_NAME_LEN: usize = 16;

/// MIB-II interface types (IANA ifType), mirroring libdnet's constants.
pub const INTF_TYPE_OTHER: u16 = 1;
pub const INTF_TYPE_ETH: u16 = 6;
pub const INTF_TYPE_TOKENRING: u16 = 9;
pub const INTF_TYPE_FDDI: u16 = 15;
pub const INTF_TYPE_PPP: u16 = 23;
pub const INTF_TYPE_LOOPBACK: u16 = 24;
pub const INTF_TYPE_SLIP: u16 = 28;
pub const INTF_TYPE_TUN: u16 = 53;

/// Interface flags, mirroring libdnet's flag constants.
pub const INTF_FLAG_UP: u16 = 0x01;
pub const INTF_FLAG_LOOPBACK: u16 = 0x02;
pub const INTF_FLAG_POINTOPOINT: u16 = 0x04;
pub const INTF_FLAG_NOARP: u16 = 0x08;
pub const INTF_FLAG_BROADCAST: u16 = 0x10;
pub const INTF_FLAG_MULTICAST: u16 = 0x20;

/// A single interface entry — mirrors `struct intf_entry`.
#[derive(Clone, Debug, Default)]
pub struct IntfEntry {
    /// Interface name.
    pub name: String,
    /// Interface type (MIB-II).
    pub intf_type: u16,
    /// Interface flags.
    pub flags: u16,
    /// Interface MTU.
    pub mtu: u32,
    /// Primary interface address.
    pub addr: Addr,
    /// Point-to-point destination address (if point-to-point).
    pub dst_addr: Addr,
    /// Link-layer (hardware) address.
    pub link_addr: Addr,
    /// Additional / alias addresses.
    pub alias_addrs: Vec<Addr>,
}

impl IntfEntry {
    /// True if the interface is administratively up.
    pub fn is_up(&self) -> bool {
        self.flags & INTF_FLAG_UP != 0
    }
    pub fn is_loopback(&self) -> bool {
        self.flags & INTF_FLAG_LOOPBACK != 0
    }
    pub fn is_point_to_point(&self) -> bool {
        self.flags & INTF_FLAG_POINTOPOINT != 0
    }
    pub fn link_addr_slice(&self) -> Option<[u8; 6]> {
        self.link_addr.to_hw()
    }
}

/// Enumerate all network interfaces on the host.
///
/// Mirrors `intf_loop()` (calling your handler once per entry); we instead
/// gather them into a `Vec`. In case enumeration is unavailable, an empty
/// vector is returned.
pub fn interface_list() -> Vec<IntfEntry> {
    #[cfg(windows)]
    {
        windows_interfaces()
    }
    #[cfg(not(windows))]
    {
        unix_interfaces()
    }
}

#[cfg(windows)]
fn windows_interfaces() -> Vec<IntfEntry> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN};

    let mut out = Vec::<IntfEntry>::new();
    let mut size: u32 = 15 * 1024;

    loop {
        let mut buf = vec![0u8; size as usize];
        let p = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                0,
                std::ptr::null_mut(),
                p,
                &mut size,
            )
        };
        if rc == NO_ERROR {
            let mut ptr = p;
            unsafe {
                while !ptr.is_null() {
                    let e = &*ptr;
                    let mut ent = IntfEntry::default();

                    let name = wide_to_string(e.FriendlyName);
                    ent.name = if !name.is_empty() {
                        name
                    } else {
                        ansi_to_string(e.AdapterName)
                    };
                    if ent.name.is_empty() {
                        ent.name = "iface".to_string();
                    }

                    ent.mtu = e.Mtu;
                    if e.IfType == 24 {
                        ent.intf_type = INTF_TYPE_LOOPBACK;
                        ent.flags |= INTF_FLAG_LOOPBACK;
                    } else {
                        ent.intf_type = INTF_TYPE_ETH;
                    }
                    if e.OperStatus == 1 {
                        ent.flags |= INTF_FLAG_UP;
                    }

                    let maclen = e.PhysicalAddressLength as usize;
                    if maclen >= 6 {
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&e.PhysicalAddress[..6]);
                        ent.link_addr = Addr::hw(mac);
                    }

                    let mut ua = e.FirstUnicastAddress;
                    while !ua.is_null() {
                        let uni = &*ua;
                        let sa = uni.Address.lpSockaddr;
                        if !sa.is_null() {
                            let sock = &*sa;
                            match sock.sa_family as u16 {
                                AF_INET => {
                                    let sin: &SOCKADDR_IN = &*(sa as *const SOCKADDR_IN);
                                    let ip = sin.sin_addr.S_un.S_addr.to_le_bytes();
                                    let addr = Addr::ipv4(std::net::Ipv4Addr::new(
                                        ip[0], ip[1], ip[2], ip[3],
                                    ));
                                    if ent.addr.addr_type == crate::addr::ADDR_TYPE_NONE {
                                        ent.addr = addr;
                                    } else {
                                        ent.alias_addrs.push(addr);
                                    }
                                }
                                AF_INET6 => {
                                    let base = sa as *const u8;
                                    let mut bytes = [0u8; 16];
                                    // sockaddr_in6: family(2) port(2) flowinfo(4) addr(16)
                                    std::ptr::copy_nonoverlapping(
                                        base.add(8),
                                        bytes.as_mut_ptr(),
                                        16,
                                    );
                                    let addr =
                                        Addr::ipv6(std::net::Ipv6Addr::from(bytes));
                                    if ent.addr.addr_type == crate::addr::ADDR_TYPE_NONE {
                                        ent.addr = addr;
                                    } else {
                                        ent.alias_addrs.push(addr);
                                    }
                                }
                                _ => {}
                            }
                        }
                        ua = uni.Next;
                    }

                    out.push(ent);
                    ptr = e.Next;
                }
            }
            return out;
        } else if rc == ERROR_BUFFER_OVERFLOW {
            size += 8 * 1024;
            continue;
        } else {
            return out;
        }
    }
}

#[cfg(windows)]
fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut v = Vec::new();
    unsafe {
        let mut i = 0;
        while *p.add(i) != 0 {
            v.push(*p.add(i));
            i += 1;
        }
    }
    String::from_utf16_lossy(&v)
}

#[cfg(windows)]
fn ansi_to_string(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut v = Vec::new();
    unsafe {
        let mut i = 0;
        while *p.add(i) != 0 {
            v.push(*p.add(i));
            i += 1;
        }
    }
    String::from_utf8_lossy(&v).into_owned()
}

#[cfg(not(windows))]
fn unix_interfaces() -> Vec<IntfEntry> {
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        use std::ffi::CStr;
        use std::net::{Ipv4Addr, Ipv6Addr};

        let mut out = Vec::new();
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
            return out;
        }
        let mut cur = ifap;
        unsafe {
            while !cur.is_null() {
                let ifa = &*cur;
                let name = if !ifa.ifa_name.is_null() {
                    CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned()
                } else {
                    String::new()
                };
                let family = if !ifa.ifa_addr.is_null() {
                    (*ifa.ifa_addr).sa_family as libc::c_int
                } else {
                    libc::AF_UNSPEC
                };

                let mut entry = IntfEntry::default();
                entry.name = name.clone();
                entry.flags = ifa.ifa_flags as u16;

                if !ifa.ifa_addr.is_null() {
                    let addr = match family {
                        libc::AF_INET => {
                            let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                            let ip = u32::from_ne_bytes(sa.sin_addr.s_addr.to_ne_bytes());
                            Addr::ipv4(Ipv4Addr::from(ip))
                        }
                        libc::AF_INET6 => {
                            let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                            Addr::ipv6(Ipv6Addr::from(sa.sin6_addr.s6_addr))
                        }
                        _ => Addr::default(),
                    };
                    if addr.addr_type != crate::addr::ADDR_TYPE_NONE {
                        entry.addr = addr;
                    }
                }

                if family == libc::AF_PACKET || family == libc::AF_LINK {
                    #[cfg(target_os = "linux")]
                    {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_ll);
                        if sa.sll_halen == 6 {
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&sa.sll_addr[..6]);
                            entry.link_addr = Addr::hw(mac);
                        }
                    }
                    #[cfg(target_os = "macos")]
                    {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_dl);
                        if sa.sdl_alen == 6 {
                            let base = ifa.ifa_addr as *const u8;
                            let off = sa.sdl_nlen;
                            let mut mac = [0u8; 6];
                            std::ptr::copy_nonoverlapping(base.add(off), mac.as_mut_ptr(), 6);
                            entry.link_addr = Addr::hw(mac);
                        }
                    }
                }

                out.push(entry);
                cur = ifa.ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
        out
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_helpers() {
        let mut e = IntfEntry::default();
        e.flags = INTF_FLAG_UP | INTF_FLAG_LOOPBACK;
        assert!(e.is_up());
        assert!(e.is_loopback());
        assert!(!e.is_point_to_point());
    }

    #[test]
    fn constants_match_mib() {
        assert_eq!(INTF_TYPE_ETH, 6);
        assert_eq!(INTF_TYPE_LOOPBACK, 24);
        assert_eq!(INTF_FLAG_UP, 0x01);
    }
}
