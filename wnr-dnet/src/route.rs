//! Routing table operations — mirrors libdnet's `route.h` / `route.c`.
//!
//! libdnet exposes the kernel routing table through a `route_t` handle. The
//! live kernel table is owned by the operating system; as with the ARP table
//! in [`crate::arp`], we expose a portable, userspace data model for the same
//! operations, plus a safe, unprivileged live lookup for the route a packet
//! to a given destination would actually take.

use crate::addr::Addr;

/// A single routing-table entry — mirrors `struct route_entry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// Destination address (with prefix length in `addr_bits`).
    pub dst: Addr,
    /// Gateway (next-hop) address.
    pub gw: Addr,
}

/// An in-memory routing table, mirroring the libdnet `route_*` API surface.
///
/// The real routing table is maintained by the operating system kernel. This
/// structure models the same operations (`add`, `add_dev`, `delete`, `get`,
/// `loop`) for user-space coordination, in the same way [`crate::arp::ArpCache`]
/// models the ARP table.
#[derive(Default, Debug)]
pub struct RouteTable {
    entries: Vec<RouteEntry>,
}

impl RouteTable {
    pub fn new() -> Self {
        RouteTable::default()
    }

    /// Add or replace a route (mirrors `route_add`).
    pub fn add(&mut self, entry: RouteEntry) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.dst == entry.dst) {
            existing.gw = entry.gw;
            return;
        }
        self.entries.push(entry);
    }

    /// Add a route bound to a specific device (mirrors `route_add_dev`).
    /// A device-scoped route is stored with its destination network.
    pub fn add_dev(&mut self, entry: RouteEntry) {
        let mut net = entry;
        net.dst = entry.dst.network();
        self.add(net);
    }

    /// Delete a route by destination (mirrors `route_delete`).
    pub fn delete(&mut self, dst: &Addr) {
        self.entries.retain(|e| e.dst != *dst);
    }

    /// Look up the route for a destination, returning the most specific
    /// (longest-prefix) matching entry (mirrors `route_get`).
    pub fn get(&self, dst: &Addr) -> Option<&RouteEntry> {
        self.entries
            .iter()
            .filter(|e| dst.addr_type == e.dst.addr_type)
            .filter(|e| net_contains(&e.dst, dst))
            .max_by_key(|e| e.dst.addr_bits)
    }

    /// Iterate over all entries (mirrors `route_loop`).
    pub fn entries(&self) -> &[RouteEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// True if `addr` lies within the network described by `net`
/// (same family, matching prefix bits).
fn net_contains(net: &Addr, addr: &Addr) -> bool {
    if net.addr_type != addr.addr_type || net.addr_type == crate::addr::ADDR_TYPE_NONE {
        return false;
    }
    let net_net = net.network();
    let mut addr_net = *addr;
    addr_net.addr_bits = net.addr_bits;
    addr_net = addr_net.network();
    net_net.data == addr_net.data
}

/// Resolve the route the kernel would actually use to reach `dst`, without
/// sending any packets — a safe, unprivileged live lookup.
///
/// Returns `(interface_name, source_address)`: the interface whose address
/// range covers the destination and the source address the kernel would
/// bind. This mirrors the information libdnet's `route_get` surfaces about
/// outbound routing, but via a `connect()` probe (no netlink / root needed).
/// Returns `None` if no interface can reach the destination.
pub fn route_to(dst: &Addr) -> Option<(String, Addr)> {
    let bind = match dst.addr_type {
        crate::addr::ADDR_TYPE_IP => "0.0.0.0:0",
        crate::addr::ADDR_TYPE_IP6 => "[::]:0",
        _ => return None,
    };
    let sa = sockaddr(dst)?;
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(sa).ok()?;
    let local = socket.local_addr().ok()?;
    let src = sockaddr_to_addr(&local);
    let ifname = crate::intf::interface_list()
        .into_iter()
        .find(|i| i.addr == src || i.alias_addrs.contains(&src))
        .map(|i| i.name)
        .unwrap_or_else(|| "?".to_string());
    Some((ifname, src))
}

/// Modify the kernel routing table — mirrors libdnet's `route_add`.
///
/// Installing a route (SIOCADDRT) requires elevated privileges (root on Unix,
/// Administrator on Windows). As with [`crate::intf::intf_set`], this validates
/// the supplied entry and reports that the mutation itself needs those
/// privileges rather than pretending to succeed.
pub fn route_add(entry: &RouteEntry) -> Result<(), String> {
    if entry.dst.addr_type == crate::addr::ADDR_TYPE_NONE {
        return Err("route_add: empty destination address".to_string());
    }
    if entry.dst.addr_bits == 0 || entry.dst.addr_bits > entry.dst.addr_len() as u16 * 8 {
        return Err(format!(
            "route_add: invalid prefix length {}",
            entry.dst.addr_bits
        ));
    }
    let gw_host = entry.gw.addr_type == crate::addr::ADDR_TYPE_IP
        || entry.gw.addr_type == crate::addr::ADDR_TYPE_IP6;
    if !gw_host {
        return Err("route_add: gateway must be an IP address".to_string());
    }
    Err(
        "route_add: modifying the kernel routing table (SIOCADDRT) requires \
         elevated privileges; install the route via the OS instead"
            .to_string(),
    )
}

/// Remove a route from the kernel routing table — mirrors libdnet's
/// `route_delete`. Like [`route_add`], this needs elevated privileges.
pub fn route_delete(entry: &RouteEntry) -> Result<(), String> {
    if entry.dst.addr_type == crate::addr::ADDR_TYPE_NONE {
        return Err("route_delete: empty destination address".to_string());
    }
    Err(
        "route_delete: modifying the kernel routing table (SIOCDELRT) requires \
         elevated privileges; remove the route via the OS instead"
            .to_string(),
    )
}

/// Convert an [`Addr`] to a `SocketAddr` with an arbitrary discard port.
fn sockaddr(a: &Addr) -> Option<std::net::SocketAddr> {
    use crate::addr::{ADDR_TYPE_IP, ADDR_TYPE_IP6};
    use std::net::{IpAddr, SocketAddr};
    match a.addr_type {
        ADDR_TYPE_IP => a.to_ipv4().map(|ip| SocketAddr::new(IpAddr::V4(ip), 9)),
        ADDR_TYPE_IP6 => a.to_ipv6().map(|ip| SocketAddr::new(IpAddr::V6(ip), 9)),
        _ => None,
    }
}

/// Convert a `SocketAddr` back to an [`Addr`], dropping the port.
fn sockaddr_to_addr(sa: &std::net::SocketAddr) -> Addr {
    match sa {
        std::net::SocketAddr::V4(v4) => Addr::ipv4(*v4.ip()),
        std::net::SocketAddr::V6(v6) => Addr::ipv6(*v6.ip()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn net(ip: Ipv4Addr, bits: u16) -> Addr {
        let mut a = Addr::ipv4(ip);
        a.addr_bits = bits;
        a
    }

    #[test]
    fn table_lives_and_loops() {
        let mut t = RouteTable::new();
        assert!(t.is_empty());
        t.add(RouteEntry {
            dst: net(Ipv4Addr::new(10, 0, 0, 0), 24),
            gw: Addr::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        });
        t.add(RouteEntry {
            dst: net(Ipv4Addr::new(0, 0, 0, 0), 0),
            gw: Addr::ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        });
        assert_eq!(t.len(), 2);
        assert_eq!(t.entries()[0].dst, net(Ipv4Addr::new(10, 0, 0, 0), 24));
    }

    #[test]
    fn get_prefers_most_specific() {
        let mut t = RouteTable::new();
        t.add(RouteEntry {
            dst: net(Ipv4Addr::new(0, 0, 0, 0), 0),
            gw: Addr::ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        });
        t.add(RouteEntry {
            dst: net(Ipv4Addr::new(10, 0, 0, 0), 8),
            gw: Addr::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        });
        t.add(RouteEntry {
            dst: net(Ipv4Addr::new(10, 1, 0, 0), 16),
            gw: Addr::ipv4(Ipv4Addr::new(10, 1, 0, 1)),
        });
        // 10.1.2.3 should match the /16, not the /8 or default.
        let dst = Addr::ipv4(Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(t.get(&dst).unwrap().dst.addr_bits, 16);
        assert_eq!(
            t.get(&dst).unwrap().gw.to_ipv4().unwrap(),
            Ipv4Addr::new(10, 1, 0, 1)
        );
        // Unrelated address falls back to the default route.
        let other = Addr::ipv4(Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(t.get(&other).unwrap().dst.addr_bits, 0);
    }

    #[test]
    fn get_respects_family() {
        let mut t = RouteTable::new();
        t.add(RouteEntry {
            dst: net(Ipv4Addr::new(0, 0, 0, 0), 0),
            gw: Addr::ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        });
        t.add(RouteEntry {
            dst: {
                let mut a = Addr::ipv6(Ipv6Addr::UNSPECIFIED);
                a.addr_bits = 0;
                a
            },
            gw: Addr::ipv6("fe80::1".parse().unwrap()),
        });
        // IPv6 query must not match the IPv4 default route.
        let v6dst = Addr::ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let expected_gw: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(t.get(&v6dst).unwrap().gw.to_ipv6().unwrap(), expected_gw);
        // And an IPv4 query must not match the IPv6 default route.
        let v4dst = Addr::ipv4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(t.get(&v4dst).unwrap().gw.to_ipv4().unwrap(), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn delete_removes() {
        let mut t = RouteTable::new();
        let d0 = net(Ipv4Addr::new(0, 0, 0, 0), 0);
        t.add(RouteEntry {
            dst: d0,
            gw: Addr::ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        });
        t.delete(&d0);
        assert!(t.is_empty());
    }

    #[test]
    fn add_dev_uses_network() {
        let mut t = RouteTable::new();
        t.add_dev(RouteEntry {
            dst: net(Ipv4Addr::new(10, 0, 0, 5), 24),
            gw: Addr::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        });
        // The destination is normalized to its network address.
        assert_eq!(
            t.entries()[0].dst.to_ipv4().unwrap(),
            Ipv4Addr::new(10, 0, 0, 0)
        );
        let query = Addr::ipv4(Ipv4Addr::new(10, 0, 0, 9));
        assert!(t.get(&query).is_some());
    }

    #[test]
    fn route_add_validates() {
        // Empty destination is rejected.
        assert!(route_add(&RouteEntry { dst: Addr::default(), gw: Addr::default() }).is_err());
        // Invalid prefix length is rejected.
        let bad = RouteEntry {
            dst: net(Ipv4Addr::new(10, 0, 0, 0), 33),
            gw: Addr::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        assert!(route_add(&bad).is_err());
        // A non-IP gateway is rejected.
        let badgw = RouteEntry {
            dst: net(Ipv4Addr::new(10, 0, 0, 0), 24),
            gw: Addr::hw([0, 0, 0, 0, 0, 0]),
        };
        assert!(route_add(&badgw).is_err());
        // A valid entry reaches the privilege-rejection path (still an Err).
        let ok = RouteEntry {
            dst: net(Ipv4Addr::new(10, 0, 0, 0), 24),
            gw: Addr::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        assert!(route_add(&ok).is_err());
    }

    #[test]
    fn route_delete_validates() {
        assert!(route_delete(&RouteEntry { dst: Addr::default(), gw: Addr::default() }).is_err());
    }
}
