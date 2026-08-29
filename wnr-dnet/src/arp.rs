//! Address Resolution Protocol — mirrors libdnet's `arp.h` / `arp.c`.
//!
//! Implements RFC 826 ARP message structures, packing/unpacking helpers, and
//! a userspace ARP cache abstraction (the OS kernel owns the real cache; this
//! is the portable data model libdnet exposes).

use crate::addr::{Addr, HW_ADDR_LEN, IP_ADDR_LEN};
use crate::eth::{EthAddr, ETH_ADDR_LEN};

/// Base ARP header length.
pub const ARP_HDR_LEN: usize = 8;
/// Base ARP message length for Ethernet/IP.
pub const ARP_ETHIP_LEN: usize = 20;

/// Hardware address format.
pub const ARP_HRD_ETH: u16 = 0x0001;
pub const ARP_HRD_IEEE802: u16 = 0x0006;
pub const ARP_HRD_IEEE80211_RADIOTAP: u16 = 0x0323;

/// Protocol address format.
pub const ARP_PRO_IP: u16 = 0x0800;

/// ARP operation.
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;
pub const ARP_OP_REVREQUEST: u16 = 3;
pub const ARP_OP_REVREPLY: u16 = 4;

/// Base ARP header — mirrors `struct arp_hdr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpHdr {
    pub hrd: u16, // hardware format
    pub pro: u16, // protocol format
    pub hln: u8,  // hardware address length
    pub pln: u8,  // protocol address length
    pub op: u16,  // operation
}

impl ArpHdr {
    /// Parse from the first `ARP_HDR_LEN` bytes (network byte order).
    pub fn parse(buf: &[u8]) -> Option<ArpHdr> {
        if buf.len() < ARP_HDR_LEN {
            return None;
        }
        Some(ArpHdr {
            hrd: u16::from_be_bytes([buf[0], buf[1]]),
            pro: u16::from_be_bytes([buf[2], buf[3]]),
            hln: buf[4],
            pln: buf[5],
            op: u16::from_be_bytes([buf[6], buf[7]]),
        })
    }

    pub fn encode(&self, buf: &mut [u8]) {
        buf[..2].copy_from_slice(&self.hrd.to_be_bytes());
        buf[2..4].copy_from_slice(&self.pro.to_be_bytes());
        buf[4] = self.hln;
        buf[5] = self.pln;
        buf[6..8].copy_from_slice(&self.op.to_be_bytes());
    }
}

/// Ethernet/IP ARP message body — mirrors `struct arp_ethip`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpEthIp {
    pub sha: EthAddr,
    pub spa: Addr,
    pub tha: EthAddr,
    pub tpa: Addr,
}

impl ArpEthIp {
    /// Parse the body that follows the ARP header for Ethernet/IP.
    pub fn parse(buf: &[u8]) -> Option<ArpEthIp> {
        if buf.len() < ARP_ETHIP_LEN {
            return None;
        }
        let mut sha = [0u8; ETH_ADDR_LEN];
        sha.copy_from_slice(&buf[0..6]);
        let spa = Addr::ipv4(std::net::Ipv4Addr::new(
            buf[6], buf[7], buf[8], buf[9],
        ));
        let mut tha = [0u8; ETH_ADDR_LEN];
        tha.copy_from_slice(&buf[10..16]);
        let tpa = Addr::ipv4(std::net::Ipv4Addr::new(
            buf[16], buf[17], buf[18], buf[19],
        ));
        Some(ArpEthIp {
            sha: EthAddr::new(sha),
            spa,
            tha: EthAddr::new(tha),
            tpa,
        })
    }

    pub fn encode(&self, buf: &mut [u8]) {
        buf[0..6].copy_from_slice(&self.sha.data);
        let sp = self.spa.to_ipv4().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        buf[6..10].copy_from_slice(&sp.octets());
        buf[10..16].copy_from_slice(&self.tha.data);
        let tp = self.tpa.to_ipv4().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        buf[16..20].copy_from_slice(&tp.octets());
    }
}

/// Full Ethernet/IP ARP message (header + body).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpMsg {
    pub hdr: ArpHdr,
    pub body: ArpEthIp,
}

impl ArpMsg {
    /// Build an Address Resolution request.
    pub fn request(spa: Addr, tpa: Addr, sha: EthAddr) -> ArpMsg {
        ArpMsg {
            hdr: ArpHdr {
                hrd: ARP_HRD_ETH,
                pro: ARP_PRO_IP,
                hln: HW_ADDR_LEN as u8,
                pln: IP_ADDR_LEN as u8,
                op: ARP_OP_REQUEST,
            },
            body: ArpEthIp {
                sha,
                spa,
                tha: EthAddr::new([0u8; ETH_ADDR_LEN]),
                tpa,
            },
        }
    }

    /// Serialize into a buffer big enough for `ARP_ETHIP_LEN + ARP_HDR_LEN`.
    pub fn encode(&self, buf: &mut [u8]) {
        self.hdr.encode(&mut buf[..ARP_HDR_LEN]);
        self.body.encode(&mut buf[ARP_HDR_LEN..]);
    }

    pub fn total_len(&self) -> usize {
        ARP_HDR_LEN + ARP_ETHIP_LEN
    }
}

/// A mapping of a protocol address to a hardware address — mirrors `struct arp_entry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpEntry {
    /// Protocol (IP) address.
    pub pa: Addr,
    /// Hardware (Ethernet) address.
    pub ha: Addr,
}

/// A simple in-memory ARP cache, mirroring the libdnet `arp_*` API surface.
///
/// The real ARP table is maintained by the operating system kernel. This
/// structure models the same operations (`add`, `delete`, `get`, `loop`) for
/// user-space coordination.
#[derive(Default, Debug)]
pub struct ArpCache {
    entries: Vec<ArpEntry>,
}

impl ArpCache {
    pub fn new() -> Self {
        ArpCache::default()
    }

    /// Add or replace an entry (mirrors `arp_add`).
    pub fn add(&mut self, entry: ArpEntry) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.pa == entry.pa) {
            existing.ha = entry.ha;
            return;
        }
        self.entries.push(entry);
    }

    /// Delete an entry by protocol address (mirrors `arp_delete`).
    pub fn delete(&mut self, pa: &Addr) {
        self.entries.retain(|e| e.pa != *pa);
    }

    /// Look up the hardware address for a protocol address (mirrors `arp_get`).
    pub fn get(&self, pa: &Addr) -> Option<&ArpEntry> {
        self.entries.iter().find(|e| e.pa == *pa)
    }

    /// Iterate over all entries (mirrors `arp_loop`).
    pub fn entries(&self) -> &[ArpEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn arp_message_roundtrip() {
        let msg = ArpMsg::request(
            Addr::ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            Addr::ipv4(Ipv4Addr::new(192, 0, 2, 2)),
            EthAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
        );
        let mut buf = vec![0u8; msg.total_len()];
        msg.encode(&mut buf);
        let hdr = ArpHdr::parse(&buf).unwrap();
        assert_eq!(hdr.op, ARP_OP_REQUEST);
        assert_eq!(hdr.hrd, ARP_HRD_ETH);
        let body = ArpEthIp::parse(&buf[ARP_HDR_LEN..]).unwrap();
        assert_eq!(body.spa, msg.body.spa);
        assert_eq!(body.tpa, msg.body.tpa);
    }

    #[test]
    fn cache_ops() {
        let mut c = ArpCache::new();
        let pa = Addr::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let ha = Addr::hw([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(c.is_empty());
        c.add(ArpEntry { pa, ha });
        assert_eq!(c.len(), 1);
        assert_eq!(c.get(&pa).unwrap().ha, ha);
        c.delete(&pa);
        assert!(c.is_empty());
    }
}
