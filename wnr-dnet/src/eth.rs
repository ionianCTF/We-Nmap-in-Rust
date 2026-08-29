//! Ethernet link-layer handling — mirrors libdnet's `eth.h` / `eth.c`.
//!
//! Provides the Ethernet address type, the fixed 14-byte Ethernet header,
//! well-known EtherTypes, and text<->binary conversion of MAC addresses.

use crate::addr::Addr;

/// Length of an Ethernet hardware address in octets.
pub const ETH_ADDR_LEN: usize = 6;
/// Length of the EtherType field in octets.
pub const ETH_TYPE_LEN: usize = 2;
/// Length of the CRC field in octets.
pub const ETH_CRC_LEN: usize = 4;
/// Length of the Ethernet header (dst + src + type).
pub const ETH_HDR_LEN: usize = 14;
/// Minimum frame length including CRC.
pub const ETH_LEN_MIN: usize = 64;
/// Maximum frame length including CRC.
pub const ETH_LEN_MAX: usize = 1518;
/// Maximum payload for a standard Ethernet frame.
pub const ETH_MTU: usize = ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN;
/// Minimum payload for a standard Ethernet frame.
pub const ETH_MIN: usize = ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN;

/// Well-known EtherTypes (host byte order constants; serialized network order).
pub const ETH_TYPE_PUP: u16 = 0x0200;
pub const ETH_TYPE_IP: u16 = 0x0800;
pub const ETH_TYPE_ARP: u16 = 0x0806;
pub const ETH_TYPE_REVARP: u16 = 0x8035;
pub const ETH_TYPE_8021Q: u16 = 0x8100;
pub const ETH_TYPE_IPV6: u16 = 0x86DD;
pub const ETH_TYPE_MPLS: u16 = 0x8847;
pub const ETH_TYPE_MPLS_MCAST: u16 = 0x8848;
pub const ETH_TYPE_PPPOEDISC: u16 = 0x8863;
pub const ETH_TYPE_PPPOE: u16 = 0x8864;
pub const ETH_TYPE_LOOPBACK: u16 = 0x9000;

/// The broadcast Ethernet address `ff:ff:ff:ff:ff:ff`.
pub const ETH_ADDR_BROADCAST: [u8; ETH_ADDR_LEN] = [0xff; ETH_ADDR_LEN];

/// An Ethernet hardware (MAC) address — mirrors `eth_addr_t`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct EthAddr {
    pub data: [u8; ETH_ADDR_LEN],
}

impl EthAddr {
    pub fn new(data: [u8; ETH_ADDR_LEN]) -> Self {
        EthAddr { data }
    }

    /// True if this is a multicast or broadcast address.
    pub fn is_multicast(&self) -> bool {
        self.data[0] & 0x01 != 0
    }

    pub fn is_broadcast(&self) -> bool {
        *self == EthAddr::new(ETH_ADDR_BROADCAST)
    }

    /// Convert to a libdnet-style polymorphic address.
    pub fn to_addr(&self) -> Addr {
        Addr::hw(self.data)
    }
}

/// Format a MAC address as text (`aa:bb:cc:dd:ee:ff`) — mirrors `eth_ntop`.
pub fn eth_ntop(addr: &EthAddr) -> String {
    let mut out = String::with_capacity(ETH_ADDR_LEN * 3);
    for (i, b) in addr.data.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Parse a MAC address from text, accepting `:` or `-` separators and
/// either 6 colon-separated octets or a `x:x:x:x:x:x` form — mirrors `eth_pton`.
pub fn eth_pton(s: &str) -> Option<EthAddr> {
    let s = s.trim();
    let mut bytes = [0u8; ETH_ADDR_LEN];
    if s.contains(':') {
        // colon form
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != ETH_ADDR_LEN {
            return None;
        }
        for (i, p) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(p, 16).ok()?;
        }
    } else if s.contains('-') {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != ETH_ADDR_LEN {
            return None;
        }
        for (i, p) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(p, 16).ok()?;
        }
    } else {
        // compact 12-hex-digit form
        let digits: Vec<char> = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if digits.len() != 12 {
            return None;
        }
        for i in 0..ETH_ADDR_LEN {
            let hi = u8::from_str_radix(&digits[i * 2].to_string(), 16).ok()?;
            let lo = u8::from_str_radix(&digits[i * 2 + 1].to_string(), 16).ok()?;
            bytes[i] = (hi << 4) | lo;
        }
    }
    Some(EthAddr::new(bytes))
}

/// A parsed Ethernet header — mirrors `struct eth_hdr`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EthHdr {
    pub dst: EthAddr,
    pub src: EthAddr,
    pub proto: u16,
}

impl EthHdr {
    /// Parse an Ethernet header from the first `ETH_HDR_LEN` bytes of a frame.
    pub fn parse(buf: &[u8]) -> Option<EthHdr> {
        if buf.len() < ETH_HDR_LEN {
            return None;
        }
        let mut dst = [0u8; ETH_ADDR_LEN];
        let mut src = [0u8; ETH_ADDR_LEN];
        dst.copy_from_slice(&buf[0..6]);
        src.copy_from_slice(&buf[6..12]);
        let proto = u16::from_be_bytes([buf[12], buf[13]]);
        Some(EthHdr {
            dst: EthAddr::new(dst),
            src: EthAddr::new(src),
            proto,
        })
    }

    /// Serialize this header to the front of a buffer (needs `ETH_HDR_LEN`).
    pub fn encode(&self, buf: &mut [u8]) {
        buf[0..6].copy_from_slice(&self.dst.data);
        buf[6..12].copy_from_slice(&self.src.data);
        buf[12..14].copy_from_slice(&self.proto.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntop_pton_roundtrip() {
        let mac = EthAddr::new([0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc]);
        let text = eth_ntop(&mac);
        assert_eq!(text, "00:11:22:aa:bb:cc");
        assert_eq!(eth_pton(&text), Some(mac));
        assert_eq!(eth_pton("00-11-22-AA-BB-CC"), Some(mac));
        assert_eq!(eth_pton("001122aabbcc"), Some(mac));
    }

    #[test]
    fn broadcast() {
        let b = EthAddr::new(ETH_ADDR_BROADCAST);
        assert!(b.is_broadcast());
        assert!(b.is_multicast());
    }

    #[test]
    fn header_encode_decode() {
        let hdr = EthHdr {
            dst: EthAddr::new(ETH_ADDR_BROADCAST),
            src: EthAddr::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            proto: ETH_TYPE_IP,
        };
        let mut buf = [0u8; ETH_HDR_LEN];
        hdr.encode(&mut buf);
        let parsed = EthHdr::parse(&buf).unwrap();
        assert_eq!(parsed, hdr);
    }
}
