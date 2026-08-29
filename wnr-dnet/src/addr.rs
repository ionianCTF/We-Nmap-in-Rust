//! Address types — mirrors libdnet's `struct addr` (DNET_ADDR).
//!
//! libdnet represents all network addresses (protocol and link-layer) with a
//! single polymorphic `struct addr` holding a family, a bit length, and the
//! raw address bytes. We provide a safe Rust representation of the same idea.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Action verbs for `addr_cmp` / `addr_btest` filtering, mirroring libdnet.
pub const ADDR_TYPE_NONE: u32 = 0;
pub const ADDR_TYPE_OSI: u32 = 1;
pub const ADDR_TYPE_IP: u32 = 2;
pub const ADDR_TYPE_IP6: u32 = 3;
pub const ADDR_TYPE_HW: u32 = 4;

/// The length of an IPv4 address in octets.
pub const IP_ADDR_LEN: usize = 4;
/// The length of an IPv6 address in octets.
pub const IP6_ADDR_LEN: usize = 16;
/// The length of a hardware (Ethernet) address in octets.
pub const HW_ADDR_LEN: usize = 6;

/// A polymorphic network address, analogous to libdnet's `struct addr`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Addr {
    /// Numeric address family (`ADDR_TYPE_*`).
    pub addr_type: u32,
    /// Number of significant bits in the address.
    pub addr_bits: u16,
    /// Raw address bytes (zero-padded to the maximum length).
    pub data: [u8; IP6_ADDR_LEN],
}

impl Addr {
    /// Construct an address from an IPv4 address.
    pub fn ipv4(ip: Ipv4Addr) -> Self {
        let mut a = Addr::default();
        a.addr_type = ADDR_TYPE_IP;
        a.addr_bits = 32;
        a.data[..IP_ADDR_LEN].copy_from_slice(&ip.octets());
        a
    }

    /// Construct an address from an IPv6 address.
    pub fn ipv6(ip: Ipv6Addr) -> Self {
        let mut a = Addr::default();
        a.addr_type = ADDR_TYPE_IP6;
        a.addr_bits = 128;
        a.data.copy_from_slice(&ip.octets());
        a
    }

    /// Construct a hardware (Ethernet) address from six bytes.
    pub fn hw(bytes: [u8; HW_ADDR_LEN]) -> Self {
        let mut a = Addr::default();
        a.addr_type = ADDR_TYPE_HW;
        a.addr_bits = 48;
        a.data[..HW_ADDR_LEN].copy_from_slice(&bytes);
        a
    }

    /// The raw protocol version (4 or 6) for IP addresses, 0 otherwise.
    pub fn ip_version(&self) -> u8 {
        match self.addr_type {
            ADDR_TYPE_IP => 4,
            ADDR_TYPE_IP6 => 6,
            _ => 0,
        }
    }

    /// Interpret this address as an IPv4 address if possible.
    pub fn to_ipv4(&self) -> Option<Ipv4Addr> {
        if self.addr_type == ADDR_TYPE_IP {
            Some(Ipv4Addr::new(
                self.data[0], self.data[1], self.data[2], self.data[3],
            ))
        } else {
            None
        }
    }

    /// Interpret this address as an IPv6 address if possible.
    pub fn to_ipv6(&self) -> Option<Ipv6Addr> {
        if self.addr_type == ADDR_TYPE_IP6 {
            Some(Ipv6Addr::from(self.data))
        } else {
            None
        }
    }

    /// Interpret this address as an Ethernet hardware address if possible.
    pub fn to_hw(&self) -> Option<[u8; HW_ADDR_LEN]> {
        if self.addr_type == ADDR_TYPE_HW {
            let mut b = [0u8; HW_ADDR_LEN];
            b.copy_from_slice(&self.data[..HW_ADDR_LEN]);
            Some(b)
        } else {
            None
        }
    }

    /// True if this is a broadcast/multicast Ethernet address
    /// (low bit of first octet set), mirroring `ETH_IS_MULTICAST`.
    pub fn is_multicast_hw(&self) -> bool {
        self.addr_type == ADDR_TYPE_HW && self.data[0] & 0x01 != 0
    }

    /// Build an address from raw bytes — mirrors libdnet's `addr_pack` macro:
    /// set the type, the number of significant bits, and copy `len` bytes of
    /// `data` (zero-padded to the 16-byte backing array).
    pub fn pack(&mut self, addr_type: u32, bits: u16, data: &[u8]) {
        self.addr_type = addr_type;
        self.addr_bits = bits;
        self.data = [0u8; IP6_ADDR_LEN];
        let n = data.len().min(IP6_ADDR_LEN);
        self.data[..n].copy_from_slice(&data[..n]);
    }

    /// Compare two addresses (type, then bits, then bytes) — mirrors `addr_cmp`.
    /// Returns `< 0`, `0`, or `> 0` in lexicographic order.
    pub fn addr_cmp(&self, other: &Addr) -> i32 {
        if self.addr_type != other.addr_type {
            return (self.addr_type as i64 - other.addr_type as i64) as i32;
        }
        if self.addr_bits != other.addr_bits {
            return (self.addr_bits as i64 - other.addr_bits as i64) as i32;
        }
        for (a, b) in self.data.iter().zip(other.data.iter()) {
            if a != b {
                return (*a as i32) - (*b as i32);
            }
        }
        0
    }

    /// Compute the network (subnet) address for this address given its
    /// `addr_bits`, clearing the host bits — mirrors `addr_net`.
    pub fn network(&self) -> Addr {
        let mut out = *self;
        let mask = Addr::bits_to_mask(self.addr_bits);
        for i in 0..IP6_ADDR_LEN {
            out.data[i] &= mask[i];
        }
        out
    }

    /// Compute the directed broadcast address for this address given its
    /// `addr_bits`, setting the host bits — mirrors `addr_bcast`.
    pub fn broadcast(&self) -> Addr {
        let mut out = *self;
        let mask = Addr::bits_to_mask(self.addr_bits);
        for i in 0..IP6_ADDR_LEN {
            out.data[i] |= !mask[i];
        }
        out
    }

    /// Convert a prefix length (`addr_bits`) into a contiguous network mask of
    /// `size` bytes — mirrors `addr_btom`. The mask has `bits` leading one bits.
    pub fn bits_to_mask_len(bits: u16, size: usize) -> Option<Vec<u8>> {
        if bits as usize > size * 8 {
            return None;
        }
        let mut mask = vec![0u8; size];
        let full = (bits / 8) as usize;
        let rem = (bits % 8) as usize;
        for m in mask.iter_mut().take(full) {
            *m = 0xff;
        }
        if rem > 0 && full < size {
            mask[full] = (0xffu8) << (8 - rem);
        }
        Some(mask)
    }

    /// Set `addr_bits` to a contiguous mask of `lines` leading ones — mirrors
    /// `addr_btom` operating on this address's 16-byte array.
    pub fn bits_to_mask(bits: u16) -> [u8; IP6_ADDR_LEN] {
        let mask = Addr::bits_to_mask_len(bits, IP6_ADDR_LEN).unwrap_or_else(|| vec![0u8; IP6_ADDR_LEN]);
        let mut out = [0u8; IP6_ADDR_LEN];
        out.copy_from_slice(&mask);
        out
    }

    /// Count the number of contiguous leading one bits in this address's bytes
    /// as a netmask — mirrors `addr_mtob`.
    pub fn mask_to_bits(&self) -> u16 {
        let mut bits = 0u16;
        for &b in self.data.iter() {
            if b == 0xff {
                bits += 8;
                continue;
            }
            let mut v = b;
            let mut count = 0;
            while v & 0x80 != 0 {
                count += 1;
                v <<= 1;
            }
            // Reject a non-contiguous mask (0 bits set inside a 1-run).
            if v != 0 && b != 0 {
                return 0;
            }
            bits += count;
            return bits;
        }
        bits
    }

    /// The number of bytes used to store this address (per its type).
    pub fn addr_len(&self) -> usize {
        match self.addr_type {
            ADDR_TYPE_IP => IP_ADDR_LEN,
            ADDR_TYPE_IP6 => IP6_ADDR_LEN,
            ADDR_TYPE_HW => HW_ADDR_LEN,
            _ => 0,
        }
    }
}

impl std::str::FromStr for Addr {
    type Err = String;

    /// Parse an address from text — mirrors `addr_pton` / `addr_aton`.
    /// Accepts IPv4 (`1.2.3.4`), IPv6 (`2001:db8::1`), and Ethernet MAC
    /// (`aa:bb:cc:dd:ee:ff`).
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Ok(ip) = s.parse::<Ipv4Addr>() {
            return Ok(Addr::ipv4(ip));
        }
        if let Ok(ip) = s.parse::<Ipv6Addr>() {
            return Ok(Addr::ipv6(ip));
        }
        if s.contains(':') {
            if let Some(eth) = crate::eth::eth_pton(s) {
                return Ok(Addr::hw(eth.data));
            }
        }
        Err(format!("could not parse address '{}'", s))
    }
}

/// Parse an address from text — mirrors libdnet's `addr_pton` / `addr_aton`.
pub fn addr_pton(s: &str) -> Option<Addr> {
    s.parse().ok()
}

/// Convert an address to text — mirrors libdnet's `addr_ntoa` (owned string).
pub fn addr_ntoa(a: &Addr) -> String {
    a.to_string()
}

/// Convert an address to text — mirrors libdnet's `addr_ntop` (in Rust we
/// return an owned `String` instead of writing into a caller buffer).
pub fn addr_ntop(a: &Addr) -> String {
    a.to_string()
}

/// Compare two addresses — mirrors libdnet's `addr_cmp`.
pub fn addr_cmp(a: &Addr, b: &Addr) -> i32 {
    a.addr_cmp(b)
}

/// Compute the network address of `a` given its `addr_bits` — mirrors
/// libdnet's `addr_net`.
pub fn addr_net(a: &Addr) -> Addr {
    a.network()
}

/// Compute the broadcast address of `a` given its `addr_bits` — mirrors
/// libdnet's `addr_bcast`.
pub fn addr_bcast(a: &Addr) -> Addr {
    a.broadcast()
}

/// Convert a prefix length to a contiguous network mask of `size` bytes —
/// mirrors libdnet's `addr_btom`.
pub fn addr_btom(bits: u16, size: usize) -> Option<Vec<u8>> {
    Addr::bits_to_mask_len(bits, size)
}

/// Convert a contiguous network mask to a prefix length — mirrors libdnet's
/// `addr_mtob`. Returns `None` if the mask is not contiguous.
pub fn addr_mtob(mask: &[u8]) -> Option<u16> {
    let mut bits: u16 = 0;
    let mut in_ones = true;
    for (i, &b) in mask.iter().enumerate() {
        if in_ones {
            if b == 0xff {
                bits += 8;
            } else {
                // Count the contiguous leading one bits in this byte.
                let mut run = 0u16;
                let mut v = b;
                while v & 0x80 != 0 {
                    run += 1;
                    v <<= 1;
                }
                // After the run, the remaining bits must all be zero.
                if v != 0 {
                    return None;
                }
                bits += run;
                in_ones = false;
            }
        } else if b != 0 {
            // A non-zero byte after the run ended is non-contiguous.
            let _ = i;
            return None;
        }
    }
    Some(bits)
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.addr_type {
            ADDR_TYPE_IP => {
                let ip = self.to_ipv4().unwrap_or(Ipv4Addr::UNSPECIFIED);
                write!(f, "{}", ip)
            }
            ADDR_TYPE_IP6 => {
                let ip = self.to_ipv6().unwrap_or(Ipv6Addr::UNSPECIFIED);
                write!(f, "{}", ip)
            }
            ADDR_TYPE_HW => {
                for (i, b) in self.data[..HW_ADDR_LEN].iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            _ => write!(f, "(unknown)"),
        }
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Addr({})", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ipv4_roundtrip() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let a = Addr::ipv4(ip);
        assert_eq!(a.to_ipv4(), Some(ip));
        assert_eq!(a.ip_version(), 4);
        assert_eq!(a.addr_bits, 32);
    }

    #[test]
    fn ipv6_roundtrip() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let a = Addr::ipv6(ip);
        assert_eq!(a.to_ipv6(), Some(ip));
        assert_eq!(a.ip_version(), 6);
    }

    #[test]
    fn hw_roundtrip() {
        let mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let a = Addr::hw(mac);
        assert_eq!(a.to_hw(), Some(mac));
        assert_eq!(a.is_multicast_hw(), false);
        assert_eq!(format!("{}", a), "de:ad:be:ef:00:01");
    }

    #[test]
    fn broadcast_detected() {
        let bcast = [0xff; 6];
        let a = Addr::hw(bcast);
        assert!(a.is_multicast_hw());
    }

    #[test]
    fn pton_ntoa_roundtrip() {
        let ip = Addr::ipv4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addr_pton("192.168.1.1"), Some(ip));
        assert_eq!(addr_ntoa(&ip), "192.168.1.1");

        let ip6 = Addr::ipv6("2001:db8::1".parse().unwrap());
        assert_eq!(addr_pton("2001:db8::1"), Some(ip6));

        let mac = Addr::hw([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        assert_eq!(addr_pton("aa:bb:cc:dd:ee:01"), Some(mac));
        assert_eq!(addr_ntoa(&mac), "aa:bb:cc:dd:ee:01");
    }

    #[test]
    fn cmp_orders() {
        let a = Addr::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let b = Addr::ipv4(Ipv4Addr::new(10, 0, 0, 2));
        let c = Addr::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(addr_cmp(&a, &b) < 0);
        assert!(addr_cmp(&b, &a) > 0);
        assert_eq!(addr_cmp(&a, &c), 0);

        // Different type sorts by type (IP < IP6 < HW in our numbering is not
        // guaranteed; here they must differ, which is what we assert).
        let d = Addr::hw([0, 0, 0, 0, 0, 1]);
        assert_ne!(addr_cmp(&a, &d), 0);
    }

    #[test]
    fn net_and_broadcast() {
        // 192.168.1.5/24 => network 192.168.1.0, broadcast 192.168.1.255
        let mut a = Addr::ipv4(Ipv4Addr::new(192, 168, 1, 5));
        a.addr_bits = 24;
        assert_eq!(addr_net(&a).to_ipv4().unwrap(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(
            addr_bcast(&a).to_ipv4().unwrap(),
            Ipv4Addr::new(192, 168, 1, 255)
        );
    }

    #[test]
    fn mask_bits_conversions() {
        // /24 mask
        assert_eq!(addr_btom(24, 4).unwrap(), vec![255, 255, 255, 0]);
        assert_eq!(addr_mtob(&[255, 255, 255, 0]), Some(24));
        assert_eq!(addr_mtob(&[255, 255, 255, 255]), Some(32));
        assert_eq!(addr_mtob(&[255, 255, 0, 255]), None); // non-contiguous
        assert_eq!(addr_mtob(&[128, 0, 0, 0]), Some(1));
        assert_eq!(addr_mtob(&[0, 0, 0, 0]), Some(0));
    }

    #[test]
    fn pack_sets_bytes() {
        let mut a = Addr::default();
        a.pack(ADDR_TYPE_IP, 24, &[10, 0, 0]);
        assert_eq!(a.addr_type, ADDR_TYPE_IP);
        assert_eq!(a.addr_bits, 24);
        assert_eq!(a.data[..3], [10, 0, 0]);
        assert_eq!(a.data[3], 0);
        assert_eq!(a.addr_len(), 4);
    }
}
