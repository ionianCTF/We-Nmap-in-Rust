//! Datalink (link-layer) type constants — mirrors pcap's `DLT_*`.
//!
//! The datalink type tells a capture consumer what the bytes of each captured
//! packet represent (Ethernet, raw IP, loopback, etc.). This mirrors the
//! constants used by libpcap / Npcap without binding to them.

/// Ethernet (10Mb, 100Mb, 1000Mb, and up).
pub const DLT_NULL: i32 = 0;
pub const DLT_EN10MB: i32 = 1;
pub const DLT_EN3MB: i32 = 2;
pub const DLT_AX25: i32 = 3;
pub const DLT_PRONET: i32 = 4;
pub const DLT_CHAOS: i32 = 5;
pub const DLT_IEEE802: i32 = 6;
pub const DLT_ARCNET: i32 = 7;
pub const DLT_SLIP: i32 = 8;
pub const DLT_PPP: i32 = 9;
pub const DLT_FDDI: i32 = 10;
pub const DLT_ATM_RFC1483: i32 = 11;
pub const DLT_RAW: i32 = 12;
pub const DLT_SLIP_BSDOS: i32 = 15;
pub const DLT_PPP_BSDOS: i32 = 16;
pub const DLT_ATM_CLIP: i32 = 19;
pub const DLT_PPP_SERIAL: i32 = 50;
pub const DLT_PPP_ETHER: i32 = 51;
pub const DLT_IEEE802_11: i32 = 105;
pub const DLT_IEEE802_11_RADIO: i32 = 127;
pub const DLT_LOOP: i32 = 108;
pub const DLT_LINUX_SLL: i32 = 113;
pub const DLT_IPV4: i32 = 228;
pub const DLT_IPV6: i32 = 229;

/// Human-readable names for common datalink types.
pub fn datalink_ntop(dlt: i32) -> &'static str {
    match dlt {
        DLT_NULL => "NULL",
        DLT_EN10MB => "EN10MB",
        DLT_IEEE802 => "IEEE802",
        DLT_ARCNET => "ARCNET",
        DLT_SLIP => "SLIP",
        DLT_PPP => "PPP",
        DLT_FDDI => "FDDI",
        DLT_RAW => "RAW",
        DLT_LOOP => "LOOP",
        DLT_LINUX_SLL => "LINUX_SLL",
        DLT_IEEE802_11 => "IEEE802_11",
        DLT_IEEE802_11_RADIO => "IEEE802_11_RADIO",
        DLT_IPV4 => "IPV4",
        DLT_IPV6 => "IPV6",
        _ => "UNKNOWN",
    }
}

/// The offset from the start of a captured frame to the start of the IP
/// header for a given datalink type. This drives L2 stripping in captures.
pub fn link_header_len(dlt: i32) -> usize {
    match dlt {
        DLT_EN10MB => 14,
        DLT_LINUX_SLL => 16,
        DLT_IEEE802_11_RADIO => 32,
        DLT_RAW | DLT_IPV4 | DLT_IPV6 | DLT_LOOP | DLT_NULL => 0,
        _ => 14,
    }
}
