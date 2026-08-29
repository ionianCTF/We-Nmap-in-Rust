//! Packet capture abstraction — mirrors libpcap's `pcap_open_live`,
//! `pcap_next_ex`, and `pcap_findalldevs` surface.
//!
//! Two capture backends are provided:
//!
//! * **Offline** — reads packets from a pcap savefile (always available).
//! * **Live** — reads packets from a live source. On Unix this uses a raw
//!   packet socket (`AF_PACKET`); on Windows it uses a raw IPv4 socket with
//!   optional `SIO_RCVALL` capture-all, which does not require the commercial
//!   Npcap driver (though it does require Administrator privileges).
//!   Windows live capture yields raw IP datagrams, so the datalink type is
//!   `DLT_RAW`.
//!
//! A shared `filters` hook lets a BPF program drop frames that do not match,
//! mirroring libpcap's kernel-side filtering.

use std::path::Path;

use crate::datalink;
use crate::savefile::{SavefileReader, SavefileWriter};

/// A snapshot of a captured packet with metadata, mirroring
/// `struct pcap_pkthdr` plus the captured bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    /// Timestamp seconds.
    pub ts_sec: u32,
    /// Timestamp sub-seconds (microseconds or nanoseconds, backend-dependent).
    pub ts_frac: u32,
    /// Number of bytes actually captured (<= snaplen).
    pub caplen: u32,
    /// Number of bytes on the wire.
    pub len: u32,
}

/// A capture handle. Wraps either an offline savefile or a live raw socket.
pub struct Capture {
    kind: CaptureKind,
    snaplen: u32,
    linktype: i32,
    /// Optional compiled BPF filter applied to every frame.
    filter: Option<crate::bpf::BpfProgram>,
    // Reused interpreter for applying `filter` across frames.
    filter_vm: crate::bpf::BpfVm,
}

enum CaptureKind {
    Offline(SavefileReader),
    #[cfg(any(unix, windows))]
    Live(crate::raw::RawCapture),
}

/// A pcap-style network device description.
#[derive(Clone, Debug)]
pub struct Device {
    pub name: String,
    pub description: String,
    pub addresses: Vec<wnr_dnet::Addr>,
    pub flags: u16,
}

/// Enumerate capture devices, mirroring `pcap_findalldevs`.
///
/// On Windows the interface is exposed via `\Device\NPF_{GUID}` names through
/// Npcap; here we derive names from the OS interface table (which is the
/// human-meaningful portion) and note the datalink type.
pub fn findalldevs() -> Vec<Device> {
    let mut out = Vec::new();
    for intf in wnr_dnet::intf::interface_list() {
        let mut addresses = vec![intf.addr];
        addresses.extend(intf.alias_addrs.iter().copied());
        out.push(Device {
            name: intf.name,
            description: match intf.intf_type {
                wnr_dnet::intf::INTF_TYPE_LOOPBACK => "Loopback interface".to_string(),
                wnr_dnet::intf::INTF_TYPE_ETH => "Ethernet".to_string(),
                wnr_dnet::intf::INTF_TYPE_PPP => "Point-to-point".to_string(),
                _ => "Network interface".to_string(),
            },
            addresses,
            flags: intf.flags,
        });
    }
    out
}

/// Look up the default capture device (first non-loopback), mirroring
/// `pcap_lookupdev` in spirit.
pub fn lookupdev() -> Option<String> {
    for d in findalldevs() {
        if d.flags & wnr_dnet::intf::INTF_FLAG_LOOPBACK == 0 {
            return Some(d.name);
        }
    }
    findalldevs().into_iter().next().map(|d| d.name)
}

impl Capture {
    /// Open a live capture, mirroring `pcap_open_live`.
    ///
    /// * `device` — interface name (see `lookupdev` / `findalldevs`)
    /// * `snaplen` — maximum bytes captured per frame
    /// * `promisc` — enable promiscuous mode
    /// * `timeout_ms` — read timeout hint (live only)
    #[allow(unused_variables)]
    pub fn open_live(
        device: &str,
        snaplen: u32,
        promisc: bool,
        timeout_ms: i32,
    ) -> Result<Capture, String> {
        #[cfg(unix)]
        {
            let raw = crate::raw::RawCapture::open(device, snaplen, promisc, timeout_ms)
                .map_err(|e| format!("unable to open device: {}", e))?;
            Ok(Capture {
                kind: CaptureKind::Live(raw),
                snaplen,
                linktype: datalink::DLT_EN10MB,
                filter: None,
                filter_vm: crate::bpf::BpfVm::new(),
            })
        }
        #[cfg(windows)]
        {
            let raw = crate::raw::RawCapture::open(device, snaplen, promisc, timeout_ms)
                .map_err(|e| format!("unable to open device ({}), try `--interfaces` to list devices", e))?;
            // Raw IPv4 sockets deliver IP datagrams with no link-layer header.
            Ok(Capture {
                kind: CaptureKind::Live(raw),
                snaplen,
                linktype: datalink::DLT_RAW,
                filter: None,
                filter_vm: crate::bpf::BpfVm::new(),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (device, promisc, timeout_ms);
            Err(format!(
                "live capture on '{}' is unsupported on this platform; \
                 use `wnr_pcap::open_offline` for savefile reading",
                device
            ))
        }
    }

    /// Open a savefile for offline reading, mirroring `pcap_open_offline`.
    pub fn open_offline(path: &Path) -> Result<Capture, String> {
        let reader = SavefileReader::open(path).map_err(|e| e.to_string())?;
        let linktype = reader.header().linktype as i32;
        let snaplen = reader.header().snaplen;
        Ok(Capture {
            kind: CaptureKind::Offline(reader),
            snaplen,
            linktype,
            filter: None,
            filter_vm: crate::bpf::BpfVm::new(),
        })
    }

    /// Set a BPF filter, mirroring `pcap_setfilter` / `pcap_compile`.
    pub fn set_filter(&mut self, expr: &str) -> Result<(), String> {
        let prog = crate::bpf::FilterBuilder::compile(expr, self.linktype)?;
        self.filter = Some(prog);
        self.filter_vm = crate::bpf::BpfVm::new();
        Ok(())
    }

    /// The datalink type of this capture.
    pub fn datalink(&self) -> i32 {
        self.linktype
    }

    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    /// Read the next packet. Returns `Ok(None)` at end of capture / no more
    /// data, mirroring `pcap_next_ex` returning 0/-2 distinctions collapsed.
    pub fn next_packet(&mut self) -> Result<Option<(PacketHeader, Vec<u8>)>, String> {
        let fetched = match &mut self.kind {
            CaptureKind::Offline(r) => r.next_packet().map_err(|e| e.to_string())?,
            #[cfg(any(unix, windows))]
            CaptureKind::Live(r) => r.next_packet().map_err(|e| e.to_string())?,
        };
        let Some(pkt) = fetched else {
            return Ok(None);
        };
        if let Some(prog) = &self.filter {
            let ok = self.filter_vm.filter_ok(&prog.insns, &pkt.data);
            if !ok {
                // Filtered; skip inwards to next matching packet.
                return self.next_packet();
            }
        }
        Ok(Some((
            PacketHeader {
                ts_sec: pkt.ts_sec,
                ts_frac: pkt.ts_frac,
                caplen: pkt.caplen,
                len: pkt.origlen,
            },
            pkt.data,
        )))
    }

    /// Convenience: write all captured packets to a pcap savefile until end.
    pub fn capture_to_file(&mut self, path: &Path, linktype: u32) -> std::io::Result<u32> {
        let mut w = SavefileWriter::create(path, self.snaplen, linktype)?;
        let mut count = 0u32;
        while let Ok(Some((hdr, data))) = self.next_packet() {
            w.write_packet(hdr.ts_sec, hdr.ts_frac, &data)?;
            count += 1;
        }
        w.flush()?;
        Ok(count)
    }
}

/// Load a capture file fully into memory for analysis.
pub fn read_all(path: &Path) -> Result<Vec<(PacketHeader, Vec<u8>)>, String> {
    let mut cap = Capture::open_offline(path)?;
    let mut out = Vec::new();
    while let Ok(Some((hdr, data))) = cap.next_packet() {
        out.push((hdr, data));
    }
    Ok(out)
}

/// Extract the IP payload from a frame given its datalink type. Returns
/// `(l3_offset, l3_len, frame)` — the offset and remaining length after the
/// link-layer header.
pub fn strip_link_header(dlt: i32, frame: &[u8]) -> Option<(usize, usize, &[u8])> {
    let off = datalink::link_header_len(dlt);
    if frame.len() < off {
        return None;
    }
    Some((off, frame.len() - off, &frame[off..]))
}
