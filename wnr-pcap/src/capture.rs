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
use crate::raw::Direction;
use crate::savefile::{SavefileReader, SavefileWriter};

/// The version string reported by this library, mirroring `pcap_lib_version`.
pub fn lib_version() -> &'static str {
    concat!("wnr-pcap ", env!("CARGO_PKG_VERSION"))
}

/// Capture statistics, mirroring `struct pcap_stat`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureStats {
    /// Packets received (for captures that support it).
    pub ps_recv: u32,
    /// Packets dropped because there was no room in the operating system's
    /// buffer (for captures that support it).
    pub ps_drop: u32,
    /// Packets dropped by the network interface (for captures that support it).
    pub ps_ifdrop: u32,
}

/// Return value a `Capture::loop_` callback can use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopControl {
    /// Keep processing packets.
    Continue,
    /// Stop processing (as if `pcap_breakloop` was called).
    Break,
}

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
    /// Packet direction filter (live captures only).
    direction: Direction,
    /// Non-blocking read mode (live captures only).
    nonblock: bool,
    /// Most recent error message, mirroring `pcap_geterr`.
    last_err: String,
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
                direction: Direction::InOut,
                nonblock: false,
                last_err: String::new(),
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
                direction: Direction::InOut,
                nonblock: false,
                last_err: String::new(),
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
            direction: Direction::InOut,
            nonblock: false,
            last_err: String::new(),
        })
    }

    /// Set a BPF filter, mirroring `pcap_setfilter` / `pcap_compile`.
    pub fn set_filter(&mut self, expr: &str) -> Result<(), String> {
        let prog = crate::bpf::FilterBuilder::compile(expr, self.linktype).map_err(|e| {
            self.last_err = format!("syntax error: {}", e);
            e
        })?;
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

    /// The most recent error message, mirroring `pcap_geterr`.
    pub fn geterr(&self) -> &str {
        &self.last_err
    }

    /// Human-readable name for this capture's datalink type, mirroring
    /// `pcap_datalink_val_to_name`.
    pub fn datalink_val_to_name(&self) -> &'static str {
        datalink::datalink_ntop(self.linktype)
    }

    /// Is this capture in non-blocking mode? Mirrors `pcap_getnonblock`.
    pub fn nonblock(&self) -> bool {
        self.nonblock
    }

    /// Set or clear non-blocking mode, mirroring `pcap_setnonblock`.
    ///
    /// The mode is stored and applied to the live backend; for offline
    /// captures it is stored but has no effect on synchronous reads.
    pub fn set_nonblock(&mut self, nb: bool) -> Result<(), String> {
        match &mut self.kind {
            CaptureKind::Offline(_) => {}
            #[cfg(any(unix, windows))]
            CaptureKind::Live(r) => {
                r.set_nonblock(nb).map_err(|e| {
                    self.last_err = e.to_string();
                    format!("pcap_setnonblock: {}", e)
                })?;
            }
        }
        self.nonblock = nb;
        Ok(())
    }

    /// Restrict capture to packets of a given direction, mirroring
    /// `pcap_setdirection`.
    pub fn set_direction(&mut self, dir: Direction) -> Result<(), String> {
        match &mut self.kind {
            CaptureKind::Offline(_) => {
                self.last_err = "pcap_setdirection: cannot set direction on an offline capture"
                    .to_string();
                return Err(self.last_err.clone());
            }
            #[cfg(any(unix, windows))]
            CaptureKind::Live(r) => r.set_direction(dir),
        }
        self.direction = dir;
        Ok(())
    }

    /// Read capture statistics, mirroring `pcap_stats`.
    pub fn stats(&self) -> CaptureStats {
        let (recv, drop) = match &self.kind {
            CaptureKind::Offline(_) => (0, 0),
            #[cfg(any(unix, windows))]
            CaptureKind::Live(r) => r.poll_stats().unwrap_or((0, 0)),
        };
        CaptureStats {
            ps_recv: recv as u32,
            ps_drop: drop as u32,
            ps_ifdrop: 0,
        }
    }

    /// Inject a raw frame onto the wire, mirroring `pcap_inject` /
    /// `pcap_sendpacket`. Only supported on live captures. Returns the number
    /// of bytes written.
    pub fn inject(&mut self, data: &[u8]) -> Result<usize, String> {
        match &mut self.kind {
            CaptureKind::Offline(_) => {
                self.last_err = "cannot inject on an offline capture".to_string();
                return Err(self.last_err.clone());
            }
            #[cfg(any(unix, windows))]
            CaptureKind::Live(r) => {
                return r.send_frame(data).map_err(|e| {
                    self.last_err = e.to_string();
                    format!("pcap_inject: {}", e)
                });
            }
        }
    }

    /// Transmit every packet in `queue`, mirroring `pcap_sendqueue_transmit`.
    ///
    /// Each packet's frame bytes are injected onto the wire in queue order.
    /// Only supported on live captures (each injection goes through
    /// [`Capture::inject`], so an offline capture fails immediately). Returns
    /// the total number of bytes transmitted.
    pub fn transmit_sendqueue(&mut self, queue: &crate::sendqueue::Sendqueue) -> Result<u32, String> {
        let mut total: u32 = 0;
        for pkt in queue.entries() {
            let n = self.inject(&pkt.data)?;
            total += n as u32;
        }
        Ok(total)
    }

    /// Process up to `count` packets from a live/offline capture, mirroring
    /// `pcap_loop`. `count == 0` means "until break / end of capture".
    /// Returns the number of packets processed.
    pub fn loop_(
        &mut self,
        count: i32,
        mut cb: impl FnMut(&PacketHeader, &[u8]) -> LoopControl,
    ) -> Result<u32, String> {
        // `count < 0` means "read forever" — treat like 0 per libpcap, but we
        // allow only 0 as the "forever" sentinel to stay deterministic.
        let limit = if count <= 0 { u32::MAX } else { count as u32 };
        let mut processed = 0u32;
        loop {
            if processed >= limit {
                return Ok(processed);
            }
            match self.next_packet() {
                Ok(Some((hdr, data))) => {
                    processed += 1;
                    if cb(&hdr, &data) == LoopControl::Break {
                        return Ok(processed);
                    }
                }
                Ok(None) => return Ok(processed),
                Err(e) => return Err(e),
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datalink;
    use crate::raw;
    use crate::raw::Direction;
    use crate::savefile::SavefileWriter;

    /// Write a 4-packet savefile and return its path.
    fn fixture() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("wnr_cap_{}.pcap", std::process::id()));
        {
            let mut w = SavefileWriter::create(&path, 65535, datalink::DLT_EN10MB as u32).unwrap();
            for i in 0..4u32 {
                w.write_packet(1000 + i, 0, &[i as u8; 8]).unwrap();
            }
            w.flush().unwrap();
        }
        path
    }

    #[test]
    fn loop_reads_all_packets() {
        let path = fixture();
        let mut cap = Capture::open_offline(&path).unwrap();
        let mut seen = Vec::new();
        let n = cap
            .loop_(0, |hdr, data| {
                seen.push((hdr.ts_sec, data.len()));
                LoopControl::Continue
            })
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(seen, vec![(1000, 8), (1001, 8), (1002, 8), (1003, 8)]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn loop_counts_exactly() {
        let path = fixture();
        let mut cap = Capture::open_offline(&path).unwrap();
        let n = cap.loop_(2, |_, _| LoopControl::Continue).unwrap();
        assert_eq!(n, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn loop_break_stops_early() {
        let path = fixture();
        let mut cap = Capture::open_offline(&path).unwrap();
        let mut count = 0;
        let n = cap
            .loop_(0, |_, _| {
                count += 1;
                if count == 3 {
                    LoopControl::Break
                } else {
                    LoopControl::Continue
                }
            })
            .unwrap();
        assert_eq!(n, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn misc_pcap_parity() {
        let path = fixture();
        let mut cap = Capture::open_offline(&path).unwrap();

        // datalink name
        assert_eq!(cap.datalink_val_to_name(), "EN10MB");
        assert_eq!(cap.snaplen(), 65535);

        // nonblock is stored without error on offline
        cap.set_nonblock(true).unwrap();
        assert!(cap.nonblock());

        // inject / set_direction reject offline
        assert!(cap.inject(&[0u8; 4]).is_err());
        assert!(cap.set_direction(Direction::In).is_err());
        assert!(!cap.geterr().is_empty());

        // stats on offline are zeros
        let s = cap.stats();
        assert_eq!(s.ps_recv, 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn lib_version_present() {
        assert!(lib_version().starts_with("wnr-pcap "));
    }

    #[test]
    fn transmit_sendqueue_rejects_offline() {
        let path = fixture();
        let mut cap = Capture::open_offline(&path).unwrap();
        let q = crate::sendqueue::Sendqueue::new(1024);
        // Injecting onto an offline capture is unsupported, so transmitting
        // a queued packet must fail (through pcap_inject).
        assert!(cap.transmit_sendqueue(&q).is_ok()); // empty queue: nothing to send
        let mut q2 = crate::sendqueue::Sendqueue::new(1024);
        q2.add_raw(1, 0, vec![0x00, 0x11, 0x22]).unwrap();
        assert!(cap.transmit_sendqueue(&q2).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn direction_matching() {
        // inbound packet types admitted for In
        assert!(raw::pkttype_matches_dir(raw::PKT_HOST, Direction::In));
        assert!(raw::pkttype_matches_dir(raw::PKT_BROADCAST, Direction::In));
        // outgoing excluded for In
        assert!(!raw::pkttype_matches_dir(raw::PKT_OUTGOING, Direction::In));
        // only outgoing for Out
        assert!(raw::pkttype_matches_dir(raw::PKT_OUTGOING, Direction::Out));
        assert!(!raw::pkttype_matches_dir(raw::PKT_HOST, Direction::Out));
        // InOut admits everything
        assert!(raw::pkttype_matches_dir(raw::PKT_OUTGOING, Direction::InOut));
        assert!(raw::pkttype_matches_dir(raw::PKT_HOST, Direction::InOut));
    }
}
