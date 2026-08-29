//! Packet transmission queue — mirrors libpcap's `pcap_sendqueue_*` API.
//!
//! libpcap (via WinPcap/Npcap) lets callers stage multiple packets into a
//! queue and then transmit them in one burst onto the wire, mirroring the
//! `pcap_sendqueue_alloc` / `pcap_sendqueue_queue` / `pcap_sendqueue_transmit`
//! / `pcap_sendqueue_destroy` surface. The queue is a fixed-size buffer: you
//! reserve a byte capacity and fail if you try to stage more than it holds.

use crate::savefile::PcapPacket;

/// A fixed-capacity queue of packets ready to be transmitted, mirroring
/// libpcap's `pcap_send_queue`.
#[derive(Clone, Debug)]
pub struct Sendqueue {
    /// Reserved capacity in bytes, mirroring `pcap_sendqueue_alloc(memsize)`.
    capacity: u32,
    /// Total bytes queued so far.
    bytes: u32,
    /// The staged packets.
    pkts: Vec<PcapPacket>,
}

impl Sendqueue {
    /// Allocate a send queue with a maximum capacity of `capacity` bytes,
    /// mirroring `pcap_sendqueue_alloc`.
    pub fn new(capacity: u32) -> Self {
        Sendqueue {
            capacity,
            bytes: 0,
            pkts: Vec::new(),
        }
    }

    /// Add a packet to the queue, mirroring `pcap_sendqueue_queue`. The
    /// packet's frame (`data`) bytes count against the queue's capacity.
    /// Returns an error if adding it would exceed the reserved capacity.
    pub fn add(&mut self, pkt: PcapPacket) -> Result<(), String> {
        let need = pkt.data.len() as u32;
        if self.bytes.saturating_add(need) > self.capacity {
            return Err(format!(
                "sendqueue: queue full ({} bytes queued + {} requested exceeds capacity {})",
                self.bytes, need, self.capacity
            ));
        }
        self.bytes += need;
        self.pkts.push(pkt);
        Ok(())
    }

    /// Add a packet by its fields, mirroring `pcap_sendqueue_queue` taking a
    /// single header + data buffer.
    pub fn add_raw(&mut self, ts_sec: u32, ts_frac: u32, data: Vec<u8>) -> Result<(), String> {
        let origlen = data.len() as u32;
        let caplen = data.len() as u32;
        self.add(PcapPacket {
            ts_sec,
            ts_frac,
            caplen,
            origlen,
            pkttype: 0,
            data,
        })
    }

    /// Remove all staged packets, mirroring `pcap_sendqueue_destroy` for a
    /// reused queue (in Rust the queue is dropped in place of an explicit
    /// `destroy`).
    pub fn clear(&mut self) {
        self.pkts.clear();
        self.bytes = 0;
    }

    /// Number of packets queued.
    pub fn len(&self) -> usize {
        self.pkts.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.pkts.is_empty()
    }

    /// Total capacity in bytes.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Bytes queued so far.
    pub fn bytes_queued(&self) -> u32 {
        self.bytes
    }

    /// Bytes of capacity still available.
    pub fn remaining(&self) -> u32 {
        self.capacity.saturating_sub(self.bytes)
    }

    /// Iterate over the staged packets, mirroring the internal queue walk
    /// libpcap performs during `pcap_sendqueue_transmit`.
    pub fn entries(&self) -> &[PcapPacket] {
        &self.pkts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(n: u8) -> PcapPacket {
        PcapPacket {
            ts_sec: 1000 + n as u32,
            ts_frac: 0,
            caplen: n as u32,
            origlen: n as u32,
            pkttype: 0,
            data: vec![n; n as usize],
        }
    }

    #[test]
    fn alloc_and_queue() {
        let mut q = Sendqueue::new(100);
        assert!(q.is_empty());
        assert_eq!(q.capacity(), 100);
        assert_eq!(q.remaining(), 100);

        q.add(pkt(10)).unwrap();
        q.add(pkt(20)).unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q.bytes_queued(), 30);
        assert_eq!(q.remaining(), 70);
    }

    #[test]
    fn capacity_is_enforced() {
        let mut q = Sendqueue::new(10);
        q.add(pkt(6)).unwrap();
        // A second 6-byte packet would push it over the 10-byte capacity.
        assert!(q.add(pkt(6)).is_err());
        assert_eq!(q.len(), 1);
        assert_eq!(q.bytes_queued(), 6);
    }

    #[test]
    fn add_raw_uses_fields() {
        let mut q = Sendqueue::new(64);
        q.add_raw(55, 44, vec![1, 2, 3, 4]).unwrap();
        let e = q.entries()[0].clone();
        assert_eq!(e.ts_sec, 55);
        assert_eq!(e.ts_frac, 44);
        assert_eq!(e.caplen, 4);
        assert_eq!(e.origlen, 4);
        assert_eq!(q.bytes_queued(), 4);
    }

    #[test]
    fn clear_resets_counters() {
        let mut q = Sendqueue::new(100);
        q.add(pkt(10)).unwrap();
        q.add(pkt(20)).unwrap();
        q.clear();
        assert!(q.is_empty());
        assert_eq!(q.bytes_queued(), 0);
        assert_eq!(q.remaining(), 100);
    }

    #[test]
    fn entries_preserves_order() {
        let mut q = Sendqueue::new(100);
        q.add(pkt(1)).unwrap();
        q.add(pkt(2)).unwrap();
        q.add(pkt(3)).unwrap();
        let secs: Vec<u32> = q.entries().iter().map(|p| p.ts_sec).collect();
        assert_eq!(secs, vec![1001, 1002, 1003]);
    }
}
