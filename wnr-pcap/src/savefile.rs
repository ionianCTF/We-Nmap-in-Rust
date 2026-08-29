//! pcap savefile reading and writing — mirrors libpcap's `pcap_dump_*` /
//! `pcap_open_offline` support for the classic little-endian pcap format.
//!
//! Layout: a 24-byte global header followed by a series of 16-byte packet
//! records (timestamp seconds, timestamp micro/nanos, captured length,
//! original length, then the frame bytes).

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

/// Magic number for the classic, little-endian, microsecond pcap file.
pub const PCAP_MAGIC_NUMBER: u32 = 0xa1b2_c3d4;
/// Magic number for the little-endian, nanosecond pcap file.
pub const PCAP_MAGIC_NUMBER_NANO: u32 = 0xa1b2_3c4d;
/// Big-endian variants (byte-swapped magic).
pub const PCAP_MAGIC_NUMBER_BE: u32 = 0xd4c3_b2a1;
pub const PCAP_MAGIC_NUMBER_NANO_BE: u32 = 0x4d3c_b2a1;

/// The pcap global header — mirrors `struct pcap_file_header`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapFileHeader {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub linktype: u32,
}

impl PcapFileHeader {
    pub fn new(snaplen: u32, linktype: u32) -> Self {
        PcapFileHeader {
            magic: PCAP_MAGIC_NUMBER,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen,
            linktype,
        }
    }

    /// Whether this header uses nanosecond precision timestamps.
    pub fn is_nano(&self) -> bool {
        matches!(
            self.magic,
            PCAP_MAGIC_NUMBER_NANO | PCAP_MAGIC_NUMBER_NANO_BE
        )
    }

    /// Whether the fields must be byte-swapped (big-endian capture).
    pub fn needs_swap(&self) -> bool {
        matches!(
            self.magic,
            PCAP_MAGIC_NUMBER_BE | PCAP_MAGIC_NUMBER_NANO_BE
        )
    }
}

/// A single captured packet record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcapPacket {
    /// Timestamp seconds.
    pub ts_sec: u32,
    /// Timestamp sub-seconds (microseconds or nanoseconds per header).
    pub ts_frac: u32,
    /// Captured length (bytes stored).
    pub caplen: u32,
    /// Original length on the wire.
    pub origlen: u32,
    /// Packet direction / type hint (see [`crate::raw::pkttype`]). Zero on
    /// captures (offline savefiles) that do not carry this information.
    pub pkttype: u16,
    /// Frame data.
    pub data: Vec<u8>,
}

/// A reader over a pcap savefile.
pub struct SavefileReader {
    header: PcapFileHeader,
    reader: BufReader<File>,
}

impl SavefileReader {
    /// Open a pcap file for reading.
    pub fn open(path: &Path) -> std::io::Result<SavefileReader> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut raw = [0u8; 24];
        reader.read_exact(&mut raw)?;

        let magic = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let swap = matches!(
            magic,
            PCAP_MAGIC_NUMBER_BE | PCAP_MAGIC_NUMBER_NANO_BE
        ) || !matches!(
            magic,
            PCAP_MAGIC_NUMBER | PCAP_MAGIC_NUMBER_NANO | PCAP_MAGIC_NUMBER_BE | PCAP_MAGIC_NUMBER_NANO_BE
        );
        if !matches!(
            magic,
            PCAP_MAGIC_NUMBER | PCAP_MAGIC_NUMBER_NANO | PCAP_MAGIC_NUMBER_BE | PCAP_MAGIC_NUMBER_NANO_BE
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a pcap file (bad magic)",
            ));
        }

        let read_u16 = |b: &[u8]| -> u16 {
            if swap {
                u16::from_be_bytes([b[0], b[1]])
            } else {
                u16::from_le_bytes([b[0], b[1]])
            }
        };
        let read_u32 = |b: &[u8]| -> u32 {
            if swap {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            }
        };

        let header = PcapFileHeader {
            magic,
            version_major: read_u16(&raw[4..6]),
            version_minor: read_u16(&raw[6..8]),
            thiszone: read_u32(&raw[8..12]) as i32,
            sigfigs: read_u32(&raw[12..16]),
            snaplen: read_u32(&raw[16..20]),
            linktype: read_u32(&raw[20..24]),
        };

        Ok(SavefileReader { header, reader })
    }

    pub fn header(&self) -> &PcapFileHeader {
        &self.header
    }

    /// Read the next packet record, if any. Returns Ok(None) on clean EOF.
    pub fn next_packet(&mut self) -> std::io::Result<Option<PcapPacket>> {
        let mut rh = [0u8; 16];
        match self.reader.read_exact(&mut rh) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let r = &rh;
        let swap = self.header.needs_swap();
        let ru32 = |b: &[u8]| -> u32 {
            if swap {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            }
        };
        let ts_sec = ru32(&r[0..4]);
        let ts_frac = ru32(&r[4..8]);
        let caplen = ru32(&r[8..12]);
        let origlen = ru32(&r[12..16]);

        if caplen > self.header.snaplen && !self.header.is_nano() && caplen > 0x100_0000 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "corrupt controller (caplen too large)",
            ));
        }
        let mut data = vec![0u8; caplen as usize];
        self.reader.read_exact(&mut data)?;

        Ok(Some(PcapPacket {
            ts_sec,
            ts_frac,
            caplen,
            origlen,
            pkttype: 0,
            data,
        }))
    }
}

/// A writer that appends packets to a pcap savefile.
pub struct SavefileWriter {
    header: PcapFileHeader,
    writer: BufWriter<File>,
}

impl SavefileWriter {
    /// Create (or truncate) a pcap file for writing.
    pub fn create(path: &Path, snaplen: u32, linktype: u32) -> std::io::Result<SavefileWriter> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        let header = PcapFileHeader::new(snaplen, linktype);
        let mut raw = [0u8; 24];
        raw[0..4].copy_from_slice(&header.magic.to_le_bytes());
        raw[4..6].copy_from_slice(&header.version_major.to_le_bytes());
        raw[6..8].copy_from_slice(&header.version_minor.to_le_bytes());
        raw[8..12].copy_from_slice(&header.thiszone.to_le_bytes());
        raw[12..16].copy_from_slice(&header.sigfigs.to_le_bytes());
        raw[16..20].copy_from_slice(&header.snaplen.to_le_bytes());
        raw[20..24].copy_from_slice(&header.linktype.to_le_bytes());
        writer.write_all(&raw)?;
        Ok(SavefileWriter { header, writer })
    }

    pub fn header(&self) -> &PcapFileHeader {
        &self.header
    }

    /// Write a packet record. The caller truncates/limits to snaplen.
    pub fn write_packet(&mut self, ts_sec: u32, ts_frac: u32, data: &[u8]) -> std::io::Result<()> {
        let caplen = data.len().min(self.header.snaplen as usize) as u32;
        let origlen = data.len() as u32;
        let mut rh = [0u8; 16];
        rh[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        rh[4..8].copy_from_slice(&ts_frac.to_le_bytes());
        rh[8..12].copy_from_slice(&caplen.to_le_bytes());
        rh[12..16].copy_from_slice(&origlen.to_le_bytes());
        self.writer.write_all(&rh)?;
        self.writer.write_all(&data[..caplen as usize])?;
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wnr_test_{}.pcap", std::process::id()));
        {
            let mut w = SavefileWriter::create(&path, 65535, 1).unwrap();
            w.write_packet(1000, 500, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
            w.write_packet(1001, 0, &[1, 2, 3, 4, 5]).unwrap();
            w.flush().unwrap();
        }
        {
            let mut r = SavefileReader::open(&path).unwrap();
            assert_eq!(r.header().linktype, 1);
            assert_eq!(r.header().snaplen, 65535);
            let p1 = r.next_packet().unwrap().unwrap();
            assert_eq!(p1.data, vec![0xde, 0xad, 0xbe, 0xef]);
            assert_eq!(p1.ts_sec, 1000);
            let p2 = r.next_packet().unwrap().unwrap();
            assert_eq!(p2.caplen, 5);
            assert!(r.next_packet().unwrap().is_none());
        }
        let _ = std::fs::remove_file(&path);
    }
}
