//! WNR — We Nmap in Rust: raw network packet capturing and sniffing library.
//!
//! A from-scratch Rust port of the packet-capture machinery **libpcap** (and
//! its Windows fork **Npcap**), the engine behind every packet Nmap receives.
//! The official
//! [libpcap](https://github.com/the-tcpdump-group/libpcap) /
//! [Npcap](https://npcap.com/) code is used purely as a behavioral reference;
//! every implementation here is written natively in safe Rust.
//!
//! # Modules
//!
//! * [`bpf`] — a full BPF virtual machine + a small filter-expression compiler
//! * [`datalink`] — DLT_* link-layer type constants
//! * [`capture`] — `Capture` handle (live + offline) and device enumeration
//! * [`savefile`] — reading/writing pcap savefiles
//! * [`raw`] — low-level raw-socket live-capture backend (Unix)
//!
//! # Example
//!
//! ```no_run
//! use wnr_pcap::Capture;
//!
//! let dev = wnr_pcap::lookupdev().unwrap();
//! let mut cap = Capture::open_live(&dev, 65535, true, 1000).unwrap();
//! cap.set_filter("tcp port 80").unwrap();
//! if let Some((hdr, frame)) = cap.next_packet().unwrap() {
//!     println!("captured {} bytes", hdr.caplen);
//! }
//! ```

pub mod bpf;
pub mod capture;
pub mod datalink;
pub mod raw;
pub mod savefile;

pub use capture::{Capture, Device, PacketHeader, findalldevs, lookupdev, read_all};
