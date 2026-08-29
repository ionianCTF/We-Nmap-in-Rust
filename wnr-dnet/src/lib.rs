//! WNR — We Nmap in Rust: low-level raw networking library.
//!
//! A from-scratch Rust port of **libdnet**, the low-level networking library
//! Nmap distributes for interface enumeration, link-layer hardware address
//! handling, and related raw networking routines. The official
//! [libdnet](https://github.com/ofalk/libdnet) repository is used purely as a
//! behavioral reference; every implementation here is written natively in
//! safe Rust.
//!
//! # Modules
//!
//! * [`addr`] — polymorphic address type (`struct addr`)
//! * [`eth`] — Ethernet link-layer header / MAC address handling
//! * [`intf`] — network interface enumeration (`struct intf_entry`)
//! * [`arp`] — ARP message structures and cache
//!
//! # Example
//!
//! ```no_run
//! use wnr_dnet::intf::interface_list;
//!
//! let ifaces = interface_list();
//! for i in ifaces {
//!     println!("{} {} ({})", i.name, i.addr, i.intf_type);
//! }
//! ```

pub mod addr;
pub mod arp;
pub mod eth;
pub mod intf;

pub use addr::Addr;
pub use eth::EthAddr;
pub use intf::{IntfEntry, interface_list};
