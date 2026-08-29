//! WNR — We Nmap in Rust: asynchronous network I/O sockets library.
//!
//! A from-scratch Rust port of **Nsock**, Nmap's internal library for safe and
//! efficient asynchronous network I/O. Nsock is the concurrency backbone that
//! lets Nmap parallelize thousands of scan probes in a single event loop
//! without manual callback bookkeeping or data races. The official
//! [nsock sources](https://github.com/nmap/nmap/tree/master/nsock) are used
//! purely as a behavioral reference; everything here is Rust.
//!
//! # Model
//!
//! * [`iod::Iod`] — I/O descriptor (one socket)
//! * [`pool::Pool`] — aggregates IODs + events, drives the event loop
//! * [`event`] — event types / statuses / loop status
//!
//! # Example (parallel connect scan)
//!
//! ```no_run
//! use wnr_nsock::pool::Pool;
//! use wnr_nsock::event::{EventStatus};
//! use std::net::SocketAddr;
//!
//! let mut pool = Pool::new(0);
//! let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
//! let iod = pool.create_iod_tcp();
//! pool.connect_tcp(iod, target, 3000, Box::new(|_, status| {
//!     match status {
//!         EventStatus::Success => println!("open"),
//!         _ => println!("closed/filtered"),
//!     }
//! }));
//! pool.run(5000);
//! ```

pub mod event;
pub mod iod;
pub mod pool;

pub use event::{EventId, EventStatus, EventType, LoopStatus};
pub use iod::{Iod, IodKind};
pub use pool::{Handler, Pool};
