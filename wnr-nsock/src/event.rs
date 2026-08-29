//! Event types and statuses — mirrors nsock's `enum nse_type` and
//! `enum nse_status`.

use std::fmt;

/// The kinds of asynchronous events, mirroring `enum nse_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    Connect,
    Read,
    Write,
    Timer,
    #[cfg(feature = "pcap")]
    PcapRead,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Connect => "CONNECT",
            EventType::Read => "READ",
            EventType::Write => "WRITE",
            EventType::Timer => "TIMER",
            #[cfg(feature = "pcap")]
            EventType::PcapRead => "PCAP_READ",
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The outcome of an asynchronous event, mirroring `enum nse_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventStatus {
    Success,
    Error,
    Timeout,
    Cancelled,
    Kill,
    Eof,
}

impl EventStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventStatus::Success => "SUCCESS",
            EventStatus::Error => "ERROR",
            EventStatus::Timeout => "TIMEOUT",
            EventStatus::Cancelled => "CANCELLED",
            EventStatus::Kill => "KILL",
            EventStatus::Eof => "EOF",
        }
    }
}

impl fmt::Display for EventStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Loop exit status returned by `Pool::run`, mirroring `nsock_loopstatus`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopStatus {
    /// No events were processed in this pass.
    NoEvents,
    /// A timeout value was supplied and elapsed before completion.
    Timeout,
    /// A fatal error occurred.
    Error,
    /// `loop_quit` was called.
    Quit,
}

/// An event id, unique within a pool.
pub type EventId = u64;
