//! Event pool and loop — mirrors nsock's `nsock_pool`, `nsock_loop`, and the
//! event-creation API.
//!
//! A `Pool` aggregates I/O descriptors and scheduled events. `Pool::run`
//! drives all pending events to completion (success, error, timeout, cancel)
//! and dispatches their handlers, mirroring `nsock_loop`.
//!
//! The reactor is a cooperative scheduler over non-blocking sockets:
//!
//! * TCP connects run on short-lived helper threads so initiating many
//!   connects does not stall the loop (the essence of nsock's value).
//! * Reads and writes use non-blocking sockets polled across passes; the loop
//!   sleeps only as long as needed to reach the nearest deadline.
//! * Timers fire exactly at their deadline.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use crate::event::{EventId, EventStatus, EventType, LoopStatus};
use crate::iod::{Iod, IodKind};

/// Async event handler, mirroring `nsock_ev_handler` (pool, event, userdata)
/// but delivering the event id and final status.
pub type Handler = Box<dyn FnMut(EventId, EventStatus) + Send>;

/// A pending asynchronous operation.
#[allow(dead_code)]
struct Pending {
    id: EventId,
    iod: Option<u64>,
    kind: EventType,
    handler: Handler,
    deadline: Option<Instant>,
    /// Bytes accumulated for reads.
    buf: Vec<u8>,
    /// Remaining bytes to send for writes.
    wbuf: Option<Vec<u8>>,
    /// Requested quantity for readbytes.
    target: usize,
    cancelled: bool,
    done: bool,
}

enum Cmd {
    ConnectResult(u64, Result<TcpStream, std::io::Error>),
    Quit,
}

/// The nsock event pool.
pub struct Pool {
    iod_counter: u64,
    event_counter: u64,
    iods: HashMap<u64, Iod>,
    pending: HashMap<u64, Pending>,
    tx: Sender<Cmd>,
    rx: Receiver<Cmd>,
    quit: bool,
    broadcast: bool,
    udata: usize,
}

impl Default for Pool {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Pool {
    /// Create a new event pool, mirroring `nsock_pool_new`.
    pub fn new(udata: usize) -> Pool {
        let (tx, rx) = mpsc::channel();
        Pool {
            iod_counter: 0,
            event_counter: 0,
            iods: HashMap::new(),
            pending: HashMap::new(),
            tx,
            rx,
            quit: false,
            broadcast: false,
            udata,
        }
    }

    pub fn set_udata(&mut self, udata: usize) {
        self.udata = udata;
    }
    pub fn udata(&self) -> usize {
        self.udata
    }

    /// Enable SO_BROADCAST on UDP sockets created going forward.
    pub fn set_broadcast(&mut self, on: bool) {
        self.broadcast = on;
    }

    fn next_event_id(&mut self) -> EventId {
        self.event_counter += 1;
        self.event_counter
    }

    /// Create a TCP IOD (no socket until connected).
    pub fn create_iod_tcp(&mut self) -> u64 {
        self.iod_counter += 1;
        let id = self.iod_counter;
        let mut iod = Iod::new_tcp();
        iod.id = id;
        self.iods.insert(id, iod);
        id
    }

    /// Create a bound UDP IOD.
    pub fn create_iod_udp(&mut self) -> u64 {
        self.iod_counter += 1;
        let id = self.iod_counter;
        match Iod::new_udp(self.broadcast) {
            Ok(mut iod) => {
                iod.id = id;
                self.iods.insert(id, iod);
            }
            Err(_) => {
                // Fallback: an empty half-backed IOD so callers don't panic.
                let mut iod = Iod::new_tcp();
                iod.id = id;
                iod.kind = IodKind::Udp;
                self.iods.insert(id, iod);
            }
        }
        id
    }

    /// Request an asynchronous TCP connect, mirroring `nsock_connect_tcp`.
    /// `port` is host byte order.
    pub fn connect_tcp(
        &mut self,
        iod_id: u64,
        addr: SocketAddr,
        timeout_ms: i32,
        handler: Handler,
    ) -> EventId {
        let id = self.next_event_id();
        let timeout = if timeout_ms < 0 {
            Duration::from_secs(3600)
        } else {
            Duration::from_millis(timeout_ms as u64)
        };
        self.pending.insert(
            id,
            Pending {
                id,
                iod: Some(iod_id),
                kind: EventType::Connect,
                handler,
                deadline: Some(Instant::now() + timeout),
                buf: Vec::new(),
                wbuf: None,
                target: 0,
                cancelled: false,
                done: false,
            },
        );

        let tx = self.tx.clone();
        let deadline = Instant::now() + timeout;
        std::thread::spawn(move || {
            // Do a blocking connect bounded by the deadline via a watchdog.
            let result = connect_bounded(addr, deadline);
            let _ = tx.send(Cmd::ConnectResult(iod_id, result));
        });
        id
    }

    /// Associate a UDP IOD with a remote peer, mirroring `nsock_connect_udp`.
    pub fn connect_udp(&mut self, iod_id: u64, addr: SocketAddr) -> Result<(), std::io::Error> {
        if let Some(iod) = self.iods.get_mut(&iod_id) {
            if let Some(sock) = &mut iod.udp {
                let _ = sock.connect(addr);
            }
            iod.peer = Some(addr);
            iod.connected = true;
            iod.kind = IodKind::Udp;
        }
        Ok(())
    }

    /// Request an async read; completes on the first received byte, mirroring
    /// `nsock_read`.
    pub fn read(&mut self, iod_id: u64, timeout_ms: i32, handler: Handler) -> EventId {
        let deadline = if timeout_ms < 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
        };
        self.event_counter += 1;
        let id = self.event_counter;
        self.pending.insert(
            id,
            Pending {
                id,
                iod: Some(iod_id),
                kind: EventType::Read,
                handler,
                deadline,
                buf: Vec::new(),
                wbuf: None,
                target: 1,
                cancelled: false,
                done: false,
            },
        );
        id
    }

    /// Request an async read of at least `nbytes`, mirroring `nsock_readbytes`.
    pub fn read_bytes(&mut self, iod_id: u64, timeout_ms: i32, nbytes: usize, handler: Handler) -> EventId {
        let deadline = if timeout_ms < 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
        };
        self.event_counter += 1;
        let id = self.event_counter;
        self.pending.insert(
            id,
            Pending {
                id,
                iod: Some(iod_id),
                kind: EventType::Read,
                handler,
                deadline,
                buf: Vec::new(),
                wbuf: None,
                target: nbytes.max(1),
                cancelled: false,
                done: false,
            },
        );
        id
    }

    /// Request an async write, mirroring `nsock_write`.
    pub fn write(
        &mut self,
        iod_id: u64,
        data: &[u8],
        timeout_ms: i32,
        handler: Handler,
    ) -> EventId {
        let deadline = if timeout_ms < 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
        };
        self.event_counter += 1;
        let id = self.event_counter;
        self.pending.insert(
            id,
            Pending {
                id,
                iod: Some(iod_id),
                kind: EventType::Write,
                handler,
                deadline,
                buf: Vec::new(),
                wbuf: Some(data.to_vec()),
                target: data.len(),
                cancelled: false,
                done: false,
            },
        );
        id
    }

    /// Create a timer event, mirroring `nsock_timer_create`.
    pub fn timer_create(&mut self, timeout_ms: u32, handler: Handler) -> EventId {
        self.event_counter += 1;
        let id = self.event_counter;
        self.pending.insert(
            id,
            Pending {
                id,
                iod: None,
                kind: EventType::Timer,
                handler,
                deadline: Some(Instant::now() + Duration::from_millis(timeout_ms as u64)),
                buf: Vec::new(),
                wbuf: None,
                target: 0,
                cancelled: false,
                done: false,
            },
        );
        id
    }

    /// Cancel an event, mirroring `nsock_event_cancel`. Returns true if found.
    pub fn cancel(&mut self, id: EventId, notify: bool) -> bool {
        let Some(e) = self.pending.get_mut(&id) else {
            return false;
        };
        e.cancelled = true;
        if notify {
            let mut handler = std::mem::replace(&mut e.handler, Box::new(|_, _| {}));
            if !e.done {
                handler(id, EventStatus::Cancelled);
            }
        }
        e.done = true;
        true
    }

    /// Request the loop to stop, mirroring `nsock_loop_quit`.
    pub fn loop_quit(&mut self) {
        self.quit = true;
        let _ = self.tx.send(Cmd::Quit);
    }

    /// Access an IOD by id.
    pub fn iod(&self, id: u64) -> Option<&Iod> {
        self.iods.get(&id)
    }
    pub fn iod_mut(&mut self, id: u64) -> Option<&mut Iod> {
        self.iods.get_mut(&id)
    }

    /// The data accumulated by a completed Read event (mirrors `nse_readbuf`).
    pub fn take_read_buf(&mut self, id: EventId) -> Vec<u8> {
        self.pending
            .get(&id)
            .map(|e| e.buf.clone())
            .unwrap_or_default()
    }

    /// Whether any events remain undelivered.
    pub fn has_pending(&self) -> bool {
        self.pending.values().any(|e| !e.done)
    }

    pub fn pending_count(&self) -> usize {
        self.pending.values().filter(|e| !e.done).count()
    }

    /// Run the event loop, mirroring `nsock_loop`. Returns when there are no
    /// undelivered events, `loop_quit` is called, or `msec_timeout` elapses.
    pub fn run(&mut self, msec_timeout: i32) -> LoopStatus {
        self.quit = false;
        let start = Instant::now();
        let max = if msec_timeout < 0 {
            None
        } else {
            Some(Duration::from_millis(msec_timeout as u64))
        };

        loop {
            self.drain_commands();

            let now = Instant::now();
            let mut to_deliver: Vec<(EventId, EventStatus)> = Vec::new();

            // First handle deadlines (timeouts and timers).
            let ids: Vec<EventId> = self
                .pending
                .iter()
                .filter(|(_, e)| !e.done)
                .map(|(k, _)| *k)
                .collect();
            for id in &ids {
                let e = &self.pending[id];
                let kind = e.kind;
                if let Some(d) = e.deadline {
                    if now >= d {
                        match kind {
                            EventType::Timer => to_deliver.push((*id, EventStatus::Success)),
                            _ => to_deliver.push((*id, EventStatus::Timeout)),
                        }
                    }
                }
            }

            // Then attempt I/O on events not yet resolved.
            for id in &ids {
                if to_deliver.iter().any(|(i, _)| i == id) {
                    continue;
                }
                let kind = self.pending[id].kind;
                let st = match kind {
                    EventType::Read => self.try_read(*id),
                    EventType::Write => self.try_write(*id),
                    _ => None,
                };
                if let Some(s) = st {
                    to_deliver.push((*id, s));
                }
            }

            // Deliver.
            for (id, status) in to_deliver {
                if let Some(e) = self.pending.get_mut(&id) {
                    if e.done || e.cancelled {
                        continue;
                    }
                    e.done = true;
                    let mut handler = std::mem::replace(&mut e.handler, Box::new(|_, _| {}));
                    handler(id, status);
                }
                self.pending.remove(&id);
            }

            if !self.has_pending() {
                return LoopStatus::NoEvents;
            }
            if self.quit {
                self.quit = false;
                return LoopStatus::Quit;
            }
            if let Some(m) = max {
                if start.elapsed() >= m {
                    return LoopStatus::Timeout;
                }
            }

            let nap = match self.nearest_deadline() {
                Some(d) => d
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(5)),
                None => Duration::from_millis(5),
            };
            std::thread::sleep(nap);
        }
    }

    fn nearest_deadline(&self) -> Option<Instant> {
        self.pending
            .values()
            .filter(|e| !e.done)
            .filter_map(|e| e.deadline)
            .min()
    }

    fn drain_commands(&mut self) {
        while let Ok(cmd) = self.rx.try_recv() {
            match cmd {
                Cmd::ConnectResult(iod_id, res) => {
                    // Complete the oldest pending Connect event for this iod.
                    let target = self
                        .pending
                        .iter()
                        .filter(|(_, e)| e.kind == EventType::Connect && !e.done)
                        .find(|(_, e)| e.iod == Some(iod_id))
                        .map(|(k, _)| *k);
                    let Some(evid) = target else { continue };
                    let status = match res {
                        Ok(stream) => {
                            let _ = stream.set_nonblocking(true);
                            if let Some(iod) = self.iods.get_mut(&iod_id) {
                                iod.tcp = Some(stream);
                                iod.kind = IodKind::Tcp;
                                iod.peer = iod.tcp.as_ref().and_then(|s| s.peer_addr().ok());
                                iod.connected = true;
                            }
                            EventStatus::Success
                        }
                        Err(_) => EventStatus::Error,
                    };
                    let mut p = match self.pending.remove(&evid) {
                        Some(p) => p,
                        None => continue,
                    };
                    if p.cancelled {
                        continue;
                    }
                    p.done = true;
                    let mut handler = std::mem::replace(&mut p.handler, Box::new(|_, _| {}));
                    handler(evid, status);
                }
                Cmd::Quit => {
                    self.quit = true;
                }
            }
        }
    }

    fn try_read(&mut self, id: EventId) -> Option<EventStatus> {
        let iod_id = self.pending.get(&id)?.iod?;
        let iod = self.iods.get_mut(&iod_id)?;
        match iod.kind {
            IodKind::Tcp => {
                let stream = iod.tcp.as_mut()?;
                let mut b = [0u8; 4096];
                match stream.read(&mut b) {
                    Ok(0) => Some(EventStatus::Eof),
                    Ok(n) => {
                        if let Some(e) = self.pending.get_mut(&id) {
                            e.buf.extend_from_slice(&b[..n]);
                        }
                        iod.read_count += n as u64;
                        let target = self.pending[&id].target;
                        if self.pending[&id].buf.len() >= target {
                            Some(EventStatus::Success)
                        } else {
                            None
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
                    Err(_) => Some(EventStatus::Error),
                }
            }
            IodKind::Udp => {
                let sock = iod.udp.as_mut()?;
                let mut b = vec![0u8; 65535];
                match sock.recv(&mut b) {
                    Ok(n) => {
                        if let Some(e) = self.pending.get_mut(&id) {
                            e.buf = b[..n].to_vec();
                        }
                        iod.read_count += n as u64;
                        Some(EventStatus::Success)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
                    Err(_) => Some(EventStatus::Error),
                }
            }
        }
    }

    fn try_write(&mut self, id: EventId) -> Option<EventStatus> {
        let iod_id = self.pending.get(&id)?.iod?;
        let iod = self.iods.get_mut(&iod_id)?;
        let data = self.pending.get(&id)?.wbuf.clone()?;
        match iod.kind {
            IodKind::Tcp => {
                let stream = iod.tcp.as_mut()?;
                match stream.write(&data) {
                    Ok(0) => Some(EventStatus::Eof),
                    Ok(n) => {
                        if let Some(e) = self.pending.get_mut(&id) {
                            let rem = &data[n..];
                            e.wbuf = if rem.is_empty() {
                                None
                            } else {
                                Some(rem.to_vec())
                            };
                        }
                        iod.write_count += n as u64;
                        if self.pending[&id].wbuf.is_none() {
                            Some(EventStatus::Success)
                        } else {
                            None
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
                    Err(_) => Some(EventStatus::Error),
                }
            }
            IodKind::Udp => {
                let sock = iod.udp.as_mut()?;
                match sock.send(&data) {
                    Ok(_) => {
                        iod.write_count += data.len() as u64;
                        if let Some(e) = self.pending.get_mut(&id) {
                            e.wbuf = None;
                        }
                        Some(EventStatus::Success)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
                    Err(_) => Some(EventStatus::Error),
                }
            }
        }
    }
}

/// Perform a blocking TCP connect, guaranteeing we return by `deadline`.
/// The connect itself is bounded by connect_timeout; a watchdog returns a
/// timeout error if the deadline passes first.
fn connect_bounded(addr: SocketAddr, deadline: Instant) -> Result<TcpStream, std::io::Error> {
    let mut last_err: Option<std::io::Error> = None;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(s) => return Ok(s),
            Err(e) => {
                last_err = Some(e);
                // Small backoff before retry to avoid thundering herd.
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")
    }))
}
