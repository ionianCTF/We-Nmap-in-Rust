//! I/O descriptors — mirrors nsock's opaque `nsock_iod`.
//!
//! An I/O descriptor wraps one socket (TCP or UDP) plus bookkeeping (counters,
//! peer/communication info). A single IOD supports one event at a time in a
//! "reasonable" order, exactly as nsock documents.

use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// What kind of socket a given IOD wraps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IodKind {
    Tcp,
    Udp,
}

/// An I/O descriptor. Mirrors `struct niod` (opaque in the original).
pub struct Iod {
    pub id: u64,
    /// The underlying TCP stream (None until connected).
    pub tcp: Option<TcpStream>,
    /// The underlying UDP socket, if any.
    pub udp: Option<UdpSocket>,
    pub kind: IodKind,
    /// Connected / peer address (communication info).
    pub peer: Option<SocketAddr>,
    /// Hostname used for SNI / labeling.
    pub hostname: Option<String>,
    /// Bytes read through this IOD.
    pub read_count: u64,
    /// Bytes written through this IOD.
    pub write_count: u64,
    /// Whether this IOD has its socket connected.
    pub connected: bool,
    /// User-settable handle.
    pub udata: usize,
}

impl std::fmt::Debug for Iod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Iod")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("peer", &self.peer)
            .field("connected", &self.connected)
            .field("read_count", &self.read_count)
            .field("write_count", &self.write_count)
            .finish()
    }
}

impl Iod {
    /// Create a TCP IOD with no socket yet (assigned on connect).
    pub fn new_tcp() -> Iod {
        Iod {
            id: 0,
            tcp: None,
            udp: None,
            kind: IodKind::Tcp,
            peer: None,
            hostname: None,
            read_count: 0,
            write_count: 0,
            connected: false,
            udata: 0,
        }
    }

    /// Create a UDP IOD bound to an ephemeral port, with optional broadcast.
    pub fn new_udp(broadcast: bool) -> std::io::Result<Iod> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        let _ = sock.set_nonblocking(true);
        if broadcast {
            let _ = sock.set_broadcast(true);
        }
        Ok(Iod {
            id: 0,
            tcp: None,
            udp: Some(sock),
            kind: IodKind::Udp,
            peer: None,
            hostname: None,
            read_count: 0,
            write_count: 0,
            connected: false,
            udata: 0,
        })
    }

    /// The numeric id of this IOD within its pool, mirroring `nsock_iod_id`.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Build an IOD wrapping an already-connected TCP stream (mirrors the
    /// `iod_new2` path that adopts an existing socket).
    pub fn from_tcp_stream(stream: TcpStream, id: u64) -> Iod {
        let _ = stream.set_nonblocking(true);
        let peer = stream.peer_addr().ok();
        Iod {
            id,
            tcp: Some(stream),
            udp: None,
            kind: IodKind::Tcp,
            peer,
            hostname: None,
            read_count: 0,
            write_count: 0,
            connected: peer.is_some(),
            udata: 0,
        }
    }

    /// Build a UDP IOD wrapping an existing socket (mirrors `iod_new2`).
    pub fn from_udp_socket(sock: UdpSocket, id: u64) -> Iod {
        let _ = sock.set_nonblocking(true);
        Iod {
            id,
            tcp: None,
            udp: Some(sock),
            kind: IodKind::Udp,
            peer: None,
            hostname: None,
            read_count: 0,
            write_count: 0,
            connected: false,
            udata: 0,
        }
    }

    /// The raw OS socket descriptor, if valid (mirrors `nsock_iod_get_sd`).
    #[cfg(unix)]
    pub fn fd(&self) -> i32 {
        use std::os::unix::io::AsRawFd;
        match &self.tcp {
            Some(s) => s.as_raw_fd(),
            None => match &self.udp {
                Some(u) => u.as_raw_fd(),
                None => -1,
            },
        }
    }

    /// Set a read/write timeout hint.
    pub fn set_timeout(&self, dur: Duration) -> std::io::Result<()> {
        if let Some(t) = &self.tcp {
            t.set_read_timeout(Some(dur))?;
            t.set_write_timeout(Some(dur))?;
        }
        if let Some(u) = &self.udp {
            u.set_read_timeout(Some(dur))?;
            u.set_write_timeout(Some(dur))?;
        }
        Ok(())
    }

    /// The local address of this IOD's socket, if bound.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        if let Some(t) = &self.tcp {
            t.local_addr().ok()
        } else if let Some(u) = &self.udp {
            u.local_addr().ok()
        } else {
            None
        }
    }

    /// The remote address, if we have a peer.
    pub fn remote_ip(&self) -> Option<IpAddr> {
        self.peer.map(|p| p.ip())
    }
}
