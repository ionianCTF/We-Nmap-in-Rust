//! Live raw-socket capture backend.
//!
//! On Linux this opens an `AF_PACKET` socket to receive raw link-layer frames.
//! On macOS/BSD the net-raw approach differs; a stub is provided so the module
//! compiles everywhere. On Windows, live capture requires the Npcap driver and
//! is intentionally not implemented here (see the `Capture::open_live` error).

use std::io;

/// Packet direction filter, mirroring libpcap's `PCAP_D_IN` / `PCAP_D_OUT` /
/// `PCAP_D_INOUT` modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Capture only packets sent to this host.
    In,
    /// Capture only packets sent by this host.
    Out,
    /// Capture packets travelling in both directions (default).
    InOut,
}

/// Linux `sll_pkttype` values — mirrors `<linux/if_packet.h>`.
pub const PKT_HOST: u16 = 0;
pub const PKT_BROADCAST: u16 = 1;
pub const PKT_MULTICAST: u16 = 2;
pub const PKT_OTHERHOST: u16 = 3;
pub const PKT_OUTGOING: u16 = 4;

/// Whether a packet with type `pkttype` is admitted by `dir`.
pub fn pkttype_matches_dir(pkttype: u16, dir: Direction) -> bool {
    match dir {
        Direction::In => pkttype != PKT_OUTGOING,
        Direction::Out => pkttype == PKT_OUTGOING,
        Direction::InOut => true,
    }
}

/// A handle to a live raw packet socket.
#[cfg(target_os = "linux")]
pub struct RawCapture {
    fd: i32,
    ifindex: i32,
    direction: Direction,
    /// Reusable read buffer sized to snaplen.
    buf: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl RawCapture {
    /// Open a raw socket on `device` and bind to it.
    pub fn open(
        device: &str,
        snaplen: u32,
        promisc: bool,
        timeout_ms: i32,
    ) -> io::Result<RawCapture> {
        #[cfg(target_os = "linux")]
        {
            let _ = &promisc;
            let _ = &timeout_ms;
            let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // Bind to the interface by name.
            let c_name = std::ffi::CString::new(device).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "bad interface name")
            })?;
            let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
            if ifindex == 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }
            let addr = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: 0,
                sll_ifindex: ifindex as i32,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };
            let rc = unsafe {
                libc::bind(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }
            // Enable non-blocking so `next_packet` can signal "no data yet".
            unsafe {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
            Ok(RawCapture {
                fd,
                ifindex: ifindex as i32,
                direction: Direction::InOut,
                buf: vec![0u8; snaplen.max(64) as usize],
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (device, snaplen, promisc, timeout_ms);
            // BSD/macOS raw capture via BPF devices is not yet implemented.
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "live raw capture not implemented on this platform",
            ))
        }
    }

    /// Read the next raw frame. Returns `Ok(None)` while no frame is ready
    /// (i.e. the non-blocking read returned WouldBlock). Frames filtered out
    /// by the configured [`Direction`] are skipped internally, so `Ok(None)`
    /// always means "no matching frame ready yet".
    pub fn next_packet(&mut self) -> io::Result<Option<crate::savefile::PcapPacket>> {
        loop {
            let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut fromlen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    self.fd,
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf.len(),
                    0,
                    &mut from as *mut _ as *mut libc::sockaddr,
                    &mut fromlen,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(err);
            }
            let n = n as usize;
            let pkttype = from.sll_pkttype as u16;
            if !pkttype_matches_dir(pkttype, self.direction) {
                continue;
            }
            return Ok(Some(crate::savefile::PcapPacket {
                ts_sec: 0,
                ts_frac: 0,
                caplen: n as u32,
                origlen: n as u32,
                pkttype,
                data: self.buf[..n].to_vec(),
            }));
        }
    }

    /// Set the packet direction filter.
    pub fn set_direction(&mut self, dir: Direction) {
        self.direction = dir;
    }

    /// Toggle non-blocking mode.
    pub fn set_nonblock(&mut self, nb: bool) -> io::Result<()> {
        let fl = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        let new = if nb { fl | libc::O_NONBLOCK } else { fl & !libc::O_NONBLOCK };
        if unsafe { libc::fcntl(self.fd, libc::F_SETFL, new) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Poll per-interface packet statistics (Linux `SO_PACKET_STATISTICS`).
    /// Returns `(packets_received, packets_dropped)`.
    pub fn poll_stats(&self) -> io::Result<(u64, u64)> {
        let mut raw = [0u8; 64];
        let mut len = raw.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                raw.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let packets = u32::from_ne_bytes(raw[0..4].try_into().unwrap_or([0; 4])) as u64;
        let drops = u32::from_ne_bytes(raw[4..8].try_into().unwrap_or([0; 4])) as u64;
        Ok((packets, drops))
    }

    /// Send a raw frame out of the bound interface, mirroring
    /// `pcap_inject` / `pcap_sendpacket`. Returns bytes written.
    pub fn send_frame(&self, data: &[u8]) -> io::Result<usize> {
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: 0,
            sll_ifindex: self.ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let n = unsafe {
            libc::sendto(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawCapture {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

/// Windows live capture backend.
///
/// Raw IPv4 sockets are used to capture live traffic without the Npcap driver:
/// we open `socket(AF_INET, SOCK_RAW, IPPROTO_IP)`, bind it to the chosen
/// interface's IPv4 address, and (when `promisc` is set) enable `SIO_RCVALL`
/// so the kernel delivers every packet transiting the interface. This yields
/// raw IP datagrams (with the IP header present), so the capture's datalink
/// type is `DLT_RAW`. Requires Administrator privileges to enable `SIO_RCVALL`.
#[cfg(windows)]
pub struct RawCapture {
    sock: windows_sys::Win32::Networking::WinSock::SOCKET,
    buf: Vec<u8>,
}

#[cfg(windows)]
impl RawCapture {
    /// Open a raw IPv4 socket bound to the interface named `device`.
    pub fn open(
        device: &str,
        snaplen: u32,
        promisc: bool,
        timeout_ms: i32,
    ) -> io::Result<RawCapture> {
        use windows_sys::Win32::Networking::WinSock as ws;

        ensure_wsa_started();

        let ipv4 = interface_ipv4(device);
        let Some(ip) = ipv4 else {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no IPv4 address for interface '{}'", device),
            ));
        };

        let sock = unsafe { ws::socket(ws::AF_INET as i32, ws::SOCK_RAW, ws::IPPROTO_IP) };
        if sock == ws::INVALID_SOCKET {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cannot open raw socket (is this process running as Administrator?); \
                 live capture without Npcap requires Admin rights",
            ));
        }

        let mut sin: ws::SOCKADDR_IN = unsafe { std::mem::zeroed() };
        sin.sin_family = ws::AF_INET as _;
        sin.sin_port = 0;
        sin.sin_addr.S_un.S_addr = u32::from_le_bytes(ip);

        let rc = unsafe {
            ws::bind(
                sock,
                &sin as *const ws::SOCKADDR_IN as *const ws::SOCKADDR,
                std::mem::size_of::<ws::SOCKADDR_IN>() as i32,
            )
        };
        if rc == ws::SOCKET_ERROR {
            unsafe { ws::closesocket(sock) };
            return Err(io::Error::last_os_error());
        }

        // Capture all packets transiting the interface when promisc is requested.
        if promisc {
            let one: u32 = 1;
            let r = unsafe { ws::ioctlsocket(sock, ws::SIO_RCVALL as i32, &one as *const _ as *mut u32) };
            if r == ws::SOCKET_ERROR {
                unsafe { ws::closesocket(sock) };
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "SIO_RCVALL failed (raw socket capture-all needs Administrator privileges)",
                ));
            }
        }

        // Non-blocking so `next_packet` can report "no data yet".
        let nb: u32 = 1;
        unsafe { ws::ioctlsocket(sock, ws::FIONBIO, &nb as *const _ as *mut u32) };

        let _ = timeout_ms;
        Ok(RawCapture {
            sock,
            buf: vec![0u8; snaplen.max(64) as usize],
        })
    }

    /// Read the next raw IP datagram. Returns `Ok(None)` while no frame is
    /// ready (non-blocking read returned WouldBlock).
    pub fn next_packet(&mut self) -> io::Result<Option<crate::savefile::PcapPacket>> {
        use windows_sys::Win32::Networking::WinSock as ws;

        let n = unsafe {
            ws::recv(
                self.sock,
                self.buf.as_mut_ptr(),
                self.buf.len() as i32,
                0,
            )
        };
        if n == ws::SOCKET_ERROR {
            let err = unsafe { ws::WSAGetLastError() };
            if err == ws::WSAEWOULDBLOCK {
                return Ok(None);
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        if n == 0 {
            return Ok(None);
        }
        let n = n as usize;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Ok(Some(crate::savefile::PcapPacket {
            ts_sec: now.as_secs() as u32,
            ts_frac: now.subsec_micros(),
            caplen: n as u32,
            origlen: n as u32,
            pkttype: 0,
            data: self.buf[..n].to_vec(),
        }))
    }

    /// No-op on Windows; raw-socket capture delivers both directions.
    pub fn set_direction(&mut self, _dir: Direction) {}

    /// Toggle non-blocking mode via `FIONBIO`.
    pub fn set_nonblock(&mut self, nb: bool) -> io::Result<()> {
        use windows_sys::Win32::Networking::WinSock as ws;
        let v: u32 = if nb { 1 } else { 0 };
        let r = unsafe { ws::ioctlsocket(self.sock, ws::FIONBIO, &v as *const _ as *mut u32) };
        if r == ws::SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// No statistics are exposed without the Npcap driver; return zeros.
    pub fn poll_stats(&self) -> io::Result<(u64, u64)> {
        Ok((0, 0))
    }

    /// The Windows raw-socket backend has no fixed destination to inject
    /// toward, so injection is reported as unsupported.
    pub fn send_frame(&self, _data: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "injection is unsupported on the raw-socket Windows backend",
        ))
    }
}

#[cfg(windows)]
impl Drop for RawCapture {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Networking::WinSock::closesocket(self.sock);
        }
    }
}

#[cfg(windows)]
fn ensure_wsa_started() {
    use std::sync::Once;
    use windows_sys::Win32::Networking::WinSock as ws;
    static START: Once = Once::new();
    START.call_once(|| {
        let mut data: ws::WSADATA = unsafe { std::mem::zeroed() };
        unsafe { ws::WSAStartup(0x0202, &mut data) };
    });
}

/// Find the first IPv4 address (as octets) for the interface `device`.
#[cfg(windows)]
fn interface_ipv4(device: &str) -> Option<[u8; 4]> {
    for e in wnr_dnet::intf::interface_list() {
        if e.name == device {
            if let Some(ip) = e.addr.to_ipv4() {
                return Some(ip.octets());
            }
            for a in &e.alias_addrs {
                if let Some(ip) = a.to_ipv4() {
                    return Some(ip.octets());
                }
            }
        }
    }
    None
}

/// BSD/macOS live capture via BPF devices is not yet implemented; a stub
/// keeps `Capture` compiling on those platforms until the backend lands.
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub struct RawCapture {
    _private: (),
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
impl RawCapture {
    pub fn open(
        _device: &str,
        _snaplen: u32,
        _promisc: bool,
        _timeout_ms: i32,
    ) -> io::Result<RawCapture> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "live raw capture not implemented on this platform",
        ))
    }

    pub fn next_packet(&mut self) -> io::Result<Option<crate::savefile::PcapPacket>> {
        Ok(None)
    }

    pub fn set_direction(&mut self, _dir: Direction) {}
    pub fn set_nonblock(&mut self, _nb: bool) -> io::Result<()> {
        Ok(())
    }
    pub fn poll_stats(&self) -> io::Result<(u64, u64)> {
        Ok((0, 0))
    }
    pub fn send_frame(&self, _data: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "live raw capture not implemented on this platform",
        ))
    }
}

/// Unsupported placeholder for any other platform so the module compiles.
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "windows"
)))]
pub struct RawCapture {
    _private: (),
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "windows"
)))]
impl RawCapture {
    pub fn open(
        _device: &str,
        _snaplen: u32,
        _promisc: bool,
        _timeout_ms: i32,
    ) -> io::Result<RawCapture> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "live capture requires Npcap on this platform",
        ))
    }

    pub fn next_packet(&mut self) -> io::Result<Option<crate::savefile::PcapPacket>> {
        Ok(None)
    }

    pub fn set_direction(&mut self, _dir: Direction) {}
    pub fn set_nonblock(&mut self, _nb: bool) -> io::Result<()> {
        Ok(())
    }
    pub fn poll_stats(&self) -> io::Result<(u64, u64)> {
        Ok((0, 0))
    }
    pub fn send_frame(&self, _data: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "live capture requires Npcap on this platform",
        ))
    }
}
