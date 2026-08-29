//! End-to-end tests of the nsock event loop against a real local TCP server.

use std::io::{Read, Write};
use std::net::TcpListener;

use wnr_nsock::event::EventStatus;
use wnr_nsock::pool::Pool;

#[test]
fn connect_write_read_roundtrip() {
    // Start a local echo server.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 256];
        let n = sock.read(&mut buf).unwrap();
        sock.write_all(&buf[..n]).unwrap();
    });

    let mut pool = Pool::new(0);
    let iod = pool.create_iod_tcp();

    // Connect.
    let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let c1 = connected.clone();
    let conn = pool.connect_tcp(
        iod,
        addr,
        3000,
        Box::new(move |_, status| {
            if status == EventStatus::Success {
                c1.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }),
    );

    // Write after connect. Since we can't chain easily, do connect first.
    pool.run(-1);
    assert!(
        connected.load(std::sync::atomic::Ordering::SeqCst),
        "connect should succeed"
    );
    pool.cancel(conn, false);

    // Now write the payload.
    let written = pool.write(
        iod,
        b"hello nsock",
        3000,
        Box::new(|_, status| assert_eq!(status, EventStatus::Success)),
    );
    pool.run(-1);
    pool.cancel(written, false);

    // And read the echoed data back.
    let read = pool.read_bytes(
        iod,
        3000,
        10,
        Box::new(|_, status| assert_eq!(status, EventStatus::Success)),
    );
    pool.run(-1);
    pool.cancel(read, false);

    server.join().unwrap();
}

#[test]
fn timer_fires() {
    let mut pool = Pool::new(0);
    let fired = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let f = fired.clone();
    pool.timer_create(
        50,
        Box::new(move |_, status| {
            if status == EventStatus::Success {
                f.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }),
    );
    pool.run(1000);
    assert_eq!(fired.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn readlines_gets_line() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.write_all(b"hello world\n").unwrap();
    });

    let mut pool = Pool::new(0);
    let iod = pool.create_iod_tcp();
    pool.connect_tcp(
        iod,
        addr,
        3000,
        Box::new(move |_, status| assert_eq!(status, EventStatus::Success)),
    );
    pool.run(-1);

    let line = pool.readlines(
        iod,
        3000,
        256,
        Box::new(|_, status| assert_eq!(status, EventStatus::Success)),
    );
    pool.run(-1);
    let buf = pool.take_read_buf(line);
    assert_eq!(buf, b"hello world\n");
    assert_eq!(pool.iod(iod).unwrap().id(), iod);
    server.join().unwrap();
}

#[test]
fn write_fmt_and_printf_roundtrip() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 64];
        let n = sock.read(&mut buf).unwrap();
        sock.write_all(&buf[..n]).unwrap();
    });

    let mut pool = Pool::new(0);
    let iod = pool.create_iod_tcp();
    pool.connect_tcp(
        iod,
        addr,
        3000,
        Box::new(move |_, status| assert_eq!(status, EventStatus::Success)),
    );
    pool.run(-1);

    let n = 42;
    pool.write_fmt(
        iod,
        format_args!("value={}\n", n),
        3000,
        Box::new(|_, status| assert_eq!(status, EventStatus::Success)),
    );
    pool.run(-1);
    pool.printf(
        iod,
        "literal",
        3000,
        Box::new(|_, status| assert_eq!(status, EventStatus::Success)),
    );
    pool.run(-1);
    server.join().unwrap();
}

#[test]
fn delete_iod_kills_pending_events() {
    let mut pool = Pool::new(0);
    let iod = pool.create_iod_tcp();
    let killed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let k = killed.clone();
    // Schedule a read that will never complete (no connection).
    pool.read(
        iod,
        60000,
        Box::new(move |_, status| {
            if status == EventStatus::Kill {
                k.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }),
    );
    assert!(pool.delete_iod(iod), "iod should exist");
    assert!(pool.iod(iod).is_none(), "iod should be gone");
    // No pending events remain once the iod's events were killed.
    assert!(!pool.has_pending());
    let _ = pool.run(100);
    assert!(killed.load(std::sync::atomic::Ordering::SeqCst), "kill fired");
}

#[test]
fn send_udp_datagram() {
    use std::net::UdpSocket;
    let recv = UdpSocket::bind("127.0.0.1:0").unwrap();
    let r = recv.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        let (n, _) = recv.recv_from(&mut buf).unwrap();
        buf[..n].to_vec()
    });

    let mut pool = Pool::new(0);
    let iod = pool.create_iod_udp();
    pool.send_udp(
        iod,
        r,
        b"ping",
        3000,
        Box::new(|_, status| assert_eq!(status, EventStatus::Success)),
    );
    pool.run(-1);
    assert_eq!(server.join().unwrap(), b"ping");
}

#[test]
fn create_iod_tcp_from_wraps_stream() {
    use std::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.write_all(b"adopted\n").unwrap();
    });

    let stream = TcpStream::connect(addr).unwrap();
    let mut pool = Pool::new(0);
    let iod = pool.create_iod_tcp_from(stream);
    assert_eq!(pool.iod(iod).unwrap().id(), iod);

    let line = pool.readlines(
        iod,
        3000,
        128,
        Box::new(|_, status| assert_eq!(status, EventStatus::Success)),
    );
    pool.run(-1);
    assert_eq!(pool.take_read_buf(line), b"adopted\n");
    server.join().unwrap();
}

#[test]
fn delete_pool_clears_state() {
    let mut pool = Pool::new(7);
    let iod = pool.create_iod_tcp();
    pool.read(iod, 60000, Box::new(|_, _| {}));
    pool.delete();
    assert!(!pool.has_pending());
    assert_eq!(pool.pending_count(), 0);
}

