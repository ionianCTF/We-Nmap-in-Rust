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
