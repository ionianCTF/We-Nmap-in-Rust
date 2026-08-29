//! WNR — We Nmap in Rust: command-line scanner.
//!
//! A small driver that exercises all three core crates:
//!
//! * `wnr --interfaces` — enumerate interfaces via `wnr-dnet`
//! * `wnr --scan <host> [-p port,port-range]` — parallel connect scan via `wnr-nsock`
//! * `wnr --pcap <file> [--filter expr]` — analyze a pcap savefile via `wnr-pcap`

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use wnr_dnet::intf::interface_list;
use wnr_nsock::event::EventStatus;
use wnr_nsock::pool::Pool;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "--interfaces" | "-i" => cmd_interfaces(),
        "--scan" | "-s" => cmd_scan(&args[2..]),
        "--pcap" | "-p" => cmd_pcap(&args[2..]),
        "--route" | "-r" => cmd_route(&args[2..]),
        "--version" | "-V" => {
            println!("WNR (We Nmap in Rust) {}", env!("CARGO_PKG_VERSION"))
        }
        "--help" | "-h" => print_usage(),
        other => {
            eprintln!("unknown command '{}'", other);
            print_usage();
        }
    }
}

fn print_usage() {
    println!(
        "WNR (We Nmap in Rust) {}\n\
         \n\
         USAGE:\n\
         \x20 wnr --interfaces                 enumerate network interfaces\n\
         \x20 wnr --scan <host> [-p PORT[,RANGE]...] [--timeout MS]\n\
         \x20 wnr --pcap <file> [--filter EXPR]\n\
         \x20 wnr --route <host>               show the route/next-hop to a host\n\
         \x20 wnr --version\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn cmd_interfaces() {
    let list = interface_list();
    if list.is_empty() {
        println!("No network interfaces could be enumerated.");
        return;
    }
    println!("{:<16} {:<18} {:<9} {:<6} {}", "INTERFACE", "ADDRESS", "MAC", "MTU", "FLAGS");
    for e in &list {
        let mac = e
            .link_addr_slice()
            .map(|m| {
                m.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":")
            })
            .unwrap_or_else(|| "-".to_string());
        let mut flags = Vec::new();
        if e.is_up() {
            flags.push("UP");
        }
        if e.is_loopback() {
            flags.push("LOOPBACK");
        }
        if e.is_point_to_point() {
            flags.push("P2P");
        }
        println!("{:<16} {:<18} {:<9} {:<6} {}", e.name, e.addr, mac, e.mtu, flags.join(","));
    }
}

fn cmd_scan(args: &[String]) {
    let mut host = None;
    let mut ports: Vec<u16> = Vec::new();
    let mut timeout_ms = 3000;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                if i + 1 < args.len() {
                    ports.extend(parse_ports(&args[i + 1]));
                    i += 1;
                }
            }
            "--timeout" => {
                if i + 1 < args.len() {
                    timeout_ms = args[i + 1].parse().unwrap_or(3000);
                    i += 1;
                }
            }
            "--filter" => {
                // accepted but unused for scan
                if i + 1 < args.len() {
                    i += 1;
                }
            }
            v if !v.starts_with('-') => host = Some(v.to_string()),
            _ => {}
        }
        i += 1;
    }
    let Some(host) = host else {
        eprintln!("no host specified");
        return;
    };
    if ports.is_empty() {
        ports.extend(1..=100);
    }

    // Resolve host.
    let addrs: Vec<SocketAddr> = (host.as_str(), 0)
        .to_socket_addrs()
        .ok()
        .map(|it| it.collect())
        .unwrap_or_default();
    if addrs.is_empty() {
        eprintln!("could not resolve host '{}'", host);
        return;
    }

    println!(
        "WNR connect-scan of {} ({} port(s), timeout {}ms)",
        host,
        ports.len(),
        timeout_ms
    );

    let mut pool = Pool::new(0);
    let total_ports = ports.len();

    for port in ports {
        let addr = SocketAddr::new(addrs[0].ip(), port);
        let iod = pool.create_iod_tcp();
        pool.connect_tcp(iod, addr, timeout_ms, Box::new(move |_, status| {
            match status {
                EventStatus::Success => println!("{:>5}/tcp open", port),
                _ => println!("{:>5}/tcp closed", port),
            }
        }));
    }

    pool.run(-1);
    println!("done ({} ports scanned)", total_ports);
}

fn cmd_pcap(args: &[String]) {
    let mut file = None;
    let mut filter = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--filter" if i + 1 < args.len() => {
                filter = Some(args[i + 1].clone());
                i += 1;
            }
            v if !v.starts_with('-') => file = Some(v.to_string()),
            _ => {}
        }
        i += 1;
    }
    let Some(file) = file else {
        eprintln!("no pcap file specified");
        return;
    };

    let path = PathBuf::from(&file);
    let mut cap = match wnr_pcap::Capture::open_offline(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to open '{}': {}", file, e);
            return;
        }
    };
    if let Some(f) = &filter {
        match cap.set_filter(f) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("invalid filter '{}': {}", f, e);
                return;
            }
        }
    }

    let mut total = 0u64;
    let mut bytes = 0u64;
    let started = std::time::Instant::now();
    while let Ok(Some((hdr, frame))) = cap.next_packet() {
        total += 1;
        bytes += hdr.caplen as u64;
        if total <= 10 {
            let (l3off, l3len, _l3) =
                wnr_pcap::capture::strip_link_header(cap.datalink(), &frame).unwrap_or((0, 0, &[]));
            println!(
                "pkt #{}: {} bytes captured ({} on wire), {} l3 bytes at off {}",
                total, hdr.caplen, hdr.len, l3len, l3off
            );
        }
    }
    println!(
        "read {} packets ({} bytes) from '{}' in {:?} ({} pkts/sec)",
        total,
        bytes,
        file,
        started.elapsed(),
        if started.elapsed().as_secs_f64() > 0.0 {
            (total as f64 / started.elapsed().as_secs_f64()) as u64
        } else {
            0
        }
    );
    if let Some(f) = filter {
        println!("filter applied: '{}'", f);
    }
}

fn cmd_route(args: &[String]) {
    let host = args.iter().find(|a| !a.starts_with('-'));
    let Some(host) = host else {
        eprintln!("no host specified");
        return;
    };
    let Some(ip) = resolve_ip(host) else {
        eprintln!("could not resolve host '{}'", host);
        return;
    };
    let dst = match ip {
        std::net::IpAddr::V4(v4) => wnr_dnet::Addr::ipv4(v4),
        std::net::IpAddr::V6(v6) => wnr_dnet::Addr::ipv6(v6),
    };
    match wnr_dnet::route::route_to(&dst) {
        Some((ifname, src)) => {
            println!(
                "route to {} ({}) -> via interface '{}' with source {}",
                host, ip, ifname, src
            );
        }
        None => {
            println!("no route to {} ({})", host, ip);
        }
    }
}

/// Resolve a hostname (or literal IP) to an [`std::net::IpAddr`].
fn resolve_ip(host: &str) -> Option<std::net::IpAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ip);
    }
    (host, 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .map(|sa| sa.ip())
}

fn parse_ports(spec: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        if part.contains('-') {
            let mut it = part.split('-');
            let a: u16 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            let b: u16 = it.next().and_then(|v| v.parse().ok()).unwrap_or(a);
            for p in a..=b.max(a) {
                out.push(p);
            }
        } else if let Ok(p) = part.parse() {
            out.push(p);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_ports() {
        assert_eq!(parse_ports("80"), vec![80]);
        assert_eq!(parse_ports("80,443,22"), vec![80, 443, 22]);
    }

    #[test]
    fn parse_ranges() {
        assert_eq!(parse_ports("1000-1002"), vec![1000, 1001, 1002]);
        assert_eq!(parse_ports("1-3,80"), vec![1, 2, 3, 80]);
    }

    #[test]
    fn parse_single_is_treated_as_range_of_one() {
        assert_eq!(parse_ports("5-5"), vec![5]);
    }

    #[test]
    fn resolve_ip_literal() {
        assert_eq!(
            resolve_ip("127.0.0.1"),
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        );
        assert!(resolve_ip("not-a-real-host.invalid").is_none());
    }
}
