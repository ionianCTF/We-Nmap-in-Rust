# We Nmap in Rust (WNR)

> **WNR** — reimplementing [Nmap](https://nmap.org/), the Network Mapper, in **Rust**.
> Every core networking and logic library is written from scratch in safe, modern Rust,
> using the official upstream repositories as the behavioral reference.

Nmap is written in C (plus Lua for scripting) and depends on a handful of battle-tested
networking libraries. This project does **not** FFI-bind those C libraries — it rewrites
each one natively in Rust, matching upstream semantics while leaning on Rust's memory
safety, strong typing, and tooling.

---

## Core Networking & Logic Libraries

Each library maps 1:1 to an upstream Nmap dependency and is implemented from scratch in
Rust, using the official source as the reference for behavior, wire formats, and edge cases.

### `wnr-pcap` — Packet Capture *(upstream: libpcap / Npcap)*

| | |
|---|---|
| **Upstream** | [the-tcpdump-group/libpcap](https://github.com/the-tcpdump-group/libpcap) &nbsp;·&nbsp; [nmap/libpcap](https://github.com/nmap/libpcap) &nbsp;·&nbsp; [nmap/npcap](https://github.com/nmap/npcap) |
| **Purpose** | Raw network packet capturing and sniffing. |

libpcap provides the system-independent interface for user-level packet capture — the
engine behind every packet Nmap receives. On Windows, the Nmap project ships **Npcap**, a
customized fork maintained specifically for Nmap. `wnr-pcap` reimplements this surface:

- Device discovery and open (`pcap_findalldevs`, `pcap_open_live` / `pcap_open`)
- Live capture in promiscuous and non-promiscuous modes
- Snapshot length (`snaplen`), BPF-style filter compilation and application
- Link-layer (datalink) type handling and `pcap_next_ex`-style packet retrieval
- Windows Npcap backend via the Npcap API, ported to Rust
- Dump/savefile read & write (`pcap_dump_open`, `pcap_open_offline`)

### `wnr-dnet` — Low-Level Raw Networking *(upstream: libdnet)*

| | |
|---|---|
| **Upstream** | [dugsong/libdnet](https://github.com/dugsong/libdnet) &nbsp;·&nbsp; [ofalk/libdnet](https://github.com/ofalk/libdnet) |
| **Purpose** | Interface enumeration, link-layer hardware (MAC) address manipulation, and other low-level raw networking routines. |

Nmap distributes a **modified** version of libdnet (its Windows code in particular is
heavily patched). `wnr-dnet` reimplements the portable low-level networking layer:

- Network interface enumeration (`dnet_intf`) — name, IP, netmask, broadcast, MAC/hardware address
- Link-layer / Ethernet address parsing and manipulation
- ARP cache lookup and manipulation
- Routing table lookup and manipulation
- Raw IP packet and Ethernet frame transmission
- Address family & CIDR/address formatting helpers

### `wnr-nsock` — Asynchronous Sockets *(upstream: Nsock)*

| | |
|---|---|
| **Upstream** | [nmap/nmap → nsock/](https://github.com/nmap/nmap/tree/master/nsock) |
| **Purpose** | Nsock — Nmap's own library for safe, efficient asynchronous network I/O (sockets). |

Nsock is a custom internal library written by the Nmap developers to provide parallel,
non-blocking, event-driven socket handling. `wnr-nsock` reimplements it on top of Rust's
async/await (e.g. `tokio`) while preserving Nsock's programming model:

- **Event pools** — `Nsock_Pool` analog: a collection of I/O descriptors processed together
- **Asynchronous I/O descriptors** — connect, write, read with timeouts and event callbacks
- **Connect / Read / Write / GetInfo / UDP events** with programmable timeouts (`Nsock_Connect`, `Nsock_Read`, `Nsock_Write`, `Nsock_ReadUDP`, …)
- **TCP, UDP, and raw socket** backends
- **Integration with `wnr-pcap`** for asynchronously capturing live packets (`nsock_pcap_open`, `Nsock_Pcap_Read_Packet`)
- Parallelism without the classic C pitfalls: no manual callback bookkeeping, no data races

This is the concurrency backbone that lets parallel port scanning, service probing, and
packet capture all proceed efficiently in a single event loop.

---

## Project Layout

```
We-Nmap-in-Rust/
├── wnr-pcap/    # packet capture library (libpcap / Npcap reimplementation)
├── wnr-dnet/    # low-level raw networking (libdnet reimplementation)
├── wnr-nsock/   # asynchronous network I/O (Nsock reimplementation)
└── README.md
```

Each crate is intended to be developed independently and layered together as WNR grows
into a full Nmap-equivalent capable of host discovery, port scanning, service/version
detection, and OS fingerprinting — all natively in Rust.

---

## Goals

- **Rust-native** — every core library written from scratch in Rust; no C FFI for the core
  networking stack.
- **Behavior parity** — match the upstream C libraries' wire behavior, documented via tests
  derived from the official repositories.
- **Memory safe** — eliminate the buffer-overflow and use-after-free classes of bugs inherent
  to the original C implementations.
- **Portable** — support the same platforms Nmap targets, including Windows via Npcap.

---

## Status

Under construction. Core library crates (`wnr-pcap`, `wnr-dnet`, `wnr-nsock`) are being
implemented from upstream reference sources.
