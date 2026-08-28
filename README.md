<div align="center">

# 🦀 WNR — We Nmap in Rust

**A fast, asynchronous network reconnaissance and port scanning engine, written from scratch in Rust.**

*"Nmap's spirit, Rust's safety and speed."*

[![Language](https://img.shields.io/badge/language-Rust-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-9cf)](https://github.com/ionianCTF/We-Nmap-in-Rust)
[![Status](https://img.shields.io/badge/status-active%20development-brightgreen)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

## 📖 Table of Contents

- [What is WNR?](#-what-is-wnr)
- [Why Rust?](#-why-rust)
- [Features](#-features)
- [Architecture](#-architecture)
- [Scan Techniques](#-scan-techniques)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Formats](#-output-formats)
- [Scripting Engine (WSE)](#-scripting-engine-wse)
- [Sample Output](#-sample-output)
- [WNR vs. Nmap](#-wnr-vs-nmap)
- [Roadmap](#-roadmap)
- [Legal & Ethical Disclaimer](#%EF%B8%8F-legal--ethical-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🧭 What is WNR?

**WNR (We Nmap in Rust)** is a network mapper and port scanner — a ground-up reimagining of the ideas behind [Nmap](https://nmap.org/), built in pure Rust. It is designed for:

- **Network inventory** — discover live hosts and map open ports on a target network.
- **Security auditing** — probe for exposed services during authorized assessments.
- **CTF & red-team reconnaissance** — quick, scriptable discovery in competitive environments.
- **Learning** — a clean, readable codebase that demonstrates raw-socket programming, asynchronous I/O, and protocol fingerprinting in Rust.

WNR targets feature parity with Nmap's core scanning workflow while leveraging Rust's memory safety, fearless concurrency, and modern ecosystem.

> ⚠️ WNR is a **work in progress**. It currently focuses on host discovery, port scanning, and service detection. See the [Roadmap](#-roadmap) for what's next.

---

## 🦀 Why Rust?

| Property | Benefit for a scanner |
| --- | --- |
| **Memory safety** | No buffer overflows, use-after-free, or dangling pointers — critical when parsing untrusted packets and service banners from the network. |
| **Zero-cost abstractions** | High-level, expressive code that compiles down to C-like performance. |
| **Async ecosystem (Tokio)** | Scan thousands of hosts/ports concurrently with a tiny memory footprint per task. |
| **Single static binary** | No runtime, no interpreter, no dependency hell — `wnr` is one self-contained executable. |
| **Fearless concurrency** | The borrow checker makes it safe to share the scan state across worker tasks. |

---

## ✨ Features

### Implemented / in development

| Feature | Description | Status |
| --- | --- | --- |
| **Host discovery** | ICMP Echo, TCP SYN ping, TCP ACK ping, UDP ping, ARP scan on local segments | ✅ |
| **TCP SYN scan (`-sS`)** | Half-open scan using raw sockets; never completes the TCP handshake | ✅ |
| **TCP Connect scan (`-sT`)** | Full-handshake scan via the OS network stack; no root required | ✅ |
| **UDP scan (`-sU`)** | Datagram probes with ICMP port-unreachable analysis | ✅ |
| **Stealth scans (`-sF`, `-sN`, `-sX`)** | FIN, NULL, and Xmas scans exploiting RFC 793 | 🔄 |
| **Service/version detection (`-sV`)** | Probe-and-banner database with regex fingerprint matching | ✅ |
| **OS fingerprinting (`-O`)** | TCP/IP stack fingerprinting (TTL, window size, TCP options, ECN behavior) | 🔄 |
| **CIDR & range parsing** | `192.168.1.0/24`, `10.0.0.1-254`, `scanme.org/16`, list files | ✅ |
| **Timing templates (`-T0` … `-T5`)** | From paranoid-slow to insane-fast parallelism profiles | ✅ |
| **Scripting engine (WSE)** | Lua-based NSE-compatible engine (powered by `mlua`) | 🔄 |
| **Multiple output formats** | Interactive terminal, normal text, JSON, XML (Nmap-compatible), grepable | ✅ |

---

## 🏗️ Architecture

WNR is organized as a Cargo workspace of focused crates, so each subsystem is independently testable and reusable:

```
wnr/
├── Cargo.toml                  # Workspace manifest
├── crates/
│   ├── wnr-cli/                # CLI front-end: argument parsing, UX, output
│   ├── wnr-core/               # Scan orchestration: scheduler, state, results
│   ├── wnr-probe/              # Raw packet crafting & parsing (L2-L4)
│   ├── wnr-service/            # Service/version detection & probe database
│   ├── wnr-os/                 # TCP/IP stack fingerprinting
│   ├── wnr-engine/             # WSE scripting engine (Lua via mlua)
│   ├── wnr-report/             # Output writers: text, JSON, XML, grepable
│   └── wnr-fingerprints/       # Bundled fingerprint/probe data
└── README.md
```

### Concurrency model

```
                 ┌──────────────────────────────┐
  CLI args ────▶ │   wnr-cli  (clap parsing)    │
                 └──────────────┬───────────────┘
                                ▼
                 ┌──────────────────────────────┐
                 │  wnr-core: Scan Scheduler    │
                 │  (Tokio, mpsc channels)      │
                 │                              │
                 │   ┌──────┐   ┌──────┐        │
                 │   │ Host │…  │ Host │        │
                 │   │queue │   │queue │        │
                 │   └──┬───┘   └──┬───┘        │
                 └──────┼──────────┼────────────┘
                        ▼          ▼
              ┌──────────────────────────┐
              │   Worker pool (async)    │
              │   packet send / recv     │
              └──────────┬───────────────┘
                         ▼
              ┌──────────────────────────┐
              │  wnr-report: results out │
              │  terminal / file / json  │
              └──────────────────────────┘
```

**Key design decisions**

- **One Tokio runtime, many tasks.** Each host gets a scan task; each port probe is a lightweight future. Back-pressure is handled with bounded `mpsc` channels.
- **Raw sockets via `socket2` + hand-rolled packet layer.** WNR crafts TCP/UDP/ICMP packets directly, giving us full control over flags, TTL, window size, and options — which is what makes stealth scans and OS fingerprinting possible.
- **Immutable scan state, message-passing results.** Workers never share mutable state; results flow back through channels to the report layer. This makes the engine deterministic and trivially parallelizable.
- **Fingerprints as data, not code.** Service probes and OS signatures live in structured data files under `wnr-fingerprints/`, so the community can extend detection without touching Rust code.
- **Zero unsafe code** in the core engine. The only `unsafe` (if any) is isolated to the raw-socket boundary and documented.

---

## 🛰️ Scan Techniques

| Flag | Technique | Root required | How it works |
| --- | --- | --- | --- |
| `-sS` | TCP SYN (half-open) | ✅ (or `CAP_NET_RAW`) | Send `SYN`; `SYN/ACK` → open, `RST` → closed, nothing → filtered. Never completes the handshake. |
| `-sT` | TCP Connect | ❌ | Full `connect()` syscall — slower and noisier, but works unprivileged. |
| `-sU` | UDP | ✅ | Send UDP probe; ICMP `port unreachable` → closed, response → open, silence → open\|filtered. |
| `-sF` | TCP FIN | ✅ | Send bare `FIN`; closed ports answer with `RST` per RFC 793. |
| `-sN` | TCP NULL | ✅ | Send packet with no flags; closed ports answer with `RST`. |
| `-sX` | Xmas | ✅ | Send `FIN,PSH,URG` (packet "lit up like a Christmas tree"). |
| `-sA` | TCP ACK | ✅ | Maps firewall rulesets — distinguishes `filtered` from `unfiltered`. |
| `-sW` | TCP Window | ✅ | Uses the TCP window size in `RST` responses to infer open/closed. |
| `-sI <zombie>` | Idle scan | ✅ | Truly blind scan through an idle "zombie" host via IPID analysis. |
| `-sP` / `-sn` | Ping-only | ❌ | Host discovery without port scanning. |

**Port selection:** single (`-p 22`), range (`-p 1-1024`), list (`-p 22,80,443`), top-N (`--top-ports 100`), all 65,535 (`-p-`), and service names (`-p ssh,http`).

---

## 📦 Installation

### Prerequisites

- [Rust](https://rustup.rs/) **1.75+** (stable toolchain)
- Linux: `libpcap` is *not* required (WNR speaks raw sockets directly), but `libc` dev headers are.
  ```bash
  # Debian / Ubuntu
  sudo apt install build-essential libc6-dev
  ```
- macOS: Xcode Command Line Tools (`xcode-select --install`).
- Windows: [Npcap](https://npcap.com/) (raw-socket scans) or use `-sT` without it.

### From crates.io

```bash
cargo install wnr
```

### From source

```bash
git clone https://github.com/ionianCTF/We-Nmap-in-Rust.git
cd We-Nmap-in-Rust
cargo build --release
sudo ./target/release/wnr --version
```

### Raw-socket permissions on Linux

Half-open and stealth scans craft raw packets, which requires privileges. You don't need full root — grant the binary just the capability it needs:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/wnr
```

---

## 🚀 Usage

### Quick start

```bash
# TCP SYN scan of the 1000 most common ports on a single host
sudo wnr -sS scanme.example.org

# Aggressive scan: OS detection + service version + default scripts
sudo wnr -A -T4 192.168.1.1

# Full-port TCP scan of an entire /24 subnet, JSON output
sudo wnr -sS -p- -oJ scan.json 10.0.0.0/24

# Quiet UDP scan of the top 100 UDP ports
sudo wnr -sU --top-ports 100 -T2 10.0.0.53

# Host discovery only (no port scan)
wnr -sn 192.168.1.0/24
```

### Full CLI reference

| Option | Description |
| --- | --- |
| `TARGET` | Hostname, IP, CIDR (`10.0.0.0/24`), range (`10.0.0.1-254`), or file (`-iL hosts.txt`) |
| `-sS` / `-sT` / `-sU` / `-sF` / `-sN` / `-sX` / `-sA` / `-sI` | Scan technique (see [table](#-scan-techniques)) |
| `-p <ports>` | Ports to scan; `-p-` for all 65,535 |
| `--top-ports <n>` | Scan the `n` most common ports |
| `-sn` | Ping scan / host discovery only |
| `-Pn` | Skip host discovery; treat all hosts as up |
| `-sV` | Service & version detection |
| `-O` | OS fingerprinting |
| `-A` | Aggressive mode: `-sV -O` + default scripts + traceroute |
| `-T<0-5>` | Timing template (paranoid → insane) |
| `--min-rate <n>` / `--max-rate <n>` | Floor / ceiling on packets per second |
| `-oN` / `-oJ` / `-oX` / `-oG` | Output: normal / JSON / XML / grepable |
| `-v` / `-vv` | Verbosity |
| `--script <name>` | Run a WSE script (see [Scripting](#-scripting-engine-wse)) |
| `-iL <file>` | Read targets from a file |
| `--exclude <hosts>` | Exclude hosts from the scan |
| `--source-port <port>` | Spoofed source port for firewall evasion |
| `-e <iface>` | Network interface to use |

### Timing templates

| Template | Name | Use case | Rate limit |
| --- | --- | --- | --- |
| `-T0` | Paranoid | IDS evasion; serial probes | 1 packet / 5 min |
| `-T1` | Sneaky | IDS evasion; serial probes | 15 s / packet |
| `-T2` | Polite | Low-bandwidth targets | ~0.4 s / packet |
| `-T3` | Normal | **Default**; dynamic pacing | N/A (adaptive) |
| `-T4` | Aggressive | Fast, reliable LAN/Internet scans | 1 ms / packet |
| `-T5` | Insane | Very fast LAN or high-bandwidth scans | 250 µs / packet |

---

## 📄 Output Formats

```bash
wnr -sS -oN normal.txt -oJ results.json -oX results.xml -oG grepable.gnmap 10.0.0.0/24
```

- **Normal** (`-oN`) — human-readable, like Nmap's classic output.
- **JSON** (`-oJ`) — structured, machine-friendly, ideal for pipelines:
  ```json
  {
    "scan": { "started": 1720000000, "args": "wnr -sS -oJ results.json 10.0.0.0/24" },
    "hosts": [
      {
        "ip": "10.0.0.1",
        "status": "up",
        "ports": [
          { "port": 22,  "protocol": "tcp", "state": "open",  "service": "ssh"  },
          { "port": 443, "protocol": "tcp", "state": "open",  "service": "https" }
        ]
      }
    ]
  }
  ```
- **XML** (`-oX`) — schema-compatible with Nmap's XML, so existing tooling keeps working.
- **Grepable** (`-oG`) — one line per host, for `grep`/`awk` workflows.

---

## 🧩 Scripting Engine (WSE)

WNR ships **WSE (WNR Scripting Engine)**, an NSE-compatible scripting layer built on [mlua](https://crates.io/crates/mlua). Scripts live in `wnr-fingerprints/scripts/` and can automate discovery, vulnerability checks, and enumeration:

```bash
sudo wnr --script http-title,banner 192.168.1.10
```

```lua
-- scripts/http-title.lua
description = "Grabs the <title> of a web page"
categories = { "discovery", "safe" }

portrule = function(host, port)
    return port.protocol == "tcp" and port.service == "http"
end

action = function(host, port)
    local socket = wnr.new_socket()
    socket:send("GET / HTTP/1.0\r\nHost: " .. host.ip .. "\r\n\r\n")
    local response = socket:receive()
    return response:match("<title>(.-)</title>") or "no title"
end
```

Scripts run inside a sandboxed Lua VM with a minimal, explicit API (`wnr.new_socket`, host/port tables, output helpers) — no access to the host filesystem or process by default.

---

## 🖥️ Sample Output

```
$ sudo wnr -sS -sV -T4 192.168.1.1

Starting WNR 0.1.0 ( https://github.com/ionianCTF/We-Nmap-in-Rust ) at 2026-08-28 12:00 UTC
Scanning 192.168.1.1 [1000 ports]
Discovered open port 22/tcp on 192.168.1.1
Discovered open port 80/tcp on 192.168.1.1
Discovered open port 443/tcp on 192.168.1.1
Service scan: 3 open ports, probing...

Nmap-style report for 192.168.1.1
PORT     STATE  SERVICE  VERSION
22/tcp   open   ssh      OpenSSH 9.6 (protocol 2.0)
80/tcp   open   http     nginx 1.25.3
443/tcp  open   ssl/http nginx 1.25.3
MAC Address: AA:BB:CC:DD:EE:FF (RouterCo)

WNR done: 1 IP address (1 host up) scanned in 2.14 seconds
```

---

## ⚖️ WNR vs. Nmap

| | **Nmap (C/C++/Lua)** | **WNR (Rust)** |
| --- | --- | --- |
| Memory safety | Manual management; decades of CVEs | Compile-time safety guarantees |
| Concurrency | Custom non-blocking engine (Nsock) | Tokio async runtime, zero-cost futures |
| Scripting | NSE (Lua 5.3) | WSE (Lua via `mlua`), NSE-compatible subset |
| Output | Text/XML/grepable | Text/JSON/XML/grepable |
| Footprint | Multi-MB binary + data files | Single static binary, fingerprints embedded |
| Extensibility | C++ modules | Cargo workspace crates + data-driven fingerprints |
| Deployment | Compile-from-source or distro packages | `cargo install wnr` or one binary copy |

WNR does **not** aim to replace Nmap overnight. Nmap's fingerprint database is the product of 25+ years of community effort. WNR's goal is to be a modern, safe, hackable alternative — and to be a great Rust codebase to learn from.

---

## 🗺️ Roadmap

- [x] Host discovery (ping sweep, ARP)
- [x] TCP SYN / Connect scans
- [x] UDP scan
- [x] Service/version detection with bundled probe database
- [x] JSON / XML / grepable output
- [ ] FIN / NULL / Xmas / ACK / Window scans
- [ ] OS fingerprinting with TCP/IP stack signatures
- [ ] Idle scan (`-sI`)
- [ ] WSE scripting engine + initial script library
- [ ] IPv6 scanning
- [ ] SCTP & IP-protocol scans (`-sY`, `-sO`)
- [ ] NSE script compatibility shim (run existing NSE scripts)
- [ ] Plugin/extension API for custom scan modules

---

## ⚠️ Legal & Ethical Disclaimer

WNR is a security tool for **authorized testing only**. Scanning networks and hosts you do not own or have explicit written permission to test is **illegal** in most jurisdictions and may violate computer-misuse laws (e.g., CFAA, Computer Misuse Act).

> **You are solely responsible for your use of this tool.** The authors assume no liability for misuse. Always obtain proper authorization and follow a responsible-disclosure policy.

---

## 🤝 Contributing

Contributions are welcome! This is a learning-first codebase — documentation, tests, and fingerprint data are as valuable as code.

1. Fork the repo and create a feature branch.
2. Add tests — the packet layer and parsers are fully unit-tested (`cargo test`).
3. Run `cargo fmt` and `cargo clippy` — the codebase is `#![deny(warnings)]`.
4. Open a PR describing what and why.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) first.

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for the full text.

*Nmap is a registered trademark of Gordon Lyon. WNR is an independent project and is not affiliated with or endorsed by the Nmap project.*
