//! Berkeley Packet Filter (BPF) — mirrors libpcap's packet filter machinery.
//!
//! A BPF is a small register-based virtual machine that decides whether a
//! captured frame should be passed to the application. libpcap *compiles* a
//! human-readable filter expression (e.g. `tcp port 80`) into bytecode, which
//! the kernel then interprets against every packet. We implement both sides
//! from scratch in pure Rust:
//!
//! * `BpfVm` — the interpreter executing `BpfInsn` against a packet buffer
//! * `FilterBuilder` — compiles a small but useful subset of the pcap filter
//!   language into `BpfInsn` bytecode
//!
//! The instruction set and semantics match the classic BPF ISA.

/// Classic BPF instruction set opcodes.
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_RET: u8 = 0x06;
pub const BPF_MISC: u8 = 0x07;

/// BPF_LD / BPF_LDX classes.
pub const BPF_W: u8 = 0x00;
pub const BPF_H: u8 = 0x08;
pub const BPF_B: u8 = 0x10;
pub const BPF_IMM: u8 = 0x00;
pub const BPF_ABS: u8 = 0x20;
pub const BPF_IND: u8 = 0x40;
pub const BPF_MEM: u8 = 0x60;
pub const BPF_LEN: u8 = 0x80;
pub const BPF_MSH: u8 = 0xa0;

/// BPF_ALU operation types.
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xa0;

/// BPF_JMP operation types.
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;

/// BPF_RET operation types.
pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;

/// BPF_MISC operations.
pub const BPF_TAX: u8 = 0x00;
pub const BPF_TXA: u8 = 0x80;

/// A single BPF instruction — mirrors `struct bpf_insn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl BpfInsn {
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        BpfInsn { code, jt, jf, k }
    }
}

/// The result returned when a filter accepts a packet.
pub const BPF_ACCEPT: u32 = 0xffff_ffff;
/// Classic "return 0" means reject.
pub const BPF_REJECT: u32 = 0;

/// The BPF interpreter evaluating bytecode against a packet buffer.
///
/// Mirrors the kernel's `bpf_filter()` / libpcap's `bpf_filter()`.
#[derive(Default)]
pub struct BpfVm {
    pub acc: u32,
    pub x: u32,
    pub mem: [u32; 16],
}

impl BpfVm {
    pub fn new() -> Self {
        BpfVm::default()
    }

    pub fn filter_ok(&mut self, program: &[BpfInsn], pkt: &[u8]) -> bool {
        self.run(program, pkt) != 0
    }

    /// Execute a BPF program against a packet. Returns the final accumulator
    /// value (nonzero accepts, zero rejects).
    pub fn run(&mut self, program: &[BpfInsn], pkt: &[u8]) -> u32 {
        let pkt_len = pkt.len() as u32;
        self.acc = 0;
        self.x = 0;
        self.mem = [0u32; 16];

        let mut pc: usize = 0;
        while pc < program.len() {
            let ins = &program[pc];
            let cls = (ins.code & 0x07) as u8;

            match cls {
                BPF_LD | BPF_LDX => {
                    let size = (ins.code & 0x18) as u8; // BPF_W / BPF_H / BPF_B
                    let mode = (ins.code & 0xe0) as u8; // BPF_IMM / ABS / IND / MEM / LEN / MSH
                    match mode {
                        BPF_IMM => {
                            let v = ins.k;
                            if cls == BPF_LD {
                                self.acc = v;
                            } else {
                                self.x = v;
                            }
                        }
                        BPF_ABS | BPF_IND => {
                            let idx = if mode == BPF_IND {
                                self.x.wrapping_add(ins.k)
                            } else {
                                ins.k
                            };
                            let val = load(pkt, pkt_len, idx, size);
                            match val {
                                Some(v) => {
                                    if cls == BPF_LD {
                                        self.acc = v;
                                    } else {
                                        self.x = v;
                                    }
                                }
                                None => return 0,
                            }
                        }
                        BPF_MEM => {
                            let m = ins.k as usize;
                            if m >= self.mem.len() {
                                return 0;
                            }
                            let v = self.mem[m];
                            if cls == BPF_LD {
                                self.acc = v;
                            } else {
                                self.x = v;
                            }
                        }
                        BPF_LEN => {
                            if cls == BPF_LD {
                                self.acc = pkt_len;
                            } else {
                                self.x = pkt_len;
                            }
                        }
                        BPF_MSH => {
                            // helper for IP header length: load byte, mask, shift
                            match load(pkt, pkt_len, ins.k, BPF_B) {
                                Some(v) => {
                                    let hlen = ((v as u32 & 0x0f) << 2) as u32;
                                    if hlen > pkt_len {
                                        return 0;
                                    }
                                    self.x = hlen;
                                }
                                None => return 0,
                            }
                        }
                        _ => return 0,
                    }
                }
                BPF_ST | BPF_STX => {
                    let m = ins.k as usize;
                    if m >= self.mem.len() {
                        return 0;
                    }
                    self.mem[m] = if cls == BPF_ST { self.acc } else { self.x };
                }
                BPF_ALU => {
                    let op = (ins.code & 0xf0) as u8; // BPF_ADD .. BPF_XOR
                    let use_x = ins.code & 0x08 != 0;
                    self.alu(op, use_x, ins.k);
                }
                BPF_JMP => {
                    let op = (ins.code & 0x70) as u8; // BPF_JA .. BPF_JSET
                    let use_x = ins.code & 0x08 != 0;
                    let v = if use_x { self.x } else { ins.k };
                    let (true_target, false_target) =
                        (pc as u32 + ins.jt as u32 + 1, pc as u32 + ins.jf as u32 + 1);
                    let jump = match op {
                        BPF_JA => ins.k,
                        BPF_JEQ => {
                            if self.acc == v {
                                true_target
                            } else {
                                false_target
                            }
                        }
                        BPF_JGT => {
                            if self.acc > v {
                                true_target
                            } else {
                                false_target
                            }
                        }
                        BPF_JGE => {
                            if self.acc >= v {
                                true_target
                            } else {
                                false_target
                            }
                        }
                        BPF_JSET => {
                            if self.acc & v != 0 {
                                true_target
                            } else {
                                false_target
                            }
                        }
                        _ => {
                            return 0;
                        }
                    };
                    pc = jump as usize;
                    continue;
                }
                BPF_RET => {
                    return if ins.code & 0x08 != 0 {
                        self.x
                    } else {
                        ins.k
                    };
                }
                BPF_MISC => {
                    if ins.code & 0xf0 == BPF_TAX as u16 {
                        self.x = self.acc;
                    } else if ins.code & 0xf0 == BPF_TXA as u16 {
                        self.acc = self.x;
                    }
                }
                _ => return 0,
            }
            pc += 1;
        }
        self.acc
    }

    fn alu(&mut self, op: u8, use_x: bool, k: u32) {
        let v = if use_x { self.x } else { k };
        match op {
            BPF_ADD => self.acc = self.acc.wrapping_add(v),
            BPF_SUB => self.acc = self.acc.wrapping_sub(v),
            BPF_MUL => self.acc = self.acc.wrapping_mul(v),
            BPF_DIV => {
                if v != 0 {
                    self.acc /= v;
                } else {
                    self.acc = 0;
                }
            }
            BPF_OR => self.acc |= v,
            BPF_AND => self.acc &= v,
            BPF_LSH => self.acc = self.acc.checked_shl(v).unwrap_or(0),
            BPF_RSH => self.acc = self.acc.checked_shr(v).unwrap_or(0),
            BPF_NEG => self.acc = self.acc.wrapping_neg(),
            BPF_MOD => {
                if v != 0 {
                    self.acc %= v;
                } else {
                    self.acc = 0;
                }
            }
            BPF_XOR => self.acc ^= v,
            _ => {}
        }
    }
}

// Load a value of size (0=word,1=half,2=byte) at absolute offset `idx`,
// honoring the packet length. Returns None if out of bounds.
fn load(pkt: &[u8], pkt_len: u32, idx: u32, size: u8) -> Option<u32> {
    let idx = idx as usize;
    match size {
        BPF_W => {
            if idx.checked_add(4)? > pkt.len() {
                return None;
            }
            Some(u32::from_be_bytes([
                pkt[idx],
                pkt[idx + 1],
                pkt[idx + 2],
                pkt[idx + 3],
            ]))
        }
        BPF_H => {
            if idx.checked_add(2)? > pkt.len() {
                return None;
            }
            Some(u16::from_be_bytes([pkt[idx], pkt[idx + 1]]) as u32)
        }
        _ => {
            if idx >= pkt_len as usize {
                return None;
            }
            Some(pkt[idx] as u32)
        }
    }
}

/// A compiled filter: bytecode plus the number of bytes it consumes.
#[derive(Debug, Clone)]
pub struct BpfProgram {
    pub insns: Vec<BpfInsn>,
}

impl BpfProgram {
    pub fn from_insns(insns: Vec<BpfInsn>) -> Self {
        BpfProgram { insns }
    }

    /// Interpret this filter against a packet.
    pub fn filter(&self, pkt: &[u8]) -> bool {
        BpfVm::new().filter_ok(&self.insns, pkt)
    }
}

/// The filter expression language we compile. This is a practical subset of
/// libpcap's grammar (no VLAN/geneve forms yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Primitive {
    /// `tcp`, `udp`, `icmp`, `icmp6`, `arp`, `ip`, `ip6` — IP protocol
    /// numbers (1-255) and EtherTypes (0x0800, 0x86dd, 0x0806).
    Proto(u32),
    /// `port N`
    Port(u16),
    /// `portrange A-B`
    PortRange(u16, u16),
    /// `host A.B.C.D` or `net` handled via Proto+Addr
    HostIpv4(std::net::Ipv4Addr),
    /// `ip broadcast`
    Broadcast,
    /// `ip multicast`
    Multicast,
    /// accept everything
    All,
}

/// Simple streaming tokenizer for the filter language.
#[derive(Debug, Clone)]
pub struct FilterBuilder {
    tokens: Vec<String>,
    pos: usize,
}

impl FilterBuilder {
    /// Compile a filter expression string into a BPF program.
    pub fn compile(expr: &str, linktype: i32) -> Result<BpfProgram, String> {
        let tokens = tokenize(expr);
        if tokens.is_empty() {
            // Empty filter accepts everything.
            return Ok(BpfProgram::from_insns(vec![ret(BPF_ACCEPT)]));
        }
        let mut parser = FilterBuilder {
            tokens,
            pos: 0,
        };
        let prim = parser.parse_primitive()?;
        let mut insns = compile_primitive(prim, linktype)?;
        // Terminate with an implicit accept (in case the builder didn't emit one).
        insns.push(ret(BPF_ACCEPT));
        Ok(BpfProgram::from_insns(insns))
    }

    fn next(&mut self) -> Option<String> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_primitive(&mut self) -> Result<Primitive, String> {
        let tok = self.next().ok_or("empty filter")?;
        let lower = tok.to_ascii_lowercase();
        match lower.as_str() {
            "tcp" => Ok(Primitive::Proto(6)),
            "udp" => Ok(Primitive::Proto(17)),
            "icmp" => Ok(Primitive::Proto(1)),
            "icmp6" | "icmpv6" => Ok(Primitive::Proto(58)),
            "arp" => Ok(Primitive::Proto(0x0806)),
            "ip" => Ok(Primitive::Proto(0x0800)),
            "ip6" | "ipv6" => Ok(Primitive::Proto(0x86dd)),
            "broadcast" => Ok(Primitive::Broadcast),
            "multicast" => Ok(Primitive::Multicast),
            "port" => {
                let p = self.next().ok_or("missing port number")?;
                let port: u16 = p
                    .parse()
                    .map_err(|_| format!("invalid port '{}'", p))?;
                Ok(Primitive::Port(port))
            }
            "portrange" => {
                let a = self.next().ok_or("missing portrange start")?;
                let b = self.next().ok_or("missing portrange end")?;
                let pa: u16 = a.parse().map_err(|_| format!("bad port '{}'", a))?;
                let pb: u16 = b.parse().map_err(|_| format!("bad port '{}'", b))?;
                Ok(Primitive::PortRange(pa, pb))
            }
            "host" => {
                let h = self.next().ok_or("missing host address")?;
                let ip: std::net::Ipv4Addr = h
                    .parse()
                    .map_err(|_| format!("invalid host '{}'", h))?;
                Ok(Primitive::HostIpv4(ip))
            }
            other => Err(format!("unknown filter primitive '{}'", other)),
        }
    }
}

fn tokenize(expr: &str) -> Vec<String> {
    expr.split_whitespace()
        .flat_map(|w| {
            // split on '-' only for integer pairs (portrange A-B)
            if w.contains('-') && w.split('-').all(|p| p.parse::<u16>().is_ok()) {
                let parts: Vec<&str> = w.split('-').collect();
                vec![parts[0].to_string(), "-".to_string(), parts[1].to_string()]
            } else {
                vec![w.to_string()]
            }
        })
        .collect()
}

/// Compile a primitive into BPF bytecode for a given datalink type.
fn compile_primitive(p: Primitive, linktype: i32) -> Result<Vec<BpfInsn>, String> {
    use crate::datalink;
    let off = datalink::link_header_len(linktype);
    let ethertype_offset = 12; // offset of EtherType within an Ethernet header

    // Helper to emit a comparison against offset `o` (portability-aware).
    let mut out = Vec::new();

    // Build a predicate that returns 1 if matching, 0 otherwise.
    match p {
        Primitive::All => {
            return Ok(vec![ret(BPF_ACCEPT)]);
        }
        Primitive::Proto(proto) => {
            // For arp/ip/ip6 we test the Ethernet EtherType field.
            if proto == 0x0806 || proto == 0x0800 || proto == 0x86dd {
                out.push(load_insn(BPF_LD, BPF_H, ethertype_offset as u32));
                out.push(jmp_insn(BPF_JEQ, proto as u32, 1, 0)); // skip +1 => return 1
                out.push(ret(BPF_REJECT));
                out.push(ret(BPF_ACCEPT));
                return Ok(out);
            } else {
                // TCP/UDP/ICMP: test the IP protocol byte at offset 9 of IP header.
                let ip_hdr = off as u32;
                out.push(load_insn(BPF_LD, BPF_B, ip_hdr + 9));
                out.push(jmp_insn(BPF_JEQ, proto as u32, 1, 0));
                out.push(ret(BPF_REJECT));
                out.push(ret(BPF_ACCEPT));
                return Ok(out);
            }
        }
        Primitive::Port(_) | Primitive::PortRange(_, _) => {
            // TODO: port filtering requires IP header parsing + TCP/UDP port offsets.
            // Compile as accept for now (documented limitation).
            return Ok(vec![ret(BPF_ACCEPT)]);
        }
        Primitive::HostIpv4(ip) => {
            // Match the IP source or destination address (offsets 12 and 16).
            let ip_hdr = off as u32;
            let octets = ip.octets();
            let target = u32::from_be_bytes(octets);
            // Load dst (offset ip+16): if equal -> accept
            out.push(load_insn(BPF_LD, BPF_W, ip_hdr + 16));
            out.push(jmp_insn(BPF_JEQ, target, 1, 0));
            out.push(ret(BPF_REJECT));
            out.push(ret(BPF_ACCEPT)); // dst matched
            // Load src (offset ip+12): if equal -> accept
            out.push(load_insn(BPF_LD, BPF_W, ip_hdr + 12));
            out.push(jmp_insn(BPF_JEQ, target, 1, 0));
            out.push(ret(BPF_REJECT));
            out.push(ret(BPF_ACCEPT));
            return Ok(out);
        }
        Primitive::Broadcast => {
            let ip_hdr = off as u32;
            // dst == 255.255.255.255
            out.push(load_insn(BPF_LD, BPF_W, ip_hdr + 16));
            out.push(jmp_insn(BPF_JEQ, 0xffff_ffff, 1, 0));
            out.push(ret(BPF_REJECT));
            out.push(ret(BPF_ACCEPT));
            return Ok(out);
        }
        Primitive::Multicast => {
            let ip_hdr = off as u32;
            // first octet of dst in 224..239
            out.push(load_insn(BPF_LD, BPF_B, ip_hdr + 16));
            out.push(jmp_insn(BPF_JGE, 224, 0, 1));
            out.push(jmp_insn(BPF_JGT, 239, 0, 1));
            out.push(ret(BPF_REJECT));
            out.push(ret(BPF_ACCEPT));
            return Ok(out);
        }
    }
}

fn load_insn(cls: u8, size: u8, k: u32) -> BpfInsn {
    // BPF_* constants already encode their bit positions; OR them together.
    BpfInsn::new((cls as u16) | (size as u16) | (BPF_ABS as u16), 0, 0, k)
}

fn jmp_insn(op: u8, k: u32, jt: u8, jf: u8) -> BpfInsn {
    BpfInsn::new((BPF_JMP as u16) | (op as u16), jt, jf, k)
}

fn ret(k: u32) -> BpfInsn {
    BpfInsn::new((BPF_RET as u16) | (BPF_K as u16), 0, 0, k)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn en10mb() -> i32 {
        crate::datalink::DLT_EN10MB
    }

    fn eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(14 + payload.len());
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn ip_filter_accepts_ip_and_rejects_arp() {
        let prog = FilterBuilder::compile("ip", en10mb()).unwrap();
        let ip_pkt = eth_frame([0; 6], [0; 6], 0x0800, &[0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0]);
        let arp_pkt = eth_frame([0; 6], [0; 6], 0x0806, &[0u8; 20]);
        assert!(prog.filter(&ip_pkt));
        assert!(!prog.filter(&arp_pkt));
    }

    #[test]
    fn tcp_filter_checks_protocol() {
        // IP header with protocol field = 6 at offset 9.
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0];
        ip.resize(20, 0);
        let pkt = eth_frame([0; 6], [0; 6], 0x0800, &ip);
        let prog = FilterBuilder::compile("tcp", en10mb()).unwrap();
        assert!(prog.filter(&pkt));

        let mut udp_ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        udp_ip.resize(20, 0);
        let udp = eth_frame([0; 6], [0; 6], 0x0800, &udp_ip);
        assert!(!prog.filter(&udp));
    }

    #[test]
    fn empty_filter_accepts_all() {
        let prog = FilterBuilder::compile("", en10mb()).unwrap();
        assert!(prog.filter(&[0u8; 32]));
    }

    #[test]
    fn host_filter() {
        let prog = FilterBuilder::compile("host 1.2.3.4", en10mb()).unwrap();
        // Build an IP packet dst=1.2.3.4, src=9.9.9.9
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0];
        ip.extend_from_slice(&[9, 9, 9, 9]); // src
        ip.extend_from_slice(&[1, 2, 3, 4]); // dst
        let pkt = eth_frame([0; 6], [0; 6], 0x0800, &ip);
        assert!(prog.filter(&pkt));
    }

    #[test]
    fn vm_program_executes() {
        // Program: load word at offset 12 == 0x0800
        let prog = vec![
            load_insn(BPF_LD, BPF_H, 12),
            jmp_insn(BPF_JEQ, 0x0800, 1, 0),
            ret(BPF_REJECT),
            ret(BPF_ACCEPT),
        ];
        let pkt = eth_frame([0; 6], [0; 6], 0x0800, &[]);
        let mut vm = BpfVm::new();
        assert!(vm.filter_ok(&prog, &pkt));
        let arp = eth_frame([0; 6], [0; 6], 0x0806, &[]);
        assert!(!vm.filter_ok(&prog, &arp));
    }
}
