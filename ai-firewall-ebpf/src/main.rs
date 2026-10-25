//---------------------------
// 1.2 || 2.1 || 3.2 || 4.2 Adaptive Defense || 5.1 Stateless default-deny || 8.1 UDP flows + IPv6 bans
//---------------------------

#![no_std]
#![no_main]

use ai_firewall_common::{
    BAN_FOREVER, CFG_DROP_PING, CFG_ENFORCE, CFG_EPHEMERAL_LOW, CFG_LEN, CFG_UDP_STRICT, FAMILY_V4,
    FAMILY_V6, PROTO_TCP, PROTO_UDP, PacketEvent, RateState, RuleKey, STAT_DROP_BLOCKLIST,
    STAT_DROP_FEED, STAT_DROP_POLICY, STAT_EVENTS_LOST, STAT_LEN, STAT_PASSED, TCP_FLAG_ACK,
    TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG, UDP_FLOW_TTL_NS, UdpFlow,
    UdpFlow6, VERDICT_DROP_POLICY, VERDICT_PASS,
};
use aya_ebpf::{
    bindings::{TC_ACT_UNSPEC, xdp_action},
    helpers::bpf_ktime_get_boot_ns,
    macros::{classifier, map, xdp},
    maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf, lpm_trie::Key},
    programs::{TcContext, XdpContext},
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// 2.1 Kernel Blocklist map: IPv4 (host order) -> expiry in CLOCK_BOOTTIME ns (0 = forever).
// Pinned under /sys/fs/bpf/ai-firewall so bans survive a daemon restart and the CLI can edit it.
#[map]
static BLOCKLIST: HashMap<u32, u64> = HashMap::<u32, u64>::pinned(65536, 0);

// 8.1 IPv6 bans by /64 prefix (first 8 address bytes, big-endian) -> expiry
#[map]
static BLOCKLIST6: HashMap<u64, u64> = HashMap::<u64, u64>::pinned(16384, 0);

// 8.1 Outbound UDP flows -> expiry. Pinned so replies keep flowing across restarts.
#[map]
static UDP_FLOWS: LruHashMap<UdpFlow, u64> = LruHashMap::<UdpFlow, u64>::pinned(65536, 0);
#[map]
static UDP_FLOWS6: LruHashMap<UdpFlow6, u64> = LruHashMap::<UdpFlow6, u64>::pinned(16384, 0);

// 3.2 Telemetry Ring Buffer (only interesting packets, so 256 KiB is plenty)
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262144, 0);

// 5.1 Inbound allow lists, indexed by port: 1 = open
#[map]
static TCP_ALLOW: Array<u8> = Array::<u8>::with_max_entries(65536, 0);
#[map]
static UDP_ALLOW: Array<u8> = Array::<u8>::with_max_entries(65536, 0);

// 11.1 "allow <port> from <cidr>" (IPv4), one trie per protocol
#[map]
static ALLOW_FROM_TCP: LpmTrie<RuleKey, u8> = LpmTrie::<RuleKey, u8>::with_max_entries(4096, 0);
#[map]
static ALLOW_FROM_UDP: LpmTrie<RuleKey, u8> = LpmTrie::<RuleKey, u8>::with_max_entries(4096, 0);

// 11.1 Per-port limit on new TCP connections from one source (brute-force guard)
#[map]
static TCP_RATE: Array<u32> = Array::<u32>::with_max_entries(65536, 0);
#[map]
static RATE_STATE: LruHashMap<u64, RateState> =
    LruHashMap::<u64, RateState>::with_max_entries(65536, 0);

// 11.2 Blocklist feeds: known-bad IPv4 networks (Spamhaus DROP, FireHOL ...), loaded by userspace
#[map]
static FEEDS: LpmTrie<[u8; 4], u8> = LpmTrie::<[u8; 4], u8>::with_max_entries(131072, 0);

#[map]
static CONFIG: Array<u32> = Array::<u32>::with_max_entries(CFG_LEN, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::<u64>::with_max_entries(STAT_LEN, 0);

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;

#[xdp]
pub fn ai_firewall(ctx: XdpContext) -> u32 {
    let action = try_ai_firewall(&ctx).unwrap_or(xdp_action::XDP_PASS);
    if action == xdp_action::XDP_PASS {
        bump(STAT_PASSED);
    }
    action
}

#[inline(always)]
fn bump(slot: u32) {
    if let Some(counter) = STATS.get_ptr_mut(slot) {
        unsafe { *counter += 1 };
    }
}

#[inline(always)]
fn config(slot: u32) -> u32 {
    CONFIG.get(slot).copied().unwrap_or(0)
}

#[inline(always)]
fn port_open(list: &Array<u8>, port: u16) -> bool {
    list.get(port as u32).copied().unwrap_or(0) != 0
}

#[inline(always)]
fn now() -> u64 {
    unsafe { bpf_ktime_get_boot_ns() }
}

#[inline(always)]
fn live(expiry: Option<&u64>) -> bool {
    match expiry {
        Some(e) => *e == BAN_FOREVER || now() < *e,
        None => false,
    }
}

/// L4 facts both IP versions feed into the same policy
struct Flow {
    proto: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    payload_len: u16,
}

/// Who sent it, for events and the detector
struct Source {
    family: u8,
    v4: u32,
    v6: u64,
}

fn try_ai_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    if start + EthHdr::LEN > end {
        return Ok(xdp_action::XDP_PASS);
    }
    let eth_hdr = unsafe { &*(start as *const EthHdr) };
    let ip_start = start + EthHdr::LEN;
    // Broadcast / multicast frames (discovery chatter from every device on the LAN)
    // are aimed at everyone, not at us: filtered like the rest, never counted as hostile
    let to_everyone = eth_hdr.dst_addr[0] & 1 != 0;

    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            if ip_start + Ipv4Hdr::LEN > end {
                return Ok(xdp_action::XDP_PASS);
            }
            let ip_hdr = unsafe { &*(ip_start as *const Ipv4Hdr) };
            let src_ip = u32::from_be(ip_hdr.src_addr);

            // Fast drop for known blocked IPs; expired entries pass even if the daemon is down
            if live(unsafe { BLOCKLIST.get(&src_ip) }) {
                bump(STAT_DROP_BLOCKLIST);
                return Ok(xdp_action::XDP_DROP);
            }
            if FEEDS.get(Key::new(32, src_ip.to_be_bytes())).is_some() {
                bump(STAT_DROP_FEED);
                return Ok(xdp_action::XDP_DROP);
            }

            // Non-first fragments carry no L4 header
            if u16::from_be(ip_hdr.frag_off) & 0x1fff != 0 {
                return Ok(xdp_action::XDP_PASS);
            }

            let ihl = ((ip_hdr.ihl() & 0x0f) as usize) * 4;
            if ihl < Ipv4Hdr::LEN {
                return Ok(xdp_action::XDP_PASS);
            }
            let l4 = ip_start + ihl;
            let proto = ip_hdr.proto as u8;

            if proto == IPPROTO_ICMP {
                return Ok(icmp_verdict(l4, end, ICMP_ECHO_REQUEST));
            }
            let Some(flow) = parse_l4(proto, l4, end) else {
                return Ok(xdp_action::XDP_PASS);
            };
            let reply = flow.proto == PROTO_UDP && {
                let exact = UdpFlow {
                    remote_ip: src_ip,
                    local_port: flow.dst_port,
                    remote_port: flow.src_port,
                };
                let any = UdpFlow {
                    remote_ip: 0,
                    local_port: flow.dst_port,
                    remote_port: 0,
                };
                live(unsafe { UDP_FLOWS.get(&exact) }) || live(unsafe { UDP_FLOWS.get(&any) })
            };
            let src = Source {
                family: FAMILY_V4,
                v4: src_ip,
                v6: 0,
            };
            Ok(policy(&src, &flow, to_everyone, reply))
        }
        EtherType::Ipv6 => {
            if ip_start + Ipv6Hdr::LEN > end {
                return Ok(xdp_action::XDP_PASS);
            }
            let ip_hdr = unsafe { &*(ip_start as *const Ipv6Hdr) };
            let src = unsafe { ip_hdr.src_addr.in6_u.u6_addr8 };
            let prefix = u64::from_be_bytes([
                src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
            ]);

            if live(unsafe { BLOCKLIST6.get(&prefix) }) {
                bump(STAT_DROP_BLOCKLIST);
                return Ok(xdp_action::XDP_DROP);
            }

            let l4 = ip_start + Ipv6Hdr::LEN;
            let proto = ip_hdr.next_hdr as u8;

            // Extension headers and NDP (ICMPv6) pass: breaking them breaks IPv6 itself
            if proto == IPPROTO_ICMPV6 {
                return Ok(icmp_verdict(l4, end, ICMPV6_ECHO_REQUEST));
            }
            let Some(flow) = parse_l4(proto, l4, end) else {
                return Ok(xdp_action::XDP_PASS);
            };
            let reply = flow.proto == PROTO_UDP && {
                let exact = UdpFlow6 {
                    remote_ip: src,
                    local_port: flow.dst_port,
                    remote_port: flow.src_port,
                };
                let any = UdpFlow6 {
                    remote_ip: [0; 16],
                    local_port: flow.dst_port,
                    remote_port: 0,
                };
                live(unsafe { UDP_FLOWS6.get(&exact) }) || live(unsafe { UDP_FLOWS6.get(&any) })
            };
            let source = Source {
                family: FAMILY_V6,
                v4: 0,
                v6: prefix,
            };
            Ok(policy(&source, &flow, to_everyone, reply))
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn icmp_verdict(l4: usize, end: usize, echo_request: u8) -> u32 {
    if l4 + 1 > end {
        return xdp_action::XDP_PASS;
    }
    let icmp_type = unsafe { *(l4 as *const u8) };
    if icmp_type == echo_request && config(CFG_DROP_PING) != 0 && config(CFG_ENFORCE) != 0 {
        bump(STAT_DROP_POLICY);
        return xdp_action::XDP_DROP;
    }
    xdp_action::XDP_PASS
}

#[inline(always)]
fn parse_l4(proto: u8, l4: usize, end: usize) -> Option<Flow> {
    if proto == IpProto::Tcp as u8 {
        if l4 + TcpHdr::LEN > end {
            return None;
        }
        let tcp_hdr = unsafe { &*(l4 as *const TcpHdr) };
        let mut tcp_flags: u8 = 0;
        if tcp_hdr.fin() != 0 {
            tcp_flags |= TCP_FLAG_FIN;
        }
        if tcp_hdr.syn() != 0 {
            tcp_flags |= TCP_FLAG_SYN;
        }
        if tcp_hdr.rst() != 0 {
            tcp_flags |= TCP_FLAG_RST;
        }
        if tcp_hdr.psh() != 0 {
            tcp_flags |= TCP_FLAG_PSH;
        }
        if tcp_hdr.ack() != 0 {
            tcp_flags |= TCP_FLAG_ACK;
        }
        if tcp_hdr.urg() != 0 {
            tcp_flags |= TCP_FLAG_URG;
        }
        let data_start = l4 + ((tcp_hdr.doff() & 0x0f) as usize) * 4;
        let payload_len = if data_start <= end {
            (end - data_start) as u16
        } else {
            0
        };
        Some(Flow {
            proto: PROTO_TCP,
            src_port: u16::from_be(tcp_hdr.source),
            dst_port: u16::from_be(tcp_hdr.dest),
            tcp_flags,
            payload_len,
        })
    } else if proto == IpProto::Udp as u8 {
        if l4 + UdpHdr::LEN > end {
            return None;
        }
        let udp_hdr = unsafe { &*(l4 as *const UdpHdr) };
        Some(Flow {
            proto: PROTO_UDP,
            src_port: u16::from_be(udp_hdr.source),
            dst_port: u16::from_be(udp_hdr.dest),
            tcp_flags: 0,
            payload_len: (end - (l4 + UdpHdr::LEN)) as u16,
        })
    } else {
        None
    }
}

/// Stand-in for ufw's "deny incoming, allow outgoing":
/// - TCP: only connection openers (SYN without ACK) need an open port; every other
///   segment belongs to a connection the kernel stack will vet (and RST if unknown).
/// - UDP: open ports, plus replies to flows we started (seen by the egress program).
///   With udp_strict off, anything to an ephemeral port counts as a reply instead.
#[inline(always)]
fn allowed_from(trie: &LpmTrie<RuleKey, u8>, src: &Source, port: u16) -> bool {
    if src.family != FAMILY_V4 {
        return false;
    }
    let p = port.to_be_bytes();
    let a = src.v4.to_be_bytes();
    trie.get(Key::new(48, [p[0], p[1], a[0], a[1], a[2], a[3]]))
        .is_some()
}

/// true when this new connection goes over the port's limit for this source
#[inline(always)]
fn over_rate(src: &Source, port: u16) -> bool {
    let packed = TCP_RATE.get(port as u32).copied().unwrap_or(0);
    if packed == 0 || src.family != FAMILY_V4 {
        return false;
    }
    let max = packed >> 16;
    let window = (packed & 0xffff) as u64 * 1_000_000_000;
    let key = ((src.v4 as u64) << 16) | port as u64;
    let t = now();
    match RATE_STATE.get_ptr_mut(&key) {
        Some(st) => {
            let st = unsafe { &mut *st };
            if t - st.window_start > window {
                st.window_start = t;
                st.count = 1;
                false
            } else {
                st.count += 1;
                st.count > max
            }
        }
        None => {
            let _ = RATE_STATE.insert(
                &key,
                &RateState {
                    window_start: t,
                    count: 1,
                    _pad: 0,
                },
                0,
            );
            false
        }
    }
}

fn policy(src: &Source, flow: &Flow, to_everyone: bool, reply: bool) -> u32 {
    let (interesting, allowed) = if flow.proto == PROTO_TCP {
        let f = flow.tcp_flags;
        let opener = (f & TCP_FLAG_SYN) != 0 && (f & TCP_FLAG_ACK) == 0;
        let fin_urg_psh = TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH;
        let odd = f == 0
            || (f & fin_urg_psh) == fin_urg_psh
            || (f & (TCP_FLAG_FIN | TCP_FLAG_ACK)) == TCP_FLAG_FIN;
        if odd {
            // Null / Xmas / FIN scans: never part of a real connection
            (true, false)
        } else if opener {
            let open = port_open(&TCP_ALLOW, flow.dst_port)
                || allowed_from(&ALLOW_FROM_TCP, src, flow.dst_port);
            (true, open && !over_rate(src, flow.dst_port))
        } else {
            (false, true)
        }
    } else {
        let loose_reply =
            config(CFG_UDP_STRICT) == 0 && (flow.dst_port as u32) >= config(CFG_EPHEMERAL_LOW);
        let reply = reply || loose_reply;
        (
            !reply,
            reply
                || port_open(&UDP_ALLOW, flow.dst_port)
                || allowed_from(&ALLOW_FROM_UDP, src, flow.dst_port),
        )
    };

    let drop = !allowed && config(CFG_ENFORCE) != 0;

    if interesting && !to_everyone {
        match EVENTS.reserve::<PacketEvent>(0) {
            Some(mut entry) => {
                entry.write(PacketEvent {
                    src6: src.v6,
                    src_ip: src.v4,
                    dst_port: flow.dst_port,
                    src_port: flow.src_port,
                    protocol: flow.proto,
                    tcp_flags: flow.tcp_flags,
                    payload_len: flow.payload_len,
                    verdict: if allowed {
                        VERDICT_PASS
                    } else {
                        VERDICT_DROP_POLICY
                    },
                    family: src.family,
                    _pad: [0; 2],
                });
                entry.submit(0);
            }
            None => bump(STAT_EVENTS_LOST),
        }
    }

    if drop {
        bump(STAT_DROP_POLICY);
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    }
}

// 8.1 Egress: remember every UDP flow we start so its replies get in.
// Runs after NAT, so VMs' and containers' flows are covered too. Never drops anything.
#[classifier]
pub fn ai_firewall_egress(ctx: TcContext) -> i32 {
    let _ = try_egress(&ctx);
    TC_ACT_UNSPEC
}

fn try_egress(ctx: &TcContext) -> Result<(), i64> {
    let eth: EthHdr = ctx.load(0)?;
    let to_everyone = eth.dst_addr[0] & 1 != 0;
    let expiry = now() + UDP_FLOW_TTL_NS;
    match eth.ether_type {
        EtherType::Ipv4 => {
            let ip: Ipv4Hdr = ctx.load(EthHdr::LEN)?;
            if ip.proto != IpProto::Udp {
                return Ok(());
            }
            let ihl = ((ip.ihl() & 0x0f) as usize) * 4;
            if ihl < Ipv4Hdr::LEN {
                return Ok(());
            }
            let udp: UdpHdr = ctx.load(EthHdr::LEN + ihl)?;
            let dst = u32::from_be(ip.dst_addr);
            let local_port = u16::from_be(udp.source);
            let key = if to_everyone || dst >> 28 == 0xe || dst == u32::MAX {
                UdpFlow {
                    remote_ip: 0,
                    local_port,
                    remote_port: 0,
                }
            } else {
                UdpFlow {
                    remote_ip: dst,
                    local_port,
                    remote_port: u16::from_be(udp.dest),
                }
            };
            let _ = UDP_FLOWS.insert(&key, &expiry, 0);
        }
        EtherType::Ipv6 => {
            let ip: Ipv6Hdr = ctx.load(EthHdr::LEN)?;
            if ip.next_hdr != IpProto::Udp {
                return Ok(());
            }
            let udp: UdpHdr = ctx.load(EthHdr::LEN + Ipv6Hdr::LEN)?;
            let dst = unsafe { ip.dst_addr.in6_u.u6_addr8 };
            let local_port = u16::from_be(udp.source);
            let key = if to_everyone || dst[0] == 0xff {
                UdpFlow6 {
                    remote_ip: [0; 16],
                    local_port,
                    remote_port: 0,
                }
            } else {
                UdpFlow6 {
                    remote_ip: dst,
                    local_port,
                    remote_port: u16::from_be(udp.dest),
                }
            };
            let _ = UDP_FLOWS6.insert(&key, &expiry, 0);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
