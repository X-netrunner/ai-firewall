//---------------------------
// Kernel-space Metrics Aggregation
//---------------------------

#![no_std]
#![no_main]

use ai_firewall_common::KernelMetrics;
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

/// Blocklist map
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

/// Metrics map
#[map]
static METRICS_MAP: HashMap<u32, KernelMetrics> = HashMap::<u32, KernelMetrics>::with_max_entries(10240, 0);

#[xdp]
pub fn ai_firewall(ctx: XdpContext) -> u32 {
    match try_ai_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_ai_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let start = ctx.data() as *const u8;
    let end = ctx.data_end() as *const u8;

    if start.wrapping_add(EthHdr::LEN) > end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_hdr = unsafe { &*(start as *const EthHdr) };
    let ether_type = eth_hdr.ether_type;
    if ether_type != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_start = start.wrapping_add(EthHdr::LEN);
    if ip_start.wrapping_add(Ipv4Hdr::LEN) > end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = unsafe { &*(ip_start as *const Ipv4Hdr) };
    let src_ip = u32::from_be(ip_hdr.src_addr);
    let proto = ip_hdr.proto;

    // 1. Instant drop if IP is in BLOCKLIST
    if unsafe { BLOCKLIST.get(&src_ip) }.is_some() {
        return Ok(xdp_action::XDP_DROP);
    }

    // 2. Compute packet length
    let pkt_len = (end as usize - start as usize) as u64;
    let transport_start = ip_start.wrapping_add(Ipv4Hdr::LEN);

    let mut is_syn = false;

    if proto == IpProto::Tcp && transport_start.wrapping_add(TcpHdr::LEN) <= end {
        let tcp_hdr = unsafe { &*(transport_start as *const TcpHdr) };
        if tcp_hdr.syn() != 0 && tcp_hdr.ack() == 0 {
            is_syn = true;
        }
    }

    // 3. Aggregate metrics in kernel map
    if let Some(metrics) = METRICS_MAP.get_ptr_mut(&src_ip) {
        unsafe {
            (*metrics).packet_count += 1;
            (*metrics).bytes_count += pkt_len;
            match proto {
                IpProto::Tcp => {
                    (*metrics).tcp_count += 1;
                    if is_syn {
                        (*metrics).syn_count += 1;
                    }
                }
                IpProto::Udp => (*metrics).udp_count += 1,
                IpProto::Icmp => (*metrics).icmp_count += 1,
                _ => {}
            }
        }
    } else {
        let new_metrics = KernelMetrics {
            packet_count: 1,
            bytes_count: pkt_len,
            tcp_count: if proto == IpProto::Tcp { 1 } else { 0 },
            udp_count: if proto == IpProto::Udp { 1 } else { 0 },
            icmp_count: if proto == IpProto::Icmp { 1 } else { 0 },
            syn_count: if is_syn { 1 } else { 0 },
            last_seen_ts: 0,
        };
        let _ = METRICS_MAP.insert(&src_ip, &new_metrics, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
