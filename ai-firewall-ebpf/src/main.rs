//---------------------------
// 1.2 || 2.1 || 3.2
//---------------------------

#![no_std]
#![no_main]

use ai_firewall_common::PacketEvent;
use aya_ebpf::{
	bindings::xdp_action, 
	macros::{map, xdp},
	maps::{HashMap, RingBuf}, 
	programs::XdpContext,
};

use aya_log_ebpf::info;

use network_types::{
	eth::{EthHdr , EtherType},
	ip::{IpProto,Ipv4Hdr},
	tcp::TcpHdr,
	udp::UdpHdr,
};

//2.1
#[map]
static BLOCKLIST: HashMap<u32, u32> =HashMap::<u32, u32>::with_max_entries(1024,0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16777216, 0);

#[xdp]
pub fn ai_firewall(ctx: XdpContext) -> u32 {
    match try_ai_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_ai_firewall(ctx: XdpContext) -> Result<u32, ()> {
    //info!(&ctx, "received a packet");
    let start = ctx.data() as *const u8;
    let end = ctx.data_end() as *const u8;

    if start.wrapping_add(EthHdr::LEN) > end {
   		return Ok(xdp_action::XDP_PASS)    	
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

    let ip_hdr = unsafe {&*(ip_start as *const Ipv4Hdr) };
	let src_addr = ip_hdr.src_addr;
    let src_ip = u32::from_be(ip_hdr.src_addr);
	let proto = ip_hdr.proto;
    
    //info!(&ctx, "Imbound IPv4 packet from IP : {:i}" ,src_ip);

	if unsafe { BLOCKLIST.get(&src_ip) }.is_some(){
		info!(&ctx, "[BLOCKED] Dropping packet from IP: {:i}",src_ip);
		return Ok(xdp_action::XDP_DROP);
	}

	let transport_start= ip_start.wrapping_add(Ipv4Hdr::LEN);
	let mut dst_port: u16 = 0;

	match proto {
		IpProto::Tcp => {
			if transport_start.wrapping_add(TcpHdr::LEN) <=end {
				let tcp_hdr = unsafe {&*(transport_start as *const TcpHdr) };
				let dst_port = u16::from_be(tcp_hdr.dest);
				info!(
					&ctx,
					"Inbound TCP packet from {:i} to port {}",src_ip ,dst_port
				);
			}
		}
		IpProto::Udp => {
					if transport_start.wrapping_add(UdpHdr::LEN) <=end {
						let udp_hdr = unsafe {&*(transport_start as *const UdpHdr) };
						let dst_port = u16::from_be(udp_hdr.dest);
						info!(
							&ctx,
							"Inbound UDP packet from {:i} to port {}",src_ip ,dst_port
						);
					}
				}
			_ => {}
	}

	//3.2
	if let Some(mut entry) = EVENTS.reserve::<PacketEvent>(0) {
		entry.write(PacketEvent {
			src_ip,
			dst_port,
			protocol: proto as u8,
			_pad: 0,
		});
		entry.submit(0);
	}
	
    Ok(xdp_action::XDP_PASS)
}


#[cfg(not(test))]
#[panic_handler]

fn panic(_info: &core::panic::PanicInfo) -> ! {
    //loop {}
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
