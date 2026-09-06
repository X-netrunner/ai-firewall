//---------------------------
// 1.2 || 2.1
//---------------------------

#![no_std]
#![no_main]

use aya_ebpf::{
	bindings::xdp_action, 
	macros::xdp, 
	programs::XdpContext
};

use aya_log_ebpf::info;

use network_types::{
	eth::{EthHdr , EtherType},
	ip::Ipv4Hdr,
}; //1.2

#[xdp]
pub fn ai_firewall(ctx: XdpContext) -> u32 {
    match try_ai_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_ai_firewall(ctx: XdpContext) -> Result<u32, ()> {
    info!(&ctx, "received a packet");
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
    } // OPTIONAL CHECK TO SEE if buffer has enough bytes for ipv4 header

    let ip_hdr = unsafe {&*(ip_start as *const Ipv4Hdr) };
    let src_ip = u32::from_be(ip_hdr.src_addr);
    
    info!(&ctx, "Imbound IPv4 packet from IP : {:i}" ,src_ip);

    Ok(xdp_action::XDP_PASS)
} //1.2


#[cfg(not(test))]
#[panic_handler]

fn panic(_info: &core::panic::PanicInfo) -> ! {
    //loop {}
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
