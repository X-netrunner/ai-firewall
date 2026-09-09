//
// 2.1 || 3.2
// 

#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelMetrics {
	pub packet_count: u64,
	pub bytes_count: u64,
	pub tcp_count: u32,
	pub udp_count: u32,
	pub icmp_count: u32,
	pub syn_count: u32,
	pub last_seen_ts: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for KernelMetrics {}
