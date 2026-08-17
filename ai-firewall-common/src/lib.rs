//
// 2.1 || 3.2
// 

#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketLog {
	pub ipv4_src: u32,
	pub ipv4_dst: u32,
	pub port: u16,
	pub protocol: u8,
	pub _pad: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
