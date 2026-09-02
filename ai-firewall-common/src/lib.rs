//
// 2.1 || 3.2
// 

#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketEvent {
    pub src_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: u8, // Memory padding to align struct to 4 bytes
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}
