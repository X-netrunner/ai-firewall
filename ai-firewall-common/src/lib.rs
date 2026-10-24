#![no_std]

pub const TCP_FLAG_FIN: u8 = 1 << 0;
pub const TCP_FLAG_SYN: u8 = 1 << 1;
pub const TCP_FLAG_RST: u8 = 1 << 2;
pub const TCP_FLAG_PSH: u8 = 1 << 3;
pub const TCP_FLAG_ACK: u8 = 1 << 4;
pub const TCP_FLAG_URG: u8 = 1 << 5;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

// Verdicts the kernel attaches to each streamed event
pub const VERDICT_PASS: u8 = 0;
pub const VERDICT_DROP_POLICY: u8 = 1;

// CONFIG array slots (written by userspace, read by XDP)
pub const CFG_ENFORCE: u32 = 0; // 1 = drop, 0 = monitor only
pub const CFG_EPHEMERAL_LOW: u32 = 1; // replies to our outbound UDP land at or above this port
pub const CFG_DROP_PING: u32 = 2; // 1 = drop inbound ICMP echo requests
pub const CFG_UDP_STRICT: u32 = 3; // 1 = ephemeral-port UDP only passes as a reply to a flow we started
pub const CFG_LEN: u32 = 4;

// STATS per-cpu array slots
pub const STAT_PASSED: u32 = 0;
pub const STAT_DROP_BLOCKLIST: u32 = 1;
pub const STAT_DROP_POLICY: u32 = 2;
pub const STAT_EVENTS_LOST: u32 = 3;
pub const STAT_DROP_FEED: u32 = 4; // from a network on a blocklist feed
pub const STAT_LEN: u32 = 5;

/// BLOCKLIST value meaning "never expires"
pub const BAN_FOREVER: u64 = 0;

/// How long an outbound UDP flow keeps accepting replies after its last packet out
pub const UDP_FLOW_TTL_NS: u64 = 180 * 1_000_000_000;

pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;

/// Outbound UDP flow, recorded on egress, looked up when a reply comes in.
/// remote_ip = 0 and remote_port = 0 mark a query sent to multicast / broadcast,
/// which any LAN device may answer.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpFlow {
    pub remote_ip: u32,
    pub local_port: u16,
    pub remote_port: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpFlow6 {
    pub remote_ip: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
}

/// Only "interesting" packets are streamed (new connection attempts, odd flags,
/// unsolicited UDP, policy drops) so established traffic costs userspace nothing.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketEvent {
    /// IPv6 sources are tracked (and banned) by their /64, since one host owns a whole /64
    pub src6: u64,
    pub src_ip: u32,
    pub dst_port: u16,
    pub src_port: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub payload_len: u16,
    pub verdict: u8,
    pub family: u8,
    pub _pad: [u8; 2],
}

impl PacketEvent {
    #[inline]
    pub fn is_syn(&self) -> bool {
        (self.tcp_flags & TCP_FLAG_SYN) != 0 && (self.tcp_flags & TCP_FLAG_ACK) == 0
    }

    #[inline]
    pub fn is_fin(&self) -> bool {
        (self.tcp_flags & TCP_FLAG_FIN) != 0
    }

    #[inline]
    pub fn is_rst(&self) -> bool {
        (self.tcp_flags & TCP_FLAG_RST) != 0
    }

    #[inline]
    pub fn is_null_scan(&self) -> bool {
        self.protocol == PROTO_TCP && self.tcp_flags == 0
    }

    #[inline]
    pub fn is_xmas_scan(&self) -> bool {
        let mask = TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH;
        (self.tcp_flags & mask) == mask
    }

    /// FIN without ACK never happens in a real connection: it's a stealth scan
    #[inline]
    pub fn is_fin_scan(&self) -> bool {
        self.protocol == PROTO_TCP && self.is_fin() && (self.tcp_flags & TCP_FLAG_ACK) == 0
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}

// 11.1 Richer rules
/// "allow <port> from <cidr>": LPM trie key data = port (big-endian) then IPv4 address (big-endian),
/// prefix length = 16 + the CIDR's bits, so one lookup of (port, source) finds the narrowest match
pub type RuleKey = [u8; 6];

/// Per-port rate limit for new TCP connections: (max << 16) | window_secs, 0 = no limit
#[inline]
pub const fn rate_pack(max: u16, window_secs: u16) -> u32 {
    ((max as u32) << 16) | window_secs as u32
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RateState {
    pub window_start: u64,
    pub count: u32,
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateState {}
