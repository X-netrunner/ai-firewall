//---------------------------
// 8.1 A traffic source: an IPv4 address, or an IPv6 /64 (one host usually owns a
// whole /64, so banning a single v6 address would be trivial to dodge)
//---------------------------

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use ai_firewall_common::{FAMILY_V6, PacketEvent};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Src {
    V4(u32),
    V6(u64),
}

impl Src {
    pub fn of(ev: &PacketEvent) -> Self {
        if ev.family == FAMILY_V6 {
            Src::V6(ev.src6)
        } else {
            Src::V4(ev.src_ip)
        }
    }

    pub fn v6_prefix(ip: Ipv6Addr) -> u64 {
        (u128::from(ip) >> 64) as u64
    }
}

impl fmt::Display for Src {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Src::V4(ip) => write!(f, "{}", Ipv4Addr::from(*ip)),
            Src::V6(p) => write!(f, "{}/64", Ipv6Addr::from((*p as u128) << 64)),
        }
    }
}

impl FromStr for Src {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let addr = s.strip_suffix("/64").unwrap_or(s);
        match addr.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) if addr == s => Ok(Src::V4(u32::from(ip))),
            Ok(IpAddr::V6(ip)) => Ok(Src::V6(Src::v6_prefix(ip))),
            _ => anyhow::bail!("{s:?} is not an IPv4 address or an IPv6 address / prefix"),
        }
    }
}

impl Serialize for Src {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Src {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for s in ["10.0.0.5", "2001:db8:1:2::/64"] {
            assert_eq!(s.parse::<Src>().unwrap().to_string(), s);
        }
        // a full v6 address bans its /64
        assert_eq!(
            "2001:db8:1:2:aaaa::1".parse::<Src>().unwrap().to_string(),
            "2001:db8:1:2::/64"
        );
        assert!("10.0.0.5/64".parse::<Src>().is_err());
        assert!("nope".parse::<Src>().is_err());
    }
}
