use crate::addr::Src;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

#[derive(Debug, Default)]
pub struct Lifelines {
    pub own: Vec<IpAddr>,
    pub gateways: Vec<IpAddr>,
    pub ssh_peers: Vec<IpAddr>,
}

impl Lifelines {
    pub fn read() -> Self {
        let mut ssh_peers = Vec::new();
        for (file, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
            if let Ok(text) = std::fs::read_to_string(file) {
                ssh_peers.extend(established_peers(&text, 22, v6));
            }
        }
        if let Some(ip) = std::env::var("SSH_CONNECTION")
            .ok()
            .and_then(|v| v.split_whitespace().next().and_then(|a| a.parse().ok()))
        {
            ssh_peers.push(ip);
        }
        let own = Command::new("ip")
            .args(["-j", "addr"])
            .output()
            .ok()
            .map(|o| own_addresses(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
        let gateways = std::fs::read_to_string("/proc/net/route")
            .map(|t| route_gateways(&t))
            .unwrap_or_default();
        Lifelines {
            own,
            gateways,
            ssh_peers,
        }
    }

    pub fn why_not(&self, target: Src) -> Option<String> {
        let hits = |list: &[IpAddr]| list.iter().any(|ip| Src::from(*ip) == target);
        if hits(&[
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]) {
            return Some(format!("{target} is this machine's loopback"));
        }
        if hits(&self.own) {
            return Some(format!("{target} is one of this machine's own addresses"));
        }
        if hits(&self.gateways) {
            return Some(format!(
                "{target} is the default gateway: banning it cuts the network"
            ));
        }
        if hits(&self.ssh_peers) {
            return Some(format!(
                "{target} has an SSH session open to this machine: banning it would lock that session out"
            ));
        }
        None
    }
}

pub fn established_peers(text: &str, local_port: u16, v6: bool) -> Vec<IpAddr> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (local, remote, state) = (f.get(1)?, f.get(2)?, f.get(3)?);
            if *state != "01" {
                return None;
            }
            let port = u16::from_str_radix(local.rsplit(':').next()?, 16).ok()?;
            if port != local_port {
                return None;
            }
            let hex = remote.split(':').next()?;
            parse_proc_addr(hex, v6)
        })
        .collect()
}

fn parse_proc_addr(hex: &str, v6: bool) -> Option<IpAddr> {
    if !v6 {
        let n = u32::from_str_radix(hex, 16).ok()?;
        return Some(IpAddr::V4(Ipv4Addr::from(n.swap_bytes())));
    }
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, word) in hex.as_bytes().chunks(8).enumerate() {
        let w = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16)
            .ok()?
            .swap_bytes();
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

pub fn route_gateways(text: &str) -> Vec<IpAddr> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let gw = u32::from_str_radix(f.get(2)?, 16).ok()?;
            (gw != 0).then(|| IpAddr::V4(Ipv4Addr::from(gw.swap_bytes())))
        })
        .collect()
}

pub fn own_addresses(json: &str) -> Vec<IpAddr> {
    let Ok(serde_json::Value::Array(ifaces)) = serde_json::from_str::<serde_json::Value>(json)
    else {
        return Vec::new();
    };
    ifaces
        .iter()
        .filter_map(|i| i.get("addr_info")?.as_array())
        .flatten()
        .filter_map(|a| a.get("local")?.as_str()?.parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_ssh_peers_from_proc_net_tcp() {
        let text = "  sl  local_address rem_address   st\n   0: 0100A8C0:0016 6400A8C0:D2F0 01 0\n   1: 0100A8C0:0016 6500A8C0:D2F1 0A 0\n   2: 0100A8C0:01BB 6600A8C0:D2F2 01 0\n";
        assert_eq!(
            established_peers(text, 22, false),
            vec!["192.168.0.100".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn reads_v6_peers() {
        let text = "hdr\n 0: 00000000000000000000000001000000:0016 B80D0120000000000000000001000000:C350 01 0\n";
        assert_eq!(
            established_peers(text, 22, true),
            vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn reads_the_default_gateway() {
        let text = "Iface\tDestination\tGateway\tFlags\nwlan0\t00000000\t0100A8C0\t0003\nwlan0\t0000A8C0\t00000000\t0001\n";
        assert_eq!(
            route_gateways(text),
            vec!["192.168.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn reads_own_addresses_from_ip_json() {
        let json = r#"[{"ifname":"lo","addr_info":[{"local":"127.0.0.1"}]},{"ifname":"wlan0","addr_info":[{"local":"192.168.0.5"},{"local":"fe80::1"}]}]"#;
        assert_eq!(own_addresses(json).len(), 3);
    }

    #[test]
    fn refuses_the_addresses_that_keep_the_machine_reachable() {
        let l = Lifelines {
            own: vec!["192.168.0.5".parse().unwrap()],
            gateways: vec!["192.168.0.1".parse().unwrap()],
            ssh_peers: vec!["10.0.0.9".parse().unwrap()],
        };
        for ip in ["127.0.0.1", "192.168.0.5", "192.168.0.1", "10.0.0.9", "::1"] {
            assert!(l.why_not(ip.parse().unwrap()).is_some(), "{ip}");
        }
        assert!(l.why_not("203.0.113.7".parse().unwrap()).is_none());
    }
}
