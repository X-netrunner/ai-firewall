//---------------------------
// 5.1 Host facts: uplink interface, gateway, DNS, own addresses, kernel clock
//---------------------------

use std::net::Ipv4Addr;

use crate::config::Cidr;

/// CLOCK_BOOTTIME in ns: the same clock `bpf_ktime_get_boot_ns` reads, and it keeps
/// counting through suspend so bans don't stretch while the laptop sleeps
pub fn boot_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn boot_secs() -> u64 {
    boot_ns() / 1_000_000_000
}

pub fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// (interface, gateway) of the lowest-metric IPv4 default route
pub fn default_route() -> Option<(String, u32)> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_route(&text)
}

fn parse_default_route(text: &str) -> Option<(String, u32)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 7 || f[1] != "00000000" || f[7] != "00000000" {
                return None;
            }
            // /proc/net/route prints the raw network-order u32 in native-endian hex
            let gw = u32::from_be(u32::from_str_radix(f[2], 16).ok()?);
            let metric: u32 = f[6].parse().ok()?;
            Some((metric, f[0].to_string(), gw))
        })
        .min_by_key(|r| r.0)
        .map(|(_, iface, gw)| (iface, gw))
}

/// Names of the active NetworkManager connections (wifi network names, "Wired connection 1" ...);
/// empty without NetworkManager
pub fn active_connections() -> Vec<String> {
    let Ok(out) = std::process::Command::new("nmcli")
        .args(["-t", "-f", "NAME", "connection", "show", "--active"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.replace("\\:", ":").replace("\\\\", "\\"))
        .filter(|l| !l.is_empty())
        .collect()
}

pub fn ifindex(iface: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub fn ephemeral_low() -> u32 {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(32768)
}

pub fn nameservers() -> Vec<u32> {
    let mut out = Vec::new();
    // resolv.conf may just point at the systemd-resolved stub, so read its upstreams too
    for path in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                if let Some(rest) = line.trim().strip_prefix("nameserver")
                    && let Ok(ip) = rest.trim().parse::<Ipv4Addr>()
                {
                    out.push(u32::from(ip));
                }
            }
        }
    }
    out
}

fn own_addresses() -> Vec<u32> {
    interface_networks().into_iter().map(|n| n.addr).collect()
}

#[derive(Debug, Clone)]
pub struct IfaceNet {
    pub iface: String,
    pub addr: u32,
    pub net: Cidr,
}

/// True for virtual-machine / container bridges (libvirt, Docker, Podman, LXD)
pub fn is_virt_bridge(iface: &str) -> bool {
    ["virbr", "docker", "br-", "podman", "lxdbr", "vmnet", "cni"]
        .iter()
        .any(|p| iface.starts_with(p))
}

pub fn virt_bridges() -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| is_virt_bridge(n))
        .collect();
    out.sort();
    out
}

/// IPv4 address and network of every interface
pub fn interface_networks() -> Vec<IfaceNet> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() && unsafe { (*ifa.ifa_addr).sa_family } as i32 == libc::AF_INET {
            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            let addr = u32::from_be(sin.sin_addr.s_addr);
            let mask = if ifa.ifa_netmask.is_null() {
                u32::MAX
            } else {
                u32::from_be(
                    unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) }
                        .sin_addr
                        .s_addr,
                )
            };
            let iface = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            out.push(IfaceNet {
                iface,
                addr,
                net: Cidr {
                    net: addr & mask,
                    mask,
                },
            });
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifap) };
    out
}

/// /64 prefixes of this machine's global IPv6 addresses (link-local is handled separately)
pub fn own_v6_prefixes() -> Vec<u64> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() && unsafe { (*ifa.ifa_addr).sa_family } as i32 == libc::AF_INET6
        {
            let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            if !ip.is_loopback() {
                out.push(crate::addr::Src::v6_prefix(ip));
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifap) };
    out.sort_unstable();
    out.dedup();
    out
}

/// Sources that must never be auto-banned: spoofed UDP "from" them could otherwise
/// trick us into cutting off our own router or DNS
pub fn auto_protected() -> Vec<Cidr> {
    let mut out = vec![Cidr::parse("127.0.0.0/8").unwrap(), Cidr::single(0)];
    if let Some((_, gw)) = default_route() {
        out.push(Cidr::single(gw));
    }
    out.extend(nameservers().into_iter().map(Cidr::single));
    out.extend(own_addresses().into_iter().map(Cidr::single));
    // Your own VMs and containers
    out.extend(
        interface_networks()
            .into_iter()
            .filter(|n| is_virt_bridge(&n.iface))
            .map(|n| n.net),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_lowest_metric_default_route() {
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            wlp3s0\t00000000\t0100430A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
            enp2s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            wlp3s0\t0000430A\t00000000\t0001\t0\t0\t600\t00C0FFFF\t0\t0\t0\n";
        let (iface, gw) = parse_default_route(text).unwrap();
        assert_eq!(iface, "enp2s0");
        assert_eq!(Ipv4Addr::from(gw), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn boot_clock_moves() {
        assert!(boot_ns() > 0);
    }
}
