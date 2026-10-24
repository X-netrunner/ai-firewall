//---------------------------
// 5.1 Config: /etc/ai-firewall/config.toml (reloaded on SIGHUP or when the file changes)
//---------------------------

use anyhow::{Context as _, bail};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::Path;

pub const DEFAULT_PATH: &str = "/etc/ai-firewall/config.toml";

pub const DEFAULT_CONFIG: &str = r#"# ai-firewall config. Apply changes with: sudo systemctl reload ai-firewall

# "enforce" drops traffic; "monitor" only logs what it would drop or ban
mode = "enforce"

# "auto" follows the default route (wifi <-> ethernet), or name one, e.g. "wlp3s0"
interface = "auto"

# Inbound ports open to everyone (like `ufw allow 22/tcp`). Outbound traffic is always allowed.
allow_tcp = []
# 68 and 546 (DHCP client) are always open so you never lose your lease.
# 5353 = mDNS (printers, .local names)
allow_udp = [5353]

allow_ping = true

# Docker (and ufw) set a drop-by-default FORWARD policy that silently cuts libvirt
# VMs off the internet. Keep a narrow exception for VM bridges in place.
keep_vm_forwarding = true

# UDP to your high ports only gets in as a reply to something you sent (like ufw's
# connection tracking). Turn off if a peer-to-peer app or game stops connecting.
udp_strict = true

# Addresses or CIDRs never auto-banned (your router, DNS servers and own
# addresses are protected automatically). e.g. ["192.168.1.0/24"]
trusted = []

# Addresses or CIDRs always dropped, e.g. ["203.0.113.7"]
blocked = []

[detector]
# Threat score is summed per source IP over this window; 1.0 or more = ban
window_secs = 10
# New TCP connection attempts per window
syn_limit = 40
# Distinct ports probed per window (port scan)
port_limit = 12
# Unsolicited UDP packets per window
udp_limit = 150
# Packets dropped by policy per window
drop_limit = 30

[bans]
# First ban length; each repeat offence doubles it up to max_secs
base_secs = 120
max_secs = 86400
# A source that stays quiet this long gets its strikes reset
forgive_secs = 21600
"#;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_iface")]
    pub interface: String,
    #[serde(default)]
    pub allow_tcp: Vec<u16>,
    #[serde(default)]
    pub allow_udp: Vec<u16>,
    #[serde(default = "yes")]
    pub allow_ping: bool,
    #[serde(default = "yes")]
    pub keep_vm_forwarding: bool,
    #[serde(default = "yes")]
    pub udp_strict: bool,
    #[serde(default)]
    pub trusted: Vec<String>,
    #[serde(default)]
    pub blocked: Vec<String>,
    #[serde(default)]
    pub detector: DetectorConfig,
    #[serde(default)]
    pub bans: BanConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectorConfig {
    pub window_secs: u64,
    pub syn_limit: u32,
    pub port_limit: u32,
    pub udp_limit: u32,
    pub drop_limit: u32,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self { window_secs: 10, syn_limit: 40, port_limit: 12, udp_limit: 150, drop_limit: 30 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BanConfig {
    pub base_secs: u64,
    pub max_secs: u64,
    pub forgive_secs: u64,
}

impl Default for BanConfig {
    fn default() -> Self {
        Self { base_secs: 120, max_secs: 86400, forgive_secs: 21600 }
    }
}

fn default_mode() -> String {
    "enforce".into()
}
fn default_iface() -> String {
    "auto".into()
}
fn yes() -> bool {
    true
}

/// IPv4 network in host order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub net: u32,
    pub mask: u32,
}

impl Cidr {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let (addr, bits) = match s.split_once('/') {
            Some((a, b)) => (a, b.parse::<u32>().with_context(|| format!("bad prefix in {s}"))?),
            None => (s, 32),
        };
        if bits > 32 {
            bail!("bad prefix in {s}");
        }
        let addr: Ipv4Addr = addr.trim().parse().with_context(|| format!("bad address {s}"))?;
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        Ok(Self { net: u32::from(addr) & mask, mask })
    }

    pub fn single(ip: u32) -> Self {
        Self { net: ip, mask: u32::MAX }
    }

    pub fn contains(&self, ip: u32) -> bool {
        ip & self.mask == self.net
    }

    #[cfg(test)]
    pub fn is_single(&self) -> bool {
        self.mask == u32::MAX
    }
}

impl Config {
    pub fn enforce(&self) -> bool {
        self.mode == "enforce"
    }

    pub fn trusted_cidrs(&self) -> anyhow::Result<Vec<Cidr>> {
        self.trusted.iter().map(|s| Cidr::parse(s)).collect()
    }

    pub fn blocked_cidrs(&self) -> anyhow::Result<Vec<Cidr>> {
        self.blocked.iter().map(|s| Cidr::parse(s)).collect()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.mode != "enforce" && self.mode != "monitor" {
            bail!("mode must be \"enforce\" or \"monitor\", got {:?}", self.mode);
        }
        self.trusted_cidrs()?;
        for c in self.blocked_cidrs()? {
            // The XDP blocklist is an exact-match map; ranges wider than /20 would crowd it
            if c.mask.leading_ones() < 20 {
                bail!("blocked ranges must be /20 (4096 addresses) or narrower");
            }
        }
        let d = &self.detector;
        if d.window_secs == 0 || d.syn_limit == 0 || d.port_limit == 0 || d.udp_limit == 0 || d.drop_limit == 0 {
            bail!("detector values must be above 0");
        }
        if self.bans.base_secs == 0 || self.bans.max_secs < self.bans.base_secs {
            bail!("bans: base_secs must be above 0 and max_secs at least base_secs");
        }
        Ok(())
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Writes the commented default the first time so there's always a file to edit
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, DEFAULT_CONFIG)?;
        }
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let cfg = Config::parse(DEFAULT_CONFIG).unwrap();
        assert!(cfg.enforce());
        assert_eq!(cfg.allow_udp, vec![5353]);
        assert_eq!(cfg.detector.port_limit, 12);
    }

    #[test]
    fn empty_config_uses_defaults() {
        let cfg = Config::parse("").unwrap();
        assert_eq!(cfg.interface, "auto");
        assert_eq!(cfg.bans.base_secs, 120);
    }

    #[test]
    fn rejects_typos() {
        assert!(Config::parse("allow_tpc = [22]").is_err());
        assert!(Config::parse("mode = \"block\"").is_err());
    }

    #[test]
    fn cidr_matching() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains(u32::from(Ipv4Addr::new(192, 168, 1, 77))));
        assert!(!c.contains(u32::from(Ipv4Addr::new(192, 168, 2, 1))));
        assert!(Cidr::parse("10.0.0.1").unwrap().is_single());
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(12345));
        assert!(Cidr::parse("1.2.3.4/33").is_err());
    }
}
