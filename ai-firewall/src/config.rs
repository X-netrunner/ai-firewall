//---------------------------
// 5.1 Config: /etc/ai-firewall/config.toml (reloaded on SIGHUP or when the file changes)
//---------------------------

use std::{net::Ipv4Addr, path::Path};

use anyhow::{Context as _, bail};
use serde::Deserialize;

pub const DEFAULT_PATH: &str = "/etc/ai-firewall/config.toml";
/// The last config the daemon applied, used when the real one is broken at boot
pub const LAST_GOOD: &str = "/var/lib/ai-firewall/last-good.toml";

pub const DEFAULT_CONFIG: &str = r#"# ai-firewall config. Apply changes with: sudo systemctl reload ai-firewall

# "enforce" drops traffic; "monitor" only logs what it would drop or ban
mode = "enforce"

# "auto" follows the default route (wifi <-> ethernet), or name one, e.g. "wlp3s0"
interface = "auto"

# Inbound ports open to everyone (like `ufw allow 22/tcp`); ranges are strings: "1714-1764".
# Outbound traffic is always allowed.
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

# Narrower rules: a port open only to some addresses, and / or a limit on new
# connections per source (over it, that source's new connections are dropped
# and count towards a ban). Examples:
# [[rule]]
# proto = "tcp"
# port = 22
# from = "192.168.1.0/24"   # leave out = from anywhere
# limit = "6/30s"           # tcp only: at most 6 new connections per 30 s per source
#
# [[rule]]
# proto = "tcp"
# port = "1714-1764"        # KDE Connect
# from = "192.168.1.0/24"

# Lists of known-bad networks, downloaded and refreshed by the daemon.
# Private and LAN ranges are always taken out of them.
[feeds]
# spamhaus-drop: hijacked / criminal netblocks (small, very few false positives)
# firehol-level1: a bigger mix of attack sources (also blocks more by mistake)
lists = ["spamhaus-drop"]
# your own: plain text, one address or CIDR per line
urls = []
refresh_hours = 24

# Network profiles: different open ports per network, picked by the
# NetworkManager connection name (`nmcli connection show --active`).
# A profile only replaces what it sets; anywhere else the settings above apply.
# [profiles.home]
# networks = ["MyHomeWifi", "Wired connection 1"]
# allow_tcp = [22, "1714-1764"]
# allow_ping = true

[notify]
# A desktop notification when a source is banned (several at once are grouped)
bans = true

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

[assistant]
# Ask the firewall what's wrong (in `ai-firewall top`, press a). Uses a local model only:
# LUNA's model if LUNA is set up, else Ollama. Without one you still get the doctor.
enabled = true
# "auto" picks a small installed model (qwen2.5:3b-instruct, llama3.2:3b, ...)
model = "auto"
# url = "http://localhost:11434"

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
    pub allow_tcp: Vec<PortSpec>,
    #[serde(default)]
    pub allow_udp: Vec<PortSpec>,
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
    #[serde(default)]
    pub assistant: AssistantConfig,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub feeds: FeedConfig,
    #[serde(default)]
    pub profiles: std::collections::BTreeMap<String, Profile>,
    #[serde(default)]
    pub notify: NotifyConfig,
}

/// A port or a range: 22 or "1714-1764"
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    One(u16),
    Text(String),
}

impl PortSpec {
    pub fn ports(&self) -> anyhow::Result<std::ops::RangeInclusive<u16>> {
        match self {
            PortSpec::One(0) => bail!("port 0 is not a port"),
            PortSpec::One(p) => Ok(*p..=*p),
            PortSpec::Text(t) => {
                let (a, b) = t.split_once('-').unwrap_or((t, t));
                let a: u16 = a
                    .trim()
                    .parse()
                    .with_context(|| format!("bad port {t:?}"))?;
                let b: u16 = b
                    .trim()
                    .parse()
                    .with_context(|| format!("bad port {t:?}"))?;
                if a == 0 || b < a || b - a >= 4096 {
                    bail!("bad port range {t:?} (1-65535, at most 4096 ports)");
                }
                Ok(a..=b)
            }
        }
    }

    pub fn label(&self) -> String {
        match self {
            PortSpec::One(p) => p.to_string(),
            PortSpec::Text(t) => t.trim().to_string(),
        }
    }
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label())
    }
}

pub fn expand(specs: &[PortSpec]) -> anyhow::Result<Vec<u16>> {
    let mut out = Vec::new();
    for s in specs {
        out.extend(s.ports()?);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub proto: String,
    pub port: PortSpec,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

impl Rule {
    /// "6/30s" -> (6, 30)
    pub fn rate(&self) -> anyhow::Result<Option<(u16, u16)>> {
        let Some(l) = &self.limit else {
            return Ok(None);
        };
        let (n, w) = l
            .split_once('/')
            .with_context(|| format!("limit {l:?} must look like 6/30s"))?;
        let w = w.trim();
        let (num, mult) = match w.chars().last() {
            Some('s') => (&w[..w.len() - 1], 1),
            Some('m') => (&w[..w.len() - 1], 60),
            _ => (w, 1),
        };
        let n: u16 = n
            .trim()
            .parse()
            .with_context(|| format!("bad limit {l:?}"))?;
        let secs: u32 = num
            .trim()
            .parse::<u32>()
            .with_context(|| format!("bad limit {l:?}"))?
            * mult;
        if n == 0 || secs == 0 || secs > 3600 {
            bail!("limit {l:?}: count and window must be above 0, window at most 1h");
        }
        Ok(Some((n, secs as u16)))
    }

    pub fn label(&self) -> String {
        let mut s = format!("{} {}", self.proto, self.port.label());
        if let Some(f) = &self.from {
            s.push_str(&format!(" from {f}"));
        }
        if let Some(l) = &self.limit {
            s.push_str(&format!(" limit {l}"));
        }
        s
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeedConfig {
    pub lists: Vec<String>,
    pub urls: Vec<String>,
    pub refresh_hours: u64,
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            lists: vec!["spamhaus-drop".into()],
            urls: Vec::new(),
            refresh_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default)]
    pub networks: Vec<String>,
    pub allow_tcp: Option<Vec<PortSpec>>,
    pub allow_udp: Option<Vec<PortSpec>>,
    pub allow_ping: Option<bool>,
    #[serde(rename = "rule")]
    pub rules: Option<Vec<Rule>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    pub bans: bool,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self { bans: true }
    }
}

/// What actually applies right now: the base settings with the active profile on top
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub profile: Option<String>,
    pub allow_tcp: Vec<PortSpec>,
    pub allow_udp: Vec<PortSpec>,
    pub allow_ping: bool,
    pub rules: Vec<Rule>,
}

impl PartialEq for Rule {
    fn eq(&self, o: &Self) -> bool {
        self.label() == o.label()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AssistantConfig {
    pub enabled: bool,
    pub model: String,
    pub url: Option<String>,
}

impl Default for AssistantConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model: "auto".into(),
            url: None,
        }
    }
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
        Self {
            window_secs: 10,
            syn_limit: 40,
            port_limit: 12,
            udp_limit: 150,
            drop_limit: 30,
        }
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
        Self {
            base_secs: 120,
            max_secs: 86400,
            forgive_secs: 21600,
        }
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
            Some((a, b)) => (
                a,
                b.parse::<u32>()
                    .with_context(|| format!("bad prefix in {s}"))?,
            ),
            None => (s, 32),
        };
        if bits > 32 {
            bail!("bad prefix in {s}");
        }
        let addr: Ipv4Addr = addr
            .trim()
            .parse()
            .with_context(|| format!("bad address {s}"))?;
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        Ok(Self {
            net: u32::from(addr) & mask,
            mask,
        })
    }

    pub fn single(ip: u32) -> Self {
        Self {
            net: ip,
            mask: u32::MAX,
        }
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
    /// The first profile listing one of the active connections wins (profiles in name order)
    pub fn profile_for(&self, active: &[String]) -> Option<String> {
        self.profiles
            .iter()
            .find(|(_, p)| p.networks.iter().any(|n| active.iter().any(|a| a == n)))
            .map(|(name, _)| name.clone())
    }

    pub fn policy(&self, profile: Option<&str>) -> Policy {
        let p = profile.and_then(|n| self.profiles.get(n));
        Policy {
            profile: p.and(profile.map(String::from)),
            allow_tcp: p
                .and_then(|p| p.allow_tcp.clone())
                .unwrap_or_else(|| self.allow_tcp.clone()),
            allow_udp: p
                .and_then(|p| p.allow_udp.clone())
                .unwrap_or_else(|| self.allow_udp.clone()),
            allow_ping: p.and_then(|p| p.allow_ping).unwrap_or(self.allow_ping),
            rules: p
                .and_then(|p| p.rules.clone())
                .unwrap_or_else(|| self.rules.clone()),
        }
    }

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
            bail!(
                "mode must be \"enforce\" or \"monitor\", got {:?}",
                self.mode
            );
        }
        self.trusted_cidrs()?;
        let check_policy = |what: &str,
                            tcp: &[PortSpec],
                            udp: &[PortSpec],
                            rules: &[Rule]|
         -> anyhow::Result<()> {
            expand(tcp).with_context(|| format!("{what} allow_tcp"))?;
            expand(udp).with_context(|| format!("{what} allow_udp"))?;
            for r in rules {
                if r.proto != "tcp" && r.proto != "udp" {
                    bail!("{what} rule {}: proto must be tcp or udp", r.label());
                }
                r.port
                    .ports()
                    .with_context(|| format!("{what} rule {}", r.label()))?;
                if let Some(f) = &r.from {
                    Cidr::parse(f).with_context(|| format!("{what} rule {}", r.label()))?;
                }
                if r.rate()?.is_some() && r.proto != "tcp" {
                    bail!("{what} rule {}: limit only works for tcp", r.label());
                }
            }
            Ok(())
        };
        check_policy("", &self.allow_tcp, &self.allow_udp, &self.rules)?;
        for (name, p) in &self.profiles {
            check_policy(
                &format!("profile {name}:"),
                p.allow_tcp.as_deref().unwrap_or(&[]),
                p.allow_udp.as_deref().unwrap_or(&[]),
                p.rules.as_deref().unwrap_or(&[]),
            )?;
        }
        for name in &self.feeds.lists {
            if crate::feeds::known(name).is_none() {
                bail!(
                    "unknown feed {name:?}; known: {}",
                    crate::feeds::KNOWN
                        .iter()
                        .map(|f| f.0)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        for u in &self.feeds.urls {
            if !u.starts_with("https://") {
                bail!("feed url {u:?} must be https://");
            }
        }
        for c in self.blocked_cidrs()? {
            // The XDP blocklist is an exact-match map; ranges wider than /20 would crowd it
            if c.mask.leading_ones() < 20 {
                bail!("blocked ranges must be /20 (4096 addresses) or narrower");
            }
        }
        let d = &self.detector;
        if d.window_secs == 0
            || d.syn_limit == 0
            || d.port_limit == 0
            || d.udp_limit == 0
            || d.drop_limit == 0
        {
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
            // Under the service's sandbox /etc is read-only: then the defaults apply from memory
            let written = path
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|_| std::fs::write(path, DEFAULT_CONFIG));
            if written.is_err() {
                return Self::parse(DEFAULT_CONFIG);
            }
        }
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    /// The config to start with: the file, or when it is broken the last one that worked
    /// (so a typo before a reboot can't leave the machine without its rules), or the defaults.
    /// The error, when there was one, is returned too so the daemon can say what's wrong.
    pub fn load_at_start(path: &Path) -> (Self, Option<anyhow::Error>) {
        match Self::load_or_create(path) {
            Ok(cfg) => (cfg, None),
            Err(e) => {
                let fallback = std::fs::read_to_string(LAST_GOOD)
                    .ok()
                    .and_then(|t| Self::parse(&t).ok())
                    .unwrap_or_else(|| {
                        Self::parse(DEFAULT_CONFIG).expect("the default config parses")
                    });
                (fallback, Some(e))
            }
        }
    }

    /// Keeps a copy of a config that was applied, for load_at_start
    pub fn remember_good(path: &Path) {
        if let Ok(text) = std::fs::read_to_string(path) {
            let _ = crate::state::write_atomic(Path::new(LAST_GOOD), text.as_bytes());
        }
    }
}

/// Opens or closes a port by editing the config file in place (comments survive);
/// the daemon notices the change within a tick
pub fn set_port(path: &Path, proto: &str, port: &PortSpec, open: bool) -> anyhow::Result<bool> {
    port.ports()?;
    let key = match proto {
        "tcp" => "allow_tcp",
        "udp" => "allow_udp",
        _ => bail!("protocol must be tcp or udp"),
    };
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut doc: toml_edit::DocumentMut = text.parse()?;
    if doc.get(key).is_none() {
        doc[key] = toml_edit::value(toml_edit::Array::new());
    }
    let arr = doc[key]
        .as_array_mut()
        .with_context(|| format!("{key} is not a list"))?;
    let pos = arr.iter().position(|v| match port {
        PortSpec::One(p) => v.as_integer() == Some(*p as i64),
        PortSpec::Text(t) => v.as_str().map(str::trim) == Some(t.trim()),
    });
    let changed = match (open, pos) {
        (true, None) => {
            match port {
                PortSpec::One(p) => arr.push(*p as i64),
                PortSpec::Text(t) => arr.push(t.trim()),
            }
            true
        }
        (false, Some(i)) => {
            arr.remove(i);
            true
        }
        _ => false,
    };
    if changed {
        let new = doc.to_string();
        Config::parse(&new)?;
        crate::state::write_atomic(path, new.as_bytes())?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let cfg = Config::parse(DEFAULT_CONFIG).unwrap();
        assert!(cfg.enforce());
        assert_eq!(cfg.allow_udp, vec![PortSpec::One(5353)]);
        assert_eq!(cfg.feeds.lists, vec!["spamhaus-drop"]);
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
    fn port_edits_keep_comments() {
        let dir = std::env::temp_dir().join(format!("aifw-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, DEFAULT_CONFIG).unwrap();
        assert!(set_port(&path, "tcp", &PortSpec::One(22), true).unwrap());
        assert!(!set_port(&path, "tcp", &PortSpec::One(22), true).unwrap());
        assert!(set_port(&path, "tcp", &PortSpec::Text("1714-1764".into()), true).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# Inbound ports open to everyone"));
        assert_eq!(
            expand(&Config::parse(&text).unwrap().allow_tcp)
                .unwrap()
                .len(),
            52
        );
        assert!(set_port(&path, "udp", &PortSpec::One(5353), false).unwrap());
        assert!(
            Config::parse(&std::fs::read_to_string(&path).unwrap())
                .unwrap()
                .allow_udp
                .is_empty()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rules_profiles_and_ranges() {
        let cfg = Config::parse(
            r#"
allow_tcp = [80]
[[rule]]
proto = "tcp"
port = 22
from = "192.168.1.0/24"
limit = "6/30s"
[profiles.home]
networks = ["HomeWifi"]
allow_tcp = [22, "1714-1764"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.rules[0].rate().unwrap(), Some((6, 30)));
        assert_eq!(cfg.profile_for(&["Cafe".into()]), None);
        assert_eq!(
            cfg.profile_for(&["HomeWifi".into()]).as_deref(),
            Some("home")
        );
        let home = cfg.policy(Some("home"));
        assert_eq!(expand(&home.allow_tcp).unwrap().len(), 52);
        assert_eq!(
            home.rules.len(),
            1,
            "a profile without rules keeps the base rules"
        );
        assert_eq!(cfg.policy(None).allow_tcp, vec![PortSpec::One(80)]);
        assert!(Config::parse("allow_tcp = [\"9-2\"]").is_err());
        assert!(Config::parse("[[rule]]\nproto = \"udp\"\nport = 53\nlimit = \"5/10s\"").is_err());
        assert!(Config::parse("[feeds]\nlists = [\"nope\"]").is_err());
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
