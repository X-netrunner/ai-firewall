//---------------------------
// Postures: a system-wide security level laid over the config (Halcyon's sysmode sets one per mode)
//---------------------------
//
// /etc/ai-firewall/posture.toml holds the name and, for stealth, the local networks:
//     name = "stealth"
//     lan = ["192.168.1.0/24"]
// The config file itself is never edited, so switching back to "secure" (or removing the file) restores it exactly.
// The daemon reloads within a tick when the file changes.

use std::path::Path;

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

use crate::config::{Cidr, Config, PortSpec, Profile, Rule};

pub const PATH: &str = "/etc/ai-firewall/posture.toml";

/// Every posture, with what it does (shown by `ai-firewall posture`)
pub const POSTURES: &[(&str, &str)] = &[
    ("secure", "your config as written"),
    (
        "relaxed",
        "your config; scan and flood detection half as sensitive (labs, busy networks)",
    ),
    (
        "lockdown",
        "every inbound port closed, ping dropped, detection twice as sensitive, bans 4x longer, always enforcing",
    ),
    (
        "stealth",
        "ping dropped; the honeypot ports open only to your local networks",
    ),
];

/// The honeypot's decoy ports (Halcyon recon-deceiver), opened to the local networks in stealth
const DECOY_TCP: &[u16] = &[21, 22, 23, 25, 80, 445, 3306, 3389, 8080];
const DECOY_UDP: &[u16] = &[53];

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Posture {
    pub name: String,
    /// stealth: networks that may reach the honeypot (sysmode passes the machine's own subnets)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lan: Vec<String>,
}

impl Posture {
    pub fn new(name: &str, lan: Vec<String>) -> anyhow::Result<Posture> {
        let p = Posture {
            name: name.to_string(),
            lan,
        };
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !POSTURES.iter().any(|(n, _)| *n == self.name) {
            bail!(
                "unknown posture {:?}; known: {}",
                self.name,
                POSTURES.iter().map(|p| p.0).collect::<Vec<_>>().join(", ")
            );
        }
        for l in &self.lan {
            Cidr::parse(l).with_context(|| format!("lan {l:?}"))?;
        }
        Ok(())
    }

    /// The posture in force: none when the file is missing. A broken file counts as none (and says why).
    pub fn load(path: &Path) -> (Option<Posture>, Option<String>) {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (None, None),
            Err(e) => return (None, Some(format!("{}: {e}", path.display()))),
        };
        match toml::from_str::<Posture>(&text)
            .map_err(anyhow::Error::from)
            .and_then(|p| p.validate().map(|()| p))
        {
            Ok(p) => (Some(p), None),
            Err(e) => (None, Some(format!("{}: {e:#}", path.display()))),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let text = format!(
            "# Written by `ai-firewall posture` (Halcyon sysmode sets it per mode). Your config.toml is not changed.\n{}",
            toml::to_string(self)?
        );
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::state::write_atomic(path, text.as_bytes())
    }

    /// The config with this posture laid over it
    pub fn apply(&self, mut cfg: Config) -> Config {
        cfg.posture = Some(self.name.clone());
        match self.name.as_str() {
            "relaxed" => scale_detector(&mut cfg, 2, 1),
            "lockdown" => {
                cfg.mode = "enforce".into();
                cfg.allow_tcp.clear();
                cfg.allow_udp.clear();
                cfg.allow_ping = false;
                cfg.rules.clear();
                for p in cfg.profiles.values_mut() {
                    *p = Profile {
                        networks: std::mem::take(&mut p.networks),
                        allow_tcp: Some(Vec::new()),
                        allow_udp: Some(Vec::new()),
                        allow_ping: Some(false),
                        rules: Some(Vec::new()),
                    };
                }
                scale_detector(&mut cfg, 1, 2);
                cfg.bans.base_secs = cfg.bans.base_secs.saturating_mul(4);
                cfg.bans.max_secs = cfg.bans.max_secs.saturating_mul(4).max(cfg.bans.base_secs);
            }
            "stealth" => {
                let decoys: Vec<Rule> = self
                    .lan
                    .iter()
                    .flat_map(|net| {
                        let tcp = DECOY_TCP.iter().map(move |p| ("tcp", *p, net));
                        let udp = DECOY_UDP.iter().map(move |p| ("udp", *p, net));
                        tcp.chain(udp)
                    })
                    .map(|(proto, port, net)| Rule {
                        proto: proto.into(),
                        port: PortSpec::One(port),
                        from: Some(net.clone()),
                        limit: None,
                    })
                    .collect();
                cfg.allow_ping = false;
                cfg.rules.extend(decoys.iter().cloned());
                for p in cfg.profiles.values_mut() {
                    p.allow_ping = Some(false);
                    if let Some(r) = p.rules.as_mut() {
                        r.extend(decoys.iter().cloned());
                    }
                }
            }
            _ => {}
        }
        cfg
    }
}

/// Multiply the detector limits by `up` and divide them by `down` (never below 1)
fn scale_detector(cfg: &mut Config, up: u32, down: u32) {
    let d = &mut cfg.detector;
    for v in [
        &mut d.syn_limit,
        &mut d.port_limit,
        &mut d.udp_limit,
        &mut d.drop_limit,
    ] {
        *v = (v.saturating_mul(up) / down).max(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"
allow_tcp = [22]
allow_udp = [5353]
[[rule]]
proto = "tcp"
port = 8000
from = "10.0.0.0/8"
[profiles.home]
networks = ["Home"]
allow_tcp = [22, 80]
"#;

    #[test]
    fn secure_changes_nothing_and_unknown_names_are_refused() {
        let cfg = Config::parse(CFG).unwrap();
        let out = Posture::new("secure", vec![]).unwrap().apply(cfg.clone());
        assert_eq!(out.policy(None), cfg.policy(None));
        assert_eq!(out.posture.as_deref(), Some("secure"));
        assert!(Posture::new("party", vec![]).is_err());
        assert!(Posture::new("stealth", vec!["not-a-net".into()]).is_err());
    }

    #[test]
    fn lockdown_closes_everything_also_in_profiles() {
        let cfg = Config::parse(CFG).unwrap();
        let out = Posture::new("lockdown", vec![]).unwrap().apply(cfg.clone());
        for profile in [None, Some("home")] {
            let p = out.policy(profile);
            assert!(p.allow_tcp.is_empty() && p.allow_udp.is_empty() && p.rules.is_empty());
            assert!(!p.allow_ping);
        }
        assert!(out.enforce());
        assert_eq!(out.detector.syn_limit, cfg.detector.syn_limit / 2);
        assert_eq!(out.bans.base_secs, cfg.bans.base_secs * 4);
        out.validate().unwrap();
    }

    #[test]
    fn stealth_opens_the_decoys_to_the_lan_only() {
        let cfg = Config::parse(CFG).unwrap();
        let out = Posture::new("stealth", vec!["192.168.1.0/24".into()])
            .unwrap()
            .apply(cfg);
        let p = out.policy(None);
        assert!(!p.allow_ping);
        assert_eq!(p.allow_tcp, vec![PortSpec::One(22)], "your own ports stay");
        assert!(
            p.rules
                .iter()
                .any(|r| r.label() == "tcp 445 from 192.168.1.0/24")
        );
        assert!(
            p.rules
                .iter()
                .any(|r| r.label() == "udp 53 from 192.168.1.0/24")
        );
        assert!(
            p.rules
                .iter()
                .any(|r| r.label() == "tcp 8000 from 10.0.0.0/8")
        );
        assert!(
            p.rules.iter().all(|r| r.from.is_some()),
            "nothing new is open to everyone"
        );
        out.validate().unwrap();
    }

    #[test]
    fn relaxed_only_softens_detection() {
        let cfg = Config::parse(CFG).unwrap();
        let out = Posture::new("relaxed", vec![]).unwrap().apply(cfg.clone());
        assert_eq!(out.policy(None), cfg.policy(None));
        assert_eq!(out.detector.port_limit, cfg.detector.port_limit * 2);
    }

    #[test]
    fn the_file_round_trips_and_a_broken_one_is_reported() {
        let dir = tempfile_dir();
        let path = dir.join("posture.toml");
        assert_eq!(Posture::load(&path), (None, None));
        let p = Posture::new("stealth", vec!["10.1.2.0/24".into()]).unwrap();
        p.save(&path).unwrap();
        assert_eq!(Posture::load(&path), (Some(p), None));
        std::fs::write(&path, "name = \"party\"\n").unwrap();
        let (none, err) = Posture::load(&path);
        assert!(none.is_none() && err.unwrap().contains("unknown posture"));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("aifw-posture-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
