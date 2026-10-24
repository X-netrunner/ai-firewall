//---------------------------
// 11.2 Blocklist feeds: public lists of known-bad IPv4 networks
//---------------------------
//
// Downloaded with curl (no TLS library in this binary), cached under /var/lib so a
// restart or an offline boot still has them, refreshed every `refresh_hours`.
// Anything touching private, LAN or reserved space is dropped while parsing: some
// lists include those ranges, and loading them would cut you off from your own network.

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime},
};

use log::{info, warn};

use crate::config::{Cidr, FeedConfig};

pub const DIR: &str = "/var/lib/ai-firewall/feeds";

/// (name, url)
pub const KNOWN: &[(&str, &str)] = &[
    (
        "spamhaus-drop",
        "https://www.spamhaus.org/drop/drop_v4.json",
    ),
    (
        "firehol-level1",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    ),
];

pub fn known(name: &str) -> Option<&'static str> {
    KNOWN.iter().find(|k| k.0 == name).map(|k| k.1)
}

/// Never blocked, whatever a list says
const RESERVED: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

fn overlaps(a: &Cidr, b: &Cidr) -> bool {
    a.contains(b.net) || b.contains(a.net)
}

/// Every IPv4 CIDR in the text (plain lists, netsets, Spamhaus JSON lines), minus reserved space.
/// Prefixes shorter than /8 are ignored: no sane list blocks a sixteenth of the internet.
pub fn parse(text: &str, protected: &[Cidr]) -> Vec<Cidr> {
    let reserved: Vec<Cidr> = RESERVED.iter().map(|r| Cidr::parse(r).unwrap()).collect();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("");
        for token in line.split(|c: char| !(c.is_ascii_digit() || c == '.' || c == '/')) {
            if token.matches('.').count() != 3 {
                continue;
            }
            let Ok(c) = Cidr::parse(token) else { continue };
            if c.mask.leading_ones() < 8
                || reserved.iter().chain(protected).any(|r| overlaps(r, &c))
            {
                continue;
            }
            out.push(c);
        }
    }
    out.sort_by_key(|c| (c.net, c.mask));
    out.dedup();
    out
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedState {
    pub name: String,
    pub entries: usize,
    /// unix time of the cached copy, 0 = never downloaded
    pub updated_unix: u64,
    pub error: Option<String>,
}

fn cache_path(name: &str) -> PathBuf {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Path::new(DIR).join(format!("{safe}.txt"))
}

fn age(path: &Path) -> Option<Duration> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .elapsed()
        .ok()
}

/// (name, url) for everything the config asks for; own urls are named by position
pub fn sources(cfg: &FeedConfig) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = cfg
        .lists
        .iter()
        .filter_map(|n| known(n).map(|u| (n.clone(), u.to_string())))
        .collect();
    out.extend(
        cfg.urls
            .iter()
            .enumerate()
            .map(|(i, u)| (format!("custom-{}", i + 1), u.clone())),
    );
    out
}

/// Downloads the sources whose cache is older than refresh_hours (blocking: run it off the async runtime)
pub fn refresh(cfg: &FeedConfig, force: bool) -> Vec<(String, Option<String>)> {
    let _ = std::fs::create_dir_all(DIR);
    let max_age = Duration::from_secs(cfg.refresh_hours.max(1) * 3600);
    let mut results = Vec::new();
    for (name, url) in sources(cfg) {
        let path = cache_path(&name);
        if !force && age(&path).is_some_and(|a| a < max_age) {
            continue;
        }
        let tmp = path.with_extension("part");
        let ok = Command::new("curl")
            .args([
                "-fsSL",
                "--max-time",
                "60",
                "--max-filesize",
                "5000000",
                "-o",
            ])
            .arg(&tmp)
            .arg(&url)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let error = if ok && std::fs::rename(&tmp, &path).is_ok() {
            info!("[*] feed {name} updated");
            None
        } else {
            let _ = std::fs::remove_file(&tmp);
            warn!("[!] feed {name}: download failed ({url}); keeping the cached copy");
            Some("download failed".to_string())
        };
        results.push((name, error));
    }
    results
}

/// The cached lists, parsed: (all networks, per-feed state)
pub fn load(
    cfg: &FeedConfig,
    protected: &[Cidr],
    errors: &[(String, Option<String>)],
) -> (Vec<Cidr>, Vec<FeedState>) {
    let mut all = Vec::new();
    let mut states = Vec::new();
    for (name, _) in sources(cfg) {
        let path = cache_path(&name);
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let nets = parse(&text, protected);
        let updated_unix = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let error = errors
            .iter()
            .find(|e| e.0 == name)
            .and_then(|e| e.1.clone());
        states.push(FeedState {
            name,
            entries: nets.len(),
            updated_unix,
            error,
        });
        all.extend(nets);
    }
    all.sort_by_key(|c| (c.net, c.mask));
    all.dedup();
    (all, states)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lists_and_keeps_lan_safe() {
        let netset = "# firehol\n10.0.0.0/8\n1.2.3.0/24\n192.168.0.0/16\n5.6.7.8\n0.0.0.0/0\n203.0.113.0/24 ; doc\n";
        let got: Vec<String> = parse(netset, &[])
            .iter()
            .map(|c| format!("{:?}", c.mask.leading_ones()))
            .collect();
        assert_eq!(got.len(), 3, "10/8, 192.168/16 and /0 are dropped: {got:?}");

        let json = "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n{\"type\":\"metadata\",\"timestamp\":1}\n";
        let nets = parse(json, &[]);
        assert_eq!(nets, vec![Cidr::parse("1.10.16.0/20").unwrap()]);

        // a protected address (your DNS server, say) inside a listed network keeps that network out
        let dns = Cidr::parse("1.10.20.1").unwrap();
        assert!(parse(json, &[dns]).is_empty());
    }

    /// AIFW_FEED_SAMPLES=path1:path2 cargo test -- --ignored: real downloaded lists
    #[test]
    #[ignore]
    fn real_lists() {
        let paths = std::env::var("AIFW_FEED_SAMPLES").expect("set AIFW_FEED_SAMPLES");
        for p in paths.split(':') {
            let text = std::fs::read_to_string(p).unwrap();
            let nets = parse(&text, &[]);
            let lan = Cidr::parse("192.168.1.10").unwrap();
            assert!(
                !nets.iter().any(|c| c.contains(lan.net)),
                "{p}: a LAN address would be blocked"
            );
            println!("{p}: {} networks", nets.len());
            assert!(nets.len() > 500);
        }
    }

    #[test]
    fn sources_follow_config() {
        let cfg = FeedConfig {
            lists: vec!["spamhaus-drop".into()],
            urls: vec!["https://example.org/x.txt".into()],
            refresh_hours: 24,
        };
        let s = sources(&cfg);
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].0, "custom-1");
    }
}
