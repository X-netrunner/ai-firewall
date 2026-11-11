//---------------------------
// Cooperative AI Antivirus Integration
//---------------------------
//
// ai-firewall and ai-antivirus form a cooperative defensive mesh for Halcyon:
// - ai-antivirus detects suspicious processes, malicious network connections and C2 endpoints
// - ai-firewall ingests those threat endpoints directly into eBPF/XDP kernel maps for wire-speed drops
// - ai-firewall exports attack telemetry so ai-antivirus and Halcyon can correlate network probes
//   with process behavior

use std::{
    collections::{HashMap as StdHashMap, HashSet},
    net::IpAddr,
    path::Path,
    process::Command,
};

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::{
    addr::Src,
    state::{BanRecord, Blocklist, expiry_for},
};

pub const AI_ANTIVIRUS_BIN: &str = "ai-antivirus";
pub const NFT_TABLE_AV: &str = "ai_antivirus";
pub const TELEMETRY_PATH: &str = "/var/lib/ai-firewall/threat-intel.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AntivirusStatus {
    pub installed: bool,
    pub active: bool,
    pub sensord_active: bool,
    pub engined_active: bool,
    pub responderd_active: bool,
    pub synced_threats: usize,
    pub last_sync_unix: u64,
    pub details: String,
}

impl Default for AntivirusStatus {
    fn default() -> Self {
        Self {
            installed: false,
            active: false,
            sensord_active: false,
            engined_active: false,
            responderd_active: false,
            synced_threats: 0,
            last_sync_unix: 0,
            details: "not checked".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatBlock {
    pub ip: Src,
    pub ttl_secs: u64,
    pub reason: String,
}

/// Detects the status of the local ai-antivirus installation
pub fn detect_status(synced_threats: usize, last_sync: u64) -> AntivirusStatus {
    let installed = is_installed();
    if !installed {
        return AntivirusStatus {
            installed: false,
            active: false,
            sensord_active: false,
            engined_active: false,
            responderd_active: false,
            synced_threats: 0,
            last_sync_unix: last_sync,
            details: "ai-antivirus is not installed".into(),
        };
    }

    let sensord = unit_active("ai-antivirus-sensord");
    let engined = unit_active("ai-antivirus-engined");
    let responderd = unit_active("ai-antivirus-responderd");
    let active = sensord || engined || responderd;

    let details = if sensord && engined && responderd {
        format!("sensord, engined, responderd active; {synced_threats} threat blocks synced to XDP")
    } else if active {
        format!(
            "partial: sensord={}, engined={}, responderd={}",
            if sensord { "on" } else { "off" },
            if engined { "on" } else { "off" },
            if responderd { "on" } else { "off" }
        )
    } else {
        "installed but services are inactive".into()
    };

    AntivirusStatus {
        installed: true,
        active,
        sensord_active: sensord,
        engined_active: engined,
        responderd_active: responderd,
        synced_threats,
        last_sync_unix: last_sync,
        details,
    }
}

pub fn is_installed() -> bool {
    Command::new(AI_ANTIVIRUS_BIN)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        || Path::new("/usr/local/bin/ai-antivirus").exists()
        || Path::new("/usr/bin/ai-antivirus").exists()
        || Path::new("/etc/ai-antivirus/ai-antivirus.toml").exists()
}

fn unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Fetches threat blocks from ai-antivirus via nftables table `inet ai_antivirus`
pub fn fetch_threats() -> Vec<ThreatBlock> {
    let mut threats = Vec::new();
    for set in ["block4", "block6"] {
        if let Some(blocks) = read_nft_set(NFT_TABLE_AV, set) {
            threats.extend(blocks);
        }
    }
    // Also check alternative table name if any (e.g. ai-antivirus with hyphen)
    if threats.is_empty() {
        for set in ["block4", "block6"] {
            if let Some(blocks) = read_nft_set("ai-antivirus", set) {
                threats.extend(blocks);
            }
        }
    }
    // Also check local shared file if present
    threats.extend(read_shared_threats());
    threats
}

fn read_nft_set(table: &str, set: &str) -> Option<Vec<ThreatBlock>> {
    let out = Command::new("nft")
        .args(["-j", "list", "set", "inet", table, set])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_nft_set_json(&text)
}

/// Parses the output of `nft -j list set inet ...`
pub fn parse_nft_set_json(json_str: &str) -> Option<Vec<ThreatBlock>> {
    let root: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let mut results = Vec::new();

    let nftables = root.get("nftables")?.as_array()?;
    for obj in nftables {
        let Some(set_obj) = obj.get("set") else {
            continue;
        };
        let Some(elems) = set_obj.get("elem").and_then(|e| e.as_array()) else {
            continue;
        };

        for elem in elems {
            // Elem can be a string IP, or an object {"elem": {"val": "...", "timeout": 3600}}
            if let Some(ip_str) = elem.as_str() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    results.push(ThreatBlock {
                        ip: Src::from(ip),
                        ttl_secs: 3600,
                        reason: "ai-antivirus threat block".into(),
                    });
                }
            } else if let Some(inner) = elem.get("elem") {
                let val_str = inner.get("val").and_then(|v| v.as_str());
                let timeout = inner
                    .get("timeout")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(3600);
                if let Some(ip_str) = val_str
                    && let Ok(ip) = ip_str.parse::<IpAddr>()
                {
                    results.push(ThreatBlock {
                        ip: Src::from(ip),
                        ttl_secs: timeout,
                        reason: "ai-antivirus C2 / network block".into(),
                    });
                }
            }
        }
    }
    Some(results)
}

fn read_shared_threats() -> Vec<ThreatBlock> {
    let path = Path::new("/var/lib/ai-antivirus/threats.json");
    let Ok(data) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(arr) = v.as_array() {
        for item in arr {
            let ip_str = item.get("ip").and_then(|i| i.as_str());
            let ttl = item.get("ttl").and_then(|t| t.as_u64()).unwrap_or(3600);
            let reason = item
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("ai-antivirus threat");
            if let Some(s) = ip_str
                && let Ok(ip) = s.parse::<IpAddr>()
            {
                out.push(ThreatBlock {
                    ip: Src::from(ip),
                    ttl_secs: ttl,
                    reason: reason.into(),
                });
            }
        }
    }
    out
}

/// Synchronizes threat blocks from ai-antivirus into the eBPF blocklist
pub fn sync_threats(
    blocklist: &mut Blocklist,
    records: &mut StdHashMap<Src, BanRecord>,
    threats: &[ThreatBlock],
) -> usize {
    let active_threat_ips: HashSet<Src> = threats.iter().map(|t| t.ip).collect();
    let mut synced = 0;

    for threat in threats {
        let ip = threat.ip;
        if !blocklist.contains(ip) {
            match blocklist.insert(ip, expiry_for(threat.ttl_secs)) {
                Ok(()) => {
                    info!(
                        "[*] synced ai-antivirus threat block: {ip} ({}s, {})",
                        threat.ttl_secs, threat.reason
                    );
                    records.insert(
                        ip,
                        BanRecord {
                            reason: threat.reason.clone(),
                            source: "antivirus".into(),
                            strikes: 1,
                        },
                    );
                    synced += 1;
                }
                Err(e) => {
                    warn!("[!] failed to sync threat {ip} to kernel blocklist: {e}");
                }
            }
        } else {
            synced += 1;
        }
    }

    // Clean up previously synced antivirus bans that are no longer in the active threat list
    let stale: Vec<Src> = records
        .iter()
        .filter(|(ip, r)| r.source == "antivirus" && !active_threat_ips.contains(ip))
        .map(|(ip, _)| *ip)
        .collect();

    for ip in stale {
        let _ = blocklist.remove(ip);
        records.remove(&ip);
        debug!("[*] lifted expired ai-antivirus threat: {ip}");
    }

    synced
}

/// Exports recent firewall ban telemetry to a shared location for ai-antivirus and Halcyon
pub fn export_telemetry(recent: &[crate::daemon::RecentBan]) {
    let path = Path::new(TELEMETRY_PATH);
    let payload = serde_json::json!({
        "timestamp_unix": crate::net::unix_secs(),
        "firewall": "ai-firewall",
        "recent_bans": recent,
    });
    if let Ok(bytes) = serde_json::to_vec_pretty(&payload) {
        let _ = crate::state::write_atomic(path, &bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_NFT_JSON: &str = r#"{
      "nftables": [
        {
          "set": {
            "family": "inet",
            "table": "ai_antivirus",
            "name": "block4",
            "type": "ipv4_addr",
            "flags": ["timeout"],
            "elem": [
              {
                "elem": {
                  "val": "203.0.113.5",
                  "timeout": 1200
                }
              },
              {
                "elem": {
                  "val": "198.51.100.22",
                  "timeout": 3600
                }
              }
            ]
          }
        }
      ]
    }"#;

    #[test]
    fn parses_nftables_json_threat_blocks() {
        let threats = parse_nft_set_json(SAMPLE_NFT_JSON).expect("should parse");
        assert_eq!(threats.len(), 2);
        assert_eq!(
            threats[0].ip,
            Src::V4(u32::from(std::net::Ipv4Addr::new(203, 0, 113, 5)))
        );
        assert_eq!(threats[0].ttl_secs, 1200);
        assert_eq!(
            threats[1].ip,
            Src::V4(u32::from(std::net::Ipv4Addr::new(198, 51, 100, 22)))
        );
        assert_eq!(threats[1].ttl_secs, 3600);
    }

    #[test]
    fn handles_empty_or_invalid_nft_json() {
        assert_eq!(parse_nft_set_json("{}"), None);
        assert_eq!(parse_nft_set_json(r#"{"nftables":[]}"#), Some(vec![]));
    }
}
