//---------------------------
// 5.1 Ban records, the pinned kernel blocklist, and what survives a reboot
//---------------------------

use std::{collections::HashMap as StdHashMap, path::Path};

use ai_firewall_common::BAN_FOREVER;
use anyhow::Context as _;
use aya::maps::{HashMap, Map, MapData};
use serde::{Deserialize, Serialize};

use crate::{
    addr::Src,
    detector::Offender,
    net::{boot_ns, boot_secs, unix_secs},
};

pub const PIN_DIR: &str = "/sys/fs/bpf/ai-firewall";
pub const STATE_FILE: &str = "/var/lib/ai-firewall/state.json";
pub const STATUS_FILE: &str = "/run/ai-firewall/status.json";

/// The two pinned kernel ban maps, seen as one list of sources
pub struct Blocklist {
    v4: HashMap<MapData, u32, u64>,
    v6: Option<HashMap<MapData, u64, u64>>,
}

impl Blocklist {
    pub fn new(v4: HashMap<MapData, u32, u64>, v6: Option<HashMap<MapData, u64, u64>>) -> Self {
        Self { v4, v6 }
    }

    pub fn insert(&mut self, src: Src, expiry: u64) -> anyhow::Result<()> {
        match src {
            Src::V4(ip) => self.v4.insert(ip, expiry, 0)?,
            Src::V6(p) => self
                .v6
                .as_mut()
                .context("this build has no IPv6 ban map")?
                .insert(p, expiry, 0)?,
        }
        Ok(())
    }

    pub fn remove(&mut self, src: Src) -> anyhow::Result<()> {
        match src {
            Src::V4(ip) => self.v4.remove(&ip)?,
            Src::V6(p) => self
                .v6
                .as_mut()
                .context("this build has no IPv6 ban map")?
                .remove(&p)?,
        }
        Ok(())
    }

    pub fn contains(&self, src: Src) -> bool {
        match src {
            Src::V4(ip) => self.v4.get(&ip, 0).is_ok(),
            Src::V6(p) => self.v6.as_ref().is_some_and(|m| m.get(&p, 0).is_ok()),
        }
    }

    /// Every (source, kernel expiry) currently in the maps
    pub fn entries(&self) -> Vec<(Src, u64)> {
        let mut out: Vec<(Src, u64)> = self
            .v4
            .iter()
            .filter_map(Result::ok)
            .map(|(ip, e)| (Src::V4(ip), e))
            .collect();
        if let Some(m) = &self.v6 {
            out.extend(
                m.iter()
                    .filter_map(Result::ok)
                    .map(|(p, e)| (Src::V6(p), e)),
            );
        }
        out
    }
}

fn open_pinned<K: aya::Pod, V: aya::Pod>(name: &str) -> anyhow::Result<HashMap<MapData, K, V>> {
    let data = MapData::from_pin(Path::new(PIN_DIR).join(name))
        .map_err(|e| anyhow::anyhow!("{e} (has `ai-firewall run` started once since boot?)"))?;
    Ok(HashMap::try_from(Map::from_map_data(data)?)?)
}

/// Opens the blocklist the daemon pinned, so the CLI works without talking to it
pub fn open_pinned_blocklist() -> anyhow::Result<Blocklist> {
    Ok(Blocklist::new(
        open_pinned("BLOCKLIST")?,
        open_pinned("BLOCKLIST6").ok(),
    ))
}

/// Kernel expiry value for a ban lasting `secs` (0 = forever)
pub fn expiry_for(secs: u64) -> u64 {
    if secs == 0 {
        BAN_FOREVER
    } else {
        boot_ns() + secs * 1_000_000_000
    }
}

/// Seconds left on a kernel expiry value, None if already expired, Some(0) if forever
pub fn remaining(expiry: u64) -> Option<u64> {
    if expiry == BAN_FOREVER {
        return Some(0);
    }
    let now = boot_ns();
    (expiry > now).then(|| (expiry - now).div_ceil(1_000_000_000))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BanRecord {
    pub reason: String,
    /// "auto", "manual" or "config"
    pub source: String,
    pub strikes: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavedBan {
    pub ip: Src,
    /// Wall-clock expiry, 0 = forever
    pub expires_unix: u64,
    pub reason: String,
    pub source: String,
    pub strikes: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavedOffender {
    pub ip: Src,
    pub strikes: u32,
    pub last_ban_unix: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Saved {
    pub bans: Vec<SavedBan>,
    pub offenders: Vec<SavedOffender>,
}

impl Saved {
    pub fn load() -> Self {
        std::fs::read_to_string(STATE_FILE)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Write-then-rename so a crash mid-write never leaves a corrupt file
    pub fn store(&self) -> anyhow::Result<()> {
        write_atomic(Path::new(STATE_FILE), &serde_json::to_vec_pretty(self)?)
    }

    pub fn capture(
        blocklist: &Blocklist,
        records: &StdHashMap<Src, BanRecord>,
        offenders: &StdHashMap<Src, Offender>,
    ) -> Self {
        let (unix, boot) = (unix_secs(), boot_secs());
        let bans = blocklist
            .entries()
            .into_iter()
            .filter_map(|(ip, expiry)| {
                let left = remaining(expiry)?;
                let rec = records.get(&ip).cloned().unwrap_or_else(manual_record);
                Some(SavedBan {
                    ip,
                    expires_unix: if left == 0 { 0 } else { unix + left },
                    reason: rec.reason,
                    source: rec.source,
                    strikes: rec.strikes,
                })
            })
            .collect();
        let offenders = offenders
            .iter()
            .map(|(&ip, o)| SavedOffender {
                ip,
                strikes: o.strikes,
                last_ban_unix: unix.saturating_sub(boot.saturating_sub(o.last_ban)),
            })
            .collect();
        Self { bans, offenders }
    }
}

pub fn manual_record() -> BanRecord {
    BanRecord {
        reason: "banned by hand".into(),
        source: "manual".into(),
        strikes: 0,
    }
}

pub fn write_atomic(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
