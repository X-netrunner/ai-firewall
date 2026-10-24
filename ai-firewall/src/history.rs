//---------------------------
// 11.3 History and notifications: what the firewall did, for you and the Center
//---------------------------
//
// history.jsonl: one JSON object per line (bans, lifts, profile switches, feed
// updates), readable by everyone, trimmed to its newest half past 2 MB.
// Notifications go to the desktop user's session through notify-send, grouped
// so a burst of bans is one notification, not twenty.

use std::{io::Write, path::Path, process::Command};

use serde::{Deserialize, Serialize};

use crate::net::unix_secs;

pub const FILE: &str = "/var/lib/ai-firewall/history.jsonl";
const MAX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub at_unix: u64,
    /// ban | lift | expire | profile | feeds
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

pub fn record(kind: &str, ip: impl ToString, detail: impl Into<String>) {
    let e = Entry {
        at_unix: unix_secs(),
        kind: kind.into(),
        ip: ip.to_string(),
        detail: detail.into(),
    };
    let Ok(line) = serde_json::to_string(&e) else {
        return;
    };
    let path = Path::new(FILE);
    if std::fs::metadata(path)
        .map(|m| m.len() > MAX_BYTES)
        .unwrap_or(false)
    {
        trim(path);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

fn trim(path: &Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let lines: Vec<&str> = text.lines().collect();
    let keep = lines[lines.len() / 2..].join("\n") + "\n";
    let _ = crate::state::write_atomic(path, keep.as_bytes());
}

/// The newest `n` entries, newest last
pub fn read(n: usize) -> Vec<Entry> {
    let text = std::fs::read_to_string(FILE).unwrap_or_default();
    let all: Vec<Entry> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    all[all.len().saturating_sub(n)..].to_vec()
}

/// The logged-in desktop user: (name, uid) of the first /run/user/<uid> with a session bus
fn desktop_user() -> Option<(String, u32)> {
    let mut uids: Vec<u32> = std::fs::read_dir("/run/user")
        .ok()?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter(|uid| *uid >= 1000 && Path::new(&format!("/run/user/{uid}/bus")).exists())
        .collect();
    uids.sort_unstable();
    let uid = *uids.first()?;
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    let name = passwd
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f.len() > 2 && f[2] == uid.to_string())?[0]
        .to_string();
    Some((name, uid))
}

/// Fire and forget; a failure only means no popup
pub fn notify(title: &str, body: &str) {
    let Some((user, uid)) = desktop_user() else {
        return;
    };
    let _ = Command::new("runuser")
        .args([
            "-u",
            &user,
            "--",
            "env",
            &format!("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"),
        ])
        .args([
            "notify-send",
            "-a",
            "ai-firewall",
            "-i",
            "security-high",
            title,
            body,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// At most one ban notification a minute: bans in between are collected into the next one,
/// so a sustained attack is a notification a minute, not one per tick
pub const NOTE_INTERVAL_SECS: u64 = 60;
const NOTE_SHOWN: usize = 3;

#[derive(Default)]
pub struct BanNotes {
    /// the first few since the last notification, shown by name
    shown: Vec<(String, String)>,
    /// all of them, named or not
    count: usize,
    last_sent: Option<u64>,
}

impl BanNotes {
    pub fn push(&mut self, ip: String, reason: String) {
        if self.shown.len() < NOTE_SHOWN {
            self.shown.push((ip, reason));
        }
        self.count += 1;
    }

    /// The notification due now, if any: (title, body)
    pub fn take(&mut self, now: u64) -> Option<(String, String)> {
        if self.count == 0
            || self
                .last_sent
                .is_some_and(|t| now.saturating_sub(t) < NOTE_INTERVAL_SECS)
        {
            return None;
        }
        let note = if self.count == 1 {
            let (ip, reason) = self.shown.remove(0);
            (format!("Banned {ip}"), reason)
        } else {
            let list: Vec<String> = self
                .shown
                .iter()
                .map(|(ip, r)| format!("{ip}: {r}"))
                .collect();
            let more = self.count - self.shown.len();
            let more = if more > 0 {
                format!("\n+{more} more")
            } else {
                String::new()
            };
            (
                format!("Banned {} sources", self.count),
                list.join("\n") + &more,
            )
        };
        self.shown.clear();
        self.count = 0;
        self.last_sent = Some(now);
        Some(note)
    }

    pub fn flush(&mut self) {
        if let Some((title, body)) = self.take(unix_secs()) {
            notify(&title, &body);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_are_throttled_and_grouped() {
        let mut n = BanNotes::default();
        assert_eq!(n.take(1000), None);
        n.push("1.1.1.1".into(), "port scan".into());
        assert_eq!(
            n.take(1000),
            Some(("Banned 1.1.1.1".into(), "port scan".into()))
        );
        // a burst within the minute waits, then comes as one
        for i in 0..10 {
            n.push(format!("2.2.2.{i}"), "udp flood".into());
        }
        assert_eq!(n.take(1030), None);
        let (title, body) = n.take(1061).unwrap();
        assert_eq!(title, "Banned 10 sources");
        assert!(
            body.starts_with("2.2.2.0: udp flood") && body.ends_with("+7 more"),
            "{body}"
        );
        assert_eq!(n.take(2000), None, "nothing new, nothing sent");
    }

    #[test]
    fn entry_round_trip() {
        let e = Entry {
            at_unix: 5,
            kind: "ban".into(),
            ip: "1.2.3.4".into(),
            detail: "port scan".into(),
        };
        let line = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<Entry>(&line).unwrap(), e);
        // empty fields are left out of the file
        let p = Entry {
            at_unix: 5,
            kind: "profile".into(),
            ip: String::new(),
            detail: "home".into(),
        };
        assert!(!serde_json::to_string(&p).unwrap().contains("\"ip\""));
    }
}
