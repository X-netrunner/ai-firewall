use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const PENDING: &str = "/var/lib/ai-firewall/rollback.json";
pub const UNIT: &str = "ai-firewall-rollback";
pub const DEFAULT_SECS: u64 = 60;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Pending {
    pub config: PathBuf,
    pub previous: String,
    pub what: String,
}

pub fn arm(
    pending_file: &Path,
    pending: &Pending,
    secs: u64,
    schedule: impl Fn(u64) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if pending_file.exists() {
        bail!(
            "another change is still waiting to be confirmed: run `ai-firewall confirm` or `ai-firewall rollback` first"
        );
    }
    crate::state::write_atomic(pending_file, serde_json::to_string(pending)?.as_bytes())?;
    if let Err(e) = schedule(secs) {
        let _ = std::fs::remove_file(pending_file);
        return Err(e.context("could not arm the automatic rollback"));
    }
    Ok(())
}

pub fn systemd_timer(secs: u64) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("finding the ai-firewall binary")?;
    let status = Command::new("systemd-run")
        .args(["--unit", UNIT, "--collect", "--quiet"])
        .arg(format!("--on-active={secs}s"))
        .arg(exe)
        .arg("rollback")
        .status()
        .context("running systemd-run")?;
    if !status.success() {
        bail!("systemd-run exited with {status}");
    }
    Ok(())
}

pub fn cancel_timer() {
    let _ = Command::new("systemctl")
        .args(["stop", &format!("{UNIT}.timer")])
        .status();
}

pub fn rollback(pending_file: &Path) -> anyhow::Result<Option<String>> {
    let Ok(text) = std::fs::read_to_string(pending_file) else {
        return Ok(None);
    };
    let pending: Pending = serde_json::from_str(&text).context("reading the pending change")?;
    crate::state::write_atomic(&pending.config, pending.previous.as_bytes())
        .with_context(|| format!("restoring {}", pending.config.display()))?;
    std::fs::remove_file(pending_file)?;
    Ok(Some(pending.what))
}

pub fn confirm(pending_file: &Path) -> anyhow::Result<Option<String>> {
    let Ok(text) = std::fs::read_to_string(pending_file) else {
        return Ok(None);
    };
    let pending: Pending = serde_json::from_str(&text).context("reading the pending change")?;
    std::fs::remove_file(pending_file)?;
    Ok(Some(pending.what))
}

pub fn ask_to_keep(secs: u64) -> Option<bool> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return None;
    }
    print!("Keep this change? It is undone in {secs} s otherwise. [y/N] ");
    let _ = std::io::stdout().flush();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        let _ = tx.send(line);
    });
    Some(matches!(
        rx.recv_timeout(std::time::Duration::from_secs(secs)).map(|l| l.trim().to_lowercase()),
        Ok(ref a) if a == "y" || a == "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let cfg = t.path().join("config.toml");
        let pending = t.path().join("rollback.json");
        std::fs::write(&cfg, "allow_tcp = [22]\n").unwrap();
        (t, cfg, pending)
    }

    fn change(cfg: &Path) -> Pending {
        let previous = std::fs::read_to_string(cfg).unwrap();
        std::fs::write(cfg, "allow_tcp = []\n").unwrap();
        Pending {
            config: cfg.to_path_buf(),
            previous,
            what: "close tcp 22".into(),
        }
    }

    #[test]
    fn an_unconfirmed_change_rolls_back() {
        let (_t, cfg, pending) = setup();
        let p = change(&cfg);
        arm(&pending, &p, 60, |_| Ok(())).unwrap();
        assert_eq!(rollback(&pending).unwrap().as_deref(), Some("close tcp 22"));
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "allow_tcp = [22]\n");
        assert!(!pending.exists());
        assert_eq!(
            rollback(&pending).unwrap(),
            None,
            "a second rollback does nothing"
        );
    }

    #[test]
    fn a_confirmed_change_stays() {
        let (_t, cfg, pending) = setup();
        let p = change(&cfg);
        arm(&pending, &p, 60, |_| Ok(())).unwrap();
        assert!(confirm(&pending).unwrap().is_some());
        assert_eq!(rollback(&pending).unwrap(), None);
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "allow_tcp = []\n");
    }

    #[test]
    fn a_failed_timer_disarms_so_the_caller_reverts() {
        let (_t, cfg, pending) = setup();
        let p = change(&cfg);
        assert!(arm(&pending, &p, 60, |_| anyhow::bail!("no systemd")).is_err());
        assert!(!pending.exists());
    }

    #[test]
    fn only_one_change_waits_at_a_time() {
        let (_t, cfg, pending) = setup();
        let p = change(&cfg);
        arm(&pending, &p, 60, |_| Ok(())).unwrap();
        let again = Pending {
            config: cfg.clone(),
            previous: String::new(),
            what: "x".into(),
        };
        assert!(arm(&pending, &again, 60, |_| Ok(())).is_err());
    }
}
