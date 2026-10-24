//---------------------------
// 7.1 `ai-firewall doctor`: find out why the network is broken, and fix it
//---------------------------
//
// Every check is plain rules, no AI. Each fix has a fixed id and does one narrow thing;
// `ai-firewall fix <id>` is the only way anything (you, the dashboard, an assistant)
// can change the system from here, so the list below is the whole allowlist.

use crate::net;
use crate::state;
use crate::tui::StatusView;
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub area: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub fix: Option<&'static str>,
}

pub struct Fix {
    pub id: &'static str,
    pub summary: &'static str,
}

pub const FIXES: &[Fix] = &[
    Fix { id: "start-firewall", summary: "restart the ai-firewall service" },
    Fix { id: "disable-ufw", summary: "turn ufw off and disable it (ai-firewall replaces it)" },
    Fix { id: "disable-firewalld", summary: "turn firewalld off and disable it" },
    Fix { id: "enable-forwarding", summary: "turn on IPv4 forwarding now and at boot (VMs and containers need it)" },
    Fix { id: "allow-vm-forwarding", summary: "let VM bridges through the FORWARD drop policy (out: all, in: replies only)" },
    Fix { id: "restart-libvirt-network", summary: "restart libvirt's networking so it re-adds its NAT rules" },
    Fix { id: "restart-resolved", summary: "restart systemd-resolved (DNS)" },
    Fix { id: "unban-protected", summary: "lift bans on your router, DNS servers, own addresses and VM networks" },
];

pub fn fix_summary(id: &str) -> Option<&'static str> {
    FIXES.iter().find(|f| f.id == id).map(|f| f.summary)
}

fn finding(area: &'static str, severity: Severity, title: impl Into<String>, detail: impl Into<String>, fix: Option<&'static str>) -> Finding {
    Finding { area, severity, title: title.into(), detail: detail.into(), fix }
}

fn is_root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn unit_active(unit: &str) -> bool {
    run("systemctl", &["is-active", "--quiet", unit]).is_some()
}

fn reachable(addr: &str) -> bool {
    addr.parse::<SocketAddr>()
        .map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(3)).is_ok())
        .unwrap_or(false)
}

// ---------- nftables ruleset ----------

#[derive(Debug, Clone, PartialEq)]
pub struct Chain {
    pub family: String,
    pub table: String,
    pub name: String,
    pub hook: Option<String>,
    pub policy_drop: bool,
    pub body: String,
}

/// Splits `nft list ruleset` output into chains (enough structure for the checks here)
pub fn parse_ruleset(text: &str) -> Vec<Chain> {
    let mut chains = Vec::new();
    let (mut family, mut table) = (String::new(), String::new());
    let mut current: Option<Chain> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("table ") {
            let mut parts = rest.trim_end_matches('{').split_whitespace();
            family = parts.next().unwrap_or("").into();
            table = parts.next().unwrap_or("").into();
        } else if let Some(rest) = t.strip_prefix("chain ") {
            current = Some(Chain {
                family: family.clone(),
                table: table.clone(),
                name: rest.trim_end_matches('{').trim().into(),
                hook: None,
                policy_drop: false,
                body: String::new(),
            });
        } else if t == "}" {
            if let Some(c) = current.take() {
                chains.push(c);
            }
        } else if let Some(c) = current.as_mut() {
            if t.starts_with("type ") {
                c.hook = t.split("hook ").nth(1).and_then(|h| h.split_whitespace().next()).map(String::from);
                c.policy_drop = t.contains("policy drop");
            } else {
                c.body.push_str(t);
                c.body.push('\n');
            }
        }
    }
    chains
}

fn ruleset() -> Option<Vec<Chain>> {
    run("nft", &["list", "ruleset"]).map(|t| parse_ruleset(&t))
}

/// Bridges for VMs whose manager doesn't punch its own hole in a FORWARD drop
/// (Docker and Podman add their own rules, libvirt and LXD don't when another tool drops)
fn vm_bridges() -> Vec<String> {
    net::virt_bridges()
        .into_iter()
        .filter(|b| b.starts_with("virbr") || b.starts_with("lxdbr") || b.starts_with("vmnet"))
        .collect()
}

/// Forward base chains that drop by default and don't yet let `bridge` out
pub fn blocking_forward_chains<'a>(chains: &'a [Chain], bridge: &str) -> Vec<&'a Chain> {
    let lets_out = format!("iifname \"{bridge}\"");
    chains
        .iter()
        .filter(|c| c.hook.as_deref() == Some("forward") && c.policy_drop)
        .filter(|c| !c.body.lines().any(|l| l.contains(&lets_out) && l.contains("accept")))
        .collect()
}

/// Inserts the two VM rules where needed; returns what changed. Used by the
/// `allow-vm-forwarding` fix and by the daemon, which re-checks every minute
/// because Docker restores its drop policy whenever it restarts.
pub fn ensure_vm_forwarding() -> anyhow::Result<Vec<String>> {
    let mut changed = Vec::new();
    let bridges = vm_bridges();
    if bridges.is_empty() {
        return Ok(changed);
    }
    let Some(chains) = ruleset() else {
        return Ok(changed);
    };
    for bridge in bridges {
        for c in blocking_forward_chains(&chains, &bridge) {
            let base = ["insert", "rule", c.family.as_str(), c.table.as_str(), c.name.as_str()];
            let quoted = format!("\"{bridge}\"");
            let reply = [&base[..], &["oifname", &quoted, "ct", "state", "related,established", "accept", "comment", "\"ai-firewall\""]].concat();
            let out = [&base[..], &["iifname", &quoted, "accept", "comment", "\"ai-firewall\""]].concat();
            for args in [reply, out] {
                let status = Command::new("nft").args(&args).status()?;
                anyhow::ensure!(status.success(), "nft {} failed", args.join(" "));
            }
            changed.push(format!("{bridge} through {} {} {}", c.family, c.table, c.name));
        }
    }
    Ok(changed)
}

/// Same protection rules the daemon uses, without a running daemon
fn protection() -> crate::detector::Detector {
    let mut d = crate::detector::Detector::new(Default::default(), Default::default());
    d.set_protected(net::auto_protected(), net::own_v6_prefixes());
    d
}

// ---------- checks ----------

pub fn diagnose() -> Vec<Finding> {
    let mut out = Vec::new();
    check_firewall(&mut out);
    check_connectivity(&mut out);
    check_vms(&mut out);
    check_bans(&mut out);
    if !is_root() {
        out.push(finding("doctor", Severity::Info, "Partial check", "run `sudo ai-firewall doctor` to also inspect firewall rules and bans", None));
    }
    out
}

fn check_firewall(out: &mut Vec<Finding>) {
    match StatusView::read() {
        Some(s) if s.alive() => {
            let iface = s.interface.as_deref().unwrap_or("nothing");
            if s.mode == "enforce" {
                out.push(finding("firewall", Severity::Ok, "ai-firewall is protecting", format!("guarding {iface}"), None));
            } else {
                out.push(finding("firewall", Severity::Info, "ai-firewall is in monitor mode", "it logs but drops nothing; set mode = \"enforce\" in the config", None));
            }
            if s.interface.is_none() {
                out.push(finding("firewall", Severity::Warn, "Not attached to any interface", "there's no default route yet, so there's nothing to guard", None));
            }
        }
        Some(_) => out.push(finding("firewall", Severity::Fail, "ai-firewall stopped responding", "its status file is stale", Some("start-firewall"))),
        None if !crate::links::pinned_ifaces().is_empty() => out.push(finding(
            "firewall",
            Severity::Warn,
            "The filter is running without its daemon",
            "the last rules still apply, but nothing bans attackers or follows network changes; `sudo ai-firewall off` stops it entirely",
            Some("start-firewall"),
        )),
        None if std::path::Path::new("/etc/systemd/system/ai-firewall.service").exists() => {
            out.push(finding("firewall", Severity::Fail, "ai-firewall is not running", "the service is installed but not running", Some("start-firewall")))
        }
        None => out.push(finding("firewall", Severity::Info, "ai-firewall is not installed as a service", "run ./packaging/install.sh", None)),
    }
    if unit_active("ufw") {
        out.push(finding(
            "firewall",
            Severity::Warn,
            "ufw is still running",
            "two firewalls stack their rules; ufw's FORWARD drop policy also cuts off VMs",
            Some("disable-ufw"),
        ));
    }
    if unit_active("firewalld") {
        out.push(finding("firewall", Severity::Warn, "firewalld is still running", "two firewalls stack their rules", Some("disable-firewalld")));
    }
}

fn check_connectivity(out: &mut Vec<Finding>) {
    let Some((iface, gw)) = net::default_route() else {
        let nm = run("nmcli", &["-t", "-f", "STATE", "general"]).unwrap_or_default();
        out.push(finding(
            "network",
            Severity::Fail,
            "Not connected",
            format!("no default route (NetworkManager: {}); connect to wifi or plug in a cable", nm.trim().if_empty("unknown")),
            None,
        ));
        return;
    };
    let gw = Ipv4Addr::from(gw);
    let internet = reachable("1.1.1.1:443") || reachable("8.8.8.8:53");
    if internet {
        out.push(finding("network", Severity::Ok, "Internet works", format!("via {iface}, router {gw}"), None));
    } else {
        out.push(finding(
            "network",
            Severity::Fail,
            "Connected, but no internet",
            format!("{iface} has router {gw}, yet nothing outside answers: a captive portal, or the router itself is offline"),
            None,
        ));
    }

    let dns_ok = run("timeout", &["4", "getent", "hosts", "archlinux.org"]).is_some();
    let servers: Vec<String> = net::nameservers().into_iter().map(|ip| Ipv4Addr::from(ip).to_string()).collect();
    if dns_ok {
        out.push(finding("dns", Severity::Ok, "DNS works", format!("servers: {}", servers.join(" ").if_empty("none listed")), None));
    } else if internet {
        let resolved = unit_active("systemd-resolved");
        out.push(finding(
            "dns",
            Severity::Fail,
            "Internet works but names don't resolve",
            format!("DNS servers {} don't answer", servers.join(" ").if_empty("(none in /etc/resolv.conf)")),
            resolved.then_some("restart-resolved"),
        ));
    }
}

fn check_vms(out: &mut Vec<Finding>) {
    let bridges = net::virt_bridges();
    if bridges.is_empty() {
        return;
    }
    let list = bridges.join(" ");
    let forwarding = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").map(|s| s.trim() == "1").unwrap_or(false);
    if !forwarding {
        out.push(finding(
            "vm",
            Severity::Fail,
            "IP forwarding is off",
            format!("VMs and containers on {list} can't reach the internet without it"),
            Some("enable-forwarding"),
        ));
    }

    if !is_root() {
        return;
    }
    let Some(chains) = ruleset() else {
        return;
    };
    let mut ok = forwarding;
    for bridge in vm_bridges() {
        let blocking = blocking_forward_chains(&chains, &bridge);
        if !blocking.is_empty() {
            ok = false;
            let who: Vec<String> = blocking.iter().map(|c| format!("{} {} {}", c.family, c.table, c.name)).collect();
            let culprit = if chains.iter().any(|c| c.name.starts_with("ufw-")) {
                "ufw"
            } else if chains.iter().any(|c| c.name.starts_with("DOCKER")) {
                "Docker"
            } else {
                "a firewall rule"
            };
            out.push(finding(
                "vm",
                Severity::Fail,
                format!("VMs on {bridge} are cut off"),
                format!("{culprit} set a drop-by-default FORWARD policy ({}) with no exception for {bridge}", who.join(", ")),
                Some("allow-vm-forwarding"),
            ));
        }
        if bridge.starts_with("virbr") && net::ifindex(&bridge).is_some() {
            let subnet = net::interface_networks().into_iter().find(|n| n.iface == bridge).map(|n| n.net);
            let has_nat = match subnet {
                Some(n) => {
                    let prefix = Ipv4Addr::from(n.net).to_string();
                    let prefix = prefix.rsplit_once('.').map(|p| p.0).unwrap_or(&prefix).to_string();
                    chains.iter().any(|c| c.body.contains("masquerade") && c.body.contains(&prefix))
                }
                None => true,
            };
            if !has_nat {
                ok = false;
                out.push(finding(
                    "vm",
                    Severity::Warn,
                    format!("No NAT for {bridge}"),
                    "libvirt's masquerade rule is missing (something flushed the ruleset), so VM traffic leaves with an address nobody can answer",
                    Some("restart-libvirt-network"),
                ));
            }
        }
    }
    if ok {
        out.push(finding("vm", Severity::Ok, "VM and container networking looks right", format!("bridges: {list}"), None));
    }
}

fn check_bans(out: &mut Vec<Finding>) {
    if !is_root() {
        return;
    }
    let Ok(blocklist) = state::open_pinned_blocklist() else {
        return;
    };
    let guard = protection();
    let hits: Vec<String> =
        blocklist.entries().into_iter().map(|e| e.0).filter(|ip| guard.is_protected(*ip)).map(|ip| ip.to_string()).collect();
    if !hits.is_empty() {
        out.push(finding(
            "firewall",
            Severity::Fail,
            "An address you depend on is banned",
            format!("{} (router, DNS, this machine or a VM network)", hits.join(" ")),
            Some("unban-protected"),
        ));
    }
}

// ---------- fixes ----------

fn sh(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    anyhow::ensure!(status.success(), "`{cmd} {}` failed", args.join(" "));
    Ok(())
}

pub fn apply(id: &str) -> anyhow::Result<String> {
    let Some(action) = action(id) else {
        anyhow::bail!("unknown fix {id:?}; known fixes: {}", FIXES.iter().map(|f| f.id).collect::<Vec<_>>().join(", "));
    };
    anyhow::ensure!(is_root(), "fixes need root: run it with sudo");
    action()
}

type Action = fn() -> anyhow::Result<String>;

fn action(id: &str) -> Option<Action> {
    let a: Action = match id {
        "start-firewall" => || sh("systemctl", &["restart", "ai-firewall"]).map(|_| "ai-firewall restarted".into()),
        "disable-ufw" => || {
            let _ = sh("ufw", &["--force", "disable"]);
            sh("systemctl", &["disable", "--now", "ufw"]).map(|_| "ufw is off and won't start at boot".into())
        },
        "disable-firewalld" => || sh("systemctl", &["disable", "--now", "firewalld"]).map(|_| "firewalld is off".into()),
        "enable-forwarding" => || {
            sh("sysctl", &["-qw", "net.ipv4.ip_forward=1"])?;
            state::write_atomic(
                std::path::Path::new("/etc/sysctl.d/90-ai-firewall.conf"),
                b"# written by `ai-firewall fix enable-forwarding`: VMs and containers need it\nnet.ipv4.ip_forward = 1\n",
            )?;
            Ok("forwarding is on, and stays on after reboot".into())
        },
        "allow-vm-forwarding" => || {
            let changed = ensure_vm_forwarding()?;
            Ok(if changed.is_empty() {
                "nothing was blocking VM bridges".into()
            } else {
                format!("let {}; ai-firewall keeps these in place", changed.join(", "))
            })
        },
        "restart-libvirt-network" => || {
            let unit = if unit_active("virtnetworkd") { "virtnetworkd" } else { "libvirtd" };
            sh("systemctl", &["restart", unit])?;
            Ok(format!("{unit} restarted; it re-adds its NAT rules"))
        },
        "restart-resolved" => || sh("systemctl", &["restart", "systemd-resolved"]).map(|_| "systemd-resolved restarted".into()),
        "unban-protected" => || {
            let mut blocklist = state::open_pinned_blocklist()?;
            let guard = protection();
            let hits: Vec<_> = blocklist.entries().into_iter().map(|e| e.0).filter(|ip| guard.is_protected(*ip)).collect();
            for ip in &hits {
                blocklist.remove(*ip)?;
            }
            Ok(format!("lifted {} bans", hits.len()))
        },
        _ => return None,
    };
    Some(a)
}

trait IfEmpty {
    fn if_empty(self, fallback: &str) -> String;
}

impl IfEmpty for &str {
    fn if_empty(self, fallback: &str) -> String {
        if self.is_empty() { fallback.into() } else { self.into() }
    }
}

impl IfEmpty for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.is_empty() { fallback.into() } else { self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULESET: &str = r#"table ip filter {
	chain DOCKER-USER {
	}

	chain FORWARD {
		type filter hook forward priority filter; policy drop;
		counter packets 0 bytes 0 jump DOCKER-USER
		counter packets 0 bytes 0 jump DOCKER-FORWARD
	}

	chain INPUT {
		type filter hook input priority filter; policy accept;
	}
}
table ip nat {
	chain POSTROUTING {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 192.168.122.0/24 ip daddr != 192.168.122.0/24 counter masquerade
	}
}
"#;

    #[test]
    fn finds_docker_forward_drop() {
        let chains = parse_ruleset(RULESET);
        assert_eq!(chains.len(), 4);
        let blocking = blocking_forward_chains(&chains, "virbr0");
        assert_eq!(blocking.len(), 1);
        assert_eq!((blocking[0].table.as_str(), blocking[0].name.as_str()), ("filter", "FORWARD"));
        assert!(chains[3].body.contains("masquerade"));
    }

    #[test]
    fn our_rule_clears_it() {
        let fixed = RULESET.replace(
            "jump DOCKER-USER\n",
            "jump DOCKER-USER\n\t\tiifname \"virbr0\" accept comment \"ai-firewall\"\n",
        );
        assert!(blocking_forward_chains(&parse_ruleset(&fixed), "virbr0").is_empty());
    }

    #[test]
    fn every_fix_id_is_handled() {
        // looks the actions up without running them
        for f in FIXES {
            assert!(action(f.id).is_some(), "{} not handled", f.id);
        }
        assert!(action("rm -rf /").is_none());
        assert!(apply("rm -rf /").unwrap_err().to_string().contains("unknown fix"));
    }
}
