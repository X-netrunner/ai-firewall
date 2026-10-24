//---------------------------
// 9.1 The assistant: ask the firewall why something doesn't work
//---------------------------
//
// A local model (Ollama, or whatever LUNA is set up with) gets the facts: doctor
// findings, firewall status, recent log lines and the config. It explains them and may
// propose actions, but only from a fixed list (doctor fixes, opening / closing a port,
// lifting a ban). Proposals are parsed here, checked, and only run when you confirm.
// Only local models are used, so nothing about your network leaves the machine.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    time::Duration,
};

use crate::{
    addr::Src,
    config::{AssistantConfig, Config},
    doctor::{self, Severity},
    tui::{StatusView, duration},
};

/// Small instruct models first: fast enough for a dashboard, good enough to read facts
const PREFERRED: &[&str] = &[
    "qwen2.5:3b-instruct",
    "qwen2.5:3b",
    "llama3.2:3b",
    "qwen2.5:7b-instruct",
    "qwen2.5:7b",
    "qwen3:4b",
    "llama3.1:8b",
    "qwen3:8b",
    "llama3.2:1b",
];

#[derive(Debug, Clone)]
pub struct Backend {
    pub host: String,
    pub model: String,
    /// "LUNA's model" or "Ollama", for the panel title
    pub via: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Fix(&'static str),
    Open(&'static str, u16),
    Close(&'static str, u16),
    Unban(Src),
}

impl Action {
    pub fn describe(&self) -> String {
        match self {
            Action::Fix(id) => doctor::fix_summary(id).unwrap_or(id).to_string(),
            Action::Open(p, port) => format!("open {p} port {port} to everyone"),
            Action::Close(p, port) => format!("close {p} port {port}"),
            Action::Unban(ip) => format!("lift the ban on {ip}"),
        }
    }

    /// The `ai-firewall` arguments that carry it out
    pub fn args(&self) -> Vec<String> {
        match self {
            Action::Fix(id) => vec!["fix".into(), id.to_string()],
            Action::Open(p, port) => vec!["open".into(), p.to_string(), port.to_string()],
            Action::Close(p, port) => vec!["close".into(), p.to_string(), port.to_string()],
            Action::Unban(ip) => vec!["unban".into(), ip.to_string()],
        }
    }

    fn parse(text: &str) -> Option<Self> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let proto = |w: &str| match w.to_ascii_lowercase().as_str() {
            "tcp" => Some("tcp"),
            "udp" => Some("udp"),
            _ => None,
        };
        match words.as_slice() {
            ["fix", id] => doctor::FIXES
                .iter()
                .find(|f| f.id == *id)
                .map(|f| Action::Fix(f.id)),
            ["open", p, port] => Some(Action::Open(
                proto(p)?,
                port.parse().ok().filter(|p| *p > 0)?,
            )),
            ["close", p, port] => Some(Action::Close(proto(p)?, port.parse().ok()?)),
            ["unban", ip] => ip.parse().ok().map(Action::Unban),
            _ => None,
        }
    }
}

/// Lines like `ACTION: open tcp 22`; anything not on the allowlist is ignored
pub fn parse_actions(reply: &str) -> Vec<Action> {
    let mut out: Vec<Action> = Vec::new();
    for line in reply.lines() {
        let line = line
            .trim()
            .trim_matches(|c| c == '*' || c == '`' || c == '-')
            .trim();
        let Some(rest) = line
            .strip_prefix("ACTION:")
            .or_else(|| line.strip_prefix("Action:"))
        else {
            continue;
        };
        if let Some(a) = Action::parse(rest.trim().trim_matches('`'))
            && !out.contains(&a)
        {
            out.push(a);
        }
    }
    out
}

/// The reply without its ACTION lines (those are shown as buttons instead)
pub fn strip_actions(reply: &str) -> String {
    reply
        .lines()
        .filter(|l| {
            !l.trim()
                .trim_matches(|c| c == '*' || c == '`' || c == '-')
                .trim()
                .to_ascii_uppercase()
                .starts_with("ACTION:")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

/// Home of the desktop user, also when running under sudo
pub fn user_home() -> Option<PathBuf> {
    match std::env::var("SUDO_USER") {
        Ok(user) if unsafe { libc::geteuid() } == 0 => std::fs::read_to_string("/etc/passwd")
            .ok()?
            .lines()
            .map(|l| l.split(':').collect::<Vec<_>>())
            .find(|f| f.len() > 5 && f[0] == user)
            .map(|f| PathBuf::from(f[5])),
        _ => std::env::var_os("HOME").map(PathBuf::from),
    }
}

/// LUNA's [llm] base_url and fast model, if LUNA is set up
fn luna_settings() -> Option<(String, Option<String>)> {
    let text = std::fs::read_to_string(user_home()?.join(".config/luna/luna.toml")).ok()?;
    let v: toml::Value = toml::from_str(&text).ok()?;
    let llm = v.get("llm")?;
    let url = llm.get("base_url")?.as_str()?.to_string();
    let model = llm
        .get("fast_model")
        .or_else(|| llm.get("model"))
        .and_then(|m| m.as_str())
        .map(String::from);
    Some((url, model))
}

/// "http://localhost:11434" -> "localhost:11434"; only loopback hosts are accepted
fn local_host(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("only plain http:// to a local model is supported")?;
    let host = rest.split('/').next().unwrap_or(rest).to_string();
    let name = host
        .rsplit_once(':')
        .map(|h| h.0)
        .unwrap_or(&host)
        .trim_matches(|c| c == '[' || c == ']');
    if !matches!(name, "localhost" | "127.0.0.1" | "::1") {
        return Err(format!(
            "{url} is not on this machine; the assistant only uses local models"
        ));
    }
    Ok(if host.contains(':') && !host.ends_with(']') {
        host
    } else {
        format!("{host}:11434")
    })
}

pub fn detect(cfg: &AssistantConfig) -> Result<Backend, String> {
    if !cfg.enabled {
        return Err(
            "the assistant is turned off in the config ([assistant] enabled = false)".into(),
        );
    }
    let luna = luna_settings();
    let (url, via) = match (&cfg.url, &luna) {
        (Some(u), _) => (u.clone(), "Ollama"),
        (None, Some((u, _))) => (u.clone(), "LUNA's model"),
        (None, None) => ("http://localhost:11434".into(), "Ollama"),
    };
    let host = local_host(&url)?;
    let tags = http(&host, "GET", "/api/tags", None, Duration::from_secs(2)).map_err(|_| {
        format!("no model server at {url}; install Ollama and `ollama pull qwen2.5:3b-instruct`")
    })?;
    let installed: Vec<String> = serde_json::from_str::<serde_json::Value>(&tags)
        .ok()
        .and_then(|v| v["models"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|m| m["name"].as_str().map(String::from))
        .collect();
    let has = |m: &str| {
        installed
            .iter()
            .any(|i| i == m || i.strip_suffix(":latest") == Some(m))
    };

    let model = if cfg.model != "auto" {
        cfg.model.clone()
    } else if let Some(m) = luna.and_then(|l| l.1).filter(|m| has(m)) {
        m
    } else if let Some(m) = PREFERRED.iter().find(|m| has(m)) {
        m.to_string()
    } else {
        // Anything that isn't a vision or embedding model
        installed
            .iter()
            .find(|m| !m.contains("vl") && !m.contains("embed") && !m.contains("llava"))
            .cloned()
            .ok_or("Ollama has no models; run `ollama pull qwen2.5:3b-instruct`")?
    };
    Ok(Backend { host, model, via })
}

/// Minimal HTTP/1.0 client: Ollama then answers without chunked encoding, and a
/// streamed reply is just newline-separated JSON until the connection closes
fn connect(
    host: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> std::io::Result<BufReader<TcpStream>> {
    // localhost is often ::1 first while Ollama listens on 127.0.0.1 only: try each
    let mut last = std::io::Error::other("no address");
    let mut stream = None;
    for addr in host.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = e,
        }
    }
    let mut stream = stream.ok_or(last)?;
    stream.set_read_timeout(Some(timeout))?;
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.0\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status)?;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    if !status.split_whitespace().nth(1).is_some_and(|c| c == "200") {
        let mut rest = String::new();
        let _ = reader.read_to_string(&mut rest);
        let msg = serde_json::from_str::<serde_json::Value>(&rest)
            .ok()
            .and_then(|v| v["error"].as_str().map(String::from))
            .unwrap_or_else(|| status.trim().to_string());
        return Err(std::io::Error::other(msg));
    }
    Ok(reader)
}

fn http(
    host: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> std::io::Result<String> {
    let mut out = String::new();
    connect(host, method, path, body, timeout)?.read_to_string(&mut out)?;
    Ok(out)
}

/// Everything the model gets to know, gathered fresh for each question
pub fn context() -> String {
    let mut out = String::new();
    out.push_str("## Doctor findings\n");
    for f in doctor::diagnose() {
        let sev = match f.severity {
            Severity::Ok => "ok",
            Severity::Info => "info",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        };
        out.push_str(&format!("- [{sev}] {}: {} ({})", f.area, f.title, f.detail));
        if let Some(id) = f.fix {
            out.push_str(&format!(" -> available: ACTION: fix {id}"));
        }
        out.push('\n');
    }

    out.push_str("\n## Firewall status\n");
    match StatusView::read() {
        Some(s) => {
            out.push_str(&format!(
                "mode {}, guarding {}, UDP {}\nopen tcp ports: {:?}, open udp ports: {:?}\npackets passed {}, dropped by policy {}, dropped from banned sources {}\n",
                s.mode,
                s.interface.as_deref().unwrap_or("nothing"),
                if s.udp_strict { "replies tracked (strict)" } else { "high ports open" },
                s.allow_tcp,
                s.allow_udp,
                s.passed,
                s.dropped_policy,
                s.dropped_blocklist
            ));
            out.push_str(&format!("{} active bans:\n", s.bans.len()));
            for b in s.bans.iter().take(15) {
                out.push_str(&format!(
                    "- {} ({}, {} left, by {})\n",
                    b.ip,
                    b.reason,
                    duration(b.remaining_secs),
                    b.source
                ));
            }
        }
        None => out.push_str("the firewall daemon is not running\n"),
    }

    if let Some(log) = run_quiet(
        "journalctl",
        &["-u", "ai-firewall", "-n", "25", "--no-pager", "-o", "cat"],
    ) && !log.trim().is_empty()
    {
        out.push_str("\n## Recent firewall log\n");
        out.push_str(&log);
    }

    out.push_str("\n## Host\n");
    let bridges = crate::net::virt_bridges();
    out.push_str(&format!(
        "VM / container bridges: {}\n",
        if bridges.is_empty() {
            "none".into()
        } else {
            bridges.join(" ")
        }
    ));
    let forward = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default();
    out.push_str(&format!(
        "IPv4 forwarding: {}\n",
        if forward.trim() == "1" { "on" } else { "OFF" }
    ));
    let services: Vec<&str> = [
        "docker",
        "libvirtd",
        "virtnetworkd",
        "podman",
        "ufw",
        "firewalld",
        "NetworkManager",
        "systemd-resolved",
    ]
    .into_iter()
    .filter(|u| run_quiet("systemctl", &["is-active", "--quiet", u]).is_some())
    .collect();
    out.push_str(&format!("running services: {}\n", services.join(" ")));
    if unsafe { libc::geteuid() } != 0 {
        out.push_str("NOTE: not running as root, so nftables rules and bans were NOT inspected. \
            If the problem could be a firewall rule, tell the user to run `sudo ai-firewall top` (or `sudo ai-firewall ask ...`) so you can see them.\n");
    }
    if crate::net::virt_bridges()
        .iter()
        .any(|b| b.starts_with("virbr"))
        && services.contains(&"docker")
    {
        out.push_str("Known issue on this setup: Docker sets the FORWARD chain policy to drop, which cuts libvirt VMs off \
            unless an exception exists. Whether it exists right now is unknown from here; applying the fix is harmless \
            if it does -> available: ACTION: fix allow-vm-forwarding\n");
    }

    out.push_str("\n## Interfaces\n");
    if let Some(addrs) = run_quiet("ip", &["-brief", "address"]) {
        out.push_str(&addrs);
    }
    out
}

fn run_quiet(cmd: &str, args: &[&str]) -> Option<String> {
    let o = std::process::Command::new(cmd).args(args).output().ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn system_prompt() -> String {
    format!(
        "You are the help assistant built into ai-firewall, the firewall on this Arch Linux desktop. \
It replaced ufw. Inbound is denied unless a port is open; outbound is always allowed; sources that scan or \
flood get banned automatically for a while. You answer the user's questions about their network, VMs, \
containers and the firewall, using ONLY the facts below, which were collected just now.\n\n\
Rules:\n\
- Be short and concrete: what is wrong, why, and what to do. Plain text, no markdown headings.\n\
- If the facts don't explain the problem, say so and say what to check next.\n\
- You can propose actions, which the user confirms with one key. Put each on its own line, exactly like:\n\
  ACTION: fix <id>            (one of: {})\n\
  ACTION: open tcp <port>     (or udp) to accept incoming connections on a port\n\
  ACTION: close tcp <port>\n\
  ACTION: unban <address>\n\
- Propose only actions that the facts support. Never propose opening a port unless the user wants \
something on this machine to be reachable from outside.\n\
- Never tell the user to disable the firewall, and never invent other commands to run as root.\n\n\
Example answer:\n\
Your VM is cut off because Docker sets the forward policy to drop, so traffic from virbr0 never leaves the machine. \
The fix adds an exception for virbr0 only: VMs can go out, and only replies come back in.\n\
ACTION: fix allow-vm-forwarding\n\n{}",
        doctor::FIXES
            .iter()
            .map(|f| f.id)
            .collect::<Vec<_>>()
            .join(", "),
        context()
    )
}

/// Streams the answer through `on_chunk`; returns the whole reply
pub fn ask(
    backend: &Backend,
    history: &[(String, String)],
    mut on_chunk: impl FnMut(&str),
) -> anyhow::Result<String> {
    let mut messages = vec![serde_json::json!({ "role": "system", "content": system_prompt() })];
    for (role, content) in history {
        messages.push(serde_json::json!({ "role": role, "content": content }));
    }
    let body = serde_json::json!({
        "model": backend.model,
        "messages": messages,
        "stream": true,
        "options": { "temperature": 0.2 },
    })
    .to_string();
    let reader = connect(
        &backend.host,
        "POST",
        "/api/chat",
        Some(&body),
        Duration::from_secs(180),
    )
    .map_err(|e| anyhow::anyhow!("{} ({}): {e}", backend.model, backend.host))?;
    let mut full = String::new();
    for line in reader.lines() {
        let line = line?;
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if let Some(err) = v["error"].as_str() {
            anyhow::bail!("{err}");
        }
        if let Some(piece) = v["message"]["content"].as_str() {
            full.push_str(piece);
            on_chunk(piece);
        }
        if v["done"].as_bool() == Some(true) {
            break;
        }
    }
    Ok(full)
}

/// What to show when no model is available: the doctor's findings, as actions
pub fn offline_answer() -> (String, Vec<Action>) {
    let findings = doctor::diagnose();
    let mut text = String::new();
    let mut actions = Vec::new();
    for f in findings.iter().filter(|f| f.severity >= Severity::Warn) {
        text.push_str(&format!("• {}: {}\n", f.title, f.detail));
        if let Some(id) = f.fix {
            actions.push(Action::Fix(id));
        }
    }
    if text.is_empty() {
        text = "The doctor found nothing wrong.".into();
    }
    (text.trim_end().to_string(), actions)
}

pub fn load_config() -> AssistantConfig {
    let path = std::path::Path::new(crate::config::DEFAULT_PATH);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| Config::parse(&t).ok())
        .map(|c| c.assistant)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_allowlisted_actions_parse() {
        let reply = "Docker drops forwarded traffic.\n\
            ACTION: fix allow-vm-forwarding\n\
            **ACTION: open tcp 22**\n\
            ACTION: fix rm-rf\n\
            ACTION: run sudo iptables -F\n\
            ACTION: open tcp 0\n\
            ACTION: unban 10.67.2.249\n\
            ACTION: fix allow-vm-forwarding\n";
        assert_eq!(
            parse_actions(reply),
            vec![
                Action::Fix("allow-vm-forwarding"),
                Action::Open("tcp", 22),
                Action::Unban("10.67.2.249".parse().unwrap()),
            ]
        );
        assert_eq!(strip_actions(reply), "Docker drops forwarded traffic.");
        assert_eq!(Action::Open("tcp", 22).args(), vec!["open", "tcp", "22"]);
    }

    #[test]
    fn refuses_remote_models() {
        assert_eq!(
            local_host("http://localhost:11434").unwrap(),
            "localhost:11434"
        );
        assert_eq!(local_host("http://127.0.0.1").unwrap(), "127.0.0.1:11434");
        assert!(local_host("http://example.com:11434").is_err());
        assert!(local_host("https://localhost:11434").is_err());
    }
}
