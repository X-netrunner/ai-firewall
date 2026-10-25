//---------------------------
// 10.1 Live tests: check the running firewall and its detector without touching the network
//---------------------------
//
// Safety limits, enforced here rather than trusted to the caller (the assistant can ask for these):
// - nothing is sent to another host. `services` only connects to 127.0.0.1, and only to ports the
//   config opens, at most MAX_PROBE_PORTS of them, one attempt each with a short timeout
// - `detector` replays simulated packets through an in-memory copy of the detector, using
//   documentation addresses (RFC 5737); the real daemon, its maps and its bans are not touched
// - `traffic` only reads the status file the daemon already writes, for at most MAX_TRAFFIC_SECS
// - no test needs root, and none changes the config or the kernel state

use std::{
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use ai_firewall_common::{
    FAMILY_V4, PROTO_TCP, PROTO_UDP, PacketEvent, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_SYN,
    TCP_FLAG_URG, VERDICT_DROP_POLICY, VERDICT_PASS,
};
use serde::Serialize;

use crate::{
    config::{Cidr, Config, PortSpec},
    detector::Detector,
    net::unix_secs,
    tui::{StatusView, duration},
};

pub const MAX_PROBE_PORTS: usize = 16;
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(300);
pub const DEFAULT_TRAFFIC_SECS: u64 = 5;
pub const MAX_TRAFFIC_SECS: u64 = 30;
/// Simulated packets per detector scenario, at most
const MAX_SIM_EVENTS: usize = 2000;

/// (name, what it checks): the names the assistant and `ai-firewall test` accept
pub const TESTS: &[(&str, &str)] = &[
    (
        "health",
        "daemon alive, status fresh, filter attached, events lost",
    ),
    (
        "ports",
        "open ports versus what is listening on this machine",
    ),
    (
        "detector",
        "simulated scans and floods against the detector with your thresholds",
    ),
    (
        "traffic",
        "packets passed and dropped per second, sampled from the status file",
    ),
    (
        "services",
        "local services on open ports answer on 127.0.0.1",
    ),
];

pub fn is_test(name: &str) -> bool {
    name == "all" || TESTS.iter().any(|t| t.0 == name)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Report {
    pub test: String,
    pub ok: bool,
    pub summary: String,
    /// (label, value) pairs, in display order
    pub stats: Vec<(String, String)>,
}

impl Report {
    fn new(test: &str) -> Self {
        Self {
            test: test.into(),
            ok: true,
            summary: String::new(),
            stats: Vec::new(),
        }
    }

    fn stat(&mut self, label: impl Into<String>, value: impl ToString) {
        self.stats.push((label.into(), value.to_string()));
    }

    /// Plain text block, used in the chat and fed back to the model
    pub fn text(&self) -> String {
        let mut out = format!(
            "{} · {} · {}\n",
            self.test,
            if self.ok { "pass" } else { "FAIL" },
            self.summary
        );
        let w = self
            .stats
            .iter()
            .map(|s| s.0.chars().count())
            .max()
            .unwrap_or(0);
        for (k, v) in &self.stats {
            out.push_str(&format!("  {k:w$}  {v}\n"));
        }
        out
    }
}

pub fn config() -> Config {
    std::fs::read_to_string(crate::config::DEFAULT_PATH)
        .ok()
        .and_then(|t| Config::parse(&t).ok())
        .unwrap_or_else(|| Config::parse("").expect("the built-in defaults parse"))
}

/// Runs one test, or all of them ("all"); `traffic_secs` is clamped to MAX_TRAFFIC_SECS
pub fn run(name: &str, traffic_secs: u64) -> Vec<Report> {
    let cfg = config();
    let status = StatusView::read();
    let one = |n: &str| match n {
        "health" => health(status.as_ref()),
        "ports" => ports(&cfg, &listening()),
        "detector" => detector(&cfg),
        "traffic" => traffic(traffic_secs, StatusView::read),
        "services" => services(&cfg),
        other => {
            let mut r = Report::new(other);
            r.ok = false;
            r.summary = format!(
                "unknown test; known: {}",
                TESTS.iter().map(|t| t.0).collect::<Vec<_>>().join(", ")
            );
            r
        }
    };
    if name == "all" {
        TESTS.iter().map(|t| one(t.0)).collect()
    } else {
        vec![one(name)]
    }
}

fn health(s: Option<&StatusView>) -> Report {
    let mut r = Report::new("health");
    let Some(s) = s else {
        r.ok = false;
        r.summary = "daemon not running (no status file)".into();
        return r;
    };
    let age = unix_secs().saturating_sub(s.updated_unix);
    let alive = s.alive();
    r.ok = alive && s.config_error.is_none() && s.interface.is_some();
    r.summary = match (alive, &s.interface, &s.config_error) {
        (false, _, _) => "daemon not responding".into(),
        (_, None, _) => "no uplink: the filter is not attached".into(),
        (_, _, Some(_)) => "config error, last good config in force".into(),
        _ => format!("{} on {}", s.mode, s.interface.as_deref().unwrap_or("-")),
    };
    r.stat("status age", format!("{age}s"));
    r.stat(
        "uptime",
        duration(s.updated_unix.saturating_sub(s.started_unix).max(1)),
    );
    r.stat("xdp mode", s.xdp_mode.as_deref().unwrap_or("-"));
    r.stat("re-attaches", s.attaches.saturating_sub(1));
    r.stat("events lost", s.events_lost);
    r.stat("tracked sources", s.tracked_sources);
    r.stat("active bans", s.bans.len());
    if let Some(e) = &s.config_error {
        r.stat("config error", e);
    }
    r
}

/// (proto, port) pairs something listens on from outside loopback, from /proc/net
fn listening() -> Vec<(&'static str, u16)> {
    let mut out = Vec::new();
    for (file, proto) in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp"),
    ] {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        out.extend(parse_proc_net(&text, proto));
    }
    out.sort();
    out.dedup();
    out
}

/// TCP sockets in LISTEN (0A) and bound UDP sockets (07), skipping loopback-only ones
fn parse_proc_net(text: &str, proto: &'static str) -> Vec<(&'static str, u16)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (local, state) = (f.get(1)?, f.get(3)?);
            let wanted = if proto == "tcp" { "0A" } else { "07" };
            if *state != wanted {
                return None;
            }
            let (addr, port) = local.split_once(':')?;
            let loopback = addr == "0100007F" || addr == "00000000000000000000000001000000";
            (!loopback).then_some((proto, u16::from_str_radix(port, 16).ok()?))
        })
        .collect()
}

fn covers(specs: &[PortSpec], port: u16) -> bool {
    specs
        .iter()
        .any(|s| s.ports().is_ok_and(|r| r.contains(&port)))
}

/// Single ports only (a range is usually for clients like KDE Connect, not one service)
fn singles(specs: &[PortSpec]) -> Vec<u16> {
    specs
        .iter()
        .filter_map(|s| s.ports().ok())
        .filter(|r| r.start() == r.end())
        .map(|r| *r.start())
        .collect()
}

fn ports(cfg: &Config, listen: &[(&'static str, u16)]) -> Report {
    let mut r = Report::new("ports");
    let mut idle = Vec::new();
    for (proto, specs) in [("tcp", &cfg.allow_tcp), ("udp", &cfg.allow_udp)] {
        for port in singles(specs) {
            if !listen.iter().any(|(p, l)| *p == proto && *l == port) {
                idle.push(format!("{proto} {port}"));
            }
        }
    }
    let blocked: Vec<String> = listen
        .iter()
        .filter(|(p, port)| {
            let specs = if *p == "tcp" {
                &cfg.allow_tcp
            } else {
                &cfg.allow_udp
            };
            // udp above 32768 is mostly client sockets, not services
            !covers(specs, *port) && !(*p == "udp" && *port >= 32768)
        })
        .map(|(p, port)| format!("{p} {port}"))
        .collect();
    let list = |v: &[String]| {
        if v.is_empty() {
            "none".to_string()
        } else {
            v.join(", ")
        }
    };
    r.stat(
        "open in config",
        format!("tcp {} · udp {}", cfg.allow_tcp.len(), cfg.allow_udp.len()),
    );
    r.stat("listening", listen.len());
    r.stat("open, nothing listening", list(&idle));
    r.stat("listening, not reachable", list(&blocked));
    r.ok = idle.is_empty();
    r.summary = if idle.is_empty() {
        "every open port has a service".into()
    } else {
        format!("{} open port(s) with nothing behind them", idle.len())
    };
    r
}

fn sim_event(src: Ipv4Addr, proto: u8, flags: u8, port: u16, verdict: u8) -> PacketEvent {
    PacketEvent {
        src6: 0,
        src_ip: u32::from(src),
        dst_port: port,
        src_port: 40000,
        protocol: proto,
        tcp_flags: flags,
        payload_len: 0,
        verdict,
        family: FAMILY_V4,
        _pad: [0; 2],
    }
}

struct Scenario {
    name: &'static str,
    expect_ban: bool,
    protected: bool,
    /// (event, simulated second) generator
    events: Vec<(PacketEvent, u64)>,
}

fn scenarios(cfg: &Config) -> Vec<Scenario> {
    // RFC 5737 documentation ranges: never routed, never contacted
    let a = Ipv4Addr::new(198, 51, 100, 7);
    let open = singles(&cfg.allow_tcp).first().copied().unwrap_or(22);
    let syn = TCP_FLAG_SYN;
    let xmas = TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG;
    let per_sec = |n: usize, i: usize| (i / n.max(1)) as u64;
    let mut v = vec![
        Scenario {
            name: "port scan",
            expect_ban: true,
            protected: false,
            events: (0..200)
                .map(|i| {
                    (
                        sim_event(a, PROTO_TCP, syn, 1000 + i as u16, VERDICT_DROP_POLICY),
                        per_sec(20, i),
                    )
                })
                .collect(),
        },
        Scenario {
            name: "connection flood",
            expect_ban: true,
            protected: false,
            events: (0..400)
                .map(|i| {
                    (
                        sim_event(a, PROTO_TCP, syn, open, VERDICT_PASS),
                        per_sec(200, i),
                    )
                })
                .collect(),
        },
        Scenario {
            name: "udp flood",
            expect_ban: true,
            protected: false,
            events: (0..1000)
                .map(|i| {
                    (
                        sim_event(a, PROTO_UDP, 0, 40000, VERDICT_DROP_POLICY),
                        per_sec(500, i),
                    )
                })
                .collect(),
        },
        Scenario {
            name: "stealth scan",
            expect_ban: true,
            protected: false,
            events: (0..10)
                .map(|i| {
                    (
                        sim_event(a, PROTO_TCP, xmas, 80 + i as u16, VERDICT_DROP_POLICY),
                        0,
                    )
                })
                .collect(),
        },
        Scenario {
            name: "normal use",
            expect_ban: false,
            protected: false,
            events: (0..180)
                .map(|i| {
                    (
                        sim_event(a, PROTO_TCP, syn, open, VERDICT_PASS),
                        per_sec(3, i),
                    )
                })
                .collect(),
        },
    ];
    v.push(Scenario {
        name: "trusted source scans",
        expect_ban: false,
        protected: true,
        events: v[0].events.clone(),
    });
    for s in &mut v {
        s.events.truncate(MAX_SIM_EVENTS);
    }
    v
}

fn detector(cfg: &Config) -> Report {
    let mut r = Report::new("detector");
    let mut failed = Vec::new();
    let mut total = 0usize;
    let started = Instant::now();
    for sc in scenarios(cfg) {
        let mut d = Detector::new(cfg.detector.clone(), cfg.bans.clone());
        if sc.protected {
            d.set_protected(
                vec![Cidr::single(u32::from(Ipv4Addr::new(198, 51, 100, 7)))],
                Vec::new(),
            );
        }
        let mut hit = None;
        for (i, (ev, t)) in sc.events.iter().enumerate() {
            total += 1;
            if let Some(ban) = d.observe(ev, 1_000_000 + t) {
                hit = Some((i + 1, *t, ban));
                break;
            }
        }
        let value = match &hit {
            Some((n, t, ban)) => format!(
                "banned after {n} packets / {}s · {} · {}",
                t,
                ban.reason,
                duration(ban.secs)
            ),
            None => format!("not banned ({} packets)", sc.events.len()),
        };
        if hit.is_some() != sc.expect_ban {
            failed.push(sc.name);
        }
        r.stat(sc.name, value);
    }
    let ns = started.elapsed().as_nanos() as u64 / total.max(1) as u64;
    r.stat("cost per packet", format!("{ns} ns"));
    r.stat(
        "thresholds",
        format!(
            "window {}s · syn {} · ports {} · udp {} · drops {}",
            cfg.detector.window_secs,
            cfg.detector.syn_limit,
            cfg.detector.port_limit,
            cfg.detector.udp_limit,
            cfg.detector.drop_limit
        ),
    );
    r.ok = failed.is_empty();
    r.summary = if failed.is_empty() {
        "attacks banned, normal use and trusted sources left alone".into()
    } else {
        format!("unexpected result: {}", failed.join(", "))
    };
    r
}

fn traffic(secs: u64, read: impl Fn() -> Option<StatusView>) -> Report {
    let secs = secs.clamp(1, MAX_TRAFFIC_SECS);
    let mut r = Report::new("traffic");
    let Some(a) = read() else {
        r.ok = false;
        r.summary = "daemon not running (no status file)".into();
        return r;
    };
    // the daemon rewrites the file every 3 s; wait for a newer one, at most secs + 4
    let deadline = Instant::now() + Duration::from_secs(secs + 4);
    let started = Instant::now();
    let mut b = None;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if let Some(s) = read()
            && s.updated_unix >= a.updated_unix + secs
        {
            b = Some(s);
            break;
        }
    }
    let Some(b) = b else {
        r.ok = false;
        r.summary = "the status file did not update".into();
        return r;
    };
    let span = b.updated_unix.saturating_sub(a.updated_unix).max(1);
    let d = |x: u64, y: u64| y.saturating_sub(x);
    let passed = d(a.passed, b.passed);
    let policy = d(a.dropped_policy, b.dropped_policy);
    let banned = d(a.dropped_blocklist, b.dropped_blocklist);
    let feed = d(a.dropped_feed, b.dropped_feed);
    let new_bans = b
        .bans
        .iter()
        .filter(|x| !a.bans.iter().any(|y| y.ip == x.ip))
        .count();
    r.stat(
        "sampled",
        format!("{span}s (waited {:.1}s)", started.elapsed().as_secs_f32()),
    );
    r.stat("passed", format!("{passed} ({}/s)", passed / span));
    r.stat(
        "dropped, closed ports",
        format!("{policy} ({}/s)", policy / span),
    );
    r.stat("dropped, banned", format!("{banned} ({}/s)", banned / span));
    r.stat("dropped, blocklists", format!("{feed} ({}/s)", feed / span));
    r.stat("new bans", new_bans);
    r.stat("events lost", d(a.events_lost, b.events_lost));
    r.ok = d(a.events_lost, b.events_lost) == 0;
    r.summary = format!(
        "{} packets/s in, {} dropped/s",
        (passed + policy + banned + feed) / span,
        (policy + banned + feed) / span
    );
    r
}

fn services(cfg: &Config) -> Report {
    let mut r = Report::new("services");
    let ports: Vec<u16> = singles(&cfg.allow_tcp)
        .into_iter()
        .take(MAX_PROBE_PORTS)
        .collect();
    if ports.is_empty() {
        r.summary = "no single tcp ports are open, nothing to check".into();
        return r;
    }
    let mut down = Vec::new();
    for port in &ports {
        // loopback only, by construction: this is the one place a live connection is made
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, *port));
        let t = Instant::now();
        let value = match TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
            Ok(_) => format!("answers ({} ms)", t.elapsed().as_millis()),
            Err(e) => {
                down.push(port.to_string());
                format!("no answer ({})", e.kind())
            }
        };
        r.stat(format!("tcp {port}"), value);
    }
    r.ok = down.is_empty();
    r.summary = if down.is_empty() {
        format!("{} service(s) answer locally", ports.len())
    } else {
        format!("nothing answers on tcp {}", down.join(", "))
    };
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(text: &str) -> Config {
        Config::parse(text).unwrap()
    }

    #[test]
    fn detector_scenarios_pass_with_defaults() {
        let r = detector(&cfg(""));
        assert!(r.ok, "{}", r.text());
        assert!(
            r.stats
                .iter()
                .any(|(k, v)| k == "port scan" && v.starts_with("banned"))
        );
        assert!(
            r.stats
                .iter()
                .any(|(k, v)| k == "normal use" && v.starts_with("not banned"))
        );
        assert!(
            r.stats
                .iter()
                .any(|(k, v)| k == "trusted source scans" && v.starts_with("not banned"))
        );
    }

    #[test]
    fn detector_reports_a_threshold_too_loose() {
        let r = detector(&cfg(
            "[detector]\nport_limit = 5000\ndrop_limit = 5000\nsyn_limit = 5000\n",
        ));
        assert!(!r.ok);
        assert!(r.summary.contains("port scan"), "{}", r.summary);
    }

    #[test]
    fn proc_net_parsing_skips_loopback_and_non_listeners() {
        let tcp = "  sl  local_address rem_address   st\n\
            0: 00000000:0016 00000000:0000 0A\n\
            1: 0100007F:0277 00000000:0000 0A\n\
            2: 00000000:1F90 0A0A0A0A:D431 01\n";
        assert_eq!(parse_proc_net(tcp, "tcp"), vec![("tcp", 22)]);
    }

    #[test]
    fn ports_finds_idle_and_unreachable() {
        let c = cfg("allow_tcp = [22, 8080]\nallow_udp = []\n");
        let r = ports(&c, &[("tcp", 22), ("tcp", 631)]);
        assert!(!r.ok);
        let get = |k: &str| r.stats.iter().find(|s| s.0 == k).unwrap().1.clone();
        assert_eq!(get("open, nothing listening"), "tcp 8080");
        assert_eq!(get("listening, not reachable"), "tcp 631");
    }

    #[test]
    fn traffic_computes_rates_from_two_samples() {
        let now = unix_secs();
        let calls = std::cell::Cell::new(0u32);
        let read = || {
            calls.set(calls.get() + 1);
            let first = calls.get() == 1;
            Some(StatusView {
                updated_unix: if first { now } else { now + 3 },
                passed: if first { 100 } else { 400 },
                dropped_policy: if first { 0 } else { 30 },
                ..Default::default()
            })
        };
        let r = traffic(3, read);
        assert!(r.ok, "{}", r.text());
        assert!(
            r.stats
                .iter()
                .any(|(k, v)| k == "passed" && v == "300 (100/s)")
        );
        assert!(
            r.stats
                .iter()
                .any(|(k, v)| k == "dropped, closed ports" && v == "30 (10/s)")
        );
    }

    #[test]
    fn traffic_window_is_capped() {
        assert_eq!(99u64.clamp(1, MAX_TRAFFIC_SECS), MAX_TRAFFIC_SECS);
    }

    #[test]
    fn health_without_daemon_fails() {
        assert!(!health(None).ok);
    }

    #[test]
    fn known_names() {
        assert!(is_test("all") && is_test("detector") && !is_test("flood-my-router"));
    }
}
