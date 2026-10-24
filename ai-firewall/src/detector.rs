//---------------------------
// 5.1 Threat detector: per-source scores over a short window, escalating bans
//---------------------------
//
// Every streamed event adds to its source's score. Each signal is normalised by its
// limit, so a score of 1.0 means "one full limit's worth of hostile behaviour", whether
// that came from one signal or a mix (a slow scan that also floods a little still trips).

use std::collections::HashMap;

use ai_firewall_common::{PROTO_UDP, PacketEvent, VERDICT_DROP_POLICY};

use crate::{
    addr::Src,
    config::{BanConfig, Cidr, DetectorConfig},
};

/// Upper bound on sources tracked at once, so a spoofed flood can't grow memory forever
const MAX_TRACKED: usize = 16384;
/// Odd-flag (null / xmas / FIN) packets needed for a full score on their own
const ODD_LIMIT: f32 = 3.0;

#[derive(Debug, Default)]
struct Track {
    window_start: u64,
    syn: u32,
    udp: u32,
    drops: u32,
    odd: u32,
    ports: Vec<u16>,
    udp_seen: bool,
    tcp_seen: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Offender {
    pub strikes: u32,
    pub last_ban: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ban {
    pub ip: Src,
    pub secs: u64,
    pub strikes: u32,
    pub score: f32,
    pub reason: &'static str,
    /// e.g. "tcp 22 23 80 +9", so a ban can be checked at a glance
    pub ports: String,
}

pub struct Detector {
    cfg: DetectorConfig,
    bans: BanConfig,
    protected: Vec<Cidr>,
    protected6: Vec<u64>,
    tracks: HashMap<Src, Track>,
    offenders: HashMap<Src, Offender>,
}

impl Detector {
    pub fn new(cfg: DetectorConfig, bans: BanConfig) -> Self {
        Self {
            cfg,
            bans,
            protected: Vec::new(),
            protected6: Vec::new(),
            tracks: HashMap::new(),
            offenders: HashMap::new(),
        }
    }

    pub fn reconfigure(&mut self, cfg: DetectorConfig, bans: BanConfig) {
        self.cfg = cfg;
        self.bans = bans;
    }

    pub fn set_protected(&mut self, protected: Vec<Cidr>, protected6: Vec<u64>) {
        self.protected = protected;
        self.protected6 = protected6;
        let tracks = std::mem::take(&mut self.tracks);
        self.tracks = tracks
            .into_iter()
            .filter(|(src, _)| !self.is_protected(*src))
            .collect();
    }

    pub fn is_protected(&self, src: Src) -> bool {
        match src {
            Src::V4(ip) => self.protected.iter().any(|c| c.contains(ip)),
            // fe80::/10 link-local: the router and every LAN neighbour share fe80::/64
            Src::V6(p) => p >> 54 == 0x3fa || self.protected6.contains(&p),
        }
    }

    pub fn tracked(&self) -> usize {
        self.tracks.len()
    }

    pub fn offenders(&self) -> &HashMap<Src, Offender> {
        &self.offenders
    }

    pub fn restore_offender(&mut self, ip: Src, offender: Offender) {
        self.offenders.insert(ip, offender);
    }

    /// Feed one event; returns a ban when the source's score reaches 1.0
    pub fn observe(&mut self, ev: &PacketEvent, now: u64) -> Option<Ban> {
        let ip = Src::of(ev);
        if self.is_protected(ip) {
            return None;
        }
        if self.tracks.len() >= MAX_TRACKED && !self.tracks.contains_key(&ip) {
            self.prune(now);
            if self.tracks.len() >= MAX_TRACKED {
                return None;
            }
        }

        let cfg = &self.cfg;
        let track = self.tracks.entry(ip).or_default();
        if now.saturating_sub(track.window_start) >= cfg.window_secs {
            *track = Track {
                window_start: now,
                ..Default::default()
            };
        }

        if ev.protocol == PROTO_UDP {
            track.udp_seen = true;
        } else {
            track.tcp_seen = true;
        }
        if ev.protocol == PROTO_UDP {
            track.udp += 1;
        } else if ev.is_null_scan() || ev.is_xmas_scan() || ev.is_fin_scan() {
            track.odd += 1;
        } else if ev.is_syn() {
            track.syn += 1;
        }
        if ev.verdict == VERDICT_DROP_POLICY {
            track.drops += 1;
        }
        if track.ports.len() <= cfg.port_limit as usize && !track.ports.contains(&ev.dst_port) {
            track.ports.push(ev.dst_port);
        }

        let signals = [
            (track.syn as f32 / cfg.syn_limit as f32, "connection flood"),
            (
                track.ports.len() as f32 / cfg.port_limit as f32,
                "port scan",
            ),
            (track.udp as f32 / cfg.udp_limit as f32, "udp flood"),
            (
                track.drops as f32 / cfg.drop_limit as f32,
                "probing closed ports",
            ),
            (track.odd as f32 / ODD_LIMIT, "stealth scan"),
        ];
        // One port is normal traffic, not a scan signal
        let score: f32 = signals.iter().map(|s| s.0).sum::<f32>() - 1.0 / cfg.port_limit as f32;
        if score < 1.0 {
            return None;
        }
        let reason = signals
            .iter()
            .max_by(|a, b| a.0.total_cmp(&b.0))
            .map(|s| s.1)
            .unwrap_or("anomaly");
        let track = self.tracks.remove(&ip).unwrap_or_default();
        let proto = match (track.tcp_seen, track.udp_seen) {
            (true, true) => "tcp/udp",
            (false, true) => "udp",
            _ => "tcp",
        };
        let mut ports: Vec<String> = track.ports.iter().take(4).map(|p| p.to_string()).collect();
        if track.ports.len() > 4 {
            ports.push(format!("+{}", track.ports.len() - 4));
        }
        let ports = format!("{proto} {}", ports.join(" "));
        Some(self.escalate(ip, score, reason, ports, now))
    }

    /// Repeat offenders get exponentially longer bans: base, 2x, 4x ... up to max
    fn escalate(
        &mut self,
        ip: Src,
        score: f32,
        reason: &'static str,
        ports: String,
        now: u64,
    ) -> Ban {
        let forgive = self.bans.forgive_secs;
        let offender = self.offenders.entry(ip).or_insert(Offender {
            strikes: 0,
            last_ban: now,
        });
        if now.saturating_sub(offender.last_ban) > forgive {
            offender.strikes = 0;
        }
        offender.strikes += 1;
        offender.last_ban = now;
        let shift = (offender.strikes - 1).min(20);
        let secs = self
            .bans
            .base_secs
            .saturating_mul(1 << shift)
            .min(self.bans.max_secs);
        Ban {
            ip,
            secs,
            strikes: offender.strikes,
            score,
            reason,
            ports,
        }
    }

    /// Drop finished windows and forgiven offenders
    pub fn prune(&mut self, now: u64) {
        let window = self.cfg.window_secs;
        self.tracks
            .retain(|_, t| now.saturating_sub(t.window_start) < window);
        let keep = self.bans.forgive_secs.saturating_add(self.bans.max_secs);
        self.offenders
            .retain(|_, o| now.saturating_sub(o.last_ban) <= keep);
    }
}

#[cfg(test)]
mod tests {
    use ai_firewall_common::{
        PROTO_TCP, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_SYN, TCP_FLAG_URG,
        VERDICT_PASS,
    };

    use super::*;

    const ATTACKER: u32 = 0x0a00_0005;
    const ATTACKER_SRC: Src = Src::V4(ATTACKER);

    fn det() -> Detector {
        Detector::new(DetectorConfig::default(), BanConfig::default())
    }

    fn ev(proto: u8, flags: u8, port: u16, verdict: u8) -> PacketEvent {
        PacketEvent {
            src6: 0,
            src_ip: ATTACKER,
            dst_port: port,
            src_port: 40000,
            protocol: proto,
            tcp_flags: flags,
            payload_len: 0,
            verdict,
            family: ai_firewall_common::FAMILY_V4,
            _pad: [0; 2],
        }
    }

    #[test]
    fn port_scan_is_banned() {
        let mut d = det();
        let mut ban = None;
        for port in 1..=20 {
            ban = ban.or(d.observe(&ev(PROTO_TCP, TCP_FLAG_SYN, port, VERDICT_DROP_POLICY), 100));
        }
        let ban = ban.expect("scan should be banned");
        assert_eq!(ban.ip, ATTACKER_SRC);
        assert_eq!(ban.reason, "port scan");
        assert!(ban.ports.starts_with("tcp 1 2 3 4 +"), "{}", ban.ports);
        assert_eq!(ban.secs, 120);
    }

    #[test]
    fn steady_use_of_an_open_port_is_fine() {
        let mut d = det();
        // 3 new connections a second to an open port for a minute
        for t in 0..60 {
            for _ in 0..3 {
                assert_eq!(
                    d.observe(&ev(PROTO_TCP, TCP_FLAG_SYN, 22, VERDICT_PASS), t),
                    None
                );
            }
        }
    }

    #[test]
    fn stealth_scans_ban_fast() {
        let mut d = det();
        let xmas = TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG;
        assert!(
            d.observe(&ev(PROTO_TCP, 0, 80, VERDICT_DROP_POLICY), 0)
                .is_none()
        );
        assert!(
            d.observe(&ev(PROTO_TCP, xmas, 81, VERDICT_DROP_POLICY), 0)
                .is_none()
        );
        let ban = d.observe(&ev(PROTO_TCP, TCP_FLAG_FIN, 82, VERDICT_DROP_POLICY), 0);
        assert!(ban.is_some());
        // a FIN+ACK is ordinary teardown, not a scan
        assert!(!ev(PROTO_TCP, TCP_FLAG_FIN | TCP_FLAG_ACK, 80, VERDICT_PASS).is_fin_scan());
    }

    #[test]
    fn repeat_offenders_escalate_then_get_forgiven() {
        let mut d = det();
        let scan = |d: &mut Detector, now| {
            (1..=20)
                .find_map(|p| d.observe(&ev(PROTO_TCP, TCP_FLAG_SYN, p, VERDICT_DROP_POLICY), now))
                .unwrap()
        };
        assert_eq!(scan(&mut d, 0).secs, 120);
        assert_eq!(scan(&mut d, 200).secs, 240);
        assert_eq!(scan(&mut d, 600).secs, 480);
        let later = 600 + BanConfig::default().forgive_secs + 1;
        assert_eq!(scan(&mut d, later).strikes, 1);
    }

    #[test]
    fn protected_sources_are_never_banned() {
        let mut d = det();
        d.set_protected(vec![Cidr::single(ATTACKER)], vec![]);
        assert!(d.is_protected(ATTACKER_SRC));
        assert!(d.is_protected("fe80::1".parse().unwrap()));
        for p in 1..=200 {
            assert!(
                d.observe(&ev(PROTO_TCP, TCP_FLAG_SYN, p, VERDICT_DROP_POLICY), 0)
                    .is_none()
            );
        }
    }

    #[test]
    fn windows_reset() {
        let mut d = det();
        for t in 0..10 {
            // a few ports per window stays well under the limits when each window resets
            for p in 1..=6 {
                assert!(
                    d.observe(&ev(PROTO_TCP, TCP_FLAG_SYN, p, VERDICT_PASS), t * 10)
                        .is_none()
                );
            }
        }
        d.prune(1000);
        assert_eq!(d.tracked(), 0);
    }
}
