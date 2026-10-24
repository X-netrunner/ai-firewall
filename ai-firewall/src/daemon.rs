//---------------------------
// 5.1 Self-healing daemon
//---------------------------
//
// Healing loop (every TICK):
//   - follows the default route: wifi <-> ethernet switches, driver reloads (new ifindex)
//     and interfaces that vanish and come back all get the XDP program re-attached
//   - expires bans, notices bans added or lifted from the CLI
//   - re-reads router / DNS / own addresses so they can never be banned
//   - reloads the config when the file changes (a broken edit keeps the last good one)
// Bans, UDP flows and the attachments themselves are pinned, so a crashed or upgraded
// daemon restarted by systemd picks everything up with no gap in filtering, and the
// kernel ignores expired bans on its own while nobody is around to sweep them.

use crate::addr::Src;
use crate::config::Config;
use crate::detector::{Ban, Detector, Offender};
use crate::state::{self, BanRecord, Blocklist, Saved};
use crate::{links, net};
use ai_firewall_common::{
    CFG_DROP_PING, CFG_ENFORCE, CFG_EPHEMERAL_LOW, CFG_UDP_STRICT, PacketEvent, STAT_DROP_BLOCKLIST,
    STAT_DROP_POLICY, STAT_EVENTS_LOST, STAT_PASSED,
};
use anyhow::Context as _;
use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::{SchedClassifier, Xdp};
use aya::{Ebpf, EbpfLoader};
use log::{debug, error, info, warn};
use serde::Serialize;
use std::collections::{HashMap as StdHashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::signal::unix::{SignalKind, signal};

const TICK: Duration = Duration::from_secs(3);
const PROTECT_REFRESH_TICKS: u64 = 20;
const SAVE_TICKS: u64 = 10;
const RECENT_BANS: usize = 20;
const DHCP_CLIENT_PORTS: [u16; 2] = [68, 546];

#[derive(Debug, Clone, Serialize)]
pub struct RecentBan {
    pub ip: Src,
    pub reason: &'static str,
    pub ports: String,
    pub score: f32,
    pub secs: u64,
    pub strikes: u32,
    pub at_unix: u64,
    pub enforced: bool,
}

struct Shared {
    detector: Detector,
    blocklist: Blocklist,
    records: StdHashMap<Src, BanRecord>,
    enforce: bool,
    recent: VecDeque<RecentBan>,
    dirty: bool,
}

struct Attachment {
    iface: String,
    ifindex: u32,
    mode: String,
    /// The egress program is attached, so strict UDP can safely be switched on
    egress: bool,
}

const PINNED_MAPS: [&str; 4] = ["BLOCKLIST", "BLOCKLIST6", "UDP_FLOWS", "UDP_FLOWS6"];

struct Ports {
    tcp: Array<MapData, u8>,
    udp: Array<MapData, u8>,
    open_tcp: HashSet<u16>,
    open_udp: HashSet<u16>,
}

#[derive(Serialize)]
pub struct Status {
    pub pid: u32,
    pub mode: String,
    pub interface: Option<String>,
    pub xdp_mode: Option<String>,
    pub udp_strict: bool,
    pub started_unix: u64,
    pub updated_unix: u64,
    pub attaches: u64,
    pub passed: u64,
    pub dropped_blocklist: u64,
    pub dropped_policy: u64,
    pub events_lost: u64,
    pub tracked_sources: usize,
    pub allow_tcp: Vec<u16>,
    pub allow_udp: Vec<u16>,
    pub bans: Vec<StatusBan>,
    pub recent: Vec<RecentBan>,
}

#[derive(Serialize)]
pub struct StatusBan {
    pub ip: Src,
    pub remaining_secs: u64,
    pub reason: String,
    pub source: String,
    pub strikes: u32,
}

pub async fn run(config_path: PathBuf, iface_override: Option<String>) -> anyhow::Result<()> {
    let mut cfg = Config::load_or_create(&config_path)?;
    if let Some(iface) = &iface_override {
        cfg.interface = iface.clone();
    }
    let mut cfg_mtime = mtime(&config_path);

    // Bump the memlock rlimit (needed for older kernel memory accounting)
    let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        debug!("[!] remove limit on locked memory failed");
    }

    let mut ebpf = load_ebpf()?;
    xdp_program(&mut ebpf)?.load()?;
    tc_program(&mut ebpf)?.load()?;

    let blocklist = Blocklist::new(
        HashMap::try_from(ebpf.take_map("BLOCKLIST").context("BLOCKLIST map missing")?)?,
        Some(HashMap::try_from(ebpf.take_map("BLOCKLIST6").context("BLOCKLIST6 map missing")?)?),
    );
    let mut settings: Array<MapData, u32> = Array::try_from(ebpf.take_map("CONFIG").context("CONFIG map missing")?)?;
    let stats: PerCpuArray<MapData, u64> = PerCpuArray::try_from(ebpf.take_map("STATS").context("STATS map missing")?)?;
    let mut ports = Ports {
        tcp: Array::try_from(ebpf.take_map("TCP_ALLOW").context("TCP_ALLOW map missing")?)?,
        udp: Array::try_from(ebpf.take_map("UDP_ALLOW").context("UDP_ALLOW map missing")?)?,
        open_tcp: HashSet::new(),
        open_udp: HashSet::new(),
    };
    let events = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map missing")?)?;

    let shared = Arc::new(Mutex::new(Shared {
        detector: Detector::new(cfg.detector.clone(), cfg.bans.clone()),
        blocklist,
        records: StdHashMap::new(),
        enforce: cfg.enforce(),
        recent: VecDeque::new(),
        dirty: false,
    }));

    apply_config(&cfg, &mut settings, &mut ports, &mut lock(&shared))?;
    restore(&mut lock(&shared));
    refresh_protection(&cfg, &mut lock(&shared));

    spawn_event_reader(events, Arc::clone(&shared))?;

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut ticker = tokio::time::interval(TICK);
    let mut attachment: Option<Attachment> = None;
    let started = net::unix_secs();
    let mut attaches = 0u64;
    let mut strict_applied: Option<bool> = None;
    let mut tick = 0u64;

    info!("[*] ai-firewall {} mode, config {}", cfg.mode, config_path.display());

    loop {
        let mut reload = false;
        tokio::select! {
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            _ = sighup.recv() => reload = true,
            _ = ticker.tick() => {}
        }
        tick += 1;

        let now_mtime = mtime(&config_path);
        if reload || now_mtime != cfg_mtime {
            cfg_mtime = now_mtime;
            match Config::load_or_create(&config_path) {
                Ok(mut new_cfg) => {
                    if let Some(iface) = &iface_override {
                        new_cfg.interface = iface.clone();
                    }
                    if let Err(e) = apply_config(&new_cfg, &mut settings, &mut ports, &mut lock(&shared)) {
                        error!("[!] could not apply new config: {e:#}");
                    } else {
                        cfg = new_cfg;
                        refresh_protection(&cfg, &mut lock(&shared));
                        info!("[*] config reloaded ({} mode)", cfg.mode);
                    }
                }
                Err(e) => error!("[!] config rejected, keeping the previous one: {e:#}"),
            }
        }

        if heal(&mut ebpf, &cfg, &mut attachment)? {
            attaches += 1;
        }
        let strict = cfg.udp_strict && attachment.as_ref().is_some_and(|a| a.egress);
        if strict_applied != Some(strict) {
            // Strict UDP without the egress program would drop every reply, DNS included
            match settings.set(CFG_UDP_STRICT, strict as u32, 0) {
                Ok(()) => strict_applied = Some(strict),
                Err(e) => error!("[!] could not set UDP mode: {e}"),
            }
        }

        {
            let mut s = lock(&shared);
            sweep(&mut s);
            if tick % PROTECT_REFRESH_TICKS == 0 {
                refresh_protection(&cfg, &mut s);
            }
        }
        if cfg.keep_vm_forwarding && tick % PROTECT_REFRESH_TICKS == 1 {
            match crate::doctor::ensure_vm_forwarding() {
                Ok(changed) => changed.iter().for_each(|c| info!("[*] healed VM networking: let {c}")),
                Err(e) => debug!("vm forwarding check failed: {e:#}"),
            }
        }
        {
            let mut s = lock(&shared);
            s.detector.prune(net::boot_secs());
            if s.dirty || tick % SAVE_TICKS == 0 {
                save(&mut s);
            }
            let status = build_status(&cfg, &s, &stats, attachment.as_ref(), started, attaches);
            if let Err(e) = serde_json::to_vec_pretty(&status)
                .map_err(anyhow::Error::from)
                .and_then(|j| state::write_atomic(Path::new(state::STATUS_FILE), &j))
            {
                debug!("status write failed: {e}");
            }
        }
    }

    // The pinned links keep filtering (with the last rules) until the next start
    // swaps in its programs; `ai-firewall off` is what actually stops the firewall.
    info!("[*] daemon stopping; filtering continues until it's back (`ai-firewall off` stops it)");
    save(&mut lock(&shared));
    let _ = std::fs::remove_file(state::STATUS_FILE);
    Ok(())
}

fn lock(shared: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    // A poisoned lock only means another task panicked mid-update; the data is still usable
    shared.lock().unwrap_or_else(|p| p.into_inner())
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Loads the eBPF object reusing the pinned BLOCKLIST; if an older build pinned an
/// incompatible map, it is replaced instead of failing to start
fn load_ebpf() -> anyhow::Result<Ebpf> {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ai-firewall"));
    std::fs::create_dir_all(state::PIN_DIR)
        .with_context(|| format!("creating {} (is bpffs mounted on /sys/fs/bpf?)", state::PIN_DIR))?;
    match EbpfLoader::new().default_map_pin_directory(state::PIN_DIR).load(bytes) {
        Ok(ebpf) => Ok(ebpf),
        Err(e) => {
            warn!("[!] pinned maps unusable ({e}), recreating them");
            for name in PINNED_MAPS {
                let _ = std::fs::remove_file(Path::new(state::PIN_DIR).join(name));
            }
            Ok(EbpfLoader::new().default_map_pin_directory(state::PIN_DIR).load(bytes)?)
        }
    }
}

fn xdp_program(ebpf: &mut Ebpf) -> anyhow::Result<&mut Xdp> {
    Ok(ebpf.program_mut("ai_firewall").context("ai_firewall program missing")?.try_into()?)
}

fn tc_program(ebpf: &mut Ebpf) -> anyhow::Result<&mut SchedClassifier> {
    Ok(ebpf.program_mut("ai_firewall_egress").context("ai_firewall_egress program missing")?.try_into()?)
}

/// Returns true when it had to (re-)attach
fn heal(ebpf: &mut Ebpf, cfg: &Config, attachment: &mut Option<Attachment>) -> anyhow::Result<bool> {
    let wanted = if cfg.interface == "auto" {
        net::default_route().map(|r| r.0).or_else(|| attachment.as_ref().map(|a| a.iface.clone()))
    } else {
        Some(cfg.interface.clone())
    };

    if let Some(a) = attachment.as_ref() {
        let current = net::ifindex(&a.iface);
        if wanted.as_deref() == Some(a.iface.as_str()) && current == Some(a.ifindex) {
            return Ok(false);
        }
        let a = attachment.take().unwrap();
        links::unpin("xdp", &a.iface);
        links::unpin("tc", &a.iface);
        if current.is_none() {
            warn!("[!] {} disappeared; waiting for it (or another uplink) to come back", a.iface);
        }
    }

    let Some(iface) = wanted else {
        return Ok(false);
    };
    let Some(ifindex) = net::ifindex(&iface) else {
        return Ok(false);
    };
    // Links left on interfaces we no longer guard
    for old in links::pinned_ifaces().into_iter().filter(|i| *i != iface) {
        links::unpin("xdp", &old);
        links::unpin("tc", &old);
    }

    // Egress first, so flows are being recorded before strict UDP checks them
    let egress = match links::attach_tc(tc_program(ebpf)?, &iface, ifindex) {
        Ok(()) => true,
        Err(e) => {
            warn!("[!] {e:#}; UDP falls back to the looser ephemeral-port rule");
            false
        }
    };
    match links::attach_xdp(xdp_program(ebpf)?, &iface, ifindex) {
        Ok((mode, reused)) => {
            if reused {
                info!("[*] took over the running filter on {iface} ({mode} XDP), no gap");
            } else {
                info!("[*] guarding {iface} ({mode} XDP)");
            }
            *attachment = Some(Attachment { iface, ifindex, mode, egress });
            Ok(true)
        }
        Err(e) => {
            error!("[!] {e:#}; retrying in {}s", TICK.as_secs());
            Ok(false)
        }
    }
}

fn apply_config(
    cfg: &Config,
    settings: &mut Array<MapData, u32>,
    ports: &mut Ports,
    s: &mut Shared,
) -> anyhow::Result<()> {
    settings.set(CFG_ENFORCE, cfg.enforce() as u32, 0)?;
    settings.set(CFG_EPHEMERAL_LOW, net::ephemeral_low(), 0)?;
    settings.set(CFG_DROP_PING, (!cfg.allow_ping) as u32, 0)?;

    let tcp: HashSet<u16> = cfg.allow_tcp.iter().copied().collect();
    let udp: HashSet<u16> = cfg.allow_udp.iter().copied().chain(DHCP_CLIENT_PORTS).collect();
    sync_ports(&mut ports.tcp, &mut ports.open_tcp, tcp)?;
    sync_ports(&mut ports.udp, &mut ports.open_udp, udp)?;

    s.enforce = cfg.enforce();
    s.detector.reconfigure(cfg.detector.clone(), cfg.bans.clone());

    // Config bans are permanent; ones removed from the file are lifted
    let mut listed = HashSet::new();
    for cidr in cfg.blocked_cidrs()? {
        let size = (!cidr.mask as u64) + 1;
        for ip in (cidr.net as u64..cidr.net as u64 + size).map(|ip| Src::V4(ip as u32)) {
            listed.insert(ip);
        }
    }
    let stale: Vec<Src> = s
        .records
        .iter()
        .filter(|(ip, r)| r.source == "config" && !listed.contains(ip))
        .map(|(ip, _)| *ip)
        .collect();
    for ip in stale {
        let _ = s.blocklist.remove(ip);
        s.records.remove(&ip);
    }
    for ip in listed {
        s.blocklist.insert(ip, state::expiry_for(0))?;
        s.records.insert(ip, BanRecord { reason: "blocked in config".into(), source: "config".into(), strikes: 0 });
    }
    s.dirty = true;
    Ok(())
}

fn sync_ports(map: &mut Array<MapData, u8>, open: &mut HashSet<u16>, wanted: HashSet<u16>) -> anyhow::Result<()> {
    for &port in open.difference(&wanted) {
        map.set(port as u32, 0, 0)?;
    }
    for &port in wanted.difference(open) {
        map.set(port as u32, 1, 0)?;
    }
    *open = wanted;
    Ok(())
}

fn refresh_protection(cfg: &Config, s: &mut Shared) {
    let mut protected = net::auto_protected();
    protected.extend(cfg.trusted_cidrs().unwrap_or_default());
    s.detector.set_protected(protected, net::own_v6_prefixes());
    // If the router or DNS changed to an address we had auto-banned, lift that ban now
    let lift: Vec<Src> = s
        .records
        .iter()
        .filter(|(ip, r)| r.source == "auto" && s.detector.is_protected(**ip))
        .map(|(ip, _)| *ip)
        .collect();
    for ip in lift {
        let _ = s.blocklist.remove(ip);
        s.records.remove(&ip);
        info!("[*] lifted ban on {ip} (now a protected address)");
        s.dirty = true;
    }
}

fn restore(s: &mut Shared) {
    let saved = Saved::load();
    let (unix, boot) = (net::unix_secs(), net::boot_secs());
    let mut restored = 0;
    for b in saved.bans {
        let ip = b.ip;
        let secs = if b.expires_unix == 0 {
            0
        } else if b.expires_unix > unix {
            b.expires_unix - unix
        } else {
            continue;
        };
        if !s.blocklist.contains(ip) && s.blocklist.insert(ip, state::expiry_for(secs)).is_ok() {
            restored += 1;
        }
        s.records.entry(ip).or_insert(BanRecord { reason: b.reason, source: b.source, strikes: b.strikes });
    }
    for o in saved.offenders {
        let last_ban = boot.saturating_sub(unix.saturating_sub(o.last_ban_unix));
        s.detector.restore_offender(o.ip, Offender { strikes: o.strikes, last_ban });
    }
    if restored > 0 {
        info!("[*] restored {restored} bans from {}", state::STATE_FILE);
    }
}

fn save(s: &mut Shared) {
    let saved = Saved::capture(&s.blocklist, &s.records, s.detector.offenders());
    match saved.store() {
        Ok(()) => s.dirty = false,
        Err(e) => warn!("[!] could not save state: {e}"),
    }
}

/// Expires bans and picks up changes made with `ai-firewall ban/unban`
fn sweep(s: &mut Shared) {
    let entries = s.blocklist.entries();
    let present: HashSet<Src> = entries.iter().map(|e| e.0).collect();
    for (ip, expiry) in entries {
        if state::remaining(expiry).is_none() {
            let _ = s.blocklist.remove(ip);
            if let Some(r) = s.records.remove(&ip) {
                info!("[*] ban on {ip} expired ({})", r.reason);
            }
            s.dirty = true;
        } else if !s.records.contains_key(&ip) {
            s.records.insert(ip, state::manual_record());
            s.dirty = true;
        }
    }
    let before = s.records.len();
    s.records.retain(|ip, _| present.contains(ip));
    s.dirty |= s.records.len() != before;
}

fn spawn_event_reader(events: RingBuf<MapData>, shared: Arc<Mutex<Shared>>) -> anyhow::Result<()> {
    let mut async_fd = tokio::io::unix::AsyncFd::new(events)?;
    tokio::task::spawn(async move {
        let mut batch: Vec<PacketEvent> = Vec::new();
        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    // Exiting makes systemd restart us with a fresh ring buffer
                    error!("[!] event ring buffer failed: {e}");
                    std::process::exit(1);
                }
            };
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                if item.len() >= std::mem::size_of::<PacketEvent>() {
                    batch.push(unsafe { std::ptr::read_unaligned(item.as_ptr() as *const PacketEvent) });
                }
            }
            guard.clear_ready();

            let now = net::boot_secs();
            let mut s = lock(&shared);
            for ev in batch.drain(..) {
                if let Some(ban) = s.detector.observe(&ev, now) {
                    enact(&mut s, ban);
                }
            }
        }
    });
    Ok(())
}

fn enact(s: &mut Shared, ban: Ban) {
    let ip = ban.ip;
    let enforced = s.enforce;
    if enforced {
        match s.blocklist.insert(ban.ip, state::expiry_for(ban.secs)) {
            Ok(()) => {
                s.records.insert(
                    ban.ip,
                    BanRecord { reason: format!("{} ({})", ban.reason, ban.ports), source: "auto".into(), strikes: ban.strikes },
                );
                s.dirty = true;
                warn!(
                    "[!] [AUTO-BAN] {ip} for {}s: {} on {} (score {:.1}, strike {})",
                    ban.secs, ban.reason, ban.ports, ban.score, ban.strikes
                );
            }
            Err(e) => error!("[!] could not ban {ip}: {e}"),
        }
    } else {
        info!("[monitor] would ban {ip} for {}s: {} on {} (score {:.1})", ban.secs, ban.reason, ban.ports, ban.score);
    }
    if s.recent.len() == RECENT_BANS {
        s.recent.pop_front();
    }
    s.recent.push_back(RecentBan {
        ip,
        reason: ban.reason,
        ports: ban.ports.clone(),
        score: ban.score,
        secs: ban.secs,
        strikes: ban.strikes,
        at_unix: net::unix_secs(),
        enforced,
    });
}

fn build_status(
    cfg: &Config,
    s: &Shared,
    stats: &PerCpuArray<MapData, u64>,
    attachment: Option<&Attachment>,
    started: u64,
    attaches: u64,
) -> Status {
    let stat = |slot| stats.get(&slot, 0).map(|v| v.iter().sum()).unwrap_or(0);
    let mut bans: Vec<StatusBan> = s
        .blocklist
        .entries()
        .into_iter()
        .filter_map(|(ip, expiry)| {
            let rec = s.records.get(&ip).cloned().unwrap_or_else(state::manual_record);
            Some(StatusBan {
                ip,
                remaining_secs: state::remaining(expiry)?,
                reason: rec.reason,
                source: rec.source,
                strikes: rec.strikes,
            })
        })
        .collect();
    bans.sort_by_key(|b| b.ip);
    let mut allow_tcp = cfg.allow_tcp.clone();
    allow_tcp.sort_unstable();
    let mut allow_udp: Vec<u16> = cfg.allow_udp.iter().copied().chain(DHCP_CLIENT_PORTS).collect();
    allow_udp.sort_unstable();
    allow_udp.dedup();
    Status {
        pid: std::process::id(),
        mode: cfg.mode.clone(),
        interface: attachment.map(|a| a.iface.clone()),
        xdp_mode: attachment.map(|a| a.mode.clone()),
        udp_strict: cfg.udp_strict && attachment.is_some_and(|a| a.egress),
        started_unix: started,
        updated_unix: net::unix_secs(),
        attaches,
        passed: stat(STAT_PASSED),
        dropped_blocklist: stat(STAT_DROP_BLOCKLIST),
        dropped_policy: stat(STAT_DROP_POLICY),
        events_lost: stat(STAT_EVENTS_LOST),
        tracked_sources: s.detector.tracked(),
        allow_tcp,
        allow_udp,
        bans,
        recent: s.recent.iter().cloned().collect(),
    }
}
