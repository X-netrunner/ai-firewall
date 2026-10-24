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

use std::{
    collections::{HashMap as StdHashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use ai_firewall_common::{
    CFG_DROP_PING, CFG_ENFORCE, CFG_EPHEMERAL_LOW, CFG_UDP_STRICT, PacketEvent, RuleKey,
    STAT_DROP_BLOCKLIST, STAT_DROP_FEED, STAT_DROP_POLICY, STAT_EVENTS_LOST, STAT_PASSED,
    rate_pack,
};
use anyhow::Context as _;
use aya::{
    Ebpf, EbpfLoader,
    maps::{
        Array, HashMap, MapData, PerCpuArray, RingBuf,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{SchedClassifier, Xdp},
};
use log::{debug, error, info, warn};
use serde::Serialize;
use tokio::signal::unix::{SignalKind, signal};

use crate::{
    addr::Src,
    config::{Cidr, Config, Policy, expand},
    detector::{Ban, Detector, Offender},
    feeds::{self, FeedState},
    history::{self, BanNotes},
    links, net,
    state::{self, BanRecord, Blocklist, Saved},
};

const TICK: Duration = Duration::from_secs(3);
const PROTECT_REFRESH_TICKS: u64 = 20;
const SAVE_TICKS: u64 = 10;
const RECENT_BANS: usize = 20;
const DHCP_CLIENT_PORTS: [u16; 2] = [68, 546];
/// Feeds: check every hour whether a list is due (each list has its own refresh_hours)
const FEED_CHECK_TICKS: u64 = 1200;

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
    notify_bans: bool,
    notes: BanNotes,
}

struct Attachment {
    iface: String,
    ifindex: u32,
    mode: String,
    /// The egress program is attached, so strict UDP can safely be switched on
    egress: bool,
}

const PINNED_MAPS: [&str; 4] = ["BLOCKLIST", "BLOCKLIST6", "UDP_FLOWS", "UDP_FLOWS6"];

/// The rule maps in the kernel, with what was last written to them (writes are diffs)
struct Kernel {
    tcp: Array<MapData, u8>,
    udp: Array<MapData, u8>,
    open_tcp: HashSet<u16>,
    open_udp: HashSet<u16>,
    from_tcp: LpmTrie<MapData, RuleKey, u8>,
    from_udp: LpmTrie<MapData, RuleKey, u8>,
    from_tcp_keys: HashSet<(u32, RuleKey)>,
    from_udp_keys: HashSet<(u32, RuleKey)>,
    rate: Array<MapData, u32>,
    rate_set: StdHashMap<u16, u32>,
    feeds: LpmTrie<MapData, [u8; 4], u8>,
    feed_nets: HashSet<(u32, u32)>,
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
    pub dropped_feed: u64,
    pub events_lost: u64,
    pub tracked_sources: usize,
    pub allow_tcp: Vec<String>,
    pub allow_udp: Vec<String>,
    pub ping: bool,
    pub profile: Option<String>,
    pub profiles: Vec<String>,
    pub rules: Vec<String>,
    pub feeds: Vec<FeedState>,
    pub feed_networks: usize,
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
    let (mut cfg, cfg_error) = Config::load_at_start(&config_path);
    match &cfg_error {
        None => Config::remember_good(&config_path),
        Some(e) => {
            error!("[!] {e:#}");
            error!("[!] running with the last config that worked until the file is fixed");
            history::notify(
                "Firewall config has an error",
                "Running with the last config that worked. Check it: ai-firewall check",
            );
        }
    }
    if let Some(iface) = &iface_override {
        cfg.interface = iface.clone();
    }
    let mut cfg_mtime = mtime(&config_path);

    // Bump the memlock rlimit (needed for older kernel memory accounting)
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        debug!("[!] remove limit on locked memory failed");
    }

    let mut ebpf = load_ebpf()?;
    xdp_program(&mut ebpf)?.load()?;
    tc_program(&mut ebpf)?.load()?;

    let blocklist = Blocklist::new(
        HashMap::try_from(
            ebpf.take_map("BLOCKLIST")
                .context("BLOCKLIST map missing")?,
        )?,
        Some(HashMap::try_from(
            ebpf.take_map("BLOCKLIST6")
                .context("BLOCKLIST6 map missing")?,
        )?),
    );
    let mut settings: Array<MapData, u32> =
        Array::try_from(ebpf.take_map("CONFIG").context("CONFIG map missing")?)?;
    let stats: PerCpuArray<MapData, u64> =
        PerCpuArray::try_from(ebpf.take_map("STATS").context("STATS map missing")?)?;
    let mut take = |name: &str| {
        ebpf.take_map(name)
            .with_context(|| format!("{name} map missing"))
    };
    let mut kernel = Kernel {
        tcp: Array::try_from(take("TCP_ALLOW")?)?,
        udp: Array::try_from(take("UDP_ALLOW")?)?,
        open_tcp: HashSet::new(),
        open_udp: HashSet::new(),
        from_tcp: LpmTrie::try_from(take("ALLOW_FROM_TCP")?)?,
        from_udp: LpmTrie::try_from(take("ALLOW_FROM_UDP")?)?,
        from_tcp_keys: HashSet::new(),
        from_udp_keys: HashSet::new(),
        rate: Array::try_from(take("TCP_RATE")?)?,
        rate_set: StdHashMap::new(),
        feeds: LpmTrie::try_from(take("FEEDS")?)?,
        feed_nets: HashSet::new(),
    };
    let events = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map missing")?)?;

    let shared = Arc::new(Mutex::new(Shared {
        detector: Detector::new(cfg.detector.clone(), cfg.bans.clone()),
        blocklist,
        records: StdHashMap::new(),
        enforce: cfg.enforce(),
        recent: VecDeque::new(),
        dirty: false,
        notify_bans: cfg.notify.bans,
        notes: BanNotes::default(),
    }));

    let mut profile = cfg.profile_for(&net::active_connections());
    apply_config(
        &cfg,
        &cfg.policy(profile.as_deref()),
        &mut settings,
        &mut kernel,
        &mut lock(&shared),
    )?;
    if let Some(p) = &profile {
        info!("[*] network profile: {p}");
    }
    restore(&mut lock(&shared));
    refresh_protection(&cfg, &mut lock(&shared));

    // Feeds: the cached copies right away, fresh ones in the background
    let mut feed_states = apply_feeds(&cfg, &mut kernel, &[]);
    let mut feed_job = Some(spawn_feed_refresh(&cfg, false));

    spawn_event_reader(events, Arc::clone(&shared))?;

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut ticker = tokio::time::interval(TICK);
    let mut attachment: Option<Attachment> = None;
    let started = net::unix_secs();
    let mut attaches = 0u64;
    let mut strict_applied: Option<bool> = None;
    let mut last_attaches = 0u64;
    let mut tick = 0u64;

    info!(
        "[*] ai-firewall {} mode, config {}",
        cfg.mode,
        config_path.display()
    );

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
                    let new_profile = new_cfg.profile_for(&net::active_connections());
                    let new_policy = new_cfg.policy(new_profile.as_deref());
                    if let Err(e) = apply_config(
                        &new_cfg,
                        &new_policy,
                        &mut settings,
                        &mut kernel,
                        &mut lock(&shared),
                    ) {
                        error!("[!] could not apply new config: {e:#}");
                    } else {
                        let feeds_changed = sources_differ(&cfg, &new_cfg);
                        cfg = new_cfg;
                        profile = new_profile;
                        Config::remember_good(&config_path);
                        if feeds_changed && feed_job.is_none() {
                            feed_job = Some(spawn_feed_refresh(&cfg, false));
                        }
                        feed_states = apply_feeds(&cfg, &mut kernel, &[]);
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
            if tick.is_multiple_of(PROTECT_REFRESH_TICKS) {
                refresh_protection(&cfg, &mut s);
            }
            s.notes.flush();
        }

        // Network profile: follows the active NetworkManager connection
        if tick % PROTECT_REFRESH_TICKS == 2 || attaches_changed(&mut last_attaches, attaches) {
            let now_profile = cfg.profile_for(&net::active_connections());
            if now_profile != profile {
                let policy = cfg.policy(now_profile.as_deref());
                match apply_config(
                    &cfg,
                    &policy,
                    &mut settings,
                    &mut kernel,
                    &mut lock(&shared),
                ) {
                    Ok(()) => {
                        let name = now_profile.clone().unwrap_or_else(|| "default".into());
                        info!("[*] network profile: {name}");
                        history::record("profile", "", name.clone());
                        history::notify(
                            &format!("Firewall profile: {name}"),
                            &policy_summary(&policy),
                        );
                        profile = now_profile;
                    }
                    Err(e) => error!("[!] could not switch profile: {e:#}"),
                }
            }
        }

        // Feeds: start a refresh when due, apply it when it's done
        if tick.is_multiple_of(FEED_CHECK_TICKS) && feed_job.is_none() {
            feed_job = Some(spawn_feed_refresh(&cfg, false));
        }
        if feed_job.as_ref().is_some_and(|j| j.is_finished()) {
            let results = feed_job.take().unwrap().await.unwrap_or_default();
            feed_states = apply_feeds(&cfg, &mut kernel, &results);
        }
        if cfg.keep_vm_forwarding && tick % PROTECT_REFRESH_TICKS == 1 {
            match crate::doctor::ensure_vm_forwarding() {
                Ok(changed) => changed
                    .iter()
                    .for_each(|c| info!("[*] healed VM networking: let {c}")),
                Err(e) => debug!("vm forwarding check failed: {e:#}"),
            }
        }
        {
            let mut s = lock(&shared);
            s.detector.prune(net::boot_secs());
            if s.dirty || tick.is_multiple_of(SAVE_TICKS) {
                save(&mut s);
            }
            let policy = cfg.policy(profile.as_deref());
            let status = build_status(
                &cfg,
                &policy,
                &feed_states,
                kernel.feed_nets.len(),
                &s,
                &stats,
                attachment.as_ref(),
                started,
                attaches,
            );
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
    std::fs::create_dir_all(state::PIN_DIR).with_context(|| {
        format!(
            "creating {} (is bpffs mounted on /sys/fs/bpf?)",
            state::PIN_DIR
        )
    })?;
    match EbpfLoader::new()
        .default_map_pin_directory(state::PIN_DIR)
        .load(bytes)
    {
        Ok(ebpf) => Ok(ebpf),
        Err(e) => {
            warn!("[!] pinned maps unusable ({e}), recreating them");
            for name in PINNED_MAPS {
                let _ = std::fs::remove_file(Path::new(state::PIN_DIR).join(name));
            }
            Ok(EbpfLoader::new()
                .default_map_pin_directory(state::PIN_DIR)
                .load(bytes)?)
        }
    }
}

fn xdp_program(ebpf: &mut Ebpf) -> anyhow::Result<&mut Xdp> {
    Ok(ebpf
        .program_mut("ai_firewall")
        .context("ai_firewall program missing")?
        .try_into()?)
}

fn tc_program(ebpf: &mut Ebpf) -> anyhow::Result<&mut SchedClassifier> {
    Ok(ebpf
        .program_mut("ai_firewall_egress")
        .context("ai_firewall_egress program missing")?
        .try_into()?)
}

/// Returns true when it had to (re-)attach
fn heal(
    ebpf: &mut Ebpf,
    cfg: &Config,
    attachment: &mut Option<Attachment>,
) -> anyhow::Result<bool> {
    let wanted = if cfg.interface == "auto" {
        net::default_route()
            .map(|r| r.0)
            .or_else(|| attachment.as_ref().map(|a| a.iface.clone()))
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
            warn!(
                "[!] {} disappeared; waiting for it (or another uplink) to come back",
                a.iface
            );
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
            *attachment = Some(Attachment {
                iface,
                ifindex,
                mode,
                egress,
            });
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
    policy: &Policy,
    settings: &mut Array<MapData, u32>,
    k: &mut Kernel,
    s: &mut Shared,
) -> anyhow::Result<()> {
    settings.set(CFG_ENFORCE, cfg.enforce() as u32, 0)?;
    settings.set(CFG_EPHEMERAL_LOW, net::ephemeral_low(), 0)?;
    settings.set(CFG_DROP_PING, (!policy.allow_ping) as u32, 0)?;

    // Ports open to everyone: the lists plus rules without `from`
    let mut tcp: HashSet<u16> = expand(&policy.allow_tcp)?.into_iter().collect();
    let mut udp: HashSet<u16> = expand(&policy.allow_udp)?
        .into_iter()
        .chain(DHCP_CLIENT_PORTS)
        .collect();
    let mut from_tcp = HashSet::new();
    let mut from_udp = HashSet::new();
    let mut rates: StdHashMap<u16, u32> = StdHashMap::new();
    for rule in &policy.rules {
        let ports = rule.port.ports()?;
        let tcp_rule = rule.proto == "tcp";
        for port in ports {
            match &rule.from {
                None if tcp_rule => drop(tcp.insert(port)),
                None => drop(udp.insert(port)),
                Some(f) => {
                    let c = Cidr::parse(f)?;
                    let p = port.to_be_bytes();
                    let a = c.net.to_be_bytes();
                    let key = (
                        16 + c.mask.leading_ones(),
                        [p[0], p[1], a[0], a[1], a[2], a[3]],
                    );
                    if tcp_rule {
                        from_tcp.insert(key)
                    } else {
                        from_udp.insert(key)
                    };
                }
            }
            if let Some((max, window)) = rule.rate()? {
                // two rules limiting one port: the stricter one wins
                let packed = rate_pack(max, window);
                rates
                    .entry(port)
                    .and_modify(|r| *r = (*r).min(packed))
                    .or_insert(packed);
            }
        }
    }
    sync_ports(&mut k.tcp, &mut k.open_tcp, tcp)?;
    sync_ports(&mut k.udp, &mut k.open_udp, udp)?;
    sync_trie(&mut k.from_tcp, &mut k.from_tcp_keys, from_tcp)?;
    sync_trie(&mut k.from_udp, &mut k.from_udp_keys, from_udp)?;
    for (&port, _) in k.rate_set.iter().filter(|(p, _)| !rates.contains_key(p)) {
        k.rate.set(port as u32, 0, 0)?;
    }
    for (&port, &packed) in &rates {
        k.rate.set(port as u32, packed, 0)?;
    }
    k.rate_set = rates;

    s.enforce = cfg.enforce();
    s.notify_bans = cfg.notify.bans;
    s.detector
        .reconfigure(cfg.detector.clone(), cfg.bans.clone());

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
        s.records.insert(
            ip,
            BanRecord {
                reason: "blocked in config".into(),
                source: "config".into(),
                strikes: 0,
            },
        );
    }
    s.dirty = true;
    Ok(())
}

fn sync_trie(
    trie: &mut LpmTrie<MapData, RuleKey, u8>,
    have: &mut HashSet<(u32, RuleKey)>,
    wanted: HashSet<(u32, RuleKey)>,
) -> anyhow::Result<()> {
    for (len, data) in have.difference(&wanted) {
        let _ = trie.remove(&Key::new(*len, *data));
    }
    for (len, data) in wanted.difference(have) {
        trie.insert(&Key::new(*len, *data), 1, 0)?;
    }
    *have = wanted;
    Ok(())
}

fn attaches_changed(last: &mut u64, now: u64) -> bool {
    std::mem::replace(last, now) != now
}

fn policy_summary(p: &Policy) -> String {
    let fmt = |v: &[crate::config::PortSpec]| {
        if v.is_empty() {
            "none".to_string()
        } else {
            v.iter().map(|s| s.label()).collect::<Vec<_>>().join(" ")
        }
    };
    format!(
        "open tcp: {}  ·  udp: {}  ·  rules: {}",
        fmt(&p.allow_tcp),
        fmt(&p.allow_udp),
        p.rules.len()
    )
}

fn sources_differ(a: &Config, b: &Config) -> bool {
    feeds::sources(&a.feeds) != feeds::sources(&b.feeds)
}

fn spawn_feed_refresh(
    cfg: &Config,
    force: bool,
) -> tokio::task::JoinHandle<Vec<(String, Option<String>)>> {
    let feeds_cfg = cfg.feeds.clone();
    tokio::task::spawn_blocking(move || feeds::refresh(&feeds_cfg, force))
}

/// Loads the cached lists into the kernel (diffing against what's there); returns their state
fn apply_feeds(
    cfg: &Config,
    k: &mut Kernel,
    results: &[(String, Option<String>)],
) -> Vec<FeedState> {
    let mut protected = net::auto_protected();
    protected.extend(cfg.trusted_cidrs().unwrap_or_default());
    let (nets, states) = feeds::load(&cfg.feeds, &protected, results);
    let wanted: HashSet<(u32, u32)> = nets.iter().map(|c| (c.net, c.mask)).collect();
    for (net, mask) in k.feed_nets.difference(&wanted) {
        let _ = k
            .feeds
            .remove(&Key::new(mask.leading_ones(), net.to_be_bytes()));
    }
    let mut failed = 0;
    for (net, mask) in wanted.difference(&k.feed_nets) {
        if k.feeds
            .insert(&Key::new(mask.leading_ones(), net.to_be_bytes()), 1, 0)
            .is_err()
        {
            failed += 1;
        }
    }
    if failed > 0 {
        warn!("[!] {failed} feed networks did not fit in the kernel map");
    }
    // logged when a download changed what is loaded, not every time the cache is re-read at start or reload
    let changed = wanted != k.feed_nets;
    let first_load = k.feed_nets.is_empty();
    k.feed_nets = wanted;
    if changed && !(first_load && results.is_empty()) {
        info!(
            "[*] feeds: {} known-bad networks blocked",
            k.feed_nets.len()
        );
        history::record(
            "feeds",
            "",
            format!(
                "{} networks from {}",
                k.feed_nets.len(),
                states
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    states
}

fn sync_ports(
    map: &mut Array<MapData, u8>,
    open: &mut HashSet<u16>,
    wanted: HashSet<u16>,
) -> anyhow::Result<()> {
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
        s.records.entry(ip).or_insert(BanRecord {
            reason: b.reason,
            source: b.source,
            strikes: b.strikes,
        });
    }
    for o in saved.offenders {
        let last_ban = boot.saturating_sub(unix.saturating_sub(o.last_ban_unix));
        s.detector.restore_offender(
            o.ip,
            Offender {
                strikes: o.strikes,
                last_ban,
            },
        );
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
                history::record("expire", ip, r.reason.clone());
            }
            s.dirty = true;
        } else if let std::collections::hash_map::Entry::Vacant(e) = s.records.entry(ip) {
            e.insert(state::manual_record());
            history::record("ban", ip, "by hand");
            s.dirty = true;
        }
    }
    let before = s.records.len();
    for ip in s.records.keys().filter(|ip| !present.contains(ip)) {
        history::record("lift", ip, "by hand");
    }
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
                    batch.push(unsafe {
                        std::ptr::read_unaligned(item.as_ptr() as *const PacketEvent)
                    });
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
                    BanRecord {
                        reason: format!("{} ({})", ban.reason, ban.ports),
                        source: "auto".into(),
                        strikes: ban.strikes,
                    },
                );
                s.dirty = true;
                warn!(
                    "[!] [AUTO-BAN] {ip} for {}s: {} on {} (score {:.1}, strike {})",
                    ban.secs, ban.reason, ban.ports, ban.score, ban.strikes
                );
                history::record(
                    "ban",
                    ip,
                    format!(
                        "{} on {}, {}, strike {}",
                        ban.reason,
                        ban.ports,
                        crate::tui::duration(ban.secs),
                        ban.strikes
                    ),
                );
                if s.notify_bans {
                    s.notes
                        .push(ip.to_string(), format!("{} on {}", ban.reason, ban.ports));
                }
            }
            Err(e) => error!("[!] could not ban {ip}: {e}"),
        }
    } else {
        info!(
            "[monitor] would ban {ip} for {}s: {} on {} (score {:.1})",
            ban.secs, ban.reason, ban.ports, ban.score
        );
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

#[allow(clippy::too_many_arguments)]
fn build_status(
    cfg: &Config,
    policy: &Policy,
    feed_states: &[FeedState],
    feed_networks: usize,
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
            let rec = s
                .records
                .get(&ip)
                .cloned()
                .unwrap_or_else(state::manual_record);
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
    let allow_tcp: Vec<String> = policy.allow_tcp.iter().map(|p| p.label()).collect();
    let mut allow_udp: Vec<String> = policy.allow_udp.iter().map(|p| p.label()).collect();
    for dhcp in DHCP_CLIENT_PORTS.map(|p| p.to_string()) {
        if !allow_udp.contains(&dhcp) {
            allow_udp.push(dhcp);
        }
    }
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
        dropped_feed: stat(STAT_DROP_FEED),
        events_lost: stat(STAT_EVENTS_LOST),
        tracked_sources: s.detector.tracked(),
        allow_tcp,
        allow_udp,
        ping: policy.allow_ping,
        profile: policy.profile.clone(),
        profiles: cfg.profiles.keys().cloned().collect(),
        rules: policy.rules.iter().map(|r| r.label()).collect(),
        feeds: feed_states.to_vec(),
        feed_networks,
        bans,
        recent: s.recent.iter().cloned().collect(),
    }
}
