//---------------------------
// 1.3 || 3.1 || 3.2 || 4.1 || 5.1
// Userspace eBPF Firewall Controller
//---------------------------

mod addr;
mod assistant;
mod config;
mod daemon;
mod detector;
mod doctor;
mod feeds;
mod history;
mod links;
mod net;
mod state;
mod tui;

use std::path::PathBuf;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use serde_json::Value;
use tui::duration;

#[derive(Debug, Parser)]
#[command(
    name = "ai-firewall",
    version,
    about = "Self-healing eBPF/XDP firewall"
)]
struct Opt {
    /// Config file
    #[arg(short, long, global = true, default_value = config::DEFAULT_PATH)]
    config: PathBuf,

    /// Interface to guard, overriding the config (e.g. lo, wlan0, eth0)
    #[arg(short, long)]
    iface: Option<String>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the firewall (the default)
    Run,
    /// Show what the running firewall is doing
    Status,
    /// Live dashboard (run with sudo to ban / unban from it)
    Top {
        /// Open straight into the "ask the firewall" panel
        #[arg(long)]
        ask: bool,
    },
    /// Ban an address now
    Ban {
        /// IPv4 address, or IPv6 address / prefix (bans its /64)
        ip: addr::Src,
        /// Minutes; 0 bans until unbanned
        #[arg(short, long, default_value_t = 60)]
        minutes: u64,
    },
    /// Lift a ban
    Unban { ip: addr::Src },
    /// Open an inbound port or range, e.g. `open tcp 22` or `open tcp 1714-1764` (edits the config)
    Open { proto: String, port: String },
    /// Close an inbound port or range (edits the config)
    Close { proto: String, port: String },
    /// What the firewall did lately: bans, lifts, profile switches, feed updates
    History {
        /// How many entries
        #[arg(short, default_value_t = 30)]
        n: usize,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Blocklist feeds: what's loaded; --refresh downloads them now
    Feeds {
        #[arg(long)]
        refresh: bool,
    },
    /// Ask the firewall's assistant why something doesn't work
    Ask { question: Vec<String> },
    /// Stop filtering completely (stops the service and removes the pinned filter)
    Off,
    /// Find out why the network (or a VM) isn't working
    Doctor {
        /// Offer to apply each fix found
        #[arg(long)]
        fix: bool,
        /// With --fix: apply without asking
        #[arg(short, long)]
        yes: bool,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Apply one fix by id (see `ai-firewall doctor`)
    Fix { id: String },
    /// Check the config file without applying it
    Check,
    /// Print the default config
    DefaultConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    match opt.cmd.unwrap_or(Cmd::Run) {
        Cmd::Run => {
            need_root()?;
            daemon::run(opt.config, opt.iface).await
        }
        Cmd::Status => status(),
        Cmd::Top { ask } => tui::run(ask),
        Cmd::Ban { ip, minutes } => {
            need_root()?;
            let mut blocklist = state::open_pinned_blocklist()?;
            blocklist.insert(ip, state::expiry_for(minutes * 60))?;
            match minutes {
                0 => println!("banned {ip} until unbanned"),
                m => println!("banned {ip} for {m} min"),
            }
            Ok(())
        }
        Cmd::Unban { ip } => {
            need_root()?;
            let mut blocklist = state::open_pinned_blocklist()?;
            blocklist
                .remove(ip)
                .with_context(|| format!("{ip} is not banned"))?;
            println!("unbanned {ip}");
            Ok(())
        }
        Cmd::Doctor { fix, yes, json } => doctor(fix, yes, json),
        Cmd::Fix { id } => {
            println!("{}", doctor::apply(&id)?);
            Ok(())
        }
        Cmd::Open { proto, port } => {
            need_root()?;
            let port = port_spec(&port);
            match config::set_port(&opt.config, &proto, &port, true)? {
                true => println!("opened {proto} {port}"),
                false => println!("{proto} {port} was already open"),
            }
            Ok(())
        }
        Cmd::Close { proto, port } => {
            need_root()?;
            let port = port_spec(&port);
            match config::set_port(&opt.config, &proto, &port, false)? {
                true => println!("closed {proto} {port}"),
                false => println!("{proto} {port} wasn't open"),
            }
            Ok(())
        }
        Cmd::Ask { question } => ask(question.join(" ")),
        Cmd::History { n, json } => {
            let entries = history::read(n);
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
                return Ok(());
            }
            if entries.is_empty() {
                println!("nothing yet ({})", history::FILE);
            }
            let now = net::unix_secs();
            for e in entries {
                println!(
                    "{:>8} ago  {:7}  {:24}  {}",
                    duration(now.saturating_sub(e.at_unix).max(1)),
                    e.kind,
                    e.ip,
                    e.detail
                );
            }
            Ok(())
        }
        Cmd::Feeds { refresh } => {
            if refresh {
                need_root()?;
                let text = std::fs::read_to_string(&opt.config)?;
                let cfg = config::Config::parse(&text)?;
                for (name, err) in feeds::refresh(&cfg.feeds, true) {
                    println!("{name}: {}", err.unwrap_or_else(|| "updated".into()));
                }
                let _ = std::process::Command::new("systemctl")
                    .args(["reload", "ai-firewall"])
                    .status();
            }
            let s = tui::StatusView::read().context("ai-firewall is not running")?;
            println!("{} known-bad networks blocked", s.feed_networks);
            let now = net::unix_secs();
            for f in &s.feeds {
                let age = if f.updated_unix == 0 {
                    "never downloaded".into()
                } else {
                    format!(
                        "updated {} ago",
                        duration(now.saturating_sub(f.updated_unix).max(1))
                    )
                };
                println!(
                    "  {:16} {:>6} networks  {}{}",
                    f.name,
                    f.entries,
                    age,
                    f.error
                        .as_deref()
                        .map(|e| format!("  ({e})"))
                        .unwrap_or_default()
                );
            }
            Ok(())
        }
        Cmd::Off => {
            need_root()?;
            let _ = std::process::Command::new("systemctl")
                .args(["stop", "ai-firewall"])
                .status();
            let n = links::unpin_all();
            println!(
                "ai-firewall is off ({n} interface{} released); `sudo systemctl start ai-firewall` turns it back on",
                if n == 1 { "" } else { "s" }
            );
            Ok(())
        }
        Cmd::Check => {
            let text = std::fs::read_to_string(&opt.config)
                .with_context(|| format!("reading {}", opt.config.display()))?;
            config::Config::parse(&text)?;
            println!("{} is valid", opt.config.display());
            Ok(())
        }
        Cmd::DefaultConfig => {
            print!("{}", config::DEFAULT_CONFIG);
            Ok(())
        }
    }
}

fn need_root() -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("needs root: run it with sudo");
    }
    Ok(())
}

fn status() -> anyhow::Result<()> {
    let text = match std::fs::read_to_string(state::STATUS_FILE) {
        Ok(t) => t,
        Err(_) => bail!("ai-firewall is not running (no {})", state::STATUS_FILE),
    };
    let s: Value = serde_json::from_str(&text)?;
    let n = |k: &str| s[k].as_u64().unwrap_or(0);
    let age = net::unix_secs().saturating_sub(n("updated_unix"));
    let alive = std::path::Path::new(&format!("/proc/{}", n("pid"))).exists() && age < 30;
    let list = |k: &str| {
        let v: Vec<String> = s[k]
            .as_array()
            .into_iter()
            .flatten()
            .map(|p| {
                p.as_str()
                    .map(String::from)
                    .unwrap_or_else(|| p.to_string())
            })
            .collect();
        if v.is_empty() {
            "none".into()
        } else {
            v.join(" ")
        }
    };

    println!(
        "ai-firewall  {}  {} mode",
        if alive { "running" } else { "NOT RESPONDING" },
        s["mode"].as_str().unwrap_or("?")
    );
    println!(
        "  guarding   {} ({} XDP), up {}, attached {}x",
        s["interface"].as_str().unwrap_or("nothing yet"),
        s["xdp_mode"].as_str().unwrap_or("-"),
        duration(n("updated_unix").saturating_sub(n("started_unix")).max(1)),
        n("attaches"),
    );
    println!(
        "  profile    {}",
        s["profile"]
            .as_str()
            .unwrap_or("default (no profile matches this network)")
    );
    println!("  open tcp   {}", list("allow_tcp"));
    println!(
        "  open udp   {}  ({})",
        list("allow_udp"),
        if s["udp_strict"].as_bool() == Some(true) {
            "other UDP only as replies to your own"
        } else {
            "high ports open to replies"
        }
    );
    println!(
        "  packets    {} passed, {} dropped by policy, {} from banned sources",
        n("passed"),
        n("dropped_policy"),
        n("dropped_blocklist")
    );
    println!(
        "  watching   {} sources, {} events lost",
        n("tracked_sources"),
        n("events_lost")
    );
    if n("feed_networks") > 0 {
        let names: Vec<&str> = s["feeds"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| f["name"].as_str())
            .collect();
        println!(
            "  feeds      {} known-bad networks ({}), {} packets from them dropped",
            n("feed_networks"),
            names.join(", "),
            n("dropped_feed")
        );
    }
    let rules: Vec<&str> = s["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r.as_str())
        .collect();
    if !rules.is_empty() {
        println!("  rules      {}", rules.join("\n             "));
    }

    let bans = s["bans"].as_array().cloned().unwrap_or_default();
    println!("\nbans ({})", bans.len());
    for b in &bans {
        println!(
            "  {:24}  {:>8}  {:6}  {}",
            b["ip"].as_str().unwrap_or("?"),
            duration(b["remaining_secs"].as_u64().unwrap_or(0)),
            b["source"].as_str().unwrap_or(""),
            b["reason"].as_str().unwrap_or("")
        );
    }

    let recent = s["recent"].as_array().cloned().unwrap_or_default();
    if !recent.is_empty() {
        println!("\nrecent detections");
        for r in recent.iter().rev().take(10) {
            let ago = net::unix_secs().saturating_sub(r["at_unix"].as_u64().unwrap_or(0));
            println!(
                "  {:24}  {:>6} ago  {}{} on {} (score {:.1}, strike {})",
                r["ip"].as_str().unwrap_or("?"),
                duration(ago.max(1)),
                if r["enforced"].as_bool() == Some(true) {
                    ""
                } else {
                    "[monitor] "
                },
                r["reason"].as_str().unwrap_or(""),
                r["ports"].as_str().unwrap_or("?"),
                r["score"].as_f64().unwrap_or(0.0),
                r["strikes"].as_u64().unwrap_or(0)
            );
        }
    }
    Ok(())
}

fn doctor(fix: bool, yes: bool, json: bool) -> anyhow::Result<()> {
    use doctor::Severity;
    let findings = doctor::diagnose();
    if json {
        let fixes: Vec<Value> = findings
            .iter()
            .filter_map(|f| f.fix)
            .map(|id| serde_json::json!({ "id": id, "summary": doctor::fix_summary(id) }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({ "findings": findings, "fixes": fixes })
            )?
        );
        return Ok(());
    }

    let tty = unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1;
    let paint = |code: &str, text: &str| {
        if tty {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    };
    for f in &findings {
        let (mark, code) = match f.severity {
            Severity::Ok => ("✓", "32"),
            Severity::Info => ("·", "36"),
            Severity::Warn => ("!", "33"),
            Severity::Fail => ("✗", "31"),
        };
        println!(
            "{} {:8} {}",
            paint(code, mark),
            paint("2", f.area),
            paint("1", &f.title)
        );
        println!("           {}", f.detail);
        if let Some(id) = f.fix {
            println!(
                "           fix: {}  {}",
                paint("35", id),
                paint("2", doctor::fix_summary(id).unwrap_or(""))
            );
        }
    }

    let pending: Vec<&'static str> = findings.iter().filter_map(|f| f.fix).collect();
    if pending.is_empty() {
        println!(
            "\n{}",
            if findings.iter().any(|f| f.severity >= Severity::Warn) {
                "nothing here can be fixed automatically"
            } else {
                "all good"
            }
        );
        return Ok(());
    }
    if !fix {
        println!("\napply with: sudo ai-firewall doctor --fix   (or: sudo ai-firewall fix <id>)");
        return Ok(());
    }
    need_root()?;
    for id in pending {
        if !yes {
            print!("\n{}? [y/N] ", doctor::fix_summary(id).unwrap_or(id));
            std::io::Write::flush(&mut std::io::stdout())?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                continue;
            }
        }
        match doctor::apply(id) {
            Ok(msg) => println!("{} {msg}", paint("32", "✓")),
            Err(e) => println!("{} {id}: {e:#}", paint("31", "✗")),
        }
    }
    Ok(())
}

fn ask(question: String) -> anyhow::Result<()> {
    if question.trim().is_empty() {
        bail!("ask a question, e.g. ai-firewall ask \"why can't my VM reach the internet?\"");
    }
    let (reply, actions) = match assistant::detect(&assistant::load_config()) {
        Ok(backend) => {
            eprintln!("({} via {})\n", backend.model, backend.via);
            let mut shown = String::new();
            let reply = assistant::ask(&backend, &[("user".into(), question)], |piece| {
                // Hold back ACTION lines; they're listed as commands below
                shown.push_str(piece);
                while let Some(i) = shown.find('\n') {
                    let line: String = shown.drain(..=i).collect();
                    if !line
                        .trim_start()
                        .trim_start_matches(['*', '`', '-'])
                        .to_ascii_uppercase()
                        .starts_with("ACTION:")
                    {
                        print!("{line}");
                    }
                }
                let _ = std::io::Write::flush(&mut std::io::stdout());
            })?;
            if !shown
                .trim_start()
                .to_ascii_uppercase()
                .starts_with("ACTION:")
            {
                println!("{shown}");
            }
            let actions = assistant::parse_actions(&reply);
            (None, actions)
        }
        Err(why) => {
            eprintln!("(no local model: {why}; here's what the doctor found)\n");
            let (text, actions) = assistant::offline_answer();
            (Some(text), actions)
        }
    };
    if let Some(text) = reply {
        println!("{text}");
    }
    if !actions.is_empty() {
        println!("\nsuggested:");
        for a in actions {
            println!(
                "  sudo ai-firewall {}    # {}",
                a.args().join(" "),
                a.describe()
            );
        }
    }
    Ok(())
}

fn port_spec(s: &str) -> config::PortSpec {
    s.parse()
        .map(config::PortSpec::One)
        .unwrap_or_else(|_| config::PortSpec::Text(s.to_string()))
}
