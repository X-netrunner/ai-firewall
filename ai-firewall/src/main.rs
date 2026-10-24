//---------------------------
// 1.3 || 3.1 || 3.2 || 4.1 || 5.1
// Userspace eBPF Firewall Controller
//---------------------------

mod addr;
mod config;
mod daemon;
mod detector;
mod doctor;
mod links;
mod net;
mod state;
mod tui;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::path::PathBuf;
use tui::duration;

#[derive(Debug, Parser)]
#[command(name = "ai-firewall", about = "Self-healing eBPF/XDP firewall")]
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
    Top,
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
        Cmd::Top => tui::run(),
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
            blocklist.remove(ip).with_context(|| format!("{ip} is not banned"))?;
            println!("unbanned {ip}");
            Ok(())
        }
        Cmd::Doctor { fix, yes, json } => doctor(fix, yes, json),
        Cmd::Fix { id } => {
            println!("{}", doctor::apply(&id)?);
            Ok(())
        }
        Cmd::Off => {
            need_root()?;
            let _ = std::process::Command::new("systemctl").args(["stop", "ai-firewall"]).status();
            let n = links::unpin_all();
            println!("ai-firewall is off ({n} interface{} released); `sudo systemctl start ai-firewall` turns it back on", if n == 1 { "" } else { "s" });
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
        let v: Vec<String> = s[k].as_array().into_iter().flatten().map(|p| p.to_string()).collect();
        if v.is_empty() { "none".into() } else { v.join(" ") }
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
    println!("  open tcp   {}", list("allow_tcp"));
    println!(
        "  open udp   {}  ({})",
        list("allow_udp"),
        if s["udp_strict"].as_bool() == Some(true) { "other UDP only as replies to your own" } else { "high ports open to replies" }
    );
    println!(
        "  packets    {} passed, {} dropped by policy, {} from banned sources",
        n("passed"),
        n("dropped_policy"),
        n("dropped_blocklist")
    );
    println!("  watching   {} sources, {} events lost", n("tracked_sources"), n("events_lost"));

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
                if r["enforced"].as_bool() == Some(true) { "" } else { "[monitor] " },
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
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "findings": findings, "fixes": fixes }))?);
        return Ok(());
    }

    let tty = unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1;
    let paint = |code: &str, text: &str| if tty { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_string() };
    for f in &findings {
        let (mark, code) = match f.severity {
            Severity::Ok => ("✓", "32"),
            Severity::Info => ("·", "36"),
            Severity::Warn => ("!", "33"),
            Severity::Fail => ("✗", "31"),
        };
        println!("{} {:8} {}", paint(code, mark), paint("2", f.area), paint("1", &f.title));
        println!("           {}", f.detail);
        if let Some(id) = f.fix {
            println!("           fix: {}  {}", paint("35", id), paint("2", doctor::fix_summary(id).unwrap_or("")));
        }
    }

    let pending: Vec<&'static str> = findings.iter().filter_map(|f| f.fix).collect();
    if pending.is_empty() {
        println!("\n{}", if findings.iter().any(|f| f.severity >= Severity::Warn) { "nothing here can be fixed automatically" } else { "all good" });
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
