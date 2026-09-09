//---------------------------
// 1.3 || 3.1 || 3.2 || 4.1 || 5.1
// Userspace eBPF Firewall Controller with TUI Dashboard
//---------------------------

use ai_firewall_common::KernelMetrics;
use anyhow::Context as _;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpMode};
use aya_log::EbpfLogger;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table},
    Terminal,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap as StdHashMap;
use std::convert::TryFrom;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as TokioMutex;

const BLOCK_TTL: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModelConfig {
    pub centroids: Vec<Vec<f64>>,
    pub anomaly_cluster_index: usize,
}

impl ModelConfig {
    pub fn predict_anomaly(&self, features: &[f64]) -> bool {
        let mut min_dist = f64::MAX;
        let mut closest_cluster = 0;

        for (cluster_idx, centroid) in self.centroids.iter().enumerate() {
            let dist: f64 = features
                .iter()
                .zip(centroid.iter())
                .map(|(x, c)| (x - c).powi(2))
                .sum();

            if dist < min_dist {
                min_dist = dist;
                closest_cluster = cluster_idx;
            }
        }

        closest_cluster == self.anomaly_cluster_index
    }
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlan0")]
    iface: String,

    #[clap(long)]
    skb: bool,

    #[clap(short, long, default_value_t = 100)]
    threshold: u32,
}

#[derive(Default, Clone)]
struct DashboardState {
    pub active_ips: Vec<(String, u64, u64, bool)>, // (IP, Packets, Bytes, Anomaly)
    pub total_packets: u64,
    pub total_bytes: u64,
    pub blocked_ips: Vec<(String, u64)>,           // (IP, TTL remaining seconds)
    pub logs: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    // 1. Bump memory lock limit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    // 2. Load compiled eBPF bytecode
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ai-firewall"
    )))?;

    // 3. Initialize eBPF Logger
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
    	eprintln!("[!] Warning: Failed to initialize eBPF logger: {}",e);
    }

    // 4. Attach XDP program
    let Opt { iface, skb, threshold } = opt;
    let program: &mut Xdp = ebpf.program_mut("ai_firewall").unwrap().try_into()?;
    program.load()?;

    if skb {
        program.attach(&iface, XdpMode::Skb)?;
    } else {
        if program.attach(&iface, XdpMode::default()).is_err() {
            program.attach(&iface, XdpMode::Skb)?;
        }
    }

    // 5. Shared state between kernel sweeper and TUI render engine
    let blocklist_map = ebpf.take_map("BLOCKLIST").context("failed to find BLOCKLIST map")?;
    let blocklist: HashMap<_, u32, u32> = HashMap::try_from(blocklist_map)?;
    let blocklist = Arc::new(TokioMutex::new(blocklist));

    let blocked_timestamps: Arc<TokioMutex<StdHashMap<u32, Instant>>> =
        Arc::new(TokioMutex::new(StdHashMap::new()));

    let dashboard_state = Arc::new(TokioMutex::new(DashboardState::default()));

    // Load pre-trained ML model
    let model_config: Option<ModelConfig> = std::fs::read_to_string("model.json")
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok());
    let model_config = Arc::new(model_config);

    // -------------------------------------------------------------
    // TASK A: Auto-Unblock Cleanup Sweeper Loop
    // -------------------------------------------------------------
    let blocklist_cleaner = Arc::clone(&blocklist);
    let timestamps_cleaner = Arc::clone(&blocked_timestamps);
    let dashboard_cleaner = Arc::clone(&dashboard_state);

    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;

            let now = Instant::now();
            let mut timestamps = timestamps_cleaner.lock().await;

            let expired_ips: Vec<u32> = timestamps
                .iter()
                .filter(|(_, added_at)| now.duration_since(**added_at) >= BLOCK_TTL)
                .map(|(&ip, _)| ip)
                .collect();

            if !expired_ips.is_empty() {
                let mut map = blocklist_cleaner.lock().await;
                let mut dash = dashboard_cleaner.lock().await;

                for ip in expired_ips {
                    if map.remove(&ip).is_ok() {
                        timestamps.remove(&ip);
                        dash.logs.push(format!("[TTL-EXPIRED] Unblocked IP {}", Ipv4Addr::from(ip)));
                    }
                }
            }

            // Update remaining TTL display list for active blocks
            let mut dash = dashboard_cleaner.lock().await;
            dash.blocked_ips = timestamps
                .iter()
                .map(|(&ip, &added_at)| {
                    let elapsed = now.duration_since(added_at).as_secs();
                    let remaining = BLOCK_TTL.as_secs().saturating_sub(elapsed);
                    (Ipv4Addr::from(ip).to_string(), remaining)
                })
                .collect();

            if dash.logs.len() > 100 {
                dash.logs.drain(0..50);
            }
        }
    });

    // -------------------------------------------------------------
    // TASK B: Kernel Map Sweeper and ML Evaluator Loop
    // -------------------------------------------------------------
    let metrics_map = ebpf.take_map("METRICS_MAP").context("failed to find METRICS_MAP")?;
    let mut metrics_map: HashMap<_, u32, KernelMetrics> = HashMap::try_from(metrics_map)?;

    let blocklist_clone = Arc::clone(&blocklist);
    let timestamps_clone = Arc::clone(&blocked_timestamps);
    let model_clone = Arc::clone(&model_config);
    let dashboard_clone = Arc::clone(&dashboard_state);

    tokio::task::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));

        loop {
            ticker.tick().await;

            let keys: Vec<u32> = metrics_map.keys().filter_map(|k| k.ok()).collect();
            let mut current_active = Vec::new();
            let mut total_p = 0;
            let mut total_b = 0;

            for src_ip in keys {
                if let Ok(metrics) = metrics_map.get(&src_ip, 0) {
                    let packet_rate = metrics.packet_count as f64;
                    let total = packet_rate.max(1.0);

                    total_p += metrics.packet_count;
                    total_b += metrics.bytes_count;

                    let feature_arr = [
                        packet_rate,
                        (metrics.bytes_count as f64) / total,
                        (metrics.tcp_count as f64) / total,
                        (metrics.udp_count as f64) / total,
                        (metrics.icmp_count as f64) / total,
                    ];

                    let is_anomaly = if let Some(ref model) = *model_clone {
                        model.predict_anomaly(&feature_arr)
                    } else {
                        packet_rate > threshold as f64
                    };

                    current_active.push((
                        Ipv4Addr::from(src_ip).to_string(),
                        metrics.packet_count,
                        metrics.bytes_count,
                        is_anomaly,
                    ));

                    if is_anomaly {
                        let mut map = blocklist_clone.lock().await;
                        let mut timestamps = timestamps_clone.lock().await;

                        if map.insert(src_ip, 1, 0).is_ok() {
                            timestamps.insert(src_ip, Instant::now());
                            let mut dash = dashboard_clone.lock().await;
                            dash.logs.push(format!(
                                "[AI-BLOCK] Blocked IP {} ({:.0} p/s) for {}s",
                                Ipv4Addr::from(src_ip),
                                packet_rate,
                                BLOCK_TTL.as_secs()
                            ));
                        }
                    }

                    let _ = metrics_map.remove(&src_ip);
                }
            }

            let mut dash = dashboard_clone.lock().await;
            dash.active_ips = current_active;
            dash.total_packets += total_p;
            dash.total_bytes += total_b;
        }
    });

    // -------------------------------------------------------------
    // TASK C: TUI Render Engine (Crossterm & Ratatui)
    // -------------------------------------------------------------
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        let state = dashboard_state.lock().await.clone();

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Length(3),  // Header stats
                        Constraint::Percentage(50), // Active traffic & blocklist table
                        Constraint::Percentage(40), // Logs panel
                    ]
                    .as_ref(),
                )
                .split(f.size());

            // Header Banner
            let header_text = format!(
                " Interface: {} | Mode: XDP | Total Packets: {} | Total Bytes: {} KB | (Press 'q' to exit)",
                iface, state.total_packets, state.total_bytes / 1024
            );
            let header = Paragraph::new(header_text)
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title(" AI Firewall Status "));
            f.render_widget(header, chunks[0]);

            // Middle Layout Split: Active IP Table vs Blocklist
            let mid_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
                .split(chunks[1]);

            // Active Traffic Table
            let rows: Vec<Row> = state
                .active_ips
                .iter()
                .map(|(ip, pkts, bytes, anomaly)| {
                    let style = if *anomaly {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Green)
                    };
                    Row::new(vec![
                        ip.clone(),
                        pkts.to_string(),
                        format!("{:.1} KB", *bytes as f64 / 1024.0),
                        if *anomaly { "ANOMALY" } else { "NORMAL" }.to_string(),
                    ])
                    .style(style)
                })
                .collect();

            let active_table = Table::new(
                rows,
                [
                    Constraint::Percentage(35),
                    Constraint::Percentage(20),
                    Constraint::Percentage(25),
                    Constraint::Percentage(20),
                ],
            )
            .header(
                Row::new(vec!["IP Address", "Pkts/s", "Data/s", "Status"])
                    .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL).title(" Live Monitored Traffic "));
            f.render_widget(active_table, mid_chunks[0]);

            // Blocklist Table
            let block_rows: Vec<Row> = state
                .blocked_ips
                .iter()
                .map(|(ip, remaining)| {
                    Row::new(vec![ip.clone(), format!("{}s", remaining)])
                        .style(Style::default().fg(Color::Red))
                })
                .collect();

            let block_table = Table::new(
                block_rows,
                [Constraint::Percentage(60), Constraint::Percentage(40)],
            )
            .header(
                Row::new(vec!["Blocked IP", "TTL Left"])
                    .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL).title(" Kernel Blocklist Map "));
            f.render_widget(block_table, mid_chunks[1]);

            // Logs Panel
            let log_items: Vec<ListItem> = state
                .logs
                .iter()
                .rev()
                .take(15)
                .map(|log| ListItem::new(log.as_str()))
                .collect();
            let logs_list = List::new(log_items)
                .block(Block::default().borders(Borders::ALL).title(" System & ML Events "));
            f.render_widget(logs_list, chunks[2]);
        })?;

        // Non-blocking exit key listener
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Char('Q') {
                    break;
                }
            }
        }
    }

    // Cleanup TUI terminal state upon quit
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    println!("[*] TUI Dashboard closed. Firewall detached cleanly.");
    Ok(())
}
