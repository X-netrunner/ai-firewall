//---------------------------
// 1.3 || 3.1 || 3.2 || 4.1 || 5.1
// Userspace eBPF Firewall Controller with Interactive TUI & File Exporter
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
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as TokioMutex;

const BLOCK_TTL: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const LOG_FILE_PATH: &str = "alerts.json";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AlertLog {
    pub timestamp: u64,
    pub event_type: String,
    pub ip: String,
    pub packet_rate: Option<f64>,
    pub bytes_rate: Option<f64>,
}

fn log_alert_to_file(alert: AlertLog) {
    if let Ok(json_str) = serde_json::to_string(&alert) {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_FILE_PATH)
        {
            let _ = writeln!(file, "{}", json_str);
            let _ = file.flush();
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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

#[derive(PartialEq)]
enum InputMode {
    Normal,
    ManualBlock,
    ManualUnblock,
}

#[derive(Default, Clone)]
struct DashboardState {
    pub active_ips: Vec<(String, u64, u64, bool)>, // (IP, Packets, Bytes, Anomaly)
    pub total_packets: u64,
    pub total_bytes: u64,
    pub blocked_ips: Vec<(String, u64)>,           // (IP, TTL remaining seconds)
    pub logs: Vec<String>,
    pub paused: bool,
}

#[tokio::main]
async fn main() {
    if let Err(e) = firewall_main().await {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
        let _ = stdout.flush();
        eprintln!("[!] AI Firewall failed: {e:?}");
        eprintln!("    Hint: run with `-i <iface>` for the right interface (e.g. `-i lo`, `-i eth0`).");
        std::process::exit(1);
    }
}

async fn firewall_main() -> Result<(), Box<dyn std::error::Error>> {
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
        eprintln!("[!] Warning: Failed to initialize eBPF logger: {}", e);
    }

    // 4. Attach XDP program
    let Opt { iface, skb, threshold } = opt;
    let program: &mut Xdp = ebpf
        .program_mut("ai_firewall")
        .context("[!] eBPF program 'ai_firewall' not found in image")?
        .try_into()?;
    program.load()?;

    let mut attached_mode = "XDP (native)";
    if skb {
        program.attach(&iface, XdpMode::Skb)?;
        attached_mode = "XDP (generic/SKB)";
    } else if program.attach(&iface, XdpMode::default()).is_err() {
        eprintln!("[!] Native XDP not available on '{iface}', falling back to generic (SKB) XDP mode.");
        program.attach(&iface, XdpMode::Skb)?;
        attached_mode = "XDP (generic/SKB)";
    }

    // 5. Shared state between kernel sweeper and TUI render engine
    let blocklist_map = ebpf.take_map("BLOCKLIST").context("[!] failed to find BLOCKLIST map")?;
    let blocklist: HashMap<_, u32, u32> = HashMap::try_from(blocklist_map)?;
    let blocklist = Arc::new(TokioMutex::new(blocklist));

    let blocked_timestamps: Arc<TokioMutex<StdHashMap<u32, Instant>>> =
        Arc::new(TokioMutex::new(StdHashMap::new()));

    let dashboard_state = Arc::new(TokioMutex::new(DashboardState::default()));

    dashboard_state.lock().await.logs.push(format!(
        "[*] AI Firewall attached to '{}' in {} mode. Waiting for traffic...",
        iface, attached_mode
    ));

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

            // Phase 1: snapshot expired IPs (lock only what we need)
            let expired_ips: Vec<u32> = {
                let timestamps = timestamps_cleaner.lock().await;
                timestamps
                    .iter()
                    .filter(|(_, added_at)| now.duration_since(**added_at) >= BLOCK_TTL)
                    .map(|(&ip, _)| ip)
                    .collect()
            };

            if !expired_ips.is_empty() {
                // Phase 2: consistent lock order (blocklist -> timestamps -> dashboard)
                let mut map = blocklist_cleaner.lock().await;
                let mut timestamps = timestamps_cleaner.lock().await;
                let mut dash = dashboard_cleaner.lock().await;

                for ip in expired_ips {
                    if map.remove(&ip).is_ok() {
                        timestamps.remove(&ip);
                        let ip_str = Ipv4Addr::from(ip).to_string();
                        dash.logs.push(format!("[*] [TTL-EXPIRED] Unblocked IP {}", ip_str));

                        log_alert_to_file(AlertLog {
                            timestamp: current_timestamp(),
                            event_type: "TTL-EXPIRED".to_string(),
                            ip: ip_str,
                            packet_rate: None,
                            bytes_rate: None,
                        });
                    }
                }
            }

            // Phase 3: refresh TTL display (timestamps -> dashboard, no blocklist)
            let remaining_ips: Vec<(String, u64)> = {
                let timestamps = timestamps_cleaner.lock().await;
                timestamps
                    .iter()
                    .map(|(&ip, &added_at)| {
                        let elapsed = now.duration_since(added_at).as_secs();
                        let remaining = BLOCK_TTL.as_secs().saturating_sub(elapsed);
                        (Ipv4Addr::from(ip).to_string(), remaining)
                    })
                    .collect()
            };

            let mut dash = dashboard_cleaner.lock().await;
            dash.blocked_ips = remaining_ips;

            if dash.logs.len() > 100 {
                dash.logs.drain(0..50);
            }
        }
    });

    // -------------------------------------------------------------
    // TASK B: Kernel Map Sweeper and ML Evaluator Loop
    // -------------------------------------------------------------
    let metrics_map = ebpf.take_map("METRICS_MAP").context("[!] failed to find METRICS_MAP")?;
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
                    let bytes_rate = metrics.bytes_count as f64;
                    let total = packet_rate.max(1.0);

                    total_p += metrics.packet_count;
                    total_b += metrics.bytes_count;

                    let feature_arr = [
                        packet_rate,
                        bytes_rate / total,
                        (metrics.tcp_count as f64) / total,
                        (metrics.udp_count as f64) / total,
                        (metrics.icmp_count as f64) / total,
                    ];

                    let is_anomaly = if let Some(ref model) = *model_clone {
                        model.predict_anomaly(&feature_arr)
                    } else {
                        packet_rate > threshold as f64
                    };

                    let ip_str = Ipv4Addr::from(src_ip).to_string();

                    current_active.push((
                        ip_str.clone(),
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
                            if !dash.paused {
                                dash.logs.push(format!(
                                    "[*] [AI-BLOCK] Blocked IP {} ({:.0} p/s) for {}s",
                                    ip_str,
                                    packet_rate,
                                    BLOCK_TTL.as_secs()
                                ));
                            }

                            log_alert_to_file(AlertLog {
                                timestamp: current_timestamp(),
                                event_type: "AI-BLOCK".to_string(),
                                ip: ip_str,
                                packet_rate: Some(packet_rate),
                                bytes_rate: Some(bytes_rate),
                            });
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
    // TASK C: Interactive TUI Render Engine (Crossterm & Ratatui)
    // -------------------------------------------------------------
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut input_mode = InputMode::Normal;
    let mut input_buffer = String::new();

    loop {
        let state = dashboard_state.lock().await.clone();

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Length(3),
                        Constraint::Length(3),
                        Constraint::Percentage(45),
                        Constraint::Percentage(35),
                    ]
                    .as_ref(),
                )
                .split(f.size());

            let header_text = format!(
                " Interface: {} | Mode: XDP | Total Packets: {} | Total Bytes: {} KB | Feed: {}",
                iface,
                state.total_packets,
                state.total_bytes / 1024,
                if state.paused { "PAUSED" } else { "LIVE" }
            );
            let header = Paragraph::new(header_text)
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title(" AI Firewall Status "));
            f.render_widget(header, chunks[0]);

            let prompt_widget = match input_mode {
                InputMode::Normal => Paragraph::new(
                    " [B] Manual Block IP  |  [U] Manual Unblock IP  |  [P] Pause/Resume Feed  |  [Q] Quit"
                )
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title(" Controls ")),

                InputMode::ManualBlock => Paragraph::new(format!("Enter IP to BLOCK: {}", input_buffer))
                    .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                    .block(Block::default().borders(Borders::ALL).title(" Action: Manual Block (Press Enter to Apply, Esc to Cancel) ")),

                InputMode::ManualUnblock => Paragraph::new(format!("Enter IP to UNBLOCK: {}", input_buffer))
                    .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                    .block(Block::default().borders(Borders::ALL).title(" Action: Manual Unblock (Press Enter to Apply, Esc to Cancel) ")),
            };
            f.render_widget(prompt_widget, chunks[1]);

            let mid_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
                .split(chunks[2]);

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

            let log_items: Vec<ListItem> = state
                .logs
                .iter()
                .rev()
                .take(15)
                .map(|log| ListItem::new(log.as_str()))
                .collect();
            let logs_list = List::new(log_items)
                .block(Block::default().borders(Borders::ALL).title(" System & ML Events "));
            f.render_widget(logs_list, chunks[3]);
        })?;

        // -------------------------------------------------------------
        // TASK D: Key Event Handler
        // -------------------------------------------------------------
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => break,
                        KeyCode::Char('b') | KeyCode::Char('B') => {
                            input_mode = InputMode::ManualBlock;
                            input_buffer.clear();
                        }
                        KeyCode::Char('u') | KeyCode::Char('U') => {
                            input_mode = InputMode::ManualUnblock;
                            input_buffer.clear();
                        }
                        KeyCode::Char('p') | KeyCode::Char('P') => {
                            let mut dash = dashboard_state.lock().await;
                            dash.paused = !dash.paused;
                        }
                        _ => {}
                    },

                    InputMode::ManualBlock => match key.code {
                        KeyCode::Enter => {
                            if let Ok(ip) = Ipv4Addr::from_str(&input_buffer) {
                                let ip_u32 = u32::from(ip);
                                let mut map = blocklist.lock().await;
                                let mut timestamps = blocked_timestamps.lock().await;

                                if map.insert(ip_u32, 1, 0).is_ok() {
                                    timestamps.insert(ip_u32, Instant::now());
                                    let mut dash = dashboard_state.lock().await;
                                    dash.logs.push(format!("[*] [MANUAL-BLOCK] Manually blocked IP {}", ip));

                                    log_alert_to_file(AlertLog {
                                        timestamp: current_timestamp(),
                                        event_type: "MANUAL-BLOCK".to_string(),
                                        ip: ip.to_string(),
                                        packet_rate: None,
                                        bytes_rate: None,
                                    });
                                }
                            }
                            input_mode = InputMode::Normal;
                        }
                        KeyCode::Esc => {
                            input_mode = InputMode::Normal;
                        }
                        KeyCode::Char(c) => {
                            input_buffer.push(c);
                        }
                        KeyCode::Backspace => {
                            input_buffer.pop();
                        }
                        _ => {}
                    },

                    InputMode::ManualUnblock => match key.code {
                        KeyCode::Enter => {
                            if let Ok(ip) = Ipv4Addr::from_str(&input_buffer) {
                                let ip_u32 = u32::from(ip);
                                let mut map = blocklist.lock().await;
                                let mut timestamps = blocked_timestamps.lock().await;

                                if map.remove(&ip_u32).is_ok() {
                                    timestamps.remove(&ip_u32);
                                    let mut dash = dashboard_state.lock().await;
                                    dash.logs.push(format!("[*] [MANUAL-UNBLOCK] Manually unblocked IP {}", ip));

                                    log_alert_to_file(AlertLog {
                                        timestamp: current_timestamp(),
                                        event_type: "MANUAL-UNBLOCK".to_string(),
                                        ip: ip.to_string(),
                                        packet_rate: None,
                                        bytes_rate: None,
                                    });
                                }
                            }
                            input_mode = InputMode::Normal;
                        }
                        KeyCode::Esc => {
                            input_mode = InputMode::Normal;
                        }
                        KeyCode::Char(c) => {
                            input_buffer.push(c);
                        }
                        KeyCode::Backspace => {
                            input_buffer.pop();
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    println!("[*] TUI Dashboard closed. Firewall detached cleanly.");
    Ok(())
}
