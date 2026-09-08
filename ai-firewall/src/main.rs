//---------------------------
// 1.3 || 3.1 || 3.2 || 4.1 || 5.1
// Userspace eBPF Firewall Controller
//---------------------------

use ai_firewall_common::PacketEvent;
use anyhow::Context as _;
use aya::maps::{HashMap, RingBuf};
use aya::programs::{Xdp, XdpMode};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use std::collections::{HashMap as StdHashMap, HashSet};
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::Mutex as TokioMutex;
use ndarray::Array1;

const BLOCK_TTL: Duration = Duration::from_secs(60); // IPs stay blocked for 60 seconds
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5); // Sweeper runs every 5 seconds

//-------------
// Impl
//-------------

impl WindowMetrics {
    pub fn to_feature_vector(&self, ip: u32) -> FeatureVector {
        let total = self.packet_count as f64;
        if total == 0.0 {
            return FeatureVector {
                ip,
                packet_rate: 0.0,
                port_diversity: 0.0,
                tcp_ratio: 0.0,
                udp_ratio: 0.0,
                icmp_ratio: 0.0,
            };
        }

        FeatureVector {
            ip,
            packet_rate: total,
            port_diversity: self.unique_ports.len() as f64,
            tcp_ratio: (self.tcp_count as f64) / total,
            udp_ratio: (self.udp_count as f64) / total,
            icmp_ratio: (self.icmp_count as f64) / total,
        }
    }
}

impl FeatureVector {
    /// Converts features into a 1D Array for ML model evaluation
    pub fn to_array(&self) -> Array1<f64> {
        ndarray::array![
            self.packet_rate,
            self.port_diversity,
            self.tcp_ratio,
            self.udp_ratio,
            self.icmp_ratio
        ]
    }
}

#[derive(Debug, Parser)]
struct Opt {
    /// Interface to attach XDP to (e.g. lo, wlan0, eth0)
    #[clap(short, long, default_value = "wlan0")]
    iface: String,

    /// Force Generic SKB mode for XDP (required for lo, wlan0, etc.)
    #[clap(long)]
    skb: bool,

    /// Verbose mode: log every single packet (default logs first packet and count milestones)
    #[clap(short, long)]
    verbose: bool,

    /// Filter to only monitor traffic to a specific destination port (e.g. -p 120)
    #[clap(short = 'p', long)]
    port: Option<u16>,

    /// Auto-block threshold (number of packets before blocking an IP, default: 100)
    #[clap(short, long, default_value_t = 100)]
    threshold: u32,

    /// Include background mDNS (5353), SSDP (1900), and broadcast discovery noise in logs
    #[clap(long)]
    include_noise: bool,
}

#[derive(Debug, Default, Clone)]
pub struct WindowMetrics {
    pub packet_count: u32,
    pub unique_ports: HashSet<u16>,
    pub tcp_count: u32,
    pub udp_count: u32,
    pub icmp_count: u32,
    pub other_proto_count: u32,
}

#[derive(Debug, Clone)]
pub struct FeatureVector {
    pub ip: u32,
    pub packet_rate: f64,
    pub port_diversity: f64,
    pub tcp_ratio: f64,
    pub udp_ratio: f64,
    pub icmp_ratio: f64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    // 1. Initialize userspace logger with INFO as default level if not set
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("╔═════════════════════════════════════════════════════════════╗");
    println!("║                 AI FIREWALL CONTROLLER (XDP)                ║");
    println!("╚═════════════════════════════════════════════════════════════╝");
    info!("[*] Initializing AI Firewall...");

    // 2. Bump the memlock rlimit (needed for kernel memory allocation)
    info!("[*] Adjusting memory lock limit (RLIMIT_MEMLOCK)...");
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("[!] remove limit on locked memory failed, ret is: {ret}");
    }

    // 3. Load the compiled eBPF bytecode embedded inside the binary
    info!("[*] Loading compiled eBPF bytecode into kernel...");
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ai-firewall"
    )))?;
    info!("[+] Successfully loaded eBPF bytecode!");

    // 4. Initialize eBPF Logger (reads info! logs sent from kernel space)
    info!("[*] Initializing kernel eBPF logger bridge...");
    match EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("[!] failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
            info!("[+] eBPF logger bridge active.");
        }
    }

    // 5. Attach XDP program dynamically based on CLI input
    let Opt {
        iface,
        skb,
        verbose,
        port: filter_port,
        threshold,
        include_noise,
    } = opt;

    info!("[*] Attaching XDP program to network interface '{}'...", iface);
    let program: &mut Xdp = ebpf.program_mut("ai_firewall").unwrap().try_into()?;
    program.load()?;

    if skb {
        program
            .attach(&iface, XdpMode::Skb)
            .context(format!("[!] failed to attach XDP program to {iface} in SKB mode"))?;
        info!("[+] Attached XDP program to '{}' in Generic (SKB) mode.", iface);
    } else {
        match program.attach(&iface, XdpMode::default()) {
            Ok(_) => {
                info!("[+] Attached XDP program to '{}' in Native (Driver) mode.", iface);
            }
            Err(err) => {
                debug!("[*] Driver mode not supported on {} ({}), trying Generic (SKB) mode...", iface, err);
                program
                    .attach(&iface, XdpMode::Skb)
                    .context(format!("[!] failed to attach XDP program to {iface} in SKB mode"))?;
                info!("[+] Attached XDP program to '{}' in Generic (SKB) mode.", iface);
            }
        }
    }

    // 6. Access eBPF BLOCKLIST map
    let blocklist_map = ebpf
        .take_map("BLOCKLIST")
        .context("failed to find BLOCKLIST map")?;
    let blocklist: HashMap<_, u32, u32> = HashMap::try_from(blocklist_map)?;
    let blocklist = Arc::new(TokioMutex::new(blocklist));

    // Shared in-memory tracker for block timestamps: IP (u32 Host Byte Order) -> Instant
    let blocked_timestamps: Arc<TokioMutex<StdHashMap<u32, Instant>>> =
        Arc::new(TokioMutex::new(StdHashMap::new()));

    // -------------------------------------------------------------
    // TASK A: Auto-Unblock Cleanup Loop (TTL Sweeper)
    // -------------------------------------------------------------
    let blocklist_cleaner = Arc::clone(&blocklist);
    let timestamps_cleaner = Arc::clone(&blocked_timestamps);

    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;

            let now = Instant::now();
            let mut timestamps = timestamps_cleaner.lock().await;

            // Find all IPs that have passed the TTL threshold
            let expired_ips: Vec<u32> = timestamps
                .iter()
                .filter(|(_, added_at)| now.duration_since(**added_at) >= BLOCK_TTL)
                .map(|(&ip, _)| ip)
                .collect();

            if !expired_ips.is_empty() {
                let mut map = blocklist_cleaner.lock().await;

                // Remove expired IPs from eBPF map and internal tracker
                for ip in expired_ips {
                    if map.remove(&ip).is_ok() {
                        timestamps.remove(&ip);
                        info!(
                            "[*] [TTL-EXPIRED] Unblocked IP {} from eBPF BLOCKLIST.",
                            Ipv4Addr::from(ip)
                        );
                    }
                }
            }
        }
    });
    info!("[+] Auto-unblock TTL sweeper running (Block TTL: {}s, Interval: {}s)", BLOCK_TTL.as_secs(), CLEANUP_INTERVAL.as_secs());

    // -------------------------------------------------------------
    // TASK B: RingBuf Event Collector & Window Aggregator
    // -------------------------------------------------------------
    if let Some(events_map) = ebpf.take_map("EVENTS") {
        let ring_buf = RingBuf::try_from(events_map)?;
        let mut async_fd = tokio::io::unix::AsyncFd::new(ring_buf)?;

        // Channel to pass raw events from RingBuf ingestion loop to Feature Aggregator
        let (tx, mut rx) = tokio::sync::mpsc::channel::<PacketEvent>(10_000);

        // 1. RingBuf Ingestion Task (Low Overhead Engine)
        tokio::task::spawn(async move {
            loop {
                let mut guard = match async_fd.readable_mut().await {
                    Ok(g) => g,
                    Err(_) => break,
                };
                let ring_buf = guard.get_inner_mut();

                while let Some(item) = ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() < std::mem::size_of::<PacketEvent>() {
                        continue;
                    }
                    let event = unsafe { *(data.as_ptr() as *const PacketEvent) };
                    let _ = tx.try_send(event);
                }
                guard.clear_ready();
            }
        });

        // 2. 1-Second Sliding Window Feature Aggregator Task
        let blocklist_clone = Arc::clone(&blocklist);
        let timestamps_clone = Arc::clone(&blocked_timestamps);

        if let Some(target_p) = filter_port {
            info!("[*] Port filter active: only monitoring port {}", target_p);
        }
        if !include_noise {
            info!("[*] Filtering out mDNS (5353) and SSDP (1900) broadcast noise from log. (Use --include-noise to view all)");
        }

        tokio::task::spawn(async move {
            let mut window_data: StdHashMap<u32, WindowMetrics> = StdHashMap::new();
            let mut ticker = tokio::time::interval(Duration::from_secs(1));

            loop {
                tokio::select! {
                    // Collect incoming packet telemetry
                    Some(event) = rx.recv() => {
                        // Noise Port Filter
                        let is_noise_port = matches!(event.dst_port, 5353 | 1900 | 5355 | 137 | 138);
                        if is_noise_port && !include_noise {
                            continue;
                        }

                        // Target Port Filter
                        if let Some(target_p) = filter_port {
                            if event.dst_port != target_p {
                                continue;
                            }
                        }

                        let metrics = window_data.entry(event.src_ip).or_default();
                        metrics.packet_count += 1;
                        metrics.unique_ports.insert(event.dst_port);
                        match event.protocol {
                            1 => metrics.icmp_count += 1,
                            6 => metrics.tcp_count += 1,
                            17 => metrics.udp_count += 1,
                            _ => metrics.other_proto_count += 1,
                        }
                    }

                   // 1-Second Interval Trigger (Evaluate Feature Vectors via ML)
                   _ = ticker.tick() => {
                       if window_data.is_empty() {
                           continue;
                       }
                   
                       for (&src_ip, metrics) in window_data.iter() {
                           let fv = metrics.to_feature_vector(src_ip);
                           let ip = Ipv4Addr::from(src_ip);
                   
                           // Feature vector: [packet_rate, port_diversity, tcp_ratio, udp_ratio, icmp_ratio]
                           let feature_arr = fv.to_array();
                   
                           // ML Anomaly Scoring Heuristic:
                           // High packet rate OR high port diversity weighted against normalized features
                           let anomaly_score = (fv.packet_rate / threshold as f64) + (fv.port_diversity / 10.0);
                   
                           if verbose || fv.packet_rate > 5.0 {
                               info!(
                                   "[*] [ML-EVAL] IP: {:15} | Rate: {:4.0} p/s | Ports: {:2} | Score: {:.2}",
                                   ip, fv.packet_rate, fv.port_diversity, anomaly_score
                               );
                           }
                   
                           // Trigger kernel auto-block if ML score crosses threshold (> 1.0)
                           if anomaly_score >= 1.0 {
                               let mut map = blocklist_clone.lock().await;
                               let mut timestamps = timestamps_clone.lock().await;
                   
                               if map.insert(src_ip, 1, 0).is_ok() {
                                   timestamps.insert(src_ip, Instant::now());
                                   warn!(
                                       "[!] [AI-BLOCK] Anomaly detected on IP {}! ML Score: {:.2} (Rate: {:.0} p/s, Ports: {}). Blocked for {}s.",
                                       ip, anomaly_score, fv.packet_rate, fv.port_diversity, BLOCK_TTL.as_secs()
                                   );
                               }
                           }
                       }
                   
                       // Reset metrics for next interval
                       window_data.clear();
                   }
                }
            }
        });

        info!("[+] Feature Aggregator active (1-second sliding window).");
    }

    info!("[+] AI Firewall is ACTIVE and monitoring '{}'. Press Ctrl+C to stop.", iface);

    signal::ctrl_c().await?;
    info!("[*] Received shutdown signal. Detaching firewall and exiting...");

    Ok(())
}
