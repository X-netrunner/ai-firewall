//---------------------------
// 1.3 || 3.1 || 3.2
//---------------------------

use ai_firewall_common::PacketEvent;
use anyhow::Context as _;
use aya::maps::{HashMap, RingBuf};
use aya::programs::{Xdp, XdpMode};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use std::collections::HashMap as StdHashMap;
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex as TokioMutex;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlan0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    // 1. Initialize userspace logger
    env_logger::init();

    // 2. Bump the memlock rlimit (needed for older kernel memory accounting)
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("[!] remove limit on locked memory failed, ret is: {ret}");
    }

    // 3. Load the compiled eBPF bytecode embedded inside the binary
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ai-firewall"
    )))?;

    // 4. Initialize eBPF Logger (reads info! logs sent from kernel space)
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
        }
    }

    // 5. Attach XDP program to network interface
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("ai_firewall").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&iface, XdpMode::default())
        .context("[!] failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    info!("[*] AI Firewall attached to {iface}. Waiting for Ctrl-C...");

    // 6. Populating the ebpf blocklist map from userspace using `take_map` (owns the map)
    let blocklist_map = ebpf
        .take_map("BLOCKLIST")
        .context("failed to find BLOCKLIST map")?;
    let blocklist: HashMap<_, u32, u32> = HashMap::try_from(blocklist_map)?;
    let blocklist = Arc::new(TokioMutex::new(blocklist));

    // Blocking 8.8.8.8
    let block_ip: Ipv4Addr = "8.8.8.8".parse()?;
    let ip_u32 = u32::from(block_ip); // Converts IP to native u32 format

    // Write IP into the eBPF map shared with kernel space ( key : IP , value : 1 flag)
    blocklist.lock().await.insert(ip_u32, 1, 0)?;
    info!("[*] Successfully added {} (u32: {}) to eBPF BLOCKLIST map!", block_ip, ip_u32);

    // 7. Consume binary RingBuf packet events using `take_map`
    if let Some(events_map) = ebpf.take_map("EVENTS") {
        let ring_buf = RingBuf::try_from(events_map)?;
        let mut async_fd = tokio::io::unix::AsyncFd::new(ring_buf)?;
        let blocklist_clone = Arc::clone(&blocklist);

        tokio::task::spawn(async move {
            let mut packet_counts: StdHashMap<u32, u32> = StdHashMap::new();

            loop {
                let mut guard = async_fd.readable_mut().await.unwrap();
                let ring_buf = guard.get_inner_mut();

                while let Some(item) = ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() < std::mem::size_of::<PacketEvent>() {
                        continue;
                    }

                    let event = unsafe { &*(data.as_ptr() as *const PacketEvent) };
                    let ip = Ipv4Addr::from(event.src_ip);

                    let count = packet_counts.entry(event.src_ip).or_insert(0);
                    *count += 1;

                    info!(
                        "[*] [EVENT] IP: {:15} | Port: {:5} | Proto: {:3} | Total: {}",
                        ip, event.dst_port, event.protocol, count
                    );

                    if *count > 100 {
                        let mut map = blocklist_clone.lock().await;
                        if map.insert(event.src_ip, 1, 0).is_ok() {
                            warn!("[!] [AUTO-BLOCK] IP {} exceeded packet threshold! Added to kernel BLOCKLIST.", ip);
                        }
                    }
                }

                guard.clear_ready();
            }
        });
    }

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
