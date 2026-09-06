//---------------------------
// 1.3 || 3.1
//---------------------------

use anyhow::Context as _;
use aya::programs::{Xdp, XdpMode};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;

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
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // 3. Load the compiled eBPF bytecode embedded inside the binary
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ai-firewall"
    )))?;

    // 4. Initialize eBPF Logger (reads info! logs sent from kernel space)
    match EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
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
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    info!("AI Firewall attached to {iface}. Waiting for Ctrl-C...");

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
