//---------------------------
// 8.1 Pinned attachments: filtering never stops while the daemon restarts
//---------------------------
//
// Both programs are attached through bpf links pinned in /sys/fs/bpf/ai-firewall.
// A restarted (or upgraded) daemon atomically swaps its freshly loaded programs into
// the existing links, so there is no moment without a filter. The daemon keeps no
// link fds of its own: removing the pin files is what detaches.

use crate::state::PIN_DIR;
use anyhow::Context as _;
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::tc::SchedClassifierLink;
use aya::programs::xdp::XdpLink;
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpMode};
use log::debug;
use std::path::PathBuf;

fn pin_path(kind: &str, iface: &str) -> PathBuf {
    PathBuf::from(PIN_DIR).join(format!("link-{kind}-{iface}"))
}

/// Sidecar holding "ifindex mode": a pin made before the interface was recreated
/// points at a dead link and must not be reused
fn meta_path(kind: &str, iface: &str) -> PathBuf {
    PathBuf::from(PIN_DIR).join(format!("link-{kind}-{iface}.meta"))
}

fn read_meta(kind: &str, iface: &str) -> Option<(u32, String)> {
    let text = std::fs::read_to_string(meta_path(kind, iface)).ok()?;
    let (idx, mode) = text.trim().split_once(' ')?;
    Some((idx.parse().ok()?, mode.to_string()))
}

fn write_meta(kind: &str, iface: &str, ifindex: u32, mode: &str) {
    let _ = std::fs::write(meta_path(kind, iface), format!("{ifindex} {mode}\n"));
}

pub fn unpin(kind: &str, iface: &str) {
    let _ = std::fs::remove_file(pin_path(kind, iface));
    let _ = std::fs::remove_file(meta_path(kind, iface));
}

/// Every interface that currently has a pinned XDP link
pub fn pinned_ifaces() -> Vec<String> {
    std::fs::read_dir(PIN_DIR)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|n| n.strip_prefix("link-xdp-").filter(|n| !n.ends_with(".meta")).map(String::from))
        .collect()
}

/// Removes every pinned link: the firewall stops filtering
pub fn unpin_all() -> usize {
    let ifaces = pinned_ifaces();
    for iface in &ifaces {
        unpin("xdp", iface);
        unpin("tc", iface);
    }
    ifaces.len()
}

/// Returns (mode, reused)
pub fn attach_xdp(program: &mut Xdp, iface: &str, ifindex: u32) -> anyhow::Result<(String, bool)> {
    let pin = pin_path("xdp", iface);
    if pin.exists() {
        match read_meta("xdp", iface) {
            Some((idx, mode)) if idx == ifindex => {
                let swapped = PinnedLink::from_pin(&pin)
                    .map_err(anyhow::Error::from)
                    .and_then(|p| Ok(XdpLink::try_from(FdLink::from(p))?))
                    .and_then(|link| Ok(program.attach_to_link(link)?));
                match swapped {
                    Ok(id) => {
                        drop(program.take_link(id)?);
                        return Ok((mode, true));
                    }
                    Err(e) => debug!("pinned XDP link on {iface} unusable: {e:#}"),
                }
            }
            _ => {}
        }
        unpin("xdp", iface);
    }

    let (id, mode) = match program.attach(iface, XdpMode::Driver) {
        Ok(id) => (id, "native"),
        Err(e) => {
            // Most wifi drivers have no native XDP; generic mode works everywhere
            debug!("native XDP on {iface} failed ({e}), using generic");
            (program.attach(iface, XdpMode::Skb).with_context(|| format!("attaching XDP to {iface}"))?, "generic")
        }
    };
    let link = program.take_link(id)?;
    let fd = FdLink::try_from(link).context("kernel attached XDP without a bpf link, so it can't be pinned")?;
    drop(fd.pin(&pin).with_context(|| format!("pinning {}", pin.display()))?);
    write_meta("xdp", iface, ifindex, mode);
    Ok((mode.to_string(), false))
}

pub fn attach_tc(program: &mut SchedClassifier, iface: &str, ifindex: u32) -> anyhow::Result<()> {
    let pin = pin_path("tc", iface);
    if pin.exists() {
        if read_meta("tc", iface).is_some_and(|(idx, _)| idx == ifindex) {
            let swapped = PinnedLink::from_pin(&pin)
                .map_err(anyhow::Error::from)
                .and_then(|p| Ok(SchedClassifierLink::try_from(FdLink::from(p))?))
                .and_then(|link| Ok(program.attach_to_link(link)?));
            match swapped {
                Ok(id) => {
                    drop(program.take_link(id)?);
                    return Ok(());
                }
                Err(e) => debug!("pinned TC link on {iface} unusable: {e:#}"),
            }
        }
        unpin("tc", iface);
    }
    let id = program.attach(iface, TcAttachType::Egress).with_context(|| format!("attaching egress program to {iface}"))?;
    let link = program.take_link(id)?;
    let fd = FdLink::try_from(link).context("kernel attached TC without a bpf link (needs Linux 6.6+)")?;
    drop(fd.pin(&pin).with_context(|| format!("pinning {}", pin.display()))?);
    write_meta("tc", iface, ifindex, "tcx");
    Ok(())
}
