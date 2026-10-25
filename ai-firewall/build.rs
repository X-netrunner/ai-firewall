use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // AYA_BUILD_SKIP=1 (no nightly / bpf-linker): build the userspace side for checks and unit tests only.
    // The embedded object is empty, so the daemon refuses to start; every other command works.
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");
    if std::env::var("AYA_BUILD_SKIP").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) {
        let out = std::env::var("OUT_DIR").context("OUT_DIR")?;
        std::fs::write(std::path::Path::new(&out).join("ai-firewall"), [])?;
        println!(
            "cargo:warning=AYA_BUILD_SKIP set: eBPF object is a placeholder, the daemon will not run"
        );
        return Ok(());
    }
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "ai-firewall-ebpf")
        .ok_or_else(|| anyhow!("[!] ai-firewall-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("[!] no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
