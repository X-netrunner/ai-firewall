#!/usr/bin/env bash
# Builds ai-firewall, installs it as a systemd service and (with --replace-ufw) retires ufw.
#   ./packaging/install.sh [--replace-ufw] [--uninstall]
set -euo pipefail
cd "$(dirname "$0")/.."

replace_ufw=false
case "${1:-}" in
    --replace-ufw) replace_ufw=true ;;
    --uninstall)
        sudo /usr/local/bin/ai-firewall off 2>/dev/null || true
        sudo systemctl disable --now ai-firewall.service 2>/dev/null || true
        sudo rm -f /usr/local/bin/ai-firewall /etc/systemd/system/ai-firewall.service
        sudo rm -rf /sys/fs/bpf/ai-firewall
        sudo systemctl daemon-reload
        echo "ai-firewall removed (config kept in /etc/ai-firewall). Re-enable ufw with: sudo systemctl enable --now ufw"
        exit 0 ;;
    "") ;;
    *) echo "usage: $0 [--replace-ufw | --uninstall]"; exit 1 ;;
esac

command -v bpf-linker >/dev/null || { echo "needs bpf-linker: cargo install bpf-linker"; exit 1; }
cargo build --release --locked

sudo install -Dm755 target/release/ai-firewall /usr/local/bin/ai-firewall
sudo install -Dm644 packaging/ai-firewall.service /etc/systemd/system/ai-firewall.service
if [[ ! -f /etc/ai-firewall/config.toml ]]; then
    /usr/local/bin/ai-firewall default-config | sudo install -Dm644 /dev/stdin /etc/ai-firewall/config.toml
fi
sudo /usr/local/bin/ai-firewall check

for fw in ufw firewalld; do
    if systemctl is-enabled "$fw.service" &>/dev/null; then
        if $replace_ufw; then
            echo "disabling $fw"
            [[ $fw == ufw ]] && sudo ufw --force disable >/dev/null || true
            sudo systemctl disable --now "$fw.service"
        else
            echo "note: $fw is enabled; ai-firewall stops it when it starts (rerun with --replace-ufw to disable it for good)"
        fi
    fi
done

sudo systemctl daemon-reload
sudo systemctl enable ai-firewall.service
sudo systemctl restart ai-firewall.service
sleep 4
/usr/local/bin/ai-firewall status || { sudo journalctl -u ai-firewall -n 30 --no-pager; exit 1; }
