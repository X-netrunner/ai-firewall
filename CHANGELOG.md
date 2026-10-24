# Changelog

## 0.2.0

- **Rules:** port ranges (`"1714-1764"`), ports open only to some networks (`[[rule]] from = ...`), and a
  per-source limit on new TCP connections (`limit = "6/30s"`), all checked in the kernel.
- **Blocklist feeds:** Spamhaus DROP by default, FireHOL level 1 or your own lists optional; refreshed daily
  with curl, cached for offline boots, private and LAN ranges always removed. `ai-firewall feeds [--refresh]`.
- **Network profiles:** different open ports per network, picked by the NetworkManager connection name.
- **Notifications and history:** bans pop up on the desktop (grouped); `ai-firewall history`.
- **Assistant:** `ai-firewall ask`, and a panel in `ai-firewall top` (`a`, or `top --ask`), using a local
  model (LUNA's if set up, else Ollama); it can only suggest actions from a fixed list.
- **No gaps:** the filter is attached through pinned bpf links, so restarts and upgrades never stop it.
- **UDP reply tracking:** an egress program records your flows; other UDP to high ports is dropped.
- **IPv6:** sources are scored and banned by /64.
- **Doctor:** `ai-firewall doctor [--fix|--json]`, `ai-firewall fix <id>`, incl. VM networking behind Docker.
- **Safer start:** a broken config at boot falls back to the last config that worked.
- **Service hardening:** devices, clock, kernel logs and modules, namespaces and exotic sockets are off-limits (`systemd-analyze security`: 4.4, OK).
- LAN discovery broadcasts no longer lead to bans; every ban records its protocol and ports.

## 0.1.0

- XDP filter with an IPv4 blocklist, a packet event ring buffer and a threshold auto-ban.
