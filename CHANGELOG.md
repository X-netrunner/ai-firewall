# Changelog

## Unreleased

- `status` and the dashboard said NOT RESPONDING for normal users under sysmode lockdown: /proc is mounted hidepid, so the
  daemon's pid is invisible. With /proc hidden, a status file under 30 s old is the proof (`tui::daemon_alive`).
- `ai-firewall status | head` panicked on the closed pipe; commands now end quietly (the daemon is unchanged).
- Tested on the host: enforce on wlan0 with real eBPF, all postures live, bans from inside the honeypot's systemd sandbox
  (CAP_BPF is enough), every sysmode mode with `sysmode verify` passing.

- **Postures** (`posture.rs`): `ai-firewall posture [secure|relaxed|lockdown|stealth] [--lan CIDR]... [--json]` lays a
  system-wide security level over the config without editing it (`/etc/ai-firewall/posture.toml`; the daemon reloads
  within a tick). secure = the config as written; relaxed = detection half as sensitive; lockdown = every inbound port
  closed (also in profiles), ping dropped, detection twice as sensitive, bans 4x longer, always enforcing; stealth = ping
  dropped and the Halcyon honeypot ports open only to the given local networks. A broken posture file is ignored and
  reported. `status`, `status.json` (`posture`, `posture_error`), the dashboard header and the Security center show it.
  Halcyon's `sysmode` sets the posture on every mode switch.
- **Model:** "auto" now prefers **qwen3.5:4b** (fits a 6 GB GPU), then LUNA's model, then the small ones as before.
  Requests send `"think": false`; a `<think>` block a model streams anyway is held back and dropped.
- The assistant is told plainly that a stopped daemon blocks nothing (it used to blame the stopped firewall for blocked
  traffic).

- **Live tests** (`selftest.rs`): `ai-firewall test [health|ports|detector|traffic|services|all] [--json]`, `/test`
  in the Ask panel, or `ACTION: test <name>` from the model (read-only, so no y / n; the model then explains the
  results). Local only, with the limits enforced in code: no traffic to other hosts, loopback probes to at most 16
  open ports, simulated packets from RFC 5737 addresses through an in-memory detector, `traffic` sampled for 30 s at most.
- **Ask panel:** no instructions or examples in it any more; test results render inline (✓ / ✗ per test, then its
  figures); suggestions are numbered chips; the graph is hidden while the panel is open so the conversation has room.
- **Dashboard:** tiles show the label above the figure, a tidier header line, shorter titles.
- `ask --json`: the answer as JSON lines (`model`, `chunk`, `tests`, `done`, `error`) for the Halcyon Security center;
  a test the model asks for runs once and the model explains it.
- **Build fixes:** `Cargo.lock` listed `castaway 0.2.4` twice (cargo refused to load it); `src/bin/train_model.rs` used
  `linfa` / `ndarray`, which are not dependencies, so the package did not build (moved to `notes/`, nothing used its
  `model.json`); `AYA_BUILD_SKIP=1` builds the userspace side without nightly / bpf-linker.
- Tests: 42 (14 new).

## 0.2.1

- **Fix:** two rules limiting the same port now keep the lower rate (count per second). Before, `5/1s`
  could win over `6/60s` because only the count was compared first.
- **Fix:** ban notifications are throttled to one a minute; bans in between are grouped into it (a
  sustained attack used to mean one every 3 seconds).
- **Config errors are visible:** `status`, the doctor, `top` and the Firewall Center say when the config
  file is broken and the last config that worked is in force (plus one desktop notification).
- Blocklist drops have their own counter (`from blocklists`), separate from bans.
- `status` shows the network profile, feeds and rules; ports print without quotes.
- History only logs feed changes that came from a download.
- Tests for rule compilation, notification grouping and IPv6 bans (28 in all).

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
