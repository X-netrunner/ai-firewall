# Docking ai-firewall into Halcyon

Everything Halcyon needs is a command or a file with a stable format. The island never
needs root: it reads files, and anything that changes state runs in a terminal through
`sudo ai-firewall ...` (or `scripts/apps.sh term-exec`).

## Files

| Path | Who writes it | Readable by | What |
|---|---|---|---|
| `/etc/ai-firewall/config.toml` | you, `ai-firewall open/close` | everyone | the config; the daemon reloads it within 3 s of a change |
| `/run/ai-firewall/status.json` | daemon, every 3 s (write + rename) | everyone | live status, schema below; missing = not running |
| `/var/lib/ai-firewall/state.json` | daemon | root | bans and strikes saved across reboots |
| `/sys/fs/bpf/ai-firewall/` | daemon | root | pinned maps and links (the filter itself) |

## status.json

```json
{
  "pid": 1234, "mode": "enforce", "interface": "wlp3s0", "xdp_mode": "generic",
  "udp_strict": true, "started_unix": 0, "updated_unix": 0, "attaches": 1,
  "passed": 0, "dropped_blocklist": 0, "dropped_policy": 0, "events_lost": 0,
  "tracked_sources": 0, "allow_tcp": [22], "allow_udp": [68, 546, 5353],
  "bans": [{ "ip": "203.0.113.7", "remaining_secs": 0, "reason": "...", "source": "auto|manual|config", "strikes": 1 }],
  "recent": [{ "ip": "...", "reason": "port scan", "ports": "tcp 21 22 +9", "score": 1.2,
               "secs": 120, "strikes": 1, "at_unix": 0, "enforced": true }]
}
```
`remaining_secs: 0` means forever. The daemon counts as alive if the file exists, `pid` is running,
and `updated_unix` is under 30 s old (this is what `ai-firewall status` and the island page check).

## Commands

| Command | Root | Use |
|---|---|---|
| `ai-firewall status` | no | human summary |
| `ai-firewall doctor --json` | no (more with root) | `{findings: [{area, severity, title, detail, fix}], fixes: [{id, summary}]}` |
| `ai-firewall fix <id>` | yes | apply one doctor fix; ids are the fixed list in `doctor.rs` |
| `ai-firewall ban <ip> --minutes N` / `unban <ip>` | yes | IPv4 address or IPv6 (bans its /64); 0 minutes = forever |
| `ai-firewall open tcp 22` / `close udp 5353` | yes | edits the config, keeps comments |
| `ai-firewall top [--ask]` | for actions | terminal dashboard, optionally opened on the assistant |
| `ai-firewall ask "..."` | no (more with root) | one-shot question to the local model |
| `ai-firewall off` | yes | stop filtering completely |

## The Security center

`quickshell/island/SecurityCenter.qml`, wired into `shell.qml` (Halcyon, 2026-10-25). It replaces the planned
`FwPage.qml` (never committed) and also hosts the Synapse antivirus:
- open it with `>security`, `>firewall`, `>antivirus`, or `qs -p ~/.config/Halcyon/quickshell/island ipc call island security`
  (`securitypage firewall|antivirus|ask` opens one page)
- Firewall page: reads `status.json` every 2 s, only while open (tiles, bans with unban, detections); Test, Doctor and
  Dashboard buttons; anything that needs root opens in the pop-out console
- Ask page: `ai-firewall ask --json`, with test chips (`/test ...`) and the model's suggestions as buttons
- greyed out, page by page, when `/usr/local/bin/ai-firewall` (or `synapsectl`) is missing; colours from `Pal.qml`

Also wired: `install.sh --firewall ai|ufw|none` (asked on first install and with `--choose`, saved as FIREWALL; builds from
`AIFW_SRC` or `AIFW_REPO`/`AIFW_REV`, keeps ufw and any installed copy if it cannot build, removes ai-firewall when you
switch away), `update.sh` passes it on, `startup-conf.sh` reports `has.firewall`, Settings > Backup & safety > Firewall,
and the safety check checks ai-firewall instead of ufw when it is installed (it no longer re-enables ufw beside it).

Not wired yet: a keybind.

sysmode and recon-deceiver now work with both firewalls (2026-10-25): every mode switch sets ufw as before and, when
ai-firewall is installed, `ai-firewall posture <mode>` (stealth passes the machine's subnets with `--lan`). The honeypot bans
with `ai-firewall ban <ip> --minutes 10` while ai-firewall runs, else with ufw. `sysmode status`, `verify`, `doctor` and
`logs` show both.

## Where Halcyon uses ufw today

| Place | What it does with ufw | ai-firewall equivalent |
|---|---|---|
| `install.sh` safety check deps | installed ufw | done: the firewall choice installs what's needed |
| `install.sh` sysmode deps | installs ufw | still does (sysmode drives ufw, see below) |
| `scripts/halcyon-doctor.sh:221` | lists ufw as a sysmode dependency | unchanged (sysmode) |
| `src/safety-check/src/main.rs` | `ufw status`, enables it if inactive | done: checks ai-firewall first, logs `ai-firewall status: Status: ...` |
| `scripts/halcyon-ai.py` (safety review) | parses `ufw status:` log lines | done: also parses the ai-firewall line |
| `tests/test_safety_review.py` | fixtures with ufw lines | done: ai-firewall cases added |
| `src/recon-deceiver` | adds and removes `recon-deceiver-ban` ufw rules | done: `ai-firewall ban <ip> --minutes 10` while ai-firewall runs (bans expire in the kernel), ufw otherwise |
| `sysmode/sysmode` | per-mode ufw defaults, logging, forward policy, allow rules on interfaces | done: ufw as before plus `ai-firewall posture <mode>` (posture.rs) |

How the sysmode modes map (ai-firewall only filters its one uplink interface, so tun+/wg+ and a decoy hotspot interface
are not affected by it; ufw's logging levels and forward policy have no ai-firewall counterpart and stay ufw-only):

| sysmode | ufw | ai-firewall posture |
|---|---|---|
| secure | logging medium, forward DROP | `secure`: the config as written |
| relaxed | logging low, forward ACCEPT | `relaxed`: detection half as sensitive |
| lockdown | default deny, deny 22, logging high | `lockdown`: nothing inbound, no ping, stricter detection, 4x bans |
| stealth | allow tun+/wg+, decoys on the hotspot, subnet isolation | `stealth`: no ping, honeypot ports open to the local subnets only |
