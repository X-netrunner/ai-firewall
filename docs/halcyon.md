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

## The island page

`quickshell/island/FwPage.qml`, wired into `shell.qml` as page `"fw"`:
- open / close it with `qs -p ~/.config/Halcyon/quickshell/island ipc call island firewall`
- it reads `status.json` every 2 s, only while open
- buttons open a terminal: Dashboard (`sudo ai-firewall top`), Ask (`top --ask`), Doctor (`doctor --fix`), unban per row
- colours come from `Pal.qml`, so it follows the wallpaper like every other page

Also wired (Halcyon branch work, 2026-10-24):
- `install.sh --firewall ai|ufw|none` (asked on first install and with `--choose`, saved as FIREWALL); ai builds from
  `AIFW_SRC` or `AIFW_REPO`/`AIFW_REV`, falls back to ufw if it can't build, keeps an installed copy if an update fails
- Settings > Backup > Firewall (greyed out without `/usr/local/bin/ai-firewall`, via `startup-conf.sh` `has.firewall`)
- launcher commands `>firewall` (the page) and `>firewall dashboard`, listed only when installed
- a tour step (`only: "firewall"`), and `>ask` sends network questions to `ai-firewall ask`
- the safety check checks ai-firewall instead of ufw when it is installed (it no longer re-enables ufw over it)

Not wired yet: a keybind.

## Where Halcyon uses ufw today

| Place | What it does with ufw | ai-firewall equivalent |
|---|---|---|
| `install.sh` safety check deps | installed ufw | done: the firewall choice installs what's needed |
| `install.sh` sysmode deps | installs ufw | still does (sysmode drives ufw, see below) |
| `scripts/halcyon-doctor.sh:221` | lists ufw as a sysmode dependency | unchanged (sysmode) |
| `src/safety-check/src/main.rs` | `ufw status`, enables it if inactive | done: checks ai-firewall first, logs `ai-firewall status: Status: ...` |
| `scripts/halcyon-ai.py` (safety review) | parses `ufw status:` log lines | done: also parses the ai-firewall line |
| `tests/test_safety_review.py` | fixtures with ufw lines | done: ai-firewall cases added |
| `src/recon-deceiver` | adds and removes `recon-deceiver-ban` ufw rules | `ai-firewall ban <ip> --minutes 10` (bans expire in the kernel by themselves, so the cleanup timer and crash leftovers go away) |
| `sysmode/sysmode` | per-mode ufw defaults, logging, forward policy, allow rules on interfaces | needs design: per-interface rules and logging levels don't exist in ai-firewall yet |

sysmode is the only part without a direct mapping: its modes set default policies, forward
policy, log levels and allow rules on specific interfaces. Decide per mode what it should become
(probably config profiles that sysmode swaps, plus `systemctl reload ai-firewall`).
