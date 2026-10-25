# ai-firewall

A lightweight, self-healing firewall for a Linux desktop, built on eBPF/XDP. It is meant
to replace ufw: inbound traffic is denied by default, outbound is always allowed, and
sources that scan or flood you get banned by themselves.

## How it works

- **In the kernel (XDP)**, every inbound packet is checked before the network stack sees it:
  - banned sources are dropped
  - a new TCP connection (SYN) is only let in on an open port
  - UDP is let in on an open port, or as a reply to a flow you started: a small egress
    program records your outgoing UDP (after NAT, so VMs and containers are covered),
    much like ufw's connection tracking. Set `udp_strict = false` to fall back to letting
    in anything sent to your high ports
  - null, Xmas and FIN stealth-scan packets are dropped
  - ICMP, IPv6 neighbour discovery and fragments pass (pings too, unless `allow_ping = false`)

  Only packets of interest (connection attempts, unsolicited UDP, drops) are sent up to
  the daemon, so normal traffic costs userspace nothing.
- **Smart bans**: every source gets a threat score over a 10 s window, built from its
  connection rate, the number of distinct ports it probes, its unsolicited UDP, its policy
  drops and any stealth-scan packets. When the score reaches 1.0 the source is banned for
  2 min. A repeat offender's ban doubles each time, up to 24 h, and the strikes are
  forgotten after 6 quiet hours. Your router, your DNS servers, your own addresses and
  anything in `trusted` are never auto-banned.
- **Self-healing**:
  - the firewall follows the default route, so it moves with you between wifi and
    ethernet, and it re-attaches after a driver reload or after an interface vanishes
    and comes back
  - the filter is attached through pinned bpf links, so a restarted or upgraded daemon
    swaps its programs in atomically: filtering never stops. If the daemon stays down,
    the last rules keep applying (`sudo ai-firewall off` is what turns the firewall off)
  - bans and UDP flows live in pinned BPF maps, so they survive a daemon restart; bans
    are also saved to `/var/lib/ai-firewall`, so they survive a reboot
  - the kernel ignores an expired ban even while the daemon is down
  - systemd restarts the daemon if it ever exits
  - a broken config edit is rejected and the last good config stays in force

## Rules, feeds, profiles

All in `/etc/ai-firewall/config.toml` (the default config explains each one):
- **Port ranges:** `allow_tcp = [22, "1714-1764"]`.
- **Narrower rules:** a port open only to some addresses, and / or a limit on new connections per source:
  ```toml
  [[rule]]
  proto = "tcp"
  port = 22
  from = "192.168.1.0/24"
  limit = "6/30s"
  ```
  A source that goes over the limit has its new connections dropped, and the drops count towards a ban.
- **Blocklist feeds:** `[feeds] lists = ["spamhaus-drop", "firehol-level1"]`, plus your own `urls`. The
  daemon downloads them with curl, caches them in `/var/lib/ai-firewall/feeds` and refreshes them every
  `refresh_hours`. Private and LAN ranges are always taken out. `sudo ai-firewall feeds --refresh` downloads them now.
- **Network profiles:** `[profiles.home] networks = ["MyHomeWifi"]` with its own `allow_tcp` / `allow_udp` /
  `allow_ping` / rules, picked by the active NetworkManager connection name.
- **Notifications and history:** bans pop up on your desktop (grouped when several come at once; turn them off
  with `[notify] bans = false`). `ai-firewall history` lists bans, lifts, profile switches and feed updates
  (`/var/lib/ai-firewall/history.jsonl`).

## Doctor

`ai-firewall doctor` checks, with plain rules and no AI:
- whether the firewall is running, and whether ufw or firewalld is still running beside it
- whether you're connected, whether the internet answers, and whether DNS works
- VM and container networking: forwarding switched off, a FORWARD drop policy (Docker and
  ufw both set one) that cuts off libvirt VMs, and libvirt NAT rules that have gone missing
- whether a ban has hit your router, your DNS, this machine or a VM network

Each problem it can fix comes with a fix id. `ai-firewall fix <id>` is the only way to
apply one, so that list of ids is everything an assistant can be allowed to do.
`--json` gives machine-readable output. With `keep_vm_forwarding = true` (the default),
the daemon puts the VM exception back whenever Docker restarts.

## Ask the firewall

Press `a` in `ai-firewall top`, or run `ai-firewall ask "why can't my VM reach the internet?"`.
A local model answers from fresh facts: doctor findings, status, recent log lines and
host details. It uses LUNA's model when LUNA is set up, otherwise Ollama; remote models
are refused, so nothing about your network leaves the machine. It can only suggest
actions from a fixed list (doctor fixes, `open`/`close` a port, `unban`), and nothing
runs until you confirm. With no model installed you get the doctor's findings instead.
Run it with sudo so it can also see firewall rules and bans.

## Live tests

`ai-firewall test [health|ports|detector|traffic|services|all] [--json]`, `/test` in the `top` Ask panel, or
the model asks for one itself (`ACTION: test <name>`; tests are read-only, so they run without a y / n and the
model explains the results in the same panel):

- **health**: daemon alive, status fresh, filter attached, events lost, active bans
- **ports**: open ports with nothing listening behind them, and services listening on ports that are closed
- **detector**: simulated port scan, connection flood, UDP flood, stealth scan, normal use and a trusted source,
  replayed through an in-memory copy of the detector with your thresholds: what gets banned, after how many
  packets, and the cost per packet
- **traffic**: packets passed and dropped per second, new bans, events lost, sampled from the status file
- **services**: whether the services on your open TCP ports answer on 127.0.0.1

Safety limits are in the code (`selftest.rs`), not in the prompt: nothing is sent to another host; the only live
connections go to 127.0.0.1, to at most 16 ports the config opens, one attempt each with a 300 ms timeout;
simulated packets use documentation addresses (RFC 5737) and never touch the running daemon; `traffic` samples
for at most 30 s. No test needs root or changes anything.

`ai-firewall ask --json "..."` prints the answer as JSON lines (`model`, `chunk`, `tests`, `done`, `error`) for
the Halcyon Security center.

## Install (replaces ufw)

```shell
./packaging/install.sh --replace-ufw     # build, install the service, disable ufw
ai-firewall status
```

The config is at `/etc/ai-firewall/config.toml`. Open a port with `allow_tcp = [22]`, then
run `sudo systemctl reload ai-firewall` (a change to the file is also picked up within 3 s).
To try it without dropping anything, set `mode = "monitor"`: it only logs what it would do.

```shell
sudo ai-firewall ban 203.0.113.7 --minutes 30   # 0 = until unbanned
sudo ai-firewall unban 203.0.113.7
sudo ai-firewall off                            # stop filtering completely
sudo ai-firewall open tcp 22                    # open a port or range (edits the config, keeps comments)
ai-firewall history                             # what it did lately
ai-firewall feeds                               # the blocklists in use
sudo ai-firewall top                            # live dashboard (Halcyon colours)
sudo ai-firewall doctor --fix                   # why is the net / my VM broken? fix it
journalctl -u ai-firewall -f                    # live detections
./packaging/install.sh --uninstall
```

IPv6 sources are scored and banned by their /64 (one host usually owns a whole /64).
Link-local neighbours (fe80::/10) and your own prefixes are never auto-banned.

Limits: TCP is checked statelessly. A TCP packet that isn't a SYN is passed to the kernel,
which resets connections it doesn't know about.

## Tests

`.cargo/config.toml` runs binaries through sudo, so run the unit tests directly:

```shell
cargo test --release -p ai-firewall --no-run && $(ls -t target/release/build/ai-firewall/*/out/ai_firewall-* | head -1)
```

Without nightly / bpf-linker, `AYA_BUILD_SKIP=1` builds only the userspace side (the embedded eBPF object is an
empty placeholder, so the daemon cannot start, but every other command and all unit tests work):

```shell
AYA_BUILD_SKIP=1 cargo test --release -p ai-firewall --no-run && $(ls -t target/release/deps/ai_firewall-* | grep -v '\.d$' | head -1)
```

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
cargo build --package ai-firewall --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"rust-lld\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/ai-firewall` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, ai-firewall is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
