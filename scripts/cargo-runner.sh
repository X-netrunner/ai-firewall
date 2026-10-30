#!/usr/bin/env bash
# Runner for Cargo: runs test binaries directly in user-space without interactive sudo prompts,
# and elevates with sudo -E for daemon execution when not already root.
set -euo pipefail

BIN="$1"
NAME="$(basename "$BIN")"

# Test binaries have underscores and a 16-hex hash suffix (e.g. ai_firewall-004ce6b8182a9f45)
# or live under deps/ or build/*/out/
if [[ "$NAME" =~ _.*-[0-9a-f]{16}$ ]] || [[ "$BIN" == */deps/* ]] || [[ "$BIN" == */build/*/out/* ]] || [[ "$EUID" -eq 0 ]]; then
    exec "$@"
fi

exec sudo -E "$@"
