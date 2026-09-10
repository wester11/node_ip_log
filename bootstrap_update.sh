#!/usr/bin/env bash
# Fetch one immutable agent release and update an already enrolled node.
# This is deliberately separate from bootstrap.sh: an update never requests
# an enrollment code and never rewrites the node identity or block state.
set -euo pipefail
umask 077

REPOSITORY="wester11/node_ip_log"
REF="${VOID_NODE_AGENT_REF:-}"

if [[ $EUID -ne 0 ]]; then
    echo "[VOID] Run through sudo." >&2
    exit 1
fi
if [[ ! "$REF" =~ ^[a-f0-9]{40}$ ]]; then
    echo "[VOID] ERROR: update requires a pinned 40-character release commit." >&2
    exit 1
fi

WORK_DIR="$(mktemp -d /tmp/void-node-agent-update.XXXXXX)"
cleanup() { rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT INT TERM

ARCHIVE_URL="https://github.com/${REPOSITORY}/archive/${REF}.tar.gz"
echo "[VOID] Downloading pinned agent update…"
if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 180 "$ARCHIVE_URL" -o "$WORK_DIR/agent.tar.gz"
elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$WORK_DIR/agent.tar.gz" "$ARCHIVE_URL"
else
    echo "[VOID] ERROR: curl or wget is required." >&2
    exit 1
fi

tar -xzf "$WORK_DIR/agent.tar.gz" -C "$WORK_DIR"
SOURCE_DIR="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d -name 'node_ip_log-*' -print -quit)"
if [[ -z "$SOURCE_DIR" ]] || [[ ! -f "$SOURCE_DIR/update.sh" ]]; then
    echo "[VOID] ERROR: downloaded update is incomplete." >&2
    exit 1
fi

bash "$SOURCE_DIR/update.sh"
