#!/usr/bin/env bash
# Download a pinned VOID Node Agent release and run its installer.
set -euo pipefail
umask 077

REPOSITORY="wester11/node_ip_log"
REF="${VOID_NODE_AGENT_REF:-main}"

if [[ ! "$REF" =~ ^[A-Za-z0-9._/-]{1,80}$ ]] || [[ "$REF" == *".."* ]]; then
    echo "[VOID] ERROR: invalid agent release." >&2
    exit 1
fi

WORK_DIR="$(mktemp -d /tmp/void-node-agent.XXXXXX)"
cleanup() { rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT INT TERM

ARCHIVE_URL="https://github.com/${REPOSITORY}/archive/${REF}.tar.gz"
echo "[VOID] Downloading the verified agent release..."
if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        "$ARCHIVE_URL" -o "$WORK_DIR/agent.tar.gz"
elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$WORK_DIR/agent.tar.gz" "$ARCHIVE_URL"
else
    echo "[VOID] ERROR: curl or wget is required." >&2
    exit 1
fi

tar -xzf "$WORK_DIR/agent.tar.gz" -C "$WORK_DIR"
SOURCE_DIR="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d -name 'node_ip_log-*' -print -quit)"
if [[ -z "$SOURCE_DIR" ]] || [[ ! -f "$SOURCE_DIR/install.sh" ]]; then
    echo "[VOID] ERROR: downloaded release is incomplete." >&2
    exit 1
fi

bash "$SOURCE_DIR/install.sh"
