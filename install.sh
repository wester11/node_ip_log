#!/usr/bin/env bash
# VOID Node Agent v2 — outbound HTTPS management, no public agent port.
set -euo pipefail
umask 077

APP_DIR=/opt/void-node-agent
STATE_DIR=/var/lib/void-node-agent
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
CENTRAL_API_URL="${CENTRAL_API_URL:-https://netvoid.ru}"
NODE_NAME="${NODE_NAME:-$(hostname -s)}"

if [[ $EUID -ne 0 ]]; then
    echo "[VOID] Run as root: sudo env VOID_NODE_ENROLLMENT_CODE=... bash install.sh" >&2
    exit 1
fi
if [[ -z "${VOID_NODE_ENROLLMENT_CODE:-}" ]]; then
    echo "[VOID] ERROR: VOID_NODE_ENROLLMENT_CODE is required." >&2
    echo "[VOID] Generate a short-lived code in the VOID admin panel or with /nodecode." >&2
    exit 1
fi
if [[ "$CENTRAL_API_URL" != https://* ]]; then
    echo "[VOID] ERROR: CENTRAL_API_URL must use HTTPS." >&2
    exit 1
fi
if [[ ! "$NODE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; then
    echo "[VOID] ERROR: invalid NODE_NAME." >&2
    exit 1
fi

echo "[VOID] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip ipset iptables ca-certificates openssl

install -d -m 700 "$APP_DIR" "$STATE_DIR"

if [[ ! -x "$APP_DIR/venv/bin/pip" ]]; then
    rm -rf "$APP_DIR/venv"
    python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$SRC_DIR/requirements.txt"

echo "[VOID] Exchanging the one-time code for this node's private identity..."
(
    cd "$SRC_DIR"
    CENTRAL_API_URL="$CENTRAL_API_URL" NODE_NAME="$NODE_NAME" \
        VOID_NODE_ENROLLMENT_CODE="$VOID_NODE_ENROLLMENT_CODE" \
        "$APP_DIR/venv/bin/python" "$SRC_DIR/startup.py"
)

# Only replace the running installation after enrollment succeeded.
install -m 600 "$SRC_DIR/main.py" "$SRC_DIR/startup.py" "$SRC_DIR/secure_channel.py" "$APP_DIR/"
install -m 600 "$SRC_DIR/requirements.txt" "$APP_DIR/requirements.txt"

# The one-time code is intentionally never written to disk.
install -m 600 /dev/null "$APP_DIR/.env"
{
    printf 'CENTRAL_API_URL=%s\n' "$CENTRAL_API_URL"
    printf 'NODE_NAME=%s\n' "$NODE_NAME"
    printf 'AGENT_HOST=127.0.0.1\n'
    printf 'AGENT_PORT=8765\n'
    printf 'AGENT_TOKEN=%s\n' "$(openssl rand -hex 32)"
    printf 'DEFAULT_TTL_HOURS=%s\n' "${DEFAULT_TTL_HOURS:-24}"
    printf 'NEVER_BLOCK=%s\n' "${NEVER_BLOCK:-}"
} > "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

install -m 644 "$SRC_DIR/void-node-agent.service" /etc/systemd/system/void-node-agent.service

# Remove the legacy public-port firewall unit. v2 listens only on loopback.
systemctl disable --now void-node-agent-firewall.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/void-node-agent-firewall.service \
      /usr/local/sbin/void-node-agent-firewall \
      /etc/default/void-node-agent-firewall

systemctl daemon-reload
systemctl enable void-node-agent >/dev/null
systemctl restart void-node-agent
sleep 2
if ! systemctl is-active --quiet void-node-agent; then
    echo "[VOID] ERROR: service did not start. Check: journalctl -u void-node-agent -n 100" >&2
    exit 1
fi

echo "[VOID] Ready. The management channel is outbound HTTPS only."
echo "[VOID] Local diagnostics: curl -s -H \"X-Agent-Token: <local token>\" http://127.0.0.1:8765/health"
echo "[VOID] Logs: journalctl -u void-node-agent -f"
