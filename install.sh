#!/usr/bin/env bash
# VOID Node Agent v2 — outbound HTTPS management, no public agent port.
set -euo pipefail
umask 077

APP_DIR=/opt/void-node-agent
STATE_DIR=/var/lib/void-node-agent
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
CENTRAL_API_URL="${CENTRAL_API_URL:-https://netvoid.ru}"
if [[ -z "${NODE_NAME:-}" ]] && [[ -r "$APP_DIR/.env" ]]; then
    previous_name="$(sed -n 's/^NODE_NAME=//p' "$APP_DIR/.env" | head -n 1 | tr -d '\r')"
    if [[ "$previous_name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; then
        NODE_NAME="$previous_name"
    fi
fi
if [[ -z "${NODE_NAME:-}" ]]; then
    node_base="$(hostname -s 2>/dev/null | tr -cd 'A-Za-z0-9_.-' | cut -c1-48)"
    node_base="${node_base:-node}"
    if [[ -r /etc/machine-id ]]; then
        node_suffix="$(tr -cd 'A-Fa-f0-9' </etc/machine-id | cut -c1-8)"
    else
        node_suffix=""
    fi
    node_suffix="${node_suffix:-$(openssl rand -hex 4)}"
    NODE_NAME="${node_base}-${node_suffix}"
fi

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
if command -v modprobe >/dev/null 2>&1; then
    modprobe ip_set >/dev/null 2>&1 || true
    modprobe ip_set_hash_ip >/dev/null 2>&1 || true
    modprobe xt_set >/dev/null 2>&1 || true
fi

if ! id -u voidnode >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin voidnode
fi
install -d -o root -g voidnode -m 750 "$APP_DIR"
install -d -o voidnode -g voidnode -m 700 "$STATE_DIR"

if [[ ! -x "$APP_DIR/venv/bin/pip" ]]; then
    rm -rf "$APP_DIR/venv"
    python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$SRC_DIR/requirements.txt"
# The service runs as the unprivileged `voidnode` user.  `umask 077` is right
# for generated secrets, but it also makes a freshly-created root-owned venv
# non-executable by that service unless we grant its dedicated group read/exec.
chown -R root:voidnode "$APP_DIR/venv"
chmod -R g+rX "$APP_DIR/venv"
chmod -R g-w "$APP_DIR/venv"

echo "[VOID] Exchanging the one-time code for this node's private identity..."
(
    cd "$SRC_DIR"
    CENTRAL_API_URL="$CENTRAL_API_URL" NODE_NAME="$NODE_NAME" \
        VOID_NODE_ENROLLMENT_CODE="$VOID_NODE_ENROLLMENT_CODE" \
        "$APP_DIR/venv/bin/python" "$SRC_DIR/startup.py"
)
chown voidnode:voidnode "$STATE_DIR/identity.json"
chmod 600 "$STATE_DIR/identity.json"

# Only replace the running installation after enrollment succeeded. Old agent
# state and its two dedicated firewall chains are removed, while Remnawave,
# Docker, Xray and unrelated rules remain untouched.
systemctl stop void-node-agent.service >/dev/null 2>&1 || true
systemctl disable --now void-node-agent-firewall.service >/dev/null 2>&1 || true
for binary in iptables ip6tables; do
    if command -v "$binary" >/dev/null 2>&1; then
        for parent in INPUT FORWARD; do
            while "$binary" -C "$parent" -j VOID-BLOCK >/dev/null 2>&1; do
                "$binary" -D "$parent" -j VOID-BLOCK >/dev/null 2>&1 || break
            done
        done
        "$binary" -F VOID-BLOCK >/dev/null 2>&1 || true
        "$binary" -X VOID-BLOCK >/dev/null 2>&1 || true
    fi
done
if command -v iptables >/dev/null 2>&1; then
    # On a clean node this legacy file does not exist.  With `pipefail`, a
    # failed sed inside command substitution used to abort installation here
    # immediately after successful enrollment, before the service was made.
    legacy_port=""
    if [[ -r /etc/default/void-node-agent-firewall ]]; then
        legacy_port="$(sed -n 's/^AGENT_PORT=//p' /etc/default/void-node-agent-firewall | tr -d "'\"" | head -n 1 || true)"
    fi
    legacy_port="${legacy_port:-8765}"
    if [[ "$legacy_port" =~ ^[0-9]{1,5}$ ]]; then
        while iptables -C INPUT -p tcp --dport "$legacy_port" -j VOID-AGENT-FW >/dev/null 2>&1; do
            iptables -D INPUT -p tcp --dport "$legacy_port" -j VOID-AGENT-FW >/dev/null 2>&1 || break
        done
    fi
    iptables -F VOID-AGENT-FW >/dev/null 2>&1 || true
    iptables -X VOID-AGENT-FW >/dev/null 2>&1 || true
fi
if command -v ipset >/dev/null 2>&1; then
    ipset destroy void-block >/dev/null 2>&1 || true
    ipset destroy void-block6 >/dev/null 2>&1 || true
fi
rm -f -- "$STATE_DIR/state.json" \
    /etc/systemd/system/void-node-agent-firewall.service \
    /usr/local/sbin/void-node-agent-firewall \
    /etc/default/void-node-agent-firewall

install -o root -g voidnode -m 640 "$SRC_DIR/main.py" "$SRC_DIR/startup.py" "$SRC_DIR/secure_channel.py" "$APP_DIR/"
install -o root -g voidnode -m 640 "$SRC_DIR/requirements.txt" "$APP_DIR/requirements.txt"

# The full network audit uses only this checksum-pinned optional binary. A
# failed download leaves the agent install healthy and keeps quick audits.
APP_DIR="$APP_DIR" bash "$SRC_DIR/install_geocheck.sh"

# The one-time code is intentionally never written to disk.
install -o voidnode -g voidnode -m 600 /dev/null "$APP_DIR/.env"
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
