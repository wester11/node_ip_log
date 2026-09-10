#!/usr/bin/env bash
# Update agent code without touching the per-node identity or local state.
set -euo pipefail
umask 077

APP_DIR=/opt/void-node-agent
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash update.sh" >&2
    exit 1
fi
if [[ ! -s /var/lib/void-node-agent/identity.json ]]; then
    echo "Node is not enrolled. Generate a replacement code and run install.sh." >&2
    exit 1
fi

# A previous installer version could finish enrollment but stop before it
# created .env.  Repair that narrow partial-install state from the root-only
# identity instead of asking the operator to consume another enrollment code.
if [[ ! -s "$APP_DIR/.env" ]]; then
    mapfile -t identity_values < <("$APP_DIR/venv/bin/python" - <<'PY'
import json
with open("/var/lib/void-node-agent/identity.json", encoding="utf-8") as handle:
    identity = json.load(handle)
print(str(identity.get("central_api_url") or ""))
print(str(identity.get("node_name") or ""))
PY
)
    CENTRAL_API_URL="${identity_values[0]:-}"
    NODE_NAME="${identity_values[1]:-}"
    if [[ "$CENTRAL_API_URL" != https://* ]] || [[ ! "$NODE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; then
        echo "Node identity is incomplete; do not overwrite it. Issue a replacement code." >&2
        exit 1
    fi
    install -d -o root -g voidnode -m 750 "$APP_DIR"
    install -o voidnode -g voidnode -m 600 /dev/null "$APP_DIR/.env"
    {
        printf 'CENTRAL_API_URL=%s\n' "$CENTRAL_API_URL"
        printf 'NODE_NAME=%s\n' "$NODE_NAME"
        printf 'AGENT_HOST=127.0.0.1\n'
        printf 'AGENT_PORT=8765\n'
        printf 'AGENT_TOKEN=%s\n' "$(openssl rand -hex 32)"
        printf 'DEFAULT_TTL_HOURS=24\n'
        printf 'NEVER_BLOCK=\n'
    } > "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo "[VOID] Repaired the incomplete local agent configuration."
fi

install -o root -g voidnode -m 640 "$SRC_DIR/main.py" "$SRC_DIR/startup.py" "$SRC_DIR/secure_channel.py" "$APP_DIR/"
install -o root -g voidnode -m 640 "$SRC_DIR/requirements.txt" "$APP_DIR/requirements.txt"
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
# See install.sh: Python's venv may have been created with root-only mode due
# to the installer umask.  The agent needs read/execute, never write access.
chown -R root:voidnode "$APP_DIR/venv"
chmod -R g+rX "$APP_DIR/venv"
chmod -R g-w "$APP_DIR/venv"
APP_DIR="$APP_DIR" bash "$SRC_DIR/install_geocheck.sh"
install -m 644 "$SRC_DIR/void-node-agent.service" /etc/systemd/system/void-node-agent.service
chown -R voidnode:voidnode /var/lib/void-node-agent
chmod 700 /var/lib/void-node-agent
chmod 600 /var/lib/void-node-agent/identity.json
systemctl daemon-reload
systemctl restart void-node-agent
systemctl is-active --quiet void-node-agent
echo "VOID Node Agent updated. Identity and block state were preserved."
