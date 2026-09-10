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

install -o root -g voidnode -m 640 "$SRC_DIR/main.py" "$SRC_DIR/startup.py" "$SRC_DIR/secure_channel.py" "$APP_DIR/"
install -o root -g voidnode -m 640 "$SRC_DIR/requirements.txt" "$APP_DIR/requirements.txt"
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
APP_DIR="$APP_DIR" bash "$SRC_DIR/install_geocheck.sh"
install -m 644 "$SRC_DIR/void-node-agent.service" /etc/systemd/system/void-node-agent.service
chown -R voidnode:voidnode /var/lib/void-node-agent
chmod 700 /var/lib/void-node-agent
chmod 600 /var/lib/void-node-agent/identity.json
systemctl daemon-reload
systemctl restart void-node-agent
systemctl is-active --quiet void-node-agent
echo "VOID Node Agent updated. Identity and block state were preserved."
