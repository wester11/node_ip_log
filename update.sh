#!/usr/bin/env bash
# Обновление кода агента на ноде (config .env не трогается).
set -euo pipefail

APP_DIR=/opt/void-node-agent
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "Запусти от root: sudo bash update.sh" >&2
    exit 1
fi

cp "$SRC_DIR"/main.py "$SRC_DIR"/startup.py "$SRC_DIR"/requirements.txt "$APP_DIR/"
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
cp "$SRC_DIR/void-node-agent.service" /etc/systemd/system/void-node-agent.service
install -m 700 "$SRC_DIR/void-node-agent-firewall.sh" /usr/local/sbin/void-node-agent-firewall
install -m 644 "$SRC_DIR/void-node-agent-firewall.service" /etc/systemd/system/void-node-agent-firewall.service
systemctl daemon-reload
if [[ -f /etc/default/void-node-agent-firewall ]]; then
    systemctl enable --now void-node-agent-firewall
fi
systemctl restart void-node-agent
echo "✅ Обновлено и перезапущено."
