#!/usr/bin/env bash
# Remove only VOID Node Agent files and firewall objects.
# Remnawave, Docker, Xray and unrelated firewall rules are not touched.
set -euo pipefail
umask 077

APP_DIR=/opt/void-node-agent
STATE_DIR=/var/lib/void-node-agent
SERVICE=void-node-agent.service
FIREWALL_SERVICE=void-node-agent-firewall.service
BLOCK_CHAIN=VOID-BLOCK
LEGACY_CHAIN=VOID-AGENT-FW
PORT=8765

if [[ $EUID -ne 0 ]]; then
    echo "[VOID] Run as root: sudo bash uninstall.sh" >&2
    exit 1
fi

if [[ -r /etc/default/void-node-agent-firewall ]]; then
    configured_port="$(sed -n 's/^AGENT_PORT=//p' /etc/default/void-node-agent-firewall | tr -d "'\"" | head -n 1)"
elif [[ -r "$APP_DIR/.env" ]]; then
    configured_port="$(sed -n 's/^AGENT_PORT=//p' "$APP_DIR/.env" | tr -d "'\"" | head -n 1)"
else
    configured_port=""
fi
if [[ "$configured_port" =~ ^[0-9]{1,5}$ ]] && (( configured_port >= 1 && configured_port <= 65535 )); then
    PORT="$configured_port"
fi

echo "[VOID] Stopping the node agent..."
systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
systemctl disable --now "$FIREWALL_SERVICE" >/dev/null 2>&1 || true

remove_jump() {
    local binary="$1" parent="$2" chain="$3"
    command -v "$binary" >/dev/null 2>&1 || return 0
    while "$binary" -C "$parent" -j "$chain" >/dev/null 2>&1; do
        "$binary" -D "$parent" -j "$chain" >/dev/null 2>&1 || break
    done
}

echo "[VOID] Removing only VOID firewall chains..."
for binary in iptables ip6tables; do
    remove_jump "$binary" INPUT "$BLOCK_CHAIN"
    remove_jump "$binary" FORWARD "$BLOCK_CHAIN"
    if command -v "$binary" >/dev/null 2>&1; then
        "$binary" -F "$BLOCK_CHAIN" >/dev/null 2>&1 || true
        "$binary" -X "$BLOCK_CHAIN" >/dev/null 2>&1 || true
    fi
done
if command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -p tcp --dport "$PORT" -j "$LEGACY_CHAIN" >/dev/null 2>&1; do
        iptables -D INPUT -p tcp --dport "$PORT" -j "$LEGACY_CHAIN" >/dev/null 2>&1 || break
    done
    iptables -F "$LEGACY_CHAIN" >/dev/null 2>&1 || true
    iptables -X "$LEGACY_CHAIN" >/dev/null 2>&1 || true
fi
if command -v ipset >/dev/null 2>&1; then
    ipset destroy void-block >/dev/null 2>&1 || true
    ipset destroy void-block6 >/dev/null 2>&1 || true
fi

rm -f -- /etc/systemd/system/void-node-agent.service \
    /etc/systemd/system/void-node-agent-firewall.service \
    /usr/local/sbin/void-node-agent-firewall \
    /etc/default/void-node-agent-firewall
rm -rf -- "$APP_DIR" "$STATE_DIR"
systemctl daemon-reload
systemctl reset-failed "$SERVICE" "$FIREWALL_SERVICE" >/dev/null 2>&1 || true

if id -u voidnode >/dev/null 2>&1; then
    userdel voidnode >/dev/null 2>&1 || true
fi

echo "[VOID] Agent removed. Remnawave, Docker and Xray were not changed."
echo "[VOID] In the admin panel press 'Revoke' for this node to invalidate its old server token."
