#!/usr/bin/env bash
# Постоянный файрвол для API агента. Применяется systemd при загрузке ноды.
set -euo pipefail

CONFIG_FILE=/etc/default/void-node-agent-firewall
CHAIN=VOID-AGENT-FW

if [[ ! -r "$CONFIG_FILE" ]]; then
    echo "void-node-agent-firewall: configuration is absent" >&2
    exit 0
fi

# shellcheck source=/etc/default/void-node-agent-firewall
source "$CONFIG_FILE"
PORT="${AGENT_PORT:-8765}"
ALLOW_LIST="${ALLOW_IPS:-}"

if [[ ! "$PORT" =~ ^[0-9]{1,5}$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "void-node-agent-firewall: invalid AGENT_PORT" >&2
    exit 1
fi

if [[ -z "$ALLOW_LIST" ]]; then
    echo "void-node-agent-firewall: ALLOW_IPS is empty" >&2
    exit 1
fi

iptables -N "$CHAIN" 2>/dev/null || true
iptables -F "$CHAIN"
iptables -A "$CHAIN" -s 127.0.0.1 -j ACCEPT

for ip in ${ALLOW_LIST//,/ }; do
    [[ -z "$ip" ]] && continue
    if [[ ! "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        echo "void-node-agent-firewall: invalid IPv4 address: $ip" >&2
        exit 1
    fi
    iptables -A "$CHAIN" -s "$ip" -j ACCEPT
done

iptables -A "$CHAIN" -j DROP
iptables -C INPUT -p tcp --dport "$PORT" -j "$CHAIN" 2>/dev/null \
    || iptables -I INPUT 1 -p tcp --dport "$PORT" -j "$CHAIN"
