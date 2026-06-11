#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# VOID Node Agent — установка на ноду ОДНОЙ командой (systemd, без Docker).
#
# Репозиторий: https://github.com/wester11/node_ip_log
#
# Вариант А (рекомендуется) — всё в одной команде, .env создаётся сам:
#
#   sudo CENTRAL_API_URL=https://netvoid.ru \
#        REGISTRATION_SECRET=<общий секрет> \
#        ALLOW_IPS=43.245.225.14,82.24.110.234 \
#        bash install.sh
#
#   NEVER_BLOCK по умолчанию = 43.245.225.14,82.24.110.234 (IP бота/панели).
#   ALLOW_IPS — кто может стучаться в порт агента (файрвол). Остальным закрыто.
#             Можно несколько через запятую. BOT_IP — старый синоним для одного IP.
#
#   • AGENT_TOKEN генерируется автоматически (openssl rand -hex 32)
#   • NODE_NAME по умолчанию = hostname (переопределить: NODE_NAME=fi-node-1)
#   • BOT_IP (опц.) — если задан и есть ufw, порт агента откроется только
#     для этого IP и закроется для всех остальных
#
# Вариант Б (классика) — заполнить .env руками:
#
#   cp .env.example .env && nano .env
#   sudo bash install.sh
#
# Что делает скрипт:
#   1. Ставит python3/venv/ipset/iptables (если нет)
#   2. Создаёт .env (вариант А) или берёт существующий (вариант Б)
#   3. Копирует файлы в /opt/void-node-agent, создаёт venv, ставит зависимости
#   4. Ставит systemd-сервис, включает автозапуск
#   5. (опц.) настраивает ufw для порта агента
#   Дальше агент сам регистрируется в боте и восстанавливает правила после ребута.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

APP_DIR=/opt/void-node-agent
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "Запусти от root: sudo bash install.sh" >&2
    exit 1
fi

# ── 1. Зависимости системы ───────────────────────────────────────────────────
# Определяем версию python для правильного имени venv-пакета (python3.12-venv и т.п.)
PYVER="$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo '')"

NEED_PKGS=()
command -v python3 >/dev/null || NEED_PKGS+=(python3)
# venv нужен ВСЕГДА: проверяем, что ensurepip реально доступен (а не просто `venv --help`)
if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    NEED_PKGS+=(python3-venv)
    [[ -n "$PYVER" ]] && NEED_PKGS+=("python${PYVER}-venv")
fi
command -v pip3 >/dev/null || python3 -c 'import pip' >/dev/null 2>&1 || NEED_PKGS+=(python3-pip)
command -v ipset    >/dev/null || NEED_PKGS+=(ipset)
command -v iptables >/dev/null || NEED_PKGS+=(iptables)
command -v openssl  >/dev/null || NEED_PKGS+=(openssl)
command -v curl     >/dev/null || NEED_PKGS+=(curl)

if (( ${#NEED_PKGS[@]} )); then
    echo "→ Ставлю пакеты: ${NEED_PKGS[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # ставим по одному, чтобы отсутствие одного пакета (напр. версии venv) не валило остальные
    for pkg in "${NEED_PKGS[@]}"; do
        apt-get install -y -qq "$pkg" || echo "⚠️ Не удалось поставить $pkg (пробую дальше)"
    done
fi

# Контрольная проверка venv — без него дальше нет смысла
if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    echo "❌ python venv недоступен. Поставь вручную и перезапусти:" >&2
    echo "   apt install -y python${PYVER:-3}-venv && sudo bash install.sh" >&2
    exit 1
fi

# ── 2. .env: из аргументов окружения или существующий файл ───────────────────
if [[ ! -f "$SRC_DIR/.env" ]]; then
    if [[ -n "${REGISTRATION_SECRET:-}" && -n "${CENTRAL_API_URL:-}" ]]; then
        NODE_NAME="${NODE_NAME:-$(hostname -s)}"
        AGENT_TOKEN="${AGENT_TOKEN:-$(openssl rand -hex 32)}"
        AGENT_PORT="${AGENT_PORT:-8765}"
        echo "→ Создаю .env автоматически (NODE_NAME=$NODE_NAME)"
        cat > "$SRC_DIR/.env" <<ENVEOF
AGENT_TOKEN=$AGENT_TOKEN
AGENT_PORT=$AGENT_PORT
AGENT_HOST=0.0.0.0
NODE_NAME=$NODE_NAME
CENTRAL_API_URL=$CENTRAL_API_URL
REGISTRATION_SECRET=$REGISTRATION_SECRET
DEFAULT_TTL_HOURS=${DEFAULT_TTL_HOURS:-24}
NEVER_BLOCK=${NEVER_BLOCK:-43.245.225.14,82.24.110.234}
REGISTER_INTERVAL_MIN=${REGISTER_INTERVAL_MIN:-10}
ENVEOF
        [[ -n "${AGENT_PUBLIC_URL:-}" ]] && echo "AGENT_PUBLIC_URL=$AGENT_PUBLIC_URL" >> "$SRC_DIR/.env"
        chmod 600 "$SRC_DIR/.env"
    else
        echo "Нет .env и не переданы переменные!" >&2
        echo "Либо: sudo CENTRAL_API_URL=... REGISTRATION_SECRET=... bash install.sh" >&2
        echo "Либо: cp .env.example .env && nano .env && sudo bash install.sh" >&2
        exit 1
    fi
else
    echo "→ Использую существующий .env"
fi

# ── 3. Файлы + venv ──────────────────────────────────────────────────────────
echo "→ Копирую в $APP_DIR"
mkdir -p "$APP_DIR" /var/lib/void-node-agent
cp "$SRC_DIR"/main.py "$SRC_DIR"/startup.py "$SRC_DIR"/requirements.txt "$APP_DIR/"
cp "$SRC_DIR/.env" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

echo "→ Создаю venv и ставлю зависимости"
if [[ ! -d "$APP_DIR/venv" ]]; then
    python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

# ── 4. systemd ───────────────────────────────────────────────────────────────
echo "→ Ставлю systemd-сервис"
cp "$SRC_DIR/void-node-agent.service" /etc/systemd/system/void-node-agent.service
systemctl daemon-reload
systemctl enable void-node-agent
systemctl restart void-node-agent

# ── 5. Файрвол (опц.): пускать к порту агента ТОЛЬКО доверенные IP ────────────
# ALLOW_IPS — список IP через запятую/пробел (бот, панель Remnawave и т.п.).
# Для обратной совместимости BOT_IP тоже учитывается.
PORT="$(grep -E '^AGENT_PORT=' "$APP_DIR/.env" | cut -d= -f2 || true)"
PORT="${PORT:-8765}"
ALLOW_LIST="${ALLOW_IPS:-${BOT_IP:-}}"
if [[ -n "$ALLOW_LIST" ]] && command -v ufw >/dev/null; then
    echo "→ Настраиваю ufw: порт $PORT только для: $ALLOW_LIST"
    # сначала разрешаем доверенным, потом запрещаем всем остальным
    for ip in ${ALLOW_LIST//,/ }; do
        [[ -z "$ip" ]] && continue
        ufw allow from "$ip" to any port "$PORT" proto tcp >/dev/null || true
        echo "   ✓ allow $ip"
    done
    ufw deny "$PORT"/tcp >/dev/null || true
    echo "   ✓ deny остальным"
elif [[ -n "$ALLOW_LIST" ]]; then
    echo "⚠️ ALLOW_IPS/BOT_IP заданы, но ufw не найден — закрой порт $PORT вручную:"
    for ip in ${ALLOW_LIST//,/ }; do
        [[ -z "$ip" ]] && continue
        echo "      ufw allow from $ip to any port $PORT proto tcp"
    done
    echo "      ufw deny $PORT/tcp"
fi

sleep 2
systemctl --no-pager -l status void-node-agent | head -12 || true

echo
echo "✅ Готово. Агент слушает порт $PORT."
echo "   Нода зарегистрируется в боте сама в течение минуты."
echo "   Проверка:  curl -s -H \"X-Agent-Token: \$(grep ^AGENT_TOKEN= $APP_DIR/.env | cut -d= -f2)\" http://127.0.0.1:$PORT/health"
echo "   Логи:      journalctl -u void-node-agent -f"
if [[ -z "${BOT_IP:-}" ]]; then
    echo "   ⚠️ Не забудь закрыть порт $PORT файрволом (только IP бота):"
    echo "      ufw allow from <IP_БОТА> to any port $PORT proto tcp && ufw deny $PORT/tcp"
fi
