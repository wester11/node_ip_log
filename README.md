# VOID Node Agent

Лёгкий агент IP-блокировок для VPN-нод (Remnawave / Xray / sing-box).
Работает как systemd-сервис (без Docker), ~30–50 МБ RAM, не мешает VPN-нагрузке.

Когда watchdog центрального бота фиксирует, что ключом (subscription link)
пользуется слишком много IP, он шлёт на ноды команду — и агент режет лишние
IP на уровне ядра через `iptables`/`ip6tables` (цепочка `VOID-BLOCK`).
Это настоящая блокировка: трафик с чужого IP дропается, а не просто рвётся
соединение в панели.

---

## Как это работает

```
            ┌─────────────┐   POST /block {ip}   ┌──────────────────┐
   бот ───▶ │ NodeManager │ ───────────────────▶ │  void-node-agent │ ──▶ iptables DROP -s ip
(watchdog)  └─────────────┘   (на все ноды)      └──────────────────┘     (цепочка VOID-BLOCK)
```

- Блокируется **только** конкретный лишний IP. IP владельца ключа и трафик
  остальных пользователей ноды не затрагиваются.
- Снятие бана: `POST /unblock`, авто-снятие при «Сменить ключ» / «Разблокировать»,
  и по TTL (по умолчанию 24 ч).
- После ребута ноды агент сам восстанавливает правила из
  `/var/lib/void-node-agent/state.json` (атомарная запись).
- **ipset.** Если в системе есть `ipset` (install.sh ставит его сам), агент
  использует один хэш-набор `void-block` + одно правило iptables вместо тысяч
  отдельных правил — O(1) матчинг, держит десятки тысяч IP без просадки.
  Если `ipset` нет — прозрачный фолбэк на обычные `iptables -s ... -j DROP`.
  Текущий режим виден в `/health` → `"backend": "ipset" | "iptables"`.

---

## Установка новой ноды

Две команды (`.env` создаётся сам, `AGENT_TOKEN` генерируется, `NODE_NAME` =
hostname). IP подставляешь СВОИ при установке — в репозитории их нет:

```bash
git clone https://github.com/wester11/node_ip_log.git && cd node_ip_log
sudo CENTRAL_API_URL=https://netvoid.ru \
     REGISTRATION_SECRET=общий_секрет_без_скобок \
     ALLOW_IPS=IP_бота,IP_панели \
     bash install.sh
```

`ALLOW_IPS` — кто может стучаться в порт агента: бот и панель Remnawave.
Установщик создаёт отдельную iptables-цепочку только для TCP-порта агента и
сохраняет её через systemd; VPN и SSH она не затрагивает. Можно перечислить
сколько угодно IPv4-адресов через запятую.

`NEVER_BLOCK` — IP, которые агент никогда не банит. Если не задан, берётся из
`ALLOW_IPS` (бот/панель и так не должны попадать под бан).

Или классически, заполнив `.env` руками:

```bash
cp .env.example .env
nano .env            # AGENT_TOKEN, CENTRAL_API_URL, REGISTRATION_SECRET, NODE_NAME
sudo bash install.sh
```

Можно и классикой: `cp .env.example .env && nano .env && sudo bash install.sh`.

Всё. Дальше нода сама:
1. Регистрируется в БД бота (`POST /internal/node/register`, подпись HMAC-SHA256)
2. Watchdog бота начинает блокировать на ней лишние IP
3. Health-watchdog бота мониторит её (`/health` каждые 5 мин); после сбоя/ребута
   дёргает `/sync` и правила восстанавливаются
4. Heartbeat-регистрация повторяется каждые 10 мин — `last_seen` всегда свежий

Обновить код агента позже: `git pull && sudo bash update.sh` (`.env` не трогается).

---

## Переменные окружения (`.env`)

| Переменная | Обяз. | Описание |
|---|:---:|---|
| `AGENT_TOKEN` | ✅ | токен API агента. Сгенерировать: `openssl rand -hex 32` |
| `CENTRAL_API_URL` | ✅ | URL бота, напр. `https://netvoid.ru` |
| `REGISTRATION_SECRET` | ✅ | общий секрет HMAC = `NODE_REGISTRATION_SECRET` у бота |
| `NODE_NAME` | ✅ | уникальное имя ноды, напр. `fi-node-1` |
| `AGENT_PORT` | | порт агента, по умолчанию `8765` |
| `AGENT_PUBLIC_URL` | | явный URL агента; если пусто — внешний IP определится сам |
| `DEFAULT_TTL_HOURS` | | TTL блокировки в часах, по умолчанию `24`, `0` = бессрочно |
| `NEVER_BLOCK` | | IP через запятую, которые нельзя банить — **впиши сюда IP бота и панели Remnawave** |
| `REGISTER_INTERVAL_MIN` | | период heartbeat, по умолчанию `10` |

⚠️ **Важно:** обязательно добавь в `NEVER_BLOCK` IP бот-сервера и панели
Remnawave, чтобы случайно не отрезать управляющий трафик. Агент и так
отказывается банить приватные/loopback адреса.

---

## API агента

Все запросы с заголовком `X-Agent-Token: <AGENT_TOKEN>` (или `Authorization: Bearer`).

| Метод | Путь | Тело |
|---|---|---|
| POST | `/block` | `{ip, ttl_hours?, reason?, sub_name?}` |
| POST | `/block/batch` | `{ips:[...], ttl_hours?, reason?, sub_name?}` |
| POST | `/unblock` | `{ip}` |
| POST | `/unblock/batch` | `{ips:[...]}` |
| GET  | `/blocked` | — текущие блокировки |
| POST | `/sync` | — переприменить state к iptables |
| POST | `/flush` | — снять ВСЕ блокировки |
| GET  | `/health` | — статус агента |

Примеры:

```bash
T=твой_AGENT_TOKEN
# заблокировать
curl -X POST -H "X-Agent-Token: $T" -H 'Content-Type: application/json' \
     -d '{"ip":"1.2.3.4","reason":"manual"}' http://127.0.0.1:8765/block
# снять бан
curl -X POST -H "X-Agent-Token: $T" -H 'Content-Type: application/json' \
     -d '{"ip":"1.2.3.4"}' http://127.0.0.1:8765/unblock
# что заблокировано
curl -s -H "X-Agent-Token: $T" http://127.0.0.1:8765/blocked | jq
# проверить цепочку на ноде
iptables -L VOID-BLOCK -n
```

---

## Эксплуатация

```bash
journalctl -u void-node-agent -f          # логи
systemctl restart void-node-agent          # рестарт
ipset list void-block                      # активные баны (если ipset)
iptables -L VOID-BLOCK -n --line-numbers   # цепочка / баны без ipset (v4)
ip6tables -L VOID-BLOCK -n                  # v6
```

Снять все баны на ноде вручную: `curl -X POST -H "X-Agent-Token: $T" http://127.0.0.1:8765/flush`

---

## Безопасность

- Не выставляй порт агента (`8765`) в открытый интернет без файрвола — передай
  IP бот-сервера в `ALLOW_IPS` при установке.
- `AGENT_TOKEN` и `REGISTRATION_SECRET` — секреты, хранятся только в `.env`
  (права `600`), в репозиторий не коммитятся (см. `.gitignore`).

---

## На стороне бота

Бот (voidbot) держит таблицу `vpn_nodes` и логирует действия в
`node_block_log` (каждый block/unblock) и `node_events` (регистрация,
падение/восстановление нод). В `.env` бота нужен `NODE_REGISTRATION_SECRET`
(тот же секрет, что `REGISTRATION_SECRET` на нодах).
