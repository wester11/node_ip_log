"""
Авторегистрация агента в центральной БД бота.

При старте (и затем каждые REGISTER_INTERVAL_MIN минут — heartbeat) агент
делает POST {CENTRAL_API_URL}/internal/node/register:

  {
    "name":         NODE_NAME,
    "agent_url":    AGENT_PUBLIC_URL или http://<внешний IP>:<AGENT_PORT>,
    "agent_token":  AGENT_TOKEN,
    "hmac_signature": HMAC-SHA256(json.dumps(payload, sort_keys=True), REGISTRATION_SECRET)
  }

ENV:
  CENTRAL_API_URL      https://netvoid.ru   (без неё регистрация выключена)
  REGISTRATION_SECRET  общий секрет (тот же, что NODE_REGISTRATION_SECRET у бота)
  NODE_NAME            fi-node-1
  AGENT_TOKEN          токен агента
  AGENT_PUBLIC_URL     (опц.) http://1.2.3.4:8765 — если не задан, внешний IP
                       определяется автоматически
  REGISTER_INTERVAL_MIN (опц., по умолчанию 10) — период heartbeat
"""

import asyncio
import hashlib
import hmac
import json
import os

import requests

CENTRAL_API_URL   = os.getenv("CENTRAL_API_URL", "").rstrip("/")
REG_SECRET        = os.getenv("REGISTRATION_SECRET", "")
NODE_NAME         = os.getenv("NODE_NAME", "")
AGENT_TOKEN       = os.getenv("AGENT_TOKEN", "")
AGENT_PORT        = int(os.getenv("AGENT_PORT", "8765"))
AGENT_PUBLIC_URL  = os.getenv("AGENT_PUBLIC_URL", "")
INTERVAL_MIN      = int(os.getenv("REGISTER_INTERVAL_MIN", "10"))

_IP_SERVICES = (
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
)


def detect_public_ip() -> str:
    for url in _IP_SERVICES:
        try:
            r = requests.get(url, timeout=5)
            if r.ok:
                ip = r.text.strip()
                if ip:
                    return ip
        except requests.RequestException:
            continue
    return ""


def sign_payload(payload: dict, secret: str) -> str:
    """HMAC-SHA256 по канонизированному JSON (sort_keys=True)."""
    raw = json.dumps(payload, sort_keys=True).encode()
    return hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def build_payload() -> dict | None:
    agent_url = AGENT_PUBLIC_URL
    if not agent_url:
        ip = detect_public_ip()
        if not ip:
            return None
        host = f"[{ip}]" if ":" in ip else ip
        agent_url = f"http://{host}:{AGENT_PORT}"
    return {"name": NODE_NAME, "agent_url": agent_url, "agent_token": AGENT_TOKEN}


def register_once() -> bool:
    """Одна попытка регистрации. True если бот ответил ok."""
    if not (CENTRAL_API_URL and REG_SECRET and NODE_NAME and AGENT_TOKEN):
        print("[agent] registration skipped: CENTRAL_API_URL/REGISTRATION_SECRET/"
              "NODE_NAME/AGENT_TOKEN not fully set")
        return False
    payload = build_payload()
    if payload is None:
        print("[agent] registration: cannot detect public ip")
        return False
    body = dict(payload)
    body["hmac_signature"] = sign_payload(payload, REG_SECRET)
    try:
        r = requests.post(
            f"{CENTRAL_API_URL}/internal/node/register",
            json=body, timeout=10,
        )
        if r.status_code == 200 and (r.json() or {}).get("ok"):
            print(f"[agent] registered as {payload['name']} → {payload['agent_url']}")
            return True
        print(f"[agent] registration rejected: {r.status_code} {r.text[:200]}")
    except requests.RequestException as e:
        print(f"[agent] registration error: {e}")
    return False


async def registration_loop() -> None:
    """Регистрируется с ретраями, затем heartbeat каждые INTERVAL_MIN минут."""
    delay = 5
    while True:
        ok = await asyncio.to_thread(register_once)
        if ok:
            await asyncio.sleep(INTERVAL_MIN * 60)
            delay = 5
        else:
            await asyncio.sleep(delay)
            delay = min(delay * 2, 300)


if __name__ == "__main__":
    register_once()
