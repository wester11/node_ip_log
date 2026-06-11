"""
VOID Node Agent — лёгкий FastAPI-агент для VPN-ноды.

Блокирует IP-адреса на уровне iptables/ip6tables (цепочка VOID-BLOCK).
Запускается как systemd-сервис от root (нужен доступ к iptables).

Эндпоинты (все требуют заголовок X-Agent-Token или Authorization: Bearer):
  POST /block          {ip, ttl_hours?, reason?, sub_name?}
  POST /block/batch    {ips: [...], ttl_hours?, reason?, sub_name?}
  POST /unblock        {ip}
  POST /unblock/batch  {ips: [...]}
  GET  /blocked        — текущие блокировки
  POST /sync           — переприменить state к iptables (после ребута/сбоя)
  POST /flush          — снять ВСЕ блокировки
  GET  /health         — статус агента

Особенности:
  • Атомарная запись state (tmp + os.replace) в /var/lib/void-node-agent/state.json
  • Восстановление правил после ребута (startup → sync)
  • TTL блокировок (фоновая чистка раз в 60 сек)
  • asyncio.Lock на все операции с iptables/state
  • Никогда не блокирует приватные/loopback адреса (защита от выстрела в ногу)
  • Авторегистрация в центральной БД бота при старте (startup.py)
"""

import asyncio
import ipaddress
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

# ── Конфигурация ─────────────────────────────────────────────────────────────
AGENT_TOKEN   = os.getenv("AGENT_TOKEN", "")
AGENT_HOST    = os.getenv("AGENT_HOST", "0.0.0.0")
AGENT_PORT    = int(os.getenv("AGENT_PORT", "8765"))
STATE_FILE    = os.getenv("STATE_FILE", "/var/lib/void-node-agent/state.json")
CHAIN         = os.getenv("CHAIN_NAME", "VOID-BLOCK")
DEFAULT_TTL_H = float(os.getenv("DEFAULT_TTL_HOURS", "24"))  # 0 = бессрочно
ALLOW_PRIVATE = os.getenv("ALLOW_PRIVATE", "0") == "1"
# IP, которые нельзя блокировать никогда (через запятую): IP бота, мониторинг
NEVER_BLOCK   = {x.strip() for x in os.getenv("NEVER_BLOCK", "").split(",") if x.strip()}

_lock = asyncio.Lock()
# state: {"blocks": {ip: {reason, sub_name, blocked_at, expires_at|null}}}
_state: dict = {"blocks": {}}

app = FastAPI(title="void-node-agent", docs_url=None, redoc_url=None)


# ── Утилиты ──────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_ip(ip: str) -> str:
    """Возвращает нормализованный IP или кидает HTTPException."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"invalid ip: {ip!r}")
    if not ALLOW_PRIVATE and (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_unspecified
    ):
        raise HTTPException(status_code=400, detail=f"refusing to block non-public ip: {ip}")
    norm = str(addr)
    if norm in NEVER_BLOCK:
        raise HTTPException(status_code=400, detail=f"ip in NEVER_BLOCK list: {ip}")
    return norm


def _check_auth(x_agent_token: Optional[str], authorization: Optional[str]) -> None:
    if not AGENT_TOKEN:
        raise HTTPException(status_code=503, detail="AGENT_TOKEN not configured")
    token = x_agent_token or ""
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    import hmac as _hmac
    if not _hmac.compare_digest(token, AGENT_TOKEN):
        raise HTTPException(status_code=403, detail="forbidden")


# ── State (атомарная запись) ─────────────────────────────────────────────────

def _load_state() -> None:
    global _state
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("blocks"), dict):
            _state = data
    except FileNotFoundError:
        _state = {"blocks": {}}
    except Exception as e:
        print(f"[agent] state load error: {e}; starting empty")
        _state = {"blocks": {}}


def _save_state() -> None:
    d = os.path.dirname(STATE_FILE)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(_state, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ── iptables / ipset ─────────────────────────────────────────────────────────
#
# Если в системе есть `ipset` — используем его: один хэш-сет hash:ip + одно
# правило iptables (-m set --match-set ... src -j DROP). Это O(1) матчинг и
# отсутствие раздувания списка правил даже при десятках тысяч IP — критично для
# масштаба. Если ipset недоступен — прозрачный фолбэк на правила -s ... -j DROP.

IPSET_V4 = os.getenv("IPSET_NAME", "void-block")
IPSET_V6 = IPSET_V4 + "6"
_HAS_IPSET = False   # определяется в _ensure_chain()


def _ipt_bin(ip: str) -> str:
    return "ip6tables" if ":" in ip else "iptables"


def _ipset_for(ip: str) -> str:
    return IPSET_V6 if ":" in ip else IPSET_V4


async def _run(*cmd: str) -> int:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return await proc.wait()


async def _detect_ipset() -> bool:
    from shutil import which
    if not which("ipset"):
        return False
    return await _run("ipset", "list", "-n") == 0


async def _ensure_chain() -> None:
    """Создаёт цепочку VOID-BLOCK (+ ipset, если есть) и врезает в INPUT/FORWARD."""
    global _HAS_IPSET
    _HAS_IPSET = await _detect_ipset()

    if _HAS_IPSET:
        # idempotent создание сетов
        await _run("ipset", "create", IPSET_V4, "hash:ip", "family", "inet", "-exist")
        await _run("ipset", "create", IPSET_V6, "hash:ip", "family", "inet6", "-exist")
        for binary, setname in (("iptables", IPSET_V4), ("ip6tables", IPSET_V6)):
            await _run(binary, "-N", CHAIN)
            if await _run(binary, "-C", CHAIN, "-m", "set",
                          "--match-set", setname, "src", "-j", "DROP") != 0:
                await _run(binary, "-A", CHAIN, "-m", "set",
                           "--match-set", setname, "src", "-j", "DROP")
            for parent in ("INPUT", "FORWARD"):
                if await _run(binary, "-C", parent, "-j", CHAIN) != 0:
                    await _run(binary, "-I", parent, "1", "-j", CHAIN)
    else:
        for binary in ("iptables", "ip6tables"):
            await _run(binary, "-N", CHAIN)
            for parent in ("INPUT", "FORWARD"):
                if await _run(binary, "-C", parent, "-j", CHAIN) != 0:
                    await _run(binary, "-I", parent, "1", "-j", CHAIN)


async def _rule_exists(ip: str) -> bool:
    if _HAS_IPSET:
        return await _run("ipset", "test", _ipset_for(ip), ip) == 0
    return await _run(_ipt_bin(ip), "-C", CHAIN, "-s", ip, "-j", "DROP") == 0


async def _add_rule(ip: str) -> bool:
    if _HAS_IPSET:
        return await _run("ipset", "add", _ipset_for(ip), ip, "-exist") == 0
    if await _rule_exists(ip):
        return True
    return await _run(_ipt_bin(ip), "-A", CHAIN, "-s", ip, "-j", "DROP") == 0


async def _del_rule(ip: str) -> bool:
    if _HAS_IPSET:
        await _run("ipset", "del", _ipset_for(ip), ip, "-exist")
        return True
    # iptables: удаляем все дубликаты, если вдруг есть
    removed = False
    while await _rule_exists(ip):
        if await _run(_ipt_bin(ip), "-D", CHAIN, "-s", ip, "-j", "DROP") != 0:
            break
        removed = True
    return removed or not await _rule_exists(ip)


async def _flush_chain() -> None:
    if _HAS_IPSET:
        await _run("ipset", "flush", IPSET_V4)
        await _run("ipset", "flush", IPSET_V6)
    else:
        for binary in ("iptables", "ip6tables"):
            await _run(binary, "-F", CHAIN)


# ── Логика блокировок (вызывать под _lock) ───────────────────────────────────

async def _block_one(ip: str, ttl_hours: Optional[float],
                     reason: str, sub_name: str) -> bool:
    ok = await _add_rule(ip)
    if not ok:
        return False
    ttl = DEFAULT_TTL_H if ttl_hours is None else ttl_hours
    expires = _iso(_utcnow() + timedelta(hours=ttl)) if ttl and ttl > 0 else None
    _state["blocks"][ip] = {
        "reason": reason or "",
        "sub_name": sub_name or "",
        "blocked_at": _iso(_utcnow()),
        "expires_at": expires,
    }
    return True


async def _unblock_one(ip: str) -> bool:
    ok = await _del_rule(ip)
    _state["blocks"].pop(ip, None)
    return ok


async def _apply_state() -> dict:
    """Переприменяет state к iptables. Возвращает счётчики."""
    await _ensure_chain()
    applied = failed = 0
    for ip in list(_state["blocks"].keys()):
        if await _add_rule(ip):
            applied += 1
        else:
            failed += 1
    return {"applied": applied, "failed": failed}


async def _purge_expired() -> int:
    now = _utcnow()
    purged = 0
    for ip, meta in list(_state["blocks"].items()):
        exp = meta.get("expires_at")
        if not exp:
            continue
        try:
            exp_dt = datetime.strptime(exp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if exp_dt <= now:
            await _unblock_one(ip)
            purged += 1
    if purged:
        _save_state()
    return purged


# ── Модели ───────────────────────────────────────────────────────────────────

class BlockReq(BaseModel):
    ip: str
    ttl_hours: Optional[float] = None
    reason: str = ""
    sub_name: str = ""


class BlockBatchReq(BaseModel):
    ips: list[str] = Field(default_factory=list)
    ttl_hours: Optional[float] = None
    reason: str = ""
    sub_name: str = ""


class UnblockReq(BaseModel):
    ip: str


class UnblockBatchReq(BaseModel):
    ips: list[str] = Field(default_factory=list)


# ── Эндпоинты ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health(x_agent_token: Optional[str] = Header(None),
                 authorization: Optional[str] = Header(None)):
    _check_auth(x_agent_token, authorization)
    return {
        "ok": True,
        "node": os.getenv("NODE_NAME", ""),
        "blocked_count": len(_state["blocks"]),
        "chain": CHAIN,
        "backend": "ipset" if _HAS_IPSET else "iptables",
        "time": _iso(_utcnow()),
    }


@app.post("/block")
async def block(req: BlockReq,
                x_agent_token: Optional[str] = Header(None),
                authorization: Optional[str] = Header(None)):
    _check_auth(x_agent_token, authorization)
    ip = _validate_ip(req.ip)
    async with _lock:
        ok = await _block_one(ip, req.ttl_hours, req.reason, req.sub_name)
        _save_state()
    if not ok:
        raise HTTPException(status_code=500, detail=f"iptables failed for {ip}")
    return {"ok": True, "ip": ip}


@app.post("/block/batch")
async def block_batch(req: BlockBatchReq,
                      x_agent_token: Optional[str] = Header(None),
                      authorization: Optional[str] = Header(None)):
    _check_auth(x_agent_token, authorization)
    results: dict[str, bool] = {}
    async with _lock:
        for raw in req.ips:
            try:
                ip = _validate_ip(raw)
            except HTTPException:
                results[raw] = False
                continue
            results[ip] = await _block_one(ip, req.ttl_hours, req.reason, req.sub_name)
        _save_state()
    return {"ok": all(results.values()) if results else True, "results": results}


@app.post("/unblock")
async def unblock(req: UnblockReq,
                  x_agent_token: Optional[str] = Header(None),
                  authorization: Optional[str] = Header(None)):
    _check_auth(x_agent_token, authorization)
    ip = req.ip.strip()
    async with _lock:
        ok = await _unblock_one(ip)
        _save_state()
    return {"ok": ok, "ip": ip}


@app.post("/unblock/batch")
async def unblock_batch(req: UnblockBatchReq,
                        x_agent_token: Optional[str] = Header(None),
                        authorization: Optional[str] = Header(None)):
    _check_auth(x_agent_token, authorization)
    results: dict[str, bool] = {}
    async with _lock:
        for raw in req.ips:
            results[raw.strip()] = await _unblock_one(raw.strip())
        _save_state()
    return {"ok": True, "results": results}


@app.get("/blocked")
async def blocked(x_agent_token: Optional[str] = Header(None),
                  authorization: Optional[str] = Header(None)):
    _check_auth(x_agent_token, authorization)
    return {"ok": True, "blocks": _state["blocks"], "count": len(_state["blocks"])}


@app.post("/sync")
async def sync(x_agent_token: Optional[str] = Header(None),
               authorization: Optional[str] = Header(None)):
    _check_auth(x_agent_token, authorization)
    async with _lock:
        await _purge_expired()
        stats = await _apply_state()
    return {"ok": stats["failed"] == 0, **stats, "count": len(_state["blocks"])}


@app.post("/flush")
async def flush(x_agent_token: Optional[str] = Header(None),
                authorization: Optional[str] = Header(None)):
    _check_auth(x_agent_token, authorization)
    async with _lock:
        await _flush_chain()
        n = len(_state["blocks"])
        _state["blocks"] = {}
        _save_state()
    return {"ok": True, "flushed": n}


# ── Фоновые задачи ───────────────────────────────────────────────────────────

async def _ttl_loop():
    while True:
        try:
            async with _lock:
                purged = await _purge_expired()
            if purged:
                print(f"[agent] ttl: unblocked {purged} expired ip(s)")
        except Exception as e:
            print(f"[agent] ttl loop error: {e}")
        await asyncio.sleep(60)


@app.on_event("startup")
async def _startup():
    _load_state()
    async with _lock:
        await _purge_expired()
        stats = await _apply_state()
    print(f"[agent] started: restored {stats['applied']} block(s), failed {stats['failed']}")
    asyncio.get_event_loop().create_task(_ttl_loop())
    # Авторегистрация в центральной БД бота (если настроена)
    if os.getenv("CENTRAL_API_URL"):
        from startup import registration_loop
        asyncio.get_event_loop().create_task(registration_loop())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=AGENT_HOST, port=AGENT_PORT, log_level="warning")
