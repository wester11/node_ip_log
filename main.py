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
  • Исходящий защищённый канал HTTPS без публичного управляющего порта
"""

import asyncio
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
import requests

# ── Конфигурация ─────────────────────────────────────────────────────────────
AGENT_TOKEN   = os.getenv("AGENT_TOKEN", "")
AGENT_HOST    = os.getenv("AGENT_HOST", "127.0.0.1")
AGENT_PORT    = int(os.getenv("AGENT_PORT", "8765"))
STATE_FILE    = os.getenv("STATE_FILE", "/var/lib/void-node-agent/state.json")
CHAIN         = os.getenv("CHAIN_NAME", "VOID-BLOCK")
DEFAULT_TTL_H = float(os.getenv("DEFAULT_TTL_HOURS", "24"))  # 0 = бессрочно
ALLOW_PRIVATE = os.getenv("ALLOW_PRIVATE", "0") == "1"
# IP, которые нельзя блокировать никогда (через запятую): IP бота, мониторинг
NEVER_BLOCK   = {x.strip() for x in os.getenv("NEVER_BLOCK", "").split(",") if x.strip()}
GEOCHECK_BIN = os.getenv("GEOCHECK_BIN", "/opt/void-node-agent/bin/geocheck")
AUDIT_USER_AGENT = "VOID-node-audit/1.0"

# These targets are deliberately fixed in the agent source. The control plane
# can select only a profile, never arbitrary URLs or shell arguments.
AUDIT_ENDPOINTS = (
    ("chatgpt", "https://chatgpt.com/", {200, 302, 303, 401, 403, 429}),
    ("openai_auth", "https://auth.openai.com/", {200, 302, 303, 401, 403, 429}),
    ("gemini", "https://gemini.google.com/", {200, 302, 303, 401, 403, 429}),
    ("google_ai_api", "https://generativelanguage.googleapis.com/", {400, 401, 403, 404, 429}),
    ("youtube", "https://www.youtube.com/", {200, 302, 303, 401, 403, 429}),
    ("youtube_premium", "https://www.youtube.com/premium", {200, 302, 303, 401, 403, 429}),
)

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


def _bounded_command(*command: str, timeout: int = 8) -> dict:
    """Run a fixed diagnostic command without accepting shell input."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
        output = (completed.stdout + completed.stderr).strip()[:6000]
        return {"exit_code": completed.returncode, "output": output}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"exit_code": -1, "output": error.__class__.__name__}


def _tcp_probe(host: str, port: int = 443) -> dict:
    import time as _time

    started = _time.monotonic()
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        address = addresses[0][4]
        with socket.create_connection(address, timeout=5):
            pass
        return {
            "ok": True,
            "ms": round((_time.monotonic() - started) * 1000),
            "address": str(address[0]),
        }
    except OSError as error:
        return {"ok": False, "error": error.__class__.__name__}


def _read_meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                key, value = line.split(":", 1)
                values[key] = int(value.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return values


def _cpu_sample() -> dict:
    def read() -> tuple[int, int, int]:
        try:
            with open("/proc/stat", encoding="utf-8") as handle:
                fields = handle.readline().split()[1:]
            values = [int(value) for value in fields]
            total = sum(values)
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            steal = values[7] if len(values) > 7 else 0
            return total, idle, steal
        except (OSError, ValueError, IndexError):
            return 0, 0, 0

    first = read()
    time.sleep(0.2)
    second = read()
    total = second[0] - first[0]
    if total <= 0:
        return {"usage_percent": None, "steal_percent": None}
    return {
        "usage_percent": round(100 * (1 - (second[1] - first[1]) / total), 1),
        "steal_percent": round(100 * (second[2] - first[2]) / total, 1),
    }


def _system_snapshot() -> dict:
    memory = _read_meminfo()
    memory_total = int(memory.get("MemTotal") or 0)
    memory_available = int(memory.get("MemAvailable") or memory.get("MemFree") or 0)
    # Some hardened systemd/procfs combinations intentionally hide meminfo
    # from an unprivileged service.  sysconf still exposes aggregate memory
    # counters there; importantly, lack of either source is "unknown", not
    # "zero RAM" and must never lower the node score.
    if memory_total <= 0:
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            memory_total = int(os.sysconf("SC_PHYS_PAGES")) * page_size
            memory_available = int(os.sysconf("SC_AVPHYS_PAGES")) * page_size
        except (OSError, ValueError, AttributeError):
            memory_total = 0
            memory_available = 0
    disk = shutil.disk_usage("/")
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = 0.0
    try:
        with open("/proc/uptime", encoding="utf-8") as handle:
            uptime_seconds = int(float(handle.read().split()[0]))
    except (OSError, ValueError, IndexError):
        uptime_seconds = None
    return {
        "cpu_count": max(1, os.cpu_count() or 1),
        "load_1": round(load1, 2),
        "load_5": round(load5, 2),
        "load_15": round(load15, 2),
        "cpu": _cpu_sample(),
        "memory_total_mb": round(memory_total / 1024 / 1024) if memory_total else None,
        "memory_available_mb": round(memory_available / 1024 / 1024) if memory_total else None,
        "memory_available_percent": round(100 * memory_available / memory_total, 1) if memory_total else None,
        "disk_free_gb": round(disk.free / 1024 / 1024 / 1024, 2),
        "disk_free_percent": round(100 * disk.free / disk.total, 1) if disk.total else None,
        "uptime_seconds": uptime_seconds,
    }


def _https_probe(name: str, url: str, expected_statuses: set[int]) -> dict:
    started = time.monotonic()
    try:
        response = requests.get(
            url,
            headers={"User-Agent": AUDIT_USER_AGENT, "Accept": "text/html,application/json;q=0.9,*/*;q=0.1"},
            timeout=(4, 12),
            allow_redirects=True,
            stream=True,
        )
        status = int(response.status_code)
        response.close()
        return {
            "name": name,
            "reachable": status in expected_statuses,
            "http_status": status,
            "ms": round((time.monotonic() - started) * 1000),
        }
    except requests.RequestException as error:
        return {
            "name": name,
            "reachable": False,
            "error": error.__class__.__name__,
            "ms": round((time.monotonic() - started) * 1000),
        }


def _public_ipv4() -> str:
    try:
        response = requests.get(
            "https://api.ipify.org",
            headers={"User-Agent": AUDIT_USER_AGENT},
            timeout=(4, 10),
        )
        value = response.text.strip()
        response.close()
        return str(ipaddress.ip_address(value)) if "." in value else ""
    except (requests.RequestException, ValueError):
        return ""


def _compact_geocheck_report() -> dict:
    """Run the checksum-pinned local binary and return a bounded JSON summary."""
    if not os.path.isfile(GEOCHECK_BIN) or not os.access(GEOCHECK_BIN, os.X_OK):
        return {"ran": False, "reason": "geocheck_not_installed"}
    try:
        completed = subprocess.run(
            [GEOCHECK_BIN, "--json", "--quiet", "-4", "--timeout", "6", "--rounds", "1", "--max-ttl", "12"],
            capture_output=True,
            text=True,
            timeout=110,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ran": False, "reason": error.__class__.__name__}
    if completed.returncode != 0:
        return {"ran": False, "reason": "geocheck_failed", "exit_code": completed.returncode}
    try:
        raw = json.loads(completed.stdout)
    except ValueError:
        return {"ran": False, "reason": "geocheck_invalid_json"}
    findings = raw.get("findings") if isinstance(raw.get("findings"), list) else []
    compact_findings = []
    for finding in findings[:16]:
        if isinstance(finding, dict):
            compact_findings.append({
                "severity": str(finding.get("severity") or "info")[:16],
                "message": str(finding.get("message") or finding.get("detail") or "")[:240],
            })
        else:
            compact_findings.append(str(finding)[:240])
    stash = raw.get("stash_checks") if isinstance(raw.get("stash_checks"), (dict, list)) else {}
    # A full report must remain comfortably below the central 128 KiB result
    # limit.  Do not preserve routes/hops verbatim: the panel only needs the
    # verdicts, while a detailed rerun can be made directly when required.
    consensus = raw.get("consensus") if isinstance(raw.get("consensus"), dict) else {}
    connectivity = raw.get("connectivity") if isinstance(raw.get("connectivity"), dict) else {}
    compact_stash = stash[:24] if isinstance(stash, list) else dict(list(stash.items())[:24])
    return {
        "ran": True,
        "duration_ms": int(raw.get("duration_ms") or 0),
        "identity": raw.get("identity") if isinstance(raw.get("identity"), dict) else {},
        "reputation": raw.get("reputation") if isinstance(raw.get("reputation"), dict) else {},
        "consensus": {key: consensus[key] for key in list(consensus)[:16]},
        "connectivity": {key: connectivity[key] for key in list(connectivity)[:16]},
        "stash_checks": compact_stash,
        "findings": compact_findings,
    }


def _network_audit(profile: str) -> dict:
    if profile not in {"quick", "full"}:
        raise ValueError("unsupported audit profile")
    started = time.monotonic()
    system = _system_snapshot()
    services = [_https_probe(name, url, expected) for name, url, expected in AUDIT_ENDPOINTS]
    geocheck = _compact_geocheck_report() if profile == "full" else {"ran": False, "reason": "quick_profile"}
    findings: list[str] = []
    score = 100
    failed_services = [probe["name"] for probe in services if not probe.get("reachable")]
    if failed_services:
        score -= min(45, 12 * len(failed_services))
        findings.append("Недоступны сервисы: " + ", ".join(failed_services))
    memory_percent = system.get("memory_available_percent")
    memory_mb = system.get("memory_available_mb")
    if (memory_percent is not None and memory_percent < 10) or (memory_mb is not None and memory_mb < 256):
        score -= 25
        findings.append("Мало свободной оперативной памяти")
    elif memory_percent is not None and memory_percent < 20:
        score -= 10
        findings.append("Свободной оперативной памяти меньше 20%")
    if (system.get("disk_free_percent") or 100) < 10 or float(system.get("disk_free_gb") or 0) < 2:
        score -= 25
        findings.append("Мало свободного места на диске")
    elif (system.get("disk_free_percent") or 100) < 20:
        score -= 10
        findings.append("Свободного места на диске меньше 20%")
    cpu_count = max(1, int(system.get("cpu_count") or 1))
    if float(system.get("load_1") or 0) / cpu_count > 2:
        score -= 15
        findings.append("Высокая нагрузка на процессор")
    if float((system.get("cpu") or {}).get("steal_percent") or 0) > 10:
        score -= 15
        findings.append("Хостер сильно отбирает CPU у VPS")
    if geocheck.get("ran"):
        alerts = [item for item in geocheck.get("findings") or [] if isinstance(item, dict) and item.get("severity") in {"alert", "error"}]
        if alerts:
            score -= min(20, 5 * len(alerts))
            findings.extend([str(item.get("message") or "Проблема маршрута") for item in alerts[:3]])
    elif profile == "full":
        findings.append("Полная геопроверка не запустилась: " + str(geocheck.get("reason") or "unknown"))
        score -= 5
    report = {
        "ok": True,
        "kind": "network_audit",
        "profile": profile,
        "score": max(0, score),
        "public_ipv4": _public_ipv4(),
        "system": system,
        "services": services,
        "geocheck": geocheck,
        "findings": findings[:12],
        "duration_ms": round((time.monotonic() - started) * 1000),
    }
    # The result endpoint has a 128 KiB hard ceiling.  A release change in
    # geocheck must never turn a healthy management poll into an oversized
    # response, so discard only optional detail as a final guardrail.
    if len(json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > 96 * 1024:
        report["geocheck"] = {
            "ran": bool(geocheck.get("ran")),
            "reason": str(geocheck.get("reason") or "report_compacted"),
            "findings": (geocheck.get("findings") or [])[:6],
        }
        report["findings"] = (report["findings"] + ["Подробный Geo-отчёт сокращён для безопасной передачи"])[:12]
    return report


async def execute_secure_command(action: str, payload: dict) -> dict:
    """Execute the central server's explicit allow-list; never a remote shell."""
    if action == "health":
        return {
            "ok": True,
            "node": os.getenv("NODE_NAME", ""),
            "blocked_count": len(_state["blocks"]),
            "backend": "ipset" if _HAS_IPSET else "iptables",
            "time": _iso(_utcnow()),
        }
    if action == "sync":
        async with _lock:
            await _purge_expired()
            stats = await _apply_state()
        return {"ok": stats["failed"] == 0, **stats, "count": len(_state["blocks"])}
    if action == "block_batch":
        ips = payload.get("ips") or []
        if not isinstance(ips, list) or len(ips) > 5000:
            raise ValueError("invalid IP batch")
        results = {}
        async with _lock:
            for raw in ips:
                try:
                    ip = _validate_ip(str(raw))
                    results[ip] = await _block_one(
                        ip,
                        payload.get("ttl_hours"),
                        str(payload.get("reason") or "")[:120],
                        str(payload.get("sub_name") or "")[:255],
                    )
                except HTTPException:
                    results[str(raw)[:64]] = False
            _save_state()
        return {"ok": all(results.values()) if results else True, "results": results}
    if action == "unblock_batch":
        ips = payload.get("ips") or []
        if not isinstance(ips, list) or len(ips) > 5000:
            raise ValueError("invalid IP batch")
        results = {}
        async with _lock:
            for raw in ips:
                value = str(raw).strip()
                try:
                    value = str(ipaddress.ip_address(value))
                except ValueError:
                    results[value[:64]] = False
                    continue
                results[value] = await _unblock_one(value)
            _save_state()
        return {"ok": True, "results": results}
    if action == "flush":
        async with _lock:
            await _flush_chain()
            count = len(_state["blocks"])
            _state["blocks"] = {}
            _save_state()
        return {"ok": True, "flushed": count}
    if action == "diagnose_telegram":
        # Fixed, read-only probes. No payload value is ever executed.
        return {
            "ok": True,
            "telegram": await asyncio.to_thread(_tcp_probe, "api.telegram.org"),
            "telegram_web": await asyncio.to_thread(_tcp_probe, "telegram.org"),
            "route": await asyncio.to_thread(_bounded_command, "ip", "route", "get", "1.1.1.1"),
            "memory": await asyncio.to_thread(_bounded_command, "free", "-m"),
            "disk": await asyncio.to_thread(_bounded_command, "df", "-h", "/"),
            "kernel": await asyncio.to_thread(_bounded_command, "uname", "-sr"),
        }
    if action == "network_audit":
        # The central API may choose a preset only.  It cannot supply a host,
        # command line, proxy or shell fragment to this privileged service.
        profile = str(payload.get("profile") or "quick")
        return await asyncio.to_thread(_network_audit, profile)
    raise ValueError("unsupported command")


@app.on_event("startup")
async def _startup():
    _load_state()
    async with _lock:
        await _purge_expired()
        stats = await _apply_state()
    print(f"[agent] started: restored {stats['applied']} block(s), failed {stats['failed']}")
    asyncio.get_event_loop().create_task(_ttl_loop())
    from secure_channel import management_loop

    asyncio.get_event_loop().create_task(management_loop(execute_secure_command))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=AGENT_HOST, port=AGENT_PORT, log_level="warning")
