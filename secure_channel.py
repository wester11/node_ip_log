"""Outbound-only HTTPS management channel for VOID nodes.

The node has no public management listener. A short-lived, single-use
enrollment code is exchanged for a unique per-node token. The token is kept
only in a service-user-readable identity file and is never printed to logs.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import tempfile
from pathlib import Path
from typing import Awaitable, Callable

import requests


AGENT_VERSION = "2.1.4"
IDENTITY_FILE = Path(os.getenv("VOID_NODE_IDENTITY_FILE", "/var/lib/void-node-agent/identity.json"))
CENTRAL_API_URL = os.getenv("CENTRAL_API_URL", "https://netvoid.ru").rstrip("/")
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": f"void-node-agent/{AGENT_VERSION}"})


class SecureChannelError(RuntimeError):
    pass


def _require_https(url: str) -> None:
    if not url.startswith("https://"):
        raise SecureChannelError("CENTRAL_API_URL must use HTTPS")


def _write_identity(identity: dict) -> None:
    IDENTITY_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".identity-", suffix=".json", dir=IDENTITY_FILE.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(identity, handle, ensure_ascii=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, IDENTITY_FILE)
        os.chmod(IDENTITY_FILE, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def load_identity() -> dict:
    try:
        data = json.loads(IDENTITY_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SecureChannelError("node is not enrolled") from error
    if not all(data.get(key) for key in ("node_id", "node_name", "node_token", "central_api_url")):
        raise SecureChannelError("node identity is incomplete")
    _require_https(str(data["central_api_url"]))
    return data


def enroll_once(enrollment_code: str, node_name: str) -> dict:
    """Consume a single-use code and persist the returned node identity."""
    _require_https(CENTRAL_API_URL)
    if not enrollment_code or not node_name:
        raise SecureChannelError("enrollment code and node name are required")
    try:
        response = _SESSION.post(
            f"{CENTRAL_API_URL}/internal/node/v2/enroll",
            json={
                "enrollment_code": enrollment_code,
                "node_name": node_name,
                "agent_version": AGENT_VERSION,
            },
            timeout=(5, 20),
        )
    except requests.RequestException as error:
        raise SecureChannelError(f"central service is unavailable: {error.__class__.__name__}") from error
    if response.status_code != 200:
        message = "activation code is invalid, expired, already used, or requires replacement"
        try:
            message = str(response.json().get("error") or message)
        except ValueError:
            pass
        raise SecureChannelError(message)
    body = response.json()
    identity = {
        "node_id": int(body["node_id"]),
        "node_name": str(body["node_name"]),
        "node_token": str(body["node_token"]),
        "central_api_url": CENTRAL_API_URL,
        "agent_version": AGENT_VERSION,
    }
    _write_identity(identity)
    return {"node_id": identity["node_id"], "node_name": identity["node_name"]}


def _headers(identity: dict) -> dict:
    return {
        "Authorization": f"Bearer {identity['node_token']}",
        "X-VOID-Node-ID": str(identity["node_id"]),
        "Accept": "application/json",
        "Cache-Control": "no-store",
    }


def _poll(identity: dict) -> dict:
    response = _SESSION.post(
        f"{identity['central_api_url']}/internal/node/v2/poll",
        headers=_headers(identity),
        json={"agent_version": AGENT_VERSION},
        timeout=(5, 35),
    )
    if response.status_code in {401, 403}:
        raise SecureChannelError("node identity was revoked; issue a new one-time code")
    response.raise_for_status()
    return response.json()


def _send_result(identity: dict, command_id: int, *, result: dict | None = None,
                 error: str | None = None) -> None:
    response = _SESSION.post(
        f"{identity['central_api_url']}/internal/node/v2/result",
        headers=_headers(identity),
        json={
            "command_id": command_id,
            "status": "failed" if error else "success",
            "result": result or {},
            "error": (error or "")[:1000],
        },
        timeout=(5, 20),
    )
    response.raise_for_status()


async def management_loop(executor: Callable[[str, dict], Awaitable[dict]]) -> None:
    """Poll the central service and execute only the agent's allow-listed actions."""
    identity = load_identity()
    delay = 2.0
    while True:
        try:
            body = await asyncio.to_thread(_poll, identity)
            delay = float(body.get("poll_after_seconds") or 3)
            command = body.get("command")
            if command:
                command_id = int(command["id"])
                try:
                    result = await executor(str(command.get("action") or ""), command.get("payload") or {})
                    if isinstance(result, dict) and result.get("ok") is False:
                        await asyncio.to_thread(
                            _send_result, identity, command_id, result=result,
                            error="action returned ok=false",
                        )
                    else:
                        await asyncio.to_thread(_send_result, identity, command_id, result=result)
                except Exception as error:
                    await asyncio.to_thread(
                        _send_result, identity, command_id,
                        error=f"{error.__class__.__name__}: {str(error)[:850]}",
                    )
                delay = 0.2
        except SecureChannelError as error:
            print(f"[agent] secure channel: {error}")
            delay = min(max(delay * 2, 10), 300)
        except (requests.RequestException, ValueError, KeyError) as error:
            print(f"[agent] secure channel temporarily unavailable: {error.__class__.__name__}")
            delay = min(max(delay * 1.8, 3), 60)
        await asyncio.sleep(delay + random.uniform(0, min(1.0, delay / 5)))
