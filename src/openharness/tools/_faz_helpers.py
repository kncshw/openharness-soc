"""FortiAnalyzer JSON-RPC 2.0 helpers with session-based auth.

All FAZ tools import from here. Uses session-based authentication
(login with username/password) with JSON-RPC 2.0 protocol and apiver 3.
Log search TIDs are tied to the session that created them, so a single
session must be used for the full create→poll→fetch cycle.

Required env vars:
    FAZ_HOST       — FortiAnalyzer URL (e.g. https://faz.example.com)
    FAZ_USER       — username
    FAZ_PASSWORD   — password

Optional env vars:
    FAZ_ADOM       — fallback/connectivity-test ADOM (default "root")
    FAZ_VERIFY_SSL — verify TLS cert (default "false")
    FAZ_ADOMS      — comma-separated allowlist of operational ADOMs the model
                     can query. Each entry may include a description after a
                     colon, e.g.:
                       FAZ_ADOMS=FortiCloud_Server:Burnaby Canada,FortiCloud_MIS_Colocation:worldwide colocations
                     If unset, the operational allowlist falls back to [FAZ_ADOM].
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta
from typing import Any

import httpx


# Accepted end_time formats for FAZ queries. FAZ accepts both ISO 8601 with 'T'
# and the space-separated form. We try them in order.
_ACCEPTED_END_TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M",
)


def parse_faz_time(value: str) -> datetime:
    """Parse a user-supplied time string for FAZ queries.

    FAZ interprets bare timestamps in its own (FortiAnalyzer-local) timezone.
    We do NOT attach timezone info — we treat the value as the wall-clock time
    in FAZ's TZ and let the API handle it.

    Accepts: 'YYYY-MM-DDTHH:MM:SS', 'YYYY-MM-DD HH:MM:SS', and minute precision.

    Raises ValueError if no format matches.
    """
    if not value:
        raise ValueError("empty time value")
    last_err: Exception | None = None
    for fmt in _ACCEPTED_END_TIME_FORMATS:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError as exc:
            last_err = exc
    raise ValueError(
        f"Could not parse time '{value}'. Use 'YYYY-MM-DD HH:MM:SS' "
        f"or 'YYYY-MM-DDTHH:MM:SS' (FAZ local time). Underlying: {last_err}"
    )


def build_time_range(end_time_str: str, minutes: int) -> dict[str, str]:
    """Build a FAZ time-range dict ending at end_time_str (or now if empty).

    Args:
        end_time_str: Optional ISO/space-separated end time. Empty = use now.
        minutes: Window duration (start = end - minutes).

    Returns:
        {"start": "YYYY-MM-DD HH:MM:SS", "end": "YYYY-MM-DD HH:MM:SS"}
        in FAZ local time format.

    Raises ValueError if end_time_str is invalid.
    """
    if end_time_str:
        end = parse_faz_time(end_time_str)
    else:
        end = datetime.now()
    start = end - timedelta(minutes=minutes)
    return {
        "start": start.strftime("%Y-%m-%d %H:%M:%S"),
        "end": end.strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_faz_config() -> dict[str, Any]:
    """Resolve FortiAnalyzer connection config from environment variables."""
    host = os.environ.get("FAZ_HOST", "")
    user = os.environ.get("FAZ_USER", "")
    password = os.environ.get("FAZ_PASSWORD", "")

    if not host or not user or not password:
        missing = []
        if not host:
            missing.append("FAZ_HOST")
        if not user:
            missing.append("FAZ_USER")
        if not password:
            missing.append("FAZ_PASSWORD")
        raise ValueError(
            f"FortiAnalyzer not configured. Set environment variables: {', '.join(missing)}"
        )

    verify_ssl = os.environ.get("FAZ_VERIFY_SSL", "false").lower() in ("true", "1", "yes")
    adom = os.environ.get("FAZ_ADOM", "root")

    return {
        "host": host.rstrip("/"),
        "user": user,
        "password": password,
        "adom": adom,
        "verify_ssl": verify_ssl,
    }


def get_configured_adoms() -> list[dict[str, str]]:
    """Return the operational ADOM allowlist as [{name, description}, ...].

    Reads FAZ_ADOMS first; format is comma-separated, with optional ':description'
    per entry, e.g.:
        FAZ_ADOMS=FortiCloud_Server:Burnaby Canada,FortiCloud_MIS_Colocation:worldwide

    If FAZ_ADOMS is unset, falls back to [FAZ_ADOM] (single-ADOM mode for the lab).
    """
    raw = os.environ.get("FAZ_ADOMS", "").strip()
    if not raw:
        fallback = os.environ.get("FAZ_ADOM", "root")
        return [{"name": fallback, "description": ""}]

    adoms: list[dict[str, str]] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            name, description = entry.split(":", 1)
            adoms.append({"name": name.strip(), "description": description.strip()})
        else:
            adoms.append({"name": entry, "description": ""})
    return adoms


def validate_adom(adom: str) -> tuple[bool, str]:
    """Check whether the given ADOM is allowed.

    Returns (is_valid, error_message). If valid, error_message is empty.
    The error message is written for an LLM consumer — it explains what to do.
    """
    configured = get_configured_adoms()
    allowed_names = [a["name"] for a in configured]

    # Build a human/model-friendly listing
    listing_lines = []
    for a in configured:
        if a["description"]:
            listing_lines.append(f"  - {a['name']} ({a['description']})")
        else:
            listing_lines.append(f"  - {a['name']}")
    listing = "\n".join(listing_lines)

    if not adom:
        return False, (
            "ADOM not specified. Before proceeding, you MUST use the ask_user_question "
            "tool to ask the user which ADOM to query.\n"
            "Available ADOMs:\n"
            f"{listing}\n"
            "Then call this tool again with adom=<chosen name>."
        )

    if adom.lower() in ("all", "*", "any", "every"):
        return False, (
            f"ADOM value '{adom}' is not allowed. You must specify exactly one ADOM. "
            "Use the ask_user_question tool to ask the user which one.\n"
            "Available ADOMs:\n"
            f"{listing}"
        )

    if adom not in allowed_names:
        return False, (
            f"Unknown ADOM '{adom}'. It is not in the configured allowlist.\n"
            "Available ADOMs:\n"
            f"{listing}\n"
            "Use ask_user_question if you are unsure which one to query."
        )

    return True, ""


async def _faz_login(client: httpx.AsyncClient, config: dict[str, Any]) -> str:
    """Login to FAZ and return session token."""
    payload = {
        "method": "exec",
        "params": [{"url": "/sys/login/user", "data": {"user": config["user"], "passwd": config["password"]}}],
        "id": 1,
    }
    resp = await client.post(f"{config['host']}/jsonrpc", json=payload)
    resp.raise_for_status()
    data = resp.json()
    session = data.get("session")
    if not session:
        raise RuntimeError(f"FAZ login failed: {data}")
    return session


async def _faz_logout(client: httpx.AsyncClient, config: dict[str, Any], session: str) -> None:
    """Logout from FAZ session."""
    try:
        await client.post(
            f"{config['host']}/jsonrpc",
            json={"method": "exec", "params": [{"url": "/sys/logout"}], "session": session, "id": 1},
        )
    except Exception:
        pass


async def _faz_call(
    client: httpx.AsyncClient,
    config: dict[str, Any],
    session: str,
    method: str,
    url: str,
    params_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a single FAZ JSON-RPC 2.0 call within an existing session."""
    params: dict[str, Any] = {
        "apiver": 3,
        "url": url,
    }
    if params_extra:
        params.update(params_extra)

    payload = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": method,
        "params": [params],
        "session": session,
    }

    resp = await client.post(f"{config['host']}/jsonrpc", json=payload)
    resp.raise_for_status()
    data = resp.json()

    if "error" in data:
        err = data["error"]
        raise RuntimeError(f"FAZ API error ({err.get('code')}): {err.get('message')}")

    return data.get("result", {})


async def faz_rpc(
    config: dict[str, Any],
    method: str,
    url: str,
    params_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a FortiAnalyzer JSON-RPC 2.0 call (login, call, logout).

    For single-shot calls like device listing. For log searches
    that need a persistent session, use faz_log_search() instead.
    """
    async with httpx.AsyncClient(verify=config["verify_ssl"], timeout=60.0) as client:
        session = await _faz_login(client, config)
        try:
            return await _faz_call(client, config, session, method, url, params_extra)
        finally:
            await _faz_logout(client, config, session)


async def faz_log_search(
    config: dict[str, Any],
    device: str,
    adom: str = "",
    logtype: str = "traffic",
    time_range: dict[str, str] | None = None,
    filter_expr: str = "",
    limit: int = 100,
    poll_interval: float = 2.0,
    max_polls: int = 90,
) -> dict[str, Any]:
    """Run an async two-step log search on FortiAnalyzer.

    Uses a single session for the entire create→poll→fetch cycle,
    because TIDs are tied to the session that created them.

    Args:
        adom: ADOM to query. Defaults to config['adom'] if empty.

    Step 1: Submit search task -> get TID
    Step 2: Poll TID until done -> return logs
    """
    if not adom:
        adom = config["adom"]

    search_params: dict[str, Any] = {
        "device": [{"devname": device}],
        "logtype": logtype,
        "limit": limit,
        "time-order": "desc",
    }
    if time_range:
        search_params["time-range"] = time_range
    if filter_expr:
        search_params["filter"] = filter_expr

    async with httpx.AsyncClient(verify=config["verify_ssl"], timeout=60.0) as client:
        session = await _faz_login(client, config)
        try:
            # Step 1: Create search task
            result = await _faz_call(
                client, config, session, method="add",
                url=f"/logview/adom/{adom}/logsearch",
                params_extra=search_params,
            )

            tid = result.get("tid")
            if not tid:
                raise RuntimeError(f"FAZ log search did not return a TID: {result}")

            # Step 2: Poll for results
            for _ in range(max_polls):
                await asyncio.sleep(poll_interval)

                fetch_result = await _faz_call(
                    client, config, session, method="get",
                    url=f"/logview/adom/{adom}/logsearch/{tid}",
                    params_extra={"limit": limit, "offset": 0},
                )

                percentage = fetch_result.get("percentage", 0)
                if percentage == 100:
                    return fetch_result

            raise RuntimeError(
                f"FAZ log search timed out after {max_polls * poll_interval}s (TID={tid})"
            )
        finally:
            await _faz_logout(client, config, session)
