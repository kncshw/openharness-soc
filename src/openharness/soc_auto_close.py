"""SOC alert auto-closer for whitelisted IPs.

Run BEFORE invoking `oh -p` on an alert. If the alert's source IP matches
the SOC whitelist (config/soc_whitelist.yaml), this script closes the alert
directly via the FortiSOAR API and exits 0. The LLM is never invoked.

If the alert does NOT match the whitelist, this script exits with code 2
so a wrapper can fall through to the LLM investigation path.

Usage:
    python -m openharness.soc_auto_close <alert_id>

Example bash wrapper pattern:
    if python -m openharness.soc_auto_close "$alert_id"; then
        echo "auto-closed"
    elif [ $? -eq 2 ]; then
        oh -p "analyze FortiSOAR alert $alert_id ..."
    else
        echo "error"; exit 1
    fi

Exit codes:
    0  alert auto-closed by whitelist match
    1  configuration / network / API error
    2  no whitelist match (caller should run the LLM investigation flow)
    3  alert is already Closed
    4  alert is in a tenant or source this agent is not scoped to
    5  alert not found

Why this exists:
    Whitelisted IPs are scanners and threat-intel collectors whose traffic
    looks like attacks. Asking a small LLM to weigh a soft whitelist hint
    against scary FAZ correlation is a known structural failure mode --
    it will over-weight the visible evidence and escalate. Code closes
    these cases deterministically; the LLM is reserved for ambiguous alerts
    where evidence actually drives the decision.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

from openharness.tools._fortisoar_helpers import fsr_get, fsr_put, get_fsr_config
from openharness.tools._whitelist import (
    Whitelist,
    WhitelistMatch,
    build_auto_close_notes,
    load_whitelist,
)
from openharness.tools.fortisoar_resolve_alert_tool import FortiSOARResolveAlertTool

CLOSER_VERSION = "soc-auto-close v0.1"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_MATCH = 2
EXIT_ALREADY_CLOSED = 3
EXIT_WRONG_SCOPE = 4
EXIT_NOT_FOUND = 5


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr)


def _stdout(msg: str) -> None:
    print(msg)


def _get_alert_status(alert: dict[str, Any]) -> str | None:
    status_obj = alert.get("status")
    if isinstance(status_obj, dict):
        return status_obj.get("itemValue")
    return None


def _get_alert_tenant(alert: dict[str, Any]) -> str:
    tenant_obj = alert.get("tenant") or {}
    if isinstance(tenant_obj, dict):
        return tenant_obj.get("name", "") or ""
    return ""


def _get_alert_source(alert: dict[str, Any]) -> str:
    source = alert.get("source") or ""
    if isinstance(source, dict):
        return source.get("name") or source.get("itemValue") or ""
    return str(source)


async def auto_close(alert_id: str) -> int:
    # 1. Config
    try:
        config = get_fsr_config()
    except ValueError as exc:
        _stderr(f"ERROR: FortiSOAR config: {exc}")
        return EXIT_ERROR

    # 2. Whitelist (empty whitelist = nothing to do, fall through)
    try:
        whitelist = load_whitelist()
    except (FileNotFoundError, ValueError) as exc:
        _stderr(f"ERROR: whitelist load failed: {exc}")
        return EXIT_ERROR

    if not whitelist.entries:
        # No whitelist configured/empty -- nothing can match. Caller should
        # invoke the LLM investigation flow.
        return EXIT_NO_MATCH

    # 3. Look up the alert (reuses the resolve tool's lookup logic, which
    # accepts 'Alert-NNN', 'NNN', or a UUID)
    try:
        alert = await FortiSOARResolveAlertTool._lookup_alert(config, alert_id)
    except RuntimeError as exc:
        _stderr(f"ERROR: alert lookup: {exc}")
        return EXIT_ERROR

    if alert is None:
        _stderr(f"alert '{alert_id}' not found in FortiSOAR")
        return EXIT_NOT_FOUND

    # 4. Tenant + source guards. Same fail-closed policy as the resolve tool.
    alert_tenant = _get_alert_tenant(alert)
    if alert_tenant != config["tenant"]:
        _stderr(
            f"REFUSE: Alert-{alert.get('id','?')} tenant '{alert_tenant or 'unknown'}' "
            f"!= configured '{config['tenant']}'"
        )
        return EXIT_WRONG_SCOPE

    alert_source = _get_alert_source(alert)
    if alert_source != config["source"]:
        _stderr(
            f"REFUSE: Alert-{alert.get('id','?')} source '{alert_source or 'unknown'}' "
            f"!= configured '{config['source']}'"
        )
        return EXIT_WRONG_SCOPE

    # 5. Already closed?
    if _get_alert_status(alert) == "Closed":
        _stderr(f"Alert-{alert.get('id','?')} is already Closed; no action")
        return EXIT_ALREADY_CLOSED

    # 6. Whitelist lookup against source IP
    src_ip = alert.get("sourceIp")
    if not src_ip:
        # No source IP to match against -- nothing the whitelist can decide.
        return EXIT_NO_MATCH

    match = whitelist.lookup_ip(str(src_ip))
    if match is None:
        return EXIT_NO_MATCH

    # 7. Build closure notes deterministically (no LLM)
    notes = build_auto_close_notes(alert, match, whitelist, CLOSER_VERSION)

    # 8. Resolve picklist IRIs
    try:
        status_iri = await FortiSOARResolveAlertTool._get_picklist_iri(
            config, "AlertStatus", "Closed"
        )
        reason_iri = await FortiSOARResolveAlertTool._get_picklist_iri(
            config, "Closure Reason", match.entry.closure_reason
        )
    except RuntimeError as exc:
        _stderr(f"ERROR: picklist lookup: {exc}")
        return EXIT_ERROR

    # 9. PUT the close
    payload = {
        "status": status_iri,
        "closureReason": reason_iri,
        "closureNotes": notes,
    }
    endpoint = f"/api/3/alerts/{alert['uuid']}"
    try:
        await fsr_put(config, endpoint, payload)
    except RuntimeError as exc:
        _stderr(f"ERROR: FortiSOAR PUT failed: {exc}")
        return EXIT_ERROR

    _stdout(f"=== Alert-{alert.get('id')} auto-closed by whitelist policy ===")
    _stdout(f"matched_entry:  {match.entry.selector} ({match.matched_on})")
    _stdout(f"reason:         {match.entry.reason}")
    _stdout(f"closure_reason: {match.entry.closure_reason}")
    _stdout(f"whitelist_sha:  {whitelist.file_sha}")
    return EXIT_OK


def main() -> None:
    if len(sys.argv) != 2:
        _stderr("usage: python -m openharness.soc_auto_close <alert_id>")
        sys.exit(EXIT_ERROR)
    alert_id = sys.argv[1].strip()
    if not alert_id:
        _stderr("alert_id is empty")
        sys.exit(EXIT_ERROR)
    rc = asyncio.run(auto_close(alert_id))
    sys.exit(rc)


if __name__ == "__main__":
    main()
