"""Print FortiSOAR Open Critical/High alert IDs, one per line.

This is a tiny CLI helper used by the `bin/oh-soc` wrapper script. It exists
because the LLM-facing `fortisoar_list_alerts` tool is intentionally capped at
20 alerts (to keep its output digestible to small models), and the wrapper
needs to drain ALL open alerts.

Usage:
    python -m openharness.soc_list_open_alerts

Output:
    One alert ID per line, in the form `Alert-NNNN`. Sorted newest first.
    Empty output (exit 0) if no Open Critical/High alerts exist for the
    configured tenant/source.

Filters (read from .env, identical to the LLM tool):
    - severity in {Critical, High}
    - status = Open
    - tenant = $FORTISOAR_TENANT
    - source = $FORTISOAR_SOURCE

Exit codes:
    0  success (zero or more alerts printed to stdout)
    1  configuration / network / API error
"""

from __future__ import annotations

import asyncio
import sys

from openharness.tools._fortisoar_helpers import fsr_get, get_fsr_config

# Drain mode: pull up to this many alerts per severity. The wrapper expects to
# see EVERY open alert (the existing 20-cap on the LLM tool is for prompt
# economy, not a real limit). 1000 is comfortably above any realistic queue
# depth and matches FortiSOAR's typical max page size.
_DRAIN_LIMIT_PER_SEVERITY = 1000

_INCLUDED_SEVERITIES = ("Critical", "High")


async def list_open_alert_ids() -> list[str]:
    """Fetch all Open Critical+High alert IDs for the configured tenant/source.

    Returns a list of `Alert-NNNN` strings sorted newest-first by createDate.
    Raises RuntimeError on FortiSOAR API errors so the CLI can surface them
    cleanly.
    """
    config = get_fsr_config()
    tenant = config.get("tenant", "")
    source = config.get("source", "")

    # Fetch each severity in parallel — same pattern as the LLM tool.
    tasks = [
        _fetch_one_severity(config, sev, tenant, source) for sev in _INCLUDED_SEVERITIES
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    merged: list[dict] = []
    errors: list[str] = []
    for sev, result in zip(_INCLUDED_SEVERITIES, results):
        if isinstance(result, Exception):
            errors.append(f"{sev}: {result}")
            continue
        merged.extend(result.get("hydra:member", []))

    # Surface errors only if NOTHING came back; partial success is acceptable
    # because the wrapper will pick up missed alerts on the next drain run.
    if errors and not merged:
        raise RuntimeError("FortiSOAR error(s): " + "; ".join(errors))

    # Newest first, matching the LLM tool's ordering
    merged.sort(key=lambda a: float(a.get("createDate") or 0), reverse=True)

    return [f"Alert-{a.get('id')}" for a in merged if a.get("id") is not None]


async def _fetch_one_severity(
    config: dict, severity: str, tenant: str, source: str
) -> dict:
    """Mirror of FortiSOARListAlertsTool._fetch_one_severity but with a much
    higher limit. Status is hardcoded to 'Open' here because that's the only
    state the wrapper ever wants to drain.
    """
    params = [
        f"$limit={_DRAIN_LIMIT_PER_SEVERITY}",
        "$offset=0",
        "$orderby=-createDate",
        f"severity.itemValue={severity}",
        "status.itemValue=Open",
    ]
    if tenant:
        params.append(f"tenant.name={tenant}")
    if source:
        params.append(f"source={source}")
    endpoint = "/api/3/alerts?" + "&".join(params)
    return await fsr_get(config, endpoint)


def main() -> None:
    try:
        ids = asyncio.run(list_open_alert_ids())
    except (ValueError, RuntimeError) as exc:
        # ValueError = config missing; RuntimeError = API failure
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    for alert_id in ids:
        print(alert_id)


if __name__ == "__main__":
    main()
