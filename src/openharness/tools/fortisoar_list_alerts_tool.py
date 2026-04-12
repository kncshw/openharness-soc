"""List alerts from FortiSOAR (Critical and High severity only)."""

from __future__ import annotations

import asyncio
from datetime import datetime

from pydantic import BaseModel, Field

from openharness.tools._fortisoar_helpers import fsr_get, get_fsr_config
from openharness.tools.base import BaseTool, ToolExecutionContext, ToolResult


# This tool is intentionally scoped to high-priority alerts only.
# Medium / Low / Info alerts are excluded because the SOC analyst agent should
# focus on what requires action. Change this tuple only after reviewing with the team.
_INCLUDED_SEVERITIES = ("Critical", "High")


def _fmt_epoch(value) -> str:
    """Convert a FortiSOAR epoch (int or float) to ISO string. Returns '' if empty."""
    if value in (None, "", 0):
        return ""
    try:
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return str(value)


def _get_picklist_value(value, key: str = "itemValue") -> str:
    """Extract the human-readable value from an inline picklist object."""
    if isinstance(value, dict):
        return str(value.get(key, "?"))
    if value is None:
        return "-"
    return str(value)


class FortiSOARListAlertsInput(BaseModel):
    """Arguments for listing FortiSOAR alerts (Critical and High only)."""

    status: str = Field(
        default="Open",
        description=(
            "Filter by alert status. Common values: 'Open', 'Investigating', 'Closed'. "
            "Leave empty to return alerts of any status. Defaults to 'Open'."
        ),
    )
    limit: int = Field(
        default=20, ge=1, le=100,
        description="Maximum number of alerts to return (1-100, default 20).",
    )


class FortiSOARListAlertsTool(BaseTool):
    """List Critical and High severity alerts in FortiSOAR."""

    name = "fortisoar_list_alerts"
    description = (
        "List security alerts from FortiSOAR for the configured tenant. This tool ONLY "
        "returns Critical and High severity alerts — Medium, Low, and Info are excluded "
        "by design to keep the agent focused on high-priority work. "
        "Filter by status (default 'Open'). Sorted newest first. "
        "Returns alert ID, name, severity, status, source IP, destination IP, source tool, "
        "and creation date. Use fortisoar_get_alert with a specific alert ID for full details."
    )
    input_model = FortiSOARListAlertsInput

    def is_read_only(self, arguments: FortiSOARListAlertsInput) -> bool:
        return True

    async def execute(
        self, arguments: FortiSOARListAlertsInput, context: ToolExecutionContext
    ) -> ToolResult:
        try:
            config = get_fsr_config()
        except ValueError as exc:
            return ToolResult(output=str(exc), is_error=True)

        tenant = config.get("tenant", "")
        source = config.get("source", "")

        # Fetch each severity in parallel (FortiSOAR GET API does not support OR filters)
        tasks = [
            self._fetch_one_severity(
                config, sev, arguments.status, arguments.limit, tenant, source
            )
            for sev in _INCLUDED_SEVERITIES
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        merged_alerts: list[dict] = []
        total_per_sev: dict[str, int] = {}
        errors: list[str] = []

        for sev, result in zip(_INCLUDED_SEVERITIES, results):
            if isinstance(result, Exception):
                errors.append(f"{sev}: {result}")
                continue
            total_per_sev[sev] = result.get("hydra:totalItems", 0)
            merged_alerts.extend(result.get("hydra:member", []))

        if errors and not merged_alerts:
            return ToolResult(
                output="FortiSOAR error(s): " + "; ".join(errors),
                is_error=True,
            )

        # Sort merged results by createDate descending
        merged_alerts.sort(key=lambda a: float(a.get("createDate") or 0), reverse=True)

        # Apply limit after merge
        display = merged_alerts[: arguments.limit]

        total_all = sum(total_per_sev.values())
        status_desc = arguments.status if arguments.status else "any status"
        tenant_desc = f"tenant={tenant}" if tenant else "tenant=all"
        source_desc = f"source={source}" if source else "source=all"

        if not display:
            return ToolResult(
                output=(
                    f"No Critical/High severity FortiSOAR alerts found "
                    f"({tenant_desc}, {source_desc}, status={status_desc})."
                )
            )

        lines = [
            f"FortiSOAR Critical/High alerts ({tenant_desc}, {source_desc}, status={status_desc}): "
            f"Critical={total_per_sev.get('Critical', 0)}, "
            f"High={total_per_sev.get('High', 0)}, "
            f"total={total_all} — showing top {len(display)} by creation date",
            "",
        ]

        for alert in display:
            alert_id = alert.get("id", "?")
            name = str(alert.get("name", ""))[:100]
            sev = _get_picklist_value(alert.get("severity"))
            status_val = _get_picklist_value(alert.get("status"))
            src_ip = alert.get("sourceIp") or "-"
            dst_ip = alert.get("destinationIp") or "-"
            source_tool = alert.get("source") or alert.get("sourceType") or "-"
            created = _fmt_epoch(alert.get("createDate"))
            tenant = _get_picklist_value(alert.get("tenant"), key="name") or "-"

            lines.append(f"Alert-{alert_id}: {name}")
            lines.append(
                f"  severity={sev}  status={status_val}  source_tool={source_tool}  tenant={tenant}"
            )
            lines.append(f"  src={src_ip}  dst={dst_ip}  created={created}")
            lines.append("")

        if errors:
            lines.append("[Warnings: " + "; ".join(errors) + "]")

        lines.append(
            "Use fortisoar_get_alert with alert_id=<Alert-NNN> to see full details "
            "(description, IOCs, sourcedata, etc.)."
        )

        return ToolResult(output="\n".join(lines))

    @staticmethod
    async def _fetch_one_severity(
        config: dict,
        severity: str,
        status: str,
        limit: int,
        tenant: str,
        source: str,
    ) -> dict:
        params = [
            f"$limit={limit}",
            "$offset=0",
            "$orderby=-createDate",
            f"severity.itemValue={severity}",
        ]
        if status:
            params.append(f"status.itemValue={status}")
        if tenant:
            params.append(f"tenant.name={tenant}")
        if source:
            params.append(f"source={source}")
        endpoint = "/api/3/alerts?" + "&".join(params)
        return await fsr_get(config, endpoint)
