"""Escalate a FortiSOAR alert to human review (status → Investigating)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from openharness.tools._fortisoar_helpers import fsr_get, fsr_put, get_fsr_config
from openharness.tools.base import BaseTool, ToolExecutionContext, ToolResult


# Reuse the same ID-parsing regexes from the resolve tool.
from openharness.tools.fortisoar_resolve_alert_tool import (
    FortiSOARResolveAlertTool,
    _ensure_bis_ai_marker,
)


class FortiSOAREscalateAlertInput(BaseModel):
    """Arguments for escalating a FortiSOAR alert to human review."""

    alert_id: str = Field(
        description=(
            "Alert identifier. Accepts 'Alert-108160', '108160', or a UUID. "
            "Get IDs from fortisoar_list_alerts."
        )
    )
    findings: str = Field(
        description=(
            "Your investigation findings — what you queried, what you found, "
            "and why you are escalating. Include specific numbers, IPs, actions, "
            "and [LOG] citations. This text is written to FortiSOAR so the human "
            "analyst can see what the AI investigated before they take over."
        ),
    )


class FortiSOAREscalateAlertTool(BaseTool):
    """Escalate a FortiSOAR alert to human review. Sets status to
    'Investigating' and records the AI's findings. MUTATING."""

    name = "fortisoar_escalate_alert"
    description = (
        "Escalate a FortiSOAR alert for human review. Sets the alert status to "
        "'Investigating' and records your investigation findings so the human "
        "analyst can see what you found. Use this instead of fortisoar_resolve_alert "
        "when you cannot confidently close the alert — for example when the "
        "escalation rule triggers (external source → internal destination with "
        "action=accept and data transfer), or when the evidence is ambiguous.\n"
        "Arguments:\n"
        "  - alert_id (required, e.g. 'Alert-107596')\n"
        "  - findings (required — your investigation summary including [LOG] citations)\n"
        "After calling this tool, output one confirmation sentence and STOP. "
        "Do NOT call fortisoar_resolve_alert afterward."
    )
    input_model = FortiSOAREscalateAlertInput

    def is_read_only(self, arguments: FortiSOAREscalateAlertInput) -> bool:
        return False

    async def execute(
        self, arguments: FortiSOAREscalateAlertInput, context: ToolExecutionContext
    ) -> ToolResult:
        try:
            config = get_fsr_config()
        except ValueError as exc:
            return ToolResult(output=str(exc), is_error=True)

        raw_id = arguments.alert_id.strip()

        # Look up the alert — reuse the resolve tool's static method
        try:
            alert = await FortiSOARResolveAlertTool._lookup_alert(config, raw_id)
        except RuntimeError as exc:
            return ToolResult(output=f"FortiSOAR error: {exc}", is_error=True)

        if alert is None:
            return ToolResult(
                output=f"Alert '{raw_id}' not found in FortiSOAR.",
                is_error=True,
            )

        # Tenant scoping
        configured_tenant = config["tenant"]
        alert_tenant_obj = alert.get("tenant") or {}
        alert_tenant = (
            alert_tenant_obj.get("name", "")
            if isinstance(alert_tenant_obj, dict) else ""
        )
        if alert_tenant != configured_tenant:
            return ToolResult(
                output=(
                    f"Access denied: Alert-{alert.get('id','?')} belongs to tenant "
                    f"'{alert_tenant or 'unknown'}', but this agent is scoped to "
                    f"tenant '{configured_tenant}'."
                ),
                is_error=True,
            )

        # Source scoping
        configured_source = config.get("source", "")
        if configured_source:
            alert_source = alert.get("source") or ""
            if isinstance(alert_source, dict):
                alert_source = (
                    alert_source.get("name")
                    or alert_source.get("itemValue")
                    or ""
                )
            if str(alert_source) != configured_source:
                return ToolResult(
                    output=(
                        f"Access denied: Alert-{alert.get('id','?')} has source "
                        f"'{alert_source or 'unknown'}', but this agent is scoped to "
                        f"source '{configured_source}'."
                    ),
                    is_error=True,
                )

        # Status check — only escalate Open alerts
        current_status = _get_status(alert)
        if current_status == "Investigating":
            return ToolResult(
                output=(
                    f"Alert-{alert.get('id','?')} is already in 'Investigating' status. "
                    f"No action taken — a human is already reviewing it."
                ),
                is_error=True,
            )
        if current_status == "Closed":
            return ToolResult(
                output=(
                    f"Alert-{alert.get('id','?')} is already Closed. "
                    f"Cannot escalate a closed alert."
                ),
                is_error=True,
            )

        # Prepend the BIS-AI marker to the findings
        findings = _ensure_bis_ai_marker(
            f"ESCALATED TO HUMAN REVIEW\n\n{arguments.findings.strip()}"
        )

        # Resolve the Investigating picklist IRI
        try:
            investigating_iri = await FortiSOARResolveAlertTool._get_picklist_iri(
                config, "AlertStatus", "Investigating"
            )
        except RuntimeError as exc:
            return ToolResult(
                output=f"FortiSOAR picklist lookup failed: {exc}",
                is_error=True,
            )

        # PUT: set status to Investigating + write findings as description update
        # We write to closureNotes even though the alert isn't closed — this field
        # is the most visible place for an analyst opening the alert in the UI.
        alert_uuid = alert.get("uuid")
        payload: dict[str, Any] = {
            "status": investigating_iri,
            "closureNotes": findings,
        }
        endpoint = f"/api/3/alerts/{alert_uuid}"
        try:
            updated = await fsr_put(config, endpoint, payload)
        except RuntimeError as exc:
            return ToolResult(
                output=f"FortiSOAR update failed: {exc}",
                is_error=True,
            )

        new_status = _get_status(updated) or "?"

        lines = [
            f"=== Alert-{alert.get('id')} escalated to human review ===",
            f"uuid: {alert_uuid}",
            f"name: {alert.get('name','')[:100]}",
            f"previous_status: {current_status}",
            f"new_status: {new_status}",
            f"findings written to FortiSOAR closureNotes for analyst review.",
        ]
        return ToolResult(output="\n".join(lines))


def _get_status(alert: dict) -> str | None:
    status_obj = alert.get("status")
    if isinstance(status_obj, dict):
        return status_obj.get("itemValue")
    return None
