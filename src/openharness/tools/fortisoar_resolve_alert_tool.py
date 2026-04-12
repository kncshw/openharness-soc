"""Resolve (close) a FortiSOAR alert with closure notes and reason."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from openharness.tools._fortisoar_helpers import fsr_get, fsr_put, get_fsr_config
from openharness.tools.base import BaseTool, ToolExecutionContext, ToolResult


def _ensure_bis_ai_marker(notes: str) -> str:
    """Idempotently prepend the BIS-AI triage marker to closure notes.

    The marker identifies AI-triaged closures so a human reviewing the alert
    in FortiSOAR can immediately tell the closure was bot-driven. Idempotent:
    if the notes already start with the marker (because the LLM copied it
    from the closure-notes template), return unchanged. Otherwise prepend.

    Empty/whitespace-only notes are returned unchanged so the caller's
    "notes too short" guard can still fire — we never want the marker to
    satisfy the minimum-length requirement on its own.

    Lazy import of the marker constant avoids a circular import: _whitelist.py
    is loaded BEFORE this module (because this module's _ALLOWED_CLOSURE_REASONS
    is imported by _whitelist at module-load time), so a top-level
    `from openharness.tools._whitelist import BIS_AI_TRIAGE_MARKER` would
    fail. Resolving the import inside the function delays it until call time.
    """
    from openharness.tools._whitelist import BIS_AI_TRIAGE_MARKER

    stripped = notes.strip()
    if not stripped:
        return notes
    if stripped.startswith(BIS_AI_TRIAGE_MARKER):
        return notes
    return f"{BIS_AI_TRIAGE_MARKER}\n\n{stripped}"


_ALERT_DISPLAY_ID_RE = re.compile(r"^Alert[- ]?(\d+)$", re.IGNORECASE)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

# Allowed closure reasons (subset of the FortiSOAR Closure Reason picklist).
# Picking a closure reason is subjective; we let the SOC agent choose from this
# list. If the model picks something not on the list, we silently substitute
# the safe default (_DEFAULT_CLOSURE_REASON) rather than erroring.
#
# 'False Positive' is intentionally NOT included — empirically the model
# over-uses it, and "the detection was wrong" is rarely the right call for
# this source. Use 'Risk Accept' or 'Tasks Completed' for authorized-but-real
# activity instead.
# 'Escalated to Incident' is also NOT included — escalation uses a different
# workflow than this resolve tool.
_ALLOWED_CLOSURE_REASONS = (
    "Resolved",
    "Duplicate",
    "Invalid",
    "Tasks Completed",
    "Risk Accept",
    "Monitor",
    "Exempt",
)

_DEFAULT_CLOSURE_REASON = "Tasks Completed"


class FortiSOARResolveAlertInput(BaseModel):
    """Arguments for closing a FortiSOAR alert."""

    alert_id: str = Field(
        description=(
            "Alert identifier. Accepts 'Alert-108160', '108160', or a UUID. "
            "Get IDs from fortisoar_list_alerts."
        )
    )
    closure_notes: str = Field(
        default="",
        description=(
            "Closure notes explaining why the alert is being closed. Include concrete "
            "evidence: source/destination IPs, action, FAZ correlation results, and "
            "your conclusion. If you call this tool with closure_notes empty or shorter "
            "than 20 characters, the tool will return a pre-built template you can copy "
            "and re-call with — so you do NOT need to write the notes from scratch."
        ),
    )
    closure_reason: str = Field(
        default=_DEFAULT_CLOSURE_REASON,
        description=(
            "Reason for closing the alert. Pick ONE from this exact list — anything "
            "outside the list is silently replaced with 'Tasks Completed':\n"
            "  - 'Tasks Completed': all follow-up tasks for this alert have been done. "
            "THIS IS THE DEFAULT — use it whenever the investigation finished cleanly "
            "and no other reason fits better.\n"
            "  - 'Risk Accept': the detection was CORRECT but the activity is authorized "
            "or expected (e.g., a known internal scanner, a sanctioned threat-intel "
            "collector like FortiRecon, an admin pen-test, an approved exception). "
            "Use this when the behavior is real but explicitly allowed.\n"
            "  - 'Resolved': the threat was real and has been remediated.\n"
            "  - 'Duplicate': another alert already covers this incident.\n"
            "  - 'Invalid': the alert data is malformed or incomplete.\n"
            "  - 'Monitor': not closing — keeping under observation.\n"
            "  - 'Exempt': this asset/user/source is exempt from this rule.\n"
            "Default: 'Tasks Completed'."
        ),
    )


class FortiSOARResolveAlertTool(BaseTool):
    """Close a FortiSOAR alert with closure notes and a reason. MUTATING."""

    name = "fortisoar_resolve_alert"
    description = (
        "Close a FortiSOAR alert. Sets status to 'Closed', sets closure_reason, "
        "and records closure_notes. MUTATING — the human will be prompted to approve.\n"
        "Arguments:\n"
        "  - alert_id (required, e.g. 'Alert-107596')\n"
        "  - closure_notes (optional — if missing, the tool returns a template you can "
        "copy and re-call with)\n"
        "  - closure_reason (defaults to 'Resolved')\n"
        "Workflow: call once with just alert_id to get a pre-built closure_notes template, "
        "then re-call with the template (modified if needed) as closure_notes. "
        "Tenant-scoped: only alerts in the configured tenant can be closed."
    )
    input_model = FortiSOARResolveAlertInput

    def is_read_only(self, arguments: FortiSOARResolveAlertInput) -> bool:
        # Mutating — triggers permission prompt in default mode
        return False

    async def execute(
        self, arguments: FortiSOARResolveAlertInput, context: ToolExecutionContext
    ) -> ToolResult:
        # Closure reason: subjective field. If the model picks something not on
        # the allowlist (including the deprecated 'False Positive'), silently
        # substitute the safe default rather than erroring. Tracked locally so
        # we can surface the substitution in the success output.
        requested_reason = arguments.closure_reason
        reason_substituted = False
        if requested_reason not in _ALLOWED_CLOSURE_REASONS:
            requested_reason = _DEFAULT_CLOSURE_REASON
            reason_substituted = True

        try:
            config = get_fsr_config()
        except ValueError as exc:
            return ToolResult(output=str(exc), is_error=True)

        raw_id = arguments.alert_id.strip()

        # Step 1: Look up the alert (we need it for tenant check, status check,
        # AND to build a closure-notes template if the model didn't provide one)
        try:
            alert = await self._lookup_alert(config, raw_id)
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
            alert_tenant_obj.get("name", "") if isinstance(alert_tenant_obj, dict) else ""
        )
        if alert_tenant != configured_tenant:
            return ToolResult(
                output=(
                    f"Access denied: Alert-{alert.get('id','?')} belongs to tenant "
                    f"'{alert_tenant or 'unknown'}', but this agent is scoped to "
                    f"tenant '{configured_tenant}'. You cannot close alerts from other tenants."
                ),
                is_error=True,
            )

        # Source scoping. Different alert sources need different SOC playbooks; the
        # agent has only been validated against the configured source. Refuse to close
        # alerts whose source has not been validated, no matter what the model says.
        configured_source = config.get("source", "")
        if configured_source:
            alert_source = alert.get("source") or ""
            if isinstance(alert_source, dict):
                alert_source = alert_source.get("name") or alert_source.get("itemValue") or ""
            if str(alert_source) != configured_source:
                return ToolResult(
                    output=(
                        f"Access denied: Alert-{alert.get('id','?')} has source "
                        f"'{alert_source or 'unknown'}', but this agent is scoped to "
                        f"source '{configured_source}'. The closure playbook for this "
                        f"source has not been validated. Refusing to close — escalate "
                        f"to a human analyst instead."
                    ),
                    is_error=True,
                )

        alert_uuid = alert.get("uuid")
        current_status = (alert.get("status") or {}).get("itemValue") if isinstance(alert.get("status"), dict) else None

        if current_status == "Closed":
            return ToolResult(
                output=(
                    f"Alert-{alert.get('id','?')} is already Closed. "
                    f"No action taken. Existing closure notes: "
                    f"{(alert.get('closureNotes') or '')[:200]}"
                ),
                is_error=True,
            )

        # Closure notes — if missing/short, build a template from the alert and
        # return it as an error. The model can then re-call with the template.
        notes = (arguments.closure_notes or "").strip()
        if len(notes) < 20:
            template = self._build_closure_notes_template(
                alert, requested_reason
            )
            return ToolResult(
                output=(
                    "closure_notes is missing or too short (minimum 20 characters of "
                    "real evidence). The tool has built a template from the alert "
                    "details for you. Re-call fortisoar_resolve_alert with the template "
                    "below as closure_notes (you can edit it to include findings from "
                    "your FAZ correlation queries):\n\n"
                    "--- COPY THIS TEMPLATE ---\n"
                    f'{template}\n'
                    "--- END TEMPLATE ---\n\n"
                    "Then call:\n"
                    f'  fortisoar_resolve_alert(alert_id="Alert-{alert.get("id","?")}", '
                    f'closure_reason="{requested_reason}", '
                    f'closure_notes="<the template above, with any edits>")'
                ),
                is_error=True,
            )

        # Step 2: Resolve picklist IRIs for status and closure reason.
        # We can construct the same picklist names by querying picklist_names by name.
        try:
            status_iri = await self._get_picklist_iri(
                config, "AlertStatus", "Closed"
            )
            reason_iri = await self._get_picklist_iri(
                config, "Closure Reason", requested_reason
            )
        except RuntimeError as exc:
            return ToolResult(output=f"FortiSOAR picklist lookup failed: {exc}", is_error=True)

        # Step 3: PUT update.
        # Prepend the BIS-AI marker to closure notes so a human reviewing the
        # alert in FortiSOAR can see at a glance that the closure was AI-driven.
        # Idempotent: if the LLM copied the marker from the template, no
        # double-prepend.
        final_notes = _ensure_bis_ai_marker(arguments.closure_notes)
        payload = {
            "status": status_iri,
            "closureReason": reason_iri,
            "closureNotes": final_notes,
        }

        endpoint = f"/api/3/alerts/{alert_uuid}"
        try:
            updated = await fsr_put(config, endpoint, payload)
        except RuntimeError as exc:
            return ToolResult(output=f"FortiSOAR update failed: {exc}", is_error=True)

        new_status = (updated.get("status") or {}).get("itemValue", "?") if isinstance(updated.get("status"), dict) else "?"
        new_reason = (updated.get("closureReason") or {}).get("itemValue", "?") if isinstance(updated.get("closureReason"), dict) else "?"

        lines = [
            f"=== Alert-{alert.get('id')} resolved ===",
            f"uuid: {alert_uuid}",
            f"name: {alert.get('name','')[:100]}",
            f"previous_status: {current_status}",
            f"new_status: {new_status}",
            f"closure_reason: {new_reason}",
        ]
        if reason_substituted:
            lines.append(
                f"note: requested closure_reason '{arguments.closure_reason}' is not "
                f"in the allowed list; substituted '{_DEFAULT_CLOSURE_REASON}'."
            )
        lines.append(f"closure_notes: {final_notes[:500]}")
        return ToolResult(output="\n".join(lines))

    @staticmethod
    def _build_closure_notes_template(alert: dict, closure_reason: str) -> str:
        """Build a copy-pasteable closure notes template from the alert's structured fields.

        Used when the LLM forgets to include closure_notes — we generate a sensible
        template that the model can copy verbatim or edit, then re-call the tool.
        """
        alert_id = alert.get("id", "?")
        name = str(alert.get("name", ""))[:120]
        src_ip = alert.get("sourceIp") or "-"
        dst_ip = alert.get("destinationIp") or "-"
        dst_port = alert.get("destinationPort") or "-"
        device = alert.get("deviceName") or "-"
        adom = alert.get("aDOM") or "-"
        severity = ""
        sev_obj = alert.get("severity")
        if isinstance(sev_obj, dict):
            severity = sev_obj.get("itemValue", "")

        # Try to get the action from sourcedata.Alert.extrainfo
        sourcedata = alert.get("sourcedata")
        action = ""
        if isinstance(sourcedata, str):
            try:
                import json as _json
                sourcedata = _json.loads(sourcedata)
            except (ValueError, TypeError):
                sourcedata = {}
        if isinstance(sourcedata, dict):
            sd_alert = sourcedata.get("Alert", {})
            if isinstance(sd_alert, dict):
                extrainfo = sd_alert.get("extrainfo") or ""
                m = re.search(r"ACTION\s*[:=]\s*([A-Za-z_]+)", str(extrainfo))
                if m:
                    action = m.group(1)
                if not action:
                    related = sourcedata.get("Related Logs") or []
                    if isinstance(related, list) and related and isinstance(related[0], dict):
                        action = str(related[0].get("action", ""))

        # Build the template
        parts = [
            f"Investigated Alert-{alert_id} ({name}).",
            f"Source IP: {src_ip}; Destination: {dst_ip}:{dst_port}; Device: {device}; ADOM: {adom}; Severity: {severity}.",
        ]
        if action:
            parts.append(f"FortiGate action on the original event: {action}.")
        parts.append(
            "FAZ correlation queries (run via faz_query_security_events and "
            "faz_query_logs ±10 min around the event time): replace this sentence "
            "with the actual counts you observed (e.g., '0 attack events, 0 source "
            "traffic before, 0 source traffic after, 0 destination follow-up')."
        )
        parts.append(
            f"Conclusion: closing as {closure_reason} based on the investigation above. "
            "Replace this sentence with your specific reasoning if you have additional context."
        )
        # Prepend the BIS-AI marker. The tool also enforces this on the PUT path
        # (idempotently), but including it in the template lets the LLM see the
        # convention and copy it verbatim. Lazy import to avoid the circular
        # dep with _whitelist (see _ensure_bis_ai_marker above).
        from openharness.tools._whitelist import BIS_AI_TRIAGE_MARKER

        return f"{BIS_AI_TRIAGE_MARKER}\n\n{' '.join(parts)}"

    @staticmethod
    async def _lookup_alert(config: dict, raw_id: str) -> dict | None:
        """Look up an alert by display ID, numeric ID, or UUID. Returns dict or None."""
        if _UUID_RE.match(raw_id):
            data = await fsr_get(config, f"/api/3/alerts/{raw_id}")
            return data if data and ("uuid" in data or data.get("@type") == "Alert") else None
        m = _ALERT_DISPLAY_ID_RE.match(raw_id)
        numeric = m.group(1) if m else (raw_id if raw_id.isdigit() else None)
        if numeric is None:
            raise RuntimeError(
                f"Invalid alert_id '{raw_id}'. Use Alert-NNN, NNN, or a UUID."
            )
        data = await fsr_get(config, f"/api/3/alerts?id={numeric}&$limit=1")
        members = data.get("hydra:member", [])
        return members[0] if members else None

    @staticmethod
    async def _get_picklist_iri(
        config: dict, picklist_name: str, item_value: str
    ) -> str:
        """Resolve a picklist item's @id (IRI) by its parent picklist name and item value."""
        # Find the picklist_name parent
        data = await fsr_get(
            config, f"/api/3/picklist_names?name={picklist_name}&$limit=1"
        )
        members = data.get("hydra:member", [])
        if not members:
            raise RuntimeError(f"Picklist '{picklist_name}' not found in FortiSOAR.")
        parent = members[0]
        items = parent.get("picklists", [])
        for item in items:
            if item.get("itemValue") == item_value:
                return item["@id"]
        raise RuntimeError(
            f"Picklist '{picklist_name}' has no item '{item_value}'. "
            f"Available: {[i.get('itemValue') for i in items]}"
        )
