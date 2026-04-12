"""Fetch full details of a FortiSOAR alert."""

from __future__ import annotations

import ast
import html
import json
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field

from openharness.tools._fortisoar_helpers import fsr_get, get_fsr_config
from openharness.tools._whitelist import (
    Whitelist,
    WhitelistMatch,
    auto_close_alert,
    load_whitelist,
)
from openharness.tools.base import BaseTool, ToolExecutionContext, ToolResult

# Closer identifier baked into the audit trail when this tool auto-closes a
# whitelisted alert. Distinct from `soc-auto-close v0.1` (the standalone CLI)
# so the closure_notes show which code path actually wrote the close.
_GET_ALERT_CLOSER_VERSION = "fortisoar_get_alert auto-close v0.1"


_ALERT_DISPLAY_ID_RE = re.compile(r"^Alert[- ]?(\d+)$", re.IGNORECASE)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

# FortiAnalyzer is in Pacific time. Use IANA name so DST switches automatically
# (PDT in summer, PST in winter). Hardcoded per user instruction; if you ever
# need to support a non-Pacific FAZ, expose this as an env var.
_FAZ_TZ = ZoneInfo("America/Los_Angeles")


def _fmt_epoch(value) -> str:
    """Format an epoch as 'YYYY-MM-DD HH:MM:SS' in local time. Used for display fields."""
    if value in (None, "", 0):
        return ""
    try:
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return str(value)


def _epoch_to_faz_local(value) -> str:
    """Convert a UTC epoch to FAZ local time string 'YYYY-MM-DD HH:MM:SS'.

    Used to construct end_time values for FAZ queries. Returns empty string on
    invalid input.
    """
    if value in (None, "", 0):
        return ""
    try:
        epoch = float(value)
    except (ValueError, TypeError):
        return ""
    try:
        return (
            datetime.fromtimestamp(epoch, tz=timezone.utc)
            .astimezone(_FAZ_TZ)
            .strftime("%Y-%m-%d %H:%M:%S")
        )
    except (OSError, OverflowError):
        return ""


def _add_minutes(faz_local_str: str, minutes: int) -> str:
    """Return a FAZ local time string offset by N minutes. Empty on failure."""
    if not faz_local_str:
        return ""
    try:
        dt = datetime.strptime(faz_local_str, "%Y-%m-%d %H:%M:%S")
        return (dt + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ""


def _strip_html(text: str) -> str:
    """Remove HTML tags and decode entities from a string."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _get_picklist_value(value, key: str = "itemValue") -> str:
    if isinstance(value, dict):
        return str(value.get(key, "?"))
    if value is None:
        return "-"
    return str(value)


def _split_csv(value) -> list[str]:
    """Split a comma-separated string into trimmed values. Returns [] on empty."""
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(",") if v.strip()]


def _extract_adom_vdom_from_description(description_stripped: str) -> tuple[str, str]:
    """Best-effort extraction of (adom, vdom) from the description text.

    Looks for the pattern 'ADOM/vdom <name>/<vdom>' or variations. Returns
    empty strings on failure.
    """
    if not description_stripped:
        return "", ""
    # Tolerate variations: 'ADOM/vdom XXX/YYY', 'ADOM XXX/YYY', etc.
    m = re.search(
        r"ADOM(?:/vdom)?\s+([A-Za-z0-9_\-]+)(?:/([A-Za-z0-9_\-]+))?",
        description_stripped,
    )
    if not m:
        return "", ""
    return m.group(1) or "", m.group(2) or ""


def _extract_action_from_extrainfo(extrainfo) -> str:
    """Pull ACTION:<value> from a FortiSOAR extrainfo string."""
    if not extrainfo:
        return ""
    m = re.search(r"ACTION\s*[:=]\s*([A-Za-z_]+)", str(extrainfo))
    return m.group(1) if m else ""


def _build_correlation_hints(alert: dict) -> dict:
    """Best-effort extraction of fields useful for FAZ correlation queries.

    Pulls from structured fields first, falls back to parsing the description
    and sourcedata. Never raises — missing fields are simply omitted.
    """
    hints: dict = {}

    # Sourcedata may be a JSON string OR an already-parsed dict
    sourcedata = alert.get("sourcedata")
    if isinstance(sourcedata, str):
        try:
            sourcedata = json.loads(sourcedata)
        except (ValueError, TypeError):
            sourcedata = {}
    if not isinstance(sourcedata, dict):
        sourcedata = {}

    sd_alert = sourcedata.get("Alert", {}) if isinstance(sourcedata.get("Alert"), dict) else {}
    related_logs = sourcedata.get("Related Logs") or []
    first_log = related_logs[0] if isinstance(related_logs, list) and related_logs else {}
    if not isinstance(first_log, dict):
        first_log = {}

    description = _strip_html(alert.get("description") or "")

    # ADOM — try structured fields first, then parse description
    adom = (
        alert.get("aDOM")
        or sd_alert.get("adom")
        or _extract_adom_vdom_from_description(description)[0]
    )
    if adom:
        hints["adom"] = str(adom)

    # vdom — only available in description or sourcedata
    vdom = (
        sd_alert.get("vdom")
        or _extract_adom_vdom_from_description(description)[1]
    )
    if vdom:
        hints["vdom"] = str(vdom)

    # Device info
    device_name = alert.get("deviceName") or sd_alert.get("devname")
    if device_name:
        hints["device_name"] = str(device_name)
    # deviceType on the alert is a Picklist dict; sourcedata.devtype is a plain string
    device_type_raw = alert.get("deviceType")
    if isinstance(device_type_raw, dict):
        device_type = device_type_raw.get("itemValue", "")
    else:
        device_type = device_type_raw or sd_alert.get("devtype")
    if device_type:
        hints["device_type"] = str(device_type)

    # Event type / log type
    event_type = sd_alert.get("eventtype") or sd_alert.get("logtype")
    if event_type:
        hints["event_type"] = str(event_type)

    # IPs (split CSV; FortiSOAR sometimes packs multiple)
    src_ips = _split_csv(alert.get("sourceIp") or sd_alert.get("epip"))
    if src_ips:
        hints["source_ips"] = src_ips
    dst_ips = _split_csv(alert.get("destinationIp") or sd_alert.get("dstepip"))
    if dst_ips:
        hints["destination_ips"] = dst_ips

    # Ports — try structured first, then first related log
    src_port = alert.get("sourcePort") or first_log.get("srcport")
    if src_port not in (None, "", "-"):
        hints["source_port"] = str(src_port)
    dst_port = alert.get("destinationPort") or first_log.get("dstport")
    if dst_port not in (None, "", "-"):
        hints["destination_port"] = str(dst_port)

    # Action — try extrainfo, then first related log
    action = _extract_action_from_extrainfo(sd_alert.get("extrainfo")) or first_log.get("action")
    if action:
        hints["action"] = str(action)

    # Detection time — most reliable: alertDetectionDate (UTC epoch). Fall back to
    # lastSeen, alerttime in sourcedata, or createDate.
    detection_epoch = (
        alert.get("alertDetectionDate")
        or alert.get("lastSeen")
        or sd_alert.get("alerttime")
        or sd_alert.get("firstlogtime")
        or alert.get("createDate")
    )
    detection_time_faz = _epoch_to_faz_local(detection_epoch)
    if detection_time_faz:
        hints["detection_time_faz_local"] = detection_time_faz
        plus10 = _add_minutes(detection_time_faz, 10)
        if plus10:
            hints["detection_time_plus_10m"] = plus10

    # Indicators block (FortiAnalyzer Indicators is a python-repr style list)
    # Worth surfacing if structured fields above are sparse.
    indicator_match = re.search(
        r"FortiAnalyzer Indicators\s+(\[.+?\])(?:\s*$|\s+\w)",
        description,
        re.DOTALL,
    )
    if indicator_match:
        try:
            parsed = ast.literal_eval(indicator_match.group(1))
            if isinstance(parsed, list):
                indicator_summary = []
                for ind in parsed:
                    if isinstance(ind, dict):
                        name = ind.get("name", "?")
                        vals = ind.get("value", [])
                        indicator_summary.append(f"{name}={vals}")
                if indicator_summary:
                    hints["indicators"] = indicator_summary
        except (ValueError, SyntaxError):
            pass  # raw description still includes it; LLM can fall back

    return hints


def _format_correlation_hints(hints: dict) -> str:
    """Format the correlation-hints section of the alert output. Returns empty
    string if there's nothing useful to show.
    """
    if not hints:
        return ""

    lines = ["", "--- correlation hints ---"]

    # Plain key-value section
    field_order = (
        "adom",
        "vdom",
        "device_name",
        "device_type",
        "event_type",
        "source_ips",
        "source_port",
        "destination_ips",
        "destination_port",
        "action",
        "detection_time_faz_local",
        "detection_time_plus_10m",
        "indicators",
    )
    for key in field_order:
        if key in hints:
            value = hints[key]
            if isinstance(value, list):
                value = ", ".join(value)
            lines.append(f"{key}: {value}")

    # Suggested correlation queries — only if we have ADOM + at least one IP + detection time
    adom = hints.get("adom", "")
    src_ips = hints.get("source_ips", [])
    dst_ips = hints.get("destination_ips", [])
    detection = hints.get("detection_time_faz_local", "")
    plus10 = hints.get("detection_time_plus_10m", "")

    if adom and (src_ips or dst_ips) and detection and plus10:
        lines.append("")
        lines.append("suggested_correlation_queries:")
        lines.append("  # Step 1: All security events 10 min after the event")
        lines.append(
            f'  faz_query_security_events(adom="{adom}", end_time="{plus10}", '
            f'time_range="10m", log_type="all")'
        )
        if src_ips:
            src = src_ips[0]
            lines.append("")
            lines.append("  # Step 2: Source IP traffic 10 min AFTER — did the source come back?")
            lines.append(
                f'  faz_query_logs(adom="{adom}", ip_address="{src}", '
                f'end_time="{plus10}", time_range="10m")'
            )
            lines.append("")
            lines.append("  # Step 3: Source IP traffic 10 min BEFORE — was there reconnaissance?")
            lines.append(
                f'  faz_query_logs(adom="{adom}", ip_address="{src}", '
                f'end_time="{detection}", time_range="10m")'
            )
        if dst_ips:
            dst = dst_ips[0]
            lines.append("")
            lines.append("  # Step 4: Destination IP traffic 10 min AFTER — lateral movement check")
            lines.append(
                f'  faz_query_logs(adom="{adom}", ip_address="{dst}", '
                f'end_time="{plus10}", time_range="10m")'
            )

    return "\n".join(lines)


class FortiSOARGetAlertInput(BaseModel):
    """Arguments for fetching a single FortiSOAR alert."""

    alert_id: str = Field(
        description=(
            "Alert identifier. Accepts three formats: "
            "1) Display ID like 'Alert-108160' (recommended — this is what the UI shows). "
            "2) Bare numeric ID like '108160'. "
            "3) Full UUID like '8d6aca33-a9c1-4338-b4c1-98beaf831982'. "
            "Get IDs from fortisoar_list_alerts."
        )
    )


class FortiSOARGetAlertTool(BaseTool):
    """Fetch full details of a single FortiSOAR alert by ID."""

    name = "fortisoar_get_alert"
    description = (
        "Fetch the full details of a single FortiSOAR alert: description, source/destination, "
        "IOCs, MITRE ATT&CK info, raw source data, timestamps, SLA, tenant, assignee, and more. "
        "Use this after fortisoar_list_alerts to investigate a specific alert. "
        "Accepts 'Alert-108160', '108160', or a UUID."
    )
    input_model = FortiSOARGetAlertInput

    def is_read_only(self, arguments: FortiSOARGetAlertInput) -> bool:
        return True

    async def execute(
        self, arguments: FortiSOARGetAlertInput, context: ToolExecutionContext
    ) -> ToolResult:
        try:
            config = get_fsr_config()
        except ValueError as exc:
            return ToolResult(output=str(exc), is_error=True)

        raw_id = arguments.alert_id.strip()

        # Normalize the ID — accept Alert-NNN, NNN, or UUID
        endpoint = self._build_lookup_endpoint(raw_id)
        if endpoint is None:
            return ToolResult(
                output=(
                    f"Invalid alert_id '{raw_id}'. "
                    "Use 'Alert-108160', '108160', or a UUID from fortisoar_list_alerts."
                ),
                is_error=True,
            )

        try:
            data = await fsr_get(config, endpoint)
        except RuntimeError as exc:
            return ToolResult(output=f"FortiSOAR error: {exc}", is_error=True)

        # Find the alert — direct fetch returns the object; query returns hydra:member
        if "hydra:member" in data:
            members = data.get("hydra:member", [])
            if not members:
                return ToolResult(
                    output=f"Alert '{raw_id}' not found in FortiSOAR.",
                    is_error=True,
                )
            alert = members[0]
        elif data.get("@type") == "Alert" or "uuid" in data:
            alert = data
        else:
            return ToolResult(
                output=f"Unexpected FortiSOAR response for '{raw_id}': {str(data)[:200]}",
                is_error=True,
            )

        # Enforce tenant scoping if configured
        configured_tenant = config.get("tenant", "")
        if configured_tenant:
            alert_tenant_obj = alert.get("tenant") or {}
            alert_tenant = (
                alert_tenant_obj.get("name", "") if isinstance(alert_tenant_obj, dict) else ""
            )
            if alert_tenant != configured_tenant:
                return ToolResult(
                    output=(
                        f"Access denied: Alert-{alert.get('id','?')} belongs to tenant "
                        f"'{alert_tenant or 'unknown'}', but this agent is scoped to "
                        f"tenant '{configured_tenant}'. You cannot investigate alerts "
                        f"from other tenants."
                    ),
                    is_error=True,
                )

        # Enforce source scoping if configured. Different alert sources need different
        # SOC playbooks; the agent has only been validated against the configured source.
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
                        f"source '{configured_source}'. The SOC playbook for this source "
                        f"has not been validated for other sources. Investigate manually "
                        f"or escalate to a human analyst."
                    ),
                    is_error=True,
                )

        # ----------------------------------------------------------------
        # Whitelist auto-close path
        # ----------------------------------------------------------------
        # If the alert's source IP matches the SOC whitelist, close the alert
        # IMMEDIATELY and return a data-starved STOP message to the LLM.
        #
        # Why this lives inside get_alert (not in a separate tool):
        #   1. The LLM is already invoked by the time this tool runs, so we
        #      cannot achieve a TRUE bypass from in here. The best we can do
        #      is shorten the LLM's life inside the loop and starve it of
        #      investigation data so it has nothing to feed the FAZ tools with.
        #   2. The whitelist file is the human-curated, git-reviewed source of
        #      truth (see memory feedback_whitelist_bypass_llm.md). Per-IP
        #      approval already happened when the entry was added; no runtime
        #      permission prompt is needed. The tool stays is_read_only=True
        #      because the whitelist file IS the approval contract.
        #   3. Skipping when the alert is already Closed is critical — we must
        #      not double-close, and we must not return a STOP message for an
        #      alert that the human has already closed manually.
        current_status_obj = alert.get("status")
        current_status = (
            current_status_obj.get("itemValue")
            if isinstance(current_status_obj, dict)
            else None
        )
        if current_status != "Closed":
            stop_result = await self._maybe_auto_close_via_whitelist(config, alert)
            if stop_result is not None:
                return stop_result

        return ToolResult(output=self._format_alert(alert))

    async def _maybe_auto_close_via_whitelist(
        self, config: dict, alert: dict
    ) -> ToolResult | None:
        """If the alert's source IP matches the whitelist, auto-close it and
        return a data-starved STOP message. Otherwise return None so the caller
        falls through to the normal compact alert format.

        On whitelist file load errors we deliberately fall through (return None)
        rather than failing the get_alert call. The investigation flow should
        still work even if the whitelist file is broken — the worst case is
        "no auto-close happens", which is the same as having no whitelist.
        """
        src_ip = alert.get("sourceIp")
        if not src_ip:
            return None

        try:
            whitelist = load_whitelist()
        except (FileNotFoundError, ValueError):
            # Whitelist file unreadable or malformed — fall through to normal
            # investigation flow rather than blocking the user. A future
            # improvement could log this somewhere visible, but we don't want
            # a typo in the YAML to wedge every get_alert call.
            return None

        if not whitelist.entries:
            return None

        match = whitelist.lookup_ip(str(src_ip))
        if match is None:
            return None

        # Hit. Do the close synchronously. If the close fails, surface the
        # error so the operator sees it instead of silently falling through —
        # this is the only branch where the tool actually mutates state, so
        # failures here are operationally important.
        try:
            await auto_close_alert(
                config, alert, match, whitelist, _GET_ALERT_CLOSER_VERSION
            )
        except RuntimeError as exc:
            return ToolResult(
                output=(
                    f"Whitelist matched Alert-{alert.get('id','?')} "
                    f"({match.entry.selector}) but auto-close failed: {exc}. "
                    f"The alert remains in its previous state; please investigate "
                    f"the FortiSOAR API error and retry, or close manually."
                ),
                is_error=True,
            )

        return ToolResult(output=self._format_auto_close_stop(alert, match))

    @staticmethod
    def _format_auto_close_stop(alert: dict, match: WhitelistMatch) -> str:
        """Build the data-starved STOP message returned to the LLM on auto-close.

        DELIBERATELY OMITTED:
          - source_ip, destination_ip, ports
          - ADOM, device, detection_time
          - any structured field the model could feed to a FAZ correlation tool
          - the full closure_notes audit trail (it's already in FortiSOAR for
            human review; the LLM does not need to see it)

        The defense here is *literal data starvation*: with no IPs/ADOMs/times
        in the response, the model has no inputs to call faz_query_logs or
        faz_query_security_events with. The empirical baseline (Gemma4 obeying
        '0 results = stop' rules without contrary data) suggests this is the
        strongest cheap defense against the model freelancing past the stop.
        """
        alert_id = alert.get("id", "?")
        return (
            f"=== Alert-{alert_id} AUTO-CLOSED BY WHITELIST POLICY ===\n"
            f"\n"
            f"This alert has been closed by the SOC whitelist. There is "
            f"nothing further to investigate. The audit trail (alert facts, "
            f"whitelist match details, and provenance) has been written to "
            f"the FortiSOAR closureNotes for human review.\n"
            f"\n"
            f"Whitelist match reason: {match.entry.reason}\n"
            f"\n"
            f"YOU HAVE NO MORE WORK TO DO. Output ONE short sentence "
            f"confirming the auto-closure (for example: \"Alert-{alert_id} "
            f"was auto-closed by whitelist policy.\") and STOP. Do NOT call "
            f"any FAZ tools. Do NOT call fortisoar_resolve_alert. The alert "
            f"is final."
        )

    @staticmethod
    def _build_lookup_endpoint(raw_id: str) -> str | None:
        """Decide which FortiSOAR endpoint to hit based on the ID format."""
        if _UUID_RE.match(raw_id):
            return f"/api/3/alerts/{raw_id}"
        m = _ALERT_DISPLAY_ID_RE.match(raw_id)
        if m:
            return f"/api/3/alerts?id={m.group(1)}&$limit=1"
        if raw_id.isdigit():
            return f"/api/3/alerts?id={raw_id}&$limit=1"
        return None

    @staticmethod
    def _format_alert(alert: dict) -> str:
        """Produce a compact, LLM-friendly summary of an alert.

        The output is deliberately short — empty/irrelevant fields are dropped
        entirely to keep the payload digestible for smaller models. Correlation
        hints (the most important section for the SOC workflow) appear FIRST so
        the model sees them before getting tired.
        """
        alert_id = alert.get("id", "?")
        name = (alert.get("name", "") or "").strip()
        status = _get_picklist_value(alert.get("status"))
        severity = _get_picklist_value(alert.get("severity"))
        atype = _get_picklist_value(alert.get("type"))
        tenant = _get_picklist_value(alert.get("tenant"), key="name")
        source_tool = alert.get("source") or alert.get("sourceType") or "-"

        lines = [
            f"=== FortiSOAR Alert-{alert_id}: {name[:120]} ===",
            f"status={status}  severity={severity}  type={atype}  tenant={tenant}  source_tool={source_tool}",
        ]

        # CORRELATION HINTS FIRST — this is what the model needs to act on.
        hints = _build_correlation_hints(alert)
        hints_section = _format_correlation_hints(hints)
        if hints_section:
            lines.append(hints_section)

        # Closure notes if the alert is already closed (rare path, but useful info)
        if alert.get("closureNotes"):
            lines.extend([
                "",
                "--- closure (already closed) ---",
                f"closure_reason: {_get_picklist_value(alert.get('closureReason'))}",
                f"closure_notes: {str(alert.get('closureNotes'))[:300]}",
            ])

        # Compact description — only if it has unique info beyond the correlation hints.
        # Trim to 600 chars to give the model context without overwhelming it.
        description = _strip_html(alert.get("description") or "")
        if description:
            lines.extend([
                "",
                "--- description (raw alert text from source tool) ---",
                description[:600] + ("..." if len(description) > 600 else ""),
            ])

        return "\n".join(lines)
