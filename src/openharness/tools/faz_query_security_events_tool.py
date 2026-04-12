"""Query FortiAnalyzer security events (attack, virus, webfilter, dlp, app-ctrl, anomaly)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from openharness.tools._faz_helpers import (
    build_time_range,
    faz_log_search,
    get_faz_config,
    validate_adom,
)
from openharness.tools.base import BaseTool, ToolExecutionContext, ToolResult


# Maximum time window per query is 10 minutes to limit load on FortiAnalyzer
# and the LLM context. The agent must run multiple queries to cover longer windows.
_TIME_RANGE_MINUTES = {
    "1m": 1,
    "5m": 5,
    "10m": 10,
}

# All security log types that FortiAnalyzer exposes for FortiGate
_SECURITY_LOG_TYPES = ("attack", "virus", "webfilter", "dlp", "app-ctrl", "anomaly")


class FAZQuerySecurityEventsInput(BaseModel):
    """Arguments for querying FortiAnalyzer security events."""

    adom: str = Field(
        default="",
        description=(
            "ADOM (Administrative Domain) to query. REQUIRED — if you do not know which "
            "ADOM to use, call faz_list_adoms first or use ask_user_question to confirm "
            "with the user. Do NOT guess. Do NOT use 'all' or wildcards."
        ),
    )
    time_range: str = Field(
        default="10m",
        description=(
            "Time window duration. Maximum is 10 minutes per query to keep FortiAnalyzer "
            "load manageable. Allowed values: '1m', '5m', '10m'. "
            "For longer windows, run multiple queries with different end_time anchors."
        ),
    )
    end_time: str = Field(
        default="",
        description=(
            "Optional anchor for the end of the time window, in FortiAnalyzer LOCAL time. "
            "Accepts 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DDTHH:MM:SS'. If empty, defaults to "
            "now. Use this to query AROUND a historical alert: e.g., set end_time to N "
            "minutes after the alert detection time to see the events around the incident."
        ),
    )
    log_type: str = Field(
        default="all",
        description=(
            "Security log type to query. Use 'all' to query every type and get a summary, "
            "or one of: 'attack' (IPS/IDS), 'virus' (antivirus), 'webfilter' (URL filtering), "
            "'dlp' (data loss prevention), 'app-ctrl' (application control), 'anomaly' (traffic anomalies)."
        ),
    )
    device: str = Field(
        default="All_FortiGate",
        description=(
            "FortiGate device name. Leave as the default 'All_FortiGate' in almost every "
            "case — it queries every device in the ADOM in a single call. Do NOT iterate "
            "over individual devices to be 'thorough': it's slower, wasteful, and produces "
            "the same answer. Only specify a single device name when you have a concrete "
            "reason to scope to one box."
        ),
    )
    limit_per_type: int = Field(
        default=20, ge=1, le=50,
        description=(
            "Maximum entries to return per log type. HARD CAP of 50 — the tool's "
            "output is aggregated stats only (counts, top events, top sources), so "
            "the per-entry cap mostly affects accuracy of the aggregation, not the "
            "output size. Default 20 is fine for triage."
        ),
    )


class FAZQuerySecurityEventsTool(BaseTool):
    """Query FortiAnalyzer for security events across multiple log types."""

    name = "faz_query_security_events"
    description = (
        "Query FortiAnalyzer security events: IPS attacks, virus detections, webfilter blocks, "
        "DLP violations, app control events, and traffic anomalies. Returns a structured summary "
        "with counts per log type and the most recent events. Use this when the user asks about "
        "'security logs', 'threats', 'attacks', 'blocked URLs', or 'security events'. "
        "This does NOT require an IP address — it returns all security events in the time range. "
        "REQUIRES the adom parameter — call faz_list_adoms first if unsure, "
        "or use ask_user_question to confirm with the user."
    )
    input_model = FAZQuerySecurityEventsInput

    def is_read_only(self, arguments: FAZQuerySecurityEventsInput) -> bool:
        return True

    async def execute(
        self, arguments: FAZQuerySecurityEventsInput, context: ToolExecutionContext
    ) -> ToolResult:
        # Validate ADOM
        ok, err = validate_adom(arguments.adom)
        if not ok:
            return ToolResult(output=err, is_error=True)

        minutes = _TIME_RANGE_MINUTES.get(arguments.time_range)
        if minutes is None:
            return ToolResult(
                output=(
                    f"Invalid time_range: '{arguments.time_range}'. "
                    f"Maximum is 10 minutes per query. Allowed values: "
                    f"{', '.join(_TIME_RANGE_MINUTES.keys())}. "
                    f"For longer windows, run multiple queries."
                ),
                is_error=True,
            )

        if arguments.log_type != "all" and arguments.log_type not in _SECURITY_LOG_TYPES:
            return ToolResult(
                output=(
                    f"Invalid log_type: '{arguments.log_type}'. "
                    f"Use 'all' or one of: {', '.join(_SECURITY_LOG_TYPES)}"
                ),
                is_error=True,
            )

        try:
            config = get_faz_config()
        except ValueError as exc:
            return ToolResult(output=str(exc), is_error=True)

        try:
            time_range = build_time_range(arguments.end_time, minutes)
        except ValueError as exc:
            return ToolResult(
                output=f"Invalid end_time: {exc}",
                is_error=True,
            )

        # Determine which log types to query
        types_to_query = _SECURITY_LOG_TYPES if arguments.log_type == "all" else (arguments.log_type,)

        # Query each type sequentially (FAZ doesn't like too many parallel searches)
        results_by_type: dict[str, dict[str, Any]] = {}
        errors_by_type: dict[str, str] = {}

        for logtype in types_to_query:
            try:
                result = await faz_log_search(
                    config,
                    device=arguments.device,
                    adom=arguments.adom,
                    logtype=logtype,
                    time_range=time_range,
                    limit=arguments.limit_per_type,
                )
                results_by_type[logtype] = result
            except RuntimeError as exc:
                errors_by_type[logtype] = str(exc)
            except Exception as exc:
                errors_by_type[logtype] = f"unexpected: {exc}"

        # Format output
        window = f"{time_range['start']} → {time_range['end']}"
        lines = [
            f"FortiAnalyzer security events in ADOM '{arguments.adom}' on {arguments.device}",
            f"window: {window} ({arguments.time_range})",
            "",
            "=== COUNTS BY LOG TYPE ===",
        ]

        total_events = 0
        for logtype in types_to_query:
            if logtype in errors_by_type:
                lines.append(f"  {logtype:12s}: ERROR ({errors_by_type[logtype]})")
            else:
                count = results_by_type[logtype].get("total-count", 0)
                total_events += count
                lines.append(f"  {logtype:12s}: {count}")

        lines.append(f"  {'TOTAL':12s}: {total_events}")

        # For each log type with events, show STRUCTURED stats only — no raw "recent" entries.
        # Smaller models collapse on long lists of raw entries; the aggregated stats
        # (actions, top events, top sources) carry all the information needed for triage.
        for logtype in types_to_query:
            if logtype in errors_by_type:
                continue
            result = results_by_type[logtype]
            entries = result.get("data", [])
            count = result.get("total-count", 0)
            if count == 0:
                continue

            lines.extend([
                "",
                f"=== {logtype.upper()} ({count} total events) ===",
            ])

            # Aggregate by action, source IP, and event name (attack/virus/hostname/app)
            actions: dict[str, int] = {}
            src_ips: dict[str, int] = {}
            event_names: dict[str, int] = {}

            for entry in entries:
                action = str(entry.get("action", "?"))
                actions[action] = actions.get(action, 0) + 1
                srcip = str(entry.get("srcip", "?"))
                if srcip != "?":
                    src_ips[srcip] = src_ips.get(srcip, 0) + 1
                name = (
                    entry.get("attack")
                    or entry.get("virus")
                    or entry.get("hostname")
                    or entry.get("app")
                    or ""
                )
                if name:
                    event_names[str(name)] = event_names.get(str(name), 0) + 1

            if actions:
                lines.append(f"  actions: {actions}")
            if event_names:
                top_names = sorted(event_names.items(), key=lambda x: -x[1])[:5]
                lines.append(f"  top_events: {[f'{n}({c})' for n,c in top_names]}")
            if src_ips:
                top_src = sorted(src_ips.items(), key=lambda x: -x[1])[:5]
                lines.append(f"  top_src_ips: {[f'{ip}({c})' for ip,c in top_src]}")

        if total_events == 0 and not errors_by_type:
            lines.append("")
            lines.append("No security events found in this time range.")

        return ToolResult(output="\n".join(lines))
