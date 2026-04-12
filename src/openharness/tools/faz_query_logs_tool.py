"""Query FortiAnalyzer traffic logs."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from openharness.tools._faz_helpers import (
    build_time_range,
    faz_log_search,
    get_faz_config,
    validate_adom,
)
from openharness.tools.base import BaseTool, ToolExecutionContext, ToolResult


_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Maximum time window per query is 10 minutes to limit load on FortiAnalyzer
# and the LLM context. The agent must run multiple queries to cover longer windows.
_TIME_RANGE_MINUTES = {
    "1m": 1,
    "5m": 5,
    "10m": 10,
}

_VALID_LOG_TYPES = ("traffic", "event")


class FAZQueryLogsInput(BaseModel):
    """Arguments for querying FortiAnalyzer traffic or event logs."""

    adom: str = Field(
        default="",
        description=(
            "ADOM (Administrative Domain) to query. REQUIRED — if you do not know which "
            "ADOM to use, call faz_list_adoms first or use ask_user_question to confirm "
            "with the user. Do NOT guess. Do NOT use 'all' or wildcards."
        ),
    )
    ip_address: str = Field(
        default="",
        description="Optional IP address filter. Leave empty to see all traffic. "
        "When set, matches both source and destination IP. Must be a valid IPv4 address.",
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
            "now. Use this to query AROUND a historical alert: set end_time to N minutes "
            "after the alert detection time, then run a second query with end_time set to "
            "the alert time itself to see what came BEFORE."
        ),
    )
    limit: int = Field(
        default=50, ge=1, le=50,
        description=(
            "Maximum log entries to return. HARD CAP of 50 — even noisy scanners "
            "produce too many entries in a 10-minute window for the model to reason "
            "over reliably. The 50-entry sample is enough to spot patterns; the "
            "tool's SUMMARY section already shows total counts and aggregated stats."
        ),
    )
    log_type: str = Field(
        default="traffic",
        description="Log type: 'traffic' (network sessions) or 'event' (system events)",
    )
    device: str = Field(
        default="All_FortiGate",
        description=(
            "FortiGate device name. Leave as the default 'All_FortiGate' in almost every "
            "case — it queries every device in the ADOM in a single call, which is what "
            "you want. Do NOT iterate over individual devices: it's slower, wasteful, and "
            "produces the same answer. Only specify a single device name when you have a "
            "concrete reason to scope to one box."
        ),
    )


class FAZQueryLogsTool(BaseTool):
    """Query FortiAnalyzer for traffic or event logs."""

    name = "faz_query_logs"
    description = (
        "Query FortiAnalyzer traffic logs (network sessions) or event logs (system events) "
        "within a specific ADOM. Use this to browse recent network activity, or filter to a "
        "specific IP address. For security incidents (IPS attacks, virus, webfilter blocks), "
        "use faz_query_security_events instead. "
        "REQUIRES the adom parameter — call faz_list_adoms first if unsure, "
        "or use ask_user_question to confirm with the user."
    )
    input_model = FAZQueryLogsInput

    def is_read_only(self, arguments: FAZQueryLogsInput) -> bool:
        return True

    async def execute(
        self, arguments: FAZQueryLogsInput, context: ToolExecutionContext
    ) -> ToolResult:
        # Validate ADOM
        ok, err = validate_adom(arguments.adom)
        if not ok:
            return ToolResult(output=err, is_error=True)

        # Validate IP if provided
        if arguments.ip_address and not _IP_PATTERN.match(arguments.ip_address):
            return ToolResult(
                output=(
                    f"Invalid IP address format: '{arguments.ip_address}'. "
                    f"Use a valid IPv4 address like '192.168.1.1', or leave empty to see all traffic."
                ),
                is_error=True,
            )

        if arguments.log_type not in _VALID_LOG_TYPES:
            return ToolResult(
                output=(
                    f"Invalid log_type: '{arguments.log_type}'. "
                    f"Use one of: {', '.join(_VALID_LOG_TYPES)}. "
                    f"For security events (attack/virus/webfilter/dlp), use faz_query_security_events."
                ),
                is_error=True,
            )

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

        try:
            config = get_faz_config()
        except ValueError as exc:
            return ToolResult(output=str(exc), is_error=True)

        # Build time range — defaults to "now" if end_time is empty
        try:
            time_range = build_time_range(arguments.end_time, minutes)
        except ValueError as exc:
            return ToolResult(
                output=f"Invalid end_time: {exc}",
                is_error=True,
            )

        # Filter: match srcip OR dstip if IP provided
        filter_expr = ""
        if arguments.ip_address:
            filter_expr = f"srcip=={arguments.ip_address} or dstip=={arguments.ip_address}"

        try:
            result = await faz_log_search(
                config,
                device=arguments.device,
                adom=arguments.adom,
                logtype=arguments.log_type,
                time_range=time_range,
                filter_expr=filter_expr,
                limit=arguments.limit,
            )
        except RuntimeError as exc:
            return ToolResult(output=f"FortiAnalyzer error: {exc}", is_error=True)
        except Exception as exc:
            return ToolResult(output=f"FortiAnalyzer request failed: {exc}", is_error=True)

        entries = result.get("data", [])
        total_count = result.get("total-count", len(entries))

        scope = f"IP {arguments.ip_address}" if arguments.ip_address else "all traffic"
        window = f"{time_range['start']} → {time_range['end']}"

        if not entries:
            return ToolResult(
                output=f"No {arguments.log_type} logs found in ADOM '{arguments.adom}' "
                f"for {scope} on {arguments.device} (window: {window})."
            )

        # First pass: aggregate stats from ALL entries (so summary numbers are accurate)
        dst_ips: dict[str, int] = {}
        dst_ports: dict[int, int] = {}
        total_sent = 0
        total_received = 0
        actions: dict[str, int] = {}
        src_ips: dict[str, int] = {}
        apps: dict[str, int] = {}

        for entry in entries:
            srcip = entry.get("srcip", "?")
            dstip = entry.get("dstip", "?")
            dstport = entry.get("dstport", "?")
            action = entry.get("action", "?")
            sent = int(entry.get("sentbyte", 0))
            rcvd = int(entry.get("rcvdbyte", 0))
            app = entry.get("app", "")

            if dstip != "?":
                dst_ips[str(dstip)] = dst_ips.get(str(dstip), 0) + 1
            if srcip != "?":
                src_ips[str(srcip)] = src_ips.get(str(srcip), 0) + 1
            if dstport != "?":
                try:
                    p = int(dstport)
                    dst_ports[p] = dst_ports.get(p, 0) + 1
                except (ValueError, TypeError):
                    pass
            if app:
                apps[str(app)] = apps.get(str(app), 0) + 1
            total_sent += sent
            total_received += rcvd
            actions[str(action)] = actions.get(str(action), 0) + 1

        top_src = sorted(src_ips.items(), key=lambda x: -x[1])[:5]
        top_dst = sorted(dst_ips.items(), key=lambda x: -x[1])[:5]
        top_ports = sorted(dst_ports.items(), key=lambda x: -x[1])[:10]
        top_apps = sorted(apps.items(), key=lambda x: -x[1])[:5]

        # SUMMARY FIRST so the model sees the most actionable info immediately.
        # IMPORTANT honesty rule: total_entries_in_window is what FAZ counted in the
        # window; analyzed_entries is what we actually pulled and aggregated. The
        # aggregation stats below (top_*, actions, bytes_*) are computed over
        # analyzed_entries, NOT total_entries_in_window. The model needs to know
        # the difference.
        truncated = total_count > len(entries)
        lines = [
            f"FortiAnalyzer {arguments.log_type} logs in ADOM '{arguments.adom}' for {scope} on {arguments.device}",
            f"window: {window} ({arguments.time_range})",
            "",
            "=== SUMMARY ===",
            f"total_entries_in_window: {total_count}",
            f"analyzed_entries: {len(entries)}{' (TRUNCATED — see note below)' if truncated else ''}",
            f"unique_src_ips: {len(src_ips)}  unique_dst_ips: {len(dst_ips)}  unique_dst_ports: {len(dst_ports)}",
            f"bytes_sent: {total_sent:,}  bytes_received: {total_received:,}",
            f"actions: {actions}",
            f"top_src_ips: {[f'{ip}({c})' for ip,c in top_src]}",
            f"top_dst_ips: {[f'{ip}({c})' for ip,c in top_dst]}",
            f"top_dst_ports: {[f'{p}({c})' for p,c in top_ports]}",
        ]
        if top_apps:
            lines.append(f"top_apps: {[f'{a}({c})' for a,c in top_apps]}")
        if truncated:
            lines.extend([
                "",
                f"NOTE: Only {len(entries)} of {total_count} entries were fetched (limit cap). "
                f"The aggregation stats above (top_*, actions, bytes_*) reflect those "
                f"{len(entries)} entries only. If you need a representative analysis of the "
                f"full window, use a narrower time_range or a more specific filter — do NOT "
                f"claim to have analyzed all {total_count} entries when you wrote the closure notes.",
            ])

        # Sample of raw entries — capped to keep output digestible for smaller models.
        # The summary above already conveys the volumetric picture; the raw entries
        # are just for the model to spot a specific anomaly if needed.
        sample_n = min(len(entries), 10)
        if sample_n > 0:
            lines.extend([
                "",
                f"=== SAMPLE ENTRIES (first {sample_n} of {len(entries)}) ===",
            ])
            for entry in entries[:sample_n]:
                ts = entry.get("itime", f"{entry.get('date', '')} {entry.get('time', '')}")
                srcip = entry.get("srcip", "?")
                dstip = entry.get("dstip", "?")
                srcport = entry.get("srcport", "?")
                dstport = entry.get("dstport", "?")
                action = entry.get("action", "?")
                sent = int(entry.get("sentbyte", 0))
                rcvd = int(entry.get("rcvdbyte", 0))
                app = entry.get("app", "")
                lines.append(
                    f"  {ts}  {srcip}:{srcport} -> {dstip}:{dstport}  "
                    f"action={action} sent={sent} rcvd={rcvd}"
                    + (f" app={app}" if app else "")
                )
            if len(entries) > sample_n:
                lines.append(
                    f"  ... ({len(entries) - sample_n} more entries — use the SUMMARY above for the volumetric picture)"
                )

        return ToolResult(output="\n".join(lines))
