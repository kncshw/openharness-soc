"""SOC alert whitelist: human-curated YAML of IPs/CIDRs that should be auto-closed.

This module is the *only* code path that touches the whitelist file. The LLM
never sees the raw YAML — the whitelist is consumed by the auto-close CLI
(`openharness.soc_auto_close`), which closes matching alerts directly via
the FortiSOAR API without invoking the LLM at all.

Design constraints (see memory `feedback_whitelist_bypass_llm.md`):
- Whitelist hits MUST bypass the LLM entirely. The whole reason this file
  exists is that whitelisted IPs (scanners, threat-intel collectors, etc.)
  produce attack-shaped traffic and small models cannot reliably weigh a soft
  whitelist hint against scary FAZ evidence.
- The whitelist is human-edited only. No auto-population from past closures.
- Every match must be auditable: closure notes cite the entry + the YAML
  file's git blob SHA so the exact rule can be reconstructed forever.

Schema safety guards:
- Each entry must have exactly one of `ip` or `cidr` (not both, not neither).
- IPs/CIDRs must parse via the stdlib `ipaddress` module.
- CIDR prefix must be /16 or longer. A typo'd `/0` or `/8` would silently
  auto-close every alert in the world, so we refuse them at load time.
- `closure_reason` must be in the resolve tool's allowlist (single source of
  truth — imported from `fortisoar_resolve_alert_tool`).
- Duplicate `ip`/`cidr` entries are rejected to avoid silent overrides.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import date
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator

from openharness.tools.fortisoar_resolve_alert_tool import (
    _ALLOWED_CLOSURE_REASONS,
    _DEFAULT_CLOSURE_REASON,
)

# Anything broader than /16 is refused at load time. A bad /8 in this file
# would silently auto-close ~16M IPs of alerts. /16 is already 65k addresses
# which is generous; if you genuinely need broader, the answer is "split it
# into multiple /16s and review each one."
_MIN_CIDR_PREFIX = 16

# Identifying marker prepended to every closure note written by the SOC AI
# agent (whitelist auto-close, LLM-driven resolve, template-driven resolve).
# The canonical definition lives in fortisoar_resolve_alert_tool.py alongside
# the rest of the closure-policy constants. We re-export it here as a
# convenience symbol so external callers can import either location.
#
# Why not import at module load? `_whitelist.py` is loaded BEFORE
# `fortisoar_resolve_alert_tool.py` because the resolve tool imports
# _ALLOWED_CLOSURE_REASONS from this file at its own module load. Importing
# back from the resolve tool here would create a circular import. Instead,
# `build_auto_close_notes` does a lazy import at call time.
BIS_AI_TRIAGE_MARKER = "[Triaged by BIS-AI Analyst — Gemma4-26B-A4B]"

_ALLOWED_CLOSURE_REASON_SET = set(_ALLOWED_CLOSURE_REASONS)


class WhitelistEntry(BaseModel):
    """One entry in the SOC whitelist YAML.

    Exactly one of `ip` or `cidr` must be set.
    """

    ip: str | None = None
    cidr: str | None = None
    reason: str = Field(min_length=10)
    added_by: str = Field(min_length=1)
    added_on: date
    expires_on: date | None = None
    closure_reason: str = _DEFAULT_CLOSURE_REASON

    @model_validator(mode="after")
    def _validate_entry(self) -> "WhitelistEntry":
        # Exactly one of ip or cidr
        if (self.ip is None) == (self.cidr is None):
            raise ValueError(
                "whitelist entry must have exactly one of 'ip' or 'cidr', not both/neither"
            )
        # Validate IP syntax
        if self.ip is not None:
            try:
                ip_address(self.ip)
            except ValueError as exc:
                raise ValueError(f"invalid 'ip' value '{self.ip}': {exc}") from exc
        # Validate CIDR syntax + prefix length floor
        if self.cidr is not None:
            try:
                net = ip_network(self.cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid 'cidr' value '{self.cidr}': {exc}") from exc
            if net.prefixlen < _MIN_CIDR_PREFIX:
                raise ValueError(
                    f"cidr '{self.cidr}' has prefix /{net.prefixlen}, which is broader "
                    f"than the safety floor /{_MIN_CIDR_PREFIX}. Refusing — a typo here "
                    f"would silently auto-close millions of alerts. If you need this "
                    f"range, split it into smaller blocks and add each one explicitly."
                )
        # closure_reason must match the resolve tool's allowlist
        if self.closure_reason not in _ALLOWED_CLOSURE_REASON_SET:
            raise ValueError(
                f"closure_reason '{self.closure_reason}' is not in the resolve tool's "
                f"allowlist {sorted(_ALLOWED_CLOSURE_REASON_SET)}"
            )
        return self

    @property
    def selector(self) -> str:
        """The ip or cidr value, whichever is set. Used for dedup + display."""
        return self.ip or self.cidr or ""


@dataclass(frozen=True)
class WhitelistMatch:
    """Result of a successful whitelist lookup."""

    entry: WhitelistEntry
    matched_on: str  # 'exact' | 'cidr'


class Whitelist(BaseModel):
    """In-memory whitelist with the file's git blob SHA for audit trails."""

    entries: list[WhitelistEntry] = Field(default_factory=list)
    file_path: str = ""
    file_sha: str = ""

    @model_validator(mode="after")
    def _no_duplicate_selectors(self) -> "Whitelist":
        seen: set[str] = set()
        for e in self.entries:
            sel = e.selector
            if sel in seen:
                raise ValueError(
                    f"duplicate whitelist entry for '{sel}'. Each ip/cidr may "
                    f"appear at most once."
                )
            seen.add(sel)
        return self

    def lookup_ip(self, ip: str) -> WhitelistMatch | None:
        """Look up an IP. Returns the first matching entry or None.

        Exact `ip` matches take precedence over `cidr` matches: we iterate
        through entries in file order and return the first hit, but exact
        matches naturally beat CIDR matches because we check `ip` first per
        entry.
        """
        try:
            target = ip_address(ip)
        except ValueError:
            return None
        for entry in self.entries:
            if entry.ip is not None:
                try:
                    if ip_address(entry.ip) == target:
                        return WhitelistMatch(entry=entry, matched_on="exact")
                except ValueError:
                    continue
            elif entry.cidr is not None:
                try:
                    if target in ip_network(entry.cidr, strict=False):
                        return WhitelistMatch(entry=entry, matched_on="cidr")
                except ValueError:
                    continue
        return None


def git_blob_sha(content: bytes) -> str:
    """Compute the git blob SHA-1 of file contents.

    Matches `git hash-object <file>` exactly. We compute it ourselves rather
    than shelling out so the auto-close path has zero subprocess dependencies.
    """
    header = f"blob {len(content)}\x00".encode()
    return hashlib.sha1(header + content).hexdigest()


def load_whitelist(path: str | Path | None = None) -> Whitelist:
    """Load and validate the SOC whitelist.

    Resolution order:
        1. Explicit `path` argument
        2. $SOC_WHITELIST_FILE env var
        3. None — returns an empty Whitelist (auto-close will fall through to LLM)

    Raises:
        FileNotFoundError: if a path is given/configured but the file doesn't exist
        ValueError: if the YAML is malformed, the schema is violated, or a
            duplicate selector is found
    """
    if path is None:
        env = os.environ.get("SOC_WHITELIST_FILE", "").strip()
        if not env:
            return Whitelist()
        path = env
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"SOC whitelist file not found: {p}")

    raw_bytes = p.read_bytes()
    try:
        loaded: Any = yaml.safe_load(raw_bytes) or []
    except yaml.YAMLError as exc:
        raise ValueError(f"whitelist YAML parse error in {p}: {exc}") from exc

    if not isinstance(loaded, list):
        raise ValueError(
            f"whitelist YAML in {p} must be a top-level list of entries, "
            f"got {type(loaded).__name__}"
        )

    entries = [WhitelistEntry.model_validate(item) for item in loaded]

    return Whitelist(
        entries=entries,
        file_path=str(p),
        file_sha=git_blob_sha(raw_bytes),
    )


def build_auto_close_notes(
    alert: dict[str, Any],
    match: WhitelistMatch,
    whitelist: Whitelist,
    closer_version: str,
) -> str:
    """Build the deterministic closure-notes string for an auto-closed alert.

    The format is fixed by code (no LLM in the loop). Every field exists to
    answer a specific audit question:
        - Alert facts: what was actually closed (durable record)
        - Whitelist match: which entry fired and why a human declared it safe
        - Provenance: which version of the whitelist + closer ran (forensics)
    """
    alert_id = alert.get("id", "?")
    src_ip = alert.get("sourceIp") or "-"
    dst_ip = alert.get("destinationIp") or "-"
    rule_name = str(alert.get("name", ""))[:200]

    detection_time = ""
    sourcedata = alert.get("sourcedata")
    if isinstance(sourcedata, str):
        try:
            import json as _json
            sourcedata = _json.loads(sourcedata)
        except (ValueError, TypeError):
            sourcedata = {}
    if isinstance(sourcedata, dict):
        sd_alert = sourcedata.get("Alert", {})
        if isinstance(sd_alert, dict):
            detection_time = str(sd_alert.get("detection_time") or "")

    fortigate_action = ""
    if isinstance(sourcedata, dict):
        related = sourcedata.get("Related Logs") or []
        if isinstance(related, list) and related and isinstance(related[0], dict):
            fortigate_action = str(related[0].get("action", ""))

    entry = match.entry
    closed_at = _utcnow_iso()

    lines = [
        BIS_AI_TRIAGE_MARKER,
        "",
        "Auto-closed by SOC agent whitelist policy. No LLM investigation performed.",
        "",
        "Alert facts:",
        f"  alert_id:         Alert-{alert_id}",
        f"  source_ip:        {src_ip}",
        f"  destination_ip:   {dst_ip}",
        f"  rule:             {rule_name}",
        f"  detection_time:   {detection_time or '-'}",
        f"  fortigate_action: {fortigate_action or '-'}",
        "",
        "Whitelist match:",
        f"  matched_entry:    {entry.selector} ({match.matched_on})",
        f"  reason:           {entry.reason}",
        f"  added_by:         {entry.added_by}",
        f"  added_on:         {entry.added_on.isoformat()}",
        f"  expires_on:       {entry.expires_on.isoformat() if entry.expires_on else 'none'}",
        f"  closure_reason:   {entry.closure_reason}",
        "",
        "Provenance:",
        f"  whitelist_file:   {whitelist.file_path}",
        f"  whitelist_sha:    {whitelist.file_sha}",
        f"  closer:           {closer_version}",
        f"  closed_at:        {closed_at}",
    ]
    return "\n".join(lines)


def _utcnow_iso() -> str:
    """UTC timestamp in ISO 8601 with second precision. Factored out for tests."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


async def auto_close_alert(
    config: dict[str, Any],
    alert: dict[str, Any],
    match: WhitelistMatch,
    whitelist: Whitelist,
    closer_version: str,
) -> dict[str, Any]:
    """Close a whitelist-matched alert via the FortiSOAR API.

    Reuses the resolve tool's static helpers for picklist resolution and the
    shared `fsr_put`. Returns the parsed FortiSOAR PUT response on success.

    Raises:
        RuntimeError: on FortiSOAR API errors. Caller is responsible for
            mapping these to user-visible messages / exit codes.

    Used by both:
      - `openharness.soc_auto_close` (the standalone CLI)
      - `fortisoar_get_alert_tool` (auto-close on whitelist hit during fetch)
    """
    # Lazy imports avoid any potential circular-import issues with
    # fortisoar_resolve_alert_tool (which is the source of truth for the
    # closure_reason allowlist that this module imports at module-load time).
    from openharness.tools._fortisoar_helpers import fsr_put
    from openharness.tools.fortisoar_resolve_alert_tool import (
        FortiSOARResolveAlertTool,
    )

    notes = build_auto_close_notes(alert, match, whitelist, closer_version)

    status_iri = await FortiSOARResolveAlertTool._get_picklist_iri(
        config, "AlertStatus", "Closed"
    )
    reason_iri = await FortiSOARResolveAlertTool._get_picklist_iri(
        config, "Closure Reason", match.entry.closure_reason
    )

    payload = {
        "status": status_iri,
        "closureReason": reason_iri,
        "closureNotes": notes,
    }
    endpoint = f"/api/3/alerts/{alert['uuid']}"
    return await fsr_put(config, endpoint, payload)
