"""Look up IP ownership information from Netbox."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from openharness.tools._netbox_helpers import lookup_ip
from openharness.tools.base import BaseTool, ToolExecutionContext, ToolResult


_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


class NetboxLookupIPInput(BaseModel):
    """Arguments for looking up an IP in Netbox."""

    ip_address: str = Field(
        description=(
            "IPv4 address to look up in Netbox. Returns the owner/description "
            "for this IP or its containing /24 subnet. Use this to find out who "
            "owns an internal IP — useful for escalation notes and closure notes."
        )
    )


class NetboxLookupIPTool(BaseTool):
    """Look up IP ownership in Netbox. Read-only."""

    name = "netbox_lookup_ip"
    description = (
        "Look up an IP address in Netbox to find its owner and description. "
        "Queries the exact IP first, then falls back to the containing /24 subnet. "
        "Returns the owner/description string from Netbox, or 'not found' if the "
        "IP is not in Netbox. Use this when you need to know who owns an IP — "
        "for example, to include the owner in escalation findings or closure notes."
    )
    input_model = NetboxLookupIPInput

    def is_read_only(self, arguments: NetboxLookupIPInput) -> bool:
        return True

    async def execute(
        self, arguments: NetboxLookupIPInput, context: ToolExecutionContext
    ) -> ToolResult:
        ip = arguments.ip_address.strip()

        if not _IP_PATTERN.match(ip):
            return ToolResult(
                output=f"Invalid IP address format: '{ip}'. Use a valid IPv4 address.",
                is_error=True,
            )

        result = lookup_ip(ip)

        if result is None:
            return ToolResult(
                output=f"Netbox lookup for {ip}: not found (IP and its /24 subnet are not in Netbox)."
            )

        source_label = "exact match" if result["source"] == "exact" else "/24 subnet match"
        return ToolResult(
            output=(
                f"Netbox lookup for {ip} ({source_label}):\n"
                f"  description: {result['description']}"
            )
        )
