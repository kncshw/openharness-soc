"""List configured FortiAnalyzer ADOMs."""

from __future__ import annotations

from pydantic import BaseModel

from openharness.tools._faz_helpers import get_configured_adoms
from openharness.tools.base import BaseTool, ToolExecutionContext, ToolResult


class FAZListAdomsInput(BaseModel):
    """No arguments — returns the configured ADOM allowlist."""


class FAZListAdomsTool(BaseTool):
    """Return the list of FortiAnalyzer ADOMs the agent is allowed to query."""

    name = "faz_list_adoms"
    description = (
        "List FortiAnalyzer ADOMs (Administrative Domains) configured for this agent. "
        "Returns each ADOM's name and description. ALWAYS call this first when the user "
        "asks about FortiAnalyzer logs/devices and has not specified an ADOM, so you can "
        "either pick the right one yourself based on the descriptions, or use ask_user_question "
        "to confirm with the user."
    )
    input_model = FAZListAdomsInput

    def is_read_only(self, arguments: FAZListAdomsInput) -> bool:
        return True

    async def execute(
        self, arguments: FAZListAdomsInput, context: ToolExecutionContext
    ) -> ToolResult:
        adoms = get_configured_adoms()
        if not adoms:
            return ToolResult(
                output="No ADOMs are configured. Set FAZ_ADOMS or FAZ_ADOM in the environment.",
                is_error=True,
            )

        lines = [f"Configured FortiAnalyzer ADOMs ({len(adoms)}):", ""]
        for a in adoms:
            if a["description"]:
                lines.append(f"  - {a['name']}: {a['description']}")
            else:
                lines.append(f"  - {a['name']}")

        return ToolResult(output="\n".join(lines))
