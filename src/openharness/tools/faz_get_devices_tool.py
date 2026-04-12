"""List managed FortiGate devices from FortiAnalyzer."""

from __future__ import annotations

from pydantic import BaseModel, Field

from openharness.tools._faz_helpers import faz_rpc, get_faz_config, validate_adom
from openharness.tools.base import BaseTool, ToolExecutionContext, ToolResult


class FAZGetDevicesInput(BaseModel):
    """Arguments for listing FAZ-managed devices."""

    adom: str = Field(
        default="",
        description=(
            "ADOM (Administrative Domain) to query. REQUIRED — if you do not know which "
            "ADOM to use, call faz_list_adoms first or use ask_user_question to confirm "
            "with the user. Do NOT guess. Do NOT use 'all' or wildcards."
        ),
    )
    filter_name: str = Field(
        default="", description="Optional device name substring filter (case-insensitive)"
    )


class FAZGetDevicesTool(BaseTool):
    """List devices managed by FortiAnalyzer."""

    name = "faz_get_devices"
    description = (
        "List all devices managed by FortiAnalyzer in a specific ADOM. Returns device name, "
        "IP, platform, firmware, and serial. "
        "USE THIS ONLY WHEN: the user explicitly asks 'what devices are in this ADOM' or "
        "you need to map an IP to a specific device by hand. "
        "DO NOT use this during alert investigation — faz_query_logs and "
        "faz_query_security_events with device='All_FortiGate' (the default) already query "
        "every device in the ADOM at once. Calling faz_get_devices and then iterating over "
        "each FortiGate is wasteful and produces no new information. "
        "REQUIRES the adom parameter — call faz_list_adoms first if unsure."
    )
    input_model = FAZGetDevicesInput

    def is_read_only(self, arguments: FAZGetDevicesInput) -> bool:
        return True

    async def execute(
        self, arguments: FAZGetDevicesInput, context: ToolExecutionContext
    ) -> ToolResult:
        # Validate ADOM
        ok, err = validate_adom(arguments.adom)
        if not ok:
            return ToolResult(output=err, is_error=True)

        try:
            config = get_faz_config()
        except ValueError as exc:
            return ToolResult(output=str(exc), is_error=True)

        adom = arguments.adom

        try:
            result = await faz_rpc(
                config, method="get",
                url=f"/dvmdb/adom/{adom}/device",
            )
        except RuntimeError as exc:
            return ToolResult(output=f"FortiAnalyzer error: {exc}", is_error=True)
        except Exception as exc:
            return ToolResult(output=f"FortiAnalyzer request failed: {exc}", is_error=True)

        # v1 API returns list with data inside, v2 returns dict with data
        if isinstance(result, list) and result:
            devices = result[0].get("data", [])
        elif isinstance(result, dict):
            devices = result.get("data", [])
        else:
            devices = []

        if not devices:
            return ToolResult(output=f"No managed devices found in ADOM '{adom}'.")

        # Apply name filter
        if arguments.filter_name:
            name_lower = arguments.filter_name.lower()
            devices = [
                d for d in devices
                if name_lower in str(d.get("name", "")).lower()
                or name_lower in str(d.get("hostname", "")).lower()
            ]
            if not devices:
                return ToolResult(
                    output=f"No devices matching '{arguments.filter_name}' found."
                )

        lines = [f"Managed devices in ADOM '{adom}' ({len(devices)}):", ""]
        for dev in devices:
            name = dev.get("name", "unknown")
            ip = dev.get("ip", "N/A")
            platform = dev.get("platform_str", dev.get("platform", "N/A"))
            firmware = dev.get("os_ver", dev.get("firmware", "N/A"))
            serial = dev.get("sn", dev.get("serial", "N/A"))
            ha_mode = dev.get("ha_mode", "")
            conn_status = dev.get("conn_status", "")

            lines.append(f"  {name}")
            lines.append(f"    IP: {ip}")
            lines.append(f"    Platform: {platform}")
            lines.append(f"    Firmware: {firmware}")
            lines.append(f"    Serial: {serial}")
            if ha_mode:
                lines.append(f"    HA Mode: {ha_mode}")
            if conn_status:
                lines.append(f"    Connection: {conn_status}")
            lines.append("")

        return ToolResult(output="\n".join(lines))
