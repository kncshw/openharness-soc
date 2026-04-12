"""Unit tests for FAZ tools with mocked HTTP responses."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from openharness.tools._faz_helpers import faz_log_search, faz_rpc, get_faz_config
from openharness.tools.base import ToolExecutionContext
from openharness.tools.faz_get_devices_tool import FAZGetDevicesInput, FAZGetDevicesTool
from openharness.tools.faz_query_logs_tool import FAZQueryLogsInput, FAZQueryLogsTool

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAZ_ENV = {
    "FAZ_HOST": "https://faz.test.local",
    "FAZ_USER": "admin",
    "FAZ_PASSWORD": "testpass",
    "FAZ_ADOM": "root",
    "FAZ_VERIFY_SSL": "false",
}


@pytest.fixture
def ctx():
    return ToolExecutionContext(cwd=Path("/tmp"))


@pytest.fixture
def faz_config():
    return {
        "host": "https://faz.test.local",
        "user": "admin",
        "password": "testpass",
        "adom": "root",
        "verify_ssl": False,
    }


def _mock_response(data: dict, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        json=data,
        request=httpx.Request("POST", "https://faz.test.local/jsonrpc"),
    )


# ---------------------------------------------------------------------------
# get_faz_config
# ---------------------------------------------------------------------------


class TestGetFazConfig:
    @patch.dict("os.environ", FAZ_ENV, clear=False)
    def test_returns_config(self):
        config = get_faz_config()
        assert config["host"] == "https://faz.test.local"
        assert config["user"] == "admin"
        assert config["password"] == "testpass"
        assert config["adom"] == "root"
        assert config["verify_ssl"] is False

    @patch.dict("os.environ", {}, clear=True)
    def test_missing_creds_raises(self):
        with pytest.raises(ValueError, match="FAZ_HOST"):
            get_faz_config()

    @patch.dict("os.environ", {"FAZ_HOST": "https://x", "FAZ_USER": "admin", "FAZ_PASSWORD": ""}, clear=True)
    def test_missing_password_raises(self):
        with pytest.raises(ValueError, match="FAZ_PASSWORD"):
            get_faz_config()


# ---------------------------------------------------------------------------
# faz_rpc
# ---------------------------------------------------------------------------


class TestFazRpc:
    @pytest.mark.asyncio
    async def test_success(self, faz_config):
        login_resp = _mock_response({"id": 1, "session": "test-session-123", "result": [{"status": {"code": 0}}]})
        data_resp = _mock_response({"jsonrpc": "2.0", "id": 1, "result": {"data": [{"name": "FGT-01"}]}})
        logout_resp = _mock_response({"id": 1, "result": [{"status": {"code": 0}}]})

        call_count = 0
        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            body = kwargs.get("json", {})
            if body.get("method") == "exec" and "/sys/login" in str(body.get("params", [{}])[0].get("url", "")):
                return login_resp
            if body.get("method") == "exec" and "/sys/logout" in str(body.get("params", [{}])[0].get("url", "")):
                return logout_resp
            return data_resp

        with patch("openharness.tools._faz_helpers.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.side_effect = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await faz_rpc(faz_config, "get", "/dvmdb/adom/root/device")

        assert result == {"data": [{"name": "FGT-01"}]}

    @pytest.mark.asyncio
    async def test_api_error_raises(self, faz_config):
        login_resp = _mock_response({"id": 1, "session": "test-session-123", "result": [{"status": {"code": 0}}]})
        error_resp = _mock_response({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "Invalid Request"}})
        logout_resp = _mock_response({"id": 1, "result": [{"status": {"code": 0}}]})

        async def mock_post(*args, **kwargs):
            body = kwargs.get("json", {})
            if body.get("method") == "exec" and "/sys/login" in str(body.get("params", [{}])[0].get("url", "")):
                return login_resp
            if body.get("method") == "exec" and "/sys/logout" in str(body.get("params", [{}])[0].get("url", "")):
                return logout_resp
            return error_resp

        with patch("openharness.tools._faz_helpers.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.side_effect = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(RuntimeError, match="Invalid Request"):
                await faz_rpc(faz_config, "get", "/bad/url")


# ---------------------------------------------------------------------------
# faz_log_search
# ---------------------------------------------------------------------------


class TestFazLogSearch:
    @pytest.mark.asyncio
    async def test_two_step_search(self, faz_config):
        login_resp = _mock_response({"id": 1, "session": "test-session", "result": [{"status": {"code": 0}}]})
        add_resp = _mock_response({"jsonrpc": "2.0", "id": 1, "result": {"tid": 99999}})
        get_resp = _mock_response({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "percentage": 100,
                "total-count": 2,
                "data": [
                    {"srcip": "10.0.0.1", "dstip": "8.8.8.8", "action": "accept"},
                    {"srcip": "10.0.0.1", "dstip": "1.1.1.1", "action": "deny"},
                ],
            },
        })
        logout_resp = _mock_response({"id": 1, "result": [{"status": {"code": 0}}]})

        async def mock_post(*args, **kwargs):
            body = kwargs.get("json", {})
            method = body.get("method", "")
            params = body.get("params", [{}])
            url = params[0].get("url", "") if params else ""
            if method == "exec" and "/sys/login" in url:
                return login_resp
            if method == "exec" and "/sys/logout" in url:
                return logout_resp
            if method == "add":
                return add_resp
            return get_resp

        with patch("openharness.tools._faz_helpers.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.side_effect = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await faz_log_search(
                faz_config,
                device="FGT-01",
                time_range={"start": "2026-04-01 00:00:00", "end": "2026-04-05 23:59:59"},
                poll_interval=0.01,
            )

        assert result["total-count"] == 2
        assert len(result["data"]) == 2


# ---------------------------------------------------------------------------
# FAZGetDevicesTool
# ---------------------------------------------------------------------------


class TestFAZGetDevicesTool:
    @pytest.mark.asyncio
    @patch.dict("os.environ", FAZ_ENV, clear=False)
    async def test_success(self, ctx):
        tool = FAZGetDevicesTool()
        mock_result = [{"data": [
            {"name": "FGT-01", "ip": "10.0.0.1", "sn": "FGT123", "platform_str": "FortiGate-60F"},
            {"name": "FGT-02", "ip": "10.0.0.2", "sn": "FGT456", "platform_str": "FortiGate-100F"},
        ], "status": {"code": 0}}]

        with patch("openharness.tools.faz_get_devices_tool.faz_rpc", new_callable=AsyncMock) as mock_rpc:
            mock_rpc.return_value = mock_result
            result = await tool.execute(FAZGetDevicesInput(adom="root"), ctx)

        assert not result.is_error
        assert "FGT-01" in result.output
        assert "FGT-02" in result.output
        assert "10.0.0.1" in result.output

    @pytest.mark.asyncio
    @patch.dict("os.environ", FAZ_ENV, clear=False)
    async def test_filter(self, ctx):
        tool = FAZGetDevicesTool()
        mock_result = [{"data": [
            {"name": "FGT-01", "ip": "10.0.0.1", "sn": "FGT123"},
            {"name": "FGT-02", "ip": "10.0.0.2", "sn": "FGT456"},
        ], "status": {"code": 0}}]

        with patch("openharness.tools.faz_get_devices_tool.faz_rpc", new_callable=AsyncMock) as mock_rpc:
            mock_rpc.return_value = mock_result
            result = await tool.execute(
                FAZGetDevicesInput(adom="root", filter_name="FGT-01"), ctx,
            )

        assert "FGT-01" in result.output
        assert "FGT-02" not in result.output

    @pytest.mark.asyncio
    @patch.dict("os.environ", {}, clear=True)
    async def test_missing_creds(self, ctx):
        tool = FAZGetDevicesTool()
        result = await tool.execute(FAZGetDevicesInput(adom="root"), ctx)
        assert result.is_error
        assert "FAZ_HOST" in result.output

    @pytest.mark.asyncio
    @patch.dict("os.environ", FAZ_ENV, clear=False)
    async def test_missing_adom(self, ctx):
        tool = FAZGetDevicesTool()
        result = await tool.execute(FAZGetDevicesInput(), ctx)
        assert result.is_error
        assert "ADOM not specified" in result.output


# ---------------------------------------------------------------------------
# FAZQueryLogsTool
# ---------------------------------------------------------------------------


class TestFAZQueryLogsTool:
    @pytest.mark.asyncio
    @patch.dict("os.environ", FAZ_ENV, clear=False)
    async def test_success(self, ctx):
        tool = FAZQueryLogsTool()
        mock_search_result = {
            "percentage": 100,
            "total-count": 2,
            "data": [
                {
                    "itime": "2026-04-05 10:00:00",
                    "srcip": "10.0.0.1", "dstip": "8.8.8.8",
                    "srcport": "54321", "dstport": "443",
                    "proto": "6", "action": "accept",
                    "sentbyte": "1024", "rcvdbyte": "2048",
                    "app": "HTTPS", "devname": "FGT-01",
                },
                {
                    "itime": "2026-04-05 10:01:00",
                    "srcip": "10.0.0.1", "dstip": "1.1.1.1",
                    "srcport": "54322", "dstport": "53",
                    "proto": "17", "action": "accept",
                    "sentbyte": "64", "rcvdbyte": "128",
                    "app": "DNS", "devname": "FGT-01",
                },
            ],
        }

        with patch("openharness.tools.faz_query_logs_tool.faz_log_search", new_callable=AsyncMock) as mock_search:
            mock_search.return_value = mock_search_result
            result = await tool.execute(
                FAZQueryLogsInput(adom="root", ip_address="10.0.0.1", time_range="10m", limit=10),
                ctx,
            )

        assert not result.is_error
        assert "10.0.0.1" in result.output
        assert "8.8.8.8" in result.output
        assert "SUMMARY" in result.output
        assert "total_entries_in_window: 2" in result.output
        assert "analyzed_entries: 2" in result.output

    @pytest.mark.asyncio
    @patch.dict("os.environ", FAZ_ENV, clear=False)
    async def test_no_logs(self, ctx):
        tool = FAZQueryLogsTool()
        with patch("openharness.tools.faz_query_logs_tool.faz_log_search", new_callable=AsyncMock) as mock_search:
            mock_search.return_value = {"percentage": 100, "total-count": 0, "data": []}
            result = await tool.execute(
                FAZQueryLogsInput(adom="root", ip_address="10.0.0.99", time_range="5m"),
                ctx,
            )

        assert not result.is_error
        assert "No traffic logs found" in result.output

    @pytest.mark.asyncio
    async def test_invalid_ip(self, ctx):
        tool = FAZQueryLogsTool()
        result = await tool.execute(
            FAZQueryLogsInput(adom="root", ip_address="not-an-ip"),
            ctx,
        )
        assert result.is_error
        assert "Invalid IP" in result.output

    @pytest.mark.asyncio
    async def test_invalid_time_range(self, ctx):
        tool = FAZQueryLogsTool()
        result = await tool.execute(
            FAZQueryLogsInput(adom="root", ip_address="10.0.0.1", time_range="99h"),
            ctx,
        )
        assert result.is_error
        assert "Invalid time_range" in result.output

    @pytest.mark.asyncio
    @patch.dict("os.environ", {}, clear=True)
    async def test_missing_creds(self, ctx):
        tool = FAZQueryLogsTool()
        # adom="root" passes validation (default fallback when no env vars)
        result = await tool.execute(
            FAZQueryLogsInput(adom="root", ip_address="10.0.0.1"),
            ctx,
        )
        assert result.is_error
        assert "FAZ_HOST" in result.output

    @pytest.mark.asyncio
    @patch.dict("os.environ", FAZ_ENV, clear=False)
    async def test_missing_adom_triggers_ask_user(self, ctx):
        """When adom is not specified, tool should return error instructing model to ask user."""
        tool = FAZQueryLogsTool()
        result = await tool.execute(
            FAZQueryLogsInput(ip_address="10.0.0.1"),
            ctx,
        )
        assert result.is_error
        assert "ADOM not specified" in result.output
        assert "ask_user_question" in result.output

    @pytest.mark.asyncio
    @patch.dict("os.environ", FAZ_ENV, clear=False)
    async def test_unknown_adom_rejected(self, ctx):
        """When adom is not in the configured allowlist, tool should reject."""
        tool = FAZQueryLogsTool()
        result = await tool.execute(
            FAZQueryLogsInput(adom="evil_adom", ip_address="10.0.0.1"),
            ctx,
        )
        assert result.is_error
        assert "Unknown ADOM" in result.output

    @pytest.mark.asyncio
    @patch.dict("os.environ", FAZ_ENV, clear=False)
    async def test_wildcard_adom_rejected(self, ctx):
        """ADOM 'all' / '*' should be rejected."""
        tool = FAZQueryLogsTool()
        result = await tool.execute(
            FAZQueryLogsInput(adom="all", ip_address="10.0.0.1"),
            ctx,
        )
        assert result.is_error
        assert "not allowed" in result.output


# ---------------------------------------------------------------------------
# FAZListAdomsTool & ADOM helpers
# ---------------------------------------------------------------------------


class TestAdomConfig:
    @patch.dict("os.environ", {"FAZ_ADOMS": "FortiCloud_Server:Burnaby,FortiCloud_MIS_Colocation:worldwide"}, clear=True)
    def test_parses_list_with_descriptions(self):
        from openharness.tools._faz_helpers import get_configured_adoms
        adoms = get_configured_adoms()
        assert len(adoms) == 2
        assert adoms[0]["name"] == "FortiCloud_Server"
        assert adoms[0]["description"] == "Burnaby"
        assert adoms[1]["name"] == "FortiCloud_MIS_Colocation"
        assert adoms[1]["description"] == "worldwide"

    @patch.dict("os.environ", {"FAZ_ADOMS": "alpha,beta"}, clear=True)
    def test_parses_list_without_descriptions(self):
        from openharness.tools._faz_helpers import get_configured_adoms
        adoms = get_configured_adoms()
        assert len(adoms) == 2
        assert adoms[0] == {"name": "alpha", "description": ""}
        assert adoms[1] == {"name": "beta", "description": ""}

    @patch.dict("os.environ", {"FAZ_ADOM": "myroot"}, clear=True)
    def test_falls_back_to_faz_adom(self):
        from openharness.tools._faz_helpers import get_configured_adoms
        adoms = get_configured_adoms()
        assert adoms == [{"name": "myroot", "description": ""}]

    @patch.dict("os.environ", {}, clear=True)
    def test_default_root(self):
        from openharness.tools._faz_helpers import get_configured_adoms
        adoms = get_configured_adoms()
        assert adoms == [{"name": "root", "description": ""}]

    @patch.dict("os.environ", {"FAZ_ADOMS": "alpha,beta"}, clear=True)
    def test_validate_adom(self):
        from openharness.tools._faz_helpers import validate_adom
        ok, _ = validate_adom("alpha")
        assert ok
        ok, err = validate_adom("")
        assert not ok and "ask_user_question" in err
        ok, err = validate_adom("all")
        assert not ok and "not allowed" in err
        ok, err = validate_adom("unknown")
        assert not ok and "Unknown ADOM" in err


class TestFAZListAdomsTool:
    @pytest.mark.asyncio
    @patch.dict("os.environ", {"FAZ_ADOMS": "FortiCloud_Server:Burnaby,FortiCloud_MIS_Colocation:worldwide"}, clear=True)
    async def test_list(self, ctx):
        from openharness.tools.faz_list_adoms_tool import FAZListAdomsInput, FAZListAdomsTool
        tool = FAZListAdomsTool()
        result = await tool.execute(FAZListAdomsInput(), ctx)
        assert not result.is_error
        assert "FortiCloud_Server" in result.output
        assert "Burnaby" in result.output
        assert "FortiCloud_MIS_Colocation" in result.output
        assert "worldwide" in result.output


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_faz_tools_registered(self):
        from openharness.tools import create_default_tool_registry
        registry = create_default_tool_registry()
        assert registry.get("faz_query_logs") is not None
        assert registry.get("faz_get_devices") is not None
        assert registry.get("faz_query_security_events") is not None
        assert registry.get("faz_list_adoms") is not None
