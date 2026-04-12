"""Unit tests for FortiSOAR tools with mocked HTTP responses."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from openharness.tools._fortisoar_helpers import (
    _generate_hmac_header,
    fsr_get,
    get_fsr_config,
)
from openharness.tools.base import ToolExecutionContext
from openharness.tools.fortisoar_get_alert_tool import (
    FortiSOARGetAlertInput,
    FortiSOARGetAlertTool,
)
from openharness.tools.fortisoar_list_alerts_tool import (
    FortiSOARListAlertsInput,
    FortiSOARListAlertsTool,
)
from openharness.tools.fortisoar_resolve_alert_tool import (
    FortiSOARResolveAlertInput,
    FortiSOARResolveAlertTool,
    _ensure_bis_ai_marker,
)
from openharness.tools._whitelist import BIS_AI_TRIAGE_MARKER


@pytest.fixture
def ctx():
    return ToolExecutionContext(cwd=Path("/tmp"))


@pytest.fixture
def fsr_config():
    return {
        "url": "https://fortisoar.test.local",
        "public_key": "PUBKEY_CONTENT",
        "private_key": "PRIVKEY_CONTENT",
        "verify_ssl": False,
        "tenant": "",
        "source": "",
    }


@pytest.fixture
def fsr_config_with_tenant():
    return {
        "url": "https://fortisoar.test.local",
        "public_key": "PUBKEY_CONTENT",
        "private_key": "PRIVKEY_CONTENT",
        "verify_ssl": False,
        "tenant": "Cloud Services",
        "source": "IS_FAZ_MIS_Cloud",
    }


@pytest.fixture
def sample_alert():
    return {
        "@id": "/api/3/alerts/d6d963b5-1b07-40a0-8dfb-953793675f93",
        "@type": "Alert",
        "id": 108160,
        "uuid": "d6d963b5-1b07-40a0-8dfb-953793675f93",
        "name": "Compromised host 10.125.19.31 with Malware",
        "description": "<p>Subject: Compromised host</p>",
        "severity": {"itemValue": "Critical"},
        "status": {"itemValue": "Open"},
        "type": {"itemValue": "IoC"},
        "state": {"itemValue": "Ready to Investigate"},
        "tenant": {"name": "Cloud Services", "uuid": "test-tenant-uuid"},
        "source": "IS_FAZ_MIS_Cloud",
        "sourceType": "FortiAnalyzer",
        "sourceId": "test-source-id",
        "sourceIp": "10.125.19.31",
        "sourcePort": "6998",
        "destinationIp": "185.162.184.10",
        "destinationPort": "65012",
        "deviceName": "IN_PNE1-A01-RH-GW-FStack",
        "deviceOwner": "FortiCloud",
        "eventCount": 20,
        "eventGenerator": "BIS_FSR_Compromised",
        "createDate": 1774896054.776861,
        "modifyDate": 1774896686.839798,
        "dueBy": 1774982454,
        "lastSeen": 1774876376,
        "sourcedata": '{"Alert": {"severity": "critical"}}',
    }


def _mock_resp(data: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        json=data,
        request=httpx.Request("GET", "https://fortisoar.test.local/api/3/alerts"),
    )


# ---------------------------------------------------------------------------
# HMAC signing
# ---------------------------------------------------------------------------


class TestHmacHeader:
    def test_returns_cs_prefix(self):
        h = _generate_hmac_header("GET", "https://x/api/3/alerts", "", "priv", "pub")
        assert h.startswith("CS ")

    def test_get_uses_public_key_as_payload(self):
        # Deterministically: call twice with same inputs should differ only by timestamp
        # and we check the format of the base64 after decoding.
        h = _generate_hmac_header("GET", "https://x/api/3/alerts", "ignored", "priv", "pub")
        import base64
        decoded = base64.b64decode(h[3:]).decode()
        parts = decoded.split(";")
        assert parts[0] == "sha256"
        assert parts[2] == "pub"  # public key appears as identifier
        assert len(parts[3]) == 64  # sha256 hex digest

    def test_post_signs_body(self):
        h1 = _generate_hmac_header("POST", "https://x/api/3/alerts", '{"a": 1}', "priv", "pub")
        h2 = _generate_hmac_header("POST", "https://x/api/3/alerts", '{"a": 2}', "priv", "pub")
        assert h1 != h2


# ---------------------------------------------------------------------------
# get_fsr_config
# ---------------------------------------------------------------------------


class TestGetFsrConfig:
    @patch.dict("os.environ", {}, clear=True)
    def test_missing_raises(self):
        with pytest.raises(ValueError, match="FORTISOAR_URL"):
            get_fsr_config()

    def test_reads_from_files(self, tmp_path):
        pub = tmp_path / "test.pub"
        pri = tmp_path / "test.pri"
        pub.write_text("  PUBKEY_DATA  \n")
        pri.write_text("PRIKEY_DATA")

        env = {
            "FORTISOAR_URL": "https://fsr.test/",
            "FORTISOAR_PUBLIC_KEY_FILE": str(pub),
            "FORTISOAR_PRIVATE_KEY_FILE": str(pri),
            "FORTISOAR_TENANT": "Cloud Services",
            "FORTISOAR_SOURCE": "IS_FAZ_MIS_Cloud",
            "FORTISOAR_VERIFY_SSL": "false",
        }
        with patch.dict("os.environ", env, clear=True):
            config = get_fsr_config()

        assert config["url"] == "https://fsr.test"  # stripped trailing slash
        assert config["public_key"] == "PUBKEY_DATA"  # stripped whitespace
        assert config["private_key"] == "PRIKEY_DATA"
        assert config["verify_ssl"] is False
        assert config["tenant"] == "Cloud Services"
        assert config["source"] == "IS_FAZ_MIS_Cloud"

    def test_missing_tenant_raises(self, tmp_path):
        """FortiSOAR must refuse to operate without an explicit tenant."""
        pub = tmp_path / "test.pub"
        pri = tmp_path / "test.pri"
        pub.write_text("PUBKEY_DATA")
        pri.write_text("PRIKEY_DATA")

        env = {
            "FORTISOAR_URL": "https://fsr.test",
            "FORTISOAR_PUBLIC_KEY_FILE": str(pub),
            "FORTISOAR_PRIVATE_KEY_FILE": str(pri),
            "FORTISOAR_SOURCE": "IS_FAZ_MIS_Cloud",
            # FORTISOAR_TENANT intentionally missing
        }
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(ValueError, match="FORTISOAR_TENANT"):
                get_fsr_config()

    def test_missing_source_raises(self, tmp_path):
        """FortiSOAR must refuse to operate without an explicit source."""
        pub = tmp_path / "test.pub"
        pri = tmp_path / "test.pri"
        pub.write_text("PUBKEY_DATA")
        pri.write_text("PRIKEY_DATA")

        env = {
            "FORTISOAR_URL": "https://fsr.test",
            "FORTISOAR_PUBLIC_KEY_FILE": str(pub),
            "FORTISOAR_PRIVATE_KEY_FILE": str(pri),
            "FORTISOAR_TENANT": "Cloud Services",
            # FORTISOAR_SOURCE intentionally missing
        }
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(ValueError, match="FORTISOAR_SOURCE"):
                get_fsr_config()


# ---------------------------------------------------------------------------
# FortiSOARListAlertsTool
# ---------------------------------------------------------------------------


class TestFortiSOARListAlertsTool:
    @pytest.mark.asyncio
    async def test_success_merges_critical_and_high(self, ctx, sample_alert, fsr_config):
        """Tool should issue two queries (Critical + High) and merge results."""
        tool = FortiSOARListAlertsTool()

        critical_alert = dict(sample_alert)
        critical_alert["id"] = 111
        critical_alert["createDate"] = 2000.0
        critical_alert["severity"] = {"itemValue": "Critical"}

        high_alert = dict(sample_alert)
        high_alert["id"] = 222
        high_alert["createDate"] = 1000.0
        high_alert["severity"] = {"itemValue": "High"}

        call_count = 0

        async def mock_fsr_get(config, endpoint):
            nonlocal call_count
            call_count += 1
            if "Critical" in endpoint:
                return {"hydra:member": [critical_alert], "hydra:totalItems": 42}
            if "High" in endpoint:
                return {"hydra:member": [high_alert], "hydra:totalItems": 7}
            raise AssertionError(f"Unexpected endpoint: {endpoint}")

        with patch(
            "openharness.tools.fortisoar_list_alerts_tool.get_fsr_config",
            return_value=fsr_config,
        ), patch(
            "openharness.tools.fortisoar_list_alerts_tool.fsr_get",
            side_effect=mock_fsr_get,
        ):
            result = await tool.execute(
                FortiSOARListAlertsInput(status="Open", limit=10), ctx,
            )

        assert not result.is_error
        # Both severities fetched
        assert call_count == 2
        # Both alert IDs present
        assert "Alert-111" in result.output
        assert "Alert-222" in result.output
        # Critical appears before High (sorted by createDate desc)
        assert result.output.index("Alert-111") < result.output.index("Alert-222")
        # Header reports both counts
        assert "Critical=42" in result.output
        assert "High=7" in result.output

    @pytest.mark.asyncio
    async def test_empty(self, ctx, fsr_config):
        tool = FortiSOARListAlertsTool()
        with patch(
            "openharness.tools.fortisoar_list_alerts_tool.get_fsr_config",
            return_value=fsr_config,
        ), patch(
            "openharness.tools.fortisoar_list_alerts_tool.fsr_get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {"hydra:member": [], "hydra:totalItems": 0}
            result = await tool.execute(FortiSOARListAlertsInput(status="Open"), ctx)

        assert not result.is_error
        assert "No Critical/High severity FortiSOAR alerts found" in result.output

    @pytest.mark.asyncio
    async def test_tenant_filter_included(self, ctx, sample_alert, fsr_config_with_tenant):
        """When FORTISOAR_TENANT is configured, queries must include tenant.name filter."""
        tool = FortiSOARListAlertsTool()
        captured_endpoints: list[str] = []

        async def mock_fsr_get(config, endpoint):
            captured_endpoints.append(endpoint)
            return {"hydra:member": [], "hydra:totalItems": 0}

        with patch(
            "openharness.tools.fortisoar_list_alerts_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_list_alerts_tool.fsr_get",
            side_effect=mock_fsr_get,
        ):
            await tool.execute(FortiSOARListAlertsInput(status="Open"), ctx)

        # Both queries must include the tenant AND source filters
        assert len(captured_endpoints) == 2
        for ep in captured_endpoints:
            assert "tenant.name=Cloud Services" in ep
            assert "source=IS_FAZ_MIS_Cloud" in ep

    @pytest.mark.asyncio
    async def test_limit_respected_after_merge(self, ctx, sample_alert, fsr_config):
        """Combined result list should be trimmed to the user-specified limit."""
        tool = FortiSOARListAlertsTool()

        def _mk(i, sev, ts):
            a = dict(sample_alert)
            a["id"] = i
            a["severity"] = {"itemValue": sev}
            a["createDate"] = ts
            return a

        async def mock_fsr_get(config, endpoint):
            if "Critical" in endpoint:
                return {
                    "hydra:member": [_mk(i, "Critical", 1000.0 + i) for i in range(5)],
                    "hydra:totalItems": 500,
                }
            return {
                "hydra:member": [_mk(i + 100, "High", 500.0 + i) for i in range(5)],
                "hydra:totalItems": 200,
            }

        with patch(
            "openharness.tools.fortisoar_list_alerts_tool.get_fsr_config",
            return_value=fsr_config,
        ), patch(
            "openharness.tools.fortisoar_list_alerts_tool.fsr_get",
            side_effect=mock_fsr_get,
        ):
            result = await tool.execute(
                FortiSOARListAlertsInput(status="Open", limit=3), ctx,
            )

        assert not result.is_error
        # Only 3 entries displayed (out of 10 merged)
        assert result.output.count("Alert-") <= 5  # header + 3 alerts + footer hint


# ---------------------------------------------------------------------------
# FortiSOARGetAlertTool
# ---------------------------------------------------------------------------


class TestFortiSOARGetAlertTool:
    @pytest.mark.asyncio
    async def test_by_display_id(self, ctx, sample_alert, fsr_config):
        tool = FortiSOARGetAlertTool()
        # Display ID triggers a query (returns hydra:member)
        mock_resp = {"hydra:member": [sample_alert], "hydra:totalItems": 1}

        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = mock_resp
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="Alert-108160"), ctx,
            )

        assert not result.is_error
        assert "Alert-108160" in result.output
        assert "Critical" in result.output
        assert "10.125.19.31" in result.output
        assert "185.162.184.10" in result.output
        assert "IN_PNE1-A01-RH-GW-FStack" in result.output

    @pytest.mark.asyncio
    async def test_by_uuid(self, ctx, sample_alert, fsr_config):
        tool = FortiSOARGetAlertTool()
        # UUID triggers a direct GET (returns alert object directly)
        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = sample_alert
            result = await tool.execute(
                FortiSOARGetAlertInput(
                    alert_id="d6d963b5-1b07-40a0-8dfb-953793675f93"
                ),
                ctx,
            )

        assert not result.is_error
        assert "Alert-108160" in result.output

    @pytest.mark.asyncio
    async def test_not_found(self, ctx, fsr_config):
        tool = FortiSOARGetAlertTool()
        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {"hydra:member": [], "hydra:totalItems": 0}
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="Alert-999999"), ctx,
            )

        assert result.is_error
        assert "not found" in result.output.lower()

    @pytest.mark.asyncio
    async def test_invalid_id(self, ctx, fsr_config):
        tool = FortiSOARGetAlertTool()
        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config,
        ):
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="not-an-id"), ctx,
            )
        assert result.is_error
        assert "Invalid alert_id" in result.output

    @pytest.mark.asyncio
    async def test_tenant_scope_matches(self, ctx, sample_alert, fsr_config_with_tenant):
        """When configured tenant matches the alert, return normally."""
        tool = FortiSOARGetAlertTool()
        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {"hydra:member": [sample_alert], "hydra:totalItems": 1}
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="Alert-108160"), ctx,
            )
        assert not result.is_error
        assert "Alert-108160" in result.output

    @pytest.mark.asyncio
    async def test_tenant_scope_rejects_foreign(self, ctx, sample_alert, fsr_config_with_tenant):
        """When the fetched alert belongs to a different tenant, return an access denied error."""
        tool = FortiSOARGetAlertTool()
        foreign_alert = dict(sample_alert)
        foreign_alert["tenant"] = {"name": "Burnaby MIS", "uuid": "other"}

        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {"hydra:member": [foreign_alert], "hydra:totalItems": 1}
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="Alert-108160"), ctx,
            )
        assert result.is_error
        assert "Access denied" in result.output
        assert "Burnaby MIS" in result.output
        assert "Cloud Services" in result.output

    @pytest.mark.asyncio
    async def test_source_scope_rejects_foreign(self, ctx, sample_alert, fsr_config_with_tenant):
        """When the fetched alert has a different source, return access denied."""
        tool = FortiSOARGetAlertTool()
        foreign_alert = dict(sample_alert)
        # Same tenant (Cloud Services) but different source
        foreign_alert["source"] = "FortiStack CA FSM"

        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {"hydra:member": [foreign_alert], "hydra:totalItems": 1}
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="Alert-108160"), ctx,
            )
        assert result.is_error
        assert "Access denied" in result.output
        assert "FortiStack CA FSM" in result.output
        assert "IS_FAZ_MIS_Cloud" in result.output

    def test_build_lookup_endpoint(self):
        # UUID → direct GET
        ep = FortiSOARGetAlertTool._build_lookup_endpoint(
            "d6d963b5-1b07-40a0-8dfb-953793675f93"
        )
        assert ep == "/api/3/alerts/d6d963b5-1b07-40a0-8dfb-953793675f93"

        # Display ID → query
        ep = FortiSOARGetAlertTool._build_lookup_endpoint("Alert-108160")
        assert ep == "/api/3/alerts?id=108160&$limit=1"

        # Bare numeric → query
        ep = FortiSOARGetAlertTool._build_lookup_endpoint("108160")
        assert ep == "/api/3/alerts?id=108160&$limit=1"

        # Invalid → None
        assert FortiSOARGetAlertTool._build_lookup_endpoint("garbage") is None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# BIS-AI triage marker
# ---------------------------------------------------------------------------


class TestBisAiMarker:
    """The BIS-AI triage marker is prepended to closure notes so a human
    reviewing the alert in FortiSOAR sees at a glance that the closure was
    AI-driven. The prepend must be idempotent (LLM may copy the marker from
    the template) and must NOT bypass the minimum-length guard."""

    def test_marker_prepended_to_plain_notes(self):
        notes = "Investigation complete. No follow-up traffic detected."
        result = _ensure_bis_ai_marker(notes)
        assert result.startswith(BIS_AI_TRIAGE_MARKER)
        assert "Investigation complete" in result
        # Marker is followed by a blank line then the original notes
        assert result == f"{BIS_AI_TRIAGE_MARKER}\n\nInvestigation complete. No follow-up traffic detected."

    def test_marker_idempotent_when_already_present(self):
        """If the LLM copied the template (which already has the marker)
        verbatim into its closure_notes, we must not double-prepend."""
        notes = f"{BIS_AI_TRIAGE_MARKER}\n\nInvestigation complete."
        result = _ensure_bis_ai_marker(notes)
        # Marker appears exactly once
        assert result.count(BIS_AI_TRIAGE_MARKER) == 1
        # Content is preserved
        assert "Investigation complete" in result

    def test_marker_idempotent_with_leading_whitespace(self):
        """LLM-supplied notes may have leading whitespace before the marker.
        The check uses `.strip()` so leading whitespace doesn't trigger a
        double-prepend."""
        notes = f"  \n  {BIS_AI_TRIAGE_MARKER}\n\nReal investigation notes here."
        result = _ensure_bis_ai_marker(notes)
        assert result.count(BIS_AI_TRIAGE_MARKER) == 1

    def test_empty_notes_returned_unchanged(self):
        """Empty/whitespace-only notes must NOT get the marker — that would
        let an LLM-supplied empty string satisfy the resolve tool's minimum
        length guard via the marker characters alone."""
        assert _ensure_bis_ai_marker("") == ""
        assert _ensure_bis_ai_marker("   ") == "   "
        assert _ensure_bis_ai_marker("\n\n") == "\n\n"


# ---------------------------------------------------------------------------
# FortiSOARResolveAlertTool
# ---------------------------------------------------------------------------


class TestFortiSOARResolveAlertTool:
    @pytest.mark.asyncio
    async def test_resolve_success(self, ctx, sample_alert, fsr_config_with_tenant):
        """Happy path: resolve an Open alert in the agent's tenant."""
        tool = FortiSOARResolveAlertTool()

        closed_iri = "/api/3/picklists/CLOSED-UUID"
        risk_accept_iri = "/api/3/picklists/RISK-ACCEPT-UUID"

        async def mock_fsr_get(config, endpoint):
            if endpoint.startswith("/api/3/alerts?id="):
                return {"hydra:member": [sample_alert], "hydra:totalItems": 1}
            if "picklist_names?name=AlertStatus" in endpoint:
                return {
                    "hydra:member": [
                        {
                            "@id": "/api/3/picklist_names/STATUS",
                            "picklists": [
                                {"itemValue": "Open", "@id": "/api/3/picklists/OPEN"},
                                {"itemValue": "Closed", "@id": closed_iri},
                            ],
                        }
                    ]
                }
            if "picklist_names?name=Closure%20Reason" in endpoint or "Closure Reason" in endpoint:
                return {
                    "hydra:member": [
                        {
                            "@id": "/api/3/picklist_names/REASON",
                            "picklists": [
                                {"itemValue": "Risk Accept", "@id": risk_accept_iri},
                                {"itemValue": "Resolved", "@id": "/api/3/picklists/RESOLVED"},
                            ],
                        }
                    ]
                }
            raise AssertionError(f"Unexpected GET: {endpoint}")

        captured_put = {}

        async def mock_fsr_put(config, endpoint, payload):
            captured_put["endpoint"] = endpoint
            captured_put["payload"] = payload
            updated = dict(sample_alert)
            updated["status"] = {"itemValue": "Closed"}
            updated["closureReason"] = {"itemValue": "Risk Accept"}
            updated["closureNotes"] = payload["closureNotes"]
            return updated

        with patch(
            "openharness.tools.fortisoar_resolve_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_put",
            side_effect=mock_fsr_put,
        ):
            result = await tool.execute(
                FortiSOARResolveAlertInput(
                    alert_id="Alert-108160",
                    closure_notes=(
                        "Investigation complete: source IP 10.125.19.31 is the FortiRecon "
                        "internal threat-intel collector. Detection accurate but activity is authorized."
                    ),
                    closure_reason="Risk Accept",
                ),
                ctx,
            )

        assert not result.is_error
        assert "resolved" in result.output.lower()
        assert "Closed" in result.output
        assert "Risk Accept" in result.output
        # Verify the PUT payload
        assert captured_put["endpoint"] == f"/api/3/alerts/{sample_alert['uuid']}"
        assert captured_put["payload"]["status"] == closed_iri
        assert captured_put["payload"]["closureReason"] == risk_accept_iri
        assert "FortiRecon" in captured_put["payload"]["closureNotes"]
        # BIS-AI marker is on the actual notes that hit FortiSOAR
        assert captured_put["payload"]["closureNotes"].startswith(BIS_AI_TRIAGE_MARKER)

    @pytest.mark.asyncio
    async def test_is_not_read_only(self):
        """Resolve tool MUST be marked as mutating so the human approves it."""
        tool = FortiSOARResolveAlertTool()
        assert tool.is_read_only(
            FortiSOARResolveAlertInput(
                alert_id="Alert-1",
                closure_notes="Padding to satisfy minimum length requirement",
                closure_reason="Resolved",
            )
        ) is False

    @pytest.mark.asyncio
    async def test_invalid_closure_reason_substituted(
        self, ctx, sample_alert, fsr_config_with_tenant
    ):
        """An invalid/off-list closure_reason (including the deprecated 'False
        Positive') must be silently substituted with 'Tasks Completed' instead
        of erroring — picking a closure reason is subjective and we'd rather
        close the alert with a safe default than fail the run."""
        tool = FortiSOARResolveAlertTool()

        closed_iri = "/api/3/picklists/CLOSED-UUID"
        tasks_completed_iri = "/api/3/picklists/TASKS-COMPLETED-UUID"

        async def mock_fsr_get(config, endpoint):
            if endpoint.startswith("/api/3/alerts?id="):
                return {"hydra:member": [sample_alert], "hydra:totalItems": 1}
            if "picklist_names?name=AlertStatus" in endpoint:
                return {
                    "hydra:member": [
                        {
                            "@id": "/api/3/picklist_names/STATUS",
                            "picklists": [
                                {"itemValue": "Closed", "@id": closed_iri},
                            ],
                        }
                    ]
                }
            if "Closure Reason" in endpoint or "Closure%20Reason" in endpoint:
                return {
                    "hydra:member": [
                        {
                            "@id": "/api/3/picklist_names/REASON",
                            "picklists": [
                                {"itemValue": "Tasks Completed", "@id": tasks_completed_iri},
                            ],
                        }
                    ]
                }
            raise AssertionError(f"Unexpected GET: {endpoint}")

        captured_put = {}

        async def mock_fsr_put(config, endpoint, payload):
            captured_put["payload"] = payload
            updated = dict(sample_alert)
            updated["status"] = {"itemValue": "Closed"}
            updated["closureReason"] = {"itemValue": "Tasks Completed"}
            updated["closureNotes"] = payload["closureNotes"]
            return updated

        with patch(
            "openharness.tools.fortisoar_resolve_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_put",
            side_effect=mock_fsr_put,
        ):
            result = await tool.execute(
                FortiSOARResolveAlertInput(
                    alert_id="Alert-108160",
                    closure_notes="Padding notes that satisfy the minimum length requirement",
                    closure_reason="False Positive",  # off-list — should be substituted
                ),
                ctx,
            )

        assert not result.is_error
        # PUT was issued with the substituted Tasks Completed IRI
        assert captured_put["payload"]["closureReason"] == tasks_completed_iri
        # Output explains the substitution so the operator can audit it
        assert "substituted 'Tasks Completed'" in result.output
        assert "False Positive" in result.output

    @pytest.mark.asyncio
    async def test_missing_notes_returns_template(self, ctx, sample_alert, fsr_config_with_tenant):
        """If closure_notes is missing/short, the tool builds a template and returns
        it as an error so the model can copy it on the next call."""
        tool = FortiSOARResolveAlertTool()

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [sample_alert], "hydra:totalItems": 1}

        with patch(
            "openharness.tools.fortisoar_resolve_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_put",
            new_callable=AsyncMock,
        ) as mock_put:
            # Call with no closure_notes — model forgot to write them
            result = await tool.execute(
                FortiSOARResolveAlertInput(
                    alert_id="Alert-108160",
                    closure_reason="Risk Accept",
                ),
                ctx,
            )

        assert result.is_error
        # Template should mention the alert ID and key facts
        assert "COPY THIS TEMPLATE" in result.output
        assert "108160" in result.output
        assert "10.125.19.31" in result.output  # source IP from sample_alert
        assert "Risk Accept" in result.output
        # Critical: no PUT should have been issued
        mock_put.assert_not_called()

    @pytest.mark.asyncio
    async def test_too_short_notes_returns_template(self, ctx, sample_alert, fsr_config_with_tenant):
        """Notes shorter than 20 chars should also trigger the template path."""
        tool = FortiSOARResolveAlertTool()

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [sample_alert], "hydra:totalItems": 1}

        with patch(
            "openharness.tools.fortisoar_resolve_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_put",
            new_callable=AsyncMock,
        ) as mock_put:
            result = await tool.execute(
                FortiSOARResolveAlertInput(
                    alert_id="Alert-108160",
                    closure_notes="too short",
                    closure_reason="Resolved",
                ),
                ctx,
            )

        assert result.is_error
        assert "COPY THIS TEMPLATE" in result.output
        mock_put.assert_not_called()

    @pytest.mark.asyncio
    async def test_foreign_tenant_rejected(self, ctx, sample_alert, fsr_config_with_tenant):
        tool = FortiSOARResolveAlertTool()
        foreign_alert = dict(sample_alert)
        foreign_alert["tenant"] = {"name": "Burnaby MIS"}

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [foreign_alert], "hydra:totalItems": 1}

        with patch(
            "openharness.tools.fortisoar_resolve_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_put",
            new_callable=AsyncMock,
        ) as mock_put:
            result = await tool.execute(
                FortiSOARResolveAlertInput(
                    alert_id="Alert-108160",
                    closure_notes="This investigation found the alert to be a false positive",
                    closure_reason="False Positive",
                ),
                ctx,
            )

        assert result.is_error
        assert "Access denied" in result.output
        # Critical: PUT must NOT have been called
        mock_put.assert_not_called()

    @pytest.mark.asyncio
    async def test_foreign_source_rejected(self, ctx, sample_alert, fsr_config_with_tenant):
        """Even if tenant matches, foreign source must be rejected — no PUT issued."""
        tool = FortiSOARResolveAlertTool()
        foreign_alert = dict(sample_alert)
        # Same tenant (Cloud Services) but different source
        foreign_alert["source"] = "FortiStack CA FSM"

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [foreign_alert], "hydra:totalItems": 1}

        with patch(
            "openharness.tools.fortisoar_resolve_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_put",
            new_callable=AsyncMock,
        ) as mock_put:
            result = await tool.execute(
                FortiSOARResolveAlertInput(
                    alert_id="Alert-108160",
                    closure_notes="Detailed investigation notes that satisfy the minimum length",
                    closure_reason="Resolved",
                ),
                ctx,
            )

        assert result.is_error
        assert "Access denied" in result.output
        assert "FortiStack CA FSM" in result.output
        # Critical: PUT must NOT have been called
        mock_put.assert_not_called()

    @pytest.mark.asyncio
    async def test_already_closed(self, ctx, sample_alert, fsr_config_with_tenant):
        tool = FortiSOARResolveAlertTool()
        closed_alert = dict(sample_alert)
        closed_alert["status"] = {"itemValue": "Closed"}
        closed_alert["closureNotes"] = "Previously closed by analyst"

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [closed_alert], "hydra:totalItems": 1}

        with patch(
            "openharness.tools.fortisoar_resolve_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_put",
            new_callable=AsyncMock,
        ) as mock_put:
            result = await tool.execute(
                FortiSOARResolveAlertInput(
                    alert_id="Alert-108160",
                    closure_notes="This investigation found the alert to be a false positive",
                    closure_reason="False Positive",
                ),
                ctx,
            )

        assert result.is_error
        assert "already Closed" in result.output
        mock_put.assert_not_called()


class TestRegistration:
    def test_fortisoar_tools_registered(self):
        from openharness.tools import create_default_tool_registry
        registry = create_default_tool_registry()
        assert registry.get("fortisoar_list_alerts") is not None
        assert registry.get("fortisoar_get_alert") is not None
        assert registry.get("fortisoar_resolve_alert") is not None


# ---------------------------------------------------------------------------
# fortisoar_get_alert: whitelist auto-close path
# ---------------------------------------------------------------------------


class TestGetAlertWhitelistAutoClose:
    """fortisoar_get_alert auto-closes alerts whose source IP matches the
    SOC whitelist, returning a data-starved STOP message instead of the
    normal alert details."""

    @pytest.fixture
    def whitelist_yaml(self, tmp_path: Path, monkeypatch):
        """Write a whitelist file matching sample_alert.sourceIp (10.125.19.31)."""
        f = tmp_path / "wl.yaml"
        f.write_text(
            "- ip: 10.125.19.31\n"
            '  reason: "FortiRecon internal threat-intel collector"\n'
            "  added_by: kaini\n"
            "  added_on: 2026-04-08\n"
            "  closure_reason: Risk Accept\n"
        )
        monkeypatch.setenv("SOC_WHITELIST_FILE", str(f))
        return f

    @pytest.fixture
    def picklist_iris(self):
        return {
            "closed": "/api/3/picklists/CLOSED-UUID",
            "risk_accept": "/api/3/picklists/RISK-ACCEPT-UUID",
        }

    @pytest.mark.asyncio
    async def test_whitelist_hit_auto_closes_and_returns_stop(
        self,
        ctx,
        sample_alert,
        fsr_config_with_tenant,
        whitelist_yaml,
        picklist_iris,
    ):
        """Whitelist hit on an Open alert: tool issues PUT to close, returns
        the STOP message, response contains NO investigation data."""
        tool = FortiSOARGetAlertTool()

        async def mock_fsr_get(config, endpoint):
            if endpoint.startswith("/api/3/alerts?id=") or endpoint.startswith("/api/3/alerts/"):
                # Both lookup paths return the alert; the second is when
                # auto_close_alert calls back into the resolve tool's static
                # methods (via the picklist resolver below). Picklist endpoints
                # are also routed here in this test.
                if "picklist_names" in endpoint:
                    pass  # fall through to picklist handling
                else:
                    return {"hydra:member": [sample_alert], "hydra:totalItems": 1}
            if "picklist_names?name=AlertStatus" in endpoint:
                return {
                    "hydra:member": [
                        {
                            "@id": "/api/3/picklist_names/STATUS",
                            "picklists": [
                                {"itemValue": "Closed", "@id": picklist_iris["closed"]},
                            ],
                        }
                    ]
                }
            if "Closure Reason" in endpoint or "Closure%20Reason" in endpoint:
                return {
                    "hydra:member": [
                        {
                            "@id": "/api/3/picklist_names/REASON",
                            "picklists": [
                                {"itemValue": "Risk Accept", "@id": picklist_iris["risk_accept"]},
                            ],
                        }
                    ]
                }
            raise AssertionError(f"unexpected GET: {endpoint}")

        captured_put = {}

        async def mock_fsr_put(config, endpoint, payload):
            captured_put["endpoint"] = endpoint
            captured_put["payload"] = payload
            return dict(sample_alert)

        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            # auto_close_alert lazy-imports fsr_put from _fortisoar_helpers
            # inside the function body, so each call re-evaluates the import
            # and the patch on the source module DOES take effect.
            "openharness.tools._fortisoar_helpers.fsr_put",
            side_effect=mock_fsr_put,
        ), patch(
            # The picklist resolver lives on FortiSOARResolveAlertTool and
            # calls fsr_get via its module-level binding (imported at load
            # time), so we must patch fsr_get at THAT location, not at the
            # _fortisoar_helpers source module.
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ):
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="Alert-108160"), ctx
            )

        # Tool succeeded
        assert not result.is_error

        # PUT was issued with the right payload (Closed + Risk Accept)
        assert captured_put["endpoint"] == f"/api/3/alerts/{sample_alert['uuid']}"
        assert captured_put["payload"]["status"] == picklist_iris["closed"]
        assert captured_put["payload"]["closureReason"] == picklist_iris["risk_accept"]
        # Audit-trail closure_notes were written to FortiSOAR
        assert "Auto-closed by SOC agent whitelist policy" in captured_put["payload"]["closureNotes"]
        assert "FortiRecon" in captured_put["payload"]["closureNotes"]
        # BIS-AI marker is the FIRST line of the audit-trail closure notes
        assert captured_put["payload"]["closureNotes"].startswith(BIS_AI_TRIAGE_MARKER)

        # STOP message returned to the LLM
        assert "AUTO-CLOSED BY WHITELIST POLICY" in result.output
        assert "Alert-108160" in result.output
        assert "FortiRecon" in result.output  # the human reason text is OK
        assert "STOP" in result.output

        # CRITICAL: data starvation. The response must NOT contain anything
        # the LLM could feed to a FAZ correlation tool.
        assert "10.125.19.31" not in result.output  # source IP -> faz_query_logs ip_address
        assert "185.162.184.10" not in result.output  # destination IP
        assert "FortiCloud_Server" not in result.output  # ADOM
        assert "FortiCloud_MIS" not in result.output  # other ADOM
        assert "correlation hints" not in result.output
        assert "suggested_correlation_queries" not in result.output
        assert "faz_query_logs" not in result.output
        assert "faz_query_security_events" not in result.output
        # Detection-time-shaped strings should not appear (no '2025-' or '2026-' dates)
        # Note: the alert ID number 108160 is fine; we're checking for date strings
        import re as _re
        assert _re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", result.output) is None

    @pytest.mark.asyncio
    async def test_whitelist_miss_returns_normal_format(
        self, ctx, sample_alert, fsr_config_with_tenant, tmp_path, monkeypatch
    ):
        """Whitelist miss: tool returns the normal compact alert format and
        does NOT issue any PUT. Existing investigation flow is unchanged."""
        # Whitelist with an entry that does NOT match sample_alert.sourceIp
        f = tmp_path / "wl.yaml"
        f.write_text(
            "- ip: 203.0.113.42\n"
            '  reason: "Some other IP that does not match the test alert"\n'
            "  added_by: kaini\n"
            "  added_on: 2026-04-08\n"
        )
        monkeypatch.setenv("SOC_WHITELIST_FILE", str(f))

        tool = FortiSOARGetAlertTool()

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [sample_alert], "hydra:totalItems": 1}

        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools._fortisoar_helpers.fsr_put",
            new_callable=AsyncMock,
        ) as mock_put:
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="Alert-108160"), ctx
            )

        assert not result.is_error
        # No PUT — alert was not closed
        mock_put.assert_not_called()
        # Normal format markers present
        assert "AUTO-CLOSED BY WHITELIST POLICY" not in result.output
        assert f"Alert-{sample_alert['id']}" in result.output

    @pytest.mark.asyncio
    async def test_already_closed_skips_whitelist_check(
        self, ctx, sample_alert, fsr_config_with_tenant, whitelist_yaml
    ):
        """If the alert is already Closed, skip the whitelist check entirely.
        Do NOT issue another PUT — that would be a double-close."""
        tool = FortiSOARGetAlertTool()
        closed_alert = dict(sample_alert)
        closed_alert["status"] = {"itemValue": "Closed"}
        closed_alert["closureNotes"] = "Previously closed by a human analyst"

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [closed_alert], "hydra:totalItems": 1}

        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools._fortisoar_helpers.fsr_put",
            new_callable=AsyncMock,
        ) as mock_put:
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="Alert-108160"), ctx
            )

        assert not result.is_error
        # No double-close
        mock_put.assert_not_called()
        # Normal format (closure-already-set branch)
        assert "AUTO-CLOSED BY WHITELIST POLICY" not in result.output

    @pytest.mark.asyncio
    async def test_no_whitelist_configured_falls_through(
        self, ctx, sample_alert, fsr_config_with_tenant, monkeypatch
    ):
        """If SOC_WHITELIST_FILE is unset, tool returns normal format
        unchanged. No regression for users who don't use the whitelist."""
        monkeypatch.delenv("SOC_WHITELIST_FILE", raising=False)
        tool = FortiSOARGetAlertTool()

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [sample_alert], "hydra:totalItems": 1}

        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools._fortisoar_helpers.fsr_put",
            new_callable=AsyncMock,
        ) as mock_put:
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="Alert-108160"), ctx
            )

        assert not result.is_error
        mock_put.assert_not_called()
        assert "AUTO-CLOSED BY WHITELIST POLICY" not in result.output

    @pytest.mark.asyncio
    async def test_malformed_whitelist_falls_through_safely(
        self,
        ctx,
        sample_alert,
        fsr_config_with_tenant,
        tmp_path,
        monkeypatch,
    ):
        """A broken whitelist YAML must NOT wedge get_alert. The tool falls
        through to the normal flow so the user can still investigate."""
        bad = tmp_path / "broken.yaml"
        bad.write_text("- ip: 10.0.0.1\n  reason: [unclosed bracket")
        monkeypatch.setenv("SOC_WHITELIST_FILE", str(bad))

        tool = FortiSOARGetAlertTool()

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [sample_alert], "hydra:totalItems": 1}

        with patch(
            "openharness.tools.fortisoar_get_alert_tool.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.tools.fortisoar_get_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ), patch(
            "openharness.tools._fortisoar_helpers.fsr_put",
            new_callable=AsyncMock,
        ) as mock_put:
            result = await tool.execute(
                FortiSOARGetAlertInput(alert_id="Alert-108160"), ctx
            )

        # get_alert still works — no PUT, normal format
        assert not result.is_error
        mock_put.assert_not_called()
        assert "AUTO-CLOSED BY WHITELIST POLICY" not in result.output
