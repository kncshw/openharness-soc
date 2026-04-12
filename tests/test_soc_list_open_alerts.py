"""Unit tests for the soc_list_open_alerts CLI helper used by bin/oh-soc."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from openharness.soc_list_open_alerts import (
    _DRAIN_LIMIT_PER_SEVERITY,
    _INCLUDED_SEVERITIES,
    list_open_alert_ids,
)


@pytest.fixture
def fsr_config_with_tenant():
    return {
        "url": "https://fortisoar.test.local",
        "public_key": "PUBKEY",
        "private_key": "PRIVKEY",
        "verify_ssl": False,
        "tenant": "Cloud Services",
        "source": "IS_FAZ_MIS_Cloud",
    }


@pytest.fixture
def crit_alerts():
    """3 Critical alerts, newest first by createDate."""
    return [
        {"id": 109201, "createDate": 1775520000.0},
        {"id": 109202, "createDate": 1775519000.0},
        {"id": 109203, "createDate": 1775518000.0},
    ]


@pytest.fixture
def high_alerts():
    return [
        {"id": 109210, "createDate": 1775519500.0},
        {"id": 109211, "createDate": 1775518500.0},
    ]


class TestListOpenAlertIds:
    @pytest.mark.asyncio
    async def test_drains_all_severities_sorted_newest_first(
        self, fsr_config_with_tenant, crit_alerts, high_alerts
    ):
        """The helper merges Critical + High results, sorts by createDate
        descending, and returns Alert-NNN strings — same ordering as the
        LLM-facing fortisoar_list_alerts tool."""

        captured_endpoints = []

        async def mock_fsr_get(config, endpoint):
            captured_endpoints.append(endpoint)
            if "Critical" in endpoint:
                return {"hydra:member": crit_alerts, "hydra:totalItems": 3}
            if "High" in endpoint:
                return {"hydra:member": high_alerts, "hydra:totalItems": 2}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        with patch(
            "openharness.soc_list_open_alerts.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.soc_list_open_alerts.fsr_get",
            side_effect=mock_fsr_get,
        ):
            ids = await list_open_alert_ids()

        # 3 Critical + 2 High = 5 total
        assert len(ids) == 5
        # All formatted as Alert-NNN
        assert all(s.startswith("Alert-") for s in ids)
        # Sorted newest first by createDate. Given fixture timestamps:
        #   109201 = 1775520000  (highest)
        #   109210 = 1775519500
        #   109202 = 1775519000
        #   109211 = 1775518500
        #   109203 = 1775518000  (lowest)
        assert ids == [
            "Alert-109201",
            "Alert-109210",
            "Alert-109202",
            "Alert-109211",
            "Alert-109203",
        ]
        # Both severities were queried (parallel fetch, one endpoint per severity)
        assert any("Critical" in e for e in captured_endpoints)
        assert any("High" in e for e in captured_endpoints)

    @pytest.mark.asyncio
    async def test_drain_limit_is_higher_than_llm_tool_cap(
        self, fsr_config_with_tenant
    ):
        """The drain helper must use a much higher limit than the LLM tool's
        20-cap. Otherwise the wrapper would only see 20 alerts per drain run."""

        async def mock_fsr_get(config, endpoint):
            # Verify the $limit param in the endpoint URL is the drain limit
            assert f"$limit={_DRAIN_LIMIT_PER_SEVERITY}" in endpoint
            return {"hydra:member": [], "hydra:totalItems": 0}

        with patch(
            "openharness.soc_list_open_alerts.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.soc_list_open_alerts.fsr_get",
            side_effect=mock_fsr_get,
        ):
            await list_open_alert_ids()

        # Sanity check the constant itself is comfortably above the LLM tool's cap
        assert _DRAIN_LIMIT_PER_SEVERITY >= 100

    @pytest.mark.asyncio
    async def test_status_is_hardcoded_to_open(self, fsr_config_with_tenant):
        """The helper only ever drains Open alerts. Investigating/Closed must
        be excluded so the wrapper doesn't reprocess work the bot or a human
        already did."""

        captured_endpoints = []

        async def mock_fsr_get(config, endpoint):
            captured_endpoints.append(endpoint)
            return {"hydra:member": [], "hydra:totalItems": 0}

        with patch(
            "openharness.soc_list_open_alerts.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.soc_list_open_alerts.fsr_get",
            side_effect=mock_fsr_get,
        ):
            await list_open_alert_ids()

        # Every endpoint URL pins status to Open
        for ep in captured_endpoints:
            assert "status.itemValue=Open" in ep

    @pytest.mark.asyncio
    async def test_tenant_and_source_filters_applied(self, fsr_config_with_tenant):
        """Tenant + source guards from the existing _fortisoar_helpers config
        must be propagated to the query so the helper respects the same
        scoping as the LLM tools."""

        captured_endpoints = []

        async def mock_fsr_get(config, endpoint):
            captured_endpoints.append(endpoint)
            return {"hydra:member": [], "hydra:totalItems": 0}

        with patch(
            "openharness.soc_list_open_alerts.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.soc_list_open_alerts.fsr_get",
            side_effect=mock_fsr_get,
        ):
            await list_open_alert_ids()

        for ep in captured_endpoints:
            assert "tenant.name=Cloud Services" in ep
            assert "source=IS_FAZ_MIS_Cloud" in ep

    @pytest.mark.asyncio
    async def test_empty_queue_returns_empty_list(self, fsr_config_with_tenant):
        """Zero open alerts is success, not error. The wrapper handles the
        empty case by printing a 'nothing to process' message."""

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [], "hydra:totalItems": 0}

        with patch(
            "openharness.soc_list_open_alerts.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.soc_list_open_alerts.fsr_get",
            side_effect=mock_fsr_get,
        ):
            ids = await list_open_alert_ids()

        assert ids == []

    @pytest.mark.asyncio
    async def test_total_failure_raises(self, fsr_config_with_tenant):
        """If BOTH severity queries fail, surface a clear error so the wrapper
        exits non-zero. Partial failures (one severity succeeds, the other
        errors) are tolerated — see test_partial_failure_returns_partial."""

        async def mock_fsr_get(config, endpoint):
            raise RuntimeError("FortiSOAR is down")

        with patch(
            "openharness.soc_list_open_alerts.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.soc_list_open_alerts.fsr_get",
            side_effect=mock_fsr_get,
        ):
            with pytest.raises(RuntimeError, match="FortiSOAR error"):
                await list_open_alert_ids()

    @pytest.mark.asyncio
    async def test_partial_failure_returns_partial(
        self, fsr_config_with_tenant, crit_alerts
    ):
        """If Critical succeeds but High fails, return the Critical alerts.
        Tolerated because the wrapper will pick up missed alerts on the next
        drain run, and we'd rather process some than none."""

        async def mock_fsr_get(config, endpoint):
            if "Critical" in endpoint:
                return {"hydra:member": crit_alerts, "hydra:totalItems": 3}
            raise RuntimeError("High severity fetch failed")

        with patch(
            "openharness.soc_list_open_alerts.get_fsr_config",
            return_value=fsr_config_with_tenant,
        ), patch(
            "openharness.soc_list_open_alerts.fsr_get",
            side_effect=mock_fsr_get,
        ):
            ids = await list_open_alert_ids()

        # Got the 3 Critical alerts despite High failing
        assert len(ids) == 3
        assert all(s.startswith("Alert-") for s in ids)
