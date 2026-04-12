"""Unit tests for the SOC whitelist + auto-close path."""

from __future__ import annotations

import subprocess
from datetime import date
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from openharness.tools._whitelist import (
    BIS_AI_TRIAGE_MARKER,
    Whitelist,
    WhitelistEntry,
    WhitelistMatch,
    build_auto_close_notes,
    git_blob_sha,
    load_whitelist,
)


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


class TestWhitelistEntrySchema:
    def test_valid_ip_entry(self):
        e = WhitelistEntry(
            ip="10.125.19.31",
            reason="FortiRecon collector permanent infrastructure",
            added_by="kaini",
            added_on=date(2026, 4, 8),
        )
        assert e.ip == "10.125.19.31"
        assert e.cidr is None
        assert e.closure_reason == "Tasks Completed"  # default
        assert e.selector == "10.125.19.31"

    def test_valid_cidr_entry(self):
        e = WhitelistEntry(
            cidr="10.125.16.0/20",
            reason="BIS internal management subnet for scanners",
            added_by="kaini",
            added_on=date(2026, 4, 8),
            closure_reason="Risk Accept",
        )
        assert e.cidr == "10.125.16.0/20"
        assert e.closure_reason == "Risk Accept"

    def test_both_ip_and_cidr_rejected(self):
        with pytest.raises(ValueError, match="exactly one of 'ip' or 'cidr'"):
            WhitelistEntry(
                ip="10.0.0.1",
                cidr="10.0.0.0/24",
                reason="rejected because both fields are set",
                added_by="kaini",
                added_on=date(2026, 4, 8),
            )

    def test_neither_ip_nor_cidr_rejected(self):
        with pytest.raises(ValueError, match="exactly one of 'ip' or 'cidr'"):
            WhitelistEntry(
                reason="rejected because neither field is set",
                added_by="kaini",
                added_on=date(2026, 4, 8),
            )

    def test_invalid_ip_rejected(self):
        with pytest.raises(ValueError, match="invalid 'ip'"):
            WhitelistEntry(
                ip="not.an.ip",
                reason="should fail ipaddress parsing",
                added_by="kaini",
                added_on=date(2026, 4, 8),
            )

    def test_invalid_cidr_rejected(self):
        with pytest.raises(ValueError, match="invalid 'cidr'"):
            WhitelistEntry(
                cidr="garbage/24",
                reason="should fail ipaddress parsing",
                added_by="kaini",
                added_on=date(2026, 4, 8),
            )

    def test_cidr_too_broad_rejected(self):
        # /8 must be refused -- 16M IPs is way too many
        with pytest.raises(ValueError, match="broader than the safety floor"):
            WhitelistEntry(
                cidr="10.0.0.0/8",
                reason="ten dot eight is way too broad for a whitelist",
                added_by="kaini",
                added_on=date(2026, 4, 8),
            )

    def test_cidr_zero_prefix_rejected(self):
        # The catastrophic case: /0 = match every IP on the internet
        with pytest.raises(ValueError, match="broader than the safety floor"):
            WhitelistEntry(
                cidr="0.0.0.0/0",
                reason="zero prefix would auto-close every alert ever",
                added_by="kaini",
                added_on=date(2026, 4, 8),
            )

    def test_cidr_at_floor_accepted(self):
        # /16 is the floor and must be accepted
        e = WhitelistEntry(
            cidr="10.125.0.0/16",
            reason="full /16 at the safety floor should be accepted",
            added_by="kaini",
            added_on=date(2026, 4, 8),
        )
        assert e.cidr == "10.125.0.0/16"

    def test_invalid_closure_reason_rejected(self):
        with pytest.raises(ValueError, match="not in the resolve tool's allowlist"):
            WhitelistEntry(
                ip="10.125.19.31",
                reason="should fail because closure_reason is not in allowlist",
                added_by="kaini",
                added_on=date(2026, 4, 8),
                closure_reason="False Positive",  # explicitly removed
            )

    def test_short_reason_rejected(self):
        with pytest.raises(ValueError):
            WhitelistEntry(
                ip="10.125.19.31",
                reason="too short",  # < 10 chars
                added_by="kaini",
                added_on=date(2026, 4, 8),
            )


# ---------------------------------------------------------------------------
# Whitelist (collection) validation + lookup
# ---------------------------------------------------------------------------


class TestWhitelistCollection:
    def _entry(self, **kwargs) -> WhitelistEntry:
        defaults = {
            "reason": "test entry for unit tests, plenty long",
            "added_by": "test",
            "added_on": date(2026, 4, 8),
        }
        defaults.update(kwargs)
        return WhitelistEntry(**defaults)

    def test_duplicate_selectors_rejected(self):
        with pytest.raises(ValueError, match="duplicate whitelist entry"):
            Whitelist(
                entries=[
                    self._entry(ip="10.125.19.31"),
                    self._entry(ip="10.125.19.31"),  # duplicate
                ]
            )

    def test_duplicate_cidr_rejected(self):
        with pytest.raises(ValueError, match="duplicate whitelist entry"):
            Whitelist(
                entries=[
                    self._entry(cidr="10.125.16.0/20"),
                    self._entry(cidr="10.125.16.0/20"),
                ]
            )

    def test_lookup_exact_ip_hit(self):
        wl = Whitelist(
            entries=[
                self._entry(ip="10.125.19.31", reason="FortiRecon collector entry"),
            ]
        )
        match = wl.lookup_ip("10.125.19.31")
        assert match is not None
        assert match.matched_on == "exact"
        assert match.entry.ip == "10.125.19.31"

    def test_lookup_cidr_hit(self):
        wl = Whitelist(
            entries=[
                self._entry(cidr="10.125.16.0/20", reason="management subnet block"),
            ]
        )
        match = wl.lookup_ip("10.125.18.47")  # inside /20
        assert match is not None
        assert match.matched_on == "cidr"
        assert match.entry.cidr == "10.125.16.0/20"

    def test_lookup_outside_cidr_miss(self):
        wl = Whitelist(
            entries=[
                self._entry(cidr="10.125.16.0/20", reason="management subnet block"),
            ]
        )
        assert wl.lookup_ip("10.126.0.1") is None

    def test_lookup_no_entries_miss(self):
        wl = Whitelist()
        assert wl.lookup_ip("10.0.0.1") is None

    def test_lookup_invalid_ip_returns_none(self):
        wl = Whitelist(entries=[self._entry(ip="10.125.19.31")])
        assert wl.lookup_ip("not.an.ip") is None

    def test_exact_takes_precedence_over_cidr(self):
        # Exact IP listed FIRST should win even though a CIDR also matches
        wl = Whitelist(
            entries=[
                self._entry(
                    ip="10.125.19.31", reason="exact entry should match first", closure_reason="Risk Accept"
                ),
                self._entry(
                    cidr="10.125.16.0/20", reason="cidr fallback for the same range"
                ),
            ]
        )
        match = wl.lookup_ip("10.125.19.31")
        assert match is not None
        assert match.matched_on == "exact"
        assert match.entry.closure_reason == "Risk Accept"


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------


class TestLoadWhitelist:
    def test_load_valid_file(self, tmp_path: Path):
        yaml_text = (
            "- ip: 10.125.19.31\n"
            '  reason: "FortiRecon internal threat-intel collector"\n'
            "  added_by: kaini\n"
            "  added_on: 2026-04-08\n"
            "  closure_reason: Risk Accept\n"
        )
        f = tmp_path / "wl.yaml"
        f.write_text(yaml_text)
        wl = load_whitelist(f)
        assert len(wl.entries) == 1
        assert wl.entries[0].ip == "10.125.19.31"
        assert wl.file_path == str(f)
        assert len(wl.file_sha) == 40  # sha-1 hex

    def test_load_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_whitelist(tmp_path / "does_not_exist.yaml")

    def test_load_malformed_yaml_raises(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text("- ip: 10.0.0.1\n  reason: [unclosed")
        with pytest.raises(ValueError, match="YAML parse error"):
            load_whitelist(f)

    def test_load_non_list_yaml_raises(self, tmp_path: Path):
        f = tmp_path / "dict.yaml"
        f.write_text("key: value\n")
        with pytest.raises(ValueError, match="must be a top-level list"):
            load_whitelist(f)

    def test_load_empty_file_returns_empty_whitelist(self, tmp_path: Path):
        f = tmp_path / "empty.yaml"
        f.write_text("")
        wl = load_whitelist(f)
        assert wl.entries == []

    def test_load_via_env_var(self, tmp_path: Path, monkeypatch):
        f = tmp_path / "wl.yaml"
        f.write_text(
            "- ip: 10.125.19.31\n"
            '  reason: "FortiRecon collector permanent infrastructure"\n'
            "  added_by: kaini\n"
            "  added_on: 2026-04-08\n"
        )
        monkeypatch.setenv("SOC_WHITELIST_FILE", str(f))
        wl = load_whitelist()
        assert len(wl.entries) == 1

    def test_load_no_env_no_path_returns_empty(self, monkeypatch):
        monkeypatch.delenv("SOC_WHITELIST_FILE", raising=False)
        wl = load_whitelist()
        assert wl.entries == []
        assert wl.file_path == ""

    def test_load_rejects_invalid_entry(self, tmp_path: Path):
        f = tmp_path / "bad_entry.yaml"
        f.write_text(
            "- cidr: 0.0.0.0/0\n"
            '  reason: "the catastrophic /0 case"\n'
            "  added_by: kaini\n"
            "  added_on: 2026-04-08\n"
        )
        with pytest.raises(ValueError):
            load_whitelist(f)


# ---------------------------------------------------------------------------
# git blob SHA
# ---------------------------------------------------------------------------


class TestGitBlobSha:
    def test_matches_git_hash_object(self, tmp_path: Path):
        """Our pure-python implementation must match `git hash-object` byte-for-byte."""
        content = b"hello whitelist\n"
        f = tmp_path / "x.txt"
        f.write_bytes(content)

        ours = git_blob_sha(content)
        try:
            theirs = subprocess.check_output(
                ["git", "hash-object", str(f)], stderr=subprocess.DEVNULL
            ).decode().strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("git not available")
        assert ours == theirs

    def test_empty_content(self):
        # `git hash-object /dev/null` is e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
        assert git_blob_sha(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"


# ---------------------------------------------------------------------------
# Closure notes template
# ---------------------------------------------------------------------------


class TestBuildAutoCloseNotes:
    def test_template_contains_required_fields(self):
        alert = {
            "id": 109191,
            "name": "Attack Apache.Log4j.Error.Log.Remote.Code.Execution detected",
            "sourceIp": "10.125.19.31",
            "destinationIp": "10.125.68.28",
            "sourcedata": '{"Alert": {"detection_time": "2026-04-08 14:23:11"}, "Related Logs": [{"action": "dropped"}]}',
        }
        entry = WhitelistEntry(
            ip="10.125.19.31",
            reason="FortiRecon internal threat-intel collector",
            added_by="kaini",
            added_on=date(2026, 4, 8),
            closure_reason="Risk Accept",
        )
        wl = Whitelist(
            entries=[entry], file_path="config/soc_whitelist.yaml", file_sha="a1b2c3d4"
        )
        match = WhitelistMatch(entry=entry, matched_on="exact")

        notes = build_auto_close_notes(alert, match, wl, "soc-auto-close v0.1")

        # BIS-AI marker is the very first line of the audit-trail closure notes
        assert notes.startswith(BIS_AI_TRIAGE_MARKER)
        # Audit-critical fields must all be present
        assert "Auto-closed by SOC agent whitelist policy" in notes
        assert "No LLM investigation performed" in notes
        assert "Alert-109191" in notes
        assert "10.125.19.31" in notes
        assert "10.125.68.28" in notes
        assert "Apache.Log4j" in notes
        assert "2026-04-08 14:23:11" in notes
        assert "dropped" in notes
        assert "FortiRecon" in notes
        assert "kaini" in notes
        assert "Risk Accept" in notes
        assert "config/soc_whitelist.yaml" in notes
        assert "a1b2c3d4" in notes  # whitelist sha
        assert "soc-auto-close v0.1" in notes


# ---------------------------------------------------------------------------
# Auto-close CLI integration (mocked FortiSOAR)
# ---------------------------------------------------------------------------


@pytest.fixture
def fsr_config():
    return {
        "url": "https://fortisoar.test.local",
        "public_key": "PUBKEY",
        "private_key": "PRIVKEY",
        "verify_ssl": False,
        "tenant": "Cloud Services",
        "source": "IS_FAZ_MIS_Cloud",
    }


@pytest.fixture
def open_alert_109191():
    return {
        "@id": "/api/3/alerts/aaa-uuid",
        "@type": "Alert",
        "id": 109191,
        "uuid": "aaa-uuid",
        "name": "Attack Apache.Log4j.Error.Log.Remote.Code.Execution detected",
        "status": {"itemValue": "Open"},
        "tenant": {"name": "Cloud Services"},
        "source": "IS_FAZ_MIS_Cloud",
        "sourceIp": "10.125.19.31",
        "destinationIp": "10.125.68.28",
        "sourcedata": '{"Alert": {"detection_time": "2026-04-08 14:23:11"}}',
    }


@pytest.fixture
def whitelist_with_fortirecon(tmp_path: Path, monkeypatch):
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


class TestAutoCloseCLI:
    @pytest.mark.asyncio
    async def test_happy_path_whitelist_hit(
        self, fsr_config, open_alert_109191, whitelist_with_fortirecon
    ):
        from openharness.soc_auto_close import EXIT_OK, auto_close

        closed_iri = "/api/3/picklists/CLOSED"
        risk_accept_iri = "/api/3/picklists/RISK-ACCEPT"

        async def mock_fsr_get(config, endpoint):
            if endpoint.startswith("/api/3/alerts?id="):
                return {"hydra:member": [open_alert_109191], "hydra:totalItems": 1}
            if "AlertStatus" in endpoint:
                return {
                    "hydra:member": [
                        {
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
                            "picklists": [
                                {"itemValue": "Risk Accept", "@id": risk_accept_iri},
                            ],
                        }
                    ]
                }
            raise AssertionError(f"unexpected GET: {endpoint}")

        captured_put = {}

        async def mock_fsr_put(config, endpoint, payload):
            captured_put["endpoint"] = endpoint
            captured_put["payload"] = payload
            return {"status": {"itemValue": "Closed"}}

        with patch(
            "openharness.soc_auto_close.get_fsr_config", return_value=fsr_config
        ), patch(
            "openharness.soc_auto_close.fsr_get", side_effect=mock_fsr_get
        ), patch(
            "openharness.soc_auto_close.fsr_put", side_effect=mock_fsr_put
        ), patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ):
            rc = await auto_close("Alert-109191")

        assert rc == EXIT_OK
        assert captured_put["endpoint"] == "/api/3/alerts/aaa-uuid"
        assert captured_put["payload"]["status"] == closed_iri
        assert captured_put["payload"]["closureReason"] == risk_accept_iri
        notes = captured_put["payload"]["closureNotes"]
        assert "Auto-closed by SOC agent whitelist policy" in notes
        assert "FortiRecon" in notes
        assert "10.125.19.31" in notes

    @pytest.mark.asyncio
    async def test_no_match_returns_2(
        self, fsr_config, open_alert_109191, whitelist_with_fortirecon
    ):
        from openharness.soc_auto_close import EXIT_NO_MATCH, auto_close

        # Switch the alert's source IP so it does NOT match the whitelist
        alert = dict(open_alert_109191)
        alert["sourceIp"] = "203.0.113.42"

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [alert], "hydra:totalItems": 1}

        with patch(
            "openharness.soc_auto_close.get_fsr_config", return_value=fsr_config
        ), patch(
            "openharness.soc_auto_close.fsr_get", side_effect=mock_fsr_get
        ), patch(
            "openharness.soc_auto_close.fsr_put", new_callable=AsyncMock
        ) as mock_put, patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ):
            rc = await auto_close("Alert-109191")

        assert rc == EXIT_NO_MATCH
        mock_put.assert_not_called()

    @pytest.mark.asyncio
    async def test_already_closed_returns_3(
        self, fsr_config, open_alert_109191, whitelist_with_fortirecon
    ):
        from openharness.soc_auto_close import EXIT_ALREADY_CLOSED, auto_close

        alert = dict(open_alert_109191)
        alert["status"] = {"itemValue": "Closed"}

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [alert], "hydra:totalItems": 1}

        with patch(
            "openharness.soc_auto_close.get_fsr_config", return_value=fsr_config
        ), patch(
            "openharness.soc_auto_close.fsr_get", side_effect=mock_fsr_get
        ), patch(
            "openharness.soc_auto_close.fsr_put", new_callable=AsyncMock
        ) as mock_put, patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ):
            rc = await auto_close("Alert-109191")

        assert rc == EXIT_ALREADY_CLOSED
        mock_put.assert_not_called()

    @pytest.mark.asyncio
    async def test_wrong_tenant_returns_4(
        self, fsr_config, open_alert_109191, whitelist_with_fortirecon
    ):
        from openharness.soc_auto_close import EXIT_WRONG_SCOPE, auto_close

        alert = dict(open_alert_109191)
        alert["tenant"] = {"name": "Burnaby MIS"}

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [alert], "hydra:totalItems": 1}

        with patch(
            "openharness.soc_auto_close.get_fsr_config", return_value=fsr_config
        ), patch(
            "openharness.soc_auto_close.fsr_get", side_effect=mock_fsr_get
        ), patch(
            "openharness.soc_auto_close.fsr_put", new_callable=AsyncMock
        ) as mock_put, patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ):
            rc = await auto_close("Alert-109191")

        assert rc == EXIT_WRONG_SCOPE
        mock_put.assert_not_called()

    @pytest.mark.asyncio
    async def test_wrong_source_returns_4(
        self, fsr_config, open_alert_109191, whitelist_with_fortirecon
    ):
        from openharness.soc_auto_close import EXIT_WRONG_SCOPE, auto_close

        alert = dict(open_alert_109191)
        alert["source"] = "Some Other Source"

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [alert], "hydra:totalItems": 1}

        with patch(
            "openharness.soc_auto_close.get_fsr_config", return_value=fsr_config
        ), patch(
            "openharness.soc_auto_close.fsr_get", side_effect=mock_fsr_get
        ), patch(
            "openharness.soc_auto_close.fsr_put", new_callable=AsyncMock
        ) as mock_put, patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ):
            rc = await auto_close("Alert-109191")

        assert rc == EXIT_WRONG_SCOPE
        mock_put.assert_not_called()

    @pytest.mark.asyncio
    async def test_alert_not_found_returns_5(
        self, fsr_config, whitelist_with_fortirecon
    ):
        from openharness.soc_auto_close import EXIT_NOT_FOUND, auto_close

        async def mock_fsr_get(config, endpoint):
            return {"hydra:member": [], "hydra:totalItems": 0}

        with patch(
            "openharness.soc_auto_close.get_fsr_config", return_value=fsr_config
        ), patch(
            "openharness.soc_auto_close.fsr_get", side_effect=mock_fsr_get
        ), patch(
            "openharness.soc_auto_close.fsr_put", new_callable=AsyncMock
        ) as mock_put, patch(
            "openharness.tools.fortisoar_resolve_alert_tool.fsr_get",
            side_effect=mock_fsr_get,
        ):
            rc = await auto_close("Alert-999999")

        assert rc == EXIT_NOT_FOUND
        mock_put.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_whitelist_returns_2(self, fsr_config, monkeypatch):
        from openharness.soc_auto_close import EXIT_NO_MATCH, auto_close

        # No whitelist file configured -- empty whitelist, fall through
        monkeypatch.delenv("SOC_WHITELIST_FILE", raising=False)

        with patch(
            "openharness.soc_auto_close.get_fsr_config", return_value=fsr_config
        ):
            rc = await auto_close("Alert-109191")

        assert rc == EXIT_NO_MATCH
