# SOC Agent: Netbox IP Ownership Lookup

**Status:** Planned — waiting on Netbox API token
**Date:** 2026-04-12
**Owner:** kaini

## Purpose

Netbox is running in the environment and contains IP-to-owner mappings for
internal assets. Integrating it as a lookup enriches the SOC agent's alert
context with ownership information:

- **"Is this IP a known asset?"** — yes/no. An internal IP not in Netbox is
  suspicious on its own (unknown device on the network).
- **"Who owns it?"** — when escalating, the notification names the owning
  team instead of just an IP address. The analyst immediately knows who to
  contact.

## What Netbox does NOT provide (for most IPs)

Per the user (2026-04-12): Netbox in this environment primarily has owner
info. Few entries have service names. So this is NOT a full CMDB with
role/service/behavioral metadata. Do not build a rich "asset context" system
around it — just ownership lookup.

Specifically:
- ✅ Is this IP a known asset? (yes/no)
- ✅ Who owns it? (owner/tenant/team)
- ❌ What's its role? (depends on Netbox admin populating this — don't rely on it)
- ❌ Is it expected to accept external connections? (not available)

## How it fits the architecture

**NOT a standalone tool.** A helper function called inside
`fortisoar_get_alert` during correlation-hint building — same pattern as
the whitelist lookup. The model never calls Netbox directly; it sees the
enriched IP labels.

**Output format — one line per IP, appended to existing labels:**

```
source_ip: 104.204.191.105 (EXTERNAL) — not in Netbox
destination_ip: 10.125.68.82 (INTERNAL) — Netbox: owner=cloud-ops, device=BIS-WEB-01
```

No behavioral guidance, no role context, no "expected traffic" hints. Just
ownership for closure notes and escalation messages.

## Escalation payoff

When SMTP/Teams is ready, the escalation email benefits directly:

```
ESCALATION: Alert-110053
Source: 104.204.191.105 (EXTERNAL, not in Netbox)
Destination: 10.125.68.82 (INTERNAL, owner: cloud-ops, device: BIS-WEB-01)
Contact: cloud-ops team
```

The analyst gets the owner name without opening Netbox themselves.

## Implementation plan

### Files

- `src/openharness/tools/_netbox_helpers.py` (NEW)
  - `get_netbox_config()` — reads `NETBOX_URL`, `NETBOX_API_TOKEN`,
    `NETBOX_VERIFY_SSL` from env. Fail-closed if missing but return None
    (not ValueError) so the alert flow isn't blocked by Netbox being down.
  - `lookup_ip(ip: str) -> dict | None` — calls
    `/api/ipam/ip-addresses/?address=<ip>`, returns `{owner, device, tenant,
    description}` or None if not found / Netbox unreachable.

- `src/openharness/tools/fortisoar_get_alert_tool.py` (MODIFY)
  - In `_label_ip()` or `_build_correlation_hints()`, call
    `_netbox_helpers.lookup_ip()` for each internal IP.
  - Append Netbox info to the label: `"10.125.68.82 (INTERNAL) — Netbox:
    owner=cloud-ops, device=BIS-WEB-01"`.
  - If Netbox is unconfigured or lookup fails, fall back to just the
    INTERNAL/EXTERNAL label (no regression for environments without Netbox).

- `.env` additions:
  ```bash
  NETBOX_URL=https://your-netbox-host
  NETBOX_API_TOKEN=your_token
  NETBOX_VERIFY_SSL=false
  ```

### Behavior on failure

Netbox being down or unconfigured MUST NOT block alert processing. The
lookup is best-effort:
- Netbox env vars unset → skip lookup, use bare labels
- Netbox unreachable → skip lookup, log warning to stderr
- IP not found in Netbox → label says "not in Netbox"
- Netbox returns data → label includes owner/device

This is different from FortiSOAR/FAZ which are fail-closed (the agent can't
work without them). Netbox is fail-open (nice to have, not required).

### Estimated effort

~Half a day: helper module, one modification to `fortisoar_get_alert_tool.py`,
env var config, tests (mocked Netbox responses).

### Prerequisites

- [ ] Netbox API token provisioned (read-only is sufficient)
- [ ] Netbox URL confirmed
- [ ] Verify which Netbox API version is running (v3.x vs v4.x — the
      `/api/ipam/ip-addresses/` endpoint is stable across versions but
      response field names may differ)

## Related documents

- `docs/soc-cmdb-and-fine-tuning-decision.md` — earlier CMDB discussion;
  Netbox is the concrete instance of that design
- Memory: `project_cmdb_first_finetuning_deferred.md` — CMDB before fine-tuning
