# SOC Agent Scoping: Tenant and Source Restrictions

This document explains how the SOC agent's scope is restricted via two
required environment variables, and how to widen the scope safely later.

## TL;DR

The agent is restricted on **two dimensions** via `.env`:

```bash
FORTISOAR_TENANT="Cloud Services"      # only this tenant's alerts
FORTISOAR_SOURCE=IS_FAZ_MIS_Cloud      # only alerts from this source tool
```

Both are **required**. If either is missing, the agent refuses to contact
FortiSOAR at all (fail-closed). This is by design — different tenants and
different alert sources need different SOC playbooks, and we don't want the
agent processing alerts outside its validated scope.

Each variable is read in **exactly one place** (`get_fsr_config()` in
`src/openharness/tools/_fortisoar_helpers.py`) and used by all three
FortiSOAR tools (`fortisoar_list_alerts`, `fortisoar_get_alert`,
`fortisoar_resolve_alert`) via `config["tenant"]` / `config["source"]`.

To change scope, edit one line in `.env`. No code changes required.

## Why both restrictions exist

| Restriction | Why it exists | Failure mode it prevents |
|---|---|---|
| `FORTISOAR_TENANT` | Shared FortiSOAR has multiple teams' alerts | Agent accidentally accessing or closing another team's alerts |
| `FORTISOAR_SOURCE` | Different sources (FortiAnalyzer IPS vs FortiSIEM brute force vs FortiWeb DLP) need different SOC playbooks; the agent has only been validated against one | Agent applying the wrong reasoning to an alert type it hasn't been validated for |

The tenant restriction is a **security boundary** (cross-team data access).
The source restriction is a **correctness boundary** (wrong playbook on
unfamiliar alert pattern).

## Where the enforcement lives (3 code paths each)

### Tenant
1. `fortisoar_list_alerts` — server-side filter (`tenant.name=<value>`) so the
   API only returns alerts in this tenant
2. `fortisoar_get_alert` — after fetch, verifies `alert.tenant.name == configured_tenant`,
   returns "Access denied" if mismatch
3. `fortisoar_resolve_alert` — same check; **PUT is never sent** if tenant
   doesn't match

### Source
1. `fortisoar_list_alerts` — server-side filter (`source=<value>`) so the API
   only returns alerts from this source
2. `fortisoar_get_alert` — after fetch, verifies `alert.source == configured_source`,
   returns "Access denied" if mismatch
3. `fortisoar_resolve_alert` — same check; **PUT is never sent** if source
   doesn't match

## How to change scope (current behavior)

### Switch to a different single tenant

```bash
FORTISOAR_TENANT="Some Other Tenant"
```

Edit `.env`, save, rerun. The agent now operates only on that tenant.
Validate the playbook against that tenant's alert patterns first.

### Switch to a different single source

```bash
FORTISOAR_SOURCE=FortiStack CA FSM
```

Edit `.env`, save, rerun. The agent now operates only on alerts from that
source. **Validate the playbook against this source first** because:
- Different alert sources have different `description` text formats
- Different sources have different `correlation hints` extraction quality
- Different sources need different `closure_reason` mappings (e.g., FortiSIEM
  brute force alerts should NOT be closed with the same logic as FortiAnalyzer
  IPS attacks)

### Remove the source restriction entirely (NOT supported by current code)

**You CANNOT just delete the `FORTISOAR_SOURCE` line from `.env`.** That
causes a fail-closed error: `"FortiSOAR not configured. Set environment
variables: FORTISOAR_SOURCE..."`. The tools refuse to run.

| Action | Result |
|---|---|
| Remove `FORTISOAR_SOURCE` from `.env` | ❌ Fails: "FORTISOAR_SOURCE is required" |
| Set `FORTISOAR_SOURCE=` (empty) | ❌ Same fail (we strip and check) |
| Set `FORTISOAR_SOURCE=Other_Source_Name` | ✅ Switches scope to that source |
| Want multiple sources or all sources | Requires a code change (see options below) |

This is intentional. We made it fail-closed so you can never *accidentally*
process alerts outside the validated scope by forgetting to set an env var.

### Future option A: support a comma-separated list (recommended when needed)

When you've validated multiple source playbooks and want the agent to handle
several at once, the cleanest enhancement is comma-separated list support:

```bash
FORTISOAR_SOURCE=IS_FAZ_MIS_Cloud,FortiStack CA FSM,Some_Webfilter_Source
```

This requires ~30 lines of code:

1. **Helper parses the list:**
   ```python
   sources = [s.strip() for s in os.environ.get("FORTISOAR_SOURCE","").split(",") if s.strip()]
   ```
2. **`fortisoar_list_alerts` issues one query per source and merges** (FortiSOAR's
   GET API doesn't support OR filters — same constraint as severity, which
   already does parallel fetches)
3. **`get_alert` / `resolve_alert` check `alert.source in configured_sources`**
4. **Update tests** to cover the multi-source case

Implementing this is YAGNI for now (we're only validated against one source).
Build it when you actually need to expand.

### Future option B: make the restriction optional

If you want a "no source restriction, allow all" mode (NOT recommended for
production but useful for ad-hoc investigation):

Two ways to do it:

**B1. Make `FORTISOAR_SOURCE` optional** (less safe — easy to forget):
- Remove `not source` from the `missing` list in `get_fsr_config()`
- The existing tool code already handles `source = ""` as "no filter"
- Result: setting `FORTISOAR_SOURCE=""` or removing it = no source restriction
- Tradeoff: a forgotten config makes the agent permissive instead of failing
  closed

**B2. Add an explicit wildcard sentinel** (safer):
- Require `FORTISOAR_SOURCE` to be set, but treat the literal value `*` as
  "match all"
- Example: `FORTISOAR_SOURCE="*"`
- Tradeoff: still fails closed if env var is missing entirely; only matches
  all when explicitly told to

For testing purposes (e.g., one-off investigation of an alert from a
different source), the cleanest workaround is to **temporarily change
`FORTISOAR_SOURCE` to that one source**, run the test, then change it back.
Don't disable the restriction — just retarget it.

## What "validated against a source" means

A source playbook is "validated" when:

1. The system prompt's investigation workflow makes sense for that alert type
2. The "correlation hints" parser in `fortisoar_get_alert` correctly extracts
   the source IP, destination IP, ADOM, event time, and action from that
   source's `description` HTML format
3. The "known benign patterns" in the prompt (e.g., zgrab, ZDI markers) apply
   to that source's alerts
4. The closure_reason mapping is correct for that source's typical outcomes
   (e.g., "blocked at perimeter → Risk Accept" is right for FortiAnalyzer IPS,
   but wrong for FortiSIEM brute force where the right reason is "Resolved"
   or "Tasks Completed")
5. We've successfully run end-to-end on a meaningful sample of that source's
   alerts in production

As of 2026-04-07, the only validated source is **`IS_FAZ_MIS_Cloud`**
(FortiAnalyzer-routed IPS attack alerts). Examples: Apache Log4j RCE,
ProxyShell, PHPUnit RCE, Apache HTTP path traversal — the typical
internet-scanning IPS noise pattern.

## Symmetry with the tenant restriction

The tenant restriction works the same way:

| Aspect | Tenant | Source |
|---|---|---|
| Env var | `FORTISOAR_TENANT` | `FORTISOAR_SOURCE` |
| Default | (none — required) | (none — required) |
| Read in | `get_fsr_config()` | `get_fsr_config()` |
| Used by | `config["tenant"]` | `config["source"]` |
| List filter | `tenant.name=<value>` | `source=<value>` |
| Get/resolve guard | Compares `alert.tenant.name` | Compares `alert.source` |
| Failure mode if missing | ValueError, agent refuses to start | ValueError, agent refuses to start |
| To widen | Edit `.env` (single source of truth) | Edit `.env` (single source of truth) |

The current tenant restriction is `Cloud Services`. The current source
restriction is `IS_FAZ_MIS_Cloud`.

## Quick reference: changing the configuration

```bash
# Current production scope (default)
FORTISOAR_TENANT="Cloud Services"
FORTISOAR_SOURCE=IS_FAZ_MIS_Cloud

# Switch to a different source for testing (validate first!)
FORTISOAR_TENANT="Cloud Services"
FORTISOAR_SOURCE=FortiStack CA FSM

# Switch tenants (only if you have permission and a validated playbook)
FORTISOAR_TENANT="Other Tenant Name"
FORTISOAR_SOURCE=IS_FAZ_MIS_Cloud
```

After editing `.env`, no restart of any service is needed — the next `oh -p`
invocation reads the new values directly.

## Verification

To verify which scope is currently active without running an agent:

```bash
cd ~/prj2026/oh-stage/OpenHarness && set -a && source .env && set +a && \
.venv/bin/oh -p "list FortiSOAR open alerts limit 1" \
  --api-format openai --base-url "http://172.27.106.27:8000/v1" \
  --api-key "sk-dummy-key" --model "google/gemma-4-26B-A4B-it" \
  --system-prompt "$(cat docs/soc-analyst-prompt-min.md)" \
  --permission-mode full_auto --output-format stream-json 2>&1 | ~/bin/oh-pretty.py
```

The list_alerts header line will show:
`FortiSOAR Critical/High alerts (tenant=Cloud Services, source=IS_FAZ_MIS_Cloud, status=Open): ...`

That confirms both restrictions are active and which values are in effect.
