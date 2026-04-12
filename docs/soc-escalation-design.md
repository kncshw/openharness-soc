# SOC Agent: Escalation via SMTP/Teams + FortiSOAR Status Transition

**Status:** Approved — ready to implement
**Date:** 2026-04-09
**Owner:** kaini

## Context

Today the SOC batch agent finishes each alert in one of three states:

1. **Whitelist auto-close** (already shipped) — alert closed by code, audit
   trail in FortiSOAR.
2. **Clean closure by Gemma4** (already shipped) — alert resolved when threat
   is blocked AND all 4 correlation queries return zero results.
3. **"Needs human review"** — Gemma4 outputs findings as text and stops.
   **Today this state has no formal escalation:** no notification, no state
   change in FortiSOAR. The alert just stays Open. The next batch run
   re-processes it from scratch.

We need an escalation mechanism that:
- Actively notifies the SOC lead via email + Microsoft Teams
- Marks the alert in FortiSOAR so the next batch run does not re-process it
- Leaves a complete audit trail (email body carries the AI's findings)

## Decision

**One new mutating tool: `escalate_alert`.**

When the batch agent decides an alert needs human review, it calls
`escalate_alert` with structured findings. The tool:

1. **Sends notification first** (SMTP to SOC lead inbox + email-to-channel for
   Teams). The AI's findings are embedded in the email body using a
   tool-controlled template (NOT model-controlled).
2. **Then transitions the alert** in FortiSOAR from `Open` → `Investigating`.
3. Returns success when both succeed.

**Order matters:** notification first, status second. The failure modes are
asymmetric:
- **Notification first → status fails:** email already sent, status stays
  Open, next batch run re-escalates and re-sends. **Recoverable** — duplicate
  email is annoying but not dangerous.
- **Status first → notification fails:** alert is now Investigating but no
  human knows. **Silent loss.** Unacceptable.

**Dedup mechanism:** FortiSOAR's existing state machine. The batch agent
already filters `fortisoar_list_alerts` for `status=Open`. Once an alert is
`Investigating`, it is naturally excluded from future batch runs. **No
SQLite, no JSON state file, no TTL configuration, no parallel state to
maintain.** FortiSOAR is the source of truth for ticket state, which is
exactly what FortiSOAR is good at as a ticketing system.

**Why we are NOT also writing a FortiSOAR comment with the AI findings:** the
findings are in the email body. Email retention policies handle the long-term
audit case. FortiSOAR in this workflow is a ticketing system, not a forensic
database. Writing findings to both places is double-bookkeeping with no
additional value.

**Why "Investigating" specifically:** confirmed by the user (2026-04-09) that
this picklist value already exists in the target FortiSOAR
`AlertStatus` picklist. No FortiSOAR schema work needed.

## Tool specification

### `escalate_alert` — inputs

| Field | Type | Required | Description |
|---|---|---|---|
| `alert_id` | str | yes | Alert identifier (`Alert-NNN`, `NNN`, or UUID) |
| `severity` | str | yes | One of `critical` \| `high` \| `medium` |
| `summary` | str | yes | 2–4 sentences: what was queried, what was found, why it concerns the AI |
| `recommended_action` | str | yes | What the human should do next |
| `confidence` | float | yes | 0.0–1.0, AI's confidence that this needs human review |

### `escalate_alert` — behavior

1. Validate inputs via Pydantic schema (severity must be in allowed set,
   confidence must be 0.0–1.0).
2. Load FortiSOAR config (`get_fsr_config()`) and SMTP config
   (`get_smtp_config()`) — both fail-closed if any required env var is
   missing.
3. Look up the alert via FortiSOAR API. Reuses the existing alert lookup
   logic.
4. Apply tenant + source guards (same fail-closed policy as existing FortiSOAR
   tools — refuse to escalate alerts outside the configured tenant/source).
5. Check current alert status:
   - If `status != Open` → return error with explicit reason
     (`"Alert-NNN is in status 'Investigating'; only Open alerts can be escalated"`)
   - This is also the dedup guard — prevents the bot from re-escalating an
     already-escalated alert if its filter slips somehow.
6. Build email subject and body using the fixed template below. The model
   only fills in structured fields; it does NOT control the email format.
7. **Send email** via SMTP to `SOC_LEAD_EMAIL` AND `SOC_TEAMS_CHANNEL_EMAIL`
   in a single multi-recipient send.
   - On failure: return error immediately, do NOT change FortiSOAR state.
8. **Resolve picklist IRI** for `AlertStatus = "Investigating"` (reuses
   `_get_picklist_iri` from the resolve tool).
9. **PUT update to FortiSOAR**: set `status` to the resolved Investigating
   IRI on the alert.
   - On failure: log warning, but return SUCCESS to the caller. The email
     went out; the alert is still Open; the next batch run will re-escalate
     and re-send the email (acceptable failure mode).
10. Return success message: `"escalation sent to <addresses>; alert status
    updated to Investigating"`.

### Email template (tool-controlled, NOT model-controlled)

```
Subject: [SOC AI ESCALATION] {severity} — Alert-{alert_id} — {alert.name truncated to 80 chars}

Body:
=== AI SOC Analyst — Escalation Notice ===

Alert:        Alert-{alert_id}
Rule:         {alert.name}
Severity:     {severity} (alert.severity: {alert.severity_field})
Confidence:   {confidence:.2f}
Tenant:       {alert.tenant}
Source:       {alert.source}
Detected:     {alert.detection_time or '-'}
Source IP:    {alert.sourceIp or '-'}
Destination:  {alert.destinationIp or '-'}

--- AI Findings Summary ---
{summary}

--- Recommended Action ---
{recommended_action}

--- Audit ---
Investigation by:     SOC AI Analyst (Gemma4-26B-A4B)
Investigation time:   {now_utc_iso}
FortiSOAR alert URL:  {FORTISOAR_URL}/alerts/{alert.uuid}

This alert has been transitioned to "Investigating" in FortiSOAR.
Please review and resolve.

---
Generated by SOC AI Analyst | openharness/soc-agent
```

Why the tool controls the format:
- Consistent template every time (the SOC lead learns to scan one shape)
- Spam filters love consistent templates from a known sender
- The model only fills in structured fields, can't accidentally include
  sensitive data it shouldn't
- One place to update the format later (not "tell the model to format
  differently")

### Permission contract

- `is_read_only = False` (mutating)
- **Batch mode** (`--permission-mode full_auto`): fires automatically without
  prompt — this is the only way the unattended cron path works.
- **TUI mode** (default permission): prompts the analyst before sending —
  external notifications are a real action with side effects, the analyst
  should approve them explicitly.

## Configuration

New environment variables to add to `.env`:

```bash
# --- SMTP for escalation notifications --------------------------------------
# All required (fail-closed) — same pattern as FortiSOAR config
SMTP_HOST=smtp.fortinet.com
SMTP_PORT=587
SMTP_USERNAME=soc-agent@fortinet.com
SMTP_PASSWORD=<provisioned at deploy time>
SMTP_FROM_ADDRESS=soc-agent@fortinet.com
SMTP_USE_TLS=true

# --- Escalation destinations ------------------------------------------------
# All required (fail-closed)
SOC_LEAD_EMAIL=<SOC lead's email>
SOC_TEAMS_CHANNEL_EMAIL=<channel's email-to-channel address>
```

`get_smtp_config()` reads these and refuses to run if any are missing —
same fail-closed pattern as `get_fsr_config()`.

## System prompt updates

Add the following section to `docs/soc-analyst-prompt-min.md` after the
existing closure rules (rough text — refine during implementation):

```markdown
## Escalation -- when you cannot confidently close

If after running the 4 correlation queries you cannot confidently close the
alert, call `escalate_alert` with structured findings as your FINAL action.
"Cannot confidently close" includes any of these cases:

- Threat was NOT blocked at the perimeter (action != dropped/blocked/denied)
- Any correlation query returned non-zero results
- Any correlation query timed out or errored AND remaining evidence is
  insufficient to decide
- Detection rule indicates a sensitive asset class (DC, DB, mail server, etc.)

After calling `escalate_alert`:
- Do NOT call any other tools
- Do NOT also call `fortisoar_resolve_alert`
- Output ONE short confirmation sentence and stop

The escalate_alert tool will:
1. Send a notification (email + Teams) to the SOC lead with your findings
2. Transition the alert to "Investigating" in FortiSOAR
3. The human will take over from there

Required fields for escalate_alert:
- alert_id: the alert you investigated
- severity: critical | high | medium
- summary: 2-4 sentences of what you queried, what you found, why it concerns
  you. Include specific numbers (event counts, IP addresses, action values).
- recommended_action: what the human should do next, in one sentence
- confidence: 0.0-1.0, your confidence this needs human review (high = "this
  definitely needs a human"; low = "I'm uncertain")
```

## Implementation plan

### Pre-requisites (verification before coding)

- [x] **"Investigating" exists in FortiSOAR AlertStatus picklist** — confirmed by user 2026-04-09
- [ ] **SMTP credentials provisioned** — host, port, username, password, from-address
- [ ] **SOC lead email address** confirmed
- [ ] **Teams email-to-channel address** confirmed (depends on Microsoft 365 admin enabling email-to-channel for the target channel)
- [ ] **Test SMTP environment available** — to avoid sending test emails to the real SOC lead during development. Could be a dev SMTP server, a catch-all test inbox, or a local mailhog instance.

### Step 1: SMTP helper module (~2 hours)

**File:** `src/openharness/tools/_smtp_helpers.py` (new)

- `get_smtp_config()` — reads `SMTP_*` and `SOC_*_EMAIL` env vars, fail-closed
- Returns `dict[str, Any]` with keys: `host`, `port`, `username`, `password`,
  `from_address`, `use_tls`, `lead_email`, `teams_channel_email`
- `send_email(config, to, subject, body)` — async function, multi-recipient,
  uses stdlib `smtplib` wrapped in `asyncio.to_thread` (avoid adding
  `aiosmtplib` as a new dep unless it's already in pyproject)
- Returns nothing on success, raises `RuntimeError` on failure with
  descriptive error message
- Tests: mock smtplib to verify (a) correct headers, (b) correct recipients,
  (c) correct error propagation, (d) TLS on/off behavior

### Step 2: `escalate_alert` tool (~3–4 hours)

**File:** `src/openharness/tools/fortisoar_escalate_alert_tool.py` (new)

- Pydantic input schema with field validators:
  - `alert_id`: regex match for the three accepted formats
  - `severity`: must be in `{critical, high, medium}`
  - `summary`: min length 30 chars (forces real content)
  - `recommended_action`: min length 10 chars
  - `confidence`: must be in `[0.0, 1.0]`
- Tool class extending `BaseTool`
- `is_read_only = False`
- `execute()` method following the 10-step behavior described above
- Reuses `FortiSOARResolveAlertTool._lookup_alert` and `_get_picklist_iri`
  (or extract them to `_fortisoar_helpers.py` if duplication becomes ugly —
  decide during implementation)
- Email body templating in a `_build_email` static method (deterministic,
  testable)
- Detailed error messages distinguishing each failure mode

### Step 3: Tool registration (~10 minutes)

**File:** `src/openharness/tools/__init__.py`

- Import `FortiSOAREscalateAlertTool`
- Add to `create_default_tool_registry()` registrations

### Step 4: System prompt update (~30 minutes)

**File:** `docs/soc-analyst-prompt-min.md`

- Add the "Escalation" section after the existing closure rules
- Update workflow numbering / language to make the "either close OR escalate"
  decision explicit
- Verify the rule "do NOT call other tools after escalate_alert" is clear

### Step 5: Tests (~2–3 hours)

**File:** `tests/test_soc_fortisoar_tools.py` (extend) — new class
`TestEscalateAlert`

Test cases:
- `test_happy_path` — Open alert, valid inputs, mocked SMTP succeeds, mocked
  PUT succeeds, both happen, success message returned, PUT payload contains
  Investigating IRI
- `test_smtp_failure_no_status_change` — SMTP raises, no PUT issued, error
  returned to caller
- `test_status_update_failure_returns_success_with_warning` — SMTP succeeds,
  PUT raises, return value is success (the email went out), warning logged
- `test_already_investigating_refused` — alert in `Investigating` state,
  refuses with explicit error message, no SMTP call, no PUT
- `test_already_closed_refused` — alert in `Closed` state, refuses, no side
  effects
- `test_foreign_tenant_refused` — guard fires before any side effects
- `test_foreign_source_refused` — guard fires before any side effects
- `test_alert_not_found` — clear error, no side effects
- `test_invalid_severity_rejected_by_schema` — Pydantic validation error
- `test_confidence_out_of_range_rejected_by_schema` — Pydantic validation error
- `test_short_summary_rejected_by_schema` — Pydantic validation error
- `test_email_template_contains_required_fields` — unit test on the
  `_build_email` static method
- `test_missing_smtp_config_clear_error` — `get_smtp_config()` failure surfaces
  cleanly

Plus tests in `test_soc_smtp.py` (or extend existing) for the SMTP helper:
- `test_get_smtp_config_missing_vars` — fail-closed
- `test_send_email_calls_smtplib_correctly` — mock smtplib, verify call
- `test_send_email_uses_tls_when_configured`

### Step 6: `.env` update (~5 minutes)

**Files:** `.env` in both `oh/` and `oh-stage/`

- Add the SMTP and SOC_* email block with placeholder values
- Replace placeholders with real values when SMTP credentials are provisioned

### Step 7: End-to-end validation (~1 hour)

- Pick a recent real alert that the batch agent escalated as text-only today
- Manually re-run the batch agent against it with the new tool registered
- Verify:
  - Email lands in test inbox with correct subject + body
  - Teams channel post appears (if email-to-channel is configured for the
    test channel)
  - FortiSOAR alert status changed to `Investigating`
  - Audit trail in alert detail looks correct
- Re-run the batch agent — verify the now-Investigating alert is NOT
  re-processed (it should be excluded by the `status=Open` filter in
  `fortisoar_list_alerts`)

### Step 8: Sync dev → stage (~10 minutes)

Per the dev-first rule: edit in `oh/`, then copy to `oh-stage/`.

Files to sync:
- `src/openharness/tools/_smtp_helpers.py` (NEW, copy verbatim)
- `src/openharness/tools/fortisoar_escalate_alert_tool.py` (NEW, copy verbatim)
- `src/openharness/tools/__init__.py` (modified — surgical port if oh-stage diverges)
- `docs/soc-analyst-prompt-min.md` (modified — surgical port if oh-stage diverges)
- `tests/test_soc_fortisoar_tools.py` (modified — surgical port)
- `.env` — manual merge (additive, no conflict expected)

Run the SOC test suite in `oh-stage/` to verify parity. Should see
test count grow to ~85 (70 today + ~15 new escalation tests).

## Estimated total effort

**1 to 1.5 days of focused work**, contingent on SMTP credentials being
available and the test inbox being set up.

## Files created / modified

### New files
- `src/openharness/tools/_smtp_helpers.py`
- `src/openharness/tools/fortisoar_escalate_alert_tool.py`

### Modified files
- `src/openharness/tools/__init__.py` (register new tool)
- `docs/soc-analyst-prompt-min.md` (escalation rule)
- `tests/test_soc_fortisoar_tools.py` (extend with escalate_alert tests)
- `.env` (SMTP + SOC_*_EMAIL block)

## Open questions to resolve before / during implementation

1. **SMTP credentials**: when will they be provisioned? Who is the owner of
   the `soc-agent@` service account?
2. **Teams channel email-to-channel address**: what is it, and is
   email-to-channel enabled in the Microsoft 365 tenant for the target
   channel?
3. **Test SMTP environment**: dev SMTP server, catch-all inbox, or local
   mailhog? Pick before implementation to avoid sending test emails to real
   recipients.
4. **Severity mapping**: should the bot pick severity from the alert's
   existing `alert.severity` field, or assess independently? Recommendation:
   default to mirroring `alert.severity`, but the schema allows the model to
   override (e.g., "alert is High but I think Critical based on what I
   found").
5. **Confidence threshold for auto-escalation**: should the system prompt
   include a hard rule like "if confidence < 0.6, always escalate regardless
   of evidence direction"? Or leave it to the model's judgment? Recommend
   leaving it to model judgment for the first iteration; revisit if Gemma4
   under-escalates uncertain cases.
6. **Should the escalate tool be hidden in TUI mode?** An analyst is already
   the human; escalating from inside a TUI session means escalating to a
   senior analyst / incident commander, which is a different workflow.
   Recommend keeping the tool available in TUI mode for that case, gated by
   the standard permission prompt.

## What this design does NOT include (deferred)

- TUI / interactive mode invocation of the broader analyst workflow (separate
  design discussion, parked)
- Daily digest of bot activity (nice-to-have, deferred)
- Multi-tier escalation (different recipients for different severities) —
  single tier for MVP
- Webhook-based Teams integration with rich cards / @mentions (deferred until
  email-to-channel limitations bite)
- On-call rotation routing (deferred — sends to a single SOC lead address; if
  on-call rotation is needed later, the lead's mailbox can route via mail
  rules or that address can become a distribution list)
- SMS / paging integration (out of scope)
- Auto-reopening alerts that the SOC lead doesn't action within N hours
  (deferred; could be a separate cron tool that checks for stale
  Investigating alerts and re-escalates)

## Failure modes and recovery

| Failure | Effect | Recovery |
|---|---|---|
| SMTP server unreachable | Email not sent, status not changed, error returned to batch agent | Next batch run retries automatically (alert still Open) |
| SMTP auth fails | Same as above | Fix credentials, next batch run retries |
| Email accepted but bounced | Same as no-email scenario from SOC lead's perspective | Out of band: SMTP server bounce notification; long-term: add bounce monitoring |
| FortiSOAR PUT fails after email sent | Email delivered, status still Open | Next batch run re-escalates (duplicate email — acceptable, marked as known failure mode) |
| `_get_picklist_iri` fails (Investigating not in picklist) | Email sent, PUT not attempted | One-time config error; fix the picklist, retry. Worth a check on first run. |
| Permission mode rejects in TUI | Tool returns error, no side effects | Analyst approves and retries |

## Related decisions and references

- `docs/soc-cmdb-and-fine-tuning-decision.md` — CMDB-first, fine-tuning deferred
- Memory: `project_soc_platform_shape.md` — Stay on OpenHarness with SOC convention layer
- Memory: `project_fortisiem_integration_plan.md` — FortiSIEM as parallel log backend
- Memory: `feedback_whitelist_in_get_alert_validated.md` — The whitelist auto-close design that this escalation design parallels
- Memory: `feedback_whitelist_bypass_llm.md` — Why we bypass the LLM for whitelist hits (the inverse case from escalation: pre-decided answers don't need the LLM; uncertain answers DO need a human)
- Memory: `feedback_dev_first_then_stage.md` — Dev → stage sync rule that applies to this build

---

**Ready to implement.** First action tomorrow: confirm SMTP credentials and
test inbox availability, then start with Step 1 (SMTP helper module).
