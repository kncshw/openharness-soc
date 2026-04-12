# SOC Agent: Escalation Reliability Experiment Plan

**Status:** Parked — revisit after production shipment
**Date:** 2026-04-10
**Owner:** kaini

## Problem statement

The SOC agent's escalation decision (close vs. escalate to human) is currently
driven entirely by the system prompt — natural language interpreted by a
probability matrix. The prompt says:

```
If action=dropped/blocked/denied AND all 4 correlation queries returned 0 → close
Otherwise → stop, output findings, recommend human review
```

This is structurally unreliable for two reasons:

1. **Natural language is ambiguous.** The model must interpret edge cases
   (action=`server-rst`, action=`timeout`, webfilter=3 but attack=0) and
   may interpret them differently on different runs.
2. **LLMs are probabilistic.** Same alert, same evidence, different run →
   potentially different verdict. There is no fixed internal standard for
   "what counts as lateral movement" — the model samples from a distribution
   of plausible standards on every run.

As of 2026-04-10, the agent has resolved 37+ alerts with 0 escalations. This
is likely correct for the current alert population (perimeter-blocked single
probes with zero follow-up), but we have no evidence of what happens on
borderline cases.

## Two separate improvements (do not conflate)

### 1. Code-level action gate (deterministic safety net)

**What:** Add a hard gate in `fortisoar_resolve_alert` that refuses to close
any alert where the FortiGate action is not in a known-safe set
(`{dropped, blocked, denied}`). If the action is `accept`, `allow`, `pass`,
`server-rst`, `timeout`, or anything else, the tool returns an error telling
the LLM to escalate instead. The LLM cannot override this.

**Why this is the real fix:** Code is deterministic. The same action value
produces the same decision every time, regardless of temperature, prompt
wording, or model version. This catches the most dangerous failure mode
(closing an alert where traffic actually went through the perimeter) with
zero reliance on the prompt.

**Safe action set (starting point, refine after production data):**
```python
_SAFE_ACTIONS = {"dropped", "blocked", "denied", "drop", "block", "deny"}
```

**Implementation:** ~15 lines in `fortisoar_resolve_alert_tool.py`, after the
status check and before the closure-notes check. Reuses the existing action
extraction logic from `_build_closure_notes_template`.

**Status:** Ready to implement. Do this BEFORE the temperature experiment —
it's a software-level fix per the project's debug-order rule.

### 2. Temperature A/B test (variance reduction)

**What:** Compare Gemma4's verdict consistency at temp=0.7 (current vLLM
default) vs temp=0.2 on a borderline alert that could plausibly go either
way (close or escalate).

**Why:** Temperature controls sampling randomness. For SOC batch tasks where
consistency matters more than creativity, lower temperature should reduce
verdict variance without affecting the model's peak accuracy. This is NOT a
fix for the escalation reliability problem (code gates are the fix), but it
IS a quality-of-life improvement that reduces noise in production.

**Infrastructure (already shipped):**
- `OH_TEMPERATURE` env var added to `openai_client.py` (per-request override)
- `.env` defaults to `OH_TEMPERATURE=0.2`
- Override for a single run: `OH_TEMPERATURE=0.7 bin/bis-soc Alert-XXXXX`

**Experiment protocol:**
1. Identify a borderline alert — one where the evidence is ambiguous enough
   that a human SOC analyst would need to think about it. Candidates:
   - action=`server-rst` (not a clean block, not a pass-through)
   - action=`timeout` (connection died, unclear if data transferred)
   - Non-zero but low correlation results (e.g., 2 traffic entries from the
     source IP in the after-window, but all were DNS lookups)
2. Run the alert 5 times at temp=0.7 (reopen in FortiSOAR between runs)
3. Run the alert 5 times at temp=0.2 (reopen between runs)
4. Record: verdict (close/escalate), closure_reason, key phrases in
   closure_notes, wall-clock time
5. Compare: is temp=0.2 more consistent? Does it change the verdict
   direction, or just reduce variance around the same center?

**Expected outcome:** temp=0.2 gives the same verdict 5/5 times; temp=0.7
gives the same verdict 3-4/5 times with 1-2 flips. If both give the same
verdict 5/5 times, temperature doesn't matter for this case and the
experiment is inconclusive (need a more borderline alert).

**What the experiment does NOT tell you:**
- Whether the model's verdict is *correct* (only a human can judge that)
- Whether temperature affects tool-calling reliability (it shouldn't — tool
  calls are structured JSON, not creative text)
- Whether a different model would do better (that's a separate experiment)

## Evidence accumulator for correlation results (future, more involved)

**What:** Each FAZ tool writes a structured record to a session-scoped
accumulator: `{query_name, total_count, key_findings}`. The resolve tool
reads this accumulator before closing and refuses if any count is non-zero.

**Why:** Currently the resolve tool has no way to verify what the FAZ queries
actually returned — it only sees the closure_notes the LLM wrote. The LLM
could write "0 events" when FAZ returned 3. The accumulator is a code-level
cross-check on the actual tool outputs.

**Status:** Design idea only. More involved than the action gate (requires
a session-scoped storage mechanism). Defer until after the action gate is
shipped and validated. May not be necessary if the action gate + temperature
reduction prove sufficient in production.

## Cheap improvements to try in parallel (from earlier discussion)

These are all cheaper than fine-tuning and were identified during the
escalation design discussion:

1. **Few-shot examples in the system prompt** for borderline cases — show the
   model 2-3 worked examples of alerts that SHOULD be escalated vs. closed
2. **Structured JSON verdict output** — force the model to emit
   `{verdict, confidence, evidence_for, evidence_against}` instead of
   free-form text. Structured outputs constrain reasoning shape.
3. **Confidence-gated escalation** — if model's self-reported confidence
   < 0.6, escalate regardless of evidence direction
4. **Model swap benchmark** — compare Gemma4-26B against Qwen2.5-32B or
   DeepSeek-R1-distill on the same borderline alerts. If a different model
   handles them substantially better, that's a cheaper fix than fine-tuning.

## Order of operations (when revisiting)

1. Ship the code-level action gate first (deterministic, highest value)
2. Run the temperature A/B on a borderline alert (cheap, informative)
3. If verdicts are still inconsistent at low temp, try few-shot examples
4. If still insufficient, try structured verdict output
5. If still insufficient, run the model swap benchmark
6. If still insufficient AND you have labeled data, consider fine-tuning
   (see `docs/soc-cmdb-and-fine-tuning-decision.md` for the full analysis)

## Related documents

- `docs/soc-escalation-design.md` — the escalate_alert tool design (SMTP +
  FortiSOAR status transition)
- `docs/soc-cmdb-and-fine-tuning-decision.md` — why fine-tuning is deferred
- Memory: `feedback_debug_order.md` — software fixes before model parameters
- Memory: `project_cmdb_first_finetuning_deferred.md` — CMDB before fine-tuning
