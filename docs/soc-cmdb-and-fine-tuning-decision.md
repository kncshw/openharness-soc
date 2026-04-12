# SOC Agent: CMDB-first, fine-tuning deferred

**Status:** Agreed (2026-04-08)
**Owner:** kaini
**Affected:** SOC agent verdict accuracy on context-dependent alerts

## Context

Gemma4-26B-A4B (the SOC analyst model) reliably handles clear-cut alerts: blocked
perimeter scans, dropped IPS detections with zero follow-up traffic, whitelist
auto-close cases. It struggles with **context-dependent alerts** where the same
log evidence has different meanings depending on the asset's role:

- **Bastion / jump host:** sustained outbound SSH to many internal subnets +
  occasional auth failures from password expiration → looks like brute force or
  lateral movement, but is normal operator activity.
- **Internal vulnerability scanner:** rapid port sweeps across subnets → looks
  like reconnaissance, but is the scanner doing its job.
- **Backup server:** large nightly data flows → looks like exfiltration.
- **Patch / config management:** software push to many hosts → looks like worm
  propagation.

These cases are noisy in production today: detection rules fire, FAZ
correlation confirms the behavior, Gemma4 escalates as a true positive, an
analyst wastes time confirming it's the bastion / scanner / backup server doing
its job. We want to cut this noise without compromising the agent's ability to
catch real attacks against the same assets (a compromised bastion is an APT
win condition, not something to rubber-stamp away).

## What we considered

### Option A — Static `soc_ip_roles.yaml` loaded into LLM context

A second YAML file (parallel to `config/soc_whitelist.yaml`) listing known
server roles. Two delivery mechanisms were discussed:

1. **System-prompt injection**: dump the entire role file into the system
   prompt at agent startup.
2. **Tool-layer enrichment**: have `fortisoar_get_alert` look up source/dest
   IPs in the role file and inject an `--- ip role context ---` block into the
   alert summary, parallel to the existing `--- correlation hints ---` block.

**Rejected** for the following reasons:

- **System-prompt injection** wastes context on every turn (50 entries × ~100
  tokens = 5000 tokens of overhead, with most entries irrelevant to any given
  alert), and suffers from position dilution (the role context is far from the
  decision turn, while FAZ evidence is close — small models over-weight
  visible/recent vs distant). Same structural failure mode that pushed us to
  bypass the LLM for whitelist hits.

- **Tool-layer enrichment** is structurally better than system-prompt injection
  but still has serious failure modes specific to role context:
    - **Compromised-asset blind spot.** A bastion role tag effectively trains
      the LLM to interpret bastion-shaped traffic as benign. If an attacker
      compromises the bastion (an APT win condition), the post-compromise
      lateral movement looks identical to legitimate operator activity. The
      role tag becomes a backdoor: the highest-value target gets the worst
      defender.
    - **Wrong tags have unbounded blast radius.** A misidentified entry biases
      every alert involving that IP forever, until someone notices.
    - **Adding entries is psychologically too easy.** Whitelist entries feel
      like security exceptions and force deliberation. Role tags feel like
      labeling reality and don't.
    - **Audit trail is fuzzy.** "The LLM was told this was a bastion and
      decided to close" is much harder to reason about than "code closed
      because IP matched whitelist entry SHA X."
    - **No structured curation discipline.** Static YAML files drift; nobody
      maintains them once they leave their author's attention.

A constrained version (asymmetric schema with `expected_behavior` AND
`raise_scrutiny_on`, never authorizes closure on its own, prompt rule forces
explicit justification, limited to 5–10 hand-picked entries) would mitigate
some of these but not the compromised-asset blind spot.

### Option B — CMDB / asset inventory integration as a tool

Build a tool: `asset_lookup(ip) → {hostname, owner, role, environment,
criticality, expected_behavior, raise_scrutiny_on}`. The agent calls it during
investigation. Asset metadata lives in the CMDB (or an equivalent structured
data store), maintained by the team that owns the assets.

**Selected** because:

- **Single source of truth maintained by asset owners**, not by SOC engineers
  trying to keep a parallel YAML in sync with reality.
- **Tool call is auditable** in the agent run trace (you can see exactly when
  asset metadata was consulted and what it returned), unlike static context
  injection where you can't tell if the LLM read the role tag or ignored it.
- **Asset metadata grows organically** as the CMDB grows; new servers don't
  require touching the SOC agent at all.
- **Same in-process tool pattern** as everything else in the SOC framework
  (FortiSOAR, FAZ, future FortiSIEM). No new architectural concept; just
  another integration helper + tool.
- **Structured data with implied behavioral indication.** The CMDB record can
  encode role + expected behavior + raise-scrutiny patterns as structured
  fields, which is much more reliable for the LLM to consume than free prose.
- **Asymmetric reasoning is encodable.** Same structured fields can carry both
  "this looks suspicious but is normal" AND "this looks routine but is high
  scrutiny" — addresses the compromised-bastion failure mode partially because
  the tool can return raise-scrutiny patterns alongside expected behaviors.

### Option C — Fine-tune Gemma4 on SOC-specific verdicts

Train Gemma4-26B on a curated dataset of (alert + correlation + asset context,
correct verdict) pairs to improve verdict accuracy on context-dependent cases.

**Deferred** (not rejected outright). Reasons:

- **Per the project's own debug-order rule** (`feedback_debug_order.md`):
  exhaust software-level fixes BEFORE touching model parameters. Fine-tuning
  is the most extreme version of touching model parameters. Cheaper levers
  (CMDB tool, structured outputs, few-shot prompts, model swap) have not yet
  been exhausted.

- **Data preparation cost is the real bottleneck.** kaini has the historical
  closure data and the hardware for training, but the *labeling and curation
  work* to turn closures into a high-quality training set is the costly part.
  Historical closures aren't all good labels — many were made by tired
  analysts under time pressure, with vague notes ("looks benign") that don't
  teach anything. Filtering to high-confidence labels, augmenting with
  synthetic data, validating against held-out human labels — that's the
  multi-week-to-multi-month project, not the GPU time.

- **Fine-tuning cannot conjure information that isn't in the inputs.** The
  bastion-vs-compromised-bastion case is genuinely ambiguous from log data
  alone, even for experienced analysts. No amount of fine-tuning can teach the
  model to make a decision that the data doesn't support. The right response
  for these cases is more data sources (EDR, host telemetry, auth logs with
  method and result, process spawning trees) or accepting human-in-the-loop
  for that alert class — not fine-tuning.

- **Lifecycle and maintenance burden.** A fine-tuned model is frozen at a
  point in time. Environment drifts. Base model updates require redoing the
  fine-tune. Catastrophic forgetting is real (fine-tuning on SOC patterns can
  degrade general capabilities). Drift detection and retraining cadence
  become ongoing operational concerns.

- **Reversibility.** CMDB integration is a few hundred lines of Python in one
  tool module; if it doesn't help, you delete the tool. A fine-tuned model is
  a months-long commitment that's much harder to walk back from.

**Conditions under which fine-tuning would become the right answer:**

1. CMDB tool is built and validated, AND
2. Few-shot prompts and structured outputs are tried, AND
3. Model swap (Qwen2.5-32B, DeepSeek R1 distill, Llama 3.3 70B) has been
   benchmarked against Gemma4 on the same alert set, AND
4. Failures remaining after all of the above are concentrated in a stable,
   well-defined task category, AND
5. A held-out evaluation set exists with ground-truth labels, AND
6. The information needed for the decision is actually in the inputs (not a
   humans-can't-decide case), AND
7. The team is committed to the model lifecycle ops (retraining, evals,
   versioning, rollback strategy)

If all seven conditions are met and the failures still hurt, fine-tuning
becomes the right next move. Until then, it would be premature optimization.

## Decision

1. **Do not build the static `soc_ip_roles.yaml` approach.** The compromised-asset
   blind spot, the unbounded blast radius of bad entries, and the
   curation/audit weakness all make it strictly worse than the CMDB tool path.

2. **Build the CMDB / asset_lookup tool integration when asset data access is
   available.** Same shape as existing integration tools. Helper module
   (`_cmdb_helpers.py`), tool module (`cmdb_lookup_asset_tool.py`), env-var
   config for CMDB endpoint and credentials, structured Pydantic schema for
   asset records, optional fields for `expected_behavior` and
   `raise_scrutiny_on` to encode asymmetric context.

3. **Defer fine-tuning indefinitely.** Reconsider only after the seven
   conditions above are met.

4. **Cheaper improvements that should be tried in parallel** (not blocked on
   CMDB):
    - Few-shot examples in `soc-analyst-prompt-min.md` for ambiguous cases
    - Structured JSON verdict output (`{verdict, confidence, evidence_for, evidence_against, decision_basis}`)
    - Confidence-gated escalation (low confidence → escalate regardless of direction)
    - Model swap experiment: benchmark Gemma4 against Qwen2.5-32B / DeepSeek R1
      distill / Llama 3.3 70B on the same alert set, document the result. A
      stronger model may solve more cases for less effort than a CMDB
      integration, AND would tell us whether the failures are capacity-bound or
      domain-bound.

## Consequences

**Positive:**
- Avoids the compromised-asset blind spot of the role-file approach.
- Avoids months of fine-tuning prep work.
- Keeps the SOC framework's "intelligence in the tool layer" thesis intact.
- All work is reversible: tools can be added or removed without retraining.

**Negative / accepted:**
- CMDB integration is blocked on asset data access (whatever form that takes
  in the target environment). If no CMDB exists, building one is a
  prerequisite project.
- Without role context of any kind, bastion-shaped noise alerts remain an
  analyst burden until CMDB integration ships. Mitigation: cheap improvements
  (few-shot prompts, structured outputs) in parallel, plus the existing
  whitelist for any high-noise IPs that are safe to fully auto-close.
- Acknowledges that some context-dependent alerts genuinely require
  human-in-the-loop and will never be reliable for automation alone, no matter
  the model. Some alerts shouldn't be automated.

## Open questions for the next session

1. **Does a CMDB / asset inventory exist in the target environment?** If yes,
   what form (ServiceNow, internal IPAM, spreadsheet, wiki page, custom DB)?
   What's its API surface? Who maintains it? This is the unblocking question.
2. **If no CMDB exists, what's the lowest-effort structured alternative?**
   A small Postgres / SQLite / YAML-loaded-into-Pydantic-models DB seeded by
   hand and grown over time. Worse than a real CMDB but better than nothing.
3. **What's the cheap model swap baseline?** Pick a candidate (Qwen2.5-32B is
   probably the easiest to spin up alongside the existing vLLM endpoint),
   benchmark on 10–20 of the noisier real alerts, document the verdict
   accuracy delta. Half-day spike.
4. **Which alerts are the biggest noise contributors today?** Knowing the
   top-N noise sources by count tells us which CMDB entries to prioritize when
   the integration ships.

## Related memory entries

- `feedback_debug_order.md` — Why fine-tuning is last resort
- `feedback_no_closure_history_db.md` — Why we don't automate from past closures
- `feedback_whitelist_bypass_llm.md` — Why whitelist hits bypass the LLM
- `feedback_whitelist_in_get_alert_validated.md` — The whitelist's bypass design
- `project_soc_platform_shape.md` — Why we stay on OpenHarness
- `project_harness_thesis.md` — Intelligence in tool layer, not model
- `project_soc_target_model.md` — Gemma4 design constraints
