# OpenHarness SOC — AI-Powered Security Alert Triage System

## Executive Summary

OpenHarness SOC is an AI-driven Security Operations Center agent that automates the triage of security alerts at enterprise scale. It leverages a locally-hosted open-source large language model (Gemma4-26B-A4B) as the reasoning engine, harnessed by a structured tool-calling framework that integrates with Fortinet's security ecosystem — FortiSOAR, FortiAnalyzer, and FortiSIEM — to investigate, correlate, and resolve security incidents autonomously.

The system's core design philosophy is **"intelligence in the tool layer, not in the model."** Rather than relying on the LLM's raw reasoning capabilities, the system encodes domain expertise into deterministic Python tools that perform CIDR classification, log aggregation, IP whitelisting, HMAC authentication, and audit trail generation. The LLM's role is deliberately constrained to tool selection, argument filling, and natural language summarization — tasks that even smaller, cost-efficient models handle reliably when the surrounding harness is well-designed.

In preliminary production testing, the system successfully triaged 37+ real security alerts with zero human intervention, correctly identifying and auto-closing benign alerts while escalating genuinely suspicious cases for human review.

## System Architecture

### The Fortinet Security Ecosystem

The system operates within Fortinet's integrated security platform:

**FortiSOAR** serves as the central orchestration and ticketing platform. It aggregates security alerts from multiple detection sources into a unified queue. When a FortiGate firewall, an IPS engine, or a threat detection rule identifies suspicious activity, the resulting alert flows into FortiSOAR regardless of which detection system originated it. FortiSOAR provides the alert lifecycle management — creation, assignment, investigation tracking, and closure — that the SOC team operates against daily.

**FortiAnalyzer (FAZ)** is the centralized log aggregation and analysis platform. Every FortiGate firewall in the network forwards its traffic logs, security event logs, and application control logs to FortiAnalyzer. When the AI agent needs to investigate an alert, it queries FortiAnalyzer to examine the actual network evidence: What traffic did the source IP generate before and after the event? Were there other security events in the same time window? Did the destination show signs of lateral movement? FortiAnalyzer holds the forensic evidence that the agent uses to make its triage decisions.

**FortiSIEM** serves a parallel role to FortiAnalyzer as a Security Information and Event Management platform. It aggregates logs and events from a broader set of sources and provides its own detection and correlation capabilities. Alerts originating from FortiSIEM also flow into FortiSOAR for unified management. The OpenHarness SOC agent queries FortiSIEM using the same correlation pattern it uses for FortiAnalyzer — the tool layer automatically dispatches to the correct log backend based on the alert's origin, and the LLM follows the same investigation workflow regardless of which backend provides the evidence.

**Netbox** provides the IP address management and asset ownership database. When the agent encounters an internal IP address during its investigation, it can query Netbox to determine which team owns the asset, what device it corresponds to, and what subnet it belongs to. This ownership information accelerates the escalation process — instead of an analyst receiving an alert about an anonymous IP address, the escalation message identifies the specific team and asset involved, enabling faster incident response.

### The OpenHarness Framework

OpenHarness is an open-source Python framework that provides the structured tool-calling loop between the LLM and the external systems. On every interaction turn, the framework:

1. **Serializes available tools** into the OpenAI-compatible function-calling format and sends them alongside the conversation to the LLM endpoint. The tool definitions include the tool name, a natural language description, and a JSON schema specifying the exact parameters the tool accepts.

2. **Receives structured tool calls** from the LLM as JSON objects — not free-text that requires parsing, but typed, schema-validated function calls with exact parameter names and values.

3. **Validates arguments** through Pydantic models before any tool code executes. Type errors, missing required fields, and out-of-range values are caught at this boundary and surfaced as clear error messages the LLM can self-correct from.

4. **Executes the tool** in the Python runtime, where the actual domain logic runs — HMAC signature computation for FortiSOAR authentication, asynchronous two-step log searches on FortiAnalyzer, RFC1918 IP classification, whitelist CIDR matching, and structured result formatting.

5. **Returns compact results** to the LLM as structured tool_result blocks, carefully formatted to maximize information density while minimizing token consumption. The LLM receives aggregated statistics, labeled data, and pre-computed suggestions rather than raw API responses.

6. **Logs the complete session** — every tool call, every result, every LLM response, and the full tool definition array — to a JSON session file for audit and debugging.

This harness architecture means the LLM never directly touches any external API. It never constructs HTTP requests, computes authentication headers, parses JSON responses, or handles errors. It operates entirely within the structured tool-calling protocol, which reduces the failure surface to the smallest possible area: selecting the right tool name and filling in the correct arguments.

### The LLM Layer

The system uses **Gemma4-26B-A4B**, a Mixture-of-Experts model with 26 billion total parameters but only approximately 4 billion active parameters per inference pass. It runs locally on a vLLM server, eliminating cloud API costs and data sovereignty concerns — no alert data or log content ever leaves the organization's network.

The model communicates with the harness through the OpenAI-compatible chat completion API. On each turn, it receives the system prompt (containing the SOC analyst workflow rules), the conversation history (including all previous tool calls and results), and the tool definitions. It responds with either a tool call (structured JSON specifying which tool to invoke and with what arguments) or a final text response (its conclusion about the alert).

The model's temperature is set to 0.2 for production batch operations, prioritizing consistency over creativity. The same alert processed on different days should produce the same verdict — a property that higher temperatures would compromise.

A critical design decision is the **tool filtering** mechanism. The OpenHarness framework ships with 44 built-in tools (including general-purpose tools like bash, file editing, web search, and code analysis). The SOC wrapper script filters this down to only the 7 tools relevant to security triage before any API call is made. This reduces token consumption on every turn and eliminates the possibility of the model accidentally invoking irrelevant tools.

### The SOC Tool Layer

This is where the system's actual intelligence resides. Each tool encodes specific domain expertise that would otherwise require the LLM to reason from first principles — a task that small models handle unreliably.

**FortiSOAR Tools:**

- **List Alerts** queries FortiSOAR for open Critical and High severity alerts within the configured tenant and alert source. The query is pre-scoped by environment variables so the agent cannot accidentally access alerts from other tenants or sources — a fail-closed design that prevents cross-tenant data leakage on shared FortiSOAR instances.

- **Get Alert** fetches the full details of a specific alert and transforms the raw FortiSOAR response (which can be 174 lines of nested JSON) into a compact 32-line summary optimized for LLM consumption. The summary places **correlation hints** first — pre-extracted structured fields (ADOM, source/destination IPs with INTERNAL/EXTERNAL labels, detection timestamp, FortiGate action) followed by copy-pasteable suggested correlation queries that the LLM can execute verbatim. This tool also performs the **whitelist auto-close** check: if the alert's source IP matches a human-curated whitelist, the tool closes the alert immediately via the FortiSOAR API and returns a data-starved stop message that prevents the LLM from investigating further.

- **Resolve Alert** closes an alert in FortiSOAR with a closure reason and detailed closure notes. The tool enforces a closure reason allowlist (preventing the model from using deprecated reasons like "False Positive"), silently substitutes a safe default when the model picks an invalid reason, prepends a "[Triaged by BIS-AI Analyst]" identification marker to every closure note, and validates that the notes contain real evidence rather than vague dismissals.

- **Escalate Alert** transitions an alert from "Open" to "Investigating" status when the agent determines that human review is required. This removes the alert from the automated processing queue while preserving the agent's investigation findings for the human analyst. When SMTP integration is available, this tool will additionally send the findings via email and Microsoft Teams to the SOC lead.

**FortiAnalyzer Tools:**

- **Query Logs** performs asynchronous two-step log searches against FortiAnalyzer (create search task, poll for completion, fetch results). The tool internally fetches up to 500 log entries for statistical aggregation but presents only 50 sample entries to the LLM, along with computed summary statistics: top source/destination IPs, top destination ports, action breakdown, byte counts, and application distribution. This design gives the LLM a statistically meaningful picture of the traffic pattern without overwhelming its context window. When the query results contain inbound accepted traffic from an external source to an internal destination, the tool appends a prominent warning that reinforces the system prompt's escalation rule.

- **Query Security Events** aggregates IPS attack events, antivirus detections, web filter blocks, DLP incidents, application control events, and anomaly detections within a specified time window. Results are presented as counts per event type with top event names and source IPs, enabling the LLM to quickly assess whether the alert is an isolated event or part of a broader attack pattern.

**Netbox Tools:**

- **Lookup IP** queries the Netbox IP address management system to retrieve ownership information for internal IP addresses. The lookup first attempts an exact IP match, then falls back to the containing /24 subnet. This provides the "who owns this asset" context that transforms an alert about an anonymous IP address into an actionable finding with a specific team contact. The tool is fail-open — if Netbox is unavailable or the IP is not found, alert processing continues normally without ownership enrichment.

**Whitelist Engine:**

The IP/CIDR whitelist is a human-curated YAML file, reviewed and version-controlled through git, that identifies IP addresses whose traffic patterns are known to trigger security alerts but represent authorized activity. The canonical example is a threat intelligence collector that deliberately communicates with suspicious destinations as part of its operational role.

When an alert's source IP matches a whitelist entry, the system bypasses the LLM entirely — the tool layer closes the alert directly with a deterministic audit trail that includes the whitelist entry's justification, the author who added it, the date it was added, and the git blob SHA of the whitelist file at the time of closure. This design eliminates the failure mode where a small LLM would attempt to weigh a soft "this IP is whitelisted" hint against concrete and alarming-looking forensic evidence from the log correlation queries.

## Alert Processing Workflow

Each alert is processed in a fresh, isolated LLM conversation to prevent cross-alert context contamination. The **bis-soc** wrapper script orchestrates this by invoking the OpenHarness framework once per alert, either for a specific alert ID or in drain mode (processing every open alert in the queue sequentially).

**Step 1 — Alert Retrieval:** The LLM calls the Get Alert tool with the alert identifier. The tool fetches the alert from FortiSOAR, applies tenant and source authorization checks, performs the whitelist lookup, classifies all IP addresses as INTERNAL or EXTERNAL using RFC1918 range checks, and returns the compact summary with correlation hints.

**Step 2 — Whitelist Check:** If the alert's source IP matches the whitelist, the tool has already closed it. The LLM receives a data-starved stop message containing no IP addresses, no timestamps, no ADOM names — nothing it could use to call follow-up tools. The LLM outputs a one-sentence confirmation and the conversation ends. This path completes in approximately 3 seconds.

**Step 3 — Evidence Correlation:** For non-whitelisted alerts, the LLM executes exactly four correlation queries suggested by the Get Alert tool's correlation hints: (1) all security events in the 10-minute window after the detection, (2) source IP traffic in the 10-minute window after the detection, (3) source IP traffic in the 10-minute window before the detection, and (4) destination IP traffic in the 10-minute window after the detection.

**Step 4 — Verdict:** Based on the correlation evidence, the LLM makes one of two decisions:
- **Resolve:** If the threat was blocked at the perimeter (action=dropped/blocked/denied) and all correlation queries returned zero results, the LLM calls the Resolve Alert tool with detailed closure notes citing specific evidence, log entry citations, and the sampled-vs-total entry counts.
- **Escalate:** If the evidence is concerning — particularly if an external source successfully connected to an internal destination with data transfer — the LLM calls the Escalate Alert tool, which transitions the alert to "Investigating" status and records the agent's findings for human review.

## Design Principles

**One alert per conversation.** Each alert is processed in a completely isolated LLM session with a fresh context window. This eliminates constraint drift (where the model gradually relaxes its rules over multiple alerts), cross-alert state contamination (where findings from one alert influence the verdict on another), and context window exhaustion (where accumulated tool outputs crowd out the system prompt's instructions).

**Code decides, LLM suggests.** Every safety-critical decision is enforced in Python code, not in the system prompt. IP classification uses the stdlib ipaddress module, not LLM pattern matching. Closure reason validation uses an allowlist with deterministic substitution, not prompt-based guidance. Whitelist matching uses exact IP comparison and CIDR containment checks, not contextual hints the model might override. The system prompt serves as a behavioral guide for the average case; the code serves as an inviolable guardrail for every case.

**Compact tool output.** FortiAnalyzer can return thousands of log entries for a single query. The tool layer aggregates these into summary statistics computed over 500 entries and presents 50 representative samples to the LLM. This keeps each tool result under 6,000 characters while providing a statistically meaningful picture of the traffic pattern. The summary includes honesty markers ("aggregated over 500 of 6,045 entries") that the system prompt requires the model to propagate into its closure notes.

**Fail-closed on authorization, fail-open on enrichment.** FortiSOAR tenant scoping, source scoping, and alert status checks are fail-closed — the tool refuses to operate if any authorization check fails. Netbox ownership lookups and whitelist file loading are fail-open — if the enrichment source is unavailable, alert processing continues without it. This distinction ensures that security boundaries are never compromised while operational availability is maximized.

**Audit trail as a first-class feature.** Every AI-triaged closure carries a "[Triaged by BIS-AI Analyst — Gemma4-26B-A4B]" marker as the first line of the closure notes. Every whitelist auto-closure includes the git blob SHA of the whitelist file that authorized it. Every session is logged as a JSON file containing the full conversation, all tool calls and results, and the complete tool definition array. This enables forensic reconstruction of any triage decision months after the fact.

## Preliminary Results

In production testing against real FortiSOAR alerts from the Cloud Services tenant:

- **37+ alerts successfully auto-triaged** in a single batch run, with each alert processed in a fresh conversation averaging 30-60 seconds (or 3 seconds for whitelist hits).

- **Zero false negatives on whitelisted sources.** Every alert from the whitelisted FortiRecon threat intelligence collector was correctly auto-closed without LLM investigation, with full audit trails written to FortiSOAR.

- **Correct escalation behavior** demonstrated on alerts involving inbound accepted traffic from external sources, with the agent explicitly citing the escalation trigger pattern and transitioning the alert to "Investigating" status.

- **Accurate duplicate detection** observed during batch processing, where the model correctly identified alerts with matching source IP, destination, and detection rule as duplicates and resolved them with appropriate closure reasons without redundant FortiAnalyzer queries.

- **Honest evidence reporting** enforced through tool-output reminders and system prompt rules, with closure notes consistently citing "sampled N of M entries" when the full log window exceeded the analysis sample, and including specific log entry citations with timestamps, IP addresses, ports, and actions.

- **Log entry citation compliance** achieved through a "reminder-at-decision-point" technique, where the instruction to include specific log citations is embedded in the tool output itself (close to where the LLM generates its response) rather than relying solely on the system prompt (which fades from attention after multiple tool-call rounds in small models).

- **IP classification accuracy** achieved by moving CIDR range checking into the tool layer using Python's ipaddress module, after observing that the LLM incorrectly classified 172.67.x.x (a public Cloudflare IP) as internal because it pattern-matched the "172." prefix against the 172.16-31 private range without performing the numeric boundary check.

## Technology Stack

| Component | Technology | Role |
|-----------|-----------|------|
| LLM | Gemma4-26B-A4B via vLLM | Reasoning engine, tool selection, natural language summarization |
| Framework | OpenHarness (Python) | Tool-calling loop, permission gating, session logging |
| Alert Platform | FortiSOAR | Alert lifecycle management, orchestration |
| Log Analytics | FortiAnalyzer | Traffic logs, security events, forensic evidence |
| SIEM | FortiSIEM | Additional log aggregation and detection (planned integration) |
| Asset Management | Netbox | IP ownership lookup for escalation context |
| Whitelist | YAML + Pydantic + ipaddress | Deterministic auto-close for known-benign sources |
| Deployment | Docker (optional) | Container-ready with Dockerfile and docker-compose |
| Version Control | Git | Whitelist SHA audit trail, session logging, configuration management |

## Roadmap

**Completed:** FortiSOAR integration (list, get, resolve, escalate), FortiAnalyzer integration (log search, security events), IP/CIDR whitelist with auto-close, Netbox IP ownership lookup, batch processing wrapper (bis-soc), tool filtering, session logging with tool array, IP classification labels, log citation enforcement, escalation tool with status transition.

**In Progress:** FortiSIEM integration (mirrors FortiAnalyzer pattern, dispatched automatically via correlation hints based on alert origin), SMTP/Teams escalation notifications (pending network access).

**Planned:** Interactive TUI mode for analyst-driven investigation of escalated cases, CMDB-driven asset context enrichment beyond ownership, multi-vendor support (Palo Alto, Cisco) via the existing tool architecture, confidence-gated escalation with structured verdict output.
