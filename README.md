# OpenHarness SOC — AI-Powered Security Alert Triage

An AI SOC analyst that automatically triages FortiSOAR security alerts by correlating evidence from FortiAnalyzer and FortiSIEM, then resolving or escalating each alert — powered by a locally-hosted LLM (Gemma4-26B) harnessed through structured tool calling.

<p align="center">
  <img src="https://img.shields.io/badge/python-≥3.10-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/LLM-Gemma4--26B-orange" alt="Gemma4">
  <img src="https://img.shields.io/badge/tests-106_passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/alerts_triaged-37+-green" alt="Alerts">
  <img src="https://img.shields.io/badge/license-MIT-yellow" alt="License">
</p>

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  bis-soc CLI                                                │
│  One alert per conversation — no constraint drift           │
└─────────────┬───────────────────────────────────────────────┘
              │
┌─────────────▼───────────────────────────────────────────────┐
│  OpenHarness Framework                                      │
│  Tool registry (7 SOC tools) · Permission checker           │
│  JSON tool-call loop · Session logger                       │
│  ─── The harness: JSON in, JSON out, deterministic ───      │
└─────────────┬───────────────────────────────────────────────┘
              │ structured JSON tool calls
┌─────────────▼───────────────────────────────────────────────┐
│  Gemma4-26B-A4B via vLLM                                    │
│  Picks tools · Fills args · Writes closure notes            │
│  Temperature 0.2 · Local inference · Zero API cost          │
└─────────────┬───────────────────────────────────────────────┘
              │ validated arguments
┌─────────────▼───────────────────────────────────────────────┐
│  SOC Tool Layer — Intelligence Lives Here                   │
│                                                             │
│  FortiSOAR          FortiAnalyzer      Other                │
│  ├─ list_alerts     ├─ query_logs      ├─ whitelist engine  │
│  ├─ get_alert       └─ query_security  ├─ netbox_lookup_ip  │
│  ├─ resolve_alert      _events         └─ (FortiSIEM next)  │
│  └─ escalate_alert                                          │
│                                                             │
│  IP labels · CIDR matching · Log aggregation · Audit trails │
└─────────────┬───────────────────────────────────────────────┘
              │
┌─────────────▼───────────────────────────────────────────────┐
│  External Systems                                           │
│  FortiSOAR (HMAC) · FortiAnalyzer (JSON-RPC) · Netbox      │
└─────────────────────────────────────────────────────────────┘
```

## Core Design Principle

**Intelligence lives in the tool layer, not in the model.**

The LLM's job is small and well-scoped: pick a tool, fill in JSON arguments, summarize results in natural language. Everything else — HMAC authentication, CIDR classification, log aggregation, whitelist matching, audit trail generation — runs in deterministic Python code. This makes the system reliable with a small, locally-hosted model that would otherwise struggle with these tasks.

## Features

### Alert Triage
- **Automated batch processing** — `bis-soc` drains all open Critical/High alerts, one per fresh LLM conversation
- **Single alert mode** — `bis-soc Alert-NNN` for targeted investigation
- **4-query correlation workflow** — security events, source IP traffic (before/after), destination IP traffic
- **Evidence-based closure** — closure notes include specific numbers, log citations, and sampled-vs-total counts

### Whitelist Auto-Close
- **Human-curated YAML** — IP and CIDR entries with justification, author, date
- **Bypasses LLM entirely** — code closes the alert, returns a data-starved stop message
- **Git SHA audit trail** — every closure cites the exact whitelist file version
- **CIDR matching** — Python `ipaddress` module, not LLM pattern matching

### Escalation
- **Status transition** — Open → Investigating, removes alert from automated queue
- **Inbound-accept detection** — tool-output warning when external source → internal destination with action=accept
- **IP classification** — every IP labeled (INTERNAL) or (EXTERNAL) by code, not by the LLM
- **SMTP/Teams notification** — planned, pending network access

### Safety Guardrails
- **Tenant + source scoping** — fail-closed, refuses to process alerts outside configured scope
- **Closure reason allowlist** — off-list picks silently substituted with safe default
- **BIS-AI marker** — `[Triaged by BIS-AI Analyst — Gemma4-26B-A4B]` on every closure
- **Tool filtering** — 44 framework tools → 7 SOC tools, reducing token waste and model confusion
- **One alert per conversation** — prevents constraint drift and context exhaustion

### Observability
- **Full session logging** — every tool call, result, and the complete tool definition array
- **[LOG] citation enforcement** — tool-output reminders force the LLM to cite specific log entries
- **"Sampled N of M" language** — honest reporting when analysis covers a sample, not the full window

## Quick Start

### Prerequisites
- Python ≥ 3.10
- A vLLM server hosting Gemma4-26B-A4B (or any OpenAI-compatible endpoint)
- FortiSOAR access (HMAC key files)
- FortiAnalyzer access (API user credentials)

### Installation

```bash
git clone https://github.com/kncshw/openharness-soc.git
cd openharness-soc
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Configuration

```bash
cp .env.example .env
# Edit .env with your credentials:
#   FortiSOAR: URL, key files, tenant, source
#   FortiAnalyzer: host, user, password, ADOMs
#   LLM: vLLM endpoint URL, model name
#   Optional: Netbox URL + token, whitelist file path
```

### Run

```bash
# Process one alert
bin/bis-soc Alert-109331

# Drain all open Critical/High alerts
bin/bis-soc
```

### Whitelist

Edit `config/soc_whitelist.yaml` to add known-benign IPs:

```yaml
- ip: 10.125.19.31
  reason: "FortiRecon internal threat-intel collector"
  added_by: kaini
  added_on: 2026-04-08
  closure_reason: Risk Accept

- cidr: 10.125.19.0/24
  reason: "Threat-intel collector subnet"
  added_by: kaini
  added_on: 2026-04-08
  closure_reason: Risk Accept
```

### Docker (optional)

```bash
docker build -f Dockerfile.soc -t bis-soc:latest .
docker compose -f docker-compose.soc.yml run --rm soc-agent           # drain all
docker compose -f docker-compose.soc.yml run --rm soc-agent Alert-NNN # single
```

## Project Structure

```
bin/
  bis-soc                     # Batch wrapper (single + drain mode)
  oh-pretty.py                # Stream-JSON pretty printer
config/
  soc_whitelist.yaml          # Human-curated IP/CIDR whitelist
docs/
  soc-analyst-prompt-min.md   # System prompt (batch mode)
  soc-system-design.md        # Full architecture document
  soc-escalation-design.md    # SMTP/Teams escalation design
  soc-netbox-integration-plan.md
  soc-harness-architecture.md # Mermaid diagrams
src/openharness/
  tools/
    _fortisoar_helpers.py     # FortiSOAR HMAC auth + REST client
    _faz_helpers.py           # FAZ JSON-RPC + async log search
    _whitelist.py             # Whitelist schema, loader, auto-close
    _netbox_helpers.py        # Netbox pynetbox wrapper
    fortisoar_list_alerts_tool.py
    fortisoar_get_alert_tool.py
    fortisoar_resolve_alert_tool.py
    fortisoar_escalate_alert_tool.py
    faz_query_logs_tool.py
    faz_query_security_events_tool.py
    netbox_lookup_ip_tool.py
  soc_auto_close.py           # Standalone auto-close CLI
  soc_list_open_alerts.py     # Alert ID lister for drain mode
tests/
  test_soc_fortisoar_tools.py # FortiSOAR tool tests
  test_soc_faz_tools.py       # FAZ tool tests
  test_soc_whitelist.py       # Whitelist + auto-close tests
  test_soc_list_open_alerts.py
```

## Integration Architecture

**FortiSOAR** is the central orchestration platform. It aggregates security alerts from FortiAnalyzer and FortiSIEM into a unified ticket queue. The SOC agent processes this queue.

**FortiAnalyzer** holds the forensic evidence — traffic logs, security events, application control logs from every FortiGate in the network. The agent queries FAZ to correlate alert evidence.

**FortiSIEM** serves the same role as FortiAnalyzer for a different set of log sources. Alerts originating from FortiSIEM also flow into FortiSOAR. The agent dispatches to the correct log backend automatically based on alert origin. *(Integration in progress)*

**Netbox** provides IP-to-owner mapping. When escalating, the agent looks up the involved IPs to identify the owning team, accelerating incident response.

## Preliminary Results

| Metric | Result |
|--------|--------|
| Alerts auto-triaged (batch) | 37+ |
| Whitelist auto-close accuracy | 100% (0 false negatives) |
| Avg time per alert (with FAZ correlation) | 30–60 seconds |
| Avg time per alert (whitelist hit) | ~3 seconds |
| Escalation on inbound-accepted traffic | Correctly triggered |
| Duplicate detection | Working (skips redundant FAZ queries) |
| False closure of action=accept alerts | Mitigated via tool-output warnings + IP labels |

## Roadmap

- [x] FortiSOAR integration (list, get, resolve, escalate)
- [x] FortiAnalyzer integration (async log search, security events)
- [x] IP/CIDR whitelist with auto-close
- [x] Batch processing wrapper (bis-soc)
- [x] Tool filtering (44 → 7)
- [x] IP classification labels (INTERNAL/EXTERNAL)
- [x] [LOG] citation enforcement
- [x] BIS-AI triage marker
- [x] Session logging with tool array
- [x] Netbox IP ownership lookup
- [x] Escalation tool (Open → Investigating)
- [ ] FortiSIEM integration (mirrors FAZ pattern)
- [ ] SMTP/Teams escalation notifications
- [ ] Interactive TUI mode for analyst escalation cases
- [ ] CMDB-driven asset context enrichment
- [ ] Multi-vendor support (Palo Alto, Cisco)

## Design Documents

| Document | Description |
|----------|-------------|
| [System Design](docs/soc-system-design.md) | Full architecture, workflow, design principles, results |
| [Escalation Design](docs/soc-escalation-design.md) | SMTP/Teams notification + status transition |
| [Architecture Diagrams](docs/soc-harness-architecture.md) | Mermaid diagrams (system, flow, tools, stack) |
| [Netbox Integration](docs/soc-netbox-integration-plan.md) | IP ownership lookup plan |
| [CMDB & Fine-tuning Decision](docs/soc-cmdb-and-fine-tuning-decision.md) | Why CMDB first, fine-tuning deferred |
| [Escalation Experiment](docs/soc-escalation-experiment-plan.md) | Temperature A/B test, action gate, verdict improvements |

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Built on the [OpenHarness](https://github.com/HKUDS/OpenHarness) agent framework. SOC tools and harness design by kaini with Claude Opus 4.6.
