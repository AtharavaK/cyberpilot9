# CyberPilot Architecture

## Overview

CyberPilot is a modular, agentic security-assessment platform. It transforms a target
(URL, Git repo, local path) into prioritized, validated, deduplicated findings with
AI-powered analysis and PDF reports.

## Architecture Layers

```
┌─────────────────────────────────────────────────────────┐
│  User / API                                             │
│  POST /scan/start  →  scan_id                           │
│  GET  /scans/{id}  →  status + findings                │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  FastAPI Backend (uvicorn :8000)                        │
│  - Authentication (Bearer API keys, SHA256 hashed)      │
│  - Scan lifecycle (start, pause, resume, cancel)        │
│  - Event streaming (Server-Sent Events)                 │
│  - PDF report generation                                │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  Master Agent (LangGraph StateGraph)                    │
│  Phase 5 graph flow:                                    │
│    planning → recon → security_analysis →                │
│    ai_analysis → decide → (iterate) → report → END     │
│                                                         │
│  Phase 1-3 nodes (preserved):                           │
│    recon → security_analysis → risk_scoring →          │
│    compliance → recommendations → report              │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  MasterSecurityAgent (planning.py)                      │
│  - create_assessment_plan(): target-aware task creation │
│  - evaluate_finding_for_followup(): finding-driven loop │
│  - should_stop(): bounded iteration + stopping criteria │
│  - AI-assisted (optional) with structured output        │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  SecurityPolicy (planning.py)                           │
│  Validates every task before execution:                 │
│  - Target scope (hostname-based, subdomains allowed)    │
│  - Allowed tools (whitelist)                            │
│  - Active scan authorization                            │
│  - SSRF protection (localhost, private IPs, metadata)  │
│  - Cancellation state                                    │
│  - Resource limits (max_tasks, max_runtime)            │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  Specialized Agents (via ToolManager)                   │
│  ┌────────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐   │
│  │Recon   │  │Code  │  │Infra │  │Web   │  │API   │   │
│  │Agent   │  │Agent │  │Agent │  │Agent │  │Agent │   │
│  │nmap    │  │semgr │  │trivy │  │zap   │  │zap   │   │
│  │http    │  │bandit│  │      │  │http  │  │http  │   │
│  │        │  │gitleak│  │      │  │      │  │      │   │
│  └────────┘  └──────┘  └──────┘  └──────┘  └──────┘   │
│  (AI Security Agent: ai_tester)                        │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  Scanners (app/services/tools/)                         │
│  - NmapScanner, SemgrepScanner, BanditScanner          │
│  - GitleaksScanner, TrivyScanner, ZapScanner           │
│  - AISecurityTester                                      │
│  Each: ScanResult(status, findings, error, duration)   │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  Finding Normalization (finding_normalizer.py)          │
│  - build_canonical_finding()                            │
│  - normalize_severity(), normalize_confidence()         │
│  - _extract_cwe_ids(), redact_sensitive_text()          │
│  - dedup_findings() (deterministic fingerprinting)     │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  AI Analysis (ai_engine.py)                             │
│  - AIEngine (optional, MockAIProvider default)          │
│  - analyze_finding() / analyze_findings()               │
│  - AIAnalysis: summary, risk, exploitability,           │
│    false_positive, remediation, references             │
│  - Secrets redacted BEFORE consumption (_redact_for_ai)  │
│  - Fixed SYSTEM_PROMPT, findings treated as untrusted   │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  Database (SQLite, aiosqlite)                           │
│  Tables: scans, findings, scan_events, scan_sessions,   │
│    api_keys, ai_analysis, assessment_tasks,             │
│    agent_decisions, triage                              │
└─────────────────────────────────────────────────────────┘
```

## Component Directory

| Path | Description |
|---|---|
| `app/api/endpoints.py` | REST API: scan lifecycle, findings, AI analysis, Phase 5 orchestration endpoints |
| `app/db/database.py` | SQLite schema initialization |
| `app/db/crud.py` | Database CRUD operations |
| `app/models/schemas.py` | Pydantic response schemas |
| `app/services/target_normalizer.py` | Phase 1: Target normalization + safe git cloning |
| `app/services/target_validation.py` | SSRF protection (localhost, private IP blocking) |
| `app/services/finding_normalizer.py` | Phase 2: Canonical finding, severity/confidence normalization, secret redaction, dedup |
| `app/services/ai_engine.py` | Phase 3: AI engine with MockAIProvider/OllamaProvider |
| `app/services/tool_manager.py` | Agent-to-scanner mapping, finding standardization |
| `app/services/master_agent.py` | Phase 4/5: LangGraph workflow with planning, execution, analysis, decision loop |
| `app/services/planning.py` | Phase 5: MasterSecurityAgent, SecurityPolicy, AssessmentPlan, SecurityTask |
| `app/services/graph_state.py` | LangGraph TypedDict state |
| `app/services/tools/*.py` | Scanner implementations |

## Security Boundaries

1. **ToolManager boundary** — all tool execution goes through ToolManager.
   Master Agent never executes shell commands directly.
2. **Policy boundary** — SecurityPolicy validates every task before execution.
   Nothing bypasses the policy layer.
3. **Target scope** — tasks cannot exceed authorized target scope.
   Sibling domains are blocked; subdomains require hostname-based matching.
4. **SSRF protection** — localhost, private IPs, cloud metadata endpoints blocked
   unless explicitly authorized via `ALLOW_PRIVATE_TARGETS=true`.
5. **Active scanning** — disabled by default. Requires explicit authorization
   via `authorize=True` or `ZAP_MODE=active`.
6. **AI trust boundary** — all scanner output, HTTP responses, filenames, URLs,
   and finding descriptions are treated as untrusted. System prompt is fixed
   and cannot be modified by tool output.
7. **Secret protection** — secrets are redacted before AI consumption via
   `redact_sensitive_text()` and `_redact_for_ai()`. Never logged or stored raw.
8. **Finding immutability** — AI analysis never modifies canonical findings.
   AIAnalysis is stored separately with a reference to the original finding.

## Phase 5 Orchestration Flow

### 1. Planning (planning_node)
- Target normalized via Phase 1 TargetNormalizer
- MasterSecurityAgent.create_assessment_plan() generates AssessmentPlan
- Target-aware: web URLs get recon/web/API/AI tasks; local paths get code/infra tasks
- Plan validated by SecurityPolicy.validate_plan()
- Tasks persisted to `assessment_tasks` table

### 2. Execution (recon_node, security_analysis_node)
- Tasks dispatched to specialized agents via ToolManager
- Each agent runs its assigned scanners
- Scanner availability checked (NOT_INSTALLED when unavailable)
- Findings normalized to canonical Finding model
- Findings persisted to `findings` table

### 3. AI Analysis (ai_analysis_node)
- AIEngine.analyze_findings() processes all findings
- Secrets redacted before AI consumption
- AIAnalysis objects stored with finding references
- MockAIProvider used when Ollama unavailable

### 4. Decision (decide_node)
- MasterSecurityAgent.evaluate_finding_for_followup() for each new finding
- HIGH/CRITICAL findings with medium+ confidence trigger follow-up tasks
- MasterSecurityAgent.should_stop() checks stopping criteria
- Stopping: all tasks complete, max iterations, max tasks, max runtime, no progress
- Decisions persisted to `agent_decisions` table

### 5. Iteration Loop
```
planning → execute → analyze → decide
  ↑ (if more work)
report → END
```
Bounded by max_iterations (default: 5).

### 6. Reporting (risk_scoring_node → report_node)
- Risk scoring aggregates finding severity/confidence
- Compliance mapping to frameworks
- Recommendations generated
- PDF reports (executive summary + technical report)
