from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any


# ── Scan Request / Response ────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target_url: HttpUrl = Field(..., example="https://example-ai-app.com")
    authorize: bool = False
    simulate: bool = True
    scan_timeout_seconds: int = 300
    scan_type: Optional[str] = None
    ports: Optional[str] = None
    os_detection: Optional[bool] = False
    scripts: Optional[str] = None
    traceroute: Optional[bool] = False
    ipv6: Optional[bool] = False
    dns_servers: Optional[str] = None
    version_intensity: Optional[int] = None
    # ── New: interactive scan control ──
    session_id: Optional[str] = None  # resume an existing session


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    data_source: str = "real_tools"
    session_id: Optional[str] = None


class ReportSummary(BaseModel):
    scan_id: str
    target_url: str
    overall_score: int
    findings: List["Finding"]
    compliance: List["ComplianceFinding"] = []
    executive_summary_pdf: Optional[str] = None
    technical_report_pdf: Optional[str] = None
    status: str = "COMPLETED"
    data_source: str = "real_tools"
    errors: List[str] = []


# ── Findings ────────────────────────────────────────────────────────────────────

class Finding(BaseModel):
    id: Optional[int] = None
    agent_name: str
    scanner: Optional[str] = None  # canonical alias for agent_name
    tool: Optional[str] = None
    severity: str
    confidence: Optional[float] = None  # 0.0 - 1.0
    title: Optional[str] = None
    category: Optional[str] = None
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    target: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    location: Optional[Dict[str, Any]] = None  # canonical location object
    cwe: Optional[List[str]] = None
    cve: Optional[List[str]] = None
    references: Optional[List[str]] = None
    status: Optional[str] = None  # triage status: open/in_progress/false_positive/accepted/remediated
    data_source: Optional[str] = None
    created_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    remediation_details: Optional[Dict[str, Any]] = None  # structured fix steps


class ComplianceFinding(BaseModel):
    agent_name: str
    severity: str
    owasp_llm: List[str]
    nist_csf: List[str]


# ── Scan Status (enhanced with progress info) ──────────────────────────────────

class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    target_url: Optional[str] = None
    overall_score: Optional[int] = None
    progress: Optional[Dict[str, Any]] = None
    data_source: Optional[str] = None
    findings_count: Optional[int] = None
    # PDF report URLs (populated when status is COMPLETED)
    executive_summary_pdf: Optional[str] = None
    technical_report_pdf: Optional[str] = None


# ── Scan Events (live streaming) ───────────────────────────────────────────────

class ScanEvent(BaseModel):
    id: int
    event_type: str
    payload: Dict[str, Any]
    created_at: str


class ScanEventsResponse(BaseModel):
    scan_id: str
    events: List[ScanEvent]
    latest_event: Optional[ScanEvent] = None


# ── Findings grouped explorer ──────────────────────────────────────────────────

class FindingsGroup(BaseModel):
    agent_name: str
    severity: str
    count: int
    findings: List[Finding]


class FindingsExplorerResponse(BaseModel):
    scan_id: str
    target_url: str
    by_agent: List[FindingsGroup]
    by_severity: List[FindingsGroup]
    triage_summary: Dict[str, int]  # status -> count
    total_findings: int


# ── Triage ─────────────────────────────────────────────────────────────────────

class TriageRequest(BaseModel):
    status: str = Field(..., pattern=r"^(open|in_progress|false_positive|accepted|remediated)$")
    note: Optional[str] = None


class TriageResponse(BaseModel):
    finding_id: int
    scan_id: str
    status: str
    note: Optional[str]
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


# ── Trends ─────────────────────────────────────────────────────────────────────

class ScanTrendResponse(BaseModel):
    target_url: str
    current_scan_id: str
    current_score: Optional[int]
    previous_scan_id: Optional[str]
    previous_score: Optional[int]
    current_by_severity: Dict[str, int]
    previous_by_severity: Optional[Dict[str, int]]
    diff: Optional[Dict[str, int]]  # positive = more findings than before


# ── Dashboard ──────────────────────────────────────────────────────────────────

class DashboardStatsResponse(BaseModel):
    total_scans: int
    by_status: Dict[str, int]
    findings_by_severity: Dict[str, int]
    open_triage_count: int
    recent_scans: List[Dict[str, Any]]


# ── Webhooks ───────────────────────────────────────────────────────────────────

class WebhookRequest(BaseModel):
    url: str
    name: Optional[str] = None
    events: List[str] = ["completed"]  # completed, critical, regression, all


class WebhookResponse(BaseModel):
    id: int
    user_id: int
    url: str
    name: Optional[str]
    events: List[str]
    created_at: str
    updated_at: str


# ── Remediation Details ────────────────────────────────────────────────────────

class RemediationStep(BaseModel):
    step: int
    title: str
    description: str
    command: Optional[str] = None
    reference: Optional[str] = None


class RemediationDetailsResponse(BaseModel):
    finding_id: int
    scan_id: str
    agent_name: str
    severity: str
    description: str
    remediation: Optional[str]
    steps: List[RemediationStep]
    references: List[str]


# ── AI Analysis (Phase 3) ──────────────────────────────────────────────────────

class AIAnalysisBase(BaseModel):
    """Base fields for AI analysis output.

    This is a SEPARATE object from Finding — the AI does NOT modify the
    original security finding.  It only produces analysis of the finding.
    """
    summary: str
    risk_explanation: str
    exploitability: str  # "low" | "medium" | "high"
    impact: str
    false_positive_assessment: str  # "likely_true" | "likely_false_positive" | "uncertain"
    confidence: float  # 0.0–1.0 — AI's confidence in its own assessment
    root_cause: Optional[str] = None
    remediation: str
    references: List[str] = Field(default_factory=list)
    priority: Optional[int] = None  # 1–10

    model_config = {"validate_assignment": True}


class AIAnalysisCreate(AIAnalysisBase):
    finding_id: Optional[int] = None
    scan_id: Optional[str] = None
    model: str = "unknown"


class AIAnalysisSchema(AIAnalysisBase):
    """Full AI analysis record as stored in / returned from the database."""
    finding_id: Optional[int] = None
    scan_id: Optional[str] = None
    model: str
    prompt_version: str = "v1.0"
    created_at: Optional[str] = None
    status: str = "completed"
    error: Optional[str] = None
    # Include scanner confidence for comparison (read-only, from original finding)
    scanner_confidence: Optional[float] = None
    scanner_severity: Optional[str] = None


class AIStatusResponse(BaseModel):
    """Response for /ai/status endpoint."""
    ai_enabled: bool
    ollama_available: bool
    model_available: bool
    ai_ready: bool
    model: str
    base_url: str
    timeout: int
    available_models: Optional[List[str]] = None
    error: Optional[str] = None


class AIBatchRequest(BaseModel):
    """Request body for batch analysis."""
    simulate: Optional[bool] = False
    max_concurrency: int = Field(default=1, ge=1, le=10)


# ── Tool Status ────────────────────────────────────────────────────────────────

class ToolStatus(BaseModel):
    """Status of a single security tool."""
    name: str
    tool_name: str
    installed: bool
    available: bool
    status: str  # "ready" | "unavailable" | "error" | "not_installed"
    version: Optional[str] = None
    enabled: bool = True
    description: Optional[str] = None


class ToolStatusResponse(BaseModel):
    """Aggregate tool status for all scanners."""
    tools: List[ToolStatus]
