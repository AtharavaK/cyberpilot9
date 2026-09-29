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
    agent_name: str
    severity: str
    description: str
    remediation: Optional[str] = None
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
    status: str = Field(..., pattern=r"^(open|false_positive|accepted|remediated)$")
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
