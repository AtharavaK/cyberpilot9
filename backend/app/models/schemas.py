from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional

class ScanRequest(BaseModel):
    target_url: HttpUrl = Field(..., example="https://example-ai-app.com")
    authorize: bool = False  # Explicit authorization for real tool scans
    simulate: bool = True  # If True, use simulation mode regardless of tool availability

class Finding(BaseModel):
    agent_name: str
    severity: str
    description: str
    remediation: Optional[str] = None

class ComplianceFinding(BaseModel):
    agent_name: str
    severity: str
    owasp_llm: List[str]
    nist_csf: List[str]

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    data_source: str = "real_tools"  # "real_tools" | "simulation" | "partial"

class ReportSummary(BaseModel):
    scan_id: str
    target_url: str
    overall_score: int
    findings: List[Finding]
    compliance: List[ComplianceFinding] = []
    executive_summary_pdf: Optional[str] = None
    technical_report_pdf: Optional[str] = None
    status: str = "COMPLETED"
    data_source: str = "real_tools"
    errors: List[str] = []
