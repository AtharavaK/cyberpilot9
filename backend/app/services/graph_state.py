from typing import TypedDict, List, Dict, Any, Optional


class Finding(TypedDict):
    agent_name: str
    severity: str
    description: str
    remediation: Optional[str]
    metadata: Optional[Dict[str, Any]]


class ComplianceFinding(TypedDict):
    finding_id: int
    agent_name: str
    severity: str
    owasp_llm: List[str]
    nist_csf: List[str]


class CyberPilotState(TypedDict):
    scan_id: str
    target_url: str
    status: str

    # Internal agent states
    recon_data: Dict[str, Any]
    recon_findings: List[Finding]
    ai_vulnerabilities: List[Finding]
    api_vulnerabilities: List[Finding]
    code_vulnerabilities: List[Finding]
    infra_vulnerabilities: List[Finding]

    # Aggregated results
    all_findings: List[Finding]
    overall_score: int
    compliance_status: str
    compliance_findings: List[ComplianceFinding]
    security_analysis_errors: List[str]

    # Final output
    final_report: Dict[str, Any]
    # Honesty tracking
    data_source: str  # "real_tools" | "simulation" | "partial"
    # User authorization for real/internal scans
    authorize: bool
    # Internal workflow bookkeeping (prefixed with _ to signal "not part of the report schema")
    _scan_started_at: float
    _scan_timeout_seconds: int
    # nmap-specific scan configuration for Recon Agent
    nmap_config: Dict[str, Any]
    # Interactive features
    remediation_details: Dict[int, Dict[str, Any]]  # per-finding structured fix steps
