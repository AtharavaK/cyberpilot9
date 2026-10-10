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
    # Normalized target info from TargetNormalizer (see target_normalizer.py).
    # Populated in start_scan_workflow; consumed by security_analysis_node.
    target_normalized: Optional[Dict[str, Any]]

    # ── Phase 5: Assessment Plan & Task State ──────────────────────────────
    assessment_plan: Optional[Dict[str, Any]]  # serialized AssessmentPlan
    tasks: List[Dict[str, Any]]                # all SecurityTasks
    agent_results: List[Dict[str, Any]]        # all AgentResults
    decisions: List[Dict[str, Any]]            # MasterDecision audit trail
    policy_decisions: List[Dict[str, Any]]     # policy validation records
    iteration: int                             # current iteration (0-indexed)
    max_iterations: int                        # bound on loop
    ai_analyses: List[Dict[str, Any]]          # AIAnalysis results for findings
    task_results: Dict[str, Dict[str, Any]]    # task_id → AgentResult
    completion_reason: Optional[str]           # why the assessment stopped
    scan_budget: Dict[str, Any]                # runtime/resource budget tracking
