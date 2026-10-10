from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
from app.models.schemas import (
    ScanRequest, ScanResponse, ReportSummary, ComplianceFinding, Finding,
    ScanStatusResponse, ScanEvent, ScanEventsResponse,
    FindingsGroup, FindingsExplorerResponse,
    TriageRequest, TriageResponse,
    ScanTrendResponse, DashboardStatsResponse,
    ToolStatus, ToolStatusResponse,
    WebhookRequest, WebhookResponse,
    RemediationDetailsResponse, RemediationStep,
    AIAnalysisSchema, AIAnalysisCreate, AIStatusResponse, AIBatchRequest,
)
from app.services import master_agent
from app.services.ai_engine import (
    AIEngine, AIAnalysis as AIAnalysisModel, AIUnavailableError,
    AIValidationError, AIError,
)
from app.services.tools import (
    NmapScanner, SemgrepScanner, BanditScanner,
    GitleaksScanner, TrivyScanner, ZapScanner, AISecurityTester,
)
from app.db import crud
from app.api.auth import validate_api_key
import os
import sys
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


router = APIRouter()


# ── Auth dependency (same as existing) ─────────────────────────────────────────

async def get_current_user(key_data: dict = Depends(validate_api_key)) -> dict:
    return key_data


# ── Health (public) ────────────────────────────────────────────────────────────

@router.get("/health")
async def health_check():
    return {"status": "ok"}


# ── Start Scan ──────────────────────────────────────────────────────────────────

@router.post("/scan/start", response_model=ScanResponse)
async def start_scan(request: ScanRequest, current_user: dict = Depends(get_current_user)):
    data_source = "simulation" if request.simulate else "real_tools"

    nmap_config = {}
    if request.scan_type:
        nmap_config["scan_type"] = request.scan_type
    if request.ports:
        nmap_config["ports"] = request.ports
    if request.os_detection:
        nmap_config["os_detection"] = True
    if request.scripts:
        nmap_config["scripts"] = request.scripts
    if request.traceroute:
        nmap_config["traceroute"] = True
    if request.ipv6:
        nmap_config["ipv6"] = True
    if request.dns_servers:
        nmap_config["dns_servers"] = request.dns_servers
    if request.version_intensity is not None:
        nmap_config["version_intensity"] = request.version_intensity

    try:
        scan_id = await master_agent.start_scan_workflow(
            str(request.target_url),
            data_source=data_source,
            authorize=request.authorize,
            scan_timeout_seconds=request.scan_timeout_seconds,
            nmap_config=nmap_config or {},
            session_id=request.session_id or "",
        )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    return ScanResponse(
        scan_id=scan_id,
        status="ACCEPTED",
        message=f"Scan initiated for {request.target_url}" + (" (simulation mode)" if request.simulate else ""),
        data_source=data_source,
        session_id=scan_id,
    )


# ── Scan Status (enhanced with progress) ───────────────────────────────────────

@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, current_user: dict = Depends(get_current_user)):
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")

    progress = None
    executive_summary_pdf = None
    technical_report_pdf = None
    if result["status"] in ("INITIALIZING", "RECONNAISSANCE", "SECURITY_ANALYSIS",
                              "RISK_SCORING", "COMPLIANCE_MAPPING", "RECOMMENDATIONS",
                              "PAUSED"):
        progress = await crud.get_scan_progress(scan_id)

    # Populate PDF URLs when scan is complete
    if result["status"] == "COMPLETED":
        final_report = result.get("final_report", {})
        if isinstance(final_report, str):
            try:
                final_report = json.loads(final_report)
            except (json.JSONDecodeError, TypeError):
                final_report = {}
        executive_summary_pdf = final_report.get("executive_summary_pdf")
        technical_report_pdf = final_report.get("technical_report_pdf")

    findings_count = len(result.get("findings", [])) if result.get("findings") else 0

    return ScanStatusResponse(
        scan_id=scan_id,
        status=result["status"],
        target_url=result.get("target_url"),
        overall_score=result.get("overall_score"),
        progress=progress,
        data_source=result.get("data_source", "real_tools"),
        findings_count=findings_count,
        executive_summary_pdf=executive_summary_pdf,
        technical_report_pdf=technical_report_pdf,
    )


# ── Scan Events (live streaming / event log) ──────────────────────────────────

@router.get("/scan/{scan_id}/events", response_model=ScanEventsResponse)
async def get_scan_events(
    scan_id: str,
    since_id: int = 0,
    current_user: dict = Depends(get_current_user),
):
    """Get all events for a scan. Poll this endpoint repeatedly for live updates,
    passing the last seen event `id` as `since_id`."""
    raw_events = await crud.get_scan_events(scan_id, since_id)
    events = [ScanEvent(id=e["id"], event_type=e["event_type"],
                         payload=e["payload"], created_at=e["created_at"])
              for e in raw_events]

    latest = await crud.get_latest_scan_event(scan_id)

    return ScanEventsResponse(
        scan_id=scan_id,
        events=events,
        latest_event=ScanEvent(id=latest["id"], event_type=latest["event_type"],
                                payload=latest["payload"], created_at=latest["created_at"]) if latest else None,
    )


# ── Report Downloads ────────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/report/executive-summary")
async def download_executive_summary(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Download executive summary PDF report."""
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")

    if result["status"] != "COMPLETED":
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    final_report = result.get("final_report") or {}
    if isinstance(final_report, str):
        try:
            final_report = json.loads(final_report)
        except (json.JSONDecodeError, TypeError):
            final_report = {}

    pdf_path = final_report.get("executive_summary_pdf")
    if not pdf_path or not os.path.exists(pdf_path):
        # Fallback to file system lookup
        basename = f"{scan_id}_executive_summary.pdf"
        fallback = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output", "reports", basename))
        if os.path.exists(fallback):
            pdf_path = fallback
        else:
            raise HTTPException(status_code=404, detail=f"Executive summary PDF not found for scan {scan_id}")

    return FileResponse(pdf_path, media_type="application/pdf",
                        filename=f"{scan_id}_executive_summary.pdf")


@router.get("/scan/{scan_id}/report/technical")
async def download_technical_report(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Download technical report PDF."""
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")

    if result["status"] != "COMPLETED":
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    final_report = result.get("final_report") or {}
    if isinstance(final_report, str):
        try:
            final_report = json.loads(final_report)
        except (json.JSONDecodeError, TypeError):
            final_report = {}

    pdf_path = final_report.get("technical_report_pdf")
    if not pdf_path or not os.path.exists(pdf_path):
        basename = f"{scan_id}_technical_report.pdf"
        fallback = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output", "reports", basename))
        if os.path.exists(fallback):
            pdf_path = fallback
        else:
            raise HTTPException(status_code=404, detail=f"Technical report PDF not found for scan {scan_id}")

    return FileResponse(pdf_path, media_type="application/pdf",
                        filename=f"{scan_id}_technical_report.pdf")


# ── Target Validation ──────────────────────────────────────────────────────────

class TargetValidationRequest(BaseModel):
    target_url: str

class TargetValidationResponse(BaseModel):
    target_url: str
    valid: bool
    target_kind: str
    normalized: str
    error: Optional[str] = None

@router.post("/scan/validate", response_model=TargetValidationResponse)
async def validate_scan_target(
    request: TargetValidationRequest,
    current_user: dict = Depends(get_current_user),
):
    """Validate and classify a target URL without starting a scan.

    Uses the backend TargetNormalizer to detect target type.
    """
    from app.services.target_normalizer import TargetNormalizer
    from app.services.target_validation import validate_target
    import dataclasses

    norm = TargetNormalizer()
    nt = await norm.normalize(request.target_url)
    nt_dict = dataclasses.asdict(nt)
    is_valid, reason = validate_target(request.target_url)
    return TargetValidationResponse(
        target_url=request.target_url,
        valid=is_valid,
        target_kind=nt_dict.get("kind", "unknown"),
        normalized=nt_dict.get("web_target") or request.target_url,
        error=None if is_valid else reason,
    )


# ── Findings Explorer (grouped) ─────────────────────────────────────────────────

@router.post("/scan/{scan_id}/pause")
async def pause_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")
    if result["status"] not in ("INITIALIZING", "RECONNAISSANCE", "SECURITY_ANALYSIS",
                                  "RISK_SCORING", "COMPLIANCE_MAPPING", "RECOMMENDATIONS"):
        raise HTTPException(status_code=400, detail=f"Cannot pause scan in status '{result['status']}'")
    await crud.mark_scan_paused(scan_id)
    await crud.add_scan_event(scan_id, "control", {"action": "pause", "message": "Scan paused by user"})
    return {"scan_id": scan_id, "status": "PAUSED", "message": "Scan paused successfully"}


@router.post("/scan/{scan_id}/resume")
async def resume_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")
    if result["status"] != "PAUSED":
        raise HTTPException(status_code=400, detail=f"Cannot resume scan in status '{result['status']}'. Only PAUSED scans can be resumed.")
    await crud.mark_scan_resumed(scan_id)
    await crud.add_scan_event(scan_id, "control", {"action": "resume", "message": "Scan resumed by user"})

    # Restart the workflow from where it left off
    session = await crud.get_scan_session(scan_id)
    current_phase = session.get("current_phase", "recon") if session else "recon"

    try:
        await master_agent.start_scan_workflow(
            result["target_url"],
            data_source=result.get("data_source", "real_tools"),
            authorize=True,  # already authorized
            scan_timeout_seconds=300,
            session_id=scan_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    return {"scan_id": scan_id, "status": "RESUMED", "message": "Scan resumed. Workflow restarting from last phase."}


@router.post("/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")
    if result["status"] in ("COMPLETED", "CANCELLED", "FAILED"):
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan in status '{result['status']}'")
    await crud.mark_scan_cancelled(scan_id)
    await crud.add_scan_event(scan_id, "control", {"action": "cancel", "message": "Scan cancelled by user"})
    # Clean up any temporary clone directories
    await crud.cleanup_scan_clone(scan_id)
    return {"scan_id": scan_id, "status": "CANCELLED", "message": "Scan cancellation requested"}


@router.post("/scan/{scan_id}/resume-failed")
async def resume_failed_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Restart a failed or timed-out scan from scratch."""
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")
    if result["status"] not in ("FAILED", "TIMEOUT", "CANCELLED"):
        raise HTTPException(status_code=400, detail=f"Can only resume-failed scans in FAILED/TIMEOUT/CANCELLED status, not '{result['status']}'")

    # Reset the scan for re-run
    await crud.update_scan_status(scan_id, "INITIALIZING")
    await crud.mark_scan_resumed(scan_id)

    try:
        new_session_id = await master_agent.start_scan_workflow(
            result["target_url"],
            data_source=result.get("data_source", "real_tools"),
            authorize=True,
            scan_timeout_seconds=300,
            session_id=scan_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    await crud.add_scan_event(scan_id, "control", {"action": "resume_failed", "message": "Failed scan restarted"})
    return {"scan_id": scan_id, "status": "RESTARTED", "message": "Scan restarted from scratch"}


# ── Findings Explorer (grouped) ─────────────────────────────────────────────────

@router.get("/scan/{scan_id}/findings", response_model=FindingsExplorerResponse)
async def get_findings_explorer(scan_id: str, current_user: dict = Depends(get_current_user)):
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")

    findings_raw = result.get("findings", [])
    if not findings_raw and result["status"] == "COMPLETED":
        # Try loading from DB directly
        db_scan = await crud.get_scan(scan_id)
        findings_raw = db_scan.get("findings", []) if db_scan else []
    else:
        db_scan = await crud.get_scan(scan_id)
        findings_raw = db_scan.get("findings", []) if db_scan else findings_raw

    # Convert raw DB dicts (which already have id + metadata JSON) to Finding objects
    findings = []
    for f in findings_raw:
        meta = f.get("metadata", {})
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except (json.JSONDecodeError, TypeError):
                meta = {}
        if isinstance(meta, dict):
            file_path = f.get("file") or meta.get("file", "")
            line = f.get("line") or meta.get("line", 0) or 0
            cwe = f.get("cwe") or meta.get("cwe", [])
            cve = f.get("cve") or meta.get("cve", [])
            refs = f.get("references") or meta.get("references", [])
            tool = f.get("tool") or meta.get("tool", "")
            title = f.get("title") or meta.get("title", "")
            category = f.get("category") or meta.get("raw_type", "")
            evidence = f.get("evidence") or meta.get("evidence", "")
            target = f.get("target") or meta.get("target", "")
            confidence = f.get("confidence") or meta.get("confidence")
            data_source = f.get("data_source") or ""
        else:
            file_path = ""
            line = 0
            cwe = []
            cve = []
            refs = []
            tool = ""
            title = ""
            category = ""
            evidence = ""
            target = ""
            confidence = None
            data_source = ""

        finding_obj = Finding(
            id=f.get("id"),
            agent_name=f.get("agent_name", "Unknown"),
            tool=tool or None,
            severity=f.get("severity", "LOW"),
            confidence=confidence,
            title=title or None,
            category=category or None,
            description=f.get("description", ""),
            evidence=evidence or None,
            remediation=f.get("remediation"),
            target=target or None,
            file=file_path or None,
            line=line,
            cwe=cwe if cwe else None,
            cve=cve if cve else None,
            references=refs if isinstance(refs, list) else None,
            data_source=data_source or None,
            metadata=meta if isinstance(meta, dict) else None,
        )
        findings.append(finding_obj)

    # Group by agent
    by_agent_map: dict = {}
    for f in findings:
        key = f.agent_name
        if key not in by_agent_map:
            by_agent_map[key] = {"agent_name": key, "severity": "", "count": 0, "findings": []}
        by_agent_map[key]["findings"].append(f)
        by_agent_map[key]["count"] = len(by_agent_map[key]["findings"])

    by_agent = sorted(by_agent_map.values(), key=lambda x: -x["count"])

    # Group by severity
    by_severity_map: dict = {}
    for f in findings:
        key = f.severity
        if key not in by_severity_map:
            by_severity_map[key] = {"agent_name": "", "severity": key, "count": 0, "findings": []}
        by_severity_map[key]["findings"].append(f)
        by_severity_map[key]["count"] = len(by_severity_map[key]["findings"])

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    by_severity = sorted(by_severity_map.values(),
                         key=lambda x: severity_order.get(x["severity"], 99))

    # Triage summary
    triage_items = await crud.get_all_triage_for_scan(scan_id)
    triage_summary = {}
    for t in triage_items:
        st = t.get("status", "open")
        triage_summary[st] = triage_summary.get(st, 0) + 1

    return FindingsExplorerResponse(
        scan_id=scan_id,
        target_url=result.get("target_url", ""),
        by_agent=by_agent,
        by_severity=by_severity,
        triage_summary=triage_summary,
        total_findings=len(findings),
    )


@router.get("/scan/{scan_id}/findings/list", response_model=List[Finding])
async def get_findings_list(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Return a flat list of all findings for a scan with full detail."""
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return result.get("all_findings", result.get("findings", []))


# ── Finding Triage ─────────────────────────────────────────────────────────────

@router.post("/findings/{finding_id}/triage", response_model=TriageResponse)
async def set_finding_triage(
    finding_id: int,
    triage: TriageRequest,
    scan_id: str = None,
    current_user: dict = Depends(get_current_user),
):
    """Set triage status for a finding. Requires scan_id as query param or in body."""
    # Get scan_id from query if not provided — use most recent scan for this finding
    # For simplicity, require the finding to belong to a scan the user can see
    # We look up the finding's scan_id from the DB
    if scan_id is None:
        # Find which scan this finding belongs to
        async with crud.get_connection() as conn:
            cursor = await conn.execute(
                "SELECT scan_id FROM findings WHERE id = ?", (finding_id,)
            )
            row = await cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Finding not found")
            scan_id = row["scan_id"]

    rid = await crud.set_finding_triage(finding_id, scan_id, triage.status, triage.note)
    triage_row = await crud.get_finding_triage(finding_id, scan_id)

    return TriageResponse(
        finding_id=finding_id,
        scan_id=scan_id,
        status=triage.status,
        note=triage.note,
        created_at=triage_row.get("created_at") if triage_row else None,
        updated_at=triage_row.get("updated_at") if triage_row else None,
    )


@router.get("/scan/{scan_id}/triage")
async def get_scan_triage(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Get all triage entries for a scan."""
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")
    triage_items = await crud.get_all_triage_for_scan(scan_id)
    return {"scan_id": scan_id, "triage": triage_items}


# ── Trends ─────────────────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/trends", response_model=ScanTrendResponse)
async def get_scan_trends(scan_id: str, current_user: dict = Depends(get_current_user)):
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")

    target_url = result.get("target_url", "")
    current_score = result.get("overall_score")

    trend = await crud.get_scan_trend(target_url, scan_id)
    if trend is None:
        return ScanTrendResponse(
            target_url=target_url,
            current_scan_id=scan_id,
            current_score=current_score,
            previous_scan_id=None,
            previous_score=None,
            current_by_severity={},
            previous_by_severity=None,
            diff=None,
        )

    return ScanTrendResponse(
        target_url=target_url,
        current_scan_id=scan_id,
        current_score=current_score,
        previous_scan_id=trend["previous_scan_id"],
        previous_score=trend["previous_score"],
        current_by_severity=trend["current"],
        previous_by_severity=trend["previous"],
        diff=trend["diff"],
    )


# ── Scan History (list all scans) ──────────────────────────────────────────────

@router.get("/scans")
async def list_all_scans(current_user: dict = Depends(get_current_user)):
    """Return all historical scans from the database."""
    return await crud.get_all_scans()


# ── Dashboard Stats ─────────────────────────────────────────────────────────────

@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    stats = await crud.get_dashboard_stats()
    return DashboardStatsResponse(
        total_scans=stats["total_scans"],
        by_status=stats["by_status"],
        findings_by_severity=stats["findings_by_severity"],
        open_triage_count=stats["open_triage_count"],
        recent_scans=stats["recent_scans"],
    )


# ── Remediation Details ─────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/findings/{finding_idx}/remediation",
            response_model=RemediationDetailsResponse)
async def get_remediation_details(
    scan_id: str,
    finding_idx: int,
    current_user: dict = Depends(get_current_user),
):
    """Get structured remediation steps for a specific finding by its index in the findings list."""
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")

    findings = result.get("all_findings", [])
    if finding_idx >= len(findings):
        raise HTTPException(status_code=404, detail=f"Finding index {finding_idx} out of range (total: {len(findings)})")

    finding = findings[finding_idx]
    details = _build_remediation_details([finding])
    detail = details.get(0, {})

    return RemediationDetailsResponse(
        finding_id=finding_idx,
        scan_id=scan_id,
        agent_name=finding.get("agent_name", "Unknown"),
        severity=finding.get("severity", "LOW"),
        description=finding.get("description", ""),
        remediation=finding.get("remediation"),
        steps=detail.get("steps", []),
        references=detail.get("references", []),
    )


def _build_remediation_details(findings):
    """Build structured remediation guidance for findings (shared with master_agent)."""
    details = {}
    for idx, f in enumerate(findings):
        agent = f.get("agent_name", "Unknown")
        severity = f.get("severity", "LOW")
        desc = f.get("description", "")
        metadata = f.get("metadata", {}) or {}

        steps = []
        step_num = 1
        steps.append({
            "step": step_num,
            "title": "Understand the finding",
            "description": f"Review the finding from {agent}: {desc[:120]}{'...' if len(desc) > 120 else ''}",
        })
        step_num += 1

        file_loc = metadata.get("file", "")
        if file_loc:
            steps.append({
                "step": step_num,
                "title": "Locate the issue",
                "description": f"Open {file_loc} in your code editor.",
                "command": f"code {file_loc}",
            })
            step_num += 1

        fix_guidance = {
            "AI Security Agent": "Review LLM system prompts. Add input sanitization, output filtering, and strict delimiters.",
            "API Security Agent": "Review API endpoint. Add auth checks, rate limiting (60 req/min per IP via Redis), and input validation.",
            "Code Review Agent": "Review flagged code. Use parameterized queries, avoid eval/exec, sanitize paths, update dependencies.",
            "Infrastructure Agent": "Review exposed service/config. Close unnecessary ports, update versions, remove defaults, apply least privilege.",
            "Recon Agent": "Verify discovered service/port/endpoint is intentional. If not, close or restrict. If yes, secure it.",
        }
        guidance = fix_guidance.get(agent, "Review the finding and apply appropriate security controls.")
        steps.append({"step": step_num, "title": "Apply the fix", "description": guidance})
        step_num += 1
        steps.append({
            "step": step_num,
            "title": "Verify the fix",
            "description": "Re-run the scan and use 'mark as remediated' triage to track progress.",
        })

        refs = []
        cwe_ids = metadata.get("cwe", [])
        if isinstance(cwe_ids, list):
            for cwe in cwe_ids:
                cwe_str = str(cwe).split("-")[-1].strip()
                if cwe_str.isdigit():
                    refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_str}.html")
        agent_refs = {
            "AI Security Agent": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "API Security Agent": "https://owasp.org/www-project-api-security/",
            "Code Review Agent": "https://semgrep.dev/docs/",
            "Infrastructure Agent": "https://cisecurity.org/cis-benchmarks/",
            "Recon Agent": "https://nmap.org/book/man.html",
        }
        ref = agent_refs.get(agent)
        if ref and ref not in refs:
            refs.append(ref)

        details[idx] = {"steps": steps, "references": refs}
    return details


# ── Webhooks ───────────────────────────────────────────────────────────────────

@router.post("/webhooks", response_model=WebhookResponse)
async def create_webhook(request: WebhookRequest, current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    webhook_id = await crud.create_webhook(user_id, request.url, request.name, request.events)
    return WebhookResponse(
        id=webhook_id,
        user_id=user_id,
        url=request.url,
        name=request.name,
        events=request.events,
        created_at="",  # filled by DB, approximate
        updated_at="",
    )


@router.get("/webhooks")
async def list_webhooks(current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    webhooks = await crud.get_webhooks_for_user(user_id)
    return {"webhooks": webhooks}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: int, current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    deleted = await crud.delete_webhook(webhook_id, user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found or not owned by you")
    return {"deleted": True}


@router.post("/webhooks/test")
async def test_webhook(request: WebhookRequest, current_user: dict = Depends(get_current_user)):
    """Send a test payload to a webhook URL without saving it."""
    import aiohttp
    test_payload = {
        "event": "test",
        "message": "CyberPilot webhook test — if you receive this, your webhook is configured correctly.",
        "timestamp": str(__import__('datetime').datetime.utcnow()),
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(request.url, json=test_payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                return {
                    "tested": True,
                    "url": request.url,
                    "status_code": resp.status,
                    "response": await resp.text(),
                }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Webhook test failed: {str(e)}")


# ─── ZAP Scanner Endpoints (Phase 4) ──────────────────────────────────────

from app.services.tools.zap_scanner import ZapScanner


def _get_zap_scanner(simulate: bool = False) -> ZapScanner:
    """Factory for ZapScanner instances (allows override in tests)."""
    return ZapScanner({
        "simulated": simulate,
        "scan_mode": os.environ.get("ZAP_MODE", "passive"),
    })


@router.get("/tools/zap/status")
async def zap_status(current_user: dict = Depends(get_current_user)):
    """Get the current status of the OWASP ZAP integration.

    Returns availability, installation status, and configuration.
    """
    scanner = _get_zap_scanner()
    status = await scanner.get_status()
    return status


# ─── Tool Status ───────────────────────────────────────────────────────────────

_TOOL_MAP = {
    "Nmap": NmapScanner,
    "Semgrep": SemgrepScanner,
    "Bandit": BanditScanner,
    "Gitleaks": GitleaksScanner,
    "Trivy": TrivyScanner,
    "OWASP ZAP": ZapScanner,
    "AI Security Tester": AISecurityTester,
}

_TOOL_DESCRIPTIONS = {
    "Nmap": "Network mapper — port discovery, OS detection, service fingerprinting",
    "Semgrep": "Static analysis — finds security issues in source code",
    "Bandit": "Python static analysis — security linting for Python code",
    "Gitleaks": "Secret detection — finds exposed credentials in source code",
    "Trivy": "Vulnerability scanner — container images, filesystems, config",
    "OWASP ZAP": "Web application security scanner — XSS, SQLi, auth, API",
    "AI Security Tester": "AI/ML security testing — prompt injection, data exposure",
}


@router.get("/tools/status", response_model=ToolStatusResponse)
async def get_tools_status(current_user: dict = Depends(get_current_user)):
    """Return the installation/availability status of all security tools."""
    import asyncio as _asyncio

    results = []
    for name, cls in _TOOL_MAP.items():
        scanner = cls({})
        installed = await scanner.check_installed()
        enabled = scanner.config.get("enabled", True) if hasattr(scanner, "config") else True
        if installed:
            status = "ready"
            available = True
        else:
            status = "not_installed"
            available = False

        # Try to get version
        version = None
        if installed:
            try:
                import asyncio as _asyncio
                proc = await _asyncio.create_subprocess_exec(
                    scanner.command_name, "--version",
                    stdout=_asyncio.subprocess.PIPE,
                    stderr=_asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                output = (stdout.decode('utf-8', errors='replace') + stderr.decode('utf-8', errors='replace')).strip()
                version = output.split('\n')[0][:120] if output else None
            except Exception:
                version = None

        results.append(ToolStatus(
            name=name,
            tool_name=scanner.tool_name,
            installed=installed,
            available=available,
            status=status,
            version=version,
            enabled=enabled,
            description=_TOOL_DESCRIPTIONS.get(name, ""),
        ))

    # Add AI engine status
    ai_available = False
    try:
        engine = AIEngine()
        status = await engine.get_status()
        ai_available = status.get("ai_ready", False)
    except Exception:
        ai_available = False
    results.append(ToolStatus(
        name="AI Engine (Ollama)",
        tool_name="ollama",
        installed=True,
        available=ai_available,
        status="ready" if ai_available else "unavailable",
        enabled=True,
        description="Large language model backend for AI security analysis",
    ))

    return ToolStatusResponse(tools=results)


@router.post("/scans/{scan_id}/zap")
async def scan_with_zap(
    scan_id: str,
    request: Optional[dict] = None,
    current_user: dict = Depends(get_current_user),
):
    """Run a ZAP scan against a scan target.

    Request body (optional JSON):
        scan_mode: "passive" | "baseline" | "active" (default: env ZAP_MODE)
        allow_internal: bool (default: false)
        target: override target URL (defaults to scan's target_url)

    Returns scan result with findings and status.
    """
    # Verify the scan exists
    scan = await crud.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    request = request or {}
    scan_mode = request.get("scan_mode", os.environ.get("ZAP_MODE", "passive"))
    allow_internal = request.get("allow_internal", False)

    # Use the scan's target URL, or override from request
    target = request.get("target") or scan.get("target_url", "")
    if not target:
        raise HTTPException(
            status_code=400,
            detail="No target URL available for this scan",
        )

    scanner = _get_zap_scanner(simulate=bool(request.get("simulate")))

    result = await scanner.scan(
        target,
        scan_type=scan_mode,
        allow_internal=allow_internal,
        timeout=request.get("timeout", scanner.scan_timeout),
        spider=request.get("spider", scan_mode != "passive"),
    )

    # Emit event
    await crud.add_scan_event(scan_id, "zap_scan_completed", {
        "tool": "zap",
        "status": result.status.value,
        "findings_count": len(result.findings),
        "duration": result.duration_seconds,
        "error": result.error,
        "scan_mode": scan_mode,
    })

    return {
        "scan_id": scan_id,
        "tool": "ZAP",
        "status": result.status.value,
        "findings_count": len(result.findings),
        "findings": result.findings,
        "duration_seconds": result.duration_seconds,
        "error": result.error,
    }


@router.get("/scans/{scan_id}/zap/status")
async def zap_scan_status(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Check ZAP tool status (not running scan status — ZAP scans are synchronous)."""
    scanner = _get_zap_scanner()
    status = await scanner.get_status()
    return {"scan_id": scan_id, "tool": "ZAP", **status}


# ─── AI Engine Endpoints (Phase 3) ─────────────────────────────────────────────

def _get_ai_engine(simulate: bool = False) -> AIEngine:
    """Create an AI engine instance, optionally forcing the mock provider."""
    if simulate:
        from app.services.ai_engine import MockAIProvider
        return AIEngine(provider=MockAIProvider(model="mock"))
    return AIEngine()


@router.get("/ai/status", response_model=AIStatusResponse)
async def get_ai_status(current_user: dict = Depends(get_current_user)):
    """Check whether the AI engine (Ollama) is available and ready."""
    engine = _get_ai_engine()
    status = await engine.get_status()
    return AIStatusResponse(**status)


@router.post("/findings/{finding_id}/analyze", response_model=AIAnalysisSchema)
async def analyze_finding(
    finding_id: int,
    request: Optional[AIBatchRequest] = None,
    current_user: dict = Depends(get_current_user),
):
    """Analyze a single finding via the AI engine.

    Loads the finding from the DB, redacts any remaining secrets, sends the
    safe finding to the AI engine, validates the response, and persists the
    analysis.  The original finding is never modified.
    """
    # 1. Load the finding
    async with crud.get_connection() as conn:
        cursor = await conn.execute(
            """SELECT f.id, f.agent_name, f.severity, f.description, f.remediation,
                      f.metadata, f.created_at,
                      s.scan_id, s.target_url, s.data_source
               FROM findings f
               JOIN scans s ON f.scan_id = s.scan_id
               WHERE f.id = ?""",
            (finding_id,),
        )
        row = await cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    finding = dict(row)
    if finding.get("metadata"):
        try:
            finding["metadata"] = json.loads(finding["metadata"])
        except (json.JSONDecodeError, TypeError):
            finding["metadata"] = {}

    # Apply canonical field mapping (same as get_findings_by_scan / get_scan)
    meta = finding.get("metadata", {})
    agent_name = finding.get("agent_name", "unknown")
    finding["scanner"] = meta.get("tool") or agent_name
    finding["agent"] = agent_name
    finding["location"] = {
        "file": meta.get("file", ""),
        "line": meta.get("line", 0),
        "path": meta.get("file", ""),
        "line_number": meta.get("line", 0),
    }
    finding["file"] = meta.get("file", "")
    finding["line"] = meta.get("line", 0)
    finding["title"] = meta.get("title", finding.get("description", "")[:80])
    finding["evidence"] = meta.get("evidence")
    finding["cwe"] = meta.get("cwe")
    finding["cve"] = meta.get("cve")
    finding["references"] = meta.get("references", [])
    finding["target"] = meta.get("target", "")
    finding["confidence"] = meta.get("confidence")
    finding["data_source"] = meta.get("data_source") or finding.get("data_source") or "real_tools"
    finding["scan_id"] = finding.get("scan_id") or ""

    # 2. Analyze via AI engine
    simulate = bool(request and request.simulate)
    engine = _get_ai_engine(simulate=simulate)

    try:
        analysis = await engine.analyze_finding(finding)
    except AIUnavailableError as e:
        raise HTTPException(status_code=503, detail=f"AI engine unavailable: {e}")
    except AIValidationError as e:
        raise HTTPException(status_code=502, detail=f"AI response validation failed: {e}")

    # 3. Persist the analysis
    try:
        analysis_dict = analysis.model_dump()
        analysis_id = await crud.create_ai_analysis(
            finding_id=finding["id"],
            scan_id=finding["scan_id"],
            model=analysis.model,
            analysis=analysis_dict,
            ai_confidence=analysis.confidence,
            status=analysis.status,
            prompt_version=analysis.prompt_version,
            error=analysis.error,
        )
    except Exception as e:
        logger.warning("Failed to persist AI analysis for finding %d: %s", finding_id, e)
        # Still return the analysis even if DB persistence fails

    # 4. Build response with scanner confidence/severity preserved separately
    return AIAnalysisSchema(
        finding_id=analysis.finding_id,
        scan_id=analysis.scan_id,
        summary=analysis.summary,
        risk_explanation=analysis.risk_explanation,
        exploitability=analysis.exploitability,
        impact=analysis.impact,
        false_positive_assessment=analysis.false_positive_assessment,
        confidence=analysis.confidence,
        root_cause=analysis.root_cause,
        remediation=analysis.remediation,
        references=analysis.references,
        priority=analysis.priority,
        model=analysis.model,
        created_at=analysis.created_at,
        status=analysis.status,
        error=analysis.error,
        scanner_confidence=finding.get("confidence"),
        scanner_severity=finding.get("severity"),
    )


@router.get("/findings/{finding_id}/analysis", response_model=AIAnalysisSchema)
async def get_finding_analysis(
    finding_id: int,
    current_user: dict = Depends(get_current_user),
):
    """Retrieve the most recent AI analysis for a finding."""
    result = await crud.get_ai_analysis_by_finding(finding_id)
    if result is None:
        raise HTTPException(status_code=404, detail="No AI analysis found for this finding")

    analysis = result.get("analysis", {})

    # Look up the original finding for scanner confidence/severity
    scanner_confidence = None
    scanner_severity = None
    async with crud.get_connection() as conn:
        cursor = await conn.execute(
            """SELECT f.severity, f.metadata
               FROM findings f WHERE f.id = ?""",
            (finding_id,),
        )
        row = await cursor.fetchone()
        if row:
            scanner_severity = row["severity"]
            meta = {}
            if row["metadata"]:
                try:
                    meta = json.loads(row["metadata"])
                except (json.JSONDecodeError, TypeError):
                    meta = {}
            scanner_confidence = meta.get("confidence")

    return AIAnalysisSchema(
        finding_id=result.get("finding_id"),
        scan_id=result.get("scan_id"),
        summary=analysis.get("summary", ""),
        risk_explanation=analysis.get("risk_explanation", ""),
        exploitability=analysis.get("exploitability", "uncertain"),
        impact=analysis.get("impact", ""),
        false_positive_assessment=analysis.get("false_positive_assessment", "uncertain"),
        confidence=analysis.get("confidence", 0.0),
        root_cause=analysis.get("root_cause"),
        remediation=analysis.get("remediation", ""),
        references=analysis.get("references", []),
        priority=analysis.get("priority"),
        model=result.get("model", "unknown"),
        prompt_version=result.get("prompt_version", "v1.0"),
        created_at=result.get("created_at"),
        status=result.get("status", "completed"),
        error=result.get("error"),
        scanner_confidence=scanner_confidence,
        scanner_severity=scanner_severity,
    )


@router.post("/scans/{scan_id}/analyze")
async def analyze_scan_findings(
    scan_id: str,
    request: Optional[AIBatchRequest] = None,
    current_user: dict = Depends(get_current_user),
):
    """Analyze all findings in a scan via the AI engine.

    Retrieves findings, optionally prioritizes critical/high findings first,
    analyzes them through the AI engine with controlled concurrency, and
    handles individual AI failures without failing the entire batch.
    """
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = result.get("all_findings", [])
    if not findings:
        # Try loading from DB
        db_scan = await crud.get_scan(scan_id)
        if db_scan:
            findings = db_scan.get("findings", [])

    if not findings:
        return {"scan_id": scan_id, "analyzed": 0, "results": []}

    # Prioritize: critical/high findings first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings_sorted = sorted(
        findings,
        key=lambda f: severity_order.get(
            (f.get("severity") or "low").upper(), 5
        ),
    )

    simulate = bool(request and request.simulate)
    max_concurrency = request.max_concurrency if request else 1
    engine = _get_ai_engine(simulate=simulate)

    # Analyze sequentially (controlled concurrency; default max_concurrency=1)
    analyses: List[Dict[str, Any]] = []
    failed = 0
    succeeded = 0

    for finding in findings_sorted:
        try:
            analysis = await engine.analyze_finding(finding)
            # Persist
            try:
                analysis_dict = analysis.model_dump()
                analysis_id = await crud.create_ai_analysis(
                    finding_id=finding.get("id"),
                    scan_id=scan_id,
                    model=analysis.model,
                    analysis=analysis_dict,
                    ai_confidence=analysis.confidence,
                    status=analysis.status,
                    prompt_version=analysis.prompt_version,
                    error=analysis.error,
                )
            except Exception as e:
                logger.warning("Failed to persist AI analysis: %s", e)

            analyses.append({
                "finding_id": finding.get("id"),
                "severity": finding.get("severity"),
                "scanner": finding.get("scanner", "unknown"),
                "analysis": analysis.model_dump(),
            })
            succeeded += 1

        except AIError as e:
            logger.warning("AI analysis failed for finding %s: %s", finding.get("id"), e)
            failed += 1
            # Record failure but continue
            await crud.create_ai_analysis(
                finding_id=finding.get("id") or 0,
                scan_id=scan_id,
                model=engine.provider.get_model_name(),
                analysis={},
                ai_confidence=0.0,
                status="failed",
                error=str(e),
            )
            analyses.append({
                "finding_id": finding.get("id"),
                "severity": finding.get("severity"),
                "error": str(e),
            })

    return {
        "scan_id": scan_id,
        "total_findings": len(findings_sorted),
        "analyzed": succeeded,
        "failed": failed,
        "results": analyses,
    }


@router.post("/findings/{finding_id}/analysis/retry", response_model=AIAnalysisSchema)
async def retry_finding_analysis(
    finding_id: int,
    request: Optional[AIBatchRequest] = None,
    current_user: dict = Depends(get_current_user),
):
    """Retry AI analysis for a finding that previously failed."""
    simulate = bool(request and request.simulate)
    engine = _get_ai_engine(simulate=simulate)

    # Load the finding (same as analyze_finding)
    async with crud.get_connection() as conn:
        cursor = await conn.execute(
            """SELECT f.id, f.agent_name, f.severity, f.description, f.remediation,
                      f.metadata, f.created_at,
                      s.scan_id, s.target_url, s.data_source
               FROM findings f
               JOIN scans s ON f.scan_id = s.scan_id
               WHERE f.id = ?""",
            (finding_id,),
        )
        row = await cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    finding = dict(row)
    if finding.get("metadata"):
        try:
            finding["metadata"] = json.loads(finding["metadata"])
        except (json.JSONDecodeError, TypeError):
            finding["metadata"] = {}

    meta = finding.get("metadata", {})
    agent_name = finding.get("agent_name", "unknown")
    finding["scanner"] = meta.get("tool") or agent_name
    finding["agent"] = agent_name
    finding["file"] = meta.get("file", "")
    finding["line"] = meta.get("line", 0)
    finding["title"] = meta.get("title", finding.get("description", "")[:80])
    finding["evidence"] = meta.get("evidence")
    finding["cwe"] = meta.get("cwe")
    finding["cve"] = meta.get("cve")
    finding["references"] = meta.get("references", [])
    finding["target"] = meta.get("target", "")
    finding["confidence"] = meta.get("confidence")
    finding["data_source"] = meta.get("data_source") or finding.get("data_source") or "real_tools"

    try:
        analysis = await engine.analyze_finding(finding)
    except AIUnavailableError as e:
        raise HTTPException(status_code=503, detail=f"AI engine unavailable: {e}")
    except AIValidationError as e:
        raise HTTPException(status_code=502, detail=f"AI response validation failed: {e}")

    # Update the failed analysis record or create a new one
    old_analysis = await crud.get_ai_analysis_by_finding(finding_id)
    if old_analysis:
        await crud.update_ai_analysis_status(
            old_analysis["id"], "completed", error=None
        )

    try:
        analysis_dict = analysis.model_dump()
        await crud.create_ai_analysis(
            finding_id=finding["id"],
            scan_id=finding["scan_id"],
            model=analysis.model,
            analysis=analysis_dict,
            ai_confidence=analysis.confidence,
            status=analysis.status,
        )
    except Exception as e:
        logger.warning("Failed to persist retried AI analysis: %s", e)

    return AIAnalysisSchema(
        finding_id=analysis.finding_id,
        scan_id=analysis.scan_id,
        summary=analysis.summary,
        risk_explanation=analysis.risk_explanation,
        exploitability=analysis.exploitability,
        impact=analysis.impact,
        false_positive_assessment=analysis.false_positive_assessment,
        confidence=analysis.confidence,
        root_cause=analysis.root_cause,
        remediation=analysis.remediation,
        references=analysis.references,
        priority=analysis.priority,
        model=analysis.model,
        created_at=analysis.created_at,
        status=analysis.status,
        error=analysis.error,
        scanner_confidence=finding.get("confidence"),
        scanner_severity=finding.get("severity"),
    )


# ─── Phase 5: Orchestration Endpoints ────────────────────────────────────────────

@router.get("/scans/{scan_id}/plan")
async def get_assessment_plan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get the assessment plan for a scan (Phase 5)."""
    try:
        from app.db.database import get_connection
        async with get_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM assessment_plans WHERE scan_id = ?",
                (scan_id,),
            )
            row = await cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=404, detail=f"No assessment plan found for scan {scan_id}"
            )
        plan = dict(row)
        if plan.get("plan_json"):
            try:
                plan["plan"] = json.loads(plan["plan_json"])
            except (json.JSONDecodeError, TypeError):
                plan["plan"] = {}
        return plan
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve plan: {e}"
        )


@router.get("/scans/{scan_id}/tasks")
async def get_scan_tasks(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get all assessment tasks for a scan (Phase 5)."""
    try:
        tasks = await crud.get_tasks_by_scan(scan_id)
        return {"scan_id": scan_id, "tasks": tasks, "count": len(tasks)}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve tasks: {e}"
        )


@router.get("/scans/{scan_id}/decisions")
async def get_scan_decisions(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get the audit trail of Master Agent decisions (Phase 5)."""
    try:
        decisions = await crud.get_decisions_by_scan(scan_id)
        return {
            "scan_id": scan_id,
            "decisions": decisions,
            "count": len(decisions),
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve decisions: {e}"
        )


@router.get("/scans/{scan_id}/agent-results")
async def get_agent_results(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get agent execution results for a scan (Phase 5)."""
    try:
        scan = await crud.get_scan(scan_id)
        if not scan:
            raise HTTPException(
                status_code=404, detail=f"Scan {scan_id} not found"
            )
        tasks = await crud.get_tasks_by_scan(scan_id)
        agent_results = [
            {
                "task_id": t.get("task_id"),
                "agent": t.get("agent"),
                "tool": t.get("tool"),
                "objective": t.get("objective"),
                "status": t.get("status"),
                "priority": t.get("priority"),
                "scan_mode": t.get("scan_mode"),
                "created_at": t.get("created_at"),
                "started_at": t.get("started_at"),
                "completed_at": t.get("completed_at"),
                "agent_result": t.get("agent_result_json") or {},
            }
            for t in tasks
        ]
        return {
            "scan_id": scan_id,
            "agent_results": agent_results,
            "count": len(agent_results),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve agent results: {e}"
        )
