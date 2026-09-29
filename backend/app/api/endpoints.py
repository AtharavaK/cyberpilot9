from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from app.models.schemas import (
    ScanRequest, ScanResponse, ReportSummary, ComplianceFinding, Finding,
    ScanStatusResponse, ScanEvent, ScanEventsResponse,
    FindingsGroup, FindingsExplorerResponse,
    TriageRequest, TriageResponse,
    ScanTrendResponse,
    DashboardStatsResponse,
    WebhookRequest, WebhookResponse,
    RemediationDetailsResponse, RemediationStep,
)
from app.services import master_agent
from app.db import crud
from app.api.auth import validate_api_key
import os
import sys
import json


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

    final_report = result.get("final_report", {})
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

    final_report = result.get("final_report", {})
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

    # Convert to Finding objects
    findings = []
    for f in findings_raw:
        finding = Finding(
            agent_name=f.get("agent_name", "Unknown"),
            severity=f.get("severity", "LOW"),
            description=f.get("description", ""),
            remediation=f.get("remediation"),
            metadata=f.get("metadata"),
        )
        findings.append(finding)

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

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
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
