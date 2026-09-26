from fastapi import APIRouter, HTTPException, Depends
from typing import List
from app.models.schemas import ScanRequest, ScanResponse, ReportSummary, ComplianceFinding
from app.services import master_agent
from app.db import crud
from fastapi.responses import FileResponse
from app.api.auth import validate_api_key, optional_api_key
import os

router = APIRouter()

# Public endpoint - no auth required for health check
@router.get("/health")
async def health_check():
    return {"status": "ok"}

# All other endpoints require authentication
async def get_current_user(key_data: dict = Depends(validate_api_key)):
    """Dependency that returns the authenticated user/key data."""
    return key_data


@router.post("/scan/start", response_model=ScanResponse)
async def start_scan(request: ScanRequest, current_user: dict = Depends(get_current_user)):
    data_source = "simulation" if request.simulate else "real_tools"
    try:
        scan_id = await master_agent.start_scan_workflow(
            request.target_url,
            data_source=data_source,
            authorize=request.authorize,
            scan_timeout_seconds=request.scan_timeout_seconds,
        )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))
    return ScanResponse(
        scan_id=scan_id,
        status="ACCEPTED",
        message=f"Scan initiated for {request.target_url}" + (" (simulation mode)" if request.simulate else ""),
        data_source=data_source
    )


@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str, current_user: dict = Depends(get_current_user)):
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")

    if result["status"] == "COMPLETED":
        compliance_data = result.get("compliance", [])
        compliance_findings = [
            ComplianceFinding(
                agent_name=c["agent_name"],
                severity=c["severity"],
                owasp_llm=c["owasp_llm"],
                nist_csf=c["nist_csf"]
            )
            for c in compliance_data
        ]
        final_report = result.get("final_report", {})
        return ReportSummary(
            scan_id=scan_id,
            target_url=result["target_url"],
            overall_score=result["overall_score"],
            findings=result.get("findings", []),
            compliance=compliance_findings,
            executive_summary_pdf=final_report.get("executive_summary_pdf"),
            technical_report_pdf=final_report.get("technical_report_pdf"),
            data_source=result.get("data_source", "real_tools"),
            errors=result.get("security_analysis_errors", []),
        )
    return {"scan_id": scan_id, "status": result["status"]}


@router.get("/scan/{scan_id}/report/executive-summary")
async def download_executive_summary(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Download executive summary PDF report."""
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")

    if result["status"] != "COMPLETED":
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    final_report = result.get("final_report", {})
    pdf_path = final_report.get("executive_summary_pdf")

    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="Executive summary PDF not found")

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"{scan_id}_executive_summary.pdf"
    )


@router.get("/scan/{scan_id}/report/technical")
async def download_technical_report(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Download technical report PDF."""
    result = await master_agent.get_scan_result(scan_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan ID not found")

    if result["status"] != "COMPLETED":
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    final_report = result.get("final_report", {})
    pdf_path = final_report.get("technical_report_pdf")

    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="Technical report PDF not found")

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"{scan_id}_technical_report.pdf"
    )


@router.get("/scans")
async def list_all_scans(current_user: dict = Depends(get_current_user)):
    """Return all historical scans from the database."""
    return await crud.get_all_scans()
