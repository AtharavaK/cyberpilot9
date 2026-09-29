"""
CyberPilot Report Generator — WeasyPrint + Jinja2 pipeline (with ReportLab fallback).

Renders the existing HTML templates to PDF via WeasyPrint when GTK3 is available.
Falls back to ReportLab for PDF generation when WeasyPrint is unavailable (e.g. no GTK3 on Windows).
"""
import os
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

# --- WeasyPrint (requires GTK3 on Windows) ---
try:
    from weasyprint import HTML
    HAS_WEASYPRINT = True
except (ImportError, OSError):
    HAS_WEASYPRINT = False

# --- ReportLab fallback ---
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(HERE, "templates", "reports")
OUTPUT_DIR = os.path.join(os.path.dirname(HERE), "..", "..", "output", "reports")
os.makedirs(TEMPLATE_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)

# ---------------------------------------------------------------------------
# Context builders (used by both WeasyPrint and ReportLab paths)
# ---------------------------------------------------------------------------

def _build_executive_context(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    findings = scan_data.get("findings", [])
    compliance = scan_data.get("compliance", [])
    overall_score = scan_data.get("overall_score", 0)
    scan_id = scan_data.get("scan_id", "unknown")
    target_url = str(scan_data.get("target_url", ""))
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")

    if overall_score >= 80:
        risk_color = "#10b981"
        risk_level = "LOW"
    elif overall_score >= 60:
        risk_color = "#f59e0b"
        risk_level = "MEDIUM"
    else:
        risk_color = "#ef4444"
        risk_level = "HIGH"

    scan_date = scan_data.get("scan_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    top_risks = []
    for f in findings[:3]:
        top_risks.append({
            "description": f.get("description", ""),
            "severity": f.get("severity", "LOW"),
            "agent_name": f.get("agent_name", ""),
            "remediation": f.get("remediation") or "No specific remediation provided.",
        })

    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "scan_date": scan_date,
        "overall_score": overall_score,
        "risk_color": risk_color,
        "risk_level": risk_level,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "total_findings": len(findings),
        "top_risks": top_risks,
        "compliance_count": len(compliance),
        "owasp_mapped": "LLM01 (Prompt Injection), LLM04 (Model DoS), LLM05 (Supply Chain), LLM09 (Overreliance), LLM10 (Model Theft)",
        "nist_mapped": "Identify (ID.RA-1), Protect (PR.AC-7, PR.DS-1, PR.DS-6, PR.IP-1), Detect (DE.AE-1, DE.CM-1)",
    }


def _build_technical_context(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    findings = scan_data.get("findings", [])
    compliance = scan_data.get("compliance", [])
    overall_score = scan_data.get("overall_score", 0)
    scan_id = scan_data.get("scan_id", "unknown")
    target_url = str(scan_data.get("target_url", ""))
    scan_date = scan_data.get("scan_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    recon_data = scan_data.get("recon_data", {})

    if overall_score >= 80:
        risk_color = "#10b981"
        risk_level = "LOW"
    elif overall_score >= 60:
        risk_color = "#f59e0b"
        risk_level = "MEDIUM"
    else:
        risk_color = "#ef4444"
        risk_level = "HIGH"

    findings_by_agent: Dict[str, List[Dict]] = {}
    for f in findings:
        agent = f.get("agent_name", "Unknown")
        findings_by_agent.setdefault(agent, []).append(f)

    compliance_by_agent: Dict[str, List[Dict]] = {}
    for c in compliance:
        agent = c.get("agent_name", "Unknown")
        compliance_by_agent.setdefault(agent, []).append(c)

    for agent, items in compliance_by_agent.items():
        for item in items:
            for key in ("owasp_llm", "nist_csf"):
                val = item.get(key)
                if isinstance(val, str):
                    try:
                        item[key] = json.loads(val)
                    except (json.JSONDecodeError, TypeError):
                        item[key] = []

    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "scan_date": scan_date,
        "overall_score": overall_score,
        "risk_color": risk_color,
        "risk_level": risk_level,
        "recon_data": recon_data,
        "findings_by_agent": findings_by_agent,
        "compliance_by_agent": compliance_by_agent,
    }


# ---------------------------------------------------------------------------
# WeasyPrint PDF path
# ---------------------------------------------------------------------------

def _render_pdf_weasyprint(html_content: str, output_path: str) -> str:
    HTML(string=html_content, base_url=HERE).write_pdf(output_path)
    return output_path


def generate_executive_summary_pdf(scan_data: Dict[str, Any], output_path: str) -> str:
    template = jinja_env.get_template("executive_summary.html")
    context = _build_executive_context(scan_data)
    html = template.render(**context)
    return _render_pdf_weasyprint(html, output_path)


def generate_technical_report_pdf(scan_data: Dict[str, Any], output_path: str) -> str:
    template = jinja_env.get_template("technical_report.html")
    context = _build_technical_context(scan_data)
    html = template.render(**context)
    return _render_pdf_weasyprint(html, output_path)


# ---------------------------------------------------------------------------
# ReportLab PDF path (fallback when WeasyPrint is unavailable)
# ---------------------------------------------------------------------------

def _render_pdf_reportlab(html_content: str, output_path: str) -> str:
    """Render a simplified PDF using ReportLab from HTML content."""
    if not HAS_REPORTLAB:
        return output_path
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    title_style = ParagraphStyle("ReportTitle", parent=styles["Heading1"],
                                  fontSize=18, spaceAfter=12, textColor=colors.HexColor("#1e293b"))
    story.append(Paragraph("CyberPilot Security Assessment Report", title_style))
    story.append(Spacer(1, 0.15 * inch))
    text_content = re.sub(r"<[^>]+>", "\n", html_content)
    text_content = re.sub(r"\n\s*\n", "\n", text_content)
    text_content = text_content.strip()
    body_style = ParagraphStyle("ReportBody", parent=styles["Normal"],
                                fontSize=10, leading=14, spaceAfter=6)
    for line in text_content.split("\n"):
        line = line.strip()
        if line:
            story.append(Paragraph(line, body_style))
            story.append(Spacer(1, 0.05 * inch))
    doc.build(story)
    return output_path


def generate_executive_summary_pdf_fallback(scan_data: Dict[str, Any], output_path: str) -> str:
    """Generate executive summary using ReportLab fallback."""
    context = _build_executive_context(scan_data)
    # Render to HTML first using Jinja, then convert to simple PDF
    template = jinja_env.get_template("executive_summary.html")
    html = template.render(**context)
    return _render_pdf_reportlab(html, output_path)


def generate_technical_report_pdf_fallback(scan_data: Dict[str, Any], output_path: str) -> str:
    """Generate technical report using ReportLab fallback."""
    context = _build_technical_context(scan_data)
    template = jinja_env.get_template("technical_report.html")
    html = template.render(**context)
    return _render_pdf_reportlab(html, output_path)


# ---------------------------------------------------------------------------
# Public API — dispatches to WeasyPrint or ReportLab
# ---------------------------------------------------------------------------

def generate_both_reports(scan_data: Dict[str, Any], output_dir: str = None) -> Dict[str, str]:
    """Generate both executive summary and technical report PDFs.

    Uses WeasyPrint when available (GTK3 installed), falls back to ReportLab.
    """
    if output_dir is None:
        output_dir = OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    scan_id = scan_data.get("scan_id", "unknown")
    exec_path = os.path.join(output_dir, f"{scan_id}_executive_summary.pdf")
    tech_path = os.path.join(output_dir, f"{scan_id}_technical_report.pdf")

    if HAS_WEASYPRINT:
        generate_executive_summary_pdf(scan_data, exec_path)
        generate_technical_report_pdf(scan_data, tech_path)
    elif HAS_REPORTLAB:
        generate_executive_summary_pdf_fallback(scan_data, exec_path)
        generate_technical_report_pdf_fallback(scan_data, tech_path)
    else:
        raise RuntimeError(
            "Both WeasyPrint and ReportLab are unavailable. Cannot generate PDF reports."
        )

    return {
        "executive_summary": os.path.abspath(exec_path),
        "technical_report": os.path.abspath(tech_path),
    }
