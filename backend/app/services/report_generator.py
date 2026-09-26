"""
CyberPilot Report Generator — WeasyPrint + Jinja2 pipeline.

Renders the existing HTML templates to PDF via WeasyPrint. This replaces
the previous 565-line ReportLab generator with a clean HTML/CSS-driven
pipeline that uses the hand-designed templates in templates/reports/.
"""
import os
import json
from datetime import datetime
from typing import Dict, Any, List
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(HERE, "templates", "reports")
OUTPUT_DIR = os.path.join(os.path.dirname(HERE), "..", "..", "output", "reports")
os.makedirs(TEMPLATE_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


def _build_executive_context(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Build Jinja context for the executive summary template."""
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
    """Build Jinja context for the technical report template."""
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
        if agent not in findings_by_agent:
            findings_by_agent[agent] = []
        findings_by_agent[agent].append(f)

    compliance_by_agent: Dict[str, List[Dict]] = {}
    for c in compliance:
        agent = c.get("agent_name", "Unknown")
        if agent not in compliance_by_agent:
            compliance_by_agent[agent] = []
        compliance_by_agent[agent].append(c)

    for agent, items in compliance_by_agent.items():
        for item in items:
            if isinstance(item.get("owasp_llm"), str):
                try:
                    item["owasp_llm"] = json.loads(item["owasp_llm"])
                except (json.JSONDecodeError, TypeError):
                    item["owasp_llm"] = []
            if isinstance(item.get("nist_csf"), str):
                try:
                    item["nist_csf"] = json.loads(item["nist_csf"])
                except (json.JSONDecodeError, TypeError):
                    item["nist_csf"] = []

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


def _render_pdf(html_content: str, output_path: str) -> str:
    """Render HTML to PDF via WeasyPrint."""
    HTML(string=html_content, base_url=HERE).write_pdf(output_path)
    return output_path


def generate_executive_summary_pdf(scan_data: Dict[str, Any], output_path: str) -> str:
    """Generate executive summary PDF from Jinja2 template."""
    template = jinja_env.get_template("executive_summary.html")
    context = _build_executive_context(scan_data)
    html = template.render(**context)
    return _render_pdf(html, output_path)


def generate_technical_report_pdf(scan_data: Dict[str, Any], output_path: str) -> str:
    """Generate technical report PDF from Jinja2 template."""
    template = jinja_env.get_template("technical_report.html")
    context = _build_technical_context(scan_data)
    html = template.render(**context)
    return _render_pdf(html, output_path)


def generate_both_reports(scan_data: Dict[str, Any], output_dir: str = None) -> Dict[str, str]:
    """Generate both executive summary and technical report PDFs."""
    if output_dir is None:
        output_dir = OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    scan_id = scan_data.get("scan_id", "unknown")
    exec_path = os.path.join(output_dir, f"{scan_id}_executive_summary.pdf")
    tech_path = os.path.join(output_dir, f"{scan_id}_technical_report.pdf")

    generate_executive_summary_pdf(scan_data, exec_path)
    generate_technical_report_pdf(scan_data, tech_path)

    return {
        "executive_summary": os.path.abspath(exec_path),
        "technical_report": os.path.abspath(tech_path),
    }
