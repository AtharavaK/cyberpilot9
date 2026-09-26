import uuid
import asyncio
import json
import os
from datetime import datetime
from typing import Dict, Any, List
from langgraph.graph import StateGraph, END
from app.services.graph_state import CyberPilotState, Finding, ComplianceFinding
from app.db import crud
from app.services import report_generator
from app.services.tool_manager import ToolManager, run_recon, run_ai_security, run_api_security, run_code_review, run_infrastructure
from urllib.parse import urlparse
import aiohttp


def calculate_risk_score(findings: List[Dict[str, Any]]) -> int:
    """Calculate overall risk score based on findings severity."""
    if not findings:
        return 100
    
    severity_weights = {"HIGH": 25, "MEDIUM": 10, "LOW": 3}
    total_penalty = sum(severity_weights.get(f.get("severity", "LOW"), 3) for f in findings)
    score = max(0, 100 - total_penalty)
    return score

# ---------------------------------------------------------
# Node Functions (Real Tool Execution) — writing to SQLite
# ---------------------------------------------------------

async def _http_recon(target_url: str) -> Dict[str, Any]:
    """Probe a URL target for API endpoints, headers, tech stack, and auth hints."""
    result = {
        "endpoints_found": 0,
        "endpoints": [],
        "auth_type": "Unknown",
        "headers": {},
        "tech_stack": [],
        "errors": [],
    }
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    probed_paths = [
        "/", "/api", "/api/v1", "/api/v1/chat", "/health", "/status",
        "/docs", "/swagger", "/openapi.json", "/redoc", "/graphql",
        "/chat", "/generate", "/completions", "/query", "/v1/completions",
    ]
    headers_to_check = [
        "Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
        "X-Django-Version", "X-Powered-CMS", "X-Storage-Policy",
        "WWW-Authenticate", "Authorization", "Content-Type",
    ]
    async with aiohttp.ClientSession() as session:
        for path in probed_paths:
            url = base + path if path.startswith("/") else f"{base}/{path}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
                    if resp.status == 200 or resp.status == 401 or resp.status == 403:
                        result["endpoints_found"] += 1
                        result["endpoints"].append({
                            "path": path,
                            "status": resp.status,
                            "content_type": resp.content_type,
                        })
                        if resp.status == 401:
                            auth_header = resp.headers.get("WWW-Authenticate", "")
                            if "Bearer" in auth_header:
                                result["auth_type"] = "Bearer Token (OAuth 2.0 / JWT)"
                            elif "Basic" in auth_header:
                                result["auth_type"] = "HTTP Basic Auth"
                            else:
                                result["auth_type"] = "Token/Auth Required (unspecified)"
                    # Collect headers from the root response
                    if path == "/":
                        for h in headers_to_check:
                            val = resp.headers.get(h)
                            if val:
                                result["headers"][h] = val
                                # Tech detection from headers
                                lower = val.lower()
                                if "nginx" in lower: result["tech_stack"].append("Nginx")
                                elif "apache" in lower: result["tech_stack"].append("Apache")
                                elif "cloudflare" in lower: result["tech_stack"].append("Cloudflare")
                                elif "express" in lower: result["tech_stack"].append("Express.js")
                                elif "django" in lower: result["tech_stack"].append("Django")
                                elif "aspnet" in lower or "microsoft" in lower: result["tech_stack"].append("ASP.NET")
                                elif "php" in lower: result["tech_stack"].append("PHP")
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                result["errors"].append(f"Error probing {path}: {str(e)}")
    return result


async def recon_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Recon Agent...")
    state["status"] = "RECONNAISSANCE"
    await crud.update_scan_status(state["scan_id"], state["status"])

    parsed = urlparse(state["target_url"])
    is_ip_target = not parsed.scheme or not parsed.netloc

    # 1. HTTP probing (primary for URL targets)
    http_result = {}
    if not is_ip_target:
        try:
            http_result = await _http_recon(state["target_url"])
        except Exception as e:
            http_result = {"errors": [str(e)]}
            print(f"[{state['scan_id']}] HTTP recon failed: {e}")

    # 2. Nmap port scan (supplementary, for network-level recon)
    nmap_endpoints = []
    nmap_errors = []
    try:
        tool_manager = ToolManager()
        nmap_result = await tool_manager.run_agent_tools("Recon Agent", state["target_url"])
        nmap_findings = [f for f in nmap_result.get("findings", []) if f.get("metadata", {}).get("tool") == "nmap"]
        for f in nmap_findings:
            meta = f.get("metadata", {})
            if meta.get("raw_type") == "open_port":
                nmap_endpoints.append({
                    "type": "network_port",
                    "port": meta.get("line"),
                    "protocol": meta.get("raw_type", "").replace("open_", ""),
                    "service": meta.get("metadata", {}).get("service", {}),
                })
        nmap_errors = nmap_result.get("errors", [])
    except Exception as e:
        nmap_errors.append(str(e))

    # Build recon data
    endpoints = http_result.get("endpoints", [])
    # Add network port findings as supplementary info (not as API endpoints)
    for pe in nmap_endpoints:
        endpoints.append(pe)

    auth_type = http_result.get("auth_type", "Unknown")
    # If Nmap found an HTTP service on a port, note it
    if nmap_endpoints and auth_type == "Unknown":
        for pe in nmap_endpoints:
            svc = pe.get("service", {})
            svc_name = svc.get("name", "").lower()
            if "http" in svc_name or "https" in svc_name:
                auth_type = "Unknown (HTTP service detected on port " + str(pe["port"]) + ")"

    state["recon_data"] = {
        "endpoints_found": len([e for e in endpoints if e.get("path")]),  # Only count HTTP endpoints
        "endpoints": endpoints,
        "auth_type": auth_type,
        "headers": http_result.get("headers", {}),
        "tech_stack": http_result.get("tech_stack", []),
        "http_probed": not is_ip_target,
        "nmap_ports_found": len(nmap_endpoints),
        "tools_run": ["http_probe"] + (["nmap"] if nmap_endpoints else []),
        "errors": http_result.get("errors", []) + nmap_errors,
    }

    # Recon findings: report open ports as INFO-level findings, report auth type
    recon_findings = []
    for pe in nmap_endpoints:
        recon_findings.append({
            "agent_name": "Recon Agent",
            "severity": "LOW",
            "description": f"Open {pe['protocol']} port {pe['port']} detected (service: {pe['service'].get('name', 'unknown')}).",
            "remediation": "Verify if this port/service should be publicly accessible. Close unnecessary ports.",
            "metadata": {"tool": "nmap", "raw_type": "open_port", "port": pe["port"]},
        })
    if auth_type != "Unknown":
        recon_findings.append({
            "agent_name": "Recon Agent",
            "severity": "LOW",
            "description": f"Authentication method detected: {auth_type}",
            "remediation": "Ensure authentication is properly configured and uses current best practices.",
            "metadata": {"tool": "http_probe", "auth_type": auth_type},
        })
    if http_result.get("tech_stack"):
        tech_list = ", ".join(http_result["tech_stack"])
        recon_findings.append({
            "agent_name": "Recon Agent",
            "severity": "LOW",
            "description": f"Technology stack detected: {tech_list}",
            "remediation": "Ensure all frameworks and libraries are updated to their latest secure versions.",
            "metadata": {"tool": "http_probe", "tech_stack": http_result["tech_stack"]},
        })

    state["recon_findings"] = recon_findings

    await crud.update_scan_status(state["scan_id"], state["status"])
    return state

async def security_analysis_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Security Analysis Agents...")
    state["status"] = "SECURITY_ANALYSIS"
    await crud.update_scan_status(state["scan_id"], state["status"])

    tool_manager = ToolManager()
    target = state["target_url"]

    # Run all security analysis agents in parallel
    try:
        # AI Security Agent
        ai_result = await tool_manager.run_agent_tools("AI Security Agent", target)
        state["ai_vulnerabilities"] = ai_result.get("findings", [])
        for f in state["ai_vulnerabilities"]:
            f["agent_name"] = "AI Security Agent"

        # API Security Agent
        api_result = await tool_manager.run_agent_tools("API Security Agent", target)
        state["api_vulnerabilities"] = api_result.get("findings", [])
        for f in state["api_vulnerabilities"]:
            f["agent_name"] = "API Security Agent"

        # Code Review Agent
        code_result = await tool_manager.run_agent_tools("Code Review Agent", target)
        state["code_vulnerabilities"] = code_result.get("findings", [])
        for f in state["code_vulnerabilities"]:
            f["agent_name"] = "Code Review Agent"

        # Infrastructure Agent
        infra_result = await tool_manager.run_agent_tools("Infrastructure Agent", target)
        state["infra_vulnerabilities"] = infra_result.get("findings", [])
        for f in state["infra_vulnerabilities"]:
            f["agent_name"] = "Infrastructure Agent"

        # Collect all errors
        all_errors = []
        for result in [ai_result, api_result, code_result, infra_result]:
            all_errors.extend(result.get("errors", []))

        state["security_analysis_errors"] = all_errors

    except Exception as e:
        print(f"[{state['scan_id']}] Security Analysis error: {e}")
        state["ai_vulnerabilities"] = []
        state["api_vulnerabilities"] = []
        state["code_vulnerabilities"] = []
        state["infra_vulnerabilities"] = []
        state["security_analysis_errors"] = [str(e)]

    # Determine data source for honesty tracking
    tools_returned_findings = any([
        state["ai_vulnerabilities"],
        state["api_vulnerabilities"],
        state["code_vulnerabilities"],
        state["infra_vulnerabilities"],
    ])
    tools_had_errors = bool(all_errors)
    
    if tools_returned_findings and not tools_had_errors:
        state["data_source"] = "real_tools"
    elif tools_returned_findings and tools_had_errors:
        state["data_source"] = "partial"
    else:
        # No tools returned findings and no errors — all tools were unavailable.
        # Mark as simulation and inject baseline findings so the scan is still useful.
        state["data_source"] = "simulation"
        print(f"[{state['scan_id']}] WARNING: No security tools available. Using baseline simulation findings.")
        state["ai_vulnerabilities"] = [{
            "agent_name": "AI Security Agent",
            "severity": "HIGH",
            "description": "Mild susceptibility to role-play jailbreak (simulation — no LLM endpoint reachable).",
            "remediation": "Implement input sanitization and strict system prompts. Connect an LLM endpoint to test against a real model.",
            "metadata": {"tool": "ai_tester", "simulated": True}
        }]
        state["api_vulnerabilities"] = [{
            "agent_name": "API Security Agent",
            "severity": "HIGH",
            "description": f"Rate limiting missing on /api/v1/chat endpoint (simulation — no scanner reachable).",
            "remediation": "Use Redis-based rate limiting (e.g., 60 req/min per IP). Connect OWASP ZAP to scan a real target.",
            "metadata": {"tool": "zap", "simulated": True}
        }]
        state["code_vulnerabilities"] = [{
            "agent_name": "Code Review Agent",
            "severity": "MEDIUM",
            "description": "Outdated dependency (requests v2.25.0) detected (simulation — no scanner reachable).",
            "remediation": "Update 'requests' library to the latest secure version. Connect Semgrep/Bandit/Gitleaks to scan real code.",
            "metadata": {"tool": "semgrep", "simulated": True}
        }]
        state["infra_vulnerabilities"] = []
        state["security_analysis_errors"] = [
            "No security tools were available to run a real assessment. Results are simulated for demonstration.",
            "To run a real assessment, ensure at least one of these is reachable: Ollama (localhost:11434), OWASP ZAP (localhost:8080), nmap, semgrep, bandit, gitleaks, trivy."
        ]

    state["all_findings"] = (
        state["ai_vulnerabilities"] +
        state["api_vulnerabilities"] +
        state["code_vulnerabilities"] +
        state["infra_vulnerabilities"]
    )

    # Add recon findings if any
    if state.get("recon_findings"):
        state["all_findings"] = state["recon_findings"] + state["all_findings"]

    await crud.update_scan_status(state["scan_id"], state["status"])
    return state

async def risk_scoring_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Risk Analysis Agent...")
    await asyncio.sleep(0.5)
    state["status"] = "RISK_SCORING"
    state["overall_score"] = calculate_risk_score(state["all_findings"])
    await crud.update_scan_status(state["scan_id"], state["status"])
    return state


# ---------------------------------------------------------
# Compliance Mapping
# ---------------------------------------------------------

# Mapping of agent findings to OWASP LLM Top 10 and NIST CSF
COMPLIANCE_MAPPING = {
    "AI Security Agent": {
        "owasp_llm": ["LLM01: Prompt Injection", "LLM02: Insecure Output Handling"],
        "nist_csf": ["ID.RA-1", "PR.DS-6", "DE.AE-1"],
    },
    "API Security Agent": {
        "owasp_llm": ["LLM04: Model Denial of Service", "LLM05: Supply Chain Vulnerabilities"],
        "nist_csf": ["PR.AC-7", "PR.DS-1", "DE.CM-1"],
    },
    "Code Review Agent": {
        "owasp_llm": ["LLM05: Supply Chain Vulnerabilities", "LLM03: Training Data Poisoning"],
        "nist_csf": ["ID.RA-1", "PR.IP-1", "DE.AE-1"],
    },
    "Infrastructure Agent": {
        "owasp_llm": ["LLM09: Overreliance", "LLM10: Model Theft"],
        "nist_csf": ["PR.DS-1", "PR.AC-3", "PR.PT-4"],
    },
}


async def compliance_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Compliance Agent...")
    await asyncio.sleep(0.5)
    state["status"] = "COMPLIANCE_MAPPING"
    state["compliance_status"] = "MAPPING"

    compliance_findings: List[ComplianceFinding] = []
    for finding in state["all_findings"]:
        agent = finding["agent_name"]
        mapping = COMPLIANCE_MAPPING.get(agent, {"owasp_llm": [], "nist_csf": []})
        compliance_findings.append({
            "finding_id": 0,  # Will be updated after findings are persisted
            "agent_name": agent,
            "severity": finding["severity"],
            "owasp_llm": mapping["owasp_llm"],
            "nist_csf": mapping["nist_csf"],
        })

    state["compliance_findings"] = compliance_findings
    await crud.update_scan_status(state["scan_id"], state["status"])
    return state


async def recommendation_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Recommendation Agent...")
    await asyncio.sleep(1)
    state["status"] = "RECOMMENDATIONS"

    for finding in state["all_findings"]:
        if finding["agent_name"] == "AI Security Agent":
            finding["remediation"] = "Implement input sanitization and strict system prompts."
        elif finding["agent_name"] == "API Security Agent":
            finding["remediation"] = "Use Redis-based rate limiting (e.g., 60 req/min per IP)."
        elif finding["agent_name"] == "Code Review Agent":
            finding["remediation"] = "Update 'requests' library to the latest secure version."

    await crud.update_scan_status(state["scan_id"], state["status"])
    return state

async def report_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Report Agent...")
    await asyncio.sleep(0.5)
    state["status"] = "COMPLETED"

    # Persist final results to SQLite
    finding_ids = await crud.complete_scan(state["scan_id"], state["overall_score"], state["all_findings"], state.get("data_source", "real_tools"))

    # Update compliance findings with actual finding IDs
    if state.get("compliance_findings"):
        for idx, cf in enumerate(state["compliance_findings"]):
            if idx < len(finding_ids):
                cf["finding_id"] = finding_ids[idx]
        await crud.save_compliance_findings(state["scan_id"], state["compliance_findings"], finding_ids)

    # Generate PDF reports
    output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "output", "reports")
    output_dir = os.path.abspath(output_dir)

    # Prepare scan data for report generation
    scan_data = {
        "scan_id": state["scan_id"],
        "target_url": state["target_url"],
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "overall_score": state["overall_score"],
        "findings": state["all_findings"],
        "compliance": state.get("compliance_findings", []),
        "recon_data": state.get("recon_data", {}),
    }

    try:
        report_paths = report_generator.generate_both_reports(scan_data, output_dir)
        state["final_report"] = {
            "summary_generated": True,
            "technical_report_generated": True,
            "executive_summary_pdf": report_paths["executive_summary"],
            "technical_report_pdf": report_paths["technical_report"],
        }
        print(f"[{state['scan_id']}] PDF reports generated: {report_paths}")
    except Exception as e:
        print(f"[{state['scan_id']}] Error generating PDF reports: {e}")
        state["final_report"] = {
            "summary_generated": False,
            "technical_report_generated": False,
            "error": str(e),
        }

    # Save final_report to database
    await crud.update_final_report(state["scan_id"], state["final_report"])

    return state

# ---------------------------------------------------------
# Graph Construction
# ---------------------------------------------------------

def build_master_agent_graph() -> StateGraph:
    workflow = StateGraph(CyberPilotState)
    workflow.add_node("recon", recon_node)
    workflow.add_node("security_analysis", security_analysis_node)
    workflow.add_node("risk_scoring", risk_scoring_node)
    workflow.add_node("compliance", compliance_node)
    workflow.add_node("recommendations", recommendation_node)
    workflow.add_node("report", report_node)

    workflow.set_entry_point("recon")
    workflow.add_edge("recon", "security_analysis")
    workflow.add_edge("security_analysis", "risk_scoring")
    workflow.add_edge("risk_scoring", "compliance")
    workflow.add_edge("compliance", "recommendations")
    workflow.add_edge("recommendations", "report")
    workflow.add_edge("report", END)

    return workflow.compile()

master_agent_app = build_master_agent_graph()

# ---------------------------------------------------------
# API Integration Functions
# ---------------------------------------------------------

async def start_scan_workflow(target_url: str, data_source: str = "real_tools", authorize: bool = False) -> str:
    scan_id = str(uuid.uuid4())
    target_url_str = str(target_url)

    # Authorization gate: require explicit authorization for real scans
    if data_source == "real_tools" and not authorize:
        raise ValueError("Real tool scans require explicit authorization (pass authorize=True)")

    # Create initial record in SQLite
    await crud.create_scan(scan_id, target_url_str, data_source)

    initial_state: CyberPilotState = {
        "scan_id": scan_id,
        "target_url": target_url_str,
        "status": "INITIALIZING",
        "recon_data": {},
        "recon_findings": [],
        "ai_vulnerabilities": [],
        "api_vulnerabilities": [],
        "code_vulnerabilities": [],
        "infra_vulnerabilities": [],
        "all_findings": [],
        "overall_score": 100,
        "compliance_status": "PENDING",
        "compliance_findings": [],
        "security_analysis_errors": [],
        "final_report": {},
        "data_source": "real_tools",  # Updated by analysis node based on tool results
    }

    asyncio.create_task(master_agent_app.ainvoke(initial_state))
    return scan_id

async def get_scan_result(scan_id: str) -> Dict[str, Any]:
    """Read directly from SQLite."""
    result = await crud.get_scan(scan_id)
    if result is None:
        return {"status": "NOT_FOUND"}
    return result