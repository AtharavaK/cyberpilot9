import uuid
import asyncio
import json
import os
import time
import logging
import shutil
from datetime import datetime
from typing import Dict, Any, List, Optional
from langgraph.graph import StateGraph, END
from app.services.graph_state import CyberPilotState, ComplianceFinding
from app.db import crud
from app.services import report_generator
from app.services.tool_manager import ToolManager
from app.services.target_normalizer import TargetNormalizer
from app.services.finding_normalizer import dedup_findings
from app.services.planning import (
    MasterSecurityAgent, AssessmentPlan, SecurityTask,
    AgentResult, MasterDecision, SecurityPolicy, PolicyValidation,
    TaskStatus, DecisionType, DecisionOutcome, Priority,
)
from app.services.ai_engine import AIEngine, AIUnavailableError, AIError
from urllib.parse import urlparse
import aiohttp

logger = logging.getLogger(__name__)


def calculate_risk_score(findings: List[Dict[str, Any]]) -> int:
    """Calculate overall risk score based on findings severity.

    Severity penalty weights (higher = more severe):
        CRITICAL = 50, HIGH = 25, MEDIUM = 10, LOW = 3, INFO = 1
    """
    if not findings:
        return 100

    severity_weights = {"CRITICAL": 50, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 1}
    total_penalty = sum(severity_weights.get(f.get("severity", "LOW"), 3) for f in findings)
    score = max(0, 100 - total_penalty)
    return score


# ── Event helpers ──────────────────────────────────────────────────────────────

async def _emit(scan_id: str, event_type: str, payload: Dict[str, Any]) -> None:
    """Write a progress/event row to scan_events table."""
    try:
        await crud.add_scan_event(scan_id, event_type, payload)
    except Exception as e:
        print(f"[{scan_id}] WARNING: failed to emit event: {e}")


async def _check_interrupt(scan_id: str) -> bool:
    """Return True if scan should stop (cancelled). Return False if paused (awaited)."""
    cancelled = await crud.is_scan_cancelled(scan_id)
    if cancelled:
        return True
    paused = await crud.is_scan_paused(scan_id)
    if paused:
        # Wait until resumed — poll every 2 seconds
        while True:
            await asyncio.sleep(2)
            cancelled = await crud.is_scan_cancelled(scan_id)
            if cancelled:
                return True
            paused = await crud.is_scan_paused(scan_id)
            if not paused:
                break
    return False


# ── HTTP Recon Helper ──────────────────────────────────────────────────────────

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
                    if path == "/":
                        for h in headers_to_check:
                            val = resp.headers.get(h)
                            if val:
                                result["headers"][h] = val
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


# ── Node Functions ─────────────────────────────────────────────────────────────

async def recon_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Recon Agent...")
    state["status"] = "RECONNAISSANCE"
    await crud.update_scan_status(state["scan_id"], state["status"])
    await crud.update_scan_session(state["scan_id"], "RECONNAISSANCE", "recon")
    await _emit(state["scan_id"], "phase", {"phase": "RECONNAISSANCE", "message": "Starting reconnaissance..."})

    parsed = urlparse(state["target_url"])
    is_ip_target = not parsed.scheme or not parsed.netloc

    # ── Check normalized target ──
    nt = state.get("target_normalized") or {}
    target_kind = nt.get("kind", "invalid")
    is_web_target = target_kind == "url"
    # For IP targets, ensure it's actually a network address, not a local path
    if is_ip_target and not is_web_target:
        # urlparse treats bare paths (no scheme) as "no scheme, no netloc" → is_ip_target=True
        # But a local filesystem path should NOT be treated as an IP/hostname target.
        is_ip_target = target_kind != "local_path"

    # 1. HTTP probing — only for web targets
    http_result = {}
    if is_web_target:
        try:
            http_result = await _http_recon(nt.get("web_target") or state["target_url"])
        except Exception as e:
            http_result = {"errors": [str(e)]}
            print(f"[{state['scan_id']}] HTTP recon failed: {e}")
    elif not is_ip_target and target_kind not in ("url",):
        # Local path or git repo — no HTTP probing
        pass
    else:
        # IP target
        try:
            http_result = await _http_recon(state["target_url"])
        except Exception as e:
            http_result = {"errors": [str(e)]}
            print(f"[{state['scan_id']}] HTTP recon failed: {e}")

    await _emit(state["scan_id"], "progress", {
        "message": (
            f"Probed {len(http_result.get('endpoints', []))} HTTP endpoints"
            if http_result
            else f"HTTP recon skipped (target kind: {target_kind})"
        ),
        "endpoints_found": len(http_result.get("endpoints", [])) if http_result else 0,
        "target_kind": target_kind,
    })

    # 2. Nmap port scan — only for web/IP targets, not local paths
    nmap_endpoints = []
    nmap_errors = []
    if is_web_target or is_ip_target:
        try:
            tool_manager = ToolManager()
            nmap_config = state.get("nmap_config", {})
            nmap_result = await tool_manager.run_agent_tools(
                "Recon Agent", nt.get("web_target") or state["target_url"],
                allow_internal=state.get("authorize", False),
                **nmap_config,
            )
            nmap_findings = [f for f in nmap_result.get("findings", []) if f.get("metadata", {}).get("tool") == "nmap"]
            for f in nmap_findings:
                meta = f.get("metadata", {})
                if meta.get("raw_type") == "open_port":
                    nmap_endpoints.append({
                        "type": "network_port",
                        "port": meta.get("port", meta.get("line", 0)),
                        "protocol": meta.get("raw_type", "").replace("open_", ""),
                        "service": meta.get("service", {}),
                    })
            nmap_errors = nmap_result.get("errors", [])
        except Exception as e:
            nmap_errors.append(str(e))
    else:
        # Local path or git repo — Nmap is not applicable
        logger.info(
            "Nmap skipped: target is a local path/repository (kind=%s), "
            "not a network target.", target_kind,
        )
        await _emit(state["scan_id"], "progress", {
            "message": f"Nmap skipped (target kind: {target_kind} — not a network target)",
            "target_kind": target_kind,
        })

    # Build recon data
    endpoints = http_result.get("endpoints", [])
    for pe in nmap_endpoints:
        endpoints.append(pe)

    auth_type = http_result.get("auth_type", "Unknown")
    if nmap_endpoints and auth_type == "Unknown":
        for pe in nmap_endpoints:
            svc = pe.get("service", {})
            svc_name = svc.get("name", "").lower()
            if "http" in svc_name or "https" in svc_name:
                auth_type = f"Unknown (HTTP service detected on port {pe['port']})"

    state["recon_data"] = {
        "endpoints_found": len([e for e in endpoints if e.get("path")]),
        "endpoints": endpoints,
        "auth_type": auth_type,
        "headers": http_result.get("headers", {}),
        "tech_stack": http_result.get("tech_stack", []),
        "http_probed": not is_ip_target,
        "nmap_ports_found": len(nmap_endpoints),
        "tools_run": ["http_probe"] + (["nmap"] if nmap_endpoints else []),
        "errors": http_result.get("errors", []) + nmap_errors,
    }

    # Recon findings
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
    await _emit(state["scan_id"], "finding_batch", {
        "agent": "Recon Agent",
        "count": len(recon_findings),
        "message": f"Found {len(recon_findings)} recon findings",
    })

    await crud.update_scan_status(state["scan_id"], state["status"])
    return state


async def security_analysis_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Security Analysis Agents...")
    state["status"] = "SECURITY_ANALYSIS"
    await crud.update_scan_status(state["scan_id"], state["status"])
    await crud.update_scan_session(state["scan_id"], "SECURITY_ANALYSIS", "security_analysis")
    await _emit(state["scan_id"], "phase", {"phase": "SECURITY_ANALYSIS", "message": "Running security analysis agents..."})

    tool_manager = ToolManager()

    # ── Resolve normalized target (populated in start_scan_workflow) ──
    nt = state.get("target_normalized") or {}
    web_target = nt.get("web_target")  # None for local_path targets
    local_path = nt.get("local_path")
    target_kind = nt.get("kind", "invalid")

    # Code-review scanners require a local filesystem path.
    has_local_target = bool(local_path) and os.path.exists(local_path)
    # Web-only agents (AI, API) require a web target URL.
    has_web_target = bool(web_target)

    authorize = state.get("authorize", False)

    try:
        # AI Security Agent — uses web target only
        if has_web_target:
            await _emit(state["scan_id"], "progress", {"message": "Running AI Security Agent..."})
            ai_result = await tool_manager.run_agent_tools(
                "AI Security Agent", web_target,
                allow_internal=authorize,
            )
        else:
            logger.info("AI Security Agent skipped: no web target (kind=%s).", target_kind)
            await _emit(state["scan_id"], "progress", {
                "message": "AI Security Agent skipped (no web target).",
                "target_kind": target_kind,
            })
            ai_result = {"tools_run": [], "findings": [], "errors": []}
        state["ai_vulnerabilities"] = ai_result.get("findings", [])
        for f in state["ai_vulnerabilities"]:
            f["agent_name"] = "AI Security Agent"
        await _emit(state["scan_id"], "finding_batch", {
            "agent": "AI Security Agent",
            "count": len(state["ai_vulnerabilities"]),
        })

        # API Security Agent — uses web target only
        if has_web_target:
            await _emit(state["scan_id"], "progress", {"message": "Running API Security Agent..."})
            api_result = await tool_manager.run_agent_tools(
                "API Security Agent", web_target,
                allow_internal=authorize,
            )
        else:
            logger.info("API Security Agent skipped: no web target (kind=%s).", target_kind)
            await _emit(state["scan_id"], "progress", {
                "message": "API Security Agent skipped (no web target).",
                "target_kind": target_kind,
            })
            api_result = {"tools_run": [], "findings": [], "errors": []}
        state["api_vulnerabilities"] = api_result.get("findings", [])
        for f in state["api_vulnerabilities"]:
            f["agent_name"] = "API Security Agent"
        await _emit(state["scan_id"], "finding_batch", {
            "agent": "API Security Agent",
            "count": len(state["api_vulnerabilities"]),
        })

        # Code Review Agent — uses local_path when available
        await _emit(state["scan_id"], "progress", {"message": "Running Code Review Agent..."})
        if has_local_target:
            code_result = await tool_manager.run_agent_tools(
                "Code Review Agent", local_path,
                allow_internal=authorize,
            )
        else:
            logger.info(
                "Code review scanners skipped: target is not a local source/repository "
                "(kind=%s).", target_kind,
            )
            await _emit(state["scan_id"], "progress", {
                "message": "Code review scanners skipped: target is not a local source/repository.",
                "target_kind": target_kind,
            })
            code_result = {
                "tools_run": [],
                "findings": [],
                "errors": ["Code review scanners skipped: no local source path.",
                           f"Target kind is '{target_kind}' — provide a local path or git repo URL."],
            }
        state["code_vulnerabilities"] = code_result.get("findings", [])
        for f in state["code_vulnerabilities"]:
            f["agent_name"] = "Code Review Agent"
        await _emit(state["scan_id"], "finding_batch", {
            "agent": "Code Review Agent",
            "count": len(state["code_vulnerabilities"]),
        })

        # Infrastructure Agent (Trivy) — uses local_path when available,
        # otherwise falls back to web_target (trivy has its own repo detection)
        await _emit(state["scan_id"], "progress", {"message": "Running Infrastructure Agent..."})
        infra_target = local_path if has_local_target else web_target
        assert infra_target is not None, "infra_target should not be None"
        infra_result = await tool_manager.run_agent_tools(
            "Infrastructure Agent", infra_target,
            allow_internal=authorize,
        )
        state["infra_vulnerabilities"] = infra_result.get("findings", [])
        for f in state["infra_vulnerabilities"]:
            f["agent_name"] = "Infrastructure Agent"
        await _emit(state["scan_id"], "finding_batch", {
            "agent": "Infrastructure Agent",
            "count": len(state["infra_vulnerabilities"]),
        })

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

    # Determine data source
    recon_had_findings = bool(state.get("recon_findings", []))
    tools_returned_findings = any([
        state["ai_vulnerabilities"],
        state["api_vulnerabilities"],
        state["code_vulnerabilities"],
        state["infra_vulnerabilities"],
    ]) or recon_had_findings
    tools_had_errors = bool(state.get("security_analysis_errors", []))

    if tools_returned_findings and not tools_had_errors:
        state["data_source"] = "real_tools"
    elif tools_returned_findings and tools_had_errors:
        state["data_source"] = "partial"
    else:
        state["data_source"] = "simulation"
        print(f"[{state['scan_id']}] WARNING: No security tools available. Using baseline simulation findings.")
        state["ai_vulnerabilities"] = [{
            "agent_name": "AI Security Agent",
            "severity": "HIGH",
            "description": "Mild susceptibility to role-play jailbreak (simulation — no LLM endpoint reachable).",
            "remediation": "Implement input sanitization and strict system prompts. Connect an LLM endpoint to test against a real model.",
            "metadata": {"tool": "ai_tester", "simulated": True},
        }]
        state["api_vulnerabilities"] = [{
            "agent_name": "API Security Agent",
            "severity": "HIGH",
            "description": "Rate limiting missing on /api/v1/chat endpoint (simulation — no scanner reachable).",
            "remediation": "Use Redis-based rate limiting (e.g., 60 req/min per IP). Connect OWASP ZAP to scan a real target.",
            "metadata": {"tool": "zap", "simulated": True},
        }]
        state["code_vulnerabilities"] = [{
            "agent_name": "Code Review Agent",
            "severity": "MEDIUM",
            "description": "Outdated dependency (requests v2.25.0) detected (simulation — no scanner reachable).",
            "remediation": "Update 'requests' library to the latest secure version. Connect Semgrep/Bandit/Gitleaks to scan real code.",
            "metadata": {"tool": "semgrep", "simulated": True},
        }]
        state["infra_vulnerabilities"] = []
        state["security_analysis_errors"] = [
            "No security tools were available to run a real assessment. Results are simulated for demonstration.",
            "To run a real assessment, ensure at least one of these is reachable: Ollama (localhost:11434), OWASP ZAP (localhost:8080), nmap, semgrep, bandit, gitleaks, trivy.",
        ]

    state["all_findings"] = (
        state["ai_vulnerabilities"] +
        state["api_vulnerabilities"] +
        state["code_vulnerabilities"] +
        state["infra_vulnerabilities"]
    )
    if state.get("recon_findings"):
        state["all_findings"] = state["recon_findings"] + state["all_findings"]

    total = len(state["all_findings"])
    await _emit(state["scan_id"], "progress", {
        "message": f"Security analysis complete. Total findings: {total}",
        "total_findings": total,
    })

    await crud.update_scan_status(state["scan_id"], state["status"])
    return state


async def risk_scoring_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Risk Analysis Agent...")
    await asyncio.sleep(0.5)
    state["status"] = "RISK_SCORING"
    await crud.update_scan_status(state["scan_id"], state["status"])
    await crud.update_scan_session(state["scan_id"], "RISK_SCORING", "risk_scoring")
    await _emit(state["scan_id"], "phase", {"phase": "RISK_SCORING", "message": "Calculating risk score..."})

    state["overall_score"] = calculate_risk_score(state["all_findings"])
    await _emit(state["scan_id"], "progress", {
        "message": f"Risk score: {state['overall_score']}/100",
        "overall_score": state["overall_score"],
    })
    await crud.update_scan_status(state["scan_id"], state["status"])
    return state


# ── Compliance Mapping ─────────────────────────────────────────────────────────

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
    "Recon Agent": {
        "owasp_llm": ["LLM03: Training Data Poisoning", "LLM09: Overreliance"],
        "nist_csf": ["ID.RA-1", "PR.DS-1", "PR.AC-3"],
    },
}

_CWE_COMPLIANCE: Dict[str, Dict[str, List[str]]] = {
    "79":  {"owasp_llm": ["LLM01: Prompt Injection"],          "nist_csf": ["PR.AC-7", "DE.CM-1"]},
    "89":  {"owasp_llm": ["LLM05: Supply Chain Vulnerabilities"], "nist_csf": ["PR.IP-1"]},
    "200": {"owasp_llm": ["LLM02: Insecure Output Handling"],  "nist_csf": ["DE.AE-1"]},
    "201": {"owasp_llm": ["LLM02: Insecure Output Handling"],  "nist_csf": ["PR.DS-1"]},
    "264": {"owasp_llm": ["LLM09: Overreliance"],              "nist_csf": ["PR.AC-3"]},
    "269": {"owasp_llm": ["LLM09: Overreliance"],              "nist_csf": ["PR.AC-3"]},
    "287": {"owasp_llm": ["LLM01: Prompt Injection"],          "nist_csf": ["PR.AC-7"]},
    "295": {"owasp_llm": ["LLM01: Prompt Injection"],          "nist_csf": ["PR.AC-7"]},
    "310": {"owasp_llm": ["LLM02: Insecure Output Handling"],  "nist_csf": ["PR.DS-1"]},
    "311": {"owasp_llm": ["LLM02: Insecure Output Handling"],  "nist_csf": ["PR.DS-1"]},
    "319": {"owasp_llm": ["LLM02: Insecure Output Handling"],  "nist_csf": ["PR.DS-1"]},
    "327": {"owasp_llm": ["LLM02: Insecure Output Handling"],  "nist_csf": ["PR.DS-1"]},
    "434": {"owasp_llm": ["LLM05: Supply Chain Vulnerabilities"], "nist_csf": ["PR.DS-1"]},
    "502": {"owasp_llm": ["LLM05: Supply Chain Vulnerabilities"], "nist_csf": ["PR.DS-1"]},
    "532": {"owasp_llm": ["LLM02: Insecure Output Handling"],  "nist_csf": ["DE.AE-1"]},
    "611": {"owasp_llm": ["LLM01: Prompt Injection"],          "nist_csf": ["PR.AC-7"]},
    "732": {"owasp_llm": ["LLM09: Overreliance"],              "nist_csf": ["PR.AC-3"]},
    "749": {"owasp_llm": ["LLM01: Prompt Injection"],          "nist_csf": ["PR.IP-1"]},
    "798": {"owasp_llm": ["LLM05: Supply Chain Vulnerabilities"], "nist_csf": ["PR.AC-7"]},
    "862": {"owasp_llm": ["LLM09: Overreliance"],              "nist_csf": ["PR.AC-3"]},
    "863": {"owasp_llm": ["LLM09: Overreliance"],              "nist_csf": ["PR.AC-3"]},
    "918": {"owasp_llm": ["LLM01: Prompt Injection"],          "nist_csf": ["PR.AC-7"]},
}


async def compliance_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Compliance Agent...")
    await asyncio.sleep(0.5)
    state["status"] = "COMPLIANCE_MAPPING"
    state["compliance_status"] = "MAPPING"
    await crud.update_scan_status(state["scan_id"], state["status"])
    await crud.update_scan_session(state["scan_id"], "COMPLIANCE_MAPPING", "compliance")
    await _emit(state["scan_id"], "phase", {"phase": "COMPLIANCE_MAPPING", "message": "Mapping findings to compliance frameworks..."})

    compliance_findings: List[ComplianceFinding] = []
    for finding in state["all_findings"]:
        agent = finding["agent_name"]
        metadata = finding.get("metadata") or {}
        owasp_llm: Optional[List[str]] = None
        nist_csf: Optional[List[str]] = None

        explicit_owasp = metadata.get("owasp", [])
        if isinstance(explicit_owasp, list) and explicit_owasp:
            owasp_llm = explicit_owasp
        else:
            cwe_ids = metadata.get("cwe", [])
            if isinstance(cwe_ids, list) and cwe_ids:
                owasp_llm = []
                nist_csf = []
                for cwe in cwe_ids:
                    cwe_str = str(cwe).split("-")[0].strip()
                    if cwe_str in _CWE_COMPLIANCE:
                        entry = _CWE_COMPLIANCE[cwe_str]
                        owasp_llm.extend(entry["owasp_llm"])
                        nist_csf.extend(entry["nist_csf"])
                if owasp_llm:
                    owasp_llm = list(dict.fromkeys(owasp_llm))
                    nist_csf = list(dict.fromkeys(nist_csf))
                else:
                    owasp_llm = None
                    nist_csf = None
            else:
                owasp_llm = None
                nist_csf = None

        if owasp_llm is None or nist_csf is None:
            mapping = COMPLIANCE_MAPPING.get(agent, {"owasp_llm": [], "nist_csf": []})
            if owasp_llm is None:
                owasp_llm = mapping["owasp_llm"]
            if nist_csf is None:
                nist_csf = mapping["nist_csf"]

        compliance_findings.append({
            "finding_id": 0,
            "agent_name": agent,
            "severity": finding["severity"],
            "owasp_llm": owasp_llm,
            "nist_csf": nist_csf,
        })

    state["compliance_findings"] = compliance_findings
    await _emit(state["scan_id"], "progress", {
        "message": f"Mapped {len(compliance_findings)} findings to compliance frameworks",
        "compliance_count": len(compliance_findings),
    })
    await crud.update_scan_status(state["scan_id"], state["status"])
    return state


async def recommendation_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Recommendation Agent...")
    await asyncio.sleep(1)
    state["status"] = "RECOMMENDATIONS"
    await crud.update_scan_status(state["scan_id"], state["status"])
    await crud.update_scan_session(state["scan_id"], "RECOMMENDATIONS", "recommendations")
    await _emit(state["scan_id"], "phase", {"phase": "RECOMMENDATIONS", "message": "Generating remediation recommendations..."})

    agent_defaults: Dict[str, str] = {
        "AI Security Agent": "Implement input sanitization and strict system prompts.",
        "API Security Agent": "Use Redis-based rate limiting (e.g., 60 req/min per IP).",
        "Code Review Agent": "Update dependencies to their latest secure versions and review code patterns.",
        "Infrastructure Agent": "Review exposed services and close unnecessary ports.",
        "Recon Agent": "Verify that discovered services and ports are intentional and properly secured.",
    }

    for finding in state["all_findings"]:
        existing = (finding.get("remediation") or "").strip()
        if not existing and finding.get("agent_name") in agent_defaults:
            finding["remediation"] = agent_defaults[finding["agent_name"]]

    await _emit(state["scan_id"], "progress", {
        "message": "Recommendations generated for all findings",
    })
    await crud.update_scan_status(state["scan_id"], state["status"])
    return state


async def report_node(state: CyberPilotState) -> CyberPilotState:
    print(f"[{state['scan_id']}] Running Report Agent...")
    await asyncio.sleep(0.5)
    state["status"] = "COMPLETED"
    await crud.update_scan_status(state["scan_id"], state["status"])
    await crud.update_scan_session(state["scan_id"], "COMPLETED", "report")
    await _emit(state["scan_id"], "phase", {"phase": "COMPLETED", "message": "Generating reports..."})

    # Deduplicate findings before persistence (same vulnerability reported by multiple scanners)
    state["all_findings"] = dedup_findings(state["all_findings"])

    # Persist final results
    finding_ids = await crud.complete_scan(state["scan_id"], state["overall_score"],
                                           state["all_findings"], state.get("data_source", "real_tools"))

    if state.get("compliance_findings"):
        for idx, cf in enumerate(state["compliance_findings"]):
            if idx < len(finding_ids):
                cf["finding_id"] = finding_ids[idx]
        await crud.save_compliance_findings(state["scan_id"], state["compliance_findings"], finding_ids)

    # Generate structured remediation details for each finding
    remediation_details = _build_remediation_details(state["all_findings"])

    # Generate PDF reports
    output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "output", "reports")
    output_dir = os.path.abspath(output_dir)

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

    # Save final_report + remediation details
    await crud.update_final_report(state["scan_id"], state["final_report"])

    await _emit(state["scan_id"], "progress", {
        "message": "Scan complete",
        "overall_score": state["overall_score"],
        "total_findings": len(state["all_findings"]),
    })
    await _emit(state["scan_id"], "completed", {
        "overall_score": state["overall_score"],
        "total_findings": len(state["all_findings"]),
        "data_source": state.get("data_source", "real_tools"),
    })

    # ── Clean up temporary clone directories ──
    _cleanup_clone(state)

    return state


def _cleanup_clone(state: CyberPilotState) -> None:
    """Safely remove temporary clone directories created by TargetNormalizer.

    Only removes directories under the system temp dir.  Never touches
    user-supplied local paths.
    """
    nt = state.get("target_normalized")
    if not nt:
        return
    clone_dir = nt.get("clone_dir")
    if not clone_dir:
        return
    if not os.path.isdir(clone_dir):
        return
    # Only remove directories we created (under /tmp)
    real_clone = os.path.realpath(clone_dir)
    tmp_base = os.path.realpath("/tmp")
    if real_clone.startswith(tmp_base):
        shutil.rmtree(real_clone, ignore_errors=True)
        logger.info("Cleaned up temporary clone: %s", real_clone)


def _build_remediation_details(findings: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    """Build structured remediation guidance for each finding (by index in findings list)."""
    details = {}
    for idx, f in enumerate(findings):
        agent = f.get("agent_name", "Unknown")
        severity = f.get("severity", "LOW")
        desc = f.get("description", "")

        steps = _generate_steps(agent, severity, desc, f)
        references = _generate_references(agent, severity, desc, f)

        details[idx] = {
            "finding_id": idx,
            "steps": steps,
            "references": references,
        }
    return details


def _generate_steps(agent: str, severity: str, description: str,
                    finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate structured remediation steps for a finding."""
    steps = []
    step_num = 1

    # Step 1: Understand the issue
    steps.append({
        "step": step_num,
        "title": "Understand the finding",
        "description": f"Review the finding from {agent}: {description[:120]}{'...' if len(description) > 120 else ''}",
    })
    step_num += 1

    # Step 2: Locate in codebase / infrastructure
    metadata = finding.get("metadata", {}) or {}
    file_loc = metadata.get("file", "")
    if file_loc:
        steps.append({
            "step": step_num,
            "title": "Locate the issue",
            "description": f"Open {file_loc} in your code editor to review the problematic code.",
            "command": f"code {file_loc}",
        })
        step_num += 1

    # Step 3: General fix guidance based on agent
    fix_guidance = {
        "AI Security Agent": (
            "Review your LLM system prompts for injection vulnerabilities. "
            "Add input sanitization, output filtering, and strict delimiter usage. "
            "Consider implementing a separate validation layer before passing user input to the model."
        ),
        "API Security Agent": (
            "Review the API endpoint for missing authentication, rate limiting, or input validation. "
            "Add proper auth checks, implement rate limiting (e.g., 60 req/min per IP via Redis), "
            "and validate all inputs against expected schemas."
        ),
        "Code Review Agent": (
            "Review the flagged code pattern. Apply secure coding practices: "
            "use parameterized queries instead of string concatenation, "
            "avoid eval/exec, sanitize file paths, and update outdated dependencies."
        ),
        "Infrastructure Agent": (
            "Review the exposed service or configuration. "
            "Close unnecessary ports, update to latest secure versions, "
            "remove default credentials, and apply least-privilege principles."
        ),
        "Recon Agent": (
            "Verify whether the discovered service, port, or endpoint is intentional. "
            "If not, close it or restrict access. If yes, ensure it's properly secured "
            "with authentication and up-to-date software."
        ),
    }

    guidance = fix_guidance.get(agent, "Review the finding and apply appropriate security controls.")
    steps.append({
        "step": step_num,
        "title": "Apply the fix",
        "description": guidance,
    })
    step_num += 1

    # Step 4: Verify
    steps.append({
        "step": step_num,
        "title": "Verify the fix",
        "description": "Run the scan again to confirm the finding is resolved. Use the 'mark as remediated' triage action to track progress.",
        "command": "Re-run scan and check findings tab",
    })

    return steps


def _generate_references(agent: str, severity: str, description: str,
                         finding: Dict[str, Any]) -> List[str]:
    """Generate reference URLs for a finding."""
    refs = []
    metadata = finding.get("metadata", {}) or {}
    cwe_ids = metadata.get("cwe", [])
    if isinstance(cwe_ids, list):
        for cwe in cwe_ids:
            cwe_str = str(cwe).split("-")[-1].strip()
            if cwe_str.isdigit():
                refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_str}.html")

    owasp_ids = metadata.get("owasp", [])
    if isinstance(owasp_ids, list):
        for owasp in owasp_ids:
            refs.append(f"https://owasp.org/www-project-{owasp.lower().replace(' ', '-')}/")

    # Agent-specific reference
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

    return refs


# ── Phase 5: Planning Node ─────────────────────────────────────────────────────

# Module-level singleton; reset per scan in start_scan_workflow
_master_agent: Optional[MasterSecurityAgent] = None
_start_time: float = 0.0


def _get_master_agent() -> MasterSecurityAgent:
    """Get or create the MasterSecurityAgent singleton."""
    global _master_agent
    if _master_agent is None:
        _master_agent = MasterSecurityAgent()
    return _master_agent


async def planning_node(state: CyberPilotState) -> CyberPilotState:
    """Phase 5: Create a structured AssessmentPlan from the normalized target.

    Uses MasterSecurityAgent.create_assessment_plan() with deterministic
    target-aware task selection (Phase 1 routing). The plan is validated
    by SecurityPolicy and persisted to the database.
    """
    global _start_time
    _start_time = time.time()

    scan_id = state["scan_id"]
    await _emit(scan_id, "phase", {
        "phase": "PLANNING",
        "message": "Creating assessment plan..."
    })

    nt = state.get("target_normalized") or {}
    target_kind = nt.get("kind", "invalid")

    master_agent = _get_master_agent()
    authorize = state.get("authorize", False)

    plan = master_agent.create_assessment_plan(
        target=state["target_url"],
        target_kind=target_kind,
        target_normalized=nt,
        authorize=authorize,
    )

    # Validate plan with security policy
    policy = SecurityPolicy(
        authorized_target=plan.authorized_target,
        authorization_mode=plan.authorization_mode,
        allow_active_scanning=plan.allow_active_scanning,
        allow_private_targets=plan.allow_private_targets,
        max_tasks=plan.max_tasks,
        max_runtime_seconds=plan.max_runtime_seconds,
    )

    validation = policy.validate_plan(plan)

    # Create a decision record for the plan
    decision = MasterDecision(
        decision_type=DecisionType.PLAN.value,
        outcome=validation.decision,
        reason=validation.reason,
    )
    await crud.save_decision(scan_id, decision.to_dict())
    state["decisions"] = state.get("decisions", []) + [decision.to_dict()]
    state["policy_decisions"] = state.get("policy_decisions", []) + [
        {"plan_id": plan.plan_id, "validation": validation.to_dict()}
    ]

    # Persist plan to DB
    await crud.save_assessment_plan(scan_id, plan.to_dict())

    # Persist tasks to DB and state
    task_dicts = [t.to_dict() for t in plan.tasks]
    await crud.save_all_tasks(scan_id, task_dicts)

    state["assessment_plan"] = plan.to_dict()
    state["tasks"] = task_dicts
    state["agent_results"] = state.get("agent_results", [])
    state["decisions"] = state.get("decisions", [])
    state["policy_decisions"] = state.get("policy_decisions", [])
    state["iteration"] = 0
    state["max_iterations"] = plan.max_iterations
    state["ai_analyses"] = state.get("ai_analyses", [])
    state["task_results"] = state.get("task_results", {})
    state["completion_reason"] = None
    state["scan_budget"] = {
        "max_iterations": plan.max_iterations,
        "max_tasks": plan.max_tasks,
        "max_runtime_seconds": plan.max_runtime_seconds,
        "tasks_started": 0,
        "tasks_completed": 0,
        "start_time": _start_time,
    }

    await _emit(scan_id, "progress", {
        "message": f"Assessment plan created: {len(plan.tasks)} tasks",
        "task_count": len(plan.tasks),
    })

    for task in plan.tasks:
        await _emit(scan_id, "progress", {
            "message": f"Task planned: {task.agent} → {task.tool}",
            "task_id": task.task_id,
            "agent": task.agent,
            "tool": task.tool,
            "priority": task.priority,
            "scan_mode": task.scan_mode,
        })

    state["status"] = "PLANNED"
    await crud.update_scan_status(scan_id, state["status"])
    return state


# ── Phase 5: AI Analysis Node ────────────────────────────────────────────────────

async def ai_analysis_node(state: CyberPilotState) -> CyberPilotState:
    """Phase 5: Run AIEngine analysis on all findings from the current iteration.

    Uses AIEngine.analyze_findings() — the Phase 3 AI engine is reused, not
    duplicated. Findings are never modified — AIAnalysis is a separate object.
    """
    scan_id = state["scan_id"]
    findings = state.get("all_findings", [])

    if not findings:
        await _emit(scan_id, "progress", {
            "message": "AI analysis skipped — no findings to analyze"
        })
        return state

    await _emit(scan_id, "phase", {
        "phase": "AI_ANALYSIS",
        "message": f"Running AI analysis on {len(findings)} findings..."
    })

    master_agent = _get_master_agent()
    ai_engine = master_agent.ai_engine

    try:
        analyses = await ai_engine.analyze_findings(findings, max_concurrency=1)

        # Store AI analyses separately from findings (Phase 3 §4 principle)
        ai_analysis_list = []
        for analysis in analyses:
            analysis_dict = analysis.model_dump() if hasattr(analysis, 'model_dump') else dict(analysis)
            ai_analysis_list.append(analysis_dict)

            # Persist to DB
            await crud.create_ai_analysis(
                finding_id=analysis_dict.get("finding_id"),
                scan_id=scan_id,
                model=analysis_dict.get("model", "unknown"),
                analysis=analysis_dict,
                ai_confidence=analysis_dict.get("confidence"),
                status=analysis_dict.get("status", "completed"),
                prompt_version=analysis_dict.get("prompt_version", "v1.0"),
                error=analysis_dict.get("error"),
            )

        state["ai_analyses"] = state.get("ai_analyses", []) + ai_analysis_list

        for analysis in ai_analysis_list:
            await _emit(scan_id, "progress", {
                "message": f"AI analysis completed for finding",
                "finding_id": analysis.get("finding_id"),
                "priority": analysis.get("priority"),
                "confidence": analysis.get("confidence"),
            })

    except AIUnavailableError:
        logger.warning("AI analysis unavailable — continuing with scanner findings only")
        await _emit(scan_id, "progress", {
            "message": "AI analysis unavailable — skipping (AI is optional)"
        })
    except Exception as e:
        logger.warning("AI analysis error: %s", e)
        await _emit(scan_id, "progress", {
            "message": f"AI analysis failed: {e}",
            "error": str(e),
        })

    return state


# ── Phase 5: Decide Node ───────────────────────────────────────────────────────

async def decide_node(state: CyberPilotState) -> CyberPilotState:
    """Phase 5: Master Agent evaluates findings and decides next action.

    Examines high-severity findings + AI analyses, creates follow-up tasks
    where additional validation is useful, checks stopping criteria,
    and routes to either iteration or final reporting.
    """
    scan_id = state["scan_id"]
    state["status"] = "EVALUATION"
    await crud.update_scan_status(scan_id, state["status"])

    master_agent = _get_master_agent()

    # Build policy from plan
    plan_dict = state.get("assessment_plan", {})
    policy = SecurityPolicy(
        authorized_target=plan_dict.get("authorized_target", ""),
        authorization_mode=plan_dict.get("authorization_mode", "explicit"),
        allow_active_scanning=plan_dict.get("allow_active_scanning", False),
        allow_private_targets=plan_dict.get("allow_private_targets", False),
        max_tasks=plan_dict.get("max_tasks", 30),
        max_runtime_seconds=plan_dict.get("max_runtime_seconds", 900),
    )

    findings = state.get("all_findings", [])
    ai_analyses = state.get("ai_analyses", [])
    authorize = state.get("authorize", False)

    # Check for cancellation
    scan_cancelled = await crud.is_scan_cancelled(scan_id)

    # Build AI analysis lookup
    ai_lookup: Dict[int, Dict[str, Any]] = {}
    for analysis in ai_analyses:
        if analysis.get("finding_id"):
            ai_lookup[analysis["finding_id"]] = analysis

    # Evaluate each new high-severity finding for follow-up
    followup_tasks: List[SecurityTask] = []
    for finding in findings:
        # Skip if this finding was already processed for follow-up
        finding_id = finding.get("id")
        ai_analysis = ai_lookup.get(finding_id) if finding_id else None

        task = master_agent.evaluate_finding_for_followup(
            finding=finding,
            ai_analysis=ai_analysis,
            authorized_target=state["target_url"],
            allow_active=authorize,
        )

        if task:
            # Validate follow-up task through policy
            validation = policy.validate_task(task, scan_cancelled=scan_cancelled)

            decision = MasterDecision(
                decision_type=DecisionType.FOLLOW_UP.value,
                outcome=validation.decision,
                reason=validation.reason,
                task_id=task.task_id,
                tool=task.tool,
                target=task.target,
                policy_validation=validation.to_dict() if not validation.approved else None,
            )
            await crud.save_decision(scan_id, decision.to_dict())
            state["decisions"] = state.get("decisions", []) + [decision.to_dict()]
            state["policy_decisions"] = state.get("policy_decisions", []) + [
                {"task_id": task.task_id, "validation": validation.to_dict()}
            ]

            if validation.approved:
                task.status = TaskStatus.APPROVED.value
                task_dict = task.to_dict()
                await crud.save_task(scan_id, task_dict)
                state["tasks"] = state.get("tasks", []) + [task_dict]
                followup_tasks.append(task)
                await _emit(scan_id, "progress", {
                    "message": f"Follow-up task created: {task.agent} → {task.tool}",
                    "task_id": task.task_id,
                    "tool": task.tool,
                })
            else:
                await _emit(scan_id, "progress", {
                    "message": f"Follow-up task blocked by policy: {task.tool}",
                    "reason": validation.reason,
                })

    # Check stopping criteria
    plan_dict = state.get("assessment_plan", {})
    plan_for_stop = AssessmentPlan(
        target=plan_dict.get("target", state["target_url"]),
        target_kind=plan_dict.get("target_kind", "unknown"),
        authorized_target=plan_dict.get("authorized_target", state["target_url"]),
        authorization_mode=plan_dict.get("authorization_mode", "explicit"),
        allow_active_scanning=plan_dict.get("allow_active_scanning", False),
        allow_private_targets=plan_dict.get("allow_private_targets", False),
        objective=plan_dict.get("objective", "assessment"),
        max_iterations=plan_dict.get("max_iterations", 5),
        max_tasks=plan_dict.get("max_tasks", 30),
        max_runtime_seconds=plan_dict.get("max_runtime_seconds", 900),
    )

    should_stop, stop_reason = master_agent.should_stop(
        iteration=state.get("iteration", 0) + 1,
        plan=plan_for_stop,
        tasks=[SecurityTask(**t) for t in state.get("tasks", [])],
        findings=findings,
        start_time=state.get("scan_budget", {}).get("start_time", time.time()),
    )

    # Also check budget exhaustion
    budget = state.get("scan_budget", {})
    if not should_stop:
        if budget.get("tasks_started", 0) >= budget.get("max_tasks", 30):
            should_stop = True
            stop_reason = f"Maximum tasks budget exhausted ({budget['max_tasks']})"
        elif budget.get("tasks_completed", 0) >= 1 and not followup_tasks:
            # No new follow-up tasks created
            should_stop = True
            stop_reason = "No additional high-value follow-up tasks identified"

    if should_stop:
        state["completion_reason"] = stop_reason
        await _emit(scan_id, "progress", {
            "message": f"Assessment stopping: {stop_reason}",
            "completion_reason": stop_reason,
        })
        state["status"] = "COMPLETED"
        await crud.update_scan_status(scan_id, state["status"])
    else:
        state["iteration"] = state.get("iteration", 0) + 1
        for task in followup_tasks:
            task.status = TaskStatus.RUNNING.value
            await crud.update_task_status(
                task.task_id, TaskStatus.RUNNING.value,
                started_at=datetime.utcnow().isoformat(),
            )
        budget["tasks_started"] = budget.get("tasks_started", 0) + len(followup_tasks)
        state["scan_budget"] = budget
        await _emit(scan_id, "progress", {
            "message": f"Starting iteration {state['iteration']} with {len(followup_tasks)} follow-up tasks",
            "iteration": state["iteration"],
        })
        state["status"] = "RUNNING"
        await crud.update_scan_status(scan_id, state["status"])

    return state


async def execute_followup_node(state: CyberPilotState) -> CyberPilotState:
    """Phase 5: Execute approved follow-up tasks via ToolManager.

    This is the execution boundary — all tool execution goes through
    ToolManager (Phase 5 §2). No direct shell commands.
    """
    scan_id = state["scan_id"]
    tasks = state.get("tasks", [])

    # Find approved/running tasks for this iteration
    new_tasks = [t for t in tasks if t.get("status") == TaskStatus.RUNNING.value]

    if not new_tasks:
        return state

    tool_manager = ToolManager()
    authorize = state.get("authorize", False)

    for task in new_tasks:
        await crud.update_task_status(
            task["task_id"], TaskStatus.RUNNING.value,
            started_at=datetime.utcnow().isoformat(),
        )
        await _emit(scan_id, "progress", {
            "message": f"Executing task: {task['agent']} → {task['tool']}",
            "task_id": task["task_id"],
        })

        try:
            agent_name = task["agent"]
            target = task["target"]
            tool_name = task["tool"]

            # Prepare tool-specific kwargs
            tool_kwargs = task.get("config", {}).copy()
            tool_kwargs["scan_type"] = task.get("scan_mode", "passive")
            tool_kwargs["allow_internal"] = authorize

            result = await tool_manager.run_agent_tools(
                agent_name, target, **tool_kwargs
            )

            task["status"] = TaskStatus.COMPLETED.value
            task["completed_at"] = datetime.utcnow().isoformat()
            task["agent_result"] = result

            await crud.update_task_status(
                task["task_id"], TaskStatus.COMPLETED.value,
                completed_at=datetime.utcnow().isoformat(),
                agent_result=result,
            )

            # Record agent result
            agent_result = AgentResult(
                agent=agent_name,
                task_id=task["task_id"],
                status="completed",
                findings=result.get("findings", []),
                observations=[],
                recommendations=[],
                tool_results=result.get("tools_run", []),
                errors=result.get("errors", []),
                duration=result.get("tools_run", [{}])[0].get("duration", 0) if result.get("tools_run") else 0,
            )
            state["agent_results"] = state.get("agent_results", []) + [agent_result.to_dict()]
            state["task_results"][task["task_id"]] = agent_result.to_dict()

            # Merge findings into all_findings
            new_findings = result.get("findings", [])
            if new_findings:
                state["all_findings"] = dedup_findings(state.get("all_findings", []) + new_findings)
                await _emit(scan_id, "finding_batch", {
                    "agent": agent_name,
                    "count": len(new_findings),
                    "task_id": task["task_id"],
                })

            budget = state.get("scan_budget", {})
            budget["tasks_completed"] = budget.get("tasks_completed", 0) + 1
            state["scan_budget"] = budget

        except Exception as e:
            task["status"] = TaskStatus.FAILED.value
            task["completed_at"] = datetime.utcnow().isoformat()
            await crud.update_task_status(
                task["task_id"], TaskStatus.FAILED.value,
                completed_at=datetime.utcnow().isoformat(),
            )
            await _emit(scan_id, "error", {
                "message": f"Task failed: {e}",
                "task_id": task["task_id"],
                "tool": task["tool"],
            })
            logger.warning("Follow-up task %s failed: %s", task["task_id"], e)

    return state


# ── Phase 5: Conditional Routing ─────────────────────────────────────────────────

def _route_after_planning(state: CyberPilotState) -> str:
    """Route after planning: always proceed to recon (existing workflow)."""
    return "recon"


def _route_after_decide(state: CyberPilotState) -> str:
    """Route after decide: continue iteration or go to report."""
    if state.get("completion_reason"):
        return "risk_scoring"
    return "execute_followup"


# ── Graph Construction ─────────────────────────────────────────────────────────

def build_master_agent_graph() -> StateGraph:
    """Build the Phase 5 Master Agent graph.

    Graph flow (Phase 5):

      planning → recon → security_analysis → ai_analysis → decide
                                                              ↓
                                                  (more work?) → execute_followup
                                                              ↓ no
                                                      risk_scoring
                                                              ↓
                                                        compliance
                                                              ↓
                                                    recommendations
                                                              ↓
                                                              report
                                                              ↓
                                                             END

    The planning node creates a structured AssessmentPlan.
    The ai_analysis node runs AIEngine on findings.
    The decide node evaluates findings + creates follow-up tasks.
    If follow-up tasks exist and budget allows → execute_followup → back to ai_analysis.
    If done → risk_scoring → compliance → recommendations → report → END.

    Existing nodes (recon, security_analysis, risk_scoring, compliance,
    recommendations, report) remain unchanged.
    """
    workflow = StateGraph(CyberPilotState)

    # Phase 5 nodes
    workflow.add_node("planning", planning_node)
    workflow.add_node("ai_analysis", ai_analysis_node)
    workflow.add_node("decide", decide_node)
    workflow.add_node("execute_followup", execute_followup_node)

    # Existing nodes (unchanged)
    workflow.add_node("recon", recon_node)
    workflow.add_node("security_analysis", security_analysis_node)
    workflow.add_node("risk_scoring", risk_scoring_node)
    workflow.add_node("compliance", compliance_node)
    workflow.add_node("recommendations", recommendation_node)
    workflow.add_node("report", report_node)

    # Entry: planning first, then existing recon
    workflow.set_entry_point("planning")
    workflow.add_edge("planning", "recon")

    # Existing linear path (unchanged)
    workflow.add_edge("recon", "security_analysis")

    # After security analysis: AI analysis of findings
    workflow.add_edge("security_analysis", "ai_analysis")

    # AI analysis → decide (evaluate findings, check stopping criteria)
    workflow.add_edge("ai_analysis", "decide")

    # Conditional: decide → execute_followup (if more work) or → risk_scoring (if done)
    workflow.add_conditional_edges(
        "decide",
        _route_after_decide,
        {
            "execute_followup": "execute_followup",
            "risk_scoring": "risk_scoring",
        },
    )

    # Execute follow-up tasks → back to AI analysis (bounded loop)
    workflow.add_edge("execute_followup", "ai_analysis")

    # Existing post-analysis path
    workflow.add_edge("risk_scoring", "compliance")
    workflow.add_edge("compliance", "recommendations")
    workflow.add_edge("recommendations", "report")
    workflow.add_edge("report", END)

    compiled = workflow.compile()
    return compiled


master_agent_app = build_master_agent_graph()


# ── API Integration Functions ──────────────────────────────────────────────────

async def start_scan_workflow(
    target_url: str,
    data_source: str = "real_tools",
    authorize: bool = False,
    scan_timeout_seconds: int = 300,
    nmap_config: Dict[str, Any] = None,
    session_id: str = "",
) -> str:
    scan_id = str(uuid.uuid4())
    target_url_str = str(target_url)

    if data_source == "real_tools" and not authorize:
        raise ValueError("Real tool scans require explicit authorization (pass authorize=True)")

    # Create session record (for pause/resume/cancel tracking)
    await crud.create_scan_session(scan_id)

    # Create initial scan record
    await crud.create_scan(scan_id, target_url_str, data_source, session_id=session_id)

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
        "data_source": "real_tools",
        "authorize": authorize,
        "nmap_config": nmap_config or {},
        "_scan_started_at": datetime.utcnow().timestamp(),
        "_scan_timeout_seconds": scan_timeout_seconds,
        "target_normalized": None,
        # Phase 5 state
        "assessment_plan": None,
        "tasks": [],
        "agent_results": [],
        "decisions": [],
        "policy_decisions": [],
        "iteration": 0,
        "max_iterations": 5,
        "ai_analyses": [],
        "task_results": {},
        "completion_reason": None,
        "scan_budget": {},
    }

    # Normalize the target once — clone repos if needed.
    # This happens before the workflow starts so all nodes share the same
    # normalized target info.
    if data_source == "real_tools":
        normalizer = TargetNormalizer()
        try:
            normalized = await normalizer.normalize(target_url_str, clone=True)
            if normalized.error:
                await crud.update_scan_error(scan_id, normalized.error)
                # Still proceed — the workflow nodes will handle missing local_path
            initial_state["target_normalized"] = {
                "original": normalized.original,
                "kind": normalized.kind,
                "web_target": normalized.web_target,
                "local_path": normalized.local_path,
                "is_local": normalized.is_local,
                "clone_dir": normalized.clone_dir,
                "scanners": normalized.scanners,
            }
            # Store clone_dir in DB so cancel/timeout handlers can clean up
            if normalized.clone_dir:
                await crud.set_scan_clone_dir(scan_id, normalized.clone_dir)
            if not normalized.error:
                logger.info(
                    "Target type: %s. Web scanners: %s. Code scanners: %s.",
                    normalized.kind,
                    normalized.scanners.get("web", []),
                    normalized.scanners.get("code_review", []) or "skipped",
                )
        except Exception as e:
            logger.warning("Target normalization failed for %s: %s", target_url_str, e)
            initial_state["target_normalized"] = {
                "original": target_url_str,
                "kind": "invalid",
                "web_target": target_url_str,
                "local_path": None,
                "is_local": False,
                "clone_dir": None,
                "error": str(e),
                "scanners": {"code_review": [], "web": [], "infra": []},
            }

    async def _watchdog():
        await asyncio.sleep(scan_timeout_seconds)
        try:
            result = await crud.get_scan(scan_id)
        except Exception:
            return
        if result and result.get("status") not in ("COMPLETED", "FAILED", "TIMEOUT", "CANCELLED"):
            await crud.update_scan_status(scan_id, "TIMEOUT")
            await crud.update_scan_session(scan_id, "TIMEOUT", "watchdog")
            await crud.update_scan_error(scan_id, f"Scan timed out after {scan_timeout_seconds}s")
            await crud.cleanup_scan_clone(scan_id)
            await _emit(scan_id, "error", {"message": f"Scan timed out after {scan_timeout_seconds}s"})

    asyncio.create_task(_watchdog())
    asyncio.create_task(master_agent_app.ainvoke(initial_state))
    return scan_id


async def get_scan_result(scan_id: str) -> Dict[str, Any]:
    """Read directly from SQLite. Merges DB findings into all_findings for API compatibility."""
    result = await crud.get_scan(scan_id)
    if result is None:
        return {"status": "NOT_FOUND"}
    # crud.get_scan returns "findings" (list of DB rows).
    # Put them into "all_findings" so the remediation endpoint and any
    # downstream consumers see the same structure as the in-memory state.
    result["all_findings"] = result.get("findings", [])
    return result
