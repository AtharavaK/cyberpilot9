"""
Tool Manager - Coordinates execution of all security scanners.
Integrates with the Master Agent workflow to replace mock data with real tool results.
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from app.services.tools import (
    TOOL_REGISTRY,
    DEFAULT_TOOL_CONFIGS,
    NmapScanner,
    SemgrepScanner,
    BanditScanner,
    GitleaksScanner,
    TrivyScanner,
    ZapScanner,
    AISecurityTester,
)

logger = logging.getLogger(__name__)


@dataclass
class AgentToolConfig:
    """Configuration for tools used by a specific agent."""
    agent_name: str
    tools: List[str]  # Tool names from registry
    configs: Dict[str, Dict[str, Any]]


# Mapping of agents to their tools
AGENT_TOOL_MAPPING = {
    "Recon Agent": AgentToolConfig(
        agent_name="Recon Agent",
        tools=["nmap"],
        configs={"nmap": DEFAULT_TOOL_CONFIGS["nmap"]}
    ),
    "AI Security Agent": AgentToolConfig(
        agent_name="AI Security Agent",
        tools=["ai_tester"],
        configs={"ai_tester": DEFAULT_TOOL_CONFIGS["ai_tester"]}
    ),
    "API Security Agent": AgentToolConfig(
        agent_name="API Security Agent",
        tools=["zap"],
        configs={"zap": DEFAULT_TOOL_CONFIGS["zap"]}
    ),
    "Code Review Agent": AgentToolConfig(
        agent_name="Code Review Agent",
        tools=["semgrep", "bandit", "gitleaks"],
        configs={
            "semgrep": DEFAULT_TOOL_CONFIGS["semgrep"],
            "bandit": DEFAULT_TOOL_CONFIGS["bandit"],
            "gitleaks": DEFAULT_TOOL_CONFIGS["gitleaks"],
        }
    ),
    "Infrastructure Agent": AgentToolConfig(
        agent_name="Infrastructure Agent",
        tools=["trivy"],
        configs={"trivy": DEFAULT_TOOL_CONFIGS["trivy"]}
    ),
}


class ToolManager:
    """Manages execution of security tools for each agent."""
    
    def __init__(self, custom_configs: Dict[str, Dict[str, Any]] = None):
        self.configs = custom_configs or DEFAULT_TOOL_CONFIGS
        self._scanner_cache = {}
    
    def _get_scanner(self, tool_name: str) -> Optional[object]:
        """Get or create scanner instance."""
        if tool_name in self._scanner_cache:
            return self._scanner_cache[tool_name]
        
        config = self.configs.get(tool_name, {})
        
        try:
            if tool_name == "nmap":
                scanner = NmapScanner(config)
            elif tool_name == "semgrep":
                scanner = SemgrepScanner(config)
            elif tool_name == "bandit":
                scanner = BanditScanner(config)
            elif tool_name == "gitleaks":
                scanner = GitleaksScanner(config)
            elif tool_name == "trivy":
                scanner = TrivyScanner(config)
            elif tool_name == "zap":
                scanner = ZapScanner(config)
            elif tool_name == "ai_tester":
                scanner = AISecurityTester(config)
            else:
                logger.warning(f"Unknown tool: {tool_name}")
                return None
            
            self._scanner_cache[tool_name] = scanner
            return scanner
        except Exception as e:
            logger.error(f"Failed to create scanner for {tool_name}: {e}")
            return None
    
    async def run_agent_tools(self, agent_name: str, target: str, **kwargs) -> Dict[str, Any]:
        """
        Run all tools configured for a specific agent.
        
        Args:
            agent_name: Name of the agent (e.g., "Recon Agent")
            target: Target URL, path, or identifier
            **kwargs: Additional arguments passed to scanners
            
        Returns:
            Dictionary with tool results and aggregated findings
        """
        agent_config = AGENT_TOOL_MAPPING.get(agent_name)
        if not agent_config:
            logger.warning(f"No tool configuration found for agent: {agent_name}")
            return {"tools_run": [], "findings": [], "errors": [f"No config for {agent_name}"]}
        
        results = {
            "agent": agent_name,
            "target": target,
            "tools_run": [],
            "findings": [],
            "errors": []
        }
        
        # Run each tool
        for tool_name in agent_config.tools:
            scanner = self._get_scanner(tool_name)
            if not scanner:
                error_msg = f"Failed to initialize {tool_name}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
                continue
            
            tool_kwargs = agent_config.configs.get(tool_name, {}).copy()
            tool_kwargs.update(kwargs)
            
            if not tool_kwargs.get("enabled", True):
                logger.info(f"Tool {tool_name} is disabled, skipping")
                continue
            
            try:
                logger.info(f"Running {tool_name} for {agent_name} on {target}")
                
                # Run the scan
                scan_result = await scanner.scan(target, **tool_kwargs)
                
                results["tools_run"].append({
                    "tool": tool_name,
                    "status": scan_result.status.value,
                    "findings_count": len(scan_result.findings),
                    "duration": scan_result.duration_seconds
                })
                
                # Convert findings to standard format
                for finding in scan_result.findings:
                    standard_finding = self._standardize_finding(
                        finding, agent_name, tool_name
                    )
                    results["findings"].append(standard_finding)
                
                if scan_result.error:
                    results["errors"].append(f"{tool_name}: {scan_result.error}")
                
            except Exception as e:
                error_msg = f"{tool_name} failed: {str(e)}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
        
        return results
    
    def _standardize_finding(self, raw_finding: Dict[str, Any], agent_name: str, tool_name: str) -> Dict[str, Any]:
        """Convert tool-specific finding to standard format."""
        # Copy over any extra fields that don't have a dedicated slot,
        # so downstream consumers (e.g. recon_node) can still see them.
        raw_type = raw_finding.get("type", "")
        metadata_extra = {}
        # nmap findings carry a nested service dict under "service"
        if raw_type == "open_port" and raw_finding.get("service"):
            metadata_extra["service"] = raw_finding["service"]
        # code scanners carry file/line — already handled below, but preserve any extra
        for k in ("file", "line", "rule_id", "cwe", "owasp", "references", "protocol"):
            if k in raw_finding and k not in ("file", "line", "rule_id", "cwe", "owasp", "references"):
                metadata_extra[k] = raw_finding[k]

        severity_map = {
            "CRITICAL": "HIGH",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "INFO": "LOW",
            "UNKNOWN": "LOW"
        }

        raw_severity = raw_finding.get("severity", "INFO").upper()
        standard_severity = severity_map.get(raw_severity, "LOW")

        # Get remediation
        remediation = raw_finding.get("remediation", "")
        if not remediation:
            remediation = self._get_default_remediation(raw_finding, tool_name)

        # Build base metadata
        metadata = {
            "tool": tool_name,
            "raw_type": raw_type,
            "raw_severity": raw_finding.get("severity", ""),
            "rule_id": raw_finding.get("rule_id", ""),
            "file": raw_finding.get("file", ""),
            "line": raw_finding.get("line", 0),
            "port": raw_finding.get("port", 0),
            "cwe": raw_finding.get("cwe", []),
            "owasp": raw_finding.get("owasp", []),
            "references": raw_finding.get("references", []),
        }
        # Merge in any extra fields captured above
        metadata.update(metadata_extra)

        return {
            "agent_name": agent_name,
            "tool": tool_name,
            "severity": standard_severity,
            "description": raw_finding.get("description", ""),
            "remediation": remediation,
            "metadata": metadata
        }
    
    def _get_default_remediation(self, finding: Dict[str, Any], tool_name: str) -> str:
        """Generate default remediation based on tool and finding type."""
        finding_type = finding.get("type", "")
        
        remediation_map = {
            "nmap": "Review open ports and services. Close unnecessary ports. Update services to latest versions.",
            "semgrep": "Review the code pattern. Apply secure coding practices. Update dependencies.",
            "bandit": "Review the Python code finding. Apply secure coding practices. Use secure alternatives.",
            "gitleaks": "Immediately rotate the exposed secret. Remove from code. Use secret management.",
            "trivy": "Upgrade vulnerable packages. Fix misconfigurations. Remove exposed secrets.",
            "zap": "Review the API endpoint. Apply security headers. Implement rate limiting.",
            "ai_tester": "Implement input validation and output filtering. Strengthen system prompts.",
        }
        
        return remediation_map.get(tool_name, "Review the finding and apply appropriate security controls.")
    
    async def run_all_agents(self, target: str, agents: List[str] = None) -> Dict[str, Any]:
        """
        Run tools for all agents or a subset.
        
        Args:
            target: Target URL or path
            agents: List of agent names to run (default: all)
            
        Returns:
            Aggregated results from all agents
        """
        if agents is None:
            agents = list(AGENT_TOOL_MAPPING.keys())
        
        all_results = {
            "target": target,
            "agents": {},
            "total_findings": 0,
            "total_errors": 0,
            "tools_executed": 0
        }
        
        # Run agents in parallel
        tasks = [
            self.run_agent_tools(agent, target)
            for agent in agents
            if agent in AGENT_TOOL_MAPPING
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for agent, result in zip(agents, results):
            if isinstance(result, Exception):
                logger.error(f"Agent {agent} failed: {result}")
                all_results["agents"][agent] = {
                    "error": str(result),
                    "findings": [],
                    "tools_run": []
                }
            else:
                all_results["agents"][agent] = result
                all_results["total_findings"] += len(result.get("findings", []))
                all_results["total_errors"] += len(result.get("errors", []))
                all_results["tools_executed"] += len(result.get("tools_run", []))
        
        return all_results


# Convenience functions for common operations
async def run_recon(target: str, config: Dict = None) -> Dict[str, Any]:
    """Run reconnaissance tools."""
    manager = ToolManager(config)
    return await manager.run_agent_tools("Recon Agent", target)


async def run_ai_security(target: str, config: Dict = None) -> Dict[str, Any]:
    """Run AI security tests."""
    manager = ToolManager(config)
    return await manager.run_agent_tools("AI Security Agent", target)


async def run_api_security(target: str, config: Dict = None) -> Dict[str, Any]:
    """Run API security scan."""
    manager = ToolManager(config)
    return await manager.run_agent_tools("API Security Agent", target)


async def run_code_review(target: str, config: Dict = None) -> Dict[str, Any]:
    """Run code review tools."""
    manager = ToolManager(config)
    return await manager.run_agent_tools("Code Review Agent", target)


async def run_infrastructure(target: str, config: Dict = None) -> Dict[str, Any]:
    """Run infrastructure scan."""
    manager = ToolManager(config)
    return await manager.run_agent_tools("Infrastructure Agent", target)


async def run_full_assessment(target: str, config: Dict = None) -> Dict[str, Any]:
    """Run complete security assessment with all agents."""
    manager = ToolManager(config)
    return await manager.run_all_agents(target)