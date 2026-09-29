"""
Security Tools Package - Unified interface for all security scanners.
"""
from app.services.tools.base import BaseScanner, ScanResult, ScanStatus
from app.services.tools.nmap_scanner import NmapScanner
from app.services.tools.semgrep_scanner import SemgrepScanner
from app.services.tools.bandit_scanner import BanditScanner
from app.services.tools.gitleaks_scanner import GitleaksScanner
from app.services.tools.trivy_scanner import TrivyScanner
from app.services.tools.zap_scanner import ZapScanner
from app.services.tools.ai_tester import AISecurityTester

__all__ = [
    "BaseScanner",
    "ScanResult", 
    "ScanStatus",
    "NmapScanner",
    "SemgrepScanner",
    "BanditScanner", 
    "GitleaksScanner",
    "TrivyScanner",
    "ZapScanner",
    "AISecurityTester",
]

# Tool registry for easy access
TOOL_REGISTRY = {
    "recon": NmapScanner,
    "code_review": {
        "semgrep": SemgrepScanner,
        "bandit": BanditScanner,
        "gitleaks": GitleaksScanner,
    },
    "infrastructure": TrivyScanner,
    "api_security": ZapScanner,
    "ai_security": AISecurityTester,
}

# Default configurations for each tool
DEFAULT_TOOL_CONFIGS = {
    "nmap": {
        "enabled": True,
        "timeout": 300,
        "scan_type": "connect",
        "ports": "top100",
    },
    "semgrep": {
        "enabled": True,
        "timeout": 300,
        "config": "auto",
    },
    "bandit": {
        "enabled": True,
        "timeout": 300,
        "severity": "low",
        "confidence": "low",
    },
    "gitleaks": {
        "enabled": True,
        "timeout": 300,
    },
    "trivy": {
        "enabled": True,
        "timeout": 300,
        "severity": "HIGH,CRITICAL",
        "vuln_type": "os,lang",
        "skip_db_update": True,
    },
    "zap": {
        "enabled": True,
        "timeout": 300,
        "zap_url": "http://localhost:8080",
    },
    "ai_tester": {
        "enabled": True,
        "timeout": 600,
        "llm_endpoint": "http://localhost:11434",
        "model": "llama2",
    },
}