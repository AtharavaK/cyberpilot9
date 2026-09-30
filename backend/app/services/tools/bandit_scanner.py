"""
Bandit scanner for Python security issues.
Used by the Code Review Agent for Python-specific SAST.
"""
import asyncio
import json
import sys
from typing import Dict, Any, List
from app.services.tools.base import BaseScanner, ScanResult, ScanStatus


class BanditScanner(BaseScanner):
    """Bandit Python security scanner wrapper."""

    @property
    def tool_name(self) -> str:
        return "Bandit"

    @property
    def command_name(self) -> str:
        return "bandit"

    async def check_installed(self) -> bool:
        """Check if bandit is available (via python -m bandit)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "bandit", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            return proc.returncode == 0
        except Exception:
            return False
    
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run Bandit scan against Python codebase.
        
        Args:
            target: Path to Python code repository
            severity: Minimum severity level (low, medium, high)
            confidence: Minimum confidence level (low, medium, high)
            extra_args: Additional bandit arguments
            
        Returns:
            ScanResult with Python security findings
        """
        import time
        start_time = time.time()
        
        # Check if bandit is installed
        if not await self.check_installed():
            return self.create_not_installed_result()
        
        # Build bandit command
        args = [sys.executable, "-m", "bandit", "-r", "-f", "json"]
        
        # Severity filter
        severity = kwargs.get("severity", "low")
        args.extend(["-ll", severity])  # Only show issues at or above this severity
        
        # Confidence filter
        confidence = kwargs.get("confidence", "low")
        args.extend(["-ii", confidence])
        
        extra_args = kwargs.get("extra_args", ["--disable-optional"])
        args.extend(extra_args)
        
        # Target path
        target_path = kwargs.get("target_path", target)
        args.append(target_path)
        
        # Run scan
        returncode, stdout, stderr = await self.run_command(args)
        duration = time.time() - start_time
        
        if returncode not in [0, 1]:  # bandit returns 1 when findings found
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                raw_output=stdout,
                error=stderr,
                duration_seconds=duration
            )
        
        # Parse JSON output
        findings = self._parse_json_output(stdout)
        
        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.SUCCESS,
            findings=findings,
            raw_output=stdout,
            duration_seconds=duration
        )
    
    def _parse_json_output(self, json_output: str) -> List[Dict[str, Any]]:
        """Parse Bandit JSON output into findings."""
        findings = []
        
        try:
            data = json.loads(json_output)
            results = data.get("results", [])
            
            for result in results:
                # Extract issue info
                issue_text = result.get("issue_text", "")
                issue_severity = result.get("issue_severity", "LOW").upper()
                issue_confidence = result.get("issue_confidence", "LOW").upper()
                test_id = result.get("test_id", "")
                test_name = result.get("test_name", "")
                
                # Map severity
                severity_map = {
                    "HIGH": "HIGH",
                    "MEDIUM": "MEDIUM",
                    "LOW": "LOW"
                }
                mapped_severity = severity_map.get(issue_severity, "LOW")
                
                # Location info
                filename = result.get("filename", "")
                line_number = result.get("line_number", 0)
                line_range = result.get("line_range", [])
                code = result.get("code", "")
                
                # CWE
                cwe = result.get("cwe", {})
                cwe_id = cwe.get("id", 0) if isinstance(cwe, dict) else 0
                
                findings.append({
                    "type": "python_finding",
                    "tool": "bandit",
                    "rule_id": f"B{test_id}" if test_id.isdigit() else test_id,
                    "severity": mapped_severity,
                    "confidence": issue_confidence,
                    "file": filename,
                    "line": line_number,
                    "line_range": line_range,
                    "code": code.strip() if code else "",
                    "message": issue_text,
                    "test_name": test_name,
                    "description": f"[{test_name}] {issue_text} in {filename}:{line_number}",
                    "cwe": [f"CWE-{cwe_id}"] if cwe_id else [],
                    "remediation": self._get_remediation(test_id, issue_text)
                })
        
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _get_remediation(self, test_id: str, message: str) -> str:
        """Get remediation advice based on test ID."""
        remediation_map = {
            "B101": "Remove assert statements from production code. Use proper error handling.",
            "B102": "Remove exec() calls. Use safer alternatives for dynamic code execution.",
            "B103": "Set proper file permissions. Avoid world-writable files.",
            "B104": "Use parameterized queries. Never format SQL with string interpolation.",
            "B105": "Use parameterized queries. Never format SQL with string interpolation.",
            "B106": "Use parameterized queries. Never format SQL with string interpolation.",
            "B107": "Use parameterized queries. Never format SQL with string interpolation.",
            "B108": "Avoid hardcoded passwords. Use environment variables or secret managers.",
            "B109": "Use proper password hashing (bcrypt, scrypt, Argon2).",
            "B110": "Use try/except with specific exception types. Avoid bare except.",
            "B111": "Use try/except with specific exception types. Avoid bare except.",
            "B112": "Avoid try/except/pass. Handle exceptions properly.",
            "B201": "Use subprocess.run() with shell=False. Avoid shell=True.",
            "B301": "Avoid pickle for untrusted data. Use JSON or safe serialization.",
            "B302": "Use safe YAML loading (yaml.safe_load).",
            "B303": "Use tempfile.mkstemp() or tempfile.mkdtemp() for temporary files.",
            "B304": "Use tempfile.mkstemp() or tempfile.mkdtemp() for temporary files.",
            "B305": "Use os.makedirs() with proper error handling.",
            "B306": "Use tempfile.mkstemp() with proper cleanup.",
            "B307": "Use subprocess with explicit arguments. Avoid shell=True.",
            "B308": "Use tempfile.mkstemp() for temporary files.",
            "B309": "Use tempfile.mkdtemp() for temporary directories.",
            "B310": "Validate and sanitize file paths. Use pathlib for safe path operations.",
            "B311": "Use secrets module for cryptographically secure random values.",
            "B312": "Use secrets module for cryptographically secure random values.",
            "B313": "Use xml.etree.ElementTree with defusedxml for XML parsing.",
            "B314": "Use xml.etree.ElementTree with defusedxml for XML parsing.",
            "B315": "Use xml.etree.ElementTree with defusedxml for XML parsing.",
            "B316": "Use xml.etree.ElementTree with defusedxml for XML parsing.",
            "B317": "Use xml.etree.ElementTree with defusedxml for XML parsing.",
            "B318": "Use xml.etree.ElementTree with defusedxml for XML parsing.",
            "B319": "Use xml.etree.ElementTree with defusedxml for XML parsing.",
            "B320": "Use xml.etree.ElementTree with defusedxml for XML parsing.",
            "B321": "Use ftp.client.FTP_TLS for secure FTP connections.",
            "B322": "Use subprocess with explicit arguments. Avoid shell=True with user input.",
            "B323": "Use subprocess with explicit arguments. Avoid shell=True with user input.",
            "B324": "Use hashlib.sha256() or stronger. Avoid MD5 for security purposes.",
            "B325": "Use hashlib.sha256() or stronger. Avoid SHA1 for security purposes.",
            "B326": "Use secrets module for cryptographically secure random values.",
            "B327": "Use secrets module for cryptographically secure random values.",
            "B328": "Use secrets module for cryptographically secure random values.",
            "B329": "Use secrets module for cryptographically secure random values.",
            "B330": "Use secrets module for cryptographically secure random values.",
            "B331": "Use secrets module for cryptographically secure random values.",
            "B501": "Use logging instead of print statements in production.",
            "B502": "Use proper template engines with auto-escaping. Avoid string formatting for HTML.",
            "B503": "Use proper template engines with auto-escaping. Avoid string formatting for HTML.",
            "B504": "Use proper template engines with auto-escaping. Avoid string formatting for HTML.",
            "B505": "Use proper template engines with auto-escaping. Avoid string formatting for HTML.",
            "B506": "Use yaml.safe_load() instead of yaml.load().",
            "B507": "Avoid hardcoded passwords. Use environment variables or secret managers.",
            "B601": "Use parameterized queries. Never concatenate user input into shell commands.",
            "B602": "Use subprocess with explicit arguments. Avoid shell=True.",
            "B603": "Use subprocess with explicit arguments. Avoid shell=True with user input.",
            "B604": "Use subprocess with explicit arguments. Avoid shell=True with user input.",
            "B605": "Use subprocess with explicit arguments. Avoid shell=True with user input.",
            "B606": "Use subprocess with explicit arguments. Avoid shell=True with user input.",
            "B607": "Use subprocess with explicit arguments. Avoid shell=True with user input.",
            "B608": "Use subprocess with explicit arguments. Avoid shell=True with user input.",
            "B609": "Use subprocess with explicit arguments. Avoid shell=True with user input.",
            "B610": "Use Django's ORM with parameterized queries.",
            "B611": "Use Django's ORM with parameterized queries.",
            "B612": "Use Django's ORM with parameterized queries.",
            "B613": "Use Django's ORM with parameterized queries.",
            "B614": "Use Django's ORM with parameterized queries.",
            "B615": "Use Django's ORM with parameterized queries.",
            "B616": "Use Django's ORM with parameterized queries.",
            "B617": "Use Django's ORM with parameterized queries.",
            "B618": "Use Django's ORM with parameterized queries.",
            "B619": "Use Django's ORM with parameterized queries.",
            "B620": "Use Django's ORM with parameterized queries.",
            "B701": "Use jinja2 with autoescape=True. Avoid |safe filter.",
            "B702": "Use jinja2 with autoescape=True. Avoid |safe filter.",
            "B703": "Use jinja2 with autoescape=True. Avoid |safe filter.",
        }
        
        return remediation_map.get(test_id, "Review the finding and apply secure coding practices.")
    
    async def scan_python_project(self, target: str) -> ScanResult:
        """Scan a Python project with default settings."""
        return await self.scan(target)