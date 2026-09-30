"""
Semgrep scanner for static application security testing (SAST).
Used by the Code Review Agent to find insecure code patterns.
"""
import asyncio
import json
import sys
import os
from typing import Dict, Any, List, Optional
from app.services.tools.base import BaseScanner, ScanResult, ScanStatus


class SemgrepScanner(BaseScanner):
    """Semgrep static analysis scanner wrapper."""
    
    @property
    def tool_name(self) -> str:
        return "Semgrep"
    
    @property
    def command_name(self) -> str:
        return "semgrep"

    @property
    def _cmd_args(self) -> List[str]:
        """Return the full command args for checking installation.
        Uses 'python -m semgrep' since semgrep is installed as a venv module."""
        return [sys.executable, "-m", "semgrep", "--version"]

    async def check_installed(self) -> bool:
        """Check if semgrep is available.
        Semgrep CLI exits with code 2 for --version (deprecation warning)
        but is still functional. Accept exit codes 0, 1, 2."""
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "semgrep", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            # semgrep returns 2 for --version (deprecation), still functional
            return proc.returncode in (0, 1, 2)
        except Exception:
            return False
    
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run Semgrep scan against target codebase.
        
        Args:
            target: Path to code repository or URL to git repo
            config: Semgrep config (e.g., "auto", "p/security-audit", "p/secrets")
            files: File patterns to scan
            extra_args: Additional semgrep arguments
            
        Returns:
            ScanResult with code findings
        """
        import time
        start_time = time.time()
        
        # Check if semgrep is installed
        if not await self.check_installed():
            return self.create_not_installed_result()
        
        # Build semgrep command — use venv bin script, NOT python -m
        # (python -m semgrep exits 2 in 1.178.0 due to deprecated __main__.py)
        args = [os.path.join(os.path.dirname(sys.executable), "semgrep"), "scan"]
        
        # Config
        config = kwargs.get("config", "auto")
        if config:
            args.extend(["--config", config])
        
        # Output format
        args.extend(["--json", "--no-git-ignore"])
        
        # Verbose for debugging
        if kwargs.get("verbose", False):
            args.append("--verbose")
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        # Target path
        target_path = kwargs.get("target_path", target)
        args.append(target_path)
        
        # Run scan
        returncode, stdout, stderr = await self.run_command(args)
        duration = time.time() - start_time
        
        if returncode not in [0, 1]:  # semgrep returns 1 when findings found
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
        """Parse Semgrep JSON output into findings."""
        findings = []
        
        try:
            data = json.loads(json_output)
            results = data.get("results", [])
            
            for result in results:
                # Extract metadata
                check_id = result.get("check_id", "")
                message = result.get("extra", {}).get("message", "")
                severity = result.get("extra", {}).get("severity", "INFO").upper()
                
                # Map severity
                severity_map = {
                    "ERROR": "HIGH",
                    "WARNING": "MEDIUM",
                    "INFO": "LOW",
                    "NOTE": "INFO"
                }
                mapped_severity = severity_map.get(severity, "INFO")
                
                # Location info
                path = result.get("path", "")
                start = result.get("start", {})
                end = result.get("end", {})
                line = start.get("line", 0)
                
                # Get code snippet
                code = ""
                if "extra" in result and "lines" in result["extra"]:
                    code = result["extra"]["lines"]
                
                # Extract metadata
                metadata = result.get("extra", {}).get("metadata", {})
                cwe = metadata.get("cwe", [])
                owasp = metadata.get("owasp", [])
                
                findings.append({
                    "type": "code_finding",
                    "tool": "semgrep",
                    "rule_id": check_id,
                    "severity": mapped_severity,
                    "file": path,
                    "line": line,
                    "code": code.strip() if code else "",
                    "message": message,
                    "description": f"[{check_id}] {message} in {path}:{line}",
                    "cwe": cwe if isinstance(cwe, list) else [cwe] if cwe else [],
                    "owasp": owasp if isinstance(owasp, list) else [owasp] if owasp else [],
                    "remediation": self._get_remediation(check_id, message)
                })
        
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _get_remediation(self, rule_id: str, message: str) -> str:
        """Get remediation advice based on rule."""
        remediation_map = {
            "hardcoded-secret": "Remove hardcoded secrets from source code. Use environment variables or secret management systems.",
            "sql-injection": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
            "xss": "Sanitize and encode user input before rendering in HTML. Use template engines with auto-escaping.",
            "path-traversal": "Validate and sanitize file paths. Use allowlists for allowed paths.",
            "command-injection": "Avoid shell commands with user input. Use subprocess with explicit arguments.",
            "insecure-deserialization": "Avoid deserializing untrusted data. Use safe serialization formats like JSON.",
            "weak-crypto": "Use strong cryptographic algorithms (AES-256, RSA-2048+, SHA-256+). Avoid MD5, SHA1, DES.",
            "insecure-random": "Use cryptographically secure random generators (secrets module in Python)."
        }
        
        for key, remediation in remediation_map.items():
            if key in rule_id.lower() or key in message.lower():
                return remediation
        
        return "Review the code finding and apply secure coding practices."
    
    async def scan_repo(self, repo_path: str, config: str = "p/security-audit") -> ScanResult:
        """Scan a local repository with security-focused config."""
        return await self.scan(repo_path, config=config)
    
    async def scan_with_config(self, target: str, configs: List[str]) -> ScanResult:
        """Scan with multiple configs."""
        # For simplicity, just use the first config
        # In production, you might want to run multiple scans
        return await self.scan(target, config=configs[0] if configs else "auto")