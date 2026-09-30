"""
Trivy scanner for container and infrastructure security.
Used by the Infrastructure Agent to scan Docker images, Kubernetes configs, and IaC.
"""
import asyncio
import json
from typing import Dict, Any, List
from app.services.tools.base import BaseScanner, ScanResult, ScanStatus


class TrivyScanner(BaseScanner):
    """Trivy vulnerability and misconfiguration scanner wrapper."""
    
    @property
    def tool_name(self) -> str:
        return "Trivy"
    
    @property
    def command_name(self) -> str:
        import os
        binary_path = "/tmp/bin/trivy"
        if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
            return binary_path
        return "trivy"

    async def check_installed(self) -> bool:
        """Check if trivy is installed. Looks in /tmp/bin first."""
        import os
        binary_path = "/tmp/bin/trivy"
        if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
            try:
                proc = await asyncio.create_subprocess_exec(
                    binary_path, "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
                return proc.returncode == 0
            except Exception:
                pass
        # Fallback to PATH lookup
        return await super().check_installed()
    
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run Trivy scan against target.
        
        Args:
            target: Docker image name, filesystem path, or git repo URL
            scan_type: Type of scan (image, fs, repo, k8s, config)
            severity: Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
            vuln_type: Vulnerability types (os, lang, config, secret)
            extra_args: Additional trivy arguments
            
        Returns:
            ScanResult with vulnerability and misconfiguration findings
        """
        import time
        start_time = time.time()
        
        # Check if trivy is installed
        if not await self.check_installed():
            return self.create_not_installed_result()
        
        # Build trivy command
        scan_type = kwargs.get("scan_type", "auto")
        
        if scan_type == "image":
            return await self._scan_image(target, kwargs)
        elif scan_type == "fs":
            return await self._scan_filesystem(target, kwargs)
        elif scan_type == "repo":
            return await self._scan_repo(target, kwargs)
        elif scan_type == "k8s":
            return await self._scan_k8s(target, kwargs)
        elif scan_type == "config":
            return await self._scan_config(target, kwargs)
        else:
            # Auto-detect based on target
            if target.startswith(("http://", "https://", "git@")):
                return await self._scan_repo(target, kwargs)
            elif ":" in target and not target.startswith("/"):
                return await self._scan_image(target, kwargs)
            else:
                return await self._scan_filesystem(target, kwargs)
    
    async def _scan_image(self, image: str, kwargs: Dict) -> ScanResult:
        """Scan a Docker image."""
        import time
        start_time = time.time()
        
        args = [self.command_name, "image", image]
        
        # Output format
        args.extend(["-f", "json"])
        
        # Severity
        severity = kwargs.get("severity", "HIGH,CRITICAL")
        args.extend(["--severity", severity])
        
        # Vulnerability types
        vuln_type = kwargs.get("vuln_type", "os,lang")
        args.extend(["--vuln-type", vuln_type])
        
        # Skip DB update
        if kwargs.get("skip_db_update", True):
            args.append("--skip-db-update")
        
        # Extra args
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        returncode, stdout, stderr = await self.run_command(args)
        duration = time.time() - start_time
        
        if returncode not in [0, 1]:
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                raw_output=stdout,
                error=stderr,
                duration_seconds=duration
            )
        
        findings = self._parse_json_output(stdout, "image")
        
        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.SUCCESS,
            findings=findings,
            raw_output=stdout,
            duration_seconds=duration
        )
    
    async def _scan_filesystem(self, path: str, kwargs: Dict) -> ScanResult:
        """Scan a filesystem for vulnerabilities and misconfigurations."""
        import time
        start_time = time.time()
        
        args = [self.command_name, "fs", path]
        
        args.extend(["-f", "json"])
        
        severity = kwargs.get("severity", "HIGH,CRITICAL")
        args.extend(["--severity", severity])
        
        vuln_type = kwargs.get("vuln_type", "os,lang,config,secret")
        args.extend(["--vuln-type", vuln_type])
        
        if kwargs.get("skip_db_update", True):
            args.append("--skip-db-update")
        
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        returncode, stdout, stderr = await self.run_command(args)
        duration = time.time() - start_time
        
        if returncode not in [0, 1]:
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                raw_output=stdout,
                error=stderr,
                duration_seconds=duration
            )
        
        findings = self._parse_json_output(stdout, "fs")
        
        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.SUCCESS,
            findings=findings,
            raw_output=stdout,
            duration_seconds=duration
        )
    
    async def _scan_repo(self, repo: str, kwargs: Dict) -> ScanResult:
        """Scan a git repository."""
        import time
        start_time = time.time()
        
        args = [self.command_name, "repo", repo]
        
        args.extend(["-f", "json"])
        
        severity = kwargs.get("severity", "HIGH,CRITICAL")
        args.extend(["--severity", severity])
        
        vuln_type = kwargs.get("vuln_type", "os,lang,config,secret")
        args.extend(["--vuln-type", vuln_type])
        
        if kwargs.get("skip_db_update", True):
            args.append("--skip-db-update")
        
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        returncode, stdout, stderr = await self.run_command(args)
        duration = time.time() - start_time
        
        if returncode not in [0, 1]:
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                raw_output=stdout,
                error=stderr,
                duration_seconds=duration
            )
        
        findings = self._parse_json_output(stdout, "repo")
        
        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.SUCCESS,
            findings=findings,
            raw_output=stdout,
            duration_seconds=duration
        )
    
    async def _scan_k8s(self, target: str, kwargs: Dict) -> ScanResult:
        """Scan Kubernetes cluster or manifests."""
        import time
        start_time = time.time()
        
        args = [self.command_name, "k8s", target]
        
        args.extend(["-f", "json"])
        
        severity = kwargs.get("severity", "HIGH,CRITICAL")
        args.extend(["--severity", severity])
        
        if kwargs.get("skip_db_update", True):
            args.append("--skip-db-update")
        
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        returncode, stdout, stderr = await self.run_command(args)
        duration = time.time() - start_time
        
        if returncode not in [0, 1]:
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                raw_output=stdout,
                error=stderr,
                duration_seconds=duration
            )
        
        findings = self._parse_json_output(stdout, "k8s")
        
        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.SUCCESS,
            findings=findings,
            raw_output=stdout,
            duration_seconds=duration
        )
    
    async def _scan_config(self, path: str, kwargs: Dict) -> ScanResult:
        """Scan configuration files for misconfigurations."""
        import time
        start_time = time.time()
        
        args = [self.command_name, "config", path]
        
        args.extend(["-f", "json"])
        
        severity = kwargs.get("severity", "HIGH,CRITICAL")
        args.extend(["--severity", severity])
        
        if kwargs.get("skip_db_update", True):
            args.append("--skip-db-update")
        
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        returncode, stdout, stderr = await self.run_command(args)
        duration = time.time() - start_time
        
        if returncode not in [0, 1]:
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                raw_output=stdout,
                error=stderr,
                duration_seconds=duration
            )
        
        findings = self._parse_json_output(stdout, "config")
        
        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.SUCCESS,
            findings=findings,
            raw_output=stdout,
            duration_seconds=duration
        )
    
    def _parse_json_output(self, json_output: str, scan_type: str) -> List[Dict[str, Any]]:
        """Parse Trivy JSON output into findings."""
        findings = []
        
        try:
            data = json.loads(json_output)
            results = data.get("Results", [])
            
            for result in results:
                target = result.get("Target", "")
                target_class = result.get("Class", "")
                target_type = result.get("Type", "")
                
                # Misconfigurations
                misconfigs = result.get("Misconfigurations", [])
                for misconfig in misconfigs:
                    findings.append({
                        "type": "misconfiguration",
                        "tool": "trivy",
                        "scan_type": scan_type,
                        "target": target,
                        "target_class": target_class,
                        "target_type": target_type,
                        "rule_id": misconfig.get("ID", ""),
                        "avd_id": misconfig.get("AVDID", ""),
                        "severity": misconfig.get("Severity", "UNKNOWN"),
                        "title": misconfig.get("Title", ""),
                        "description": misconfig.get("Description", ""),
                        "message": misconfig.get("Message", ""),
                        "resolution": misconfig.get("Resolution", ""),
                        "namespace": misconfig.get("Namespace", ""),
                        "query": misconfig.get("Query", ""),
                        "file": misconfig.get("FilePath", ""),
                        "line": misconfig.get("LineNumber", 0),
                        "cause": misconfig.get("CauseMetadata", {}),
                        "remediation": misconfig.get("Resolution", "") or "Review and fix the misconfiguration according to security best practices."
                    })
                
                # Vulnerabilities
                vulns = result.get("Vulnerabilities", [])
                for vuln in vulns:
                    findings.append({
                        "type": "vulnerability",
                        "tool": "trivy",
                        "scan_type": scan_type,
                        "target": target,
                        "target_class": target_class,
                        "target_type": target_type,
                        "vuln_id": vuln.get("VulnerabilityID", ""),
                        "pkg_name": vuln.get("PkgName", ""),
                        "installed_version": vuln.get("InstalledVersion", ""),
                        "fixed_version": vuln.get("FixedVersion", ""),
                        "severity": vuln.get("Severity", "UNKNOWN"),
                        "title": vuln.get("Title", ""),
                        "description": vuln.get("Description", ""),
                        "references": vuln.get("References", []),
                        "cvss": vuln.get("CVSS", {}),
                        "cwe_ids": vuln.get("CweIDs", []),
                        "remediation": f"Upgrade {vuln.get('PkgName', 'package')} to version {vuln.get('FixedVersion', 'latest')} or apply vendor patch."
                    })
                
                # Secrets
                secrets = result.get("Secrets", [])
                for secret in secrets:
                    findings.append({
                        "type": "secret",
                        "tool": "trivy",
                        "scan_type": scan_type,
                        "target": target,
                        "rule_id": secret.get("RuleID", ""),
                        "severity": secret.get("Severity", "UNKNOWN"),
                        "category": secret.get("Category", ""),
                        "description": secret.get("Description", ""),
                        "match": secret.get("Match", ""),
                        "file": secret.get("FilePath", ""),
                        "line": secret.get("StartLine", 0),
                        "remediation": "Remove the secret from code. Rotate the credential immediately and store in a secure secret management system."
                    })
        
        except json.JSONDecodeError:
            pass
        
        return findings
    
    async def scan_docker_image(self, image: str) -> ScanResult:
        """Scan a Docker image for vulnerabilities."""
        return await self._scan_image(image, {})
    
    async def scan_filesystem(self, path: str) -> ScanResult:
        """Scan filesystem for vulnerabilities and misconfigurations."""
        return await self._scan_filesystem(path, {})
    
    async def scan_k8s_manifests(self, path: str) -> ScanResult:
        """Scan Kubernetes manifests for misconfigurations."""
        return await self._scan_config(path, {})