"""
Trivy scanner for container and infrastructure security.
Used by the Infrastructure Agent to scan Docker images, Kubernetes configs, and IaC.
"""
import asyncio
import json
import time
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

    # Map legacy vuln_type values (os,lang,config,secret) to trivy 0.74+ --scanners values
    _VULN_TYPE_MAP = {
        "os": "vuln",
        "lang": "vuln",
        "config": "misconfig",
        "secret": "secret",
    }

    def _build_scanners_arg(self, kwargs: Dict) -> str:
        """Convert vuln_type or scanners kwarg to a --scanners value string."""
        # If callers pass --scanners directly, use that
        scanners = kwargs.get("scanners")
        if scanners:
            return scanners

        # Convert legacy vuln_type to scanners
        vuln_type = kwargs.get("vuln_type", "os,lang")
        parts = [p.strip() for p in vuln_type.split(",") if p.strip()]
        mapped = []
        for p in parts:
            mapped_val = self._VULN_TYPE_MAP.get(p, p)
            if mapped_val not in mapped:
                mapped.append(mapped_val)
        return ",".join(mapped) if mapped else "vuln"

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run Trivy scan against target.

        Args:
            target: Docker image name, filesystem path, or git repo URL
            scan_type: Type of scan (image, fs, repo, k8s, config)
            severity: Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
            vuln_type: Legacy vulnerability types (os, lang, config, secret) — mapped to --scanners
            scanners: Direct trivy --scanners value (vuln, misconfig, secret, license)
            skip_db_update: If True, pass --skip-db-update (fails on fresh install; auto-retries without it)
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

    def _build_base_args(self, subcommand: str, target: str, kwargs: Dict, scan_type_label: str) -> List[str]:
        """Build the common trivy args for any subcommand."""
        args = [self.command_name, subcommand, target]
        args.extend(["-f", "json"])
        args.extend(["-q", "--no-progress", "--skip-version-check"])

        severity = kwargs.get("severity", "HIGH,CRITICAL")
        args.extend(["--severity", severity])

        scanners = self._build_scanners_arg(kwargs)
        args.extend(["--scanners", scanners])

        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)

        return args

    async def _run_trivy(self, args: List[str], scan_type_label: str, start_time: float) -> ScanResult:
        """Run trivy, handling --skip-db-update first-run failures."""
        # Try with --skip-db-update first
        if "--skip-db-update" in args or True:  # We add it below conditionally
            pass

        returncode, stdout, stderr = await self.run_command(args)

        # If --skip-db-update caused a first-run error, retry without it
        if returncode != 0 and "cannot be specified on the first run" in stderr:
            args2 = [a for a in args if a != "--skip-db-update"]
            returncode, stdout, stderr = await self.run_command(args2)

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

        findings = self._parse_json_output(stdout, scan_type_label)

        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.SUCCESS,
            findings=findings,
            raw_output=stdout,
            duration_seconds=duration
        )

    async def _scan_image(self, image: str, kwargs: Dict) -> ScanResult:
        """Scan a Docker image."""
        start_time = time.time()

        args = self._build_base_args("image", image, kwargs, "image")
        args.extend(["--scanners", self._build_scanners_arg(kwargs)])
        return await self._run_trivy(args, "image", start_time)

    async def _scan_filesystem(self, path: str, kwargs: Dict) -> ScanResult:
        """Scan a filesystem for vulnerabilities and misconfigurations."""
        start_time = time.time()

        args = self._build_base_args("fs", path, kwargs, "fs")
        return await self._run_trivy(args, "fs", start_time)

    async def _scan_repo(self, repo: str, kwargs: Dict) -> ScanResult:
        """Scan a git repository."""
        start_time = time.time()

        args = self._build_base_args("repo", repo, kwargs, "repo")
        return await self._run_trivy(args, "repo", start_time)

    async def _scan_k8s(self, target: str, kwargs: Dict) -> ScanResult:
        """Scan Kubernetes cluster or manifests."""
        start_time = time.time()

        args = [self.command_name, "k8s", target]
        args.extend(["-f", "json", "-q", "--no-progress", "--skip-version-check"])
        severity = kwargs.get("severity", "HIGH,CRITICAL")
        args.extend(["--severity", severity])
        scanners = self._build_scanners_arg(kwargs)
        args.extend(["--scanners", scanners])
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)

        return await self._run_trivy(args, "k8s", start_time)

    async def _scan_config(self, path: str, kwargs: Dict) -> ScanResult:
        """Scan configuration files for misconfigurations."""
        start_time = time.time()

        args = self._build_base_args("config", path, kwargs, "config")
        return await self._run_trivy(args, "config", start_time)

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
                        "title": secret.get("Title", ""),
                        "description": f"[{secret.get('RuleID', '')}] {secret.get('Title', '')} in {target}:{secret.get('StartLine', 0)}",
                        "match": secret.get("Match", ""),
                        "file": target,  # filepath is in the parent result's Target field
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
        return await self._scan_filesystem(path, {"skip_db_update": False})

    async def scan_k8s_manifests(self, path: str) -> ScanResult:
        """Scan Kubernetes manifests for misconfigurations."""
        return await self._scan_config(path, {"scan_type": "config", "skip_db_update": False})
