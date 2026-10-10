"""
Gitleaks scanner for secret detection.
Used by the Code Review Agent to find hardcoded secrets, API keys, and credentials.
"""
import asyncio
import json
from typing import Dict, Any, List
from app.services.tools.base import BaseScanner, ScanResult, ScanStatus


class GitleaksScanner(BaseScanner):
    """Gitleaks secret detection scanner wrapper."""

    @property
    def tool_name(self) -> str:
        return "Gitleaks"

    @property
    def command_name(self) -> str:
        """Return the gitleaks executable name for PATH lookup."""
        return "gitleaks"

    async def check_installed(self) -> bool:
        """Check if gitleaks is installed and available on PATH."""
        # Standard PATH lookup — no hardcoded paths
        import shutil
        return shutil.which("gitleaks") is not None

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run Gitleaks scan against target codebase.

        Args:
            target: Path to code repository
            config: Path to gitleaks config file
            baseline: Path to baseline file
            extra_args: Additional gitleaks arguments

        Returns:
            ScanResult with secret findings
        """
        import time
        start_time = time.time()

        # Check if gitleaks is installed
        if not await self.check_installed():
            return self.create_not_installed_result()

        # Build gitleaks command
        args = [self.command_name, "detect", "--source", target]

        # Output format — gitleaks v8 requires -r - to write JSON report to stdout
        args.extend(["-f", "json", "-r", "-"])

        # Suppress banner/colors in stderr for cleaner logs
        args.extend(["--no-banner", "--no-color"])
        # Redact secrets in all output — never expose actual secret values
        args.append("--redact")

        # Verbose
        if kwargs.get("verbose", False):
            args.append("-v")

        # Config
        config = kwargs.get("config")
        if config:
            args.extend(["-c", config])

        # Baseline
        baseline = kwargs.get("baseline")
        if baseline:
            args.extend(["--baseline-path", baseline])

        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)

        # Run scan
        returncode, stdout, stderr = await self.run_command(args)
        duration = time.time() - start_time

        # Gitleaks returns 1 when leaks found, 0 when clean
        if returncode not in [0, 1]:
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
        """Parse Gitleaks JSON output into findings.

        Handles both JSON array format (gitleaks v8 with -r -) and JSONL format
        (older versions that output one JSON object per line).
        """
        findings = []

        try:
            # Try parsing as a single JSON document first (v8 array format with -r -)
            try:
                data = json.loads(json_output.strip())
                if isinstance(data, list):
                    results = data
                elif isinstance(data, dict):
                    results = [data]
                else:
                    results = []
            except json.JSONDecodeError:
                # Fall back to JSONL parsing (one object per line)
                results = []
                for line in json_output.strip().split('\n'):
                    if not line.strip():
                        continue
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            for result in results:
                # Extract leak info
                rule_id = result.get("RuleID", "")
                description = result.get("Description", "")
                secret = result.get("Secret", "")
                file = result.get("File", "")
                line_num = result.get("StartLine", 0)
                commit = result.get("Commit", "")
                author = result.get("Author", "")
                email = result.get("Email", "")
                date = result.get("Date", "")
                tag = result.get("Tag", "")

                # Mask secret for display — never store the full unmasked secret
                masked_secret = secret[:4] + "*" * (len(secret) - 8) + secret[-4:] if len(secret) > 8 else "****"
                # Ensure the masked secret is also redacted of any pattern matches
                from app.services.finding_normalizer import redact_sensitive_text
                masked_secret = redact_sensitive_text(masked_secret)

                findings.append({
                    "type": "secret_finding",
                    "tool": "gitleaks",
                    "rule_id": rule_id,
                    "severity": "HIGH",  # Secrets are always high severity
                    "file": file,
                    "line": line_num,
                    "secret": masked_secret,
                    # secret_full intentionally omitted — never store full secrets
                    "description": f"[{rule_id}] {description} found in {file}:{line_num}",
                    "commit": commit,
                    "author": author,
                    "email": email,
                    "date": date,
                    "tag": tag,
                    "remediation": self._get_remediation(rule_id, description)
                })
        except Exception:
            pass

        return findings

    def _get_remediation(self, rule_id: str, description: str) -> str:
        """Get remediation advice based on rule."""
        remediation_map = {
            "aws-access-key": "Rotate the AWS access key immediately. Remove from code and use IAM roles or AWS Secrets Manager.",
            "aws-secret-key": "Rotate the AWS secret key immediately. Remove from code and use IAM roles or AWS Secrets Manager.",
            "github-token": "Revoke the GitHub token immediately. Generate a new one and store securely.",
            "gitlab-token": "Revoke the GitLab token immediately. Generate a new one and store securely.",
            "slack-token": "Revoke the Slack token immediately. Generate a new one and store securely.",
            "stripe-key": "Revoke the Stripe key immediately. Generate a new one and store securely.",
            "generic-api-key": "Rotate the API key immediately. Store in environment variables or secret manager.",
            "private-key": "Rotate the private key immediately. Remove from code and use secure key storage.",
            "ssh-private-key": "Rotate the SSH key immediately. Remove from code and use SSH agent or key management.",
            "pgp-private-key": "Rotate the PGP key immediately. Remove from code and use secure key storage.",
            "jwt": "Rotate the JWT secret immediately. Use secure key storage.",
            "database-url": "Rotate database credentials immediately. Use environment variables for connection strings.",
            "docker-config": "Remove Docker config from code. Use Docker credential helpers.",
            "npm-token": "Revoke the NPM token immediately. Generate a new one and store securely.",
            "pypi-token": "Revoke the PyPI token immediately. Generate a new one and store securely.",
        }

        for key, remediation in remediation_map.items():
            if key in rule_id.lower() or key in description.lower():
                return remediation

        return "Immediately rotate/regenerate the exposed secret. Remove from source code and store in a secure secret management system (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)."

    async def scan_repo(self, target: str) -> ScanResult:
        """Scan a repository for secrets."""
        return await self.scan(target)
