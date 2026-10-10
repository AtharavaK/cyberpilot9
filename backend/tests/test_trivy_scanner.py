"""
Phase 7B: Trivy Scanner Tests.

Tests covering:
  - Scanner availability detection (installed/unavailable)
  - Configuration handling
  - Target handling (local filesystem paths, image names, git repos)
  - Output parsing (vulnerabilities, misconfigurations, secrets)
  - Severity filtering (valid + invalid values)
  - CWE/CVE extraction
  - Reference extraction
  - Evidence redaction
  - Canonical finding pipeline
  - Deduplication
  - Malformed JSON output
  - Empty results
  - Timeout handling
  - Connection / command failure
  - No shell=True / no command injection
"""
import asyncio
import json
import os
import shutil
import sys
from unittest.mock import AsyncMock, MagicMock, patch, ANY

import pytest

from app.services.tools.trivy_scanner import TrivyScanner
from app.services.tools.base import ScanResult, ScanStatus
from app.services.finding_normalizer import build_canonical_finding, dedup_findings


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def trivy_scanner():
    """A TrivyScanner with default config."""
    return TrivyScanner({"skip_db_update": True, "severity": "HIGH,CRITICAL"})


SAMPLE_TRIVY_RESULTS = {
    "SchemaVersion": 2,
    "CreatedAt": "2024-01-01T00:00:00Z",
    "ArtifactName": "/tmp/test_target",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "requirements.txt",
            "Class": "com.something",
            "Type": "python-pkg",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-12345",
                    "PkgName": "requests",
                    "InstalledVersion": "2.27.1",
                    "FixedVersion": "2.31.0",
                    "Severity": "MEDIUM",
                    "Title": "requests: some vulnerability",
                    "Description": "Requests is an HTTP library...",
                    "References": [
                        {"URL": "https://github.com/psf/requests/security/advisories/12345"},
                        {"URL": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"},
                    ],
                    "CVSS": {"3.1": {"Score": 5.3, "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}},
                    "CweIDs": ["CWE-200"],
                },
                {
                    "VulnerabilityID": "CVE-2024-67890",
                    "PkgName": "pyyaml",
                    "InstalledVersion": "5.4.1",
                    "FixedVersion": "6.0.1",
                    "Severity": "HIGH",
                    "Title": "PyYAML: arbitrary code execution",
                    "Description": "PyYAML 5.x allows arbitrary code execution.",
                    "References": [{"URL": "https://github.com/yaml/pyyaml/issues/123"}],
                    "CVSS": {},
                    "CweIDs": ["CWE-502"],
                },
            ],
        },
        {
            "Target": "config.yaml",
            "Class": "config",
            "Type": "yaml",
            "Misconfigurations": [
                {
                    "Type": "yaml",
                    "ID": "AVD-KSV0001",
                    "AVDID": "AVD-KSV0001",
                    "Severity": "HIGH",
                    "Title": "Misconfigured security policy",
                    "Description": "The configuration does not enforce security policies.",
                    "Message": "Missing security context",
                    "Resolution": "Add a security context to your configuration.",
                    "Namespace": "kubernetes",
                    "FilePath": "config.yaml",
                    "LineNumber": 15,
                    "Query": "deny",
                }
            ],
        },
        {
            "Target": "secrets.json",
            "Class": "secret",
            "Type": "json",
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Category": "aws",
                    "Severity": "HIGH",
                    "Title": "AWS Access Key ID",
                    "StartLine": 3,
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                },
                {
                    "RuleID": "github-pat",
                    "Category": "github",
                    "Severity": "HIGH",
                    "Title": "GitHub PAT",
                    "StartLine": 7,
                    "Match": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
                },
            ],
        },
    ],
}


# ── 1. Scanner Availability ────────────────────────────────────────────────

class TestTrivyAvailability:
    """Tests for Trivy availability detection."""

    async def test_trivy_installed(self, trivy_scanner):
        """check_installed returns True when trivy is on PATH."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        with patch("shutil.which", return_value="/usr/local/bin/trivy"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            assert await trivy_scanner.check_installed() is True

    async def test_trivy_not_installed(self):
        """check_installed returns False when trivy is not on PATH."""
        scanner = TrivyScanner({})
        with patch("shutil.which", return_value=None):
            assert await scanner.check_installed() is False

    async def test_check_available_true(self, trivy_scanner):
        """check_available returns True when trivy is installed."""
        with patch.object(trivy_scanner, "check_installed", AsyncMock(return_value=True)):
            available, detail = await trivy_scanner.check_available()
            assert available is True
            assert "available" in detail.lower()

    async def test_check_available_false(self, trivy_scanner):
        """check_available returns False when trivy is not installed."""
        with patch.object(trivy_scanner, "check_installed", AsyncMock(return_value=False)):
            available, detail = await trivy_scanner.check_available()
            assert available is False
            assert "not installed" in detail.lower() or "not in PATH" in detail.lower()


# ── 2. Target routing ──────────────────────────────────────────────────────

class TestTargetRouting:
    """Tests for scan_type auto-detection."""

    @pytest.mark.parametrize("target,scan_type,expected_method", [
        ("/local/path", "auto", "_scan_filesystem"),
        ("/tmp/test", "fs", "_scan_filesystem"),
        ("https://github.com/user/repo", "auto", "_scan_repo"),
        ("git@github.com:user/repo.git", "auto", "_scan_repo"),
        ("myimage:latest", "auto", "_scan_image"),
        ("myregistry.io/repo/app:v1.0", "auto", "_scan_image"),
    ])
    async def test_target_routing(self, trivy_scanner, target, scan_type, expected_method):
        """Targets are routed to the correct scan method."""
        method = getattr(trivy_scanner, expected_method)
        with patch.object(trivy_scanner, expected_method, new_callable=AsyncMock) as mock_method, \
             patch.object(trivy_scanner, "check_installed", AsyncMock(return_value=True)), \
             patch.object(trivy_scanner, "_run_trivy", AsyncMock()) as mock_run:
            mock_run.return_value = ScanResult(
                tool_name="Trivy", status=ScanStatus.SUCCESS, findings=[], raw_output="[]"
            )
            await trivy_scanner.scan(target, scan_type=scan_type, skip_db_update=True)
            assert mock_method.called

    async def test_not_installed_returns_not_installed(self):
        """Scan returns NOT_INSTALLED when trivy is not installed."""
        scanner = TrivyScanner({})
        with patch.object(scanner, "check_installed", AsyncMock(return_value=False)):
            result = await scanner.scan("/tmp/test", scan_type="fs")
            assert result.status == ScanStatus.NOT_INSTALLED
            assert result.findings == []


# ── 3. Severity filtering ────────────────────────────────────────────────

class TestSeverityFiltering:
    """Tests for severity filtering."""

    def test_filter_valid_severities(self, trivy_scanner):
        """Valid severities are kept."""
        result = trivy_scanner._filter_severity("HIGH,CRITICAL,MEDIUM")
        assert "HIGH" in result and "CRITICAL" in result and "MEDIUM" in result

    def test_filter_invalid_severity_info(self, trivy_scanner):
        """INFO is filtered out (not a Trivy severity)."""
        result = trivy_scanner._filter_severity("HIGH,MEDIUM,INFO")
        assert "INFO" not in result
        assert "HIGH" in result and "MEDIUM" in result

    def test_filter_all_invalid_defaults(self, trivy_scanner):
        """All invalid severities default to HIGH,CRITICAL."""
        result = trivy_scanner._filter_severity("FOO,BAR,BAZ")
        assert result == "HIGH,CRITICAL"

    def test_filter_empty(self, trivy_scanner):
        """Empty severity defaults to HIGH,CRITICAL."""
        result = trivy_scanner._filter_severity("")
        assert result == "HIGH,CRITICAL"


# ── 4. Output parsing ──────────────────────────────────────────────────────

class TestOutputParsing:
    """Tests for _parse_json_output."""

    def test_parse_vulnerabilities(self, trivy_scanner):
        """Vulnerabilities are parsed correctly."""
        findings = trivy_scanner._parse_json_output(
            json.dumps(SAMPLE_TRIVY_RESULTS), "fs"
        )
        vuln_findings = [f for f in findings if f["type"] == "vulnerability"]
        assert len(vuln_findings) == 2

        v = vuln_findings[0]
        assert v["vuln_id"] == "CVE-2024-12345"
        assert v["pkg_name"] == "requests"
        assert v["installed_version"] == "2.27.1"
        assert v["fixed_version"] == "2.31.0"
        assert v["severity"] == "MEDIUM"
        assert v["title"] == "requests: some vulnerability"
        assert v["cwe"] == ["CWE-200"]
        assert v["cve"] == "CVE-2024-12345"
        assert len(v["references"]) == 2

    def test_parse_misconfigurations(self, trivy_scanner):
        """Misconfigurations are parsed correctly."""
        findings = trivy_scanner._parse_json_output(
            json.dumps(SAMPLE_TRIVY_RESULTS), "fs"
        )
        misconfig_findings = [f for f in findings if f["type"] == "misconfiguration"]
        assert len(misconfig_findings) == 1

        m = misconfig_findings[0]
        assert m["rule_id"] == "AVD-KSV0001"
        assert m["severity"] == "HIGH"
        assert m["file"] == "config.yaml"
        assert m["line"] == 15

    def test_parse_secrets(self, trivy_scanner):
        """Secrets are parsed and redacted."""
        findings = trivy_scanner._parse_json_output(
            json.dumps(SAMPLE_TRIVY_RESULTS), "fs"
        )
        secret_findings = [f for f in findings if f["type"] == "secret"]
        assert len(secret_findings) == 2

        s = secret_findings[0]
        assert s["rule_id"] == "aws-access-key-id"
        assert s["severity"] == "HIGH"
        # Secret match should be redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in s["match"]

    def test_parse_empty_results(self, trivy_scanner):
        """Empty Results array produces no findings."""
        findings = trivy_scanner._parse_json_output(
            json.dumps({"Results": []}), "fs"
        )
        assert findings == []

    def test_parse_malformed_json(self, trivy_scanner):
        """Malformed JSON produces no findings (no crash)."""
        findings = trivy_scanner._parse_json_output(
            "this is not json", "fs"
        )
        assert findings == []

    def test_parse_missing_keys(self, trivy_scanner):
        """Results with missing keys are handled gracefully."""
        data = {"Results": [{"Target": "test.txt"}]}
        findings = trivy_scanner._parse_json_output(json.dumps(data), "fs")
        assert findings == []

    def test_parse_empty_output(self, trivy_scanner):
        """Empty string produces no findings."""
        findings = trivy_scanner._parse_json_output("", "fs")
        assert findings == []


# ── 5. Canonical Finding Pipeline ──────────────────────────────────────────

class TestCanonicalPipeline:
    """Tests for findings flowing through build_canonical_finding."""

    def test_vulnerability_canonical(self, trivy_scanner):
        """Vulnerability findings pass through canonical pipeline."""
        findings = trivy_scanner._parse_json_output(
            json.dumps(SAMPLE_TRIVY_RESULTS), "fs"
        )
        vuln = [f for f in findings if f["type"] == "vulnerability"][0]
        canonical = build_canonical_finding(vuln, "Infrastructure Agent", "trivy")
        assert canonical["tool"] == "trivy"
        assert canonical["severity"] == "MEDIUM"
        assert canonical["title"] == "requests: some vulnerability"
        assert "CVE-2024-12345" in canonical["cve"]
        assert "CWE-200" in canonical["cwe"]
        assert len(canonical["references"]) > 0
        assert "2.31.0" in canonical["remediation"]

    def test_misconfig_canonical(self, trivy_scanner):
        """Misconfiguration findings pass through canonical pipeline."""
        findings = trivy_scanner._parse_json_output(
            json.dumps(SAMPLE_TRIVY_RESULTS), "fs"
        )
        misconfig = [f for f in findings if f["type"] == "misconfiguration"][0]
        canonical = build_canonical_finding(misconfig, "Infrastructure Agent", "trivy")
        assert canonical["tool"] == "trivy"
        assert canonical["severity"] == "HIGH"
        assert canonical["rule_id"] == "AVD-KSV0001"
        assert canonical["file"] == "config.yaml"

    def test_secret_canonical(self, trivy_scanner):
        """Secret findings pass through canonical pipeline with redaction."""
        findings = trivy_scanner._parse_json_output(
            json.dumps(SAMPLE_TRIVY_RESULTS), "fs"
        )
        secret = [f for f in findings if f["type"] == "secret"][0]
        canonical = build_canonical_finding(secret, "Infrastructure Agent", "trivy")
        assert canonical["tool"] == "trivy"
        assert canonical["severity"] == "HIGH"
        assert canonical["rule_id"] == "aws-access-key-id"
        # Secret value must not appear in evidence
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(canonical)


# ── 6. Deduplication ───────────────────────────────────────────────────────

class TestDeduplication:
    """Tests for finding deduplication."""

    def test_duplicate_findings_deduplicated(self, trivy_scanner):
        """Identical findings are deduplicated."""
        findings = trivy_scanner._parse_json_output(
            json.dumps(SAMPLE_TRIVY_RESULTS), "fs"
        )
        # Add a duplicate
        findings.append(findings[0])
        deduped = dedup_findings(findings)
        assert len(deduped) < len(findings)


# ── 7. Timeout handling ───────────────────────────────────────────────────

class TestTimeoutHandling:
    """Tests for timeout behavior."""

    async def test_scan_timeout(self, trivy_scanner):
        """Scan respects timeout from config."""
        scanner = TrivyScanner({"timeout": 1, "skip_db_update": True})
        with patch.object(scanner, "check_installed", AsyncMock(return_value=True)), \
             patch.object(scanner, "_run_trivy", AsyncMock(side_effect=asyncio.TimeoutError())):
            result = await scanner.scan("/tmp/test", scan_type="fs", skip_db_update=True)
            assert result.status in (ScanStatus.FAILED, ScanStatus.TIMEOUT)


# ── 8. Command injection safety ───────────────────────────────────────────

class TestCommandInjectionSafety:
    """Trivy scanner must not allow command or argument injection."""

    def test_no_shell_true(self, trivy_scanner):
        """Trivy scanner never uses shell=True."""
        import inspect
        source = inspect.getsource(trivy_scanner.__class__)
        assert "shell=True" not in source

    def test_no_os_system(self, trivy_scanner):
        """Trivy scanner never uses os.system."""
        import inspect
        source = inspect.getsource(trivy_scanner.__class__)
        assert "os.system" not in source

    def test_target_with_shell_chars(self, trivy_scanner):
        """Target with shell metacharacters is handled safely (passed as exec args, not shell)."""
        # The scanner uses asyncio.create_subprocess_exec which does NOT use shell
        # So shell metacharacters are safe — they're just part of the argument string
        malicious_target = "/tmp/test; rm -rf /"
        args = trivy_scanner._build_base_args("fs", malicious_target, {"skip_db_update": True}, "fs")
        # The target is a single argument element, not interpreted by a shell
        assert malicious_target in args


# ── 9. Failure handling ─────────────────────────────────────────────────────
#
# Verifies graceful degradation when Trivy encounters problems that should
# NOT crash the scan orchestration layer.


class TestFailureHandling:
    """Trivy scanner graceful-degradation under various failure modes."""

    async def test_trivy_unavailable(self):
        """Scan returns NOT_INSTALLED status when trivy is not on PATH."""
        scanner = TrivyScanner({})
        with patch("shutil.which", return_value=None):
            result = await scanner.scan("/tmp/test", scan_type="fs")
        assert result.status == ScanStatus.NOT_INSTALLED
        assert result.findings == []
        assert "not installed" in result.error.lower() or "not in PATH" in result.error.lower()

    async def test_invalid_target(self, trivy_scanner):
        """Trivy error on invalid target returns FAILED status, not a crash."""
        with patch.object(trivy_scanner, "check_installed", AsyncMock(return_value=True)), \
             patch.object(trivy_scanner, "run_command", AsyncMock(return_value=(2, "", "no such file or directory"))):
            result = await trivy_scanner.scan("/nonexistent/path/xyz123", scan_type="fs")
        assert result.status == ScanStatus.FAILED
        assert result.findings == []

    async def test_empty_output(self, trivy_scanner):
        """Empty JSON output produces no findings without crashing."""
        with patch.object(trivy_scanner, "check_installed", AsyncMock(return_value=True)), \
             patch.object(trivy_scanner, "run_command", AsyncMock(return_value=(0, "", ""))):
            result = await trivy_scanner.scan("/tmp/test", scan_type="fs")
        assert result.status == ScanStatus.SUCCESS
        assert result.findings == []

    async def test_malformed_output(self, trivy_scanner):
        """Malformed (non-JSON) output produces no findings without crashing."""
        with patch.object(trivy_scanner, "check_installed", AsyncMock(return_value=True)), \
             patch.object(trivy_scanner, "run_command", AsyncMock(return_value=(0, "not json", ""))):
            result = await trivy_scanner.scan("/tmp/test", scan_type="fs")
        assert result.status == ScanStatus.SUCCESS
        assert result.findings == []

    async def test_db_update_failure_handled(self, trivy_scanner):
        """Trivy exits 0 even when DB update is skipped; scanner still parses."""
        # Simulate trivy running successfully (return code 1 is valid for trivy
        # when vulnerabilities are found, but we test code 0 with DB error in stderr)
        trivy_output = json.dumps({"SchemaVersion": 2, "Results": []})
        with patch.object(trivy_scanner, "check_installed", AsyncMock(return_value=True)), \
             patch.object(trivy_scanner, "run_command", AsyncMock(return_value=(0, trivy_output, "DB update failed"))):
            result = await trivy_scanner.scan("/tmp/test", scan_type="fs")
        assert result.status == ScanStatus.SUCCESS
        assert result.findings == []

    async def test_trivy_internal_error(self, trivy_scanner):
        """Trivy crashes with exit code 2 → FAILED status."""
        with patch.object(trivy_scanner, "check_installed", AsyncMock(return_value=True)), \
             patch.object(trivy_scanner, "run_command", AsyncMock(return_value=(2, "", "internal error"))):
            result = await trivy_scanner.scan("/tmp/test", scan_type="fs")
        assert result.status == ScanStatus.FAILED
        assert "internal error" in result.error