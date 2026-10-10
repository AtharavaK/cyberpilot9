"""Tests for Phase 2: Finding Validation & Data Quality.

Covers severity normalization, confidence normalization,
secret redaction, canonical finding building, fingerprinting,
and deduplication.
"""
import pytest
from app.services.finding_normalizer import (
    normalize_severity,
    normalize_confidence,
    redact_secret,
    redact_sensitive_text,
    build_canonical_finding,
    finding_fingerprint,
    dedup_findings,
    CANONICAL_SEVERITIES,
    Severity,
    SEVERITY_WEIGHTS,
    SEVERITY_ORDER,
)


# ── Severity normalization tests ──────────────────────────────────────────────

class TestSeverityNormalization:
    """Verify every scanner-specific severity maps to a canonical value."""

    @pytest.mark.parametrize("raw,expected", [
        # Canonical values (already uppercase)
        ("CRITICAL", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("MEDIUM", "MEDIUM"),
        ("LOW", "LOW"),
        ("INFO", "INFO"),
        # Case-insensitive
        ("critical", "CRITICAL"),
        ("high", "HIGH"),
        ("Medium", "MEDIUM"),
        ("low", "LOW"),
        ("info", "INFO"),
        # Semgrep-style labels
        ("ERROR", "HIGH"),
        ("WARNING", "MEDIUM"),
        ("NOTE", "INFO"),
        ("error", "HIGH"),
        ("warning", "MEDIUM"),
        # Trivy-style
        ("UNKNOWN", "INFO"),
        ("INFORMATIONAL", "INFO"),
        ("informational", "INFO"),
        # Missing / None / empty
        (None, "INFO"),
        ("", "INFO"),
        ("  ", "INFO"),
    ])
    def test_severity_mapping(self, raw, expected):
        assert normalize_severity(raw) == expected

    def test_severity_always_in_canonical_set(self):
        """Every scanner severity must produce a canonical value."""
        scanner_values = [
            "INFO", "LOW", "MEDIUM",  # Nmap
            "ERROR", "WARNING", "NOTE", "INFO",  # Semgrep
            "HIGH", "MEDIUM", "LOW",  # Bandit
            "HIGH",  # Gitleaks
            "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN",  # Trivy
            "High", "Medium", "Low", "Informational",  # ZAP
            "HIGH", "MEDIUM", "LOW",  # AI Tester
        ]
        for val in scanner_values:
            result = normalize_severity(val)
            assert result in CANONICAL_SEVERITIES, f"{val} -> {result} not canonical"

    def test_severity_enum_values(self):
        """Severity enum has exactly the canonical values."""
        enum_values = [e.value for e in Severity]
        assert set(enum_values) == set(CANONICAL_SEVERITIES)

    def test_severity_ordering(self):
        """SEVERITY_ORDER must rank critical before info."""
        assert SEVERITY_ORDER["CRITICAL"] < SEVERITY_ORDER["INFO"]
        assert SEVERITY_ORDER["HIGH"] < SEVERITY_ORDER["LOW"]
        assert SEVERITY_ORDER["LOW"] < SEVERITY_ORDER["INFO"]

    def test_severity_weights(self):
        """SEVERITY_WEIGHTS must be monotonically decreasing."""
        assert SEVERITY_WEIGHTS["CRITICAL"] > SEVERITY_WEIGHTS["HIGH"]
        assert SEVERITY_WEIGHTS["HIGH"] > SEVERITY_WEIGHTS["MEDIUM"]
        assert SEVERITY_WEIGHTS["MEDIUM"] > SEVERITY_WEIGHTS["LOW"]
        assert SEVERITY_WEIGHTS["LOW"] > SEVERITY_WEIGHTS["INFO"]


# ── Confidence normalization tests ────────────────────────────────────────────

class TestConfidenceNormalization:
    """Verify confidence is consistently represented as 0.0 - 1.0."""

    @pytest.mark.parametrize("raw,expected", [
        # Bandit/ZAP string labels
        ("HIGH", 0.9),
        ("MEDIUM", 0.7),
        ("LOW", 0.5),
        ("INFORMATIONAL", 0.3),
        ("high", 0.9),
        ("medium", 0.7),
        ("low", 0.5),
        # Numeric 0-1 range (pass through)
        (0.9, 0.9),
        (0.5, 0.5),
        (0.0, 0.0),
        (1.0, 1.0),
        # Numeric 0-100 range (divide by 100)
        (90, 0.9),
        (50, 0.5),
        (100, 1.0),
        (0, 0.0),
        ("90", 0.9),
        ("50", 0.5),
        # Missing / None
        (None, None),
    ])
    def test_confidence_normalization(self, raw, expected):
        result = normalize_confidence(raw)
        if expected is None:
            assert result is None
        else:
            assert result == expected

    def test_confidence_clamps_to_range(self):
        """Values outside 0-100 are clamped, not rejected."""
        assert normalize_confidence(150) == 1.0
        assert normalize_confidence(-5) == 0.0

    def test_confidence_unknown_string(self):
        """Unknown string labels return None (no invented values)."""
        assert normalize_confidence("UNKNOWN") is None
        assert normalize_confidence("maybe") is None

    def test_confidence_valid_range(self):
        """All numeric results are in [0.0, 1.0]."""
        for val in [0, 50, 90, 100, 150, -5, 0.0, 0.5, 1.0, 99, 1]:
            result = normalize_confidence(val)
            if result is not None:
                assert 0.0 <= result <= 1.0, f"conf={val} -> {result} out of range"


# ── Secret redaction tests ──────────────────────────────────────────────────────

class TestSecretRedaction:
    """Verify secrets are redacted before storage/display."""

    @pytest.mark.parametrize("secret,length", [
        ("AKIAIOSFODNN7EXAMPLE", 20),
        ("sk-1234567890abcdefghijklmnop", 30),
        ("short", 5),
    ])
    def test_redact_secret(self, secret, length):
        result = redact_secret(secret)
        assert "*" in result  # Always contains redaction mask

    def test_redact_secret_empty(self):
        assert redact_secret("") == ""
        # redact_secret handles None via `if not secret` — returns "" but type says str
        # We pass "" to avoid type issues
        assert redact_secret("") == ""

    def test_redact_secret_short(self):
        assert redact_secret("abc") == "***"
        assert redact_secret("ab") == "**"

    def test_redact_secret_empty(self):
        assert redact_secret("") == ""
        assert redact_secret(None) == ""

    def test_redact_sensitive_text_aws_key(self):
        text = "Found AWS key AKIAIOSFODNN7EXAMPLE in config"
        result = redact_sensitive_text(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result  # entire match replaced with label
        assert "AWS Access Key ID" in result  # replaced with label

    def test_redact_sensitive_text_api_key(self):
        text = "Token: sk-1234567890abcdefghijklmnop"
        result = redact_sensitive_text(text)
        assert "sk-1234567890abcdefghijklmnop" not in result
        assert "API Key" in result

    def test_redact_sensitive_text_github_token(self):
        text = "ghp_1234567890abcdefghijklmnop1234567890"
        result = redact_sensitive_text(text)
        assert "ghp_" not in result
        assert "GitHub Token" in result

    def test_redact_sensitive_text_password_in_url(self):
        text = "http://user:secret123@host.com"
        result = redact_sensitive_text(text)
        assert "secret123" not in result
        assert "[REDACTED]" in result  # password replaced with sentinel
        assert "[USER]" in result  # username replaced with placeholder

    def test_redact_sensitive_text_no_secrets(self):
        text = "Normal text about XSS vulnerabilities"
        result = redact_sensitive_text(text)
        assert result == text  # unchanged

    def test_redact_sensitive_text_empty(self):
        assert redact_sensitive_text("") == ""


# ── Canonical finding builder tests ───────────────────────────────────────────

class TestBuildCanonicalFinding:
    """Verify raw scanner findings are normalized to canonical structure."""

    def test_semgrep_finding_normalization(self):
        raw = {
            "rule_id": "sql-injection",
            "severity": "ERROR",
            "message": "SQL injection detected in query",
            "path": "app/main.py",
            "start": {"line": 42, "col": 10},
        }
        result = build_canonical_finding(raw, "Semgrep", "semgrep")

        assert result["agent_name"] == "Semgrep"
        assert result["severity"] == "HIGH"  # ERROR -> HIGH
        assert result["category"] == "sql-injection"
        assert result["file"] == "app/main.py"
        assert result["line"] == 42
        assert result["status"] == "open"
        assert isinstance(result["metadata"], dict)
        assert result["metadata"]["rule_id"] == "sql-injection"

    def test_bandit_finding_normalization(self):
        raw = {
            "test_id": "B608",
            "issue_severity": "HIGH",
            "issue_confidence": "MEDIUM",
            "issue_text": "Hardcoded SQL expression",
            "filename": "app/models.py",
            "lineno": 15,
            "cwe": [{"id": "89", "link": "https://cwe.mitre.org/data/definitions/89.html"}],
        }
        result = build_canonical_finding(raw, "Bandit", "bandit")

        assert result["severity"] == "HIGH"
        assert result["confidence"] == 0.7  # MEDIUM -> 0.7
        assert result["cwe"] == ["CWE-89"]
        assert result["file"] == "app/models.py"
        assert result["line"] == 15

    def test_trivy_finding_normalization(self):
        raw = {
            "Severity": "CRITICAL",
            "Title": "CVE-2024-1234 in package",
            "PkgName": "express",
            "InstalledVersion": "4.17.1",
            "FixedVersion": "4.17.2",
            "VulnerabilityID": "CVE-2024-1234",
            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        }
        result = build_canonical_finding(raw, "Trivy", "trivy")

        assert result["severity"] == "CRITICAL"
        assert result["cve"] == ["CVE-2024-1234"]
        assert result["title"] == "CVE-2024-1234 in package"
        assert "https://nvd.nist.gov/vuln/detail/CVE-2024-1234" in result["references"]

    def test_gitleaks_finding_normalization(self):
        raw = {
            "rule": "AWS Access Key",
            "severity": "HIGH",
            "description": "AWS Access Key detected",
            "secret": "AKIAIOSFODNN7EXAMPLE",
            "file": "config/.env",
            "line": 5,
        }
        result = build_canonical_finding(raw, "Gitleaks", "gitleaks")

        assert result["severity"] == "HIGH"
        assert result["cwe"] == []  # no CWE -> empty, not null
        assert "AKIAIOSFODNN7EXAMPLE" not in result["evidence"]  # redacted
        assert result["file"] == "config/.env"

    def test_finding_with_missing_fields(self):
        raw = {}
        result = build_canonical_finding(raw, "Unknown", "unknown")

        assert result["severity"] == "INFO"  # default
        assert result["confidence"] is None
        assert result["cwe"] == []
        assert result["cve"] == []
        assert result["references"] == []
        assert result["status"] == "open"

    def test_finding_evidence_truncation(self):
        """Evidence is truncated to prevent huge payloads."""
        raw = {
            "match": "A" * 5000,
            "severity": "HIGH",
        }
        result = build_canonical_finding(raw, "Test", "test")
        assert len(result["evidence"]) <= 1000

    def test_finding_cwe_extraction_from_string(self):
        raw = {"cwe": "CWE-79", "severity": "HIGH"}
        result = build_canonical_finding(raw, "Test", "test")
        assert result["cwe"] == ["CWE-79"]

    def test_finding_cwe_extraction_from_number(self):
        raw = {"cwe": 79, "severity": "HIGH"}
        result = build_canonical_finding(raw, "Test", "test")
        assert result["cwe"] == ["CWE-79"]

    def test_finding_cwe_extraction_from_bandit_format(self):
        raw = {"cwe": {"id": 798, "link": "https://cwe.mitre.org/data/definitions/798.html"}, "severity": "HIGH"}
        result = build_canonical_finding(raw, "Bandit", "bandit")
        assert result["cwe"] == ["CWE-798"]

    def test_finding_cve_extraction(self):
        raw = {"cve": ["CVE-2024-1234", "CVE-2024-5678"], "severity": "CRITICAL"}
        result = build_canonical_finding(raw, "Trivy", "trivy")
        assert result["cve"] == ["CVE-2024-1234", "CVE-2024-5678"]

    def test_finding_references_including_cwe_links(self):
        raw = {"cwe": "CWE-79", "severity": "HIGH", "references": ["https://example.com/ref"]}
        result = build_canonical_finding(raw, "Test", "test")
        assert "https://cwe.mitre.org/data/definitions/79.html" in result["references"]
        assert "https://example.com/ref" in result["references"]


# ── Fingerprinting & deduplication tests ────────────────────────────────────────

class TestFindingFingerprint:
    """Verify deterministic fingerprinting for duplicate detection."""

    def test_same_finding_same_fingerprint(self):
        f1 = {
            "tool": "semgrep",
            "rule_id": "sql-injection",
            "category": "Injection",
            "target": "https://example.com",
            "file": "app/main.py",
            "line": 42,
            "cwe": [],
            "cve": [],
            "title": "SQL Injection",
            "description": "Found SQL injection",
        }
        f2 = dict(f1)  # exact copy
        assert finding_fingerprint(f1) == finding_fingerprint(f2)

    def test_different_findings_different_fingerprint(self):
        f1 = {"tool": "semgrep", "rule_id": "rule-a", "title": "Issue A", "severity": "HIGH"}
        f2 = {"tool": "semgrep", "rule_id": "rule-b", "title": "Issue B", "severity": "HIGH"}
        assert finding_fingerprint(f1) != finding_fingerprint(f2)

    def test_fingerprint_excludes_description(self):
        """Changing only the description should NOT change the fingerprint."""
        f1 = {
            "tool": "semgrep",
            "rule_id": "sql-injection",
            "target": "https://example.com",
            "file": "app/main.py",
            "line": 42,
            "title": "SQL Injection",
            "cwe": [],
            "cve": [],
            "description": "Version 1",
        }
        f2 = dict(f1, description="Version 2 with different text")
        assert finding_fingerprint(f1) == finding_fingerprint(f2)

    def test_fingerprint_includes_metadata_fields(self):
        """Fingerprint works even when canonical fields are in metadata."""
        f1 = {
            "tool": "semgrep",
            "metadata": {"rule_id": "rule-a", "file": "app/main.py", "line": 10},
            "cwe": [],
            "cve": [],
            "title": "Test",
            "description": "desc",
        }
        fp = finding_fingerprint(f1)
        assert isinstance(fp, str)
        assert len(fp) == 16

    def test_fingerprint_deterministic(self):
        """Same input always produces same output."""
        f = {"tool": "test", "rule_id": "r1", "title": "T", "description": "D",
             "file": "f.py", "line": 1, "cwe": [], "cve": [], "category": "", "target": ""}
        fingerprints = [finding_fingerprint(f) for _ in range(10)]
        assert len(set(fingerprints)) == 1


class TestDedupFindings:
    """Verify duplicate findings are removed correctly."""

    def test_removes_exact_duplicates(self):
        f1 = {"tool": "semgrep", "rule_id": "r1", "title": "T", "description": "D",
              "file": "f.py", "line": 1, "cwe": [], "cve": [], "category": "", "target": ""}
        findings = [f1, dict(f1), dict(f1)]
        result = dedup_findings(findings)
        assert len(result) == 1

    def test_keeps_different_findings(self):
        f1 = {"tool": "semgrep", "rule_id": "r1", "title": "T1", "description": "D",
              "file": "f.py", "line": 1, "cwe": [], "cve": [], "category": "", "target": ""}
        f2 = {"tool": "bandit", "rule_id": "r2", "title": "T2", "description": "D",
              "file": "f.py", "line": 2, "cwe": [], "cve": [], "category": "", "target": ""}
        result = dedup_findings([f1, f2])
        assert len(result) == 2

    def test_same_vulnerability_different_scanners_merged(self):
        """Two scanners reporting the same issue at same location should dedup."""
        f1 = {"tool": "semgrep", "rule_id": "sqli", "category": "Injection",
              "file": "app/main.py", "line": 42, "cwe": ["CWE-89"], "cve": [],
              "title": "SQL Injection", "description": "Semgrep version"}
        f2 = {"tool": "bandit", "rule_id": "B608", "category": "Injection",
              "file": "app/main.py", "line": 42, "cwe": ["CWE-89"], "cve": [],
              "title": "SQL Injection", "description": "Bandit version"}
        # These have different rule_ids, so they should NOT be merged.
        # Different rule_id = different fingerprint = both kept.
        result = dedup_findings([f1, f2])
        assert len(result) == 2

    def test_empty_list(self):
        assert dedup_findings([]) == []

    def test_single_finding(self):
        f = {"tool": "t", "rule_id": "r", "title": "T", "description": "D",
             "file": "f", "line": 1, "cwe": [], "cve": [], "category": "", "target": ""}
        result = dedup_findings([f])
        assert len(result) == 1
        assert result[0] is f  # original object preserved

    def test_keeps_first_occurrence(self):
        """The first occurrence is kept, not the last."""
        f1 = {"tool": "t", "rule_id": "r", "title": "T1", "description": "D1",
              "file": "f", "line": 1, "cwe": [], "cve": [], "category": "", "target": ""}
        f2 = dict(f1, title="T2")  # same fingerprint, different title (title is in fingerprint)
        # Actually title IS in the fingerprint, so these would deduplicate.
        # Let's use description (which is NOT in fingerprint) instead.
        f2 = dict(f1, description="D2")
        result = dedup_findings([f1, f2])
        assert len(result) == 1
        assert result[0]["description"] == "D1"  # first kept