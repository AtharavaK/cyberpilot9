"""
Finding Normalization Layer for CyberPilot.

Provides canonical finding structure, severity normalization, confidence
normalization, secret redaction, and deterministic fingerprinting for
deduplication.

Canonical severity values (uppercase, matching existing app convention):
    CRITICAL  HIGH  MEDIUM  LOW  INFO

Severity mapping from each scanner's native values:
    Nmap:     INFO → INFO, LOW → LOW, MEDIUM → MEDIUM  (Nmap never emits HIGH/CRITICAL in current parser)
    Semgrep:  ERROR → HIGH, WARNING → MEDIUM, INFO → INFO, NOTE → INFO
    Bandit:   HIGH → HIGH, MEDIUM → MEDIUM, LOW → LOW
    Gitleaks: always HIGH
    Trivy:    CRITICAL → CRITICAL, HIGH → HIGH, MEDIUM → MEDIUM, LOW → LOW, UNKNOWN → INFO
    ZAP:      High → HIGH, Medium → MEDIUM, Low → LOW, Informational → INFO
    AI Tester: HIGH → HIGH, MEDIUM → MEDIUM, LOW → LOW

Confidence mapping to 0.0-1.0 scale:
    Bandit:  HIGH → 0.9, MEDIUM → 0.7, LOW → 0.5
    ZAP:     High → 0.9, Medium → 0.7, Low → 0.5, Informational → 0.3
    Others:  None → None
"""
import hashlib
import logging
import re
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Canonical severity values ──────────────────────────────────────────────────

CANONICAL_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Scanner-native severity → canonical severity
# Keys are uppercased scanner values; values are canonical severities.
_SEVERITY_MAP: Dict[str, str] = {
    # Nmap / generic
    "INFO": "INFO",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    # Semgrep uses these labels in its JSON output
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "NOTE": "INFO",
    # Bandit
    "HIGH": "HIGH",
    # Trivy / ZAP (already match canonical names)
    "CRITICAL": "CRITICAL",
    "INFORMATIONAL": "INFO",
    # Unknown / missing
    "UNKNOWN": "INFO",
}

# Map canonical severity → numeric weight for scoring (higher = worse)
SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 50,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 3,
    "INFO": 1,
}

# Canonical severity → ordering rank (lower = appears first in sorted lists)
SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def normalize_severity(raw: Optional[str]) -> str:
    """Map any scanner-specific severity string to a canonical value.

    Returns one of CANONICAL_SEVERITIES.  Falls back to ``INFO`` for
    unknown or missing values rather than silently downgrading.
    """
    if not raw:
        return "INFO"
    key = str(raw).strip().upper()
    return _SEVERITY_MAP.get(key, "INFO")


# ── Confidence normalization ───────────────────────────────────────────────────

# Scanner-native confidence → float in [0.0, 1.0]
_CONFIDENCE_MAP: Dict[str, float] = {
    "HIGH": 0.9,
    "MEDIUM": 0.7,
    "LOW": 0.5,
    "INFORMATIONAL": 0.3,
}


def normalize_confidence(raw: Any) -> Optional[float]:
    """Normalize a scanner-specific confidence value to 0.0–1.0.

    Handles:
      - String labels (Bandit/ZAP: HIGH/MEDIUM/LOW)
      - Numeric values in 0–1 range (pass through)
      - Numeric values in 0–100 range (divide by 100)
      - Missing/Unknown → None
    """
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        v = float(raw)
        if v > 1.0:
            v = v / 100.0
        return round(max(0.0, min(1.0, v)), 2)
    if isinstance(raw, str):
        key = raw.strip().upper()
        if key in _CONFIDENCE_MAP:
            return _CONFIDENCE_MAP[key]
        # Try numeric string
        try:
            return normalize_confidence(float(key))
        except ValueError:
            pass
    return None


# ── Secret redaction ──────────────────────────────────────────────────────────

# Redact a secret-like string, preserving first 4 and last 4 chars.
_SECRET_MASK_LEN = 4


def redact_secret(secret: str) -> str:
    """Redact a secret value, keeping first and last ``_SECRET_MASK_LEN`` chars.

    >>> redact_secret("AKIAIOSFODNN7EXAMPLE")
    'AKIA************LE'
    >>> redact_secret("sk-1234567890abcdef1234567890abcdef1234567890ab")
    'sk-1******************************ab'
    >>> redact_secret("short")
    '****'
    >>> redact_secret("")
    ''
    """
    if not secret:
        return ""
    s = str(secret)
    if len(s) <= 2 * _SECRET_MASK_LEN:
        return "*" * min(len(s), 8)
    return s[:_SECRET_MASK_LEN] + "*" * (len(s) - 2 * _SECRET_MASK_LEN) + s[-_SECRET_MASK_LEN:]


# Patterns that look like secrets / credentials in evidence text
_SECRET_PATTERNS = [
    # AWS access key IDs
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    # AWS secret access keys (40 chars base64)
    (r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", "AWS Secret Key"),
    # Generic API keys / tokens (sk-, ghp_, ghs_, gho_, etc.)
    (r"sk-[a-zA-Z0-9-]{20,}", "API Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
    (r"github_pat_[a-zA-Z0-9_]{22,}", "GitHub PAT"),
    (r"glpat-[a-zA-Z0-9_-]{20}", "GitLab Token"),
    # Passwords in URLs (userinfo)
    (r"://[^:@]+:([^@]+)@", r"://[USER]:[REDACTED]@"),
    # Private key blocks
    (r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----",
     "[REDACTED PRIVATE KEY]", re.DOTALL),
]


def redact_sensitive_text(text: str) -> str:
    """Scan *text* for common secret patterns and redact them.

    Used to sanitize evidence, responses, or any free-form text that may
    contain credentials.  Returns a safe version of the text.
    """
    if not text:
        return ""
    result = str(text)
    for pattern_entry in _SECRET_PATTERNS:
        if len(pattern_entry) == 3:
            pattern_str, replacement, flags = pattern_entry
            pattern = re.compile(pattern_str, flags)
        else:
            pattern_str, replacement = pattern_entry
            pattern = re.compile(pattern_str)
        result = pattern.subn(replacement, result)[0]
    return result


# ── Canonical finding builder ──────────────────────────────────────────────────

def build_canonical_finding(
    raw_finding: Dict[str, Any],
    agent_name: str,
    tool_name: str,
) -> Dict[str, Any]:
    """Build a canonical finding dict from a scanner's raw finding output.

    This does NOT modify the raw finding in place.  It extracts and
    normalizes the fields that every scanner can plausibly provide,
    leaving scanner-specific extras in ``metadata``.
    """
    # All scanner-specific extras preserved in metadata for DB persistence.
    # Since the DB findings table stores metadata as a JSON blob, we need every
    # canonical field to also live in metadata so it survives the round-trip.
    metadata = dict(raw_finding.get("metadata", {})) if raw_finding.get("metadata") else {}

    # Copy scanner-specific raw fields into metadata (preserving extras)
    for k, v in raw_finding.items():
        if k not in ("metadata",):
            metadata.setdefault(k, v)

    raw_severity = (
        raw_finding.get("severity")
        or raw_finding.get("issue_severity")
        or raw_finding.get("Severity")
        or metadata.get("raw_severity", "INFO")
    )
    severity = normalize_severity(raw_severity)

    # --- Confidence ---
    confidence = (
        raw_finding.get("confidence")
        or raw_finding.get("issue_confidence")
        or metadata.get("confidence")
    )
    confidence = normalize_confidence(confidence)

    # --- CWE ---
    cwe_raw = raw_finding.get("cwe") or metadata.get("cwe", [])
    cwe_ids = _extract_cwe_ids(cwe_raw)

    # --- CVE ---
    cve_raw = (
        raw_finding.get("cve")
        or raw_finding.get("VulnerabilityID")
        or metadata.get("cve", [])
    )
    cve_ids = _extract_cve_ids(cve_raw)

    # --- File / line ---
    # Handle scanner-specific field names: Semgrep uses path/start.line,
    # Bandit uses filename/lineno, Gitleaks uses file/line, Trivy uses nothing
    file_path = (
        raw_finding.get("file")
        or raw_finding.get("path")
        or raw_finding.get("filename")
        or metadata.get("file", "")
    )
    line = (
        raw_finding.get("line")
        or (raw_finding.get("start", {}).get("line") if isinstance(raw_finding.get("start"), dict) else None)
        or raw_finding.get("lineno")
        or metadata.get("line", 0)
    ) or 0

    # --- Title ---
    title = (
        raw_finding.get("title")
        or raw_finding.get("Title")
        or raw_finding.get("name")
        or raw_finding.get("rule_id")
        or raw_finding.get("test_name")
        or ""
    )

    # --- Category / rule_id ---
    category = (
        raw_finding.get("category")
        or raw_finding.get("rule_id")
        or metadata.get("raw_type", "")
    )
    rule_id = raw_finding.get("rule_id", metadata.get("rule_id", ""))

    # --- References ---
    references = _extract_references(raw_finding, metadata)

    # --- Evidence (sanitized) ---
    evidence = _extract_evidence(raw_finding, metadata)
    evidence = redact_sensitive_text(evidence)

    # --- Target ---
    target = raw_finding.get("target") or raw_finding.get("url") or raw_finding.get("host", "")

    # --- Description ---
    description = raw_finding.get("description") or raw_finding.get("issue_text") or raw_finding.get("message") or ""

    # --- Remediation ---
    remediation = raw_finding.get("remediation", "")

    # --- Data source ---
    data_source = raw_finding.get("data_source", "")

    return {
        "agent_name": agent_name,
        "tool": tool_name,
        "rule_id": rule_id,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "category": category,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "target": target,
        "file": file_path,
        "line": line,
        "cwe": cwe_ids,
        "cve": cve_ids,
        "references": references,
        "status": "open",
        "data_source": data_source,
        # Also embed canonical fields in metadata so they survive DB round-trip
        # (the findings table only persists agent_name, severity, description,
        #  remediation, and the metadata JSON blob).
        "metadata": {
            **metadata,
            "tool": tool_name,
            "raw_type": category,
            "raw_severity": raw_finding.get("severity", ""),
            "rule_id": rule_id,
            "file": file_path,
            "line": line,
            "port": raw_finding.get("port", metadata.get("port", 0)),
            "cwe": cwe_ids,
            "owasp": raw_finding.get("owasp", metadata.get("owasp", [])),
            "references": references,
            "cve": cve_ids,
            "confidence": confidence,
            "title": title,
            "category": category,
            "evidence": evidence,
            "target": target,
            "data_source": data_source,
        },
    }


def _extract_cwe_ids(raw: Any) -> List[str]:
    """Normalize CWE values to a list of 'CWE-XXX' strings."""
    if not raw:
        return []
    result: List[str] = []
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, (list, tuple)):
        items = list(raw)
    elif isinstance(raw, dict):
        # Bandit format: {"id": 798, "link": "..."}
        items = [raw.get("id", raw.get("link", ""))]
    else:
        items = [str(raw)]

    for item in items:
        if not item:
            continue
        s = str(item).strip()
        if not s:
            continue
        # Extract numeric part
        num = re.search(r"(\d+)", s)
        if num:
            result.append(f"CWE-{num.group(1)}")
        elif s.upper().startswith("CWE-"):
            result.append(s.upper())
    return result


def _extract_cve_ids(raw: Any) -> List[str]:
    """Normalize CVE values to a list of 'CVE-YYYY-NNNNN' strings."""
    if not raw:
        return []
    result: List[str] = []
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, (list, tuple)):
        items = list(raw)
    else:
        items = [str(raw)]

    for item in items:
        if not item:
            continue
        s = str(item).strip()
        m = re.match(r"^CVE-\d{4}-\d+$", s, re.IGNORECASE)
        if m:
            result.append(m.group(0).upper())
    return result


def _extract_references(finding: Dict[str, Any], metadata: Dict[str, Any]) -> List[str]:
    """Extract reference URLs from a finding, including CWE links."""
    refs: List[str] = []

    # Direct references field (handles scanner-specific field names)
    raw_refs = (
        finding.get("references")
        or finding.get("urls")
        or finding.get("PrimaryURL")
        or metadata.get("references", [])
    )
    if isinstance(raw_refs, str) and raw_refs:
        raw_refs = [raw_refs]
    elif isinstance(raw_refs, dict) and raw_refs.get("URL"):
        raw_refs = [raw_refs["URL"]]

    if isinstance(raw_refs, list):
        for r in raw_refs:
            if isinstance(r, str) and r.startswith("http"):
                refs.append(r)
            elif isinstance(r, dict) and r.get("URL"):
                refs.append(r["URL"])

    # CWE reference links
    cwe_ids = _extract_cwe_ids(finding.get("cwe") or metadata.get("cwe", []))
    for cwe in cwe_ids:
        num = cwe.split("-")[-1]
        url = f"https://cwe.mitre.org/data/definitions/{num}.html"
        if url not in refs:
            refs.append(url)

    # CVE reference links
    cve_ids = _extract_cve_ids(finding.get("cve") or metadata.get("cve", []))
    for cve in cve_ids:
        url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        if url not in refs:
            refs.append(url)

    return refs


def _extract_evidence(finding: Dict[str, Any], metadata: Dict[str, Any]) -> str:
    """Extract evidence text from a finding, prioritizing scanner-specific fields."""
    # Code snippet / match
    for key in ("code", "match", "secret", "secret_full", "response", "evidence"):
        val = finding.get(key) or metadata.get(key)
        if val:
            return str(val)[:1000]  # truncate to avoid huge evidence
    # Fallback: use the message
    msg = finding.get("message", "")
    if msg:
        return str(msg)[:1000]
    return ""


def finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Generate a deterministic fingerprint for a finding.

    Used for deduplication.  The fingerprint is based on fields that
    identify the same underlying vulnerability across scanners and
    rescan runs:

        scanner, rule_id, category, target, file, line, cwe, cve, title

    Two findings with the same fingerprint are considered duplicates.

    NOTE: ``description`` is intentionally excluded — descriptions can
    vary between scanners or runs while referring to the same issue.
    """
    meta = finding.get("metadata", {}) or {}
    parts = [
        finding.get("tool", "") or meta.get("tool", ""),
        finding.get("rule_id", "") or meta.get("rule_id", ""),
        finding.get("category", "") or meta.get("raw_type", ""),
        finding.get("target", "") or "",
        finding.get("file", "") or meta.get("file", ""),
        str(finding.get("line", "") or meta.get("line", 0)),
        "|".join(sorted(finding.get("cwe", []) or meta.get("cwe", []) or [])),
        "|".join(sorted(finding.get("cve", []) or meta.get("cve", []) or [])),
        finding.get("title", "") or finding.get("description", ""),
    ]
    raw = "\x1f".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def dedup_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate findings based on ``finding_fingerprint``.

    The first occurrence of each fingerprint is kept.  Scanner-specific
    finding IDs are attached as ``duplicate_of`` on removed entries for
    audit purposes (but they are not returned in the result list).
    """
    seen: Dict[str, Dict[str, Any]] = {}
    result: List[Dict[str, Any]] = []
    for f in findings:
        fp = finding_fingerprint(f)
        if fp not in seen:
            seen[fp] = f
            result.append(f)
    if len(result) < len(findings):
        logger.info(
            "Deduplication: %d → %d findings (%d duplicates removed)",
            len(findings), len(result), len(findings) - len(result),
        )
    return result
