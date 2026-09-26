import json
from typing import Any, Dict, List, Optional
from app.db.database import get_connection


async def create_scan(scan_id: str, target_url: str, data_source: str = "real_tools") -> None:
    """Insert a new scan record."""
    async with get_connection() as conn:
        await conn.execute(
            "INSERT INTO scans (scan_id, target_url, status, data_source) VALUES (?, ?, 'INITIALIZING', ?)",
            (scan_id, target_url, data_source),
        )
        await conn.commit()


async def update_scan_status(scan_id: str, status: str) -> None:
    """Update the status of an in-progress scan."""
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET status = ?, updated_at = datetime('now') WHERE scan_id = ?",
            (status, scan_id),
        )
        await conn.commit()


async def complete_scan(scan_id: str, overall_score: int, findings: List[Dict[str, Any]], data_source: str = "real_tools") -> List[int]:
    """Persist the final score and findings when a scan completes."""
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET status = 'COMPLETED', overall_score = ?, data_source = ?, updated_at = datetime('now') WHERE scan_id = ?",
            (overall_score, data_source, scan_id),
        )
        finding_ids = []
        for f in findings:
            cursor = await conn.execute(
                """INSERT INTO findings (scan_id, agent_name, severity, description, remediation)
                   VALUES (?, ?, ?, ?, ?)""",
                (scan_id, f["agent_name"], f["severity"], f["description"], f.get("remediation")),
            )
            finding_ids.append(cursor.lastrowid)
        await conn.commit()
    return finding_ids


async def update_final_report(scan_id: str, final_report: Dict[str, Any]) -> None:
    """Update the final_report JSON for a completed scan."""
    import json
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET final_report = ?, updated_at = datetime('now') WHERE scan_id = ?",
            (json.dumps(final_report), scan_id),
        )
        await conn.commit()


async def save_compliance_findings(scan_id: str, compliance_findings: List[Dict[str, Any]], finding_ids: List[int]) -> None:
    """Persist compliance mappings for each finding."""
    async with get_connection() as conn:
        for idx, cf in enumerate(compliance_findings):
            finding_id = finding_ids[idx] if idx < len(finding_ids) else None
            await conn.execute(
                """INSERT INTO compliance (scan_id, finding_id, agent_name, severity, owasp_llm, nist_csf)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    finding_id,
                    cf["agent_name"],
                    cf["severity"],
                    json.dumps(cf["owasp_llm"]),
                    json.dumps(cf["nist_csf"]),
                ),
            )
        await conn.commit()


async def get_compliance_findings(scan_id: str) -> List[Dict[str, Any]]:
    """Fetch compliance findings for a scan."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT agent_name, severity, owasp_llm, nist_csf FROM compliance WHERE scan_id = ?",
            (scan_id,),
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["owasp_llm"] = json.loads(d["owasp_llm"])
            d["nist_csf"] = json.loads(d["nist_csf"])
            result.append(d)
        return result


async def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single scan with its findings and compliance data."""
    async with get_connection() as conn:
        cursor = await conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        scan = dict(row)
        scan["data_source"] = row["data_source"] if row["data_source"] else "real_tools"
        cursor = await conn.execute(
            "SELECT id, agent_name, severity, description, remediation FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        findings_rows = await cursor.fetchall()
        scan["findings"] = [dict(f) for f in findings_rows]
        cursor = await conn.execute(
            "SELECT agent_name, severity, owasp_llm, nist_csf FROM compliance WHERE scan_id = ?",
            (scan_id,),
        )
        compliance_rows = await cursor.fetchall()
        scan["compliance"] = []
        for row in compliance_rows:
            d = dict(row)
            d["owasp_llm"] = json.loads(d["owasp_llm"])
            d["nist_csf"] = json.loads(d["nist_csf"])
            scan["compliance"].append(d)

        # Add final_report if available
        if scan.get("final_report"):
            try:
                scan["final_report"] = json.loads(scan["final_report"])
            except (json.JSONDecodeError, TypeError):
                scan["final_report"] = {}

        return scan


async def get_all_scans() -> List[Dict[str, Any]]:
    """Fetch all scans ordered by most recent first."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT scan_id, target_url, status, overall_score, created_at, data_source FROM scans ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [{"scan_id": r[0], "target_url": r[1], "status": r[2], "overall_score": r[3], "created_at": r[4], "data_source": r[5] or "real_tools"} for r in rows]


# API Key Management

async def create_api_key(key_hash: str, key_prefix: str, name: str = "default") -> int:
    """Create a new API key record."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "INSERT INTO api_keys (key_hash, key_prefix, name) VALUES (?, ?, ?)",
            (key_hash, key_prefix, name),
        )
        await conn.commit()
        return cursor.lastrowid


async def get_api_key_by_hash(key_hash: str) -> Optional[Dict[str, Any]]:
    """Fetch API key by hash."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ?",
            (key_hash,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_api_key_by_id(key_id: int) -> Optional[Dict[str, Any]]:
    """Fetch API key by ID."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM api_keys WHERE id = ?",
            (key_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def list_api_keys() -> List[Dict[str, Any]]:
    """List all API keys (without hashes)."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT id, key_prefix, name, created_at, last_used, is_active FROM api_keys ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def update_api_key_last_used(key_id: int) -> None:
    """Update last_used timestamp for an API key."""
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE api_keys SET last_used = datetime('now') WHERE id = ?",
            (key_id,),
        )
        await conn.commit()


async def revoke_api_key(key_id: int) -> bool:
    """Revoke (disable) an API key."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "UPDATE api_keys SET is_active = 0 WHERE id = ?",
            (key_id,),
        )
        await conn.commit()
        return cursor.rowcount > 0


async def update_scan_error(scan_id: str, error_message: str) -> None:
    """Record a scan-level error (e.g. timeout, fatal tool failure)."""
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET status = 'FAILED', updated_at = datetime('now') WHERE scan_id = ?",
            (scan_id,),
        )
        # Append to existing security_analysis_errors JSON, or create a new list.
        row = await conn.execute(
            "SELECT security_analysis_errors FROM scans WHERE scan_id = ?",
            (scan_id,),
        )
        existing = (await row.fetchone())[0]
        try:
            errors: list = json.loads(existing) if existing else []
        except (json.JSONDecodeError, TypeError):
            errors = []
        if error_message not in errors:
            errors.append(error_message)
        await conn.execute(
            "UPDATE scans SET security_analysis_errors = ? WHERE scan_id = ?",
            (json.dumps(errors), scan_id),
        )
        await conn.commit()
