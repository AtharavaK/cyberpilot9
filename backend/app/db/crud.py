import json
import logging
import os
import shutil
from typing import Any, Dict, List, Optional
from app.db.database import get_connection

logger = logging.getLogger(__name__)


# ── Scans ──────────────────────────────────────────────────────────────────────

async def create_scan(scan_id: str, target_url: str, data_source: str = "real_tools",
                      session_id: str = None, webhook_id: int = None) -> None:
    async with get_connection() as conn:
        await conn.execute(
            """INSERT INTO scans (scan_id, target_url, status, data_source, session_id, webhook_id)
               VALUES (?, ?, 'INITIALIZING', ?, ?, ?)""",
            (scan_id, target_url, data_source, session_id, webhook_id),
        )
        await conn.commit()


async def update_scan_status(scan_id: str, status: str) -> None:
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET status = ?, updated_at = datetime('now') WHERE scan_id = ?",
            (status, scan_id),
        )
        await conn.commit()


async def update_scan_session(scan_id: str, status: str, current_phase: str = None,
                               paused_at: str = None, resumed_at: str = None,
                               cancelled_at: str = None, completed_at: str = None,
                               failed_at: str = None) -> None:
    """Update the scan_sessions row for this scan."""
    async with get_connection() as conn:
        await conn.execute(
            """UPDATE scans SET status = ?, updated_at = datetime('now') WHERE scan_id = ?""",
            (status, scan_id),
        )
        await conn.execute(
            """UPDATE scan_sessions
               SET status = ?, current_phase = ?, paused_at = ?, resumed_at = ?,
                   cancelled_at = ?, completed_at = ?, failed_at = ?, updated_at = datetime('now')
               WHERE scan_id = ?""",
            (status, current_phase, paused_at, resumed_at, cancelled_at, completed_at, failed_at, scan_id),
        )
        await conn.commit()


async def mark_scan_paused(scan_id: str) -> None:
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET paused = 1, status = 'PAUSED', updated_at = datetime('now') WHERE scan_id = ?",
            (scan_id,),
        )
        await conn.execute(
            "UPDATE scan_sessions SET status = 'paused', paused_at = datetime('now'), updated_at = datetime('now') WHERE scan_id = ?",
            (scan_id,),
        )
        await conn.commit()


async def mark_scan_resumed(scan_id: str) -> None:
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET paused = 0, status = 'INITIALIZING', updated_at = datetime('now') WHERE scan_id = ?",
            (scan_id,),
        )
        await conn.execute(
            "UPDATE scan_sessions SET status = 'active', resumed_at = datetime('now'), updated_at = datetime('now') WHERE scan_id = ?",
            (scan_id,),
        )
        await conn.commit()


async def mark_scan_cancelled(scan_id: str) -> None:
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET cancelled = 1, status = 'CANCELLED', updated_at = datetime('now') WHERE scan_id = ?",
            (scan_id,),
        )
        await conn.execute(
            "UPDATE scan_sessions SET status = 'cancelled', cancelled_at = datetime('now'), updated_at = datetime('now') WHERE scan_id = ?",
            (scan_id,),
        )
        await conn.commit()


async def complete_scan(scan_id: str, overall_score: int, findings: List[Dict[str, Any]],
                        data_source: str = "real_tools") -> List[int]:
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET status = 'COMPLETED', overall_score = ?, data_source = ?, updated_at = datetime('now') WHERE scan_id = ?",
            (overall_score, data_source, scan_id),
        )
        finding_ids = []
        for f in findings:
            cursor = await conn.execute(
                """INSERT INTO findings (scan_id, agent_name, severity, description, remediation, metadata, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
                (scan_id, f["agent_name"], f["severity"], f["description"],
                 f.get("remediation"), json.dumps(f.get("metadata", {}))),
            )
            finding_ids.append(cursor.lastrowid)
        await conn.commit()
    return finding_ids


async def update_final_report(scan_id: str, final_report: Dict[str, Any]) -> None:
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET final_report = ?, updated_at = datetime('now') WHERE scan_id = ?",
            (json.dumps(final_report), scan_id),
        )
        await conn.commit()


async def save_compliance_findings(scan_id: str, compliance_findings: List[Dict[str, Any]],
                                    finding_ids: List[int]) -> None:
    async with get_connection() as conn:
        for idx, cf in enumerate(compliance_findings):
            finding_id = finding_ids[idx] if idx < len(finding_ids) else None
            await conn.execute(
                """INSERT INTO compliance (scan_id, finding_id, agent_name, severity, owasp_llm, nist_csf)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (scan_id, finding_id, cf["agent_name"], cf["severity"],
                 json.dumps(cf["owasp_llm"]), json.dumps(cf["nist_csf"])),
            )
        await conn.commit()


async def get_compliance_findings(scan_id: str) -> List[Dict[str, Any]]:
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
    async with get_connection() as conn:
        cursor = await conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        scan = dict(row)
        scan["data_source"] = row["data_source"] if row["data_source"] else "real_tools"
        cursor = await conn.execute(
            "SELECT id, agent_name, severity, description, remediation, metadata, created_at FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        findings_rows = await cursor.fetchall()
        scan["findings"] = []
        for f in findings_rows:
            fd = dict(f)
            if fd.get("metadata"):
                try:
                    fd["metadata"] = json.loads(fd["metadata"])
                except (json.JSONDecodeError, TypeError):
                    fd["metadata"] = {}
            # Apply canonical field mapping (same as get_findings_by_scan)
            meta = fd.get("metadata", {})
            fd["scanner"] = meta.get("tool") or fd.get("agent_name", "unknown")
            fd["location"] = {
                "file": meta.get("file", ""),
                "line": meta.get("line", 0),
                "path": meta.get("file", ""),
                "line_number": meta.get("line", 0),
            }
            fd["file"] = meta.get("file", "")
            fd["line"] = meta.get("line", 0)
            scan["findings"].append(fd)
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

        if scan.get("final_report"):
            try:
                scan["final_report"] = json.loads(scan["final_report"])
            except (json.JSONDecodeError, TypeError):
                scan["final_report"] = {}
        if scan.get("security_analysis_errors"):
            try:
                scan["security_analysis_errors"] = json.loads(scan["security_analysis_errors"])
            except (json.JSONDecodeError, TypeError):
                scan["security_analysis_errors"] = []

        return scan


async def get_all_scans() -> List[Dict[str, Any]]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT scan_id, target_url, status, overall_score, created_at, data_source FROM scans ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [{"scan_id": r[0], "target_url": r[1], "status": r[2], "overall_score": r[3],
                 "created_at": r[4], "data_source": r[5] or "real_tools"} for r in rows]


# ── Scan Events (live progress / event log) ────────────────────────────────────

async def add_scan_event(scan_id: str, event_type: str, payload: Dict[str, Any]) -> int:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "INSERT INTO scan_events (scan_id, event_type, payload) VALUES (?, ?, ?)",
            (scan_id, event_type, json.dumps(payload)),
        )
        await conn.commit()
        return cursor.lastrowid


async def get_scan_events(scan_id: str, since_id: int = 0) -> List[Dict[str, Any]]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT id, event_type, payload, created_at FROM scan_events WHERE scan_id = ? AND id > ? ORDER BY id ASC",
            (scan_id, since_id),
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["payload"] = json.loads(d["payload"])
            result.append(d)
        return result


async def get_latest_scan_event(scan_id: str) -> Optional[Dict[str, Any]]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT id, event_type, payload, created_at FROM scan_events WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
            (scan_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        d = dict(row)
        d["payload"] = json.loads(d["payload"])
        return d


# ── Finding Triage ─────────────────────────────────────────────────────────────

async def set_finding_triage(finding_id: int, scan_id: str, status: str,
                              note: str = None) -> int:
    async with get_connection() as conn:
        # Check if triage already exists
        cursor = await conn.execute(
            "SELECT id FROM finding_triage WHERE finding_id = ? AND scan_id = ?",
            (finding_id, scan_id),
        )
        existing = await cursor.fetchone()
        if existing:
            rid = existing["id"]
            await conn.execute(
                "UPDATE finding_triage SET status = ?, note = ?, updated_at = datetime('now') WHERE id = ?",
                (status, note, rid),
            )
        else:
            cursor = await conn.execute(
                """INSERT INTO finding_triage (finding_id, scan_id, status, note)
                   VALUES (?, ?, ?, ?)""",
                (finding_id, scan_id, status, note),
            )
            rid = cursor.lastrowid
        await conn.commit()
        return rid


async def get_finding_triage(finding_id: int, scan_id: str) -> Optional[Dict[str, Any]]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM finding_triage WHERE finding_id = ? AND scan_id = ?",
            (finding_id, scan_id),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_all_triage_for_scan(scan_id: str) -> List[Dict[str, Any]]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            """SELECT ft.*, f.agent_name, f.severity, f.description
               FROM finding_triage ft
               JOIN findings f ON ft.finding_id = f.id
               WHERE ft.scan_id = ?
               ORDER BY ft.created_at DESC""",
            (scan_id,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def verify_finding_fixed(finding_id: int, scan_id: str,
                                verified_scan_id: str) -> None:
    """Mark a finding as remediated and link the verifying scan."""
    async with get_connection() as conn:
        await conn.execute(
            """UPDATE finding_triage
               SET status = 'remediated', verified_scan_id = ?, updated_at = datetime('now')
               WHERE finding_id = ? AND scan_id = ?""",
            (verified_scan_id, finding_id, scan_id),
        )
        await conn.commit()


# ── Scan Sessions ──────────────────────────────────────────────────────────────

async def create_scan_session(scan_id: str) -> int:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "INSERT INTO scan_sessions (scan_id, status) VALUES (?, 'active')",
            (scan_id,),
        )
        await conn.commit()
        return cursor.lastrowid


async def get_scan_session(scan_id: str) -> Optional[Dict[str, Any]]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM scan_sessions WHERE scan_id = ?",
            (scan_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def is_scan_paused(scan_id: str) -> bool:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT paused FROM scans WHERE scan_id = ?",
            (scan_id,),
        )
        row = await cursor.fetchone()
        return bool(row and row["paused"])


async def is_scan_cancelled(scan_id: str) -> bool:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT cancelled FROM scans WHERE scan_id = ?",
            (scan_id,),
        )
        row = await cursor.fetchone()
        return bool(row and row["cancelled"])


async def get_scan_progress(scan_id: str) -> Optional[Dict[str, Any]]:
    """Get the current phase and progress of a scan from scan_sessions + scan_events."""
    session = await get_scan_session(scan_id)
    if not session:
        return None
    latest_event = await get_latest_scan_event(scan_id)
    return {
        "session": session,
        "latest_event": latest_event,
    }


# ── Scan Webhooks ──────────────────────────────────────────────────────────────

async def create_webhook(user_id: int, url: str, name: str = None,
                          events: List[str] = None) -> int:
    async with get_connection() as conn:
        cursor = await conn.execute(
            """INSERT INTO scan_webhooks (user_id, url, name, events)
               VALUES (?, ?, ?, ?)""",
            (user_id, url, name, json.dumps(events or ["completed"])),
        )
        await conn.commit()
        return cursor.lastrowid


async def get_webhooks_for_user(user_id: int) -> List[Dict[str, Any]]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM scan_webhooks WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["events"] = json.loads(d["events"])
            result.append(d)
        return result


async def delete_webhook(webhook_id: int, user_id: int) -> bool:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "DELETE FROM scan_webhooks WHERE id = ? AND user_id = ?",
            (webhook_id, user_id),
        )
        await conn.commit()
        return cursor.rowcount > 0


async def fire_webhooks_for_event(user_id: int, event_type: str,
                                   scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Find matching webhooks and return their URLs (caller should POST to them)."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM scan_webhooks WHERE user_id = ?",
            (user_id,),
        )
        rows = await cursor.fetchall()
        matched = []
        for row in rows:
            d = dict(row)
            events = json.loads(d["events"])
            if event_type in events or "all" in events:
                matched.append(d)
        return matched


# ── Dashboard / Stats ──────────────────────────────────────────────────────────

async def get_dashboard_stats(user_id: int = None) -> Dict[str, Any]:
    """Aggregate stats across all scans."""
    async with get_connection() as conn:
        # Total scans
        cursor = await conn.execute(
            "SELECT COUNT(*) as cnt FROM scans"
        )
        total_scans = (await cursor.fetchone())["cnt"]

        # By status
        cursor = await conn.execute(
            "SELECT status, COUNT(*) as cnt FROM scans GROUP BY status"
        )
        by_status = {r["status"]: r["cnt"] for r in await cursor.fetchall()}

        # Findings by severity (all time)
        cursor = await conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        )
        findings_by_severity = {r["severity"]: r["cnt"] for r in await cursor.fetchall()}

        # Recent scans (last 10)
        cursor = await conn.execute(
            "SELECT scan_id, target_url, status, overall_score, created_at, data_source FROM scans ORDER BY created_at DESC LIMIT 10"
        )
        recent = []
        for row in await cursor.fetchall():
            recent.append({
                "scan_id": row[0], "target_url": row[1], "status": row[2],
                "overall_score": row[3], "created_at": row[4],
                "data_source": row[5] or "real_tools",
            })

        # Open triage items (open, in_progress, false_positive, accepted — not remediated)
        cursor = await conn.execute(
            """SELECT COUNT(*) as cnt FROM finding_triage
               WHERE status IN ('open', 'in_progress', 'false_positive', 'accepted')"""
        )
        open_triage = (await cursor.fetchone())["cnt"]

        return {
            "total_scans": total_scans,
            "by_status": by_status,
            "findings_by_severity": findings_by_severity,
            "open_triage_count": open_triage,
            "recent_scans": recent,
        }


async def get_scan_trend(target_url: str, current_scan_id: str) -> Optional[Dict[str, Any]]:
    """Compare current scan with the most recent previous scan on the same target."""
    async with get_connection() as conn:
        # Get current scan findings
        cursor = await conn.execute(
            "SELECT id, severity FROM findings WHERE scan_id = ?",
            (current_scan_id,),
        )
        current_findings = await cursor.fetchall()
        current_by_severity = {}
        for row in current_findings:
            sev = row["severity"]
            current_by_severity[sev] = current_by_severity.get(sev, 0) + 1

        # Get previous scan on same target
        cursor = await conn.execute(
            """SELECT scan_id, status, overall_score, created_at
               FROM scans
               WHERE target_url = ? AND scan_id != ? AND status = 'COMPLETED'
               ORDER BY created_at DESC LIMIT 1""",
            (target_url, current_scan_id),
        )
        prev_row = await cursor.fetchone()
        if not prev_row:
            return {"current": current_by_severity, "previous": None, "diff": None}

        prev_scan_id = prev_row["scan_id"]
        cursor = await conn.execute(
            "SELECT id, severity FROM findings WHERE scan_id = ?",
            (prev_scan_id,),
        )
        prev_findings = await cursor.fetchall()
        previous_by_severity = {}
        for row in prev_findings:
            sev = row["severity"]
            previous_by_severity[sev] = previous_by_severity.get(sev, 0) + 1

        # Compute diff
        all_severities = set(current_by_severity.keys()) | set(previous_by_severity.keys())
        diff = {}
        for sev in all_severities:
            c = current_by_severity.get(sev, 0)
            p = previous_by_severity.get(sev, 0)
            diff[sev] = c - p

        return {
            "current": current_by_severity,
            "previous": previous_by_severity,
            "diff": diff,
            "previous_scan_id": prev_scan_id,
            "previous_score": prev_row["overall_score"],
            "current_score": None,  # filled by caller
        }


# ── API Key Management ─────────────────────────────────────────────────────────

async def create_api_key(key_hash: str, key_prefix: str, name: str = "default") -> int:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "INSERT INTO api_keys (key_hash, key_prefix, name) VALUES (?, ?, ?)",
            (key_hash, key_prefix, name),
        )
        await conn.commit()
        return cursor.lastrowid


async def get_api_key_by_hash(key_hash: str) -> Optional[Dict[str, Any]]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ?",
            (key_hash,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_api_key_by_id(key_id: int) -> Optional[Dict[str, Any]]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM api_keys WHERE id = ?",
            (key_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def list_api_keys() -> List[Dict[str, Any]]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT id, key_prefix, name, created_at, last_used, is_active FROM api_keys ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def update_api_key_last_used(key_id: int) -> None:
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE api_keys SET last_used = datetime('now') WHERE id = ?",
            (key_id,),
        )
        await conn.commit()


async def revoke_api_key(key_id: int) -> bool:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "UPDATE api_keys SET is_active = 0 WHERE id = ?",
            (key_id,),
        )
        await conn.commit()
        return cursor.rowcount > 0


async def delete_all_api_keys() -> int:
    """Delete all API keys (used by tests and cleanup). Returns count deleted."""
    async with get_connection() as conn:
        cursor = await conn.execute("DELETE FROM api_keys")
        await conn.commit()
        return cursor.rowcount


async def update_scan_error(scan_id: str, error_message: str) -> None:
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET status = 'FAILED', updated_at = datetime('now') WHERE scan_id = ?",
            (scan_id,),
        )
        await conn.execute(
            "UPDATE scan_sessions SET status = 'failed', failed_at = datetime('now'), updated_at = datetime('now') WHERE scan_id = ?",
            (scan_id,),
        )
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


async def set_scan_clone_dir(scan_id: str, clone_dir: str) -> None:
    """Store the temporary clone directory path for cleanup on cancel/timeout."""
    if not clone_dir:
        return
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE scans SET clone_dir = ?, updated_at = datetime('now') WHERE scan_id = ?",
            (clone_dir, scan_id),
        )
        await conn.commit()


async def get_scan_clone_dir(scan_id: str) -> Optional[str]:
    """Retrieve the stored clone directory for a scan, if any."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT clone_dir FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = await cursor.fetchone()
        return row["clone_dir"] if row and row["clone_dir"] else None


async def cleanup_scan_clone(scan_id: str) -> None:
    """Safely clean up the temporary clone directory for a scan.

    Only removes directories under the system temp dir.
    """
    import os
    import shutil
    clone_dir = await get_scan_clone_dir(scan_id)
    if not clone_dir:
        return
    if not os.path.isdir(clone_dir):
        return
    real_clone = os.path.realpath(clone_dir)
    tmp_base = os.path.realpath("/tmp")
    if real_clone.startswith(tmp_base):
        shutil.rmtree(real_clone, ignore_errors=True)
        logger.info("Cleaned up temporary clone for scan %s: %s", scan_id, real_clone)


async def get_findings_by_scan(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieve findings for a scan with canonical field names for frontend consumption.

    Returns findings sorted by severity (critical first) then by created_at.
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    async with get_connection() as conn:
        cursor = await conn.execute(
            """SELECT id, agent_name, severity, description, remediation, metadata, created_at
               FROM findings WHERE scan_id = ? ORDER BY id""",
            (scan_id,),
        )
        rows = await cursor.fetchall()

    results = []
    for row in rows:
        f = dict(row)
        if f.get("metadata"):
            try:
                f["metadata"] = json.loads(f["metadata"])
            except (json.JSONDecodeError, TypeError):
                f["metadata"] = {}
        # Canonical field names for frontend
        meta = f.get("metadata", {})
        agent_name = f.get("agent_name", "unknown")
        # Use the actual scanner tool name when available (e.g. semgrep, bandit)
        # instead of the LLM agent name (e.g. "Code Review Agent")
        f["scanner"] = meta.get("tool") or agent_name
        f["agent"] = agent_name
        f["location"] = {
            "file": meta.get("file", ""),
            "line": meta.get("line", 0),
            "path": meta.get("file", ""),
            "line_number": meta.get("line", 0),
        }
        f["file"] = meta.get("file", "")
        f["line"] = meta.get("line", 0)
        f["title"] = meta.get("title", f.get("description", "")[:80])
        f["description"] = f.get("description", "")
        f["evidence"] = meta.get("evidence")
        f["cwe"] = meta.get("cwe")
        f["cve"] = meta.get("cve")
        f["references"] = meta.get("references", [])
        f["target"] = meta.get("target", "")
        f["confidence"] = meta.get("confidence")
        f["data_source"] = meta.get("data_source") or f.get("data_source") or "real_tools"
        results.append(f)

    results.sort(key=lambda x: (severity_order.get(x.get("severity", "low").lower(), 5), x.get("id", 0)))
    return results


# ── AI Analysis (Phase 3) ───────────────────────────────────────────────────────

async def create_ai_analysis(
    finding_id: int,
    scan_id: str,
    model: str,
    analysis: Dict[str, Any],
    ai_confidence: Optional[float] = None,
    status: str = "completed",
    prompt_version: str = "v1.0",
    error: Optional[str] = None,
) -> int:
    """Persist an AI analysis record.

    Returns the DB id of the new ai_analysis row.
    """
    async with get_connection() as conn:
        cursor = await conn.execute(
            """INSERT INTO ai_analysis
                 (finding_id, scan_id, model, analysis_json, ai_confidence, status, prompt_version, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding_id, scan_id, model, json.dumps(analysis),
             ai_confidence, status, prompt_version, error),
        )
        await conn.commit()
        return cursor.lastrowid or 0


async def get_ai_analysis_by_finding(finding_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve the most recent AI analysis for a finding."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            """SELECT id, finding_id, scan_id, model, analysis_json, ai_confidence,
                      status, prompt_version, error, created_at
               FROM ai_analysis
               WHERE finding_id = ?
               ORDER BY id DESC LIMIT 1""",
            (finding_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_ai_analysis(row)


async def get_ai_analysis_by_finding_and_scan(finding_id: int, scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve AI analysis for a specific finding within a specific scan."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            """SELECT id, finding_id, scan_id, model, analysis_json, ai_confidence,
                      status, prompt_version, error, created_at
               FROM ai_analysis
               WHERE finding_id = ? AND scan_id = ?
               ORDER BY id DESC LIMIT 1""",
            (finding_id, scan_id),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_ai_analysis(row)


async def get_ai_analyses_for_scan(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieve all AI analyses for a scan's findings."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            """SELECT id, finding_id, scan_id, model, analysis_json, ai_confidence,
                      status, prompt_version, error, created_at
               FROM ai_analysis
               WHERE scan_id = ?
               ORDER BY id DESC""",
            (scan_id,),
        )
        rows = await cursor.fetchall()
        return [_row_to_ai_analysis(r) for r in rows]


async def update_ai_analysis_status(analysis_id: int, status: str,
                                    error: Optional[str] = None) -> None:
    """Update the status of an AI analysis record (e.g. to mark as failed)."""
    async with get_connection() as conn:
        await conn.execute(
            """UPDATE ai_analysis
               SET status = ?, error = ?
               WHERE id = ?""",
            (status, error, analysis_id),
        )
        await conn.commit()


def _row_to_ai_analysis(row) -> Dict[str, Any]:
    """Convert a DB row to a dict with parsed analysis_json."""
    d = dict(row)
    if d.get("analysis_json"):
        try:
            d["analysis"] = json.loads(d["analysis_json"])
        except (json.JSONDecodeError, TypeError):
            d["analysis"] = {}
    else:
        d["analysis"] = {}
    return d


# ── Phase 5: Assessment Tasks ──────────────────────────────────────────────────

async def save_assessment_plan(
    scan_id: str, plan_data: Dict[str, Any]
) -> None:
    """Persist an AssessmentPlan to the assessment_plans table."""
    plan_json = json.dumps(plan_data, default=str)
    async with get_connection() as conn:
        await conn.execute(
            """INSERT OR REPLACE INTO assessment_plans
               (plan_id, scan_id, target, target_kind, authorized_target,
                authorization_mode, allow_active_scanning, allow_private_targets,
                objective, plan_json, max_iterations, max_tasks,
                max_runtime_seconds)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                plan_data.get("plan_id"),
                scan_id,
                plan_data.get("target"),
                plan_data.get("target_kind"),
                plan_data.get("authorized_target"),
                plan_data.get("authorization_mode"),
                int(plan_data.get("allow_active_scanning", False)),
                int(plan_data.get("allow_private_targets", False)),
                plan_data.get("objective"),
                plan_json,
                plan_data.get("max_iterations", 5),
                plan_data.get("max_tasks", 30),
                plan_data.get("max_runtime_seconds", 900),
            ),
        )
        await conn.commit()


async def save_task(scan_id: str, task: Dict[str, Any]) -> None:
    """Persist a single SecurityTask."""
    async with get_connection() as conn:
        await conn.execute(
            """INSERT OR REPLACE INTO assessment_tasks
               (task_id, scan_id, agent, tool, objective, target, priority,
                status, dependencies, reason, config, scan_mode,
                created_at, started_at, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task.get("task_id"),
                scan_id,
                task.get("agent"),
                task.get("tool"),
                task.get("objective"),
                task.get("target"),
                task.get("priority"),
                task.get("status", "pending"),
                json.dumps(task.get("dependencies", [])),
                task.get("reason"),
                json.dumps(task.get("config", {})),
                task.get("scan_mode", "passive"),
                task.get("created_at"),
                task.get("started_at"),
                task.get("completed_at"),
            ),
        )
        await conn.commit()


async def save_all_tasks(scan_id: str, tasks: List[Dict[str, Any]]) -> None:
    """Batch-save a list of task dicts."""
    for task in tasks:
        await save_task(scan_id, task)


async def update_task_status(
    task_id: str, status: str, started_at: str = None,
    completed_at: str = None, agent_result: Dict[str, Any] = None,
) -> None:
    """Update a task's status and timestamps."""
    async with get_connection() as conn:
        result_json = json.dumps(agent_result) if agent_result else None
        await conn.execute(
            """UPDATE assessment_tasks SET status = ?, started_at = COALESCE(?, started_at),
               completed_at = COALESCE(?, completed_at), agent_result_json = COALESCE(?, agent_result_json)
               WHERE task_id = ?""",
            (status, started_at, completed_at, result_json, task_id),
        )
        await conn.commit()


async def get_tasks_by_scan(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieve all tasks for a scan, with parsed dependencies/config/result."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            """SELECT * FROM assessment_tasks WHERE scan_id = ? ORDER BY priority, created_at""",
            (scan_id,),
        )
        rows = await cursor.fetchall()

    tasks = []
    for row in rows:
        t = dict(row)
        for json_field in ("dependencies", "config", "agent_result_json"):
            if t.get(json_field):
                try:
                    t[json_field] = json.loads(t[json_field])
                except (json.JSONDecodeError, TypeError):
                    t[json_field] = {} if json_field != "agent_result_json" else {}
        tasks.append(t)
    return tasks


async def get_pending_tasks(scan_id: str) -> List[Dict[str, Any]]:
    """Get tasks that are pending or approved (ready to run)."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            """SELECT * FROM assessment_tasks
               WHERE scan_id = ? AND status IN ('pending', 'approved')
               ORDER BY priority, created_at""",
            (scan_id,),
        )
        rows = await cursor.fetchall()
    tasks = []
    for row in rows:
        t = dict(row)
        for json_field in ("dependencies", "config"):
            if t.get(json_field):
                try:
                    t[json_field] = json.loads(t[json_field])
                except (json.JSONDecodeError, TypeError):
                    t[json_field] = {}
        tasks.append(t)
    return tasks


# ── Phase 5: Agent Decisions / Audit Trail ─────────────────────────────────────

async def save_decision(scan_id: str, decision: Dict[str, Any]) -> None:
    """Persist a Master Agent decision to the audit trail."""
    async with get_connection() as conn:
        await conn.execute(
            """INSERT INTO agent_decisions
               (decision_id, scan_id, decision_type, outcome, reason,
                task_id, agent, tool, target, policy_validation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                decision.get("decision_id"),
                scan_id,
                decision.get("decision_type"),
                decision.get("outcome"),
                decision.get("reason"),
                decision.get("task_id"),
                decision.get("agent"),
                decision.get("tool"),
                decision.get("target"),
                json.dumps(decision.get("policy_validation", {})) if decision.get("policy_validation") else None,
            ),
        )
        await conn.commit()


async def get_decisions_by_scan(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieve all decisions for a scan (audit trail)."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            """SELECT * FROM agent_decisions WHERE scan_id = ?
               ORDER BY created_at""",
            (scan_id,),
        )
        rows = await cursor.fetchall()
    decisions = []
    for row in rows:
        d = dict(row)
        if d.get("policy_validation"):
            try:
                d["policy_validation"] = json.loads(d["policy_validation"])
            except (json.JSONDecodeError, TypeError):
                d["policy_validation"] = {}
        decisions.append(d)
    return decisions
