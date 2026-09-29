import json
from typing import Any, Dict, List, Optional
from app.db.database import get_connection


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
                """INSERT INTO findings (scan_id, agent_name, severity, description, remediation, metadata)
                   VALUES (?, ?, ?, ?, ?, ?)""",
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
            "SELECT id, agent_name, severity, description, remediation, metadata FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        findings_rows = await cursor.fetchall()
        scan["findings"] = []
        for f in findings_rows:
            fd = dict(f)
            if fd.get("metadata"):
                fd["metadata"] = json.loads(fd["metadata"])
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

        # Open triage items
        cursor = await conn.execute(
            """SELECT COUNT(*) as cnt FROM finding_triage
               WHERE status IN ('open', 'false_positive', 'accepted')"""
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
