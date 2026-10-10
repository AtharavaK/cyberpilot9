import aiosqlite
import os
from contextlib import asynccontextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "cyberpilot.db")
DB_PATH = os.path.abspath(DB_PATH)

async def init_db():
    """Create tables if they don't exist. Safe to call repeatedly — all are IF NOT EXISTS."""
    async with aiosqlite.connect(DB_PATH) as conn:
        # ── scans table (with new columns for interactive features) ──────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id             TEXT PRIMARY KEY,
                target_url          TEXT NOT NULL,
                status              TEXT NOT NULL DEFAULT 'INITIALIZING',
                overall_score       INTEGER,
                final_report        TEXT,
                data_source         TEXT DEFAULT 'real_tools',
                security_analysis_errors TEXT DEFAULT '[]',
                created_at          DATETIME DEFAULT (datetime('now')),
                updated_at          DATETIME DEFAULT (datetime('now')),
                session_id          TEXT,          -- FK to scan_sessions
                paused              INTEGER DEFAULT 0,
                cancelled           INTEGER DEFAULT 0,
                webhook_id          INTEGER        -- FK to scan_webhooks (optional)
            )
        """)

        # Migration: add columns missing from older databases
        for col_def, col_name in [
            ("data_source TEXT DEFAULT 'real_tools'",            "data_source"),
            ("security_analysis_errors TEXT DEFAULT '[]'",       "security_analysis_errors"),
            ("session_id TEXT",                                  "session_id"),
            ("paused INTEGER DEFAULT 0",                        "paused"),
            ("cancelled INTEGER DEFAULT 0",                     "cancelled"),
            ("webhook_id INTEGER",                              "webhook_id"),
            ("clone_dir TEXT",                                 "clone_dir"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE scans ADD COLUMN {col_def}")
            except aiosqlite.OperationalError:
                pass  # already exists

        # ── findings table (with triage + remediation details) ──────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT NOT NULL,
                agent_name      TEXT NOT NULL,
                severity        TEXT NOT NULL,
                description     TEXT NOT NULL,
                remediation     TEXT,
                metadata        TEXT,          -- JSON
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)

        for col_def, col_name in [
            ("remediation_details TEXT",   "remediation_details"),
            ("created_at DATETIME DEFAULT (datetime('now'))", "created_at"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE findings ADD COLUMN {col_def}")
            except aiosqlite.OperationalError:
                pass

        # ── compliance table ─────────────────────────────────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS compliance (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id       TEXT NOT NULL,
                finding_id    INTEGER NOT NULL,
                agent_name    TEXT NOT NULL,
                severity      TEXT NOT NULL,
                owasp_llm     TEXT NOT NULL,  -- JSON array
                nist_csf      TEXT NOT NULL,  -- JSON array
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            )
        """)

        # ── api_keys table ───────────────────────────────────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash    TEXT NOT NULL UNIQUE,
                key_prefix  TEXT NOT NULL,
                name        TEXT,
                created_at  DATETIME DEFAULT (datetime('now')),
                last_used   DATETIME,
                is_active   INTEGER DEFAULT 1
            )
        """)

        # ── NEW: scan_events — live progress / event log per scan ───────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                event_type  TEXT NOT NULL,     -- 'status', 'phase', 'finding', 'progress', 'error', 'info'
                payload     TEXT NOT NULL,     -- JSON
                created_at  DATETIME DEFAULT (datetime('now')),
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)

        # ── NEW: finding_triage — per-finding triage state ──────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS finding_triage (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id      INTEGER NOT NULL,
                scan_id         TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'open',  -- open | false_positive | accepted | remediated
                note            TEXT,
                verified_scan_id TEXT,         -- scan_id of scan that verified this was fixed
                created_at      DATETIME DEFAULT (datetime('now')),
                updated_at      DATETIME DEFAULT (datetime('now')),
                FOREIGN KEY (finding_id) REFERENCES findings(id),
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)

        # ── NEW: scan_webhooks — user notification rules ────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_webhooks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,   -- api_keys.id
                url         TEXT NOT NULL,
                name        TEXT,
                events      TEXT NOT NULL DEFAULT '[]',  -- JSON: ['completed','critical','regression']
                created_at  DATETIME DEFAULT (datetime('now')),
                updated_at  DATETIME DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES api_keys(id)
            )
        """)

        # ── NEW: ai_analysis — AI engine analysis results (Phase 3) ────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS ai_analysis (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id          INTEGER,              -- nullable: AI analysis may run
                                                              -- before finding is persisted
                scan_id             TEXT NOT NULL,
                model               TEXT NOT NULL,
                analysis_json       TEXT NOT NULL,     -- full AIAnalysis as JSON
                ai_confidence       REAL,              -- AI's confidence in its own assessment
                status              TEXT DEFAULT 'completed',  -- completed / failed
                prompt_version      TEXT DEFAULT 'v1.0',
                error               TEXT,
                created_at          DATETIME DEFAULT (datetime('now')),
                FOREIGN KEY (finding_id) REFERENCES findings(id),
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_analysis_finding ON ai_analysis(finding_id)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_analysis_scan ON ai_analysis(scan_id)"
        )

        # ── NEW: scan_sessions — pause/resume/cancel state ──────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT NOT NULL UNIQUE,
                status          TEXT NOT NULL DEFAULT 'active',  -- active | paused | resumed | cancelled | completed | failed
                current_phase   TEXT,           -- last phase the scan reached
                paused_at       DATETIME,
                resumed_at      DATETIME,
                cancelled_at    DATETIME,
                completed_at    DATETIME,
                failed_at       DATETIME,
                created_at      DATETIME DEFAULT (datetime('now')),
                updated_at      DATETIME DEFAULT (datetime('now')),
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)

        # ── NEW: assessment_tasks — Phase 5 task persistence ─────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS assessment_tasks (
                task_id            TEXT PRIMARY KEY,
                scan_id            TEXT NOT NULL,
                agent              TEXT NOT NULL,
                tool               TEXT NOT NULL,
                objective          TEXT,
                target             TEXT,
                priority           INTEGER,
                status             TEXT DEFAULT 'pending',
                dependencies       TEXT DEFAULT '[]',  -- JSON
                reason             TEXT,
                config             TEXT DEFAULT '{}',  -- JSON
                scan_mode          TEXT DEFAULT 'passive',
                created_at         DATETIME DEFAULT (datetime('now')),
                started_at         DATETIME,
                completed_at       DATETIME,
                agent_result_json  TEXT,  -- JSON: AgentResult serialized
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assessment_tasks_scan ON assessment_tasks(scan_id)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assessment_tasks_status ON assessment_tasks(status)"
        )

        # ── NEW: agent_decisions — Phase 5 audit trail ────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_decisions (
                decision_id          TEXT PRIMARY KEY,
                scan_id              TEXT NOT NULL,
                decision_type        TEXT NOT NULL,
                outcome              TEXT NOT NULL,
                reason               TEXT,
                task_id              TEXT,
                agent                TEXT,
                tool                 TEXT,
                target               TEXT,
                policy_validation    TEXT,  -- JSON
                created_at           DATETIME DEFAULT (datetime('now')),
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
                FOREIGN KEY (task_id) REFERENCES assessment_tasks(task_id)
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_decisions_scan ON agent_decisions(scan_id)"
        )

        # ── NEW: assessment_plans — Phase 5 plan persistence ─────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS assessment_plans (
                plan_id            TEXT PRIMARY KEY,
                scan_id            TEXT NOT NULL UNIQUE,
                target             TEXT,
                target_kind        TEXT,
                authorized_target   TEXT,
                authorization_mode  TEXT,
                allow_active_scanning INTEGER DEFAULT 0,
                allow_private_targets   INTEGER DEFAULT 0,
                objective          TEXT,
                plan_json          TEXT NOT NULL,  -- full AssessmentPlan as JSON
                max_iterations      INTEGER DEFAULT 5,
                max_tasks           INTEGER DEFAULT 30,
                max_runtime_seconds INTEGER DEFAULT 900,
                created_at          DATETIME DEFAULT (datetime('now')),
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assessment_plans_scan ON assessment_plans(scan_id)"
        )

        # ── Migration: allow NULL finding_id in ai_analysis ──────────────────
        # SQLite cannot ALTER COLUMN to drop a NOT NULL constraint, so use the
        # table-rebuild pattern.  This is idempotent: if the column is already
        # nullable (new DB) the pragma check skips the migration.
        col_info = await conn.execute_fetchall(
            "PRAGMA table_info(ai_analysis)"
        )
        finding_col_nullable = any(
            row[1] == "finding_id" and row[3] == 0 for row in col_info
        )
        if not finding_col_nullable:
            # Rebuild ai_analysis with a nullable finding_id
            await conn.executescript("""
                CREATE TABLE ai_analysis_new (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id          INTEGER,
                    scan_id             TEXT NOT NULL,
                    model               TEXT NOT NULL,
                    analysis_json       TEXT NOT NULL,
                    ai_confidence       REAL,
                    status              TEXT DEFAULT 'completed',
                    prompt_version      TEXT DEFAULT 'v1.0',
                    error               TEXT,
                    created_at          DATETIME DEFAULT (datetime('now')),
                    FOREIGN KEY (finding_id) REFERENCES findings(id),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                );
                INSERT INTO ai_analysis_new (id, finding_id, scan_id, model,
                    analysis_json, ai_confidence, status, prompt_version,
                    error, created_at)
                SELECT id, finding_id, scan_id, model, analysis_json,
                    ai_confidence, status, prompt_version, error, created_at
                FROM ai_analysis;
                DROP TABLE ai_analysis;
                ALTER TABLE ai_analysis_new RENAME TO ai_analysis;
                CREATE INDEX IF NOT EXISTS idx_ai_analysis_finding ON ai_analysis(finding_id);
                CREATE INDEX IF NOT EXISTS idx_ai_analysis_scan ON ai_analysis(scan_id);
            """)

        await conn.commit()
    print(f"[DB] Initialized SQLite database at: {DB_PATH}")


@asynccontextmanager
async def get_connection():
    """Async SQLite connection context manager."""
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    try:
        yield conn
    finally:
        await conn.close()
