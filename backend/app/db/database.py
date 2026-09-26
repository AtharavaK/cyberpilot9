import aiosqlite
import os
from contextlib import asynccontextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "cyberpilot.db")
DB_PATH = os.path.abspath(DB_PATH)

async def init_db():
    """Create tables if they don't exist."""
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id     TEXT PRIMARY KEY,
                target_url  TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'INITIALIZING',
                overall_score INTEGER,
                final_report TEXT,
                data_source TEXT DEFAULT 'real_tools',
                security_analysis_errors TEXT DEFAULT '[]',
                created_at  DATETIME DEFAULT (datetime('now')),
                updated_at  DATETIME DEFAULT (datetime('now'))
            )
        """)
        # Migration for existing databases: add missing columns
        for column_def, col_name in [
            ("data_source TEXT DEFAULT 'real_tools'", "data_source"),
            ("security_analysis_errors TEXT DEFAULT '[]'", "security_analysis_errors"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE scans ADD COLUMN {column_def}")
            except aiosqlite.OperationalError:
                pass  # Column already exists
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                agent_name  TEXT NOT NULL,
                severity    TEXT NOT NULL,
                description TEXT NOT NULL,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)
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
