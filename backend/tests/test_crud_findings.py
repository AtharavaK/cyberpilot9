"""Tests for Phase 2: CRUD layer finding retrieval and clone cleanup.

Tests data persistence of canonical finding fields,
clone directory lifecycle (store → cleanup), and the
get_findings_by_scan API.
"""
import asyncio
import os
import tempfile
import pytest
from app.db.database import init_db, get_connection
from app.db import crud
from app.services.finding_normalizer import (
    build_canonical_finding, finding_fingerprint,
)


@pytest.fixture(autouse=True)
async def db_setup():
    """Initialize a fresh DB for each test."""
    # Remove existing DB to ensure clean state
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cyberpilot.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    await init_db()
    yield


class TestGetFindingsByScan:
    """Verify get_findings_by_scan returns canonical fields from DB."""

    async def test_findings_have_canonical_fields(self):
        scan_id = "test-findings-canonical-001"
        await crud.create_scan(scan_id, "https://example.com")

        # Insert a canonical finding with metadata
        raw_finding = {
            "tool": "semgrep",
            "rule_id": "sql-injection",
            "severity": "ERROR",
            "file": "app/main.py",
            "line": 42,
            "cwe": ["CWE-89"],
            "title": "SQL Injection",
            "description": "Untrusted data in SQL query",
            "evidence": "SELECT * FROM users WHERE id = {user_id}",
            "confidence": 0.9,
            "references": ["https://semgrep.dev/docs/"],
            "data_source": "real_tools",
        }
        canonical = build_canonical_finding(raw_finding, "Code Review Agent", "semgrep")
        await crud.complete_scan(scan_id, 50, [canonical], "real_tools")

        findings = await crud.get_findings_by_scan(scan_id)
        assert len(findings) == 1
        f = findings[0]
        assert f["scanner"] == "semgrep"  # tool name from metadata, not agent_name
        assert f["severity"] == "HIGH"  # ERROR normalized to HIGH
        assert f["file"] == "app/main.py"
        assert f["line"] == 42
        assert f["cwe"] == ["CWE-89"]
        assert f["confidence"] == 0.9
        assert f["data_source"] == "real_tools"
        assert f["location"]["file"] == "app/main.py"
        assert f["location"]["line"] == 42

    async def test_findings_sorted_by_severity(self):
        scan_id = "test-findings-sorted-001"
        await crud.create_scan(scan_id, "https://example.com")

        findings = [
            build_canonical_finding(
                {"tool": "t", "severity": "LOW", "description": "low finding"},
                "Agent", "t"
            ),
            build_canonical_finding(
                {"tool": "t", "severity": "CRITICAL", "description": "critical finding"},
                "Agent", "t"
            ),
            build_canonical_finding(
                {"tool": "t", "severity": "HIGH", "description": "high finding"},
                "Agent", "t"
            ),
        ]
        await crud.complete_scan(scan_id, 10, findings, "real_tools")
        result = await crud.get_findings_by_scan(scan_id)
        assert len(result) == 3
        assert result[0]["severity"] == "CRITICAL"
        assert result[1]["severity"] == "HIGH"
        assert result[2]["severity"] == "LOW"

    async def test_findings_have_created_at(self):
        scan_id = "test-findings-created-001"
        await crud.create_scan(scan_id, "https://example.com")
        canonical = build_canonical_finding(
            {"tool": "t", "severity": "HIGH", "description": "test"}, "Agent", "t"
        )
        await crud.complete_scan(scan_id, 50, [canonical], "real_tools")
        findings = await crud.get_findings_by_scan(scan_id)
        assert len(findings) == 1
        assert findings[0].get("created_at") is not None


class TestCloneCleanup:
    """Verify clone directory cleanup on cancel/timeout."""

    async def test_set_and_cleanup_clone_dir(self):
        scan_id = "test-clone-cleanup-001"
        await crud.create_scan(scan_id, "https://github.com/test/repo")

        # Create a temp dir under /tmp to simulate a clone (cleanup only works under /tmp)
        tmp_base = "/tmp"
        clone_dir = os.path.join(tmp_base, "cyberpilot_clone_test_" + os.urandom(4).hex())
        os.makedirs(clone_dir)
        marker_file = os.path.join(clone_dir, "marker.txt")
        with open(marker_file, "w") as f:
            f.write("test")

        await crud.set_scan_clone_dir(scan_id, clone_dir)
        assert os.path.exists(marker_file)

        await crud.cleanup_scan_clone(scan_id)
        assert not os.path.exists(clone_dir), "Clone dir should be removed after cleanup"

    async def test_cleanup_nonexistent_clone_dir(self):
        """Cleaning up a non-existent clone dir should be a no-op."""
        scan_id = "test-clone-nonexist-001"
        await crud.create_scan(scan_id, "https://example.com")
        await crud.set_scan_clone_dir(scan_id, "/tmp/nonexistent_clone_dir_12345")
        # Should not raise
        await crud.cleanup_scan_clone(scan_id)

    async def test_cleanup_not_in_tmp(self):
        """Clone dirs outside /tmp are never deleted."""
        scan_id = "test-clone-safety-001"
        await crud.create_scan(scan_id, "https://example.com")
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_dir = os.path.join(tmpdir, "not_a_clone")
            os.makedirs(safe_dir)
            await crud.set_scan_clone_dir(scan_id, safe_dir)
            await crud.cleanup_scan_clone(scan_id)
            # Directory should still exist (outside /tmp)
            assert os.path.exists(safe_dir), "Non-/tmp dir should NOT be cleaned up"

    async def test_cleanup_null_clone_dir(self):
        """Null clone_dir is a safe no-op."""
        scan_id = "test-clone-null-001"
        await crud.create_scan(scan_id, "https://example.com")
        await crud.set_scan_clone_dir(scan_id, None)
        await crud.cleanup_scan_clone(scan_id)  # should not raise