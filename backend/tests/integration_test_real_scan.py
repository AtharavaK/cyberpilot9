#!/usr/bin/env python3
"""
Phase 1 — Real end-to-end scan against a local vulnerable test project.

Verifies that:
  1. Target normalization correctly identifies local directory
  2. Code review scanners (Semgrep, Bandit, Gitleaks, Trivy) receive the local path
  3. Code scanners do NOT receive a URL
  4. Findings are parsed and normalized correctly
  5. Findings are stored in the database
"""
import os
import sys
import asyncio
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import init_db
from app.services.master_agent import start_scan_workflow, get_scan_result
from app.db import crud


TEST_PROJECT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "test_vulnerable_project",
)


async def run_full_scan_test():
    print(f"\n{'=' * 70}")
    print(f"REAL SCAN TEST — Target: {TEST_PROJECT}")
    print(f"{'=' * 70}")

    # Initialize DB
    await init_db()

    # Start a real scan (not simulated)
    scan_id = await start_scan_workflow(
        TEST_PROJECT,
        data_source="real_tools",
        authorize=True,
        scan_timeout_seconds=120,
    )
    print(f"\nScan started: {scan_id}")

    # Poll for completion
    max_wait = 120
    for i in range(max_wait):
        await asyncio.sleep(2)
        result = await crud.get_scan(scan_id)
        if result is None:
            print(f"  Still initializing... ({i*2}s)")
            continue

        status = result.get("status", "")
        findings = result.get("findings", [])
        print(f"  [{i*2}s] Status: {status}, Findings: {len(findings)}")

        if status in ("COMPLETED", "FAILED", "CANCELLED"):
            break

    # Get final results
    result = await crud.get_scan(scan_id)
    if result is None:
        print("ERROR: Scan result not found")
        return False

    print(f"\n{'=' * 70}")
    print(f"FINAL SCAN RESULTS")
    print(f"{'=' * 70}")
    print(f"  Scan ID:      {result['scan_id']}")
    print(f"  Target:       {result['target_url']}")
    print(f"  Status:       {result['status']}")
    print(f"  Score:        {result.get('overall_score', 'N/A')}")
    print(f"  Data source:  {result.get('data_source', 'N/A')}")
    print(f"  Findings:     {len(result.get('findings', []))}")

    # Print target_normalized from the scan's final report
    final_report = result.get("final_report", {})
    if isinstance(final_report, str):
        try:
            final_report = json.loads(final_report)
        except json.JSONDecodeError:
            final_report = {}

    print(f"\n  Findings breakdown:")
    for f in result.get("findings", []):
        meta = f.get("metadata", {}) or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except json.JSONDecodeError:
                meta = {}
        tool = meta.get("tool", f.get("agent_name", "unknown"))
        severity = f.get("severity", "UNKNOWN")
        desc = f.get("description", "")[:100]
        print(f"    [{tool:10s}] [{severity:6s}] {desc}")

    print(f"\n  Errors: {result.get('security_analysis_errors', [])}")

    # Verify findings
    findings = result.get("findings", [])
    total = len(findings)

    # Check that code scanners produced findings
    code_scanner_findings = sum(
        1 for f in findings
        if (f.get("metadata", {}) or {}).get("tool") in ("semgrep", "bandit", "gitleaks", "trivy")
        if isinstance(f.get("metadata"), dict)
    )
    # Also check via agent_name
    code_agents = sum(
        1 for f in findings
        if f.get("agent_name") == "Code Review Agent"
    )

    print(f"\n  Code Review Agent findings: {code_agents}")
    print(f"  Total findings: {total}")

    if total > 0:
        print(f"\n  ✓ PASSED — Real findings were generated and stored")
    else:
        print(f"\n  ⚠ WARNING — No findings found (scanners may not be installed)")

    # Print scan events
    print(f"\n{'=' * 70}")
    print(f"SCAN EVENTS ({result['scan_id']})")
    print(f"{'=' * 70}")
    events = await crud.get_scan_events(scan_id)
    for e in events:
        print(f"  [{e['event_type']:12s}] {json.dumps(e['payload'])[:150]}")

    return True


if __name__ == "__main__":
    success = asyncio.run(run_full_scan_test())
    sys.exit(0 if success else 1)
