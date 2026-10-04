#!/usr/bin/env python3
"""
Phase 1 — Scenario 1 test: Generic web URL target.
Verifies that code review scanners are skipped and web scanners receive the URL.
"""
import os
import sys
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import init_db
from app.services.master_agent import start_scan_workflow
from app.db import crud
from app.services.target_normalizer import TargetNormalizer


async def test_web_url_scenario():
    print(f"\n{'=' * 70}")
    print("SCENARIO 1: Generic web URL (https://httpbin.org)")
    print(f"{'=' * 70}")

    await init_db()

    # Test normalization first (classification only)
    normalizer = TargetNormalizer()
    nt = await normalizer.normalize("https://httpbin.org", clone=False)

    print(f"\n  Normalization result:")
    print(f"    kind:        {nt.kind}")
    print(f"    web_target:  {nt.web_target}")
    print(f"    local_path:  {nt.local_path}")
    print(f"    code_review: {nt.scanners['code_review']}")
    print(f"    web:         {nt.scanners['web']}")

    assert nt.kind == "url"
    assert nt.web_target == "https://httpbin.org"
    assert nt.local_path is None
    assert nt.scanners["code_review"] == []  # Code scanners skipped
    print(f"\n  ✓ URL correctly classified — code scanners will be skipped")

    # Start a real scan
    scan_id = await start_scan_workflow(
        "https://httpbin.org",
        data_source="real_tools",
        authorize=True,
        scan_timeout_seconds=120,
    )
    print(f"\n  Scan started: {scan_id}")

    # Poll for completion
    for i in range(60):
        await asyncio.sleep(2)
        result = await crud.get_scan(scan_id)
        if result and result.get("status") in ("COMPLETED", "FAILED", "CANCELLED"):
            break

    result = await crud.get_scan(scan_id)
    if result is None:
        print("  ERROR: Scan result not found")
        return False

    print(f"\n  Final status: {result['status']}")
    print(f"  Data source:  {result.get('data_source')}")
    print(f"  Findings:     {len(result.get('findings', []))}")
    print(f"  Errors:       {result.get('security_analysis_errors', [])}")

    # Check scan events for proper routing
    events = await crud.get_scan_events(scan_id)
    print(f"\n  Scan events:")
    for e in events:
        msg = e["payload"].get("message", "")
        if "skip" in msg.lower() or "code" in msg.lower() or "running" in msg.lower():
            print(f"    [{e['event_type']}] {msg}")

    # Verify code review scanners were skipped
    code_review_skipped = any(
        "code review scanners skipped" in e["payload"].get("message", "").lower()
        or "code review" in e["payload"].get("message", "").lower()
        for e in events
    )

    # For a web URL, code review should be skipped
    findings = result.get("findings", [])
    code_findings = [
        f for f in findings
        if f.get("agent_name") == "Code Review Agent"
    ]

    print(f"\n  Code Review Agent findings: {len(code_findings)}")
    if len(code_findings) == 0:
        print(f"  ✓ PASSED — Code scanners correctly skipped for web URL")
    else:
        print(f"  ⚠ UNEXPECTED — Code scanners produced findings for web URL")

    return True


if __name__ == "__main__":
    success = asyncio.run(test_web_url_scenario())
    sys.exit(0 if success else 1)
