import urllib.request, json, time

BASE = "http://127.0.0.1:8000/api/v1"
# Bootstrap: no API key needed when no keys exist in the database.
# After creating a key via POST /auth/keys, supply it as:
#   AUTH_HEADERS = {"Authorization": f"Bearer {API_KEY}"}
AUTH_HEADERS = {"Content-Type": "application/json"}  # bootstrap mode

# --- Start scan ---
payload = json.dumps({"target_url": "https://demo-ai-app.com"}).encode()
req = urllib.request.Request(f"{BASE}/scan/start", data=payload,
                             headers=AUTH_HEADERS, method="POST")
with urllib.request.urlopen(req) as r:
    start_resp = json.loads(r.read())

scan_id = start_resp["scan_id"]
print(f"[START] scan_id={scan_id}  status={start_resp['status']}")
print(f"        message={start_resp['message']}")

# --- Poll status ---
for attempt in range(10):
    time.sleep(2)
    req = urllib.request.Request(f"{BASE}/scan/{scan_id}/status", headers=AUTH_HEADERS)
    with urllib.request.urlopen(req) as r:
        status_resp = json.loads(r.read())
    current = status_resp.get("status", "COMPLETED")
    print(f"[POLL {attempt+1}] status={current}")
    if current == "COMPLETED" or "overall_score" in status_resp:
        print("\n=== FINAL REPORT ===")
        print(f"  Target:        {status_resp.get('target_url')}")
        print(f"  Overall Score: {status_resp.get('overall_score')}/100")
        print(f"  Findings ({len(status_resp.get('findings', []))}):")
        for f in status_resp.get("findings", []):
            print(f"    [{f['severity']}] {f['agent_name']}: {f['description']}")
            if f.get('remediation'):
                print(f"           -> {f['remediation']}")
        
        # Check compliance
        if status_resp.get("compliance"):
            print(f"\n  Compliance Mappings ({len(status_resp.get('compliance', []))}):")
            for c in status_resp.get("compliance", []):
                print(f"    {c['agent_name']}: {', '.join(c['owasp_llm'])} | {', '.join(c['nist_csf'])}")
        
        # Check PDF links
        if status_resp.get("executive_summary_pdf"):
            print(f"\n  Executive Summary PDF: {status_resp['executive_summary_pdf']}")
        if status_resp.get("technical_report_pdf"):
            print(f"  Technical Report PDF: {status_resp['technical_report_pdf']}")
        
        # Test PDF downloads
        print("\n=== PDF DOWNLOAD TEST ===")
        exec_resp = urllib.request.urlopen(urllib.request.Request(f"{BASE}/scan/{scan_id}/report/executive-summary", headers=AUTH_HEADERS))
        print(f"  Executive Summary: {exec_resp.status} - {len(exec_resp.read())} bytes")
        
        tech_resp = urllib.request.urlopen(urllib.request.Request(f"{BASE}/scan/{scan_id}/report/technical", headers=AUTH_HEADERS))
        print(f"  Technical Report: {tech_resp.status} - {len(tech_resp.read())} bytes")
        
        print("\n=== ALL TESTS PASSED ===")
        break
