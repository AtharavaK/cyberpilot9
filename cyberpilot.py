import time
import sys
import argparse
import os

def print_step(step_name, description):
    print(f"\n[{step_name}] {description}")
    print("-" * 60)
    time.sleep(1)

def simulate_agent(agent_name, responsibility, output_lines):
    print(f"--> Invoking {agent_name}...")
    print(f"    Responsibility: {responsibility}")
    time.sleep(1.5)
    for line in output_lines:
        print(f"    [+] {line}")
        time.sleep(0.5)
    print(f"--> {agent_name} completed.\n")

def generate_mock_reports(target):
    output_dir = "output/reports"
    os.makedirs(output_dir, exist_ok=True)
    
    exec_summary_path = os.path.join(output_dir, "executive_summary.md")
    with open(exec_summary_path, "w") as f:
        f.write(f"# Executive Summary: {target}\n\n")
        f.write("## Overview\nCyberPilot has completed the autonomous security assessment of the target application.\n")
        f.write("## Overall Security Score\n**78/100 (Fair)**\n\n")
        f.write("## Key Findings\n- 1 High Severity: Missing rate limits on `/api/v1/chat`.\n")
        f.write("- 2 Medium Severity: Outdated dependency, environment variables in docker-compose.\n")
    
    tech_report_path = os.path.join(output_dir, "technical_report.md")
    with open(tech_report_path, "w") as f:
        f.write(f"# Technical Vulnerability Report: {target}\n\n")
        f.write("## 1. Prompt Injection & Jailbreak (AI Security Agent)\n")
        f.write("- **Status**: Vulnerability Detected\n- **Details**: Mild susceptibility to role-play jailbreak.\n- **Remediation**: Implement input sanitization and strict system prompts.\n\n")
        f.write("## 2. Missing Rate Limiting (API Security Agent)\n")
        f.write("- **Status**: Vulnerability Detected\n- **Details**: The `/api/v1/chat` endpoint allows unlimited requests.\n- **Remediation**: Use Redis-based rate limiting (e.g., 60 req/min per IP).\n\n")
        f.write("## 3. Outdated Dependencies (Code Review Agent)\n")
        f.write("- **Status**: Warning\n- **Details**: `requests v2.25.0` is outdated.\n- **Remediation**: Update 'requests' library to the latest secure version.\n")

def main():
    parser = argparse.ArgumentParser(description="CyberPilot - Autonomous Multi-Agent AI Security Assessment")
    parser.add_argument("--target", required=True, help="The target URL or application to assess (e.g., https://my-ai-app.com)")
    args = parser.parse_args()

    target = args.target

    print("=" * 60)
    print(" CyberPilot - Autonomous Multi-Agent AI Security Assessment")
    print(f" Target: {target}")
    print("=" * 60)
    time.sleep(1)

    print("\nInitializing Master Agent Workflow...")
    time.sleep(1)

    # 1. Authorisation
    print_step("AUTHORISATION", "Verifying target scope and permissions...")
    print(f"    [+] Target scope ({target}) authorized.")
    print("    [+] Authentication credentials loaded.")
    time.sleep(1)

    # 2. Recon
    print_step("RECONNAISSANCE", "Collecting authorized target information.")
    simulate_agent(
        "Recon Agent",
        "Collection of authorized target information (APIs, Auth, AI models, Public endpoints)",
        [
            f"Discovered 3 public API endpoints for {target}.",
            "Identified LLM interaction endpoint (/api/v1/chat).",
            "Detected OAuth 2.0 authentication method."
        ]
    )

    # 3. Security Analysis
    print_step("SECURITY ANALYSIS", "Running specialized agents for in-depth security assessment.")
    simulate_agent(
        "AI Security Agent",
        "Evaluation of AI-specific vulnerabilities (Prompt injection, Jailbreak resilience, etc.)",
        [
            "Testing Prompt Injection...",
            "VULNERABILITY DETECTED: Mild susceptibility to role-play jailbreak.",
            "Testing Sensitive Data Exposure...",
            "PASS: No PII leakage detected in model responses."
        ]
    )
    
    simulate_agent(
        "API Security Agent",
        "Assessment of API security (Auth, Rate Limiting, CORS, etc.)",
        [
            "Running OWASP ZAP simulated scan...",
            "PASS: HTTPS enforced.",
            "WARNING: Rate limiting missing on /api/v1/chat endpoint.",
            "PASS: CORS policy is restrictive."
        ]
    )

    simulate_agent(
        "Code Review Agent",
        "Review of application source code for insecure practices",
        [
            "Running SAST tools (Semgrep, Bandit)...",
            "PASS: No hardcoded secrets detected.",
            "WARNING: Outdated dependency (requests v2.25.0) detected."
        ]
    )

    simulate_agent(
        "Infrastructure Agent",
        "Analysis of deployment security (Docker, DB, TLS)",
        [
            "Scanning Docker configuration...",
            "PASS: Docker image runs as non-root user.",
            "WARNING: Environment variables passed directly in docker-compose.yml."
        ]
    )

    # 4. Risk Scoring
    print_step("RISK SCORING", "Calculating severity and prioritization.")
    simulate_agent(
        "Risk Analysis Agent",
        "Severity calculation and prioritization",
        [
            "Calculating aggregate risk score...",
            "Overall Security Score: 78/100 (Fair)",
            "Risk Distribution: 1 High, 2 Medium, 0 Low.",
            "High Priority: Implement rate limiting on /api/v1/chat."
        ]
    )

    # 5. Compliance Mapping
    print_step("COMPLIANCE MAPPING", "Mapping findings to recognized standards.")
    simulate_agent(
        "Compliance Agent",
        "Mapping findings to recognized standards",
        [
            "Checking against OWASP Top 10 for LLM Applications...",
            "FINDING MAPS TO: LLM04: Model Denial of Service (due to missing rate limits).",
            "Checking against NIST Cybersecurity Framework...",
            "Alignment check complete."
        ]
    )

    # 6. Recommendations
    print_step("RECOMMENDATIONS", "Generating remediation guidance.")
    simulate_agent(
        "Recommendation Agent",
        "Generation of remediation guidance",
        [
            "Guidance for Role-Play Jailbreak: Implement input sanitization and strict system prompts.",
            "Guidance for Rate Limiting: Use Redis-based rate limiting (e.g., 60 req/min per IP).",
            "Guidance for Dependencies: Update 'requests' library to the latest secure version."
        ]
    )

    # 7. Report & Dashboard
    print_step("REPORT & EXPORT", "Creating structured reports.")
    simulate_agent(
        "Report Agent",
        "Creation of structured reports (Executive Summary, Technical Report)",
        [
            "Generating Executive Summary PDF (mocked as .md)...",
            "Generating Technical Vulnerability Report...",
        ]
    )
    
    print("    [+] Saving reports to output/reports/ directory...")
    generate_mock_reports(target)
    time.sleep(1)
    print("    [+] Reports successfully saved.")
    print("--> Report Agent completed.\n")

    print("=" * 60)
    print(" Assessment Complete. Human-in-the-loop review recommended.")
    print("=" * 60)
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAssessment aborted by user.")
        sys.exit(0)
