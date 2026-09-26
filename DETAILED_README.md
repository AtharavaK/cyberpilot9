# CyberPilot - Detailed Architecture and Agent Roles

## 1. Project Overview
CyberPilot is an Agentic AI platform for autonomous security assessment of AI applications. The platform identifies vulnerabilities, evaluates risks, and generates remediation recommendations, maintaining a human-in-the-loop approach.

## 2. Architecture
The system follows a multi-agent architecture:
`User → Dashboard → API Gateway → Master Agent → Specialised Agents → Knowledge Base → Database → Reports`

## 3. Specialized Agents

| Agent Name | Primary Responsibility | Focus Areas | Simulated Tools | Deliverables |
| --- | --- | --- | --- | --- |
| **Master Agent** | Workflow coordination | Assessment planning | N/A | Assessment plan |
| **Recon Agent** | Collect authorized info | APIs, Auth methods, Public endpoints | Nmap | Target information |
| **AI Security Agent** | AI-specific vulnerabilities | Prompt injection, Jailbreak, Data exposure | N/A | AI vulnerability analysis |
| **API Security Agent** | API security | Auth, API keys, Rate limiting, CORS | OWASP ZAP | API security assessment |
| **Code Review Agent** | Source code review | Hardcoded credentials, Dependency flaws | Semgrep, Bandit, Gitleaks | Code review findings |
| **Infrastructure Agent** | Deployment security | Docker, TLS, DB config | Trivy | Infrastructure assessment |
| **Risk Analysis Agent** | Severity calculation | Risk score, Severity level, Business impact | N/A | Overall Security Score |
| **Compliance Agent** | Standards mapping | Compliance status | N/A | Compliance Report (OWASP, NIST) |
| **Recommendation Agent** | Remediation guidance | Secure coding, Best practices | N/A | Developer Action Plan |
| **Report Agent** | Structured reports | Technical and executive docs | N/A | Executive Summary, PDF Export |

## 4. Technology Stack
The full theoretical implementation utilizes:
- **Backend/Framework:** Python, FastAPI, LangGraph
- **Frontend:** React, Tailwind CSS
- **LLM/DB:** Ollama, PostgreSQL/SQLite, ChromaDB
- **Security Tools:** OWASP ZAP, Semgrep, Bandit, Trivy, Gitleaks, Nmap

## 5. Workflow Execution
1. **Authorisation:** Verify permissions and scope.
2. **Recon:** Gather intel on the application structure.
3. **Security Analysis:** Specialized agents perform checks concurrently.
4. **Risk Scoring:** Aggregate findings into a quantifiable score.
5. **Compliance Mapping:** Map findings to OWASP LLM Top 10 and NIST frameworks.
6. **Recommendations:** Formulate actionable remediation steps.
7. **Reporting:** Generate executive and technical reports for human review.
