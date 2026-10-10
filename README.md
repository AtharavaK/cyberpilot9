# CyberPilot

CyberPilot is an autonomous security assessment platform that orchestrates
specialized AI agents and open-source security tools to evaluate
authorized targets — AI applications, web services, codebases, and
infrastructure.

## Architecture

The platform runs as two local services:

- **FastAPI backend** (Python 3.11) — exposes a REST API and serves the
  built frontend. Persists all data (scans, findings, API keys) in a
  local SQLite database (`backend/cyberpilot.db`).
- **React + Vite frontend** — a single-page application served by the
  backend in production; during development it runs on its own dev server
  (port 5173) with Vite's proxy forwarding API requests to the backend.

### Orchestration

The **Master Security Agent** (`backend/app/services/master_agent.py`) is a
LangGraph state-machine that drives each scan through the following phases:

1. **Planning** — a target-aware assessment plan is created via
   `MasterSecurityAgent.create_assessment_plan()`, validated by a
   `SecurityPolicy`, and persisted to the database.
2. **Reconnaissance** — active and passive probing of HTTP endpoints
   (Nmap port scanning when applicable).
3. **Security Analysis** — a suite of specialized agents run in parallel:
   - **AI Security Agent** (Ollama provider, optional)
   - **API Security Agent** (OWASP ZAP)
   - **Code Review Agent** (Semgrep, Bandit, Gitleaks)
   - **Infrastructure Agent** (Trivy)
4. **AI Analysis** — findings are passed to the AI engine for contextual
   analysis. AI output is stored separately from scanner findings and never
   modifies the original evidence.
5. **Decision / Follow-up** — the master agent evaluates findings and may
   create follow-up tasks within a bounded iteration budget.
6. **Risk Scoring** — findings are scored and aggregated into an overall
   security score.
7. **Compliance Mapping** — findings are mapped to NIST CSF, OWASP LLM,
   and OWASP Top 10 controls.
8. **Recommendations** — prioritized remediation guidance is generated.
9. **Report Generation** — executive summary and technical PDF reports
   are produced (WeasyPrint).

### Core subsystems

- **Target Normalization** (`target_normalizer.py`) — classifies each
  target as a URL, git repository (auto-cloned to a temp dir), or local
  filesystem path, and routes it to the appropriate scanners.
- **Canonical Finding Pipeline** (`finding_normalizer.py`) — normalizes
  raw scanner output into a unified `Finding` schema, redacts secrets from
  evidence, and provides deterministic fingerprinting for deduplication.
- **Security Policy** (`planning.py`) — enforces authorization scope,
  blocks SSRF (private IPs, file:// scheme, etc.), and gates active
  scanning behind explicit `authorize=True`.
- **AI Engine** (`ai_engine.py`) — supports `MockAIProvider` (default) and
  `OllamaProvider` (when `AI_ENABLED=true`). Ollama is optional; the
  platform runs without it.
- **Tool Manager** (`tool_manager.py`) — instantiates and coordinates all
  security scanners, caching instances per tool name.

### Security tools

| Tool | Agent | What it scans |
|------|-------|---------------|
| Nmap | Recon Agent | Open ports, service/version detection, OS fingerprinting |
| OWASP ZAP | API Security Agent | Web application vulnerabilities (baseline + active scan) |
| Semgrep | Code Review Agent | Static analysis — code patterns and security anti-patterns |
| Bandit | Code Review Agent | Python-specific security linting |
| Gitleaks | Code Review Agent | Secret / credential detection in source code |
| Trivy | Infrastructure Agent | Container images, filesystems, IaC — vulnerabilities + misconfigurations |

### Authentication

API requests are authenticated with bearer tokens (`Authorization: Bearer
cpk_...`). The first user creates an API key via the `POST /setup` endpoint;
subsequent keys are managed through `GET/POST/DELETE /api/v1/auth/keys`.
Keys are stored as SHA-256 hashes in the database.

## Installation

### Prerequisites

- Python 3.11+
- Node.js 20+ (for frontend development)
- npm

### Quick start (development)

```bash
# 1. Start both backend and frontend (from project root)
./start.sh

# Backend API:   http://localhost:8000
# Frontend:      http://localhost:5173
```

The backend auto-detects the first run and redirects to `/setup` to create
an API key.

### Manual startup

```bash
# Backend
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev -- --port 5173
```

### Production frontend build

```bash
cd frontend
npm run build
```

The built files are served by the backend at `/` and `/app/`.

## Configuration

Environment variables (all optional):

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_PORT` | `8000` | Backend server port |
| `APP_ENV` | `development` | Set to `production` for production CORS restrictions |
| `APP_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated list of allowed CORS origins |
| `VITE_API_URL` | `http://localhost:8000/api/v1` | Frontend API base URL (used as fallback when no stored URL) |
| `VITE_API_PROXY_TARGET` | `http://localhost:8000` | Vite dev-server proxy target for backend API |
| `AI_ENABLED` | `false` | Enable Ollama AI analysis (`MockAIProvider` is used otherwise) |

## Testing

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

Current status: 416 tests passing (as of Phase 7B).

### Frontend

```bash
cd frontend
npm install
npx vitest run
npm run build
```

Current status: 45 tests passing; production build verified.

## Project layout

```
cyberpilot/
├── backend/
│   ├── app/
│   │   ├── api/          # REST API routes + auth
│   │   ├── db/           # SQLite persistence layer
│   │   ├── models/       # Pydantic schemas
│   │   ├── services/     # Master agent, tool manager, scanners, normalizers
│   │   └── main.py       # FastAPI application entry point
│   ├── requirements.txt
│   ├── tests/            # Backend test suite
│   └── pytest.ini
├── frontend/
│   ├── src/              # React components, pages, services
│   ├── package.json
│   └── vite.config.js
├── start.sh              # Unified dev launcher (backend + frontend)
└── README.md             # This file
```

## Documentation

- `backend/PROJECT_STATUS.md` — detailed project status and Phase tracking.
- Full API documentation is available at `/docs` (Swagger UI) when the
  backend is running.

## License

This project is for authorized security assessment use only. Only scan
targets you own or have explicit written permission to assess.
