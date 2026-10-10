# CyberPilot Frontend

A React + Vite single-page application for the CyberPilot security
assessment platform. It communicates with the FastAPI backend via a REST
API and renders scan results, findings, AI analysis, and reports.

## Development

### Prerequisites

- Node.js 20+
- npm

### Install dependencies

```bash
npm install
```

### Start development server

```bash
npm run dev
```

The dev server starts on `http://localhost:5173` and proxies API requests
to `http://localhost:8000` (the backend).

### Run tests

```bash
npm run test
# or
npx vitest run
```

### Build for production

```bash
npm run build
```

The built files are output to `dist/` and are served by the backend
during normal operation.

### Project structure

```
src/
├── pages/              # Route-level pages (Dashboard, Findings, Reports, etc.)
├── components/         # Reusable UI components
├── services/           # API client (api.js)
├── context/            # React context for shared state
├── types/              # Shared type definitions
├── assets/             # Static assets
└── __tests__/          # Vitest test suite
```
