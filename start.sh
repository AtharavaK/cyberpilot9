#!/bin/bash
# CyberPilot — Unified launcher
# Starts backend API + frontend dev server with environment config.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

# Load .env if present
if [ -f "$SCRIPT_DIR/.env" ]; then
    echo "[CyberPilot] Loading .env..."
    set -a
    . "$SCRIPT_DIR/.env"
    set +a
fi

echo "[CyberPilot] Starting backend on port ${APP_PORT:-8000}..."
echo "[CyberPilot] Frontend will proxy to backend at ${VITE_API_PROXY_TARGET:-http://localhost:8000}"

# Ensure backend venv exists and deps are installed (WSL/Linux)
if ! ls "$BACKEND_DIR/.venv/bin/python" >/dev/null 2>&1 && ! ls "$BACKEND_DIR/venv/bin/python" >/dev/null 2>&1; then
    echo "[CyberPilot] Backend venv not found. Creating with uv..."
    cd "$BACKEND_DIR"
    if command -v uv >/dev/null 2>&1; then
        uv venv --python python3 .venv 2>/dev/null || uv venv .venv 2>/dev/null || true
    fi
    if ls .venv/bin/python >/dev/null 2>&1; then
        .venv/bin/python -m pip install -r requirements.txt 2>/dev/null || true
    fi
fi

# Start backend
cd "$BACKEND_DIR"
if ls .venv/bin/python >/dev/null 2>&1; then
    .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port "${APP_PORT:-8000}" &
elif command -v uv >/dev/null 2>&1 && ls .venv/bin/python >/dev/null 2>&1; then
    .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port "${APP_PORT:-8000}" &
else
    echo "[CyberPilot] WARNING: No backend Python venv found. Install deps first:"
    echo "  cd backend && uv venv && .venv/bin/python -m pip install -r requirements.txt"
    echo "Starting without backend..."
    BACKEND_PID=""
fi

# Give backend a moment to start
sleep 2

# Start frontend (with Vite proxy to backend so no CORS issues in dev)
cd "$FRONTEND_DIR"
npm run dev -- --port "${FRONTEND_PORT:-5173}" &
FRONTEND_PID=$!

echo ""
echo "[CyberPilot] Backend PID: $BACKEND_PID (http://localhost:${APP_PORT:-8000})"
echo "[CyberPilot] Frontend PID: $FRONTEND_PID (http://localhost:${FRONTEND_PORT:-5173})"
echo "[CyberPilot] Press Ctrl+C to stop both"

# Trap to clean up on exit
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" SIGINT SIGTERM

# Wait for either to exit
wait
