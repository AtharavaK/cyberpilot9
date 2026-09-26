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

# Start backend
cd "$BACKEND_DIR"
source venv_linux/bin/activate 2>/dev/null || source venv/bin/activate 2>/dev/null || true
uvicorn app.main:app --host 0.0.0.0 --port "${APP_PORT:-8000}" &
BACKEND_PID=$!

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
