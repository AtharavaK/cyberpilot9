@echo off
echo Starting CyberPilot Backend and Frontend...

cd backend
REM Start backend server
start cmd /k ".\venv\Scripts\activate && uvicorn app.main:app --port 8000 --reload"

cd ..\frontend
REM Start frontend dev server
start cmd /k "npm run dev"

echo Both servers started!
