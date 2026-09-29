from fastapi import FastAPI, Request, Form
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import os as _os
import sys as _sys
import webbrowser
import threading
import time

# ── Path resolution ──────────────────────────────────────────────────────────
# PyInstaller one-dir mode: bundled files are in _MEIPASS (next to .exe as _internal/)
#   cyberpilot.exe
#   _internal/     <-- PyInstaller archive (contains app/, frontend/dist/, runtime/)
#   cyberpilot.db  (created at runtime, alongside .exe)
#
# Works in development too (from source tree).
if getattr(_sys, "frozen", False):
    _MEIPASS = _sys._MEIPASS
    _EXE_DIR = _os.path.dirname(_sys.executable)
    _FRONTEND_DIST = _os.path.join(_MEIPASS, "frontend", "dist")
    _APP_DIR = _MEIPASS
    _DB_PATH = _os.path.join(_EXE_DIR, "cyberpilot.db")
    # Add runtime DLL directory to Windows DLL search path (for WeasyPrint GTK3)
    _RUNTIME_DIR = _os.path.join(_MEIPASS, "runtime")
    if _os.path.isdir(_RUNTIME_DIR):
        try:
            _os.add_dll_directory(_RUNTIME_DIR)
        except (AttributeError, OSError):
            pass  # Python < 3.8 or non-Windows
else:
    _APP_DIR = _os.path.dirname(_os.path.abspath(__file__))
    _BACKEND_DIR = _os.path.dirname(_APP_DIR)
    _FRONTEND_DIST = _os.path.join(_BACKEND_DIR, "frontend", "dist")
    _DB_PATH = _os.path.join(_BACKEND_DIR, "cyberpilot.db")

# ── Configurable port ────────────────────────────────────────────────────────
import argparse as _argparse
_arg_parser = _argparse.ArgumentParser(add_help=False)
_arg_parser.add_argument("--port", type=int, default=None)
_arg_opts, _ = _arg_parser.parse_known_args()
if _arg_opts.port is not None:
    _APP_PORT = _arg_opts.port
else:
    _APP_PORT = int(_os.environ.get("APP_PORT", 8000))

# Fresh-start flag: standalone .exe always starts with no pre-existing keys
_HAS_EXISTING_KEYS = False

app = FastAPI(
    title="CyberPilot",
    description="Agentic AI Platform for Autonomous Security Assessment",
    version="1.0.0",
)

# CORS
_raw_origins = _os.environ.get("APP_CORS_ORIGINS",
    "http://localhost:5173,http://localhost:5174,http://localhost:5175,"
    "http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:5175,"
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:*")
_ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount frontend assets
if _os.path.isdir(_FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=_os.path.join(_FRONTEND_DIST, "assets")), name="frontend_assets")

# Import routers
from app.api.endpoints import router as api_router
from app.api.auth_routes import router as auth_router
from app.db.database import init_db

app.include_router(api_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")

# ── Override DB path used by database.py ─────────────────────────────────────
import app.db.database as _db_mod
_db_mod.DB_PATH = _DB_PATH

@app.on_event("startup")
async def startup_event():
    await init_db()
    # Auto-open browser after a short delay
    def _open_browser():
        time.sleep(2)
        webbrowser.open(f"http://localhost:{_APP_PORT}")
    threading.Thread(target=_open_browser, daemon=True).start()

# ── Setup page HTML ──────────────────────────────────────────────────────────
_SETUP_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberPilot — Setup</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0f111a;
    color: #e1e4f0;
  }
  .setup-card {
    background: #1a1d2e;
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 16px;
    padding: 2.5rem;
    width: 100%;
    max-width: 420px;
    box-shadow: 0 25px 50px rgba(0,0,0,0.4);
  }
  .logo {
    font-size: 1.5rem;
    font-weight: 700;
    color: #00f0ff;
    margin-bottom: 0.25rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .logo svg { width: 28px; height: 28px; }
  .subtitle { color: #7a7f9a; font-size: 0.875rem; margin-bottom: 2rem; }
  h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 0.5rem; }
  p.desc { color: #7a7f9a; font-size: 0.875rem; margin-bottom: 1.5rem; line-height: 1.5; }
  .key-display {
    background: #12141f;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    font-size: 0.8125rem;
    color: #00f0ff;
    word-break: break-all;
    user-select: all;
    margin-bottom: 0.5rem;
    cursor: pointer;
    min-height: 2.5rem;
    display: flex;
    align-items: center;
  }
  .key-display:hover { border-color: rgba(0,240,255,0.3); }
  .key-label {
    font-size: 0.75rem;
    color: #7a7f9a;
    margin-bottom: 0.375rem;
    display: block;
  }
  button.primary {
    width: 100%;
    padding: 0.75rem 1rem;
    background: #00f0ff;
    color: #0f111a;
    border: none;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
    margin-top: 1rem;
  }
  button.primary:hover { background: #33f5ff; transform: translateY(-1px); }
  button.secondary {
    width: 100%;
    padding: 0.625rem 1rem;
    background: transparent;
    color: #7a7f9a;
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 8px;
    font-size: 0.8125rem;
    cursor: pointer;
    margin-top: 0.5rem;
    transition: all 0.15s;
  }
  button.secondary:hover { border-color: rgba(255,255,255,0.2); color: #e1e4f0; }
  .error { color: #ff5c5c; font-size: 0.8125rem; margin-bottom: 1rem; display: none; }
  .spinner {
    display: inline-block;
    width: 16px; height: 16px;
    border: 2px solid rgba(0,240,255,0.2);
    border-top-color: #00f0ff;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
    margin-right: 0.5rem;
    vertical-align: middle;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .footer { margin-top: 1.5rem; font-size: 0.75rem; color: #4a4f6a; text-align: center; }
</style>
</head>
<body>
<div class="setup-card">
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 2L2 7l10 5 10-5-10-5z"/>
      <path d="M2 17l10 5 10-5"/>
      <path d="M2 12l10 5 10-5"/>
    </svg>
    CyberPilot
  </div>
  <div class="subtitle">Security Assessment Platform</div>
  <h1 id="title">Create your API key</h1>
  <p class="desc" id="desc">This is the first time CyberPilot is running on this machine. Create an API key to authenticate with the platform.</p>
  <label class="key-label" id="keyLabel" style="display:none;">Your API Key — click to copy</label>
  <div class="key-display" id="keyDisplay" style="display:none;" onclick="copyKey()"></div>
  <div class="error" id="errorMsg"></div>
  <button class="primary" id="actionBtn" onclick="generateKey()">Generate API Key</button>
  <button class="secondary" id="retryBtn" style="display:none;" onclick="generateKey()">Generate another key</button>
  <div class="footer">CyberPilot v1.0.0 — Running locally</div>
</div>
<script>
  let currentKey = null;
  async function generateKey() {
    const btn = document.getElementById('actionBtn');
    const retry = document.getElementById('retryBtn');
    const keyDisplay = document.getElementById('keyDisplay');
    const keyLabel = document.getElementById('keyLabel');
    const errorMsg = document.getElementById('errorMsg');
    const title = document.getElementById('title');
    const desc = document.getElementById('desc');
    errorMsg.style.display = 'none';
    errorMsg.textContent = '';
    btn.innerHTML = '<span class="spinner"></span>Creating key...';
    btn.disabled = true;
    try {
      const formData = new FormData();
      formData.append('name', 'local-setup');
      const res = await fetch('/setup', { method: 'POST', body: formData });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Failed to create key' }));
        throw new Error(err.detail || 'Failed to create API key');
      }
      const data = await res.json();
      currentKey = data.key;
      keyDisplay.textContent = currentKey;
      keyDisplay.style.display = 'flex';
      keyLabel.style.display = 'block';
      title.textContent = 'Your API key is ready';
      desc.textContent = 'Save this key somewhere safe. You will need it to authenticate with the CyberPilot API.';
      btn.style.display = 'none';
      retry.style.display = 'block';
      // Show "Go to App" button
      const goBtn = document.createElement('button');
      goBtn.className = 'primary';
      goBtn.textContent = 'Go to CyberPilot';
      goBtn.style.marginTop = '1rem';
      goBtn.onclick = () => { window.location.href = '/'; };
      actionBtn.parentNode.insertBefore(goBtn, actionBtn.nextSibling);
      // Auto-redirect after 5 seconds
      setTimeout(() => { window.location.href = '/'; }, 5000);
    } catch (err) {
      errorMsg.textContent = err.message;
      errorMsg.style.display = 'block';
      btn.innerHTML = 'Generate API Key';
      btn.disabled = false;
    }
  }
  function copyKey() {
    const el = document.getElementById('keyDisplay');
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
</script>
</body>
</html>"""

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Serve frontend, or redirect to setup if no keys exist."""
    from app.db import crud
    async def check_keys():
        try:
            keys = await crud.list_api_keys()
            return len([k for k in keys if k.get("is_active", False)]) > 0
        except Exception:
            return False
    if not await check_keys():
        return RedirectResponse(url="/setup")
    index_path = _os.path.join(_FRONTEND_DIST, "index.html")
    if _os.path.isfile(index_path):
        return FileResponse(index_path)
    return HTMLResponse("""<!DOCTYPE html>
<html><head><meta http-equiv="refresh" content="0;url=/app/"></head>
<body><p>Loading CyberPilot...</p></body></html>""")

@app.get("/app/", response_class=HTMLResponse)
async def serve_app(request: Request):
    """Serve the frontend SPA."""
    index_path = _os.path.join(_FRONTEND_DIST, "index.html")
    if _os.path.isfile(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<html><body><h1>CyberPilot</h1><p>Frontend not built.</p></body></html>")

@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    """First-time API key creation page."""
    return HTMLResponse(_SETUP_PAGE)

@app.post("/setup", response_class=JSONResponse)
async def create_first_key(name: str = Form("default")):
    """Create the first API key."""
    import secrets, hashlib, time
    from app.db import crud
    api_key = f"cpk_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    key_prefix = api_key[:8]
    now = int(time.time())
    await crud.create_api_key(key_hash, key_prefix, name)
    return JSONResponse(content={"key": api_key, "name": name})

@app.get("/health")
async def health_check():
    return {"status": "ok", "port": _APP_PORT}

@app.get("/api")
async def api_info():
    return {"message": "Welcome to the CyberPilot API Gateway",
            "docs": "/docs",
            "app": "/app/",
            "port": _APP_PORT}

if __name__ == "__main__" or getattr(_sys, "frozen", False):
    import uvicorn as _uvicorn

    print("=" * 60)
    print("CyberPilot — Security Assessment Platform")
    print("=" * 60)
    print(f"Port: {_APP_PORT}")
    print(f"Database: {_DB_PATH}")
    print(f"Frontend: {_FRONTEND_DIST}")
    print(f"Frozen: {getattr(_sys, 'frozen', False)}")
    print(f"API Keys: {'EXISTING' if _HAS_EXISTING_KEYS else 'FRESH (no keys yet)'}")
    print("=" * 60)

    # Open browser on startup (frozen mode only)
    if getattr(_sys, "frozen", False):
        import webbrowser as _wb, threading as _th
        _th.Thread(target=lambda: _wb.open(f"http://localhost:{_APP_PORT}"), daemon=True).start()

    _uvicorn.run(app, host="0.0.0.0", port=_APP_PORT, log_level="info")
