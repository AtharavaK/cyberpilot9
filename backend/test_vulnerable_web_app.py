"""
Intentionally vulnerable web application for Phase 4 ZAP testing.

Runs a small Flask-like app on localhost:5000 with known vulnerabilities:
  - XSS in /search
  - SQL injection in /api/user
  - Command injection in /api/ping
  - Info disclosure in /debug
  - Weak headers (no CSP, no HSTS)
  - Directory listing / missing auth
  - Hardcoded secret in /config.js
  - Open redirect in /redirect

Usage:
    python3 vulnerable_web_app.py
    # Then: python3 -m zap-baseline.py -t http://localhost:5000
"""
import http.server
import json
import os
import subprocess
import urllib.parse
from http import HTTPStatus


PORT = 5000
HOST = "localhost"


# Page templates
HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>Vulnerable App</title></head>
<body>
{content}
</body>
</html>"""


class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler with intentionally vulnerable endpoints."""

    def _send_html(self, body, status=200, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Intentionally missing security headers: no CSP, no HSTS, no X-Frame-Options
        extra_headers = extra_headers or {}
        for k, v in extra_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _send_json(self, data, status=200, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        extra_headers = extra_headers or {}
        for k, v in extra_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # ── 1. XSS in /search ──────────────────────────────────────
        if path == "/search":
            query = params.get("q", [""])[0]
            # Reflected XSS — query parameter is inserted into HTML without escaping
            content = f"""
<h1>Search Results</h1>
<p>You searched for: {query}</p>
<form method="GET" action="/search">
    <input type="text" name="q" value="{query}">
    <button type="submit">Search</button>
</form>
"""
            self._send_html(HTML_TEMPLATE.format(content=content))
            return

        # ── 2. SQL injection in /api/user ────────────────────────────
        if path == "/api/user":
            user_id = params.get("id", ["1"])[0]
            # Simulated SQL injection — in a real app this would hit a DB
            # For testing, we just return data that reflects the input
            content = f"""
<h1>API: User Lookup</h1>
<p>Query: SELECT * FROM users WHERE id = '{user_id}'</p>
<p>User: admin (id=1, role=admin)</p>
<p>User: guest (id=2, role=user)</p>
<form method="GET" action="/api/user">
    <input type="text" name="id" value="{user_id}">
    <button type="submit">Lookup</button>
</form>
"""
            self._send_html(HTML_TEMPLATE.format(content=content))
            return

        # ── 3. Command injection in /api/ping ─────────────────────────
        if path == "/api/ping":
            host = params.get("host", ["localhost"])[0]
            # Intentionally vulnerable to command injection
            try:
                result = subprocess.check_output(
                    f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT,
                    timeout=5
                ).decode("utf-8", errors="replace")
            except Exception as e:
                result = str(e)
            content = f"""
<h1>Ping Result</h1>
<pre>{result}</pre>
"""
            self._send_html(HTML_TEMPLATE.format(content=content))
            return

        # ── 4. Info disclosure in /debug ──────────────────────────────
        if path == "/debug":
            content = HTML_TEMPLATE.format(content="""
<h1>Debug Information</h1>
<pre>
SECRET_KEY: 9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c
DATABASE_URL: postgresql://admin:s3cr3t@db.internal:5432/app
DEBUG: True
ADMIN_TOKEN: ghp_abcdefghijklmnopqrstuvwxyz0123456789
</pre>
""")
            self._send_html(content)
            return

        # ── 5. Hardcoded secret in /config.js ────────────────────────
        if path == "/config.js":
            content = """
// Frontend configuration
window.APP_CONFIG = {
    apiUrl: "http://localhost:5000/api",
    debug: true,
    apiKey: "sk-1234567890abcdefghijklmnop",
    // Hardcoded AWS credentials — should never be in client-side JS
    awsAccessKey: "AKIAIOSFODNN7EXAMPLE",
    awsSecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
};
"""
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
            return

        # ── 6. Open redirect in /redirect ────────────────────────────
        if path == "/redirect":
            to = params.get("to", [""])[0]
            if to:
                self._redirect(to)
                return
            content = HTML_TEMPLATE.format(content="""
<h1>Redirect</h1>
<form method="GET" action="/redirect">
    <input type="text" name="to" placeholder="Enter URL">
    <button type="submit">Go</button>
</form>
""")
            self._send_html(content)
            return

        # ── 7. Missing security headers on all responses ────────────
        # All responses intentionally lack CSP, HSTS, X-Frame-Options

        # ── 8. Directory listing simulation ───────────────────────────
        if path == "/uploads":
            content = HTML_TEMPLATE.format(content="""
<h1>Uploads Directory</h1>
<ul>
    <li><a href="/uploads/backup.zip">backup.zip</a></li>
    <li><a href="/uploads/config.bak">config.bak</a></li>
    <li><a href="/uploads/2024-01-report.pdf">2024-01-report.pdf</a></li>
</ul>
""")
            self._send_html(content)
            return

        # ── Index ────────────────────────────────────────────────────
        if path == "/" or path == "":
            content = HTML_TEMPLATE.format(content="""
<h1>Vulnerable Test Application</h1>
<p>This application is intentionally vulnerable for security testing.</p>
<h2>Available endpoints:</h2>
<ul>
    <li><a href="/search?q=test">/search?q=test</a> — Reflected XSS test</li>
    <li><a href="/api/user?id=1">/api/user?id=1</a> — SQL Injection test</li>
    <li><a href="/api/ping?host=127.0.0.1">/api/ping?host=127.0.0.1</a> — Command Injection</li>
    <li><a href="/debug">/debug</a> — Information Disclosure</li>
    <li><a href="/config.js">/config.js</a> — Hardcoded Secrets</li>
    <li><a href="/redirect?to=http://evil.com">/redirect</a> — Open Redirect</li>
    <li><a href="/uploads">/uploads</a> — Directory Listing</li>
</ul>
""")
            self._send_html(content)
            return

        # 404
        self._send_html(HTML_TEMPLATE.format(content="<h1>404 Not Found</h1>"), status=404)

    def log_message(self, format, *args):
        # Suppress default logging for cleaner test output
        pass


def run_server(host=HOST, port=PORT):
    """Start the vulnerable web application."""
    server = http.server.HTTPServer((host, port), VulnerableHandler)
    print(f"Vulnerable web app running at http://{host}:{port}")
    print("Known vulnerabilities:")
    print("  - XSS in /search")
    print("  - SQL Injection in /api/user")
    print("  - Command Injection in /api/ping")
    print("  - Info Disclosure in /debug")
    print("  - Hardcoded secrets in /config.js")
    print("  - Open Redirect in /redirect")
    print("  - Missing security headers everywhere")
    print("  - Directory listing in /uploads")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
