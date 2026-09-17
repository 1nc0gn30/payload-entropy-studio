# 🛡️ Payload Entropy Studio

[![CI](https://github.com/1nc0gn30/payload-entropy-studio/actions/workflows/ci.yml/badge.svg)](https://github.com/1nc0gn30/payload-entropy-studio/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20runtime-success.svg)](https://github.com/1nc0gn30/payload-entropy-studio)
[![MCP Server](https://img.shields.io/badge/MCP-FastMCP%202024--11--05-blueviolet.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Security Payload Threat Analyzer, Shannon Entropy Profiler & WAF Rule Synthesizer with Material 3 Web UI, Multi-OS CLI, FastMCP stdio server, and zero external runtime dependencies.**

---

## ✨ Features

- 🛡️ **Multi-Vector Threat Analyzer**: Evaluates input strings for 10+ major attack vectors including SQL Injection, Cross-Site Scripting (XSS), Command Injection, Path Traversal (LFI), Server-Side Template Injection (SSTI), SSRF, XXE, and Prototype Pollution, with automated **CWE** and **MITRE ATT&CK** classification.
- 🔓 **Recursive De-obfuscation Engine**: Unmasks multi-layered evasions across URL percent encoding (including double/triple encoding), Hex escapes, Unicode escapes, Base64 blocks, HTML entities, and string concatenations.
- 📊 **Shannon Entropy & Kolmogorov Complexity Profiler**: Computes global and sliding-window byte entropy ($H(X)$ from 0.0 to 8.0 bits/byte) to instantly detect encrypted reverse shells, packed payloads, and shellcode.
- 🧱 **Automated WAF & IDS Rule Generator**: Automatically synthesizes production-ready defense rules in **ModSecurity 3 / OWASP CRS**, **Cloudflare WAF Expression**, **AWS WAF v2 JSON**, and **Suricata IDS**.
- 🎨 **Google Material 3 Light Mode Web UI**: Real-time payload decoder, entropy spectrum visualizer, interactive attack sample library, and 1-click rule copy.
- ⚡ **Zero Third-Party Runtime Dependencies**: 100% Python Standard Library runtime (`re`, `math`, `zlib`, `collections`, `urllib`, `html`, `base64`, `http.server`, `argparse`).
- 🤖 **FastMCP Server Protocol**: Full Model Context Protocol (MCP) JSON-RPC 2.0 stdio server for Claude Desktop, Cursor, Cline, and autonomous AI agents.

---

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/1nc0gn30/payload-entropy-studio.git
cd payload-entropy-studio

# Install in editable mode
pip install -e .
```

---

## 💻 CLI Usage

```bash
# Analyze a suspicious attack payload
payload-entropy analyze "%3Cscript%3Ealert(document.cookie)%3C/script%3E"

# Recursively de-obfuscate a multi-layered payload
payload-entropy deobfuscate "%252e%252e%252f%252e%252e%252fetc%2fpasswd"

# Profile Shannon entropy and byte distribution
payload-entropy entropy "payload.bin" --window-size 32

# Synthesize WAF rules (ModSecurity, Cloudflare, AWS WAF, Suricata)
payload-entropy waf "1' UNION SELECT 1,username,password FROM users--"

# Launch Google Material 3 Payload Studio Web UI
payload-entropy serve --port 8095

# Start FastMCP stdio server for LLM agents
payload-entropy mcp

# Run system diagnostics
payload-entropy doctor
```

---

## 🤖 Model Context Protocol (MCP) Setup

Add `payload-entropy-studio` to your Claude Desktop or Cursor configuration:

```json
{
  "mcpServers": {
    "payload-entropy": {
      "command": "python3",
      "args": ["-m", "payload_entropy_studio", "mcp"]
    }
  }
}
```

### Registered MCP Tools:
- `payload_analyze`: Full multi-vector threat analysis, risk scoring, CWE & MITRE ATT&CK mapping.
- `payload_deobfuscate`: Step-by-step recursive de-obfuscation history.
- `payload_entropy`: Shannon entropy score, sliding window heatmap, and byte distribution.
- `payload_waf_rules`: Synthesize ModSecurity, Cloudflare, AWS WAF, and Suricata rules.
- `payload_diagnostics`: Platform and toolchain health check.

---

## 🧪 Running Tests

```bash
pytest -v
```

---

## 📜 License

MIT License © 2026 1nc0gn30
