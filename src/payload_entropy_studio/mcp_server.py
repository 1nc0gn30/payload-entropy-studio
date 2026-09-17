"""
Model Context Protocol (MCP) Server for payload-entropy-studio.
Conforms to MCP protocol version 2024-11-05 and JSON-RPC 2.0 over stdio.
Zero external runtime dependencies.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from payload_entropy_studio.deobfuscator import DeobfuscationEngine
from payload_entropy_studio.entropy_engine import analyze_entropy_profile
from payload_entropy_studio.threat_analyzer import ThreatAnalyzer
from payload_entropy_studio.waf_generator import generate_waf_rules

SERVER_NAME = "payload-entropy-studio"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"


class MCPServer:
    """Model Context Protocol stdio server implementation."""

    def __init__(self) -> None:
        self.threat_analyzer = ThreatAnalyzer()
        self.deobfuscator = DeobfuscationEngine()

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return registered MCP tool schemas."""
        return [
            {
                "name": "payload_analyze",
                "description": "Perform comprehensive multi-vector security threat analysis, risk scoring, CWE & MITRE ATT&CK mapping on a suspicious input or attack payload.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "The raw or obfuscated payload string to analyze."
                        }
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "payload_deobfuscate",
                "description": "Recursively unmask obfuscated payloads across multiple layers (URL encoding, Hex/Unicode escapes, Base64, HTML entities, string concatenations).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Obfuscated payload string."
                        }
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "payload_entropy",
                "description": "Calculate Shannon entropy, sliding window heatmap, Kolmogorov complexity proxy, and byte distribution of payload or binary buffer.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "String or binary hex representation."
                        },
                        "window_size": {
                            "type": "integer",
                            "default": 32,
                            "description": "Sliding window size in bytes."
                        }
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "payload_waf_rules",
                "description": "Synthesize production WAF rules (ModSecurity CRS, Cloudflare WAF, AWS WAF, Suricata IDS) to block the analyzed payload.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Payload string."
                        }
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "payload_diagnostics",
                "description": "Run environment, platform, and security engine diagnostics.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]

    def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tool and format MCP result."""
        if tool_name == "payload_analyze":
            payload = arguments["payload"]
            report = self.threat_analyzer.analyze(payload)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(report.to_dict(), indent=2)
                    }
                ]
            }

        elif tool_name == "payload_deobfuscate":
            payload = arguments["payload"]
            res = self.deobfuscator.deobfuscate(payload)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(res.to_dict(), indent=2)
                    }
                ]
            }

        elif tool_name == "payload_entropy":
            payload = arguments["payload"]
            w_size = int(arguments.get("window_size", 32))
            rep = analyze_entropy_profile(payload, window_size=w_size)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(rep.to_dict(), indent=2)
                    }
                ]
            }

        elif tool_name == "payload_waf_rules":
            payload = arguments["payload"]
            report = self.threat_analyzer.analyze(payload)
            rules = generate_waf_rules(report)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "threat": report.primary_threat,
                            "severity": report.severity.value,
                            "rules": rules
                        }, indent=2)
                    }
                ]
            }

        elif tool_name == "payload_diagnostics":
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "server": SERVER_NAME,
                            "version": SERVER_VERSION,
                            "protocol_version": PROTOCOL_VERSION,
                            "platform": sys.platform,
                            "python_version": sys.version,
                            "zero_dependencies": True,
                            "status": "HEALTHY"
                        }, indent=2)
                    }
                ]
            }

        raise ValueError(f"Unknown tool: {tool_name}")

    def handle_request(self, request_str: str) -> Optional[str]:
        """Process JSON-RPC 2.0 request string and return formatted response."""
        try:
            req = json.loads(request_str)
        except Exception as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
            })

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}
                }
            })

        elif method == "notifications/initialized":
            return None

        elif method == "ping":
            return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}})

        elif method == "tools/list":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.get_tool_definitions()}
            })

        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                res = self.handle_tool_call(name, arguments)
                return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res})
            except Exception as e:
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": str(e)}
                })

        return json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}
        })

    def run_stdio(self) -> None:
        """Run stdio loop reading JSON-RPC requests."""
        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue
            resp = self.handle_request(line_str)
            if resp:
                sys.stdout.write(resp + "\n")
                sys.stdout.flush()


def run_mcp_server() -> None:
    """Entrypoint to launch MCP stdio server."""
    server = MCPServer()
    server.run_stdio()
