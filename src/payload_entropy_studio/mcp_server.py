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
            },
            {
                "name": "payload_polyglot_audit",
                "description": "Analyze raw payload or file stream to detect dual-context polyglots (GIF+JS, PNG+PHP, PDF+JS, JPEG+ZIP, SVG+XSS) and multi-format magic byte evasions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Raw string, hex representation, or base64 data to inspect for polyglot characteristics."
                        }
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "payload_ast_obfuscation",
                "description": "Analyze scripts and queries for structural AST evasion, dynamic evaluation wrappers, environment variable splitting, and bracket property lookups.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Script or query code snippet to analyze for AST obfuscation."
                        }
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "payload_markov_profile",
                "description": "Compute N-gram frequency distribution, first-order Markov transition probability matrix, conditional transition entropy, and Kullback-Leibler divergence from baseline.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Payload string or hex representation."
                        },
                        "ngram_order": {
                            "type": "integer",
                            "default": 2,
                            "description": "N-gram order (1, 2, or 3)."
                        }
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "payload_lsh_fingerprint",
                "description": "Compute 64-bit SimHash and MinHash locality-sensitive fingerprints with Hamming distance metrics for detecting polymorphic payload mutations.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Payload string or hex representation."
                        },
                        "compare_with": {
                            "type": "string",
                            "description": "Optional second payload to compare similarity against."
                        }
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "payload_detect_shellcode",
                "description": "Analyze binary, shellcode, or hex payloads for x86/x64 NOP sleds, call/pop GetPC stubs, syscall/int80 patterns, XOR decoder loops, and non-printable byte density.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Raw, escaped (\\x90), or hex string payload."
                        }
                    },
                    "required": ["payload"]
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

        elif tool_name == "payload_polyglot_audit":
            from payload_entropy_studio.polyglot_analyzer import analyze_polyglot_payload
            payload = arguments["payload"]
            rep = analyze_polyglot_payload(payload)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(rep.to_dict(), indent=2)
                    }
                ]
            }

        elif tool_name == "payload_ast_obfuscation":
            from payload_entropy_studio.ast_obfuscation_detector import analyze_ast_obfuscation
            payload = arguments["payload"]
            rep = analyze_ast_obfuscation(payload)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(rep.to_dict(), indent=2)
                    }
                ]
            }

        elif tool_name == "payload_markov_profile":
            from payload_entropy_studio.markov_lsh import (
                analyze_markov_lsh_profile,
                build_markov_transition_matrix,
                calculate_ngram_frequencies,
            )
            payload = arguments["payload"]
            order = int(arguments.get("ngram_order", 2))
            report = analyze_markov_lsh_profile(payload)
            ngrams = calculate_ngram_frequencies(payload, n=order)
            res_data = report.to_dict()
            res_data["ngrams"] = ngrams
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(res_data, indent=2)
                    }
                ]
            }

        elif tool_name == "payload_lsh_fingerprint":
            from payload_entropy_studio.markov_lsh import (
                calculate_hamming_distance,
                calculate_simhash_similarity,
                compute_minhash,
                compute_simhash,
                estimate_jaccard_similarity,
                simhash_hex,
            )
            payload = arguments["payload"]
            sh = compute_simhash(payload)
            minhash = compute_minhash(payload, num_perm=32)
            out: Dict[str, Any] = {
                "simhash": simhash_hex(sh),
                "simhash_int": sh,
                "minhash_signature": minhash,
            }
            if "compare_with" in arguments and arguments["compare_with"]:
                other = arguments["compare_with"]
                sh2 = compute_simhash(other)
                minhash2 = compute_minhash(other, num_perm=32)
                out["comparison"] = {
                    "other_simhash": simhash_hex(sh2),
                    "hamming_distance": calculate_hamming_distance(sh, sh2),
                    "simhash_similarity": calculate_simhash_similarity(sh, sh2),
                    "minhash_jaccard_similarity": estimate_jaccard_similarity(minhash, minhash2),
                }
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(out, indent=2)
                    }
                ]
            }

        elif tool_name == "payload_detect_shellcode":
            from payload_entropy_studio.markov_lsh import detect_shellcode_heuristics
            payload = arguments["payload"]
            res = detect_shellcode_heuristics(payload)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(res, indent=2)
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
