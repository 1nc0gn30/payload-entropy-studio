"""Tests for FastMCP JSON-RPC 2.0 stdio server."""

import json
import pytest
from payload_entropy_studio.mcp_server import MCPServer


def test_mcp_initialize():
    server = MCPServer()
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    res = json.loads(server.handle_request(req))
    assert res["id"] == 1
    assert res["result"]["serverInfo"]["name"] == "payload-entropy-studio"


def test_mcp_tools_list():
    server = MCPServer()
    req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    res = json.loads(server.handle_request(req))
    tool_names = [t["name"] for t in res["result"]["tools"]]
    assert "payload_analyze" in tool_names
    assert "payload_deobfuscate" in tool_names
    assert "payload_entropy" in tool_names
    assert "payload_waf_rules" in tool_names
    assert "payload_diagnostics" in tool_names


def test_mcp_tool_analyze():
    server = MCPServer()
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "payload_analyze",
            "arguments": {"payload": "1' OR '1'='1"}
        }
    })
    res = json.loads(server.handle_request(req))
    data = json.loads(res["result"]["content"][0]["text"])
    assert data["primary_threat"] == "SQL_INJECTION"
    assert data["risk_score"] > 0


def test_mcp_tool_deobfuscate():
    server = MCPServer()
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "payload_deobfuscate",
            "arguments": {"payload": "%3Cscript%3E"}
        }
    })
    res = json.loads(server.handle_request(req))
    data = json.loads(res["result"]["content"][0]["text"])
    assert data["normalized_payload"] == "<script>"


def test_mcp_tool_entropy():
    server = MCPServer()
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "payload_entropy",
            "arguments": {"payload": "ABCDEF123456"}
        }
    })
    res = json.loads(server.handle_request(req))
    data = json.loads(res["result"]["content"][0]["text"])
    assert "shannon_entropy" in data
