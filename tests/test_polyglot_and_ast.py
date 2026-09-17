"""Unit tests for Polyglot File Payload Classifier & Structural AST Obfuscation Detector."""

import json
import pytest

from payload_entropy_studio import (
    ASTObfuscationReport,
    MCPServer,
    PolyglotReport,
    analyze_ast_obfuscation,
    analyze_polyglot_payload,
    detect_file_formats,
)
from payload_entropy_studio.cli import main as cli_main
from payload_entropy_studio.ui_server import PayloadHTTPHandler


def test_detect_file_formats_magic_bytes():
    assert "GIF" in detect_file_formats(b"GIF89a\x01\x00\x01\x00")
    assert "PNG" in detect_file_formats(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    assert "JPEG" in detect_file_formats(b"\xff\xd8\xff\xe0\x00\x10JFIF")
    assert "PDF" in detect_file_formats(b"%PDF-1.7 \n1 0 obj")
    assert "ZIP" in detect_file_formats(b"PK\x03\x04\x14\x00")
    assert "SVG" in detect_file_formats(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>")


def test_gif_javascript_polyglot():
    # Canonical GIF89a / JS polyglot trick
    gif_js_payload = b"GIF89a/*=1;alert('XSS_POLYGLOT');*/=alert(document.domain);"
    report = analyze_polyglot_payload(gif_js_payload)

    assert isinstance(report, PolyglotReport)
    assert report.is_polyglot is True
    assert report.polyglot_class == "GIF_JAVASCRIPT_POLYGLOT"
    assert report.risk_score >= 90.0
    assert "GIF" in report.detected_formats
    assert len(report.embedded_scripts) > 0
    assert len(report.mitigation_advice) > 0


def test_png_php_webshell_polyglot():
    png_php_payload = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR<?php eval($_POST['x']); ?>"
    report = analyze_polyglot_payload(png_php_payload)

    assert report.is_polyglot is True
    assert report.polyglot_class == "PNG_PHP_WEBSHELL_POLYGLOT"
    assert report.risk_score >= 90.0
    assert "PNG" in report.detected_formats
    assert "PHP" in report.detected_formats


def test_pdf_javascript_polyglot():
    pdf_js_payload = b"%PDF-1.4\n1 0 obj\n<< /Names << /JavaScript << /Names [(DocOpen) << /S /JavaScript /JS (app.alert('PDF_XSS');) >>] >> >> >>\nendobj"
    report = analyze_polyglot_payload(pdf_js_payload)

    assert report.is_polyglot is True
    assert report.polyglot_class == "PDF_ACTION_SCRIPT_POLYGLOT"
    assert "PDF" in report.detected_formats


def test_benign_plain_payload_polyglot():
    benign_text = "Welcome to the application dashboard!"
    report = analyze_polyglot_payload(benign_text)

    assert report.is_polyglot is False
    assert report.polyglot_class == "MONOLITHIC_PAYLOAD"
    assert report.risk_score < 40.0


def test_ast_obfuscation_eval_wrapper():
    payload = "eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))"
    report = analyze_ast_obfuscation(payload)

    assert isinstance(report, ASTObfuscationReport)
    assert report.obfuscation_detected is True
    assert "DYNAMIC_EVAL_WRAPPER" in report.evasion_techniques
    assert report.complexity_score >= 35.0


def test_ast_obfuscation_bracket_and_concat():
    payload = "window['ev' + 'al']('ale' + 'rt(1)')"
    report = analyze_ast_obfuscation(payload)

    assert report.obfuscation_detected is True
    assert "BRACKET_PROPERTY_LOOKUP" in report.evasion_techniques or "STRING_CONCATENATION_EVASION" in report.evasion_techniques
    assert len(report.deobfuscation_hints) > 0


def test_ast_obfuscation_bash_splitting():
    payload = "c''at${IFS}/etc/passwd"
    report = analyze_ast_obfuscation(payload)

    assert report.obfuscation_detected is True
    assert "SHELL_ENV_SPLITTING" in report.evasion_techniques
    assert "SHELL_QUOTE_ESCAPE_INSERTION" in report.evasion_techniques


def test_ast_clean_code():
    report = analyze_ast_obfuscation("function add(a, b) { return a + b; }")
    assert report.obfuscation_detected is False
    assert report.complexity_score == 0.0


def test_cli_polyglot_and_ast_subcommands(capsys):
    # polyglot CLI test
    ret_poly = cli_main(["polyglot", "GIF89a/*=1;alert(1);", "--json"])
    assert ret_poly == 0
    out_poly = capsys.readouterr().out
    data_poly = json.loads(out_poly)
    assert data_poly["is_polyglot"] is True
    assert "polyglot_class" in data_poly

    # ast CLI test
    ret_ast = cli_main(["ast", "eval(atob('test'))", "--json"])
    assert ret_ast == 0
    out_ast = capsys.readouterr().out
    data_ast = json.loads(out_ast)
    assert data_ast["obfuscation_detected"] is True
    assert "complexity_score" in data_ast


def test_mcp_polyglot_and_ast_tools():
    mcp = MCPServer()

    # Tool: payload_polyglot_audit
    req_poly = json.dumps({
        "jsonrpc": "2.0",
        "id": "poly-1",
        "method": "tools/call",
        "params": {
            "name": "payload_polyglot_audit",
            "arguments": {"payload": "GIF89a/*=1;alert(1);"}
        }
    })
    resp_poly = json.loads(mcp.handle_request(req_poly))
    assert "result" in resp_poly
    content_poly = json.loads(resp_poly["result"]["content"][0]["text"])
    assert content_poly["is_polyglot"] is True

    # Tool: payload_ast_obfuscation
    req_ast = json.dumps({
        "jsonrpc": "2.0",
        "id": "ast-1",
        "method": "tools/call",
        "params": {
            "name": "payload_ast_obfuscation",
            "arguments": {"payload": "window['ev'+'al']('1')"}
        }
    })
    resp_ast = json.loads(mcp.handle_request(req_ast))
    assert "result" in resp_ast
    content_ast = json.loads(resp_ast["result"]["content"][0]["text"])
    assert content_ast["obfuscation_detected"] is True
