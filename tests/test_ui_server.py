"""Tests for UI Web Server and REST API."""

import json
import threading
import time
import urllib.request
import pytest
from payload_entropy_studio.ui_server import run_ui_server


@pytest.fixture(scope="module")
def live_server():
    server = run_ui_server(host="127.0.0.1", port=8195)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    yield "http://127.0.0.1:8195"
    server.shutdown()
    server.server_close()


def test_api_health(live_server):
    req = urllib.request.Request(f"{live_server}/api/health")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "ok"
        assert data["service"] == "payload-entropy-studio"


def test_api_analyze(live_server):
    payload = json.dumps({"payload": "<script>alert(1)</script>"}).encode("utf-8")
    req = urllib.request.Request(f"{live_server}/api/analyze", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["primary_threat"] == "XSS"


def test_api_deobfuscate(live_server):
    payload = json.dumps({"payload": "%3Cscript%3E"}).encode("utf-8")
    req = urllib.request.Request(f"{live_server}/api/deobfuscate", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["normalized_payload"] == "<script>"


def test_api_entropy(live_server):
    payload = json.dumps({"payload": "1234567890ABCDEF"}).encode("utf-8")
    req = urllib.request.Request(f"{live_server}/api/entropy", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "shannon_entropy" in data


def test_api_waf(live_server):
    payload = json.dumps({"payload": "1' OR 1=1"}).encode("utf-8")
    req = urllib.request.Request(f"{live_server}/api/waf", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "rules" in data


def test_ui_index_html(live_server):
    req = urllib.request.Request(f"{live_server}/")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        content = resp.read().decode("utf-8")
        assert "<!DOCTYPE html>" in content
        assert "Payload & Entropy Studio" in content


def test_api_markov(live_server):
    payload = json.dumps({"payload": "SELECT * FROM users WHERE id = 1"}).encode("utf-8")
    req = urllib.request.Request(f"{live_server}/api/markov", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "conditional_entropy" in data
        assert "kl_divergence_natural" in data
        assert "top_ngrams" in data


def test_api_lsh(live_server):
    payload = json.dumps({"payload": "<script>alert('XSS')</script>"}).encode("utf-8")
    req = urllib.request.Request(f"{live_server}/api/lsh", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "simhash_hex" in data
        assert "simhash_int" in data
        assert "minhash_signature" in data


def test_api_shellcode(live_server):
    # NOP sled + shellcode test
    sc_hex = "909090909090909031c050682f2f7368682f62696e89e3505389e1b00bcd80"
    payload = json.dumps({"payload": sc_hex, "is_hex": True}).encode("utf-8")
    req = urllib.request.Request(f"{live_server}/api/shellcode", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "is_shellcode_likely" in data
        assert "nop_sled_detected" in data
        assert data["nop_sled_detected"] is True

