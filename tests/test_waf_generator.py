"""Tests for WAF Rule Synthesizer."""

import pytest
from payload_entropy_studio.threat_analyzer import ThreatAnalyzer
from payload_entropy_studio.waf_generator import generate_waf_rules


def test_generate_waf_rules(threat_analyzer):
    report = threat_analyzer.analyze("<script>alert(1)</script>")
    rules = generate_waf_rules(report)

    assert "modsecurity" in rules
    assert "cloudflare" in rules
    assert "aws_waf" in rules
    assert "suricata" in rules

    assert "SecRule" in rules["modsecurity"]
    assert "http.request" in rules["cloudflare"]
    assert "RegexMatchStatement" in rules["aws_waf"]
    assert "alert http" in rules["suricata"]
