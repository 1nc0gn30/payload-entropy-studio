"""
Deep Multi-Vector Threat Analyzer & MITRE ATT&CK / CWE Signature Engine.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from payload_entropy_studio.deobfuscator import DeobfuscationEngine
from payload_entropy_studio.entropy_engine import analyze_entropy_profile


class ThreatSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatSignature:
    """Security signature definition."""
    category: str
    pattern: str
    weight: int
    cwe_id: str
    mitre_attack: str
    description: str


# Knowledge Base of Attack Signatures
THREAT_SIGNATURES: List[ThreatSignature] = [
    # 1. SQL Injection
    ThreatSignature("SQL_INJECTION", r"(\b(?:UNION\s+ALL\s+SELECT|UNION\s+SELECT|SELECT\s+.*?\s+FROM|INSERT\s+INTO|UPDATE\s+.*?\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE)\b)", 30, "CWE-89", "T1190", "SQL DML/DDL statement injection"),
    ThreatSignature("SQL_INJECTION", r"(\b(?:SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(\s*\d+|WAITFOR\s+DELAY\b|PG_SLEEP\s*\(\s*\d+\s*\)))", 35, "CWE-89", "T1190", "Time-based blind SQL injection payload"),
    ThreatSignature("SQL_INJECTION", r"('(?:--|#|/\*)|'\s*OR\s+'?\d+'?='?\d+'?|'\s*OR\s+1=1|\bOR\s+1=1\b)", 25, "CWE-89", "T1190", "Tautological Boolean SQL authentication bypass"),

    # 2. XSS (Cross-Site Scripting)
    ThreatSignature("XSS", r"(<script\b[^>]*>.*?</script>|<script\b|javascript:\s*[\w(]|vbscript:)", 30, "CWE-79", "T1059.007", "Inline or embedded JavaScript execution tag"),
    ThreatSignature("XSS", r"(\b(?:onerror|onload|onmouseover|onclick|onfocus|onblur|ontoggle|onanimationstart)\s*=\s*['\"]?[^'\">]+)", 25, "CWE-79", "T1059.007", "HTML DOM Event handler execution vector"),
    ThreatSignature("XSS", r"(\b(?:document\.cookie|document\.domain|window\.location|eval\s*\(|Function\s*\()|alert\s*\(|prompt\s*\(|confirm\s*\()", 25, "CWE-79", "T1059.007", "DOM manipulation or reflective dialog execution"),

    # 3. Command Injection
    ThreatSignature("COMMAND_INJECTION", r"(;\s*(?:cat\s+/etc/passwd|ls\s+-la|whoami|uname\s+-a|id|pwd|netstat|ipconfig|ifconfig|curl\s+|wget\s+)|\|\s*(?:bash|sh|cmd\.exe|powershell))", 35, "CWE-78", "T1059", "Chained shell system command invocation"),
    ThreatSignature("COMMAND_INJECTION", r"(`(?:id|whoami|cat\s+/etc/passwd|ls)`|\$\((?:id|whoami|cat\s+/etc/passwd|uname)\))", 30, "CWE-78", "T1059", "Subshell command substitution syntax"),
    ThreatSignature("COMMAND_INJECTION", r"(/bin/(?:bash|sh|zsh|dash)|cmd\.exe|powershell(?:\.exe)?\s+(?:-nop|-w\s+hidden|-enc))", 35, "CWE-78", "T1059", "Direct shell interpreter execution"),

    # 4. Path Traversal / LFI
    ThreatSignature("PATH_TRAVERSAL_LFI", r"(\.\./\.\./|\.\.\\\.\.\\|%2e%2e%2f|%252e%252e%252f|\.\./|\.\.\\)", 20, "CWE-22", "T1006", "Directory traversal relative path escape sequence"),
    ThreatSignature("PATH_TRAVERSAL_LFI", r"(/etc/(?:passwd|shadow|hosts|issue|os-release)|c:[\\/]windows[\\/]win\.ini|php://(?:filter|input|expect)|file://)", 30, "CWE-22", "T1006", "Sensitive operating system file disclosure or PHP wrapper"),

    # 5. SSTI (Server-Side Template Injection)
    ThreatSignature("SSTI", r"(\{\{\s*(?:7\*7|config|self|request|class|mro|subclasses)\s*\}\}|\$\{.*\}|<%=\s*.*?\s*%>|\[\[\s*.*?\s*\]\])", 30, "CWE-1336", "T1190", "Template engine expression injection (Jinja2, Twig, Freemarker, Spring)"),

    # 6. SSRF
    ThreatSignature("SSRF", r"(https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|metadata\.google\.internal|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+))", 25, "CWE-918", "T1090", "Loopback, RFC1918 private IP, or cloud metadata IP access attempt"),

    # 7. XXE
    ThreatSignature("XXE", r"(<!DOCTYPE\s+\w+\s+\[\s*<!ENTITY\s+\w+\s+SYSTEM\s+['\"][^'\"]+['\"]|\bSYSTEM\s+['\"](?:file://|http://))", 35, "CWE-611", "T1190", "XML External Entity declaration"),

    # 8. Prototype Pollution
    ThreatSignature("PROTOTYPE_POLLUTION", r"(__proto__|constructor\.prototype|prototype\[['\"]?\w+['\"]?\])", 25, "CWE-1321", "T1190", "JavaScript Prototype chain pollution vector"),
]


@dataclass
class ThreatReport:
    """Complete security threat evaluation report."""
    raw_payload: str
    normalized_payload: str
    primary_threat: str
    secondary_threats: List[str]
    severity: ThreatSeverity
    risk_score: int  # 0 to 100
    matched_rules: List[Dict[str, Any]]
    cwe_mappings: List[str]
    mitre_attack_mappings: List[str]
    entropy_summary: Dict[str, Any]
    deobfuscation_summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_payload": self.raw_payload,
            "normalized_payload": self.normalized_payload,
            "primary_threat": self.primary_threat,
            "secondary_threats": self.secondary_threats,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "cwe_mappings": self.cwe_mappings,
            "mitre_attack_mappings": self.mitre_attack_mappings,
            "matched_rules": self.matched_rules,
            "entropy": self.entropy_summary,
            "deobfuscation": self.deobfuscation_summary,
        }


class ThreatAnalyzer:
    """Security analyzer inspecting payloads for malicious threat signatures."""

    def __init__(self) -> None:
        self.deobfuscator = DeobfuscationEngine()

    def analyze(self, payload: str) -> ThreatReport:
        """Perform comprehensive threat analysis on raw payload."""
        # Step 1: De-obfuscate payload
        deobf_res = self.deobfuscator.deobfuscate(payload)
        normalized = deobf_res.normalized_payload

        # Step 2: Entropy profiling
        entropy_rep = analyze_entropy_profile(payload)

        # Step 3: Match signatures on both raw and normalized representations
        matched_rules: List[Dict[str, Any]] = []
        threat_scores: Dict[str, int] = {}
        cwe_set = set()
        mitre_set = set()

        for sig in THREAT_SIGNATURES:
            # Check normalized first, then raw
            m = re.search(sig.pattern, normalized, re.IGNORECASE) or re.search(sig.pattern, payload, re.IGNORECASE)
            if m:
                matched_snippet = m.group(0)
                matched_rules.append({
                    "category": sig.category,
                    "cwe": sig.cwe_id,
                    "mitre": sig.mitre_attack,
                    "weight": sig.weight,
                    "description": sig.description,
                    "matched_subpattern": matched_snippet
                })
                threat_scores[sig.category] = threat_scores.get(sig.category, 0) + sig.weight
                cwe_set.add(sig.cwe_id)
                mitre_set.add(sig.mitre_attack)

        # Compute cumulative risk score
        base_score = sum(threat_scores.values())
        if entropy_rep.is_suspicious_entropy:
            base_score += 25
        if deobf_res.total_layers_unwrapped > 1:
            base_score += 15

        risk_score = min(100, base_score)

        # Severity mapping
        if risk_score >= 70:
            severity = ThreatSeverity.CRITICAL
        elif risk_score >= 45:
            severity = ThreatSeverity.HIGH
        elif risk_score >= 25:
            severity = ThreatSeverity.MEDIUM
        elif risk_score > 0:
            severity = ThreatSeverity.LOW
        else:
            severity = ThreatSeverity.INFO

        # Primary vs Secondary Threats
        if threat_scores:
            sorted_threats = sorted(threat_scores.items(), key=lambda x: x[1], reverse=True)
            primary_threat = sorted_threats[0][0]
            secondary_threats = [t[0] for t in sorted_threats[1:]]
        else:
            if entropy_rep.is_suspicious_entropy:
                primary_threat = "HIGH_ENTROPY_SUSPICIOUS_PAYLOAD"
            else:
                primary_threat = "BENIGN_OR_UNCLASSIFIED"
            secondary_threats = []

        return ThreatReport(
            raw_payload=payload,
            normalized_payload=normalized,
            primary_threat=primary_threat,
            secondary_threats=secondary_threats,
            severity=severity,
            risk_score=risk_score,
            matched_rules=matched_rules,
            cwe_mappings=sorted(list(cwe_set)),
            mitre_attack_mappings=sorted(list(mitre_set)),
            entropy_summary=entropy_rep.to_dict(),
            deobfuscation_summary=deobf_res.to_dict()
        )
