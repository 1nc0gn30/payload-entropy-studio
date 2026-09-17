"""
payload-entropy-studio: Security Payload Threat Analyzer, Shannon Entropy Profiler & WAF Rule Synthesizer.
Zero external runtime dependencies.
"""

from __future__ import annotations

from payload_entropy_studio.deobfuscator import (
    DeobfuscationEngine,
    DeobfuscationResult,
)
from payload_entropy_studio.entropy_engine import (
    EntropyClassification,
    EntropyReport,
    analyze_entropy_profile,
    calculate_shannon_entropy,
)
from payload_entropy_studio.mcp_server import MCPServer, run_mcp_server
from payload_entropy_studio.threat_analyzer import (
    ThreatAnalyzer,
    ThreatReport,
    ThreatSeverity,
)
from payload_entropy_studio.waf_generator import generate_waf_rules

__version__ = "0.1.0"
__author__ = "1nc0gn30"

__all__ = [
    "ThreatAnalyzer",
    "ThreatReport",
    "ThreatSeverity",
    "DeobfuscationEngine",
    "DeobfuscationResult",
    "calculate_shannon_entropy",
    "analyze_entropy_profile",
    "EntropyReport",
    "EntropyClassification",
    "generate_waf_rules",
    "MCPServer",
    "run_mcp_server",
]
