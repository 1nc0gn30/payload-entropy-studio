"""
payload-entropy-studio: Security Payload Threat Analyzer, Shannon Entropy Profiler & WAF Rule Synthesizer.
Zero external runtime dependencies.
"""

from __future__ import annotations

from payload_entropy_studio.ast_obfuscation_detector import (
    ASTObfuscationReport,
    analyze_ast_obfuscation,
)
from payload_entropy_studio.deobfuscator import (
    DeobfuscationEngine,
    DeobfuscationResult,
)
from payload_entropy_studio.entropy_engine import (
    EntropyClassification,
    EntropyReport,
    StatisticalRandomnessReport,
    analyze_entropy_profile,
    analyze_statistical_randomness,
    calculate_chi_square,
    calculate_serial_correlation,
    calculate_shannon_entropy,
    estimate_monte_carlo_pi,
)
from payload_entropy_studio.mcp_server import MCPServer, run_mcp_server
from payload_entropy_studio.polyglot_analyzer import (
    PolyglotReport,
    analyze_polyglot_payload,
    detect_file_formats,
)
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
    "calculate_chi_square",
    "estimate_monte_carlo_pi",
    "calculate_serial_correlation",
    "analyze_statistical_randomness",
    "EntropyReport",
    "EntropyClassification",
    "StatisticalRandomnessReport",
    "generate_waf_rules",
    "MCPServer",
    "run_mcp_server",
    "PolyglotReport",
    "analyze_polyglot_payload",
    "detect_file_formats",
    "ASTObfuscationReport",
    "analyze_ast_obfuscation",
]

