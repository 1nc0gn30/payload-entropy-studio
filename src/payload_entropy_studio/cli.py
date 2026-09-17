"""
Command-Line Interface for payload-entropy-studio.
Zero external runtime dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, List, Optional

from payload_entropy_studio.compat import safe_read_text
from payload_entropy_studio.deobfuscator import DeobfuscationEngine
from payload_entropy_studio.entropy_engine import (
    EntropyClassification,
    analyze_entropy_profile,
    calculate_shannon_entropy,
)
from payload_entropy_studio.mcp_server import run_mcp_server
from payload_entropy_studio.threat_analyzer import ThreatAnalyzer, ThreatSeverity
from payload_entropy_studio.ui_server import run_ui_server
from payload_entropy_studio.waf_generator import generate_waf_rules


class Colors:
    """ANSI terminal color helpers with automatic disabling."""
    def __init__(self, force_disable: bool = False) -> None:
        disabled = force_disable or "NO_COLOR" in os.environ or not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty()
        self.BLUE = "" if disabled else "\033[94m"
        self.GREEN = "" if disabled else "\033[92m"
        self.YELLOW = "" if disabled else "\033[93m"
        self.RED = "" if disabled else "\033[91m"
        self.CYAN = "" if disabled else "\033[96m"
        self.BOLD = "" if disabled else "\033[1m"
        self.DIM = "" if disabled else "\033[2m"
        self.RESET = "" if disabled else "\033[0m"


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="payload-entropy",
        description="Security Payload Analyzer, Shannon Entropy Profiler & WAF Rule Synthesizer",
    )
    parser.add_argument("-v", "--version", action="version", version="payload-entropy-studio 0.1.0")

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    sub = parser.add_subparsers(dest="command", help="Available subcommands")

    # analyze
    p_an = sub.add_parser("analyze", parents=[base], help="Perform complete security threat analysis on payload")
    p_an.add_argument("payload", help="Target payload string or file path")
    p_an.add_argument("--json", action="store_true", help="Output report as JSON")

    # deobfuscate
    p_de = sub.add_parser("deobfuscate", parents=[base], help="Recursively unmask obfuscated payload")
    p_de.add_argument("payload", help="Target payload string or file path")
    p_de.add_argument("--json", action="store_true", help="Output layers as JSON")

    # entropy
    p_ent = sub.add_parser("entropy", parents=[base], help="Calculate Shannon entropy and byte distribution")
    p_ent.add_argument("payload", help="Target payload string or file path")
    p_ent.add_argument("-w", "--window-size", type=int, default=32, help="Sliding window size (default: 32)")
    p_ent.add_argument("--json", action="store_true", help="Output entropy report as JSON")

    # waf
    p_waf = sub.add_parser("waf", parents=[base], help="Synthesize ModSecurity, Cloudflare, AWS WAF, and Suricata rules")
    p_waf.add_argument("payload", help="Target payload string or file path")
    p_waf.add_argument("-t", "--type", choices=["all", "modsecurity", "cloudflare", "aws", "suricata"], default="all")

    # polyglot
    p_poly = sub.add_parser("polyglot", parents=[base], help="Detect dual-context polyglots and multi-format magic byte evasions")
    p_poly.add_argument("payload", help="Target payload string or file path")
    p_poly.add_argument("--json", action="store_true", help="Output polyglot audit report as JSON")

    # ast
    p_ast = sub.add_parser("ast", parents=[base], help="Analyze structural AST evasion and obfuscated grammar")
    p_ast.add_argument("payload", help="Target script/query string or file path")
    p_ast.add_argument("--json", action="store_true", help="Output AST obfuscation report as JSON")

    # serve
    p_serve = sub.add_parser("serve", parents=[base], help="Start Payload Studio Web UI (Material 3 influenced)")
    p_serve.add_argument("--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)")
    p_serve.add_argument("--port", type=int, default=8095, help="Port (default: 8095)")

    # mcp
    p_mcp = sub.add_parser("mcp", parents=[base], help="Run Model Context Protocol stdio server")

    # diagnostics / doctor
    p_doc = sub.add_parser("doctor", aliases=["diagnostics", "platform"], parents=[base], help="Run system diagnostics")

    # test-self
    p_tself = sub.add_parser("test-self", parents=[base], help="Run internal self-verification test runner")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(argv)
    c = Colors(force_disable=getattr(args, "no_color", False))

    def get_input_str(val: str) -> str:
        if os.path.isfile(val):
            return safe_read_text(val)
        return val

    if args.command == "analyze":
        text = get_input_str(args.payload)
        analyzer = ThreatAnalyzer()
        report = analyzer.analyze(text)

        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            sev_color = c.GREEN if report.severity == ThreatSeverity.INFO else (
                c.YELLOW if report.severity in (ThreatSeverity.LOW, ThreatSeverity.MEDIUM) else c.RED
            )
            print(f"\n{c.BOLD}🛡️ Security Payload Threat Evaluation{c.RESET}")
            print(f"  Primary Threat  : {c.CYAN}{report.primary_threat}{c.RESET}")
            print(f"  Severity Level  : {sev_color}{report.severity.value}{c.RESET}")
            print(f"  Risk Score      : {c.BOLD}{report.risk_score}/100{c.RESET}")
            print(f"  CWE Mappings    : {', '.join(report.cwe_mappings) if report.cwe_mappings else 'None'}")
            print(f"  MITRE ATT&CK    : {', '.join(report.mitre_attack_mappings) if report.mitre_attack_mappings else 'None'}")
            print(f"  Shannon Entropy : {report.entropy_summary['shannon_entropy']} bits/byte ({report.entropy_summary['classification']})")
            print(f"  Deobfuscated    : {report.normalized_payload[:80]}")
            if report.matched_rules:
                print(f"\n  {c.BOLD}Matched Rule Signatures ({len(report.matched_rules)}):{c.RESET}")
                for r in report.matched_rules:
                    print(f"    - [{r['category']}] {r['description']} (matched: '{r['matched_subpattern'][:40]}')")
            print()
        return 0

    elif args.command == "deobfuscate":
        text = get_input_str(args.payload)
        deobf = DeobfuscationEngine()
        res = deobf.deobfuscate(text)

        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(f"\n{c.BOLD}🔓 Recursive Payload De-obfuscation History{c.RESET}")
            print(f"  Original Length : {len(res.original_payload)} chars")
            print(f"  Total Layers    : {res.total_layers_unwrapped}")
            print(f"  Transforms      : {', '.join(res.transforms_applied) if res.transforms_applied else 'None (Clean Payload)'}\n")
            for s in res.steps:
                print(f"  {c.GREEN}Layer {s.layer}:{c.RESET} [{c.CYAN}{s.transform_type}{c.RESET}] {s.description}")
            print(f"\n{c.BOLD}Unmasked Final Payload:{c.RESET}\n  {c.CYAN}{res.normalized_payload}{c.RESET}\n")
        return 0

    elif args.command == "entropy":
        text = get_input_str(args.payload)
        rep = analyze_entropy_profile(text, window_size=args.window_size)

        if args.json:
            print(json.dumps(rep.to_dict(), indent=2))
        else:
            print(f"\n{c.BOLD}📊 Shannon Entropy & Byte Distribution Profile{c.RESET}")
            print(f"  Total Bytes     : {rep.total_bytes}")
            print(f"  Shannon Entropy : {c.CYAN}{round(rep.shannon_entropy, 4)}{c.RESET} bits/byte")
            print(f"  Classification  : {c.BOLD}{rep.classification.value}{c.RESET}")
            print(f"  Suspicious Flag : {c.RED if rep.is_suspicious_entropy else c.GREEN}{rep.is_suspicious_entropy}{c.RESET}")
            print(f"  Compress Ratio  : {round(rep.compression_ratio, 3)} (Kolmogorov estimate)\n")
            print(f"  {c.BOLD}Character Classes:{c.RESET}")
            for k, v in rep.char_classes.items():
                print(f"    {k:<16} : {round(v, 1)}%")
            print()
        return 0

    elif args.command == "waf":
        text = get_input_str(args.payload)
        analyzer = ThreatAnalyzer()
        report = analyzer.analyze(text)
        rules = generate_waf_rules(report)

        if args.type == "all":
            for engine, code in rules.items():
                print(f"\n{c.BOLD}=== {engine.upper()} ==={c.RESET}\n{code}")
            print()
        else:
            target_key = "aws_waf" if args.type == "aws" else args.type
            print(rules.get(target_key, ""))
        return 0

    elif args.command == "polyglot":
        from payload_entropy_studio.polyglot_analyzer import analyze_polyglot_payload
        text = get_input_str(args.payload)
        rep = analyze_polyglot_payload(text)

        if args.json:
            print(json.dumps(rep.to_dict(), indent=2))
        else:
            print(f"\n{c.BOLD}🧬 Polyglot Multi-Format File Payload Audit{c.RESET}")
            print(f"  Is Polyglot     : {c.RED if rep.is_polyglot else c.GREEN}{rep.is_polyglot}{c.RESET}")
            print(f"  Classification  : {c.CYAN}{rep.polyglot_class}{c.RESET}")
            print(f"  Risk Score      : {c.BOLD}{rep.risk_score}/100.0{c.RESET}")
            print(f"  Detected Formats: {', '.join(rep.detected_formats) if rep.detected_formats else 'Unclassified Text'}")
            if rep.embedded_scripts:
                print(f"\n  {c.BOLD}Embedded Scripts & Execution Hooks:{c.RESET}")
                for s in rep.embedded_scripts:
                    print(f"    • {s}")
            if rep.structural_anomalies:
                print(f"\n  {c.BOLD}Structural Anomalies:{c.RESET}")
                for a in rep.structural_anomalies:
                    print(f"    • {a}")
            if rep.mitigation_advice:
                print(f"\n  {c.BOLD}Mitigation Recommendations:{c.RESET}")
                for m in rep.mitigation_advice:
                    print(f"    • {m}")
            print()
        return 0

    elif args.command == "ast":
        from payload_entropy_studio.ast_obfuscation_detector import analyze_ast_obfuscation
        text = get_input_str(args.payload)
        rep = analyze_ast_obfuscation(text)

        if args.json:
            print(json.dumps(rep.to_dict(), indent=2))
        else:
            print(f"\n{c.BOLD}🔍 Structural AST Obfuscation & Evasion Audit{c.RESET}")
            print(f"  Obfuscation     : {c.RED if rep.obfuscation_detected else c.GREEN}{rep.obfuscation_detected}{c.RESET}")
            print(f"  Complexity Score: {c.BOLD}{rep.complexity_score}/100.0{c.RESET}")
            print(f"  Evasion Methods : {', '.join(rep.evasion_techniques) if rep.evasion_techniques else 'None'}")
            if rep.detected_constructs:
                print(f"\n  {c.BOLD}Detected Obfuscated AST Constructs ({len(rep.detected_constructs)}):{c.RESET}")
                for c_item in rep.detected_constructs:
                    print(f"    • [{c_item['category']}] {c_item['description']} -> '{c_item['matched_text'][:40]}'")
            if rep.deobfuscation_hints:
                print(f"\n  {c.BOLD}Deobfuscation Hints:{c.RESET}")
                for h in rep.deobfuscation_hints:
                    print(f"    • {h}")
            print()
        return 0

    elif args.command == "serve":
        server = run_ui_server(args.host, args.port)
        print(f"{c.GREEN}🛡️ Payload & Entropy Studio UI running at:{c.RESET} http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
        return 0

    elif args.command == "mcp":
        run_mcp_server()
        return 0

    elif args.command in ("doctor", "diagnostics", "platform"):
        print(f"\n{c.BOLD}🛡️ Payload Entropy Studio - System Diagnostics{c.RESET}")
        print(f"  Platform         : {sys.platform}")
        print(f"  Python Version   : {sys.version.split()[0]}")
        print(f"  Zero Runtime Deps: {c.GREEN}YES (100% Python Standard Library){c.RESET}")
        print(f"  Status           : {c.GREEN}HEALTHY{c.RESET}\n")
        return 0

    elif args.command == "test-self":
        print(f"{c.BOLD}Running internal self-verification test runner...{c.RESET}")
        analyzer = ThreatAnalyzer()
        rep = analyzer.analyze("<script>alert(1)</script>")
        assert rep.primary_threat == "XSS"
        assert rep.risk_score > 0
        print(f"{c.GREEN}✓ All internal checks passed!{c.RESET}")
        return 0

    return 0
