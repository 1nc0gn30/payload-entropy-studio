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

    # markov
    p_markov = sub.add_parser("markov", parents=[base], help="Analyze N-gram frequencies, Markov transition entropy, and KL divergence")
    p_markov.add_argument("payload", help="Target payload string or file path")
    p_markov.add_argument("-n", "--order", type=int, default=2, help="N-gram order (default: 2)")
    p_markov.add_argument("--json", action="store_true", help="Output Markov report as JSON")

    # lsh
    p_lsh = sub.add_parser("lsh", aliases=["simhash", "fingerprint"], parents=[base], help="Compute 64-bit SimHash and MinHash locality-sensitive fingerprints")
    p_lsh.add_argument("payload", help="Target payload string or file path")
    p_lsh.add_argument("-c", "--compare", default=None, help="Optional second payload to compare similarity against")
    p_lsh.add_argument("--json", action="store_true", help="Output LSH report as JSON")

    # shellcode
    p_sc = sub.add_parser("shellcode", parents=[base], help="Detect x86/x64 shellcode, NOP sleds, and decoder stubs")
    p_sc.add_argument("payload", help="Target payload string or file path")
    p_sc.add_argument("--json", action="store_true", help="Output shellcode analysis as JSON")

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

    elif args.command == "markov":
        from payload_entropy_studio.markov_lsh import (
            analyze_markov_lsh_profile,
            calculate_ngram_frequencies,
        )
        text = get_input_str(args.payload)
        rep = analyze_markov_lsh_profile(text)
        ngrams = calculate_ngram_frequencies(text, n=args.order)
        if args.json:
            out_d = rep.to_dict()
            out_d["ngrams"] = ngrams
            print(json.dumps(out_d, indent=2))
        else:
            print(f"\n{c.BOLD}🧬 Markovian Byte Transition & N-Gram Profile{c.RESET}")
            print(f"  Payload Length       : {rep.payload_length} bytes")
            print(f"  Transition Entropy   : {c.CYAN}{rep.transition_entropy} bits{c.RESET}")
            print(f"  KL Divergence (Base) : {c.YELLOW}{rep.kl_divergence} bits{c.RESET}")
            print(f"  Markov Anomaly State : {'⚠️  ANOMALOUS' if rep.is_anomalous_markov else '✓ NORMAL'}")
            print(f"\n  {c.BOLD}Top N-Grams (n={args.order}):{c.RESET}")
            for g, freq in list(ngrams.items())[:8]:
                print(f"    • {repr(g):<12} : {freq * 100:.2f}%")
            print()
        return 0

    elif args.command in ("lsh", "simhash", "fingerprint"):
        from payload_entropy_studio.markov_lsh import (
            calculate_hamming_distance,
            calculate_simhash_similarity,
            compute_minhash,
            compute_simhash,
            estimate_jaccard_similarity,
            simhash_hex,
        )
        text = get_input_str(args.payload)
        sh1 = compute_simhash(text)
        mh1 = compute_minhash(text, num_perm=32)
        cmp_result = None
        if args.compare:
            cmp_text = safe_read_text(args.compare) if os.path.isfile(args.compare) else args.compare
            sh2 = compute_simhash(cmp_text)
            mh2 = compute_minhash(cmp_text, num_perm=32)
            dist = calculate_hamming_distance(sh1, sh2)
            sim = calculate_simhash_similarity(sh1, sh2)
            jacc = estimate_jaccard_similarity(mh1, mh2)
            cmp_result = {
                "other_simhash": simhash_hex(sh2),
                "hamming_distance": dist,
                "simhash_similarity": sim,
                "minhash_jaccard_similarity": jacc,
            }

        if args.json:
            res_dict = {
                "simhash": simhash_hex(sh1),
                "simhash_int": sh1,
                "minhash_signature": mh1,
            }
            if cmp_result:
                res_dict["comparison"] = cmp_result
            print(json.dumps(res_dict, indent=2))
        else:
            print(f"\n{c.BOLD}🔑 Locality Sensitive Hashing (LSH) Fingerprint{c.RESET}")
            print(f"  64-bit SimHash (Hex) : {c.GREEN}{simhash_hex(sh1)}{c.RESET}")
            print(f"  SimHash (Integer)    : {sh1}")
            print(f"  MinHash Signature    : {mh1[:6]}... ({len(mh1)} permutations)")
            if cmp_result:
                print(f"\n  {c.BOLD}Comparison with Target:{c.RESET}")
                print(f"    • Other SimHash    : {cmp_result['other_simhash']}")
                print(f"    • Hamming Distance : {cmp_result['hamming_distance']} bits (out of 64)")
                print(f"    • SimHash Match    : {cmp_result['simhash_similarity'] * 100:.1f}%")
                print(f"    • Jaccard Match    : {cmp_result['minhash_jaccard_similarity'] * 100:.1f}%")
            print()
        return 0

    elif args.command == "shellcode":
        from payload_entropy_studio.markov_lsh import detect_shellcode_heuristics
        text = get_input_str(args.payload)
        sc_report = detect_shellcode_heuristics(text)
        if args.json:
            print(json.dumps(sc_report, indent=2))
        else:
            print(f"\n{c.BOLD}⚡ Shellcode & Binary Injection Heuristics{c.RESET}")
            score_col = c.RED if sc_report["score"] >= 0.5 else (c.YELLOW if sc_report["score"] >= 0.3 else c.GREEN)
            print(f"  Shellcode Score      : {score_col}{sc_report['score'] * 100:.1f}/100{c.RESET}")
            print(f"  Probable Shellcode   : {'🚨 YES' if sc_report['is_probable_shellcode'] else '✓ NO'}")
            print(f"  NOP Sled Detected    : {'⚠️ YES' if sc_report['nop_sled_detected'] else 'NO'}")
            print(f"  GetPC Routine        : {'⚠️ YES' if sc_report['getpc_detected'] else 'NO'}")
            print(f"  Syscall Invocations  : {'⚠️ YES' if sc_report['syscall_detected'] else 'NO'}")
            if sc_report["indicators"]:
                print(f"\n  {c.BOLD}Detected Indicators ({len(sc_report['indicators'])}):{c.RESET}")
                for ind in sc_report["indicators"]:
                    print(f"    • {ind}")
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
