"""Structural AST & Grammar Obfuscation Analyzer for Scripts and Queries.

Evaluates syntactic constructs across JavaScript, Bash, PowerShell, and SQL
for evasion techniques, character interleaving, dynamic property resolution,
string splitting, and execution wrapper obfuscation.
100% Python Standard Library.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ASTObfuscationReport:
    """Detailed structural obfuscation assessment report."""
    obfuscation_detected: bool
    complexity_score: float
    evasion_techniques: List[str]
    detected_constructs: List[Dict[str, Any]]
    deobfuscation_hints: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obfuscation_detected": self.obfuscation_detected,
            "complexity_score": round(self.complexity_score, 2),
            "evasion_techniques": list(self.evasion_techniques),
            "detected_constructs": [dict(c) for c in self.detected_constructs],
            "deobfuscation_hints": list(self.deobfuscation_hints),
        }


OBFUSCATION_PATTERNS: List[Tuple[str, str, int, str]] = [
    # Category, Regex, Weight, Description
    (
        "DYNAMIC_EVAL_WRAPPER",
        r"(\b(?:eval|Function|execScript|setTimeout|setInterval)\s*\(\s*(?:atob|Buffer\.from|String\.fromCharCode|unescape|decodeURIComponent))",
        35,
        "Dynamic code execution wrapper decoding encoded/obfuscated strings",
    ),
    (
        "BRACKET_PROPERTY_LOOKUP",
        r"(\b(?:window|this|self|globalThis|top|parent)\s*\[\s*['\"][^'\"]+['\"]\s*\+\s*['\"][^'\"]+['\"])",
        25,
        "Bracket notation computed property evasion (e.g. window['ev'+'al'])",
    ),
    (
        "STRING_CONCATENATION_EVASION",
        r"((?:['\"][a-zA-Z0-9_\-\.]{1,4}['\"]\s*\+\s*){2,}['\"][a-zA-Z0-9_\-\.]{1,4}['\"])",
        20,
        "Fragmented string literal concatenation to evade keyword filters",
    ),
    (
        "SHELL_ENV_SPLITTING",
        r"(\$\{IFS\}|\$@|\$\*|\$u|\$1|\$9|\$\{\w+:\d+:\d+\})",
        25,
        "Bash/sh environment variable substitution and IFS whitespace evasion",
    ),
    (
        "SHELL_QUOTE_ESCAPE_INSERTION",
        r"(\b[a-zA-Z]{1,3}(?:''|\"\")[a-zA-Z]{1,4}|\\[a-zA-Z]\\[a-zA-Z])",
        20,
        "Bash command quote insertion or backslash escaping (e.g., c''at or \\c\\a\\t)",
    ),
    (
        "HEX_OCTAL_ESCAPED_IDENTIFIERS",
        r"((?:\\x[0-9a-fA-F]{2}){2,}|(?:\\u[0-9a-fA-F]{4}){2,}|(?:\\0[0-7]{2}){2,})",
        20,
        "Repeated hex, unicode, or octal escaped byte sequences",
    ),
    (
        "POWERSHELL_BACKTICK_SPLIT",
        r"(`[a-zA-Z]`[a-zA-Z]`[a-zA-Z]|(?:iex|Invoke-Expression)\s*\(|\[Convert\]::FromBase64String)",
        30,
        "PowerShell backtick keyword obfuscation or Invoke-Expression payload",
    ),
    (
        "HEX_ENCODED_IP_ADDRESS",
        r"(\b0x[0-9a-fA-F]{8}\b|\b0[0-7]{10,12}\b|\b2130706433\b)",
        25,
        "Hex, octal, or dword encoded IP address to bypass SSRF URL sanitizers",
    ),
    (
        "SQL_COMMENT_SPLITTING",
        r"(/\*![\s\S]*?\*/|/\*[\s\S]*?\*/\s*(?:SELECT|UNION|FROM|WHERE))",
        25,
        "MySQL conditional comment execution (/*!...*/) or inline comment evasion",
    ),
    (
        "OBFUSCATED_VAR_NAMES",
        r"(\b_0x[a-f0-9]{4,6}\b|\b[a-zA-Z0-9_$]{1,2}\s*=\s*\[[\s\S]{10,}\])",
        15,
        "JavaScript packer identifier mangling (e.g., Javascript-Obfuscator _0x hex names)",
    ),
]


def analyze_ast_obfuscation(payload: str) -> ASTObfuscationReport:
    """Analyze script or query text for structural AST evasion and obfuscation techniques.

    Args:
        payload: Input string (JavaScript, Bash, SQL, PowerShell, etc.).

    Returns:
        ASTObfuscationReport: Comprehensive obfuscation scoring and detected techniques.
    """
    if not payload or not isinstance(payload, str):
        return ASTObfuscationReport(
            obfuscation_detected=False,
            complexity_score=0.0,
            evasion_techniques=[],
            detected_constructs=[],
            deobfuscation_hints=["Empty or non-string payload."],
        )

    evasion_techniques = set()
    detected_constructs: List[Dict[str, Any]] = []
    total_weight = 0

    # 1. Regex signature inspection for AST/grammar evasion patterns
    for category, pattern, weight, description in OBFUSCATION_PATTERNS:
        matches = list(re.finditer(pattern, payload, re.IGNORECASE))
        if matches:
            evasion_techniques.add(category)
            total_weight += weight
            for m in matches[:3]:  # Capture top 3 instances per category
                detected_constructs.append({
                    "category": category,
                    "matched_text": m.group(0),
                    "start": m.start(),
                    "end": m.end(),
                    "description": description,
                    "weight": weight,
                })

    # 2. Check for Non-printable / Zero-width characters
    zero_width_chars = [c for c in payload if ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x00AD)]
    if zero_width_chars:
        evasion_techniques.add("ZERO_WIDTH_CHARACTER_INTERLEAVING")
        total_weight += 30
        detected_constructs.append({
            "category": "ZERO_WIDTH_CHARACTER_INTERLEAVING",
            "matched_text": f"Found {len(zero_width_chars)} zero-width characters (e.g. \\u{ord(zero_width_chars[0]):04x})",
            "start": 0,
            "end": len(payload),
            "description": "Zero-width spaces or soft hyphens inserted to defeat string matching filters",
            "weight": 30,
        })

    # 3. Structural concatenation count
    concat_plus_count = payload.count("+")
    if concat_plus_count >= 5 and len(payload) < 200:
        evasion_techniques.add("EXCESSIVE_CONCATENATION_DENSITY")
        total_weight += 15

    # 4. Obfuscation complexity score
    complexity_score = min(100.0, float(total_weight))
    obfuscation_detected = complexity_score >= 25.0

    # 5. Remediation / Deobfuscation Hints
    hints: List[str] = []
    if "DYNAMIC_EVAL_WRAPPER" in evasion_techniques:
        hints.append("Normalize dynamic code execution: isolate decoder arguments and trace decoded AST.")
    if "BRACKET_PROPERTY_LOOKUP" in evasion_techniques or "STRING_CONCATENATION_EVASION" in evasion_techniques:
        hints.append("Fold constant string concatenations (e.g. 'e'+'v'+'a'+'l' -> 'eval') prior to inspection.")
    if "SHELL_ENV_SPLITTING" in evasion_techniques or "SHELL_QUOTE_ESCAPE_INSERTION" in evasion_techniques:
        hints.append("Normalize shell tokens by stripping empty quotes, IFS variables, and bash backslashes.")
    if "ZERO_WIDTH_CHARACTER_INTERLEAVING" in evasion_techniques:
        hints.append("Sanitize input with NFKC unicode normalization and strip zero-width characters (\\u200B-\\u200D, \\uFEFF).")
    if not hints:
        hints.append("Payload exhibits standard un-obfuscated grammar.")

    return ASTObfuscationReport(
        obfuscation_detected=obfuscation_detected,
        complexity_score=complexity_score,
        evasion_techniques=sorted(list(evasion_techniques)),
        detected_constructs=detected_constructs,
        deobfuscation_hints=hints,
    )
