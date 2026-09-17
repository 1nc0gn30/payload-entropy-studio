"""
WAF Rule Synthesizer: ModSecurity CRS, Cloudflare WAF, AWS WAF, and Suricata IDS Rules.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from payload_entropy_studio.threat_analyzer import ThreatReport


def generate_waf_rules(report: ThreatReport) -> Dict[str, str]:
    """Synthesize production WAF filter rules from detected payload threats."""
    threat = report.primary_threat
    sample_pattern = ""

    if report.matched_rules:
        sample_pattern = report.matched_rules[0].get("matched_subpattern", "")

    if not sample_pattern:
        sample_pattern = re.escape(report.normalized_payload[:32])
    else:
        sample_pattern = re.escape(sample_pattern[:32])

    rule_id = 900001 + abs(hash(report.raw_payload)) % 90000

    # 1. ModSecurity CRS Rule
    modsec_rule = f"""# ModSecurity 3 / OWASP CRS Custom Filter
SecRule ARGS|REQUEST_URI|REQUEST_BODY "@rx {sample_pattern}" \\
    "id:{rule_id},\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'Blocked {threat} Attack Pattern',\\
    tag:'application-multi',\\
    tag:'security-threat',\\
    severity:'CRITICAL'"
"""

    # 2. Cloudflare WAF Expression
    cf_expr = f"""(http.request.uri.query contains "{sample_pattern}" or http.request.body.raw contains "{sample_pattern}")"""

    # 3. AWS WAF v2 JSON Pattern Set
    aws_waf_rule = json.dumps({
        "Name": f"Block-{threat}-{rule_id}",
        "Priority": 10,
        "Action": {"Block": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": f"Metric-{threat}"
        },
        "Statement": {
            "RegexMatchStatement": {
                "SearchString": sample_pattern,
                "FieldToMatch": {"QueryString": {}},
                "TextTransformations": [
                    {"Priority": 0, "Type": "URL_DECODE"},
                    {"Priority": 1, "Type": "LOWERCASE"}
                ]
            }
        }
    }, indent=2)

    # 4. Suricata IDS Signature
    suricata_rule = f"""alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET ATTACK Known {threat} Injection Attempt"; flow:established,to_server; content:"{sample_pattern[:20]}"; nocase; http_uri; sid:{rule_id}; rev:1; classtype:web-application-attack;)"""

    return {
        "modsecurity": modsec_rule.strip(),
        "cloudflare": cf_expr,
        "aws_waf": aws_waf_rule,
        "suricata": suricata_rule
    }
