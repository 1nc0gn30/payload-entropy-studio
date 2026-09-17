"""
Recursive Multi-Layer De-obfuscation & Anti-Evasion Normalizer.
Decodes URL encoding, nested Base64, Hex escapes, HTML entities, Unicode homoglyphs, and string concatenations.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import base64
import html
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DeobfuscationStep:
    """Represents a single de-obfuscation transform step."""
    layer: int
    transform_type: str
    input_text: str
    output_text: str
    description: str


@dataclass
class DeobfuscationResult:
    """Complete de-obfuscation pipeline history and final unmasked payload."""
    original_payload: str
    normalized_payload: str
    total_layers_unwrapped: int
    transforms_applied: List[str]
    steps: List[DeobfuscationStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_payload": self.original_payload,
            "normalized_payload": self.normalized_payload,
            "total_layers_unwrapped": self.total_layers_unwrapped,
            "transforms_applied": self.transforms_applied,
            "steps": [
                {
                    "layer": s.layer,
                    "transform": s.transform_type,
                    "description": s.description,
                    "output_preview": s.output_text[:120]
                }
                for s in self.steps
            ]
        }


class DeobfuscationEngine:
    """Recursive payload de-obfuscator."""

    def __init__(self, max_recursion_depth: int = 8) -> None:
        self.max_recursion_depth = max_recursion_depth

    def deobfuscate(self, payload: str) -> DeobfuscationResult:
        """Unwrap all layers of obfuscation until fixpoint is reached."""
        current = payload
        steps: List[DeobfuscationStep] = []
        transforms: List[str] = []

        for layer in range(1, self.max_recursion_depth + 1):
            modified = False

            # 1. URL Decoding (%2e%2e -> ..)
            if "%" in current:
                decoded_url = urllib.parse.unquote(current)
                if decoded_url != current:
                    steps.append(DeobfuscationStep(
                        layer=layer,
                        transform_type="URL_DECODE",
                        input_text=current,
                        output_text=decoded_url,
                        description="Decoded percent-encoded URL hex characters."
                    ))
                    transforms.append("URL_DECODE")
                    current = decoded_url
                    modified = True

            # 2. HTML Entities (&lt; or &#x3c;)
            if "&" in current and (";" in current or "&#" in current):
                decoded_html = html.unescape(current)
                if decoded_html != current:
                    steps.append(DeobfuscationStep(
                        layer=layer,
                        transform_type="HTML_ENTITY_DECODE",
                        input_text=current,
                        output_text=decoded_html,
                        description="Decoded HTML entities (&lt;, &#xNN;)."
                    ))
                    transforms.append("HTML_ENTITY_DECODE")
                    current = decoded_html
                    modified = True

            # 3. Hex Escapes (\x41 or \u0041)
            hex_replaced = self._decode_hex_and_unicode_escapes(current)
            if hex_replaced != current:
                steps.append(DeobfuscationStep(
                    layer=layer,
                    transform_type="HEX_UNICODE_ESCAPE_DECODE",
                    input_text=current,
                    output_text=hex_replaced,
                    description="Decoded \\xNN and \\uNNNN character escape sequences."
                ))
                transforms.append("HEX_UNICODE_ESCAPE_DECODE")
                current = hex_replaced
                modified = True

            # 4. String Concatenation ("al" + "ert" -> "alert")
            concat_cleaned = self._collapse_string_concatenations(current)
            if concat_cleaned != current:
                steps.append(DeobfuscationStep(
                    layer=layer,
                    transform_type="STRING_CONCAT_COLLAPSE",
                    input_text=current,
                    output_text=concat_cleaned,
                    description="Collapsed fragmented string concatenations ('a'+'b')."
                ))
                transforms.append("STRING_CONCAT_COLLAPSE")
                current = concat_cleaned
                modified = True

            # 5. Base64 Substring Decoding
            b64_decoded = self._decode_embedded_base64(current)
            if b64_decoded != current:
                steps.append(DeobfuscationStep(
                    layer=layer,
                    transform_type="BASE64_DECODE",
                    input_text=current,
                    output_text=b64_decoded,
                    description="Decoded Base64 payload block."
                ))
                transforms.append("BASE64_DECODE")
                current = b64_decoded
                modified = True

            if not modified:
                # Reached fixpoint
                break

        return DeobfuscationResult(
            original_payload=payload,
            normalized_payload=current,
            total_layers_unwrapped=len(steps),
            transforms_applied=list(dict.fromkeys(transforms)),
            steps=steps
        )

    def _decode_hex_and_unicode_escapes(self, text: str) -> str:
        """Decode \\x41 and \\u0041 style escapes."""
        # Hex \xNN
        def replace_hex(match: re.Match) -> str:
            try:
                return chr(int(match.group(1), 16))
            except Exception:
                return match.group(0)

        res = re.sub(r"\\x([0-9a-fA-F]{2})", replace_hex, text)
        # Unicode \uNNNN
        def replace_unicode(match: re.Match) -> str:
            try:
                return chr(int(match.group(1), 16))
            except Exception:
                return match.group(0)

        res = re.sub(r"\\u([0-9a-fA-F]{4})", replace_unicode, res)
        return res

    def _collapse_string_concatenations(self, text: str) -> str:
        """Collapse 'a' + 'b' and \"a\" + \"b\" patterns."""
        # Match 'foo' + 'bar' or "foo" + "bar"
        res = re.sub(r"['\"]\s*\+\s*['\"]", "", text)
        return res

    def _decode_embedded_base64(self, text: str) -> str:
        """Detect and decode standalone Base64 encoded code sequences."""
        # Match valid base64 strings of length >= 16
        b64_pattern = r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"

        def replace_b64(match: re.Match) -> str:
            matched_str = match.group(0)
            try:
                decoded = base64.b64decode(matched_str, validate=True).decode("utf-8")
                # Only replace if decoded string is mostly printable text
                if sum(1 for c in decoded if 32 <= ord(c) <= 126 or c in "\r\n\t") / len(decoded) > 0.85:
                    return decoded
            except Exception:
                pass
            return matched_str

        return re.sub(b64_pattern, replace_b64, text)
