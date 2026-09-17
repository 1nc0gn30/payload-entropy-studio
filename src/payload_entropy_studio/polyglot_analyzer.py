"""Dual-Context Polyglot File Payload Classifier & Multi-Format Header Validator.

Analyzes raw byte payloads and strings to detect cross-context polyglots
(e.g., GIF+JavaScript, PNG+PHP, PDF+JS, JPEG+ZIP, and SVG+XSS) where a file is
valid according to one file format parser while simultaneously being executed
by a secondary interpreter or browser context.
100% Python Standard Library.
"""

from __future__ import annotations

import binascii
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass
class PolyglotReport:
    """Detailed evaluation report for dual-context polyglots."""
    is_polyglot: bool
    detected_formats: List[str]
    polyglot_class: str
    risk_score: float
    embedded_scripts: List[str]
    structural_anomalies: List[str]
    mitigation_advice: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_polyglot": self.is_polyglot,
            "detected_formats": list(self.detected_formats),
            "polyglot_class": self.polyglot_class,
            "risk_score": round(self.risk_score, 2),
            "embedded_scripts": list(self.embedded_scripts),
            "structural_anomalies": list(self.structural_anomalies),
            "mitigation_advice": list(self.mitigation_advice),
        }


# File format magic signatures
MAGIC_SIGNATURES: Dict[str, bytes] = {
    "GIF": b"GIF8",
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "PDF": b"%PDF-",
    "ZIP": b"PK\x03\x04",
    "ELF": b"\x7fELF",
    "PE_EXE": b"MZ",
    "XML": b"<?xml",
    "SVG": b"<svg",
    "HTML": b"<!DOCTYPE html",
}


def _to_bytes(data: Union[str, bytes]) -> bytes:
    """Normalize payload input to bytes."""
    if isinstance(data, bytes):
        return data
    try:
        # Check if hex-encoded string like "\x47\x49\x46..." or "474946..."
        stripped = data.strip()
        if stripped.startswith("\\x"):
            hex_str = stripped.replace("\\x", "")
            return bytes.fromhex(hex_str)
        return data.encode("utf-8", errors="surrogateescape")
    except Exception:
        return str(data).encode("latin-1", errors="replace")


def detect_file_formats(raw_bytes: bytes) -> List[str]:
    """Identify matching file formats by magic bytes and structure."""
    formats = []
    prefix = raw_bytes[:16]

    if prefix.startswith(b"GIF87a") or prefix.startswith(b"GIF89a"):
        formats.append("GIF")
    if raw_bytes.startswith(MAGIC_SIGNATURES["PNG"]):
        formats.append("PNG")
    if raw_bytes.startswith(MAGIC_SIGNATURES["JPEG"]):
        formats.append("JPEG")
    if raw_bytes.startswith(MAGIC_SIGNATURES["PDF"]):
        formats.append("PDF")
    if raw_bytes.startswith(MAGIC_SIGNATURES["ZIP"]) or (b"PK\x03\x04" in raw_bytes and b"PK\x05\x06" in raw_bytes):
        formats.append("ZIP")
    if raw_bytes.startswith(MAGIC_SIGNATURES["ELF"]):
        formats.append("ELF")
    if raw_bytes.startswith(MAGIC_SIGNATURES["PE_EXE"]):
        formats.append("PE_EXE")

    text_lower = raw_bytes[:512].lower()
    if b"<svg" in text_lower:
        formats.append("SVG")
    elif b"<?xml" in text_lower:
        formats.append("XML")
    elif b"<!doctype html" in text_lower or b"<html" in text_lower:
        formats.append("HTML")

    return formats


def analyze_polyglot_payload(payload: Union[str, bytes]) -> PolyglotReport:
    """Analyze a payload for dual-context polyglot constructs and stealth execution channels.

    Args:
        payload: String or raw bytes of the candidate file/payload.

    Returns:
        PolyglotReport: Detected file formats, polyglot classification, and mitigation advice.
    """
    data_bytes = _to_bytes(payload)
    detected_formats = detect_file_formats(data_bytes)
    embedded_scripts: List[str] = []
    anomalies: List[str] = []
    mitigations: List[str] = []

    # Text interpretation of bytes for regex analysis
    text_sample = data_bytes.decode("latin-1", errors="replace")

    # 1. Check for Embedded JavaScript execution patterns
    js_patterns = [
        (r"(<script\b[^>]*>[\s\S]*?</script>)", "HTML/SVG <script> block"),
        (r"(javascript:\s*[\w(])", "javascript: URI scheme handler"),
        (r"(\b(?:alert|eval|confirm|prompt|Function)\s*\([^)]*\))", "Executable JS function call"),
        (r"(/\*[\s\S]*?\*/\s*=\s*[\w\d]+)", "GIF/Image comment assignment polyglot trick"),
        (r"(\bdocument\.cookie\b|\bwindow\.location\b)", "DOM credential access call"),
        (r"(onload\s*=\s*['\"][^'\"]+['\"])", "Embedded onload attribute"),
    ]
    for pattern, desc in js_patterns:
        m = re.search(pattern, text_sample, re.IGNORECASE)
        if m:
            embedded_scripts.append(f"{desc}: '{m.group(0)[:60]}'")

    # 2. Check for Embedded PHP Execution
    php_patterns = [
        (r"(<\?(?:php|=)[\s\S]*?\?>)", "Embedded PHP code block"),
        (r"(\b(?:eval|system|passthru|shell_exec|exec|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE))", "PHP webshell execution hook"),
    ]
    for pattern, desc in php_patterns:
        m = re.search(pattern, text_sample, re.IGNORECASE)
        if m:
            embedded_scripts.append(f"{desc}: '{m.group(0)[:60]}'")
            if "PHP" not in detected_formats:
                detected_formats.append("PHP")

    # 3. Check for Embedded Shell / ELF / PE execution
    if b"#!/bin/sh" in data_bytes or b"#!/bin/bash" in data_bytes:
        detected_formats.append("SHELL_SCRIPT")
        embedded_scripts.append("Shell script shebang (#!/bin/sh)")

    # 4. Check for ZIP / JAR appended to image (ZIP file header after start)
    if ("GIF" in detected_formats or "JPEG" in detected_formats or "PNG" in detected_formats) and (b"PK\x03\x04" in data_bytes[16:]):
        detected_formats.append("ZIP")
        anomalies.append("ZIP central directory / local file header embedded inside image stream")

    # 5. Classify Polyglot Type
    polyglot_class = "NONE"
    risk_score = 0.0
    is_polyglot = False

    if "GIF" in detected_formats and any("JS" in s or "script" in s or "/*" in s for s in embedded_scripts):
        is_polyglot = True
        polyglot_class = "GIF_JAVASCRIPT_POLYGLOT"
        risk_score = 95.0
        anomalies.append("Valid GIF header followed by JavaScript block comment closure (GIF89a/* trick)")
        mitigations.append("Strictly validate MIME headers and force Content-Disposition: attachment for uploaded images.")
        mitigations.append("Re-encode images through an image processing pipeline (stripping non-image byte streams).")

    elif "PNG" in detected_formats and "PHP" in detected_formats:
        is_polyglot = True
        polyglot_class = "PNG_PHP_WEBSHELL_POLYGLOT"
        risk_score = 98.0
        anomalies.append("Valid PNG image header with embedded executable PHP web shell tags")
        mitigations.append("Store uploads on dedicated static CDN without PHP engine handler mapping (.php extension restrictions).")

    elif "PDF" in detected_formats and (b"/JavaScript" in data_bytes or b"/JS" in data_bytes or b"/Launch" in data_bytes):
        is_polyglot = True
        polyglot_class = "PDF_ACTION_SCRIPT_POLYGLOT"
        risk_score = 90.0
        anomalies.append("PDF document stream contains /JavaScript or /Launch interactive actions")
        mitigations.append("Flatten uploaded PDFs or strip interactive /Names /JavaScript catalog dictionaries.")

    elif "JPEG" in detected_formats and "ZIP" in detected_formats:
        is_polyglot = True
        polyglot_class = "JPEG_ZIP_ARCHIVE_POLYGLOT"
        risk_score = 88.0
        anomalies.append("Dual-format JPEG image concatenated with ZIP archive file tables (stego-dropper)")
        mitigations.append("Verify image EOF markers (\xff\xd9 for JPEG) and truncate all trailing data.")

    elif "SVG" in detected_formats and embedded_scripts:
        is_polyglot = True
        polyglot_class = "SVG_SCRIPT_INJECTION_POLYGLOT"
        risk_score = 92.0
        anomalies.append("SVG vector graphic containing active scripting elements or event handlers")
        mitigations.append("Sanitize SVG XML through DOMPurify or render via <img> tag with Content-Security-Policy sandbox.")

    elif len(detected_formats) >= 2:
        is_polyglot = True
        polyglot_class = f"HYBRID_{'_'.join(detected_formats[:2])}_POLYGLOT"
        risk_score = 75.0
        anomalies.append(f"Payload satisfies multiple file format signatures simultaneously: {detected_formats}")
        mitigations.append("Enforce single strict content-type validation and prevent dual-execution handlers.")

    elif embedded_scripts and len(detected_formats) == 1 and detected_formats[0] in ("GIF", "PNG", "JPEG", "PDF"):
        is_polyglot = True
        polyglot_class = f"{detected_formats[0]}_EMBEDDED_CODE_POLYGLOT"
        risk_score = 85.0
        mitigations.append("Disallow raw binary uploads to be served with executable browser MIME types.")

    if not is_polyglot:
        polyglot_class = "MONOLITHIC_PAYLOAD"
        risk_score = 10.0 if not embedded_scripts else 40.0
        mitigations.append("Standard input validation and Content-Type verification sufficient.")

    return PolyglotReport(
        is_polyglot=is_polyglot,
        detected_formats=detected_formats,
        polyglot_class=polyglot_class,
        risk_score=risk_score,
        embedded_scripts=embedded_scripts,
        structural_anomalies=anomalies,
        mitigation_advice=mitigations,
    )
