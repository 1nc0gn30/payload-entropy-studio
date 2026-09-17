"""Tests for recursive de-obfuscation pipeline."""

import pytest
from payload_entropy_studio.deobfuscator import DeobfuscationEngine


def test_url_decoding(deobfuscator):
    res = deobfuscator.deobfuscate("%3Cscript%3E")
    assert res.normalized_payload == "<script>"
    assert res.total_layers_unwrapped >= 1


def test_double_url_decoding(deobfuscator):
    res = deobfuscator.deobfuscate("%252e%252e%252fetc%2fpasswd")
    assert res.normalized_payload == "../etc/passwd"
    assert res.total_layers_unwrapped >= 2


def test_hex_and_unicode_escapes(deobfuscator):
    res = deobfuscator.deobfuscate(r"\x3c\x73\x63\x72\x69\x70\x74\x3e")
    assert res.normalized_payload == "<script>"


def test_string_concatenation_collapse(deobfuscator):
    res = deobfuscator.deobfuscate("al' + 'ert(docu' + 'ment.cookie)")
    assert "alert(document.cookie)" in res.normalized_payload
