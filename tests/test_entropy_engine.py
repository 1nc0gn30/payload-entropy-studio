"""Tests for Shannon Entropy and Sliding Window Profiler."""

import pytest
from payload_entropy_studio.entropy_engine import (
    EntropyClassification,
    analyze_entropy_profile,
    calculate_shannon_entropy,
)


def test_shannon_entropy_calculation():
    # Repetitive single character has 0 entropy
    assert calculate_shannon_entropy("AAAAAAA") == 0.0

    # High entropy random-like string
    high_ent = calculate_shannon_entropy(bytes(range(256)))
    assert high_ent >= 7.99

    # Normal English text is around 3.5-4.5
    eng_ent = calculate_shannon_entropy("The quick brown fox jumps over the lazy dog.")
    assert 3.0 <= eng_ent <= 5.0


def test_entropy_profile_analysis():
    payload = "SELECT * FROM users WHERE id=1; " + "A" * 50
    rep = analyze_entropy_profile(payload)
    assert rep.total_bytes == len(payload)
    assert rep.shannon_entropy > 0.0
    assert "printable_pct" in rep.char_classes
    assert rep.classification in EntropyClassification


def test_empty_entropy_profile():
    rep = analyze_entropy_profile("")
    assert rep.total_bytes == 0
    assert rep.shannon_entropy == 0.0
    assert len(rep.byte_distribution_256) == 256


def test_byte_distribution_and_adaptive_window():
    # Test 256-bin distribution
    data = b"ABC" * 10 + bytes([0x00, 0xFF])
    rep = analyze_entropy_profile(data)
    assert len(rep.byte_distribution_256) == 256
    assert rep.byte_distribution_256[ord("A")] == 10
    assert rep.byte_distribution_256[ord("B")] == 10
    assert rep.byte_distribution_256[ord("C")] == 10
    assert rep.byte_distribution_256[0x00] == 1
    assert rep.byte_distribution_256[0xFF] == 1
    # Check adaptive sliding window on short payload (len = 32)
    assert len(rep.sliding_window_profile) > 0
    d = rep.to_dict()
    assert "byte_distribution_256" in d
    assert len(d["byte_distribution_256"]) == 256

