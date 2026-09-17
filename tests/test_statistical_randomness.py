"""Unit tests for statistical randomness and packer/crypter detection."""

import os
from payload_entropy_studio import (
    StatisticalRandomnessReport,
    analyze_statistical_randomness,
    calculate_chi_square,
    calculate_serial_correlation,
    estimate_monte_carlo_pi,
)


def test_chi_square_uniform_random():
    # 2048 pseudo-random bytes from os.urandom
    data = os.urandom(2048)
    chi_sq = calculate_chi_square(data)
    # Degrees of freedom = 255. For 2048 bytes of random data, Chi-sq is typically between 180 and 340.
    assert chi_sq < 450.0


def test_chi_square_structured_text():
    text = "SELECT * FROM users WHERE username = 'admin' AND password = 'password' UNION SELECT 1, 2, 3--"
    chi_sq = calculate_chi_square(text)
    # Structured plain ASCII text concentrates on a few dozen byte values, giving very high Chi-sq
    assert chi_sq > 1000.0


def test_monte_carlo_pi_approximation():
    # Random byte stream coordinates should approximate Pi
    data = os.urandom(4096)
    pi_val, err_pct = estimate_monte_carlo_pi(data)
    assert 2.7 <= pi_val <= 3.6
    assert err_pct < 15.0


def test_serial_correlation():
    # Highly correlated repeated sequence
    pattern = b"ABCD" * 100
    corr = calculate_serial_correlation(pattern)
    assert abs(corr) > 0.0

    # Constant byte stream variance is 0
    zeros = b"\x00" * 100
    assert calculate_serial_correlation(zeros) == 0.0


def test_analyze_statistical_randomness_packer_detection():
    # Random packed payload simulation
    crypto_payload = os.urandom(1024)
    report = analyze_statistical_randomness(crypto_payload)

    assert isinstance(report, StatisticalRandomnessReport)
    assert report.shannon_entropy >= 7.0
    assert report.packer_detected is True
    assert report.packer_confidence_pct >= 60.0
    assert report.chi_square_assessment == "Highly Uniform (Crypto/Packed)"
    d = report.to_dict()
    assert "monte_carlo_pi" in d
    assert "packer_detected" in d


def test_analyze_statistical_randomness_plain_text():
    plain_text = "This is a standard English text sentence without any encryption."
    report = analyze_statistical_randomness(plain_text)

    assert report.packer_detected is False
    assert report.shannon_entropy < 5.0
