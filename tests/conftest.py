"""Pytest configuration and fixtures for payload-entropy-studio."""

import os
import sys
from pathlib import Path
import pytest

# Ensure src is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from payload_entropy_studio.deobfuscator import DeobfuscationEngine
from payload_entropy_studio.threat_analyzer import ThreatAnalyzer


@pytest.fixture
def threat_analyzer() -> ThreatAnalyzer:
    return ThreatAnalyzer()


@pytest.fixture
def deobfuscator() -> DeobfuscationEngine:
    return DeobfuscationEngine()
