"""
Shannon Entropy, Sliding Window Profiler & Byte Frequency Distribution Engine.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import collections
import math
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


class EntropyClassification(str, Enum):
    NORMAL_TEXT = "NORMAL_TEXT"  # 1.0 - 4.5 bits
    CODE_SCRIPT = "CODE_SCRIPT"  # 4.5 - 5.5 bits
    OBFUSCATED_DATA = "OBFUSCATED_DATA"  # 5.5 - 6.8 bits
    HIGH_ENTROPY_PACKED = "HIGH_ENTROPY_PACKED"  # 6.8 - 8.0 bits (shellcode / crypto)


@dataclass
class EntropyReport:
    """Comprehensive entropy and byte distribution metrics."""
    total_bytes: int
    shannon_entropy: float  # 0.0 to 8.0
    classification: EntropyClassification
    is_suspicious_entropy: bool
    compression_ratio: float  # zlib ratio (estimate of Kolmogorov complexity)
    byte_frequencies: Dict[int, int]  # Top byte distribution
    char_classes: Dict[str, float]  # Percentages: printable, whitespace, control, high_bit, special
    sliding_window_profile: List[Dict[str, Any]] = field(default_factory=list)
    byte_distribution_256: List[int] = field(default_factory=lambda: [0] * 256)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_bytes": self.total_bytes,
            "shannon_entropy": round(self.shannon_entropy, 4),
            "classification": self.classification.value,
            "is_suspicious_entropy": self.is_suspicious_entropy,
            "compression_ratio": round(self.compression_ratio, 4),
            "char_classes": {k: round(v, 2) for k, v in self.char_classes.items()},
            "sliding_window_profile": self.sliding_window_profile,
            "byte_distribution_256": self.byte_distribution_256,
        }


def calculate_shannon_entropy(data: Union[bytes, str]) -> float:
    """Calculate Shannon Entropy (in bits per byte, 0.0 - 8.0) for byte or string input."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if not raw:
        return 0.0

    length = len(raw)
    counts = collections.Counter(raw)
    entropy = 0.0

    for count in counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return entropy


def analyze_entropy_profile(
    data: Union[bytes, str],
    window_size: int = 32,
    step_size: int = 8
) -> EntropyReport:
    """
    Perform deep statistical entropy analysis including sliding window heatmap and character classes.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else data
    length = len(raw)

    if length == 0:
        return EntropyReport(
            total_bytes=0,
            shannon_entropy=0.0,
            classification=EntropyClassification.NORMAL_TEXT,
            is_suspicious_entropy=False,
            compression_ratio=1.0,
            byte_frequencies={},
            char_classes={"printable_pct": 0.0, "whitespace_pct": 0.0, "control_pct": 0.0, "high_bit_pct": 0.0, "special_pct": 0.0},
            sliding_window_profile=[],
            byte_distribution_256=[0] * 256,
        )

    # 1. Global Shannon Entropy
    global_entropy = calculate_shannon_entropy(raw)

    # 2. Classification
    if global_entropy >= 6.8:
        classification = EntropyClassification.HIGH_ENTROPY_PACKED
        is_suspicious = True
    elif global_entropy >= 5.6:
        classification = EntropyClassification.OBFUSCATED_DATA
        is_suspicious = True
    elif global_entropy >= 4.5:
        classification = EntropyClassification.CODE_SCRIPT
        is_suspicious = False
    else:
        classification = EntropyClassification.NORMAL_TEXT
        is_suspicious = False

    # 3. Compression ratio (Kolmogorov complexity proxy)
    try:
        compressed_len = len(zlib.compress(raw, level=9))
        comp_ratio = compressed_len / max(1, length)
    except Exception:
        comp_ratio = 1.0

    # 4. Fast 256-bin Byte Distribution & Character Classes (Single Pass)
    dist = [0] * 256
    for b in raw:
        dist[b] += 1

    printable = sum(dist[32:127])
    whitespace = dist[9] + dist[10] + dist[13] + dist[32]
    control = sum(dist[:32]) - (dist[9] + dist[10] + dist[13])
    high_bit = sum(dist[128:256])
    alphanumeric_space = sum(dist[48:58]) + sum(dist[65:91]) + sum(dist[97:123]) + dist[32]
    special = max(0, printable - alphanumeric_space)

    inv_len = 100.0 / length
    char_classes = {
        "printable_pct": printable * inv_len,
        "whitespace_pct": whitespace * inv_len,
        "control_pct": control * inv_len,
        "high_bit_pct": high_bit * inv_len,
        "special_pct": special * inv_len,
    }

    # 5. Top Byte Frequencies
    byte_counts = collections.Counter(raw)
    top_frequencies = dict(byte_counts.most_common(10))

    # 6. Sliding Window Profile (Adaptive for short & long payloads)
    sliding_profile = []
    eff_window = window_size
    eff_step = step_size
    if length < window_size and length >= 8:
        eff_window = max(4, length // 3)
        eff_step = max(1, length // 10)

    if length >= eff_window:
        for offset in range(0, length - eff_window + 1, eff_step):
            chunk = raw[offset: offset + eff_window]
            chunk_entropy = calculate_shannon_entropy(chunk)
            sliding_profile.append({
                "offset": offset,
                "window_size": eff_window,
                "entropy": round(chunk_entropy, 3),
                "is_spike": chunk_entropy >= 6.5
            })

    return EntropyReport(
        total_bytes=length,
        shannon_entropy=global_entropy,
        classification=classification,
        is_suspicious_entropy=is_suspicious,
        compression_ratio=comp_ratio,
        byte_frequencies=top_frequencies,
        char_classes=char_classes,
        sliding_window_profile=sliding_profile,
        byte_distribution_256=dist,
    )
