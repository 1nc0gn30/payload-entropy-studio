"""
Markovian Transition Profiler, Locality Sensitive Hashing (SimHash/MinHash),
and Shellcode Heuristics Engine for Security Payloads.

Zero external runtime dependencies (100% Python standard library).
Provides:
1. N-gram frequency distribution and Markov conditional transition entropy:
   H(X_t | X_{t-1}) = - sum_{i,j} P(i) P(j|i) log2 P(j|i)
2. Kullback-Leibler (KL) divergence against natural language and standard HTTP query baselines:
   D_KL(P || Q) = sum_i P(i) log2 (P(i) / Q(i))
3. 64-bit SimHash locality-sensitive fingerprinting with Hamming distance metrics
   for detecting polymorphic payload mutations and near-duplicate cluster classification.
4. MinHash signature generation with Universal Hash Permutations for Jaccard similarity estimation.
5. x86/x64 shellcode heuristic detection (NOP sleds, GetPC routines, syscalls, decoder stubs).
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union


# ---------------------------------------------------------------------------
# Default Baseline Character Distributions (Natural Text & Common HTTP Queries)
# ---------------------------------------------------------------------------

# Normalized ASCII frequency distribution for standard English text & HTTP inputs
# ASCII 0-255: letters, digits, spaces, and punctuation have high mass; non-printables near zero
_BASELINE_DISTRIBUTION: Dict[int, float] = {}
for _b in range(256):
    if 97 <= _b <= 122:      # a-z
        _BASELINE_DISTRIBUTION[_b] = 0.025
    elif 65 <= _b <= 90:     # A-Z
        _BASELINE_DISTRIBUTION[_b] = 0.008
    elif 48 <= _b <= 57:     # 0-9
        _BASELINE_DISTRIBUTION[_b] = 0.015
    elif _b in (32, 44, 46, 58, 59, 61, 38, 47, 63, 45, 95):  # common delimiters
        _BASELINE_DISTRIBUTION[_b] = 0.012
    else:                    # other characters / non-printables
        _BASELINE_DISTRIBUTION[_b] = 0.0001

# Normalize baseline
_baseline_total = sum(_BASELINE_DISTRIBUTION.values())
for _b in range(256):
    _BASELINE_DISTRIBUTION[_b] /= _baseline_total


# ---------------------------------------------------------------------------
# Input Normalization Helper
# ---------------------------------------------------------------------------

def to_bytes(payload: Union[str, bytes, Sequence[int]]) -> bytes:
    """Safely convert string, bytes, or hex sequence into raw bytes."""
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        # Check if string looks like continuous hex (e.g., "\x90\x90" or "909090")
        if payload.startswith(("\\x", "\\X")):
            try:
                hex_clean = re.sub(r"\\[xX]", "", payload)
                return bytes.fromhex(hex_clean)
            except ValueError:
                pass
        if len(payload) >= 16 and len(payload) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", payload):
            try:
                return bytes.fromhex(payload)
            except ValueError:
                pass
        return payload.encode("utf-8", errors="replace")
    return bytes(payload)


# ---------------------------------------------------------------------------
# 1. N-Gram Frequencies & Markov Transition Matrix
# ---------------------------------------------------------------------------

def calculate_ngram_frequencies(payload: Union[str, bytes], n: int = 2) -> Dict[str, float]:
    """Calculate normalized n-gram frequency distribution of payload."""
    raw = to_bytes(payload)
    if len(raw) < n or n < 1:
        return {}

    counts: Dict[bytes, int] = {}
    total = len(raw) - n + 1

    for i in range(total):
        gram = raw[i:i + n]
        counts[gram] = counts.get(gram, 0) + 1

    result: Dict[str, float] = {}
    for gram, cnt in counts.items():
        # Represent as hex or ascii string
        try:
            key = gram.decode("ascii")
            if not key.isprintable():
                key = gram.hex()
        except UnicodeDecodeError:
            key = gram.hex()
        result[key] = round(cnt / total, 5)

    return result


def build_markov_transition_matrix(payload: Union[str, bytes]) -> Dict[int, Dict[int, float]]:
    """Build first-order Markov transition probability matrix P(byte_t | byte_{t-1})."""
    raw = to_bytes(payload)
    if len(raw) < 2:
        return {}

    transitions: Dict[int, Dict[int, int]] = {}
    totals: Dict[int, int] = {}

    for i in range(len(raw) - 1):
        b1, b2 = raw[i], raw[i + 1]
        if b1 not in transitions:
            transitions[b1] = {}
            totals[b1] = 0
        transitions[b1][b2] = transitions[b1].get(b2, 0) + 1
        totals[b1] += 1

    matrix: Dict[int, Dict[int, float]] = {}
    for b1, dests in transitions.items():
        matrix[b1] = {}
        tot = totals[b1]
        for b2, cnt in dests.items():
            matrix[b1][b2] = round(cnt / tot, 6)

    return matrix


def calculate_transition_entropy(payload: Union[str, bytes]) -> float:
    """Calculate conditional Markov transition entropy H(X_t | X_{t-1}) in bits.

    H(X_t | X_{t-1}) = - sum_{i} P(i) * sum_{j} P(j | i) * log2 P(j | i)
    High transition entropy indicates random, encrypted, or packed shellcode bytes.
    Low transition entropy indicates structured text, repeated NOP patterns, or code.
    """
    raw = to_bytes(payload)
    if len(raw) < 2:
        return 0.0

    # Unigram probabilities P(i)
    unigram_counts: Dict[int, int] = {}
    for b in raw[:-1]:
        unigram_counts[b] = unigram_counts.get(b, 0) + 1
    total_unigrams = len(raw) - 1

    matrix = build_markov_transition_matrix(raw)
    cond_entropy = 0.0

    for b1, trans in matrix.items():
        p_b1 = unigram_counts[b1] / total_unigrams
        row_entropy = 0.0
        for b2, p_trans in trans.items():
            if p_trans > 0.0:
                row_entropy -= p_trans * math.log2(p_trans)
        cond_entropy += p_b1 * row_entropy

    return round(cond_entropy, 4)


def calculate_kl_divergence(
    payload: Union[str, bytes],
    baseline: Optional[Dict[int, float]] = None,
) -> float:
    """Calculate Kullback-Leibler divergence D_KL(P || Q) in bits against baseline.

    P = observed byte distribution of payload
    Q = expected standard baseline distribution
    D_KL = sum_i P(i) * log2( P(i) / Q(i) )
    """
    raw = to_bytes(payload)
    if not raw:
        return 0.0

    base_dist = baseline or _BASELINE_DISTRIBUTION

    counts: Dict[int, int] = {}
    for b in raw:
        counts[b] = counts.get(b, 0) + 1
    total = len(raw)

    kl = 0.0
    for b in range(256):
        if b in counts:
            p_i = counts[b] / total
            q_i = base_dist.get(b, 1e-6)
            if p_i > 0.0 and q_i > 0.0:
                kl += p_i * math.log2(p_i / q_i)

    return round(max(0.0, kl), 4)


# ---------------------------------------------------------------------------
# 2. Locality-Sensitive Hashing (SimHash & MinHash)
# ---------------------------------------------------------------------------

def _hash64(token: str) -> int:
    """Deterministic 64-bit integer hash for tokens using MD5."""
    digest = hashlib.md5(token.encode("utf-8")).digest()
    # Take first 8 bytes as 64-bit unsigned integer
    return int.from_bytes(digest[:8], byteorder="big", signed=False)


def compute_simhash(payload: Union[str, bytes], hash_bits: int = 64) -> int:
    """Compute 64-bit SimHash locality-sensitive fingerprint.

    Breaks payload into overlapping 3-character shingles and creates a bit-vector
    where near-identical payloads produce minimal Hamming distances.
    """
    raw = to_bytes(payload)
    if not raw:
        return 0

    # Extract overlapping trigrams
    shingles: Dict[str, int] = {}
    n = 3
    if len(raw) < n:
        shingles[raw.hex()] = 1
    else:
        for i in range(len(raw) - n + 1):
            shingle = raw[i:i + n].hex()
            shingles[shingle] = shingles.get(shingle, 0) + 1

    # Initialize v accumulator vector
    v = [0] * hash_bits

    for shingle, weight in shingles.items():
        h = _hash64(shingle)
        for i in range(hash_bits):
            bit = (h >> i) & 1
            if bit == 1:
                v[i] += weight
            else:
                v[i] -= weight

    fingerprint = 0
    for i in range(hash_bits):
        if v[i] > 0:
            fingerprint |= (1 << i)

    return fingerprint


def simhash_hex(simhash: int) -> str:
    """Format 64-bit SimHash as 16-character lowercase hex string."""
    return f"{simhash:016x}"


def calculate_hamming_distance(hash1: int, hash2: int) -> int:
    """Calculate the Hamming distance (differing bits) between two integer hashes."""
    return bin(hash1 ^ hash2).count("1")


def calculate_simhash_similarity(hash1: int, hash2: int, hash_bits: int = 64) -> float:
    """Calculate normalized similarity [0.0, 1.0] from SimHash Hamming distance."""
    dist = calculate_hamming_distance(hash1, hash2)
    return round(max(0.0, 1.0 - (dist / hash_bits)), 4)


# Deterministic parameters for universal hashing in MinHash
# h_i(x) = (a_i * x + b_i) % _PRIME
_PRIME = 4294967311  # 2^32 - 5 (large 32-bit prime)
_UNIVERSAL_A = [
    (1103515245 * (i + 1) + 12345) % (_PRIME - 1) + 1 for i in range(128)
]
_UNIVERSAL_B = [
    (214013 * (i + 1) + 2531011) % _PRIME for i in range(128)
]


def compute_minhash(payload: Union[str, bytes], num_perm: int = 64) -> List[int]:
    """Compute MinHash signature array using universal hash permutations.

    Enables high-speed Jaccard similarity estimation without storing raw payloads.
    """
    raw = to_bytes(payload)
    if not raw:
        return [0] * num_perm

    # Extract 3-byte shingles
    n = 3
    shingle_hashes: Set[int] = set()
    if len(raw) < n:
        shingle_hashes.add(_hash64(raw.hex()) & 0xFFFFFFFF)
    else:
        for i in range(len(raw) - n + 1):
            shingle_hashes.add(_hash64(raw[i:i + n].hex()) & 0xFFFFFFFF)

    num_perm = min(num_perm, 128)
    signatures = [0xFFFFFFFF] * num_perm

    for sh_val in shingle_hashes:
        for i in range(num_perm):
            a = _UNIVERSAL_A[i]
            b = _UNIVERSAL_B[i]
            val = (a * sh_val + b) % _PRIME
            if val < signatures[i]:
                signatures[i] = val

    return signatures


def estimate_jaccard_similarity(sig1: Sequence[int], sig2: Sequence[int]) -> float:
    """Estimate Jaccard set similarity between two MinHash signatures."""
    if not sig1 or not sig2 or len(sig1) != len(sig2):
        return 0.0

    matches = sum(1 for a, b in zip(sig1, sig2) if a == b)
    return round(matches / len(sig1), 4)


def cluster_payloads(
    payloads: Sequence[Union[str, bytes]],
    similarity_threshold: float = 0.85,
) -> List[Dict[str, Any]]:
    """Group near-duplicate payloads into threat family clusters via SimHash."""
    clusters: List[Dict[str, Any]] = []

    for idx, p in enumerate(payloads):
        p_str = p if isinstance(p, str) else p.decode("latin1", errors="replace")
        sh = compute_simhash(p)
        matched_cluster = None

        for c in clusters:
            rep_sh = c["representative_simhash"]
            sim = calculate_simhash_similarity(sh, rep_sh)
            if sim >= similarity_threshold:
                matched_cluster = c
                break

        if matched_cluster is not None:
            matched_cluster["items"].append({
                "index": idx,
                "payload": p_str[:120],
                "simhash": simhash_hex(sh),
            })
            matched_cluster["size"] += 1
        else:
            clusters.append({
                "cluster_id": len(clusters) + 1,
                "representative_simhash": sh,
                "representative_hex": simhash_hex(sh),
                "size": 1,
                "items": [{
                    "index": idx,
                    "payload": p_str[:120],
                    "simhash": simhash_hex(sh),
                }],
            })

    return clusters


# ---------------------------------------------------------------------------
# 3. Shellcode & Binary Injection Heuristics
# ---------------------------------------------------------------------------

def detect_shellcode_heuristics(payload: Union[str, bytes]) -> Dict[str, Any]:
    """Analyze payload for x86/x64 shellcode signatures, NOP sleds, and decoder stubs."""
    raw = to_bytes(payload)
    indicators: List[str] = []
    score = 0.0

    if not raw:
        return {
            "score": 0.0,
            "is_probable_shellcode": False,
            "indicators": [],
            "nop_sled_detected": False,
            "getpc_detected": False,
            "syscall_detected": False,
        }

    # 1. NOP Sled Detection (\x90 sequence)
    # Check for >= 8 consecutive standard NOPs
    nop_matches = re.findall(b"\x90{8,}", raw)
    has_nop_sled = False
    if nop_matches:
        has_nop_sled = True
        max_nop_len = max(len(m) for m in nop_matches)
        indicators.append(f"Standard x86 NOP sled (0x90 x {max_nop_len})")
        score += min(0.4, 0.1 + 0.05 * (max_nop_len // 8))

    # Multi-byte or polymorphic NOP equivalents (inc/dec register sequences)
    poly_nop = re.findall(b"[\x40-\x4f]{8,}", raw)
    if poly_nop:
        has_nop_sled = True
        indicators.append("x86 32-bit polymorphic single-byte slide (INC/DEC series)")
        score += 0.3

    # 2. GetPC (Get Program Counter) EIP/RIP relative call/pop patterns
    # \xe8\x00\x00\x00\x00\x58 (call 0; pop eax)
    # \xd9\xee\xd9\x74\x24\xf4 (fldz; fnstenv [esp-0xc])
    has_getpc = False
    if re.search(b"\xe8\x00\x00\x00\x00[\x58-\x5f]", raw):
        has_getpc = True
        indicators.append("x86 Call/Pop GetPC routine (call $+5; pop reg)")
        score += 0.4
    if b"\xd9\xee" in raw or b"\xd9\x74\x24" in raw:
        has_getpc = True
        indicators.append("x87 FPU fnstenv/fstenv GetPC exploit pattern")
        score += 0.45

    # 3. System Call & Software Interrupt Patterns
    has_syscall = False
    if b"\x0f\x05" in raw:
        has_syscall = True
        indicators.append("x86_64 SYSCALL instruction opcode (0x0F 0x05)")
        score += 0.35
    if b"\xcd\x80" in raw:
        has_syscall = True
        indicators.append("Linux x86 int 0x80 syscall interrupt (0xCD 0x80)")
        score += 0.35
    if b"\xcd\x2e" in raw or b"\x0f\x34" in raw:
        has_syscall = True
        indicators.append("Windows native KiFastSystemCall/sysenter (0x0F 0x34 or 0xCD 0x2E)")
        score += 0.35

    # 4. XOR Decoder Stub Loop Pattern
    # \x31... or \x30... or \x83\xf... with loop (\xe2) or jnz (\x75)
    if re.search(b"[\x30-\x33][\xc0-\xff].{1,16}[\x75\xe2]", raw):
        indicators.append("Self-decrypting XOR loop stub with conditional branch")
        score += 0.3

    # 5. Non-printable byte density
    non_printable = sum(1 for b in raw if b < 32 or b > 126)
    non_printable_ratio = non_printable / len(raw) if len(raw) > 0 else 0.0
    if non_printable_ratio > 0.45 and len(raw) >= 32:
        indicators.append(f"High non-printable byte density ({non_printable_ratio:.1%})")
        score += 0.2

    # Clamp score to [0.0, 1.0]
    total_score = round(min(1.0, score), 4)

    return {
        "score": total_score,
        "is_probable_shellcode": total_score >= 0.5,
        "is_shellcode_likely": total_score >= 0.5,
        "indicators": indicators,
        "nop_sled_detected": has_nop_sled,
        "getpc_detected": has_getpc,
        "syscall_detected": has_syscall,
        "non_printable_ratio": round(non_printable_ratio, 4),
    }


# ---------------------------------------------------------------------------
# 4. Unified Markov & LSH Analysis Report
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class MarkovLSHReport:
    """Complete Markov Transition, LSH Fingerprinting, and Shellcode Analysis."""
    payload_length: int
    transition_entropy: float
    kl_divergence: float
    simhash: str
    simhash_int: int
    minhash_signature: List[int]
    shellcode_score: float
    is_probable_shellcode: bool
    is_anomalous_markov: bool
    shellcode_indicators: List[str]
    top_bigrams: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_length": self.payload_length,
            "transition_entropy": self.transition_entropy,
            "conditional_entropy": self.transition_entropy,
            "kl_divergence": self.kl_divergence,
            "kl_divergence_natural": self.kl_divergence,
            "simhash": self.simhash,
            "simhash_hex": self.simhash,
            "simhash_int": self.simhash_int,
            "minhash_signature": self.minhash_signature,
            "shellcode_score": self.shellcode_score,
            "is_probable_shellcode": self.is_probable_shellcode,
            "is_shellcode_likely": self.is_probable_shellcode,
            "is_anomalous_markov": self.is_anomalous_markov,
            "shellcode_indicators": self.shellcode_indicators,
            "top_bigrams": self.top_bigrams,
            "top_ngrams": self.top_bigrams,
        }


def analyze_markov_lsh_profile(payload: Union[str, bytes]) -> MarkovLSHReport:
    """Run full Markov, LSH fingerprint, and shellcode heuristic analysis."""
    raw = to_bytes(payload)
    trans_entropy = calculate_transition_entropy(raw)
    kl_div = calculate_kl_divergence(raw)
    sh_int = compute_simhash(raw)
    sh_hex = simhash_hex(sh_int)
    minhash_sig = compute_minhash(raw, num_perm=32)
    shell_res = detect_shellcode_heuristics(raw)

    # Anomaly condition: either high transition entropy (> 5.5 bits) or high KL divergence (> 4.5 bits)
    is_anomalous = trans_entropy > 5.5 or kl_div > 4.5

    all_bigrams = calculate_ngram_frequencies(raw, n=2)
    # Sort top 8 bigrams
    top_bigrams = dict(sorted(all_bigrams.items(), key=lambda x: x[1], reverse=True)[:8])

    return MarkovLSHReport(
        payload_length=len(raw),
        transition_entropy=trans_entropy,
        kl_divergence=kl_div,
        simhash=sh_hex,
        simhash_int=sh_int,
        minhash_signature=minhash_sig,
        shellcode_score=shell_res["score"],
        is_probable_shellcode=shell_res["is_probable_shellcode"],
        is_anomalous_markov=is_anomalous,
        shellcode_indicators=shell_res["indicators"],
        top_bigrams=top_bigrams,
    )
