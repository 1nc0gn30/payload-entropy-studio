"""Tests for CLI subcommands."""

import pytest
from payload_entropy_studio.cli import main


def test_cli_help(capsys):
    ret = main([])
    assert ret == 0
    out = capsys.readouterr().out
    assert "payload-entropy" in out

    with pytest.raises(SystemExit):
        main(["--help"])


def test_cli_analyze(capsys):
    ret = main(["analyze", "<script>alert(1)</script>"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "XSS" in out


def test_cli_analyze_json(capsys):
    ret = main(["analyze", "1' OR '1'='1", "--json"])
    assert ret == 0
    out = capsys.readouterr().out
    assert '"primary_threat": "SQL_INJECTION"' in out


def test_cli_deobfuscate(capsys):
    ret = main(["deobfuscate", "%252e%252e%252fetc/passwd"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "../etc/passwd" in out


def test_cli_entropy(capsys):
    ret = main(["entropy", "ABCDEF1234567890"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "Shannon Entropy" in out


def test_cli_waf(capsys):
    ret = main(["waf", "<script>alert(1)</script>"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "MODSECURITY" in out


def test_cli_doctor(capsys):
    ret = main(["doctor"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "HEALTHY" in out


def test_cli_test_self(capsys):
    ret = main(["test-self"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "All internal checks passed" in out
