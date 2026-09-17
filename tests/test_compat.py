"""Tests for cross-platform compatibility utilities."""

import pytest
from payload_entropy_studio.compat import (
    normalize_path,
    ensure_dir,
    safe_join,
    atomic_write_bytes,
    atomic_write_text,
    safe_read_bytes,
    safe_read_text,
    get_default_storage_dir,
)


def test_normalize_path():
    p = normalize_path(".")
    assert p.is_absolute()


def test_ensure_dir(tmp_path):
    d = ensure_dir(tmp_path / "payloads" / "reports")
    assert d.is_dir()


def test_safe_join(tmp_path):
    valid = safe_join(tmp_path, "sub", "report.json")
    assert valid.name == "report.json"

    with pytest.raises(PermissionError):
        safe_join(tmp_path, "../outside.json")


def test_atomic_write_and_read(tmp_path):
    target = tmp_path / "sample.txt"
    atomic_write_text(target, "attack payload")
    assert target.exists()
    assert safe_read_text(target) == "attack payload"


def test_get_default_storage_dir():
    d = get_default_storage_dir()
    assert d.is_dir()
