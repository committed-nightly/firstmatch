from __future__ import annotations

from pathlib import Path

import pytest

from firstmatch.oracle import Oracle, ssh_path

needs_ssh = pytest.mark.skipif(ssh_path() is None, reason="no ssh on PATH")


@pytest.fixture
def write_config(tmp_path: Path):
    """Write a config and hand back its path."""

    def _write(text: str, name: str = "config") -> Path:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    return _write


@pytest.fixture
def oracle():
    if ssh_path() is None:
        pytest.skip("no ssh on PATH")
    return Oracle()
