"""Pytest fixtures shared across the DECON test suite."""

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_default_config_path(monkeypatch, tmp_path):
    """Prevent developer-local ~/.config settings from affecting tests."""
    monkeypatch.setattr(
        "decon.config.DEFAULT_CONFIG_PATH",
        Path(tmp_path) / "decon.toml",
    )
