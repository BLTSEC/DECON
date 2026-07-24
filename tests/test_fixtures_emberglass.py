"""Contract tests against the synthetic Operation Emberglass notes.

These assert the property that actually matters: no sensitive value survives,
and the analytical content that makes redacted output useful does. See
tests/fixtures/emberglass/README.md for provenance.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from decon.config import apply_config_to_engine
from decon.engine import RedactionEngine

FIXTURES = Path(__file__).parent / "fixtures" / "emberglass"
EXPECTATIONS = json.loads((FIXTURES / "expectations.json").read_text())
NOTES = sorted(FIXTURES.glob("*.md"))
# README.md documents the fixtures; it is not engagement material.
NOTES = [p for p in NOTES if p.name != "README.md"]

# Bare identifiers that no generic rule can anchor on. Declaring them is the
# operator's job; this mirrors a realistic engagement config.
ENGAGEMENT_CONFIG = {
    "custom": {
        "hostnames": ["DC01", "PORTAL", "FILES01"],
        "usernames": ["svc_archive", "analyst.demo"],
        "shares": ["SYSVOL", "NETLOGON"],
    }
}


def _corpus() -> str:
    return "\n".join(p.read_text() for p in NOTES)


def _engine(config: dict | None = None) -> RedactionEngine:
    engine = RedactionEngine()
    if config:
        apply_config_to_engine(engine, config)
    return engine


class TestEmberglassContract:
    def test_fixtures_are_present(self):
        assert len(NOTES) == 7

    # The core promise. Runs with NO custom config, so it also proves the
    # built-in rules alone handle everything in must_remove.
    @pytest.mark.parametrize("secret", EXPECTATIONS["must_remove"])
    def test_sensitive_value_does_not_survive(self, secret):
        assert secret not in _engine().redact(_corpus())

    # Redaction has to leave something behind worth reading.
    @pytest.mark.parametrize("keeper", EXPECTATIONS["must_preserve"])
    def test_analytical_content_survives(self, keeper):
        assert keeper in _engine().redact(_corpus())

    # Repeated values must keep one identity, or topology is lost.
    @pytest.mark.parametrize("value", EXPECTATIONS["repeated_values"])
    def test_repeated_value_maps_to_one_placeholder(self, value):
        engine = _engine(ENGAGEMENT_CONFIG)
        redacted = engine.redact(_corpus())
        placeholders = {
            placeholder
            for original, placeholder in engine.mapping.items()
            if original.casefold() == value.casefold()
        }
        assert len(placeholders) == 1, f"{value} split across {placeholders}"
        assert value not in redacted

    def test_round_trip_restores_the_corpus(self):
        engine = _engine()
        text = _corpus()
        assert engine.unredact(engine.redact(text)) == text

    def test_redaction_is_idempotent(self):
        engine = _engine(ENGAGEMENT_CONFIG)
        once = engine.redact(_corpus())
        assert engine.redact(once) == once


class TestEmberglassWithEngagementConfig:
    """Typed targets close the bare-identifier gap without a --redact crutch."""

    @pytest.mark.parametrize("token", ["svc_archive", "PORTAL", "FILES01"])
    def test_bare_identifiers_are_redacted(self, token):
        redacted = _engine(ENGAGEMENT_CONFIG).redact(_corpus())
        assert token not in redacted

    def test_no_must_remove_value_survives(self):
        redacted = _engine(ENGAGEMENT_CONFIG).redact(_corpus())
        leaked = [v for v in EXPECTATIONS["must_remove"] if v in redacted]
        assert leaked == []

    def test_no_must_preserve_value_is_lost(self):
        redacted = _engine(ENGAGEMENT_CONFIG).redact(_corpus())
        lost = [v for v in EXPECTATIONS["must_preserve"] if v not in redacted]
        assert lost == []
