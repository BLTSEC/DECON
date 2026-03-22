"""Tests for config loading and profile resolution."""

import tempfile
import os
from pathlib import Path

from decon.config import (
    ConfigError,
    apply_config_to_engine,
    load_config,
    resolve_profile,
)
from decon.engine import RedactionEngine


class TestLoadConfig:
    def test_missing_file(self):
        config = load_config(Path("/nonexistent/path/decon.toml"))
        assert config == {}

    def test_valid_toml(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".toml", delete=False
        ) as f:
            f.write('[rules]\nipv4 = false\n\n[llm]\nenabled = true\n')
            path = f.name
        try:
            config = load_config(Path(path))
            assert config["rules"]["ipv4"] is False
            assert config["llm"]["enabled"] is True
        finally:
            os.unlink(path)

    def test_invalid_toml_raises_config_error(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".toml", delete=False
        ) as f:
            f.write("[rules\nipv4 = true\n")
            path = f.name
        try:
            try:
                load_config(Path(path))
                assert False, "Expected ConfigError"
            except ConfigError:
                pass
        finally:
            os.unlink(path)


class TestResolveProfile:
    def test_standard_default(self):
        config = {"rules": {"ipv4": True, "mac": False}}
        result = resolve_profile(config)
        assert result == {"ipv4": True, "mac": False}

    def test_profile_override(self):
        config = {
            "rules": {"ipv4": True, "mac": True},
            "profiles": {"internal": {"ipv4": False}},
        }
        result = resolve_profile(config, "internal")
        assert result["ipv4"] is False
        assert result["mac"] is True


class TestApplyConfig:
    def test_disable_rule_via_config(self):
        config = {"rules": {"mac": False}}
        engine = RedactionEngine()
        apply_config_to_engine(engine, config)

        result = engine.redact("mac aa:bb:cc:dd:ee:ff here")
        assert "aa:bb:cc:dd:ee:ff" in result  # not redacted

    def test_custom_values(self):
        config = {"custom": {"values": ["SecretProject"]}}
        engine = RedactionEngine()
        apply_config_to_engine(engine, config)

        result = engine.redact("Working on SecretProject today")
        assert "SecretProject" not in result

    def test_custom_patterns(self):
        config = {
            "custom": {
                "patterns": [
                    {
                        "name": "test_domain",
                        "pattern": r"[a-z]+\.test\.local",
                        "replacement": "HOST_{n:02d}.example.internal",
                    }
                ]
            }
        }
        engine = RedactionEngine()
        apply_config_to_engine(engine, config)

        result = engine.redact("connect to db.test.local")
        assert "db.test.local" not in result

    def test_invalid_custom_pattern_raises_config_error(self):
        config = {
            "custom": {
                "patterns": [
                    {
                        "name": "broken",
                        "pattern": r"[unterminated",
                    }
                ]
            }
        }
        engine = RedactionEngine()
        try:
            apply_config_to_engine(engine, config)
            assert False, "Expected ConfigError"
        except ConfigError:
            pass
