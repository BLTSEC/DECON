"""Tests for config loading and profile resolution."""

import os
import tempfile
from pathlib import Path

import pytest

from decon.config import (
    ConfigError,
    apply_config_to_engine,
    init_config,
    load_config,
    resolve_profile,
)
from decon.engine import RedactionEngine


class TestLoadConfig:
    def test_missing_file(self):
        config = load_config(Path("/nonexistent/path/decon.toml"))
        assert config == {}

    def test_valid_toml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("[rules]\nipv4 = false\n\n[llm]\nenabled = true\n")
            path = f.name
        try:
            config = load_config(Path(path))
            assert config["rules"]["ipv4"] is False
            assert config["llm"]["enabled"] is True
        finally:
            os.unlink(path)

    def test_init_config_is_owner_only(self, tmp_path, monkeypatch):
        path = tmp_path / "config" / "decon.toml"
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", path)
        assert init_config() == path
        assert os.stat(path).st_mode & 0o777 == 0o600

    def test_invalid_toml_raises_config_error(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
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

    def test_default_profile_applies_custom_values_extra(self):
        config = {
            "default_profile": "client-share",
            "profiles": {"client-share": {"custom_values_extra": ["Nighthawk"]}},
        }
        engine = RedactionEngine()
        apply_config_to_engine(engine, config)
        assert "Nighthawk" not in engine.redact("Project Nighthawk")

    def test_unknown_profile_is_rejected(self):
        engine = RedactionEngine()
        try:
            apply_config_to_engine(engine, {}, "typo")
            assert False, "Expected ConfigError"
        except ConfigError as e:
            assert "Unknown profile" in str(e)

    @pytest.mark.parametrize(
        ("config", "message"),
        [
            ({"rules": {"ipv4": "false"}}, "must be true or false"),
            ({"rules": {"ipvv4": False}}, "Unknown rule"),
            ({"custom": {"values": "secret"}}, "array of strings"),
            ({"custom": {"allowlist": [""]}}, "non-empty strings"),
            ({"custom": {"target_domains": [1]}}, "non-empty strings"),
            ({"custom": {"hostnames": "DC01"}}, "array of strings"),
            ({"custom": {"usernames": [""]}}, "non-empty strings"),
            ({"custom": {"netbios": [1]}}, "non-empty strings"),
            ({"custom": {"shares": [None]}}, "non-empty strings"),
            ({"llm": {"enabled": "yes"}}, "llm.enabled"),
            ({"llm": {"required": "yes"}}, "llm.required"),
            ({"llm": {"host": ""}}, "llm.host"),
            ({"audit": {"enabled": "yes"}}, "audit.enabled"),
            ({"audit": {"path": ""}}, "audit.path"),
            ({"ask": {"provider": "gemini"}}, "ask.provider"),
            ({"ask": {"models": "claude"}}, "ask.models must be a table"),
            ({"ask": {"models": {"gemini": "x"}}}, "Unknown provider"),
            ({"ask": {"models": {"claude": ""}}}, "ask.models.claude"),
            ({"ask": {"max_tokens": 0.5}}, "ask.max_tokens"),
            ({"ask": {"max_tokens": 0}}, "positive integer"),
            ({"ask": {"warn_chars": -1}}, "ask.warn_chars"),
            ({"ask": {"cli": "isolated"}}, "ask.cli must be a table"),
            ({"ask": {"cli": {"mode": "unsafe"}}}, "ask.cli.mode"),
            (
                {"ask": {"cli": {"timeout_seconds": True}}},
                "ask.cli.timeout_seconds",
            ),
            (
                {"ask": {"cli": {"timeout_seconds": 0}}},
                "positive integer",
            ),
        ],
    )
    def test_invalid_config_types_are_rejected(self, config, message):
        with pytest.raises(ConfigError, match=message):
            apply_config_to_engine(RedactionEngine(), config)

    @pytest.mark.parametrize("provider", ["codex", "claude-code"])
    def test_cli_ask_providers_are_valid(self, provider):
        apply_config_to_engine(
            RedactionEngine(),
            {
                "ask": {
                    "provider": provider,
                    "models": {provider: "explicit-model"},
                    "cli": {"mode": "isolated", "timeout_seconds": 30},
                }
            },
        )

    def test_custom_pattern_must_not_match_empty_text(self):
        config = {"custom": {"patterns": [{"pattern": r"x*"}]}}
        with pytest.raises(ConfigError, match="must not match empty text"):
            apply_config_to_engine(RedactionEngine(), config)

    def test_custom_pattern_replacement_is_validated(self):
        config = {
            "custom": {
                "patterns": [
                    {"pattern": r"secret", "replacement": "[CUSTOM_{missing}]"}
                ]
            }
        }
        with pytest.raises(ConfigError, match="Invalid replacement"):
            apply_config_to_engine(RedactionEngine(), config)

    def test_custom_pattern_replacement_must_vary(self):
        config = {
            "custom": {
                "patterns": [{"pattern": r"secret", "replacement": "[CUSTOM_REDACTED]"}]
            }
        }
        with pytest.raises(ConfigError, match="Invalid replacement"):
            apply_config_to_engine(RedactionEngine(), config)


class TestAllRulesSwitch:
    """`all` states intent once instead of a deny-list that drifts."""

    def test_all_false_disables_every_builtin(self):
        engine = RedactionEngine()
        apply_config_to_engine(engine, {"profiles": {"ctf": {"all": False}}}, "ctf")
        assert [r.name for r in engine.rules if r.enabled] == []

    def test_all_true_enables_every_builtin(self):
        engine = RedactionEngine()
        apply_config_to_engine(
            engine, {"rules": {"ipv4": False}, "profiles": {"x": {"all": True}}}, "x"
        )
        assert all(r.enabled for r in engine.rules)

    # Per-rule keys must win over the blanket, so it stays a starting point.
    def test_per_rule_overrides_win(self):
        engine = RedactionEngine()
        apply_config_to_engine(
            engine, {"profiles": {"x": {"all": False, "ipv4": True}}}, "x"
        )
        assert [r.name for r in engine.rules if r.enabled] == ["ipv4"]

    def test_works_in_the_global_rules_table(self):
        engine = RedactionEngine()
        apply_config_to_engine(engine, {"rules": {"all": False}})
        assert [r.name for r in engine.rules if r.enabled] == []

    # Values under [custom] are explicit instructions, not built-in guesses.
    def test_custom_values_survive_all_false(self):
        engine = RedactionEngine()
        apply_config_to_engine(
            engine,
            {
                "profiles": {"ctf": {"all": False}},
                "custom": {"values_nocase": ["bltsec"]},
            },
            "ctf",
        )
        assert "bltsec" not in engine.redact("user bltsec here")

    def test_non_boolean_all_is_rejected(self):
        with pytest.raises(ConfigError, match="true or false"):
            apply_config_to_engine(
                RedactionEngine(), {"profiles": {"y": {"all": "yes"}}}, "y"
            )
