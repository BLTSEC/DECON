"""Tests for the public function API.

These pin the contract a script depends on: the mapping direction, the
round-trip, and the fact that a provider only ever receives redacted text.
"""

from __future__ import annotations

import pytest

import decon
import decon.ask as ask_mod
from decon import ask_safely, build_engine, desanitize, sanitize
from decon.config import ConfigError, load_targets

TARGETS = """\
# Engagement identifiers
domain:acme.com
netbios:ACME
username:jsmith
hostname:DC01
share:SYSVOL
"""


@pytest.fixture
def targets_file(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text(TARGETS)
    return path


class TestPublicSurface:
    def test_functions_are_exported(self):
        assert callable(decon.sanitize)
        assert callable(decon.desanitize)
        assert callable(decon.ask_safely)

    def test_version_is_exported(self):
        assert decon.__version__

    # Two places declare the version, and the pre-commit example in the README
    # pins a tag that has to match. Keep them from drifting.
    def test_version_matches_pyproject(self):
        import tomllib
        from pathlib import Path

        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        declared = tomllib.loads(pyproject.read_text())["project"]["version"]
        assert declared == decon.__version__


class TestSanitize:
    def test_returns_text_and_mapping(self):
        clean, mapping = sanitize("Host dc01.corp.local", use_config=False)
        assert "dc01.corp.local" not in clean
        assert mapping

    # The mapping is placeholder -> original, the inverse of engine.mapping.
    # Getting this backwards makes desanitize() a silent no-op.
    def test_mapping_is_keyed_by_placeholder(self):
        clean, mapping = sanitize("Host dc01.corp.local", use_config=False)
        assert "dc01.corp.local" in mapping.values()
        assert "dc01.corp.local" not in mapping
        for placeholder in mapping:
            assert placeholder in clean

    def test_round_trip_is_lossless(self):
        original = "Host dc01.corp.local at 10.4.12.50 with CORP\\jsmith\n"
        clean, mapping = sanitize(original, use_config=False)
        assert desanitize(clean, mapping) == original

    def test_empty_input(self):
        clean, mapping = sanitize("", use_config=False)
        assert clean == ""
        assert mapping == {}

    def test_clean_input_maps_nothing(self):
        clean, mapping = sanitize("nothing sensitive here", use_config=False)
        assert clean == "nothing sensitive here"
        assert mapping == {}


class TestDesanitize:
    def test_restores_values(self):
        assert desanitize("see [X_1]", {"[X_1]": "real"}) == "see real"

    def test_empty_mapping_is_identity(self):
        assert desanitize("unchanged", {}) == "unchanged"

    # A placeholder that is a prefix of another must not be partially replaced.
    def test_longest_placeholder_wins(self):
        mapping = {"[H_1]": "short", "[H_10]": "long"}
        assert desanitize("[H_10]", mapping) == "long"

    @pytest.mark.parametrize(
        "mapping",
        [
            {"": "real"},
            {"[X_1]": ""},
            {1: "real"},
            {"[X_1]": 1},
            [],
        ],
    )
    def test_invalid_mapping_is_rejected(self, mapping):
        with pytest.raises(ValueError, match="mapping must contain"):
            desanitize("text", mapping)

    def test_non_string_text_is_rejected(self):
        with pytest.raises(TypeError, match="text must be a string"):
            desanitize(None, {})


class TestKnownTargets:
    def test_each_category_is_applied(self, targets_file):
        text = "ACME host DC01 share SYSVOL user jsmith at acme.com"
        clean, _ = sanitize(text, targets_file, use_config=False)
        for value in ("ACME", "DC01", "SYSVOL", "jsmith", "acme.com"):
            assert value not in clean

    def test_missing_file_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="does not exist"):
            sanitize("text", tmp_path / "absent.txt", use_config=False)

    def test_comments_and_blank_lines_ignored(self, tmp_path):
        path = tmp_path / "t.txt"
        path.write_text("# a comment\n\n   \nhostname:DC01\n")
        assert load_targets(path)["hostname"] == ["DC01"]

    # Silently skipping a bad category would leave the value unredacted, which
    # is the worst failure mode for a sanitizer.
    def test_unknown_category_is_rejected(self, tmp_path):
        path = tmp_path / "t.txt"
        path.write_text("hostnames:DC01\n")
        with pytest.raises(ConfigError, match="unknown category"):
            load_targets(path)

    def test_malformed_line_is_rejected(self, tmp_path):
        path = tmp_path / "t.txt"
        path.write_text("DC01\n")
        with pytest.raises(ConfigError, match="expected 'category:value'"):
            load_targets(path)

    def test_error_names_the_line_number(self, tmp_path):
        path = tmp_path / "t.txt"
        path.write_text("hostname:DC01\nbogus:x\n")
        with pytest.raises(ConfigError, match=":2:"):
            load_targets(path)


class TestQueryCloudSafe:
    SOURCE = "Pivot from dc01.corp.local at 10.4.12.50 using CORP\\jsmith"

    def test_provider_never_sees_a_real_value(self, monkeypatch):
        sent = {}

        def fake(prompt, model, max_tokens, **kwargs):
            sent["prompt"] = prompt
            return "Nothing found."

        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", fake)
        ask_safely(self.SOURCE, use_config=False, audit=False)
        for secret in ("dc01.corp.local", "10.4.12.50", "jsmith"):
            assert secret not in sent["prompt"]

    def test_response_is_restored(self, monkeypatch):
        monkeypatch.setitem(
            ask_mod._PROVIDERS,
            "claude",
            lambda *a, **k: "Start at [HOST_REDACTED_0001].",
        )
        answer, mapping = ask_safely(
            self.SOURCE, use_config=False, audit=False
        )
        assert "dc01.corp.local" in answer
        assert mapping

    def test_provider_is_selectable(self, monkeypatch):
        seen = {}
        monkeypatch.setitem(
            ask_mod._PROVIDERS,
            "ollama",
            lambda *a, **k: seen.setdefault("called", True) and "ok",
        )
        ask_safely(
            self.SOURCE, provider="ollama", use_config=False, audit=False
        )
        assert seen["called"]

    def test_unknown_provider_raises(self):
        with pytest.raises(decon.AskError, match="unknown provider"):
            ask_safely(self.SOURCE, provider="nope", use_config=False)

    def test_audit_can_be_disabled(self, monkeypatch):
        from decon.audit import audit_path

        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", lambda *a, **k: "ok")
        ask_safely(self.SOURCE, use_config=False, audit=False)
        assert not audit_path().exists()

    def test_audit_records_the_query(self, monkeypatch):
        from decon.audit import audit_path

        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", lambda *a, **k: "ok")
        ask_safely(self.SOURCE, use_config=False, audit=True)
        assert "ask_safely" in audit_path().read_text()

    def test_audit_config_can_disable_library_logging(
        self, tmp_path, monkeypatch
    ):
        from decon.audit import audit_path

        config = tmp_path / "decon.toml"
        config.write_text("[audit]\nenabled = false\n")
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", config)
        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", lambda *a, **k: "ok")

        ask_safely(self.SOURCE)

        assert not audit_path().exists()

    def test_audit_config_path_is_used_by_library(self, tmp_path, monkeypatch):
        configured_log = tmp_path / "configured.audit.jsonl"
        config = tmp_path / "decon.toml"
        config.write_text(f'[audit]\npath = "{configured_log}"\n')
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", config)
        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", lambda *a, **k: "ok")

        ask_safely(self.SOURCE)

        assert configured_log.exists()


class TestBuildEngine:
    def test_returns_a_usable_engine(self):
        engine = build_engine(use_config=False)
        assert "dc01.corp.local" not in engine.redact("host dc01.corp.local")

    def test_targets_file_rules_are_registered(self, targets_file):
        engine = build_engine(targets_file, use_config=False)
        assert "DC01" not in engine.redact("the DC01 box")
