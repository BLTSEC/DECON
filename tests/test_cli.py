"""Tests for CLI interface."""

import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from decon.cli import main, _prompt_llm_review
from decon.engine import RedactionEngine
from decon.llm import parse_findings


class TestCLIBasic:
    def test_version(self, capsys):
        try:
            main(["--version"])
        except SystemExit:
            pass
        captured = capsys.readouterr()
        assert "decon" in captured.out

    def test_list_rules(self, capsys):
        ret = main(["--list-rules"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "ipv4" in captured.out
        assert "email" in captured.out

    def test_stdin_redaction(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("Server 10.4.12.50 is up\n"))
        ret = main([])
        assert ret == 0
        captured = capsys.readouterr()
        assert "10.4.12.50" not in captured.out
        assert "[IPV4_REDACTED_0001]" in captured.out

    def test_dry_run(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("Server 10.4.12.50\n"))
        ret = main(["--dry-run"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "10.4.12.50" in captured.err
        assert "[IPV4_REDACTED_0001]" in captured.err

    def test_dry_run_shows_short_rdns_alias_with_matching_host_index(
        self, monkeypatch, capsys
    ):
        monkeypatch.setattr(
            "sys.stdin",
            StringIO(
                "Nmap scan report for castelblack.north.sevenkingdoms.local (10.1.10.22)\n"
                "rDNS record for 10.1.10.22: CASTELBLACK\n"
            ),
        )
        ret = main(["--dry-run"])
        assert ret == 0
        captured = capsys.readouterr()
        assert (
            "castelblack.north.sevenkingdoms.local -> [HOST_REDACTED_0001]"
            in captured.err
        )
        assert "CASTELBLACK -> [HOST_SHORT_REDACTED_0001]" in captured.err

    def test_disable_flag(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        ret = main(["--disable", "ipv4"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "10.4.12.50" in captured.out

    def test_redact_custom_values(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "sys.stdin",
            StringIO("The password is Heartsbane and user is jon.snow\n"),
        )
        ret = main(["--redact", "Heartsbane,jon.snow"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Heartsbane" not in captured.out
        assert "jon.snow" not in captured.out
        assert "[CUSTOM_REDACTED_0001]" in captured.out

    def test_redact_case_insensitive(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "sys.stdin",
            StringIO("Found HEARTSBANE in the config\n"),
        )
        ret = main(["--redact", "Heartsbane"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "HEARTSBANE" not in captured.out

    def test_verbose(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50 admin@test.com\n"))
        ret = main(["-v"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Redaction stats:" in captured.err

    def test_file_input(self, tmp_path, capsys):
        f = tmp_path / "test.log"
        f.write_text("Server 192.168.1.1 running\n")
        ret = main([str(f)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "192.168.1.1" not in captured.out

    def test_invalid_utf8_file_reports_clean_error(self, tmp_path, capsys):
        path = tmp_path / "binary.log"
        path.write_bytes(b"valid prefix\xffinvalid")
        assert main([str(path)]) == 1
        captured = capsys.readouterr()
        assert "Error reading" in captured.err
        assert "Traceback" not in captured.err

    def test_unknown_rule(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("test\n"))
        ret = main(["--disable", "fakrule"])
        assert ret == 1

    def test_export_map(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        map_path = str(tmp_path / "map.json")
        ret = main(["--export-map", map_path])
        assert ret == 0
        with open(map_path) as f:
            data = json.load(f)
        assert "10.4.12.50" in data["mapping"]

    def test_check_with_imported_map_detects_existing_replacements(
        self, tmp_path, monkeypatch, capsys
    ):
        map_path = tmp_path / "map.json"
        map_path.write_text(
            json.dumps(
                {
                    "mapping": {"10.4.12.50": "10.0.0.1"},
                    "counters": {"ipv4": 1},
                }
            )
        )
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        ret = main(["--import-map", str(map_path), "--check"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Found 1 value(s) to redact" in captured.err

    def test_dry_run_with_imported_map_lists_replacements(
        self, tmp_path, monkeypatch, capsys
    ):
        map_path = tmp_path / "map.json"
        map_path.write_text(
            json.dumps(
                {
                    "mapping": {"10.4.12.50": "10.0.0.1"},
                    "counters": {"ipv4": 1},
                }
            )
        )
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        ret = main(["--import-map", str(map_path), "--dry-run"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "10.4.12.50 -> 10.0.0.1" in captured.err

    def test_output_dir_preserves_unique_paths(self, tmp_path, capsys):
        first = tmp_path / "a" / "scan.txt"
        second = tmp_path / "b" / "scan.txt"
        first.parent.mkdir()
        second.parent.mkdir()
        first.write_text("10.1.1.1\n")
        second.write_text("10.2.2.2\n")
        output_dir = tmp_path / "clean"

        ret = main(
            [str(first), str(second), "--output-dir", str(output_dir), "--quiet"]
        )

        assert ret == 0
        assert (output_dir / "a" / "scan.redacted.txt").exists()
        assert (output_dir / "b" / "scan.redacted.txt").exists()
        assert (output_dir / "a" / "scan.redacted.txt").read_text().strip() == "[IPV4_REDACTED_0001]"
        assert (output_dir / "b" / "scan.redacted.txt").read_text().strip() == "[IPV4_REDACTED_0002]"

    def test_invalid_config_reports_clean_error(self, tmp_path, monkeypatch, capsys):
        config_path = tmp_path / "decon.toml"
        config_path.write_text("[rules\nipv4 = true\n")
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", config_path)
        ret = main([])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Invalid TOML in config" in captured.err

    def test_tmux_failure_does_not_fallback_to_stdin(
        self, monkeypatch, capsys
    ):
        monkeypatch.setattr("decon.cli.capture_tmux_pane", lambda quiet=False: None)
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        ret = main(["--tmux"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "[IPV4_REDACTED_0001]" not in captured.out

    def test_clipboard_failure_does_not_fallback_to_stdin(
        self, monkeypatch, capsys
    ):
        monkeypatch.setattr("decon.cli.read_clipboard", lambda quiet=False: None)
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        ret = main(["--clipboard-in"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "[IPV4_REDACTED_0001]" not in captured.out


class TestParseFindings:
    def test_extracts_values(self):
        response = "FOUND: jimmy.johns\nFOUND: DC01\n"
        assert parse_findings(response) == ["jimmy.johns", "DC01"]

    def test_deduplicates(self):
        response = "FOUND: DC01\nFOUND: dc01\n"
        assert parse_findings(response) == ["DC01"]

    def test_strips_quotes_and_whitespace(self):
        response = "FOUND: \"jimmy.johns\"\nFOUND:  'DC01' \n"
        assert parse_findings(response) == ["jimmy.johns", "DC01"]

    def test_skips_empty(self):
        response = "FOUND:\nFOUND: DC01\n"
        assert parse_findings(response) == ["DC01"]

    def test_normalizes_commentary(self):
        response = "FOUND: 10.1.2.3 (target IP)\n"
        assert parse_findings(response) == ["10.1.2.3"]

    def test_clean_response(self):
        assert parse_findings("CLEAN") == []

    def test_accepts_indented_bulleted_and_mixed_case_findings(self):
        response = "  - Found: first-value\n* FOUND: second-value\n"
        assert parse_findings(response) == ["first-value", "second-value"]


class TestPromptLLMReview:
    def test_select_all(self):
        tty = StringIO("all\n")
        with patch("builtins.open", return_value=tty):
            result = _prompt_llm_review(["jimmy.johns", "DC01"])
        assert result == ["jimmy.johns", "DC01"]

    def test_enter_defaults_to_all(self):
        tty = StringIO("\n")
        with patch("builtins.open", return_value=tty):
            result = _prompt_llm_review(["jimmy.johns", "DC01"])
        assert result == ["jimmy.johns", "DC01"]

    def test_select_numbers(self):
        tty = StringIO("2\n")
        with patch("builtins.open", return_value=tty):
            result = _prompt_llm_review(["jimmy.johns", "DC01"])
        assert result == ["DC01"]

    def test_select_multiple(self):
        tty = StringIO("1,2\n")
        with patch("builtins.open", return_value=tty):
            result = _prompt_llm_review(["jimmy.johns", "DC01"])
        assert result == ["jimmy.johns", "DC01"]

    def test_none_skips(self):
        tty = StringIO("none\n")
        with patch("builtins.open", return_value=tty):
            result = _prompt_llm_review(["jimmy.johns", "DC01"])
        assert result == []

    def test_tty_unavailable_defaults_to_all(self):
        with patch("builtins.open", side_effect=OSError):
            result = _prompt_llm_review(["jimmy.johns"])
        assert result == ["jimmy.johns"]


class TestLLMInteractiveFlow:
    def test_interactive_redacts_selected(self, monkeypatch, capsys):
        """When LLM flags values and user selects them, they get redacted."""
        monkeypatch.setattr(
            "sys.stdin", StringIO("Logged in as jimmy.johns on DC01\n")
        )
        monkeypatch.setattr(
            "decon.cli.llm_review",
            lambda text, model, host, quiet: "FOUND: jimmy.johns\nFOUND: DC01",
        )
        monkeypatch.setattr("sys.stderr", type("FakeTTY", (), {
            "write": sys.stderr.write,
            "flush": sys.stderr.flush,
            "isatty": lambda self: True,
        })())
        tty = StringIO("all\n")
        with patch("builtins.open", return_value=tty):
            ret = main(["--llm"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "jimmy.johns" not in captured.out
        assert "DC01" not in captured.out
        assert "REDACTED_" in captured.out

    def test_noninteractive_prints_warnings(self, monkeypatch, capsys):
        """When stderr is not a TTY, fall back to warning-only output."""
        monkeypatch.setattr(
            "sys.stdin", StringIO("Logged in as jimmy.johns on DC01\n")
        )
        monkeypatch.setattr(
            "decon.cli.llm_review",
            lambda text, model, host, quiet: "FOUND: jimmy.johns\nFOUND: DC01",
        )
        ret = main(["--llm"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "FOUND: jimmy.johns" in captured.err
        assert "jimmy.johns" in captured.out

    def test_finding_containing_clean_is_not_discarded(
        self, monkeypatch, capsys
    ):
        monkeypatch.setattr("sys.stdin", StringIO("Project CLEANROOM\n"))
        monkeypatch.setattr(
            "decon.cli.llm_review",
            lambda text, model, host, quiet: "FOUND: CLEANROOM",
        )
        ret = main(["--llm"])
        assert ret == 0
        assert "FOUND: CLEANROOM" in capsys.readouterr().err

    def test_check_fails_on_llm_only_finding(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("ordinary text\n"))
        monkeypatch.setattr(
            "decon.cli.llm_review",
            lambda text, model, host, quiet: "FOUND: overlooked-name",
        )
        assert main(["--check", "--llm"]) == 1
        captured = capsys.readouterr()
        assert "llm: 1" in captured.err
        assert captured.out == ""

    def test_dry_run_lists_llm_only_finding(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("ordinary text\n"))
        monkeypatch.setattr(
            "decon.cli.llm_review",
            lambda text, model, host, quiet: "FOUND: overlooked-name",
        )
        assert main(["--dry-run", "--llm"]) == 0
        captured = capsys.readouterr()
        assert "LLM findings:" in captured.err
        assert "overlooked-name" in captured.err
        assert captured.out == ""

    def test_diff_runs_llm_review(self, monkeypatch, capsys):
        calls = []
        monkeypatch.setattr("sys.stdin", StringIO("ordinary text\n"))
        monkeypatch.setattr(
            "decon.cli.llm_review",
            lambda text, model, host, quiet: calls.append(text) or "CLEAN",
        )
        assert main(["--diff", "--llm"]) == 0
        assert calls == ["ordinary text\n"]
        assert capsys.readouterr().out == ""

    def test_batch_runs_llm_review_for_each_file(self, tmp_path, monkeypatch):
        first = tmp_path / "first.txt"
        second = tmp_path / "second.txt"
        output = tmp_path / "redacted"
        first.write_text("first ordinary value\n")
        second.write_text("second ordinary value\n")
        calls = []
        monkeypatch.setattr(
            "decon.cli.llm_review",
            lambda text, model, host, quiet: calls.append(text) or "CLEAN",
        )
        assert main([
            str(first),
            str(second),
            "--output-dir",
            str(output),
            "--llm",
            "--quiet",
        ]) == 0
        assert calls == ["first ordinary value\n", "second ordinary value\n"]

    def test_quiet_dry_run_is_silent(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("10.1.2.3\n"))
        assert main(["--dry-run", "--quiet"]) == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""


class TestCLIFailureStatus:
    def test_export_map_failure_returns_nonzero(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        ret = main(["--export-map", "/nonexistent-parent/map.json"])
        assert ret == 1
        assert "Error writing map" in capsys.readouterr().err

    def test_imported_map_does_not_override_cli_allowlist(
        self, tmp_path, monkeypatch, capsys
    ):
        path = tmp_path / "map.json"
        path.write_text(json.dumps({
            "mapping": {"10.4.12.50": "[IPV4_REDACTED_0001]"},
            "counters": {"ipv4": 1},
        }))
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        ret = main(["--import-map", str(path), "--allow", "10.4.12.50"])
        assert ret == 0
        assert capsys.readouterr().out == "10.4.12.50\n"

    def test_allowlisted_import_can_be_reexported_and_reimported(
        self, tmp_path, monkeypatch, capsys
    ):
        imported = tmp_path / "imported.json"
        exported = tmp_path / "exported.json"
        imported.write_text(json.dumps({
            "mapping": {"10.4.12.50": "[IPV4_REDACTED_0001]"},
            "counters": {"ipv4": 1},
        }))
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        assert main([
            "--import-map",
            str(imported),
            "--allow",
            "10.4.12.50",
            "--export-map",
            str(exported),
            "--quiet",
        ]) == 0
        engine = RedactionEngine()
        engine.import_map(str(exported))
        assert engine.redact("10.4.12.50") == "10.4.12.50"
