"""Tests for CLI interface."""

import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from decon.cli import main, _prompt_llm_review
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
        assert "10.0.0.1" in captured.out

    def test_dry_run(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("Server 10.4.12.50\n"))
        ret = main(["--dry-run"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "10.4.12.50" in captured.err
        assert "10.0.0.1" in captured.err

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
            "castelblack.north.sevenkingdoms.local -> HOST_01.example.internal"
            in captured.err
        )
        assert "CASTELBLACK -> HOST_01" in captured.err

    def test_disable_flag(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        ret = main(["--disable", "ipv4"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "10.4.12.50" in captured.out

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
        assert (output_dir / "a" / "scan.redacted.txt").read_text().strip() == "10.0.0.1"
        assert (output_dir / "b" / "scan.redacted.txt").read_text().strip() == "10.0.0.2"

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
        assert "10.0.0.1" not in captured.out

    def test_clipboard_failure_does_not_fallback_to_stdin(
        self, monkeypatch, capsys
    ):
        monkeypatch.setattr("decon.cli.read_clipboard", lambda quiet=False: None)
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        ret = main(["--clipboard-in"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "10.0.0.1" not in captured.out


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
