"""Tests for CLI interface."""

import sys
from io import StringIO
from decon.cli import main


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
        import json
        with open(map_path) as f:
            data = json.load(f)
        assert "10.4.12.50" in data["mapping"]
