"""Tests for output helpers."""

from __future__ import annotations

import subprocess

from decon.output import capture_tmux_pane, read_clipboard, write_clipboard


class TestQuietMode:
    def test_write_clipboard_quiet_suppresses_stderr(self, monkeypatch, capsys):
        def fake_run(*args, **kwargs):
            raise FileNotFoundError

        monkeypatch.setattr(subprocess, "run", fake_run)

        assert write_clipboard("hello", quiet=True) is False
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_read_clipboard_quiet_suppresses_stderr(self, monkeypatch, capsys):
        def fake_run(*args, **kwargs):
            raise FileNotFoundError

        monkeypatch.setattr(subprocess, "run", fake_run)

        assert read_clipboard(quiet=True) is None
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_capture_tmux_quiet_suppresses_stderr(self, monkeypatch, capsys):
        def fake_run(*args, **kwargs):
            raise FileNotFoundError

        monkeypatch.setattr(subprocess, "run", fake_run)

        assert capture_tmux_pane(quiet=True) is None
        captured = capsys.readouterr()
        assert captured.err == ""
