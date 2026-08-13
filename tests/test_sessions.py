"""Named-session, audit-history, and restoration coverage."""

from __future__ import annotations

import json
import os
import stat
from io import StringIO

import pytest

from decon.audit import audit_path
from decon.cli import main
from decon.engine import RedactionEngine
from decon.state import session_path

# ---------------------------------------------------------------------------
# Named sessions (--session / --restore)
# ---------------------------------------------------------------------------


class TestSessions:
    def test_session_round_trip_via_cli(self, monkeypatch, capsys):
        original = "Server 10.4.12.50 and host dc01.corp.local\n"
        monkeypatch.setattr("sys.stdin", StringIO(original))
        assert main(["--session"]) == 0
        redacted = capsys.readouterr().out
        assert "10.4.12.50" not in redacted

        monkeypatch.setattr("sys.stdin", StringIO(redacted))
        assert main(["--restore"]) == 0
        assert capsys.readouterr().out == original

    def test_named_sessions_are_independent(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host alpha.corp.local\n"))
        assert main(["--session", "alpha"]) == 0
        first = capsys.readouterr().out

        monkeypatch.setattr("sys.stdin", StringIO("host bravo.corp.local\n"))
        assert main(["--session", "bravo"]) == 0
        capsys.readouterr()

        monkeypatch.setattr("sys.stdin", StringIO(first))
        assert main(["--restore", "alpha"]) == 0
        assert "alpha.corp.local" in capsys.readouterr().out

    def test_list_sessions(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        main(["--session", "engagement"])
        capsys.readouterr()
        assert main(["--list-sessions"]) == 0
        assert "engagement" in capsys.readouterr().out

    def test_unknown_session_exits_nonzero(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("text\n"))
        assert main(["--restore", "nope"]) == 1
        assert "no saved session" in capsys.readouterr().err

    # argparse gives --session an optional value, so it will swallow a
    # following filename. That must be an error, not a session named scan.txt.
    def test_session_swallowing_a_filename_is_rejected(self, tmp_path, capsys):
        target = tmp_path / "scan.txt"
        target.write_text("host dc01.corp.local\n")
        assert main(["--session", str(target)]) == 1
        assert "consumed" in capsys.readouterr().err

    @pytest.mark.parametrize("name", ["../escape", "a/b", ""])
    def test_invalid_session_names_are_rejected(self, name, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("text\n"))
        assert main(["--session", name]) == 1
        assert "session name" in capsys.readouterr().err

    def test_session_file_is_owner_only(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        main(["--session", "perms"])
        capsys.readouterr()
        path = session_path("perms")
        assert path.exists()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700

    def test_session_ttl_is_stored_as_metadata(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--session", "short", "--session-ttl", "30m"]) == 0
        capsys.readouterr()

        metadata = json.loads(session_path("short").read_text())["session"]
        assert set(metadata) == {"created_at", "expires_at"}
        assert metadata["expires_at"] > metadata["created_at"]

    def test_expired_session_is_removed_and_cannot_restore(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--session", "expired"]) == 0
        redacted = capsys.readouterr().out

        path = session_path("expired")
        data = json.loads(path.read_text())
        data["session"] = {
            "created_at": "2020-01-01T00:00:00+00:00",
            "expires_at": "2020-01-01T00:01:00+00:00",
        }
        path.write_text(json.dumps(data))

        monkeypatch.setattr("sys.stdin", StringIO(redacted))
        assert main(["--restore", "expired"]) == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "expired and was removed" in captured.err
        assert not path.exists()

    def test_list_sessions_prunes_expired_maps(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--session", "stale"]) == 0
        capsys.readouterr()

        path = session_path("stale")
        data = json.loads(path.read_text())
        data["session"] = {
            "created_at": "2020-01-01T00:00:00+00:00",
            "expires_at": "2020-01-02T00:00:00+00:00",
        }
        path.write_text(json.dumps(data))

        assert main(["--list-sessions"]) == 0
        captured = capsys.readouterr()
        assert "stale" not in captured.out
        assert "Removed 1 expired session" in captured.err
        assert not path.exists()

    def test_consume_deletes_session_after_successful_restore(
        self, monkeypatch, capsys
    ):
        original = "host dc01.corp.local\n"
        monkeypatch.setattr("sys.stdin", StringIO(original))
        assert main(["--session", "once"]) == 0
        redacted = capsys.readouterr().out

        monkeypatch.setattr("sys.stdin", StringIO(redacted))
        assert main(["--restore", "once", "--consume"]) == 0
        captured = capsys.readouterr()
        assert captured.out == original
        assert "Consumed session 'once'" in captured.err
        assert not session_path("once").exists()

    def test_failed_output_does_not_consume_session(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--session", "retry"]) == 0
        redacted = capsys.readouterr().out

        monkeypatch.setattr("sys.stdin", StringIO(redacted))
        monkeypatch.setattr("decon.cli._write_output", lambda *args, **kwargs: False)
        assert main(["--restore", "retry", "--consume"]) == 1
        assert session_path("retry").exists()

    @pytest.mark.parametrize(
        "args, message",
        [
            (["--session-ttl", "1h"], "requires --session"),
            (["--session", "bad", "--session-ttl", "soon"], "session TTL"),
            (["--session", "bad", "--session-ttl", "0h"], "session TTL"),
            (["--consume"], "requires --restore"),
            (["--unredact", "map.json", "--consume"], "requires --restore"),
        ],
    )
    def test_session_lifecycle_flags_are_validated(self, args, message, capsys):
        assert main(args) == 1
        assert message in capsys.readouterr().err

    def test_invalid_session_metadata_fails_closed(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--session", "damaged"]) == 0
        redacted = capsys.readouterr().out

        path = session_path("damaged")
        data = json.loads(path.read_text())
        data["session"]["expires_at"] = "not-a-time"
        path.write_text(json.dumps(data))

        monkeypatch.setattr("sys.stdin", StringIO(redacted))
        assert main(["--restore", "damaged"]) == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "invalid timestamps" in captured.err
        assert path.exists()

    def test_pre_metadata_session_remains_restorable(self, monkeypatch, capsys):
        engine = RedactionEngine()
        redacted = engine.redact("host dc01.corp.local\n")
        engine.export_map(str(session_path("legacy")))

        monkeypatch.setattr("sys.stdin", StringIO(redacted))
        assert main(["--restore", "legacy"]) == 0
        assert capsys.readouterr().out == "host dc01.corp.local\n"

    def test_restore_is_mutually_exclusive_with_diff(self, capsys):
        assert main(["--restore", "--diff"]) == 1
        assert "mutually exclusive" in capsys.readouterr().err

    def test_session_and_restore_together_is_rejected(self, capsys):
        assert main(["--session", "--restore"]) == 1
        assert "cannot be used together" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class TestAuditLog:
    def _entries(self):
        path = audit_path()
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line]

    def test_records_substitutions_by_default(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main([]) == 0
        capsys.readouterr()

        entries = self._entries()
        assert len(entries) == 1
        assert entries[0]["mode"] == "redact"
        subs = entries[0]["substitutions"]
        assert any(s["original"] == "dc01.corp.local" for s in subs)
        assert all({"category", "original", "placeholder"} <= s.keys() for s in subs)

    def test_appends_one_line_per_run(self, monkeypatch, capsys):
        for host in ("dc01.corp.local", "dc02.corp.local"):
            monkeypatch.setattr("sys.stdin", StringIO(f"host {host}\n"))
            main([])
            capsys.readouterr()
        assert len(self._entries()) == 2

    def test_clean_input_writes_nothing(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("nothing sensitive here\n"))
        assert main([]) == 0
        capsys.readouterr()
        assert self._entries() == []

    def test_no_audit_flag_suppresses_the_log(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--no-audit"]) == 0
        capsys.readouterr()
        assert self._entries() == []

    def test_log_is_owner_only(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        main([])
        capsys.readouterr()
        path = audit_path()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700

    # A broken audit log must never cost the operator their sanitized output.
    def test_unwritable_log_warns_but_still_redacts(self, monkeypatch, capsys):
        monkeypatch.setenv("DECON_STATE_DIR", "/dev/null/cannot-exist")
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main([]) == 0
        captured = capsys.readouterr()
        assert "[HOST_REDACTED_0001]" in captured.out
        assert "dc01.corp.local" not in captured.out
        assert "audit log" in captured.err

    # --check is the documented CI mode. Writing every real value to disk on
    # each pre-commit run would be a surprise, and it discloses nothing.
    @pytest.mark.parametrize("flag", ["--check", "--dry-run", "--diff"])
    def test_detection_modes_do_not_write_the_log(self, flag, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        main([flag])
        capsys.readouterr()
        assert self._entries() == []

    # A configured path may live in a directory the user manages; DECON must
    # not silently chmod it, though the log file itself stays 0600.
    def test_configured_path_does_not_chmod_the_users_directory(
        self, tmp_path, monkeypatch, capsys
    ):
        notes = tmp_path / "notes"
        notes.mkdir(mode=0o755)
        os.chmod(notes, 0o755)
        log = notes / "audit.jsonl"

        config = tmp_path / "decon.toml"
        config.write_text(f'[audit]\npath = "{log}"\n')
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", config)

        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main([]) == 0
        capsys.readouterr()

        assert stat.S_IMODE(notes.stat().st_mode) == 0o755
        assert stat.S_IMODE(log.stat().st_mode) == 0o600

    def test_existing_configured_log_is_tightened(self, tmp_path, monkeypatch, capsys):
        log = tmp_path / "audit.jsonl"
        log.write_text("")
        os.chmod(log, 0o644)
        config = tmp_path / "decon.toml"
        config.write_text(f'[audit]\npath = "{log}"\n')
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", config)

        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main([]) == 0
        capsys.readouterr()

        assert stat.S_IMODE(log.stat().st_mode) == 0o600

    def test_batch_mode_records_each_file(self, tmp_path, monkeypatch, capsys):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("host dc01.corp.local\n")
        b.write_text("host dc02.corp.local\n")
        out = tmp_path / "out"
        assert main([str(a), str(b), "--output-dir", str(out)]) == 0
        capsys.readouterr()

        entries = self._entries()
        assert len(entries) == 2
        assert {e["sources"][0] for e in entries} == {str(a), str(b)}


# ---------------------------------------------------------------------------
# Session hygiene and unresolved-placeholder warnings
# ---------------------------------------------------------------------------


class TestSessionHygiene:
    def _save(self, name, monkeypatch, capsys, text="host dc01.corp.local\n"):
        monkeypatch.setattr("sys.stdin", StringIO(text))
        main(["--session", name])
        capsys.readouterr()

    def test_forget_removes_the_reversible_map(self, monkeypatch, capsys):
        self._save("doomed", monkeypatch, capsys)
        assert session_path("doomed").exists()
        assert main(["--forget", "doomed"]) == 0
        capsys.readouterr()
        assert not session_path("doomed").exists()

    def test_forget_unknown_session_exits_nonzero(self, capsys):
        assert main(["--forget", "nope"]) == 1
        assert "no saved session" in capsys.readouterr().err

    def test_forget_all_clears_every_session(self, monkeypatch, capsys):
        for name in ("one", "two"):
            self._save(name, monkeypatch, capsys)
        assert main(["--forget-all"]) == 0
        capsys.readouterr()
        assert main(["--list-sessions"]) == 0
        assert "No saved sessions" in capsys.readouterr().err

    # Session housekeeping must not depend on a parseable config.
    def test_session_admin_survives_a_broken_config(
        self, tmp_path, monkeypatch, capsys
    ):
        broken = tmp_path / "decon.toml"
        broken.write_text("this is not = valid toml [[[\n")
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", broken)
        assert main(["--list-sessions"]) == 0

    def test_restore_survives_a_broken_config(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--session", "recovery"]) == 0
        redacted = capsys.readouterr().out

        broken = tmp_path / "decon.toml"
        broken.write_text("this is not = valid toml [[[\n")
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", broken)
        monkeypatch.setattr("sys.stdin", StringIO(redacted))

        assert main(["--restore", "recovery"]) == 0
        captured = capsys.readouterr()
        assert "dc01.corp.local" in captured.out
        assert "audit logging is disabled" in captured.err

    @pytest.mark.parametrize(
        "args",
        [
            ["--forget", "one", "--forget-all"],
            ["--list-sessions", "--forget-all"],
            ["--forget", "one", "notes.txt"],
        ],
    )
    def test_session_admin_rejects_conflicting_work(self, args, capsys):
        assert main(args) == 1
        error = capsys.readouterr().err
        assert "standalone" in error or "mutually exclusive" in error

    def test_restore_rejects_output_dir(self, capsys):
        assert main(["--restore", "last", "notes.txt", "--output-dir", "out"]) == 1
        assert "--output-dir cannot be used" in capsys.readouterr().err


class TestUnresolvedPlaceholders:
    def test_reformatted_placeholder_is_reported(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        main(["--session"])
        capsys.readouterr()

        # A model reply that restores one placeholder, mangles one, invents one.
        reply = "Check [HOST_REDACTED_0001], [HOST_REDACTED_1], [IPV4_REDACTED_0099].\n"
        monkeypatch.setattr("sys.stdin", StringIO(reply))
        assert main(["--restore"]) == 0
        captured = capsys.readouterr()

        assert "dc01.corp.local" in captured.out
        assert "2 placeholder(s) had no mapping" in captured.err
        assert "[HOST_REDACTED_1]" in captured.err
        assert "[IPV4_REDACTED_0099]" in captured.err

    def test_no_warning_when_everything_resolves(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        main(["--session"])
        redacted = capsys.readouterr().out

        monkeypatch.setattr("sys.stdin", StringIO(redacted))
        assert main(["--restore"]) == 0
        assert "had no mapping" not in capsys.readouterr().err

    def test_quiet_suppresses_the_warning(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        main(["--session"])
        capsys.readouterr()
        monkeypatch.setattr("sys.stdin", StringIO("[HOST_REDACTED_0099]\n"))
        assert main(["--restore", "--quiet"]) == 0
        assert "had no mapping" not in capsys.readouterr().err


class TestReverseAuditing:
    def test_restore_is_recorded(self, monkeypatch, capsys):
        from decon.audit import audit_path

        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        main(["--session"])
        redacted = capsys.readouterr().out

        monkeypatch.setattr("sys.stdin", StringIO(redacted))
        main(["--restore"])
        capsys.readouterr()

        modes = [
            json.loads(line)["mode"]
            for line in audit_path().read_text().splitlines()
            if line
        ]
        assert modes == ["redact", "restore"]
