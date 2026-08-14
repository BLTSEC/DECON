"""v0.9.1 exact-prompt confirmation regressions."""

from __future__ import annotations

import hashlib
from io import StringIO

import decon.ask as ask_mod
from decon.cli import main


class TestPreparedPromptDispatch:
    def test_prepared_prompt_reaches_provider_unchanged(self, monkeypatch):
        sent: dict[str, str] = {}

        def provider(prompt, model, max_tokens, **kwargs):
            sent["prompt"] = prompt
            return "ok"

        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", provider)
        prepared = "question\n\n---\n[HOST_REDACTED_0001]\n---"

        assert ask_mod._ask_prepared(prepared, provider="claude") == "ok"
        assert sent["prompt"] == prepared


class TestConfirmAsk:
    @staticmethod
    def _provider(monkeypatch) -> dict[str, str]:
        sent: dict[str, str] = {}

        def provider(prompt, model, max_tokens, **kwargs):
            sent["prompt"] = prompt
            return "ok"

        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", provider)
        return sent

    def test_confirm_displays_and_sends_same_prompt(self, monkeypatch, capsys):
        sent = self._provider(monkeypatch)
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        monkeypatch.setattr("decon.cli._read_ask_confirmation", lambda: "yes\n")

        assert (
            main(
                [
                    "--ask",
                    "What next?",
                    "--confirm-ask",
                    "--no-audit",
                ]
            )
            == 0
        )

        captured = capsys.readouterr()
        prepared = sent["prompt"]
        digest = hashlib.sha256(prepared.encode("utf-8")).hexdigest()
        assert "dc01.corp.local" not in prepared
        assert "[HOST_REDACTED_" in prepared
        assert prepared in captured.err
        assert f"SHA-256: {digest}" in captured.err
        assert "Confirmed." in captured.err

    def test_decline_never_contacts_provider_or_writes_audit(self, monkeypatch, capsys):
        from decon.audit import audit_path

        sent = self._provider(monkeypatch)
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        monkeypatch.setattr("decon.cli._read_ask_confirmation", lambda: "no\n")

        assert main(["--ask", "What next?", "--confirm-ask"]) == 1
        assert sent == {}
        assert not audit_path().exists()
        assert "provider was not contacted" in capsys.readouterr().err

    def test_missing_terminal_fails_without_contacting_provider(
        self, monkeypatch, capsys
    ):
        sent = self._provider(monkeypatch)
        monkeypatch.setattr("sys.stdin", StringIO("ordinary text\n"))

        def unavailable():
            raise OSError("no controlling terminal")

        monkeypatch.setattr("decon.cli._read_ask_confirmation", unavailable)

        assert (
            main(
                [
                    "--ask",
                    "What next?",
                    "--confirm-ask",
                    "--no-audit",
                ]
            )
            == 1
        )
        assert sent == {}
        assert "requires an interactive terminal" in capsys.readouterr().err

    def test_confirm_requires_ask(self, capsys):
        assert main(["--confirm-ask"]) == 1
        assert "--confirm-ask requires --ask" in capsys.readouterr().err

    def test_confirm_and_preview_are_mutually_exclusive(self, capsys):
        assert (
            main(
                [
                    "--ask",
                    "What next?",
                    "--confirm-ask",
                    "--ask-preview",
                ]
            )
            == 1
        )
        assert "cannot be used with --ask-preview" in capsys.readouterr().err
