"""Tests for the --ask round trip.

No network: every provider is stubbed. What matters here is that only redacted
text is handed to a provider, that the reply is restored, and that a refusal or
a missing SDK produces a clear error rather than a traceback.
"""

from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

import pytest

import decon.ask as ask_mod
from decon.ask import AskError, ask
from decon.cli import main


@pytest.fixture
def stub_provider(monkeypatch):
    """Replace the claude provider and capture what was sent to it."""
    sent = {}

    def _install(reply="ok"):
        def fake(prompt, model, max_tokens, **kwargs):
            sent["prompt"] = prompt
            sent["model"] = model
            sent["max_tokens"] = max_tokens
            sent.update(kwargs)
            return reply

        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", fake)
        return sent

    return _install


class TestAskFunction:
    def test_unknown_provider_is_rejected(self):
        with pytest.raises(AskError, match="unknown provider"):
            ask("q", "doc", provider="bogus")

    def test_non_string_provider_is_rejected(self):
        with pytest.raises(AskError, match="unknown provider"):
            ask("q", "doc", provider=[])

    def test_empty_question_is_rejected(self):
        with pytest.raises(AskError, match="must not be empty"):
            ask("   ", "doc", provider="claude")

    @pytest.mark.parametrize(
        ("argument", "value", "message"),
        [
            ("question", None, "question must be a string"),
            ("document", None, "document must be a string"),
            ("model", "", "model must be a non-empty string"),
            ("host", "", "host must be a non-empty string"),
        ],
    )
    def test_invalid_string_arguments_are_rejected(
        self, argument, value, message
    ):
        kwargs = {"question": "q", "document": "doc", argument: value}
        with pytest.raises(AskError, match=message):
            ask(**kwargs)

    @pytest.mark.parametrize("value", [0, -1, True, 1.5])
    def test_invalid_max_tokens_is_rejected(self, value):
        with pytest.raises(AskError, match="positive integer"):
            ask("q", "doc", provider="claude", max_tokens=value)

    def test_default_model_is_used(self, stub_provider):
        sent = stub_provider()
        ask("q", "doc", provider="claude")
        assert sent["model"] == ask_mod.DEFAULT_MODELS["claude"]

    def test_explicit_model_overrides_default(self, stub_provider):
        sent = stub_provider()
        ask("q", "doc", provider="claude", model="claude-sonnet-5")
        assert sent["model"] == "claude-sonnet-5"

    def test_prompt_contains_question_and_document(self, stub_provider):
        sent = stub_provider()
        ask("What next?", "[HOST_REDACTED_0001] is up", provider="claude")
        assert "What next?" in sent["prompt"]
        assert "[HOST_REDACTED_0001] is up" in sent["prompt"]

    def test_empty_document_sends_bare_question(self, stub_provider):
        sent = stub_provider()
        ask("What next?", "", provider="claude")
        assert sent["prompt"] == "What next?"

    def test_missing_sdk_explains_how_to_install(self, monkeypatch):
        monkeypatch.setattr(
            ask_mod, "_require", lambda *a, **k: (_ for _ in ()).throw(
                AskError("provider requires the 'anthropic' package. Install it with: x")
            ),
        )
        with pytest.raises(AskError, match="anthropic"):
            ask("q", "doc", provider="claude")


class TestClaudeProvider:
    def _client(self, *, stop_reason="end_turn", text="an answer"):
        message = SimpleNamespace(
            stop_reason=stop_reason,
            stop_details=SimpleNamespace(category="cyber"),
            content=[SimpleNamespace(type="text", text=text)],
        )

        class Stream:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *exc):
                return False

            def get_final_message(self_inner):
                return message

        client = SimpleNamespace(
            beta=SimpleNamespace(
                messages=SimpleNamespace(stream=lambda **kwargs: Stream())
            )
        )
        return client

    def _module(self, client):
        return SimpleNamespace(
            Anthropic=lambda: client,
            APIStatusError=type("APIStatusError", (Exception,), {}),
            APIConnectionError=type("APIConnectionError", (Exception,), {}),
        )

    def test_returns_text(self, monkeypatch):
        module = self._module(self._client())
        monkeypatch.setattr(ask_mod, "_require", lambda *a, **k: module)
        assert ask_mod._ask_claude("p", "claude-opus-5", 100) == "an answer"

    # A refusal is HTTP 200 with empty/partial content, so it must be checked
    # before reading content — security material can trip cyber classifiers.
    def test_refusal_raises_with_category(self, monkeypatch):
        module = self._module(self._client(stop_reason="refusal", text=""))
        monkeypatch.setattr(ask_mod, "_require", lambda *a, **k: module)
        with pytest.raises(AskError, match="declined.*cyber"):
            ask_mod._ask_claude("p", "claude-opus-5", 100)

    def test_empty_response_raises(self, monkeypatch):
        module = self._module(self._client(text="   "))
        monkeypatch.setattr(ask_mod, "_require", lambda *a, **k: module)
        with pytest.raises(AskError, match="empty response"):
            ask_mod._ask_claude("p", "claude-opus-5", 100)


class TestOpenAIProvider:
    def test_disables_response_storage(self, monkeypatch):
        sent = {}
        response = SimpleNamespace(output_text="an answer")
        client = SimpleNamespace(
            responses=SimpleNamespace(
                create=lambda **kwargs: sent.update(kwargs) or response
            )
        )
        module = SimpleNamespace(
            OpenAI=lambda: client,
            APIStatusError=type("APIStatusError", (Exception,), {}),
            APIConnectionError=type("APIConnectionError", (Exception,), {}),
        )
        monkeypatch.setattr(ask_mod, "_require", lambda *a, **k: module)

        assert ask_mod._ask_openai("p", "gpt-5", 100) == "an answer"
        assert sent["store"] is False


class TestAskCli:
    SOURCE = (
        "Host dc01.corp.local at 10.4.12.50 with CORP\\jsmith "
        "and password is `hunter2!`\n"
    )
    SECRETS = ["dc01.corp.local", "10.4.12.50", "jsmith", "hunter2!"]

    # The invariant the whole feature exists to preserve.
    def test_no_real_value_reaches_the_provider(
        self, stub_provider, monkeypatch, capsys
    ):
        sent = stub_provider("Nothing to report.")
        monkeypatch.setattr("sys.stdin", StringIO(self.SOURCE))
        assert main(["--ask", "What next?"]) == 0
        capsys.readouterr()
        for secret in self.SECRETS:
            assert secret not in sent["prompt"]

    def test_real_values_in_question_are_redacted_and_restored(
        self, stub_provider, monkeypatch, capsys
    ):
        sent = stub_provider("Investigate [IPV4_REDACTED_0002].")
        monkeypatch.setattr("sys.stdin", StringIO(self.SOURCE))

        assert main(["--ask", "What about 10.99.0.7?"]) == 0
        captured = capsys.readouterr()

        assert "10.99.0.7" not in sent["prompt"]
        assert "[IPV4_REDACTED_0002]" in sent["prompt"]
        assert "10.99.0.7" in captured.out

    def test_llm_findings_are_auto_redacted_before_ask(
        self, stub_provider, monkeypatch, capsys
    ):
        sent = stub_provider("ok")
        monkeypatch.setattr(
            "sys.stdin",
            StringIO("Project Nighthawk is the target\n"),
        )
        monkeypatch.setattr(
            "decon.cli.llm_review",
            lambda text, model, host, quiet: (
                "FOUND: Project Nighthawk"
                if "Project Nighthawk" in text
                else "CLEAN"
            ),
        )

        assert main(["--ask", "Summarize", "--llm"]) == 0
        captured = capsys.readouterr()

        assert "Project Nighthawk" not in sent["prompt"]
        assert "[CUSTOM_REDACTED_" in sent["prompt"]
        assert "auto-redacted" in captured.err

    def test_question_review_findings_are_reapplied_to_document(
        self, stub_provider, monkeypatch, capsys
    ):
        sent = stub_provider("ok")
        monkeypatch.setattr(
            "sys.stdin",
            StringIO("Project Nighthawk is the target\n"),
        )
        reviews = iter(["CLEAN", "FOUND: Project Nighthawk"])
        monkeypatch.setattr(
            "decon.cli.llm_review",
            lambda text, model, host, quiet: next(reviews),
        )

        assert main(["--ask", "Summarize", "--llm"]) == 0
        capsys.readouterr()

        assert "Project Nighthawk" not in sent["prompt"]
        assert "[CUSTOM_REDACTED_" in sent["prompt"]

    def test_answer_is_restored_to_real_values(
        self, stub_provider, monkeypatch, capsys
    ):
        stub_provider("Pivot from [HOST_REDACTED_0001] at [IPV4_REDACTED_0001].")
        monkeypatch.setattr("sys.stdin", StringIO(self.SOURCE))
        assert main(["--ask", "What next?"]) == 0
        out = capsys.readouterr().out
        assert "dc01.corp.local" in out
        assert "10.4.12.50" in out
        assert out.endswith("\n")

    def test_provider_error_exits_nonzero(self, monkeypatch, capsys):
        def boom(*a, **k):
            raise AskError("could not reach the Claude API")

        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", boom)
        monkeypatch.setattr("sys.stdin", StringIO(self.SOURCE))
        assert main(["--ask", "q"]) == 1
        assert "could not reach" in capsys.readouterr().err

    def test_empty_prompt_is_rejected(self, capsys):
        assert main(["--ask", "  "]) == 1
        assert "non-empty prompt" in capsys.readouterr().err

    @pytest.mark.parametrize("flag", [["--provider", "ollama"], ["--model", "x"]])
    def test_provider_options_require_ask(self, flag, capsys):
        assert main(flag) == 1
        assert "require --ask" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "flag", ["--dry-run", "--check", "--diff"]
    )
    def test_conflicting_modes_are_rejected(self, flag, capsys):
        assert main(["--ask", "q", flag]) == 1
        assert "cannot be used with" in capsys.readouterr().err

    def test_provider_flag_selects_provider(self, monkeypatch, capsys):
        seen = {}

        def fake(prompt, model, max_tokens, **kwargs):
            seen["called"] = True
            return "ok"

        monkeypatch.setitem(ask_mod._PROVIDERS, "ollama", fake)
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--ask", "q", "--provider", "ollama"]) == 0
        capsys.readouterr()
        assert seen["called"]

    def test_ask_still_records_audit(self, stub_provider, monkeypatch, capsys):
        from decon.audit import audit_path

        stub_provider("ok")
        monkeypatch.setattr("sys.stdin", StringIO(self.SOURCE))
        main(["--ask", "q"])
        capsys.readouterr()
        assert audit_path().exists()


class TestProviderModelPairing:
    """A model named in config belongs to the provider configured with it."""

    def _config(self, tmp_path, monkeypatch, body):
        path = tmp_path / "decon.toml"
        path.write_text(body)
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", path)

    def _capture(self, monkeypatch, provider):
        seen = {}

        def fake(prompt, model, max_tokens, **kwargs):
            seen["model"] = model
            return "ok"

        monkeypatch.setitem(ask_mod._PROVIDERS, provider, fake)
        return seen

    def test_cli_provider_override_ignores_configured_model(
        self, tmp_path, monkeypatch, capsys
    ):
        self._config(
            tmp_path, monkeypatch,
            '[ask]\nprovider = "claude"\nmodel = "claude-opus-5"\n',
        )
        seen = self._capture(monkeypatch, "ollama")
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--ask", "q", "--provider", "ollama"]) == 0
        capsys.readouterr()
        assert seen["model"] == ask_mod.DEFAULT_MODELS["ollama"]

    def test_configured_model_is_used_for_its_own_provider(
        self, tmp_path, monkeypatch, capsys
    ):
        self._config(
            tmp_path, monkeypatch,
            '[ask]\nprovider = "claude"\nmodel = "claude-sonnet-5"\n',
        )
        seen = self._capture(monkeypatch, "claude")
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--ask", "q"]) == 0
        capsys.readouterr()
        assert seen["model"] == "claude-sonnet-5"

    def test_explicit_model_flag_always_wins(self, tmp_path, monkeypatch, capsys):
        self._config(
            tmp_path, monkeypatch,
            '[ask]\nprovider = "claude"\nmodel = "claude-opus-5"\n',
        )
        seen = self._capture(monkeypatch, "ollama")
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--ask", "q", "--provider", "ollama", "--model", "llama3"]) == 0
        capsys.readouterr()
        assert seen["model"] == "llama3"


class TestSizeGuard:
    def test_small_input_is_not_flagged(self):
        assert ask_mod.size_warning("short document") is None

    def test_large_input_is_flagged(self):
        warning = ask_mod.size_warning("x" * 60_000)
        assert warning is not None
        assert "60,000 characters" in warning

    def test_threshold_is_configurable(self):
        assert ask_mod.size_warning("x" * 300, warn_chars=200) is not None
        assert ask_mod.size_warning("x" * 300, warn_chars=1000) is None

    def test_zero_disables_the_guard(self):
        assert ask_mod.size_warning("x" * 10_000, warn_chars=0) is None

    def test_cli_warns_before_sending(self, tmp_path, monkeypatch, capsys):
        config = tmp_path / "decon.toml"
        config.write_text("[ask]\nwarn_chars = 100\n")
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", config)
        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", lambda *a, **k: "ok")
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n" * 40))
        assert main(["--ask", "q"]) == 0
        assert "may exceed the model's context window" in capsys.readouterr().err


class TestPerProviderModels:
    def _config(self, tmp_path, monkeypatch, body):
        path = tmp_path / "decon.toml"
        path.write_text(body)
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", path)

    def _capture(self, monkeypatch, provider):
        seen = {}
        monkeypatch.setitem(
            ask_mod._PROVIDERS,
            provider,
            lambda prompt, model, max_tokens, **k: (
                seen.__setitem__("model", model),
                "ok",
            )[1],
        )
        return seen

    BODY = (
        "[ask]\n"
        'provider = "claude"\n'
        "[ask.models]\n"
        'claude = "claude-opus-5"\n'
        'ollama = "qwen3.5:9b"\n'
    )

    def test_each_provider_gets_its_own_model(
        self, tmp_path, monkeypatch, capsys
    ):
        self._config(tmp_path, monkeypatch, self.BODY)
        seen = self._capture(monkeypatch, "ollama")
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--ask", "q", "--provider", "ollama"]) == 0
        capsys.readouterr()
        assert seen["model"] == "qwen3.5:9b"

    def test_default_provider_uses_its_entry(self, tmp_path, monkeypatch, capsys):
        self._config(tmp_path, monkeypatch, self.BODY)
        seen = self._capture(monkeypatch, "claude")
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))
        assert main(["--ask", "q"]) == 0
        capsys.readouterr()
        assert seen["model"] == "claude-opus-5"
