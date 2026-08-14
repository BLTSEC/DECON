"""v0.9 hybrid classification, outbound safety, and credential regressions."""

from __future__ import annotations

import json
import time
from io import StringIO

import pytest

import decon.ask as ask_mod
from decon import AskError, ask_safely
from decon.cli import main
from decon.config import apply_config_to_engine
from decon.engine import RedactionEngine
from decon.pii import (
    PIIClassification,
    classify_pii_candidates,
    collect_pii_candidates,
)
from decon.safety import SafetyFinding

TEST_CARD = "4111 1111 1111 1111"
TEST_HASH = "0123456789abcdef0123456789abcdef"


class TestCredentialRegressions:
    def test_hashcat_nt_hash_and_plaintext_are_typed_and_reversible(self):
        source = f"{TEST_HASH}:RecoveredPass!\n"
        engine = RedactionEngine()
        redacted = engine.redact(source)

        assert redacted.startswith("NTLM_HASH_")
        assert "[SECRET_REDACTED_" in redacted
        assert TEST_HASH not in redacted
        assert "RecoveredPass!" not in redacted
        assert engine.unredact(redacted) == source

    def test_impacket_empty_lm_hash_form(self):
        result = RedactionEngine().redact(
            f"secretsdump.py corp/user@host -hashes :{TEST_HASH}\n"
        )
        assert "-hashes :NTLM_HASH_" in result
        assert TEST_HASH not in result

    def test_context_identified_nt_hash_is_replaced_everywhere(self):
        source = f"tool -hashes :{TEST_HASH} target; repeated={TEST_HASH}"
        result = RedactionEngine().redact(source)
        assert TEST_HASH not in result
        assert result.count("NTLM_HASH_01") == 2

    def test_bare_hash_is_only_enabled_by_pentest_profile(self):
        standard = RedactionEngine()
        pentest = RedactionEngine()
        apply_config_to_engine(pentest, {}, "pentest")

        assert standard.redact(TEST_HASH) == TEST_HASH
        assert pentest.redact(TEST_HASH).startswith("NTLM_HASH_")

    def test_long_unbroken_token_is_processed_linearly(self):
        started = time.perf_counter()
        RedactionEngine().redact("a" * 80_000)
        assert time.perf_counter() - started < 2.0


class TestPIICandidateClassification:
    def _candidates(self, text=TEST_CARD):
        return collect_pii_candidates(text, RedactionEngine().rules)

    def test_collects_valid_card_without_redacting(self):
        candidates = self._candidates(f"scan id {TEST_CARD}\n")
        assert [(item.rule_name, item.value) for item in candidates] == [
            ("credit_card", TEST_CARD)
        ]

    def test_allowlisted_candidate_is_not_classified(self):
        assert (
            collect_pii_candidates(
                TEST_CARD,
                RedactionEngine().rules,
                allowlist={TEST_CARD},
            )
            == []
        )

    def test_structured_keep_decision(self, monkeypatch):
        candidates = self._candidates()
        monkeypatch.setattr(
            "decon.pii._ollama_classify_request",
            lambda batch, model, host: json.dumps(
                {
                    "decisions": [
                        {"id": candidate.id, "action": "keep"} for candidate in batch
                    ]
                }
            ),
        )

        result = classify_pii_candidates(
            candidates,
            model="test",
            host="http://localhost:11434",
            quiet=True,
        )
        assert result is not None
        assert result.selections == {}
        assert result.kept == 1
        assert result.kept_values == frozenset({TEST_CARD})

    def test_conflicting_occurrences_redact_same_value_everywhere(self, monkeypatch):
        candidates = self._candidates(f"id {TEST_CARD}\npayment card {TEST_CARD}\n")

        def response(batch, model, host):
            return json.dumps(
                {
                    "decisions": [
                        {"id": batch[0].id, "action": "keep"},
                        {"id": batch[1].id, "action": "redact"},
                    ]
                }
            )

        monkeypatch.setattr("decon.pii._ollama_classify_request", response)
        result = classify_pii_candidates(
            candidates,
            model="test",
            host="http://localhost:11434",
            quiet=True,
        )
        assert result is not None
        assert result.selections == {"credit_card": {TEST_CARD}}

    def test_invalid_response_retries_once_then_falls_back(self, monkeypatch):
        calls = 0

        def invalid(batch, model, host):
            nonlocal calls
            calls += 1
            return '{"decisions": []}'

        monkeypatch.setattr("decon.pii._ollama_classify_request", invalid)
        assert (
            classify_pii_candidates(
                self._candidates(),
                model="test",
                host="http://localhost:11434",
                quiet=True,
            )
            is None
        )
        assert calls == 2

    @pytest.mark.parametrize(
        "response",
        [
            '{"decisions":[{"id":"PII_9999","action":"keep"}]}',
            '{"decisions":[{"id":"PII_0001","action":"keep"},'
            '{"id":"PII_0001","action":"redact"}]}',
            '{"decisions":[{"id":"PII_0001","action":"ignore"}]}',
        ],
    )
    def test_unknown_duplicate_and_invalid_decisions_fail_closed(
        self, response, monkeypatch
    ):
        monkeypatch.setattr(
            "decon.pii._ollama_classify_request",
            lambda *args: response,
        )
        assert (
            classify_pii_candidates(
                self._candidates(),
                model="test",
                host="http://localhost:11434",
                quiet=True,
            )
            is None
        )

    def test_nonloopback_requires_explicit_opt_in(self, monkeypatch):
        monkeypatch.setattr(
            "decon.pii._ollama_classify_request",
            lambda *args: pytest.fail("remote reviewer must not receive candidates"),
        )
        assert (
            classify_pii_candidates(
                self._candidates(),
                model="test",
                host="http://192.168.1.50:11434",
                quiet=True,
            )
            is None
        )

    def test_cli_llm_keeps_classifier_approved_telemetry(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO(f"scan id {TEST_CARD}\n"))
        monkeypatch.setattr(
            "decon.cli.classify_pii_candidates",
            lambda candidates, **kwargs: PIIClassification({}, 1, 0, 0),
        )
        monkeypatch.setattr("decon.cli.llm_review", lambda *args, **kwargs: "CLEAN")

        assert main(["--llm", "--no-audit"]) == 0
        assert TEST_CARD in capsys.readouterr().out

    def test_final_review_cannot_undo_classifier_keep(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO(f"scan id {TEST_CARD}\n"))
        monkeypatch.setattr(
            "decon.cli.classify_pii_candidates",
            lambda candidates, **kwargs: PIIClassification(
                {},
                1,
                0,
                0,
                frozenset({TEST_CARD}),
            ),
        )
        monkeypatch.setattr(
            "decon.cli.llm_review",
            lambda *args, **kwargs: f"FOUND: {TEST_CARD}",
        )

        assert main(["--llm", "--no-audit"]) == 0
        assert TEST_CARD in capsys.readouterr().out

    def test_optional_llm_failure_redacts_every_candidate(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO(f"scan id {TEST_CARD}\n"))
        monkeypatch.setattr(
            "decon.cli.classify_pii_candidates", lambda *args, **kwargs: None
        )
        monkeypatch.setattr("decon.cli.llm_review", lambda *args, **kwargs: None)

        assert main(["--llm", "--no-audit"]) == 0
        output = capsys.readouterr().out
        assert TEST_CARD not in output
        assert "CC_REDACTED_" in output

    def test_strict_llm_classification_failure_emits_nothing(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO(TEST_CARD))
        monkeypatch.setattr(
            "decon.cli.classify_pii_candidates", lambda *args, **kwargs: None
        )

        assert main(["--strict-llm", "--no-audit"]) == 1
        assert capsys.readouterr().out == ""

    def test_batch_redacts_pii_globally_when_context_decisions_disagree(
        self, tmp_path, monkeypatch
    ):
        first = tmp_path / "first.txt"
        second = tmp_path / "second.txt"
        output = tmp_path / "redacted"
        first.write_text(f"scan id {TEST_CARD}\n", encoding="utf-8")
        second.write_text(f"payment card {TEST_CARD}\n", encoding="utf-8")
        decisions = iter(
            (
                PIIClassification(
                    {},
                    1,
                    0,
                    0,
                    frozenset({TEST_CARD}),
                ),
                PIIClassification(
                    {"credit_card": {TEST_CARD}},
                    0,
                    1,
                    0,
                ),
            )
        )
        monkeypatch.setattr(
            "decon.cli.classify_pii_candidates",
            lambda candidates, **kwargs: next(decisions),
        )
        monkeypatch.setattr("decon.cli.llm_review", lambda *args, **kwargs: "CLEAN")

        assert (
            main(
                [
                    str(first),
                    str(second),
                    "--output-dir",
                    str(output),
                    "--llm",
                    "--no-audit",
                ]
            )
            == 0
        )
        for path in (output / "first.redacted.txt", output / "second.redacted.txt"):
            redacted = path.read_text(encoding="utf-8")
            assert TEST_CARD not in redacted
            assert "CC_REDACTED_" in redacted


class TestAskSafety:
    PRIVATE_KEY = (
        "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----"
    )

    def _provider(self, monkeypatch):
        sent: dict[str, str] = {}

        def fake(prompt, model, max_tokens, **kwargs):
            sent["prompt"] = prompt
            return "ok"

        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", fake)
        return sent

    def test_ask_preview_never_calls_provider(self, monkeypatch, capsys):
        from decon.audit import audit_path

        sent = self._provider(monkeypatch)
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))

        assert main(["--ask", "What next?", "--ask-preview"]) == 0
        output = capsys.readouterr().out
        assert "What next?" in output
        assert "[HOST_REDACTED_" in output
        assert sent == {}
        assert not audit_path().exists()

    def test_unsafe_preview_is_printed_but_returns_nonzero(self, monkeypatch, capsys):
        sent = self._provider(monkeypatch)
        monkeypatch.setattr("sys.stdin", StringIO(self.PRIVATE_KEY))

        assert (
            main(
                [
                    "--disable",
                    "private_key",
                    "--ask",
                    "Summarize",
                    "--ask-preview",
                    "--no-audit",
                ]
            )
            == 1
        )
        captured = capsys.readouterr()
        assert "BEGIN PRIVATE KEY" in captured.out
        assert "Preview is unsafe" in captured.err
        assert sent == {}

    def test_outbound_survivor_blocks_provider(self, monkeypatch, capsys):
        sent = self._provider(monkeypatch)
        monkeypatch.setattr("sys.stdin", StringIO(self.PRIVATE_KEY))

        assert (
            main(
                [
                    "--disable",
                    "private_key",
                    "--ask",
                    "Summarize",
                    "--no-audit",
                ]
            )
            == 1
        )
        assert sent == {}
        assert "transmission blocked" in capsys.readouterr().err

    def test_disabled_context_rule_cannot_leak_api_key(self, monkeypatch, capsys):
        sent = self._provider(monkeypatch)
        monkeypatch.setattr(
            "sys.stdin",
            StringIO("api_key=synthetic-test-key-12345"),
        )

        assert (
            main(
                [
                    "--disable",
                    "context_secret",
                    "--ask",
                    "Summarize",
                    "--no-audit",
                ]
            )
            == 1
        )
        assert sent == {}
        assert "context_credential=1" in capsys.readouterr().err

    def test_force_ask_is_explicit_bypass(self, monkeypatch, capsys):
        sent = self._provider(monkeypatch)
        monkeypatch.setattr("sys.stdin", StringIO(self.PRIVATE_KEY))

        assert (
            main(
                [
                    "--disable",
                    "private_key",
                    "--ask",
                    "Summarize",
                    "--force-ask",
                    "--no-audit",
                ]
            )
            == 0
        )
        assert "BEGIN PRIVATE KEY" in sent["prompt"]
        assert "bypassing" in capsys.readouterr().err

    def test_force_cannot_bypass_strict_llm_failure(self, monkeypatch, capsys):
        sent = self._provider(monkeypatch)
        monkeypatch.setattr("sys.stdin", StringIO(TEST_CARD))
        monkeypatch.setattr(
            "decon.cli.classify_pii_candidates", lambda *args, **kwargs: None
        )

        assert (
            main(
                [
                    "--strict-llm",
                    "--ask",
                    "Summarize",
                    "--force-ask",
                    "--no-audit",
                ]
            )
            == 1
        )
        assert sent == {}
        assert capsys.readouterr().out == ""

    def test_public_domain_warning_is_count_only(self, monkeypatch, capsys):
        sent = self._provider(monkeypatch)
        domain = "portal.corporate-example.com"
        monkeypatch.setattr("sys.stdin", StringIO(f"target {domain}\n"))

        assert main(["--ask", "Summarize", "--no-audit"]) == 0
        captured = capsys.readouterr()
        assert domain in sent["prompt"]
        assert "public_domain=1" in captured.err
        assert domain not in captured.err

    def test_ask_redacts_pii_globally_when_context_decisions_disagree(
        self, monkeypatch, capsys
    ):
        sent = self._provider(monkeypatch)
        monkeypatch.setattr("sys.stdin", StringIO(f"scan id {TEST_CARD}\n"))
        decisions = iter(
            (
                PIIClassification(
                    {},
                    1,
                    0,
                    0,
                    frozenset({TEST_CARD}),
                ),
                PIIClassification(
                    {"credit_card": {TEST_CARD}},
                    0,
                    1,
                    0,
                ),
            )
        )
        monkeypatch.setattr(
            "decon.cli.classify_pii_candidates",
            lambda candidates, **kwargs: next(decisions),
        )
        monkeypatch.setattr("decon.cli.llm_review", lambda *args, **kwargs: "CLEAN")

        assert (
            main(
                [
                    "--llm",
                    "--ask",
                    f"Explain {TEST_CARD}",
                    "--no-audit",
                ]
            )
            == 0
        )
        capsys.readouterr()
        assert TEST_CARD not in sent["prompt"]
        assert sent["prompt"].count("CC_REDACTED_") == 2

    def test_library_safety_gate_and_force_override(self, monkeypatch):
        sent = self._provider(monkeypatch)
        monkeypatch.setattr(
            "decon.api.scan_high_risk",
            lambda text: [SafetyFinding("private_key", 0, 1)],
        )
        with pytest.raises(AskError, match="transmission blocked"):
            ask_safely(
                self.PRIVATE_KEY,
                use_config=False,
                audit=False,
            )

        answer, _mapping = ask_safely(
            self.PRIVATE_KEY,
            use_config=False,
            audit=False,
            force_ask=True,
        )
        assert answer == "ok"
        assert "PRIVATE_KEY_REDACTED_" in sent["prompt"]


class TestAuditAndDoctor:
    def test_full_audit_is_explicit(self, tmp_path, monkeypatch, capsys):
        audit = tmp_path / "audit.jsonl"
        config = tmp_path / "decon.toml"
        config.write_text(
            f'[audit]\ndetail = "full"\npath = "{audit}"\n', encoding="utf-8"
        )
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr("sys.stdin", StringIO("host dc01.corp.local\n"))

        assert main([]) == 0
        capsys.readouterr()
        entry = json.loads(audit.read_text())
        assert entry["sources"] == ["-"]
        assert entry["substitutions"][0]["original"] == "dc01.corp.local"

    def test_forced_empty_ask_attempt_is_audited(self, monkeypatch, capsys):
        from decon.audit import audit_path

        monkeypatch.setitem(ask_mod._PROVIDERS, "claude", lambda *a, **k: "ok")
        monkeypatch.setattr("sys.stdin", StringIO(TestAskSafety.PRIVATE_KEY))

        assert (
            main(
                [
                    "--disable",
                    "private_key",
                    "--ask",
                    "Summarize",
                    "--force-ask",
                ]
            )
            == 0
        )
        capsys.readouterr()
        entry = json.loads(audit_path().read_text())
        assert entry["status"] == "forced_attempt"
        assert entry["total"] == 0

    def test_doctor_does_not_create_state(self, tmp_path, monkeypatch, capsys):
        state = tmp_path / "never-created"
        monkeypatch.setenv("DECON_STATE_DIR", str(state))
        monkeypatch.setattr(
            "decon.doctor._ollama_models",
            lambda host: (_ for _ in ()).throw(OSError("offline")),
        )

        assert main(["--doctor"]) == 0
        assert not state.exists()
        assert "state directory has not been created" in capsys.readouterr().out

    def test_required_ollama_failure_makes_doctor_nonzero(
        self, tmp_path, monkeypatch, capsys
    ):
        config = tmp_path / "decon.toml"
        config.write_text("[llm]\nrequired = true\n", encoding="utf-8")
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr(
            "decon.doctor._ollama_models",
            lambda host: (_ for _ in ()).throw(OSError("offline")),
        )

        assert main(["--doctor"]) == 1
        assert "FAIL Ollama" in capsys.readouterr().out

    def test_doctor_rejects_group_readable_config(self, tmp_path, monkeypatch, capsys):
        config = tmp_path / "decon.toml"
        config.write_text("", encoding="utf-8")
        config.chmod(0o644)
        monkeypatch.setattr("decon.config.DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr(
            "decon.doctor._ollama_models",
            lambda host: (_ for _ in ()).throw(OSError("offline")),
        )

        assert main(["--doctor"]) == 1
        assert "config permissions" in capsys.readouterr().out
