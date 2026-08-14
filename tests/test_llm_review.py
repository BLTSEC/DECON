"""Local LLM review chunking and response-filter coverage."""

from __future__ import annotations

import json

import pytest


class TestLLMChunking:
    def test_placeholder_regex_covers_new_types(self):
        """Verify the placeholder regex matches all new placeholder formats."""
        from decon.llm import _PLACEHOLDER_RE

        new_placeholders = [
            "[IPV4_REDACTED_0001]",
            "[HOST_REDACTED_0001]",
            "[DOMAIN_REDACTED_0001]",
            "[CUSTOM_REDACTED_0001]",
            "[CUSTOM_HOST_REDACTED_0001]",
            "NTLM_HASH_01",
            "DOMAIN_USER_01",
            "UNC_PATH_01",
            "PRIVATE_KEY_REDACTED_01",
            "REDACTED_01",
            "example.internal0",
        ]
        for p in new_placeholders:
            assert _PLACEHOLDER_RE.match(p), f"Placeholder not matched: {p}"

    def test_chunker_preserves_full_input_with_overlap(self):
        from decon.llm import (
            LLM_CHUNK_OVERLAP,
            MAX_LLM_CHARS,
            _chunk_review_text,
        )

        text = "a" * (MAX_LLM_CHARS * 2 + 123)
        chunks = _chunk_review_text(text)
        assert len(chunks) >= 3
        assert all(len(chunk) <= MAX_LLM_CHARS for chunk in chunks)
        assert chunks[0].startswith(text[:100])
        assert chunks[-1].endswith(text[-100:])
        for previous, current in zip(chunks, chunks[1:]):
            assert previous[-LLM_CHUNK_OVERLAP:] == current[:LLM_CHUNK_OVERLAP]

    def test_llm_review_checks_tail_instead_of_truncating(self, monkeypatch, capsys):
        from decon.llm import (
            MAX_LLM_CHARS,
            MAX_REVIEW_OUTPUT_TOKENS,
            REVIEW_RESPONSE_SCHEMA,
            llm_review,
        )

        payloads = []

        class FakeResponse:
            def __init__(self, content):
                self.content = content

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps({"message": {"content": self.content}}).encode()

        def fake_urlopen(request, timeout):
            assert timeout == 300
            payload = json.loads(request.data.decode())
            payloads.append(payload)
            assert payload["messages"][0]["role"] == "system"
            assert payload["format"] == REVIEW_RESPONSE_SCHEMA
            assert payload["options"]["num_predict"] == MAX_REVIEW_OUTPUT_TOKENS
            prompt = payload["messages"][1]["content"]
            findings = (
                [{"value": "tail-secret", "category": "project"}]
                if "tail-secret" in prompt
                else []
            )
            content = json.dumps({"findings": findings})
            return FakeResponse(content)

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        text = "a" * (MAX_LLM_CHARS * 2) + "\ntail-secret"
        response = llm_review(text)

        assert len(payloads) >= 3
        assert "tail-secret" in payloads[-1]["messages"][1]["content"]
        assert response == "FOUND: tail-secret"
        captured = capsys.readouterr()
        assert "LLM chunks" in captured.err
        assert "truncat" not in captured.err.lower()

    def test_invalid_review_protocol_is_not_treated_as_clean(self, monkeypatch, capsys):
        from decon.llm import llm_review

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps(
                    {"message": {"content": "Looks safe to me."}}
                ).encode()

        monkeypatch.setattr(
            "urllib.request.urlopen", lambda request, timeout: FakeResponse()
        )

        assert llm_review("ordinary text") is None
        assert "outside the JSON review schema" in capsys.readouterr().err

    def test_hallucinated_finding_is_not_treated_as_a_real_leak(
        self, monkeypatch, capsys
    ):
        from decon.llm import llm_review

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "findings": [
                                        {
                                            "value": "invented.example",
                                            "category": "target",
                                        }
                                    ]
                                }
                            )
                        }
                    }
                ).encode()

        monkeypatch.setattr(
            "urllib.request.urlopen", lambda request, timeout: FakeResponse()
        )

        assert llm_review("ordinary text") is None
        assert "absent from input" in capsys.readouterr().err


class TestLLMPostFilterNormalization:
    """Test that the post-filter handles LLM-added context on placeholder values."""

    def test_ip_with_port_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: [IPV4_REDACTED_0001]:81"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_ip_with_parenthetical_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: [IPV4_REDACTED_0001] (target IP)"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_ip_with_dash_commentary_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: [IPV4_REDACTED_0001] - used as target"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    # Observed from a real qwen3.5:9b review run: the model reports a finding
    # with the key it was found under. The value is already redacted, so the
    # line is pure triage noise.
    @pytest.mark.parametrize(
        "raw",
        [
            "FOUND: token=[SECRET_REDACTED_0002]",
            "FOUND: owner=[EMAIL_REDACTED_0002]",
            "FOUND: password: [SECRET_REDACTED_0001]",
        ],
    )
    def test_keyed_placeholder_filtered(self, raw):
        from decon.llm import _filter_placeholder_findings

        assert _filter_placeholder_findings(raw) == "CLEAN"

    # Stripping the key must only inform the filter decision, never rewrite a
    # finding that should still be redacted.
    def test_keyed_real_value_is_kept_verbatim(self):
        from decon.llm import _filter_placeholder_findings

        result = _filter_placeholder_findings("FOUND: password=hunter2")
        assert "password=hunter2" in result

    def test_ip_with_protocol_prefix_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: http-get://[IPV4_REDACTED_0001]:81/"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_plain_placeholder_still_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: [IPV4_REDACTED_0001]"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_software_with_context_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: OpenSSH (in banner)"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_real_finding_preserved(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: basic-auth-user"
        result = _filter_placeholder_findings(raw)
        assert "FOUND:" in result
        assert "basic-auth-user" in result

    def test_mixed_real_and_placeholder(self):
        from decon.llm import _filter_placeholder_findings

        raw = (
            "FOUND: [IPV4_REDACTED_0001]:81\n"
            "FOUND: basic-auth-user\n"
            "FOUND: [IPV4_REDACTED_0002] (target)"
        )
        result = _filter_placeholder_findings(raw)
        assert "basic-auth-user" in result
        assert "IPV4_REDACTED_0001" not in result
        assert "IPV4_REDACTED_0002" not in result

    def test_normalize_finding_direct(self):
        from decon.llm import _normalize_finding

        assert _normalize_finding("10.0.0.1:81") == "10.0.0.1"
        assert _normalize_finding("10.0.0.1 (target IP)") == "10.0.0.1"
        assert _normalize_finding("10.0.0.1 - target") == "10.0.0.1"
        assert _normalize_finding("http-get://10.0.0.1:81/") == "10.0.0.1"
        assert _normalize_finding("https://10.0.0.3/path") == "10.0.0.3"
        assert _normalize_finding("OpenSSH (in banner)") == "OpenSSH"
        assert _normalize_finding("basic-auth-user") == "basic-auth-user"
        assert _normalize_finding("example.internal0.") == "example.internal0"


class TestLLMPostFilterArtifacts:
    """Test that timestamps and public wordlist filenames are filtered."""

    def test_timestamp_datetime_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 2024-09-09 16:04:31"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_timestamp_date_only_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 2024-09-09"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_timestamp_time_only_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 16:04:31"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_timestamp_iso_t_separator_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 2024-09-09T16:04:31"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_timestamp_with_timezone_and_year_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 14:28:13 CDT 2026"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_ctime_style_timestamp_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: Tue Mar 24 14:28:13 CDT 2026"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_duration_seconds_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 3.15 seconds"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_wordlist_filename_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 2023-200_most_used_passwords.txt"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_rockyou_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: rockyou.txt"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_seclists_directory_list_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: directory-list-2.3-medium.txt"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_multiple_timestamps_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 2024-09-09 16:04:31\nFOUND: 2024-09-09 16:04:32"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_real_finding_not_affected(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 2023-200_most_used_passwords.txt\nFOUND: admin@corp.local"
        result = _filter_placeholder_findings(raw)
        assert "admin@corp.local" in result
        assert "2023-200_most_used_passwords.txt" not in result

    def test_nmap_boilerplate_urls_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: https://nmap.org\nFOUND: https://nmap.org/submit/"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_suffixed_parent_domain_placeholder_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: example.internal0."
        assert _filter_placeholder_findings(raw) == "CLEAN"
