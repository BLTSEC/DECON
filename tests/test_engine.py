"""Tests for RedactionEngine."""

import json
import tempfile
import os
from decon.engine import RedactionEngine


class TestConsistentMapping:
    def test_same_ip_same_placeholder(self):
        engine = RedactionEngine()
        result = engine.redact("Server 10.4.12.50 can't reach 10.4.12.1. Retry 10.4.12.50.")
        # First IP gets 10.0.0.1, second gets 10.0.0.2
        assert "10.4.12.50" not in result
        assert "10.4.12.1" not in result
        # Same IP -> same placeholder
        assert result.count("10.0.0.1") == 2  # 10.4.12.50 appears twice
        assert result.count("10.0.0.2") == 1  # 10.4.12.1 appears once

    def test_email_redaction(self):
        engine = RedactionEngine()
        result = engine.redact("Contact admin@corp.com or admin@corp.com for help")
        assert "admin@corp.com" not in result
        assert "user_01@example.com" in result
        # Same email -> same placeholder
        assert result.count("user_01@example.com") == 2

    def test_mixed_types(self):
        engine = RedactionEngine()
        text = "Host 10.4.12.50 email admin@test.com ip 10.4.12.50"
        result = engine.redact(text)
        assert "10.4.12.50" not in result
        assert "admin@test.com" not in result

    def test_no_redaction_needed(self):
        engine = RedactionEngine()
        text = "This is a normal sentence with no sensitive data."
        result = engine.redact(text)
        assert result == text


class TestEnableDisable:
    def test_disable_rule(self):
        engine = RedactionEngine()
        engine.disable_rule("ipv4")
        result = engine.redact("Server 10.4.12.50")
        assert "10.4.12.50" in result

    def test_enable_rule(self):
        engine = RedactionEngine()
        engine.disable_rule("ipv4")
        engine.enable_rule("ipv4")
        result = engine.redact("Server 10.4.12.50")
        assert "10.4.12.50" not in result

    def test_unknown_rule(self):
        engine = RedactionEngine()
        try:
            engine.disable_rule("nonexistent")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass


class TestCustomValues:
    def test_case_sensitive(self):
        engine = RedactionEngine()
        engine.add_custom_values(["ACME Corp"])
        result = engine.redact("Working for ACME Corp on a project")
        assert "ACME Corp" not in result

    def test_case_insensitive(self):
        engine = RedactionEngine()
        engine.add_custom_values(["jsmith"], case_sensitive=False)
        result = engine.redact("User JSMITH logged in as jsmith")
        assert "JSMITH" not in result
        assert "jsmith" not in result


class TestCustomPattern:
    def test_custom_regex(self):
        engine = RedactionEngine()
        engine.add_custom_pattern(
            name="internal_domain",
            pattern=r"[a-z0-9-]+\.corp\.acme\.com",
            replacement="HOST_{n:02d}.example.internal",
        )
        result = engine.redact("ssh to db01.corp.acme.com")
        assert "db01.corp.acme.com" not in result
        assert "HOST_01.example.internal" in result


class TestExportImportMap:
    def test_roundtrip(self):
        engine1 = RedactionEngine()
        engine1.redact("Server 10.4.12.50 and 10.4.12.1")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        try:
            engine1.export_map(path)

            engine2 = RedactionEngine()
            engine2.import_map(path)

            # New engine should use same mapping
            result = engine2.redact("Connecting to 10.4.12.50")
            assert "10.0.0.1" in result
        finally:
            os.unlink(path)


class TestListRules:
    def test_returns_all_rules(self):
        engine = RedactionEngine()
        rules = engine.list_rules()
        assert len(rules) > 0
        assert all("name" in r for r in rules)
        assert all("enabled" in r for r in rules)


class TestStats:
    def test_stats_populated(self):
        engine = RedactionEngine()
        engine.redact("10.4.12.50 admin@test.com")
        stats = engine.get_stats()
        assert "ipv4" in stats
        assert "email" in stats


class TestJWTRedaction:
    def test_jwt_redacted(self):
        engine = RedactionEngine()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = engine.redact(f"Bearer {jwt}")
        assert jwt not in result
        assert "JWT_REDACTED_01" in result


class TestContextSecret:
    def test_api_key_value_redacted(self):
        engine = RedactionEngine()
        result = engine.redact('api_key=sk_live_abc123def456ghi')
        assert "sk_live_abc123def456ghi" not in result
        assert "api_key=" in result  # label preserved


class TestMACRedaction:
    def test_mac_redacted(self):
        engine = RedactionEngine()
        result = engine.redact("interface aa:bb:cc:dd:ee:ff")
        assert "aa:bb:cc:dd:ee:ff" not in result
        assert "00:DE:AD:00:00:01" in result
