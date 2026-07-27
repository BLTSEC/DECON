"""Tests for RedactionEngine."""

import os
import tempfile

import pytest

from decon.engine import RedactionEngine


class TestConsistentMapping:
    def test_same_ip_same_placeholder(self):
        engine = RedactionEngine()
        result = engine.redact("Server 10.4.12.50 can't reach 10.4.12.1. Retry 10.4.12.50.")
        # First and second IPs get distinct typed placeholders.
        assert "10.4.12.50" not in result
        assert "10.4.12.1" not in result
        # Same IP -> same placeholder
        assert result.count("[IPV4_REDACTED_0001]") == 2
        assert result.count("[IPV4_REDACTED_0002]") == 1

    def test_email_redaction(self):
        engine = RedactionEngine()
        result = engine.redact("Contact admin@corp.com or admin@corp.com for help")
        assert "admin@corp.com" not in result
        assert "[EMAIL_REDACTED_0001]" in result
        # Same email -> same placeholder
        assert result.count("[EMAIL_REDACTED_0001]") == 2

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
        assert result.count("[CUSTOM_REDACTED_0001]") == 2

    def test_empty_value_is_rejected(self):
        try:
            RedactionEngine().add_custom_values([""])
            assert False, "Should have raised ValueError"
        except ValueError:
            pass


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
        assert "[HOST_REDACTED_0001]" in result

    def test_empty_matching_regex_is_rejected(self):
        try:
            RedactionEngine().add_custom_pattern("bad", r"x*")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_constant_placeholder_is_rejected(self):
        try:
            RedactionEngine().add_custom_pattern(
                "bad", r"secret", replacement="[CUSTOM_REDACTED]"
            )
            assert False, "Should have raised ValueError"
        except ValueError:
            pass


class TestTargetDomains:
    def test_target_domains_are_case_insensitive(self):
        engine = RedactionEngine()
        engine.add_target_domains(["contoso.com"])
        result = engine.redact("MAIL.CONTOSO.COM and Mail.Contoso.Com")
        assert "MAIL.CONTOSO.COM" not in result
        assert "Mail.Contoso.Com" not in result
        assert result.count("[HOST_REDACTED_0001]") == 2


class TestTypedTargets:
    """Engagement identifiers keep their type instead of collapsing to CUSTOM."""

    @pytest.mark.parametrize(
        ("method", "value", "placeholder"),
        [
            ("add_target_hostnames", "DC01", "[HOST_SHORT_REDACTED_0001]"),
            ("add_target_usernames", "svc_backup", "DOMAIN_USER_01"),
            ("add_target_netbios", "ACME", "[DOMAIN_REDACTED_0001]"),
            ("add_target_shares", "SYSVOL", "[SHARE_REDACTED_0001]"),
        ],
    )
    def test_typed_placeholder(self, method, value, placeholder):
        engine = RedactionEngine()
        getattr(engine, method)([value])
        result = engine.redact(f"the {value} entry")
        assert value not in result
        assert placeholder in result

    @pytest.mark.parametrize(
        ("method", "value"),
        [
            ("add_target_hostnames", "DC01"),
            ("add_target_usernames", "svc_backup"),
            ("add_target_netbios", "ACME"),
            ("add_target_shares", "SYSVOL"),
        ],
    )
    def test_case_insensitive(self, method, value):
        engine = RedactionEngine()
        getattr(engine, method)([value])
        result = engine.redact(f"{value.upper()} and {value.lower()}")
        assert value.upper() not in result
        assert value.lower() not in result

    @pytest.mark.parametrize(
        ("method", "value"),
        [
            ("add_target_hostnames", "DC01"),
            ("add_target_usernames", "jsmith"),
            ("add_target_shares", "SYSVOL"),
        ],
    )
    def test_rejects_empty_values(self, method, value):
        engine = RedactionEngine()
        with pytest.raises(ValueError):
            getattr(engine, method)([""])

    # A bare short name must not mint a second identity for a host already
    # mapped via its FQDN.
    def test_bare_hostname_reuses_fqdn_placeholder(self):
        engine = RedactionEngine()
        engine.add_target_hostnames(["DC01"])
        result = engine.redact("DC01.corp.example.com is the DC. Reach DC01 directly.")
        assert "DC01" not in result
        assert "[HOST_REDACTED_0001]" in result
        assert "[HOST_SHORT_REDACTED_0001]" in result

    # The boundary must reject a dot that continues a domain label, but allow
    # one that ends a sentence.
    def test_does_not_match_inside_an_fqdn(self):
        engine = RedactionEngine()
        engine.add_target_netbios(["corp"])
        result = engine.redact("host dc01.corp.example.com here")
        assert "[DOMAIN_REDACTED_0001]" not in result

    def test_matches_at_end_of_sentence(self):
        engine = RedactionEngine()
        engine.add_target_usernames(["jsmith"])
        result = engine.redact("readable by jsmith.")
        assert "jsmith" not in result
        assert result.endswith(".")

    def test_roundtrip_restores_all_types(self):
        engine = RedactionEngine()
        engine.add_target_hostnames(["DC01"])
        engine.add_target_usernames(["jsmith"])
        engine.add_target_netbios(["ACME"])
        engine.add_target_shares(["SYSVOL"])
        text = "ACME host DC01 shares SYSVOL with jsmith."
        redacted = engine.redact(text)
        assert engine.unredact(redacted) == text

    def test_share_placeholder_is_not_re_redacted(self):
        engine = RedactionEngine()
        engine.add_target_shares(["SYSVOL"])
        once = engine.redact("mount SYSVOL now")
        assert engine.redact(once) == once


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
            assert "[IPV4_REDACTED_0001]" in result
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
        assert "[MAC_REDACTED_0001]" in result
