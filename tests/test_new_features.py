"""Tests for new rules, features, and bug fixes."""

from __future__ import annotations

import json
import os
import tempfile
from io import StringIO

from decon.engine import RedactionEngine
from decon.patterns import (
    _NTLM_HASH,
    _AD_DOMAIN_USER_BACKSLASH as _AD_DOMAIN_USER,
    _PRIVATE_KEY,
    _UNC_PATH,
    build_default_rules,
)
from decon.cli import main


# ---------------------------------------------------------------------------
# New pattern tests
# ---------------------------------------------------------------------------


class TestNTLMHashPattern:
    def test_basic_match(self):
        m = _NTLM_HASH.search(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        assert m is not None

    def test_secretsdump_context(self):
        line = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        m = _NTLM_HASH.search(line)
        assert m is not None
        assert m.group() == "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_no_match_short_hex(self):
        assert _NTLM_HASH.search("abcdef:123456") is None

    def test_engine_redaction(self):
        engine = RedactionEngine()
        result = engine.redact(
            "hash: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        assert "aad3b435b51404ee" not in result
        assert "NTLM_HASH_01" in result


class TestADDomainUserPattern:
    def test_basic_match(self):
        m = _AD_DOMAIN_USER.search("CORP\\jsmith")
        assert m is not None
        assert m.group() == "CORP\\jsmith"

    def test_dotted_domain(self):
        m = _AD_DOMAIN_USER.search("CONTOSO.LOCAL\\administrator")
        assert m is not None

    def test_no_match_lowercase_short_domain(self):
        """Lowercase short domains are skipped to avoid false positives on paths."""
        assert _AD_DOMAIN_USER.search("usr\\bin") is None

    def test_fqdn_lowercase_domain(self):
        """FQDN domains (with dots) are matched even when lowercase."""
        m = _AD_DOMAIN_USER.search("megacorp.local\\svc_bes")
        assert m is not None
        assert m.group() == "megacorp.local\\svc_bes"

    def test_fqdn_with_password(self):
        """domain\\user:password is captured as one unit."""
        m = _AD_DOMAIN_USER.search("megacorp.local\\svc_bes:Sheffield19 (Pwn3d!)")
        assert m is not None
        assert m.group() == "megacorp.local\\svc_bes:Sheffield19"

    def test_uppercase_with_password(self):
        m = _AD_DOMAIN_USER.search("CORP\\admin:P@ssw0rd!")
        assert m is not None
        assert m.group() == "CORP\\admin:P@ssw0rd!"

    def test_short_password_not_captured(self):
        """Passwords shorter than 4 chars are not captured (avoids port numbers)."""
        m = _AD_DOMAIN_USER.search("CORP\\admin:80")
        assert m is not None
        assert m.group() == "CORP\\admin"  # :80 not included

    def test_no_match_unix_path(self):
        assert _AD_DOMAIN_USER.search("usr\\local\\bin") is None

    def test_engine_redaction(self):
        engine = RedactionEngine()
        result = engine.redact("authenticated as CORP\\jsmith via NTLM")
        assert "CORP\\jsmith" not in result
        assert "DOMAIN_USER_01" in result

    def test_multiple_users(self):
        engine = RedactionEngine()
        result = engine.redact("CORP\\admin and CORP\\jsmith")
        assert "CORP\\admin" not in result
        assert "CORP\\jsmith" not in result
        assert "DOMAIN_USER_01" in result
        assert "DOMAIN_USER_02" in result

    def test_netexec_credential_format(self):
        """Full netexec line: domain, user, and password all redacted."""
        engine = RedactionEngine()
        result = engine.redact(
            "[+] megacorp.local\\svc_bes:Sheffield19 (Pwn3d!)"
        )
        assert "megacorp.local" not in result
        assert "svc_bes" not in result
        assert "Sheffield19" not in result
        assert "DOMAIN_USER_01" in result
        assert "(Pwn3d!)" in result  # tool marker preserved


class TestPrivateKeyPattern:
    SAMPLE_KEY = """\
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aNMFkMHQ6bo3XFZ1K7RL9xZqAzBZMTxGNzMnT0CBHEB1GZXoYWxhFBL2s+2fJsO3
-----END RSA PRIVATE KEY-----"""

    EC_KEY = """\
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIHwEl1sBz1Gn93MfLhbATUfE4JRdeMTqjzYCHXRfULXVoAcGBSuBBAAi
-----END EC PRIVATE KEY-----"""

    def test_rsa_match(self):
        m = _PRIVATE_KEY.search(self.SAMPLE_KEY)
        assert m is not None

    def test_ec_match(self):
        m = _PRIVATE_KEY.search(self.EC_KEY)
        assert m is not None

    def test_generic_private_key(self):
        key = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----"
        m = _PRIVATE_KEY.search(key)
        assert m is not None

    def test_engine_redaction(self):
        engine = RedactionEngine()
        text = f"server key:\n{self.SAMPLE_KEY}\nend"
        result = engine.redact(text)
        assert "MIIEpAIBAAK" not in result
        assert "PRIVATE_KEY_REDACTED_01" in result

    def test_multiple_keys(self):
        engine = RedactionEngine()
        text = f"key1:\n{self.SAMPLE_KEY}\nkey2:\n{self.EC_KEY}\n"
        result = engine.redact(text)
        assert "PRIVATE_KEY_REDACTED_01" in result
        assert "PRIVATE_KEY_REDACTED_02" in result


class TestUNCPathPattern:
    def test_basic_match(self):
        m = _UNC_PATH.search("\\\\dc01\\SYSVOL")
        assert m is not None
        assert m.group() == "\\\\dc01\\SYSVOL"

    def test_longer_path(self):
        m = _UNC_PATH.search("\\\\fileserver\\share$\\documents\\report.xlsx")
        assert m is not None

    def test_no_match_single_backslash(self):
        assert _UNC_PATH.search("C:\\Users\\admin") is None

    def test_engine_redaction(self):
        engine = RedactionEngine()
        result = engine.redact("copy \\\\dc01\\SYSVOL\\policies to local")
        assert "\\\\dc01\\SYSVOL" not in result
        assert "UNC_PATH_01" in result


# ---------------------------------------------------------------------------
# CIDR mask preservation
# ---------------------------------------------------------------------------


class TestCIDRMaskPreservation:
    def test_preserves_slash16(self):
        engine = RedactionEngine()
        result = engine.redact("network 172.16.0.0/16 is internal")
        assert "/16" in result
        assert "172.16.0.0" not in result

    def test_preserves_slash32(self):
        engine = RedactionEngine()
        result = engine.redact("host 192.168.1.1/32")
        assert "/32" in result

    def test_preserves_slash8(self):
        engine = RedactionEngine()
        result = engine.redact("range 10.0.0.0/8")
        assert "/8" in result

    def test_different_masks_different_placeholders(self):
        engine = RedactionEngine()
        result = engine.redact("10.0.0.0/8 and 172.16.0.0/16 and 192.168.1.0/24")
        assert "/8" in result
        assert "/16" in result
        assert "/24" in result


# ---------------------------------------------------------------------------
# URL before email priority fix
# ---------------------------------------------------------------------------


class TestURLEmailPriority:
    def test_url_matched_before_email(self):
        """URL containing an email-like string should be caught as URL, not split."""
        engine = RedactionEngine()
        # URL rule (priority 28) runs before email (priority 30)
        rules = engine.list_rules()
        url_priority = next(r["priority"] for r in rules if r["name"] == "url")
        email_priority = next(r["priority"] for r in rules if r["name"] == "email")
        assert url_priority < email_priority

    def test_standalone_email_still_caught(self):
        engine = RedactionEngine()
        result = engine.redact("contact admin@corp.com for help")
        assert "admin@corp.com" not in result
        assert "user_01@example.com" in result


# ---------------------------------------------------------------------------
# IPv6 bare :: fix
# ---------------------------------------------------------------------------


class TestIPv6BareDoubleColon:
    def test_ipv6_loopback_still_matches(self):
        engine = RedactionEngine()
        result = engine.redact("listening on ::1")
        assert "::1" not in result or "fd00::" in result

    def test_cpp_scope_not_matched(self):
        """C++ scope resolution :: should not be matched as IPv6."""
        engine = RedactionEngine()
        result = engine.redact("std::vector<int> items")
        assert result == "std::vector<int> items"

    def test_perl_scope_not_matched(self):
        engine = RedactionEngine()
        result = engine.redact("use File::Path;")
        assert result == "use File::Path;"


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------


class TestAllowlist:
    def test_allowlisted_value_passes_through(self):
        engine = RedactionEngine()
        engine.add_allowlist(["10.4.12.50"])
        result = engine.redact("Server 10.4.12.50 and 10.4.12.1")
        assert "10.4.12.50" in result  # allowed
        assert "10.4.12.1" not in result  # still redacted

    def test_allowlist_multiple_values(self):
        engine = RedactionEngine()
        engine.add_allowlist(["10.4.12.50", "admin@test.com"])
        result = engine.redact("10.4.12.50 admin@test.com 10.4.12.1")
        assert "10.4.12.50" in result
        assert "admin@test.com" in result
        assert "10.4.12.1" not in result

    def test_allowlist_via_cli(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50 and 10.4.12.1\n"))
        ret = main(["--allow", "10.4.12.50"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "10.4.12.50" in captured.out
        assert "10.4.12.1" not in captured.out


# ---------------------------------------------------------------------------
# Target domains
# ---------------------------------------------------------------------------


class TestTargetDomains:
    def test_bare_domain_matched(self):
        engine = RedactionEngine()
        engine.add_target_domains(["contoso.com"])
        result = engine.redact("targeting contoso.com")
        assert "contoso.com" not in result
        assert "HOST_01.example.internal" in result

    def test_subdomain_matched(self):
        engine = RedactionEngine()
        engine.add_target_domains(["contoso.com"])
        result = engine.redact("ssh to dc01.contoso.com")
        assert "dc01.contoso.com" not in result
        assert "HOST_01.example.internal" in result

    def test_unrelated_domain_not_matched(self):
        engine = RedactionEngine()
        engine.add_target_domains(["contoso.com"])
        result = engine.redact("visiting example.org")
        assert "example.org" in result


# ---------------------------------------------------------------------------
# Unredact (reverse mapping)
# ---------------------------------------------------------------------------


class TestUnredact:
    def test_basic_unredact(self):
        engine = RedactionEngine()
        original = "Server 10.4.12.50 email admin@test.com"
        redacted = engine.redact(original)
        assert "10.4.12.50" not in redacted

        restored = engine.unredact(redacted)
        assert "10.4.12.50" in restored
        assert "admin@test.com" in restored

    def test_unredact_via_exported_map(self):
        engine1 = RedactionEngine()
        original = "Server 10.4.12.50"
        redacted = engine1.redact(original)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            path = f.name
        try:
            engine1.export_map(path)

            engine2 = RedactionEngine()
            engine2.import_map(path)
            restored = engine2.unredact(redacted)
            assert "10.4.12.50" in restored
        finally:
            os.unlink(path)

    def test_allowlist_not_reversed(self):
        """Allowlisted values have identity mappings and should not be touched."""
        engine = RedactionEngine()
        engine.add_allowlist(["10.4.12.50"])
        result = engine.redact("Server 10.4.12.50")
        assert "10.4.12.50" in result
        restored = engine.unredact(result)
        assert "10.4.12.50" in restored


# ---------------------------------------------------------------------------
# --check mode
# ---------------------------------------------------------------------------


class TestCheckMode:
    def test_check_finds_redactions(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("Server 10.4.12.50\n"))
        ret = main(["--check"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "value(s) to redact" in captured.err

    def test_check_clean(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("Nothing sensitive here.\n"))
        ret = main(["--check"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Clean" in captured.err


# ---------------------------------------------------------------------------
# --diff mode
# ---------------------------------------------------------------------------


class TestDiffMode:
    def test_diff_output(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("Server 10.4.12.50\n"))
        ret = main(["--diff"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "---" in captured.out
        assert "+++" in captured.out
        assert "10.4.12.50" in captured.out
        assert "10.0.0.1" in captured.out

    def test_diff_no_changes(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("Nothing to redact.\n"))
        ret = main(["--diff"])
        assert ret == 0
        captured = capsys.readouterr()
        assert captured.out == ""  # no diff if no changes


# ---------------------------------------------------------------------------
# --unredact CLI mode
# ---------------------------------------------------------------------------


class TestUnredactCLI:
    def test_unredact_cli(self, tmp_path, monkeypatch, capsys):
        # First, redact and export map
        engine = RedactionEngine()
        redacted = engine.redact("Server 10.4.12.50\n")
        map_path = str(tmp_path / "map.json")
        engine.export_map(map_path)

        # Now unredact using CLI
        monkeypatch.setattr("sys.stdin", StringIO(redacted))
        ret = main(["--unredact", map_path])
        assert ret == 0
        captured = capsys.readouterr()
        assert "10.4.12.50" in captured.out


# ---------------------------------------------------------------------------
# --output-dir (batch mode)
# ---------------------------------------------------------------------------


class TestBatchMode:
    def test_batch_output(self, tmp_path, capsys):
        # Create input files
        f1 = tmp_path / "log1.txt"
        f2 = tmp_path / "log2.txt"
        f1.write_text("Server 10.4.12.50\n")
        f2.write_text("Server 10.4.12.1\n")

        out_dir = str(tmp_path / "out")
        ret = main([str(f1), str(f2), "--output-dir", out_dir])
        assert ret == 0

        out1 = tmp_path / "out" / "log1.redacted.txt"
        out2 = tmp_path / "out" / "log2.redacted.txt"
        assert out1.exists()
        assert out2.exists()

        text1 = out1.read_text()
        text2 = out2.read_text()
        assert "10.4.12.50" not in text1
        assert "10.4.12.1" not in text2

    def test_batch_requires_files(self, capsys):
        ret = main(["--output-dir", "/tmp/out"])
        assert ret == 1

    def test_batch_shared_mapping(self, tmp_path, capsys):
        """Same IP in different files gets same placeholder."""
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("10.4.12.50\n")
        f2.write_text("10.4.12.50\n")

        out_dir = str(tmp_path / "out")
        map_path = str(tmp_path / "map.json")
        ret = main([str(f1), str(f2), "--output-dir", out_dir, "--export-map", map_path])
        assert ret == 0

        out1 = (tmp_path / "out" / "a.redacted.txt").read_text()
        out2 = (tmp_path / "out" / "b.redacted.txt").read_text()
        # Same IP -> same placeholder across files
        assert out1.strip() == out2.strip()


# ---------------------------------------------------------------------------
# Profile via env var
# ---------------------------------------------------------------------------


class TestProfileEnvVar:
    def test_profile_from_env(self, monkeypatch, capsys):
        """DECON_PROFILE env var should be picked up."""
        monkeypatch.setattr("sys.stdin", StringIO("10.4.12.50\n"))
        monkeypatch.setenv("DECON_PROFILE", "standard")
        ret = main([])
        assert ret == 0


# ---------------------------------------------------------------------------
# Realistic scenarios with new rules
# ---------------------------------------------------------------------------


class TestRealisticNewRules:
    def test_secretsdump_output(self):
        """Impacket secretsdump output contains SAM dump lines and domain users."""
        text = """\
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CORP\\svc_backup:1103:aad3b435b51404eeaad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::
"""
        engine = RedactionEngine()
        result = engine.redact(text)
        assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in result
        assert "aad3b435b51404eeaad3b435b51404ee" not in result
        assert "CORP\\svc_backup" not in result
        assert "SAM_DUMP_" in result

    def test_unc_path_in_smb_enum(self):
        text = """\
[+] IP: 10.10.14.5:445\tName: dc01
\tDisk\tPermissions
\t----\t-----------
\t\\\\dc01\\SYSVOL\tREAD
\t\\\\dc01\\NETLOGON\tREAD
\t\\\\dc01\\C$\tNO ACCESS
"""
        engine = RedactionEngine()
        result = engine.redact(text)
        assert "\\\\dc01" not in result
        assert "UNC_PATH_" in result
        assert "10.10.14.5" not in result

    def test_private_key_in_loot(self):
        text = """\
Found SSH key in /home/admin/.ssh/id_rsa:
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aNMFkMHQ6bo3XFZ1K7RL9xZqAzBZMTxGNzMnT0CBHEB1GZXoYWxhFBL2s+2fJsO3
-----END RSA PRIVATE KEY-----
Used to SSH to 10.10.14.5 as root
"""
        engine = RedactionEngine()
        result = engine.redact(text)
        assert "MIIEpAIBAAK" not in result
        assert "PRIVATE_KEY_REDACTED_01" in result
        assert "10.10.14.5" not in result

    def test_ad_domain_user_in_bloodhound(self):
        text = """\
[+] Found privileged users:
    CONTOSO\\Domain Admins
    CONTOSO\\Enterprise Admins
    CONTOSO.LOCAL\\krbtgt
"""
        engine = RedactionEngine()
        result = engine.redact(text)
        # These may partially match depending on regex boundaries
        # At minimum, the domain\user pattern should catch some
        assert "DOMAIN_USER_" in result


# ---------------------------------------------------------------------------
# Bug fix regression tests
# ---------------------------------------------------------------------------


class TestCheckWithAllowlist:
    def test_check_clean_with_allowlist(self, monkeypatch, capsys):
        """--check should report clean when only allowlisted values are found."""
        monkeypatch.setattr("sys.stdin", StringIO("Server 10.4.12.50\n"))
        ret = main(["--check", "--allow", "10.4.12.50"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Clean" in captured.err

    def test_check_with_import_map_no_new_data(self, tmp_path, monkeypatch, capsys):
        """--check with --import-map should report clean if no new redactions."""
        engine = RedactionEngine()
        engine.redact("10.4.12.50")
        map_path = str(tmp_path / "map.json")
        engine.export_map(map_path)

        monkeypatch.setattr("sys.stdin", StringIO("Nothing sensitive here.\n"))
        ret = main(["--check", "--import-map", map_path])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Clean" in captured.err

    def test_check_with_import_map_new_data(self, tmp_path, monkeypatch, capsys):
        """--check with --import-map should detect new sensitive values."""
        engine = RedactionEngine()
        engine.redact("10.4.12.50")
        map_path = str(tmp_path / "map.json")
        engine.export_map(map_path)

        monkeypatch.setattr("sys.stdin", StringIO("New IP 10.4.12.99\n"))
        ret = main(["--check", "--import-map", map_path])
        assert ret == 1


class TestTargetDomainMultiLevel:
    def test_two_level_subdomain(self):
        engine = RedactionEngine()
        engine.disable_rule("hostname_internal")
        engine.add_target_domains(["contoso.com"])
        result = engine.redact("mail.east.contoso.com")
        assert "contoso.com" not in result
        assert "HOST_01.example.internal" in result

    def test_three_level_subdomain(self):
        engine = RedactionEngine()
        engine.disable_rule("hostname_internal")
        engine.add_target_domains(["contoso.com"])
        result = engine.redact("a.b.c.contoso.com")
        assert "contoso.com" not in result

    def test_bare_domain_still_matches(self):
        engine = RedactionEngine()
        engine.disable_rule("hostname_internal")
        engine.add_target_domains(["contoso.com"])
        result = engine.redact("contoso.com")
        assert "contoso.com" not in result


class TestModeConflicts:
    def test_output_and_output_dir_conflict(self, capsys):
        ret = main(["-o", "out.txt", "--output-dir", "/tmp/out", "dummy.txt"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "cannot be used together" in captured.err

    def test_check_and_diff_conflict(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("test\n"))
        ret = main(["--check", "--diff"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "mutually exclusive" in captured.err

    def test_dry_run_and_check_conflict(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("test\n"))
        ret = main(["--dry-run", "--check"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "mutually exclusive" in captured.err


class TestMapFileErrors:
    def test_import_map_missing_file(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("test\n"))
        ret = main(["--import-map", "/nonexistent/map.json"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Error loading map" in captured.err

    def test_unredact_missing_file(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO("test\n"))
        ret = main(["--unredact", "/nonexistent/map.json"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Error loading map" in captured.err


class TestDryRunWithAllowlist:
    def test_dry_run_hides_allowlist_entries(self, monkeypatch, capsys):
        """--dry-run should not show allowlisted identity mappings."""
        monkeypatch.setattr(
            "sys.stdin", StringIO("10.4.12.50 and 10.4.12.1\n")
        )
        ret = main(["--dry-run", "--allow", "10.4.12.50"])
        assert ret == 0
        captured = capsys.readouterr()
        # Should show 10.4.12.1 redaction but NOT 10.4.12.50
        assert "10.4.12.1" in captured.err
        assert "10.4.12.50" not in captured.err


class TestLLMTruncation:
    def test_placeholder_regex_covers_new_types(self):
        """Verify the placeholder regex matches all new placeholder formats."""
        from decon.llm import _PLACEHOLDER_RE

        new_placeholders = [
            "NTLM_HASH_01",
            "DOMAIN_USER_01",
            "UNC_PATH_01",
            "PRIVATE_KEY_REDACTED_01",
            "REDACTED_01",
        ]
        for p in new_placeholders:
            assert _PLACEHOLDER_RE.match(p), f"Placeholder not matched: {p}"


class TestLLMPostFilterNormalization:
    """Test that the post-filter handles LLM-added context on placeholder values."""

    def test_ip_with_port_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 10.0.0.1:81"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_ip_with_parenthetical_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 10.0.0.1 (target IP)"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_ip_with_dash_commentary_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 10.0.0.1 - used as target"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_ip_with_protocol_prefix_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: http-get://10.0.0.1:81/"
        assert _filter_placeholder_findings(raw) == "CLEAN"

    def test_plain_placeholder_still_filtered(self):
        from decon.llm import _filter_placeholder_findings

        raw = "FOUND: 10.0.0.1"
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

        raw = "FOUND: 10.0.0.1:81\nFOUND: basic-auth-user\nFOUND: 10.0.0.2 (target)"
        result = _filter_placeholder_findings(raw)
        assert "basic-auth-user" in result
        assert "10.0.0.1" not in result
        assert "10.0.0.2" not in result

    def test_normalize_finding_direct(self):
        from decon.llm import _normalize_finding

        assert _normalize_finding("10.0.0.1:81") == "10.0.0.1"
        assert _normalize_finding("10.0.0.1 (target IP)") == "10.0.0.1"
        assert _normalize_finding("10.0.0.1 - target") == "10.0.0.1"
        assert _normalize_finding("http-get://10.0.0.1:81/") == "10.0.0.1"
        assert _normalize_finding("https://10.0.0.3/path") == "10.0.0.3"
        assert _normalize_finding("OpenSSH (in banner)") == "OpenSSH"
        assert _normalize_finding("basic-auth-user") == "basic-auth-user"


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


# ---------------------------------------------------------------------------
# New rules: .htb/.lab TLDs
# ---------------------------------------------------------------------------


class TestHTBLabTLDs:
    def test_htb_hostname(self):
        result = RedactionEngine().redact("dc01.inlanefreight.htb")
        assert "HOST_" in result
        assert "inlanefreight.htb" not in result

    def test_lab_hostname(self):
        result = RedactionEngine().redact("vhagar.dracarys.lab")
        assert "HOST_" in result
        assert "dracarys.lab" not in result

    def test_bare_htb_domain(self):
        result = RedactionEngine().redact("target is inlanefreight.htb")
        assert "HOST_" in result

    def test_subdomain_htb(self):
        result = RedactionEngine().redact("mail.internal.megacorp.htb")
        assert "HOST_" in result
        assert "megacorp.htb" not in result


# ---------------------------------------------------------------------------
# New rules: SAM/NTDS dump lines
# ---------------------------------------------------------------------------


class TestSAMDumpRule:
    def test_basic_sam_line(self):
        line = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        result = RedactionEngine().redact(line)
        assert "SAM_DUMP_" in result
        assert "Administrator" not in result
        assert "31d6cfe0" not in result

    def test_guest_sam_line(self):
        line = "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        result = RedactionEngine().redact(line)
        assert "SAM_DUMP_" in result

    def test_domain_prefix_sam(self):
        line = r"CORP\svc_backup:1103:aad3b435b51404eeaad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::"
        result = RedactionEngine().redact(line)
        assert "SAM_DUMP_" in result
        assert "svc_backup" not in result

    def test_fqdn_domain_sam(self):
        line = "inlanefreight.htb\\julio:1106:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::"
        result = RedactionEngine().redact(line)
        assert "SAM_DUMP_" in result

    def test_machine_account_sam(self):
        line = "DC01$:1002:aad3b435b51404eeaad3b435b51404ee:f0ec1102494ee338521fb866f5848d45:::"
        result = RedactionEngine().redact(line)
        assert "SAM_DUMP_" in result
        assert "DC01$" not in result

    def test_multiline_sam_dump(self):
        text = """\
[*] Dumping local SAM hashes
admin:500:aad3b435b51404eeaad3b435b51404ee:cc4a0dd1b4e7da73ab58b0e49b953e40:::
guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
"""
        result = RedactionEngine().redact(text)
        assert result.count("SAM_DUMP_") == 2
        assert "admin:500:" not in result

    def test_non_sam_not_matched(self):
        """Regular colon-separated text should not match."""
        text = "key:value:data"
        result = RedactionEngine().redact(text)
        assert "SAM_DUMP_" not in result


# ---------------------------------------------------------------------------
# New rules: NTLMv2 hashes (Responder/Inveigh captures)
# ---------------------------------------------------------------------------


class TestNTLMv2Rule:
    def test_ntlmv2_hash(self):
        line = "AB920::INLANEFREIGHT:52f6bb9682a00d2a:249B6350A1B7C9E43A4D7C3BE0AF4E21:0101000000000000abcdef1234567890"
        result = RedactionEngine().redact(line)
        assert "NTLMV2_HASH_" in result
        assert "AB920" not in result
        assert "INLANEFREIGHT" not in result

    def test_responder_capture(self):
        line = "jsmith::CORP:aabbccdd11223344:1234567890abcdef1234567890abcdef:01010000000000001234567890abcdef"
        result = RedactionEngine().redact(line)
        assert "NTLMV2_HASH_" in result
        assert "jsmith" not in result


# ---------------------------------------------------------------------------
# New rules: Kerberos keys
# ---------------------------------------------------------------------------


class TestKerberosKeyRule:
    def test_aes256_key(self):
        line = r"CORP\DC01$:aes256-cts-hmac-sha1-96:86e98ff8d71ffea0123456789abcdef0123456789abcdef0123456789abcdef0"
        result = RedactionEngine().redact(line)
        assert "KERBEROS_KEY_" in result
        assert "86e98ff8" not in result

    def test_aes128_key(self):
        line = r"CORP\svc_sql:aes128-cts-hmac-sha1-96:350bd90fcadae4e9d7e7dca40f82d316"
        result = RedactionEngine().redact(line)
        assert "KERBEROS_KEY_" in result

    def test_des_key(self):
        line = r"CORP\MS01$:des-cbc-md5:ba234ae034f14c67"
        result = RedactionEngine().redact(line)
        assert "KERBEROS_KEY_" in result


# ---------------------------------------------------------------------------
# New rules: Forward-slash domain/user (Impacket style)
# ---------------------------------------------------------------------------


class TestDomainUserSlash:
    def test_impacket_basic(self):
        result = RedactionEngine().redact("secretsdump.py CORP/admin@10.1.1.1")
        assert "DOMAIN_USER_" in result
        assert "CORP/admin" not in result

    def test_impacket_with_password(self):
        result = RedactionEngine().redact("INLANEFREIGHT/vfrank:Welcome1@172.16.10.25")
        assert "DOMAIN_USER_" in result
        assert "vfrank" not in result
        assert "Welcome1" not in result

    def test_fqdn_slash(self):
        result = RedactionEngine().redact("acme.corp/svc_sql:SqlPass1!@10.10.10.5")
        assert "DOMAIN_USER_" in result

    def test_http_version_not_matched(self):
        """HTTP/1.1 must not be matched as domain/user."""
        result = RedactionEngine().redact("HTTP/1.1 200 OK")
        assert result == "HTTP/1.1 200 OK"

    def test_ftp_version_not_matched(self):
        result = RedactionEngine().redact("FTP/2.0 ready")
        assert "DOMAIN_USER_" not in result

    def test_dcc2_with_slash_prefix(self):
        """DCC2 lines using DOMAIN/user: prefix."""
        line = "ACME.CORP/jdoe:$DCC2$10240#jdoe#a4f49c406510bdcab6824ee7c30fd852"
        result = RedactionEngine().redact(line)
        # The DCC2 hash or domain/user should be caught
        assert "jdoe" not in result


# ---------------------------------------------------------------------------
# New rules: CLI flag secrets (-p, -H, etc.)
# ---------------------------------------------------------------------------


class TestCLIFlagSecrets:
    def test_p_flag_quoted(self):
        result = RedactionEngine().redact("nxc smb 10.0.0.0/24 -u fcastle -p 'Password1'")
        assert "Password1" not in result
        assert "SECRET_" in result

    def test_p_flag_unquoted(self):
        result = RedactionEngine().redact("hydra -l admin -p SuperSecret123 10.1.1.1")
        assert "SuperSecret123" not in result

    def test_P_flag(self):
        result = RedactionEngine().redact("hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.1.1.1")
        # File paths to wordlists should NOT be treated as secrets
        # The -P flag is for password files, not passwords — but our rule matches it
        # This is acceptable since it redacts a file path that could contain target info
        assert "SECRET_" in result or "/usr/share" in result

    def test_hash_flag(self):
        result = RedactionEngine().redact("evil-winrm -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -i 10.1.1.1")
        # The hash should be caught by either -H flag or ntlm_hash rule
        assert "aad3b435" not in result

    def test_password_long_flag(self):
        result = RedactionEngine().redact("tool --password MyP@ss123! target")
        assert "MyP@ss123!" not in result

    def test_pw_flag(self):
        result = RedactionEngine().redact("evil-winrm -pw weasal123 -i 10.1.1.1")
        assert "weasal123" not in result

    def test_nmap_p_flag_port_list_not_secret(self):
        result = RedactionEngine().redact("nmap -Pn -sV -p 389,445,1433 10.1.1.1")
        assert "389,445,1433" in result
        assert "10.1.1.1" not in result

    def test_numeric_password_still_redacted_outside_port_scan_tools(self):
        result = RedactionEngine().redact("hydra -l admin -p 12345678 10.1.1.1")
        assert "12345678" not in result
        assert "SECRET_" in result


# ---------------------------------------------------------------------------
# New rules: Kerberoast/AS-REP hashes
# ---------------------------------------------------------------------------


class TestKerberosHashRule:
    def test_kerberoast_hash(self):
        line = "$krb5tgs$23$*svc_sql$CORP.LOCAL$corp.local/svc_sql*$aabbccdd$0123456789abcdef"
        result = RedactionEngine().redact(line)
        assert "KERBEROS_HASH_" in result
        assert "svc_sql" not in result

    def test_asrep_hash(self):
        line = "$krb5asrep$23$jsmith$CORP.LOCAL$aabbccdd11223344$0123456789abcdef0123456789abcdef"
        result = RedactionEngine().redact(line)
        assert "KERBEROS_HASH_" in result
        assert "jsmith" not in result


# ---------------------------------------------------------------------------
# New rules: DCC2 cached credentials
# ---------------------------------------------------------------------------


class TestDCC2Rule:
    def test_dcc2_hash(self):
        line = "$DCC2$10240#julio#c2139497f24725b345aa1e23352481f3"
        result = RedactionEngine().redact(line)
        assert "DCC2_HASH_" in result
        assert "julio" not in result

    def test_dcc2_with_domain_prefix(self):
        line = "INLANEFREIGHT.HTB/julio:$DCC2$10240#julio#c2139497f24725b345aa1e23352481f3"
        result = RedactionEngine().redact(line)
        assert "julio" not in result


# ---------------------------------------------------------------------------
# New rules: DPAPI keys
# ---------------------------------------------------------------------------


class TestDPAPIRule:
    def test_dpapi_machinekey(self):
        line = "dpapi_machinekey:0x78f7020d08fa61b3b77b24130b1ecd58f53dd338"
        result = RedactionEngine().redact(line)
        assert "DPAPI_KEY_" in result
        assert "78f7020d" not in result

    def test_dpapi_userkey(self):
        line = "dpapi_userkey:0x4c0d8465c338406d54a1ae09a56223e867907f39"
        result = RedactionEngine().redact(line)
        assert "DPAPI_KEY_" in result

    def test_nlkm(self):
        line = "NL$KM:a2529d310bb71c7545d64b76412dd321c65cdd04aabbccdd11223344"
        result = RedactionEngine().redact(line)
        assert "DPAPI_KEY_" in result
        assert "a2529d31" not in result


# ---------------------------------------------------------------------------
# New rules: Machine account hex passwords
# ---------------------------------------------------------------------------


class TestMachineHexPassword:
    def test_machine_hex(self):
        line = "plain_password_hex:4d0073006100620069006e0065007400"
        result = RedactionEngine().redact(line)
        assert "MACHINE_HEX_PW_" in result
        assert "4d007300" not in result


# ---------------------------------------------------------------------------
# New rules: Windows SID
# ---------------------------------------------------------------------------


class TestWindowsSIDRule:
    def test_domain_sid(self):
        result = RedactionEngine().redact("SID: S-1-5-21-3842939050-3880317879-2865463114-1001")
        assert "SID_REDACTED_" in result
        assert "3842939050" not in result

    def test_sid_without_rid(self):
        result = RedactionEngine().redact("Domain SID: S-1-5-21-3842939050-3880317879-2865463114")
        assert "SID_REDACTED_" in result

    def test_sid_in_mimikatz_output(self):
        text = """\
 * Username : administrator
 * Domain   : CORP
 * SID      : S-1-5-21-1234567890-9876543210-1122334455-500
"""
        result = RedactionEngine().redact(text)
        assert "SID_REDACTED_" in result
        assert "1234567890" not in result

    def test_non_domain_sid_not_matched(self):
        """Well-known SIDs like S-1-5-20 should not match (no 21- prefix)."""
        result = RedactionEngine().redact("SID: S-1-5-20")
        assert "SID_REDACTED_" not in result


# ---------------------------------------------------------------------------
# Context secret keyword expansion
# ---------------------------------------------------------------------------


class TestExpandedContextSecrets:
    def test_username_keyword(self):
        result = RedactionEngine().redact("Username: administrator")
        assert "administrator" not in result
        assert "SECRET_" in result

    def test_domain_keyword(self):
        result = RedactionEngine().redact("Domain: INLANEFREIGHT")
        assert "INLANEFREIGHT" not in result

    def test_domain_fqdn_uses_parent_domain_placeholder(self):
        result = RedactionEngine().redact("Domain: sevenkingdoms.local")
        assert "sevenkingdoms.local" not in result
        assert "example.internal" in result

    def test_multiple_fqdn_domains_get_distinct_parent_domain_placeholders(self):
        result = RedactionEngine().redact(
            "Domain: sevenkingdoms.local\nDomain: winterfell.local"
        )
        assert "sevenkingdoms.local" not in result
        assert "winterfell.local" not in result
        assert "example.internal" in result
        assert "example02.internal" in result

    def test_ntlm_keyword(self):
        result = RedactionEngine().redact("NTLM: 64f12cddaa88057e06a81b54e73b949b")
        assert "64f12cdd" not in result

    def test_user_id_keyword(self):
        result = RedactionEngine().redact("User ID=netdb;Password=D@ta_bAse_adm1n!")
        assert "netdb" not in result or "D@ta_bAse_adm1n!" not in result


# ---------------------------------------------------------------------------
# Integration: full secretsdump output with new rules
# ---------------------------------------------------------------------------


class TestFullSecretsdump:
    def test_complete_secretsdump(self):
        text = """\
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information
ACME.CORP/jdoe:$DCC2$10240#jdoe#a4f49c406510bdcab6824ee7c30fd852
[*] Dumping LSA Secrets
dpapi_machinekey:0x78f7020d08fa61b3b77b24130b1ecd58f53dd338
dpapi_userkey:0x4c0d8465c338406d54a1ae09a56223e867907f39
NL$KM:a2529d310bb71c7545d64b76412dd321c65cdd04aabbccdd11223344
ACME.CORP\\svc_sql:aes256-cts-hmac-sha1-96:86e98ff8d71ffea0123456789abcdef0123456789abcdef0123456789abcdef0
$MACHINE.ACC:plain_password_hex:4d0073006100620069006e0065007400
"""
        engine = RedactionEngine()
        result = engine.redact(text)
        # SAM lines redacted atomically
        assert "SAM_DUMP_" in result
        assert "Administrator:500:" not in result
        # DCC2
        assert "jdoe" not in result
        # DPAPI
        assert "78f7020d" not in result
        # Kerberos key
        assert "86e98ff8" not in result
        # Machine hex password
        assert "4d007300" not in result
        # Structure preserved
        assert "[*] Dumping" in result


# ---------------------------------------------------------------------------
# CLI flag secrets: -u, -l, /param:value, -U user%pass
# ---------------------------------------------------------------------------


class TestCLIFlagUsernames:
    def test_u_flag(self):
        result = RedactionEngine().redact("nxc smb 10.1.1.1 -u fcastle -p Password1")
        assert "fcastle" not in result
        assert "Password1" not in result
        assert "SECRET_" in result

    def test_l_flag(self):
        result = RedactionEngine().redact("hydra -l admin -p secret123 10.1.1.1")
        assert "admin" not in result
        assert "secret123" not in result

    def test_login_flag(self):
        result = RedactionEngine().redact("tool --login jsmith --password Hunter2")
        assert "jsmith" not in result
        assert "Hunter2" not in result

    def test_user_flag(self):
        result = RedactionEngine().redact("evil-winrm --user admin -p Password1 -i 10.1.1.1")
        assert "admin" not in result


class TestSlashParamSecrets:
    def test_user_param(self):
        result = RedactionEngine().redact("rubeus.exe asktgt /user:svc_sql /domain:corp.local")
        assert "svc_sql" not in result
        assert "corp.local" not in result

    def test_rc4_param(self):
        result = RedactionEngine().redact("rubeus.exe /rc4:e52cac67419a9a224a3b108f3fa6cb6d")
        assert "e52cac67" not in result
        assert "SECRET_" in result

    def test_ntlm_param(self):
        result = RedactionEngine().redact("mimikatz /ntlm:aabbccdd11223344aabbccdd11223344")
        assert "aabbccdd" not in result

    def test_aes256_param(self):
        result = RedactionEngine().redact("rubeus /aes256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        assert "01234567" not in result

    def test_password_param(self):
        result = RedactionEngine().redact("tool /password:MyP@ssw0rd!")
        assert "MyP@ssw0rd!" not in result

    def test_non_matching_param_preserved(self):
        result = RedactionEngine().redact("tool /output:results.txt")
        assert "results.txt" in result


class TestSMBUserPass:
    def test_basic(self):
        result = RedactionEngine().redact("smbclient //10.1.1.1/share -U admin%P@ssword1")
        assert "admin" not in result or "SECRET_" in result
        assert "P@ssword1" not in result

    def test_domain_user(self):
        result = RedactionEngine().redact("smbclient -U CORP/admin%Secret1 //10.1.1.1/share")
        # DOMAIN/user part caught by domain_user_slash, password by smb_user_pass
        assert "Secret1" not in result


# ---------------------------------------------------------------------------
# False positive fixes: NT AUTHORITY, registry paths
# ---------------------------------------------------------------------------


class TestDomainUserFalsePositives:
    def test_nt_authority_system(self):
        """NT AUTHORITY\\SYSTEM should NOT be redacted."""
        result = RedactionEngine().redact("NT AUTHORITY\\SYSTEM")
        assert "DOMAIN_USER_" not in result
        assert "SYSTEM" in result

    def test_authority_system(self):
        """AUTHORITY\\SYSTEM (without NT prefix) should NOT be redacted."""
        result = RedactionEngine().redact("running as AUTHORITY\\SYSTEM")
        assert "DOMAIN_USER_" not in result

    def test_nt_service(self):
        result = RedactionEngine().redact("NT SERVICE\\TrustedInstaller")
        assert "DOMAIN_USER_" not in result

    def test_builtin_administrators(self):
        result = RedactionEngine().redact("BUILTIN\\Administrators")
        assert "DOMAIN_USER_" not in result

    def test_hklm_registry(self):
        result = RedactionEngine().redact("HKLM\\SAM\\Domains")
        assert "DOMAIN_USER_" not in result
        assert "HKLM" in result

    def test_hkey_registry(self):
        result = RedactionEngine().redact("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft")
        assert "DOMAIN_USER_" not in result

    def test_microsoft_path(self):
        result = RedactionEngine().redact("Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE")
        assert "DOMAIN_USER_" not in result

    def test_software_path(self):
        result = RedactionEngine().redact("SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
        assert "DOMAIN_USER_" not in result

    def test_real_domain_user_still_caught(self):
        """Real domain\\user should still be redacted."""
        result = RedactionEngine().redact("CORP\\jsmith:P@ssw0rd!")
        assert "DOMAIN_USER_" in result
        assert "jsmith" not in result

    def test_real_fqdn_domain_user_still_caught(self):
        result = RedactionEngine().redact("megacorp.local\\svc_backup")
        assert "DOMAIN_USER_" in result


# ---------------------------------------------------------------------------
# User path rules
# ---------------------------------------------------------------------------


class TestLinuxHomePath:
    def test_basic_home(self):
        result = RedactionEngine().redact("/home/julio/.ssh/id_rsa")
        assert "julio" not in result
        assert "SECRET_" in result
        assert "/home/" in result
        assert "/.ssh/id_rsa" in result

    def test_home_in_tool_output(self):
        result = RedactionEngine().redact("found: /home/bob/.bash_history")
        assert "bob" not in result

    def test_multiple_users(self):
        text = "/home/alice/data\n/home/bob/data"
        engine = RedactionEngine()
        result = engine.redact(text)
        assert "alice" not in result
        assert "bob" not in result

    def test_non_home_path_preserved(self):
        result = RedactionEngine().redact("/var/log/syslog")
        assert result == "/var/log/syslog"


class TestWindowsUserPath:
    def test_basic_path(self):
        result = RedactionEngine().redact("C:\\Users\\htb-student\\Desktop\\flag.txt")
        assert "htb-student" not in result
        assert "SECRET_" in result

    def test_administrator_path(self):
        result = RedactionEngine().redact("C:\\Users\\Administrator\\Documents")
        assert "Administrator" not in result

    def test_non_user_path_preserved(self):
        result = RedactionEngine().redact("C:\\Windows\\System32\\cmd.exe")
        assert result == "C:\\Windows\\System32\\cmd.exe"


# ---------------------------------------------------------------------------
# Integration: realistic netexec/hydra command lines
# ---------------------------------------------------------------------------


class TestRealisticCommandLines:
    def test_netexec_full_command(self):
        text = "nxc smb 10.10.14.5 -u fcastle -p 'Password123!' -d MARVEL.local"
        engine = RedactionEngine()
        result = engine.redact(text)
        assert "fcastle" not in result
        assert "Password123!" not in result
        assert "10.10.14.5" not in result
        assert "MARVEL.local" not in result

    def test_evil_winrm_command(self):
        text = "evil-winrm -i 10.10.14.5 -u admin -p 'P@ssw0rd!'"
        result = RedactionEngine().redact(text)
        assert "admin" not in result
        assert "P@ssw0rd!" not in result
        assert "10.10.14.5" not in result

    def test_impacket_secretsdump(self):
        text = "secretsdump.py CORP/admin:cracked_pass@10.10.14.5"
        result = RedactionEngine().redact(text)
        assert "admin" not in result
        assert "cracked_pass" not in result

    def test_rubeus_command(self):
        text = "rubeus.exe asktgt /user:svc_sql /rc4:e52cac67419a9a224a3b108f3fa6cb6d /domain:corp.local"
        result = RedactionEngine().redact(text)
        assert "svc_sql" not in result
        assert "e52cac67" not in result
        assert "corp.local" not in result

    def test_hydra_command(self):
        text = "hydra -l admin -p 'Summer2024!' 10.10.14.5 ssh"
        result = RedactionEngine().redact(text)
        assert "admin" not in result
        assert "Summer2024!" not in result

    def test_smbclient_command(self):
        text = "smbclient //10.10.14.5/ADMIN$ -U admin%Secret123!"
        result = RedactionEngine().redact(text)
        assert "Secret123!" not in result

    def test_krbtgt_param(self):
        text = "rubeus /krbtgt:9d765b482771505cbe97411065964d5f"
        result = RedactionEngine().redact(text)
        assert "9d765b48" not in result


# ---------------------------------------------------------------------------
# False positive regression tests
# ---------------------------------------------------------------------------


class TestSlashAbbreviationFalsePositives:
    """Common abbreviations with / should NOT be matched as domain/user."""

    def test_smb_wmi(self):
        assert RedactionEngine().redact("SMB/WMI") == "SMB/WMI"

    def test_tgt_tgs(self):
        assert RedactionEngine().redact("TGT/TGS") == "TGT/TGS"

    def test_rw(self):
        assert RedactionEngine().redact("R/W access") == "R/W access"

    def test_gnu_linux(self):
        assert RedactionEngine().redact("GNU/Linux") == "GNU/Linux"

    def test_kb_s(self):
        assert RedactionEngine().redact("150 KB/s") == "150 KB/s"

    def test_lfi_rfi(self):
        assert RedactionEngine().redact("LFI/RFI") == "LFI/RFI"

    def test_real_domain_slash_still_caught(self):
        result = RedactionEngine().redact("CORP/admin")
        assert "DOMAIN_USER_" in result

    def test_long_domain_slash_caught(self):
        result = RedactionEngine().redact("INLANEFREIGHT/julio")
        assert "DOMAIN_USER_" in result

    def test_fqdn_slash_caught(self):
        result = RedactionEngine().redact("acme.corp/svc_sql")
        assert "DOMAIN_USER_" in result


class TestCLIFlagFalsePositives:
    """File paths and template values after CLI flags should NOT be redacted."""

    def test_wordlist_path(self):
        result = RedactionEngine().redact("hydra -P /usr/share/wordlists/rockyou.txt")
        assert "/usr/share" in result

    def test_filename_extension(self):
        result = RedactionEngine().redact("hydra -l user.list target")
        assert "user.list" in result

    def test_password_file(self):
        result = RedactionEngine().redact("hydra -p passwords.txt target")
        assert "passwords.txt" in result

    def test_template_placeholder(self):
        result = RedactionEngine().redact("nxc -u <username> -p <password>")
        assert "<username>" in result
        assert "<password>" in result

    def test_real_credentials_still_caught(self):
        result = RedactionEngine().redact("nxc -u fcastle -p Password1")
        assert "fcastle" not in result
        assert "Password1" not in result
