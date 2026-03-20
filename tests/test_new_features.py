"""Tests for new rules, features, and bug fixes."""

from __future__ import annotations

import json
import os
import tempfile
from io import StringIO

from decon.engine import RedactionEngine
from decon.patterns import (
    _NTLM_HASH,
    _AD_DOMAIN_USER,
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
        """Impacket secretsdump output contains NTLM hashes and domain users."""
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
        assert "NTLM_HASH_" in result
        assert "DOMAIN_USER_" in result

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
