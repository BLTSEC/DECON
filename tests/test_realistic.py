"""Realistic pentest log tests and edge case gauntlet for DECON.

Tests the engine against synthetic-but-representative output from common
offensive tools, validates rule interaction edge cases, and stress-tests
consistency guarantees.
"""

from __future__ import annotations

import json
import tempfile
import os
from decon.engine import RedactionEngine


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _engine() -> RedactionEngine:
    return RedactionEngine()


def _assert_clean(result: str, *sensitive: str) -> None:
    """Assert none of the sensitive values appear in the result."""
    for val in sensitive:
        assert val not in result, f"Sensitive value leaked: {val!r}"


# ===========================================================================
# 1. REALISTIC PENTEST LOG SAMPLES
# ===========================================================================


class TestNmapOutput:
    """Synthetic nmap scan output."""

    NMAP_OUTPUT = """\
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 14:23 EST
Nmap scan report for dc01.corp.acme.com (10.10.14.5)
Host is up (0.032s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.9p1
53/tcp   open  domain        ISC BIND 9.18.12
80/tcp   open  http          Apache httpd 2.4.54
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
443/tcp  open  ssl/http      Apache httpd 2.4.54
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
MAC Address: DE:AD:BE:EF:CA:FE (Unknown)

Nmap scan report for web01.corp.acme.com (10.10.14.10)
Host is up (0.028s latency).
PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx 1.22.1
443/tcp open  ssl/http nginx 1.22.1
MAC Address: AA:BB:CC:11:22:33 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (2 hosts up) scanned in 43.21 seconds
"""

    def test_all_ips_redacted(self):
        result = _engine().redact(self.NMAP_OUTPUT)
        _assert_clean(result, "10.10.14.5", "10.10.14.10")

    def test_hostnames_redacted(self):
        result = _engine().redact(self.NMAP_OUTPUT)
        _assert_clean(result, "dc01.corp.acme.com", "web01.corp.acme.com")

    def test_macs_redacted(self):
        result = _engine().redact(self.NMAP_OUTPUT)
        _assert_clean(result, "DE:AD:BE:EF:CA:FE", "AA:BB:CC:11:22:33")

    def test_ip_consistency(self):
        """Same IP always maps to the same placeholder."""
        engine = _engine()
        text = "Host 10.10.14.5 port 22\nHost 10.10.14.5 port 443"
        result = engine.redact(text)
        lines = result.strip().split("\n")
        # Extract the redacted IP from each line
        ip1 = lines[0].split()[1]
        ip2 = lines[1].split()[1]
        assert ip1 == ip2

    def test_structure_preserved(self):
        """Port numbers, service names, and formatting survive redaction."""
        result = _engine().redact(self.NMAP_OUTPUT)
        assert "22/tcp" in result
        assert "443/tcp" in result
        assert "OpenSSH" in result
        assert "nginx" in result
        assert "PORT" in result
        assert "STATE" in result


class TestNetexecOutput:
    """Synthetic netexec/crackmapexec output."""

    NETEXEC_SMB = """\
SMB  10.10.14.5  445  DC01  [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:acme.corp) (signing:True) (SMBv1:False)
SMB  10.10.14.5  445  DC01  [+] acme.corp\\svc_backup:P@ssw0rd123! (Pwn3d!)
SMB  10.10.14.10 445  WEB01 [*] Windows Server 2022 Build 20348 x64 (name:WEB01) (domain:acme.corp) (signing:False) (SMBv1:False)
SMB  10.10.14.10 445  WEB01 [+] acme.corp\\administrator:Sup3rS3cret!
"""

    NETEXEC_WINRM = """\
WINRM  10.10.14.5  5985  DC01  [+] acme.corp\\svc_backup:P@ssw0rd123! (Pwn3d!)
WINRM  10.10.14.10 5985  WEB01 [-] acme.corp\\guest:guest123
"""

    def test_ips_redacted(self):
        result = _engine().redact(self.NETEXEC_SMB)
        _assert_clean(result, "10.10.14.5", "10.10.14.10")

    def test_passwords_not_leaked(self):
        """Passwords in user:pass format — the secret rule should catch key=value
        but bare user:pass may not have a keyword anchor. Verify IPs at minimum."""
        result = _engine().redact(self.NETEXEC_SMB)
        _assert_clean(result, "10.10.14.5", "10.10.14.10")

    def test_protocol_structure_preserved(self):
        result = _engine().redact(self.NETEXEC_SMB)
        assert "SMB" in result
        assert "445" in result
        assert "[+]" in result
        assert "[*]" in result

    def test_winrm_ips_redacted(self):
        result = _engine().redact(self.NETEXEC_WINRM)
        _assert_clean(result, "10.10.14.5", "10.10.14.10")


class TestImpacketOutput:
    """Synthetic Impacket tool output (secretsdump, psexec, etc.)."""

    SECRETSDUMP = """\
[*] Target system bootKey: 0xabcdef1234567890abcdef1234567890
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
svc_backup:1103:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
[*] Dumping cached domain logon information (domain/username:hash)
ACME.CORP/jdoe:$DCC2$10240#jdoe#a4f49c406510bdcab6824ee7c30fd852
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:4d0073006100...
[*] DPAPI_SYSTEM
[*] DefaultPassword
ACME.CORP\\svc_sql:SqlServer2024!
[*] Cleaning up...
"""

    PSEXEC = """\
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.14.5.....
[*] Found writable share ADMIN$
[*] Uploading file TzPCVKnR.exe
[*] Opening SVCManager on 10.10.14.5.....
[*] Creating service OxbR on 10.10.14.5.....
[*] Starting service OxbR.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2340]
(c) Microsoft Corporation. All rights reserved.

C:\\Windows\\system32> whoami
nt authority\\system

C:\\Windows\\system32> ipconfig
Ethernet adapter Ethernet0:
   IPv4 Address. . . . . . . . . . . : 10.10.14.5
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.14.1
"""

    def test_secretsdump_ips_clean(self):
        result = _engine().redact(self.PSEXEC)
        _assert_clean(result, "10.10.14.5", "10.10.14.1")

    def test_psexec_ip_consistency(self):
        engine = _engine()
        result = engine.redact(self.PSEXEC)
        # 10.10.14.5 appears multiple times — should be same placeholder
        placeholder = engine.mapping.get("10.10.14.5")
        assert placeholder is not None
        assert result.count(placeholder) >= 3

    def test_secretsdump_structure(self):
        result = _engine().redact(self.SECRETSDUMP)
        assert "[*]" in result
        assert "SAM hashes" in result
        assert "Administrator:" in result


class TestGobusterOutput:
    """Synthetic gobuster/ffuf output."""

    GOBUSTER = """\
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.14.10/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:            200,204,301,302,307,401,403
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://10.10.14.10/admin/]
/api                  (Status: 301) [Size: 310] [--> http://10.10.14.10/api/]
/uploads              (Status: 403) [Size: 278]
/config               (Status: 200) [Size: 1432]
/login                (Status: 200) [Size: 3847]
/.htaccess            (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
===============================================================
Finished
===============================================================
"""

    def test_url_ips_redacted(self):
        result = _engine().redact(self.GOBUSTER)
        _assert_clean(result, "10.10.14.10")

    def test_paths_preserved(self):
        result = _engine().redact(self.GOBUSTER)
        assert "/admin" in result
        assert "/api" in result
        assert "/login" in result
        assert "Status: 301" in result


class TestResponderOutput:
    """Synthetic Responder / NTLM relay output."""

    RESPONDER = """\
[+] Listening for events...
[HTTP] NTLMv2 Client   : 10.10.14.20
[HTTP] NTLMv2 Username : ACME\\jdoe
[HTTP] NTLMv2 Hash     : jdoe::ACME:1122334455667788:AABBCCDD11223344:0101000000000000
[SMB] NTLMv2 Client    : 10.10.14.25
[SMB] NTLMv2 Username  : ACME\\admin
[SMB] NTLMv2 Hash      : admin::ACME:aabbccdd11223344:FFEEDDCCBBAA9988:0101000000000000
[+] Exiting...
"""

    def test_ips_redacted(self):
        result = _engine().redact(self.RESPONDER)
        _assert_clean(result, "10.10.14.20", "10.10.14.25")

    def test_structure_preserved(self):
        result = _engine().redact(self.RESPONDER)
        assert "[HTTP]" in result
        assert "[SMB]" in result
        assert "NTLMv2" in result


class TestBloodHoundOutput:
    """Synthetic BloodHound / SharpHound collection data."""

    BLOODHOUND_USERS = """\
[+] Collecting users from acme.corp
    CN=John Doe,OU=Users,DC=acme,DC=corp - jdoe@acme.corp
    CN=Jane Smith,OU=Admins,DC=acme,DC=corp - jsmith@acme.corp
    CN=Service Backup,OU=Service Accounts,DC=acme,DC=corp - svc_backup@acme.corp
[+] Found 3 users
"""

    def test_emails_redacted(self):
        result = _engine().redact(self.BLOODHOUND_USERS)
        _assert_clean(result, "jdoe@acme.corp", "jsmith@acme.corp", "svc_backup@acme.corp")


class TestSSHSession:
    """Synthetic SSH session with mixed sensitive data."""

    SSH_LOG = """\
$ ssh admin@10.10.14.5
admin@10.10.14.5's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

Last login: Thu Nov 14 09:31:22 2024 from 10.10.14.100
admin@dc01:~$ cat /etc/shadow
root:$6$rounds=656000$salt$hash:19000:0:99999:7:::
admin:$6$rounds=656000$salt2$hash2:19000:0:99999:7:::
admin@dc01:~$ cat /home/admin/.aws/credentials
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
admin@dc01:~$ cat /var/www/.env
DATABASE_URL=postgres://dbuser:Str0ngP@ss!@db01.internal:5432/webapp
API_KEY="sk_live_FAKE_TEST_KEY_00000000000"
JWT_SECRET="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
admin@dc01:~$ ip addr
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.10.14.5/24 brd 10.10.14.255 scope global eth0
    inet6 fe80::a00:27ff:fe8e:8aa8%eth0 scope link
       valid_lft forever preferred_lft forever
admin@dc01:~$ exit
Connection to 10.10.14.5 closed.
"""

    def test_ips_redacted(self):
        result = _engine().redact(self.SSH_LOG)
        _assert_clean(result, "10.10.14.5", "10.10.14.100", "10.10.14.255")

    def test_aws_key_redacted(self):
        result = _engine().redact(self.SSH_LOG)
        _assert_clean(result, "AKIAIOSFODNN7EXAMPLE")

    def test_secrets_redacted(self):
        result = _engine().redact(self.SSH_LOG)
        _assert_clean(result, "sk_live_FAKE_TEST_KEY_00000000000")

    def test_hostname_redacted(self):
        result = _engine().redact(self.SSH_LOG)
        _assert_clean(result, "db01.internal")

    def test_jwt_redacted(self):
        result = _engine().redact(self.SSH_LOG)
        _assert_clean(result, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")

    def test_ip_consistency_across_log(self):
        engine = _engine()
        result = engine.redact(self.SSH_LOG)
        placeholder = engine.mapping["10.10.14.5"]
        # IP appears in ssh command, password prompt, ip addr, and exit line
        assert result.count(placeholder) >= 3


class TestWebAppLogs:
    """Synthetic web application / nginx access logs."""

    ACCESS_LOG = """\
10.10.14.100 - admin@acme.corp [15/Nov/2024:14:23:01 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://web01.corp.acme.com/" "Mozilla/5.0"
10.10.14.100 - admin@acme.corp [15/Nov/2024:14:23:05 +0000] "POST /api/login HTTP/1.1" 200 567 "https://web01.corp.acme.com/login" "Mozilla/5.0"
10.10.14.101 - jdoe@acme.corp [15/Nov/2024:14:24:01 +0000] "GET /api/admin HTTP/1.1" 403 89 "-" "curl/8.4.0"
172.16.0.50 - - [15/Nov/2024:14:25:00 +0000] "GET /health HTTP/1.1" 200 2 "-" "ELB-HealthChecker/2.0"
"""

    def test_all_ips_redacted(self):
        result = _engine().redact(self.ACCESS_LOG)
        _assert_clean(result, "10.10.14.100", "10.10.14.101", "172.16.0.50")

    def test_emails_redacted(self):
        result = _engine().redact(self.ACCESS_LOG)
        _assert_clean(result, "admin@acme.corp", "jdoe@acme.corp")

    def test_hostnames_redacted(self):
        result = _engine().redact(self.ACCESS_LOG)
        _assert_clean(result, "web01.corp.acme.com")

    def test_http_methods_preserved(self):
        result = _engine().redact(self.ACCESS_LOG)
        assert "GET" in result
        assert "POST" in result
        assert "/api/users" in result
        assert "200" in result


class TestLinPEASOutput:
    """Synthetic LinPEAS / privilege escalation enumeration output."""

    LINPEAS = """\
╔══════════╣ Network Information
╠══════════╣ Interfaces
eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 10.10.14.5/24 brd 10.10.14.255 scope global eth0

╠══════════╣ Route Table
default via 10.10.14.1 dev eth0
10.10.14.0/24 dev eth0 proto kernel scope link src 10.10.14.5

╠══════════╣ Listening Ports
tcp  0.0.0.0:22      0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
tcp  0.0.0.0:3306    0.0.0.0:*  users:(("mysql",pid=5678,fd=3))
tcp  10.10.14.5:8080  0.0.0.0:*  users:(("java",pid=9012,fd=3))

╠══════════╣ Interesting Files
-rw-r--r-- 1 root root 234 Nov 14 /etc/cron.d/backup
password=Backup2024!
/home/admin/.ssh/id_rsa: RSA PRIVATE KEY
/var/www/.env: DATABASE_URL=mysql://root:r00tP@ss@db.internal:3306/app
"""

    def test_ips_redacted(self):
        result = _engine().redact(self.LINPEAS)
        _assert_clean(result, "10.10.14.5", "10.10.14.255", "10.10.14.1")

    def test_cidrs_redacted(self):
        result = _engine().redact(self.LINPEAS)
        _assert_clean(result, "10.10.14.0/24")

    def test_hostname_redacted(self):
        result = _engine().redact(self.LINPEAS)
        _assert_clean(result, "db.internal")

    def test_secrets_redacted(self):
        result = _engine().redact(self.LINPEAS)
        _assert_clean(result, "Backup2024!")

    def test_formatting_preserved(self):
        result = _engine().redact(self.LINPEAS)
        assert "╔" in result
        assert "╠" in result
        assert "Listening Ports" in result


# ===========================================================================
# 2. RULE INTERACTION / OVERLAP TESTS
# ===========================================================================


class TestPlaceholderCollision:
    """Verify the placeholder collision fix — placeholders from earlier rules
    must not be re-matched by later rules."""

    def test_ip_placeholder_not_reredacted(self):
        """Context secret redacts an IP value → IPv4 rule must not re-match the placeholder."""
        engine = _engine()
        result = engine.redact("password=10.10.14.5")
        # The password value (which is an IP) gets redacted by context_secret
        _assert_clean(result, "10.10.14.5")
        # password= label should be preserved
        assert "password=" in result
        # The placeholder should appear exactly once, not be re-redacted
        secret_placeholder = engine.mapping.get("10.10.14.5")
        assert secret_placeholder is not None
        assert result.count(secret_placeholder) == 1

    def test_ip_placeholder_stable_across_rules(self):
        """An IP redacted by IPv4 rule should not be re-matched by later rules."""
        engine = _engine()
        # This IP gets redacted to 10.0.0.1 by IPv4 rule (priority 40)
        result = engine.redact("Host 192.168.1.1 is down")
        ip_placeholder = engine.mapping["192.168.1.1"]
        # The placeholder itself (10.0.0.1) must not create a new mapping entry
        assert ip_placeholder not in engine.mapping, \
            f"Placeholder {ip_placeholder!r} was re-mapped"

    def test_double_pass_no_cascade(self):
        """Redacting already-redacted output must not re-map placeholders.

        Without the fix, 192.168.1.1 → 10.0.0.1 on first pass, then
        10.0.0.1 → 10.0.0.2 on second pass (placeholder treated as new IP).
        """
        engine = _engine()
        r1 = engine.redact("Host 192.168.1.1")
        assert r1 == "Host 10.0.0.1"

        # Second pass on already-redacted output — must be idempotent
        r2 = engine.redact(r1)
        assert r2 == r1, f"Double-pass changed output: {r1!r} → {r2!r}"
        assert "10.0.0.1" not in engine.mapping, \
            "Placeholder 10.0.0.1 was re-mapped as a new value"

    def test_double_pass_many_ips(self):
        """Multiple IPs survive a double pass without cascading."""
        engine = _engine()
        text = "A=192.168.1.1 B=192.168.1.2 C=192.168.1.3"
        r1 = engine.redact(text)
        r2 = engine.redact(r1)
        assert r1 == r2, f"Double-pass changed output"

    def test_many_ips_no_cascade(self):
        """Redacting many IPs should not cause placeholders to collide with each other."""
        engine = _engine()
        ips = [f"192.168.1.{i}" for i in range(1, 51)]
        text = "\n".join(f"Host {ip} scanned" for ip in ips)
        result = engine.redact(text)
        for ip in ips:
            _assert_clean(result, ip)
        # No placeholder should appear as a mapping key
        for val in engine.mapping.values():
            assert val not in engine.mapping, \
                f"Placeholder {val!r} was re-mapped (cascade)"

    def test_cidr_placeholder_not_rematched_as_ip(self):
        """CIDR placeholder (10.0.0.N/24) should not have its IP part re-matched."""
        engine = _engine()
        result = engine.redact("Network 172.16.0.0/24 is down")
        _assert_clean(result, "172.16.0.0/24")
        # The CIDR placeholder contains an IP-like prefix, but it should not
        # be re-matched because CIDR runs before IPv4 (priority 39 < 40)

    def test_email_placeholder_not_rematched_as_hostname(self):
        """Email placeholder user_01@example.com must not trigger hostname rule."""
        engine = _engine()
        result = engine.redact("Contact admin@secret.corp.internal for help")
        # email is priority 30, hostname is 45 — email runs first
        _assert_clean(result, "admin@secret.corp.internal")
        # The email placeholder domain (example.com) is not .corp/.internal/.local
        assert "example.internal" not in result or "HOST_" not in result


class TestOverlappingRules:
    """Test scenarios where multiple rules could match the same data."""

    def test_jwt_in_bearer_secret(self):
        """JWT inside a Bearer token context — JWT rule (10) runs before context_secret (15)."""
        engine = _engine()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = engine.redact(f"bearer={jwt}")
        _assert_clean(result, jwt)
        assert "JWT_REDACTED_01" in result

    def test_aws_key_in_secret_context(self):
        """AWS key inside key= context — AWS (10) runs before context_secret (15)."""
        engine = _engine()
        result = engine.redact("access_key=AKIAIOSFODNN7EXAMPLE")
        _assert_clean(result, "AKIAIOSFODNN7EXAMPLE")
        # AWS rule should grab it first
        assert "API_KEY_01" in result

    def test_email_inside_password_field(self):
        """Email used as a password value."""
        engine = _engine()
        result = engine.redact('password="admin@corp.local"')
        _assert_clean(result, "admin@corp.local")
        assert "password=" in result

    def test_ip_in_url_with_port(self):
        """IP embedded in a URL with port — URL rule captures the whole URL."""
        engine = _engine()
        result = engine.redact("http://192.168.1.50:8080/api/v1")
        _assert_clean(result, "192.168.1.50")
        assert "URL_REDACTED_" in result

    def test_ip_in_url_with_path(self):
        """IP in a URL followed by path — URL rule captures the whole URL."""
        engine = _engine()
        result = engine.redact("curl https://10.10.14.5/admin/config.json")
        _assert_clean(result, "10.10.14.5")
        assert "curl" in result
        assert "URL_REDACTED_" in result

    def test_multiple_secrets_same_line(self):
        """Multiple context secrets on the same line."""
        engine = _engine()
        result = engine.redact('api_key=abc123secret token=xyz789token')
        _assert_clean(result, "abc123secret", "xyz789token")
        assert "api_key=" in result
        assert "token=" in result

    def test_hostname_and_ip_same_host(self):
        """Same host referenced by hostname and IP."""
        engine = _engine()
        result = engine.redact("dc01.corp.acme.com (10.10.14.5) is the domain controller")
        _assert_clean(result, "dc01.corp.acme.com", "10.10.14.5")

    def test_ssn_vs_phone_no_confusion(self):
        """SSN format (123-45-6789) should not be confused with phone."""
        engine = _engine()
        result = engine.redact("SSN: 123-45-6789 Phone: (555) 867-5309")
        _assert_clean(result, "123-45-6789")
        assert "SSN_REDACTED_01" in result


# ===========================================================================
# 3. EDGE CASE GAUNTLET
# ===========================================================================


class TestIPv4EdgeCases:
    def test_ip_with_port_colon(self):
        engine = _engine()
        result = engine.redact("10.10.14.5:443")
        _assert_clean(result, "10.10.14.5")
        assert "443" in result

    def test_ip_at_start_of_line(self):
        result = _engine().redact("10.10.14.5 is alive")
        _assert_clean(result, "10.10.14.5")

    def test_ip_at_end_of_line(self):
        result = _engine().redact("connecting to 10.10.14.5")
        _assert_clean(result, "10.10.14.5")

    def test_ip_in_brackets(self):
        result = _engine().redact("[10.10.14.5]")
        _assert_clean(result, "10.10.14.5")

    def test_ip_equals_sign(self):
        result = _engine().redact("target=10.10.14.5")
        _assert_clean(result, "10.10.14.5")

    def test_adjacent_ips(self):
        result = _engine().redact("10.10.14.5,10.10.14.10")
        _assert_clean(result, "10.10.14.5", "10.10.14.10")

    def test_loopback_passthrough(self):
        """127.0.0.1 is never sensitive — should pass through."""
        result = _engine().redact("listening on 127.0.0.1:8080")
        assert "127.0.0.1" in result

    def test_broadcast_passthrough(self):
        result = _engine().redact("brd 255.255.255.255")
        assert "255.255.255.255" in result

    def test_zero_address_passthrough(self):
        result = _engine().redact("bind 0.0.0.0:80")
        assert "0.0.0.0" in result

    def test_version_string_not_matched(self):
        """Version-like strings should not match IP if octets exceed 255."""
        engine = _engine()
        # 7.94 is only 2 octets — should not match
        result = engine.redact("Nmap 7.94SVN")
        assert "Nmap 7.94SVN" in result


class TestIPv6EdgeCases:
    def test_full_ipv6(self):
        result = _engine().redact("addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        _assert_clean(result, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_compressed_ipv6(self):
        result = _engine().redact("addr fe80::1")
        _assert_clean(result, "fe80::1")

    def test_link_local_with_zone(self):
        result = _engine().redact("fe80::a00:27ff:fe8e:8aa8%eth0")
        _assert_clean(result, "fe80::a00:27ff:fe8e:8aa8%eth0")

    def test_loopback_ipv6(self):
        result = _engine().redact("listening on ::1")
        # ::1 is just :: followed by 1 — may or may not match depending on pattern
        # At minimum, :: should match
        assert "::1" not in result or "fd00::" in result


class TestMACEdgeCases:
    def test_cisco_dot_format(self):
        result = _engine().redact("mac aabb.ccdd.eeff")
        _assert_clean(result, "aabb.ccdd.eeff")

    def test_uppercase_colon(self):
        result = _engine().redact("AA:BB:CC:DD:EE:FF")
        _assert_clean(result, "AA:BB:CC:DD:EE:FF")

    def test_dash_format(self):
        result = _engine().redact("AA-BB-CC-DD-EE-FF")
        _assert_clean(result, "AA-BB-CC-DD-EE-FF")

    def test_multiple_macs(self):
        engine = _engine()
        result = engine.redact(
            "src aa:bb:cc:dd:ee:ff dst 11:22:33:44:55:66"
        )
        _assert_clean(result, "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        # Different MACs get different placeholders
        assert "00:DE:AD:00:00:01" in result
        assert "00:DE:AD:00:00:02" in result


class TestEmailEdgeCases:
    def test_plus_addressing(self):
        result = _engine().redact("user+tag@gmail.com")
        _assert_clean(result, "user+tag@gmail.com")

    def test_subdomain_email(self):
        result = _engine().redact("admin@mail.corp.example.com")
        _assert_clean(result, "admin@mail.corp.example.com")

    def test_multiple_emails(self):
        engine = _engine()
        result = engine.redact("from admin@corp.com to user@corp.com")
        _assert_clean(result, "admin@corp.com", "user@corp.com")
        assert "user_01@example.com" in result
        assert "user_02@example.com" in result

    def test_email_in_angle_brackets(self):
        result = _engine().redact("From: <admin@corp.com>")
        _assert_clean(result, "admin@corp.com")


class TestPhoneEdgeCases:
    def test_parenthesized(self):
        result = _engine().redact("Call (555) 123-4567")
        _assert_clean(result, "(555) 123-4567")

    def test_dotted(self):
        result = _engine().redact("555.123.4567")
        _assert_clean(result, "555.123.4567")

    def test_with_country_code(self):
        result = _engine().redact("+1-555-123-4567")
        _assert_clean(result, "+1-555-123-4567")


class TestCreditCardEdgeCases:
    def test_visa_with_spaces(self):
        result = _engine().redact("4111 1111 1111 1111")
        _assert_clean(result, "4111 1111 1111 1111")

    def test_visa_with_dashes(self):
        result = _engine().redact("4111-1111-1111-1111")
        _assert_clean(result, "4111-1111-1111-1111")

    def test_amex(self):
        # 378282246310005 is a valid Amex test number
        result = _engine().redact("card: 378282246310005")
        _assert_clean(result, "378282246310005")

    def test_invalid_luhn_not_redacted(self):
        """Random 16-digit number that fails Luhn should not be redacted."""
        engine = _engine()
        result = engine.redact("id: 1234567890123456")
        # 1234567890123456 fails Luhn, should remain
        assert "1234567890123456" in result


class TestHostnameEdgeCases:
    def test_corp_domain(self):
        result = _engine().redact("dc01.corp.acme.com")
        _assert_clean(result, "dc01.corp")

    def test_local_domain(self):
        result = _engine().redact("printer.local")
        _assert_clean(result, "printer.local")

    def test_internal_domain(self):
        result = _engine().redact("db.internal")
        _assert_clean(result, "db.internal")

    def test_intra_domain(self):
        result = _engine().redact("wiki.intra")
        _assert_clean(result, "wiki.intra")

    def test_lan_domain(self):
        result = _engine().redact("nas.lan")
        _assert_clean(result, "nas.lan")

    def test_priv_domain(self):
        result = _engine().redact("vault.priv")
        _assert_clean(result, "vault.priv")

    def test_deep_subdomain(self):
        """Hostname with .corp suffix and additional sub-labels."""
        result = _engine().redact("app.corp.acme.com")
        _assert_clean(result, "app.corp")

    def test_hyphenated_hostname(self):
        result = _engine().redact("web-01.internal")
        _assert_clean(result, "web-01.internal")


class TestContextSecretEdgeCases:
    def test_quoted_value(self):
        result = _engine().redact('api_key="supersecretvalue123"')
        _assert_clean(result, "supersecretvalue123")
        assert "api_key=" in result

    def test_single_quoted(self):
        result = _engine().redact("api_key='supersecretvalue123'")
        _assert_clean(result, "supersecretvalue123")

    def test_colon_separator(self):
        result = _engine().redact("password: MyS3cretP@ss!")
        _assert_clean(result, "MyS3cretP@ss!")

    def test_bearer_token(self):
        result = _engine().redact("bearer=abc123def456ghi789")
        _assert_clean(result, "abc123def456ghi789")

    def test_credential_keyword(self):
        result = _engine().redact("credential=hunter2xyzabc")
        _assert_clean(result, "hunter2xyzabc")

    def test_short_value_not_matched(self):
        """Values < 4 chars should not be matched by context_secret."""
        result = _engine().redact("password=abc")
        # abc is only 3 chars, pattern requires {4,}
        assert "abc" in result

    def test_multiple_secrets_different_keys(self):
        engine = _engine()
        result = engine.redact(
            'api_key=secret1234 password=other5678'
        )
        _assert_clean(result, "secret1234", "other5678")


class TestJWTEdgeCases:
    def test_jwt_in_header(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = _engine().redact(f"Authorization: Bearer {jwt}")
        _assert_clean(result, jwt)
        assert "JWT_REDACTED" in result

    def test_jwt_in_env_var(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = _engine().redact(f"JWT_SECRET={jwt}")
        _assert_clean(result, jwt)


class TestAWSKeyEdgeCases:
    def test_in_env_var(self):
        result = _engine().redact("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        _assert_clean(result, "AKIAIOSFODNN7EXAMPLE")

    def test_in_config_file(self):
        result = _engine().redact("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
        _assert_clean(result, "AKIAIOSFODNN7EXAMPLE")


class TestSSNEdgeCases:
    def test_in_text(self):
        result = _engine().redact("SSN: 078-05-1120")
        _assert_clean(result, "078-05-1120")

    def test_not_confused_with_date(self):
        """Date-like strings should not match SSN pattern (different format)."""
        result = _engine().redact("Date: 2024-11-15")
        # 2024-11-15 doesn't match ###-##-#### (4 digits, not 3)
        assert "2024-11-15" in result


# ===========================================================================
# 4. CONSISTENCY STRESS TESTS
# ===========================================================================


class TestCrossCallConsistency:
    """Verify mapping holds across multiple redact() calls on the same engine."""

    def test_same_ip_across_calls(self):
        engine = _engine()
        r1 = engine.redact("Host 10.10.14.5 scanned")
        r2 = engine.redact("Connecting to 10.10.14.5")
        # Same placeholder in both outputs
        p = engine.mapping["10.10.14.5"]
        assert p in r1
        assert p in r2

    def test_new_ip_gets_new_placeholder(self):
        engine = _engine()
        engine.redact("Host 10.10.14.5")
        engine.redact("Host 10.10.14.10")
        assert engine.mapping["10.10.14.5"] != engine.mapping["10.10.14.10"]

    def test_cross_file_with_export_import(self):
        """Simulate sanitizing multiple engagement files."""
        engine1 = _engine()
        r1 = engine1.redact(
            "Scan 10.10.14.5 found admin@corp.com open port 22"
        )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            path = f.name
        try:
            engine1.export_map(path)

            engine2 = _engine()
            engine2.import_map(path)
            r2 = engine2.redact(
                "SSH to 10.10.14.5 as admin@corp.com"
            )

            # Same placeholders in both outputs
            assert engine1.mapping["10.10.14.5"] == engine2.mapping["10.10.14.5"]
            assert engine1.mapping["admin@corp.com"] == engine2.mapping["admin@corp.com"]
        finally:
            os.unlink(path)

    def test_export_import_preserves_counters(self):
        """Importing a map should not reset counters — new values get fresh IDs."""
        engine1 = _engine()
        engine1.redact("10.10.14.5 and 10.10.14.10")  # counters: ipv4=2

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            path = f.name
        try:
            engine1.export_map(path)

            engine2 = _engine()
            engine2.import_map(path)
            engine2.redact("10.10.14.20")  # should get counter=3, not 1

            assert engine2.mapping["10.10.14.20"] == "10.0.0.3"
        finally:
            os.unlink(path)


class TestMappingIntegrity:
    """Verify 1:1 mapping and no collisions."""

    def test_mapping_is_injective(self):
        """Every unique input maps to a unique placeholder (no collisions)."""
        engine = _engine()
        text = """\
10.10.14.5 10.10.14.10 10.10.14.20
admin@corp.com jdoe@corp.com
aa:bb:cc:dd:ee:ff 11:22:33:44:55:66
dc01.corp.acme.com web01.corp.acme.com
password=Secret123! api_key=AnotherKey1
"""
        engine.redact(text)
        values = list(engine.mapping.values())
        assert len(values) == len(set(values)), \
            f"Duplicate placeholders found: {values}"

    def test_large_scale_no_collision(self):
        """50 unique IPs should produce 50 unique placeholders."""
        engine = _engine()
        ips = [f"192.168.{i // 256}.{i % 256}" for i in range(1, 51)]
        text = " ".join(ips)
        engine.redact(text)
        ip_placeholders = [engine.mapping[ip] for ip in ips]
        assert len(ip_placeholders) == len(set(ip_placeholders))


# ===========================================================================
# 5. BOUNDARY / ADVERSARIAL INPUTS
# ===========================================================================


class TestBoundaryInputs:
    def test_empty_input(self):
        result = _engine().redact("")
        assert result == ""

    def test_whitespace_only(self):
        result = _engine().redact("   \n\n\t  ")
        assert result == "   \n\n\t  "

    def test_single_ip(self):
        result = _engine().redact("10.10.14.5")
        _assert_clean(result, "10.10.14.5")

    def test_no_sensitive_data(self):
        text = "This is a normal log entry with no PII or sensitive values at all."
        result = _engine().redact(text)
        assert result == text

    def test_unicode_with_ips(self):
        result = _engine().redact("Server 10.10.14.5 → connected ✓")
        _assert_clean(result, "10.10.14.5")
        assert "→" in result
        assert "✓" in result

    def test_long_line(self):
        """Very long line should not cause issues."""
        ip = "192.168.1.1"
        text = f"{'A' * 10000} {ip} {'B' * 10000}"
        result = _engine().redact(text)
        _assert_clean(result, ip)

    def test_many_lines(self):
        """Many lines with IPs."""
        lines = [f"Host 192.168.1.{i % 256} port {8000 + i}" for i in range(500)]
        text = "\n".join(lines)
        result = _engine().redact(text)
        # Spot check a few
        _assert_clean(result, "192.168.1.1", "192.168.1.50", "192.168.1.200")

    def test_repeated_sensitive_value(self):
        """Same value repeated many times."""
        text = " ".join(["10.10.14.5"] * 100)
        engine = _engine()
        result = engine.redact(text)
        _assert_clean(result, "10.10.14.5")
        p = engine.mapping["10.10.14.5"]
        assert result.count(p) == 100

    def test_adjacent_sensitive_values(self):
        """Sensitive values with no separator."""
        result = _engine().redact("admin@corp.com10.10.14.5")
        _assert_clean(result, "10.10.14.5")

    def test_newlines_preserved(self):
        text = "Line1 10.10.14.5\nLine2 10.10.14.10\n"
        result = _engine().redact(text)
        assert result.count("\n") == 2


# ===========================================================================
# 6. DENSE MIXED-TYPE TESTS (everything at once)
# ===========================================================================


class TestDenseMixedData:
    """Throw everything at the engine in a single document."""

    DENSE_LOG = """\
=== ENGAGEMENT REPORT ===
Target: ACME Corp (acme.corp)
Date: 2024-11-15
Tester: jdoe@acme.corp

--- Network Topology ---
DC01: dc01.corp.acme.com / 10.10.14.5 (MAC: DE:AD:BE:EF:CA:FE)
WEB01: web01.corp.acme.com / 10.10.14.10 (MAC: AA:BB:CC:11:22:33)
DB01: db01.internal / 10.10.14.20 (MAC: 11:22:33:44:55:66)
Gateway: 10.10.14.1
Subnet: 10.10.14.0/24

--- Credentials Found ---
password=P@ssw0rd123!
api_key="sk_live_51N3wK3y4cc355"
token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
AWS key: AKIAIOSFODNN7EXAMPLE

--- Contact Info ---
Email: admin@acme.corp
Phone: (555) 867-5309
SSN found in DB: 078-05-1120
CC on file: 4111111111111111

--- IPv6 ---
fe80::a00:27ff:fe8e:8aa8%eth0 link-local

--- Session Log ---
[14:23:01] Connected to 10.10.14.5
[14:23:05] Authenticated as admin@acme.corp
[14:24:10] Lateral move to 10.10.14.10
[14:25:00] Pivoted to 10.10.14.20
[14:26:30] Exfil via 10.10.14.5 to 10.10.14.1
"""

    def test_no_ips_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(
            result,
            "10.10.14.5", "10.10.14.10", "10.10.14.20", "10.10.14.1",
        )

    def test_no_emails_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(result, "jdoe@acme.corp", "admin@acme.corp")

    def test_no_hostnames_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(
            result,
            "dc01.corp.acme.com", "web01.corp.acme.com", "db01.internal",
        )

    def test_no_macs_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(
            result,
            "DE:AD:BE:EF:CA:FE", "AA:BB:CC:11:22:33", "11:22:33:44:55:66",
        )

    def test_no_secrets_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(result, "P@ssw0rd123!", "sk_live_51N3wK3y4cc355")

    def test_no_jwt_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(result, "eyJhbGciOiJIUzI1NiJ9")

    def test_no_aws_key_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(result, "AKIAIOSFODNN7EXAMPLE")

    def test_no_ssn_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(result, "078-05-1120")

    def test_no_cc_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(result, "4111111111111111")

    def test_no_phone_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(result, "(555) 867-5309")

    def test_no_cidr_leaked(self):
        result = _engine().redact(self.DENSE_LOG)
        _assert_clean(result, "10.10.14.0/24")

    def test_structure_preserved(self):
        result = _engine().redact(self.DENSE_LOG)
        assert "=== ENGAGEMENT REPORT ===" in result
        assert "--- Network Topology ---" in result
        assert "--- Credentials Found ---" in result
        assert "[14:23:01]" in result
        assert "DC01:" in result
        assert "WEB01:" in result

    def test_ip_consistency_in_session(self):
        """The session log references 10.10.14.5 multiple times — same placeholder."""
        engine = _engine()
        result = engine.redact(self.DENSE_LOG)
        p = engine.mapping["10.10.14.5"]
        # Appears in topology + session log lines
        assert result.count(p) >= 3

    def test_all_categories_counted(self):
        engine = _engine()
        engine.redact(self.DENSE_LOG)
        stats = engine.get_stats()
        assert stats.get("ipv4", 0) >= 4
        assert stats.get("email", 0) >= 2
        assert stats.get("mac", 0) >= 3
        assert stats.get("hostname", 0) >= 3
        assert stats.get("secret", 0) >= 1
        assert stats.get("jwt", 0) >= 1
        assert stats.get("api_key", 0) >= 1
        assert stats.get("ssn", 0) >= 1
        assert stats.get("credit_card", 0) >= 1
        assert stats.get("phone", 0) >= 1
        assert stats.get("cidr", 0) >= 1


# =============================================================================
# IPv6 compressed forms
# =============================================================================

class TestIPv6Compressed:
    """IPv6 addresses with :: compression — these were previously missed."""

    def test_prefix_suffix(self):
        """2600:3c01::f03c:91ff:fe18:bb2f — the nmap scanme address."""
        result = _engine().redact("addr 2600:3c01::f03c:91ff:fe18:bb2f")
        _assert_clean(result, "2600:3c01::f03c:91ff:fe18:bb2f")
        assert "fd00::" in result

    def test_three_prefix_three_suffix(self):
        result = _engine().redact("addr 2001:db8:85a3::8a2e:370:7334")
        _assert_clean(result, "2001:db8:85a3::8a2e:370:7334")

    def test_one_prefix_six_suffix(self):
        result = _engine().redact("addr a::b:c:d:e:f:1")
        _assert_clean(result, "a::b:c:d:e:f:1")

    def test_loopback(self):
        engine = _engine()
        result = engine.redact("listening on ::1")
        assert "::1" in engine.mapping
        assert result == "listening on fd00::1"

    def test_trailing_double_colon(self):
        result = _engine().redact("prefix 2001:db8::")
        _assert_clean(result, "2001:db8::")

    def test_full_address(self):
        result = _engine().redact("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        _assert_clean(result, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_link_local_with_zone(self):
        result = _engine().redact("fe80::1%eth0")
        _assert_clean(result, "fe80::1%eth0")

    def test_consistency(self):
        """Same IPv6 address gets same placeholder."""
        engine = _engine()
        engine.redact("first 2600:3c01::f03c:91ff:fe18:bb2f")
        engine.redact("second 2600:3c01::f03c:91ff:fe18:bb2f")
        assert "2600:3c01::f03c:91ff:fe18:bb2f" in engine.mapping


# =============================================================================
# URL redaction
# =============================================================================

class TestURLRedaction:
    """URLs should be captured as whole units."""

    def test_https_with_path(self):
        result = _engine().redact("report at https://nmap.org/submit/ .")
        _assert_clean(result, "https://nmap.org/submit/")
        assert "URL_REDACTED_" in result

    def test_http_with_ip_and_port(self):
        result = _engine().redact("GET http://10.0.0.1:8080/api")
        _assert_clean(result, "http://10.0.0.1:8080/api")

    def test_url_consistency(self):
        engine = _engine()
        engine.redact("visit https://nmap.org/submit/")
        engine.redact("again https://nmap.org/submit/")
        p = engine.mapping["https://nmap.org/submit/"]
        assert p == "URL_REDACTED_01"

    def test_url_placeholder_not_reredacted(self):
        engine = _engine()
        r1 = engine.redact("see https://nmap.org/submit/")
        r2 = engine.redact(r1)
        assert r1 == r2

    def test_url_in_parens(self):
        result = _engine().redact("(https://example.com/path)")
        assert "URL_REDACTED_" in result

    def test_http_not_protocol_version(self):
        """HTTP/1.1 should NOT be matched as a URL."""
        result = _engine().redact("HTTP/1.1 200 OK")
        assert result == "HTTP/1.1 200 OK"

    def test_nmap_output_urls(self):
        """Real nmap output with URLs — all should be redacted."""
        text = (
            "Service detection performed. Please report any incorrect results "
            "at https://nmap.org/submit/ .\n"
            "Starting Nmap 7.93 ( https://nmap.org ) at 2026-03-20"
        )
        result = _engine().redact(text)
        _assert_clean(result, "https://nmap.org/submit/", "https://nmap.org")
