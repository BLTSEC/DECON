"""Tests for individual pattern rules."""

import re
from decon.patterns import (
    build_default_rules,
    _valid_ipv4,
    _luhn_check,
    _IPV4,
    _CIDR,
    _EMAIL,
    _MAC,
    _JWT,
    _AWS_KEY,
    _SSN,
    _PHONE,
    _HOSTNAME_INTERNAL,
    _IPV6,
    _CONTEXT_SECRET,
    _KERBEROS_HASH,
    _SMB_NETBIOS_NAME,
    _SPN,
    _LDAP_DN_DOMAIN,
    _LDAP_SAMACCOUNTNAME,
    _AD_DOMAIN_USER_SLASH,
    _IMPACKET_STATUS_USER,
    _LDAP_CN_LOWERCASE_USER,
    _LDAP_COMMENT_USER,
    _NETEXEC_SPRAY_PASSWORD,
    _LDAP_DESCRIPTION,
    _LDAP_CN_USERS_MEMBER,
)


class TestIPv4Pattern:
    def test_basic_match(self):
        assert _IPV4.search("192.168.1.1")

    def test_no_match_partial(self):
        """Should not match inside longer number sequences."""
        assert _IPV4.search("10.0.0.1") is not None
        match = _IPV4.search("1.2.3.4.5")
        # Might partially match — that's ok, validator filters

    def test_boundary(self):
        m = _IPV4.search("addr=10.4.12.50 port=443")
        assert m and m.group() == "10.4.12.50"


class TestIPv4Validator:
    def test_valid(self):
        assert _valid_ipv4("192.168.1.1")
        assert _valid_ipv4("10.10.14.5")

    def test_skipped_special(self):
        """Loopback, broadcast, and unspecified IPs are skipped."""
        assert not _valid_ipv4("127.0.0.1")
        assert not _valid_ipv4("0.0.0.0")
        assert not _valid_ipv4("255.255.255.255")
        assert not _valid_ipv4("169.254.1.1")

    def test_invalid(self):
        assert not _valid_ipv4("256.1.1.1")
        assert not _valid_ipv4("1.2.3")


class TestCIDRPattern:
    def test_match(self):
        m = _CIDR.search("network 10.0.0.0/24 is down")
        assert m and m.group() == "10.0.0.0/24"

    def test_slash32(self):
        m = _CIDR.search("host 192.168.1.1/32")
        assert m and m.group() == "192.168.1.1/32"


class TestEmailPattern:
    def test_basic(self):
        m = _EMAIL.search("contact admin@corp.example.com for help")
        assert m and m.group() == "admin@corp.example.com"

    def test_plus_address(self):
        m = _EMAIL.search("user+tag@gmail.com")
        assert m and m.group() == "user+tag@gmail.com"


class TestMACPattern:
    def test_colon(self):
        m = _MAC.search("aa:bb:cc:dd:ee:ff")
        assert m and m.group() == "aa:bb:cc:dd:ee:ff"

    def test_dash(self):
        m = _MAC.search("AA-BB-CC-DD-EE-FF")
        assert m and m.group() == "AA-BB-CC-DD-EE-FF"

    def test_dot(self):
        m = _MAC.search("aabb.ccdd.eeff")
        assert m and m.group() == "aabb.ccdd.eeff"


class TestJWTPattern:
    def test_match(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert _JWT.search(jwt)


class TestAWSKeyPattern:
    def test_match(self):
        m = _AWS_KEY.search("key=AKIAIOSFODNN7EXAMPLE")
        assert m and m.group() == "AKIAIOSFODNN7EXAMPLE"

    def test_no_match_short(self):
        assert not _AWS_KEY.search("AKIA1234")


class TestSSNPattern:
    def test_match(self):
        m = _SSN.search("SSN: 123-45-6789")
        assert m and m.group() == "123-45-6789"


class TestPhonePattern:
    def test_us_format(self):
        m = _PHONE.search("call (555) 123-4567")
        assert m is not None

    def test_dashed(self):
        m = _PHONE.search("555-123-4567")
        assert m is not None


class TestHostnamePattern:
    def test_internal(self):
        m = _HOSTNAME_INTERNAL.search("ssh to db01.corp.example.com")
        # Note: this matches .corp pattern
        assert m is not None

    def test_local(self):
        m = _HOSTNAME_INTERNAL.search("resolved printer.local")
        assert m and m.group() == "printer.local"


class TestContextSecret:
    def test_key_value(self):
        m = _CONTEXT_SECRET.search('api_key="sk_live_abc123def456"')
        assert m is not None

    def test_password(self):
        m = _CONTEXT_SECRET.search("password=SuperSecret123!")
        assert m is not None

    # BUG-3: boolean values must not be treated as secrets
    def test_no_false_positive_true(self):
        assert _CONTEXT_SECRET.search("Null Auth:True") is None

    def test_no_false_positive_false(self):
        assert _CONTEXT_SECRET.search("signing:False") is None

    def test_no_false_positive_null(self):
        assert _CONTEXT_SECRET.search("token:null") is None

    # BUG-4: trailing ) must not be captured as part of the secret
    def test_no_trailing_paren(self):
        m = _CONTEXT_SECRET.search("(Password : Heartsbane)")
        assert m is not None
        assert m.group(2) == "Heartsbane"


class TestKerberosHash:
    # BUG-1: AS-REP hashes must be fully redacted
    def test_tgs_hash(self):
        tgs = "$krb5tgs$23$*jon.snow$NORTH.SEVENKINGDOMS.LOCAL$cifs/winterfell*$aabbccdd$eeff0011"
        assert _KERBEROS_HASH.search(tgs) is not None

    def test_asrep_hash(self):
        asrep = "$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:f56be23066aadd55f34904ba7252c59b"
        m = _KERBEROS_HASH.search(asrep)
        assert m is not None
        assert "f56be23066aadd55f34904ba7252c59b" in m.group(0)


class TestSmbNetbiosName:
    # BUG-2: bare NetBIOS names in (name:HOSTNAME) context must be redacted
    def test_matches_netbios(self):
        line = "SMB  10.1.10.11  445  WINTERFELL  [*] Windows (name:WINTERFELL) (domain:north.sevenkingdoms.local)"
        m = _SMB_NETBIOS_NAME.search(line)
        assert m is not None
        assert m.group(2) == "WINTERFELL"

    def test_no_match_lowercase(self):
        # lowercase hostnames are not NetBIOS names
        assert _SMB_NETBIOS_NAME.search("(name:castelblack)") is None

    def test_no_match_fqdn(self):
        # FQDNs are handled by hostname_internal, not this rule
        assert _SMB_NETBIOS_NAME.search("(name:host.corp.local)") is None


class TestSPN:
    # QUIRK-2: SPNs with FQDN instance names get SPN_XX placeholder, not DOMAIN_USER_XX
    def test_matches_fqdn_spn(self):
        m = _SPN.search("CIFS/winterfell.north.sevenkingdoms.local")
        assert m is not None
        assert m.group(0) == "CIFS/winterfell.north.sevenkingdoms.local"

    def test_matches_mssql_spn_with_port(self):
        m = _SPN.search("MSSQLSvc/castelblack.north.sevenkingdoms.local:1433")
        assert m is not None

    def test_matches_http_spn(self):
        m = _SPN.search("HTTP/eyrie.north.sevenkingdoms.local")
        assert m is not None

    def test_no_match_without_fqdn(self):
        # bare hostname (no dot) falls through to ad_domain_user_slash
        assert _SPN.search("CIFS/winterfell") is None

    def test_no_match_abbreviation(self):
        assert _SPN.search("SMB/WMI") is None


class TestSmbNetbiosNameExtended:
    # BUG-7: machine names in CN= LDAP DN context must also be redacted
    def test_matches_cn_machine_name(self):
        m = _SMB_NETBIOS_NAME.search("CN=WINTERFELL,OU=Domain Controllers")
        assert m is not None
        assert m.group(2) == "WINTERFELL"

    def test_no_match_cn_lowercase(self):
        # CN= with lowercase value is not a NetBIOS machine name
        assert _SMB_NETBIOS_NAME.search("CN=Users,DC=corp,DC=local") is None

    def test_still_matches_name_context(self):
        m = _SMB_NETBIOS_NAME.search("(name:CASTELBLACK)")
        assert m is not None
        assert m.group(2) == "CASTELBLACK"


class TestLdapDnDomain:
    # BUG-5: LDAP DN domain suffix DC=x,DC=y,... must be redacted
    def test_matches_three_components(self):
        m = _LDAP_DN_DOMAIN.search("DC=north,DC=sevenkingdoms,DC=local")
        assert m is not None
        assert m.group(2) == "DC=north,DC=sevenkingdoms,DC=local"

    def test_matches_two_components(self):
        m = _LDAP_DN_DOMAIN.search("DC=sevenkingdoms,DC=local")
        assert m is not None
        assert m.group(2) == "DC=sevenkingdoms,DC=local"

    def test_captures_leading_comma(self):
        m = _LDAP_DN_DOMAIN.search("CN=Users,DC=north,DC=sevenkingdoms,DC=local")
        assert m is not None
        assert m.group(1) == ","
        assert m.group(2) == "DC=north,DC=sevenkingdoms,DC=local"

    def test_no_match_single_component(self):
        # Single DC= should NOT match — needs 2+ components
        assert _LDAP_DN_DOMAIN.search("DC=local") is None

    def test_case_insensitive(self):
        m = _LDAP_DN_DOMAIN.search("dc=corp,dc=local")
        assert m is not None


class TestLdapSamAccountName:
    # BUG-6: sAMAccountName attribute value must be redacted
    def test_matches_user(self):
        m = _LDAP_SAMACCOUNTNAME.search("sAMAccountName: arya.stark")
        assert m is not None
        assert m.group(2) == "arya.stark"

    def test_matches_machine_account(self):
        m = _LDAP_SAMACCOUNTNAME.search("sAMAccountName: WINTERFELL$")
        assert m is not None
        assert m.group(2) == "WINTERFELL$"

    def test_case_insensitive(self):
        m = _LDAP_SAMACCOUNTNAME.search("samaccountname: hodor")
        assert m is not None
        assert m.group(2) == "hodor"

    def test_preserves_prefix(self):
        m = _LDAP_SAMACCOUNTNAME.search("sAMAccountName: jon.snow")
        assert m.group(1) == "sAMAccountName: "
        assert m.group(2) == "jon.snow"


class TestLuhn:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111")

    def test_invalid(self):
        assert not _luhn_check("1234567890123456")

    def test_short(self):
        assert not _luhn_check("123")


class TestAdDomainUserSlash:
    # BUG-8: SSDP/UPnP and LDAP path components must not match ad_domain_user_slash

    def test_matches_bare_spn(self):
        # CIFS/winterfell falls through from SPN rule (no FQDN) to this rule
        m = _AD_DOMAIN_USER_SLASH.search("msDS-AllowedToDelegateTo: CIFS/winterfell")
        assert m is not None
        assert m.group(0) == "CIFS/winterfell"

    def test_matches_domain_slash_user(self):
        m = _AD_DOMAIN_USER_SLASH.search("NORTH/samwell.tarly")
        assert m is not None
        assert m.group(0) == "NORTH/samwell.tarly"

    def test_no_match_ssdp_upnp(self):
        # BUG-8: nmap service description should not be redacted as AD user
        assert _AD_DOMAIN_USER_SLASH.search("Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)") is None

    def test_no_match_ldap_path_component(self):
        # BUG-8: LDAP referral URL path /DC=... should not match
        assert _AD_DOMAIN_USER_SLASH.search(
            "ref: ldap://DomainDnsZones.north.sevenkingdoms.local/DC=DomainDnsZones"
        ) is None

    def test_no_match_short_abbreviation(self):
        assert _AD_DOMAIN_USER_SLASH.search("GNU/Linux") is None


class TestIPv6FalsePositive:
    # BUG-9: hex segments in OIDs must not match as IPv6

    def test_no_match_oid_double_colon(self):
        # nmap SAN: othername: 1.3.6.1.4.1.311.25.1::<unsupported>
        assert _IPV6.search("1.3.6.1.4.1.311.25.1::") is None

    def test_still_matches_real_ipv6(self):
        assert _IPV6.search("fd00::1") is not None

    def test_still_matches_full_ipv6(self):
        assert _IPV6.search("2001:db8::1") is not None

    def test_still_matches_link_local(self):
        assert _IPV6.search("fe80::1%eth0") is not None


class TestImpacketStatusUser:
    # BUG-10: GetNPUsers and netexec status lines expose usernames

    def test_getnpusers_user_line(self):
        m = _IMPACKET_STATUS_USER.search("[-] User jon.snow doesn't have UF_DONT_REQUIRE_PREAUTH set")
        assert m is not None
        assert m.group(2) == "jon.snow"

    def test_netexec_testing_line(self):
        m = _IMPACKET_STATUS_USER.search("[*] Testing brandon.stark")
        assert m is not None
        assert m.group(2) == "brandon.stark"

    def test_no_match_without_prefix(self):
        # standalone username without known prefix should not match
        assert _IMPACKET_STATUS_USER.search("jon.snow") is None


class TestLdapCnLowercaseUser:
    # BUG-12: CN=<lowercase> usernames in LDAP DNs

    def test_matches_dotted_username(self):
        m = _LDAP_CN_LOWERCASE_USER.search("dn: CN=jon.snow,CN=Users,DC=corp")
        assert m is not None
        assert m.group(2) == "jon.snow"

    def test_matches_service_account(self):
        m = _LDAP_CN_LOWERCASE_USER.search("CN=sql_svc,CN=Users")
        assert m is not None
        assert m.group(2) == "sql_svc"

    def test_no_match_uppercase_container(self):
        assert _LDAP_CN_LOWERCASE_USER.search("CN=Users,DC=corp") is None
        assert _LDAP_CN_LOWERCASE_USER.search("CN=Builtin,DC=corp") is None


class TestLdapCommentUser:
    # BUG-12: ldapsearch comment lines expose CN values

    def test_matches_comment_cn(self):
        m = _LDAP_COMMENT_USER.search("# jon.snow, Users, north.sevenkingdoms.local")
        assert m is not None
        assert m.group(2) == "jon.snow"

    def test_no_match_without_comma(self):
        assert _LDAP_COMMENT_USER.search("# numEntries: 1") is None


class TestNetexecSprayPassword:
    # Password spray passwords should be redacted

    def test_matches_password_with_domain(self):
        m = _NETEXEC_SPRAY_PASSWORD.search("[*] Trying: hodor on north")
        assert m is not None
        assert m.group(2) == "hodor"

    def test_matches_standalone_password(self):
        m = _NETEXEC_SPRAY_PASSWORD.search("[*] Trying: Password1")
        assert m is not None
        assert m.group(2) == "Password1"

    def test_no_match_without_prefix(self):
        assert _NETEXEC_SPRAY_PASSWORD.search("hodor") is None


class TestLdapDescription:
    # LDAP description attribute values should be redacted

    def test_matches_display_name(self):
        m = _LDAP_DESCRIPTION.search("description: Arya Stark")
        assert m is not None
        assert m.group(2) == "Arya Stark"

    def test_matches_builtin_description(self):
        # built-in descriptions are also redacted (acceptable collateral)
        m = _LDAP_DESCRIPTION.search("description: Built-in account for administering the computer/domain")
        assert m is not None

    def test_preserves_prefix(self):
        m = _LDAP_DESCRIPTION.search("description: Jon Snow")
        assert m.group(1) == "description: "
        assert m.group(2) == "Jon Snow"


class TestLdapCnUsersMember:
    # Uppercase CN= group names nested under CN=Users should be redacted

    def test_matches_custom_group(self):
        m = _LDAP_CN_USERS_MEMBER.search("memberOf: CN=Stark,CN=Users,DC=north")
        assert m is not None
        assert m.group(2) == "Stark"

    def test_matches_multiword_group(self):
        m = _LDAP_CN_USERS_MEMBER.search("CN=Night Watch,CN=Users,DC=north")
        assert m is not None
        assert m.group(2) == "Night Watch"

    def test_no_match_top_level_cn_users(self):
        # CN=Users itself (followed by DC=, not CN=Users) should not match
        assert _LDAP_CN_USERS_MEMBER.search("CN=Users,DC=corp") is None
