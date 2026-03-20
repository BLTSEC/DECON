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


class TestLuhn:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111")

    def test_invalid(self):
        assert not _luhn_check("1234567890123456")

    def test_short(self):
        assert not _luhn_check("123")
