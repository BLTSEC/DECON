"""Independent trust-boundary checks for LLM-bound material."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from decon.pattern_catalog import (
    _AWS_KEY,
    _DCC2_HASH,
    _DPAPI_KEY,
    _IMPACKET_HASHES,
    _JWT,
    _KERBEROS_HASH,
    _KERBEROS_KEY,
    _MACHINE_HEX_PASSWORD,
    _NTHASH_PLAINTEXT,
    _NTLM_HASH,
    _NTLMV2_HASH,
    _PRIVATE_KEY,
    _SAM_DUMP,
)


@dataclass(frozen=True)
class SafetyFinding:
    """A high-confidence survivor found immediately before transmission."""

    category: str
    start: int
    end: int


_HIGH_RISK_PATTERNS = (
    ("private_key", _PRIVATE_KEY),
    ("api_key", _AWS_KEY),
    ("jwt", _JWT),
    ("kerberos_hash", _KERBEROS_HASH),
    ("kerberos_key", _KERBEROS_KEY),
    ("ntlmv2_hash", _NTLMV2_HASH),
    ("ntlm_hash", _NTLM_HASH),
    ("sam_dump", _SAM_DUMP),
    ("dcc2_hash", _DCC2_HASH),
    ("dpapi_key", _DPAPI_KEY),
    ("machine_hex_password", _MACHINE_HEX_PASSWORD),
    ("nthash_plaintext", _NTHASH_PLAINTEXT),
    ("impacket_hashes", _IMPACKET_HASHES),
)

_CONTEXT_CREDENTIAL = re.compile(
    r"(?i)(?:api[_-]?(?:key|secret)|access[_-]?key|client[_-]?secret|"
    r"token|password|passwd|passphrase|secret|credential|bearer)"
    r"\s*[:=]\s*['\"]?(?P<value>[^\s,'\"\}]{4,})"
)
_PROSE_CREDENTIAL = re.compile(
    r"(?i)(?:password|passwd|passphrase|secret|api[_\s-]?key|token|credential)s?"
    r"\s+(?:(?:is|was|are|were|set\s+to|changed\s+to)\s+)?"
    r"['\"`](?P<value>[^'\"`\r\n]{3,})['\"`]"
)
_CLI_CREDENTIAL = re.compile(
    r"(?i)(?:^|\s)(?:-pw|--password|--token|--api[_-]?key)\s+"
    r"['\"]?(?P<value>[^\s'\"]{3,})"
)
_PLACEHOLDER_SHAPE = re.compile(
    r"(?:\[[A-Z][A-Z0-9_]*_REDACTED_\d+\](?:/\d{1,3})?"
    r"|[A-Z][A-Z0-9_]*(?:_REDACTED)?_\d+)",
)

_PUBLIC_DOMAIN = re.compile(
    r"(?<![.\w])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}(?![.\w])"
)

_SAFE_PUBLIC_DOMAINS = {
    "nmap.org",
    "example.com",
    "example.net",
    "example.org",
}


def is_loopback_url(url: str) -> bool:
    """Return whether an HTTP(S) URL names a loopback host directly."""
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return False
    if not hostname:
        return False
    if hostname.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def is_remote_provider(provider: str, host: str) -> bool:
    """Return whether an ask provider crosses the local-machine boundary."""
    return provider != "ollama" or not is_loopback_url(host)


def scan_high_risk(text: str) -> list[SafetyFinding]:
    """Find high-confidence credential material without using engine state."""
    findings: list[SafetyFinding] = []
    covered: set[tuple[int, int]] = set()
    for category, pattern in _HIGH_RISK_PATTERNS:
        for match in pattern.finditer(text):
            span = match.span()
            if span in covered:
                continue
            covered.add(span)
            findings.append(SafetyFinding(category, *span))
    for category, pattern in (
        ("context_credential", _CONTEXT_CREDENTIAL),
        ("prose_credential", _PROSE_CREDENTIAL),
        ("cli_credential", _CLI_CREDENTIAL),
    ):
        for match in pattern.finditer(text):
            value = match.group("value").rstrip("'\".,;:!?)")
            if value.casefold() in {"true", "false", "null", "none"}:
                continue
            if _PLACEHOLDER_SHAPE.fullmatch(value):
                continue
            span = match.span("value")
            if span in covered:
                continue
            covered.add(span)
            findings.append(SafetyFinding(category, *span))
    return sorted(findings, key=lambda finding: finding.start)


def candidate_warning_counts(
    text: str,
    *,
    mapped_originals: tuple[str, ...] = (),
) -> dict[str, int]:
    """Count possible public domains and surviving mapped short host labels."""
    domains = {
        match.group(0).casefold().rstrip(".")
        for match in _PUBLIC_DOMAIN.finditer(text)
        if match.group(0).casefold().rstrip(".") not in _SAFE_PUBLIC_DOMAINS
        and "example.internal" not in match.group(0).casefold()
    }

    short_hosts: set[str] = set()
    for original in mapped_originals:
        if _PUBLIC_DOMAIN.fullmatch(original) is None:
            continue
        label = original.split(".", 1)[0]
        if len(label) < 2:
            continue
        if re.search(
            rf"(?<![.\w]){re.escape(label)}(?![.\w])",
            text,
            re.IGNORECASE,
        ):
            short_hosts.add(label.casefold())

    counts: dict[str, int] = {}
    if domains:
        counts["public_domain"] = len(domains)
    if short_hosts:
        counts["bare_hostname"] = len(short_hosts)
    return counts
