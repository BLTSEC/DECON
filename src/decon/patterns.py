"""Built-in regex rules for data sanitization."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Rule:
    """A single redaction rule with regex pattern and placeholder template."""

    name: str
    category: str
    priority: int
    pattern: re.Pattern[str]
    placeholder_template: str
    enabled: bool = True
    validator: Callable[[str], bool] | None = None

    def apply(
        self,
        text: str,
        mapping: dict[str, str],
        counters: dict[str, int],
    ) -> str:
        """Apply this rule to text, updating mapping and counters."""
        # Build reverse lookup of existing placeholder values so we never
        # re-redact a placeholder produced by an earlier rule.
        placeholder_values = set(mapping.values())

        def _replace(match: re.Match[str]) -> str:
            value = match.group(0)

            if self.validator and not self.validator(value):
                return value

            # Skip values that are already placeholders from a prior rule
            if value in placeholder_values:
                return value

            if value in mapping:
                return mapping[value]

            cat = self.category
            n = counters.get(cat, 0) + 1
            counters[cat] = n

            placeholder = self.placeholder_template.format(n=n)
            mapping[value] = placeholder
            placeholder_values.add(placeholder)
            return placeholder

        return self.pattern.sub(_replace, text)


def _valid_ipv4(value: str) -> bool:
    """Check all octets are 0-255."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(0 <= int(p) <= 255 for p in parts)



def _luhn_check(value: str) -> bool:
    """Luhn algorithm for credit card validation."""
    digits = [int(d) for d in value if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# --- Pattern constants ---

# IPv4: 4 dotted decimal octets, not preceded by dot/digit, not followed by digit or dot+digit
_IPV4 = re.compile(
    r"(?<![.\d])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?![\d]|\.[\d])"
)

# CIDR notation (IPv4/mask)
_CIDR = re.compile(
    r"(?<![.\d])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"/(?:3[0-2]|[12]?\d)"
    r"(?![\d/])"
)

# IPv6 — common forms (full, compressed, mixed)
_IPV6 = re.compile(
    r"(?<![:\w])"
    r"(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"  # full
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"  # trailing ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"  # :: with one group after
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"  # leading ::
    r"|::"  # just ::
    r"|fe80:(?::[0-9a-fA-F]{1,4}){0,4}%[0-9a-zA-Z]+"  # link-local
    r")"
    r"(?![:\w])"
)

# MAC address (colon, dash, or dot separated)
_MAC = re.compile(
    r"(?<![:\w])"
    r"(?:"
    r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
    r"|[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}"
    r"|[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
    r")"
    r"(?![:\w])"
)

# Email
_EMAIL = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# Phone numbers (US-style, requires formatting chars to avoid matching bare digit runs)
_PHONE = re.compile(
    r"(?<!\d)"
    r"(?:"
    r"\+?1[-.\s]"
    r")?"
    r"(?:"
    r"\(\d{3}\)[-.\s]?\d{3}[-.\s]\d{4}"  # (555) 123-4567
    r"|\d{3}[-.]\d{3}[-.]\d{4}"          # 555-123-4567 or 555.123.4567
    r")"
    r"(?!\d)"
)

# SSN
_SSN = re.compile(
    r"(?<!\d)"
    r"\d{3}-\d{2}-\d{4}"
    r"(?!\d)"
)

# Credit card (13-19 digits, optionally separated by spaces or dashes)
_CC = re.compile(
    r"(?<!\d)"
    r"(?:\d[ -]?){12,18}\d"
    r"(?!\d)"
)

# JWT (three base64url segments separated by dots)
_JWT = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)

# AWS access key (starts with AKIA, 20 chars)
_AWS_KEY = re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")


# Generic API key / token in key=value or key: value contexts
_CONTEXT_SECRET = re.compile(
    r"(?i)"
    r"(?:api[_-]?key|api[_-]?secret|access[_-]?key|private[_-]?key|"
    r"secret[_-]?key|signing[_-]?key|client[_-]?secret|"
    r"token|password|passwd|secret|auth|credential|bearer)"
    r"(?:\s*[:=]\s*)"
    r"(['\"]?)([^\s'\"]{4,})\1"
)

# Internal hostnames (patterns like host.corp.example.com, *.internal, *.local)
_HOSTNAME_INTERNAL = re.compile(
    r"(?<![.\w])"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\.(?:corp|internal|local|intra|priv|lan)"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"(?![.\w])"
)


def _context_secret_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
) -> str:
    """Special handler for context-anchored secrets — redacts only the value part."""
    placeholder_values = set(mapping.values())

    def _replace(match: re.Match[str]) -> str:
        value = match.group(2)
        quote = match.group(1)

        # Skip values that are already placeholders from a prior rule
        if value in placeholder_values:
            full = match.group(0)
            return full

        if value in mapping:
            placeholder = mapping[value]
        else:
            cat = rule.category
            n = counters.get(cat, 0) + 1
            counters[cat] = n
            placeholder = rule.placeholder_template.format(n=n)
            mapping[value] = placeholder
            placeholder_values.add(placeholder)

        # Rebuild the full match with only the value replaced
        full = match.group(0)
        start = full[: match.start(2) - match.start(0)]
        end = full[match.end(2) - match.start(0) :]
        return start + placeholder + end

    return rule.pattern.sub(_replace, text)


def build_default_rules() -> list[Rule]:
    """Return the default rule set, sorted by priority."""
    rules = [
        Rule(
            name="jwt",
            category="jwt",
            priority=10,
            pattern=_JWT,
            placeholder_template="JWT_REDACTED_{n:02d}",
        ),
        Rule(
            name="aws_key",
            category="api_key",
            priority=10,
            pattern=_AWS_KEY,
            placeholder_template="API_KEY_{n:02d}",
        ),
        Rule(
            name="context_secret",
            category="secret",
            priority=15,
            pattern=_CONTEXT_SECRET,
            placeholder_template="SECRET_{n:02d}",
        ),
        Rule(
            name="ssn",
            category="ssn",
            priority=20,
            pattern=_SSN,
            placeholder_template="SSN_REDACTED_{n:02d}",
        ),
        Rule(
            name="credit_card",
            category="credit_card",
            priority=20,
            pattern=_CC,
            placeholder_template="CC_REDACTED_{n:02d}",
            validator=_luhn_check,
        ),
        Rule(
            name="email",
            category="email",
            priority=30,
            pattern=_EMAIL,
            placeholder_template="user_{n:02d}@example.com",
        ),
        Rule(
            name="phone",
            category="phone",
            priority=30,
            pattern=_PHONE,
            placeholder_template="(555) 555-{n:04d}",
        ),
        Rule(
            name="cidr",
            category="cidr",
            priority=39,
            pattern=_CIDR,
            placeholder_template="10.0.0.{n}/24",
        ),
        Rule(
            name="ipv4",
            category="ipv4",
            priority=40,
            pattern=_IPV4,
            placeholder_template="10.0.0.{n}",
            validator=_valid_ipv4,
        ),
        Rule(
            name="ipv6",
            category="ipv6",
            priority=40,
            pattern=_IPV6,
            placeholder_template="fd00::{n:x}",
        ),
        Rule(
            name="mac",
            category="mac",
            priority=40,
            pattern=_MAC,
            placeholder_template="00:DE:AD:00:00:{n:02X}",
        ),
        Rule(
            name="hostname_internal",
            category="hostname",
            priority=45,
            pattern=_HOSTNAME_INTERNAL,
            placeholder_template="HOST_{n:02d}.example.internal",
        ),
    ]

    # Override apply for context_secret to use the special handler
    for r in rules:
        if r.name == "context_secret":
            r.apply = lambda text, mapping, counters, _r=r: _context_secret_apply(
                _r, text, mapping, counters
            )

    rules.sort(key=lambda r: r.priority)
    return rules
