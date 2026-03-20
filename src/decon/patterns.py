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


# IPs that are never sensitive — loopback, unspecified, link-local, documentation.
_SKIP_IPV4 = frozenset({
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
})

# Prefixes that are never target IPs (loopback range, link-local, documentation)
_SKIP_IPV4_PREFIXES = ("127.", "169.254.", "192.0.2.", "198.51.100.", "203.0.113.")


def _valid_ipv4(value: str) -> bool:
    """Check all octets are 0-255 and not a loopback/special address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    if not all(0 <= int(p) <= 255 for p in parts):
        return False
    # Skip loopback and other non-sensitive addresses
    if value in _SKIP_IPV4:
        return False
    if any(value.startswith(p) for p in _SKIP_IPV4_PREFIXES):
        return False
    return True


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

# IPv6 — all standard forms (full, compressed, link-local with zone ID)
# Note: bare :: (unspecified address) excluded to avoid false positives on
# C++/Perl/Ruby scope resolution operators. ::1 and other :: with groups
# are still matched.
_IPV6 = re.compile(
    r"(?<![:\w])"
    r"(?:"
    r"fe80:(?::[0-9a-fA-F]{1,4}){0,4}%[0-9a-zA-Z]+"             # link-local w/ zone
    r"|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"                # full (8 groups)
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                              # trailing ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"             # N:: + 1 suffix
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){2}"      # N:: + 2 suffix
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){3}"      # N:: + 3 suffix
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){4}"      # N:: + 4 suffix
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){5}"      # N:: + 5 suffix
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){6}"               # 1:: + 6 suffix
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"            # leading :: (at least one group)
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

# URL (http:// and https://)
_URL = re.compile(
    r"https?://"
    r"[^\s<>\"\x27\)\]]*"
    r"[^\s<>\"\x27\)\].,;:!?\-]"
)

# Public code/tool hosting domains — URLs to these are references to public
# resources (tools, wordlists, docs), not target infrastructure.  Sensitive
# values inside them (org names, repo names) are caught by custom value rules.
_PUBLIC_URL_DOMAINS = frozenset({
    "github.com", "raw.githubusercontent.com", "gist.github.com",
    "gitlab.com", "bitbucket.org",
    "exploit-db.com", "cvedetails.com",
    "attack.mitre.org",
})


def _valid_url(value: str) -> bool:
    """Skip URLs pointing to well-known public tool/resource domains."""
    # Extract domain from URL
    stripped = value.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    return stripped not in _PUBLIC_URL_DOMAINS

# Generic API key / token in key=value or key: value contexts
_CONTEXT_SECRET = re.compile(
    r"(?i)"
    r"(?:api[_-]?key|api[_-]?secret|access[_-]?key|private[_-]?key|"
    r"secret[_-]?key|signing[_-]?key|client[_-]?secret|"
    r"token|password|passwd|secret|auth|credential|bearer|"
    r"user\s*id|username|ntlm|domain)"
    r"(?:\s*[:=]\s*)"
    r"(['\"]?)([^\s'\"]{4,})\1"
)

# CLI flag secrets: -p/-P/-pw 'password', -H 'hash', --password 'value'
# Matches flags followed by a space and a value (quoted or unquoted)
_CLI_FLAG_SECRET = re.compile(
    r"(?:^|\s)"
    r"(?:-p|-P|-pw|--password|--pw|-H|--hash|--hashes)"
    r"\s+"
    r"(['\"]?)([^\s'\"]{3,})\1"
    r"(?=\s|$)"
)

# Internal hostnames (patterns like dc01.corp.local, dc01.corp.acme.com, *.htb, *.lab)
# Matches any hostname containing an internal TLD segment, with optional labels
# before and after the TLD (e.g., dc01.corp.acme.com, mail.inlanefreight.htb).
_HOSTNAME_INTERNAL = re.compile(
    r"(?<![.\w])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"  # optional subdomains before TLD
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\.(?:corp|internal|local|intra|priv|lan|htb|lab)"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"  # optional labels after TLD
    r"(?![.\w])"
)

# Private key blocks (PEM format)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"
    r"[\s\S]*?"
    r"-----END (?:[A-Z]+ )?PRIVATE KEY-----"
)

# NTLM hash pairs (LM:NT format, 32 hex chars each)
_NTLM_HASH = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:[0-9a-fA-F]{32}(?![0-9a-fA-F])"
)

# SAM/NTDS dump lines: user:RID:LMhash:NThash:::
# Covers secretsdump output with optional domain prefix (domain\user or domain/user)
_SAM_DUMP = re.compile(
    r"^(?:[^\s:]+[\\\/])?[^\s:]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::$",
    re.MULTILINE,
)

# NTLMv2 / Net-NTLM hash (Responder/Inveigh captures)
# Format: user::DOMAIN:challenge:NTLMv2response (challenge is 16 hex, response is long hex)
_NTLMV2_HASH = re.compile(
    r"[^\s:]+::[^\s:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]{20,}"
)

# Kerberos encryption keys from secretsdump LSA output
# Format: domain\user:aes256-cts-hmac-sha1-96:hexkey
_KERBEROS_KEY = re.compile(
    r"[^\s:]+:(?:aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5):[0-9a-fA-F]+"
)

# Active Directory domain\username with optional :password
# Backslash: CORP\user, megacorp.local\user (standard Windows notation)
# Optional :password captures credentials in tool output (netexec, crackmapexec).
_AD_DOMAIN_USER_BACKSLASH = re.compile(
    r"(?<![\w\\])"
    r"(?:"
    r"[A-Z][A-Z0-9._-]{0,14}"                          # CORP, CONTOSO.LOCAL
    r"|[a-zA-Z0-9](?:[a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}"    # megacorp.local (FQDN)
    r")"
    r"\\[a-zA-Z0-9._-]+"                                # \username
    r"(?::[^\s]{4,})?"                                   # optional :password
    r"(?![\w\\])"
)

# Impacket-style domain/username with optional :password@host
# Forward-slash: DOMAIN/user:pass@host, DOMAIN/user@host
# Username must start with alpha (avoids HTTP/1.1, FTP/2.0, etc.)
_AD_DOMAIN_USER_SLASH = re.compile(
    r"(?<![\w\/])"
    r"(?:"
    r"[A-Z][A-Z0-9._-]{0,14}"                           # CORP, CONTOSO.LOCAL
    r"|[a-zA-Z0-9](?:[a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}"     # megacorp.local (FQDN)
    r")"
    r"\/[a-zA-Z][a-zA-Z0-9._-]*"                         # /username (must start with alpha)
    r"(?::[^\s@]{4,})?(?:@[^\s]+)?"                       # optional :password@host
    r"(?![\w\/])"
)

# Kerberoast hash ($krb5tgs$) and AS-REP hash ($krb5asrep$)
# These contain username and domain, plus the hash itself
_KERBEROS_HASH = re.compile(
    r"\$krb5(?:tgs|asrep)\$\d*\$[^\s:]+(?:\$[^\s]+)+"
)

# DCC2 / Domain Cached Credentials
# Format: $DCC2$10240#username#hash  or  DOMAIN/user:$DCC2$...
_DCC2_HASH = re.compile(
    r"(?:[^\s:]*\$)?DCC2\$\d+#[^#]+#[0-9a-fA-F]{32}"
)

# DPAPI keys (dpapi_machinekey, dpapi_userkey, NL$KM)
_DPAPI_KEY = re.compile(
    r"(?:dpapi_machinekey|dpapi_userkey|NL\$KM)\s*:\s*(?:0x)?[0-9a-fA-F]{20,}"
)

# Machine account plaintext hex password
_MACHINE_HEX_PASSWORD = re.compile(
    r"plain_password_hex:[0-9a-fA-F]{32,}"
)

# Windows SID (S-1-5-21-...)
_WINDOWS_SID = re.compile(
    r"S-1-5-21-\d+-\d+-\d+(?:-\d+)?"
)

# UNC paths (\\server\share)
_UNC_PATH = re.compile(
    r"\\\\[a-zA-Z0-9._-]+(?:\\[a-zA-Z0-9._$-]+)+"
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


def _cidr_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
) -> str:
    """Special handler for CIDR — preserves the original subnet mask."""
    placeholder_values = set(mapping.values())

    def _replace(match: re.Match[str]) -> str:
        value = match.group(0)

        if value in placeholder_values:
            return value

        if value in mapping:
            return mapping[value]

        _ip, mask = value.rsplit("/", 1)
        cat = rule.category
        n = counters.get(cat, 0) + 1
        counters[cat] = n
        placeholder = f"10.0.0.{n}/{mask}"
        mapping[value] = placeholder
        placeholder_values.add(placeholder)
        return placeholder

    return rule.pattern.sub(_replace, text)


def build_default_rules() -> list[Rule]:
    """Return the default rule set, sorted by priority."""
    rules = [
        Rule(
            name="private_key",
            category="private_key",
            priority=5,
            pattern=_PRIVATE_KEY,
            placeholder_template="PRIVATE_KEY_REDACTED_{n:02d}",
        ),
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
            name="kerberos_hash",
            category="kerberos_hash",
            priority=7,
            pattern=_KERBEROS_HASH,
            placeholder_template="KERBEROS_HASH_{n:02d}",
        ),
        Rule(
            name="sam_dump",
            category="sam_dump",
            priority=8,
            pattern=_SAM_DUMP,
            placeholder_template="SAM_DUMP_{n:02d}",
        ),
        Rule(
            name="ntlmv2_hash",
            category="ntlmv2_hash",
            priority=9,
            pattern=_NTLMV2_HASH,
            placeholder_template="NTLMV2_HASH_{n:02d}",
        ),
        Rule(
            name="kerberos_key",
            category="kerberos_key",
            priority=9,
            pattern=_KERBEROS_KEY,
            placeholder_template="KERBEROS_KEY_{n:02d}",
        ),
        Rule(
            name="dcc2_hash",
            category="dcc2_hash",
            priority=11,
            pattern=_DCC2_HASH,
            placeholder_template="DCC2_HASH_{n:02d}",
        ),
        Rule(
            name="dpapi_key",
            category="dpapi_key",
            priority=11,
            pattern=_DPAPI_KEY,
            placeholder_template="DPAPI_KEY_{n:02d}",
        ),
        Rule(
            name="machine_hex_password",
            category="machine_hex_password",
            priority=11,
            pattern=_MACHINE_HEX_PASSWORD,
            placeholder_template="MACHINE_HEX_PW_{n:02d}",
        ),
        Rule(
            name="ntlm_hash",
            category="ntlm_hash",
            priority=12,
            pattern=_NTLM_HASH,
            placeholder_template="NTLM_HASH_{n:02d}",
        ),
        Rule(
            name="context_secret",
            category="secret",
            priority=15,
            pattern=_CONTEXT_SECRET,
            placeholder_template="SECRET_{n:02d}",
        ),
        Rule(
            name="cli_flag_secret",
            category="secret",
            priority=16,
            pattern=_CLI_FLAG_SECRET,
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
            name="ad_domain_user",
            category="ad_domain_user",
            priority=25,
            pattern=_AD_DOMAIN_USER_BACKSLASH,
            placeholder_template="DOMAIN_USER_{n:02d}",
        ),
        Rule(
            name="ad_domain_user_slash",
            category="ad_domain_user",
            priority=25,
            pattern=_AD_DOMAIN_USER_SLASH,
            placeholder_template="DOMAIN_USER_{n:02d}",
        ),
        Rule(
            name="url",
            category="url",
            priority=28,
            pattern=_URL,
            placeholder_template="URL_REDACTED_{n:02d}",
            validator=_valid_url,
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
            name="unc_path",
            category="unc_path",
            priority=34,
            pattern=_UNC_PATH,
            placeholder_template="UNC_PATH_{n:02d}",
        ),
        Rule(
            name="windows_sid",
            category="windows_sid",
            priority=18,
            pattern=_WINDOWS_SID,
            placeholder_template="SID_REDACTED_{n:02d}",
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

    # Override apply for rules with special handlers
    for r in rules:
        if r.name in ("context_secret", "cli_flag_secret"):
            r.apply = lambda text, mapping, counters, _r=r: _context_secret_apply(
                _r, text, mapping, counters
            )
        elif r.name == "cidr":
            r.apply = lambda text, mapping, counters, _r=r: _cidr_apply(
                _r, text, mapping, counters
            )

    rules.sort(key=lambda r: r.priority)
    return rules
