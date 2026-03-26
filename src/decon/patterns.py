"""Built-in regex rules for data sanitization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


# Type alias for custom apply functions.
# Signature: (rule, text, mapping, counters, applied) -> str
ApplyFn = Callable[
    [
        "Rule",
        str,
        dict[str, str],
        dict[str, int],
        list[tuple[str, str, str]] | None,
    ],
    str,
]


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
    apply_fn: ApplyFn | None = None
    mapping_key_fn: Callable[[str], str] | None = None

    def apply(
        self,
        text: str,
        mapping: dict[str, str],
        counters: dict[str, int],
        applied: list[tuple[str, str, str]] | None = None,
    ) -> str:
        """Apply this rule to text, updating mapping and counters."""
        if self.apply_fn:
            return self.apply_fn(self, text, mapping, counters, applied)

        # Default: replace the entire match with a placeholder.
        placeholder_values = set(mapping.values())

        def _replace(match: re.Match[str]) -> str:
            value = match.group(0)
            mapping_key = self.mapping_key_fn(value) if self.mapping_key_fn else value

            if self.validator and not self.validator(value):
                return value

            if value in placeholder_values:
                return value

            if mapping_key in mapping:
                placeholder = mapping[mapping_key]
                if applied is not None:
                    applied.append((self.category, value, placeholder))
                return placeholder

            cat = self.category
            n = counters.get(cat, 0) + 1
            counters[cat] = n

            placeholder = self.placeholder_template.format(n=n)
            mapping[mapping_key] = placeholder
            placeholder_values.add(placeholder)
            if applied is not None:
                applied.append((self.category, value, placeholder))
            return placeholder

        return self.pattern.sub(_replace, text)


# ---------------------------------------------------------------------------
# Special apply handlers
# ---------------------------------------------------------------------------


def _group_replace_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    group: int,
    applied: list[tuple[str, str, str]] | None = None,
) -> str:
    """Replace only the specified capture group, preserving the rest of the match.

    Used by context_secret (group 2), cli_flag_secret (group 2),
    slash_param_secret (group 1), linux_home_path (group 1),
    and windows_user_path (group 1).
    """
    placeholder_values = set(mapping.values())

    def _replace(match: re.Match[str]) -> str:
        value = match.group(group)
        mapping_key = rule.mapping_key_fn(value) if rule.mapping_key_fn else value
        if value in placeholder_values:
            return match.group(0)

        if mapping_key in mapping:
            placeholder = mapping[mapping_key]
        else:
            cat = rule.category
            n = counters.get(cat, 0) + 1
            counters[cat] = n
            placeholder = rule.placeholder_template.format(n=n)
            mapping[mapping_key] = placeholder
            placeholder_values.add(placeholder)

        if applied is not None:
            applied.append((rule.category, value, placeholder))
        full = match.group(0)
        start = full[: match.start(group) - match.start(0)]
        end = full[match.end(group) - match.start(0) :]
        return start + placeholder + end

    return rule.pattern.sub(_replace, text)


def _assign_placeholder(
    category: str,
    template: str,
    value: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    placeholder_values: set[str],
    applied: list[tuple[str, str, str]] | None = None,
    mapping_key: str | None = None,
) -> str:
    """Return a stable placeholder for a value, creating it if needed."""
    mapping_key = value if mapping_key is None else mapping_key

    if mapping_key in mapping:
        placeholder = mapping[mapping_key]
    else:
        n = counters.get(category, 0) + 1
        counters[category] = n
        placeholder = template.format(n=n)
        mapping[mapping_key] = placeholder
        placeholder_values.add(placeholder)

    if applied is not None:
        applied.append((category, value, placeholder))
    return placeholder


def _assign_domain_placeholder(
    value: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    placeholder_values: set[str],
    applied: list[tuple[str, str, str]] | None = None,
    mapping_key: str | None = None,
) -> str:
    """Return a stable parent-domain-style placeholder for FQDN domain values."""
    mapping_key = value if mapping_key is None else mapping_key

    if mapping_key in mapping:
        placeholder = mapping[mapping_key]
    else:
        n = counters.get("domain", 0) + 1
        counters["domain"] = n
        placeholder = "example.internal" if n == 1 else f"example{n:02d}.internal"
        mapping[mapping_key] = placeholder
        placeholder_values.add(placeholder)

    if applied is not None:
        applied.append(("domain", value, placeholder))
    return placeholder


def _cidr_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    applied: list[tuple[str, str, str]] | None = None,
) -> str:
    """Special handler for CIDR — preserves the original subnet mask."""
    placeholder_values = set(mapping.values())

    def _replace(match: re.Match[str]) -> str:
        value = match.group(0)

        if value in placeholder_values:
            return value

        if value in mapping:
            placeholder = mapping[value]
            if applied is not None:
                applied.append((rule.category, value, placeholder))
            return placeholder

        _ip, mask = value.rsplit("/", 1)
        cat = rule.category
        n = counters.get(cat, 0) + 1
        counters[cat] = n
        placeholder = f"10.0.0.{n}/{mask}"
        mapping[value] = placeholder
        placeholder_values.add(placeholder)
        if applied is not None:
            applied.append((rule.category, value, placeholder))
        return placeholder

    return rule.pattern.sub(_replace, text)


def _domain_context_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    applied: list[tuple[str, str, str]] | None = None,
) -> str:
    """Apply Domain:/domain= redaction with domain-style placeholders for FQDNs."""
    placeholder_values = set(mapping.values())

    def _replace(match: re.Match[str]) -> str:
        value = match.group(2)
        if value in placeholder_values:
            return match.group(0)

        normalized, suffix = _split_domain_context_value(value)
        if _looks_like_fqdn(normalized):
            placeholder = _assign_domain_placeholder(
                value=value,
                mapping=mapping,
                counters=counters,
                placeholder_values=placeholder_values,
                applied=applied,
                mapping_key=normalized.casefold(),
            )
        else:
            placeholder = _assign_placeholder(
                category=rule.category,
                template=rule.placeholder_template,
                value=value,
                mapping=mapping,
                counters=counters,
                placeholder_values=placeholder_values,
                applied=applied,
                mapping_key=value,
            )
        full = match.group(0)
        start = full[: match.start(2) - match.start(0)]
        end = full[match.end(2) - match.start(0) :]
        return start + placeholder + suffix + end

    return rule.pattern.sub(_replace, text)


def _smb_user_pass_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    applied: list[tuple[str, str, str]] | None = None,
) -> str:
    """Special handler for -U user%password — redacts both user and password."""
    placeholder_values = set(mapping.values())

    def _replace(match: re.Match[str]) -> str:
        user = match.group(1)
        password = match.group(2)
        for value in (user, password):
            mapping_key = rule.mapping_key_fn(value) if rule.mapping_key_fn else value
            if mapping_key not in mapping and value not in placeholder_values:
                cat = rule.category
                n = counters.get(cat, 0) + 1
                counters[cat] = n
                placeholder = rule.placeholder_template.format(n=n)
                mapping[mapping_key] = placeholder
                placeholder_values.add(placeholder)
        user_key = rule.mapping_key_fn(user) if rule.mapping_key_fn else user
        pass_key = rule.mapping_key_fn(password) if rule.mapping_key_fn else password
        user_ph = mapping.get(user_key, user)
        pass_ph = mapping.get(pass_key, password)
        if applied is not None:
            applied.append((rule.category, user, user_ph))
            applied.append((rule.category, password, pass_ph))
        prefix = match.group(0)[: match.start(1) - match.start(0)]
        return prefix + user_ph + "%" + pass_ph

    return rule.pattern.sub(_replace, text)


# Convenience factories for apply_fn — avoids repeating the group number.
def _apply_group(group: int) -> ApplyFn:
    """Return an apply_fn that replaces a specific capture group."""
    return lambda rule, text, m, c, a: _group_replace_apply(
        rule, text, m, c, group, a
    )


def _cli_flag_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    applied: list[tuple[str, str, str]] | None = None,
) -> str:
    """Apply CLI flag secret rule, skipping file paths and template placeholders."""
    placeholder_values = set(mapping.values())

    def _replace(match: re.Match[str]) -> str:
        flag = match.group(1)
        value = match.group(3)
        mapping_key = rule.mapping_key_fn(value) if rule.mapping_key_fn else value
        # Skip file paths, template placeholders, and other non-secret values
        if _CLI_FLAG_SKIP_RE.match(value):
            return match.group(0)
        if flag == "-p" and _looks_like_port_spec(value) and _is_port_scan_command(text, match.start(0)):
            return match.group(0)
        if value in placeholder_values:
            return match.group(0)

        if mapping_key in mapping:
            placeholder = mapping[mapping_key]
        else:
            cat = rule.category
            n = counters.get(cat, 0) + 1
            counters[cat] = n
            placeholder = rule.placeholder_template.format(n=n)
            mapping[mapping_key] = placeholder
            placeholder_values.add(placeholder)

        if applied is not None:
            applied.append((rule.category, value, placeholder))
        full = match.group(0)
        start = full[: match.start(3) - match.start(0)]
        end = full[match.end(3) - match.start(0) :]
        return start + placeholder + end

    return rule.pattern.sub(_replace, text)


def _url_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    applied: list[tuple[str, str, str]] | None = None,
) -> str:
    """Apply URL redaction, skipping standard Nmap boilerplate URLs."""
    placeholder_values = set(mapping.values())

    def _replace(match: re.Match[str]) -> str:
        value = match.group(0)
        mapping_key = rule.mapping_key_fn(value) if rule.mapping_key_fn else value

        if rule.validator and not rule.validator(value):
            return value
        if _is_nmap_boilerplate_url(text, match.start(0), value):
            return value
        if value in placeholder_values:
            return value

        if mapping_key in mapping:
            placeholder = mapping[mapping_key]
            if applied is not None:
                applied.append((rule.category, value, placeholder))
            return placeholder

        cat = rule.category
        n = counters.get(cat, 0) + 1
        counters[cat] = n

        placeholder = rule.placeholder_template.format(n=n)
        mapping[mapping_key] = placeholder
        placeholder_values.add(placeholder)
        if applied is not None:
            applied.append((rule.category, value, placeholder))
        return placeholder

    return rule.pattern.sub(_replace, text)


def _looks_like_port_spec(value: str) -> bool:
    """Return True for Nmap-style port lists/ranges like 80,443 or T:80,U:53."""
    if not _PORT_SPEC.fullmatch(value):
        return False

    for token in value.split(","):
        if ":" in token:
            _, token = token.split(":", 1)
        if "-" in token:
            start, end = token.split("-", 1)
            ports = (start, end)
        else:
            ports = (token,)
        if any(not 0 <= int(port) <= 65535 for port in ports):
            return False
    return True


def _is_port_scan_command(text: str, match_start: int) -> bool:
    """Return True when the current match appears inside a port-scan command line."""
    line_start = text.rfind("\n", 0, match_start) + 1
    line_end = text.find("\n", match_start)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].lower()
    return any(tool in line for tool in ("nmap", "rustscan", "masscan", "naabu"))


def _is_nmap_boilerplate_url(text: str, match_start: int, value: str) -> bool:
    """Return True for the stock nmap.org URLs shown in standard Nmap output."""
    if value not in {"https://nmap.org", "https://nmap.org/submit/"}:
        return False

    line_start = text.rfind("\n", 0, match_start) + 1
    line_end = text.find("\n", match_start)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]

    return (
        line.startswith("Starting Nmap ")
        or line.startswith(
            "Service detection performed. Please report any incorrect results "
        )
    )


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

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


# Public code/tool hosting domains — URLs to these are references to public
# resources (tools, wordlists, docs), not target infrastructure.
_PUBLIC_URL_DOMAINS = frozenset({
    "github.com", "raw.githubusercontent.com", "gist.github.com",
    "gitlab.com", "bitbucket.org",
    "exploit-db.com", "cvedetails.com",
    "attack.mitre.org",
})


def _valid_url(value: str) -> bool:
    """Skip URLs pointing to well-known public tool/resource domains."""
    stripped = value.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    return stripped not in _PUBLIC_URL_DOMAINS


# Windows built-in identities and registry paths — not real credentials.
_SKIP_DOMAIN_PREFIXES = frozenset({
    "NT AUTHORITY", "NT SERVICE", "IIS APPPOOL", "BUILTIN",
    "AUTHORITY", "SERVICE",
    "NT-AUTORITÄT", "AUTORITE NT",
    "Font",
})

_SKIP_DOMAIN_PATTERNS = (
    "HKLM", "HKCU", "HKEY_", "Registry", "Microsoft",
    "SOFTWARE", "SYSTEM", "Classes", "CurrentVersion",
)

_SKIP_DOMAIN_USERS = frozenset({
    "SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE", "LOCALSERVICE",
    "NETWORKSERVICE", "DefaultAccount", "WDAGUtilityAccount",
    "IUSR", "DefaultAppPool",
})


def _valid_domain_user(value: str) -> bool:
    """Skip Windows built-in identities and registry paths."""
    sep = value.find("\\")
    if sep == -1:
        return True
    domain = value[:sep]
    user = value[sep + 1:].split(":")[0]
    if domain.upper() in {s.upper() for s in _SKIP_DOMAIN_PREFIXES}:
        return False
    if user.upper() in {s.upper() for s in _SKIP_DOMAIN_USERS}:
        return False
    if any(domain.upper().startswith(p.upper()) for p in _SKIP_DOMAIN_PATTERNS):
        return False
    return True


_FQDN_LIKE = re.compile(
    r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_HOST_PLACEHOLDER = re.compile(r"HOST_\d{2}(?:\.example\.internal)?")


def _normalize_domain_context_value(value: str) -> str:
    """Trim punctuation/noise from Domain: values before FQDN detection."""
    normalized = value.rstrip(".,;:!?)]}")
    normalized = re.sub(r"(?i)(\.[a-z]{2,63})\d+$", r"\1", normalized)
    return normalized.rstrip(".")


def _split_domain_context_value(value: str) -> tuple[str, str]:
    """Return a normalized Domain: value plus any stripped suffix to preserve."""
    trimmed = value.rstrip(".,;:!?)]}")
    trailing = value[len(trimmed):]
    trimmed_no_dot = trimmed.rstrip(".")

    match = re.fullmatch(
        r"(?i)"
        r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})"
        r"(\d*)",
        trimmed_no_dot,
    )
    if match:
        normalized = match.group(1)
        suffix = trimmed_no_dot[len(normalized):] + trimmed[len(trimmed_no_dot):] + trailing
        return normalized, suffix

    return _normalize_domain_context_value(value), trailing


def _looks_like_fqdn(value: str) -> bool:
    """Return True if the value looks like a fully-qualified domain name."""
    return bool(_FQDN_LIKE.fullmatch(value))


def _hostname_first_label(value: str) -> str | None:
    """Return the lowercase first label for a hostname-like value."""
    if "." not in value:
        return None
    label = value.split(".", 1)[0]
    return label.casefold() if label else None


def _short_hostname_placeholder(value: str) -> str:
    """Return the short HOST_XX form for a hostname placeholder."""
    if value.endswith(".example.internal"):
        return value.split(".", 1)[0]
    return value


def _find_hostname_alias_placeholder(value: str, mapping: dict[str, str]) -> str | None:
    """Reuse an existing hostname placeholder when a single-label alias is unique."""
    label = value.casefold()
    matches = {
        placeholder
        for key, placeholder in mapping.items()
        if _HOST_PLACEHOLDER.fullmatch(placeholder)
        and _hostname_first_label(key) == label
    }
    if len(matches) == 1:
        return next(iter(matches))
    return None


def _rdns_hostname_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    applied: list[tuple[str, str, str]] | None = None,
) -> str:
    """Redact single-label reverse-DNS hostnames with hostname placeholders."""
    placeholder_values = set(mapping.values())

    def _replace(match: re.Match[str]) -> str:
        value = match.group(2)
        if value in placeholder_values:
            return match.group(0)
        placeholder = _find_hostname_alias_placeholder(value, mapping)
        if placeholder is not None:
            placeholder = _short_hostname_placeholder(placeholder)
            mapping[value.casefold()] = placeholder
            placeholder_values.add(placeholder)
            if applied is not None:
                applied.append((rule.category, value, placeholder))
            full = match.group(0)
            start = full[: match.start(2) - match.start(0)]
            end = full[match.end(2) - match.start(0) :]
            return start + placeholder + end
        placeholder = _assign_placeholder(
            category=rule.category,
            template=rule.placeholder_template,
            value=value,
            mapping=mapping,
            counters=counters,
            placeholder_values=placeholder_values,
            applied=applied,
            mapping_key=value.casefold(),
        )
        full = match.group(0)
        start = full[: match.start(2) - match.start(0)]
        end = full[match.end(2) - match.start(0) :]
        return start + placeholder + end

    return rule.pattern.sub(_replace, text)


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_IPV4 = re.compile(
    r"(?<![.\d])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?![\d]|\.[\d])"
)

_CIDR = re.compile(
    r"(?<![.\d])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"/(?:3[0-2]|[12]?\d)"
    r"(?![\d/])"
)

_IPV6 = re.compile(
    r"(?<![:\w])"
    r"(?:"
    r"fe80:(?::[0-9a-fA-F]{1,4}){0,4}%[0-9a-zA-Z]+"
    r"|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){6}"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    r")"
    r"(?![:\w])"
)

_MAC = re.compile(
    r"(?<![:\w])"
    r"(?:"
    r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
    r"|[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}"
    r"|[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
    r")"
    r"(?![:\w])"
)

_EMAIL = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

_PHONE = re.compile(
    r"(?<!\d)"
    r"(?:\+?1[-.\s])?"
    r"(?:"
    r"\(\d{3}\)[-.\s]?\d{3}[-.\s]\d{4}"
    r"|\d{3}[-.]\d{3}[-.]\d{4}"
    r")"
    r"(?!\d)"
)

_SSN = re.compile(
    r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"
)

_CC = re.compile(
    r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"
)

_JWT = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)

_AWS_KEY = re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")

_URL = re.compile(
    r"https?://"
    r"[^\s<>\"\x27\)\]]*"
    r"[^\s<>\"\x27\)\].,;:!?\-]"
)

_CONTEXT_SECRET = re.compile(
    r"(?i)"
    r"(?:api[_-]?key|api[_-]?secret|access[_-]?key|private[_-]?key|"
    r"secret[_-]?key|signing[_-]?key|client[_-]?secret|"
    r"token|password|passwd|secret|auth|credential|bearer|"
    r"user\s*id|username|ntlm)"
    r"(?:\s*[:=]\s*)"
    r"(['\"]?)(?!(?:true|false|null|none)\b)([^\s'\"]{4,})(?<![).,;])\1"
)

_DOMAIN_CONTEXT = re.compile(
    r"(?i)"
    r"(?:domain)"
    r"(?:\s*[:=]\s*)"
    r"(['\"]?)([^\s'\"]{4,})\1"
)

_RDNS_SINGLE_LABEL = re.compile(
    r"(?im)"
    r"(rDNS record for [^:\n]+:\s+)"
    r"([A-Z][A-Z0-9-]{1,62})"
    r"(?=\s|$)"
)

_SMB_NETBIOS_NAME = re.compile(
    r"(\(name:)([A-Z][A-Z0-9-]{1,14})(?=\))"
)

_CLI_FLAG_SECRET = re.compile(
    r"(?:^|\s)"
    r"(-p|-P|-pw|--password|--pw|-H|--hash|--hashes"
    r"|-u|-l|--user|--login|--username|-U)"
    r"\s+"
    r"(['\"]?)([^\s'\"]{3,})\2"
    r"(?=\s|$)"
)

# Values that look like file paths, template placeholders, or flags — not secrets
_CLI_FLAG_SKIP_RE = re.compile(
    r"^(?:"
    r"[/<]"                       # starts with / (path) or < (template placeholder)
    r"|.*\.\w{2,4}$"              # ends with file extension (.txt, .list, etc.)
    r"|None\b"                    # Python None in output
    r"|-"                         # another flag
    r")"
)

_SLASH_PARAM_SECRET = re.compile(
    r"\/(?:user|rc4|ntlm|aes256|aes128|des|password|pass|credential|domain|krbtgt)"
    r":([^\s\/]{3,})"
)

_SMB_USER_PASS = re.compile(
    r"(?:^|\s)-U\s+([^\s%]+)%([^\s]{3,})"
    r"(?=\s|$)"
)

_HOSTNAME_INTERNAL = re.compile(
    r"(?<![.\w])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\.(?:corp|internal|local|intra|priv|lan|htb|lab)"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"(?![.\w])"
)

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"
    r"[\s\S]*?"
    r"-----END (?:[A-Z]+ )?PRIVATE KEY-----"
)

_NTLM_HASH = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:[0-9a-fA-F]{32}(?![0-9a-fA-F])"
)

_SAM_DUMP = re.compile(
    r"^(?:[^\s:]+[\\\/])?[^\s:]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::$",
    re.MULTILINE,
)

_NTLMV2_HASH = re.compile(
    r"[^\s:]+::[^\s:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]{20,}"
)

_KERBEROS_KEY = re.compile(
    r"[^\s:]+:(?:aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5):[0-9a-fA-F]+"
)

_AD_DOMAIN_USER_BACKSLASH = re.compile(
    r"(?<![\w\\])"
    r"(?:"
    r"[A-Z][A-Z0-9._-]{0,14}"
    r"|[a-zA-Z0-9](?:[a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}"
    r")"
    r"\\[a-zA-Z0-9._-]+"
    r"(?::[^\s]{4,})?"
    r"(?![\w\\])"
)

# Forward-slash requires FQDN domain (with dots) OR uppercase domain of 4+ chars
# to avoid matching abbreviations like SMB/WMI, TGT/TGS, R/W, GNU/Linux.
_AD_DOMAIN_USER_SLASH = re.compile(
    r"(?<![\w\/])"
    r"(?:"
    r"[A-Z][A-Z0-9]{3,14}"                              # CORP, INLANEFREIGHT (4+ uppercase)
    r"|[a-zA-Z0-9](?:[a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}"     # megacorp.local (FQDN)
    r")"
    r"\/[a-zA-Z][a-zA-Z0-9._-]*"                         # /username (must start with alpha)
    r"(?::[^\s@]{4,})?(?:@[^\s]+)?"                       # optional :password@host
    r"(?![\w\/])"
)

_KERBEROS_HASH = re.compile(
    r"\$krb5(?:tgs|asrep)\$\d*\$"
    r"(?:[^\s:]+(?:\$[^\s]+)+"   # TGS: $-delimited segments
    r"|[^\s:]+:[^\s]+)"           # AS-REP: user@DOMAIN:hexhash
)

_DCC2_HASH = re.compile(
    r"(?:[^\s:]*\$)?DCC2\$\d+#[^#]+#[0-9a-fA-F]{32}"
)

_DPAPI_KEY = re.compile(
    r"(?:dpapi_machinekey|dpapi_userkey|NL\$KM)\s*:\s*(?:0x)?[0-9a-fA-F]{20,}"
)

_MACHINE_HEX_PASSWORD = re.compile(
    r"plain_password_hex:[0-9a-fA-F]{32,}"
)

_LINUX_HOME_PATH = re.compile(
    r"/(?:home/)([a-zA-Z0-9._-]+)"
)

_WINDOWS_USER_PATH = re.compile(
    r"(?i)C:\\\\?Users\\\\?"
    r"([a-zA-Z0-9._\s-]+?)(?=\\\\|\\|/|\s|$)"
)

_WINDOWS_SID = re.compile(
    r"S-1-5-21-\d+-\d+-\d+(?:-\d+)?"
)

_UNC_PATH = re.compile(
    r"\\\\[a-zA-Z0-9._-]+(?:\\[a-zA-Z0-9._$-]+)+"
)

_PORT_SPEC = re.compile(
    r"^(?:[TUSP]:)?\d{1,5}(?:-\d{1,5})?"
    r"(?:,(?:[TUSP]:)?\d{1,5}(?:-\d{1,5})?)*$"
)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------


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
            name="domain_context",
            category="secret",
            priority=15,
            pattern=_DOMAIN_CONTEXT,
            placeholder_template="SECRET_{n:02d}",
            apply_fn=_domain_context_apply,
        ),
        Rule(
            name="context_secret",
            category="secret",
            priority=15,
            pattern=_CONTEXT_SECRET,
            placeholder_template="SECRET_{n:02d}",
            apply_fn=_apply_group(2),
        ),
        Rule(
            name="cli_flag_secret",
            category="secret",
            priority=16,
            pattern=_CLI_FLAG_SECRET,
            placeholder_template="SECRET_{n:02d}",
            apply_fn=_cli_flag_apply,
        ),
        Rule(
            name="slash_param_secret",
            category="secret",
            priority=16,
            pattern=_SLASH_PARAM_SECRET,
            placeholder_template="SECRET_{n:02d}",
            apply_fn=_apply_group(1),
        ),
        Rule(
            name="smb_user_pass",
            category="secret",
            priority=16,
            pattern=_SMB_USER_PASS,
            placeholder_template="SECRET_{n:02d}",
            apply_fn=_smb_user_pass_apply,
        ),
        Rule(
            name="windows_sid",
            category="windows_sid",
            priority=18,
            pattern=_WINDOWS_SID,
            placeholder_template="SID_REDACTED_{n:02d}",
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
            validator=_valid_domain_user,
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
            apply_fn=_url_apply,
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
            name="linux_home_path",
            category="secret",
            priority=36,
            pattern=_LINUX_HOME_PATH,
            placeholder_template="SECRET_{n:02d}",
            apply_fn=_apply_group(1),
        ),
        Rule(
            name="windows_user_path",
            category="secret",
            priority=36,
            pattern=_WINDOWS_USER_PATH,
            placeholder_template="SECRET_{n:02d}",
            apply_fn=_apply_group(1),
        ),
        Rule(
            name="cidr",
            category="cidr",
            priority=39,
            pattern=_CIDR,
            placeholder_template="10.0.0.{n}/24",
            apply_fn=_cidr_apply,
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
            priority=44,
            pattern=_HOSTNAME_INTERNAL,
            placeholder_template="HOST_{n:02d}.example.internal",
        ),
        Rule(
            name="rdns_single_label",
            category="hostname",
            priority=45,
            pattern=_RDNS_SINGLE_LABEL,
            placeholder_template="HOST_{n:02d}",
            apply_fn=_rdns_hostname_apply,
        ),
        Rule(
            name="smb_netbios_name",
            category="hostname",
            priority=46,
            pattern=_SMB_NETBIOS_NAME,
            placeholder_template="HOST_{n:02d}",
            apply_fn=_rdns_hostname_apply,
        ),
    ]

    rules.sort(key=lambda r: r.priority)
    return rules


def get_placeholder_templates() -> list[str]:
    """Return all placeholder template strings from the default rules.

    Used by llm.py to auto-generate the placeholder regex.
    """
    return [r.placeholder_template for r in build_default_rules()]
