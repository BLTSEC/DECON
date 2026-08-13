"""Built-in regex rules for data sanitization."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable

from decon.pattern_catalog import (
    _CLI_FLAG_SKIP_RE,
    _CLI_USER_FLAGS,
    _PORT_SPEC,
)

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

_TYPED_PLACEHOLDER = re.compile(
    r"(?:"
    r"\[(?:(?:IPV4|IPV6|MAC|EMAIL|PHONE|SECRET|HOST|HOST_SHORT|DOMAIN|CIDR|SHARE)"
    r"_REDACTED|CUSTOM_(?:[A-Z0-9]+_)*REDACTED)_\d+\](?:/\d{1,3})?"
    r"|(?:PRIVATE_KEY_REDACTED|KERBEROS_HASH|SAM_DUMP|NTLMV2_HASH|"
    r"KERBEROS_KEY|JWT_REDACTED|API_KEY|DCC2_HASH|DPAPI_KEY|"
    r"MACHINE_HEX_PW|NTLM_HASH|SID_REDACTED|SSN_REDACTED|"
    r"CC_REDACTED|SPN|DOMAIN_USER|URL_REDACTED|UNC_PATH)_\d+"
    r")"
)


def _is_typed_placeholder(value: str) -> bool:
    """Return whether a value belongs to DECON's explicit placeholder namespace."""
    return bool(_TYPED_PLACEHOLDER.fullmatch(value))


def _allocate_placeholder(
    category: str,
    template: str,
    counters: dict[str, int],
    placeholder_values: set[str],
) -> str:
    """Allocate the next unused placeholder for a category."""
    n = counters.get(category, 0) + 1
    attempted: set[str] = set()
    while True:
        placeholder = template.format(n=n)
        if placeholder in attempted:
            raise ValueError("placeholder template must produce a unique value for {n}")
        attempted.add(placeholder)
        if placeholder not in placeholder_values:
            counters[category] = n
            placeholder_values.add(placeholder)
            return placeholder
        n += 1


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

            if value in placeholder_values or _is_typed_placeholder(value):
                return value

            if mapping_key in mapping:
                placeholder = mapping[mapping_key]
                if placeholder == mapping_key:
                    return value
                if applied is not None:
                    applied.append((self.category, value, placeholder))
                return placeholder

            placeholder = _allocate_placeholder(
                self.category,
                self.placeholder_template,
                counters,
                placeholder_values,
            )
            mapping[mapping_key] = placeholder
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
        if value in placeholder_values or _is_typed_placeholder(value):
            return match.group(0)

        if mapping_key in mapping:
            placeholder = mapping[mapping_key]
            if placeholder == mapping_key:
                return match.group(0)
        else:
            placeholder = _allocate_placeholder(
                rule.category,
                rule.placeholder_template,
                counters,
                placeholder_values,
            )
            mapping[mapping_key] = placeholder

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
        if placeholder == mapping_key:
            return value
    else:
        placeholder = _allocate_placeholder(
            category,
            template,
            counters,
            placeholder_values,
        )
        mapping[mapping_key] = placeholder

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
        if placeholder == mapping_key:
            return value
    else:
        placeholder = _allocate_placeholder(
            "domain",
            "[DOMAIN_REDACTED_{n:04d}]",
            counters,
            placeholder_values,
        )
        mapping[mapping_key] = placeholder

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
        # The mask is preserved outside the logical CIDR identity. Reserve an
        # existing index across every mask, not only an identical rendered
        # placeholder such as ...0001]/24 versus ...0001]/16.
        for existing in tuple(placeholder_values):
            match = re.fullmatch(r"\[CIDR_REDACTED_(\d+)\](?:/\d{1,3})?", existing)
            if match:
                placeholder_values.add(f"[CIDR_REDACTED_{match.group(1)}]/{mask}")
        placeholder = _allocate_placeholder(
            rule.category,
            f"[CIDR_REDACTED_{{n:04d}}]/{mask}",
            counters,
            placeholder_values,
        )
        mapping[value] = placeholder
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
        if value in placeholder_values or _is_typed_placeholder(value):
            return match.group(0)

        normalized, suffix = _split_domain_context_value(value)
        if _looks_like_fqdn(normalized):
            placeholder = _assign_domain_placeholder(
                # Only the normalized portion is replaced. The suffix remains
                # in the document and must not also be stored in the reverse map.
                value=normalized,
                mapping=mapping,
                counters=counters,
                placeholder_values=placeholder_values,
                applied=None,
                mapping_key=normalized.casefold(),
            )
            category = "domain"
        else:
            placeholder = _assign_placeholder(
                category=rule.category,
                template=rule.placeholder_template,
                value=normalized,
                mapping=mapping,
                counters=counters,
                placeholder_values=placeholder_values,
                applied=None,
                mapping_key=normalized,
            )
            category = rule.category
        # Scanner banners sometimes append noise (for example local0.) and the
        # regex also captures ordinary punctuation. Register the complete
        # rendered token so strict unredaction never has to replace a valid
        # placeholder prefix inside a longer string.
        rendered = placeholder + suffix
        if suffix:
            mapping.setdefault(value, rendered)
            placeholder_values.add(rendered)
        if applied is not None:
            applied.append((category, value, rendered))
        full = match.group(0)
        start = full[: match.start(2) - match.start(0)]
        end = full[match.end(2) - match.start(0) :]
        return start + rendered + end

    return rule.pattern.sub(_replace, text)


def _context_secret_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    applied: list[tuple[str, str, str]] | None = None,
) -> str:
    """Redact quoted or unquoted context-anchored secret values."""
    placeholder_values = set(mapping.values())
    safe_literals = {"true", "false", "null", "none"}

    def _replace(match: re.Match[str]) -> str:
        group = 2
        value = match.group(group)

        if not value or value.casefold() in safe_literals:
            return match.group(0)
        if (
            value.startswith("[")
            and match.end() < len(match.string)
            and match.string[match.end()] == "]"
            and _is_typed_placeholder(value + "]")
        ):
            return match.group(0)
        if value in placeholder_values or _is_typed_placeholder(value):
            return match.group(0)

        placeholder = _assign_placeholder(
            category=rule.category,
            template=rule.placeholder_template,
            value=value,
            mapping=mapping,
            counters=counters,
            placeholder_values=placeholder_values,
            applied=applied,
        )
        full = match.group(0)
        start = full[: match.start(group) - match.start(0)]
        end = full[match.end(group) - match.start(0) :]
        return start + placeholder + end

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
        # The two halves are different kinds of thing, so they get different
        # placeholder namespaces — a username is an identity, not a credential.
        kinds = (
            (user, "ad_domain_user", "DOMAIN_USER_{n:02d}"),
            (password, rule.category, rule.placeholder_template),
        )
        for value, category, template in kinds:
            mapping_key = rule.mapping_key_fn(value) if rule.mapping_key_fn else value
            if (
                mapping_key not in mapping
                and value not in placeholder_values
                and not _is_typed_placeholder(value)
            ):
                placeholder = _allocate_placeholder(
                    category,
                    template,
                    counters,
                    placeholder_values,
                )
                mapping[mapping_key] = placeholder
        user_key = rule.mapping_key_fn(user) if rule.mapping_key_fn else user
        pass_key = rule.mapping_key_fn(password) if rule.mapping_key_fn else password
        user_ph = mapping.get(user_key, user)
        pass_ph = mapping.get(pass_key, password)
        if applied is not None:
            if user_ph != user:
                applied.append(("ad_domain_user", user, user_ph))
            if pass_ph != password:
                applied.append((rule.category, password, pass_ph))
        prefix = match.group(0)[: match.start(1) - match.start(0)]
        return prefix + user_ph + "%" + pass_ph

    return rule.pattern.sub(_replace, text)


# Convenience factories for apply_fn — avoids repeating the group number.
def _apply_group(group: int) -> ApplyFn:
    """Return an apply_fn that replaces a specific capture group."""
    return lambda rule, text, m, c, a: _group_replace_apply(rule, text, m, c, group, a)


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
        group = next(
            group_number
            for group_number in (2, 3, 4)
            if match.group(group_number) is not None
        )
        value = match.group(group)
        mapping_key = rule.mapping_key_fn(value) if rule.mapping_key_fn else value
        # Skip file paths, template placeholders, and other non-secret values
        if _CLI_FLAG_SKIP_RE.match(value):
            return match.group(0)
        if (
            flag == "-U"
            and "%" in value
            and all(
                part in placeholder_values or _is_typed_placeholder(part)
                for part in value.split("%", 1)
            )
        ):
            return match.group(0)
        if (
            flag == "-p"
            and _looks_like_port_spec(value)
            and _is_port_scan_command(text, match.start(0))
        ):
            return match.group(0)
        if value in placeholder_values or _is_typed_placeholder(value):
            return match.group(0)

        # A value after -u is a username, not a credential. Emitting it as
        # SECRET says the wrong thing about what it is, and splits one identity
        # across two placeholder namespaces when the same account also appears
        # as DOMAIN\user elsewhere.
        if flag in _CLI_USER_FLAGS:
            category, template = "ad_domain_user", "DOMAIN_USER_{n:02d}"
        else:
            category, template = rule.category, rule.placeholder_template

        if mapping_key in mapping:
            placeholder = mapping[mapping_key]
            if placeholder == mapping_key:
                return match.group(0)
        else:
            placeholder = _allocate_placeholder(
                category,
                template,
                counters,
                placeholder_values,
            )
            mapping[mapping_key] = placeholder

        if applied is not None:
            applied.append((category, value, placeholder))
        full = match.group(0)
        start = full[: match.start(group) - match.start(0)]
        end = full[match.end(group) - match.start(0) :]
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
            if placeholder == mapping_key:
                return value
            if applied is not None:
                applied.append((rule.category, value, placeholder))
            return placeholder

        placeholder = _allocate_placeholder(
            rule.category,
            rule.placeholder_template,
            counters,
            placeholder_values,
        )
        mapping[mapping_key] = placeholder
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

    return line.startswith("Starting Nmap ") or line.startswith(
        "Service detection performed. Please report any incorrect results "
    )


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# IPs that are never sensitive — loopback, unspecified, link-local, documentation.
_SKIP_IPV4 = frozenset(
    {
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
    }
)

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


def _canonical_ipv6(value: str) -> str:
    """Return a stable key for equivalent IPv6 spellings."""
    address, separator, zone = value.partition("%")
    canonical = ipaddress.IPv6Address(address).compressed.casefold()
    # Zone identifiers can be case-sensitive interface names on Unix systems.
    return canonical + (separator + zone if separator else "")


def _canonical_mac(value: str) -> str:
    """Return twelve lowercase hexadecimal characters for a MAC address."""
    return re.sub(r"[:.-]", "", value).casefold()


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


# Windows built-in identities and registry paths — not real credentials.
_SKIP_DOMAIN_PREFIXES = frozenset(
    {
        "NT AUTHORITY",
        "NT SERVICE",
        "IIS APPPOOL",
        "BUILTIN",
        "AUTHORITY",
        "SERVICE",
        "NT-AUTORITÄT",
        "AUTORITE NT",
        "Font",
    }
)

_SKIP_DOMAIN_PATTERNS = (
    "HKLM",
    "HKCU",
    "HKEY_",
    "Registry",
    "Microsoft",
    "SOFTWARE",
    "SYSTEM",
    "Classes",
    "CurrentVersion",
)

_SKIP_DOMAIN_USERS = frozenset(
    {
        "SYSTEM",
        "NETWORK SERVICE",
        "LOCAL SERVICE",
        "LOCALSERVICE",
        "NETWORKSERVICE",
        "DefaultAccount",
        "WDAGUtilityAccount",
        "IUSR",
        "DefaultAppPool",
    }
)


def _valid_domain_user(value: str) -> bool:
    """Skip Windows built-in identities and registry paths."""
    sep = value.find("\\")
    if sep == -1:
        return True
    domain = value[:sep]
    user = value[sep + 1 :].split(":")[0]
    if domain.upper() in {s.upper() for s in _SKIP_DOMAIN_PREFIXES}:
        return False
    if user.upper() in {s.upper() for s in _SKIP_DOMAIN_USERS}:
        return False
    if any(domain.upper().startswith(p.upper()) for p in _SKIP_DOMAIN_PATTERNS):
        return False
    return True


_FQDN_LIKE = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HOST_PLACEHOLDER = re.compile(
    r"(?:\[HOST_REDACTED_\d+\]|\[HOST_SHORT_REDACTED_\d+\]|"
    r"HOST_\d+(?:\.example\.internal)?)"
)


def _normalize_domain_context_value(value: str) -> str:
    """Trim punctuation/noise from Domain: values before FQDN detection."""
    normalized = value.rstrip(".,;:!?)]}")
    normalized = re.sub(r"(?i)(\.[a-z]{2,63})\d+$", r"\1", normalized)
    return normalized.rstrip(".")


def _split_domain_context_value(value: str) -> tuple[str, str]:
    """Return a normalized Domain: value plus any stripped suffix to preserve."""
    trimmed = value.rstrip(".,;:!?)]}")
    trailing = value[len(trimmed) :]
    trimmed_no_dot = trimmed.rstrip(".")

    match = re.fullmatch(
        r"(?i)"
        r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})"
        r"(\d*)",
        trimmed_no_dot,
    )
    if match:
        normalized = match.group(1)
        suffix = (
            trimmed_no_dot[len(normalized) :]
            + trimmed[len(trimmed_no_dot) :]
            + trailing
        )
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
    if value.startswith("[HOST_REDACTED_"):
        return value.replace("[HOST_REDACTED_", "[HOST_SHORT_REDACTED_", 1)
    if value.startswith("[HOST_SHORT_REDACTED_"):
        return value
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


def _ldap_dn_domain_apply(
    rule: Rule,
    text: str,
    mapping: dict[str, str],
    counters: dict[str, int],
    applied: list[tuple[str, str, str]] | None = None,
) -> str:
    """Redact LDAP DN domain suffix (DC=x,DC=y,...), reusing existing hostname placeholders."""
    placeholder_values = set(mapping.values())

    def _replace(match: re.Match[str]) -> str:
        leading = match.group(1)
        dc_chain = match.group(2)
        if dc_chain in placeholder_values:
            return match.group(0)

        # Convert DC=north,DC=sevenkingdoms,DC=local → north.sevenkingdoms.local
        parts = re.findall(r"(?i)DC=([a-zA-Z0-9-]+)", dc_chain)
        fqdn = ".".join(parts)
        fqdn_key = fqdn.casefold()

        # Reuse an existing placeholder if hostname_internal already mapped this domain
        placeholder = None
        for key, ph in mapping.items():
            if key.casefold() == fqdn_key:
                placeholder = ph
                break

        if placeholder is None:
            placeholder = _assign_domain_placeholder(
                value=fqdn,
                mapping=mapping,
                counters=counters,
                placeholder_values=placeholder_values,
                applied=None,
                mapping_key=fqdn_key,
            )
        # Keep the LDAP serialization reversible while sharing the underlying
        # domain identity. A composite token restores to the original DC= chain;
        # the inner domain token still restores to the canonical FQDN elsewhere.
        rendered = "DC=" + placeholder
        mapping.setdefault(dc_chain, rendered)
        placeholder_values.add(rendered)
        if applied is not None:
            applied.append((rule.category, dc_chain, rendered))

        return leading + rendered

    return rule.pattern.sub(_replace, text)
