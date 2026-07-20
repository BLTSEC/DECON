"""RedactionEngine — core redaction logic with consistent placeholder mapping."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from decon.patterns import Rule, build_default_rules

AppliedRedaction = tuple[str, str, str]
_HOST_PLACEHOLDER = re.compile(
    r"(?<![\w])(?:\[HOST_REDACTED_(\d+)\]|\[HOST_SHORT_REDACTED_(\d+)\]|"
    r"HOST_(\d+)(?:\.example\.internal)?)(?![.\w])"
)
# RFC 2849 LDIF line folding: continuation lines start with a single space.
_LDAP_FOLD = re.compile(r"\n (?=\S)")
_LDAP_MARKER = re.compile(r"(?:^|\n)(?:dn|memberOf|ref): ", re.MULTILINE)


@dataclass
class RedactionReport:
    """Detailed result for a single redaction pass."""

    text: str
    applied: list[AppliedRedaction]

    @property
    def changed(self) -> bool:
        """Whether any replacements were applied."""
        return bool(self.applied)

    def unique_applied(self) -> list[AppliedRedaction]:
        """Return applied replacements in first-seen order without duplicates."""
        seen: set[AppliedRedaction] = set()
        unique: list[AppliedRedaction] = []
        for item in self.applied:
            if item in seen:
                continue
            seen.add(item)
            unique.append(item)
        return unique


@dataclass
class RedactionEngine:
    """Applies redaction rules with consistent placeholder mapping.

    Same real value -> same placeholder throughout the entire document.
    """

    rules: list[Rule] = field(default_factory=build_default_rules)
    mapping: dict[str, str] = field(default_factory=dict)
    reverse_mapping: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    allowlist: set[str] = field(default_factory=set)

    def redact(self, text: str) -> str:
        """Redact sensitive data from text using all enabled rules."""
        return self.redact_with_report(text).text

    @staticmethod
    def _unfold_ldap(text: str) -> str:
        """Unfold LDAP/LDIF line continuations (RFC 2849).

        Only applied when LDAP markers (dn:, memberOf:, ref:) are detected
        to avoid mangling non-LDAP output like ASCII art banners.
        """
        if not _LDAP_MARKER.search(text):
            return text
        return _LDAP_FOLD.sub("", text)

    def redact_with_report(self, text: str) -> RedactionReport:
        """Redact text and return details about replacements applied."""
        text = self._unfold_ldap(text)
        existing_hostname_placeholders = {
            value
            for value in self.mapping.values()
            if _HOST_PLACEHOLDER.fullmatch(value)
        }
        applied: list[AppliedRedaction] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            text = rule.apply(text, self.mapping, self.counters, applied)
        text = self._retrospective_replace(text, applied)
        if not existing_hostname_placeholders:
            text, applied = self._normalize_hostname_placeholders(text, applied)
        for _category, original, placeholder in applied:
            if original != placeholder:
                self.reverse_mapping.setdefault(placeholder, original)
        return RedactionReport(text=text, applied=applied)

    def _retrospective_replace(
        self,
        text: str,
        applied: list[AppliedRedaction],
    ) -> str:
        """Replace remaining standalone occurrences of already-mapped values.

        After all pattern rules run, some mapped values (hostnames, domains,
        usernames) may still appear in contexts that no rule anticipated.
        This pass uses word boundaries to replace them case-insensitively.

        Only applies to short identifier-like values (4-30 chars, no special
        characters) mapped to HOST_, DOMAIN_USER_, or example* placeholders
        to minimize false positive risk.
        """
        # Collect safe candidates: identifiers already mapped by pattern rules
        _safe_prefixes = (
            "[HOST_",
            "HOST_",  # legacy mappings
            "DOMAIN_USER_",
            "[DOMAIN_REDACTED_",
        )
        candidates: list[tuple[str, str]] = []
        for original, placeholder in self.mapping.items():
            if original == placeholder:  # allowlist identity
                continue
            if not any(placeholder.startswith(p) for p in _safe_prefixes):
                continue
            # Skip very short values (false positive risk) and non-identifiers
            if len(original) < 4:
                continue
            # Allow FQDNs up to 80 chars (hostname.subdomain.domain.tld patterns)
            # but cap other identifiers at 30 to skip hashes and long values
            is_fqdn = "." in original and placeholder.startswith(
                ("[HOST_", "HOST_", "[DOMAIN_REDACTED_")
            )
            if len(original) > 80 or (len(original) > 30 and not is_fqdn):
                continue
            if not re.fullmatch(r"[a-zA-Z0-9._$-]+", original):
                continue
            candidates.append((original, placeholder))

        if not candidates:
            return text

        # Sort longest-first to avoid partial replacement
        candidates.sort(key=lambda x: len(x[0]), reverse=True)
        for original, placeholder in candidates:
            # Domain-type entries (example*.internal) use a permissive lookbehind
            # that allows '.' before the match — catches subdomains like
            # _msdcs.sevenkingdoms.local where the domain appears after a dot.
            # Hostname/user entries use strict boundaries to avoid partial matches.
            if placeholder.startswith("[DOMAIN_REDACTED_"):
                lookbehind = r"(?<!\w)"
            else:
                lookbehind = r"(?<![.\w])"
            pattern = re.compile(
                lookbehind + re.escape(original) + r"(?![.\w])",
                re.IGNORECASE,
            )
            new_text = pattern.sub(placeholder, text)
            if new_text != text:
                # Track the replacement if new occurrences were found
                if placeholder.startswith(("[HOST_", "HOST_")):
                    cat = "hostname"
                elif placeholder.startswith("DOMAIN_USER_"):
                    cat = "ad_domain_user"
                else:
                    cat = "domain"
                applied.append((cat, original, placeholder))
                text = new_text

        return text

    def unredact(self, text: str) -> str:
        """Replace placeholders with original values using reverse mapping."""
        reverse = dict(self.reverse_mapping)
        for original, placeholder in self.mapping.items():
            if original != placeholder:
                reverse.setdefault(placeholder, original)
        # Sort by length (longest first) to avoid partial replacements
        for placeholder in sorted(reverse, key=len, reverse=True):
            text = text.replace(placeholder, reverse[placeholder])
        return text

    def enable_rule(self, name: str) -> None:
        """Enable a rule by name."""
        for rule in self.rules:
            if rule.name == name:
                rule.enabled = True
                return
        raise ValueError(f"Unknown rule: {name}")

    def disable_rule(self, name: str) -> None:
        """Disable a rule by name."""
        for rule in self.rules:
            if rule.name == name:
                rule.enabled = False
                return
        raise ValueError(f"Unknown rule: {name}")

    def add_allowlist(self, values: list[str]) -> None:
        """Add values to the allowlist (they will pass through unredacted)."""
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("allowlist values must be non-empty strings")
            previous = self.mapping.get(value)
            self.allowlist.add(value)
            self.mapping[value] = value  # identity mapping
            if (
                previous is not None
                and previous != value
                and previous not in self.mapping.values()
            ):
                self.reverse_mapping.pop(previous, None)

    def add_custom_values(
        self, values: list[str], case_sensitive: bool = True
    ) -> None:
        """Add custom literal values to redact."""
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("custom values must be non-empty strings")
            flags = 0 if case_sensitive else re.IGNORECASE
            pattern = re.compile(re.escape(value), flags)
            rule = Rule(
                name=f"custom_value_{value[:20]}",
                category="custom",
                priority=50,
                pattern=pattern,
                placeholder_template="[CUSTOM_REDACTED_{n:04d}]",
                mapping_key_fn=(str.casefold if not case_sensitive else None),
            )
            self._add_rule(rule)

    def add_custom_pattern(
        self,
        name: str,
        pattern: str,
        replacement: str = "[CUSTOM_REDACTED_{n:04d}]",
    ) -> None:
        """Add a custom regex pattern rule."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("custom pattern name must be a non-empty string")
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("custom pattern must be a non-empty string")
        if not isinstance(replacement, str) or not replacement:
            raise ValueError("placeholder template must be a non-empty string")
        compiled = re.compile(pattern)
        if compiled.search("") is not None:
            raise ValueError("custom pattern must not match empty text")
        try:
            first = replacement.format(n=1)
            second = replacement.format(n=2)
        except (KeyError, IndexError, ValueError) as e:
            raise ValueError(f"invalid placeholder template: {e}") from e
        if not first or first == second:
            raise ValueError("placeholder template must vary with {n}")
        rule = Rule(
            name=name,
            category="custom",
            priority=50,
            pattern=compiled,
            placeholder_template=replacement,
        )
        self._add_rule(rule)

    def add_target_domains(self, domains: list[str]) -> None:
        """Add target domain rules that match any subdomain."""
        for domain in domains:
            if not isinstance(domain, str) or not domain.strip():
                raise ValueError("target domains must be non-empty strings")
            escaped = re.escape(domain)
            pattern = re.compile(
                r"(?<![.\w])"
                r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
                + escaped
                + r"(?![.\w])",
                re.IGNORECASE,
            )
            rule = Rule(
                name=f"target_{domain}",
                category="hostname",
                priority=44,
                pattern=pattern,
                placeholder_template="[HOST_REDACTED_{n:04d}]",
                mapping_key_fn=str.casefold,
            )
            self._add_rule(rule)

    def export_map(self, path: str) -> None:
        """Export the current mapping atomically with owner-only permissions."""
        destination = Path(path)
        fd, temporary_path = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "version": 2,
                        "mapping": self.mapping,
                        "reverse_mapping": self.reverse_mapping,
                        "counters": self.counters,
                    },
                    f,
                    indent=2,
                )
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary_path, destination)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise

    def import_map(self, path: str) -> None:
        """Import a mapping from a JSON file for cross-file consistency."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("mapping file root must be a JSON object")
        version = data.get("version", 1)
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version not in (1, 2)
        ):
            raise ValueError(f"unsupported mapping file version: {version!r}")
        if version == 2 and "reverse_mapping" not in data:
            raise ValueError("version 2 mapping file is missing reverse_mapping")
        imported_mapping = data.get("mapping", {})
        imported_reverse = data.get("reverse_mapping", {})
        imported_counters = data.get("counters", {})
        if not isinstance(imported_mapping, dict) or not all(
            isinstance(key, str)
            and bool(key)
            and isinstance(value, str)
            and bool(value)
            for key, value in imported_mapping.items()
        ):
            raise ValueError(
                "mapping must be an object containing non-empty string keys and values"
            )
        if not isinstance(imported_reverse, dict) or not all(
            isinstance(key, str)
            and bool(key)
            and isinstance(value, str)
            and bool(value)
            for key, value in imported_reverse.items()
        ):
            raise ValueError(
                "reverse_mapping must contain non-empty string keys and values"
            )
        unknown_reverse_keys = set(imported_reverse) - set(imported_mapping.values())
        if unknown_reverse_keys:
            raise ValueError(
                "reverse_mapping contains placeholders absent from mapping"
            )
        if not isinstance(imported_counters, dict) or not all(
            isinstance(cat, str)
            and bool(cat)
            and isinstance(count, int)
            and not isinstance(count, bool)
            and count >= 0
            for cat, count in imported_counters.items()
        ):
            raise ValueError("counters must be an object containing non-negative integers")

        self.mapping.update(imported_mapping)
        self.reverse_mapping.update(imported_reverse)
        for original, placeholder in imported_mapping.items():
            if original != placeholder:
                self.reverse_mapping.setdefault(placeholder, original)
        valid_placeholders = set(self.mapping.values())
        self.reverse_mapping = {
            placeholder: original
            for placeholder, original in self.reverse_mapping.items()
            if placeholder in valid_placeholders
        }
        for cat, count in imported_counters.items():
            self.counters[cat] = max(self.counters.get(cat, 0), count)

    def get_stats(self) -> dict[str, int]:
        """Return redaction counts per category."""
        return dict(self.counters)

    def list_rules(self) -> list[dict[str, str | int | bool]]:
        """Return info about all rules."""
        return [
            {
                "name": r.name,
                "category": r.category,
                "priority": r.priority,
                "enabled": r.enabled,
            }
            for r in self.rules
        ]

    def _add_rule(self, rule: Rule) -> None:
        """Add a rule and keep rule order stable by priority."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    @staticmethod
    def _remap_hostname_placeholder(
        value: str,
        remap_ids: dict[int, int],
    ) -> str:
        """Remap a hostname placeholder while preserving short/full style."""
        match = _HOST_PLACEHOLDER.fullmatch(value)
        if not match:
            return value

        old_id = int(match.group(1) or match.group(2) or match.group(3))
        new_id = remap_ids.get(old_id, old_id)
        if value.startswith("[HOST_REDACTED_"):
            return f"[HOST_REDACTED_{new_id:04d}]"
        if value.startswith("[HOST_SHORT_REDACTED_"):
            return f"[HOST_SHORT_REDACTED_{new_id:04d}]"
        if value.endswith(".example.internal"):
            return f"HOST_{new_id:02d}.example.internal"
        return f"HOST_{new_id:02d}"

    def _normalize_hostname_placeholders(
        self,
        text: str,
        applied: list[AppliedRedaction],
    ) -> tuple[str, list[AppliedRedaction]]:
        """Renumber hostname placeholders by first textual appearance.

        This runs only when the engine had no preexisting hostname placeholders,
        so it preserves cross-document consistency for imported/shared mappings.
        """
        ordered_ids: list[int] = []
        seen_ids: set[int] = set()
        for match in _HOST_PLACEHOLDER.finditer(text):
            placeholder_id = int(match.group(1) or match.group(2) or match.group(3))
            if placeholder_id in seen_ids:
                continue
            seen_ids.add(placeholder_id)
            ordered_ids.append(placeholder_id)

        remap_ids = {
            old_id: index
            for index, old_id in enumerate(ordered_ids, start=1)
            if old_id != index
        }
        if not remap_ids:
            self.counters["hostname"] = max(self.counters.get("hostname", 0), len(ordered_ids))
            return text, applied

        text = _HOST_PLACEHOLDER.sub(
            lambda m: self._remap_hostname_placeholder(m.group(0), remap_ids),
            text,
        )
        self.mapping = {
            key: self._remap_hostname_placeholder(value, remap_ids)
            for key, value in self.mapping.items()
        }
        self.counters["hostname"] = len(ordered_ids)
        applied = [
            (
                category,
                value,
                (
                    self._remap_hostname_placeholder(placeholder, remap_ids)
                    if category == "hostname"
                    else placeholder
                ),
            )
            for category, value, placeholder in applied
        ]
        return text, applied
