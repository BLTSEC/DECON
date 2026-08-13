"""RedactionEngine — core redaction logic with consistent placeholder mapping."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from decon.default_rules import build_default_rules
from decon.patterns import (
    Rule,
    _apply_group,
    _rdns_hostname_apply,
)

AppliedRedaction = tuple[str, str, str]
_HOST_PLACEHOLDER = re.compile(
    r"(?<![\w])(?:\[HOST_REDACTED_(\d+)\]|\[HOST_SHORT_REDACTED_(\d+)\]|"
    r"HOST_(\d+)(?:\.example\.internal)?)(?![.\w])"
)
# Any DECON-shaped placeholder, bracketed or bare. Deliberately looser than
# patterns._TYPED_PLACEHOLDER (which validates an exact known type) so that a
# reformatted or foreign placeholder is still recognised as one.
_ANY_PLACEHOLDER = re.compile(
    r"\[[A-Z][A-Z0-9_]*_REDACTED_\d+\](?:/\d{1,3})?"
    r"|(?<![\w])(?:[A-Z][A-Z0-9_]*_)?(?:HASH|KEY|DUMP|USER|PATH|SPN|SID)_\d+(?![\w])"
    r"|(?<![\w])[A-Z][A-Z0-9_]*_REDACTED_\d+(?![\w])"
    r"|(?<![\w])HOST_\d+(?:\.example\.internal)?(?![.\w])"
)

# RFC 2849 LDIF line folding: continuation lines start with a single space.
# Scope unfolding to LDAP attributes instead of stripping indentation globally
# as soon as a document happens to contain one LDAP marker.
_LDAP_FOLDED_VALUE = re.compile(
    r"^(?:dn|memberOf|ref):[^\r\n]*(?:\r?\n [^\r\n]*)+",
    re.IGNORECASE | re.MULTILINE,
)
_LDAP_FOLD = re.compile(r"\r?\n (?=\S)")


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

        Only continuation lines belonging to recognized LDAP attributes are
        unfolded. Indented prose elsewhere in a mixed document is preserved.
        """
        return _LDAP_FOLDED_VALUE.sub(
            lambda match: _LDAP_FOLD.sub("", match.group(0)),
            text,
        )

    def redact_with_report(self, text: str) -> RedactionReport:
        """Redact text and return details about replacements applied."""
        text = self._unfold_ldap(text)
        # Reserve every placeholder token already present in the input. Without
        # this, a fresh value can be assigned the same token and unredaction
        # silently replaces both the foreign token and the value we redacted.
        transient_reservations: list[str] = []
        for match in _ANY_PLACEHOLDER.finditer(text):
            placeholder = match.group(0)
            reservations = {placeholder}
            host_match = _HOST_PLACEHOLDER.fullmatch(placeholder)
            if host_match:
                index = int(
                    host_match.group(1) or host_match.group(2) or host_match.group(3)
                )
                # Legacy, FQDN, short, and modern host tokens share one logical
                # namespace even though their rendered strings differ.
                reservations.update(
                    {
                        f"[HOST_REDACTED_{index:04d}]",
                        f"[HOST_SHORT_REDACTED_{index:04d}]",
                        f"HOST_{index:02d}",
                        f"HOST_{index:02d}.example.internal",
                    }
                )
            for reservation in reservations:
                if reservation not in self.mapping:
                    self.mapping[reservation] = reservation
                    transient_reservations.append(reservation)
        existing_hostname_placeholders = {
            value
            for value in self.mapping.values()
            if _HOST_PLACEHOLDER.fullmatch(value)
        }
        applied: list[AppliedRedaction] = []
        try:
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
        finally:
            # Reservations are allocation guards, not user mappings. Keeping
            # them would pollute exported maps and violate double-pass behavior.
            for placeholder in transient_reservations:
                if self.mapping.get(placeholder) == placeholder:
                    self.mapping.pop(placeholder, None)

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

        # Apply each boundary class in a single pass. The previous one-regex-per-
        # identity loop made large AD datasets quadratic in document size.
        domain_candidates = [
            item for item in candidates if item[1].startswith("[DOMAIN_REDACTED_")
        ]
        strict_candidates = [
            item for item in candidates if not item[1].startswith("[DOMAIN_REDACTED_")
        ]

        def _replace_candidates(
            current: str,
            items: list[tuple[str, str]],
            lookbehind: str,
        ) -> str:
            if not items:
                return current
            by_value: dict[str, tuple[str, str]] = {}
            for original, placeholder in sorted(
                items, key=lambda item: len(item[0]), reverse=True
            ):
                by_value.setdefault(original.casefold(), (original, placeholder))
            alternatives = "|".join(
                re.escape(original) for original, _placeholder in by_value.values()
            )
            pattern = re.compile(
                lookbehind + "(?:" + alternatives + r")(?![.\w])",
                re.IGNORECASE,
            )

            def _replace(match: re.Match[str]) -> str:
                original, placeholder = by_value[match.group(0).casefold()]
                if placeholder.startswith(("[HOST_", "HOST_")):
                    category = "hostname"
                elif placeholder.startswith("DOMAIN_USER_"):
                    category = "ad_domain_user"
                else:
                    category = "domain"
                applied.append((category, original, placeholder))
                return placeholder

            return pattern.sub(_replace, current)

        # Domains allow a preceding dot so parent domains inside a subdomain are
        # found; hostnames and users retain strict standalone boundaries.
        text = _replace_candidates(text, domain_candidates, r"(?<!\w)")
        text = _replace_candidates(text, strict_candidates, r"(?<![.\w])")

        return text

    @staticmethod
    def _replacement_pattern(placeholders: set[str]) -> re.Pattern[str] | None:
        """Compile a pattern matching only complete, standalone placeholders."""
        if not placeholders:
            return None
        alternatives = "|".join(
            re.escape(value) for value in sorted(placeholders, key=len, reverse=True)
        )
        # Reject alphanumeric extensions (TOKEN0) and domain-like embedding
        # (TOKEN.attacker.test), while allowing ordinary sentence punctuation.
        return re.compile(r"(?<![-.\w])(?:" + alternatives + r")(?!\w|[-.]\w)")

    def reverse_map(self) -> dict[str, str]:
        """Return placeholder -> original for everything this engine knows.

        This is the direction a caller needs to restore text, and the shape
        the public sanitize()/desanitize() API hands back.
        """
        reverse = dict(self.reverse_mapping)
        for original, placeholder in self.mapping.items():
            if original != placeholder:
                reverse.setdefault(placeholder, original)
        return reverse

    def unredact(self, text: str) -> str:
        """Replace placeholders with original values using reverse mapping."""
        reverse = self.reverse_map()
        pattern = self._replacement_pattern(set(reverse))
        if pattern is None:
            return text
        return pattern.sub(lambda match: reverse[match.group(0)], text)

    def applied_for_unredaction(self, text: str) -> list[AppliedRedaction]:
        """Return the mappings that unredact() would use on this text.

        Lets a caller record what a restore actually re-materialized, rather
        than the whole map.
        """
        reverse = self.reverse_map()
        pattern = self._replacement_pattern(set(reverse))
        if pattern is None:
            return []
        restored: list[AppliedRedaction] = []
        seen: set[str] = set()
        for match in pattern.finditer(text):
            placeholder = match.group(0)
            if placeholder in seen:
                continue
            seen.add(placeholder)
            restored.append(("restore", reverse[placeholder], placeholder))
        return restored

    def unresolved_placeholders(self, text: str) -> list[str]:
        """Return DECON-shaped placeholders in text that this engine cannot map.

        After unredact(), anything still matching a placeholder pattern was
        never restored — usually because it was reformatted (zero-padding
        dropped, wrapped in markdown) or belongs to a different map.
        """
        seen: set[str] = set()
        unresolved: list[str] = []
        for match in _ANY_PLACEHOLDER.finditer(text):
            value = match.group(0)
            if value in seen:
                continue
            seen.add(value)
            unresolved.append(value)
        return unresolved

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

    def add_custom_values(self, values: list[str], case_sensitive: bool = True) -> None:
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

    def _add_literal_target_rules(
        self,
        values: list[str],
        *,
        kind: str,
        category: str,
        placeholder_template: str,
        priority: int,
        apply_fn=None,
    ) -> None:
        """Register one case-insensitive literal rule per engagement identifier.

        Shared by the typed target helpers below. Unlike add_custom_values(),
        these keep their type: a hostname becomes a HOST placeholder and a
        username a DOMAIN_USER placeholder, so the redacted text still
        distinguishes a host from a user from a share.
        """
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"target {kind} must be non-empty strings")
            # Group 2 holds the identifier so hostname rules can share
            # _rdns_hostname_apply, which replaces that group.
            #
            # Boundaries reject a dot only when it continues a domain label, so
            # DC01 does not match inside DC01.corp.example.com but does match at
            # the end of a sentence ("...readable by jsmith.").
            pattern = re.compile(
                r"(?<!\w)(?<!\w\.)"
                r"()(" + re.escape(value) + r")"
                r"(?!\w)(?!\.\w)",
                re.IGNORECASE,
            )
            rule = Rule(
                name=f"target_{kind}_{value}",
                category=category,
                priority=priority,
                pattern=pattern,
                placeholder_template=placeholder_template,
                mapping_key_fn=str.casefold,
                apply_fn=apply_fn or _apply_group(2),
            )
            self._add_rule(rule)

    def add_target_hostnames(self, hostnames: list[str]) -> None:
        """Add short/NetBIOS hostname rules (DC01, FILESERV01).

        Runs after hostname_internal at the same priority, so a bare DC01
        reuses the placeholder already assigned to DC01.corp.example.com
        rather than minting a second identity for the same machine.
        """
        self._add_literal_target_rules(
            hostnames,
            kind="hostname",
            category="hostname",
            placeholder_template="[HOST_SHORT_REDACTED_{n:04d}]",
            priority=44,
            apply_fn=_rdns_hostname_apply,
        )

    def add_target_usernames(self, usernames: list[str]) -> None:
        """Add bare username rules (jsmith, svc_backup)."""
        self._add_literal_target_rules(
            usernames,
            kind="username",
            category="ad_domain_user",
            placeholder_template="DOMAIN_USER_{n:02d}",
            priority=45,
        )

    def add_target_netbios(self, names: list[str]) -> None:
        """Add short NetBIOS domain rules (ACME, EMBERGLASS)."""
        self._add_literal_target_rules(
            names,
            kind="netbios",
            category="domain",
            placeholder_template="[DOMAIN_REDACTED_{n:04d}]",
            priority=45,
        )

    def add_target_shares(self, shares: list[str]) -> None:
        """Add SMB share name rules (SYSVOL, HR-Data)."""
        self._add_literal_target_rules(
            shares,
            kind="share",
            category="share",
            placeholder_template="[SHARE_REDACTED_{n:04d}]",
            priority=45,
        )

    def export_map(
        self,
        path: str,
        *,
        session_metadata: dict[str, str] | None = None,
    ) -> None:
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
                payload = {
                    "version": 2,
                    "mapping": self.mapping,
                    "reverse_mapping": self.reverse_mapping,
                    "counters": self.counters,
                }
                if session_metadata is not None:
                    payload["session"] = session_metadata
                json.dump(payload, f, indent=2)
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
            raise ValueError(
                "counters must be an object containing non-negative integers"
            )

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
            self.counters["hostname"] = max(
                self.counters.get("hostname", 0), len(ordered_ids)
            )
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
