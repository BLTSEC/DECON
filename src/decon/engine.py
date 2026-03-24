"""RedactionEngine — core redaction logic with consistent placeholder mapping."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from decon.patterns import Rule, build_default_rules

AppliedRedaction = tuple[str, str, str]
_HOST_PLACEHOLDER = re.compile(r"HOST_(\d{2})(?:\.example\.internal)?")


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
    counters: dict[str, int] = field(default_factory=dict)
    allowlist: set[str] = field(default_factory=set)

    def redact(self, text: str) -> str:
        """Redact sensitive data from text using all enabled rules."""
        return self.redact_with_report(text).text

    def redact_with_report(self, text: str) -> RedactionReport:
        """Redact text and return details about replacements applied."""
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
        if not existing_hostname_placeholders:
            text, applied = self._normalize_hostname_placeholders(text, applied)
        return RedactionReport(text=text, applied=applied)

    def unredact(self, text: str) -> str:
        """Replace placeholders with original values using reverse mapping."""
        reverse = {v: k for k, v in self.mapping.items()
                   if v != k}  # skip allowlist identity mappings
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
            self.allowlist.add(value)
            self.mapping[value] = value  # identity mapping

    def add_custom_values(
        self, values: list[str], case_sensitive: bool = True
    ) -> None:
        """Add custom literal values to redact."""
        for value in values:
            flags = 0 if case_sensitive else re.IGNORECASE
            pattern = re.compile(re.escape(value), flags)
            rule = Rule(
                name=f"custom_value_{value[:20]}",
                category="custom",
                priority=50,
                pattern=pattern,
                placeholder_template="REDACTED_{n:02d}",
                mapping_key_fn=(str.casefold if not case_sensitive else None),
            )
            self._add_rule(rule)

    def add_custom_pattern(
        self,
        name: str,
        pattern: str,
        replacement: str = "REDACTED_{n:02d}",
    ) -> None:
        """Add a custom regex pattern rule."""
        rule = Rule(
            name=name,
            category="custom",
            priority=50,
            pattern=re.compile(pattern),
            placeholder_template=replacement,
        )
        self._add_rule(rule)

    def add_target_domains(self, domains: list[str]) -> None:
        """Add target domain rules that match any subdomain."""
        for domain in domains:
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
                placeholder_template="HOST_{n:02d}.example.internal",
                mapping_key_fn=str.casefold,
            )
            self._add_rule(rule)

    def export_map(self, path: str) -> None:
        """Export the current mapping to a JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {"mapping": self.mapping, "counters": self.counters},
                f,
                indent=2,
            )

    def import_map(self, path: str) -> None:
        """Import a mapping from a JSON file for cross-file consistency."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.mapping.update(data.get("mapping", {}))
        for cat, count in data.get("counters", {}).items():
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

        old_id = int(match.group(1))
        new_id = remap_ids.get(old_id, old_id)
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
            placeholder_id = int(match.group(1))
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
