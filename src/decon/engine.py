"""RedactionEngine — core redaction logic with consistent placeholder mapping."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from decon.patterns import Rule, build_default_rules


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
        for rule in self.rules:
            if not rule.enabled:
                continue
            text = rule.apply(text, self.mapping, self.counters)
        return text

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
            )
            self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

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
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    def add_target_domains(self, domains: list[str]) -> None:
        """Add target domain rules that match any subdomain."""
        for domain in domains:
            escaped = re.escape(domain)
            pattern = re.compile(
                r"(?<![.\w])"
                r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
                + escaped
                + r"(?![.\w])"
            )
            rule = Rule(
                name=f"target_{domain}",
                category="hostname",
                priority=44,
                pattern=pattern,
                placeholder_template="HOST_{n:02d}.example.internal",
            )
            self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    def export_map(self, path: str) -> None:
        """Export the current mapping to a JSON file."""
        with open(path, "w") as f:
            json.dump(
                {"mapping": self.mapping, "counters": self.counters},
                f,
                indent=2,
            )

    def import_map(self, path: str) -> None:
        """Import a mapping from a JSON file for cross-file consistency."""
        with open(path) as f:
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
