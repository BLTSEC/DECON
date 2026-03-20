"""TOML config loader with profile resolution."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "decon" / "decon.toml"

DEFAULT_CONFIG = """\
default_profile = "standard"

[rules]
# Toggle built-in rules on/off globally
# ipv4 = true
# email = true
# mac = false

[llm]
enabled = false
model = "qwen3.5:9b"
host = "http://localhost:11434"

[custom]
values = []          # case-sensitive literal strings
values_nocase = []   # case-insensitive literal strings
allowlist = []       # values to pass through unredacted
target_domains = []  # target domains — auto-generates hostname rules

# [[custom.patterns]]
# name = "internal_domains"
# pattern = '[a-z0-9-]+\\\\.corp\\\\.example\\\\.com'
# replacement = "HOST_{n:02d}.example.internal"

# [profiles.client-share]
# hostname_internal = true
# custom_values_extra = ["Nighthawk"]
"""


def load_config(path: Path | None = None) -> dict:
    """Load and parse the TOML config file."""
    if path is None:
        path = DEFAULT_CONFIG_PATH

    if not path.exists():
        return {}

    with open(path, "rb") as f:
        return tomllib.load(f)


def resolve_profile(config: dict, profile: str | None = None) -> dict:
    """Resolve rule overrides: global [rules] -> profile -> returns merged dict."""
    rules = dict(config.get("rules", {}))

    if profile is None:
        profile = config.get("default_profile", "standard")

    if profile != "standard":
        profile_cfg = config.get("profiles", {}).get(profile, {})
        rules.update(profile_cfg)

    return rules


def apply_config_to_engine(engine, config: dict, profile: str | None = None) -> None:
    """Apply config settings to a RedactionEngine instance."""
    rule_overrides = resolve_profile(config, profile)

    # Apply rule enable/disable from config
    for rule in engine.rules:
        if rule.name in rule_overrides:
            rule.enabled = bool(rule_overrides[rule.name])

    # Custom literal values
    custom = config.get("custom", {})
    values = custom.get("values", [])
    if values:
        engine.add_custom_values(values, case_sensitive=True)

    values_nocase = custom.get("values_nocase", [])
    if values_nocase:
        engine.add_custom_values(values_nocase, case_sensitive=False)

    # Custom regex patterns
    for pat in custom.get("patterns", []):
        engine.add_custom_pattern(
            name=pat.get("name", "custom"),
            pattern=pat["pattern"],
            replacement=pat.get("replacement", "REDACTED_{n:02d}"),
        )

    # Target domains
    target_domains = custom.get("target_domains", [])
    if target_domains:
        engine.add_target_domains(target_domains)

    # Allowlist
    allowlist = custom.get("allowlist", [])
    if allowlist:
        engine.add_allowlist(allowlist)

    # Profile-specific extra values
    if profile and profile != "standard":
        profile_cfg = config.get("profiles", {}).get(profile, {})
        extra = profile_cfg.get("custom_values_extra", [])
        if extra:
            engine.add_custom_values(extra, case_sensitive=True)


def init_config() -> Path:
    """Create default config file. Returns path."""
    path = DEFAULT_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        print(f"Config already exists: {path}", file=sys.stderr)
    else:
        path.write_text(DEFAULT_CONFIG)
        print(f"Created config: {path}", file=sys.stderr)
    return path


def get_llm_config(config: dict) -> dict:
    """Extract LLM settings from config."""
    return config.get("llm", {})
