"""TOML config loader with profile resolution."""

from __future__ import annotations

import os
import re
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
# replacement = "[CUSTOM_HOST_REDACTED_{n:04d}]"

# [profiles.client-share]
# hostname_internal = true
# custom_values_extra = ["Nighthawk"]
"""


class ConfigError(ValueError):
    """Raised when the DECON config file is invalid."""


def _require_table(config: dict, key: str) -> dict:
    """Return a TOML table, rejecting values of the wrong type."""
    value = config.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be a table")
    return value


def _string_list(table: dict, key: str, *, prefix: str) -> list[str]:
    """Return a list of non-empty strings from a configuration table."""
    value = table.get(key, [])
    qualified = f"{prefix}.{key}"
    if not isinstance(value, list):
        raise ConfigError(f"{qualified} must be an array of strings")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ConfigError(f"{qualified} must contain only non-empty strings")
    return value


def load_config(path: Path | None = None) -> dict:
    """Load and parse the TOML config file."""
    if path is None:
        path = DEFAULT_CONFIG_PATH

    if not path.exists():
        return {}

    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"Invalid TOML in config {path}: {e}") from e
    except OSError as e:
        raise ConfigError(f"Could not read config {path}: {e}") from e


def resolve_profile(config: dict, profile: str | None = None) -> dict:
    """Resolve rule overrides: global [rules] -> profile -> returns merged dict."""
    if not isinstance(config, dict):
        raise ConfigError("config root must be a table")
    rules = dict(_require_table(config, "rules"))

    if profile is None:
        profile = config.get("default_profile", "standard")

    if profile != "standard":
        profiles = _require_table(config, "profiles")
        if profile not in profiles:
            raise ConfigError(f"Unknown profile: {profile}")
        profile_cfg = profiles[profile]
        if not isinstance(profile_cfg, dict):
            raise ConfigError(f"profiles.{profile} must be a table")
        rules.update(profile_cfg)

    return rules


def apply_config_to_engine(engine, config: dict, profile: str | None = None) -> None:
    """Apply config settings to a RedactionEngine instance."""
    if not isinstance(config, dict):
        raise ConfigError("config root must be a table")

    configured_default = config.get("default_profile", "standard")
    if not isinstance(configured_default, str) or not configured_default.strip():
        raise ConfigError("default_profile must be a non-empty string")

    profiles = _require_table(config, "profiles")
    effective_profile = profile or config.get("default_profile", "standard")
    if not isinstance(effective_profile, str) or not effective_profile.strip():
        raise ConfigError("profile must be a non-empty string")
    if effective_profile != "standard" and effective_profile not in profiles:
        raise ConfigError(f"Unknown profile: {effective_profile}")

    known_rules = {rule.name for rule in engine.rules}
    global_rules = _require_table(config, "rules")
    for name, enabled in global_rules.items():
        if name not in known_rules:
            raise ConfigError(f"Unknown rule in config: {name}")
        if not isinstance(enabled, bool):
            raise ConfigError(f"Rule {name} must be true or false")

    for profile_name, profile_cfg in profiles.items():
        if not isinstance(profile_name, str) or not profile_name.strip():
            raise ConfigError("profile names must be non-empty strings")
        if not isinstance(profile_cfg, dict):
            raise ConfigError(f"profiles.{profile_name} must be a table")
        for name, enabled in profile_cfg.items():
            if name == "custom_values_extra":
                _string_list(
                    profile_cfg,
                    name,
                    prefix=f"profiles.{profile_name}",
                )
            elif name not in known_rules:
                raise ConfigError(
                    f"Unknown rule in profile {profile_name}: {name}"
                )
            elif not isinstance(enabled, bool):
                raise ConfigError(
                    f"Rule {name} in profile {profile_name} must be true or false"
                )

    rule_overrides = resolve_profile(config, effective_profile)

    # Apply rule enable/disable from config
    for rule in engine.rules:
        if rule.name in rule_overrides:
            rule.enabled = rule_overrides[rule.name]

    # Custom literal values
    custom = _require_table(config, "custom")
    values = _string_list(custom, "values", prefix="custom")
    if values:
        engine.add_custom_values(values, case_sensitive=True)

    values_nocase = _string_list(custom, "values_nocase", prefix="custom")
    if values_nocase:
        engine.add_custom_values(values_nocase, case_sensitive=False)

    # Custom regex patterns
    patterns = custom.get("patterns", [])
    if not isinstance(patterns, list):
        raise ConfigError("custom.patterns must be an array of tables")
    for i, pat in enumerate(patterns, start=1):
        if not isinstance(pat, dict):
            raise ConfigError(
                f"custom.patterns[{i}] must be a table with at least a pattern"
            )
        pattern = pat.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ConfigError(
                f"custom.patterns[{i}].pattern must be a non-empty string"
            )
        name = pat.get("name", "custom")
        replacement = pat.get("replacement", "[CUSTOM_REDACTED_{n:04d}]")
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"custom.patterns[{i}].name must be a non-empty string")
        if not isinstance(replacement, str) or not replacement:
            raise ConfigError(
                f"custom.patterns[{i}].replacement must be a non-empty string"
            )
        try:
            compiled = re.compile(pattern)
            if compiled.search("") is not None:
                raise ConfigError(
                    f"custom.patterns[{i}].pattern must not match empty text"
                )
            replacement.format(n=1)
            engine.add_custom_pattern(
                name=name,
                pattern=pattern,
                replacement=replacement,
            )
        except re.error as e:
            raise ConfigError(
                f"Invalid regex in custom.patterns[{i}] ({name}): {e}"
            ) from e
        except ConfigError:
            raise
        except (KeyError, IndexError, ValueError) as e:
            raise ConfigError(
                f"Invalid replacement in custom.patterns[{i}] ({name}): {e}"
            ) from e

    # Target domains
    target_domains = _string_list(custom, "target_domains", prefix="custom")
    if target_domains:
        engine.add_target_domains(target_domains)

    # Allowlist
    allowlist = _string_list(custom, "allowlist", prefix="custom")
    if allowlist:
        engine.add_allowlist(allowlist)

    # Profile-specific extra values
    if effective_profile != "standard":
        profile_cfg = profiles[effective_profile]
        if not isinstance(profile_cfg, dict):
            raise ConfigError(f"profiles.{effective_profile} must be a table")
        extra = _string_list(
            profile_cfg,
            "custom_values_extra",
            prefix=f"profiles.{effective_profile}",
        )
        if extra:
            engine.add_custom_values(extra, case_sensitive=True)

    llm = _require_table(config, "llm")
    if "enabled" in llm and not isinstance(llm["enabled"], bool):
        raise ConfigError("llm.enabled must be true or false")
    for key in ("model", "host"):
        if key in llm and (
            not isinstance(llm[key], str) or not llm[key].strip()
        ):
            raise ConfigError(f"llm.{key} must be a non-empty string")


def init_config() -> Path:
    """Create default config file. Returns path."""
    path = DEFAULT_CONFIG_PATH
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"Config already exists: {path}", file=sys.stderr)
        return path
    except OSError as e:
        raise ConfigError(f"Could not create config {path}: {e}") from e

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(DEFAULT_CONFIG)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            path.unlink()
        except OSError:
            pass
        raise
    print(f"Created config: {path}", file=sys.stderr)
    return path


def get_llm_config(config: dict) -> dict:
    """Extract LLM settings from config."""
    return config.get("llm", {})
