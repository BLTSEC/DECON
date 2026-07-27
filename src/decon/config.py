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

[audit]
# Every substitution is logged to ~/.local/state/decon/audit.jsonl.
# The log contains the real values — treat it like a mapping file.
enabled = true
# path = "~/engagement-audit.jsonl"

[ask]
# Provider for --ask. Cloud providers need: pip install 'decon[ask]'
provider = "claude"
# host = "http://localhost:11434"   # ollama only
# max_tokens = 16000
# warn_chars = 50000                # warn above this input size; 0 disables

# [ask.models]                      # per-provider, so --provider is always safe
# claude = "claude-opus-5"
# ollama = "qwen3.5:9b"

[custom]
values = []          # case-sensitive literal strings
values_nocase = []   # case-insensitive literal strings
allowlist = []       # values to pass through unredacted
target_domains = []  # target domains — auto-generates hostname rules

# Typed engagement identifiers — keep their type instead of becoming
# generic [CUSTOM_REDACTED_] placeholders
hostnames = []       # short/NetBIOS host names, e.g. "DC01"
usernames = []       # bare usernames, e.g. "svc_backup"
netbios = []         # NetBIOS domain names, e.g. "ACME"
shares = []          # SMB share names, e.g. "SYSVOL"

# [[custom.patterns]]
# name = "internal_domains"
# pattern = '[a-z0-9-]+\\\\.corp\\\\.example\\\\.com'
# replacement = "[CUSTOM_HOST_REDACTED_{n:04d}]"

# [profiles.client-share]
# hostname_internal = true
# custom_values_extra = ["Nighthawk"]
"""


# Reserved key in [rules] and in any profile: sets every BUILT-IN rule at once.
# A deny-list profile silently drifts as rules are added -- listing 33 rule names
# stops covering the rule added next release. `all` states the intent instead.
# Scoped to built-ins: values declared under [custom] are explicit instructions
# and still apply, so `all = false` never stops redacting your own identifiers.
ALL_RULES = "all"


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
        if name != ALL_RULES and name not in known_rules:
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
            elif name != ALL_RULES and name not in known_rules:
                raise ConfigError(
                    f"Unknown rule in profile {profile_name}: {name}"
                )
            elif name != "custom_values_extra" and not isinstance(enabled, bool):
                raise ConfigError(
                    f"Rule {name} in profile {profile_name} must be true or false"
                )

    # Apply layer by layer ([rules], then the profile) rather than from a
    # flattened dict, so precedence holds in both directions: a profile's
    # `all = true` must be able to re-enable a rule the global table turned off.
    # Within a layer, `all` lands first so its own per-rule keys override it --
    # `all = false` plus `ipv4 = true` yields ipv4 only.
    layers = [global_rules]
    if effective_profile != "standard":
        layers.append(profiles[effective_profile])

    for layer in layers:
        blanket = layer.get(ALL_RULES)
        for rule in engine.rules:
            if blanket is not None:
                rule.enabled = blanket
            if rule.name in layer:
                rule.enabled = layer[rule.name]

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

    # Typed engagement identifiers — unlike custom.values these keep their type,
    # so a hostname stays distinguishable from a username in redacted output.
    for key, add in (
        ("hostnames", engine.add_target_hostnames),
        ("usernames", engine.add_target_usernames),
        ("netbios", engine.add_target_netbios),
        ("shares", engine.add_target_shares),
    ):
        values = _string_list(custom, key, prefix="custom")
        if values:
            add(values)

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

    ask = _require_table(config, "ask")
    providers = ("claude", "openai", "ollama")
    if "provider" in ask and ask["provider"] not in providers:
        raise ConfigError("ask.provider must be claude, openai, or ollama")
    for key in ("model", "host"):
        if key in ask and (
            not isinstance(ask[key], str) or not ask[key].strip()
        ):
            raise ConfigError(f"ask.{key} must be a non-empty string")
    models = ask.get("models", {})
    if not isinstance(models, dict):
        raise ConfigError("ask.models must be a table of provider = model")
    for name, value in models.items():
        if name not in providers:
            raise ConfigError(f"Unknown provider in ask.models: {name}")
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"ask.models.{name} must be a non-empty string")
    if "max_tokens" in ask and (
        not isinstance(ask["max_tokens"], int)
        or isinstance(ask["max_tokens"], bool)
        or ask["max_tokens"] <= 0
    ):
        raise ConfigError("ask.max_tokens must be a positive integer")
    if "warn_chars" in ask and (
        not isinstance(ask["warn_chars"], int)
        or isinstance(ask["warn_chars"], bool)
        or ask["warn_chars"] < 0
    ):
        raise ConfigError("ask.warn_chars must be a non-negative integer")

    audit = _require_table(config, "audit")
    if "enabled" in audit and not isinstance(audit["enabled"], bool):
        raise ConfigError("audit.enabled must be true or false")
    if "path" in audit and (
        not isinstance(audit["path"], str) or not audit["path"].strip()
    ):
        raise ConfigError("audit.path must be a non-empty string")


def init_config(*, quiet: bool = False) -> Path:
    """Create default config file. Returns path."""
    path = DEFAULT_CONFIG_PATH
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if not quiet:
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
    if not quiet:
        print(f"Created config: {path}", file=sys.stderr)
    return path


# Plain-text engagement targets: one "category:value" per line, blank lines and
# # comments ignored. Each category maps onto a typed rule builder, so an entry
# keeps its type instead of collapsing into a generic custom value.
#
# This is a portable, per-engagement alternative to the [custom] tables in
# decon.toml — a file you can hand to a teammate or generate from a scope
# document, rather than per-user configuration.
_TARGET_CATEGORIES = ("domain", "netbios", "username", "hostname", "share")


def load_targets(path: Path | str) -> dict[str, list[str]]:
    """Parse a plain-text targets file into per-category value lists.

    An explicitly supplied path must exist. Silently treating a typo as an
    empty targets file would leave engagement identifiers unredacted.
    """
    target_path = Path(path).expanduser()
    targets: dict[str, list[str]] = {c: [] for c in _TARGET_CATEGORIES}
    if not target_path.exists():
        raise ConfigError(f"Targets file does not exist: {target_path}")

    try:
        lines = target_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as e:
        raise ConfigError(f"Could not read targets file {target_path}: {e}") from e

    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        category, separator, value = line.partition(":")
        category = category.strip().lower()
        value = value.strip()
        if not separator or not value:
            raise ConfigError(
                f"{target_path}:{number}: expected 'category:value', got {line!r}"
            )
        if category not in targets:
            # Silently skipping would leave the value unredacted, which is the
            # worst possible failure mode for a sanitizer.
            known = ", ".join(_TARGET_CATEGORIES)
            raise ConfigError(
                f"{target_path}:{number}: unknown category {category!r} "
                f"(expected one of: {known})"
            )
        targets[category].append(value)
    return targets


def apply_targets(engine, path: Path | str) -> dict[str, list[str]]:
    """Load a targets file and register its rules on an engine."""
    targets = load_targets(path)
    for category, add in (
        ("domain", engine.add_target_domains),
        ("hostname", engine.add_target_hostnames),
        ("username", engine.add_target_usernames),
        ("netbios", engine.add_target_netbios),
        ("share", engine.add_target_shares),
    ):
        if targets[category]:
            add(targets[category])
    return targets


def get_llm_config(config: dict) -> dict:
    """Extract LLM settings from config."""
    return config.get("llm", {})


def get_audit_config(config: dict) -> dict:
    """Extract audit-log settings from config."""
    return config.get("audit", {})
