"""Public function API for using DECON as a library.

The CLI is the primary interface, but a sanitization proxy is often something
you want to call from a script:

    from decon import sanitize, desanitize, ask_safely

    clean, mapping = sanitize(raw_notes)
    answer, mapping = ask_safely("What are two attack paths?")

`mapping` is placeholder -> original, which is the direction you need to
restore text and the shape `desanitize()` expects. Note this is the inverse of
`RedactionEngine.mapping`, which is keyed by the original value.

Engagement identifiers can be supplied either through DECON's TOML config or a
plain-text targets file (`category:value` per line, one of domain, netbios,
username, hostname, share). The TOML config is applied first, so a targets file
adds to it rather than replacing it.
"""

from __future__ import annotations

import os
from pathlib import Path

from decon.ask import (
    DEFAULT_CLI_MODE,
    DEFAULT_CLI_TIMEOUT_SECONDS,
    DEFAULT_MAX_TOKENS,
    DEFAULT_PROVIDER,
)
from decon.ask import ask as _ask
from decon.audit import write_entry
from decon.config import (
    apply_config_to_engine,
    apply_targets,
    get_audit_config,
    load_config,
)
from decon.engine import RedactionEngine

__all__ = [
    "build_engine",
    "sanitize",
    "desanitize",
    "ask_safely",
]


def _build_engine_with_config(
    targets_path: Path | str | None = None,
    *,
    profile: str | None = None,
    use_config: bool = True,
) -> tuple[RedactionEngine, dict]:
    """Build an engine and return the configuration that was applied."""
    engine = RedactionEngine()
    config: dict = {}
    if use_config:
        config = load_config()
        apply_config_to_engine(
            engine,
            config,
            profile or os.environ.get("DECON_PROFILE"),
        )
    if targets_path is not None:
        apply_targets(engine, targets_path)
    return engine, config


def build_engine(
    targets_path: Path | str | None = None,
    *,
    profile: str | None = None,
    use_config: bool = True,
) -> RedactionEngine:
    """Return an engine with config and any targets-file rules applied.

    Set `use_config=False` for a deterministic engine that ignores the
    developer's own ~/.config/decon/decon.toml — useful in tests.
    """
    engine, _config = _build_engine_with_config(
        targets_path,
        profile=profile,
        use_config=use_config,
    )
    return engine


def sanitize(
    text: str,
    targets_path: Path | str | None = None,
    *,
    profile: str | None = None,
    use_config: bool = True,
) -> tuple[str, dict[str, str]]:
    """Redact text, returning the redacted text and a placeholder -> original map."""
    engine = build_engine(
        targets_path,
        profile=profile,
        use_config=use_config,
    )
    return engine.redact(text), engine.reverse_map()


def desanitize(text: str, mapping: dict[str, str]) -> str:
    """Restore original values in text using a placeholder -> original map."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not isinstance(mapping, dict) or not all(
        isinstance(placeholder, str)
        and bool(placeholder)
        and isinstance(original, str)
        and bool(original)
        for placeholder, original in mapping.items()
    ):
        raise ValueError(
            "mapping must contain non-empty string placeholders and original values"
        )
    # Reuse the engine's boundary-aware restoration. Literal str.replace()
    # would turn a mutated token such as [IPV4_REDACTED_0001]0 into a plausible
    # but incorrect address.
    engine = RedactionEngine(rules=[])
    engine.reverse_mapping.update(mapping)
    return engine.unredact(text)


def ask_safely(
    prompt: str,
    provider: str = DEFAULT_PROVIDER,
    targets_path: Path | str | None = None,
    *,
    model: str | None = None,
    host: str = "http://localhost:11434",
    max_tokens: int = DEFAULT_MAX_TOKENS,
    cli_mode: str = DEFAULT_CLI_MODE,
    cli_timeout_seconds: int = DEFAULT_CLI_TIMEOUT_SECONDS,
    profile: str | None = None,
    use_config: bool = True,
    audit: bool = True,
) -> tuple[str, dict[str, str]]:
    """Sanitize a prompt, send it to a provider, and restore the response.

    Returns the restored response and the placeholder -> original map used.
    Only the engine's sanitized output leaves this process; the original prompt
    is never sent directly. As with every regex-based sanitizer, callers must
    still account for identifiers no configured rule recognizes. Raises
    AskError if the provider is unavailable or declines.
    """
    engine, config = _build_engine_with_config(
        targets_path,
        profile=profile,
        use_config=use_config,
    )
    report = engine.redact_with_report(prompt)
    mapping = engine.reverse_map()

    # A provider can fail after receiving the request, so record the attempt
    # before crossing the trust boundary without claiming a completed response.
    audit_config = get_audit_config(config)
    if audit and audit_config.get("enabled", True):
        write_entry(
            report.unique_applied(),
            mode="ask_safely",
            status="attempted",
            sources=[f"<{provider}>"],
            path=audit_config.get("path"),
            quiet=True,
        )

    # The whole prompt is the question here; there is no separate document.
    answer = _ask(
        report.text,
        "",
        provider=provider,
        model=model,
        host=host,
        max_tokens=max_tokens,
        cli_mode=cli_mode,
        cli_timeout_seconds=cli_timeout_seconds,
    )
    restored = desanitize(answer, mapping)

    return restored, mapping
