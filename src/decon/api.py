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

from decon.ask import DEFAULT_MAX_TOKENS, DEFAULT_PROVIDER
from decon.ask import ask as _ask
from decon.audit import write_entry
from decon.config import (
    apply_config_to_engine,
    apply_targets,
    load_config,
)
from decon.engine import RedactionEngine

__all__ = [
    "build_engine",
    "sanitize",
    "desanitize",
    "ask_safely",
]


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
    engine = RedactionEngine()
    if use_config:
        config = load_config()
        apply_config_to_engine(
            engine,
            config,
            profile or os.environ.get("DECON_PROFILE"),
        )
    if targets_path is not None:
        apply_targets(engine, targets_path)
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
    # Longest first, so a placeholder that is a prefix of another cannot be
    # partially replaced.
    for placeholder in sorted(mapping, key=len, reverse=True):
        text = text.replace(placeholder, mapping[placeholder])
    return text


def ask_safely(
    prompt: str,
    provider: str = DEFAULT_PROVIDER,
    targets_path: Path | str | None = None,
    *,
    model: str | None = None,
    host: str = "http://localhost:11434",
    max_tokens: int = DEFAULT_MAX_TOKENS,
    profile: str | None = None,
    use_config: bool = True,
    audit: bool = True,
) -> tuple[str, dict[str, str]]:
    """Sanitize a prompt, send it to a provider, and restore the response.

    Returns the restored response and the placeholder -> original map used.
    Only redacted text leaves this process; the provider never sees a real
    value. Raises AskError if the provider is unavailable or declines.
    """
    engine = build_engine(
        targets_path,
        profile=profile,
        use_config=use_config,
    )
    report = engine.redact_with_report(prompt)
    mapping = engine.reverse_map()

    if audit:
        write_entry(
            report.unique_applied(),
            mode="ask_safely",
            sources=[f"<{provider}>"],
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
    )
    return desanitize(answer, mapping), mapping
