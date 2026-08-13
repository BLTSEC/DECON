"""CLI entry point for decon."""

from __future__ import annotations

import argparse
import difflib
import os
import sys
from pathlib import Path
from typing import Callable

from decon import __version__
from decon.ask import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_PROVIDER,
    DEFAULT_WARN_CHARS,
    AskError,
    ask,
    size_warning,
)
from decon.audit import write_entry
from decon.cli_validation import validate_args, validate_path_collisions
from decon.config import (
    ConfigError,
    apply_config_to_engine,
    apply_targets,
    get_audit_config,
    get_llm_config,
    init_config,
    load_config,
)
from decon.engine import RedactionEngine
from decon.llm import llm_review, parse_findings
from decon.output import (
    capture_tmux_pane,
    read_clipboard,
    write_clipboard,
    write_file,
    write_stdout,
)
from decon.state import (
    DEFAULT_SESSION,
    StateError,
    list_sessions,
    session_path,
)


def _split_csv(value: str) -> list[str]:
    """Split a comma-separated CLI value list, dropping empty entries."""
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decon",
        description="Sanitize operational data before sharing. "
        "Consistent placeholders preserve analytical value.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help="Files to redact (default: stdin)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"decon {__version__}",
    )

    # Input modes
    input_group = parser.add_argument_group("input")
    input_group.add_argument(
        "--tmux",
        action="store_true",
        help="Capture active tmux pane scrollback",
    )
    input_group.add_argument(
        "--clipboard-in",
        action="store_true",
        help="Read from system clipboard",
    )

    # Output modes
    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "-c",
        "--clipboard",
        action="store_true",
        help="Copy output to clipboard",
    )
    output_group.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write output to file",
    )
    output_group.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Write redacted files to directory (one per input file)",
    )

    # Options
    parser.add_argument(
        "-p",
        "--profile",
        metavar="NAME",
        help='Config profile (default: "standard")',
    )
    parser.add_argument(
        "--enable",
        metavar="RULES",
        help="Enable rules (comma-separated)",
    )
    parser.add_argument(
        "--disable",
        metavar="RULES",
        help="Disable rules (comma-separated)",
    )
    parser.add_argument(
        "--allow",
        metavar="VALUES",
        help="Values to pass through unredacted (comma-separated)",
    )
    parser.add_argument(
        "--redact",
        metavar="VALUES",
        help="Extra literal values to redact (comma-separated)",
    )
    parser.add_argument(
        "--targets",
        metavar="FILE",
        help="Load engagement identifiers from a category:value file",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Local LLM safety check via Ollama",
    )
    parser.add_argument(
        "--ask",
        metavar="PROMPT",
        help="Ask an LLM about the redacted input, then restore real values",
    )
    parser.add_argument(
        "--provider",
        choices=["claude", "openai", "ollama"],
        help="Provider for --ask (default: claude)",
    )
    parser.add_argument(
        "--model",
        metavar="NAME",
        help="Model for --ask (default: provider's default)",
    )
    parser.add_argument(
        "--export-map",
        metavar="FILE",
        help="Save mapping to JSON",
    )
    parser.add_argument(
        "--import-map",
        metavar="FILE",
        help="Load prior mapping for cross-file consistency",
    )
    parser.add_argument(
        "--unredact",
        metavar="MAP_FILE",
        help="Reverse redaction using a mapping file",
    )
    parser.add_argument(
        "--session",
        nargs="?",
        const=DEFAULT_SESSION,
        metavar="NAME",
        help='Save the mapping as a named session (default: "last")',
    )
    parser.add_argument(
        "--restore",
        nargs="?",
        const=DEFAULT_SESSION,
        metavar="NAME",
        help="Restore real values using a saved session",
    )
    parser.add_argument(
        "--list-sessions",
        action="store_true",
        help="Show saved session names",
    )
    parser.add_argument(
        "--forget",
        metavar="NAME",
        help="Delete a saved session and its reversible mapping",
    )
    parser.add_argument(
        "--forget-all",
        action="store_true",
        help="Delete every saved session",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be redacted",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if redactions needed (for CI/pre-commit)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Show unified diff of original vs redacted",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Show all rules and status",
    )
    parser.add_argument(
        "--init-config",
        action="store_true",
        help="Create default config file",
    )
    parser.add_argument(
        "--no-audit",
        action="store_true",
        help="Do not record this run in the audit log",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress stderr messages",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show redaction stats",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    err = validate_args(args)
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    err = _validate_paths(args)
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    if args.init_config:
        try:
            init_config(quiet=args.quiet)
            return 0
        except ConfigError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    # Session housekeeping needs no config, so a broken config file must not
    # stop you listing or deleting sessions.
    status = _run_session_admin(args)
    if status is not None:
        return status

    # Restoring is an emergency/recovery path and needs no redaction rules.
    # A broken unrelated profile or custom regex must not prevent access to a
    # saved map. Load only a valid audit subsection, and fail closed on auditing
    # if even the TOML or audit settings are unusable.
    if args.restore is not None or args.unredact:
        config = _load_reverse_config(args)
        return _run_reverse(args, RedactionEngine(), config)

    try:
        config = load_config()
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    engine = RedactionEngine()
    profile = args.profile or os.environ.get("DECON_PROFILE")
    try:
        apply_config_to_engine(engine, config, profile)
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not _apply_cli_overrides(args, engine):
        return 1

    if args.list_rules:
        for info in engine.list_rules():
            state = "enabled" if info["enabled"] else "disabled"
            print(
                f"  [{state:>8}]  {info['name']:<25} "
                f"priority={info['priority']}  category={info['category']}"
            )
        return 0

    # Imported maps may contain entries for configured allowlisted values.
    # Reapply allowlists after import so explicit pass-through rules win.
    if engine.allowlist:
        engine.add_allowlist(list(engine.allowlist))
    if args.allow:
        engine.add_allowlist(_split_csv(args.allow))

    if args.output_dir:
        return _batch_process(args, engine, config)

    text = _read_input(args)
    if text is None:
        return 1

    return _run_redaction(args, engine, config, text)


def _run_session_admin(args: argparse.Namespace) -> int | None:
    """Handle --list-sessions and --forget. Returns None if neither applies."""
    if args.forget:
        try:
            path = session_path(args.forget)
        except StateError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        if not path.exists():
            print(
                f"Error: no saved session named {args.forget!r}",
                file=sys.stderr,
            )
            return 1
        try:
            path.unlink()
        except OSError as e:
            print(f"Error removing session {args.forget}: {e}", file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"Forgot session {args.forget!r}", file=sys.stderr)
        return 0

    if args.forget_all:
        names = list_sessions()
        if not names:
            if not args.quiet:
                print("No saved sessions.", file=sys.stderr)
            return 0
        removed = 0
        for name in names:
            try:
                session_path(name).unlink()
                removed += 1
            except (OSError, StateError) as e:
                print(f"Error removing session {name}: {e}", file=sys.stderr)
                return 1
        if not args.quiet:
            print(f"Forgot {removed} session(s)", file=sys.stderr)
        return 0

    if args.list_sessions:
        names = list_sessions()
        if not names:
            print("No saved sessions.", file=sys.stderr)
        for name in names:
            print(name)
        return 0

    return None


def _load_reverse_config(args: argparse.Namespace) -> dict:
    """Load only safe audit settings for a restore/unredact operation.

    Reverse operations do not need profiles, custom patterns, or enabled-rule
    state. Ignoring those sections keeps recovery available when a redaction
    setting is broken. If the TOML or audit subsection itself is invalid,
    auditing is disabled rather than unexpectedly persisting restored values.
    """
    try:
        config = load_config()
    except ConfigError as e:
        if not args.quiet:
            print(
                f"Warning: ignoring invalid config during restore ({e}); "
                "audit logging is disabled for this run",
                file=sys.stderr,
            )
        return {"audit": {"enabled": False}}

    audit = config.get("audit", {})
    valid = isinstance(audit, dict)
    if valid and "enabled" in audit:
        valid = isinstance(audit["enabled"], bool)
    if valid and "path" in audit:
        valid = isinstance(audit["path"], str) and bool(audit["path"].strip())
    if not valid:
        if not args.quiet:
            print(
                "Warning: invalid audit config during restore; "
                "audit logging is disabled for this run",
                file=sys.stderr,
            )
        return {"audit": {"enabled": False}}
    return {"audit": audit}


def _apply_cli_overrides(
    args: argparse.Namespace,
    engine: RedactionEngine,
) -> bool:
    """Apply CLI rule, target, literal, and mapping overrides. False on error."""
    for flag_value, action in (
        (args.enable, engine.enable_rule),
        (args.disable, engine.disable_rule),
    ):
        if not flag_value:
            continue
        err = _apply_rule_names(_split_csv(flag_value), action)
        if err:
            print(f"Unknown rule: {err}", file=sys.stderr)
            return False

    if args.redact:
        engine.add_custom_values(_split_csv(args.redact), case_sensitive=False)

    if args.targets:
        try:
            apply_targets(engine, args.targets)
        except ConfigError as e:
            print(f"Error loading targets: {e}", file=sys.stderr)
            return False

    if args.import_map:
        try:
            engine.import_map(args.import_map)
        except (OSError, ValueError) as e:
            print(f"Error loading map {args.import_map}: {e}", file=sys.stderr)
            return False
    return True


def _resolve_reverse_map(args: argparse.Namespace) -> str | None:
    """Return the map path for --restore or --unredact, or None on error."""
    if args.unredact:
        return args.unredact

    try:
        path = session_path(args.restore)
    except StateError as e:
        print(f"Error: {e}", file=sys.stderr)
        return None
    if not path.exists():
        known = list_sessions()
        hint = f" Known sessions: {', '.join(known)}" if known else ""
        print(
            f"Error: no saved session named {args.restore!r}.{hint}",
            file=sys.stderr,
        )
        return None
    return str(path)


def _run_reverse(
    args: argparse.Namespace,
    engine: RedactionEngine,
    config: dict,
) -> int:
    """Restore real values from a session (--restore) or map (--unredact)."""
    map_path = _resolve_reverse_map(args)
    if map_path is None:
        return 1

    label = (
        f"session {args.restore}" if args.unredact is None else f"map {args.unredact}"
    )
    try:
        engine.import_map(map_path)
    except (OSError, ValueError) as e:
        print(f"Error loading {label}: {e}", file=sys.stderr)
        return 1

    text = _read_input(args)
    if text is None:
        return 1

    result = engine.unredact(text)
    _warn_unresolved(args, engine, result)
    restored_applied = engine.applied_for_unredaction(text)
    if not _write_output(args, result, sensitive=True):
        return 1
    # Record only after the restored material was successfully emitted.
    _record_audit(
        args,
        config,
        restored_applied,
        mode="restore" if args.unredact is None else "unredact",
    )
    return 0


def _run_redaction(
    args: argparse.Namespace,
    engine: RedactionEngine,
    config: dict,
    text: str,
) -> int:
    """Redact, optionally review/ask, then emit in whichever mode was chosen."""
    report = engine.redact_with_report(text)
    result = report.text
    applied = report.unique_applied()
    changed = report.changed

    result, llm_findings, llm_applied = _review_with_llm(
        args,
        config,
        engine,
        result,
        interactive=not (args.check or args.dry_run),
        announce=not (args.check or args.dry_run),
        auto_redact=args.ask is not None,
    )

    redacted_question: str | None = None
    question_applied: list[tuple[str, str, str]] = []
    if args.ask is not None:
        # The operator's question can contain the same infrastructure values as
        # the document. Run it through the same stateful engine so both sides of
        # the provider prompt share placeholders and reverse cleanly.
        question_report = engine.redact_with_report(args.ask)
        redacted_question = question_report.text
        question_applied.extend(question_report.unique_applied())
        redacted_question, question_findings, question_llm_applied = _review_with_llm(
            args,
            config,
            engine,
            redacted_question,
            interactive=False,
            announce=True,
            auto_redact=True,
        )
        question_applied.extend(question_llm_applied)

        # Question-only LLM findings register new custom rules. Reapply those
        # rules to the document before it leaves the process too. Key this off
        # the findings rather than replacements in the question: even a noisy
        # reviewer finding that is absent from the question could be present in
        # the document and must not knowingly pass to the provider.
        if question_findings:
            sync_report = engine.redact_with_report(result)
            result = sync_report.text
            question_applied.extend(sync_report.unique_applied())

    audit_applied = _unique_applied(applied + llm_applied + question_applied)

    if args.ask is not None:
        assert redacted_question is not None
        # Provider calls can fail after transmission. Record the attempt before
        # crossing that trust boundary, without claiming a completed response.
        _record_audit(
            args,
            config,
            audit_applied,
            mode="ask",
            status="attempted",
        )
        return _run_ask(
            args,
            engine,
            config,
            redacted_question,
            result,
        )
    if args.check:
        return _run_check(args, applied, llm_findings, changed=changed)
    if args.dry_run:
        return _run_dry_run(args, applied, llm_findings, changed=changed)
    if args.diff:
        return _run_diff(text, result)

    if not _write_output(args, result):
        return 1
    _record_audit(args, config, audit_applied, mode="redact")
    if not _export_map(args, engine):
        return 1
    _print_stats(args, engine)
    return 0


def _run_ask(
    args: argparse.Namespace,
    engine: RedactionEngine,
    config: dict,
    question: str,
    redacted: str,
) -> int:
    """Send redacted text to a provider and restore the reply."""
    answer = _ask_provider(args, config, question, redacted)
    if answer is None:
        return 1

    restored = engine.unredact(answer)
    _warn_unresolved(args, engine, restored)
    # A model answer is prose, not a file being round-tripped, so make sure it
    # ends on its own line rather than running into the shell prompt.
    if not restored.endswith("\n"):
        restored += "\n"

    if not _write_output(args, restored, sensitive=True):
        return 1
    if not _export_map(args, engine):
        return 1
    _print_stats(args, engine)
    return 0


def _run_check(
    args: argparse.Namespace,
    applied: list[tuple[str, str, str]],
    llm_findings: list[str],
    *,
    changed: bool,
) -> int:
    """Exit non-zero when anything would be redacted (CI / pre-commit)."""
    if changed or llm_findings:
        if not args.quiet:
            total = len(applied) + len(llm_findings)
            print(f"Found {total} value(s) to redact:", file=sys.stderr)
            stats = _stats_for_applied(applied)
            if llm_findings:
                stats["llm"] = len(llm_findings)
            for category, count in sorted(stats.items()):
                print(f"  {category}: {count}", file=sys.stderr)
        return 1
    if not args.quiet:
        print("Clean — no redactions needed.", file=sys.stderr)
    return 0


def _run_dry_run(
    args: argparse.Namespace,
    applied: list[tuple[str, str, str]],
    llm_findings: list[str],
    *,
    changed: bool,
) -> int:
    """Preview the substitutions without emitting redacted output."""
    if args.quiet:
        return 0
    if not changed and not llm_findings:
        print("No redactions found.", file=sys.stderr)
        return 0
    if changed:
        print("Redactions that would be applied:", file=sys.stderr)
        for _category, real, placeholder in sorted(applied, key=lambda x: x[2]):
            print(f"  {real} -> {placeholder}", file=sys.stderr)
    if llm_findings:
        print("LLM findings:", file=sys.stderr)
        for value in llm_findings:
            print(f"  {value}", file=sys.stderr)
    return 0


def _run_diff(original: str, redacted: str) -> int:
    """Show a unified diff of original against redacted."""
    sys.stdout.writelines(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            redacted.splitlines(keepends=True),
            fromfile="original",
            tofile="redacted",
        )
    )
    return 0


def _warn_unresolved(
    args: argparse.Namespace,
    engine: RedactionEngine,
    text: str,
) -> None:
    """Warn about placeholders left in restored text.

    Boundary-aware unredaction deliberately leaves a reformatted or embedded
    placeholder untouched. Warn so it cannot silently read as real output.
    """
    if args.quiet:
        return
    unresolved = engine.unresolved_placeholders(text)
    if not unresolved:
        return
    shown = ", ".join(unresolved[:5])
    more = f" (+{len(unresolved) - 5} more)" if len(unresolved) > 5 else ""
    print(
        f"Warning: {len(unresolved)} placeholder(s) had no mapping and were "
        f"left as-is: {shown}{more}",
        file=sys.stderr,
    )


def _ask_provider(
    args: argparse.Namespace,
    config: dict,
    question: str,
    redacted: str,
) -> str | None:
    """Send redacted text to a provider. Returns None on failure.

    Both the question and document have already been through the same engine;
    neither original string is sent directly.
    """
    ask_cfg = config.get("ask", {})
    configured_provider = ask_cfg.get("provider", DEFAULT_PROVIDER)
    provider = args.provider or configured_provider

    # Models are keyed by provider so a name can never be sent to the wrong one.
    # The flat `model` key still works, but only for the provider it was
    # configured beside.
    model = args.model
    if model is None:
        model = ask_cfg.get("models", {}).get(provider)
    if model is None and provider == configured_provider:
        model = ask_cfg.get("model")

    if not args.quiet:
        warning = size_warning(
            f"{question}\n{redacted}",
            ask_cfg.get("warn_chars", DEFAULT_WARN_CHARS),
        )
        if warning:
            print(f"Warning: {warning}", file=sys.stderr)
        print(
            f"Sending redacted text to {provider} ({model or 'default model'})...",
            file=sys.stderr,
        )
    try:
        return ask(
            question,
            redacted,
            provider=provider,
            model=model,
            host=ask_cfg.get("host", "http://localhost:11434"),
            max_tokens=ask_cfg.get("max_tokens", DEFAULT_MAX_TOKENS),
        )
    except AskError as e:
        print(f"Error: {e}", file=sys.stderr)
        return None


def _record_audit(
    args: argparse.Namespace,
    config: dict,
    applied: list[tuple[str, str, str]],
    *,
    mode: str,
    status: str = "emitted",
    sources: list[str] | None = None,
) -> None:
    """Record this run's substitutions unless auditing is switched off."""
    if args.no_audit:
        return
    audit_cfg = get_audit_config(config)
    if not audit_cfg.get("enabled", True):
        return
    write_entry(
        applied,
        mode=mode,
        status=status,
        sources=sources or (args.files or None),
        path=audit_cfg.get("path"),
        quiet=args.quiet,
    )


def _llm_enabled(args: argparse.Namespace, config: dict) -> bool:
    """Return whether LLM review is enabled for this invocation."""
    llm_cfg = get_llm_config(config)
    return bool(
        args.llm or os.environ.get("DECON_LLM") == "1" or llm_cfg.get("enabled", False)
    )


def _review_with_llm(
    args: argparse.Namespace,
    config: dict,
    engine: RedactionEngine,
    result: str,
    *,
    interactive: bool,
    announce: bool,
    auto_redact: bool = False,
) -> tuple[str, list[str], list[tuple[str, str, str]]]:
    """Run optional LLM review.

    Returns the updated text, the findings, and any substitutions the operator
    accepted — the last of which belongs in the audit log alongside the
    deterministic ones.
    """
    if not _llm_enabled(args, config):
        return result, [], []

    llm_cfg = get_llm_config(config)
    review = llm_review(
        result,
        model=llm_cfg.get("model", "qwen3.5:9b"),
        host=llm_cfg.get("host", "http://localhost:11434"),
        quiet=args.quiet,
    )
    if not review or review.strip() == "CLEAN":
        return result, [], []

    findings = parse_findings(review)
    if not findings:
        return result, [], []

    accepted: list[tuple[str, str, str]] = []
    if auto_redact:
        # A cloud-bound --ask operation must never knowingly transmit a value
        # the local reviewer just identified. Other modes retain the existing
        # operator-review behavior.
        engine.add_custom_values(findings, case_sensitive=False)
        report = engine.redact_with_report(result)
        result = report.text
        accepted = report.unique_applied()
        if announce and not args.quiet:
            print(
                f"LLM review auto-redacted {len(findings)} potential leak(s) "
                "before provider transmission",
                file=sys.stderr,
            )
    elif interactive and not args.quiet and sys.stderr.isatty():
        selected = _prompt_llm_review(findings)
        if selected:
            engine.add_custom_values(selected, case_sensitive=False)
            report = engine.redact_with_report(result)
            result = report.text
            accepted = report.unique_applied()
            print(f"Redacted {len(selected)} value(s)", file=sys.stderr)
    elif announce and not args.quiet:
        print("LLM review flagged potential issues:", file=sys.stderr)
        print(review, file=sys.stderr)
        print("---", file=sys.stderr)
    return result, findings, accepted


def _prompt_llm_review(findings: list[str]) -> list[str]:
    """Present LLM findings interactively and return values selected for redaction."""
    print("\nLLM flagged potential leaks:", file=sys.stderr)
    for i, value in enumerate(findings, 1):
        print(f"  [{i}] {value}", file=sys.stderr)
    print(
        "\nRedact? (1,2 / all / none) [all]: ",
        file=sys.stderr,
        end="",
    )
    sys.stderr.flush()

    try:
        with open("/dev/tty") as tty:
            choice = tty.readline().strip()
    except OSError:
        return list(findings)

    if not choice or choice.lower() == "all":
        return list(findings)
    if choice.lower() == "none":
        return []

    selected: list[str] = []
    for token in choice.replace(",", " ").split():
        try:
            idx = int(token)
            if 1 <= idx <= len(findings):
                selected.append(findings[idx - 1])
        except ValueError:
            continue
    return selected


def _write_output(
    args: argparse.Namespace,
    result: str,
    *,
    sensitive: bool = False,
) -> bool:
    """Write result to the configured output destination."""
    try:
        if args.output:
            write_file(
                result,
                args.output,
                quiet=args.quiet,
                sensitive=sensitive,
            )
        elif args.clipboard:
            return write_clipboard(result, quiet=args.quiet)
        else:
            write_stdout(result)
    except OSError as e:
        if not args.quiet:
            print(f"Error writing output: {e}", file=sys.stderr)
        return False
    return True


def _export_map(args: argparse.Namespace, engine: RedactionEngine) -> bool:
    """Export the mapping to an explicit path and/or a named session."""
    if args.export_map:
        try:
            engine.export_map(args.export_map)
        except OSError as e:
            print(f"Error writing map {args.export_map}: {e}", file=sys.stderr)
            return False
        if not args.quiet:
            print(f"Mapping exported to {args.export_map}", file=sys.stderr)

    if args.session is not None:
        try:
            engine.export_map(str(session_path(args.session)))
        except (OSError, StateError) as e:
            print(f"Error saving session {args.session}: {e}", file=sys.stderr)
            return False
        if not args.quiet:
            print(
                f"Session {args.session!r} saved — "
                f"restore with: decon --restore {args.session}",
                file=sys.stderr,
            )
    return True


def _apply_rule_names(
    rule_names: list[str],
    action: Callable[[str], None],
) -> str | None:
    """Apply an enable/disable action for each rule name."""
    for name in rule_names:
        try:
            action(name)
        except ValueError:
            return name
    return None


def _batch_process(
    args: argparse.Namespace,
    engine: RedactionEngine,
    config: dict,
) -> int:
    """Process multiple files, writing each to output-dir."""
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as e:
        print(
            f"Error creating output directory {args.output_dir}: {e}", file=sys.stderr
        )
        return 1
    output_paths = _build_batch_output_paths(args.files, args.output_dir)

    for path in args.files:
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeError) as e:
            print(f"Error reading {path}: {e}", file=sys.stderr)
            return 1

        report = engine.redact_with_report(text)
        result = report.text
        result, _findings, llm_applied = _review_with_llm(
            args,
            config,
            engine,
            result,
            interactive=False,
            announce=True,
        )
        out_path = output_paths[path]
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            write_file(result, str(out_path), quiet=args.quiet)
        except OSError as e:
            print(f"Error writing {out_path}: {e}", file=sys.stderr)
            return 1
        _record_audit(
            args,
            config,
            report.unique_applied() + llm_applied,
            mode="redact",
            sources=[path],
        )

    if not _export_map(args, engine):
        return 1
    _print_stats(args, engine)
    return 0


def _print_stats(args: argparse.Namespace, engine: RedactionEngine) -> None:
    """Print verbose stats if requested."""
    if args.verbose and not args.quiet:
        stats = engine.get_stats()
        if stats:
            print("Redaction stats:", file=sys.stderr)
            for cat, count in sorted(stats.items()):
                print(f"  {cat}: {count}", file=sys.stderr)
        else:
            print("No redactions performed.", file=sys.stderr)


def _build_batch_output_paths(
    input_paths: list[str], output_dir: str
) -> dict[str, Path]:
    """Build unique output paths for batch processing."""
    resolved_parents = [str(Path(path).resolve().parent) for path in input_paths]
    common_parent = Path(os.path.commonpath(resolved_parents))
    output_root = Path(output_dir)
    output_paths: dict[str, Path] = {}

    for raw_path in input_paths:
        path = Path(raw_path).resolve()
        try:
            rel_path = path.relative_to(common_parent)
        except ValueError:
            rel_path = Path(path.name)
        out_path = output_root / rel_path.parent / f"{path.stem}.redacted{path.suffix}"
        output_paths[raw_path] = out_path

    return output_paths


def _validate_paths(args: argparse.Namespace) -> str | None:
    """Preflight all file sources and destinations before reading or writing."""
    sources: list[tuple[str, str | Path]] = [
        (f"input file {path!r}", path) for path in args.files
    ]
    for label, path in (
        ("--targets", args.targets),
        ("--import-map", args.import_map),
        ("--unredact map", args.unredact),
    ):
        if path:
            sources.append((label, path))
    if args.restore is not None:
        try:
            sources.append(("--restore session", session_path(args.restore)))
        except StateError:
            # validate_args owns the user-facing session-name error.
            pass

    destinations: list[tuple[str, str | Path]] = []
    if args.output:
        destinations.append(("--output", args.output))
    if args.export_map:
        destinations.append(("--export-map", args.export_map))
    if args.session is not None:
        try:
            destinations.append(("--session", session_path(args.session)))
        except StateError:
            pass
    if args.output_dir and args.files:
        for source, path in _build_batch_output_paths(
            args.files, args.output_dir
        ).items():
            destinations.append((f"batch output for {source!r}", path))

    return validate_path_collisions(sources, destinations)


def _stats_for_applied(applied: list[tuple[str, str, str]]) -> dict[str, int]:
    """Return category counts for applied redactions."""
    stats: dict[str, int] = {}
    for category, _real, _placeholder in applied:
        stats[category] = stats.get(category, 0) + 1
    return stats


def _unique_applied(
    applied: list[tuple[str, str, str]],
) -> list[tuple[str, str, str]]:
    """Deduplicate substitutions while preserving their first-seen order."""
    return list(dict.fromkeys(applied))


def _read_input(args: argparse.Namespace) -> str | None:
    """Read input from files, stdin, clipboard, or tmux."""
    texts: list[str] = []

    if args.tmux:
        text = capture_tmux_pane(quiet=args.quiet)
        if text is None:
            return None
        texts.append(text)

    if args.clipboard_in:
        text = read_clipboard(quiet=args.quiet)
        if text is None:
            return None
        texts.append(text)

    if args.files:
        for path in args.files:
            try:
                with open(path, encoding="utf-8") as f:
                    texts.append(f.read())
            except (OSError, UnicodeError) as e:
                print(f"Error reading {path}: {e}", file=sys.stderr)
                return None

    # Default: stdin (only if no other input was provided)
    if not texts:
        if sys.stdin.isatty():
            print(
                "Reading from stdin (Ctrl+D to end)...",
                file=sys.stderr,
            )
        texts.append(sys.stdin.read())

    return "\n".join(texts)


if __name__ == "__main__":
    sys.exit(main())
