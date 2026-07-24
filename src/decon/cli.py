"""CLI entry point for decon."""

from __future__ import annotations

import argparse
import difflib
import os
import sys
from pathlib import Path
from typing import Callable

from decon import __version__
from decon.engine import RedactionEngine
from decon.ask import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_PROVIDER,
    DEFAULT_WARN_CHARS,
    AskError,
    ask,
    size_warning,
)
from decon.audit import write_entry
from decon.config import (
    ConfigError,
    apply_config_to_engine,
    get_audit_config,
    get_llm_config,
    init_config,
    load_config,
)
from decon.output import (
    capture_tmux_pane,
    read_clipboard,
    write_clipboard,
    write_file,
    write_stdout,
)
from decon.llm import llm_review, parse_findings
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


def _validate_args(args: argparse.Namespace) -> str | None:
    """Return an error message if args are invalid, or None if OK."""
    # Mutual exclusion: output destinations
    destinations = [
        args.output is not None,
        args.output_dir is not None,
        args.clipboard,
    ]
    if sum(destinations) > 1:
        return "--output, --output-dir, and --clipboard cannot be used together"

    # Mutual exclusion: modes
    modes = [args.dry_run, args.check, args.diff]
    if args.unredact:
        modes.append(True)
    if args.restore is not None:
        modes.append(True)
    if sum(modes) > 1:
        return (
            "--dry-run, --check, --diff, --unredact, and --restore "
            "are mutually exclusive"
        )

    # --session and --restore take an OPTIONAL name, so argparse will happily
    # swallow a following filename as the name. Catch that rather than
    # silently writing a session called "scan.txt".
    for flag, value in (("--session", args.session), ("--restore", args.restore)):
        if value is None or args.files:
            continue
        if os.path.exists(value):
            return (
                f"{flag} consumed {value!r} as a session name. "
                f"Put the flag after the file ({flag} -c {value}), "
                f"or name the session explicitly ({flag}=NAME {value})"
            )

    if args.session is not None and args.restore is not None:
        return "--session and --restore cannot be used together"

    # Validate names up front so a typo fails before any work is done.
    for value in (args.session, args.restore):
        if value is None:
            continue
        try:
            session_path(value)
        except StateError as e:
            return str(e)

    if args.ask is not None:
        if not args.ask.strip():
            return "--ask requires a non-empty prompt"
        conflicting = [
            name
            for name, value in (
                ("--dry-run", args.dry_run),
                ("--check", args.check),
                ("--diff", args.diff),
                ("--unredact", args.unredact),
                ("--restore", args.restore is not None),
                ("--output-dir", args.output_dir),
            )
            if value
        ]
        if conflicting:
            return f"--ask cannot be used with {', '.join(conflicting)}"

    if args.output_dir and any(
        (args.dry_run, args.check, args.diff, args.unredact)
    ):
        return (
            "--output-dir cannot be used with --dry-run, --check, "
            "--diff, or --unredact"
        )

    if args.output_dir and (args.tmux or args.clipboard_in):
        return "--output-dir cannot be used with --tmux or --clipboard-in"

    if (args.dry_run or args.check or args.diff) and (
        args.output or args.clipboard
    ):
        return (
            "--output and --clipboard cannot be used with --dry-run, "
            "--check, or --diff"
        )

    # --output-dir requires files
    if args.output_dir and not args.files:
        return "--output-dir requires file arguments"

    return None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.init_config:
        try:
            init_config()
            return 0
        except ConfigError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    err = _validate_args(args)
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    # Session housekeeping needs no config, so a broken config file must not
    # stop you listing or deleting sessions.
    status = _run_session_admin(args)
    if status is not None:
        return status

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

    if args.list_rules:
        for info in engine.list_rules():
            state = "enabled" if info["enabled"] else "disabled"
            print(
                f"  [{state:>8}]  {info['name']:<25} "
                f"priority={info['priority']}  category={info['category']}"
            )
        return 0

    if not _apply_cli_overrides(args, engine):
        return 1

    # Reverse modes turn placeholders back into real values.
    if args.restore is not None or args.unredact:
        return _run_reverse(args, engine, config)

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


def _apply_cli_overrides(
    args: argparse.Namespace,
    engine: RedactionEngine,
) -> bool:
    """Apply --enable/--disable/--redact/--import-map. False on error."""
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
    # Restoring re-materializes real values, so it belongs in the trail too.
    _record_audit(
        args,
        config,
        engine.applied_for_unredaction(text),
        mode="restore" if args.unredact is None else "unredact",
    )
    return 0 if _write_output(args, result) else 1


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
    )

    # Audit only the runs that actually emit redacted output. --check reports a
    # count, --dry-run previews to stderr, and --diff prints the original text
    # rather than a shareable artifact; none of them are a disclosure event, and
    # writing the real values to disk on every CI --check would be a surprise.
    # Recorded after the LLM review so operator-accepted findings are included.
    if not (args.check or args.dry_run or args.diff):
        _record_audit(
            args,
            config,
            applied + llm_applied,
            mode="ask" if args.ask is not None else "redact",
        )

    if args.ask is not None:
        return _run_ask(args, engine, config, result)
    if args.check:
        return _run_check(args, applied, llm_findings, changed=changed)
    if args.dry_run:
        return _run_dry_run(args, applied, llm_findings, changed=changed)
    if args.diff:
        return _run_diff(text, result)

    if not _write_output(args, result):
        return 1
    if not _export_map(args, engine):
        return 1
    _print_stats(args, engine)
    return 0


def _run_ask(
    args: argparse.Namespace,
    engine: RedactionEngine,
    config: dict,
    redacted: str,
) -> int:
    """Send redacted text to a provider and restore the reply."""
    answer = _ask_provider(args, config, redacted)
    if answer is None:
        return 1

    restored = engine.unredact(answer)
    _warn_unresolved(args, engine, restored)
    # A model answer is prose, not a file being round-tripped, so make sure it
    # ends on its own line rather than running into the shell prompt.
    if not restored.endswith("\n"):
        restored += "\n"

    if not _write_output(args, restored):
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

    unredact() is a literal replacement, so a placeholder the model reformatted
    (dropped zero-padding, wrapped in emphasis) silently survives and reads as
    if it were real output. Say so rather than letting it pass.
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
    redacted: str,
) -> str | None:
    """Send redacted text to a provider. Returns None on failure.

    Everything sent has already been through the engine — the provider never
    sees an unredacted value.
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
            redacted, ask_cfg.get("warn_chars", DEFAULT_WARN_CHARS)
        )
        if warning:
            print(f"Warning: {warning}", file=sys.stderr)
        print(
            f"Sending redacted text to {provider} ({model or 'default model'})...",
            file=sys.stderr,
        )
    try:
        return ask(
            args.ask,
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
        sources=sources or (args.files or None),
        path=audit_cfg.get("path"),
        quiet=args.quiet,
    )


def _llm_enabled(args: argparse.Namespace, config: dict) -> bool:
    """Return whether LLM review is enabled for this invocation."""
    llm_cfg = get_llm_config(config)
    return bool(
        args.llm
        or os.environ.get("DECON_LLM") == "1"
        or llm_cfg.get("enabled", False)
    )


def _review_with_llm(
    args: argparse.Namespace,
    config: dict,
    engine: RedactionEngine,
    result: str,
    *,
    interactive: bool,
    announce: bool,
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
    if interactive and not args.quiet and sys.stderr.isatty():
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


def _write_output(args: argparse.Namespace, result: str) -> bool:
    """Write result to the configured output destination."""
    try:
        if args.output:
            write_file(result, args.output, quiet=args.quiet)
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
        print(f"Error creating output directory {args.output_dir}: {e}", file=sys.stderr)
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
        _record_audit(
            args,
            config,
            report.unique_applied() + llm_applied,
            mode="redact",
            sources=[path],
        )
        out_path = output_paths[path]
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            write_file(result, str(out_path), quiet=args.quiet)
        except OSError as e:
            print(f"Error writing {out_path}: {e}", file=sys.stderr)
            return 1

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


def _stats_for_applied(
    applied: list[tuple[str, str, str]]
) -> dict[str, int]:
    """Return category counts for applied redactions."""
    stats: dict[str, int] = {}
    for category, _real, _placeholder in applied:
        stats[category] = stats.get(category, 0) + 1
    return stats


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
