"""Argument compatibility checks for the DECON command-line interface."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from decon.state import StateError, parse_session_ttl, session_path


def _same_path(first: str | Path, second: str | Path) -> bool:
    """Return whether two path spellings identify the same destination."""
    left = Path(first).expanduser().resolve(strict=False)
    right = Path(second).expanduser().resolve(strict=False)
    if left == right:
        return True
    try:
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


def validate_path_collisions(
    sources: list[tuple[str, str | Path]],
    destinations: list[tuple[str, str | Path]],
    *,
    allowed_source_destination_pairs: frozenset[tuple[str, str]] = frozenset(),
) -> str | None:
    """Reject outputs that alias inputs or other outputs, except approved pairs."""
    for index, (label, path) in enumerate(destinations):
        for other_label, other_path in destinations[index + 1 :]:
            if _same_path(path, other_path):
                return f"{label} and {other_label} resolve to the same path: {path}"
        for source_label, source_path in sources:
            if _same_path(path, source_path):
                if (source_label, label) in allowed_source_destination_pairs:
                    continue
                return (
                    f"{label} would overwrite {source_label}: {path}; "
                    "choose a different destination"
                )
    return None


def _enabled_names(options: tuple[tuple[str, bool], ...]) -> list[str]:
    """Return flag names whose conditions are enabled."""
    return [name for name, enabled in options if enabled]


def _operation_options(args: argparse.Namespace) -> tuple[tuple[str, bool], ...]:
    """Describe processing flags once for every compatibility check."""
    return (
        ("FILE", bool(args.files)),
        ("--tmux", args.tmux),
        ("--clipboard-in", args.clipboard_in),
        ("--clipboard", args.clipboard),
        ("--output", args.output is not None),
        ("--output-dir", args.output_dir is not None),
        ("--profile", args.profile is not None),
        ("--enable", args.enable is not None),
        ("--disable", args.disable is not None),
        ("--allow", args.allow is not None),
        ("--redact", args.redact is not None),
        ("--targets", args.targets is not None),
        ("--llm", args.llm),
        ("--strict-llm", args.strict_llm),
        ("--ask", args.ask is not None),
        ("--ask-preview", args.ask_preview),
        ("--confirm-ask", args.confirm_ask),
        ("--force-ask", args.force_ask),
        ("--provider", args.provider is not None),
        ("--model", args.model is not None),
        ("--export-map", args.export_map is not None),
        ("--import-map", args.import_map is not None),
        ("--unredact", args.unredact is not None),
        ("--session", args.session is not None),
        ("--session-ttl", args.session_ttl is not None),
        ("--restore", args.restore is not None),
        ("--consume", args.consume),
        ("--dry-run", args.dry_run),
        ("--check", args.check),
        ("--diff", args.diff),
        ("--list-rules", args.list_rules),
        ("--no-audit", args.no_audit),
        ("--verbose", args.verbose),
    )


def validate_args(args: argparse.Namespace) -> str | None:
    """Return an error message if parsed CLI arguments are invalid."""
    standalone_actions = _enabled_names(
        (
            ("--init-config", args.init_config),
            ("--list-sessions", args.list_sessions),
            ("--forget", args.forget is not None),
            ("--forget-all", args.forget_all),
            ("--doctor", args.doctor),
        )
    )
    if len(standalone_actions) > 1:
        return f"{', '.join(standalone_actions)} are mutually exclusive"
    if standalone_actions:
        conflicts = _enabled_names(_operation_options(args))
        if conflicts:
            return (
                f"{standalone_actions[0]} is a standalone action and cannot be "
                f"used with {', '.join(conflicts)}"
            )

    if args.list_rules:
        allowed = {"--profile", "--enable", "--disable", "--list-rules"}
        conflicts = _enabled_names(
            tuple(item for item in _operation_options(args) if item[0] not in allowed)
        )
        if conflicts:
            return (
                "--list-rules is an informational action and cannot be used with "
                f"{', '.join(conflicts)}"
            )

    destinations = [
        args.output is not None,
        args.output_dir is not None,
        args.clipboard,
    ]
    if sum(destinations) > 1:
        return "--output, --output-dir, and --clipboard cannot be used together"

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

    # These flags take an optional name, so argparse may consume a following
    # filename as that name. Catch it rather than creating a misleading session.
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

    if args.session_ttl is not None:
        if args.session is None:
            return "--session-ttl requires --session"
        try:
            parse_session_ttl(args.session_ttl)
        except StateError as e:
            return str(e)

    if args.consume and args.restore is None:
        return "--consume requires --restore"

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
        conflicting = _enabled_names(
            (
                ("--dry-run", args.dry_run),
                ("--check", args.check),
                ("--diff", args.diff),
                ("--unredact", args.unredact is not None),
                ("--restore", args.restore is not None),
                ("--output-dir", args.output_dir is not None),
            )
        )
        if conflicting:
            return f"--ask cannot be used with {', '.join(conflicting)}"
    elif args.provider is not None or args.model is not None:
        flags = _enabled_names(
            (
                ("--provider", args.provider is not None),
                ("--model", args.model is not None),
            )
        )
        return f"{', '.join(flags)} require --ask"

    if args.ask_preview and args.ask is None:
        return "--ask-preview requires --ask"
    if args.confirm_ask and args.ask is None:
        return "--confirm-ask requires --ask"
    if args.confirm_ask and args.ask_preview:
        return "--confirm-ask cannot be used with --ask-preview"
    if args.force_ask and args.ask is None:
        return "--force-ask requires --ask"
    if args.force_ask and args.ask_preview:
        return "--force-ask cannot be used with --ask-preview"

    if args.output_dir and any(
        (
            args.dry_run,
            args.check,
            args.diff,
            args.unredact,
            args.restore is not None,
        )
    ):
        return (
            "--output-dir cannot be used with --dry-run, --check, "
            "--diff, --unredact, or --restore"
        )

    if args.output_dir and (args.tmux or args.clipboard_in):
        return "--output-dir cannot be used with --tmux or --clipboard-in"

    if (args.dry_run or args.check or args.diff) and (args.output or args.clipboard):
        return (
            "--output and --clipboard cannot be used with --dry-run, --check, or --diff"
        )

    if args.output_dir and not args.files:
        return "--output-dir requires file arguments"

    if args.restore is not None or args.unredact:
        conflicts = _enabled_names(
            (
                ("--profile", args.profile is not None),
                ("--enable", args.enable is not None),
                ("--disable", args.disable is not None),
                ("--allow", args.allow is not None),
                ("--redact", args.redact is not None),
                ("--targets", args.targets is not None),
                ("--llm", args.llm),
                ("--strict-llm", args.strict_llm),
                ("--import-map", args.import_map is not None),
                ("--export-map", args.export_map is not None),
                ("--session", args.session is not None),
                ("--session-ttl", args.session_ttl is not None),
                ("--list-rules", args.list_rules),
                ("--verbose", args.verbose),
            )
        )
        if conflicts:
            reverse_flag = "--restore" if args.restore is not None else "--unredact"
            return f"{reverse_flag} cannot be used with {', '.join(conflicts)}"

    return None
