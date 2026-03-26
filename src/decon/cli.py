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
from decon.config import (
    ConfigError,
    apply_config_to_engine,
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
        "--llm",
        action="store_true",
        help="Local LLM safety check via Ollama",
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
    if args.output and args.output_dir:
        return "--output and --output-dir cannot be used together"

    # Mutual exclusion: modes
    modes = [args.dry_run, args.check, args.diff]
    if args.unredact:
        modes.append(True)
    if sum(modes) > 1:
        return "--dry-run, --check, --diff, and --unredact are mutually exclusive"

    # --output-dir requires files
    if args.output_dir and not args.files:
        return "--output-dir requires file arguments"

    return None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --init-config: create config and exit
    if args.init_config:
        init_config()
        return 0

    # Validate argument combinations
    err = _validate_args(args)
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    # Load config
    try:
        config = load_config()
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Build engine
    engine = RedactionEngine()

    # Apply config (profile from arg, env var, or config default)
    profile = args.profile or os.environ.get("DECON_PROFILE")
    try:
        apply_config_to_engine(engine, config, profile)
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # --list-rules: show rules and exit
    if args.list_rules:
        for info in engine.list_rules():
            status = "enabled" if info["enabled"] else "disabled"
            print(
                f"  [{status:>8}]  {info['name']:<25} "
                f"priority={info['priority']}  category={info['category']}"
            )
        return 0

    # CLI --enable/--disable overrides
    for flag_value, action in (
        (args.enable, engine.enable_rule),
        (args.disable, engine.disable_rule),
    ):
        if not flag_value:
            continue
        err = _apply_rule_names(_split_csv(flag_value), action)
        if err:
            print(f"Unknown rule: {err}", file=sys.stderr)
            return 1

    # Allowlist
    if args.allow:
        engine.add_allowlist(_split_csv(args.allow))

    # Import prior mapping
    if args.import_map:
        try:
            engine.import_map(args.import_map)
        except (OSError, ValueError) as e:
            print(f"Error loading map {args.import_map}: {e}", file=sys.stderr)
            return 1

    # --unredact mode: reverse redaction using mapping file
    if args.unredact:
        try:
            engine.import_map(args.unredact)
        except (OSError, ValueError) as e:
            print(f"Error loading map {args.unredact}: {e}", file=sys.stderr)
            return 1
        text = _read_input(args)
        if text is None:
            return 1
        result = engine.unredact(text)
        _write_output(args, result)
        return 0

    # --output-dir mode: batch process files
    if args.output_dir:
        return _batch_process(args, engine)

    # Gather input
    text = _read_input(args)
    if text is None:
        return 1

    # Redact
    report = engine.redact_with_report(text)
    result = report.text
    applied_redactions = report.unique_applied()
    changed = report.changed

    # --check mode: exit non-zero if new redactions found
    if args.check:
        if changed:
            print(f"Found {len(applied_redactions)} value(s) to redact:", file=sys.stderr)
            for cat, count in sorted(_stats_for_applied(applied_redactions).items()):
                print(f"  {cat}: {count}", file=sys.stderr)
            return 1
        if not args.quiet:
            print("Clean — no redactions needed.", file=sys.stderr)
        return 0

    # --dry-run: show mapping instead of output
    if args.dry_run:
        if not changed:
            print("No redactions found.", file=sys.stderr)
        else:
            print("Redactions that would be applied:", file=sys.stderr)
            for _category, real, placeholder in sorted(
                applied_redactions, key=lambda x: x[2]
            ):
                print(f"  {real} -> {placeholder}", file=sys.stderr)
        return 0

    # --diff: show unified diff
    if args.diff:
        diff = difflib.unified_diff(
            text.splitlines(keepends=True),
            result.splitlines(keepends=True),
            fromfile="original",
            tofile="redacted",
        )
        sys.stdout.writelines(diff)
        return 0

    # LLM review
    llm_cfg = get_llm_config(config)
    use_llm = (
        args.llm
        or os.environ.get("DECON_LLM") == "1"
        or llm_cfg.get("enabled", False)
    )

    if use_llm:
        review = llm_review(
            result,
            model=llm_cfg.get("model", "qwen3.5:9b"),
            host=llm_cfg.get("host", "http://localhost:11434"),
            quiet=args.quiet,
        )
        if review and "CLEAN" not in review:
            findings = parse_findings(review)
            if findings and not args.quiet and sys.stderr.isatty():
                selected = _prompt_llm_review(findings)
                if selected:
                    engine.add_custom_values(selected, case_sensitive=False)
                    result = engine.redact(result)
                    print(
                        f"Redacted {len(selected)} value(s)",
                        file=sys.stderr,
                    )
            elif findings and not args.quiet:
                print("LLM review flagged potential issues:", file=sys.stderr)
                print(review, file=sys.stderr)
                print("---", file=sys.stderr)

    # Output
    _write_output(args, result)

    # Export mapping
    _export_map(args, engine)

    # Verbose stats
    _print_stats(args, engine)

    return 0


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


def _write_output(args: argparse.Namespace, result: str) -> None:
    """Write result to the configured output destination."""
    if args.output:
        write_file(result, args.output, quiet=args.quiet)
    elif args.clipboard:
        write_clipboard(result, quiet=args.quiet)
    else:
        write_stdout(result)


def _export_map(args: argparse.Namespace, engine: RedactionEngine) -> None:
    """Export mapping if requested."""
    if args.export_map:
        try:
            engine.export_map(args.export_map)
        except OSError as e:
            print(f"Error writing map {args.export_map}: {e}", file=sys.stderr)
            return
        if not args.quiet:
            print(f"Mapping exported to {args.export_map}", file=sys.stderr)


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
) -> int:
    """Process multiple files, writing each to output-dir."""
    os.makedirs(args.output_dir, exist_ok=True)
    output_paths = _build_batch_output_paths(args.files, args.output_dir)

    for path in args.files:
        try:
            with open(path) as f:
                text = f.read()
        except OSError as e:
            print(f"Error reading {path}: {e}", file=sys.stderr)
            return 1

        result = engine.redact(text)
        out_path = output_paths[path]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        write_file(result, str(out_path), quiet=args.quiet)

    _export_map(args, engine)
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
                with open(path) as f:
                    texts.append(f.read())
            except OSError as e:
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
