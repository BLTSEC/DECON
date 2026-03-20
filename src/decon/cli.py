"""CLI entry point for decon."""

from __future__ import annotations

import argparse
import os
import sys

from decon import __version__
from decon.engine import RedactionEngine
from decon.config import (
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
from decon.llm import llm_review


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
        "--dry-run",
        action="store_true",
        help="Show what would be redacted",
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --init-config: create config and exit
    if args.init_config:
        init_config()
        return 0

    # Load config
    config = load_config()

    # Build engine
    engine = RedactionEngine()

    # Apply config
    apply_config_to_engine(engine, config, args.profile)

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
    if args.enable:
        for name in args.enable.split(","):
            name = name.strip()
            try:
                engine.enable_rule(name)
            except ValueError:
                print(f"Unknown rule: {name}", file=sys.stderr)
                return 1

    if args.disable:
        for name in args.disable.split(","):
            name = name.strip()
            try:
                engine.disable_rule(name)
            except ValueError:
                print(f"Unknown rule: {name}", file=sys.stderr)
                return 1

    # Import prior mapping
    if args.import_map:
        engine.import_map(args.import_map)

    # Gather input
    text = _read_input(args)
    if text is None:
        return 1

    # Redact
    result = engine.redact(text)

    # --dry-run: show mapping instead of output
    if args.dry_run:
        if not engine.mapping:
            print("No redactions found.", file=sys.stderr)
        else:
            print("Redactions that would be applied:", file=sys.stderr)
            for real, placeholder in sorted(
                engine.mapping.items(), key=lambda x: x[1]
            ):
                print(f"  {real} -> {placeholder}", file=sys.stderr)
        return 0

    # LLM review
    use_llm = args.llm or os.environ.get("DECON_LLM") == "1"
    if not use_llm:
        llm_cfg = get_llm_config(config)
        use_llm = llm_cfg.get("enabled", False)

    if use_llm:
        llm_cfg = get_llm_config(config)
        review = llm_review(
            result,
            model=llm_cfg.get("model", "qwen3.5:9b"),
            host=llm_cfg.get("host", "http://localhost:11434"),
            quiet=args.quiet,
        )
        if review and "CLEAN" not in review:
            print("LLM review flagged potential issues:", file=sys.stderr)
            print(review, file=sys.stderr)
            print("---", file=sys.stderr)

    # Output
    if args.output:
        write_file(result, args.output)
    elif args.clipboard:
        write_clipboard(result)
    else:
        write_stdout(result)

    # Export mapping
    if args.export_map:
        engine.export_map(args.export_map)
        if not args.quiet:
            print(f"Mapping exported to {args.export_map}", file=sys.stderr)

    # Verbose stats
    if args.verbose and not args.quiet:
        stats = engine.get_stats()
        if stats:
            print("Redaction stats:", file=sys.stderr)
            for cat, count in sorted(stats.items()):
                print(f"  {cat}: {count}", file=sys.stderr)
        else:
            print("No redactions performed.", file=sys.stderr)

    return 0


def _read_input(args: argparse.Namespace) -> str | None:
    """Read input from files, stdin, clipboard, or tmux."""
    texts: list[str] = []

    if args.tmux:
        text = capture_tmux_pane()
        if text:
            texts.append(text)

    if args.clipboard_in:
        text = read_clipboard()
        if text:
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
