"""Argument parser for the DECON command-line interface."""

from __future__ import annotations

import argparse

from decon import __version__
from decon.state import DEFAULT_SESSION


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
        "--strict-llm",
        action="store_true",
        help="Require a successful clean LLM review before emitting output",
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
        "--session-ttl",
        metavar="DURATION",
        help="Expire a saved session after a duration such as 30m, 24h, or 7d",
    )
    parser.add_argument(
        "--restore",
        nargs="?",
        const=DEFAULT_SESSION,
        metavar="NAME",
        help="Restore real values using a saved session",
    )
    parser.add_argument(
        "--consume",
        action="store_true",
        help="Delete the saved session after a successful --restore",
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
