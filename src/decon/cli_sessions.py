"""Named-session lifecycle helpers for the DECON CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from decon.engine import RedactionEngine
from decon.state import (
    StateError,
    list_sessions,
    new_session_metadata,
    session_is_expired,
    session_path,
)


def _remove(path: Path, *, label: str) -> str | None:
    """Remove a session path and return an error message on failure."""
    try:
        path.unlink()
    except OSError as e:
        return f"Error removing session {label}: {e}"
    return None


def run_session_admin(args: argparse.Namespace) -> int | None:
    """Handle list/forget actions, returning None for normal processing."""
    if args.forget:
        try:
            path = session_path(args.forget)
        except StateError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        if not path.exists():
            print(f"Error: no saved session named {args.forget!r}", file=sys.stderr)
            return 1
        if error := _remove(path, label=args.forget):
            print(error, file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"Forgot session {args.forget!r}", file=sys.stderr)
        return 0

    if args.forget_all:
        names = list_sessions()
        for name in names:
            try:
                path = session_path(name)
            except StateError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            if error := _remove(path, label=name):
                print(error, file=sys.stderr)
                return 1
        if not args.quiet:
            message = (
                f"Forgot {len(names)} session(s)" if names else "No saved sessions."
            )
            print(message, file=sys.stderr)
        return 0

    if args.list_sessions:
        active: list[str] = []
        expired = 0
        for name in list_sessions():
            path = session_path(name)
            try:
                stale = session_is_expired(path)
            except StateError:
                # Leave damaged sessions visible so the operator can forget
                # them or see the detailed error during restore.
                active.append(name)
                continue
            if stale:
                if error := _remove(path, label=name):
                    print(error, file=sys.stderr)
                    return 1
                expired += 1
            else:
                active.append(name)
        if not active:
            print("No saved sessions.", file=sys.stderr)
        for name in active:
            print(name)
        if expired and not args.quiet:
            print(f"Removed {expired} expired session(s)", file=sys.stderr)
        return 0

    return None


def resolve_session(name: str) -> Path | None:
    """Resolve an active named session and report user-facing failures."""
    try:
        path = session_path(name)
    except StateError as e:
        print(f"Error: {e}", file=sys.stderr)
        return None
    if not path.exists():
        known = list_sessions()
        hint = f" Known sessions: {', '.join(known)}" if known else ""
        print(f"Error: no saved session named {name!r}.{hint}", file=sys.stderr)
        return None
    try:
        expired = session_is_expired(path)
    except StateError as e:
        print(f"Error: {e}", file=sys.stderr)
        return None
    if not expired:
        return path
    if error := _remove(path, label=name):
        print(f"Error: session {name!r} expired; {error.lower()}", file=sys.stderr)
    else:
        print(f"Error: session {name!r} expired and was removed", file=sys.stderr)
    return None


def save_session(args: argparse.Namespace, engine: RedactionEngine) -> bool:
    """Persist the engine mapping when --session was requested."""
    if args.session is None:
        return True
    try:
        engine.export_map(
            str(session_path(args.session)),
            session_metadata=new_session_metadata(args.session_ttl),
        )
    except (OSError, StateError) as e:
        print(f"Error saving session {args.session}: {e}", file=sys.stderr)
        return False
    if not args.quiet:
        expiry = f" (expires after {args.session_ttl})" if args.session_ttl else ""
        print(
            f"Session {args.session!r} saved{expiry} — "
            f"restore with: decon --restore {args.session}",
            file=sys.stderr,
        )
    return True


def consume_session(path: Path, *, name: str, quiet: bool) -> bool:
    """Delete a successfully restored session."""
    if error := _remove(path, label=name):
        print(
            f"Error: restored output was emitted, but {error.lower()}", file=sys.stderr
        )
        return False
    if not quiet:
        print(f"Consumed session {name!r}", file=sys.stderr)
    return True
