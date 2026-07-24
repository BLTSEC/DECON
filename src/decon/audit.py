"""Append-only audit trail of every substitution DECON makes.

Enabled by default. The log necessarily contains the real values that were
redacted, so it is written with the same care as an exported map: an owner-only
directory, mode 0600, and never committed.

Auditing must never cost the operator their sanitized output — a failure to
write warns on stderr and the redaction proceeds.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from decon.state import StateError, ensure_dir, state_dir

AUDIT_FILENAME = "audit.jsonl"


def audit_path(configured: str | None = None) -> Path:
    """Return the audit log path, honouring an explicit config override."""
    if configured:
        return Path(configured).expanduser()
    return state_dir() / AUDIT_FILENAME


def write_entry(
    substitutions: list[tuple[str, str, str]],
    *,
    mode: str,
    sources: list[str] | None = None,
    path: str | None = None,
    quiet: bool = False,
) -> bool:
    """Append one JSON record describing this run's substitutions.

    Returns True when a record was written. A run that changed nothing writes
    nothing, so the log stays a record of actual disclosure risk.
    """
    if not substitutions:
        return False

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": mode,
        "sources": sources or ["-"],
        "substitutions": [
            {"category": category, "original": original, "placeholder": placeholder}
            for category, original, placeholder in substitutions
        ],
    }

    try:
        destination = audit_path(path)
        # Only tighten permissions on DECON's own state directory. A configured
        # path may sit in a directory the user manages; the log file itself is
        # still created 0600 below either way.
        ensure_dir(destination.parent, tighten=path is None)
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except (OSError, StateError, ValueError) as e:
        # Never fail a redaction because the audit log is unwritable.
        if not quiet:
            print(f"Warning: could not write audit log ({e})", file=sys.stderr)
        return False
    return True
