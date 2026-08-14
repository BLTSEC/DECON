"""Append-only audit trail of DECON operations.

The default metadata format records counts only. An explicit ``detail=full``
setting adds source paths and reversible values and must be protected like an
exported map.

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
    status: str = "emitted",
    sources: list[str] | None = None,
    path: str | None = None,
    detail: str = "metadata",
    record_empty: bool = False,
    quiet: bool = False,
) -> bool:
    """Append one JSON record describing this run's substitutions.

    Returns True when a record was written. A run that changed nothing normally
    writes nothing; ``record_empty`` exists for explicit boundary events such
    as a forced provider transmission.
    """
    if not substitutions and not record_empty:
        return False

    if detail not in {"metadata", "full"}:
        raise ValueError("audit detail must be metadata or full")

    categories: dict[str, int] = {}
    for category, _original, _placeholder in substitutions:
        categories[category] = categories.get(category, 0) + 1

    entry: dict[str, object] = {
        "schema_version": 2,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "operation": mode,
        "status": status,
        "source_count": len(sources) if sources else 1,
        "total": len(substitutions),
        "categories": categories,
    }
    if detail == "full":
        entry["sources"] = sources or ["-"]
        entry["substitutions"] = [
            {"category": category, "original": original, "placeholder": placeholder}
            for category, original, placeholder in substitutions
        ]

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
            # The creation mode does not affect an existing file. Tighten it on
            # every append so a configured log cannot silently remain group- or
            # world-readable after being created elsewhere.
            os.fchmod(fd, 0o600)
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except (OSError, StateError, ValueError) as e:
        # Never fail a redaction because the audit log is unwritable.
        if not quiet:
            print(f"Warning: could not write audit log ({e})", file=sys.stderr)
        return False
    return True
