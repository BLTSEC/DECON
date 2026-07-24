"""Owner-only state directory for sessions and the audit log.

Everything DECON persists here contains real, unredacted values, so the
directory is created 0700 and every file inside it 0600 — the same posture as
an exported map.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# A session name becomes a filename, so keep it to characters that cannot
# traverse or escape the sessions directory.
_SAFE_NAME = re.compile(r"[A-Za-z0-9._-]+")

DEFAULT_SESSION = "last"


class StateError(ValueError):
    """Raised when the state directory or a session name is unusable."""


def state_dir() -> Path:
    """Return the base state directory, honouring XDG_STATE_HOME."""
    override = os.environ.get("DECON_STATE_DIR")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "decon"


def ensure_dir(path: Path, *, tighten: bool = True) -> Path:
    """Create a directory and return it.

    With `tighten` (the default) the directory is forced to 0700, because
    mkdir(parents=True) applies the process umask and usually leaves DECON's
    own state world-readable.

    Pass `tighten=False` for a user-configured destination: silently changing
    the mode of a directory the user manages is a side effect DECON has no
    business causing. Files written inside are still created 0600 by the
    caller, which is the protection that matters.
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
        if tighten:
            # Tighten the base directory too, not just the leaf.
            for target in {state_dir(), path}:
                if target.is_dir():
                    os.chmod(target, 0o700)
    except OSError as e:
        raise StateError(f"could not prepare {path}: {e}") from e
    return path


def session_path(name: str | None) -> Path:
    """Return the map path for a session name, validating the name."""
    # Only an absent flag defaults; an explicitly empty name is an error rather
    # than a silent write to the default session.
    name = DEFAULT_SESSION if name is None else name.strip()
    if not name:
        raise StateError("session name must not be empty")
    if not _SAFE_NAME.fullmatch(name) or name in {".", ".."}:
        raise StateError(
            f"invalid session name {name!r}: "
            "use letters, digits, dot, dash, or underscore"
        )
    return ensure_dir(state_dir() / "sessions") / f"{name}.json"


def list_sessions() -> list[str]:
    """Return known session names, sorted."""
    directory = state_dir() / "sessions"
    if not directory.is_dir():
        return []
    return sorted(p.stem for p in directory.glob("*.json"))
