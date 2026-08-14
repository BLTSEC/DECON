"""Owner-only state directory for sessions and the audit log.

Sessions and optional full-detail audits contain real values. Metadata audits
do not, but all state uses the stricter posture: directories are 0700 and files
are 0600.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

# A session name becomes a filename, so keep it to characters that cannot
# traverse or escape the sessions directory.
_SAFE_NAME = re.compile(r"[A-Za-z0-9._-]+")
_TTL = re.compile(r"([1-9][0-9]*)([smhdw])", re.IGNORECASE)
_TTL_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_MAX_TTL_SECONDS = 10 * 365 * 86400

DEFAULT_SESSION = "last"


class StateError(ValueError):
    """Raised when the state directory or a session name is unusable."""


def parse_session_ttl(value: str) -> timedelta:
    """Parse a compact lifetime such as 30m, 24h, or 7d."""
    match = _TTL.fullmatch(value.strip())
    if not match:
        raise StateError(
            "session TTL must be a positive whole number followed by "
            "s, m, h, d, or w (for example: 30m, 24h, 7d)"
        )
    seconds = int(match.group(1)) * _TTL_SECONDS[match.group(2).lower()]
    if seconds > _MAX_TTL_SECONDS:
        raise StateError("session TTL must not exceed 3650d")
    return timedelta(seconds=seconds)


def new_session_metadata(ttl: str | None = None) -> dict[str, str]:
    """Build timestamp metadata for a saved session."""
    created = datetime.now(UTC)
    metadata = {"created_at": created.isoformat()}
    if ttl:
        metadata["expires_at"] = (created + parse_session_ttl(ttl)).isoformat()
    return metadata


def session_is_expired(path: Path, *, now: datetime | None = None) -> bool:
    """Validate session metadata and report whether its TTL elapsed."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as e:
        raise StateError(f"could not inspect session {path.stem!r}: {e}") from e
    if not isinstance(data, dict):
        raise StateError(f"invalid session map {path.stem!r}: root must be an object")
    metadata = data.get("session")
    if metadata is None:  # Sessions created before TTL support never expire.
        return False
    if not isinstance(metadata, dict) or set(metadata) - {"created_at", "expires_at"}:
        raise StateError(f"invalid metadata in session {path.stem!r}")
    try:
        created = datetime.fromisoformat(metadata["created_at"])
        expires_raw = metadata.get("expires_at")
        expires = datetime.fromisoformat(expires_raw) if expires_raw else None
    except (KeyError, TypeError, ValueError) as e:
        raise StateError(f"invalid timestamps in session {path.stem!r}") from e
    if created.tzinfo is None or (expires is not None and expires.tzinfo is None):
        raise StateError(f"session {path.stem!r} timestamps require a timezone")
    if expires is None:
        return False
    if expires <= created:
        raise StateError(f"session {path.stem!r} expires_at must follow created_at")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC) >= expires.astimezone(UTC)


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
