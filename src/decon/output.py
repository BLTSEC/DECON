"""Output handlers: stdout, clipboard, file, tmux capture."""

from __future__ import annotations

import subprocess
import sys

_CLIPBOARD_WRITE_COMMANDS = [
    ["pbcopy"],
    ["wl-copy"],
    ["xclip", "-selection", "clipboard"],
    ["xsel", "--clipboard", "--input"],
]

_CLIPBOARD_READ_COMMANDS = [
    ["pbpaste"],
    ["wl-paste"],
    ["xclip", "-selection", "clipboard", "-o"],
    ["xsel", "--clipboard", "--output"],
]


def write_stdout(text: str) -> None:
    """Write redacted text to stdout."""
    sys.stdout.write(text)
    sys.stdout.flush()


def write_file(text: str, path: str, quiet: bool = False) -> None:
    """Write redacted text to a file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    if not quiet:
        print(f"Written to {path}", file=sys.stderr)


def write_clipboard(text: str, quiet: bool = False) -> bool:
    """Copy redacted text to system clipboard."""
    for cmd in _CLIPBOARD_WRITE_COMMANDS:
        try:
            subprocess.run(cmd, input=text.encode(), check=True, capture_output=True)
            if not quiet:
                print("Copied to clipboard", file=sys.stderr)
            return True
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError:
            continue
    if not quiet:
        print("No clipboard tool found (pbcopy/wl-copy/xclip/xsel)", file=sys.stderr)
    return False


def read_clipboard(quiet: bool = False) -> str | None:
    """Read text from system clipboard."""
    for cmd in _CLIPBOARD_READ_COMMANDS:
        try:
            result = subprocess.run(cmd, capture_output=True, check=True)
            return result.stdout.decode()
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError:
            continue
    if not quiet:
        print("No clipboard tool found (pbpaste/wl-paste/xclip/xsel)", file=sys.stderr)
    return None


def capture_tmux_pane(quiet: bool = False) -> str | None:
    """Capture the active tmux pane's scrollback buffer."""
    try:
        result = subprocess.run(
            ["tmux", "capture-pane", "-p", "-S", "-"],
            capture_output=True,
            check=True,
        )
        return result.stdout.decode()
    except FileNotFoundError:
        if not quiet:
            print("tmux not found", file=sys.stderr)
        return None
    except subprocess.CalledProcessError as e:
        if not quiet:
            print(f"tmux capture failed: {e}", file=sys.stderr)
        return None
