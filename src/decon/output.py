"""Output handlers: stdout, clipboard, file, tmux capture."""

from __future__ import annotations

import subprocess
import sys


def write_stdout(text: str) -> None:
    """Write redacted text to stdout."""
    sys.stdout.write(text)
    sys.stdout.flush()


def write_file(text: str, path: str, quiet: bool = False) -> None:
    """Write redacted text to a file."""
    with open(path, "w") as f:
        f.write(text)
    if not quiet:
        print(f"Written to {path}", file=sys.stderr)


def write_clipboard(text: str) -> None:
    """Copy redacted text to system clipboard."""
    for cmd in [
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
    ]:
        try:
            subprocess.run(cmd, input=text.encode(), check=True, capture_output=True)
            print("Copied to clipboard", file=sys.stderr)
            return
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError:
            continue
    print("No clipboard tool found (pbcopy/wl-copy/xclip/xsel)", file=sys.stderr)


def read_clipboard() -> str:
    """Read text from system clipboard."""
    for cmd in [
        ["pbpaste"],
        ["wl-paste"],
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, check=True)
            return result.stdout.decode()
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError:
            continue
    print("No clipboard tool found (pbpaste/wl-paste/xclip/xsel)", file=sys.stderr)
    return ""


def capture_tmux_pane() -> str:
    """Capture the active tmux pane's scrollback buffer."""
    try:
        result = subprocess.run(
            ["tmux", "capture-pane", "-p", "-S", "-"],
            capture_output=True,
            check=True,
        )
        return result.stdout.decode()
    except FileNotFoundError:
        print("tmux not found", file=sys.stderr)
        return ""
    except subprocess.CalledProcessError as e:
        print(f"tmux capture failed: {e}", file=sys.stderr)
        return ""
