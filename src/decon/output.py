"""Output handlers: stdout, clipboard, file, tmux capture."""

from __future__ import annotations

import subprocess
import sys


def write_stdout(text: str) -> None:
    """Write redacted text to stdout."""
    sys.stdout.write(text)
    sys.stdout.flush()


def write_file(text: str, path: str) -> None:
    """Write redacted text to a file."""
    with open(path, "w") as f:
        f.write(text)
    print(f"Written to {path}", file=sys.stderr)


def write_clipboard(text: str) -> None:
    """Copy redacted text to system clipboard."""
    try:
        proc = subprocess.run(
            ["pbcopy"],
            input=text.encode(),
            check=True,
            capture_output=True,
        )
    except FileNotFoundError:
        # Try xclip/xsel on Linux
        try:
            proc = subprocess.run(
                ["xclip", "-selection", "clipboard"],
                input=text.encode(),
                check=True,
                capture_output=True,
            )
        except FileNotFoundError:
            try:
                proc = subprocess.run(
                    ["xsel", "--clipboard", "--input"],
                    input=text.encode(),
                    check=True,
                    capture_output=True,
                )
            except FileNotFoundError:
                print(
                    "No clipboard tool found (pbcopy/xclip/xsel)",
                    file=sys.stderr,
                )
                return
    print("Copied to clipboard", file=sys.stderr)


def read_clipboard() -> str:
    """Read text from system clipboard."""
    try:
        result = subprocess.run(
            ["pbpaste"], capture_output=True, check=True
        )
        return result.stdout.decode()
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["xclip", "-selection", "clipboard", "-o"],
                capture_output=True,
                check=True,
            )
            return result.stdout.decode()
        except FileNotFoundError:
            try:
                result = subprocess.run(
                    ["xsel", "--clipboard", "--output"],
                    capture_output=True,
                    check=True,
                )
                return result.stdout.decode()
            except FileNotFoundError:
                print(
                    "No clipboard tool found (pbpaste/xclip/xsel)",
                    file=sys.stderr,
                )
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
