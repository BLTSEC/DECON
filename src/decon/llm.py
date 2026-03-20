"""Ollama integration for LLM safety-net review of redacted text."""

from __future__ import annotations

import json
import sys
import urllib.request
import urllib.error


REVIEW_PROMPT = """\
Redacted text below uses SAFE placeholders (10.0.0.X, user_XX@example.com, \
HOST_XX.example.internal, 00:DE:AD:00:00:XX, SECRET_XX, API_KEY_XX, etc). \
Do NOT flag these.

Find only MISSED sensitive data: real IPs, emails, hostnames, credentials, \
person/company/project names, usernames, internal URLs.

Reply CLEAN if nothing found. Otherwise one FOUND: per line. No explanation.

---
{text}
---"""


def llm_review(
    text: str,
    model: str = "qwen3.5:9b",
    host: str = "http://localhost:11434",
    quiet: bool = False,
) -> str | None:
    """Send redacted text to Ollama for review.

    Returns the LLM's response, or None if Ollama is unavailable.
    """
    url = f"{host}/api/chat"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "user", "content": REVIEW_PROMPT.format(text=text)},
        ],
        "stream": False,
        "think": False,
        "options": {
            "num_predict": 256,
            "temperature": 0,
        },
    }).encode()

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode())
            return data.get("message", {}).get("content", "")
    except urllib.error.URLError as e:
        if not quiet:
            print(
                f"Warning: Ollama not available ({e}), proceeding with regex-only output",
                file=sys.stderr,
            )
        return None
    except Exception as e:
        if not quiet:
            print(
                f"Warning: LLM review failed ({e}), proceeding with regex-only output",
                file=sys.stderr,
            )
        return None
