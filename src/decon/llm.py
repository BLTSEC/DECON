"""Ollama integration for LLM safety-net review of redacted text."""

from __future__ import annotations

import json
import re
import sys
import urllib.request
import urllib.error

# Maximum characters to send to the LLM (avoids context overflow on large files)
MAX_LLM_CHARS = 12000

# Patterns that match DECON's own placeholder values
_PLACEHOLDER_RE = re.compile(
    r"^(?:"
    r"10\.0\.0\.\d+"            # IPv4 placeholders
    r"|fd00::[0-9a-fA-F]+"     # IPv6 placeholders
    r"|10\.0\.0\.\d+/\d+"      # CIDR placeholders
    r"|user_\d+@example\.com"   # email placeholders
    r"|HOST_\d+\.example\.internal"  # hostname placeholders
    r"|00:DE:AD:00:00:[0-9A-F]+"    # MAC placeholders
    r"|SECRET_\d+"              # secret placeholders
    r"|API_KEY_\d+"             # API key placeholders
    r"|JWT_REDACTED_\d+"        # JWT placeholders
    r"|URL_REDACTED_\d+"        # URL placeholders
    r"|SSN_REDACTED_\d+"        # SSN placeholders
    r"|CC_REDACTED_\d+"         # credit card placeholders
    r"|NTLM_HASH_\d+"          # NTLM hash placeholders
    r"|DOMAIN_USER_\d+"         # AD domain\user placeholders
    r"|UNC_PATH_\d+"            # UNC path placeholders
    r"|PRIVATE_KEY_REDACTED_\d+"  # private key placeholders
    r"|REDACTED_\d+"            # custom value placeholders
    r"|\(555\) 555-\d+"        # phone placeholders
    r")$"
)


REVIEW_PROMPT = """\
This is redacted pentest output. Placeholders (10.0.0.X, fd00::X, \
user_XX@example.com, HOST_XX.example.internal, SECRET_XX, \
URL_REDACTED_XX, NTLM_HASH_XX, DOMAIN_USER_XX, UNC_PATH_XX, \
PRIVATE_KEY_REDACTED_XX, etc.) are SAFE — ignore them completely.

Flag ANY real-world value that survived redaction. Real domains, \
hostnames, IPs, URLs, emails, usernames, person names, company names, \
or credentials are leaks — even well-known public ones like nmap.org \
or scanme.nmap.org.

Do NOT flag software names, version strings, or vendor names that appear \
in service banners or tool output (e.g., Apache, OpenSSH, Ubuntu, Linux, \
Nmap, NLnet Labs). These are findings, not target identifiers.

Reply CLEAN if nothing found. Otherwise one FOUND: per line. No explanation.

---
{text}
---"""


def _filter_placeholder_findings(response: str) -> str:
    """Remove FOUND: lines that reference DECON's own placeholders."""
    lines = []
    for line in response.splitlines():
        if line.startswith("FOUND:"):
            # Extract the flagged value — strip quotes and whitespace
            value = line[len("FOUND:"):].strip().strip('"').strip("'").strip()
            if _PLACEHOLDER_RE.match(value):
                continue
        lines.append(line)
    filtered = "\n".join(lines).strip()
    # If all FOUND: lines were placeholders, treat as clean
    if not any(l.startswith("FOUND:") for l in lines):
        return "CLEAN"
    return filtered


def llm_review(
    text: str,
    model: str = "qwen3.5:9b",
    host: str = "http://localhost:11434",
    quiet: bool = False,
) -> str | None:
    """Send redacted text to Ollama for review.

    Returns the LLM's response, or None if Ollama is unavailable.
    """
    # Truncate to avoid context overflow
    review_text = text
    if len(text) > MAX_LLM_CHARS:
        review_text = text[:MAX_LLM_CHARS] + "\n\n[... truncated ...]"
        if not quiet:
            print(
                f"Warning: text truncated to {MAX_LLM_CHARS} chars for LLM review",
                file=sys.stderr,
            )

    url = f"{host}/api/chat"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "user", "content": REVIEW_PROMPT.format(text=review_text)},
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
            raw = data.get("message", {}).get("content", "")
            return _filter_placeholder_findings(raw)
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
