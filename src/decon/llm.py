"""Ollama integration for LLM safety-net review of redacted text."""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request

from decon.patterns import get_placeholder_templates

# Maximum characters to send in a single LLM request.
MAX_LLM_CHARS = 12000
LLM_CHUNK_OVERLAP = 256


def _build_placeholder_re() -> re.Pattern[str]:
    """Auto-generate a regex matching all DECON placeholder formats.

    Derived from the actual placeholder_template strings in build_default_rules()
    so new rules are automatically covered without manual updates here.
    """
    fragments: list[str] = []
    for tmpl in get_placeholder_templates():
        # Escape regex-special chars in the literal parts
        escaped = re.escape(tmpl)
        # Replace format specifiers with appropriate regex patterns
        # {n:02d}, {n:04d}, {n} -> \d+
        # {n:x}, {n:02X} -> [0-9a-fA-F]+
        escaped = re.sub(r"\\{n(?::[^}]*)?\\}", lambda m: (
            r"[0-9a-fA-F]+" if any(c in m.group() for c in "xX")
            else r"\d+"
        ), escaped)
        fragments.append(escaped)

    # Also match default and documented custom placeholder formats.
    fragments.append(r"\[CUSTOM_[A-Z0-9_]*REDACTED_\d+\]")
    # Typed engagement targets are registered from config at runtime, so their
    # templates are not in build_default_rules().
    fragments.append(r"\[SHARE_REDACTED_\d+\]")
    # Legacy custom value placeholders remain safe for imported/older output.
    fragments.append(r"REDACTED_\d+")
    # Domain-context FQDN placeholders are parent-domain style.
    fragments.append(r"example(?:\d+)?\.internal\d*")

    return re.compile(r"^(?:" + "|".join(fragments) + r")$")


_PLACEHOLDER_RE = _build_placeholder_re()
_FINDING_LINE_RE = re.compile(
    r"^\s*(?:[-*]\s*)?FOUND\s*:\s*(.*?)\s*$",
    re.IGNORECASE,
)


REVIEW_PROMPT = """\
This is redacted pentest output. Placeholders ([IPV4_REDACTED_XXXX], \
[IPV6_REDACTED_XXXX], [MAC_REDACTED_XXXX], [EMAIL_REDACTED_XXXX], \
[HOST_REDACTED_XXXX], [HOST_SHORT_REDACTED_XXXX], [DOMAIN_REDACTED_XXXX], \
[SECRET_REDACTED_XXXX], [SHARE_REDACTED_XXXX], [CUSTOM_REDACTED_XXXX], \
URL_REDACTED_XX, NTLM_HASH_XX, NTLMV2_HASH_XX, SAM_DUMP_XX, \
KERBEROS_KEY_XX, KERBEROS_HASH_XX, DCC2_HASH_XX, DPAPI_KEY_XX, \
SID_REDACTED_XX, DOMAIN_USER_XX, UNC_PATH_XX, \
PRIVATE_KEY_REDACTED_XX, etc.) are SAFE — ignore them completely.

Flag ANY real-world value that survived redaction. Every real domain, \
hostname, IP, URL, email, username, person/company/project name, or \
credential is a leak — even well-known public ones like nmap.org or \
scanme.nmap.org. If it is not a placeholder, it should have been redacted.

Reply CLEAN if nothing found. Otherwise one FOUND: per line. No explanation.

---
{text}
---"""


# Software/vendor/OS names commonly found in service banners and tool output.
# These are findings (what is running), not target identifiers (who owns it).
# Post-filtered because the LLM prompt is deliberately aggressive ("flag everything")
# and small models can't reliably distinguish software names from real leaks.
_SAFE_SOFTWARE = {
    # Web servers
    "apache", "apache httpd", "nginx", "iis", "tomcat", "lighttpd", "httpd",
    "caddy", "gunicorn", "uvicorn",
    # SSH / remote access
    "openssh", "dropbear", "putty",
    # Operating systems
    "ubuntu", "debian", "centos", "fedora", "kali", "alpine", "rhel",
    "red hat", "suse", "arch linux", "gentoo", "slackware",
    "linux", "windows", "windows server", "macos", "freebsd", "openbsd",
    "unix", "solaris",
    # Vendors / orgs in banners
    "microsoft", "nlnet labs", "nsd", "isc", "isc bind", "bind",
    "nmap", "nmap project",
    # Databases
    "mysql", "postgresql", "mariadb", "mongodb", "redis", "mssql",
    "sql server", "oracle", "sqlite", "cassandra", "elasticsearch",
    # Languages / runtimes
    "php", "python", "java", "node.js", "ruby", "perl", "go", ".net",
    # CI / infra tools
    "jenkins", "grafana", "gitlab", "docker", "kubernetes", "ansible",
    "terraform", "prometheus", "nagios", "zabbix",
    # CMS / web apps
    "wordpress", "drupal", "joomla",
    # Protocols
    "ssl", "tls", "http", "https", "ftp", "smtp", "dns", "ldap",
    "kerberos", "smb", "rdp", "vnc", "snmp", "ntp",
    # Security tools (appear in output headers)
    "gobuster", "metasploit", "burp", "nessus", "openvas", "nikto",
    "sqlmap", "hydra", "john", "hashcat", "responder", "bloodhound",
    "mimikatz", "crackmapexec", "netexec", "impacket", "certipy",
    "smbclient", "rpcclient", "enum4linux", "linpeas", "winpeas",
}


# Timestamps in tool output are never sensitive — they show when a tool ran,
# not anything about the target. Common formats:
#   2024-09-09 16:04:31   |   2024-09-09T16:04:31   |   16:04:31
#   14:28:13 CDT 2026     |   Tue Mar 24 14:28:13 CDT 2026   |   2024-09-09
_TIMESTAMP_RE = re.compile(
    r"^(?:"
    r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}(?::\d{2})?"  # datetime
    r"|\d{4}-\d{2}-\d{2}"                              # date only
    r"|\d{2}:\d{2}:\d{2}"                              # time only
    r"|\d{2}:\d{2}:\d{2}(?:\s+[A-Z]{2,5})?\s+\d{4}"   # time tz year
    r"|(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+[A-Z]{2,5})?\s+\d{4}"  # ctime/date
    r")$"
)

# Tool runtimes / elapsed times are also non-sensitive artifacts.
_DURATION_RE = re.compile(
    r"^\d+(?:\.\d+)?\s*"
    r"(?:ms|msec|msecs|millisecond|milliseconds|"
    r"s|sec|secs|second|seconds|"
    r"m|min|mins|minute|minutes|"
    r"h|hr|hrs|hour|hours)$",
    re.IGNORECASE,
)

# Well-known public wordlists and resources that appear in pentest commands.
# These are tool inputs (what was used), not target data.
_SAFE_WORDLISTS = {
    # SecLists / common password lists
    "rockyou.txt", "rockyou.txt.gz",
    "common.txt", "big.txt", "raft-large-words.txt", "raft-medium-words.txt",
    "raft-small-words.txt", "raft-large-files.txt", "raft-medium-files.txt",
    "directory-list-2.3-medium.txt", "directory-list-2.3-small.txt",
    "directory-list-2.3-big.txt", "directory-list-lowercase-2.3-medium.txt",
    "best1050.txt", "darkweb2017-top10000.txt",
    "2023-200_most_used_passwords.txt",
    "fasttrack.txt", "probable-v2-top1575.txt", "probable-v2-top12000.txt",
    "xato-net-10-million-passwords.txt",
    # Username lists
    "names.txt", "usernames.txt", "top-usernames-shortlist.txt",
    # DNS / subdomains
    "subdomains-top1million-5000.txt", "subdomains-top1million-20000.txt",
    "subdomains-top1million-110000.txt", "bitquark-subdomains-top100000.txt",
    "fierce-hostlist.txt", "namelist.txt",
}

# Intentionally preserved Nmap boilerplate URLs.
_SAFE_URLS = {
    "https://nmap.org",
    "https://nmap.org/submit/",
}


def _is_safe_software(value: str) -> bool:
    """Check if a flagged value is a known software/vendor name."""
    normalized = value.lower().strip()
    if normalized in _SAFE_SOFTWARE:
        return True
    # Also check if the value is "Name vX.Y.Z" (software + version)
    parts = normalized.split()
    if len(parts) >= 2 and parts[0] in _SAFE_SOFTWARE:
        return True
    return False


def _is_safe_artifact(value: str) -> bool:
    """Check if a flagged value is a safe non-sensitive artifact."""
    stripped = value.strip()
    if _TIMESTAMP_RE.match(stripped):
        return True
    if _DURATION_RE.match(stripped):
        return True
    if stripped.lower() in _SAFE_WORDLISTS:
        return True
    if stripped.lower() in _SAFE_URLS:
        return True
    return False


def _normalize_finding(value: str) -> str:
    """Normalize a FOUND: value by stripping LLM-added context.

    The LLM may append port numbers, parenthetical explanations, or
    trailing commentary to placeholder values, e.g.:
      10.0.0.1:81  |  10.0.0.1 (target IP)  |  10.0.0.1 - used as target
    Strip these so the core value can match _PLACEHOLDER_RE.
    """
    # Strip parenthetical suffix: "10.0.0.1 (target IP)" -> "10.0.0.1"
    value = re.sub(r"\s*\(.*\)\s*$", "", value)
    # Strip trailing commentary after " - " or " — "
    value = re.sub(r"\s+[-–—].*$", "", value)
    # Strip port suffix from IPs: "10.0.0.1:81" -> "10.0.0.1"
    value = re.sub(r"^(\d+\.\d+\.\d+\.\d+):\d+$", r"\1", value)
    # Strip protocol prefix: "http-get://10.0.0.1:81/" -> "10.0.0.1"
    value = re.sub(r"^[a-zA-Z][-a-zA-Z0-9+.]*://", "", value)
    # Strip port/path suffixes appended to typed DECON placeholders.
    value = re.sub(
        r"^(\[[A-Z][A-Z0-9_]*\])(?::\d+)?(?:/.*)?$",
        r"\1",
        value,
    )
    # Strip trailing path/port after protocol removal: "10.0.0.1:81/" -> "10.0.0.1"
    value = re.sub(r"^(\d+\.\d+\.\d+\.\d+)[:/].*$", r"\1", value)
    return value.strip().rstrip(".,;:!?")


# A finding sometimes arrives with the key it was found under, e.g.
# "token=[SECRET_REDACTED_0002]". The value is already redacted, so the line is
# noise, but the prefix stops it matching the placeholder pattern.
_KEYED_VALUE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,30}\s*[:=]\s*(.+)$")


def _strip_key_prefix(value: str) -> str:
    """Return the value half of a key=value finding, or the input unchanged."""
    match = _KEYED_VALUE.match(value)
    return match.group(1).strip() if match else value


def _filter_placeholder_findings(response: str) -> str:
    """Remove FOUND: lines that reference placeholders or safe software names."""
    lines = []
    seen_findings: set[str] = set()
    for line in response.splitlines():
        match = _FINDING_LINE_RE.match(line)
        if not match:
            continue
        value = match.group(1).strip().strip('"').strip("'").strip()
        if not value:
            continue
        normalized = _normalize_finding(value)
        # Test the key-stripped form too, so "token=[SECRET_REDACTED_0002]" is
        # recognised as already-redacted. Only the *filter* decision uses this;
        # the reported value is left untouched, so nothing that should be
        # redacted is silently rewritten.
        candidates = {value, normalized, _normalize_finding(_strip_key_prefix(value))}
        if any(_PLACEHOLDER_RE.match(c) for c in candidates if c):
            continue
        if _is_safe_software(normalized) or _is_safe_software(value):
            continue
        if _is_safe_artifact(normalized) or _is_safe_artifact(value):
            continue
        # Dedup repeated findings, including across overlapping LLM chunks.
        if normalized.lower() in seen_findings:
            continue
        seen_findings.add(normalized.lower())
        lines.append(f"FOUND: {value}")
    filtered = "\n".join(lines).strip()
    if not any(line.startswith("FOUND:") for line in lines):
        return "CLEAN"
    return filtered


def parse_findings(response: str) -> list[str]:
    """Extract clean values from FOUND: lines in an LLM review response."""
    values: list[str] = []
    seen: set[str] = set()
    for line in response.splitlines():
        match = _FINDING_LINE_RE.match(line)
        if not match:
            continue
        raw = match.group(1).strip().strip('"').strip("'").strip()
        if not raw:
            continue
        value = _normalize_finding(raw)
        if value and value.lower() not in seen:
            seen.add(value.lower())
            values.append(value)
    return values


def _chunk_review_text(text: str) -> list[str]:
    """Split text into overlapping, line-aware chunks for complete review."""
    if len(text) <= MAX_LLM_CHARS:
        return [text]

    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + MAX_LLM_CHARS, len(text))
        if end < len(text):
            line_end = text.rfind("\n", start + 1, end)
            if line_end > start:
                end = line_end + 1
        chunks.append(text[start:end])
        if end == len(text):
            break
        start = max(end - LLM_CHUNK_OVERLAP, start + 1)
    return chunks


def _ollama_request(text: str, model: str, host: str) -> str:
    """Send one review chunk to Ollama and return its raw response text."""
    url = f"{host.rstrip('/')}/api/chat"
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
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = json.loads(resp.read().decode())
    return data.get("message", {}).get("content", "")


def llm_review(
    text: str,
    model: str = "qwen3.5:9b",
    host: str = "http://localhost:11434",
    quiet: bool = False,
) -> str | None:
    """Send redacted text to Ollama for review.

    Returns the LLM's response, or None if Ollama is unavailable.
    """
    chunks = _chunk_review_text(text)
    if len(chunks) > 1:
        if not quiet:
            print(
                f"Reviewing large input in {len(chunks)} LLM chunks",
                file=sys.stderr,
            )

    try:
        raw_responses = [
            _ollama_request(chunk, model=model, host=host) for chunk in chunks
        ]
        return _filter_placeholder_findings("\n".join(raw_responses))
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
