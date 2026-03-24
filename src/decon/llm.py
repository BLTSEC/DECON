"""Ollama integration for LLM safety-net review of redacted text."""

from __future__ import annotations

import json
import re
import sys
import urllib.request
import urllib.error

from decon.patterns import get_placeholder_templates

# Maximum characters to send to the LLM (avoids context overflow on large files)
MAX_LLM_CHARS = 12000


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

    # Also match custom value placeholders (from add_custom_values)
    fragments.append(r"REDACTED_\d+")
    # Domain-context FQDN placeholders are parent-domain style.
    fragments.append(r"example(?:\d+)?\.internal\d*")

    return re.compile(r"^(?:" + "|".join(fragments) + r")$")


_PLACEHOLDER_RE = _build_placeholder_re()


REVIEW_PROMPT = """\
This is redacted pentest output. Placeholders (10.0.0.X, fd00::X, \
user_XX@example.com, HOST_XX.example.internal, HOST_XX, example.internal, SECRET_XX, \
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
# not anything about the target.  Common formats:
#   2024-09-09 16:04:31   |   2024-09-09T16:04:31   |   16:04:31   |   2024-09-09
_TIMESTAMP_RE = re.compile(
    r"^(?:"
    r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}(?::\d{2})?"  # datetime
    r"|\d{4}-\d{2}-\d{2}"                              # date only
    r"|\d{2}:\d{2}:\d{2}"                              # time only
    r")$"
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
    # Strip trailing path/port after protocol removal: "10.0.0.1:81/" -> "10.0.0.1"
    value = re.sub(r"^(\d+\.\d+\.\d+\.\d+)[:/].*$", r"\1", value)
    return value.strip().rstrip(".,;:!?")


def _filter_placeholder_findings(response: str) -> str:
    """Remove FOUND: lines that reference placeholders or safe software names."""
    lines = []
    seen_findings: set[str] = set()
    for line in response.splitlines():
        if line.startswith("FOUND:"):
            value = line[len("FOUND:"):].strip().strip('"').strip("'").strip()
            if not value:
                continue
            normalized = _normalize_finding(value)
            if _PLACEHOLDER_RE.match(normalized) or _PLACEHOLDER_RE.match(value):
                continue
            if _is_safe_software(normalized) or _is_safe_software(value):
                continue
            if _is_safe_artifact(normalized) or _is_safe_artifact(value):
                continue
            # Dedup repeated findings
            if normalized.lower() in seen_findings:
                continue
            seen_findings.add(normalized.lower())
        lines.append(line)
    filtered = "\n".join(lines).strip()
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
