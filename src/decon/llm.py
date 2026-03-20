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


def _filter_placeholder_findings(response: str) -> str:
    """Remove FOUND: lines that reference placeholders or safe software names."""
    lines = []
    seen_findings: set[str] = set()
    for line in response.splitlines():
        if line.startswith("FOUND:"):
            value = line[len("FOUND:"):].strip().strip('"').strip("'").strip()
            if not value:
                continue
            if _PLACEHOLDER_RE.match(value):
                continue
            if _is_safe_software(value):
                continue
            # Dedup repeated findings
            if value.lower() in seen_findings:
                continue
            seen_findings.add(value.lower())
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
