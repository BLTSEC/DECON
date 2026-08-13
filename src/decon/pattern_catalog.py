"""Compiled regex catalog used by DECON's ordered redaction rules.

Keeping declarations separate from rule application logic makes both modules
easier to scan while preserving the private names imported by existing users.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_IPV4 = re.compile(
    r"(?<![.\d])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?![\d]|\.[\d])"
)

_CIDR = re.compile(
    r"(?<![.\d])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"/(?:3[0-2]|[12]?\d)"
    r"(?![\d/])"
)

_IPV6 = re.compile(
    r"(?<![.:\w])"
    r"(?:"
    r"fe80:(?::[0-9a-fA-F]{1,4}){0,4}%[0-9a-zA-Z]+"
    r"|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){6}"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    r")"
    r"(?![:\w])",
    re.IGNORECASE,
)

_MAC = re.compile(
    r"(?<![:\w])"
    r"(?:"
    r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
    r"|[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}"
    r"|[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
    r")"
    r"(?![:\w])"
)

_EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

_PHONE = re.compile(
    r"(?<!\d)"
    r"(?:\+?1[-.\s])?"
    r"(?:"
    r"\(\d{3}\)[-.\s]?\d{3}[-.\s]\d{4}"
    r"|\d{3}[-.]\d{3}[-.]\d{4}"
    r")"
    r"(?!\d)"
)

_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

_CC = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

_AWS_KEY = re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")

# Backticks terminate a URL: notes are written in Markdown, and `<url>` in
# inline code would otherwise have its closing backtick swallowed into the
# placeholder, leaving the surrounding formatting unbalanced.
_URL = re.compile(
    r"https?://"
    r"[^\s<>\"\x27\)\]`]*"
    r"[^\s<>\"\x27\)\].,;:!?\-`]"
)

_CONTEXT_SECRET = re.compile(
    r"(?i)"
    r"(?:api[_-]?key|api[_-]?secret|access[_-]?key|private[_-]?key|"
    r"secret[_-]?key|signing[_-]?key|client[_-]?secret|"
    r"token|password|passwd|secret|auth|credential|bearer|"
    r"user\s*id|username|ntlm)"
    r"(?:\s*[:=]\s*)"
    r"(['\"]?)"
    r"(?!(?:true|false|null|none)\1(?=$|[\s,)\]}]))"
    r"(.+?)\1"
    r"(?=$|[\s,)\]}])"
)

# Secrets stated in prose rather than as key=value — the dominant shape in
# hand-written notes:
#     The password is `Hunter2!`.
#     ...and the fake password
#     `Lantern-Cobalt-47!`.          <- keyword and value on separate lines
# The connector verb is optional (real notes often omit it), so the delimiter —
# a quote or markdown backtick — is what does the work: it stops the match
# running away to end of line, and it keeps undelimited prose like "the password
# is stored in Vault" from matching at all. Intervening whitespace may include a
# newline, but the value itself may not span lines.
# Group 1 = delimiter, group 2 = value, matching _context_secret_apply.
_PROSE_SECRET = re.compile(
    r"(?i)"
    r"(?:password|passwd|passphrase|secret|api[_\s-]?key|token|credential)s?"
    r"\s+(?:(?:is|was|are|were|set\s+to|changed\s+to)\s+)?"
    r"(['\"`])([^'\"`\r\n]{3,})\1"
)

_DOMAIN_CONTEXT = re.compile(
    r"(?i)"
    r"(?:domain)"
    r"(?:\s*[:=]\s*)"
    r"(['\"]?)([^\s'\"]{4,})\1"
)

_RDNS_SINGLE_LABEL = re.compile(
    r"(?im)"
    r"(rDNS record for [^:\n]+:\s+)"
    r"([A-Z][A-Z0-9-]{1,62})"
    r"(?=\s|$)"
)

_SMB_NETBIOS_NAME = re.compile(r"(\(name:|CN=)([A-Z][A-Z0-9-]{1,14})(?=\)|,)")

# Matches LDAP DN domain suffix: DC=north,DC=sevenkingdoms,DC=local
# Leading comma (group 1) is preserved; DC= chain (group 2) is replaced.
# Requires 2+ DC= components so single DC=foo never fires as a false positive.
_LDAP_DN_DOMAIN = re.compile(r"(?i)(,?)(DC=[a-zA-Z0-9-]+(?:,DC=[a-zA-Z0-9-]+)+)")

# Matches LDAP sAMAccountName attribute value.
# Handles both attribute output (sAMAccountName: value) and filter syntax (sAMAccountName=value).
# Group 1 = attribute prefix; group 2 = value to redact.
# Excludes ) from value to avoid consuming the closing paren in LDAP search filters.
_LDAP_SAMACCOUNTNAME = re.compile(r"(?i)(sAMAccountName[=:]\s*)([^\s\n)]+)")

# BUG-10: Impacket GetNPUsers.py "[-] User <name> doesn't have..." and
# netexec/CME "[*] Testing <name>" status lines.
# Group 1 = status prefix; group 2 = username to redact.
_IMPACKET_STATUS_USER = re.compile(
    r"(\[-\] User |\[\*\] Testing |\[!\] Testing )([a-zA-Z][a-zA-Z0-9._-]+)(?=\s|$)"
)

# netexec password spray "[*] Trying: <password>" status lines.
# Group 1 = prefix; group 2 = password value to redact (everything up to end-of-line
# or the literal " on " domain suffix common in spray output).
_NETEXEC_SPRAY_PASSWORD = re.compile(r"(\[\*\] Trying:\s+)(\S+?)(?=\s+on\s|\s*\n|\s*$)")

# BUG-12: CN=<lowercase-name> in LDAP DNs (user objects like CN=jon.snow).
# Requires lowercase start to avoid matching well-known containers (CN=Users,
# CN=Builtin, CN=Configuration, CN=Schema, etc. which start uppercase).
# Group 1 = CN= prefix; group 2 = username to redact.
_LDAP_CN_LOWERCASE_USER = re.compile(r"(CN=)([a-z][a-z0-9._-]+)(?=[,\n])")

# BUG-12: ldapsearch comment line "# <name>, <parent>, ..." format.
# The first word on lines like "# jon.snow, Users, north.sevenkingdoms.local"
# is the CN value and should be redacted.
# Group 1 = "# " prefix; group 2 = name to redact.
_LDAP_COMMENT_USER = re.compile(r"(?m)^(#\s+)([a-z][a-z0-9._-]+)(?=,)")

# LDAP description attribute — user display names and custom account notes.
# Redacts all description: values; built-in descriptions (Administrator, Guest,
# krbtgt) are acceptable collateral since their sAMAccountName is already hidden.
# Group 1 = attribute prefix; group 2 = value to redact.
_LDAP_DESCRIPTION = re.compile(r"(?i)(description:\s+)([^\n]+)")

# JSON "description": "value" format (BloodHound, AD-related JSON exports).
# Matches person display names like "Jon Snow", "Samwell Tarly (Password : ...)"
# Group 1 = JSON key+quote prefix; group 2 = value to redact (up to closing quote).
_JSON_DESCRIPTION = re.compile(r'("description":\s*")([^"]{2,}?)(")')

# CN=<GroupOrUserName> in memberOf/DN context when nested directly under
# CN=Users or CN=Builtin. Matches uppercase-start names like CN=Stark and
# CN=Night Watch that are not caught by _LDAP_CN_LOWERCASE_USER.
# Group 1 = CN= prefix; group 2 = name to redact.
_LDAP_CN_USERS_MEMBER = re.compile(
    r"(CN=)([A-Z][^,\n]+?)(?=,CN=(?:Users|Builtin)(?:[,\n]|$))"
)

# nmap NTLM info fields (rdp-ntlm-info, smb2-ntlm-info):
# Target_Name, NetBIOS_Domain_Name, NetBIOS_Computer_Name are short NetBIOS
# names that may not appear elsewhere as FQDNs.
# Group 1 = field prefix; group 2 = value to redact.
_NMAP_NTLM_FIELD = re.compile(
    r"(\|\s+(?:Target_Name|NetBIOS_Domain_Name|NetBIOS_Computer_Name):\s+)(\S+)"
)

# BUG-13: Standalone username in GetUserSPNs.py / GetNPUsers.py kerberoast table
# Name column.  By priority 49 the SPN rule (priority 24) has already replaced
# SPNs with SPN_XX, so the Name column appears right after the placeholder.
# Group 0 is the full match; capture group 1 = username.
_KERBEROAST_TABLE_NAME = re.compile(r"(?:SPN_\d+)\s{2,}([a-z][a-z0-9._-]+)(?=\s)")

_CLI_FLAG_SECRET = re.compile(
    r"(?:^|\s)"
    r"(-p|-P|-pw|-w|-W|--password|--pw|-H|--hash|--hashes"
    r"|-u|-l|--user|--login|--username|-U)"
    r"\s+"
    r'(?:"([^"\r\n]+)"|\'([^\'\r\n]+)\'|([^\s\'\"]+))'
    r"(?=\s|$)"
)

# Flags whose value is an identity rather than a credential. -U is excluded:
# in netexec/smbclient it carries user%password, handled by smb_user_pass.
_CLI_USER_FLAGS = frozenset({"-u", "-l", "--user", "--login", "--username"})

# Values that look like file paths, template placeholders, or flags — not secrets
_CLI_FLAG_SKIP_RE = re.compile(
    r"^(?:"
    r"[/<]"  # starts with / (path) or < (template placeholder)
    r"|None\b"  # Python None in output
    r"|-"  # another flag
    r"|%\{"  # curl -w format string (%{http_code}, etc.)
    r")"
)

_SLASH_PARAM_SECRET = re.compile(
    r"\/(?:user|rc4|ntlm|aes256|aes128|des|password|pass|credential|domain|krbtgt)"
    r":([^\s\/]{3,})"
)

_SMB_USER_PASS = re.compile(
    r"(?:^|\s)-U\s+([^\s%]+)%([^\s]{3,})"
    r"(?=\s|$)"
)

_HOSTNAME_INTERNAL = re.compile(
    r"(?<![.\w])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\.(?:corp|internal|local|intra|priv|lan|htb|lab)"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"(?![.\w])",
    re.IGNORECASE,
)

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?P<key_type>(?:[A-Z]+ )?PRIVATE KEY)-----"
    r"[\s\S]*?"
    r"(?:-----END (?P=key_type)-----|\Z)"
)

_NTLM_HASH = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:[0-9a-fA-F]{32}(?![0-9a-fA-F])"
)

_SAM_DUMP = re.compile(
    r"^(?:[^\s:]+[\\\/])?[^\s:]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::$",
    re.MULTILINE,
)

_NTLMV2_HASH = re.compile(
    r"[^\s:]+::[^\s:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]{20,}"
)

_KERBEROS_KEY = re.compile(
    r"[^\s:]+:(?:aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5):[0-9a-fA-F]+"
)

_AD_DOMAIN_USER_BACKSLASH = re.compile(
    r"(?<![\w\\])"
    r"(?:"
    r"[A-Z][A-Z0-9._-]{0,14}"
    r"|[a-zA-Z0-9](?:[a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}"
    r")"
    r"\\[a-zA-Z0-9._-]+"
    r"(?::[^\s]{4,})?"
    r"(?![\w\\])"
)

# Kerberos SPN format: ServiceClass/hostname.domain[:port]
# Must be checked before ad_domain_user_slash (priority 24 vs 25).
# Requires an FQDN instance name (at least one dot) to avoid false positives
# on short abbreviations like CIFS/host (no dot) which fall through to ad_domain_user_slash.
# The lookbehind excludes '.' so a ServiceClass can never be the tail of a domain:
# without it, impacket targets like domain.local/user:password matched as
# "local/user" and the surviving password was left unredacted.
_SPN = re.compile(
    r"(?<![\w./])"
    r"[A-Za-z][A-Za-z0-9_-]{1,30}"  # ServiceClass (e.g. CIFS, MSSQLSvc)
    r"/[a-zA-Z0-9](?:[a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}"  # /host.domain (FQDN required)
    r"(?::[0-9]{1,5})?"  # optional :port
    r"(?![\w\/])"
)

# Forward-slash requires FQDN domain (with dots) OR uppercase domain of 4+ chars
# to avoid matching abbreviations like SMB/WMI, TGT/TGS, R/W, GNU/Linux.
# The hostname/username after / must start with lowercase to exclude protocol
# abbreviations like SSDP/UPnP and LDAP path components like domain.local/DC=...
_AD_DOMAIN_USER_SLASH = re.compile(
    # Excludes '.' for the same reason as _SPN: without it a match can begin
    # mid-domain, so https://portal.example.internal/login reads as the
    # domain/user pair "example.internal/login" and splits the URL in two.
    r"(?<![\w./])"
    r"(?:"
    r"[A-Z][A-Z0-9]{3,14}"  # CORP, INLANEFREIGHT (4+ uppercase)
    r"|[a-zA-Z0-9](?:[a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}"  # megacorp.local (FQDN)
    r")"
    r"\/[a-z][a-zA-Z0-9._-]*"  # /username (must start with lowercase)
    r"(?::[^\s@]{4,})?(?:@[^\s]+)?"  # optional :password@host
    r"(?![\w\/])"
)

_KERBEROS_HASH = re.compile(
    r"\$krb5(?:tgs|asrep)\$\d*\$"
    r"(?:[^\s:]+(?:\$[^\s]+)+"  # TGS: $-delimited segments
    r"|[^\s:]+:[^\s]+)"  # AS-REP: user@DOMAIN:hexhash
)

_DCC2_HASH = re.compile(r"(?:[^\s:]*\$)?DCC2\$\d+#[^#]+#[0-9a-fA-F]{32}")

_DPAPI_KEY = re.compile(
    r"(?:dpapi_machinekey|dpapi_userkey|NL\$KM)\s*:\s*(?:0x)?[0-9a-fA-F]{20,}"
)

_MACHINE_HEX_PASSWORD = re.compile(r"plain_password_hex:[0-9a-fA-F]{32,}")

_LINUX_HOME_PATH = re.compile(r"/(?:home/)([a-zA-Z0-9._-]+)")

_WINDOWS_USER_PATH = re.compile(
    r"(?i)C:\\\\?Users\\\\?"
    r"([a-zA-Z0-9._\s-]+?)(?=\\\\|\\|/|\s|$)"
)

_WINDOWS_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+(?:-\d+)?")

_UNC_PATH = re.compile(r"\\\\[a-zA-Z0-9._-]+(?:\\[a-zA-Z0-9._$-]+)+")

_PORT_SPEC = re.compile(
    r"^(?:[TUSP]:)?\d{1,5}(?:-\d{1,5})?"
    r"(?:,(?:[TUSP]:)?\d{1,5}(?:-\d{1,5})?)*$"
)
