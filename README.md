# DECON

<p align="center">
  <img src="assets/decon.jpg" alt="decon" width="100%">
</p>

Sanitize operational data before sharing. Consistent placeholders preserve analytical value.

Pentest, red team, and CTF logs need to be sanitized before pasting into Claude Code, ChatGPT, or any non-private LLM for analysis. DECON replaces sensitive values with consistent placeholders so the data remains useful — same IP always maps to the same placeholder, preserving topology and relationships so the LLM can still reason about the data.

## Install

```bash
pipx install .
```

Or with `uv`:

```bash
uv tool install .
```

Zero runtime dependencies. Python 3.11+ only (stdlib `tomllib`).

## Usage

```bash
# Pipe logs through decon
cat pentest.log | decon

# Redact files
decon scan_results.txt nmap_output.txt

# Copy sanitized output to clipboard
decon -c scan_results.txt

# Capture tmux scrollback
decon --tmux

# Read from clipboard, write to file
decon --clipboard-in -o clean.log

# Continuous tmux capture (push model — decon reads stdin natively)
tmux pipe-pane -o 'decon >> ~/loot/clean.log'

# See what would be redacted without modifying output
decon --dry-run scan_results.txt

# Show redaction stats on stderr
decon -v scan_results.txt

# Show unified diff of original vs redacted
decon --diff scan_results.txt

# Check if a file contains sensitive data (for CI/pre-commit)
decon --check scan_results.txt && echo "clean" || echo "needs redaction"
```

## How It Works

The core feature is **consistent placeholder mapping** — the same real value gets the same placeholder every time it appears, across the entire input. This means IP topology, user actions, and host groupings are preserved in the sanitized output.

```
$ echo "10.4.12.50 can't reach 10.4.12.1. Retrying 10.4.12.50..." | decon
10.0.0.1 can't reach 10.0.0.2. Retrying 10.0.0.1...
```

`10.4.12.50` maps to `10.0.0.1` everywhere. `10.4.12.1` maps to `10.0.0.2` everywhere. The relationship between the two hosts is preserved — the LLM can still tell which host couldn't reach which.

## Rules

Rules are applied in priority order to prevent partial matches (e.g., JWTs are matched before generic patterns can consume parts of them).

| Category | Example Input | Example Output | Priority |
|----------|--------------|----------------|----------|
| Private Key | `-----BEGIN RSA PRIVATE KEY-----...` | `PRIVATE_KEY_REDACTED_01` | 5 |
| Kerberoast/AS-REP | `$krb5tgs$23$*svc_sql$CORP...` | `KERBEROS_HASH_01` | 7 |
| SAM/NTDS Dump | `Admin:500:LMhash:NThash:::` | `SAM_DUMP_01` | 8 |
| NTLMv2 Hash | `user::DOMAIN:challenge:response` | `NTLMV2_HASH_01` | 9 |
| Kerberos Key | `CORP\DC01$:aes256-cts-...:hex` | `KERBEROS_KEY_01` | 9 |
| JWT | `eyJhbGciOi...` | `JWT_REDACTED_01` | 10 |
| AWS Key | `AKIAIOSFODNN7EXAMPLE` | `API_KEY_01` | 10 |
| DCC2 Cache | `$DCC2$10240#user#hash` | `DCC2_HASH_01` | 11 |
| DPAPI Key | `dpapi_machinekey:0xaabb...` | `DPAPI_KEY_01` | 11 |
| Machine Hex PW | `plain_password_hex:4d00...` | `MACHINE_HEX_PW_01` | 11 |
| NTLM Hash | `aad3b435...:31d6cfe0...` | `NTLM_HASH_01` | 12 |
| Secrets | `api_key="sk_live_..."` | `api_key="SECRET_01"` | 15 |
| CLI Flag Secrets | `-p 'Password1'` | `-p 'SECRET_01'` | 16 |
| Windows SID | `S-1-5-21-384293...` | `SID_REDACTED_01` | 18 |
| SSN | `123-45-6789` | `SSN_REDACTED_01` | 20 |
| Credit Card | `4111111111111111` | `CC_REDACTED_01` | 20 |
| AD Domain\User | `CORP\jsmith:P@ssw0rd` | `DOMAIN_USER_01` | 25 |
| AD Domain/User | `CORP/admin:pass@host` | `DOMAIN_USER_01` | 25 |
| URL | `https://target.com/api` | `URL_REDACTED_01` | 28 |
| Email | `admin@corp.com` | `user_01@example.com` | 30 |
| Phone | `(555) 123-4567` | `(555) 555-0001` | 30 |
| UNC Path | `\\dc01\SYSVOL` | `UNC_PATH_01` | 34 |
| CIDR | `10.0.0.0/16` | `10.0.0.1/16` | 39 |
| IPv4 | `192.168.1.50` | `10.0.0.1` | 40 |
| IPv6 | `fe80::1` | `fd00::1` | 40 |
| MAC | `aa:bb:cc:dd:ee:ff` | `00:DE:AD:00:00:01` | 40 |
| Hostname | `dc01.corp.local` | `HOST_01.example.internal` | 45 |

Loopback and special addresses (`127.0.0.1`, `0.0.0.0`, `255.255.255.255`, `169.254.x.x`) pass through unredacted — they're never target infrastructure.

URLs pointing to public code hosting and security reference sites (`github.com`, `gitlab.com`, `exploit-db.com`, `attack.mitre.org`, etc.) also pass through. Sensitive values within them (org names, repo names) are still caught by custom value rules.

Context-anchored secrets (priority 15) preserve the label and only redact the value — `password=Hunter2` becomes `password=SECRET_01`, so the LLM knows a password was there without seeing the actual credential. CLI flag secrets (priority 16) catch `-p`, `-P`, `-H`, `--password`, `--hash` flags common in hydra, netexec, evil-winrm commands.

SAM/NTDS dump lines are redacted atomically — the entire `user:RID:LMhash:NThash:::` line becomes a single placeholder, preventing username leaks from partial matching.

NTLMv2 hashes match Responder/Inveigh capture format (`user::DOMAIN:challenge:response`), which is distinct from the LM:NT pair format.

Kerberoast (`$krb5tgs$`) and AS-REP (`$krb5asrep$`) hashes, DCC2 cached credentials (`$DCC2$`), DPAPI keys, Kerberos encryption keys (AES256/AES128/DES), and machine account hex passwords are all matched from secretsdump/LSA output.

AD domain\user patterns match both backslash (Windows) and forward-slash (Impacket) notation. Uppercase short domains (`CORP\jsmith`) and FQDN domains (`megacorp.local\svc_bes`). When credentials follow the username, the password is captured too.

Internal hostnames match `.corp`, `.local`, `.internal`, `.intra`, `.priv`, `.lan`, `.htb`, and `.lab` TLDs — covering both real engagement and CTF/lab environments.

CIDR notation preserves the original subnet mask — `10.0.0.0/16` becomes `10.0.0.1/16`, not `/24`.

Credit card detection uses Luhn validation to avoid false positives on random digit sequences.

Windows SIDs matching `S-1-5-21-...` identify specific domain users and machines. Well-known SIDs (like `S-1-5-20`) are not matched.

Private key blocks match PEM format (`-----BEGIN * PRIVATE KEY-----` through `-----END * PRIVATE KEY-----`), covering RSA, EC, DSA, and OPENSSH key types.

```bash
decon --list-rules          # show all rules with status
decon --disable mac,phone   # skip specific rules
decon --enable ssn          # enable specific rules
```

## Config

```bash
decon --init-config   # creates default config
```

Config location:

| OS | Path |
|----|------|
| Linux | `~/.config/decon/decon.toml` |
| macOS | `~/.config/decon/decon.toml` |

Same path on both — `--init-config` creates the directory if it doesn't exist. Works the same whether installed via `pipx`, `uv tool`, or a local venv.

Config supports global rule toggles, profiles for different audiences, custom literal values, custom regex patterns, target domains, and allowlists:

```toml
default_profile = "standard"

[rules]
ipv4 = true
email = true
mac = false           # disable globally

[custom]
values = ["ACME Corp", "Project Nighthawk"]          # case-sensitive
values_nocase = ["jsmith", "proddb"]                  # case-insensitive
target_domains = ["contoso.com", "acmecorp.org"]      # auto-generates hostname rules
allowlist = ["scanme.nmap.org"]                        # pass through unredacted

[[custom.patterns]]
name = "internal_domains"
pattern = '[a-z0-9-]+\.corp\.acme\.com'
replacement = "HOST_{n:02d}.example.internal"

[profiles.client-share]
hostname_internal = true
custom_values_extra = ["Nighthawk"]

[profiles.internal]
ipv4 = false
mac = false
```

Resolution order: global `[rules]` -> profile overrides -> CLI `--enable`/`--disable`.

```bash
decon -p client-share report.txt    # use a specific profile
DECON_PROFILE=client-share decon report.txt   # or via env var
```

See `config.example.toml` for a complete reference.

### Target Domains

The built-in hostname rule only catches internal TLDs (`.corp`, `.internal`, `.local`, etc.). Real engagements have targets like `dc01.contoso.com` or `mail.acmecorp.org`. Add them to `target_domains` and DECON auto-generates hostname rules that match the bare domain and any subdomain:

```toml
[custom]
target_domains = ["contoso.com", "acmecorp.org"]
```

This matches `contoso.com`, `dc01.contoso.com`, `mail.internal.contoso.com`, etc. — all mapped to `HOST_XX.example.internal` placeholders.

### Allowlist

Values you want to pass through unredacted:

```toml
[custom]
allowlist = ["scanme.nmap.org", "10.0.0.1"]
```

Or via CLI:

```bash
decon --allow "scanme.nmap.org,10.0.0.1" pentest.log
```

Allowlisted values are exact matches on what the regex captures.

## Cross-File Consistency

When sanitizing multiple files from the same engagement, export the mapping so placeholders stay consistent across all output:

```bash
decon --export-map map.json scan1.txt > clean1.txt
decon --import-map map.json scan2.txt > clean2.txt
decon --import-map map.json --export-map map.json scan3.txt > clean3.txt
```

The mapping file is JSON — `10.4.12.50` maps to `10.0.0.1` in every file.

### Batch Mode

Process multiple files at once, writing each to an output directory with a shared mapping:

```bash
decon *.txt --output-dir clean/
# creates clean/scan1.redacted.txt, clean/scan2.redacted.txt, etc.

# With cross-file mapping export
decon *.txt --output-dir clean/ --export-map map.json
```

### Reverse Redaction

After LLM analysis, restore original values using the exported mapping:

```bash
# Redact and save mapping
decon --export-map map.json pentest.log > clean.log

# ... paste clean.log into LLM, get analysis back ...

# Restore original values in the LLM's response
echo "The issue is on 10.0.0.1 port 443" | decon --unredact map.json
# → "The issue is on 10.4.12.50 port 443"
```

## CI / Pre-Commit Check

Use `--check` to verify files are clean before sharing. Exits 0 if no redactions needed, 1 if sensitive data found:

```bash
decon --check report.txt && echo "safe to share" || echo "contains sensitive data"
```

Output includes a category breakdown on stderr:

```
Found 5 value(s) to redact:
  email: 1
  ipv4: 3
  secret: 1
```

## Diff Mode

See exactly what would change before committing to a redaction:

```bash
decon --diff pentest.log
```

```diff
--- original
+++ redacted
@@ -1,3 +1,3 @@
-Server 10.4.12.50 is up
+Server 10.0.0.1 is up
 Port 443/tcp open
-Contact admin@corp.com
+Contact user_01@example.com
```

## LLM Safety Net

DECON's regex engine handles the heavy lifting, but regex can't catch everything — a client name mentioned conversationally, a bare username, or a non-standard credential format. The optional LLM pass acts as a **reviewer, not a redactor**. It receives the already-redacted text and flags anything suspicious that the regex missed.

The LLM never sees the original data. It only reviews what would already be safe to share. Large inputs are automatically truncated to avoid context overflow.

The LLM prompt is deliberately aggressive ("flag everything"), and a deterministic post-filter strips known false positives: DECON's own placeholder patterns (even when the LLM appends port numbers or context), common software/vendor names from service banners (Apache, OpenSSH, Ubuntu, etc.), timestamps from tool output, well-known public wordlist filenames (rockyou.txt, SecLists files, etc.), and duplicate findings. This avoids relying on small models to make nuanced judgment calls.

### Setting Up Ollama

[Ollama](https://ollama.com) runs models locally — nothing leaves your machine.

```bash
brew install ollama
ollama serve

# In another terminal — pull a model with good instruction following
ollama pull qwen3.5:9b
```

We use `qwen3.5:9b` (~6.6GB) — fast, accurate, and the review task only needs classification, not creative generation. Larger models like `qwen3.5:27b` don't catch more and are significantly slower. Any model that can reliably return `CLEAN` or `FOUND:` lines will work.

Configure the model in your config:

```toml
[llm]
enabled = false
model = "qwen3.5:9b"
host = "http://localhost:11434"
```

### Using from Exegol / Docker

If you run DECON inside an [Exegol](https://exegol.readthedocs.io) container (or any Docker container), the `--llm` flag needs to reach Ollama on the host.

**Host side — bind Ollama to all interfaces:**

Add to your macOS `~/.zshrc` (or equivalent shell profile):

```bash
export OLLAMA_HOST="0.0.0.0"
```

Restart your terminal and relaunch Ollama from the terminal (the GUI app won't pick up shell exports).

**Lock down port 11434 with pf (recommended):**

Binding to `0.0.0.0` exposes Ollama on all interfaces. Use macOS's built-in packet filter to restrict access to localhost and Docker/OrbStack subnets:

```bash
# Create the anchor file
sudo tee /etc/pf.anchors/ollama <<'EOF'
# Allow localhost and OrbStack/Docker subnets to reach Ollama
pass in quick on lo0 proto tcp from any to any port 11434
pass in quick proto tcp from 192.168.215.0/24 to any port 11434
block in quick proto tcp from any to any port 11434
EOF

# Add the anchor to pf.conf (one-time setup)
echo 'anchor "ollama"' | sudo tee -a /etc/pf.conf
echo 'load anchor "ollama" from "/etc/pf.anchors/ollama"' | sudo tee -a /etc/pf.conf

# Load the rules
sudo pfctl -f /etc/pf.conf -e
```

This allows only your machine and containers to reach Ollama — external hosts on your LAN are blocked.

**Container side — point DECON at the host:**

Docker containers can reach the host via `host.docker.internal` (resolved via DNS on OrbStack, or `/etc/hosts` on Docker Desktop). Set this in your container's `~/.config/decon/decon.toml`:

```toml
[llm]
enabled = true
host = "http://host.docker.internal:11434"
```

Then `decon --llm` works from inside the container the same as on the host.

### Using the LLM Pass

```bash
# CLI flag
decon --llm pentest.log

# Environment variable
DECON_LLM=1 decon pentest.log

# Or set enabled = true in config for always-on
```

If Ollama isn't running, DECON warns on stderr and proceeds with regex-only output — it never blocks.

When the LLM flags something:

```
LLM review flagged potential issues:
FOUND: "Nighthawk" appears to be a project codename on line 14
FOUND: "jdoe" on line 23 may be a real username
---
```

Output still goes to stdout as normal. Add flagged values to your `[custom]` config and re-run if needed.

### Example

Regex handles the bulk — IPs, emails, MACs, keys all get consistent placeholders:

```
$ echo 'Server 10.4.12.50 cant reach 10.4.12.1
User admin@acmecorp.com connected from aa:bb:cc:dd:ee:ff
api_key="sk_live_abc123def456ghi789"
SSH to db01.corp.acme.com as jsmith' | decon -v

Server 10.0.0.1 cant reach 10.0.0.2
User user_01@example.com connected from 00:DE:AD:00:00:01
api_key="SECRET_01"
SSH to HOST_01.example.internal as jsmith

Redaction stats:
  email: 1
  hostname: 1
  ipv4: 2
  mac: 1
  secret: 1
```

Notice `jsmith` slipped through — it's a real username but there's no regex pattern for that. Add `--llm` and the local model catches it:

```
$ echo '...' | decon --llm 2>&1 >/dev/null

LLM review flagged potential issues:
FOUND: "jsmith" - username could identify a real person
---
```

Add the flagged value to your config and re-run:

```bash
# Add to ~/.config/decon/decon.toml under [custom]
# values = ["jsmith"]

decon --llm pentest.log > clean.log
```

## Using with NOCAP

DECON pairs naturally with [NOCAP](https://github.com/BLTSEC/nocap) (`cap`). NOCAP captures tool output with smart file routing during engagements — DECON sanitizes those captures before they leave your machine. The two tools compose through standard pipes and file paths.

### Sanitize the last capture

`cap last` returns the path to your most recent capture. Pipe it through `decon`:

```bash
# Sanitize last capture and copy to clipboard for pasting into an LLM
decon -c $(cap last)

# Same thing, with LLM review
decon -c --llm $(cap last)
```

### Sanitize and view with cap cat

`cap cat` renders a capture to stdout with ANSI/VT100 cleaned up. Pipe that into `decon`:

```bash
# Rendered + sanitized output
cap cat | decon

# Rendered + sanitized + copied to clipboard
cap cat | decon -c
```

### Sanitize an entire engagement directory

After an engagement, sanitize all captures in bulk with a consistent mapping across files:

```bash
cd /workspace/10.10.10.5

# Batch mode — consistent mapping across all files
decon recon/*.txt --output-dir clean/ --export-map map.json

# Or manually with cross-file consistency
for f in recon/*.txt; do
    decon --import-map map.json --export-map map.json "$f" > "clean/$(basename $f)"
done

# Same IPs/emails get the same placeholders across every file
```

### Capture, then sanitize, then ask an LLM

The common workflow — run a tool, capture with `cap`, sanitize with `decon`, paste into Claude Code or ChatGPT:

```bash
# Run the scan
cap nmap -sCV 10.10.10.5

# Sanitize the capture and copy to clipboard
decon -c $(cap last)

# Now paste into your LLM of choice — no real IPs, hostnames, or creds
```

### Retroactive capture + sanitize

Forgot to `cap` a command? Grab it from tmux scrollback, then sanitize:

```bash
# Grab last command output from tmux history
cap grab

# Sanitize what was just grabbed
decon -c $(cap last)
```

### Sanitize tmux scrollback directly

Both tools can pull from tmux. Use whichever fits the moment:

```bash
# NOCAP grabbed it already — sanitize the file
decon $(cap last)

# Skip the file, sanitize tmux scrollback directly
decon --tmux -c
```

### Live sanitized logging

Pipe a tmux pane through `decon` for a continuously sanitized log:

```bash
# Everything in the pane gets sanitized as it's written
tmux pipe-pane -o 'decon >> ~/loot/clean.log'
```

### Bulk sanitize with cap summary

Use `cap summary` to find specific captures, then sanitize them:

```bash
# Find all captures with passwords, sanitize them
cap summary passwords
# Grab the paths and sanitize
decon -v /workspace/10.10.10.5/loot/netexec_smb.txt

# Sanitize all captures matching a keyword
for f in $(cap summary creds 2>/dev/null | awk '{print $NF}'); do
    decon --import-map map.json --export-map map.json "$f" \
        > "clean/$(basename $f)"
done
```

### Suggested shell aliases

```bash
# Sanitize last capture to clipboard — the most common combo
alias dcap='decon -c $(cap last)'

# Same with LLM review
alias dcap-llm='decon -c --llm $(cap last)'

# Sanitize + verbose stats
alias dcapv='decon -cv $(cap last)'
```

## Full CLI Reference

```
decon [OPTIONS] [FILE...]

Input:
  FILE...               Files to redact (default: stdin)
  --tmux                Capture active tmux pane scrollback
  --clipboard-in        Read from system clipboard

Output:
  -c, --clipboard       Copy to clipboard
  -o, --output FILE     Write to file
  --output-dir DIR      Write redacted files to directory (one per input file)
  (default)             stdout

Rules:
  --enable RULES        Enable rules (comma-separated)
  --disable RULES       Disable rules (comma-separated)
  --allow VALUES        Pass values through unredacted (comma-separated)
  --list-rules          Show all rules and status

Modes:
  --dry-run             Show what would be redacted
  --check               Exit non-zero if redactions needed (for CI)
  --diff                Show unified diff of original vs redacted
  --unredact MAP_FILE   Reverse redaction using a mapping file

Mapping:
  --export-map FILE     Save mapping to JSON
  --import-map FILE     Load prior mapping for cross-file consistency

Options:
  -p, --profile NAME    Config profile (default: "standard")
  --llm                 Local LLM safety check via Ollama
  --init-config         Create default config file
  -q, --quiet           Suppress stderr messages
  -v, --verbose         Show redaction stats
  --version             Show version
```

Environment variables:
- `DECON_LLM=1` — enable LLM review (same as `--llm`)
- `DECON_PROFILE=name` — set config profile (same as `-p name`)

## License

MIT
