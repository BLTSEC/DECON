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
| JWT | `eyJhbGciOi...` | `JWT_REDACTED_01` | 10 |
| AWS Key | `AKIAIOSFODNN7EXAMPLE` | `API_KEY_01` | 10 |
| Secrets | `api_key="sk_live_..."` | `api_key="SECRET_01"` | 15 |
| SSN | `123-45-6789` | `SSN_REDACTED_01` | 20 |
| Credit Card | `4111111111111111` | `CC_REDACTED_01` | 20 |
| Email | `admin@corp.com` | `user_01@example.com` | 30 |
| Phone | `(555) 123-4567` | `(555) 555-0001` | 30 |
| CIDR | `10.0.0.0/24` | `10.0.0.1/24` | 39 |
| IPv4 | `192.168.1.50` | `10.0.0.1` | 40 |
| IPv6 | `fe80::1` | `fd00::1` | 40 |
| MAC | `aa:bb:cc:dd:ee:ff` | `00:DE:AD:00:00:01` | 40 |
| Hostname | `db01.corp.local` | `HOST_01.example.internal` | 45 |

Context-anchored secrets (priority 15) preserve the label and only redact the value — `password=Hunter2` becomes `password=SECRET_01`, so the LLM knows a password was there without seeing the actual credential.

Credit card detection uses Luhn validation to avoid false positives on random digit sequences.

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

Config supports global rule toggles, profiles for different audiences, custom literal values, and custom regex patterns:

```toml
default_profile = "standard"

[rules]
ipv4 = true
email = true
mac = false           # disable globally

[custom]
values = ["ACME Corp", "Project Nighthawk"]          # case-sensitive
values_nocase = ["jsmith", "proddb"]                  # case-insensitive

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
```

See `config.example.toml` for a complete reference.

## Cross-File Consistency

When sanitizing multiple files from the same engagement, export the mapping so placeholders stay consistent across all output:

```bash
decon --export-map map.json scan1.txt > clean1.txt
decon --import-map map.json scan2.txt > clean2.txt
decon --import-map map.json --export-map map.json scan3.txt > clean3.txt
```

The mapping file is JSON — `10.4.12.50` maps to `10.0.0.1` in every file.

## LLM Safety Net

DECON's regex engine handles the heavy lifting, but regex can't catch everything — a client name mentioned conversationally, an implied project reference, or a non-standard credential format. The optional LLM pass acts as a **reviewer, not a redactor**. It receives the already-redacted text and flags anything suspicious that the regex missed.

The LLM never sees the original data. It only reviews what would already be safe to share.

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

# Sanitize recon/ captures with cross-file consistency
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
  (default)             stdout

Options:
  -p, --profile NAME    Config profile (default: "standard")
  --enable RULES        Enable rules (comma-separated)
  --disable RULES       Disable rules (comma-separated)
  --llm                 Local LLM safety check via Ollama
  --export-map FILE     Save mapping to JSON
  --import-map FILE     Load prior mapping
  --dry-run             Show what would be redacted
  --list-rules          Show all rules and status
  --init-config         Create default config file
  -q, --quiet           Suppress stderr messages
  -v, --verbose         Show redaction stats
  --version             Show version
```

## License

MIT
