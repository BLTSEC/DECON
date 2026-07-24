# DECON

<p align="center">
  <img src="assets/decon.jpg" alt="decon" width="100%">
</p>

<p align="center">
  <strong>Sanitize operational data without destroying its analytical value.</strong>
</p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="Zero dependencies" src="https://img.shields.io/badge/runtime_dependencies-0-2ea44f">
  <img alt="License MIT" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-it-redacts">Rules</a> ·
  <a href="#everyday-workflows">Workflows</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#optional-ollama-review">Ollama</a>
</p>

DECON replaces sensitive values in pentest, red-team, and CTF output with
consistent placeholders before the data is shared with an LLM, ticket, report,
or teammate.

```text
10.42.0.15 cannot reach 10.42.0.1. Retrying 10.42.0.15...
```

becomes:

```text
[IPV4_REDACTED_0001] cannot reach [IPV4_REDACTED_0002]. Retrying [IPV4_REDACTED_0001]...
```

The same value always receives the same placeholder, so relationships,
topology, and repetition remain visible.

> [!IMPORTANT]
> Redaction reduces exposure; it does not prove that text is safe. Review
> sensitive output before sharing it, especially when using custom rules or the
> optional LLM safety net.

## Quick start

Requires Python 3.11+ and has no runtime dependencies.

```bash
git clone https://github.com/BLTSEC/DECON.git
cd DECON

# Choose one
pipx install .
uv tool install .
```

```bash
# stdin -> stdout
cat pentest.log | decon

# files -> stdout
decon scan.txt nmap.txt

# file -> clipboard
decon -c scan.txt

# inspect before sharing
decon --diff scan.txt

# CI / pre-commit check: 0 = clean, 1 = redactions found
decon --check report.md
```

## Why DECON

| Capability | What it gives you |
|---|---|
| Consistent mapping | Repeated values keep the same identity after redaction |
| Typed placeholders | IPs, hosts, email addresses, secrets, and other values stay distinguishable |
| Operational awareness | Handles common Nmap, NetExec, Impacket, LDAP, Kerberos, SMB, and secretsdump formats |
| Reversible maps | Restore original values locally when a workflow requires it |
| Batch processing | Share one mapping across an entire engagement directory |
| Local LLM review | Ask Ollama to flag values the deterministic rules may have missed |
| LLM round trip | Ask a model about redacted data and get an answer with real values restored |
| Audit trail | Every substitution recorded to an owner-only JSONL log |
| Zero dependencies | Core runs on the Python standard library |

## What it redacts

DECON applies ordered rules so high-specificity formats are handled before
generic patterns.

| Group | Examples |
|---|---|
| Network | IPv4, IPv6, CIDR, MAC addresses, URLs, internal hostnames, target domains, UNC paths |
| Credentials | Private keys, JWTs, AWS keys, passwords, tokens, CLI credentials, API secrets |
| Active Directory | Domain users, SPNs, SIDs, SAM/NTDS rows, NTLM/NTLMv2, Kerberos, DCC2, DPAPI |
| Identity and PII | Email addresses, phone numbers, SSNs, credit-card numbers with Luhn validation |
| Local context | Linux home directories, Windows user profiles, LDAP attributes, BloodHound descriptions |

Representative output:

```text
10.42.0.15                  -> [IPV4_REDACTED_0001]
2001:db8::15                -> [IPV6_REDACTED_0001]
aa:bb:cc:dd:ee:ff           -> [MAC_REDACTED_0001]
admin@example.org           -> [EMAIL_REDACTED_0001]
dc01.corp.local             -> [HOST_REDACTED_0001]
password=correct-horse      -> password=[SECRET_REDACTED_0001]
```

Use the CLI for the authoritative rule list:

```bash
decon --list-rules
decon --disable mac,phone scan.txt
decon --enable ssn report.txt
```

### Intentional pass-throughs

DECON avoids several common false positives:

- Loopback, unspecified, link-local, and documentation IPv4 ranges
- Public tool and reference URLs such as GitHub and MITRE ATT&CK
- Standard Nmap boilerplate URLs
- Windows built-in identities and registry paths
- Nmap port lists following `-p`

Use an allowlist when a value must remain unchanged:

```bash
decon --allow "scanme.nmap.org,10.0.0.1" scan.txt
```

## Everyday workflows

```bash
# Preview the values and placeholders without emitting redacted output
decon --dry-run scan.txt

# Show a unified diff
decon --diff scan.txt

# Show category statistics on stderr
decon --verbose scan.txt

# Capture the active tmux pane
decon --tmux -c

# Clipboard input -> file output
decon --clipboard-in --output clean.log

# Add case-insensitive values for this run
decon --redact "Project Nighthawk,jsmith" notes.md
```

If an explicitly requested input source such as `--tmux` or `--clipboard-in`
cannot be read, DECON exits non-zero instead of silently falling back to stdin.

### Batch processing

```bash
decon reports/**/*.txt --output-dir clean/
```

Files retain their relative paths and share one in-memory mapping:

```text
reports/web/scan.txt  -> clean/web/scan.redacted.txt
reports/ad/scan.txt   -> clean/ad/scan.redacted.txt
```

## Configuration

Create `~/.config/decon/decon.toml` with owner-only permissions:

```bash
decon --init-config
```

A compact configuration example:

```toml
default_profile = "standard"

[rules]
phone = false
credit_card = false

[custom]
values = ["Project Nighthawk"]
values_nocase = ["jsmith", "proddb"]
target_domains = ["corp.example"]
allowlist = ["scanme.nmap.org"]

# Typed engagement identifiers — keep their type in the output
hostnames = ["DC01", "prod-web-01"]
usernames = ["svc_backup"]
netbios = ["ACME"]
shares = ["SYSVOL", "HR-Data"]

[[custom.patterns]]
name = "ticket_ids"
pattern = 'CLIENT-[0-9]{4}'
replacement = "[CUSTOM_REDACTED_{n:04d}]"

[profiles.client-share]
hostname_internal = true
custom_values_extra = ["Internal Codename"]

[llm]
enabled = false
model = "qwen3.5:9b"
host = "http://localhost:11434"
```

Precedence is predictable:

```text
[rules] -> selected profile -> --enable / --disable
```

Set every built-in rule at once with `all`, then override individually. Within a
layer `all` is applied first, so per-rule keys win:

```toml
[profiles.ctf]
all = false          # lab infrastructure is public — redact nothing built-in

[profiles.network-only]
all = false
ipv4 = true          # ...except addresses
ipv6 = true
```

Prefer this over listing every rule name to disable: a deny-list silently stops
covering rules added in later releases, while `all` states the intent once.

`all` applies to built-in rules only. Values you declare under `[custom]` are
explicit instructions and keep redacting regardless, so `all = false` never
stops protecting your own identifiers.

```bash
decon --profile client-share report.txt
DECON_PROFILE=client-share decon report.txt
```

Invalid tables, rule names, value types, regular expressions, and placeholder
templates fail with a concise configuration error. See
[`config.example.toml`](config.example.toml) for the complete example.

### Typed engagement identifiers

Regex catches common formats, but every engagement has its own naming
conventions — a host called `prod-web-01` slips past the generic hostname rules,
and a bare `DC01` or `SYSVOL` mentioned in prose has nothing to key on.

Declaring these under `[custom]` closes the gap **without losing type**. Unlike
`values` and `values_nocase`, which collapse everything into
`[CUSTOM_REDACTED_nnnn]`, each typed array keeps its own placeholder namespace:

| Key | Placeholder |
|---|---|
| `hostnames` | `[HOST_SHORT_REDACTED_nnnn]` |
| `usernames` | `DOMAIN_USER_nn` |
| `netbios` | `[DOMAIN_REDACTED_nnnn]` |
| `shares` | `[SHARE_REDACTED_nnnn]` |

All four match case-insensitively. A bare hostname reuses the placeholder
already assigned to its FQDN, so `DC01` and `DC01.corp.example.com` stay one
machine rather than becoming two.

> [!TIP]
> These match anywhere the bare token appears, so avoid declaring a value that
> is also an ordinary word in text you want to keep — listing `ACME` as
> `netbios` will also redact it inside a project codename like
> `Operation ACME`. Drop the entry, or narrow it with a `[[custom.patterns]]`
> rule instead.

## Consistent and reversible mappings

Export a map when placeholders must remain stable across separate commands:

```bash
decon --export-map engagement.decon-map.json scan-1.txt > clean-1.txt
decon --import-map engagement.decon-map.json scan-2.txt > clean-2.txt

# Update the same map with newly discovered values
decon \
  --import-map engagement.decon-map.json \
  --export-map engagement.decon-map.json \
  scan-3.txt > clean-3.txt
```

Restore placeholders after local analysis:

```bash
echo "Investigate [IPV4_REDACTED_0001]:443" \
  | decon --unredact engagement.decon-map.json
```

> [!CAUTION]
> Maps, saved sessions, and the audit log all contain the original sensitive
> values. DECON writes them atomically with mode `0600` inside an owner-only
> directory, and this repository ignores `map.json` and `*.decon-map.json`.
> Never commit, upload, or share any of them.

Case-insensitive and canonicalized values—such as hostname case variants,
equivalent IPv6 spellings, and alternate MAC formats—share a placeholder. A
map retains the first-seen original spelling for reverse redaction.

### Sessions

A session is a map DECON names and stores for you, so a paste-into-a-chat round
trip is two short commands instead of a map path you have to keep track of:

```bash
decon --session -c scan.txt     # redact -> clipboard, mapping saved as "last"
# paste into the assistant, copy its reply
decon --restore -c              # placeholders -> real values, back to clipboard
```

Name a session to keep concurrent engagements apart, and clean up when the
engagement ends:

```bash
decon --session acme -c scan.txt
decon --restore acme -c
decon --list-sessions
decon --forget acme          # delete one reversible map
decon --forget-all           # delete them all
```

Sessions live in `~/.local/state/decon/sessions/` (or `$XDG_STATE_HOME`). Each
one is a reversible map, so `--forget` them when you no longer need the round
trip.

If a restored placeholder has no mapping — a model reformatted it, or it came
from a different session — DECON says so rather than leaving it to look like
real output:

```text
Warning: 2 placeholder(s) had no mapping and were left as-is:
  [HOST_REDACTED_1], [IPV4_REDACTED_0099]
```

> [!TIP]
> `--session` and `--restore` take an *optional* name, so a bare
> `decon --session scan.txt` would read `scan.txt` as the session name. DECON
> detects that and tells you to write `decon --session -c scan.txt` or
> `decon --session=NAME scan.txt` instead.

### Audit log

Every substitution is appended to `~/.local/state/decon/audit.jsonl` as one JSON
record per run:

```json
{"ts":"2026-07-24T12:00:00+00:00","mode":"redact","sources":["scan.txt"],
 "substitutions":[{"category":"hostname","original":"dc01.corp.local",
                   "placeholder":"[HOST_REDACTED_0001]"}]}
```

Runs that redact nothing write nothing. If the log cannot be written, DECON
warns and still produces your sanitized output — auditing never costs you the
redaction. Turn it off per run with `--no-audit`, or permanently:

```toml
[audit]
enabled = false
# path = "~/engagement-audit.jsonl"
```

## Optional Ollama review

Regex cannot reliably identify every bare username, project name, or unusual
credential. `--llm` sends the regex-redacted text to an Ollama-compatible
endpoint and asks it to report possible survivors.

```bash
brew install ollama
ollama serve
ollama pull qwen3.5:9b

decon --llm scan.txt
```

The LLM is a **reviewer, not an automatic redactor**. Findings are shown on
stderr in non-interactive runs. In an interactive terminal, you can choose
which findings to redact.

LLM review also works with:

- `--check` — LLM-only findings produce exit status 1
- `--dry-run` — findings appear in the preview
- `--diff` — reviews the proposed redacted text
- `--output-dir` — reviews every batch file and reports findings

Large inputs are reviewed in overlapping, line-aware chunks rather than being
truncated. If Ollama is unavailable, DECON warns and continues with the
deterministic rules.

> [!WARNING]
> The review text may still contain the exact sensitive values the regex rules
> missed. The default endpoint is local. Point `llm.host` only at a system you
> trust, and secure Ollama before exposing it to a container or network.

For a container, configure the host endpoint explicitly:

```toml
[llm]
enabled = true
host = "http://host.docker.internal:11434"
```

## Asking an LLM directly

`--ask` closes the loop: DECON redacts your input, sends the sanitized text with
your question, then restores the real values in the answer. You write and read
real infrastructure; the provider only ever sees placeholders.

```bash
decon --ask "What are two attack paths here?" scan.txt
decon --ask "Summarize the AD findings" --provider ollama notes.md
```

Because placeholders are consistent, the model can still reason about topology
and repetition — it just does so over `[HOST_REDACTED_0001]` instead of a real
hostname, and its answer comes back with your hostnames restored.

Cloud providers need the optional extra; Ollama needs nothing beyond the
standard library:

```bash
pipx inject decon anthropic openai     # or: pip install 'decon[ask]'
export ANTHROPIC_API_KEY=...           # or OPENAI_API_KEY
```

```toml
[ask]
provider = "claude"          # claude | openai | ollama
host = "http://localhost:11434"
max_tokens = 16000
warn_chars = 50000           # warn above this input size; 0 disables

[ask.models]                 # keyed by provider, so --provider is always safe
claude = "claude-opus-5"
ollama = "qwen3.5:9b"
```

DECON warns before sending an unusually large document, since it cannot know a
provider's context limit or your budget.

> [!NOTE]
> Redaction reduces exposure; it does not prove the text is safe to send. Review
> `decon --dry-run` output before pointing `--ask` at a third-party API for the
> first time on a new engagement. Prefer `--provider ollama` when nothing may
> leave the machine.

If a provider's safety classifiers decline the request — security tooling can
trip them — DECON reports the refusal and its category rather than failing with
a traceback. The Claude provider also opts into server-side fallback, so a
declined request is retried on another model automatically.

## Using DECON as a library

The CLI is the primary interface, but the proxy is often something you want to
call from a script:

```python
from decon import sanitize, desanitize, ask_safely

clean, mapping = sanitize(raw_notes)
restored = desanitize(clean, mapping)

# Sanitize, ask a model, restore the answer — in one call
answer, mapping = ask_safely("What are two attack paths here?")
```

`mapping` is `{placeholder: original}` — the direction you need to restore
text, and what `desanitize()` expects. Note this is the inverse of
`RedactionEngine.mapping`, which is keyed by the original value.

### Per-engagement targets file

Engagement identifiers can come from a plain-text file instead of the TOML
config — one `category:value` per line, where category is one of `domain`,
`netbios`, `username`, `hostname`, or `share`:

```text
# acme-targets.txt
domain:acme.com
netbios:ACME
username:svc_backup
hostname:DC01
share:SYSVOL
```

```python
clean, mapping = sanitize(text, "acme-targets.txt")
```

Use this when the identifiers belong to the engagement rather than to you — a
file you can generate from a scope document or hand to a teammate, versus
`~/.config/decon/decon.toml`, which is per-user. The TOML config is applied
first, so a targets file adds to it.

An unknown category is an error rather than a silent skip, and the message
names the file and line — quietly ignoring a typo'd `hostnames:DC01` would
leave that value unredacted.

For full control, build the engine yourself:

```python
from decon import build_engine

engine = build_engine("acme-targets.txt", profile="client-share")
report = engine.redact_with_report(text)
print(report.unique_applied())      # (category, original, placeholder) tuples
```

## Pre-commit hook

The strongest place to catch a leak is before it is ever committed. DECON ships
a hook definition, so guarding a notes vault is a few lines:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/BLTSEC/DECON
    rev: v0.4.0
    hooks:
      - id: decon
```

```bash
pre-commit install
```

The hook runs `decon --check` over staged text files and fails the commit with a
per-category breakdown when anything would be redacted:

```text
Found 9 value(s) to redact:
  ad_domain_user: 2
  hostname: 1
  ipv4: 1
  secret: 2
  spn: 2
  windows_sid: 1
```

It defaults to `.md`, `.txt`, `.log`, `.json`, and `.csv`. Narrow or widen it in
your own config:

```yaml
      - id: decon
        files: ^notes/.*\.md$
        exclude: ^notes/templates/
```

`--check` reads and reports only — it writes no output and no audit log, so the
hook never persists the values it finds.

## NOCAP integration

DECON pairs with [NOCAP](https://github.com/BLTSEC/nocap) (`cap`) for a simple
capture -> sanitize -> share workflow.

```bash
# Sanitize the most recent capture to the clipboard
decon -c "$(cap last)"

# Include local LLM review
decon -c --llm "$(cap last)"

# Render a capture, sanitize it, and copy it
cap cat | decon -c

# Capture tmux history, then sanitize the result
cap grab
decon -c "$(cap last)"
```

Useful aliases:

```bash
alias dcap='decon -c "$(cap last)"'
alias dcap-llm='decon -c --llm "$(cap last)"'
```

## CLI at a glance

Run `decon --help` for the complete, current reference.

| Task | Command |
|---|---|
| Clipboard output | `-c`, `--clipboard` |
| File output | `-o FILE`, `--output FILE` |
| Batch output | `--output-dir DIR` |
| Tmux input | `--tmux` |
| Clipboard input | `--clipboard-in` |
| Preview | `--dry-run` |
| Unified diff | `--diff` |
| CI check | `--check` |
| Custom literals | `--redact VALUES` |
| Allowlist | `--allow VALUES` |
| Mapping | `--import-map FILE`, `--export-map FILE`, `--unredact FILE` |
| Sessions | `--session [NAME]`, `--restore [NAME]`, `--list-sessions`, `--forget NAME`, `--forget-all` |
| Rule control | `--enable RULES`, `--disable RULES`, `--list-rules` |
| Profile | `--profile NAME` |
| Local LLM review | `--llm` |
| Ask an LLM | `--ask PROMPT`, `--provider NAME`, `--model NAME` |
| Audit | `--no-audit` |

Environment variables:

| Variable | Purpose |
|---|---|
| `DECON_PROFILE=name` | Select a configuration profile |
| `DECON_LLM=1` | Enable Ollama review |
| `DECON_STATE_DIR=path` | Override the sessions and audit-log directory |

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

## License

[MIT](LICENSE)
