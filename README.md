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
  <a href="#how-it-works">How it works</a> ·
  <a href="#common-workflows">Workflows</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#documentation">Documentation</a>
</p>

DECON replaces sensitive values in pentest, red-team, and CTF output with
consistent typed placeholders before the data is shared with an LLM, ticket,
report, or teammate.

```text
10.42.0.15 cannot reach 10.42.0.1. Retrying 10.42.0.15...
```

becomes:

```text
[IPV4_REDACTED_0001] cannot reach [IPV4_REDACTED_0002]. Retrying [IPV4_REDACTED_0001]...
```

Repeated values keep the same identity, preserving topology and relationships
without exposing the originals.

> [!IMPORTANT]
> Redaction reduces exposure; it does not prove that text is safe. Review
> sensitive output before sharing it.

## Quick start

DECON requires Python 3.11+ and has no runtime dependencies.

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

# file -> clipboard
decon -c scan.txt

# inspect before sharing
decon --diff scan.txt

# CI check: 0 = clean, 1 = redactions found
decon --check report.md
```

## How it works

DECON applies deterministic rules in priority order, then assigns stable
placeholders within the run or imported mapping.

| Group | Examples |
|---|---|
| Network | IPv4, IPv6, CIDR, MAC, URLs, internal hosts, UNC paths |
| Credentials | Private keys, JWTs, AWS keys, passwords, tokens, API secrets |
| Active Directory | Domain users, SPNs, SIDs, SAM/NTDS, NTLM, Kerberos, DCC2, DPAPI |
| Identity and PII | Email, phone, SSN, credit-card numbers with Luhn validation |
| Local context | Home directories, Windows profiles, LDAP and BloodHound fields |

```text
10.42.0.15             -> [IPV4_REDACTED_0001]
admin@example.org      -> [EMAIL_REDACTED_0001]
dc01.corp.local        -> [HOST_REDACTED_0001]
password=correct-horse -> password=[SECRET_REDACTED_0001]
```

Use `decon --list-rules` for the authoritative rule list.

DECON intentionally preserves loopback, link-local and documentation IPv4
ranges, standard Nmap boilerplate URLs, Windows built-in identities, and Nmap
port lists. Explicitly allow other known-safe values when needed:

```bash
decon --allow "scanme.nmap.org,10.0.0.1" scan.txt
```

## Common workflows

### Inspect and share

```bash
decon --dry-run scan.txt                 # substitutions only
decon --diff scan.txt                    # unified diff
decon --verbose scan.txt                 # category counts
decon --tmux -c                          # active tmux pane -> clipboard
decon --clipboard-in -o clean.log        # clipboard -> file
decon --redact "Nighthawk,jsmith" notes.md
```

### Engagement identifiers

Generic rules cannot infer every client naming convention. Put known targets in
a portable file:

```text
# acme-targets.txt
domain:corp.acme.com
netbios:ACME
username:svc_backup
hostname:DC01
share:HR-Data
```

```bash
decon --targets acme-targets.txt scan.txt
```

### Batch processing

```bash
decon reports/**/*.txt --output-dir clean/
```

Files retain their relative paths and share one mapping across the batch.

### Reversible sessions

```bash
decon --session acme --session-ttl 24h -c scan.txt
# Paste the redacted content, then copy the response
decon --restore acme --consume -c
```

`--consume` deletes the session only after successful output. Sessions are
owner-only plaintext maps; use short TTLs and remove them when finished.

```bash
decon --list-sessions
decon --forget acme
decon --forget-all
```

### Local safety review

Ollama can review already-redacted text for identifiers missed by deterministic
rules:

```toml
[llm]
enabled = false
required = false
model = "qwen3.5:9b"
host = "http://localhost:11434"
```

```bash
decon --llm scan.txt
# Fail closed unless review succeeds and no findings remain
decon --strict-llm scan.txt
```

See [LLM review and direct questions](docs/llm.md) before enabling a provider.

## Configuration

Create an owner-only config:

```bash
decon --init-config
```

```toml
default_profile = "standard"

[rules]
phone = false
credit_card = false

[custom]
values = ["Project Nighthawk"]
values_nocase = ["jsmith"]
target_domains = ["corp.example"]
hostnames = ["DC01", "prod-web-01"]
usernames = ["svc_backup"]
netbios = ["ACME"]
shares = ["SYSVOL", "HR-Data"]
allowlist = ["scanme.nmap.org"]
```

Configuration lives at `~/.config/decon/decon.toml`. See the
[configuration reference](docs/configuration.md) for profiles, custom regexes,
and typed identifiers.

## Safety boundaries

- Maps, sessions, and audit entries contain original sensitive values.
- Persisted DECON state is owner-only (`0700` directories and `0600` files).
- Maps are replaced atomically but are not encrypted.
- LLM review is a secondary safety net, not a replacement for deterministic
  rules or human review.
- `--ask` sends only sanitized text, but provider use still creates an external
  trust boundary.
- Never commit, upload, or share reversible maps or audit logs.

## Documentation

| Guide | Contents |
|---|---|
| [Configuration](docs/configuration.md) | Rules, profiles, custom patterns, typed identifiers |
| [Mappings and sessions](docs/mappings-and-sessions.md) | Stable maps, restore, TTLs, audit history |
| [LLM workflows](docs/llm.md) | Ollama review, strict mode, provider questions |
| [Python library](docs/library.md) | `sanitize`, `desanitize`, `ask_safely`, target files |
| [Integrations](docs/integrations.md) | Pre-commit and NOCAP |

Run `decon --help` for the complete CLI reference.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
ruff check src tests
```

## License

MIT — see [LICENSE](LICENSE).
