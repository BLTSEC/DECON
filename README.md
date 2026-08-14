# DECON

<p align="center">
  <img src="assets/decon.jpg" alt="DECON banner" width="100%">
</p>

<p align="center">
  <strong>Sanitize engagement data without destroying its analytical value.</strong>
</p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="Zero runtime dependencies" src="https://img.shields.io/badge/runtime_dependencies-0-2ea44f">
  <img alt="License MIT" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#operator-workflow">Operator workflow</a> ·
  <a href="#command-cheat-sheet">Commands</a> ·
  <a href="#trust-model">Trust model</a> ·
  <a href="#documentation">Documentation</a>
</p>

DECON is a local-first sanitization layer for pentest, red-team, and CTF output.
It replaces sensitive values with stable, typed placeholders before the data is
sent to an LLM, pasted into a ticket, added to a report, or shared with a
teammate.

```text
10.42.0.15 cannot reach 10.42.0.1. Retrying 10.42.0.15...
```

```text
[IPV4_REDACTED_0001] cannot reach [IPV4_REDACTED_0002]. Retrying [IPV4_REDACTED_0001]...
```

Repeated values retain the same placeholder, preserving topology and attack
paths without exposing the originals.

> [!IMPORTANT]
> DECON reduces disclosure risk; it cannot prove that arbitrary text is safe.
> Preview sensitive material before it crosses an engagement trust boundary.

## Quick start

DECON requires Python 3.11+ and has no runtime dependencies.

```bash
git clone https://github.com/BLTSEC/DECON.git
cd DECON
uv tool install .                       # or: pipx install .

decon --init-config
decon --doctor
```

```bash
decon --diff scan.txt                   # inspect
decon -o scan.redacted.txt scan.txt     # write file
decon -c scan.txt                       # copy to clipboard
```

## Operator workflow

### 1. Declare the engagement

Generic rules cannot infer client codenames or naming conventions. Keep a target
file outside the repository:

```text
# ~/engagements/acme.targets
domain:corp.acme.com
netbios:ACME
hostname:DC01
username:svc_backup
share:HR-Data
```

Add arbitrary names and labels under `[custom].values_nocase` in the config.

### 2. Inspect deterministic redaction

```bash
decon --profile pentest \
  --targets ~/engagements/acme.targets \
  --diff notes.md
```

The built-in `pentest` profile adds standalone NT-hash detection. It is opt-in
because a bare 32-character hexadecimal value may be an MD5 checksum.

### 3. Require local Ollama review

```toml
# ~/.config/decon/decon.toml
[llm]
model = "qwen3.5:9b"
host = "http://localhost:11434"
```

```bash
# Credentials and declared targets remain deterministic. Ollama classifies
# ambiguous PII and reviews the sanitized result for missed identifiers.
decon --strict-llm \
  --profile pentest \
  --targets ~/engagements/acme.targets \
  notes.md
```

`uncertain` means redact. Strict mode emits nothing if classification or final
review fails. Raw candidate context stays on loopback unless
`llm.allow_remote = true` is explicitly configured.

### 4. Confirm and ask

```bash
decon --strict-llm \
  --targets ~/engagements/acme.targets \
  --provider codex \
  --ask "Prioritize the attack paths and recommend the next three checks." \
  --confirm-ask notes.md
```

DECON sanitizes once, displays the exact outbound user prompt and its SHA-256
digest, then sends those same in-memory bytes only after confirmation. It
restores known placeholders in the answer. Use `--provider ollama` to keep both
review and analysis local.

Use `--ask-preview` for a no-authentication, no-transmission dry run. Local LLM
decisions are probabilistic, so its output is exact for that invocation but is
not a guarantee that a separate run will produce identical bytes.

| Provider | Boundary | Authentication |
|---|---|---|
| `ollama` | Local | None |
| `codex` | Remote via Codex CLI | ChatGPT subscription (`codex login`) |
| `claude-code` | Remote via Claude Code | Claude subscription (`claude auth login`) |
| `openai` | Remote API | `OPENAI_API_KEY` + `openai` SDK |
| `claude` | Remote API | `ANTHROPIC_API_KEY` + `anthropic` SDK |

CLI providers use an isolated, non-persistent run by default. See
[LLM workflows](docs/llm.md) before enabling a remote provider.

## Command cheat sheet

| Goal | Command |
|---|---|
| stdin → stdout | `cat scan.txt \| decon` |
| Show substitutions | `decon --dry-run scan.txt` |
| Review a unified diff | `decon --diff scan.txt` |
| Copy sanitized output | `decon -c scan.txt` |
| Sanitize active tmux pane | `decon --tmux -c` |
| Sanitize clipboard input | `decon --clipboard-in -o clean.txt` |
| Add literal values | `decon --redact "codename,jsmith" notes.md` |
| Preserve safe values | `decon --allow "scanme.nmap.org" scan.txt` |
| Process a directory tree | `decon reports/**/*.txt --output-dir clean/` |
| Confirm exact prompt, then send | `decon --ask "..." --confirm-ask notes.md` |
| Preview without sending | `decon --ask "..." --ask-preview notes.md` |
| CI/pre-commit check | `decon --check report.md` |
| Inspect rules | `decon --list-rules` |
| Validate setup | `decon --doctor` |

Batch files retain relative paths and share one mapping. Conservative PII and
leak decisions are applied across the batch before any output is written.

### Manual round trip

Use a short-lived session when manually sharing sanitized content:

```bash
decon --session acme --session-ttl 24h -c notes.md
# Paste the response back, then restore and delete the session
decon --restore acme --consume -c
```

Sessions and exported maps contain the original values. They are owner-only
plaintext files, not encrypted vaults.

## Configuration

`decon --init-config` creates `~/.config/decon/decon.toml` with owner-only
permissions. A practical engagement layer looks like this:

```toml
[custom]
target_domains = ["corp.example"]
values_nocase = ["Project Nighthawk"]
allowlist = ["scanme.nmap.org"]

[audit]
enabled = true
detail = "metadata"
```

CLI flags override configuration. Run `decon --doctor` after changing models,
providers, permissions, or authentication. Use `decon --list-rules` for the
authoritative detector list.

## Trust model

1. **Deterministic core** redacts credentials, infrastructure, configured
   targets, and unambiguous identifiers locally.
2. **Optional local model** classifies ambiguous PII and reviews the result. It
   never rewrites the document or controls placeholder mappings.
3. **Outbound gate** blocks remote `--ask` calls when an independent scanner
   still finds high-confidence credential material.
4. **Provider boundary** receives only the sanitized prompt, but remains an
   external trust boundary.

> [!CAUTION]
> `--force-ask` bypasses an outbound credential block. Use it only after
> inspecting the prepared prompt and confirming a false positive. It cannot
> bypass a failed `--strict-llm` review.

Audit records are metadata-only by default. Maps, sessions, and full-detail
audit logs may contain original values; never commit or share them.

## Documentation

| Guide | Contents |
|---|---|
| [Configuration](docs/configuration.md) | Rules, profiles, custom patterns, typed targets |
| [Mappings and sessions](docs/mappings-and-sessions.md) | Restore, TTLs, audit history |
| [LLM workflows](docs/llm.md) | Ollama, strict review, prompt preview, providers |
| [Python library](docs/library.md) | `sanitize`, `desanitize`, `ask_safely` |
| [Integrations](docs/integrations.md) | Pre-commit and NOCAP |

Run `decon --help` for the complete CLI reference.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest -q && ruff check src tests
```

## License

MIT — see [LICENSE](LICENSE).
