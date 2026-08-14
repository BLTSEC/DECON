# Python library and engagement targets

[← README](../README.md)

The CLI is the primary interface, but the proxy is often something you want to
call from a script:

```python
from decon import sanitize, desanitize, ask_safely

clean, mapping = sanitize(raw_notes)
restored = desanitize(clean, mapping)

# Keep the complete analysis local with Ollama
answer, mapping = ask_safely(
    f"What are two attack paths in these notes?\n\n{raw_notes}",
    provider="ollama",
)

# Remote subscription call; the library does not ask for confirmation
answer, mapping = ask_safely(
    f"What should I investigate next?\n\n{raw_notes}",
    provider="codex",
)
```

`mapping` is `{placeholder: original}` — the direction you need to restore
text, and what `desanitize()` expects. Note this is the inverse of
`RedactionEngine.mapping`, which is keyed by the original value.

`ask_safely()` accepts `claude`, `openai`, `ollama`, `codex`, and
`claude-code`. The CLI-backed providers use `cli_mode="isolated"` and a
600-second timeout by default; override these with `cli_mode="standard"` and
`cli_timeout_seconds=...` when normal project context is intentionally needed.
They require subscription authentication and do not inherit API-key/provider
environment variables.

Before a remote call, `ask_safely()` independently blocks known credential
survivors. It then transmits immediately: the library API does not run local
LLM review or offer the CLI's exact-prompt confirmation. Use
`decon --strict-llm --confirm-ask` when an operator must approve the outbound
prompt. `force_ask=True` is an explicit bypass for a reviewed scanner false
positive, not a substitute for review.

## Per-engagement targets file

Load a target file directly from the CLI:

```bash
decon --targets ~/engagements/acme.targets notes.md
decon --targets ~/engagements/acme.targets --strict-llm \
  --provider codex --confirm-ask \
  --ask "What should I investigate next?" notes.md
```

Engagement identifiers can come from a plain-text file instead of the TOML
config — one `category:value` per line, where category is one of `domain`,
`netbios`, `username`, `hostname`, or `share`:

```text
# ~/engagements/acme.targets
domain:acme.com
netbios:ACME
username:svc_backup
hostname:DC01
share:SYSVOL
```

```python
clean, mapping = sanitize(text, "~/engagements/acme.targets")
```

Use this when the identifiers belong to the engagement rather than to you — a
file you can generate from a scope document, versus
`~/.config/decon/decon.toml`, which is per-user. The TOML config is applied
first, so a targets file adds to it.

> [!CAUTION]
> A targets file contains original client identifiers. Keep `*.targets` outside
> repositories unless version control is explicitly authorized, and share it
> only through an engagement-approved channel.

An unknown category or missing file is an error rather than a silent skip, and
parse errors name the file and line — quietly ignoring a typo'd
`hostnames:DC01` or `acme-targtes.txt` would leave values unredacted.

For full control, build the engine yourself:

```python
from decon import build_engine

engine = build_engine("~/engagements/acme.targets", profile="client-share")
report = engine.redact_with_report(text)
print(report.unique_applied())  # (category, original, placeholder) tuples
```
