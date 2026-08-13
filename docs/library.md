# Python library and engagement targets

[← README](../README.md)

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

## Per-engagement targets file

Load a target file directly from the CLI:

```bash
decon --targets acme-targets.txt notes.md
decon --targets acme-targets.txt --llm --ask "What should I investigate next?" notes.md
```

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

An unknown category or missing file is an error rather than a silent skip, and
parse errors name the file and line — quietly ignoring a typo'd
`hostnames:DC01` or `acme-targtes.txt` would leave values unredacted.

For full control, build the engine yourself:

```python
from decon import build_engine

engine = build_engine("acme-targets.txt", profile="client-share")
report = engine.redact_with_report(text)
print(report.unique_applied())      # (category, original, placeholder) tuples
```
