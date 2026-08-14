# Integrations

[← README](../README.md)

The strongest place to catch a leak is before it is ever committed. DECON ships
a hook definition, so guarding a notes vault is a few lines:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/BLTSEC/DECON
    rev: v0.9.0
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
