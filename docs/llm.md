# LLM review and direct questions

[← README](../README.md)

Regex cannot reliably identify every bare username, project name, or unusual
credential. `--llm` sends the regex-redacted text to an Ollama-compatible
endpoint and asks it to report possible survivors.

```bash
brew install ollama
ollama serve
ollama pull qwen3.5:9b

decon --llm scan.txt
```

The LLM is normally a **reviewer, not an automatic redactor**. Findings are
shown on stderr in non-interactive runs. In an interactive terminal, you can
choose which findings to redact. The exception is `--llm --ask`: anything the
local reviewer flags is automatically redacted before the prompt can be sent to
the selected provider.

LLM review also works with:

- `--check` — LLM-only findings produce exit status 1
- `--dry-run` — findings appear in the preview
- `--diff` — reviews the proposed redacted text
- `--output-dir` — reviews every batch file and reports findings

Large inputs are reviewed in overlapping, line-aware chunks rather than being
truncated. If Ollama is unavailable, DECON warns and continues with the
deterministic rules.

Use `--strict-llm` when continuing without that safety check is unacceptable:

```bash
decon --strict-llm -o scan.redacted.txt scan.txt
decon --strict-llm --ask "What should I investigate next?" scan.txt
```

Strict mode implies `--llm` and emits nothing unless Ollama returns a valid
`CLEAN`/`FOUND:` response and every finding is redacted. Interactive runs may
accept all findings; `--ask` redacts them automatically before provider
transmission. Non-interactive output is blocked when findings remain. Batch
mode reviews every file before creating the output tree, so one failed review
cannot leave a partially emitted batch. Enable the same policy by default with
`required = true` under `[llm]`.

> [!WARNING]
> The review text may still contain the exact sensitive values the regex rules
> missed. The default endpoint is local. Point `llm.host` only at a system you
> trust, and secure Ollama before exposing it to a container or network. Strict
> mode prevents fail-open output; it cannot prove that a probabilistic reviewer
> noticed every leak or resisted instructions embedded in the reviewed text.

For a container, configure the host endpoint explicitly:

```toml
[llm]
enabled = true
required = true
host = "http://host.docker.internal:11434"
```

## Asking an LLM directly

`--ask` closes the loop: DECON redacts both your question and input with one
shared mapping, sends only those sanitized strings, then restores the real
values in the answer. You write and read real infrastructure while the provider
reasons over stable placeholders.

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

DECON warns before sending an unusually large question and document, since it
cannot know a provider's context limit or your budget. OpenAI requests set
`store=false` to avoid retaining a reusable Responses API object; normal
provider abuse-monitoring and account-level retention policies may still apply.

> [!NOTE]
> Redaction reduces exposure; it does not prove the text is safe to send. Review
> `decon --dry-run` output before pointing `--ask` at a third-party API for the
> first time on a new engagement. Prefer `--provider ollama` when nothing may
> leave the machine.

If a provider's safety classifiers decline the request — security tooling can
trip them — DECON reports the refusal and its category rather than failing with
a traceback. The Claude provider also opts into server-side fallback, so a
declined request is retried on another model automatically.
