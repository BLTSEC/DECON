# LLM review and direct questions

[← README](../README.md)

Regex cannot reliably distinguish PII from timestamp-shaped telemetry, or find
every bare username, project name, and unusual credential. `--llm` therefore
runs a hybrid local pipeline:

1. Credentials, configured targets, and unambiguous identifiers redact
   deterministically.
2. Ollama classifies card, phone, and SSN-shaped candidates as `keep`, `redact`,
   or `uncertain`, using bounded surrounding context.
3. DECON applies typed placeholders itself and reviews the result for survivors.

The model returns candidate IDs through an enforced JSON schema. It never
rewrites the document or controls placeholder mappings, and `uncertain` always
means redact.

```bash
brew install ollama
ollama serve
ollama pull qwen3.5:9b

decon --llm scan.txt
```

PII decisions are applied automatically. Final-review findings are shown on
stderr in non-interactive runs; an interactive terminal can choose which ones
to redact. With `--llm --ask`, final-review findings are automatically redacted
before the provider boundary.

LLM review also works with:

- `--check` — LLM-only findings produce exit status 1
- `--dry-run` — findings appear in the preview
- `--diff` — reviews the proposed redacted text
- `--output-dir` — reviews every batch file and reports findings

Large inputs are reviewed in overlapping, line-aware chunks rather than being
truncated. Candidate requests are also bounded and batched. If optional Ollama
classification is unavailable or invalid, DECON warns and conservatively
redacts every ambiguous candidate before continuing.

Use `--strict-llm` when continuing without that safety check is unacceptable:

```bash
decon --strict-llm -o scan.redacted.txt scan.txt
decon --strict-llm --provider ollama \
  --ask "What should I investigate next?" scan.txt
```

Strict mode implies `--llm` and emits nothing unless classification and the
structured final review both succeed and every final finding is resolved.
Interactive runs may accept findings; `--ask` redacts them automatically before
provider transmission. Non-interactive output is blocked when findings remain.
Batch mode reviews every file before creating the output tree, so one failure
cannot leave a partially emitted batch. Enable the same policy by default with
`required = true` under `[llm]`.

> [!WARNING]
> Candidate context contains the exact PII-shaped value. DECON requires a
> loopback Ollama URL by default. A non-loopback reviewer is used only after the
> explicit `llm.allow_remote = true` trust-boundary opt-in. Strict mode prevents
> fail-open output; it cannot prove that a probabilistic model made every
> judgment correctly or resisted every instruction embedded in reviewed text.

For a container, configure the host endpoint explicitly:

```toml
[llm]
enabled = true
required = true
host = "http://host.docker.internal:11434"
allow_remote = true
```

## Asking an LLM directly

`--ask` closes the loop: DECON redacts both your question and input with one
shared mapping, sends only those sanitized strings, then restores the real
values in the answer. You write and read real infrastructure while the provider
reasons over stable placeholders.

```bash
# Keep analysis local
decon --provider ollama --ask "What are two attack paths here?" scan.txt

# Inspect without provider auth or transmission; exact for this invocation
decon --ask "What are two attack paths here?" --ask-preview scan.txt

# Review once, confirm the exact bytes, then send through Codex
decon --strict-llm --ask "What should I investigate next?" \
  --provider codex --confirm-ask notes.md

# The same workflow through a Claude subscription
decon --strict-llm --ask "Summarize the attack paths" \
  --provider claude-code --confirm-ask notes.md
```

Because placeholders are consistent, the model can still reason about topology
and repetition — it just does so over `[HOST_REDACTED_0001]` instead of a real
hostname, and its answer comes back with your hostnames restored.

`--confirm-ask` is the recommended interactive remote-provider workflow. DECON
sanitizes and runs local review once, displays the exact sanitized user prompt
with its SHA-256 digest, and asks for confirmation. A `yes` sends that same
in-memory string without rerunning Ollama. Confirmation is read from the
controlling terminal, so redirected document input remains safe.

`--ask-preview` remains useful for offline inspection, export, and automation.
It never authenticates to or contacts the selected provider. Because local LLM
classification and review are probabilistic, a preview is exact only for that
invocation; starting a second DECON process may produce a different prompt.

Choose a provider according to where it runs and how it authenticates:

| Provider | Backend | Authentication |
|---|---|---|
| `ollama` | Local Ollama server | None |
| `codex` | Installed Codex CLI | ChatGPT subscription (`codex login`) |
| `claude-code` | Installed Claude Code CLI | Claude subscription (`claude auth login`) |
| `openai` | OpenAI API | `OPENAI_API_KEY` |
| `claude` | Anthropic API | `ANTHROPIC_API_KEY` |

```bash
codex login
env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN claude auth login
```

The API providers need the optional extra; Ollama and the CLI providers use
only the Python standard library:

```bash
pipx inject decon anthropic openai     # or: pip install 'decon[ask]'
export ANTHROPIC_API_KEY=...           # or OPENAI_API_KEY
```

For `codex` and `claude-code`, DECON intentionally removes API-key and alternate
provider environment variables from the child process, then verifies that the
CLI is using first-party subscription authentication **before** sending the
sanitized prompt. It will not silently fall back to metered API billing. Omit
`--model` to use the CLI's selected default.

Set provider defaults, model overrides, size warnings, and CLI isolation under
`[ask]`; see [Configuration](configuration.md#direct-question-providers) for a
complete example. Command-line flags override those defaults.

CLI runs are isolated by default: DECON uses an empty owner-only temporary
directory, disables session persistence, ignores Codex user rules/config, and
starts Claude Code in safe mode with tools and Chrome integration disabled.
Codex also stays in its read-only sandbox. Temporary state is deleted when the
command ends.

`mode = "standard"` opts into the current directory and normal CLI
customization. This can expose project files, instructions, hooks, or tool
results that DECON did not sanitize. Use it only when that additional local
context is intentional and trusted.

DECON warns before sending an unusually large question and document, since it
cannot know a provider's context limit or your budget. OpenAI requests set
`store=false` to avoid retaining a reusable Responses API object; normal
provider abuse-monitoring and account-level retention policies may still apply.

Immediately before a remote provider call, DECON independently scans the exact
outbound user prompt for known credential forms. High-confidence survivors
block transmission; possible undeclared public domains and bare host labels
produce count-only warnings. `--force-ask` bypasses a credential block and is
intentionally noisy. It cannot bypass a failed `--strict-llm` run.

> [!NOTE]
> Redaction reduces exposure; it does not prove the text is safe to send. Review
> the in-process `--confirm-ask` prompt before remote transmission. Use
> `--ask-preview` when no transmission is allowed, but do not treat one run as a
> byte-for-byte approval of a later run. Codex and Claude Code still send the
> sanitized prompt to their remote services. Prefer `--provider ollama` when
> nothing may leave the machine.

If a provider's safety classifiers decline the request — security tooling can
trip them — DECON reports the refusal and its category rather than failing with
a traceback. The Claude provider also opts into server-side fallback, so a
declined request is retried on another model automatically.
