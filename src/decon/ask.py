"""Send redacted text to an LLM and restore real values in the reply.

This completes the proxy loop: the operator writes prompts about real
infrastructure and reads answers about real infrastructure, while the provider
receives only the engine-sanitized prompt.

Ollama, Codex CLI, and Claude Code work with the standard library. The Claude
and OpenAI API providers use their official SDKs, installed as an optional
extra so DECON's core stays dependency-free:

    pipx inject decon anthropic      # or: pip install 'decon[ask]'
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import urllib.error
import urllib.request
from contextlib import nullcontext
from pathlib import Path

DEFAULT_PROVIDER = "claude"
DEFAULT_MAX_TOKENS = 16000
DEFAULT_CLI_MODE = "isolated"
DEFAULT_CLI_TIMEOUT_SECONDS = 600
CLI_MODES = ("isolated", "standard")

# Roughly 4 chars per token, so ~50k chars is ~12k tokens of input. Past this a
# run is worth a heads-up: it costs real money on a metered provider and may
# crowd the context window on a local one.
DEFAULT_WARN_CHARS = 50_000

DEFAULT_MODELS = {
    "claude": "claude-opus-5",
    "openai": "gpt-5",
    "ollama": "qwen3.5:9b",
    # CLI providers deliberately inherit the model selected by the installed
    # CLI unless the operator passes --model or configures ask.models.
    "codex": None,
    "claude-code": None,
}
PROVIDER_NAMES = tuple(DEFAULT_MODELS)

SYSTEM_PROMPT = (
    "You are assisting a security professional on an authorized engagement. "
    "The material below has been sanitized: values like [IPV4_REDACTED_0001], "
    "[HOST_REDACTED_0001], DOMAIN_USER_01, and [SECRET_REDACTED_0001] are "
    "placeholders standing in for real infrastructure. Reason about them as "
    "stable identities and refer to them by their placeholder exactly as "
    "written, so the operator can map your answer back. Do not invent real "
    "hostnames, addresses, or credentials."
)


class AskError(RuntimeError):
    """Raised when a provider is unavailable, misconfigured, or declines."""


def _require(module: str, extra_hint: str):
    """Import an optional SDK, or explain how to install it."""
    try:
        return __import__(module)
    except ImportError as e:  # pragma: no cover - exercised via monkeypatch
        raise AskError(
            f"provider requires the {module!r} package. Install it with: {extra_hint}"
        ) from e


def _build_prompt(question: str, document: str) -> str:
    """Combine the operator's question with the redacted material."""
    if not document.strip():
        return question
    return f"{question}\n\n---\n{document}\n---"


def _ask_claude(prompt: str, model: str, max_tokens: int, **_: object) -> str:
    anthropic = _require("anthropic", "pipx inject decon anthropic")
    client = anthropic.Anthropic()

    try:
        # Streaming keeps a long answer from hitting the request timeout.
        # Thinking is on by default on Opus 5, and max_tokens covers thinking
        # plus the reply, so leave real headroom.
        with client.beta.messages.stream(
            model=model,
            max_tokens=max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
            # Security material can trip cyber-category safety classifiers.
            # Server-side fallback retries on another model instead of
            # failing the command outright.
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        ) as stream:
            response = stream.get_final_message()
    except anthropic.APIStatusError as e:
        raise AskError(f"Claude API error ({e.status_code}): {e.message}") from e
    except anthropic.APIConnectionError as e:
        raise AskError(f"could not reach the Claude API: {e}") from e

    # A refusal returns HTTP 200 with empty or partial content, so check
    # stop_reason before touching content.
    if response.stop_reason == "refusal":
        detail = getattr(response, "stop_details", None)
        category = getattr(detail, "category", None) or "unspecified"
        raise AskError(
            f"the model declined this request (category: {category}). "
            "The redacted material may still read as offensive tooling; "
            "try narrowing the question."
        )

    text = "".join(
        block.text for block in response.content if getattr(block, "type", "") == "text"
    )
    if not text.strip():
        raise AskError("the model returned an empty response")
    return text


def _ask_openai(prompt: str, model: str, max_tokens: int, **_: object) -> str:
    openai = _require("openai", "pipx inject decon openai")
    client = openai.OpenAI()
    try:
        response = client.responses.create(
            model=model,
            max_output_tokens=max_tokens,
            instructions=SYSTEM_PROMPT,
            input=prompt,
            # DECON is explicitly a data-minimization boundary. Do not retain a
            # reusable Responses API object after this one-shot request.
            store=False,
        )
    except openai.APIStatusError as e:
        raise AskError(f"OpenAI API error: {e}") from e
    except openai.APIConnectionError as e:
        raise AskError(f"could not reach the OpenAI API: {e}") from e

    text = getattr(response, "output_text", "") or ""
    if not text.strip():
        raise AskError("the model returned an empty response")
    return text


def _ask_ollama(
    prompt: str,
    model: str,
    max_tokens: int,
    host: str = "http://localhost:11434",
    **_: object,
) -> str:
    url = f"{host.rstrip('/')}/api/chat"
    payload = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "think": False,
            "options": {"num_predict": max_tokens, "temperature": 0},
        }
    ).encode()

    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            data = json.loads(response.read().decode())
    except urllib.error.URLError as e:
        raise AskError(f"could not reach Ollama at {host}: {e}") from e
    except (ValueError, json.JSONDecodeError) as e:
        raise AskError(f"unexpected response from Ollama: {e}") from e

    if not isinstance(data, dict):
        raise AskError("unexpected response from Ollama: expected a JSON object")
    message = data.get("message", {})
    if not isinstance(message, dict):
        raise AskError("unexpected response from Ollama: invalid message object")
    text = message.get("content", "")
    if not isinstance(text, str):
        raise AskError("unexpected response from Ollama: message content is not text")
    if not text.strip():
        raise AskError("the model returned an empty response")
    return text


_SUBSCRIPTION_ENV_REMOVALS = {
    "codex": (
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "OPENAI_BASE_URL",
    ),
    "claude-code": (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_BEDROCK_BASE_URL",
        "ANTHROPIC_VERTEX_BASE_URL",
        "ANTHROPIC_FOUNDRY_BASE_URL",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
        "CLAUDE_CODE_SKIP_VERTEX_AUTH",
        "CLAUDE_CODE_SKIP_FOUNDRY_AUTH",
    ),
}


def _subscription_environment(provider: str) -> dict[str, str]:
    """Return a child environment that cannot select metered API auth."""
    env = os.environ.copy()
    for name in _SUBSCRIPTION_ENV_REMOVALS[provider]:
        env.pop(name, None)
    return env


def _run_process(
    command: list[str],
    *,
    provider_label: str,
    env: dict[str, str],
    timeout: int,
    prompt: str | None = None,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a provider command without a shell and normalize failures."""
    try:
        return subprocess.run(
            command,
            input=prompt,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            env=env,
            cwd=cwd,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:
        binary = command[0]
        raise AskError(
            f"{provider_label} executable {binary!r} was not found on PATH"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise AskError(f"{provider_label} timed out after {timeout} seconds") from e
    except KeyboardInterrupt as e:  # pragma: no cover - requires a real signal
        raise AskError(f"{provider_label} was interrupted") from e
    except OSError as e:
        raise AskError(f"could not start {provider_label}: {e}") from e


def _failure_detail(result: subprocess.CompletedProcess[str]) -> str:
    """Return a bounded provider diagnostic suitable for a terminal error."""
    detail = (result.stderr or result.stdout or "").strip()
    if len(detail) > 1000:
        detail = f"...{detail[-1000:]}"
    return detail


def _require_codex_subscription(env: dict[str, str], timeout: int) -> None:
    """Fail before transmission unless Codex is signed in through ChatGPT."""
    result = _run_process(
        ["codex", "login", "status"],
        provider_label="Codex CLI authentication check",
        env=env,
        timeout=min(timeout, 30),
    )
    status = f"{result.stdout}\n{result.stderr}"
    if result.returncode != 0 or "Logged in using ChatGPT" not in status:
        raise AskError(
            "Codex CLI is not signed in with ChatGPT. Run `codex login` and "
            "choose ChatGPT subscription authentication."
        )


def _require_claude_code_subscription(env: dict[str, str], timeout: int) -> None:
    """Fail before transmission unless Claude Code uses first-party OAuth."""
    result = _run_process(
        ["claude", "auth", "status"],
        provider_label="Claude Code authentication check",
        env=env,
        timeout=min(timeout, 30),
    )
    try:
        status = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        status = {}
    authenticated = (
        result.returncode == 0
        and isinstance(status, dict)
        and status.get("loggedIn") is True
        and status.get("apiProvider") == "firstParty"
        and status.get("authMethod") not in (None, "none", "api_key")
    )
    if not authenticated:
        raise AskError(
            "Claude Code is not signed in with a Claude subscription. Unset "
            "ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN, run `claude auth login`, "
            "and choose your Claude subscription."
        )


def _provider_working_directory(cli_mode: str):
    """Use an empty private directory unless normal CLI context was requested."""
    if cli_mode == "isolated":
        return tempfile.TemporaryDirectory(prefix="decon-ask-")
    return nullcontext(None)


def _cli_answer(
    command: list[str],
    prompt: str,
    *,
    provider_label: str,
    env: dict[str, str],
    timeout: int,
    cwd: str | Path | None,
) -> str:
    result = _run_process(
        command,
        provider_label=provider_label,
        env=env,
        timeout=timeout,
        prompt=prompt,
        cwd=cwd,
    )
    if result.returncode != 0:
        detail = _failure_detail(result)
        suffix = f": {detail}" if detail else ""
        raise AskError(
            f"{provider_label} exited with status {result.returncode}{suffix}"
        )
    if not result.stdout.strip():
        raise AskError(f"{provider_label} returned an empty response")
    return result.stdout


def _ask_codex(
    prompt: str,
    model: str | None,
    _max_tokens: int,
    *,
    cli_mode: str = DEFAULT_CLI_MODE,
    cli_timeout_seconds: int = DEFAULT_CLI_TIMEOUT_SECONDS,
    **_: object,
) -> str:
    env = _subscription_environment("codex")
    _require_codex_subscription(env, cli_timeout_seconds)
    command = [
        "codex",
        "exec",
        "--ephemeral",
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--color",
        "never",
    ]
    if cli_mode == "isolated":
        command.extend(("--ignore-user-config", "--ignore-rules"))
    if model is not None:
        command.extend(("--model", model))
    command.append(SYSTEM_PROMPT)

    with _provider_working_directory(cli_mode) as cwd:
        return _cli_answer(
            command,
            prompt,
            provider_label="Codex CLI",
            env=env,
            timeout=cli_timeout_seconds,
            cwd=cwd,
        )


def _ask_claude_code(
    prompt: str,
    model: str | None,
    _max_tokens: int,
    *,
    cli_mode: str = DEFAULT_CLI_MODE,
    cli_timeout_seconds: int = DEFAULT_CLI_TIMEOUT_SECONDS,
    **_: object,
) -> str:
    env = _subscription_environment("claude-code")
    _require_claude_code_subscription(env, cli_timeout_seconds)
    command = [
        "claude",
        "-p",
        "--no-session-persistence",
        "--permission-mode",
        "dontAsk",
        "--output-format",
        "text",
        "--no-chrome",
        "--system-prompt",
        SYSTEM_PROMPT,
    ]
    if cli_mode == "isolated":
        command.extend(("--safe-mode", "--tools", ""))
    if model is not None:
        command.extend(("--model", model))

    with _provider_working_directory(cli_mode) as cwd:
        return _cli_answer(
            command,
            prompt,
            provider_label="Claude Code",
            env=env,
            timeout=cli_timeout_seconds,
            cwd=cwd,
        )


_PROVIDERS = {
    "claude": _ask_claude,
    "openai": _ask_openai,
    "ollama": _ask_ollama,
    "codex": _ask_codex,
    "claude-code": _ask_claude_code,
}


def size_warning(document: str, warn_chars: int = DEFAULT_WARN_CHARS) -> str | None:
    """Return a warning when the material is large enough to be worth flagging.

    DECON has no way to know a provider's context limit or the operator's
    budget, so this informs rather than blocks.
    """
    if warn_chars <= 0 or len(document) <= warn_chars:
        return None
    return (
        f"input is {len(document):,} characters (~{len(document) // 4:,} tokens). "
        "This may exceed the model's context window or cost more than expected."
    )


def ask(
    question: str,
    document: str,
    *,
    provider: str = DEFAULT_PROVIDER,
    model: str | None = None,
    host: str = "http://localhost:11434",
    max_tokens: int = DEFAULT_MAX_TOKENS,
    cli_mode: str = DEFAULT_CLI_MODE,
    cli_timeout_seconds: int = DEFAULT_CLI_TIMEOUT_SECONDS,
) -> str:
    """Send a question plus redacted material to a provider and return the reply.

    The caller is responsible for redacting `document` first and for restoring
    the reply afterwards — this function never sees the unredacted text.
    """
    if not isinstance(provider, str) or provider not in _PROVIDERS:
        known = ", ".join(sorted(_PROVIDERS))
        raise AskError(f"unknown provider {provider!r}. Choose one of: {known}")
    if not isinstance(question, str):
        raise AskError("the question must be a string")
    if not question.strip():
        raise AskError("the question must not be empty")
    if not isinstance(document, str):
        raise AskError("the document must be a string")
    if model is not None and (not isinstance(model, str) or not model.strip()):
        raise AskError("the model must be a non-empty string")
    if not isinstance(host, str) or not host.strip():
        raise AskError("the host must be a non-empty string")
    if (
        not isinstance(max_tokens, int)
        or isinstance(max_tokens, bool)
        or max_tokens <= 0
    ):
        raise AskError("max_tokens must be a positive integer")
    if not isinstance(cli_mode, str) or cli_mode not in CLI_MODES:
        known = ", ".join(CLI_MODES)
        raise AskError(f"cli_mode must be one of: {known}")
    if (
        not isinstance(cli_timeout_seconds, int)
        or isinstance(cli_timeout_seconds, bool)
        or cli_timeout_seconds <= 0
    ):
        raise AskError("cli_timeout_seconds must be a positive integer")

    return _PROVIDERS[provider](
        _build_prompt(question, document),
        model or DEFAULT_MODELS[provider],
        max_tokens,
        host=host,
        cli_mode=cli_mode,
        cli_timeout_seconds=cli_timeout_seconds,
    )
