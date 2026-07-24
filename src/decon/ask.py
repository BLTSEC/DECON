"""Send redacted text to an LLM and restore real values in the reply.

This completes the proxy loop: the operator writes prompts about real
infrastructure and reads answers about real infrastructure, while the provider
only ever sees placeholders.

Only the Ollama provider works with the standard library. The Claude and OpenAI
providers use their official SDKs, installed as an optional extra so DECON's
core stays dependency-free:

    pipx inject decon anthropic      # or: pip install 'decon[ask]'
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

DEFAULT_PROVIDER = "claude"
DEFAULT_MAX_TOKENS = 16000

# Roughly 4 chars per token, so ~50k chars is ~12k tokens of input. Past this a
# run is worth a heads-up: it costs real money on a metered provider and may
# crowd the context window on a local one.
DEFAULT_WARN_CHARS = 50_000

DEFAULT_MODELS = {
    "claude": "claude-opus-5",
    "openai": "gpt-5",
    "ollama": "qwen3.5:9b",
}

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
            f"provider requires the {module!r} package. "
            f"Install it with: {extra_hint}"
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

    text = data.get("message", {}).get("content", "")
    if not text.strip():
        raise AskError("the model returned an empty response")
    return text


_PROVIDERS = {
    "claude": _ask_claude,
    "openai": _ask_openai,
    "ollama": _ask_ollama,
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
) -> str:
    """Send a question plus redacted material to a provider and return the reply.

    The caller is responsible for redacting `document` first and for restoring
    the reply afterwards — this function never sees the unredacted text.
    """
    if provider not in _PROVIDERS:
        known = ", ".join(sorted(_PROVIDERS))
        raise AskError(f"unknown provider {provider!r}. Choose one of: {known}")
    if not question.strip():
        raise AskError("the question must not be empty")

    return _PROVIDERS[provider](
        _build_prompt(question, document),
        model or DEFAULT_MODELS[provider],
        max_tokens,
        host=host,
    )
