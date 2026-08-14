"""Read-only environment diagnostics for ``decon --doctor``."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from decon import config as config_module
from decon.ask import DEFAULT_MODELS, DEFAULT_PROVIDER
from decon.config import (
    ConfigError,
    apply_config_to_engine,
    get_llm_config,
    load_config,
)
from decon.engine import RedactionEngine
from decon.state import state_dir


def _permission_issue(path: Path, expected: int) -> str | None:
    try:
        if not path.exists():
            return None
        actual = stat.S_IMODE(path.stat().st_mode)
    except OSError as error:
        return f"could not inspect {path}: {error}"
    if actual & 0o077:
        return f"{path} permissions are {actual:04o}; expected {expected:04o}"
    return None


def _ollama_models(host: str) -> set[str]:
    request = urllib.request.Request(f"{host.rstrip('/')}/api/tags")
    with urllib.request.urlopen(request, timeout=3) as response:
        data = json.loads(response.read().decode())
    if not isinstance(data, dict) or not isinstance(data.get("models"), list):
        raise ValueError("invalid /api/tags response")
    return {
        item["name"]
        for item in data["models"]
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }


def _cli_auth(provider: str) -> tuple[bool, str]:
    binary = "codex" if provider == "codex" else "claude"
    if shutil.which(binary) is None:
        return False, f"{binary} is not installed"
    try:
        version_result = subprocess.run(
            [binary, "--version"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        version = (
            (version_result.stdout or version_result.stderr).strip().splitlines()[0]
        )
    except (OSError, subprocess.TimeoutExpired, IndexError):
        version = f"{binary} version unavailable"
    command = (
        ["codex", "login", "status"]
        if provider == "codex"
        else ["claude", "auth", "status"]
    )
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, f"authentication check failed: {error}"
    output = f"{result.stdout}\n{result.stderr}"
    if provider == "codex":
        authenticated = result.returncode == 0 and "Logged in using ChatGPT" in output
    else:
        try:
            status_data = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError):
            status_data = {}
        authenticated = (
            result.returncode == 0
            and isinstance(status_data, dict)
            and status_data.get("loggedIn") is True
            and status_data.get("apiProvider") == "firstParty"
            and status_data.get("authMethod") not in (None, "none", "api_key")
        )
    auth = "authenticated" if authenticated else "not authenticated"
    return authenticated, f"{version}; {auth}"


def run_doctor(*, quiet: bool = False) -> int:
    """Print diagnostics without creating state or prompting providers."""
    checks: list[tuple[str, str, str]] = []
    failed = False

    try:
        config = load_config()
        apply_config_to_engine(RedactionEngine(), config)
        checks.append(("PASS", "config", "configuration is valid"))
    except ConfigError as error:
        config = {}
        checks.append(("FAIL", "config", str(error)))
        failed = True

    config_path = config_module.DEFAULT_CONFIG_PATH
    issue = _permission_issue(config_path, 0o600)
    if issue:
        checks.append(("FAIL", "config permissions", issue))
        failed = True
    elif config_path.exists():
        checks.append(("PASS", "config permissions", "owner-only"))
    else:
        checks.append(("INFO", "config", "no config file; built-in defaults apply"))

    current_state = state_dir()
    issue = _permission_issue(current_state, 0o700)
    if issue:
        checks.append(("FAIL", "state permissions", issue))
        failed = True
    elif current_state.exists():
        checks.append(("PASS", "state permissions", "owner-only"))
    else:
        checks.append(("INFO", "state", "state directory has not been created"))

    audit_config = config.get("audit", {})
    if isinstance(audit_config, dict) and audit_config.get("path"):
        audit_path = Path(str(audit_config["path"])).expanduser()
        issue = _permission_issue(audit_path, 0o600)
        if issue:
            checks.append(("FAIL", "audit permissions", issue))
            failed = True
        elif audit_path.exists():
            checks.append(("PASS", "audit permissions", "owner-only"))

    llm = get_llm_config(config)
    llm_active = bool(llm.get("enabled") or llm.get("required"))
    host = llm.get("host", "http://localhost:11434")
    model = llm.get("model", "qwen3.5:9b")
    try:
        models = _ollama_models(host)
        if model in models:
            checks.append(("PASS", "Ollama", f"{model} is available"))
        else:
            level = "FAIL" if llm_active else "WARN"
            checks.append((level, "Ollama", f"configured model {model} is missing"))
            failed = failed or llm_active
    except (OSError, ValueError, urllib.error.URLError) as error:
        level = "FAIL" if llm_active else "INFO"
        checks.append((level, "Ollama", f"unavailable at {host}: {error}"))
        failed = failed or llm_active

    ask_config = (
        config.get("ask", {}) if isinstance(config.get("ask", {}), dict) else {}
    )
    provider = ask_config.get("provider", DEFAULT_PROVIDER)
    provider_is_explicit = "provider" in ask_config
    provider_ok = True
    provider_detail = ""
    if provider == "openai":
        provider_ok = importlib.util.find_spec("openai") is not None and bool(
            os.environ.get("OPENAI_API_KEY")
        )
        provider_detail = (
            "SDK and API key present" if provider_ok else "SDK or API key missing"
        )
    elif provider == "claude":
        provider_ok = importlib.util.find_spec("anthropic") is not None and bool(
            os.environ.get("ANTHROPIC_API_KEY")
        )
        provider_detail = (
            "SDK and API key present" if provider_ok else "SDK or API key missing"
        )
    elif provider in {"codex", "claude-code"}:
        provider_ok, provider_detail = _cli_auth(provider)
    else:
        ask_host = ask_config.get("host", "http://localhost:11434")
        ask_models = ask_config.get("models", {})
        ask_model = (
            (ask_models.get("ollama") if isinstance(ask_models, dict) else None)
            or ask_config.get("model")
            or DEFAULT_MODELS["ollama"]
        )
        try:
            models = _ollama_models(ask_host)
            provider_ok = ask_model in models
            provider_detail = (
                f"{ask_model} is available"
                if provider_ok
                else f"configured model {ask_model} is missing"
            )
        except (OSError, ValueError, urllib.error.URLError) as error:
            provider_ok = False
            provider_detail = f"unavailable at {ask_host}: {error}"

    if provider_ok:
        checks.append(("PASS", "ask provider", f"{provider}: {provider_detail}"))
    else:
        level = "FAIL" if provider_is_explicit else "INFO"
        checks.append((level, "ask provider", f"{provider}: {provider_detail}"))
        failed = failed or provider_is_explicit

    if not quiet:
        for level, label, detail in checks:
            print(f"{level:<4} {label}: {detail}")
    return 1 if failed else 0
