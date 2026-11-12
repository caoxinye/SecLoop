# SPDX-License-Identifier: Apache-2.0
"""Vendor-neutral LLM client for SecLoop — **shared by the evaluation and the training path**.

The same abstraction serves all three LLM call sites of the project (INTERFACES §7):

1. the agent generating a defence strategy (``agent/main.py``),
2. the ``use_vllm`` generation step during SA-GRPO training,
3. the penalty / over-defence LLM judge inside
   ``training/src/open_r1/rewards.py`` (``sa_cascade_reward``).

TRAINING ENTRY POINT (import this, do not duplicate HTTP code)
-------------------------------------------------------------
.. code-block:: python

    from agent.llm.llm_interface import get_llm_client            # <- the factory
    from agent.llm.llm_interface import LLMConfigError, LLMEndpointError

    client = get_llm_client()                                     # reads agent/config.json
    text = client.chat([{"role": "user", "content": prompt}], temperature=0.0)

    # explicit endpoint (e.g. the vLLM server started by the training recipe):
    client = get_llm_client(base_url="http://127.0.0.1:8000/v1", model="my-served-model")

``agent`` is a package rooted at the SecLoop repository root, so ``training/`` must have
that root on ``sys.path`` (the same shim it already needs for
``agent.tools.security_tools``).  The only third-party dependency of this module is
``requests``; there is no vendor SDK, no cloud endpoint and no key anywhere in the tree.

PROMPT CONTRACT (INTERFACES §8, paper Eq.4 ``P = [C, T_A, E]``)
--------------------------------------------------------------
``build_prompt`` / ``build_messages`` produce the canonical three-section prompt in the
frozen order ``C -> T_A -> E``.  The training path imports the very same helper, so the
inference prompt and the training prompt are structurally identical *by construction*
(an inference prompt that drops ``E`` violates the contract).

CONFIGURATION (INTERFACES §7.1)
-------------------------------
``agent/config.json``::

    {"llm": {"base_url": "http://127.0.0.1:8000/v1",
             "model": "<served-model-name>",
             "api_key_env": "LLM_API_KEY",      # an env-var NAME, never a value
             "temperature": 0.0,
             "timeout_s": 120}}

``SECLOOP_AGENT_CONFIG`` may point at a different config file.

FAIL LOUDLY
-----------
An unconfigured endpoint raises :class:`LLMConfigError` at construction time and an
unreachable endpoint raises :class:`LLMEndpointError`.  This module never returns an
empty strategy, an empty string or ``0.0`` as a silent degradation.

Self-check (INTERFACES §7.2)::

    python -m agent.llm.llm_interface --check
    # -> LLM endpoint OK: http://127.0.0.1:8000/v1 model=<served-model-name>
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

#: Default config file: ``<repo>/agent/config.json``.
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.json"

#: Environment variable that overrides the config-file location.
CONFIG_PATH_ENV = "SECLOOP_AGENT_CONFIG"

#: Frozen prompt-section order of INTERFACES §8 (``P = [C, T_A, E]``).
PROMPT_SECTION_ORDER: tuple[str, str, str] = ("C", "T_A", "E")

_HTTP_URL_RE = re.compile(r"^https?://\S+$")

_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)

_CLIENT_KEYS = (
    "base_url",
    "model",
    "api_key_env",
    "temperature",
    "timeout_s",
    "max_tokens",
    "max_retries",
    "system_prompt",
)

_TOOL_REPORT_PROMPT = """You are a network security analyst on the blue team.
Write a concise threat report for the operator based on the IDS detection summary below.

The report must contain:
1. Threat type and severity
2. Affected assets (hosts, services, IP addresses)
3. Likely attacker and intent
4. Recommended defensive response

IDS detection summary:
{summary}
"""


# --------------------------------------------------------------------------------------
# Errors — every failure mode is explicit; nothing degrades silently.
# --------------------------------------------------------------------------------------
class LLMError(RuntimeError):
    """Base class for every LLM failure in SecLoop."""


class LLMConfigError(LLMError):
    """The endpoint is not configured (missing/blank ``base_url`` or ``model``)."""


class LLMEndpointError(LLMError):
    """The endpoint was configured but is unreachable / rejected the request."""


class LLMResponseError(LLMError):
    """The endpoint answered, but the answer could not be used."""


class StrategyParseError(LLMResponseError):
    """The model answer did not contain a usable JSON tool-call array."""


# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------
def resolve_config_path(config_path: str | os.PathLike[str] | None = None) -> Path:
    """Return the config file to use (argument > ``SECLOOP_AGENT_CONFIG`` > default)."""
    if config_path is not None:
        return Path(config_path)
    from_env = os.environ.get(CONFIG_PATH_ENV)
    if from_env and from_env.strip():
        return Path(from_env.strip())
    return DEFAULT_CONFIG_PATH


def load_config(config_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Load the whole ``agent/config.json`` document.

    Raises:
        LLMConfigError: file missing, unreadable, or not a JSON object.
    """
    path = resolve_config_path(config_path)
    if not path.is_file():
        raise LLMConfigError(
            f"agent config not found: {path} "
            f"(set {CONFIG_PATH_ENV} or pass --config; expected INTERFACES §7.1 layout)"
        )
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - environment dependent
        raise LLMConfigError(f"cannot read agent config {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMConfigError(f"agent config {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LLMConfigError(f"agent config {path} must be a JSON object, got {type(data).__name__}")
    return data


def load_llm_config(config_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Return the ``llm`` block of the config file (INTERFACES §7.1)."""
    config = load_config(config_path)
    llm = config.get("llm")
    if not isinstance(llm, Mapping):
        raise LLMConfigError(
            f"agent config {resolve_config_path(config_path)} has no 'llm' object; "
            "see INTERFACES §7.1"
        )
    return dict(llm)


def load_environment_config(config_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Return the ``environment`` block that renders the ``E`` section (§8)."""
    config = load_config(config_path)
    environment = config.get("environment", {})
    if not isinstance(environment, Mapping):
        raise LLMConfigError("'environment' in the agent config must be a JSON object")
    return dict(environment)


def resolve_api_key(api_key_env: str | None) -> str | None:
    """Resolve the API key **name** in ``api_key_env`` to its environment value.

    ``api_key_env`` always holds the *name* of an environment variable (INTERFACES §7.1);
    no key value is ever stored in the repository.  Returns ``None`` when the variable is
    unset or empty — local OpenAI-compatible servers usually need no key at all.
    """
    if not api_key_env:
        return None
    name = str(api_key_env).strip()
    if not name:
        return None
    value = os.environ.get(name)
    if value is None:
        logger.debug("environment variable %s is not set; sending no Authorization header", name)
        return None
    value = value.strip()
    return value or None


# --------------------------------------------------------------------------------------
# Prompt assembly — the frozen ``P = [C, T_A, E]`` contract (INTERFACES §8)
# --------------------------------------------------------------------------------------
def _require_non_empty(value: Any, what: str) -> str:
    text = "" if value is None else str(value).strip()
    if not text:
        raise ValueError(
            f"the {what} section of the prompt is empty; INTERFACES §8 requires P = [C, T_A, E]"
        )
    return text


def build_prompt(
    ids_summary: str,
    tool_descriptions: str,
    *,
    platform: str = "Linux",
    description: str = "",
    available_tools: Sequence[str] | None = None,
) -> str:
    """Render the canonical prompt ``P = [C, T_A, E]`` in the frozen order C -> T_A -> E.

    Args:
        ids_summary: ``C`` — the summariser ``S_r`` output (``ids/combine_ids_log.py``).
        tool_descriptions: ``T_A`` — ``tool_manager.get_tool_descriptions()``.
        platform: ``E`` — target platform (``Linux`` / ``Windows``).
        description: ``E`` — free-text environment description.
        available_tools: ``E`` — tool names usable inside that environment.

    Raises:
        ValueError: any of the three sections would be empty.
    """
    summary = _require_non_empty(ids_summary, "C (IDS detection summary)")
    tools_text = _require_non_empty(tool_descriptions, "T_A (available tool definitions)")
    if available_tools is None:
        raise ValueError(
            "the E section needs 'available_tools' (the tools usable inside the target "
            "environment); INTERFACES §8 requires P = [C, T_A, E]"
        )
    env_tools = ", ".join(str(name).strip() for name in available_tools if str(name).strip())
    if not env_tools:
        raise ValueError(
            "the E section needs at least one available tool; INTERFACES §8 requires P = [C, T_A, E]"
        )
    env_platform = str(platform).strip() or "Linux"

    return (
        "Select and invoke the appropriate security response tool based on the following "
        "IDS detection summary.\n"
        "\n"
        "IDS detection summary:\n"
        f"{summary}\n"
        "\n"
        "Available tool definitions:\n"
        f"{tools_text}\n"
        "\n"
        "Target environment:\n"
        f"- Platform: {env_platform}\n"
        f"- Description: {str(description).strip()}\n"
        f"- Available tools: {env_tools}\n"
        "\n"
        "Return a list of tools to call in JSON format, with a tool name and parameters "
        "for each tool call. For example:\n"
        "```json\n"
        "[\n"
        '  {"tool": "block_ip", "params": {"ip": "192.168.57.199"}}\n'
        "]\n"
        "```"
    )


def build_messages(
    ids_summary: str,
    tool_descriptions: str,
    *,
    system_prompt: str | None = None,
    platform: str = "Linux",
    description: str = "",
    available_tools: Sequence[str] | None = None,
) -> list[dict[str, str]]:
    """Return the chat messages for :func:`build_prompt` (same order as ``grpo.py``)."""
    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": str(system_prompt)})
    messages.append(
        {
            "role": "user",
            "content": build_prompt(
                ids_summary,
                tool_descriptions,
                platform=platform,
                description=description,
                available_tools=available_tools,
            ),
        }
    )
    return messages


# --------------------------------------------------------------------------------------
# Robust tool-call extraction
# --------------------------------------------------------------------------------------
def _scan_balanced(text: str, opener: str, closer: str) -> str | None:
    """Return the first balanced ``opener..closer`` span, ignoring brackets in strings."""
    start = text.find(opener)
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def _json_candidates(text: str) -> Iterable[str]:
    """Yield plausible JSON payloads from a model answer, most trustworthy first."""
    for match in _FENCE_RE.finditer(text):
        fenced = match.group(1).strip()
        if fenced:
            yield fenced
    stripped = text.strip()
    if stripped:
        yield stripped
    for opener, closer in (("[", "]"), ("{", "}")):
        span = _scan_balanced(text, opener, closer)
        if span:
            yield span


def _coerce_params(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise StrategyParseError(f"tool 'params' is not valid JSON: {exc}") from exc
        if not isinstance(parsed, Mapping):
            raise StrategyParseError(f"tool 'params' must be a JSON object, got {type(parsed).__name__}")
        return dict(parsed)
    raise StrategyParseError(f"tool 'params' must be an object or JSON string, got {type(value).__name__}")


def _normalise_call(item: Any, valid_tools: set[str] | None) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise StrategyParseError(f"each tool call must be a JSON object, got {type(item).__name__}")

    function = item.get("function")
    if isinstance(function, Mapping):  # OpenAI function-call shape
        source: Mapping[str, Any] = function
        name = source.get("name")
        params = source.get("arguments", {})
    else:
        name = item.get("tool") or item.get("name") or item.get("tool_name")
        params = item.get("params", item.get("parameters", item.get("arguments", {})))

    if not isinstance(name, str) or not name.strip():
        raise StrategyParseError(f"tool call without a tool name: {item!r}")
    name = name.strip()
    if valid_tools is not None and name not in valid_tools:
        raise StrategyParseError(
            f"model requested unknown tool {name!r}; known tools: {sorted(valid_tools)}"
        )
    return {"tool": name, "params": _coerce_params(params)}


def extract_tool_calls(
    text: str,
    valid_tools: Iterable[str] | None = None,
    *,
    allow_empty: bool = False,
) -> list[dict[str, Any]]:
    """Extract a JSON tool-call strategy from a raw model answer.

    Tolerates markdown fences, surrounding prose, ``{"tool_calls": [...]}`` wrappers,
    OpenAI-style ``{"function": {"name": ..., "arguments": ...}}`` entries and stringified
    ``params``.  The result is always ``[{"tool": "<name>", "params": {...}}, ...]``.

    Raises:
        StrategyParseError: nothing parseable was found, a tool name is illegal, or the
            strategy is empty (unless ``allow_empty=True``).  An empty strategy is never
            returned silently.
    """
    if not isinstance(text, str) or not text.strip():
        raise StrategyParseError("the model returned an empty answer; no tool-call strategy")

    allowed = set(valid_tools) if valid_tools is not None else None
    payload: Any = None
    parse_errors: list[str] = []
    for candidate in _json_candidates(text):
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError as exc:
            parse_errors.append(str(exc))
            continue
        break
    else:
        detail = f" (last error: {parse_errors[-1]})" if parse_errors else ""
        raise StrategyParseError(
            "no JSON tool-call strategy found in the model answer"
            f"{detail}; raw answer: {text.strip()[:400]!r}"
        )

    if isinstance(payload, Mapping):
        for key in ("tool_calls", "strategy", "calls", "tools"):
            nested = payload.get(key)
            if isinstance(nested, list):
                payload = nested
                break

    if isinstance(payload, Mapping):
        items: list[Any] = [payload]
    elif isinstance(payload, list):
        items = payload
    else:
        raise StrategyParseError(
            f"the tool-call strategy must be a JSON array, got {type(payload).__name__}"
        )

    strategy = [_normalise_call(item, allowed) for item in items]
    if not strategy and not allow_empty:
        raise StrategyParseError("the model returned an empty strategy ([]); refusing to continue")
    return strategy


# --------------------------------------------------------------------------------------
# The client
# --------------------------------------------------------------------------------------
class LLMClient:
    """Minimal client for any OpenAI-compatible *serving* endpoint.

    Works against the protocol implemented locally by vLLM, SGLang, Ollama and TGI —
    addressed purely by ``base_url``, so no vendor name or cloud endpoint appears here.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        api_key_env: str | None = None,
        temperature: float = 0.0,
        timeout_s: float = 120.0,
        max_tokens: int = 1024,
        max_retries: int = 2,
        system_prompt: str | None = None,
        environment: Mapping[str, Any] | None = None,
        session: requests.Session | None = None,
    ) -> None:
        resolved_base = str(base_url or "").strip().rstrip("/")
        resolved_model = str(model or "").strip()
        if not resolved_base:
            raise LLMConfigError(
                "LLM endpoint is not configured: 'llm.base_url' is empty. Set it in "
                "agent/config.json (INTERFACES §7.1); the agent never degrades silently."
            )
        if not _HTTP_URL_RE.match(resolved_base):
            raise LLMConfigError(f"'llm.base_url' must be an http(s) URL, got {resolved_base!r}")
        if not resolved_model:
            raise LLMConfigError(
                "LLM endpoint is not configured: 'llm.model' is empty. Set the served model "
                "name in agent/config.json (INTERFACES §7.1)."
            )

        self.base_url = resolved_base
        self.model = resolved_model
        self.api_key_env = api_key_env or None
        self.temperature = float(temperature)
        self.timeout_s = float(timeout_s)
        self.max_tokens = int(max_tokens)
        self.max_retries = max(0, int(max_retries))
        self.system_prompt = system_prompt
        self.environment = dict(environment or {})
        self._session = session or requests.Session()

    # -- construction ------------------------------------------------------------------
    @classmethod
    def from_config(
        cls,
        config: Mapping[str, Any] | None = None,
        *,
        config_path: str | os.PathLike[str] | None = None,
        **overrides: Any,
    ) -> "LLMClient":
        """Build a client from ``agent/config.json`` (or an already-loaded config dict).

        ``config`` may be the whole document or just its ``llm`` block.  Keyword overrides
        (``base_url``, ``model``, ``api_key_env``, ``temperature``, ``timeout_s``,
        ``max_tokens``, ``max_retries``, ``system_prompt``) win over the file.
        """
        if config is None:
            document = load_config(config_path)
        elif isinstance(config, Mapping):
            document = config
        else:
            raise LLMConfigError(f"config must be a mapping, got {type(config).__name__}")

        if "llm" in document:
            llm_block: Any = document.get("llm")
            environment: Any = document.get("environment")
        else:  # the caller passed the inner block directly
            llm_block = document
            environment = None
        if not isinstance(llm_block, Mapping):
            raise LLMConfigError("the 'llm' block of the agent config must be a JSON object")
        if environment is not None and not isinstance(environment, Mapping):
            raise LLMConfigError("the 'environment' block of the agent config must be a JSON object")

        unknown = set(overrides) - set(_CLIENT_KEYS)
        if unknown:
            raise LLMConfigError(f"unknown LLM client override(s): {sorted(unknown)}")

        params: dict[str, Any] = {key: llm_block[key] for key in _CLIENT_KEYS if key in llm_block}
        # ``agent.system_prompt`` is where the shipped config documents the system
        # prompt (``agent/README.md``: "the non-``llm`` blocks are agent-local"), and it
        # is read as a fallback: the ``llm`` block wins if it carries one, and an
        # explicit kwarg still wins over both.
        agent_block = document.get("agent")
        if "system_prompt" not in params and isinstance(agent_block, Mapping):
            configured_prompt = agent_block.get("system_prompt")
            if configured_prompt is not None:
                params["system_prompt"] = configured_prompt
        params.update(overrides)
        return cls(environment=environment, **params)

    # -- introspection -----------------------------------------------------------------
    def describe(self) -> str:
        """One-line description of the configured endpoint (contains no secret)."""
        key_state = "set" if resolve_api_key(self.api_key_env) else "unset"
        return (
            f"base_url={self.base_url} model={self.model} "
            f"temperature={self.temperature} timeout_s={self.timeout_s} "
            f"api_key_env={self.api_key_env or '-'} ({key_state}) "
            f"system_prompt={'set' if self.system_prompt else '-'}"
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"LLMClient(base_url={self.base_url!r}, model={self.model!r})"

    # -- transport ---------------------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        key = resolve_api_key(self.api_key_env)
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def _post_chat(self, payload: Mapping[str, Any], *, timeout_s: float | None = None) -> dict[str, Any]:
        """POST ``/chat/completions`` and return the decoded body, raising on any failure."""
        url = f"{self.base_url}/chat/completions"
        timeout = float(timeout_s if timeout_s is not None else self.timeout_s)
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            if attempt:
                time.sleep(min(0.5 * attempt, 2.0))
            try:
                response = self._session.post(
                    url, headers=self._headers(), json=dict(payload), timeout=timeout
                )
            except requests.Timeout as exc:
                last_error = exc
                logger.warning("LLM request to %s timed out after %.1fs (attempt %d)", url, timeout, attempt + 1)
                continue
            except requests.RequestException as exc:
                last_error = exc
                logger.warning("LLM request to %s failed: %s (attempt %d)", url, exc, attempt + 1)
                continue

            if response.status_code != 200:
                body = (response.text or "").strip()[:300]
                raise LLMEndpointError(
                    f"LLM endpoint {url} returned HTTP {response.status_code}: {body}"
                )
            try:
                data = response.json()
            except ValueError as exc:
                raise LLMResponseError(
                    f"LLM endpoint {url} returned a non-JSON body: {(response.text or '')[:200]!r}"
                ) from exc
            if not isinstance(data, dict):
                raise LLMResponseError(
                    f"LLM endpoint {url} returned {type(data).__name__}, expected a JSON object"
                )
            return data

        raise LLMEndpointError(
            f"LLM endpoint unreachable at {url} after {self.max_retries + 1} attempt(s): {last_error}"
        )

    def chat(
        self,
        messages: Sequence[Mapping[str, Any]] | str,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        timeout_s: float | None = None,
    ) -> str:
        """Run one chat completion and return the assistant text.

        Args:
            messages: a chat-message list, or a plain string treated as one user message.
            temperature: overrides the configured temperature.
            max_tokens: overrides the configured ``max_tokens``.
            timeout_s: overrides the configured timeout.

        Raises:
            LLMConfigError: the client was built without a usable endpoint.
            LLMEndpointError: connection refused / timeout / non-200 status.
            LLMResponseError: the answer carried no usable text.
        """
        if isinstance(messages, str):
            normalised: list[dict[str, Any]] = [{"role": "user", "content": messages}]
        elif isinstance(messages, Sequence):
            normalised = []
            for index, message in enumerate(messages):
                if not isinstance(message, Mapping):
                    raise LLMConfigError(f"message #{index} must be a mapping, got {type(message).__name__}")
                role = str(message.get("role") or "user")
                content = message.get("content")
                if content is None:
                    raise LLMConfigError(f"message #{index} has no 'content'")
                normalised.append({"role": role, "content": content})
        else:
            raise LLMConfigError(f"messages must be a list or a string, got {type(messages).__name__}")

        if not normalised:
            raise LLMConfigError("cannot send an empty message list")
        if self.system_prompt and not any(m["role"] == "system" for m in normalised):
            normalised.insert(0, {"role": "system", "content": self.system_prompt})

        payload = {
            "model": self.model,
            "messages": normalised,
            "temperature": self.temperature if temperature is None else float(temperature),
            "max_tokens": self.max_tokens if max_tokens is None else int(max_tokens),
            "stream": False,
        }
        data = self._post_chat(payload, timeout_s=timeout_s)

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMResponseError(f"LLM answer has no 'choices': {str(data)[:300]}")
        first = choices[0]
        message = first.get("message") if isinstance(first, Mapping) else None
        content: Any = message.get("content") if isinstance(message, Mapping) else None
        if content is None and isinstance(first, Mapping):
            content = first.get("text")
        if not isinstance(content, str) or not content.strip():
            raise LLMResponseError(f"LLM answer carries no text content: {str(first)[:300]}")
        return content

    def complete(self, prompt: str, *, system: str | None = None, **kwargs: Any) -> str:
        """Convenience wrapper: one plain user prompt -> assistant text."""
        messages: list[dict[str, Any]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self.chat(messages, **kwargs)

    # -- self-check (INTERFACES §7.2) ---------------------------------------------------
    def check(self) -> str:
        """Verify connectivity and return ``LLM endpoint OK: <base_url> model=<model>``.

        Tries ``GET /models`` first (cheap) and falls back to a one-token chat completion
        for servers that do not implement the listing endpoint.

        A self-check that cannot fail is not a self-check.  When the endpoint lists its
        models and the configured one is **not** among them, an unlisted model is
        **confirmed against the endpoint**: the one-token chat has to actually succeed.  If
        it does, the endpoint is usable and the OK line says the model was not listed (some
        gateways accept any name); if it does not, the check fails and names what the
        endpoint does serve.

        Raises:
            LLMEndpointError: the endpoint is configured but not usable.
        """
        ok_line = f"LLM endpoint OK: {self.base_url} model={self.model}"
        probe_timeout = min(self.timeout_s, 10.0)
        problems: list[str] = []

        try:
            response = self._session.get(
                f"{self.base_url}/models", headers=self._headers(), timeout=probe_timeout
            )
            if response.status_code == 200:
                served: list[str] = []
                try:
                    payload = response.json()
                except ValueError:
                    payload = {}
                data = payload.get("data") if isinstance(payload, Mapping) else None
                if isinstance(data, list):
                    served = [
                        str(entry.get("id"))
                        for entry in data
                        if isinstance(entry, Mapping) and entry.get("id") is not None
                    ]
                if served:
                    if self.model in served:
                        return ok_line
                    logger.warning(
                        "model %r is not listed by %s/models (served: %s); confirming with a "
                        "real request before reporting OK",
                        self.model,
                        self.base_url,
                        served,
                    )
                    return self._confirm_unlisted(ok_line, served=served)
                # An empty listing is not authoritative -- most likely the server simply
                # does not implement it -- so fall through to the one-token chat probe.
            else:
                problems.append(f"GET /models -> HTTP {response.status_code}")
        except requests.RequestException as exc:
            problems.append(f"GET /models -> {exc}")

        try:
            self.chat([{"role": "user", "content": "ping"}], max_tokens=1, temperature=0.0)
        except LLMError as exc:
            problems.append(f"POST /chat/completions -> {exc}")
        else:
            return ok_line

        raise LLMEndpointError(
            f"LLM endpoint not usable at {self.base_url}: " + "; ".join(problems)
        )

    def _confirm_unlisted(self, ok_line: str, *, served: list[str]) -> str:
        """Decide whether an unlisted model is nonetheless served (part of ``check``).

        Both verdicts are explicit: a gateway that accepts any model name is usable and is
        reported as such, with the discrepancy spelled out; one that rejects the name is
        not usable, and the error names the models it does serve.
        """
        try:
            self.chat([{"role": "user", "content": "ping"}], max_tokens=1, temperature=0.0)
        except LLMError as exc:
            raise LLMEndpointError(
                f"LLM endpoint at {self.base_url} does not serve model {self.model!r}: "
                f"GET /models lists {', '.join(served)}, and a one-token request failed "
                f"with: {exc}"
            ) from exc
        suffix = f" (WARNING: not listed by /models; served: {', '.join(served)})"
        logger.warning("%s%s", ok_line, suffix)
        return ok_line + suffix

    # -- SecLoop high-level helpers -----------------------------------------------------
    def generate_threat_report(self, ids_summary: str, *, max_tokens: int | None = None) -> str:
        """Produce the human-readable threat report for a summarised alert set."""
        summary = _require_non_empty(ids_summary, "C (IDS detection summary)")
        return self.complete(
            _TOOL_REPORT_PROMPT.format(summary=summary), max_tokens=max_tokens
        ).strip()

    def generate_tool_calls(
        self,
        ids_summary: str,
        tool_manager: Any | None = None,
        *,
        platform: str | None = None,
        description: str | None = None,
        available_tools: Sequence[str] | None = None,
        valid_tools: Iterable[str] | None = None,
        max_tokens: int | None = None,
        allow_empty: bool = False,
    ) -> list[dict[str, Any]]:
        """Assemble ``P = [C, T_A, E]`` and return the JSON tool-call strategy.

        ``tool_manager`` defaults to the shared registry in ``agent/tools``.  The ``E``
        section falls back to the ``environment`` block of ``agent/config.json`` and then
        to ``Platform: Linux`` / the registry's tool names.

        Raises:
            ValueError: a prompt section would be empty.
            LLMError (subclasses): bad configuration, unreachable endpoint, unparseable
                answer.  An empty or unparsable strategy is never returned silently.
        """
        manager = tool_manager
        if manager is None:
            from agent.tools.security_tools import create_security_tools  # local import: keep this module light

            manager = create_security_tools()

        tool_descriptions = manager.get_tool_descriptions()
        env = self.environment
        env_tools = (
            list(available_tools)
            if available_tools is not None
            else list(env.get("tools") or manager.get_available_tools())
        )
        env_platform = platform if platform is not None else str(env.get("platform") or "Linux")
        env_description = description if description is not None else str(env.get("description") or "")

        messages = build_messages(
            ids_summary,
            tool_descriptions,
            system_prompt=self.system_prompt,
            platform=env_platform,
            description=env_description,
            available_tools=env_tools,
        )
        raw = self.chat(messages, max_tokens=max_tokens)
        allowed = set(valid_tools) if valid_tools is not None else set(manager.get_available_tools())
        strategy = extract_tool_calls(raw, allowed, allow_empty=allow_empty)
        logger.info("LLM produced a %d-tool strategy", len(strategy))
        return strategy


def get_llm_client(
    config: Mapping[str, Any] | None = None,
    *,
    config_path: str | os.PathLike[str] | None = None,
    **overrides: Any,
) -> LLMClient:
    """**Shared factory — the entry point the training path imports.**

    Reads ``agent/config.json`` (INTERFACES §7.1) unless ``config``/``config_path`` is
    given, and never falls back to a default endpoint: an unconfigured or blank endpoint
    raises :class:`LLMConfigError` instead of returning ``0.0``/``""``.
    """
    return LLMClient.from_config(config, config_path=config_path, **overrides)


# --------------------------------------------------------------------------------------
# CLI: python -m agent.llm.llm_interface --check
# --------------------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agent.llm.llm_interface",
        description="SecLoop vendor-neutral LLM client (shared by evaluation and training).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify endpoint connectivity (INTERFACES §7.2) and exit",
    )
    parser.add_argument("--config", default=None, help=f"config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument(
        "--print-config",
        action="store_true",
        help="print the resolved llm block (api_key_env is a NAME; no key is ever shown)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="logging level (default: INFO)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point.  Returns the process exit code (0 ok, 1 failure)."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.print_config:
        try:
            client = get_llm_client(config_path=args.config)
        except LLMConfigError as exc:
            sys.stderr.write(f"LLM endpoint NOT configured: {exc}\n")
            return 1
        sys.stdout.write(f"{client.describe()}\n")
        return 0

    if args.check:
        try:
            client = get_llm_client(config_path=args.config)
        except LLMConfigError as exc:
            sys.stderr.write(f"LLM endpoint NOT configured: {exc}\n")
            return 1
        try:
            sys.stdout.write(f"{client.check()}\n")
        except LLMError as exc:
            sys.stderr.write(f"LLM endpoint check FAILED: {exc}\n")
            return 1
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI
    raise SystemExit(main())
