# SPDX-License-Identifier: Apache-2.0
"""The agent config schema must do what the repository says it does.

``agent/config.json`` carries an ``agent`` block with ``system_prompt`` and
``max_tokens``.  ``agent/README.md`` calls the non-``llm`` blocks "agent-local", and
``max_tokens`` is read by ``main.py``; ``agent.system_prompt`` must be read too, or it
looks configured and changes no request, because the client reads that key only inside
the ``llm`` block.

These tests pin the wiring, and then follow the value all the way into the chat
messages, because "the attribute is set" is not the property that matters.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import requests

from agent.llm.llm_interface import (
    LLMClient,
    LLMConfigError,
    LLMEndpointError,
    build_messages,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_CONFIG = REPO_ROOT / "agent" / "config.json"

LLM_BLOCK = {"base_url": "http://127.0.0.1:8000/v1", "model": "test-model"}


# ---------------------------------------------------------------------------------------
# Config wiring
# ---------------------------------------------------------------------------------------
def test_agent_block_system_prompt_is_honoured():
    """``agent.system_prompt`` reaches ``client.system_prompt``, not just the config."""
    client = LLMClient.from_config(
        {"llm": LLM_BLOCK, "agent": {"system_prompt": "Be terse."}}
    )
    assert client.system_prompt == "Be terse."


def test_the_llm_block_wins_over_the_agent_block():
    client = LLMClient.from_config(
        {
            "llm": {**LLM_BLOCK, "system_prompt": "from llm"},
            "agent": {"system_prompt": "from agent"},
        }
    )
    assert client.system_prompt == "from llm"


def test_an_explicit_override_wins_over_both():
    client = LLMClient.from_config(
        {
            "llm": {**LLM_BLOCK, "system_prompt": "from llm"},
            "agent": {"system_prompt": "from agent"},
        },
        system_prompt="explicit",
    )
    assert client.system_prompt == "explicit"


def test_a_null_agent_prompt_means_unset_not_empty():
    """The shipped config sets ``null``; that must stay "no system prompt"."""
    client = LLMClient.from_config({"llm": LLM_BLOCK, "agent": {"system_prompt": None}})
    assert client.system_prompt is None


def test_an_llm_block_passed_on_its_own_still_works():
    """``from_config`` accepts the inner block directly; no ``agent`` key exists then."""
    client = LLMClient.from_config({**LLM_BLOCK, "system_prompt": "inner"})
    assert client.system_prompt == "inner"
    assert LLMClient.from_config(LLM_BLOCK).system_prompt is None


def test_unknown_overrides_are_still_rejected():
    with pytest.raises(LLMConfigError):
        LLMClient.from_config({"llm": LLM_BLOCK}, not_a_real_key=1)


def test_the_shipped_config_loads_and_describes_its_prompt_state():
    # A path goes through `config_path`; passing it as `config` is a type error.
    client = LLMClient.from_config(config_path=SHIPPED_CONFIG)
    described = client.describe()
    assert "system_prompt=" in described, "an operator cannot see whether the prompt is active"
    assert "base_url=" in described
    # `describe` is printed by `--check-llm`; it must never echo a secret value.
    assert "api_key_env" in described


def test_the_shipped_agent_block_still_declares_max_tokens():
    document = json.loads(SHIPPED_CONFIG.read_text(encoding="utf-8"))
    assert isinstance(document["agent"]["max_tokens"], int)


# ---------------------------------------------------------------------------------------
# The value has to reach the request, not just the attribute
# ---------------------------------------------------------------------------------------
def test_the_system_prompt_becomes_a_system_message():
    messages = build_messages(
        "IDS summary",
        "- block_ip: ...",
        system_prompt="Be terse.",
        available_tools=["block_ip"],
    )
    assert messages[0] == {"role": "system", "content": "Be terse."}
    assert messages[1]["role"] == "user"


def test_no_system_message_is_invented_when_none_is_configured():
    for configured in (None, ""):
        messages = build_messages(
            "IDS summary",
            "- block_ip: ...",
            system_prompt=configured,
            available_tools=["block_ip"],
        )
        assert all(message["role"] != "system" for message in messages)


def test_the_configured_prompt_and_the_message_builder_agree():
    """The two halves of the same feature: config -> client -> messages."""
    client = LLMClient.from_config(
        {"llm": LLM_BLOCK, "agent": {"system_prompt": "Stay in scope."}}
    )
    messages = build_messages(
        "IDS summary",
        "- block_ip: ...",
        system_prompt=client.system_prompt,
        available_tools=["block_ip"],
    )
    assert messages[0]["content"] == "Stay in scope."


# ---------------------------------------------------------------------------------------
# The endpoint self-check must be able to fail
# ---------------------------------------------------------------------------------------
class _Response:
    def __init__(self, status_code: int, payload=None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _Session:
    """Serves ``GET /models`` and ``POST /chat/completions`` from a script."""

    def __init__(self, models_response, chat_ok: bool) -> None:
        self.models_response = models_response
        self.chat_ok = chat_ok
        self.chat_calls = 0
        self.get_calls = 0

    def get(self, url, **kwargs):  # noqa: D102
        self.get_calls += 1
        if self.models_response is None:
            raise requests.RequestException("connection refused")
        return self.models_response

    def post(self, url, **kwargs):  # noqa: D102
        self.chat_calls += 1
        if not self.chat_ok:
            return _Response(404, {"error": {"message": "model not found"}})
        return _Response(
            200,
            {
                "choices": [{"message": {"role": "assistant", "content": "pong"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )


def _client(session):
    return LLMClient(**{**LLM_BLOCK, "session": session, "max_retries": 0})


def test_a_listed_model_is_reported_ok_without_a_chat_call():
    session = _Session(_Response(200, {"data": [{"id": "test-model"}]}), chat_ok=True)
    assert "model=test-model" in _client(session).check()
    assert session.chat_calls == 0, "a matching listing needs no extra request"


def test_an_unlisted_model_that_the_endpoint_still_serves_is_ok_but_says_so():
    """Some gateways accept any model name; the verdict must still name the discrepancy."""
    session = _Session(_Response(200, {"data": [{"id": "other-model"}]}), chat_ok=True)
    line = _client(session).check()
    assert "OK" in line
    assert "WARNING" in line and "other-model" in line
    assert session.chat_calls == 1


def test_an_unlisted_model_the_endpoint_rejects_fails_the_check():
    """A mis-typed `llm.model` must not pass a self-check.

    With only a log warning the mistake surfaces as a 404 in the middle of a run
    instead of at `--check-llm`.
    """
    session = _Session(_Response(200, {"data": [{"id": "other-model"}]}), chat_ok=False)
    with pytest.raises(LLMEndpointError) as excinfo:
        _client(session).check()
    message = str(excinfo.value)
    assert "test-model" in message and "other-model" in message, "the error must name both"


def test_a_server_without_a_model_listing_still_falls_back_to_chat():
    session = _Session(_Response(404, None), chat_ok=True)
    assert "OK" in _client(session).check()
    assert session.chat_calls == 1


def test_an_empty_listing_is_not_authoritative():
    """An empty `data` is a server that does not implement the endpoint, not a rejection."""
    session = _Session(_Response(200, {"data": []}), chat_ok=True)
    assert "OK" in _client(session).check()


def test_an_unreachable_endpoint_still_fails():
    session = _Session(None, chat_ok=False)
    with pytest.raises(LLMEndpointError):
        _client(session).check()
