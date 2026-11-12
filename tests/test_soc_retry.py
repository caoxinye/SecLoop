# SPDX-License-Identifier: Apache-2.0
"""Capacity exhaustion is retryable, and must not be read as a failed strategy.

``INTERFACES.md`` §3.1 is explicit: ``429`` means the VM pool is exhausted and a client
**must** handle it differently from ``200 + success:false`` -- the first is retryable, the
second says the strategy itself did not work. Collapsing both into one exception lets the
reward layer score the round ``0.0``, so a busy pool teaches the policy that a good
strategy had failed.

These tests use a fake session and a stubbed clock: no network, no sleeping.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

pytest.importorskip("requests", reason="the SOC client needs requests")

import requests  # noqa: E402

from agent.tools.batch_executor import (  # noqa: E402
    SOCBusyError,
    SOCUnavailableError,
    VMConfig,
    parse_retry_after,
    retryable_policy,
)

VM = VMConfig(red_vm="kali", blue_vm="target", attack_mode="sqli", source="test")
STRATEGY = [{"tool": "bash", "params": {"command": "true"}}]


class FakeResponse:
    def __init__(self, status_code: int, headers: dict[str, str] | None = None, body: Any = None):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body if body is not None else {"success": True, "feedback": {}}
        self.text = ""

    def json(self) -> Any:
        return self._body


class FakeSession:
    """Returns queued responses (or raises queued exceptions) and records attempts."""

    def __init__(self, *script: Any) -> None:
        self.script = list(script)
        self.attempts = 0

    def post(self, url: str, *, json: Any = None, timeout: float | None = None) -> FakeResponse:
        self.attempts += 1
        if not self.script:
            raise AssertionError("FakeSession ran out of queued responses")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def no_sleep(monkeypatch):
    """Record requested backoff without actually sleeping."""
    slept: list[float] = []

    def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("agent.tools.batch_executor.time.sleep", fake_sleep)
    return slept


def executor_for(session: FakeSession):
    from agent.tools.batch_executor import BatchExecutor

    return BatchExecutor(endpoint="http://soc.test", session=session, vm_config=VM)


# ---------------------------------------------------------------------------------------
# parse_retry_after (pure)
# ---------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [("5", 5.0), ("0", 0.0), (" 12 ", 12.0), ("-3", 0.0), ("", None), (None, None),
     ("soon", None), ("abc", None), ("1e3", 1000.0)],
)
def test_retry_after_delta_seconds(raw, expected) -> None:
    assert parse_retry_after(raw) == expected


def test_retry_after_accepts_an_http_date() -> None:
    from datetime import datetime, timezone

    value = parse_retry_after(
        "Wed, 21 Oct 2026 07:28:00 GMT",
        now=datetime(2026, 10, 21, 7, 27, 30, tzinfo=timezone.utc),
    )
    assert value == 30.0


def test_retry_after_in_the_past_is_zero_not_negative() -> None:
    from datetime import datetime, timezone

    value = parse_retry_after(
        "Wed, 21 Oct 2026 07:28:00 GMT",
        now=datetime(2026, 10, 21, 8, 0, 0, tzinfo=timezone.utc),
    )
    assert value == 0.0


def test_the_default_policy_is_to_exclude(monkeypatch) -> None:
    monkeypatch.delenv("SECLOOP_RETRYABLE_POLICY", raising=False)
    assert retryable_policy() == "exclude"
    monkeypatch.setenv("SECLOOP_RETRYABLE_POLICY", "nonsense")
    assert retryable_policy() == "exclude", "an unknown value must not disable the policy"
    monkeypatch.setenv("SECLOOP_RETRYABLE_POLICY", "zero")
    assert retryable_policy() == "zero"


# ---------------------------------------------------------------------------------------
# The transport
# ---------------------------------------------------------------------------------------
def test_a_429_is_retried_and_can_succeed(no_sleep) -> None:
    session = FakeSession(FakeResponse(429, {"Retry-After": "2"}), FakeResponse(200))
    body = executor_for(session).submit_strategy(STRATEGY)
    assert body["success"] is True
    assert session.attempts == 2
    assert no_sleep == [2.0], "the server's Retry-After must be honoured"


def test_retry_without_retry_after_falls_back_to_exponential_backoff(no_sleep) -> None:
    session = FakeSession(FakeResponse(429), FakeResponse(429), FakeResponse(200))
    executor_for(session).submit_strategy(STRATEGY)
    assert no_sleep == [1.0, 2.0], "1s, 2s, ... when the server does not say"


def test_a_hostile_retry_after_cannot_stall_the_run(no_sleep) -> None:
    session = FakeSession(FakeResponse(429, {"Retry-After": "999999"}), FakeResponse(200))
    executor_for(session).submit_strategy(STRATEGY)
    assert no_sleep == [60.0], "the sleep is capped"


def test_transport_errors_are_retried_too(no_sleep) -> None:
    session = FakeSession(requests.ConnectionError("boom"), FakeResponse(200))
    assert executor_for(session).submit_strategy(STRATEGY)["success"] is True
    assert session.attempts == 2


def test_exhausting_the_retry_budget_raises_a_retryable_error(no_sleep, monkeypatch) -> None:
    monkeypatch.setenv("SECLOOP_RETRY_ATTEMPTS", "3")
    session = FakeSession(FakeResponse(429), FakeResponse(429), FakeResponse(429))
    with pytest.raises(SOCBusyError) as excinfo:
        executor_for(session).submit_strategy(STRATEGY)
    # Distinct type *and* a message that says what to do about it.
    assert "exclude" in str(excinfo.value)
    assert session.attempts == 3
    assert isinstance(excinfo.value, SOCUnavailableError), "existing handlers must still catch it"


def test_a_non_429_error_is_not_retried(no_sleep) -> None:
    """`500` is not capacity pressure; retrying it would just repeat the failure."""
    session = FakeSession(FakeResponse(500))
    with pytest.raises(SOCUnavailableError) as excinfo:
        executor_for(session).submit_strategy(STRATEGY)
    assert not isinstance(excinfo.value, SOCBusyError)
    assert session.attempts == 1
    assert no_sleep == []


def test_a_200_carrying_success_false_is_never_retried(no_sleep) -> None:
    """The other half of §3.1: the SOC answered, and the answer was "the strategy failed"."""
    session = FakeSession(FakeResponse(200, body={"success": False, "error": "rejected"}))
    body = executor_for(session).submit_strategy(STRATEGY)
    assert body["success"] is False
    assert session.attempts == 1
    assert no_sleep == []
